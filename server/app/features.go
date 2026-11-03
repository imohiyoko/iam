package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/authn/method"
	dirldap "github.com/imohiyoko/iam/authn/method/ldap"
	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// preparers は、後からフィーチャーを有効にするときの準備処理（design.md 11.12 の enabling）。冪等にする。
var preparers = map[string]func(ctx context.Context, a *App) error{
	feature.Org: prepareOrg,
}

// cleaner はフィーチャーを無効にするときの、データの数え上げと片付け（11.12 の disabling）。
// Purge は1つのトランザクションで最大 limit 件片付け、片付けた件数を返す。nil なら片付けは運営者が API で行う。
type cleaner struct {
	Count func(ctx context.Context, tx port.Tx) (int, error)
	Purge func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error)
	// Hint は Purge が無いときに、データの片付け方を示す。
	Hint string
}

// cleaners はデータを残すフィーチャーの片付け。無いフィーチャーはデータを残さない（warnings など）。
var cleaners = map[string]cleaner{
	feature.Org: {Count: countSharedOrgs,
		Hint: "delete the shared Orgs (POST /v1/admin/orgs/{org_id}:delete); personal Orgs are kept and reused when org is enabled again"},
	feature.OrgLoginPolicy: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return org.HasLoginPolicy(o) })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachOrg(ctx, tx, limit, func(o port.Org) (bool, error) { return org.ClearLoginPolicy(ctx, tx, o, now) })
	}},
	// ログインポリシーの min_aal を外す（ADR 0093）。条件の aal_at_least は残し、判定し続ける（外すと緩むため。運営者が外す）。
	feature.ACR: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return org.HasMinAAL(o) })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachOrg(ctx, tx, limit, func(o port.Org) (bool, error) { return org.ClearMinAAL(ctx, tx, o, now) })
	}},
	// 親子関係を外す（ADR 0078）。
	feature.OrgHierarchy: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return o.ParentID != "", nil })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachOrg(ctx, tx, limit, func(o port.Org) (bool, error) { return org.ClearParent(ctx, tx, o, now) })
	}},
	feature.Quota: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.QuotaGrants().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.QuotaGrants().Purge(ctx, limit)
		}},
	// 管理ユーザーは個人ユーザーに戻し、Org 専用 SSO の connection（外部 ID を無効化する）、ログインポリシーの require_sso、
	// ドメインを消す（ADR 0076、0077）。
	feature.OrgManagedUsers: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := tx.Users().CountManaged(ctx)
		if err != nil {
			return 0, err
		}
		c, err := eachOwnedConnections(ctx, tx, -1, time.Time{}, false)
		if err != nil {
			return 0, err
		}
		p, err := eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return org.HasRequireSSO(o) })
		if err != nil {
			return 0, err
		}
		d, err := tx.OrgDomains().Count(ctx)
		return n + c + p + d, err
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := tx.Users().ReleaseManaged(ctx, limit, now)
		if err != nil || n >= limit {
			return n, err
		}
		c, err := eachOwnedConnections(ctx, tx, limit-n, now, true)
		if n += c; err != nil || n >= limit {
			return n, err
		}
		p, err := eachOrg(ctx, tx, limit-n, func(o port.Org) (bool, error) { return org.ClearRequireSSO(ctx, tx, o, now) })
		if n += p; err != nil || n >= limit {
			return n, err
		}
		d, err := tx.OrgDomains().Purge(ctx, limit-n)
		return n + d, err
	}},
	// Group としての所属と閉包の行を消す（ADR 0079。閉包から消すので、消し始めたら含む Group の付与は効かない）。
	feature.NestedGroups: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.Groups().CountNested(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.Groups().PurgeNested(ctx, limit)
		}},
	// 値と定義を消す（ADR 0080）。
	feature.CustomAttributes: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.Attributes().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.Attributes().Purge(ctx, limit)
		}},
	feature.ServiceAccounts: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachServiceAccount(ctx, tx, -1, func(port.ServiceAccount) (bool, error) { return true, nil })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachServiceAccount(ctx, tx, limit, func(sa port.ServiceAccount) (bool, error) {
			return true, tx.ServiceAccounts().SetDeleted(ctx, sa.RealmID, sa.ID, now)
		})
	}},
	// 既定以外の realm（ADR 0083）。realm の削除はまだ無いため、realm があるうちは無効にできない。
	feature.MultiRealm: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		rs, err := tx.Realms().List(ctx)
		return max(len(rs)-1, 0), err
	}, Hint: "realms other than the default cannot be deleted yet: keep multi_realm enabled while they exist"},
	// 連携先の許可と交換の認可を消す（ADR 0099）。
	feature.TokenExchange: exchangeCleaner,
	feature.Impersonation: impersonationCleaner,
	// 端末の記録を消す（ADR 0105）。ロックアウトとボット対策の状態は EphemeralStore にあり、期限で消える。
	feature.DeviceRecognition: deviceCleaner,
	// 購読と署名の鍵（データ鍵）を消す（ADR 0100）。
	feature.EventSubscriptions: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.EventSubscriptions().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return eventsub.Purge(ctx, tx, limit)
		}},
	// SAML の connection（realm 共通と Org 専用）を消し、紐付けた外部 ID を無効化する（ADR 0098）。
	feature.SAML: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachTypedConnection(ctx, tx, saml.Type, -1, time.Time{}, false)
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachTypedConnection(ctx, tx, saml.Type, limit, now, true)
	}},
	// Org のログインポリシーの passkey と、realm の設定の passkey_policy を外す（ADR 0096）。設定ファイルの realm.passkey_policy は
	// 運用者が消す（フィーチャーが止まっていれば使わない）。登録済みの passkey の attestation の列は残す。
	feature.PasskeyAttestation: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return org.HasPasskeyPolicy(o) })
		if err != nil {
			return 0, err
		}
		r, err := eachRealmPasskeyPolicy(ctx, tx, -1, time.Time{}, false)
		return n + r, err
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachOrg(ctx, tx, limit, func(o port.Org) (bool, error) { return org.ClearPasskeyPolicy(ctx, tx, o, now) })
		if err != nil || n >= limit {
			return n, err
		}
		r, err := eachRealmPasskeyPolicy(ctx, tx, limit-n, now, true)
		return n + r, err
	}},
	// 連携先の Front-Channel Logout の登録を外す（ADR 0094。post_logout_redirect_uris は前からある項目なので残す）。
	feature.OIDCLogout: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return hasFrontChannel(c), nil })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !hasFrontChannel(c) {
				return false, nil
			}
			c.FrontchannelLogoutURI, c.FrontchannelLogoutSessionRequired, c.UpdatedAt = "", false, now
			return true, tx.Clients().Update(ctx, c)
		})
	}},
	// LDAP の connection（realm 共通と Org 専用）を消し、紐付けた外部 ID を無効化し、同期の Group の対応を外す（ADR 0102）。
	// 同期が作った Group と所属は、ふつうの Group として残す。
	feature.LDAP: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachTypedConnection(ctx, tx, dirldap.Type, -1, time.Time{}, false)
		if err != nil {
			return n, err
		}
		g, err := tx.DirectoryGroups().Count(ctx)
		return n + g, err
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachTypedConnection(ctx, tx, dirldap.Type, limit, now, true)
		if err != nil || n >= limit {
			return n, err
		}
		g, err := tx.DirectoryGroups().Purge(ctx, limit-n)
		return n + g, err
	}},
	// パスワードは authn_credentials（方式 password。ADR 0101）にある。
	feature.Password: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return tx.Credentials().Count(ctx, method.Password)
	}, Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
		return tx.Credentials().Purge(ctx, method.Password, limit)
	}},
	// 連携先の Device Authorization Grant の許可を外す（ADR 0095）。途中の要求は EphemeralStore にあり、期限で消える。
	feature.DeviceFlow: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return c.DeviceGrant, nil })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !c.DeviceGrant {
				return false, nil
			}
			c.DeviceGrant, c.UpdatedAt = false, now
			return true, tx.Clients().Update(ctx, c)
		})
	}},
	// WS-Federation の RP と署名の証明書を消す（ADR 0110）。ログイン画面で待つ間の要求は EphemeralStore にあり、期限で消える。
	feature.WSFed: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.WSFed().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.WSFed().Purge(ctx, limit)
		}},
	// 本人の Personal Access Token と realm のポリシーを消す（ADR 0109）。
	feature.PersonalAccessTokens: patCleaner,
	// DPoP と OAuth の mTLS（ADR 0113）。連携先の設定を外し、結び付けたトークンを消す。
	feature.DPoP:           dpopCleaner,
	feature.MTLSClientAuth: mtlsCleaner,
	// 連携先と realm の PAR の必須を外す（ADR 0112）。預かった request_uri は EphemeralStore にあり、期限で消える。
	feature.PAR: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return c.RequirePAR, nil })
		if err != nil {
			return 0, err
		}
		r, err := eachRealmFlag(ctx, tx, "require_pushed_authorization_requests", -1, time.Time{})
		return n + r, err
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !c.RequirePAR {
				return false, nil
			}
			c.RequirePAR, c.UpdatedAt = false, now
			return true, tx.Clients().Update(ctx, c)
		})
		if err != nil || n >= limit {
			return n, err
		}
		r, err := eachRealmFlag(ctx, tx, "require_pushed_authorization_requests", limit-n, now)
		return n + r, err
	}},
	// 自前の API（リソースサーバー）の登録を消す（ADR 0112）。発行済みの aud を持つトークンは、フィーチャーが止まれば
	// 検証で使えない（fail-closed）ので、期限まで残してよい。
	feature.ResourceIndicators: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.OAuthResources().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.OAuthResources().Purge(ctx, limit)
		}},
	// 連携先の CIBA の登録（モードと ping の通知先）を外す（ADR 0114）。途中の要求は EphemeralStore にあり、期限で消える。
	feature.CIBA: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return c.CIBAMode != "" || c.CIBANotificationEndpoint != "", nil })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if c.CIBAMode == "" && c.CIBANotificationEndpoint == "" {
				return false, nil
			}
			c.CIBAMode, c.CIBANotificationEndpoint, c.UpdatedAt = "", "", now
			return true, tx.Clients().Update(ctx, c)
		})
	}},
	// SAML の SP の登録と IdP の署名の証明書を消す（ADR 0115）。ログイン画面で待つ間の要求は EphemeralStore にあり、期限で消える。
	feature.SAMLIdP: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.SAMLIdP().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.SAMLIdP().Purge(ctx, limit)
		}},
	// 連携先と realm の FAPI 2.0 Security Profile を外す（ADR 0117）。PAR の必須・送信者制約の設定は連携先に残したもののまま。
	feature.FAPI2: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return c.FAPI2, nil })
		if err != nil {
			return 0, err
		}
		r, err := eachRealmFlag(ctx, tx, "fapi2_security_profile", -1, time.Time{})
		return n + r, err
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !c.FAPI2 {
				return false, nil
			}
			c.FAPI2, c.UpdatedAt = false, now
			return true, tx.Clients().Update(ctx, c)
		})
		if err != nil || n >= limit {
			return n, err
		}
		r, err := eachRealmFlag(ctx, tx, "fapi2_security_profile", limit-n, now)
		return n + r, err
	}},
	// Workload Identity Federation の発行者・結び付けと、結び付けで発行したアクセストークンを消す（ADR 0116）。
	// 取得した JWKS と jti は EphemeralStore にあり、期限で消える。
	feature.WorkloadIdentity: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.WorkloadIdentity().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.WorkloadIdentity().Purge(ctx, limit)
		}},
}

// eachRealmFlag は realm の設定の真偽値の項目 key（require_pushed_authorization_requests など）が真の realm を数える。
// now が零でなければ、最大 limit 件（負なら全部）を偽にする（ほかの設定はそのまま残す）。
func eachRealmFlag(ctx context.Context, tx port.Tx, key string, limit int, now time.Time) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		if limit >= 0 && n >= limit {
			break
		}
		var m map[string]json.RawMessage
		if len(r.Settings) == 0 || json.Unmarshal(r.Settings, &m) != nil {
			continue
		}
		var on bool
		if json.Unmarshal(m[key], &on) != nil || !on {
			continue
		}
		n++
		if now.IsZero() {
			continue
		}
		m[key] = json.RawMessage("false")
		if r.Settings, err = json.Marshal(m); err != nil {
			return n, err
		}
		r.UpdatedAt = now
		if err := tx.Realms().Update(ctx, r); err != nil {
			return n, err
		}
	}
	return n, nil
}

// eachClient は全 realm の連携先に fn を呼び、true を返した数を数える。limit が 0 以上なら、その数で止める。
func eachClient(ctx context.Context, tx port.Tx, limit int, fn func(port.Client) (bool, error)) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		cs, err := tx.Clients().List(ctx, r.ID)
		if err != nil {
			return n, err
		}
		for _, c := range cs {
			if limit >= 0 && n >= limit {
				return n, nil
			}
			ok, err := fn(c)
			if err != nil {
				return n, err
			}
			if ok {
				n++
			}
		}
	}
	return n, nil
}

// hasFrontChannel は連携先が Front-Channel Logout を登録しているか（フィーチャー oidc_logout のデータ）。
func hasFrontChannel(c port.Client) bool {
	return c.FrontchannelLogoutURI != "" || c.FrontchannelLogoutSessionRequired
}

// methodCleaner は、フィーチャー name で動く認証方式のプラグイン（ADR 0092）の認証情報の数え上げと片付け。方式が無ければ false。
func methodCleaner(name string) (cleaner, bool) {
	var names []string
	for _, a := range method.Registered() {
		if a.Info().Feature == name {
			names = append(names, a.Info().Name)
		}
	}
	if len(names) == 0 {
		return cleaner{}, false
	}
	return cleaner{Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n := 0
		for _, m := range names {
			c, err := tx.Credentials().Count(ctx, m)
			if err != nil {
				return 0, err
			}
			n += c
		}
		return n, nil
	}, Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
		n := 0
		for _, m := range names {
			c, err := tx.Credentials().Purge(ctx, m, limit-n)
			if n += c; err != nil || n >= limit {
				return n, err
			}
		}
		return n, nil
	}}, true
}

// eachOwnedConnections は全 realm の Org 専用の connection を数える。purge なら limit（0 以上なら）まで消す。
func eachOwnedConnections(ctx context.Context, tx port.Tx, limit int, now time.Time, purge bool) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		if !purge {
			c, err := tx.Connections().CountOwned(ctx, r.ID)
			if err != nil {
				return 0, err
			}
			n += c
			continue
		}
		cs, err := tx.Connections().List(ctx, r.ID)
		if err != nil {
			return n, err
		}
		owners := map[string]bool{}
		for _, c := range cs {
			if c.OwnerOrgID != "" {
				owners[c.OwnerOrgID] = true
			}
		}
		for o := range owners {
			if limit >= 0 && n >= limit {
				return n, nil
			}
			c, err := org.PurgeConnections(ctx, tx, r.ID, o, now, limit-n)
			if n += c; err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// eachTypedConnection は全 realm の、種類が typ の connection を数える。purge なら limit（0 以上なら）まで、外部 ID を無効化して消す
// （ディレクトリの同期の Group の対応も外す。Group は残る）。
func eachTypedConnection(ctx context.Context, tx port.Tx, typ string, limit int, now time.Time, purge bool) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		cs, err := tx.Connections().List(ctx, r.ID)
		if err != nil {
			return n, err
		}
		for _, c := range cs {
			if c.Type != typ {
				continue
			}
			if limit >= 0 && n >= limit {
				return n, nil
			}
			if purge {
				if _, err := tx.Identities().RevokeByConnection(ctx, r.ID, c.ID, now, org.RevokeConnectionDeleted); err != nil {
					return n, err
				}
				if _, err := tx.DirectoryGroups().DeleteByConnection(ctx, r.ID, c.ID); err != nil {
					return n, err
				}
				if err := tx.Connections().Delete(ctx, r.ID, c.ID); err != nil {
					return n, err
				}
			}
			n++
		}
	}
	return n, nil
}

// countSharedOrgs は削除されていない共有 Org を数える。
func countSharedOrgs(ctx context.Context, tx port.Tx) (int, error) {
	return eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return o.Kind == port.OrgShared && o.DeletedAt == nil, nil })
}

// eachOrg は全 realm の Org に fn を呼び、true を返した数を数える。limit が 0 以上なら、その数で止める。
func eachOrg(ctx context.Context, tx port.Tx, limit int, fn func(port.Org) (bool, error)) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		for after := ""; ; {
			page, err := tx.Orgs().List(ctx, r.ID, after, prepareBatch)
			if err != nil {
				return n, err
			}
			for _, o := range page {
				after = o.ID
				ok, err := fn(o)
				if err != nil {
					return n, err
				}
				if ok {
					n++
				}
				if limit >= 0 && n >= limit {
					return n, nil
				}
			}
			if len(page) < prepareBatch {
				break
			}
		}
	}
	return n, nil
}

// eachServiceAccount は全 realm の、削除していない配信用でないサービスアカウント（フィーチャー service_accounts のデータ）に
// fn を呼び、true を返した数を数える。limit が 0 以上なら、その数で止める。
func eachServiceAccount(ctx context.Context, tx port.Tx, limit int, fn func(port.ServiceAccount) (bool, error)) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		for after := ""; ; {
			page, err := tx.ServiceAccounts().List(ctx, r.ID, after, prepareBatch)
			if err != nil {
				return n, err
			}
			for _, sa := range page {
				after = sa.ID
				if sa.DeletedAt != nil {
					continue
				}
				if delivery, err := deliveryOnly(ctx, tx, sa); err != nil || delivery {
					if err != nil {
						return n, err
					}
					continue
				}
				ok, err := fn(sa)
				if err != nil {
					return n, err
				}
				if ok {
					n++
				}
				if limit >= 0 && n >= limit {
					return n, nil
				}
			}
			if len(page) < prepareBatch {
				break
			}
		}
	}
	return n, nil
}

// prepareBatch は準備処理の1つのトランザクションで扱う件数。
const prepareBatch = 200

// EnableFeature はフィーチャーを有効にする（11.12）：台帳を enabling にし、準備処理を行い、active にする。
// 既に active なら何もせず false を返す。動いているサーバーには、再起動で反映する。
func (a *App) EnableFeature(ctx context.Context, name string) (bool, error) {
	i := slices.IndexFunc(a.binary, func(f feature.Feature) bool { return f.Name == name })
	if i < 0 {
		return false, fmt.Errorf("feature: %s is not included in this binary", name)
	}
	f := a.binary[i]
	if enabled := derefFeatures(a.cfg.Features); (enabled == nil && !f.DefaultEnabled) || (enabled != nil && !slices.Contains(enabled, name)) {
		return false, fmt.Errorf("feature: %s is disabled in config; enable it in `features` first", name)
	}
	var ledger []port.FeatureRecord
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		ledger, err = tx.Features().List(ctx)
		return err
	}); err != nil {
		return false, err
	}
	state := func(n string) port.FeatureState {
		for _, r := range ledger {
			if r.Feature == n {
				return r.State
			}
		}
		return ""
	}
	if state(name) == port.FeatureActive {
		return false, nil
	}
	for _, r := range f.Requires {
		if state(r) != port.FeatureActive {
			return false, fmt.Errorf("feature: %s requires %s; enable it first", name, r)
		}
	}
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return tx.Features().Put(ctx, port.FeatureRecord{Feature: name, State: port.FeatureEnabling, DataVersion: f.DataVersion, UpdatedAt: a.deps.Clock.Now()})
	}); err != nil {
		return false, err
	}
	if p := preparers[name]; p != nil {
		if err := p(ctx, a); err != nil {
			return false, fmt.Errorf("feature: prepare %s: %w", name, err)
		}
	}
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Features().Put(ctx, port.FeatureRecord{Feature: name, State: port.FeatureActive, DataVersion: f.DataVersion, UpdatedAt: a.deps.Clock.Now()}); err != nil {
			return err
		}
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "feature.enabled", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"features": []string{name}, "reason": "cli"},
		})
		return err
	})
	return err == nil, err
}

// prepareOrg は既存のユーザーに個人 Org を作る（11.13）。既存の realm 範囲のロール付与は realm 範囲のまま残す。
// 準備の後に作られたユーザーの取りこぼしは、ログイン時に org.Service.Pick が作って補う。
func prepareOrg(ctx context.Context, a *App) error {
	svc := &org.Service{Clock: a.deps.Clock}
	var realms []port.Realm
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		realms, err = tx.Realms().List(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, r := range realms {
		for after := ""; ; {
			var n int
			err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				us, err := tx.Users().List(ctx, r.ID, after, prepareBatch)
				if err != nil {
					return err
				}
				n = len(us)
				for _, u := range us {
					after = u.ID
					if u.Status != port.UserActive {
						continue
					}
					if _, err := svc.EnsurePersonal(ctx, tx, u, ""); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			if n < prepareBatch {
				break
			}
		}
	}
	return nil
}

// DisableResult は DisableFeature の結果。
type DisableResult struct {
	// Done は無効化が終わった（データが 0 件になり、台帳から消した）。
	Done bool
	// Remaining は残っているデータの件数。Purged は今回片付けた件数。
	Remaining, Purged int
	// Hint は Purge できないときの片付け方。
	Hint string
}

// ErrFeatureRequired は、無効にしようとしたフィーチャーに依存するものがまだ有効なこと。
var ErrFeatureRequired = errors.New("feature: required by another feature")

// DisableFeature はフィーチャーを無効にする（11.12）：台帳を disabling にし（再起動したサーバーは書き込まない）、
// データが 0 件なら台帳から消す。purge なら片付けてから数える。データが残れば disabling のまま Remaining を返す。
// 台帳に無ければ何もせず Done を返す。
func (a *App) DisableFeature(ctx context.Context, name string, purge bool) (DisableResult, error) {
	if !slices.ContainsFunc(a.binary, func(f feature.Feature) bool { return f.Name == name }) {
		return DisableResult{}, fmt.Errorf("feature: %s is not included in this binary; disable it with a binary that includes it", name)
	}
	var rec *port.FeatureRecord
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ledger, err := tx.Features().List(ctx)
		if err != nil {
			return err
		}
		for _, r := range ledger {
			if r.Feature == name {
				rec = &r
				continue
			}
			for _, f := range a.binary {
				if f.Name == r.Feature && slices.Contains(f.Requires, name) {
					return fmt.Errorf("%w: %s requires %s; disable %s first", ErrFeatureRequired, r.Feature, name, r.Feature)
				}
			}
		}
		if rec == nil || rec.State == port.FeatureDisabling {
			return nil
		}
		rec.State, rec.UpdatedAt = port.FeatureDisabling, a.deps.Clock.Now()
		if err := tx.Features().Put(ctx, *rec); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "feature.disabling", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"features": []string{name}, "reason": "cli"},
		})
		return err
	}); err != nil || rec == nil {
		return DisableResult{Done: err == nil}, err
	}
	c, hasData := cleaners[name]
	if !hasData {
		c, hasData = methodCleaner(name)
	}
	var res DisableResult
	if hasData && purge && c.Purge == nil {
		return res, fmt.Errorf("feature: %s data cannot be purged here: %s", name, c.Hint)
	}
	for hasData && purge {
		var n int
		if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			n, err = c.Purge(ctx, tx, a.deps.Clock.Now(), prepareBatch)
			return err
		}); err != nil {
			return res, err
		}
		res.Purged += n
		// 1回で limit に満たなくても続ける（階層は葉から外すので、1回で外せない Org が残る）。何も片付かなければ終わり。
		if n == 0 {
			break
		}
	}
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if hasData {
			var err error
			if res.Remaining, err = c.Count(ctx, tx); err != nil || res.Remaining > 0 {
				res.Hint = c.Hint
				return err
			}
		}
		if err := tx.Features().Delete(ctx, name); err != nil {
			return err
		}
		res.Done = true
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "feature.disabled", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"features": []string{name}, "reason": "cli", "purged": res.Purged},
		})
		return err
	})
	return res, err
}

// eachRealmPasskeyPolicy は、設定に認証器のポリシー（passkey_policy）を持つ realm の行を数える。purge なら limit（0 以上なら）
// まで、ポリシーを null（無し）にする（ADR 0096）。
func eachRealmPasskeyPolicy(ctx context.Context, tx port.Tx, limit int, now time.Time, purge bool) (int, error) {
	rs, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if limit >= 0 && n >= limit {
			break
		}
		var m map[string]json.RawMessage
		if len(r.Settings) == 0 || json.Unmarshal(r.Settings, &m) != nil {
			continue
		}
		var p *attestation.Policy
		if raw, ok := m["passkey_policy"]; !ok || json.Unmarshal(raw, &p) != nil || p.Empty() {
			continue
		}
		n++
		if !purge {
			continue
		}
		m["passkey_policy"] = json.RawMessage("null")
		if r.Settings, err = json.Marshal(m); err != nil {
			return n, err
		}
		r.UpdatedAt = now
		if err := tx.Realms().Update(ctx, r); err != nil {
			return n, err
		}
	}
	return n, nil
}
