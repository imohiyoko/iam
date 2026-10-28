package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Back-Channel Logout（OpenID Connect Back-Channel Logout 1.0、design.md 5.2、ADR 0066）。
//
// ログインの系列が終わると（ログアウト・失効・停止など）、その系列の認可を失効させ、backchannel_logout_uri を登録した
// 連携先ごとに Logout Token の送信を outbox に積む（失効と同じトランザクション。少なくとも1回）。送信は LogoutDeliverer。

// LogoutTopic は Back-Channel Logout の outbox のトピック。
const LogoutTopic = "backchannel_logout"

// RevokeReasonLogout はログインの系列が終わったことによる認可の失効。
const RevokeReasonLogout = "session_ended"

// 既定の値。
const (
	// DefaultLogoutGiveUp は送れない Logout Token をあきらめるまでの時間。
	DefaultLogoutGiveUp = time.Hour
	// LogoutTokenTTL は Logout Token の exp（OIDC Back-Channel Logout 2.4 は2分以内を勧める）。
	LogoutTokenTTL = 2 * time.Minute
	logoutTimeout  = 5 * time.Second
	logoutEvent    = "http://schemas.openid.net/event/backchannel-logout"
)

// logoutMessage は outbox に積む中身（内部 ID。外には出さない）。
type logoutMessage struct {
	RealmID  string `json:"realm_id"`
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
	SID      string `json:"sid"`
	// FirstAt は最初に積んだ時刻（積み直したときだけ入る。あきらめるまでの時間はここから数える）。
	FirstAt *time.Time `json:"first_at,omitempty"`
}

// LineageEnded はログインの系列が終わったとき、その系列の認可を失効させ、Back-Channel Logout を積む（session.LineageHook）。
// 期限の切れていない認可を持つ連携先に送る（連携先が自分で失効させた認可でも、連携先のログインは残りうるので送る）。
// 停止が解けて同じ系列がまた終わっても、2度は送らない。
func (t *Tokens) LineageEnded(ctx context.Context, tx port.Tx, realmID, sid, reason, requestID string) error {
	gs, err := tx.Grants().ListBySID(ctx, realmID, sid)
	if err != nil {
		return err
	}
	now := t.Clock.Now()
	sent := map[string]bool{}
	for _, g := range gs {
		// 期限切れの認可と、系列が終わったことで失効させた（送った）認可は飛ばす。
		if !now.Before(g.ExpiresAt) || (g.RevokedAt != nil && g.RevokeReason == RevokeReasonLogout) {
			continue
		}
		cl, err := tx.Clients().Get(ctx, realmID, g.ClientID)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if !revoked(g, now) {
			if err := t.revoke(ctx, tx, cl, g, RevokeReasonLogout, requestID, now); err != nil {
				return err
			}
		}
		if cl.BackchannelLogoutURI == "" || sent[cl.ID] {
			continue
		}
		sent[cl.ID] = true
		b, err := json.Marshal(logoutMessage{RealmID: realmID, ClientID: cl.ID, UserID: g.UserID, SID: sid})
		if err != nil {
			return err
		}
		if err := tx.Outbox().Add(ctx, port.OutboxMessage{ID: id.NewExternal(id.Outbox), Topic: LogoutTopic, Payload: b, CreatedAt: now}); err != nil {
			return err
		}
	}
	return nil
}

// LogoutDeliverer は outbox の Back-Channel Logout を連携先に送る（eventlog.Relay の Deliver）。
type LogoutDeliverer struct {
	Storage port.Storage
	Keys    *Keys
	Clock   clock.Clock
	Issuer  string
	// HTTP は送信に使う（nil なら 5 秒で打ち切り、転送を追わないクライアント）。
	HTTP *http.Client
	// GiveUp は送れないものをあきらめるまでの時間（既定 1 時間）。それまでは次の送出でまた送る。
	GiveUp time.Duration
	Log    *slog.Logger
}

func (d *LogoutDeliverer) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return &http.Client{Timeout: logoutTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (d *LogoutDeliverer) logger() *slog.Logger {
	if d.Log == nil {
		return slog.Default()
	}
	return d.Log
}

// Deliver は送れたもの・送らなくてよいもの（連携先が消えた・送り先が外れた・読めない・あきらめた）・積み直したものの ID を返す。
// 送れなかったものは、1件の失敗で残りを止めないよう、エラーにせず outbox の末尾に積み直して次の送出に回す
// （先頭に残すと、送れないものが1回の取り出し件数を埋めて、後ろの送れるものを塞ぐ）。
func (d *LogoutDeliverer) Deliver(ctx context.Context, msgs []port.OutboxMessage) ([]string, error) {
	giveUp := ttlOr(d.GiveUp, DefaultLogoutGiveUp)
	var done []string
	for _, m := range msgs {
		var x logoutMessage
		if err := json.Unmarshal(m.Payload, &x); err != nil {
			d.logger().ErrorContext(ctx, "backchannel logout: skipping unreadable message", "id", m.ID, "error", err)
			done = append(done, m.ID)
			continue
		}
		uri, token, err := d.token(ctx, m.ID, x)
		if err == nil && uri == "" {
			done = append(done, m.ID)
			continue
		}
		// 保存先や署名の一時的な失敗も、送れなかったときと同じく、あきらめるまで次の送出でまた試す。
		if err == nil {
			err = d.post(ctx, uri, token)
		}
		if err == nil {
			done = append(done, m.ID)
			continue
		}
		first := m.CreatedAt
		if x.FirstAt != nil {
			first = *x.FirstAt
		}
		if d.Clock.Now().Sub(first) >= giveUp {
			d.logger().WarnContext(ctx, "backchannel logout: giving up", "id", m.ID, "error", err)
			done = append(done, m.ID)
			continue
		}
		// 積み直せなければ（保存先の障害など）、そのまま残して次の送出でまた試す。
		if rerr := d.requeue(ctx, m, x, first); rerr != nil {
			d.logger().InfoContext(ctx, "backchannel logout: will retry", "id", m.ID, "error", err, "requeue_error", rerr)
			continue
		}
		d.logger().InfoContext(ctx, "backchannel logout: will retry", "id", m.ID, "error", err)
		done = append(done, m.ID)
	}
	return done, nil
}

// requeue は送れなかったメッセージを、最初に積んだ時刻を持たせて outbox の末尾に積み直す。
func (d *LogoutDeliverer) requeue(ctx context.Context, m port.OutboxMessage, x logoutMessage, first time.Time) error {
	x.FirstAt = &first
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	return d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return tx.Outbox().Add(ctx, port.OutboxMessage{ID: id.NewExternal(id.Outbox), Topic: m.Topic, Payload: b, CreatedAt: d.Clock.Now()})
	})
}

// token は Logout Token（OIDC Back-Channel Logout 2.4）を作る。送らなくてよければ uri は空。
func (d *LogoutDeliverer) token(ctx context.Context, jti string, x logoutMessage) (uri, token string, err error) {
	err = d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cl, err := tx.Clients().Get(ctx, x.RealmID, x.ClientID)
		if errors.Is(err, errs.NotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if cl.BackchannelLogoutURI == "" {
			return nil
		}
		now := d.Clock.Now()
		claims := map[string]any{"iss": d.Issuer, "aud": cl.PublicID, "iat": now.Unix(), "exp": now.Add(LogoutTokenTTL).Unix(),
			"jti": jti, "sid": x.SID, "events": map[string]any{logoutEvent: map[string]any{}}}
		// 消去したユーザーは sub を出さない（sid だけで足りる）。
		if u, err := tx.Users().Get(ctx, x.RealmID, x.UserID); err == nil {
			claims["sub"] = u.PublicID
		} else if !errors.Is(err, errs.NotFound) {
			return err
		}
		b, err := json.Marshal(claims)
		if err != nil {
			return err
		}
		if token, err = d.Keys.Sign(ctx, tx, x.RealmID, cl.IDTokenAlg, "logout+jwt", b); err != nil {
			return err
		}
		uri = cl.BackchannelLogoutURI
		return nil
	})
	return uri, token, err
}

func (d *LogoutDeliverer) post(ctx context.Context, uri, token string) error {
	ctx, cancel := context.WithTimeout(ctx, logoutTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.client().Do(req) // #nosec G704 -- 送り先は運営者が登録した backchannel_logout_uri
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
