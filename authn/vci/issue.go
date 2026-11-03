package vci

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// 発行（credential エンドポイント。OpenID4VCI 8）と失効（Token Status List）。

// status list の大きさと発行の上限。
const (
	// StatusListSize は status list の番号の数（1 bit ずつ。16 KiB）。
	StatusListSize = 1 << 17
	// StatusListTTL は status list token の ttl（検証者が取り直すまでの長さ）。
	StatusListTTL = 5 * time.Minute
	// statusListExp は status list token の exp（iat から）。
	statusListExp = 10 * time.Minute
	// allocAttempts は空いた番号を選ぶ回数。
	allocAttempts = 8
	// expiredBatch は発行のときに消す期限切れの記録の数。
	expiredBatch = 100
	// MaxRequestSize は credential の要求の本文の上限。
	MaxRequestSize = 64 << 10
)

// CredentialRequest は読んだ credential の要求。
type CredentialRequest struct {
	ConfigurationID string
	Proof           string
}

// ParseCredentialRequest は credential の要求（JSON）を読む。credential_configuration_id と、proofs.jwt のちょうど 1 つを求める。
// 単数の proof、credential_identifier（authorization_details を持たないので発行していない）、応答の暗号化は拒む。
func ParseCredentialRequest(b []byte) (CredentialRequest, error) {
	if len(b) > MaxRequestSize {
		return CredentialRequest{}, vciError(CodeInvalidCredentialRequest, "too large")
	}
	m, err := sdjwt.DecodeObject(b)
	if err != nil {
		return CredentialRequest{}, vciError(CodeInvalidCredentialRequest, "json")
	}
	if _, ok := m["credential_response_encryption"]; ok {
		return CredentialRequest{}, vciError(CodeInvalidEncryptionParameters, "encryption is not supported")
	}
	if _, ok := m["proof"]; ok {
		return CredentialRequest{}, vciError(CodeInvalidCredentialRequest, "proof (singular) is not supported; use proofs")
	}
	if _, ok := m["credential_identifier"]; ok {
		return CredentialRequest{}, vciError(CodeUnknownCredentialIdentifier, reasonCredentialIdentifierNotIssued)
	}
	cid, ok := m["credential_configuration_id"].(string)
	if !ok || cid == "" {
		return CredentialRequest{}, vciError(CodeInvalidCredentialRequest, "credential_configuration_id is required")
	}
	proofs, ok := m["proofs"].(map[string]any)
	if !ok {
		return CredentialRequest{}, vciError(CodeInvalidProof, "proofs is required")
	}
	if len(proofs) != 1 {
		return CredentialRequest{}, vciError(CodeInvalidProof, reasonUnsupportedProofType)
	}
	jwts, ok := proofs["jwt"].([]any)
	if !ok {
		return CredentialRequest{}, vciError(CodeInvalidProof, reasonUnsupportedProofType)
	}
	if len(jwts) != 1 {
		return CredentialRequest{}, vciError(CodeInvalidProof, "exactly one proof is supported")
	}
	jwt, ok := jwts[0].(string)
	if !ok || jwt == "" {
		return CredentialRequest{}, vciError(CodeInvalidProof, "proof is not a string")
	}
	return CredentialRequest{ConfigurationID: cid, Proof: jwt}, nil
}

// allows は g が定義 c を発行してよいかを返す。
func (g Grant) allows(c port.VCICredentialConfiguration) bool {
	if g.Flow == FlowPreAuthorized {
		return slices.Contains(g.ConfigurationIDs, c.ConfigurationID)
	}
	return c.Scope != "" && slices.Contains(g.Scopes, c.Scope)
}

// Issued は発行した資格情報。
type Issued struct {
	Credential string
	Record     port.VCIIssuedCredential
}

// Issue は credential の要求に応えて SD-JWT VC を発行する。誤りは *Error（OpenID4VCI 8.3.1.2 の code）で、監査ログに理由を残す。
func (s *Service) Issue(ctx context.Context, g Grant, body []byte, requestID string) (Issued, error) {
	out, cid, err := s.issue(ctx, g, body, requestID)
	if code, reason := CodeOf(err); code != "" {
		s.rejected(ctx, g, cid, code, reason, requestID)
	}
	return out, err
}

func (s *Service) rejected(ctx context.Context, g Grant, cid, code, reason, requestID string) {
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		actor := audit.Actor{Type: "anonymous"}
		if u, err := tx.Users().Get(ctx, g.RealmID, g.UserID); err == nil {
			actor = audit.Actor{Type: "user", ID: u.PublicID}
		}
		d := map[string]any{"error": code, "reason": reason, "flow": g.Flow}
		if cid != "" {
			d["configuration_id"] = cid
		}
		if g.ClientID != "" {
			d["client_id"] = g.ClientID
		}
		return record(ctx, tx, s.Clock, "vci.credential_rejected", audit.ResultFailure, g.RealmID, actor, requestID, d)
	})
	if err != nil && s.Log != nil {
		s.Log.WarnContext(ctx, "vci: audit credential rejection", "error", err)
	}
}

func (s *Service) issue(ctx context.Context, g Grant, body []byte, requestID string) (Issued, string, error) {
	req, err := ParseCredentialRequest(body)
	if err != nil {
		return Issued{}, "", err
	}
	cid := req.ConfigurationID
	var c port.VCICredentialConfiguration
	var cfg Config
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		c, err = tx.VCI().GetConfigurationByConfigurationID(ctx, g.RealmID, cid)
		if err != nil {
			return err
		}
		cfg, err = Parse(c)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return Issued{}, cid, vciError(CodeUnknownCredentialConfiguration, "unknown configuration")
	}
	if err != nil {
		return Issued{}, cid, err
	}
	if !g.allows(c) {
		return Issued{}, cid, vciError(CodeCredentialRequestDenied, reasonConfigurationNotAuthorized)
	}
	now := s.Clock.Now()
	p, err := VerifyProof(req.Proof, ProofOptions{Audience: s.Issuer, Now: now, ClientID: g.ClientID})
	if err != nil {
		return Issued{}, cid, err
	}
	if err := s.useNonce(ctx, g.RealmID, p.Nonce); err != nil {
		return Issued{}, cid, err
	}
	// 期限切れの記録を消して番号を空ける（失敗しても発行は続ける）。
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := tx.VCI().DeleteExpiredCredentials(ctx, g.RealmID, now, expiredBatch)
		return err
	}); err != nil && s.Log != nil {
		s.Log.WarnContext(ctx, "vci: delete expired credentials", "error", err)
	}
	jwk, err := publicJWK(p.Key)
	if err != nil {
		return Issued{}, cid, vciError(CodeInvalidProof, "jwk")
	}
	for range allocAttempts {
		idx, err := rand.Int(rand.Reader, big.NewInt(StatusListSize))
		if err != nil {
			return Issued{}, cid, err
		}
		var out Issued
		err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			out, err = s.issueOne(ctx, tx, g, c, cfg, jwk, p.Thumbprint, int(idx.Int64()), now, requestID)
			return err
		})
		if errors.Is(err, errs.Conflict) {
			continue // 番号が使われていた。選び直す
		}
		return out, cid, err
	}
	return Issued{}, cid, errs.WithCode(errs.KindUnavailable, codeStatusListExhausted, "no free status list index")
}

func publicJWK(k jose.JSONWebKey) (map[string]any, error) {
	b, err := k.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func (s *Service) issueOne(ctx context.Context, tx port.Tx, g Grant, c port.VCICredentialConfiguration, cfg Config, jwk map[string]any,
	jkt string, idx int, now time.Time, requestID string) (Issued, error) {
	u, err := tx.Users().Get(ctx, g.RealmID, g.UserID)
	if errors.Is(err, errs.NotFound) {
		return Issued{}, vciError(CodeCredentialRequestDenied, "user")
	}
	if err != nil {
		return Issued{}, err
	}
	if u.Status != port.UserActive {
		return Issued{}, vciError(CodeCredentialRequestDenied, "user_inactive")
	}
	if g.checkLineage {
		ss, _, err := s.Sessions.CheckLineage(ctx, tx, g.RealmID, g.SID, now)
		if errors.Is(err, session.ErrInvalid) || (err == nil && ss.PrincipalID != g.UserID) {
			return Issued{}, vciError(CodeCredentialRequestDenied, reasonSessionEnded)
		}
		if err != nil {
			return Issued{}, err
		}
	}
	values, err := s.values(ctx, tx, u, cfg)
	if err != nil {
		return Issued{}, err
	}
	exp := now.Add(cfg.Validity())
	rec := port.VCIIssuedCredential{ID: id.NewExternal(id.VCICredential), RealmID: g.RealmID, UserID: u.ID, ConfigurationID: c.ConfigurationID,
		StatusIndex: idx, HolderJKT: jkt, IssuedAt: now, ExpiresAt: exp}
	if err := tx.VCI().CreateCredential(ctx, rec); err != nil {
		return Issued{}, err
	}
	claims := map[string]any{"iss": s.Issuer, "vct": cfg.VCT, "iat": now.Unix(), "exp": exp.Unix(), "cnf": map[string]any{"jwk": jwk},
		"status": map[string]any{"status_list": map[string]any{"idx": idx, "uri": s.URL(StatusListPath)}}}
	var sd []string
	for _, cl := range cfg.Claims {
		v, ok := values[cl.Name]
		if !ok {
			continue
		}
		claims[cl.Name] = v
		if cl.SelectivelyDisclosable {
			sd = append(sd, cl.Name)
		}
	}
	b, err := sdjwt.Build(claims, sd)
	if err != nil {
		return Issued{}, err
	}
	payload, err := json.Marshal(b.Payload)
	if err != nil {
		return Issued{}, err
	}
	jwt, err := s.Keys.Sign(ctx, tx, g.RealmID, port.AlgES256, sdjwt.TypeVC, payload)
	if err != nil {
		return Issued{}, err
	}
	d := map[string]any{"configuration_id": c.ConfigurationID, "credential_id": rec.ID, "flow": g.Flow}
	if g.ClientID != "" {
		d["client_id"] = g.ClientID
	}
	if err := record(ctx, tx, s.Clock, "vci.credential_issued", audit.ResultSuccess, g.RealmID, audit.Actor{Type: "user", ID: u.PublicID},
		requestID, d); err != nil {
		return Issued{}, err
	}
	return Issued{Credential: sdjwt.Serialize(jwt, b.Disclosures), Record: rec}, nil
}

// values は定義のクレームの値を本人のデータから作る。必須の値が無ければ credential_request_denied。
func (s *Service) values(ctx context.Context, tx port.Tx, u port.User, cfg Config) (map[string]any, error) {
	out := map[string]any{}
	var email *port.UserEmail
	var attrs map[string]any
	for _, cl := range cfg.Claims {
		var v any
		var ok bool
		switch {
		case cl.Source == SourceUserID:
			v, ok = u.PublicID, true
		case cl.Source == SourceEmail || cl.Source == SourceEmailVerified:
			if email == nil {
				e, err := s.primaryEmail(ctx, tx, u)
				if err != nil {
					return nil, err
				}
				email = &e
			}
			if cl.Source == SourceEmailVerified {
				v, ok = email.VerifiedAt != nil, email.ID != ""
				break
			}
			if email.ID != "" && len(email.Ciphertext) > 0 {
				addr, err := s.Accounts.EmailAddress(ctx, tx, *email)
				if err != nil && !errors.Is(err, pii.ErrShredded) {
					return nil, err
				}
				v, ok = addr, err == nil && addr != ""
			}
		case strings.HasPrefix(cl.Source, SourceAttributePrefix):
			if s.Attributes == nil {
				break
			}
			if attrs == nil {
				var err error
				if attrs, err = s.Attributes.Values(ctx, tx, u, false); err != nil {
					return nil, err
				}
			}
			v, ok = attrs[strings.TrimPrefix(cl.Source, SourceAttributePrefix)]
		case cl.Source == SourceConst:
			x, err := sdjwt.DecodeJSON(cl.Value)
			if err != nil {
				return nil, err
			}
			v, ok = x, true
		}
		if !ok {
			if cl.Mandatory {
				return nil, vciError(CodeCredentialRequestDenied, reasonMissingMandatoryClaim)
			}
			continue
		}
		out[cl.Name] = v
	}
	return out, nil
}

func (s *Service) primaryEmail(ctx context.Context, tx port.Tx, u port.User) (port.UserEmail, error) {
	es, err := tx.Emails().ListByUser(ctx, u.RealmID, u.ID)
	if err != nil {
		return port.UserEmail{}, err
	}
	for _, e := range es {
		if e.IsPrimary {
			return e, nil
		}
	}
	return port.UserEmail{}, nil
}

// Revoke は発行した資格情報を失効させる（status list の値を 1 にする）。
func (s *Service) Revoke(ctx context.Context, tx port.Tx, c port.VCIIssuedCredential, actor audit.Actor, requestID string) error {
	if err := tx.VCI().RevokeCredential(ctx, c.RealmID, c.ID, s.Clock.Now()); err != nil {
		return err
	}
	if c.RevokedAt != nil {
		return nil
	}
	return record(ctx, tx, s.Clock, "vci.credential_revoked", audit.ResultSuccess, c.RealmID, actor, requestID,
		map[string]any{"credential_id": c.ID, "configuration_id": c.ConfigurationID})
}

// StatusList は realm の status list token（Token Status List 5、6）を返す。
func (s *Service) StatusList(ctx context.Context, tx port.Tx, realmID string) (string, error) {
	now := s.Clock.Now()
	idx, err := tx.VCI().ListRevokedIndexes(ctx, realmID, now)
	if err != nil {
		return "", err
	}
	lst, err := EncodeStatusList(idx)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{"sub": s.URL(StatusListPath), "iat": now.Unix(), "exp": now.Add(statusListExp).Unix(),
		"ttl": int(StatusListTTL / time.Second), "status_list": map[string]any{"bits": 1, "lst": lst}})
	if err != nil {
		return "", err
	}
	return s.Keys.Sign(ctx, tx, realmID, port.AlgES256, StatusListType, payload)
}

// EncodeStatusList は失効した番号（値 1）の status list（1 bit。番号 i はバイト i/8 の下から i%8 番目の bit）を ZLIB で圧縮し、
// base64url にする（Token Status List 4.1）。範囲の外の番号は誤り。
func EncodeStatusList(revoked []int) (string, error) {
	bits := make([]byte, StatusListSize/8)
	for _, i := range revoked {
		if i < 0 || i >= StatusListSize {
			return "", errors.New("vci: status index out of range")
		}
		bits[i/8] |= 1 << (i % 8)
	}
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(bits); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// IssuerMetadata は JWT VC Issuer Metadata（SD-JWT VC 5）。jwks は realm の ES256 の公開鍵（退役した鍵を含む）。
func (s *Service) IssuerMetadata(ctx context.Context, tx port.Tx, realmID string) (map[string]any, error) {
	b, err := s.Keys.JWKS(ctx, tx, realmID)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, err
	}
	keys := []map[string]any{}
	for _, k := range set.Keys {
		if k["kty"] == "EC" {
			keys = append(keys, k)
		}
	}
	return map[string]any{"issuer": s.Issuer, "jwks": map[string]any{"keys": keys}}, nil
}
