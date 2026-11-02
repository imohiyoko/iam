package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/port"
)

// passkey の attestation と認証器のポリシー（フィーチャー passkey_attestation、design.md 9.4、ADR 0096）。

// apiPasskeyPolicy は API の認証器のポリシー（公開 API と管理 API で同じ形）。
type apiPasskeyPolicy interface {
	publicapi.PasskeyPolicy | adminapi.PasskeyPolicy
}

// passkeyPolicyIn は API のポリシーを読む（形は attestation.Policy と同じ JSON）。nil・空なら nil。
func passkeyPolicyIn[T apiPasskeyPolicy](p *T) *attestation.Policy {
	if p == nil {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	var out attestation.Policy
	if json.Unmarshal(b, &out) != nil || out.Empty() {
		return nil
	}
	return &out
}

// passkeyPolicyOut はポリシーを API の形にする。空なら nil。
func passkeyPolicyOut[T apiPasskeyPolicy](p *attestation.Policy) *T {
	if p.Empty() {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	var out T
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return &out
}

// userPasskey は管理 API の passkey（AAGUID と認証器の名前を付ける）。passkey は authn_credentials の方式 passkey（ADR 0106）。
func (a *App) userPasskey(ctx context.Context, tx port.Tx, c port.Credential) (adminapi.UserPasskey, error) {
	_, p, err := passkeym.Read(ctx, tx, a.pii, c)
	if err != nil {
		return adminapi.UserPasskey{}, err
	}
	out := adminapi.UserPasskey{Id: c.PublicID, Name: p.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt, Attested: p.Attested}
	if s := attestation.FormatAAGUID(p.AAGUID); s != "" {
		u := uuid.MustParse(s)
		out.Aaguid = &u
	}
	if p.AttestationFormat != "" {
		out.AttestationFormat = &p.AttestationFormat
	}
	if n := a.root.metadata.Name(p.AAGUID); n != "" {
		out.AuthenticatorName = &n
	}
	return out, nil
}

// metadataRefresh は MDS の BLOB を読み直す間隔（既定 24 時間）。
func metadataRefresh(cfg config.Config) time.Duration {
	if d := cfg.Passkey.Attestation.MetadataRefresh.D(); d > 0 {
		return d
	}
	return 24 * time.Hour
}

// newMetadata は設定のルートと信頼の起点を読み、認証器のメタデータを作る。fido_mds のアダプタがあれば最初の BLOB を読む
// （読めなければ警告して、設定した信頼の起点だけで動く。読み直しは Serve のバックグラウンド）。
func newMetadata(ctx context.Context, cfg config.Config, d Deps) (*attestation.Metadata, error) {
	ac := cfg.Passkey.Attestation
	mc := attestation.Config{Clock: d.Clock, Log: d.Logger}
	if ac.MetadataRootFile != "" {
		certs, err := readCerts(ac.MetadataRootFile)
		if err != nil {
			return nil, fmt.Errorf("passkey.attestation.metadata_root_file: %w", err)
		}
		if len(certs) != 1 {
			return nil, errors.New("passkey.attestation.metadata_root_file: want exactly one certificate")
		}
		mc.Root = certs[0].Raw
	}
	for i, t := range ac.TrustedAuthenticators {
		tr := attestation.Trusted{AAGUID: uuid.MustParse(t.AAGUID), Name: t.Name}
		for _, f := range t.RootFiles {
			certs, err := readCerts(f)
			if err != nil {
				return nil, fmt.Errorf("passkey.attestation.trusted_authenticators[%d]: %w", i, err)
			}
			tr.Roots = append(tr.Roots, certs...)
		}
		mc.Trusted = append(mc.Trusted, tr)
	}
	m := attestation.New(mc)
	if d.FIDOMDS == nil {
		d.Logger.Warn("passkey attestation: fido_mds is not configured; only trusted_authenticators are used as trust anchors")
		return m, nil
	}
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := m.Refresh(fctx, d.FIDOMDS); err != nil {
		d.Logger.Warn("passkey attestation: could not load the metadata blob; retrying in the background", "error", err)
	}
	return m, nil
}

// readCerts は PEM の証明書を読む。
func readCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- 運用者が設定したパス
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no PEM certificate", path)
	}
	return out, nil
}
