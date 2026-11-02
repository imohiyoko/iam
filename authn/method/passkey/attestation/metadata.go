package attestation

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// Trusted は MDS に無い認証器（社内で配る鍵など）の信頼の起点。設定ファイルの passkey.attestation.trusted_authenticators。
type Trusted struct {
	AAGUID uuid.UUID
	Name   string
	Roots  []*x509.Certificate
}

// Config はメタデータの設定。
type Config struct {
	// Root は BLOB の署名を確かめるルート証明書（DER）。nil なら FIDO Alliance の本番のルート（GlobalSign Root R46）。
	Root []byte
	// Trusted は設定した信頼の起点。MDS の項目より先に引く（同じ AAGUID なら名前と信頼の起点はこちらを使い、
	// status report は MDS のものを使う）。
	Trusted []Trusted
	Clock   clock.Clock
	Log     *slog.Logger
}

// Metadata は認証器のメタデータ。BLOB は Load で差し替え、引くのはメモリの写しだけ（ホットパスで外部に問い合わせない）。
type Metadata struct {
	root    string
	trusted map[uuid.UUID]Trusted
	clock   clock.Clock
	log     *slog.Logger
	snap    atomic.Pointer[snapshot]
}

type snapshot struct {
	number     int
	nextUpdate time.Time
	loadedAt   time.Time
	byAAGUID   map[uuid.UUID]*metadata.Entry
	byKeyID    map[string]*metadata.Entry
}

// New は BLOB を読む前の（空の）メタデータを作る。
func New(cfg Config) *Metadata {
	m := &Metadata{root: metadata.ProductionMDSRoot, trusted: map[uuid.UUID]Trusted{}, clock: cfg.Clock, log: cfg.Log}
	if cfg.Root != nil {
		m.root = base64.StdEncoding.EncodeToString(cfg.Root)
	}
	if m.clock == nil {
		m.clock = clock.System{}
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	for _, t := range cfg.Trusted {
		m.trusted[t.AAGUID] = t
	}
	return m
}

// ErrStale は、読んだ BLOB の番号が今のものより古いこと（巻き戻しの拒否）。
var ErrStale = errors.New("attestation: metadata blob is older than the loaded one")

// MaxBlobBytes は BLOB の大きさの上限（本番の BLOB は数 MB）。
const MaxBlobBytes = 64 << 20

// Load は BLOB（MDS3 の JWT）の署名をルートで確かめ、読んだものに差し替える。番号が今のものより小さければ ErrStale、
// 同じなら何もしない。読めない項目は飛ばす（本番の BLOB には、ライブラリの知らない形の項目がある）。
func (m *Metadata) Load(blob []byte) error {
	if len(blob) > MaxBlobBytes {
		return fmt.Errorf("attestation: metadata blob too large (%d bytes)", len(blob))
	}
	dec, err := metadata.NewDecoder(metadata.WithRootCertificate(m.root), metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return err
	}
	payload, err := dec.DecodeBytes([]byte(strings.TrimSpace(string(blob))))
	if err != nil {
		return fmt.Errorf("attestation: metadata blob: %w", err)
	}
	md, err := dec.Parse(payload)
	if err != nil {
		return fmt.Errorf("attestation: metadata blob: %w", err)
	}
	cur := m.snap.Load()
	switch {
	case cur != nil && md.Parsed.Number < cur.number:
		return fmt.Errorf("%w (%d < %d)", ErrStale, md.Parsed.Number, cur.number)
	case cur != nil && md.Parsed.Number == cur.number:
		return nil
	}
	s := &snapshot{number: md.Parsed.Number, nextUpdate: md.Parsed.NextUpdate, loadedAt: m.clock.Now(),
		byAAGUID: map[uuid.UUID]*metadata.Entry{}, byKeyID: map[string]*metadata.Entry{}}
	for i := range md.Parsed.Entries {
		e := &md.Parsed.Entries[i]
		if e.AaGUID != uuid.Nil {
			s.byAAGUID[e.AaGUID] = e
		}
		for _, k := range e.AttestationCertificateKeyIdentifiers {
			s.byKeyID[strings.ToLower(k)] = e
		}
	}
	// 他の読み込みと競っても、番号の大きい方だけを残す。
	for {
		cur := m.snap.Load()
		if cur != nil && cur.number >= s.number {
			return nil
		}
		if m.snap.CompareAndSwap(cur, s) {
			break
		}
	}
	m.log.Info("passkey attestation metadata loaded", "number", s.number, "entries", len(s.byAAGUID), "unparsed", len(md.Unparsed),
		"next_update", s.nextUpdate.Format(time.DateOnly))
	if s.nextUpdate.Before(m.clock.Now()) {
		m.log.Warn("passkey attestation metadata is past its next update", "next_update", s.nextUpdate.Format(time.DateOnly))
	}
	return nil
}

// Refresh は src から BLOB を取って読む。
func (m *Metadata) Refresh(ctx context.Context, src port.FIDOMetadataSource) error {
	b, err := src.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("attestation: fetch metadata: %w", err)
	}
	if err := m.Load(b); err != nil && !errors.Is(err, ErrStale) {
		return err
	}
	return nil
}

// Run は interval ごとに Refresh する（ctx が終わるまで）。失敗は警告に残し、読んだ写しを使い続ける。
func (m *Metadata) Run(ctx context.Context, src port.FIDOMetadataSource, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Refresh(ctx, src); err != nil && ctx.Err() == nil {
				m.log.WarnContext(ctx, "could not refresh passkey attestation metadata", "error", err)
			}
		}
	}
}

// Status は読んだ BLOB の番号・次の更新日・項目の数。読んでいなければ ok が false。
func (m *Metadata) Status() (number int, nextUpdate time.Time, entries int, ok bool) {
	s := m.snap.Load()
	if s == nil {
		return 0, time.Time{}, 0, false
	}
	return s.number, s.nextUpdate, len(s.byAAGUID), true
}

func (m *Metadata) lookup(aaguid uuid.UUID) *metadata.Entry {
	if s := m.snap.Load(); s != nil {
		return s.byAAGUID[aaguid]
	}
	return nil
}

// Name は認証器の名前（設定した名前、MDS の description の順）。分からなければ空。
func (m *Metadata) Name(aaguid []byte) string {
	if m == nil {
		return ""
	}
	u, err := uuid.FromBytes(aaguid)
	if err != nil || len(aaguid) != 16 {
		return ""
	}
	if t, ok := m.trusted[u]; ok && t.Name != "" {
		return t.Name
	}
	if e := m.lookup(u); e != nil {
		return e.MetadataStatement.Description
	}
	return ""
}

// entry は attestation の検証に使う項目。設定した信頼の起点があれば、MDS の項目の信頼の起点に足す。
func (m *Metadata) entry(aaguid uuid.UUID) *metadata.Entry {
	e := m.lookup(aaguid)
	t, ok := m.trusted[aaguid]
	if !ok {
		return e
	}
	var out metadata.Entry
	if e != nil {
		out = *e
	} else {
		out.AaGUID = aaguid
		out.MetadataStatement.AaGUID = aaguid
		out.MetadataStatement.AttestationTypes = metadata.AuthenticatorAttestationTypes{metadata.BasicFull, metadata.AttCA, metadata.AnonCA}
	}
	out.MetadataStatement.AttestationRootCertificates = append(append([]*x509.Certificate{}, out.MetadataStatement.AttestationRootCertificates...), t.Roots...)
	return &out
}

// Result は登録の attestation を信頼の起点に照らした結果。
type Result struct {
	// Format は attestation の形式（none、packed、tpm、android-key、apple、fido-u2f など）。
	Format string
	// Type は attestation の種類（basic_full、self、attca、anonca、none など）。
	Type string
	// Attested は証明書の連なりを信頼の起点（MDS の項目か設定）まで確かめたか。
	Attested bool
	// Detail は attested でない理由（監査ログ用）。
	Detail string
}

// Verify は登録の attestation（形式ごとの署名の検証はライブラリが済ませたもの）の証明書の連なりを、信頼の起点に照らす。
// none・self・ECDAA・compound は attested にしない。
func (m *Metadata) Verify(ctx context.Context, obj *protocol.AttestationObject) Result {
	r := Result{Format: obj.Format, Type: obj.Type}
	x5c, _ := obj.AttStatement["x5c"].([]any)
	switch {
	case obj.Format == string(protocol.AttestationFormatNone):
		r.Detail = "no attestation"
		return r
	case len(x5c) == 0:
		r.Detail = "no certificate chain (" + obj.Type + ")"
		return r
	}
	var aaguid uuid.UUID
	if b := obj.AuthData.AttData.AAGUID; len(b) == 16 {
		aaguid = uuid.Must(uuid.FromBytes(b))
	}
	if e := protocol.ValidateMetadataWithAuthenticatorData(ctx, provider{m}, aaguid, obj.Type, obj.Format, x5c, &obj.AuthData); e != nil {
		r.Detail = strings.TrimSpace(e.Details + " " + e.DevInfo)
		return r
	}
	r.Attested = true
	return r
}

// provider は go-webauthn の metadata.ExtendedProvider。項目が必須で、信頼の起点と attestation の種類を確かめる。
// 状態（status report）はポリシーの判定（Evaluate）で見るので、ここでは見ない。
type provider struct{ m *Metadata }

var _ metadata.ExtendedProvider = provider{}

func (p provider) GetEntry(_ context.Context, aaguid uuid.UUID) (*metadata.Entry, error) {
	return p.m.entry(aaguid), nil
}

func (p provider) GetEntryByKeyIdentifier(_ context.Context, keyID string) (*metadata.Entry, error) {
	if s := p.m.snap.Load(); s != nil {
		return s.byKeyID[strings.ToLower(keyID)], nil
	}
	return nil, nil
}

func (provider) GetValidateEntry(context.Context) bool                                { return true }
func (provider) GetValidateEntryPermitZeroAAGUID(context.Context) bool                { return false }
func (provider) GetValidateEntryKeyIdentifier(context.Context) bool                   { return true }
func (provider) GetValidateTrustAnchor(context.Context) bool                          { return true }
func (provider) GetValidateStatus(context.Context) bool                               { return false }
func (provider) GetValidateAttestationTypes(context.Context) bool                     { return true }
func (provider) GetValidateStatusCertificateScope(context.Context) bool               { return false }
func (provider) GetValidateAAGUID(context.Context) bool                               { return false }
func (provider) GetValidateAttestationFormats(context.Context) bool                   { return false }
func (provider) GetValidateAlgorithms(context.Context) bool                           { return false }
func (provider) GetValidateBackupEligibility(context.Context) bool                    { return false }
func (provider) GetValidateExtensions(context.Context) bool                           { return false }
func (provider) GetValidateUserVerification(context.Context) bool                     { return false }
func (provider) ValidateStatusReports(context.Context, []metadata.StatusReport) error { return nil }
