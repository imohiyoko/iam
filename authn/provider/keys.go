// Package provider は OIDC Provider のコア：連携先、ID トークンの署名鍵、認可コード、トークン（design.md 5.1、5.5、9.3）。
//
// HTTP とプロトコルの解釈（zitadel/oidc）は server が受け持ち、ここは状態と判断を持つ。
package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// ID トークンの署名鍵（9.3、ADR 0040、0041）。realm ごとに ES256 と ML-DSA-65 の鍵を1つずつ使い、JWKS に並べる。
// フィーチャー rs256 が動いていれば RS256 の鍵も足す（ADR 0122）。
// 秘密鍵はマスター鍵から導いた鍵で暗号化して Storage に置く。退役した鍵は RetiredKeyTTL の間 JWKS に残す
// （発行済みの ID トークンを検証できるように）。

// Algs は署名に使うアルゴリズム（JWKS に並べる順）。フィーチャー rs256 の RS256 は含まない（Keys.Algs で足す）。
var Algs = []string{port.AlgMLDSA65, port.AlgES256}

// RS256Feature は RS256 の署名のフィーチャー（既定オフ。ADR 0122）。
var RS256Feature = feature.Feature{Name: feature.RS256, DataVersion: 1}

// RSAKeyBits は RS256 の鍵の大きさ。P-256 と同じ 128 bit の強さ（NIST SP 800-57）にし、2030 年より後も使える大きさにする。
const RSAKeyBits = 3072

// AlgMLDSA65 は JOSE のアルゴリズム名（RFC 9964）。
const AlgMLDSA65 jose.SignatureAlgorithm = port.AlgMLDSA65

// ErrUnknownKey は JWS の kid の鍵が無いこと。
var ErrUnknownKey = errs.WithCode(errs.KindInvalid, "unknown_key", "unknown signing key")

// Keys は署名鍵を管理する。
type Keys struct {
	Crypter *pii.Crypter
	Clock   clock.Clock
	// RetiredKeyTTL は退役した鍵を JWKS に残す期間（ID トークンの寿命より長くする）。
	RetiredKeyTTL time.Duration
	// RS256 はフィーチャー rs256 が動いているか。動いていれば RS256 の鍵を用意し、連携先が選べる（ADR 0122）。
	RS256 bool
}

// Algs は realm で用意する署名のアルゴリズム（JWKS に並べる順。Discovery の id_token_signing_alg_values_supported）。
func (k *Keys) Algs() []string {
	if k.RS256 {
		return append(slices.Clone(Algs), port.AlgRS256)
	}
	return Algs
}

// Advertised は Discovery の id_token_signing_alg_values_supported に載せるアルゴリズム。フィーチャー rs256 を無効にしている
// 間（片付けで RS256 の鍵が退役するまで）は、RS256 の連携先にまだ RS256 で署名するので RS256 も載せる（ADR 0122）。
func (k *Keys) Advertised(ctx context.Context, tx port.Tx, realmID string) ([]string, error) {
	if k.RS256 {
		return k.Algs(), nil
	}
	ok, err := k.hasActive(ctx, tx, realmID, port.AlgRS256)
	if err != nil || !ok {
		return Algs, err
	}
	return append(slices.Clone(Algs), port.AlgRS256), nil
}

func sealPurpose(kid string) string { return "signing_key\x00" + kid }

// Ensure は realm に、アルゴリズムごとの使っている鍵が無ければ作る。
func (k *Keys) Ensure(ctx context.Context, tx port.Tx, realmID string) error {
	ks, err := tx.SigningKeys().List(ctx, realmID)
	if err != nil {
		return err
	}
	for _, alg := range k.Algs() {
		if !slices.ContainsFunc(ks, func(x port.SigningKey) bool { return x.Alg == alg && x.RetiredAt == nil }) {
			if _, err := k.create(ctx, tx, realmID, alg); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *Keys) create(ctx context.Context, tx port.Tx, realmID, alg string) (port.SigningKey, error) {
	var pub, priv []byte
	switch alg {
	case port.AlgES256:
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return port.SigningKey{}, err
		}
		if pub, err = x509.MarshalPKIXPublicKey(&sk.PublicKey); err != nil {
			return port.SigningKey{}, err
		}
		if priv, err = x509.MarshalPKCS8PrivateKey(sk); err != nil {
			return port.SigningKey{}, err
		}
	case port.AlgMLDSA65:
		sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return port.SigningKey{}, err
		}
		pub, priv = sk.PublicKey().Bytes(), sk.Bytes()
	case port.AlgRS256:
		sk, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
		if err != nil {
			return port.SigningKey{}, err
		}
		if pub, err = x509.MarshalPKIXPublicKey(&sk.PublicKey); err != nil {
			return port.SigningKey{}, err
		}
		if priv, err = x509.MarshalPKCS8PrivateKey(sk); err != nil {
			return port.SigningKey{}, err
		}
	default:
		return port.SigningKey{}, errs.New(errs.KindInvalid, "unsupported alg %s", alg)
	}
	key := port.SigningKey{ID: id.NewExternal(id.SigningKey), RealmID: realmID, Alg: alg, Public: pub, CreatedAt: k.Clock.Now()}
	sealed, err := k.Crypter.Seal(ctx, sealPurpose(key.ID), priv)
	if err != nil {
		return port.SigningKey{}, err
	}
	key.Private = sealed
	return key, tx.SigningKeys().Create(ctx, key)
}

// Rotate は alg の鍵を新しくし、今の鍵を退役させる。古い鍵は RetiredKeyTTL の間 JWKS に残る。
func (k *Keys) Rotate(ctx context.Context, tx port.Tx, realmID, alg string) (port.SigningKey, error) {
	ks, err := tx.SigningKeys().List(ctx, realmID)
	if err != nil {
		return port.SigningKey{}, err
	}
	now := k.Clock.Now()
	for _, x := range ks {
		if x.Alg == alg && x.RetiredAt == nil {
			if err := tx.SigningKeys().Retire(ctx, realmID, x.ID, now); err != nil {
				return port.SigningKey{}, err
			}
		}
	}
	return k.create(ctx, tx, realmID, alg)
}

// published は JWKS に載せる鍵（使っている鍵と、退役から RetiredKeyTTL の内の鍵）。期限の過ぎた鍵は消す。
func (k *Keys) published(ctx context.Context, tx port.Tx, realmID string) ([]port.SigningKey, error) {
	ks, err := tx.SigningKeys().List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	now := k.Clock.Now()
	out := ks[:0]
	for _, x := range ks {
		if x.RetiredAt != nil && !now.Before(x.RetiredAt.Add(k.RetiredKeyTTL)) {
			if err := tx.SigningKeys().Delete(ctx, realmID, x.ID); err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, x)
	}
	return out, nil
}

// JWKS は realm の公開鍵の集合（RFC 7517）を返す。AKP（ML-DSA-65）と EC（ES256）、あれば RSA（RS256）を並べる。
func (k *Keys) JWKS(ctx context.Context, tx port.Tx, realmID string) ([]byte, error) {
	ks, err := k.published(ctx, tx, realmID)
	if err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	for _, x := range ks {
		pub, err := publicKey(x)
		if err != nil {
			return nil, err
		}
		j, err := jwk.Import[jwk.Key](pub)
		if err != nil {
			return nil, err
		}
		if err := j.Set(jwk.KeyIDKey, x.ID); err != nil {
			return nil, err
		}
		if err := j.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return nil, err
		}
		switch x.Alg {
		case port.AlgES256:
			if err := j.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
				return nil, err
			}
		case port.AlgRS256:
			if err := j.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
				return nil, err
			}
		}
		if err := set.AddKey(j); err != nil {
			return nil, err
		}
	}
	return json.Marshal(set)
}

func publicKey(x port.SigningKey) (any, error) {
	switch x.Alg {
	case port.AlgES256, port.AlgRS256:
		return x509.ParsePKIXPublicKey(x.Public)
	case port.AlgMLDSA65:
		return mldsa.NewPublicKey(mldsa.MLDSA65(), x.Public)
	}
	return nil, errs.New(errs.KindInternal, "unsupported alg %s", x.Alg)
}

// hasActive は realm に alg の使っている鍵があるか。
func (k *Keys) hasActive(ctx context.Context, tx port.Tx, realmID, alg string) (bool, error) {
	ks, err := tx.SigningKeys().List(ctx, realmID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(ks, func(x port.SigningKey) bool { return x.Alg == alg && x.RetiredAt == nil }), nil
}

// active は alg の使っている鍵を返す。無ければ作る。
func (k *Keys) active(ctx context.Context, tx port.Tx, realmID, alg string) (port.SigningKey, error) {
	ks, err := tx.SigningKeys().List(ctx, realmID)
	if err != nil {
		return port.SigningKey{}, err
	}
	for i := len(ks) - 1; i >= 0; i-- {
		if ks[i].Alg == alg && ks[i].RetiredAt == nil {
			return ks[i], nil
		}
	}
	return k.create(ctx, tx, realmID, alg)
}

// Published は公開している鍵（使っている鍵と、退役から RetiredKeyTTL の内の鍵）を返す。期限の過ぎた鍵は消す。
func (k *Keys) Published(ctx context.Context, tx port.Tx, realmID string) ([]port.SigningKey, error) {
	return k.published(ctx, tx, realmID)
}

// ECSigner は ES256 の使っている鍵（無ければ作る）と、その秘密鍵を返す（JWS 以外の署名。WS-Federation の XML 署名。ADR 0110）。
func (k *Keys) ECSigner(ctx context.Context, tx port.Tx, realmID string) (port.SigningKey, *ecdsa.PrivateKey, error) {
	key, err := k.active(ctx, tx, realmID, port.AlgES256)
	if err != nil {
		return port.SigningKey{}, nil, err
	}
	raw, err := k.Crypter.Open(ctx, sealPurpose(key.ID), key.Private)
	if err != nil {
		return port.SigningKey{}, nil, err
	}
	p, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return port.SigningKey{}, nil, err
	}
	sk, ok := p.(*ecdsa.PrivateKey)
	if !ok {
		return port.SigningKey{}, nil, errs.New(errs.KindInternal, "signing key %s is not ECDSA", key.ID)
	}
	return key, sk, nil
}

// Sign は claims（JSON）を alg の使っている鍵で署名した JWS（compact）を返す。ヘッダーに kid と typ を付ける（ADR 0040）。
func (k *Keys) Sign(ctx context.Context, tx port.Tx, realmID, alg, typ string, claims []byte) (string, error) {
	if alg == port.AlgRS256 && !k.RS256 {
		// フィーチャー rs256 が止まっていれば RS256 の鍵を新しく作らない。片付けで鍵が退役した後は、連携先の選択も
		// ES256 に戻っている（片付けは連携先を先に戻す）ので、片付けの前に読んだ連携先の署名も ES256 にする。
		ok, err := k.hasActive(ctx, tx, realmID, port.AlgRS256)
		if err != nil {
			return "", err
		}
		if !ok {
			alg = port.AlgES256
		}
	}
	key, err := k.active(ctx, tx, realmID, alg)
	if err != nil {
		return "", err
	}
	raw, err := k.Crypter.Open(ctx, sealPurpose(key.ID), key.Private)
	if err != nil {
		return "", err
	}
	var sk jose.SigningKey
	switch alg {
	case port.AlgES256:
		p, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return "", err
		}
		sk = jose.SigningKey{Algorithm: jose.ES256, Key: p}
	case port.AlgMLDSA65:
		p, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), raw)
		if err != nil {
			return "", err
		}
		sk = jose.SigningKey{Algorithm: AlgMLDSA65, Key: mldsaSigner{p}}
	case port.AlgRS256:
		// フィーチャー rs256 を無効にしている間も、片付けで連携先の選択が ES256 に戻るまでは RS256 で署名し続ける
		// （黙って ES256 にすると RP の検証が通らなくなるため。ADR 0122）。鍵が退役した後は上で ES256 にしている。
		p, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return "", err
		}
		rk, ok := p.(*rsa.PrivateKey)
		if !ok {
			return "", errs.New(errs.KindInternal, "signing key %s is not RSA", key.ID)
		}
		sk = jose.SigningKey{Algorithm: jose.RS256, Key: rk}
	default:
		return "", errs.New(errs.KindInvalid, "unsupported alg %s", alg)
	}
	signer, err := jose.NewSigner(sk, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), key.ID))
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Verify は realm の鍵（JWKS に載っているもの）で JWS を検証し、ペイロードを返す。
func (k *Keys) Verify(ctx context.Context, tx port.Tx, realmID, compact string) ([]byte, error) {
	return k.VerifyType(ctx, tx, realmID, compact, "")
}

// VerifyType は Verify に加えて、ヘッダーの typ が typ であることを確かめる（空なら確かめない）。同じ鍵で署名する
// ID トークン（JWT）と Logout Token（logout+jwt）を取り違えないように使う。
func (k *Keys) VerifyType(ctx context.Context, tx port.Tx, realmID, compact, typ string) ([]byte, error) {
	sig, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256, AlgMLDSA65, jose.RS256})
	if err != nil {
		return nil, errs.WithCode(errs.KindInvalid, "invalid_token", "malformed jws")
	}
	if len(sig.Signatures) != 1 {
		return nil, errs.WithCode(errs.KindInvalid, "invalid_token", "unexpected signatures")
	}
	h := sig.Signatures[0].Header
	if got, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "" && got != typ {
		return nil, errs.WithCode(errs.KindInvalid, "invalid_token", "unexpected typ")
	}
	ks, err := k.published(ctx, tx, realmID)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(ks, func(x port.SigningKey) bool { return x.ID == h.KeyID && x.Alg == h.Algorithm })
	if i < 0 {
		return nil, ErrUnknownKey
	}
	pub, err := publicKey(ks[i])
	if err != nil {
		return nil, err
	}
	var vk any = pub
	if p, ok := pub.(*mldsa.PublicKey); ok {
		vk = mldsaVerifier{p}
	}
	payload, err := sig.Verify(vk)
	if err != nil {
		return nil, errs.WithCode(errs.KindInvalid, "invalid_token", "bad signature")
	}
	return payload, nil
}

// mldsaSigner は go-jose の OpaqueSigner に crypto/mldsa を差し込む（ADR 0040）。
type mldsaSigner struct{ key *mldsa.PrivateKey }

// Public は nil を返す（go-jose の JSONWebKey は ML-DSA の公開鍵を扱えない。kid は SignerOptions で付ける）。
func (s mldsaSigner) Public() *jose.JSONWebKey        { return nil }
func (s mldsaSigner) Algs() []jose.SignatureAlgorithm { return []jose.SignatureAlgorithm{AlgMLDSA65} }

func (s mldsaSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != AlgMLDSA65 {
		return nil, jose.ErrUnsupportedAlgorithm
	}
	// JOSE の ML-DSA は純粋な ML-DSA（事前ハッシュなし、空のコンテキスト）。
	return s.key.Sign(nil, payload, &mldsa.Options{})
}

type mldsaVerifier struct{ pub *mldsa.PublicKey }

func (v mldsaVerifier) VerifyPayload(payload, sig []byte, alg jose.SignatureAlgorithm) error {
	if alg != AlgMLDSA65 {
		return jose.ErrUnsupportedAlgorithm
	}
	if err := mldsa.Verify(v.pub, payload, sig, &mldsa.Options{}); err != nil {
		return errors.New("ml-dsa: invalid signature")
	}
	return nil
}
