package sdjwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// SD-JWT の組み立て（発行者の側。OpenID4VCI の発行。ADR 0119）。検証（Verify）と同じパッケージに置き、組み立てたものが
// 自前の検証に通ることをテストで確かめる。

// SaltSize は開示の salt のバイト数（RFC 9901 4.2.1 の 128 bit）。
const SaltSize = 16

// 足すデコイの数の範囲（RFC 9901 4.2.5。開示できるクレームの数を隠す）。
const (
	minDecoys = 1
	maxDecoys = 4
)

// Built は組み立てた SD-JWT の payload と開示。
type Built struct {
	// Payload は発行者が署名する payload（`_sd`・`_sd_alg` を含む）。
	Payload map[string]any
	// Disclosures は開示（base64url）。
	Disclosures []string
}

// Build は claims の最上位のうち sd の名前を選択的に開示できるクレームにし、payload と開示を返す。
// claims は書き換えない。sd の名前が claims に無い・予約の名前（Reserved、`_sd`、`_sd_alg`、`...`）なら誤り。
func Build(claims map[string]any, sd []string) (Built, error) {
	out := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		if k == "_sd" || k == "_sd_alg" || k == "..." {
			return Built{}, fmt.Errorf("sdjwt: reserved claim name %q", k)
		}
		out[k] = v
	}
	var digests []string
	var disclosures []string
	for _, name := range sd {
		v, ok := out[name]
		if !ok {
			return Built{}, fmt.Errorf("sdjwt: claim %q to disclose is missing", name)
		}
		if slices.Contains(Reserved, name) {
			return Built{}, fmt.Errorf("sdjwt: claim %q must not be selectively disclosed", name)
		}
		d, err := NewDisclosure(name, v)
		if err != nil {
			return Built{}, err
		}
		delete(out, name)
		disclosures = append(disclosures, d)
		digests = append(digests, Digest(d))
	}
	if len(sd) > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(maxDecoys-minDecoys+1))
		if err != nil {
			return Built{}, err
		}
		for range int(n.Int64()) + minDecoys {
			d, err := randomSalt()
			if err != nil {
				return Built{}, err
			}
			digests = append(digests, Digest(d))
		}
		// 並べ替えて、どのダイジェストがどのクレームかを順から読めないようにする（RFC 9901 4.2.4.1）。
		slices.Sort(digests)
		list := make([]any, len(digests))
		for i, d := range digests {
			list[i] = d
		}
		out["_sd"] = list
	}
	out["_sd_alg"] = "sha-256"
	return Built{Payload: out, Disclosures: disclosures}, nil
}

// NewDisclosure はオブジェクトのクレームの開示（`[salt, 名前, 値]` の JSON の base64url）を作る。
func NewDisclosure(name string, value any) (string, error) {
	if name == "" || name == "_sd" || name == "..." {
		return "", errors.New("sdjwt: invalid disclosure name")
	}
	salt, err := randomSalt()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomSalt() (string, error) {
	b := make([]byte, SaltSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Serialize は発行者の JWT と開示を SD-JWT（`<JWT>~<開示>~…~`。key binding の JWT なし）にする。
func Serialize(issuerJWT string, disclosures []string) string {
	var b strings.Builder
	b.WriteString(issuerJWT)
	b.WriteByte('~')
	for _, d := range disclosures {
		b.WriteString(d)
		b.WriteByte('~')
	}
	return b.String()
}
