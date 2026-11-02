// Package file はホスト先が置いた FIDO Metadata Service（MDS3）の BLOB をファイルから読む FIDOMetadataSource
// （フィーチャー passkey_attestation、ADR 0096）。ネットワークに出られない構成では、ホスト先が別の手段で BLOB を取って置く。
// 署名はコアが確かめる。
package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterFIDOMDS("file", func(_ context.Context, cfg plugin.Config) (port.FIDOMetadataSource, error) {
		if err := cfg.CheckOptions("path"); err != nil {
			return nil, err
		}
		p := cfg.Option("path", "")
		if p == "" {
			return nil, errors.New("fido_mds file: path is required")
		}
		return Source{Path: p}, nil
	})
}

// Source はファイルの BLOB。
type Source struct{ Path string }

// Fetch はファイルを読む（読むたびに開き直すので、ホスト先が置き換えれば次の読み込みで反映される）。
func (s Source) Fetch(context.Context) ([]byte, error) {
	f, err := os.Open(s.Path) // #nosec G304 -- 運用者が設定したパス
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, attestation.MaxBlobBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > attestation.MaxBlobBytes {
		return nil, fmt.Errorf("fido_mds file: %s is too large", s.Path)
	}
	return b, nil
}
