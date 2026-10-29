// Package file はファイルに鍵を置く KeyStore のアダプタ。形式と権限の条件は keyfile を参照。
package file

import (
	"context"
	"fmt"

	"github.com/imohiyoko/iam/adapters/keystore/keyfile"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterKeyStore("file", func(_ context.Context, cfg plugin.Config) (port.KeyStore, error) {
		if err := cfg.CheckOptions("path"); err != nil {
			return nil, err
		}
		path := cfg.Option("path", "")
		if path == "" {
			return nil, fmt.Errorf("keystore file: path is required")
		}
		return keyfile.Load(path)
	})
}
