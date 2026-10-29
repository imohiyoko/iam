// Package env は環境変数から鍵を読む KeyStore のアダプタ。
//
// 環境変数 IAM_KEYS（名前は設定の variable で変えられる）に、file アダプタと同じ形式（keyfile）の JSON を入れる。
// 読み込んだ後は環境変数から消す。
package env

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/imohiyoko/iam/adapters/keystore/keyfile"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterKeyStore("env", func(_ context.Context, cfg plugin.Config) (port.KeyStore, error) {
		if err := cfg.CheckOptions("variable"); err != nil {
			return nil, err
		}
		return Load(cfg.Option("variable", "IAM_KEYS"))
	})
}

// Load は環境変数 name から鍵を読み込む。
func Load(name string) (*keyfile.Store, error) {
	v := os.Getenv(name)
	if v == "" {
		return nil, fmt.Errorf("keystore env: %s is not set", name)
	}
	// 子プロセスに引き継がれないよう、読んだら消す。
	if err := os.Unsetenv(name); err != nil {
		return nil, err
	}
	var k keyfile.Keys
	if err := json.Unmarshal([]byte(v), &k); err != nil {
		return nil, fmt.Errorf("keystore env: %s: %w", name, err)
	}
	return keyfile.FromKeys(k)
}
