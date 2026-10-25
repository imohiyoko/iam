// Package env は環境変数から鍵を読む KeyStore のアダプタ。
//
// 環境変数 IAM_KEYS（名前は設定の variable で変えられる）に、file アダプタと同じ形式の JSON を入れる。
package env

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/imohiyoko/iam/adapters/keystore/file"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterKeyStore("env", func(_ context.Context, cfg plugin.Config) (port.KeyStore, error) {
		return Load(cfg.Option("variable", "IAM_KEYS"))
	})
}

// Load は環境変数 name から鍵を読み込む。
func Load(name string) (*file.Store, error) {
	v := os.Getenv(name)
	if v == "" {
		return nil, fmt.Errorf("keystore env: %s is not set", name)
	}
	var k file.Keys
	if err := json.Unmarshal([]byte(v), &k); err != nil {
		return nil, fmt.Errorf("keystore env: %s: %w", name, err)
	}
	return file.FromKeys(k)
}
