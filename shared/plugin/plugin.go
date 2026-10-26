// Package plugin はアダプタの自己登録を受け付ける（design.md 11.11）。
//
// アダプタのパッケージは init で Register* を呼ぶ。バイナリに含めるアダプタは
// cmd（または `iam build` が生成する main）が import するかで決まり、設定ファイルで名前を選ぶ。
package plugin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"sync"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// Config はアダプタを作るときに渡す共通の値。
type Config struct {
	Clock   clock.Clock
	Logger  *slog.Logger
	Stdout  io.Writer
	Options map[string]string // 設定ファイルのアダプタごとの項目
	// Dev は開発ビルドかどうか。開発専用のアダプタはこれが false なら作成を拒否する。
	Dev bool
}

// CheckOptions は allowed 以外の項目があればエラーにする（設定の書き間違いを黙って無視しない）。
func (c Config) CheckOptions(allowed ...string) error {
	for k := range c.Options {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("plugin: unknown option %q (allowed: %v)", k, allowed)
		}
	}
	return nil
}

// Option は Options の値を返す。無ければ def。
func (c Config) Option(key, def string) string {
	if v, ok := c.Options[key]; ok && v != "" {
		return v
	}
	return def
}

type (
	StorageFactory   func(context.Context, Config) (port.Storage, error)
	EphemeralFactory func(context.Context, Config) (port.EphemeralStore, error)
	NotifierFactory  func(context.Context, Config) (port.Notifier, error)
	KeyStoreFactory  func(context.Context, Config) (port.KeyStore, error)
	EventSinkFactory func(context.Context, Config) (port.EventSink, error)
	// BreachCheckFactory は漏洩済みパスワードの確認（フィーチャー password で使う）。
	BreachCheckFactory func(context.Context, Config) (port.BreachChecker, error)
)

// Kind はアダプタの種類。
type Kind string

const (
	KindStorage     Kind = "storage"
	KindEphemeral   Kind = "ephemeral"
	KindNotifier    Kind = "notifier"
	KindKeyStore    Kind = "keystore"
	KindEventSink   Kind = "event_sink"
	KindBreachCheck Kind = "breach_check"
)

var (
	mu        sync.Mutex
	factories = map[Kind]map[string]any{}
)

func register(k Kind, name string, f any) {
	mu.Lock()
	defer mu.Unlock()
	if factories[k] == nil {
		factories[k] = map[string]any{}
	}
	if _, dup := factories[k][name]; dup {
		panic(fmt.Sprintf("plugin: duplicate %s adapter %q", k, name))
	}
	factories[k][name] = f
}

func RegisterStorage(name string, f StorageFactory)     { register(KindStorage, name, f) }
func RegisterEphemeral(name string, f EphemeralFactory) { register(KindEphemeral, name, f) }
func RegisterNotifier(name string, f NotifierFactory)   { register(KindNotifier, name, f) }
func RegisterKeyStore(name string, f KeyStoreFactory)   { register(KindKeyStore, name, f) }
func RegisterEventSink(name string, f EventSinkFactory) { register(KindEventSink, name, f) }
func RegisterBreachCheck(name string, f BreachCheckFactory) {
	register(KindBreachCheck, name, f)
}

func lookup[F any](k Kind, name string) (F, error) {
	mu.Lock()
	defer mu.Unlock()
	f, ok := factories[k][name].(F)
	if !ok {
		var zero F
		return zero, fmt.Errorf("plugin: %s adapter %q is not included in this binary", k, name)
	}
	return f, nil
}

func Storage(name string) (StorageFactory, error) { return lookup[StorageFactory](KindStorage, name) }
func Ephemeral(name string) (EphemeralFactory, error) {
	return lookup[EphemeralFactory](KindEphemeral, name)
}
func Notifier(name string) (NotifierFactory, error) {
	return lookup[NotifierFactory](KindNotifier, name)
}
func KeyStore(name string) (KeyStoreFactory, error) {
	return lookup[KeyStoreFactory](KindKeyStore, name)
}
func EventSink(name string) (EventSinkFactory, error) {
	return lookup[EventSinkFactory](KindEventSink, name)
}

func BreachCheck(name string) (BreachCheckFactory, error) {
	return lookup[BreachCheckFactory](KindBreachCheck, name)
}

// Registered はバイナリに含まれるアダプタを種類ごとに名前順で返す（マニフェスト用）。
func Registered() map[Kind][]string {
	mu.Lock()
	defer mu.Unlock()
	out := map[Kind][]string{}
	for k, m := range factories {
		for n := range m {
			out[k] = append(out[k], n)
		}
		sort.Strings(out[k])
	}
	return out
}
