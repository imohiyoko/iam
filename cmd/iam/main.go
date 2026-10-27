// Command iam は設定を読み、アダプタを選んで IAM を起動する（design.md 2.2）。
//
// このバイナリに含めるアダプタとフィーチャーは、下の import で決まる（自己登録。design.md 11.11）。
// 将来は `iam build` が build.yaml からこの import の一覧を生成する。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/imohiyoko/iam/adapters/keystore/file"
	"github.com/imohiyoko/iam/server/app"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/plugin"

	// アダプタ（全部入りの構成）。
	_ "github.com/imohiyoko/iam/adapters/breachcheck/hibp"
	_ "github.com/imohiyoko/iam/adapters/ephemeral/memory"
	_ "github.com/imohiyoko/iam/adapters/eventsink/stdout"
	_ "github.com/imohiyoko/iam/adapters/keystore/env"
	_ "github.com/imohiyoko/iam/adapters/notifier/dev"
	_ "github.com/imohiyoko/iam/adapters/storage/memory"
	_ "github.com/imohiyoko/iam/adapters/storage/postgres"
	_ "github.com/imohiyoko/iam/adapters/storage/sqlite"
)

// version はビルド時に -ldflags "-X main.version=…" で埋め込む。
var version = ""

const usage = `usage: iam <command> [flags]

commands:
  serve     -config iam.yaml        IAM を起動する
  migrate   -config iam.yaml        Storage のマイグレーションを適用する
  features enable -config iam.yaml <name>
                                    フィーチャーを有効にする（準備処理の後に active。サーバーは再起動で反映）
  version   [-manifest]             バージョン（とバイナリの構成）を表示する
  keys generate -out keys.json      KeyStore（file）用の鍵を作る
  operator create -config iam.yaml -email <address> [-role realm:owner] [-ttl 15m]
                                    運営者を作り、1回限りのログイン用リンクのトークンを表示する
`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "iam:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("command required")
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stdout, stderr)
	case "migrate":
		return migrate(ctx, args[1:], stdout, stderr)
	case "version":
		return printVersion(args[1:], stdout, stderr)
	case "keys":
		return keys(args[1:], stdout, stderr)
	case "operator":
		return operator(ctx, args[1:], stdout, stderr)
	case "features":
		return features(ctx, args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadConfig(fs *flag.FlagSet, args []string) (config.Config, error) {
	path := fs.String("config", "iam.yaml", "設定ファイル")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return config.Load(*path)
}

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	deps, closeFn, err := build(ctx, cfg, log, stdout)
	if err != nil {
		return err
	}
	defer closeFn()
	a, err := app.New(ctx, cfg, deps, feature.Registered())
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

// build は設定で選んだアダプタを作る。
func build(ctx context.Context, cfg config.Config, log *slog.Logger, stdout io.Writer) (app.Deps, func(), error) {
	clk := clock.System{}
	pc := func(a config.Adapter) plugin.Config {
		return plugin.Config{Clock: clk, Logger: log, Stdout: stdout, Options: a.Options, Dev: cfg.Dev}
	}
	d := app.Deps{Clock: clk, Logger: log}
	sf, err := plugin.Storage(cfg.Storage.Driver)
	if err != nil {
		return d, nil, err
	}
	if d.Storage, err = sf(ctx, pc(cfg.Storage)); err != nil {
		return d, nil, err
	}
	closeFn := func() { _ = d.Storage.Close() }
	fail := func(err error) (app.Deps, func(), error) { closeFn(); return d, nil, err }

	ef, err := plugin.Ephemeral(cfg.Ephemeral.Driver)
	if err != nil {
		return fail(err)
	}
	if d.Ephemeral, err = ef(ctx, pc(cfg.Ephemeral)); err != nil {
		return fail(err)
	}
	kf, err := plugin.KeyStore(cfg.KeyStore.Driver)
	if err != nil {
		return fail(err)
	}
	if d.KeyStore, err = kf(ctx, pc(cfg.KeyStore)); err != nil {
		return fail(err)
	}
	xf, err := plugin.EventSink(cfg.EventSink.Driver)
	if err != nil {
		return fail(err)
	}
	if d.EventSink, err = xf(ctx, pc(cfg.EventSink)); err != nil {
		return fail(err)
	}
	nf, err := plugin.Notifier(cfg.Notifier.Driver)
	if err != nil {
		return fail(err)
	}
	if d.Notifier, err = nf(ctx, pc(cfg.Notifier)); err != nil {
		return fail(err)
	}
	if cfg.BreachCheck.Driver != "" {
		bf, err := plugin.BreachCheck(cfg.BreachCheck.Driver)
		if err != nil {
			return fail(err)
		}
		if d.BreachCheck, err = bf(ctx, pc(cfg.BreachCheck)); err != nil {
			return fail(err)
		}
	}
	return d, closeFn, nil
}

func migrate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	sf, err := plugin.Storage(cfg.Storage.Driver)
	if err != nil {
		return err
	}
	opts := map[string]string{}
	for k, v := range cfg.Storage.Options {
		opts[k] = v
	}
	opts["auto_migrate"] = "true"
	s, err := sf(ctx, plugin.Config{Clock: clock.System{}, Options: opts, Dev: cfg.Dev})
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "migrations applied")
	return s.Close()
}

func operator(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: iam operator create -config iam.yaml -email <address> [-role realm:owner] [-ttl 15m]")
	}
	fs := flag.NewFlagSet("operator create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	email := fs.String("email", "", "運営者のメールアドレス（所有は実行する人が確かめる）")
	roleName := fs.String("role", "realm:owner", "付与するロール")
	ttl := fs.Duration("ttl", 15*time.Minute, "ログイン用リンクの有効期間（最大 24h）")
	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	if *email == "" {
		return errors.New("-email is required")
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	deps, closeFn, err := build(ctx, cfg, log, stdout)
	if err != nil {
		return err
	}
	defer closeFn()
	a, err := app.New(ctx, cfg, deps, feature.Registered())
	if err != nil {
		return err
	}
	op, err := a.CreateOperator(ctx, *email, *roleName, *ttl)
	if err != nil {
		return err
	}
	// 監査ログの外部出力は outbox に残り、次に `iam serve` が送る。
	what := "added role to existing user"
	if op.Created {
		what = "created operator"
	}
	fmt.Fprintf(stdout, "%s %s (%s)\n", what, op.UserID, *roleName)
	fmt.Fprintf(stdout, "one-time login token (expires %s). Give it only to the operator:\n%s\n",
		op.ExpiresAt.Format(time.RFC3339), op.LinkToken)
	if u := strings.TrimSuffix(cfg.Server.PublicURL, "/"); u != "" {
		fmt.Fprintf(stdout, "open in a browser: %s/login/link#token=%s\n", u, op.LinkToken)
	} else {
		fmt.Fprintln(stdout, "open <public_url>/login/link#token=<token> in a browser, or POST /v1/login/link:redeem {\"token\": \"...\"}")
	}
	return nil
}

func features(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	const use = "usage: iam features enable -config iam.yaml <name>"
	if len(args) == 0 || args[0] != "enable" {
		return errors.New(use)
	}
	fs := flag.NewFlagSet("features enable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(use)
	}
	name := fs.Arg(0)
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	deps, closeFn, err := build(ctx, cfg, log, stdout)
	if err != nil {
		return err
	}
	defer closeFn()
	a, err := app.New(ctx, cfg, deps, feature.Registered())
	if err != nil {
		return err
	}
	changed, err := a.EnableFeature(ctx, name)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Fprintf(stdout, "%s is already active\n", name)
		return nil
	}
	fmt.Fprintf(stdout, "%s is now active. Restart the servers to apply it.\n", name)
	return nil
}

func printVersion(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifest := fs.Bool("manifest", false, "バイナリに含まれるフィーチャーとアダプタを JSON で表示する")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m := app.BuildManifest(version)
	if !*manifest {
		fmt.Fprintln(stdout, m.Version)
		return nil
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

func keys(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("usage: iam keys generate -out keys.json")
	}
	fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "keys.json", "書き出す先（既にあれば上書きしない）")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	k, err := file.Generate()
	if err != nil {
		return err
	}
	if err := file.Write(*out, k); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s (master key %s, index key %s). Back it up: data cannot be recovered without it.\n",
		*out, k.CurrentMasterKey, k.CurrentIndexKey)
	return nil
}
