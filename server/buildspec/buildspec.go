// Package buildspec はバイナリに含めるフィーチャーとアダプタの選択（build.yaml。design.md 11.11、ADR 0073）。
//
// `iam build` は build.yaml を読み、選んだものだけを import するファイル（cmd/iam/imports.go）を作ってビルドする。
// リポジトリの cmd/iam/imports.go は全部入り（All）から作ったもの。
package buildspec

import (
	"bytes"
	"errors"
	"fmt"
	"go/format"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/authn/botcheck"
	"github.com/imohiyoko/iam/authn/device"
	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/authn/hook"
	"github.com/imohiyoko/iam/authn/lockout"
	"github.com/imohiyoko/iam/authn/merge"
	"github.com/imohiyoko/iam/authn/method/hotp"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/authz/manage"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/realm"
)

const module = "github.com/imohiyoko/iam"

// featureCatalog はバイナリに含められるフィーチャー（宣言と、登録するパッケージ）。
var featureCatalog = map[string]struct {
	decl feature.Feature
	pkg  string
}{
	feature.Org:                {org.Feature, module + "/features/org"},
	feature.OrgManagedUsers:    {org.ManagedUsersFeature, module + "/features/orgmanagedusers"},
	feature.OrgHierarchy:       {org.HierarchyFeature, module + "/features/orghierarchy"},
	feature.OrgLoginPolicy:     {org.PolicyFeature, module + "/features/orgloginpolicy"},
	feature.Quota:              {org.QuotaFeature, module + "/features/quota"},
	feature.Warnings:           {warning.Feature, module + "/features/warnings"},
	feature.Password:           {password.Feature, module + "/features/password"},
	feature.ServiceAccounts:    {serviceaccount.Feature, module + "/features/serviceaccounts"},
	feature.NestedGroups:       {manage.NestedGroupsFeature, module + "/features/nestedgroups"},
	feature.CustomAttributes:   {attribute.Feature, module + "/features/customattributes"},
	feature.FlowHooks:          {hook.Feature, module + "/features/flowhooks"},
	feature.AccountMerge:       {merge.Feature, module + "/features/accountmerge"},
	feature.MultiRealm:         {realm.Feature, module + "/features/multirealm"},
	feature.PasskeyAttestation: {passkey.AttestationFeature, module + "/features/passkeyattestation"},
	feature.TokenExchange:      {provider.TokenExchangeFeature, module + "/features/tokenexchange"},
	feature.Impersonation:      {provider.ImpersonationFeature, module + "/features/impersonation"},
	feature.ACR:                {acr.Feature, module + "/features/acr"},
	feature.OIDCLogout:         {provider.LogoutFeature, module + "/features/oidclogout"},
	feature.HOTP:               {hotp.Feature, module + "/features/hotp"},
	feature.SAML:               {saml.Feature, module + "/features/saml"},
	feature.OrgAuditLog:        {eventlog.OrgAuditLogFeature, module + "/features/orgauditlog"},
	feature.EventSubscriptions: {eventsub.Feature, module + "/features/eventsubscriptions"},
	feature.DeviceFlow:         {provider.DeviceFeature, module + "/features/deviceflow"},
	feature.AccountLockout:     {lockout.Feature, module + "/features/accountlockout"},
	feature.DeviceRecognition:  {device.Feature, module + "/features/devicerecognition"},
	feature.LoginRisk:          {device.RiskFeature, module + "/features/loginrisk"},
	feature.BotProtection:      {botcheck.Feature, module + "/features/botprotection"},
}

// adapterCatalog はバイナリに含められるアダプタのパッケージ。
var adapterCatalog = map[plugin.Kind]map[string]string{
	plugin.KindStorage: {
		"memory": module + "/adapters/storage/memory", "sqlite": module + "/adapters/storage/sqlite", "postgres": module + "/adapters/storage/postgres",
	},
	plugin.KindEphemeral: {"memory": module + "/adapters/ephemeral/memory", "redis": module + "/adapters/ephemeral/redis"},
	plugin.KindKeyStore:  {"file": module + "/adapters/keystore/file", "env": module + "/adapters/keystore/env"},
	plugin.KindEventSink: {
		"stdout": module + "/adapters/eventsink/stdout", "syslog": module + "/adapters/eventsink/syslog",
		"otlp": module + "/adapters/eventsink/otlp", "webhook": module + "/adapters/eventsink/webhook",
	},
	plugin.KindNotifier:    {"dev": module + "/adapters/notifier/dev", "webhook": module + "/adapters/notifier/webhook"},
	plugin.KindBreachCheck: {"hibp": module + "/adapters/breachcheck/hibp"},
	plugin.KindFIDOMDS:     {"file": module + "/adapters/fidomds/file", "http": module + "/adapters/fidomds/http"},
	plugin.KindGeoIP:       {"static": module + "/adapters/geoip/static"},
	plugin.KindBotCheck:    {"siteverify": module + "/adapters/botcheck/siteverify", "dev": module + "/adapters/botcheck/dev"},
}

// requiredKinds は起動に必ず要るアダプタの種類（breach_check・fido_mds・geoip・bot_check は任意）。
var requiredKinds = []plugin.Kind{plugin.KindStorage, plugin.KindEphemeral, plugin.KindKeyStore, plugin.KindEventSink, plugin.KindNotifier}

// Spec は build.yaml。
type Spec struct {
	Features []string                 `yaml:"features"`
	Adapters map[plugin.Kind][]string `yaml:"adapters"`
}

// Parse は build.yaml を読み、Check で確かめる。未知の項目はエラー。
func Parse(b []byte) (Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("build.yaml: %w", err)
	}
	return s, s.Check()
}

// All は全部入りの構成。
func All() Spec {
	s := Spec{Adapters: map[plugin.Kind][]string{}}
	for n := range featureCatalog {
		s.Features = append(s.Features, n)
	}
	sort.Strings(s.Features)
	for k, m := range adapterCatalog {
		for n := range m {
			s.Adapters[k] = append(s.Adapters[k], n)
		}
		sort.Strings(s.Adapters[k])
	}
	return s
}

// Check は名前が既知で、起動に要るアダプタがあり、フィーチャーの依存先が含まれることを確かめる（ビルド時の検査）。
func (s Spec) Check() error {
	var problems []string
	for _, n := range s.Features {
		if _, ok := featureCatalog[n]; !ok {
			problems = append(problems, fmt.Sprintf("unknown feature %q (known: %s)", n, strings.Join(sortedKeys(featureCatalog), ", ")))
		}
	}
	for k, names := range s.Adapters {
		known, ok := adapterCatalog[k]
		if !ok {
			problems = append(problems, fmt.Sprintf("unknown adapter kind %q", k))
			continue
		}
		for _, n := range names {
			if _, ok := known[n]; !ok {
				problems = append(problems, fmt.Sprintf("unknown %s adapter %q (known: %s)", k, n, strings.Join(sortedKeys(known), ", ")))
			}
		}
	}
	for _, k := range requiredKinds {
		if len(s.Adapters[k]) == 0 {
			problems = append(problems, fmt.Sprintf("adapters.%s: at least one adapter is required", k))
		}
	}
	if err := feature.CheckBuild(s.Binary()); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return errors.New("build.yaml: " + strings.Join(problems, "; "))
	}
	return nil
}

// Binary は選んだフィーチャーの宣言を名前順に返す（feature.Registered と同じ形。features plan で使う）。
func (s Spec) Binary() []feature.Feature {
	var out []feature.Feature
	for _, n := range s.Features {
		if f, ok := featureCatalog[n]; ok && !slices.ContainsFunc(out, func(x feature.Feature) bool { return x.Name == n }) {
			out = append(out, f.decl)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Imports は cmd/iam の imports.go の中身を返す。
func (s Spec) Imports() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// Code generated by `iam build`; DO NOT EDIT.\n\n")
	b.WriteString("package main\n\n// このバイナリに含めるフィーチャーとアダプタ（自己登録。design.md 11.11）。\nimport (\n")
	b.WriteString("\t// フィーチャー。\n")
	for _, f := range s.Binary() {
		fmt.Fprintf(&b, "\t_ %q\n", featureCatalog[f.Name].pkg)
	}
	b.WriteString("\n\t// アダプタ。\n")
	var pkgs []string
	for k, names := range s.Adapters {
		for _, n := range names {
			if p := adapterCatalog[k][n]; p != "" && !slices.Contains(pkgs, p) {
				pkgs = append(pkgs, p)
			}
		}
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		fmt.Fprintf(&b, "\t_ %q\n", p)
	}
	b.WriteString(")\n")
	return format.Source(b.Bytes())
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
