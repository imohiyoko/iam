package buildspec

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	s, err := Parse([]byte(`
features: [org, quota]
adapters:
  storage: [postgres]
  ephemeral: [redis]
  keystore: [env]
  event_sink: [otlp]
  notifier: [webhook]
`))
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.Imports()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/features/org\"", "/features/quota\"", "/adapters/storage/postgres\"", "/adapters/notifier/webhook\""} {
		if !strings.Contains(string(code), want) {
			t.Errorf("imports lack %s:\n%s", want, code)
		}
	}
	for _, unwanted := range []string{"/features/password\"", "/adapters/storage/sqlite\"", "/adapters/notifier/dev\""} {
		if strings.Contains(string(code), unwanted) {
			t.Errorf("imports include %s", unwanted)
		}
	}
}

func TestParseRejects(t *testing.T) {
	base := "adapters: {storage: [sqlite], ephemeral: [memory], keystore: [file], event_sink: [stdout], notifier: [dev]}\n"
	cases := map[string]string{
		"unknown field":      base + "bogus: 1\n",
		"unknown feature":    base + "features: [nope]\n",
		"missing requires":   base + "features: [quota]\n",
		"unknown adapter":    "adapters: {storage: [mysql], ephemeral: [memory], keystore: [file], event_sink: [stdout], notifier: [dev]}\n",
		"unknown kind":       base[:len(base)-2] + ", queue: [x]}\n",
		"missing notifier":   "adapters: {storage: [sqlite], ephemeral: [memory], keystore: [file], event_sink: [stdout]}\n",
		"missing everything": "features: [org]\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := Parse([]byte(base + "features: [org, quota]\n")); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
}

func TestAllIsValid(t *testing.T) {
	if err := All().Check(); err != nil {
		t.Fatal(err)
	}
}
