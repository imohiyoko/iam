package config

import (
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	c, err := Parse([]byte(`
dev: true
storage:
  driver: memory
keystore:
  driver: file
  path: /etc/iam/keys.json
features: [org]
security:
  session:
    absolute_lifetime: {default: 7d, min: 1h, max: 30d}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Driver != "memory" || c.Storage.Options["path"] != "" {
		t.Fatalf("storage = %+v", c.Storage)
	}
	if c.KeyStore.Options["path"] != "/etc/iam/keys.json" {
		t.Fatalf("keystore = %+v", c.KeyStore)
	}
	if c.Ephemeral.Driver != "memory" || c.Notifier.Driver != "dev" {
		t.Fatalf("defaults not applied: %+v %+v", c.Ephemeral, c.Notifier)
	}
	if c.Features == nil || len(*c.Features) != 1 {
		t.Fatalf("features = %v", c.Features)
	}
	if got := c.Security.Session.AbsoluteLifetime.Default.D(); got != 7*24*time.Hour {
		t.Fatalf("lifetime = %v", got)
	}
}

func TestParseEmptyUsesDefaults(t *testing.T) {
	c, err := Parse([]byte("dev: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Driver != "sqlite" || c.Features != nil {
		t.Fatalf("%+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":          "dev: true\nbogus: 1\n",
		"dev notifier":           "notifier: {driver: dev}\n",
		"same addr":              "dev: true\nserver: {public_addr: ':1', admin_addr: ':1'}\n",
		"bad range":              "dev: true\nsecurity: {session: {absolute_lifetime: {default: 100d, min: 1h, max: 90d}}}\n",
		"bad timezone":           "dev: true\nrealm: {slug: x, timezone: Mars/Base}\n",
		"bad duration":           "dev: true\noutbox: {interval: 1x}\n",
		"overflow days":          "dev: true\noutbox: {interval: 106752d}\n",
		"negative min":           "dev: true\nsecurity: {session: {max_auth_age: {default: 15m, min: -1h, max: 1d}}}\n",
		"options without driver": "dev: true\nstorage: {path: /var/lib/iam/iam.db}\n",
		"public_url path":        "dev: true\nserver: {public_url: 'https://id.example.com/iam'}\n",
		"public_url query":       "dev: true\nserver: {public_url: 'https://id.example.com?x=1'}\n",
		"public_url empty query": "dev: true\nserver: {public_url: 'https://id.example.com/?'}\n",
		"public_url fragment":    "dev: true\nserver: {public_url: 'https://id.example.com#a'}\n",
		"public_url userinfo":    "dev: true\nserver: {public_url: 'https://u:p@id.example.com'}\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestPublicURLAcceptsOrigin(t *testing.T) {
	for _, u := range []string{"https://id.example.com", "https://id.example.com/", "http://localhost:8080"} {
		if _, err := Parse([]byte("dev: true\nserver: {public_url: '" + u + "'}\n")); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "15m": 15 * time.Minute} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"d", "1.5d", "xd"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("%s: want error", in)
		}
	}
}

func TestExternalIDsMustBeRandom(t *testing.T) {
	if _, err := Parse([]byte("dev: true\nids: {external: uuidv7}\n")); err == nil || !strings.Contains(err.Error(), "ids.external") {
		t.Fatalf("want ids.external error, got %v", err)
	}
	if _, err := Parse([]byte("dev: true\nids: {internal: sequential}\n")); err == nil || !strings.Contains(err.Error(), "ids.internal") {
		t.Fatalf("want ids.internal error, got %v", err)
	}
	if _, err := Parse([]byte("dev: true\nids: {internal: random}\n")); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyRelyingParty(t *testing.T) {
	c, err := Parse([]byte("dev: true\nserver: {public_url: \"https://id.example.com\"}\nrealm: {slug: acme}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rp, name, origins, ok := c.PasskeyRP(); !ok || rp != "id.example.com" || name != "acme" || len(origins) != 1 || origins[0] != "https://id.example.com" {
		t.Fatalf("defaults = %q %q %v %v", rp, name, origins, ok)
	}
	c, err = Parse([]byte("dev: true\npasskey: {rp_id: example.com, origins: [\"https://id.example.com\", \"https://app.example.net\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rp, _, origins, ok := c.PasskeyRP(); !ok || rp != "example.com" || len(origins) != 2 {
		t.Fatalf("explicit = %q %v %v", rp, origins, ok)
	}
	if _, _, _, ok := Default().PasskeyRP(); ok {
		t.Fatal("passkeys must be disabled without public_url or rp_id")
	}
	for _, y := range []string{
		"passkey: {rp_id: example.com}\n",
		"passkey: {rp_id: \"https://example.com\", origins: [\"https://example.com\"]}\n",
		"passkey: {rp_id: example.com, origins: [\"ftp://example.com\"]}\n",
		"passkey: {rp_id: example.com, origins: [\"https://example.com/login\"]}\n",
	} {
		if _, err := Parse([]byte("dev: true\n" + y)); err == nil || !strings.Contains(err.Error(), "passkey") {
			t.Errorf("%s: want passkey error, got %v", y, err)
		}
	}
}

func TestSecondFactorAndPasswordRules(t *testing.T) {
	for _, y := range []string{
		"dev: true\nsecurity: {second_factor: {ttl: 2h}}\n",
		"dev: true\nsecurity: {second_factor: {max_attempts: 0}}\n",
		"dev: true\nsecurity: {password: {argon2: {memory_kib: 4}}}\n",
		"dev: true\nsecurity: {password: {argon2: {parallelism: 0}}}\n",
		// 本番では OWASP の下限より軽くできない。
		"security: {password: {argon2: {memory_kib: 8192}}}\n",
		"security: {password: {argon2: {iterations: 1}}}\n",
		"dev: true\nsecurity: {suspension_categories: [billing]}\n",
		"dev: true\nsecurity: {recovery: {methods: [sms]}}\n",
		"dev: true\nsecurity: {recovery: {ttl: 2h}}\n",
		"dev: true\nsecurity: {suspension_categories: [Fraud]}\n",
	} {
		if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "security.") {
			t.Errorf("%s: want a security error, got %v", y, err)
		}
	}
	if _, err := Parse([]byte("dev: true\nsecurity: {suspension_categories: [fraud_review]}\n")); err != nil {
		t.Errorf("extra category: %v", err)
	}
	if _, err := Parse([]byte("dev: true\nsecurity: {password: {argon2: {memory_kib: 8, iterations: 1}}}\n")); err != nil {
		t.Errorf("light params in dev: %v", err)
	}
}
