package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

const esIssuer = "https://id.example.test"

// Front-Channel Logout の登録は、フィーチャーが動いていて、戻り先と同じオリジンのときだけ受け付ける（ADR 0094）。
func TestClientsFrontChannel(t *testing.T) {
	k := testkit.New(t)
	actor := audit.Actor{Type: "user", ID: "usr_op"}
	on, off := &provider.Clients{Clock: k.Clock, FrontChannel: true}, &provider.Clients{Clock: k.Clock}
	base := provider.ClientInput{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, AuthMethod: port.ClientAuthNone}
	create := func(c *provider.Clients, in provider.ClientInput) (port.Client, error) {
		var cl port.Client
		err := k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			var err error
			cl, _, err = c.Create(ctx, tx, k.RealmID, in, actor, "req")
			return err
		})
		return cl, err
	}
	with := func(uri string, required bool) provider.ClientInput {
		in := base
		in.FrontchannelLogoutURI, in.FrontchannelLogoutSessionRequired = uri, required
		return in
	}
	for name, uri := range map[string]string{
		"other origin": "https://evil.example.com/fcl",
		"other port":   "https://app.example.com:8443/fcl",
		"fragment":     "https://app.example.com/fcl#x",
		"http":         "http://app.example.com/fcl",
		"relative":     "/fcl",
	} {
		if _, err := create(on, with(uri, true)); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := create(off, with("https://app.example.com/fcl", false)); !errors.Is(err, errs.Invalid) || !strings.Contains(err.Error(), "oidc_logout") {
		t.Fatalf("feature off: %v", err)
	}
	cl, err := create(on, with("https://app.example.com/fcl?a=1", true))
	if err != nil || cl.FrontchannelLogoutURI != "https://app.example.com/fcl?a=1" || !cl.FrontchannelLogoutSessionRequired {
		t.Fatalf("created = %+v, %v", cl, err)
	}
	// session_required は URI が無ければ外す。
	if cl, err := create(on, with("", true)); err != nil || cl.FrontchannelLogoutSessionRequired {
		t.Fatalf("required without uri = %+v, %v", cl, err)
	}
	update := func(c *provider.Clients, in provider.ClientInput) (port.Client, error) {
		var up port.Client
		err := k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			cur, err := tx.Clients().Get(ctx, k.RealmID, cl.ID)
			if err != nil {
				return err
			}
			up, _, err = c.Update(ctx, tx, cur, in, actor, "req")
			return err
		})
		return up, err
	}
	// 無効化の途中：残っている値は変えなければ受け付け、変えるのは拒み、外すのは受け付ける。
	keep := with("https://app.example.com/fcl?a=1", true)
	keep.Name = "Renamed"
	if up, err := update(off, keep); err != nil || up.Name != "Renamed" {
		t.Fatalf("keep while off = %+v, %v", up, err)
	}
	if _, err := update(off, with("https://app.example.com/other", true)); !errors.Is(err, errs.Invalid) {
		t.Fatalf("change while off: %v", err)
	}
	if up, err := update(off, base); err != nil || up.FrontchannelLogoutURI != "" || up.FrontchannelLogoutSessionRequired {
		t.Fatalf("remove while off = %+v, %v", up, err)
	}
}

// esEnv はログアウトの要求を確かめる環境（連携先と、その ID トークンを作る）。
type esEnv struct {
	k      *testkit.Kit
	tokens *provider.Tokens
	client port.Client
}

func newESEnv(t *testing.T) *esEnv {
	t.Helper()
	k := testkit.New(t)
	keys := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour}
	e := &esEnv{k: k, tokens: &provider.Tokens{Clock: k.Clock, Keys: keys, Issuer: esIssuer}}
	c := &provider.Clients{Clock: k.Clock, FrontChannel: true}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		e.client, _, err = c.Create(ctx, tx, k.RealmID, provider.ClientInput{Name: "App", RedirectURIs: []string{"https://app.example.com/cb"},
			PostLogoutRedirectURIs: []string{"https://app.example.com/bye", "https://app.example.com/bye2?x=1"}, AuthMethod: port.ClientAuthNone,
			FrontchannelLogoutURI: "https://app.example.com/fcl?a=1", FrontchannelLogoutSessionRequired: true}, audit.Actor{Type: "system"}, "")
		return err
	})
	return e
}

func (e *esEnv) sign(t *testing.T, alg, typ string, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var out string
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		out, err = e.tokens.Keys.Sign(ctx, tx, e.k.RealmID, alg, typ, b)
		return err
	})
	return out
}

func (e *esEnv) idToken(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	now := e.k.Clock.Now()
	c := map[string]any{"iss": esIssuer, "sub": "usr_alice", "aud": e.client.PublicID, "azp": e.client.PublicID, "sid": "sid_1",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if edit != nil {
		edit(c)
	}
	return e.sign(t, port.AlgES256, "JWT", c)
}

func (e *esEnv) end(t *testing.T, in provider.EndSessionInput) (provider.EndSession, error) {
	t.Helper()
	var out provider.EndSession
	err := e.k.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = e.tokens.EndSession(ctx, tx, e.k.RealmID, in)
		return err
	})
	return out, err
}

func TestEndSessionRequest(t *testing.T) {
	e := newESEnv(t)
	hint := e.idToken(t, nil)
	// 期限切れの ID トークンも受け付ける（署名と aud は確かめる）。
	e.k.Clock.Advance(48 * time.Hour)
	got, err := e.end(t, provider.EndSessionInput{IDTokenHint: hint, PostLogoutRedirectURI: "https://app.example.com/bye2?x=1", State: "s 1"})
	if err != nil || got.ClientID != e.client.PublicID || got.ClientName != "App" || got.HintSub != "usr_alice" || got.HintSID != "sid_1" {
		t.Fatalf("end = %+v, %v", got, err)
	}
	if u := got.RedirectURL(); u != "https://app.example.com/bye2?x=1&state=s+1" {
		t.Fatalf("redirect = %s", u)
	}
	// client_id だけでも戻り先を確かめられる。何も無ければ戻さない。
	if got, err := e.end(t, provider.EndSessionInput{ClientID: e.client.PublicID, PostLogoutRedirectURI: "https://app.example.com/bye"}); err != nil ||
		got.RedirectURL() != "https://app.example.com/bye" || got.HintSID != "" {
		t.Fatalf("client_id = %+v, %v", got, err)
	}
	if got, err := e.end(t, provider.EndSessionInput{}); err != nil || got.RedirectURL() != "" || got.ClientID != "" {
		t.Fatalf("empty = %+v, %v", got, err)
	}

	other := e.sign(t, port.AlgES256, "JWT", map[string]any{"iss": esIssuer, "sub": "usr_alice", "aud": "cli_unknown", "sid": "sid_1"})
	for name, in := range map[string]provider.EndSessionInput{
		"unregistered redirect":   {ClientID: e.client.PublicID, PostLogoutRedirectURI: "https://app.example.com/bye/"},
		"redirect without client": {PostLogoutRedirectURI: "https://app.example.com/bye"},
		"unknown client":          {ClientID: "cli_unknown"},
		"client mismatch":         {IDTokenHint: hint, ClientID: "cli_other"},
		"unknown aud":             {IDTokenHint: other},
		"tampered":                {IDTokenHint: hint[:len(hint)-4] + "AAAA"},
		"garbage":                 {IDTokenHint: "x.y.z"},
		"wrong iss":               {IDTokenHint: e.idToken(t, func(c map[string]any) { c["iss"] = "https://other.example" })},
		"no sub":                  {IDTokenHint: e.idToken(t, func(c map[string]any) { delete(c, "sub") })},
		"azp not in aud":          {IDTokenHint: e.idToken(t, func(c map[string]any) { c["azp"] = "cli_x" })},
		"many aud without azp": {IDTokenHint: e.idToken(t, func(c map[string]any) {
			c["aud"] = []string{e.client.PublicID, "cli_x"}
			delete(c, "azp")
		})},
		"logout token typ": {IDTokenHint: e.sign(t, port.AlgES256, "logout+jwt", map[string]any{"iss": esIssuer, "sub": "usr_alice", "aud": e.client.PublicID})},
		"logout token events": {IDTokenHint: e.idToken(t, func(c map[string]any) {
			c["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}
		})},
		"long state": {State: strings.Repeat("s", provider.MaxLogoutState+1)},
		"long hint":  {IDTokenHint: strings.Repeat("a", provider.MaxIDTokenHint+1)},
	} {
		if _, err := e.end(t, in); !errors.Is(err, provider.ErrInvalidLogoutRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// aud が配列でも azp で連携先が決まる。ML-DSA-65 の ID トークンも受け付ける。
	multi := e.idToken(t, func(c map[string]any) { c["aud"] = []string{e.client.PublicID, "cli_x"} })
	ml := e.sign(t, port.AlgMLDSA65, "JWT", map[string]any{"iss": esIssuer, "sub": "usr_alice", "aud": e.client.PublicID, "sid": "sid_2"})
	for _, h := range []string{multi, ml} {
		if got, err := e.end(t, provider.EndSessionInput{IDTokenHint: h}); err != nil || got.ClientID != e.client.PublicID {
			t.Fatalf("hint = %+v, %v", got, err)
		}
	}
	// 別の realm の鍵で署名したものは受け付けない。
	var foreign string
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		foreign, err = e.tokens.Keys.Sign(ctx, tx, id.New(id.Realm), port.AlgES256, "JWT",
			[]byte(`{"iss":"`+esIssuer+`","sub":"usr_alice","aud":"`+e.client.PublicID+`"}`))
		return err
	})
	if _, err := e.end(t, provider.EndSessionInput{IDTokenHint: foreign}); !errors.Is(err, provider.ErrInvalidLogoutRequest) {
		t.Fatalf("foreign realm: %v", err)
	}
}

func TestFrontChannelURLsAndHold(t *testing.T) {
	e := newESEnv(t)
	ctx := context.Background()
	quiet := port.Client{ID: id.New(id.Client), PublicID: id.NewExternal(id.Client), RealmID: e.k.RealmID, Name: "Q", TrustLevel: port.TrustFirstParty,
		RedirectURIs: []string{"https://q.example.com/cb"}, AuthMethod: port.ClientAuthNone, IDTokenAlg: port.AlgES256,
		FrontchannelLogoutURI: "https://q.example.com/fcl", CreatedAt: e.k.Clock.Now(), UpdatedAt: e.k.Clock.Now()}
	none := quiet
	none.ID, none.PublicID, none.FrontchannelLogoutURI = id.New(id.Client), id.NewExternal(id.Client), ""
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		for _, c := range []port.Client{quiet, none} {
			if err := tx.Clients().Create(ctx, c); err != nil {
				return err
			}
		}
		now := e.k.Clock.Now()
		for i, c := range []string{e.client.ID, quiet.ID, e.client.ID, none.ID} {
			g := port.Grant{ID: id.New(id.Grant), RealmID: e.k.RealmID, ClientID: c, UserID: "usr", SID: "sid_1", Scopes: []string{"openid"},
				AuthTime: now, CreatedAt: now.Add(time.Duration(i) * time.Second), ExpiresAt: now.Add(time.Hour)}
			if err := tx.Grants().Create(ctx, g); err != nil {
				return err
			}
		}
		return nil
	})
	var urls []string
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		urls, err = e.tokens.FrontChannelURLs(ctx, tx, e.k.RealmID, "sid_1")
		return err
	})
	want := []string{"https://app.example.com/fcl?a=1&iss=https%3A%2F%2Fid.example.test&sid=sid_1", "https://q.example.com/fcl"}
	if !slices.Equal(urls, want) {
		t.Fatalf("urls = %v", urls)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		if urls, err = e.tokens.FrontChannelURLs(ctx, tx, e.k.RealmID, "sid_other"); err != nil || len(urls) != 0 {
			t.Fatalf("other sid = %v, %v", urls, err)
		}
		return nil
	})

	f := &provider.Flow{Cache: e.k.Cache, Crypter: e.k.Crypter, Clock: e.k.Clock}
	rid, err := f.HoldLogout(ctx, provider.EndSession{RealmID: e.k.RealmID, SID: "sid_1", PrincipalID: "usr", RedirectURI: "https://app.example.com/bye"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.TakeLogout(ctx, id.New(id.Realm), rid); !errors.Is(err, provider.ErrLogoutRequestExpired) {
		t.Fatalf("other realm: %v", err)
	}
	// 別の realm で取り出そうとしたものも、もう使えない（1回だけ）。
	if _, err := f.TakeLogout(ctx, e.k.RealmID, rid); !errors.Is(err, provider.ErrLogoutRequestExpired) {
		t.Fatalf("after other realm: %v", err)
	}
	rid, _ = f.HoldLogout(ctx, provider.EndSession{RealmID: e.k.RealmID, SID: "sid_1"})
	got, err := f.TakeLogout(ctx, e.k.RealmID, rid)
	if err != nil || got.SID != "sid_1" {
		t.Fatalf("take = %+v, %v", got, err)
	}
	if _, err := f.TakeLogout(ctx, e.k.RealmID, rid); !errors.Is(err, provider.ErrLogoutRequestExpired) {
		t.Fatalf("take twice: %v", err)
	}
	rid, _ = f.HoldLogout(ctx, provider.EndSession{RealmID: e.k.RealmID})
	e.k.Clock.Advance(provider.DefaultLogoutRequestTTL)
	if _, err := f.TakeLogout(ctx, e.k.RealmID, rid); !errors.Is(err, provider.ErrLogoutRequestExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := f.TakeLogout(ctx, e.k.RealmID, ""); !errors.Is(err, provider.ErrLogoutRequestExpired) {
		t.Fatalf("empty: %v", err)
	}
}
