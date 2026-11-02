package wsfed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 要求（WS-Federation 1.2 の 13.2）の引数の解析と、RP と戻り先の決定。知らないものは受けない（ADR 0110）。

// wa の値。
const (
	ActionSignIn  = "wsignin1.0"
	ActionSignOut = "wsignout1.0"
)

const (
	maxContextLen = 2048
	// maxFreshMinutes は wfresh の上限（100 年。Duration のあふれを防ぐ。これより大きい値は制限なしと同じ）。
	maxFreshMinutes = 100 * 365 * 24 * 60
)

// 要求の誤り。どれも RP に戻さずに 400 にする（戻り先を信用できない）。
var (
	ErrBadRequest   = errs.WithCode(errs.KindInvalid, "invalid_request", "invalid ws-federation request")
	ErrUnsupported  = errs.WithCode(errs.KindInvalid, "unsupported_request", "unsupported ws-federation request parameter")
	ErrUnknownRealm = errs.WithCode(errs.KindInvalid, "unknown_realm", "unknown wtrealm")
	ErrUnknownReply = errs.WithCode(errs.KindInvalid, "unknown_reply", "wreply is not registered for the relying party")
	// ErrRequestExpired はログイン画面で待つ間の要求が無い（期限切れ・完了済み）。
	ErrRequestExpired = errs.WithCode(errs.KindNotFound, "request_expired", "ws-federation request expired")
)

// Request は解析した要求。
type Request struct {
	Action string
	// Realm は wtrealm、Reply は wreply（空なら RP の既定）、Context は wctx（そのまま返す）。
	Realm, Reply, Context string
	// Fresh は wfresh（分）。nil なら求めない。0 は今からのログインを求める。
	Fresh *int
}

// known は読む引数（どれも 1 回まで）。unsupported は応えられない引数（あれば拒む）。
var (
	known       = []string{"wa", "wtrealm", "wreply", "wctx", "wfresh", "wct", "whr"}
	unsupported = []string{"wreq", "wreqptr", "wauth", "wresult", "wresultptr", "wp", "wattr", "wattrptr", "wpseudo", "wpseudoptr"}
)

// ParseRequest は要求の引数を読む。wa は wsignin1.0 か wsignout1.0、wsignin1.0 では wtrealm が要る。
// 応えられない引数（wreq・wauth など）や、同じ引数が 2 回あるものは受けない。whr と wct は読まない。
func ParseRequest(q url.Values) (Request, error) {
	for _, k := range known {
		if len(q[k]) > 1 {
			return Request{}, ErrBadRequest
		}
	}
	for _, k := range unsupported {
		if q.Has(k) {
			return Request{}, ErrUnsupported
		}
	}
	r := Request{Action: q.Get("wa"), Realm: q.Get("wtrealm"), Reply: q.Get("wreply"), Context: q.Get("wctx")}
	switch r.Action {
	case ActionSignIn:
		if r.Realm == "" {
			return Request{}, ErrBadRequest
		}
	case ActionSignOut:
	default:
		return Request{}, ErrBadRequest
	}
	if len(r.Realm) > maxRealmLen || len(r.Reply) > maxReplyURLLen || len(r.Context) > maxContextLen ||
		!utf8.ValidString(r.Realm) || !utf8.ValidString(r.Reply) || !utf8.ValidString(r.Context) {
		return Request{}, ErrBadRequest
	}
	if q.Has("wfresh") {
		v := q.Get("wfresh")
		if v == "" || len(v) > 10 || !allDigits(v) {
			return Request{}, ErrBadRequest
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return Request{}, ErrBadRequest
		}
		n = min(n, maxFreshMinutes)
		r.Fresh = &n
	}
	return r, nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Lookup は wtrealm の RP と、トークンを返す先（wreply が登録と完全一致のときだけ。空なら RP の既定）を決める。
// 登録に無い wtrealm は ErrUnknownRealm、許可リストに無い wreply は ErrUnknownReply。
func (s *Service) Lookup(ctx context.Context, realmID, wtrealm, wreply string) (port.WSFedRelyingParty, string, error) {
	if wtrealm == "" {
		return port.WSFedRelyingParty{}, "", ErrUnknownRealm
	}
	var rp port.WSFedRelyingParty
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		rp, err = tx.WSFed().GetRelyingPartyByRealm(ctx, realmID, wtrealm)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return port.WSFedRelyingParty{}, "", ErrUnknownRealm
	}
	if err != nil {
		return port.WSFedRelyingParty{}, "", err
	}
	reply, err := ReplyFor(rp, wreply)
	return rp, reply, err
}

// ReplyFor は RP にトークンを返す先を決める。wreply は登録と完全一致のときだけ使い、空なら最初の登録。
func ReplyFor(rp port.WSFedRelyingParty, wreply string) (string, error) {
	if wreply == "" {
		if len(rp.ReplyURLs) == 0 {
			return "", ErrUnknownReply
		}
		return rp.ReplyURLs[0], nil
	}
	if !slices.Contains(rp.ReplyURLs, wreply) {
		return "", ErrUnknownReply
	}
	return wreply, nil
}

// Pending はログイン画面で待つ間の要求。
type Pending struct {
	RealmID string `json:"realm_id"`
	// RPID と Realm は RP の ID と wtrealm（戻ったときに登録が変わっていないかを確かめる）。
	RPID    string `json:"rp_id"`
	Realm   string `json:"realm"`
	Reply   string `json:"reply"`
	Context string `json:"context,omitempty"`
	// LoginAfter は wfresh=0 のとき、この時刻より後の本人確認を求める。MaxAge は wfresh の正の値（秒）。
	LoginAfter *time.Time `json:"login_after,omitempty"`
	MaxAge     *int64     `json:"max_age,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

// NewPending は要求から Pending を作る（wfresh を時刻の条件にする）。
func NewPending(realmID string, rp port.WSFedRelyingParty, reply string, r Request, now time.Time) Pending {
	p := Pending{RealmID: realmID, RPID: rp.ID, Realm: rp.Realm, Reply: reply, Context: r.Context}
	if r.Fresh != nil {
		if *r.Fresh == 0 {
			p.LoginAfter = &now
		} else {
			sec := int64(*r.Fresh) * 60
			p.MaxAge = &sec
		}
	}
	return p
}

// Fresh は authAt の本人確認が wfresh を満たすかを返す。
func (p Pending) Fresh(authAt, now time.Time) bool {
	if p.LoginAfter != nil && authAt.Before(*p.LoginAfter) {
		return false
	}
	if p.MaxAge != nil && now.Sub(authAt) > time.Duration(*p.MaxAge)*time.Second {
		return false
	}
	return true
}

const (
	pendingPurpose = "flow.wsfed_request"
	pendingPrefix  = "wsfed:request:v1:"
)

func pendingKey(rid string) string {
	h := sha256.Sum256([]byte(rid))
	return pendingPrefix + base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Service) requestTTL() time.Duration {
	if s.RequestTTL <= 0 {
		return 10 * time.Minute
	}
	return s.RequestTTL
}

// Hold はログイン画面で待つ間、要求を封をして預かり、その ID（秘密。256 bit）を返す。
func (s *Service) Hold(ctx context.Context, p Pending) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	rid := base64.RawURLEncoding.EncodeToString(b)
	ttl := s.requestTTL()
	p.ExpiresAt = s.Clock.Now().Add(ttl)
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sealed, err := s.Crypter.Seal(ctx, pendingPurpose, raw)
	if err != nil {
		return "", err
	}
	return rid, s.Cache.Set(ctx, pendingKey(rid), sealed, ttl)
}

// Resume は預かった要求を返す（消さない。ログインをやり直せるように）。無ければ ErrRequestExpired。
func (s *Service) Resume(ctx context.Context, realmID, rid string) (Pending, error) {
	if rid == "" || len(rid) > 128 {
		return Pending{}, ErrRequestExpired
	}
	b, ok, err := s.Cache.Get(ctx, pendingKey(rid))
	if err != nil {
		return Pending{}, err
	}
	if !ok {
		return Pending{}, ErrRequestExpired
	}
	raw, err := s.Crypter.Open(ctx, pendingPurpose, b)
	var p Pending
	if err != nil || json.Unmarshal(raw, &p) != nil || p.RealmID != realmID || !s.Clock.Now().Before(p.ExpiresAt) {
		return Pending{}, ErrRequestExpired
	}
	return p, nil
}

// Drop は預かった要求を消す（トークンを渡した後）。
func (s *Service) Drop(ctx context.Context, rid string) error {
	return s.Cache.Delete(ctx, pendingKey(rid))
}
