// Package audit は監査ログのイベントとハッシュチェーンを扱う（design.md 6章）。
//
// Storage の監査ログは1本のハッシュチェーンにする。各レコードのハッシュは
// HMAC-SHA-256(監査の鍵, 前のハッシュ || ペイロード) で、ペイロードはイベントの正規化した JSON（ADR 0086）。
// 監査の鍵が無い構成と、鍵を入れる前のレコードは SHA-256(前のハッシュ || ペイロード)。
// 1件でも書き換えると、それ以降のハッシュが合わなくなる。鍵付きなら、DB を書き換えられる人でも鍵が無ければ作り直せない。
package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersion はイベントの形式のバージョン（公開の契約。design.md 11.10）。
const SchemaVersion = 1

// Result は操作の結果。
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

// Actor は操作の主体。
type Actor struct {
	Type string `json:"type"` // user / service_account / system / operator_cli
	ID   string `json:"id,omitempty"`
}

// Event は監査ログの1件（design.md 6.2）。
//
// IP と UserAgent は個人情報として扱い、外部出力（External）には含めない。記録するときは保持期間の後も残してよい形
// （TruncateIP、ClassifyUA）にし、全文は Client に暗号化して置く（ADR 0063）。
// Details には個人情報を入れない（必要なら ID で参照する）。
type Event struct {
	Version   int       `json:"v"`
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Result    Result    `json:"result"`
	Actor     Actor     `json:"actor"`
	RealmID   string    `json:"realm_id,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"` // 公開のセッション ID のみ
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	// Client は IP と User-Agent の全文の暗号文（shared/eventlog が書く）。外部出力には含めない。
	Client    string         `json:"client,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	// Chain は外部出力にだけ付ける、チェーン上の位置（ハッシュの対象外）。
	// 受け取る側（SIEM）は seq の欠けと hash の一致で、末尾の削除や書き換えを検出できる。
	Chain *ChainRef `json:"chain,omitempty"`
}

// ChainRef はチェーン上の位置。
type ChainRef struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"` // 16進
}

// Record はチェーンに載ったイベント。
type Record struct {
	Seq      int64  // 1 から始まる通し番号
	RealmID  string // 検索用の列。ペイロードの realm_id と一致することを Verify で確かめる
	PrevHash []byte // 先頭は Genesis
	Hash     []byte
	Payload  []byte // 正規化した JSON。検証はこれから行う
	// KeyID はハッシュを計算した監査の鍵の ID（ADR 0086）。空なら鍵なし（SHA-256）。
	KeyID string
}

// Checkpoint は保持期間で切り詰めた位置（design.md 6.5）。Seq 以下のレコードは消えていて、
// 検証は Seq+1 から Hash を前のハッシュとして始める。At は切り詰めた時刻。KeyID は最後に消したレコードの監査の鍵の ID
// （鍵付きなら、続きのレコードも鍵付きでなければならない。ADR 0086）。
type Checkpoint struct {
	Seq   int64
	Hash  []byte
	At    time.Time
	KeyID string
}

// Genesis は先頭のレコードの PrevHash。
var Genesis = make([]byte, sha256.Size)

// ErrChainBroken はチェーンの検証に失敗したことを表す。
var ErrChainBroken = errors.New("audit: hash chain broken")

// Marshal はイベントを正規化した JSON にする。時刻は UTC に揃える。
func Marshal(e Event) ([]byte, error) {
	if e.Version == 0 {
		e.Version = SchemaVersion
	}
	e.Time = e.Time.UTC()
	e.Chain = nil
	// encoding/json は構造体のフィールドを定義順に、map のキーを昇順に出力するため、
	// 同じイベントは常に同じバイト列になる。
	return json.Marshal(e)
}

// Unmarshal はペイロードからイベントを復元する。
func Unmarshal(p []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.UseNumber()
	if err := dec.Decode(&e); err != nil {
		return Event{}, err
	}
	return e, nil
}

// Hash は鍵なしのチェーンのハッシュを計算する。
func Hash(prev, payload []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

// MAC は鍵付きのチェーンのハッシュを計算する（ADR 0086）。
func MAC(key, prev, payload []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

// Next は直前のレコード（無ければ nil）に続く、鍵なしのレコードを作る。
func Next(last *Record, e Event) (Record, error) { return NextKeyed(last, e, "", nil) }

// NextKeyed は直前のレコードに続くレコードを、監査の鍵 key（ID は keyID）で作る。keyID が空なら鍵なし。
func NextKeyed(last *Record, e Event, keyID string, key []byte) (Record, error) {
	payload, err := Marshal(e)
	if err != nil {
		return Record{}, err
	}
	prev, seq := Genesis, int64(1)
	if last != nil {
		prev, seq = last.Hash, last.Seq+1
	}
	r := Record{Seq: seq, RealmID: e.RealmID, PrevHash: prev, Payload: payload, KeyID: keyID}
	if keyID == "" {
		r.Hash = Hash(prev, payload)
	} else {
		r.Hash = MAC(key, prev, payload)
	}
	return r, nil
}

// Verify は records が prev から連続した、鍵なしの正しいチェーンかを確かめる。
// prev は records[0] の直前のハッシュ（先頭からなら Genesis、切り詰め後はチェックポイント）。
// 戻り値は最後のハッシュ。鍵付きのレコードは Chain で確かめる。
func Verify(prev []byte, firstSeq int64, records []Record) ([]byte, error) {
	c := Chain{Prev: prev, Next: firstSeq}
	if err := c.Verify(records); err != nil {
		return nil, err
	}
	return c.Prev, nil
}

// Chain はチェーンを何回かに分けて確かめる途中の状態。Prev は次のレコードの直前のハッシュ、Next は次の seq。
// Keys は監査の鍵を ID で返す（nil なら鍵付きのレコードは確かめられない）。
type Chain struct {
	Prev []byte
	Next int64
	Keys func(keyID string) ([]byte, error)
	// Keyed は前のレコードが鍵付きだったこと（チェックポイントの KeyID から始める）。
	Keyed bool
}

// Verify は records が続きの正しいチェーンかを確かめ、状態を進める。鍵付きのレコードの後に鍵なしのレコードがあれば
// 壊れているとみなす（鍵の無い人が後ろを作り直して、鍵なしに戻すことを防ぐ）。
func (c *Chain) Verify(records []Record) error {
	for _, r := range records {
		if r.Seq != c.Next {
			return fmt.Errorf("%w: seq %d: want %d", ErrChainBroken, r.Seq, c.Next)
		}
		if !bytes.Equal(r.PrevHash, c.Prev) {
			return fmt.Errorf("%w: seq %d: prev hash mismatch", ErrChainBroken, r.Seq)
		}
		var want []byte
		switch {
		case r.KeyID == "" && c.Keyed:
			return fmt.Errorf("%w: seq %d: unkeyed record after keyed records", ErrChainBroken, r.Seq)
		case r.KeyID == "":
			want = Hash(c.Prev, r.Payload)
		case c.Keys == nil:
			return fmt.Errorf("%w: seq %d: audit key %q is not available", ErrChainBroken, r.Seq, r.KeyID)
		default:
			key, err := c.Keys(r.KeyID)
			if err != nil {
				return fmt.Errorf("%w: seq %d: audit key %q: %v", ErrChainBroken, r.Seq, r.KeyID, err)
			}
			want, c.Keyed = MAC(key, c.Prev, r.Payload), true
		}
		if !hmac.Equal(r.Hash, want) {
			return fmt.Errorf("%w: seq %d: hash mismatch", ErrChainBroken, r.Seq)
		}
		// 検索用の realm_id の列はハッシュの対象外なので、ペイロードと突き合わせる。
		e, err := Unmarshal(r.Payload)
		if err != nil {
			return fmt.Errorf("%w: seq %d: %v", ErrChainBroken, r.Seq, err)
		}
		if e.RealmID != r.RealmID {
			return fmt.Errorf("%w: seq %d: realm_id column does not match payload", ErrChainBroken, r.Seq)
		}
		c.Prev, c.Next = r.Hash, c.Next+1
	}
	return nil
}

// External は外部出力（EventSink）向けに outbox へ積むイベント。全文の暗号文（Client）を外す。
// 切り詰めた IP と User-Agent の大分類は残し、出力先ごとに そのまま・仮名化・出さない を選ぶ
// （design.md 6.3、adapters/eventsink/sinkfmt、ADR 0071）。
func External(e Event) Event {
	e.Client = ""
	return e
}
