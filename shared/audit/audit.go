// Package audit は監査ログのイベントとハッシュチェーンを扱う（design.md 6章）。
//
// Storage の監査ログは1本のハッシュチェーンにする。各レコードのハッシュは
// SHA-256(前のハッシュ || ペイロード) で、ペイロードはイベントの正規化した JSON。
// 1件でも書き換えると、それ以降のハッシュが合わなくなる。
package audit

import (
	"bytes"
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
// IP と UserAgent は個人情報として扱い、外部出力（External）には含めない。
// Details には個人情報を入れない（必要なら ID で参照する）。
type Event struct {
	Version   int            `json:"v"`
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Type      string         `json:"type"`
	Result    Result         `json:"result"`
	Actor     Actor          `json:"actor"`
	RealmID   string         `json:"realm_id,omitempty"`
	OrgID     string         `json:"org_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"` // 公開のセッション ID のみ
	IP        string         `json:"ip,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// Record はチェーンに載ったイベント。
type Record struct {
	Seq      int64  // 1 から始まる通し番号
	PrevHash []byte // 先頭は Genesis
	Hash     []byte
	Payload  []byte // 正規化した JSON。検証はこれから行う
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

// Hash はチェーンのハッシュを計算する。
func Hash(prev, payload []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

// Next は直前のレコード（無ければ nil）に続くレコードを作る。
func Next(last *Record, e Event) (Record, error) {
	payload, err := Marshal(e)
	if err != nil {
		return Record{}, err
	}
	prev, seq := Genesis, int64(1)
	if last != nil {
		prev, seq = last.Hash, last.Seq+1
	}
	return Record{Seq: seq, PrevHash: prev, Hash: Hash(prev, payload), Payload: payload}, nil
}

// Verify は records が prev から連続した正しいチェーンかを確かめる。
// prev は records[0] の直前のハッシュ（先頭からなら Genesis、切り詰め後はチェックポイント）。
// 戻り値は最後のハッシュ。
func Verify(prev []byte, firstSeq int64, records []Record) ([]byte, error) {
	for i, r := range records {
		if r.Seq != firstSeq+int64(i) {
			return nil, fmt.Errorf("%w: seq %d: want %d", ErrChainBroken, r.Seq, firstSeq+int64(i))
		}
		if !bytes.Equal(r.PrevHash, prev) {
			return nil, fmt.Errorf("%w: seq %d: prev hash mismatch", ErrChainBroken, r.Seq)
		}
		if !bytes.Equal(r.Hash, Hash(prev, r.Payload)) {
			return nil, fmt.Errorf("%w: seq %d: hash mismatch", ErrChainBroken, r.Seq)
		}
		prev = r.Hash
	}
	return prev, nil
}

// External は外部出力（EventSink）向けのイベント。個人情報を含めない。
// 仮名化などの出力先ごとの選択は M6 で追加する（design.md 6.3）。
func External(e Event) Event {
	e.IP = ""
	e.UserAgent = ""
	return e
}
