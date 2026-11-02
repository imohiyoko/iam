package audit

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// 監査ログの照会のための索引（ADR 0100）。
//
// 索引はペイロードから作る値で、ハッシュの対象外にする（チェーンの形は変えない）。Storage は追記のときに IndexOf で列を作り、
// 照会は索引で絞り込む。索引の列は書き換えられても検証で気付けないので、照会の結果は Matches でペイロードと突き合わせ直す。

// MaxRefLength は対象の ID（Refs）に入れる値の長さの上限。長い値は ID ではないとみなす。
const MaxRefLength = 200

// Index はペイロードから作る照会の索引。
type Index struct {
	EventID   string
	Unix      int64 // 時刻の UNIX 秒（切り捨て）
	Type      string
	Result    string
	ActorType string
	ActorID   string
	OrgID     string
	// Refs は対象の ID。details の、名前が _id で終わる文字列の値（重複なし、昇順）。
	Refs []string
}

// IndexOf はペイロードから索引を作る。マイグレーションの SQL（既存のレコードの埋め戻し）と同じ規則にする。
func IndexOf(payload []byte) (Index, error) {
	var p struct {
		ID     string                     `json:"id"`
		Time   time.Time                  `json:"time"`
		Type   string                     `json:"type"`
		Result string                     `json:"result"`
		Actor  Actor                      `json:"actor"`
		OrgID  string                     `json:"org_id"`
		Detail map[string]json.RawMessage `json:"details"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return Index{}, err
	}
	ix := Index{EventID: p.ID, Unix: p.Time.Unix(), Type: p.Type, Result: p.Result, ActorType: p.Actor.Type, ActorID: p.Actor.ID, OrgID: p.OrgID}
	for k, raw := range p.Detail {
		if !strings.HasSuffix(k, "_id") {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" || len(s) > MaxRefLength {
			continue
		}
		ix.Refs = append(ix.Refs, s)
	}
	slices.Sort(ix.Refs)
	ix.Refs = slices.Compact(ix.Refs)
	return ix, nil
}

// Filter は監査ログの照会の条件。空の項目は条件にしない。時刻は [Since, Until)。
type Filter struct {
	Since, Until time.Time
	// Type は種類の完全一致、TypePrefix は前方一致（"login." など）。
	Type, TypePrefix string
	Result           Result
	ActorType        string
	ActorID          string
	OrgID            string
	// Ref は対象の ID（details の *_id のどれか）。
	Ref string
}

// Matches はイベントが条件に合うかを、ペイロードから確かめる（索引の列を信じない）。
func (f Filter) Matches(e Event) bool {
	switch {
	case !f.Since.IsZero() && e.Time.Before(f.Since):
	case !f.Until.IsZero() && !e.Time.Before(f.Until):
	case f.Type != "" && e.Type != f.Type:
	case f.TypePrefix != "" && !strings.HasPrefix(e.Type, f.TypePrefix):
	case f.Result != "" && e.Result != f.Result:
	case f.ActorType != "" && e.Actor.Type != f.ActorType:
	case f.ActorID != "" && e.Actor.ID != f.ActorID:
	case f.OrgID != "" && e.OrgID != f.OrgID:
	case f.Ref != "" && !hasRef(e.Details, f.Ref):
	default:
		return true
	}
	return false
}

func hasRef(details map[string]any, ref string) bool {
	for k, v := range details {
		if s, ok := v.(string); ok && s == ref && strings.HasSuffix(k, "_id") {
			return true
		}
	}
	return false
}
