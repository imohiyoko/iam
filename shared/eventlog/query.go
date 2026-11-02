package eventlog

import (
	"context"
	"errors"
	"strconv"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの照会と、範囲を指定したチェーンの検証（ADR 0100）。

// OrgAuditLogFeature は Org の管理者が自分の Org の監査ログを読むフィーチャー（ADR 0100）。データは持たない。
var OrgAuditLogFeature = feature.Feature{Name: feature.OrgAuditLog, DataVersion: 1, Requires: []string{feature.Org}}

// MaxPage は照会の1回の件数の上限。
const MaxPage = 200

// MaxVerifyRange は1回の検証で確かめるレコードの数の上限。
const MaxVerifyRange = 100_000

// Entry は照会で返す1件。
type Entry struct {
	Seq   int64
	Hash  []byte
	Event audit.Event
}

// ErrInvalidCursor はページングのカーソルが読めないこと。
var ErrInvalidCursor = errors.New("eventlog: invalid cursor")

// Cursor は次のページのカーソル（seq を文字列にしたもの。この seq より古いものを返す）。
func Cursor(seq int64) string { return strconv.FormatInt(seq, 10) }

// ParseCursor は Cursor を読む。空なら 0（最新から）。
func ParseCursor(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, ErrInvalidCursor
	}
	return n, nil
}

// Query は q で絞り込んだイベントを新しい順に返す。続きがあれば next（次の q.BeforeSeq）が正になる。
//
// 索引の列は書き換えられてもチェーンの検証で気付けないため、返す前にペイロードを読み、realm と条件を突き合わせ直す
// （合わないものは返さない。Org の範囲の照会で、別の Org のイベントを見せないため）。
func Query(ctx context.Context, tx port.Tx, q port.AuditQuery) (entries []Entry, next int64, err error) {
	if q.Limit <= 0 || q.Limit > MaxPage {
		q.Limit = MaxPage
	}
	limit := q.Limit
	q.Limit++
	rs, err := tx.Audit().Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	if len(rs) > limit {
		rs, next = rs[:limit], rs[limit-1].Seq
	}
	entries = make([]Entry, 0, len(rs))
	for _, r := range rs {
		if e, ok := match(r, q.RealmID, q.Filter); ok {
			entries = append(entries, Entry{Seq: r.Seq, Hash: r.Hash, Event: e})
		}
	}
	return entries, next, nil
}

// Get はイベント ID の1件を返す。無ければ（保持期間で消したものを含む）errs.NotFound。
func Get(ctx context.Context, tx port.Tx, realmID, eventID string) (Entry, error) {
	r, err := tx.Audit().GetByEventID(ctx, realmID, eventID)
	if err != nil {
		return Entry{}, err
	}
	e, ok := match(r, realmID, audit.Filter{})
	if !ok || e.ID != eventID {
		return Entry{}, errs.New(errs.KindNotFound, "audit event")
	}
	return Entry{Seq: r.Seq, Hash: r.Hash, Event: e}, nil
}

func match(r audit.Record, realmID string, f audit.Filter) (audit.Event, bool) {
	e, err := audit.Unmarshal(r.Payload)
	if err != nil || r.RealmID != realmID || e.RealmID != realmID || !f.Matches(e) {
		return audit.Event{}, false
	}
	return e, true
}

// RangeResult は範囲の検証の結果。
type RangeResult struct {
	// FromSeq・ToSeq は確かめた範囲（ToSeq < FromSeq なら空）。
	FromSeq, ToSeq int64
	// PrevHash は FromSeq の前のハッシュ。Anchored なら先頭（Genesis）かチェックポイントのハッシュで、
	// そうでなければ FromSeq のレコードが持つ前のハッシュ（呼び出し側が前の範囲の LastHash と突き合わせる）。
	PrevHash []byte
	Anchored bool
	// LastHash は ToSeq のハッシュ（壊れていれば nil）。
	LastHash []byte
	// Checkpoint は保持期間で切り詰めた位置。HeadSeq はチェーンの最新の seq。
	Checkpoint *audit.Checkpoint
	HeadSeq    int64
	// Broken は検証に失敗した位置と理由。成功なら nil。
	Broken *audit.BrokenError
}

// ErrRangeTooLarge は範囲が MaxVerifyRange を超えること。
var ErrRangeTooLarge = errors.New("eventlog: verify range too large")

// ErrTruncatedDuringVerify は検証の途中で、保持期間の掃除が範囲の先頭を消したこと（やり直せばよい）。
var ErrTruncatedDuringVerify = errors.New("eventlog: audit log truncated during verification")

// VerifyRange は seq の範囲 [from, to] のチェーンを確かめる（全 realm の1本のチェーン）。from が 0 か切り詰めた位置以前なら
// 残っている先頭から、to が 0 か最新より後なら最新まで。範囲が MaxVerifyRange を超えれば ErrRangeTooLarge。
// s が ClientSealer を通した Storage なら、その監査の鍵で鍵付きのレコードも確かめる（ADR 0086）。
func VerifyRange(ctx context.Context, s port.Storage, from, to int64) (RangeResult, error) {
	const page = 500
	var res RangeResult
	c, err := newChain(ctx, s)
	if err != nil {
		return res, err
	}
	first := int64(1)
	var before *audit.Record
	if err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cp, err := tx.Audit().Checkpoint(ctx)
		if err != nil {
			return err
		}
		res.Checkpoint, res.PrevHash = cp, audit.Genesis
		if cp != nil {
			first, res.PrevHash, c.Keyed = cp.Seq+1, cp.Hash, cp.KeyID != ""
		}
		last, err := tx.Audit().Last(ctx)
		if err != nil {
			return err
		}
		if last != nil {
			res.HeadSeq = last.Seq
		}
		// 途中から確かめるときは、直前のレコードが鍵付きかだけを借りる（そのハッシュは確かめない）。
		if from > first {
			rs, err := tx.Audit().Scan(ctx, from-1, 1)
			if err != nil {
				return err
			}
			if len(rs) == 1 && rs[0].Seq == from-1 {
				before = &rs[0]
			}
		}
		return nil
	}); err != nil {
		return res, err
	}
	if from < first {
		from = first
	}
	if to <= 0 || to > res.HeadSeq {
		to = res.HeadSeq
	}
	res.FromSeq, res.ToSeq = from, to
	res.Anchored = from == first
	if to < from {
		res.ToSeq = from - 1
		return res, nil
	}
	if to-from+1 > MaxVerifyRange {
		return res, ErrRangeTooLarge
	}
	c.Next, c.Prev = from, res.PrevHash
	if !res.Anchored {
		// 先頭に繋がらない範囲は、最初のレコードが持つ前のハッシュから始める（呼び出し側が前の範囲と突き合わせる）。
		c.Prev = nil
		if before != nil {
			c.Keyed = before.KeyID != ""
		}
	}
	for c.Next <= to {
		var rs []audit.Record
		if err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			rs, err = tx.Audit().Scan(ctx, c.Next, int(min(int64(page), to-c.Next+1)))
			return err
		}); err != nil {
			return res, err
		}
		if len(rs) == 0 {
			return res, truncatedOr(ctx, s, c.Next, &audit.BrokenError{Seq: c.Next, Reason: audit.BrokenSeqGap}, &res)
		}
		if c.Prev == nil {
			c.Prev = rs[0].PrevHash
			res.PrevHash = c.Prev
		}
		if err := c.Verify(rs); err != nil {
			be, ok := errors.AsType[*audit.BrokenError](err)
			if !ok {
				return res, err
			}
			return res, truncatedOr(ctx, s, be.Seq, be, &res)
		}
	}
	res.LastHash = c.Prev
	return res, nil
}

// truncatedOr は seq の位置での失敗が、検証の途中の切り詰めによるものなら ErrTruncatedDuringVerify を返し、
// そうでなければ res に失敗を書く。
func truncatedOr(ctx context.Context, s port.Storage, seq int64, broken *audit.BrokenError, res *RangeResult) error {
	var cp *audit.Checkpoint
	if err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		cp, err = tx.Audit().Checkpoint(ctx)
		return err
	}); err != nil {
		return err
	}
	if cp != nil && cp.Seq >= seq && (res.Checkpoint == nil || cp.Seq != res.Checkpoint.Seq) {
		return ErrTruncatedDuringVerify
	}
	res.Broken, res.LastHash = broken, nil
	return nil
}
