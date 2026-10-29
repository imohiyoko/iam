// Package sqldump は SQL の Storage（SQLite・PostgreSQL）の中身を、アダプタに依らない形で書き出し・読み込む
// （`iam storage export / import`。design.md 2.4、ADR 0068）。
//
// 2つのアダプタは同じスキーマ（表と列の名前、TEXT・BLOB/BYTEA・INTEGER/BIGINT。ADR 0067）を持つので、表ごとの行を
// そのまま運べる。形式は JSON Lines：1行目がヘッダー（形式の版と表・列の一覧）、続いて1行に1行（表の名前と値）。
// 値は null、整数（JSON の数）、文字列、バイト列（{"b": base64}）のどれか。読み込み先は空でなければならない。
package sqldump

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Format は形式の版。
const Format = "iam-storage-dump/v1"

// Table は表の名前と、運ぶ列（並びは書き出したとき）。
type Table struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	// OrderBy は書き出す行の並び（SQL の ORDER BY の中身。空なら1列目）。ヘッダーには出さない。
	OrderBy string `json:"-"`
}

// Dialect はアダプタごとの違い。
type Dialect struct {
	// Tables は運ぶ表を、読み込める順（参照される表を先）に返す。
	Tables func(ctx context.Context, q Querier) ([]Table, error)
	// Placeholder は i 番目（1から）の引数の書き方（? か $i）。
	Placeholder func(i int) string
}

// Querier は *sql.Tx と *sql.DB。
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type header struct {
	Format string  `json:"format"`
	Tables []Table `json:"tables"`
}

type line struct {
	T string            `json:"t"`
	V []json.RawMessage `json:"v"`
}

type bytesValue struct {
	B string `json:"b"`
}

// Stats は運んだ件数。
type Stats map[string]int

// Export は q（一貫した読み取りのできるトランザクション）の全部の表を w に書く。
func Export(ctx context.Context, q Querier, d Dialect, w io.Writer) (Stats, error) {
	tables, err := d.Tables(ctx, q)
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	if err := enc.Encode(header{Format: Format, Tables: tables}); err != nil {
		return nil, err
	}
	stats := Stats{}
	for _, t := range tables {
		order := t.OrderBy
		if order == "" {
			order = quote(t.Columns[0])
		}
		rows, err := q.QueryContext(ctx, "SELECT "+columnList(t.Columns)+" FROM "+quote(t.Name)+" ORDER BY "+order) // #nosec G202 -- 名前はスキーマから
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", t.Name, err)
		}
		n, err := exportRows(rows, enc, t)
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", t.Name, err)
		}
		stats[t.Name] = n
	}
	return stats, bw.Flush()
}

func exportRows(rows *sql.Rows, enc *json.Encoder, t Table) (int, error) {
	defer rows.Close()
	n := 0
	vals := make([]any, len(t.Columns))
	ptrs := make([]any, len(t.Columns))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		l := line{T: t.Name, V: make([]json.RawMessage, len(vals))}
		for i, v := range vals {
			b, err := encodeValue(v)
			if err != nil {
				return n, fmt.Errorf("column %s: %w", t.Columns[i], err)
			}
			l.V[i] = b
		}
		if err := enc.Encode(l); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func encodeValue(v any) (json.RawMessage, error) {
	switch x := v.(type) {
	case nil:
		return json.RawMessage("null"), nil
	case int64:
		return json.Marshal(x)
	case string:
		return json.Marshal(x)
	case []byte:
		return json.Marshal(bytesValue{B: base64.StdEncoding.EncodeToString(x)})
	}
	return nil, fmt.Errorf("unsupported value type %T", v)
}

func decodeValue(b json.RawMessage) (any, error) {
	switch {
	case string(b) == "null":
		return nil, nil
	case len(b) > 0 && b[0] == '"':
		var s string
		err := json.Unmarshal(b, &s)
		return s, err
	case len(b) > 0 && b[0] == '{':
		var x bytesValue
		if err := json.Unmarshal(b, &x); err != nil {
			return nil, err
		}
		v, err := base64.StdEncoding.DecodeString(x.B)
		if v == nil {
			v = []byte{}
		}
		return v, err
	}
	var n int64
	err := json.Unmarshal(b, &n)
	return n, err
}

// ErrNotEmpty は読み込み先に行があること。
var ErrNotEmpty = errors.New("sqldump: target storage is not empty")

// Import は r を q（トランザクション）に読み込む。読み込み先の表と列が書き出し元と一致し、空でなければならない。
func Import(ctx context.Context, q Querier, d Dialect, r io.Reader) (Stats, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("sqldump: empty input")
	}
	var h header
	if err := json.Unmarshal(sc.Bytes(), &h); err != nil || h.Format != Format {
		return nil, fmt.Errorf("sqldump: not a %s file", Format)
	}
	target, err := d.Tables(ctx, q)
	if err != nil {
		return nil, err
	}
	if err := sameSchema(h.Tables, target); err != nil {
		return nil, err
	}
	for _, t := range target {
		has, err := hasRows(ctx, q, t.Name)
		if err != nil {
			return nil, err
		}
		if has {
			return nil, fmt.Errorf("%w (%s)", ErrNotEmpty, t.Name)
		}
	}
	inserts := map[string]string{}
	cols := map[string]int{}
	for _, t := range h.Tables {
		ph := make([]string, len(t.Columns))
		for i := range ph {
			ph[i] = d.Placeholder(i + 1)
		}
		inserts[t.Name] = "INSERT INTO " + quote(t.Name) + " (" + columnList(t.Columns) + ") VALUES (" + strings.Join(ph, ", ") + ")"
		cols[t.Name] = len(t.Columns)
	}
	stats := Stats{}
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("sqldump: line %d: %w", sum(stats)+2, err)
		}
		stmt, ok := inserts[l.T]
		if !ok || len(l.V) != cols[l.T] {
			return nil, fmt.Errorf("sqldump: line %d: unknown table or column count (%s)", sum(stats)+2, l.T)
		}
		args := make([]any, len(l.V))
		for i, b := range l.V {
			if args[i], err = decodeValue(b); err != nil {
				return nil, fmt.Errorf("sqldump: line %d: %w", sum(stats)+2, err)
			}
		}
		if _, err := q.ExecContext(ctx, stmt, args...); err != nil {
			return nil, fmt.Errorf("sqldump: import %s: %w", l.T, err)
		}
		stats[l.T]++
	}
	return stats, sc.Err()
}

func sameSchema(src, dst []Table) error {
	want := map[string][]string{}
	for _, t := range dst {
		c := slices.Clone(t.Columns)
		slices.Sort(c)
		want[t.Name] = c
	}
	if len(src) != len(dst) {
		return fmt.Errorf("sqldump: schema mismatch: %d tables in the file, %d in the target (run the same version)", len(src), len(dst))
	}
	for _, t := range src {
		c := slices.Clone(t.Columns)
		slices.Sort(c)
		if w, ok := want[t.Name]; !ok || !slices.Equal(w, c) {
			return fmt.Errorf("sqldump: schema mismatch at table %s (run the same version)", t.Name)
		}
	}
	return nil
}

func sum(s Stats) int {
	n := 0
	for _, v := range s {
		n += v
	}
	return n
}

func quote(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

func columnList(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = quote(c)
	}
	return strings.Join(q, ", ")
}

// hasRows は表に行があるかを返す（読み出しの失敗を空と取り違えない）。
func hasRows(ctx context.Context, q Querier, table string) (bool, error) {
	rows, err := q.QueryContext(ctx, "SELECT 1 FROM "+quote(table)+" LIMIT 1") // #nosec G202 -- 名前はスキーマから
	if err != nil {
		return false, err
	}
	defer rows.Close()
	has := rows.Next()
	return has, rows.Err()
}
