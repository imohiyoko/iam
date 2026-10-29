package sqlite

import (
	"context"
	"io"

	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/sqldump"
)

var _ port.Dumper = (*Storage)(nil)

var dialect = sqldump.Dialect{
	Placeholder: func(int) string { return "?" },
	// 表は作った順（参照される表が先）。
	Tables: func(ctx context.Context, q sqldump.Querier) ([]sqldump.Table, error) {
		rows, err := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'goose_db_version' ORDER BY rowid`)
		if err != nil {
			return nil, err
		}
		var names []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				_ = rows.Close()
				return nil, err
			}
			names = append(names, n)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		out := make([]sqldump.Table, 0, len(names))
		for _, n := range names {
			cols, err := columns(ctx, q, n)
			if err != nil {
				return nil, err
			}
			t := sqldump.Table{Name: n, Columns: cols}
			if n == "shared_outbox" {
				t.OrderBy = "created_at, rowid"
			}
			out = append(out, t)
		}
		return out, nil
	},
}

func columns(ctx context.Context, q sqldump.Querier, table string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// Export は中身を書き出す（BEGIN IMMEDIATE のトランザクションの中で。一貫した時点）。
func (s *Storage) Export(ctx context.Context, w io.Writer) (map[string]int, error) {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = t.Rollback() }()
	return sqldump.Export(ctx, t, dialect, w)
}

// Import は空の DB に読み込む（1つのトランザクションで）。
func (s *Storage) Import(ctx context.Context, r io.Reader) (map[string]int, error) {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = t.Rollback() }()
	stats, err := sqldump.Import(ctx, t, dialect, r)
	if err != nil {
		return nil, err
	}
	return stats, mapErr(t.Commit())
}
