package postgres

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/sqldump"
)

var _ port.Dumper = (*Storage)(nil)

var dialect = sqldump.Dialect{
	Placeholder: func(i int) string { return fmt.Sprintf("$%d", i) },
	// 表は名前の順で、外部キーで参照される表を先にする。outbox の ord は PostgreSQL だけの列なので運ばない
	// （読み込んだ順に振り直される）。
	Tables: func(ctx context.Context, q sqldump.Querier) ([]sqldump.Table, error) {
		rows, err := q.QueryContext(ctx, `
SELECT c.table_name, c.column_name,
       EXISTS (SELECT 1 FROM information_schema.constraint_column_usage u
               JOIN information_schema.table_constraints tc ON tc.constraint_name = u.constraint_name AND tc.constraint_schema = u.constraint_schema
               WHERE tc.constraint_type = 'FOREIGN KEY' AND u.table_schema = c.table_schema AND u.table_name = c.table_name) AS referenced
FROM information_schema.columns c
JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
WHERE c.table_schema = current_schema() AND c.table_name <> 'goose_db_version'
ORDER BY c.table_name, c.ordinal_position`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []sqldump.Table
		ref := map[string]bool{}
		for rows.Next() {
			var table, col string
			var referenced bool
			if err := rows.Scan(&table, &col, &referenced); err != nil {
				return nil, err
			}
			if len(out) == 0 || out[len(out)-1].Name != table {
				t := sqldump.Table{Name: table}
				if table == "shared_outbox" {
					t.OrderBy = "created_at, ord"
				}
				out = append(out, t)
				ref[table] = referenced
			}
			if table == "shared_outbox" && col == "ord" {
				continue
			}
			out[len(out)-1].Columns = append(out[len(out)-1].Columns, col)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		slices.SortStableFunc(out, func(a, b sqldump.Table) int {
			switch {
			case ref[a.Name] && !ref[b.Name]:
				return -1
			case !ref[a.Name] && ref[b.Name]:
				return 1
			}
			return 0
		})
		return out, nil
	},
}

// Export は中身を書き出す（advisory lock を取ったトランザクションの中で。書き込みと直列なので一貫した時点）。
func (s *Storage) Export(ctx context.Context, w io.Writer) (map[string]int, error) {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = t.Rollback() }()
	if _, err := t.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, txLockKey); err != nil {
		return nil, mapErr(err)
	}
	return sqldump.Export(ctx, t, dialect, w)
}

// Import は空の DB に読み込む（1つのトランザクションで）。
func (s *Storage) Import(ctx context.Context, r io.Reader) (map[string]int, error) {
	t, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = t.Rollback() }()
	if _, err := t.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, txLockKey); err != nil {
		return nil, mapErr(err)
	}
	stats, err := sqldump.Import(ctx, t, dialect, r)
	if err != nil {
		return nil, err
	}
	return stats, mapErr(t.Commit())
}
