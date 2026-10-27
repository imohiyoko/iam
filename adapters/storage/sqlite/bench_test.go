package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// BenchmarkPointLookup は ID による1件の取得を1トランザクションで行う。
// セッションの有効性のキャッシュに外れたときの検証（design.md 5.3）と、認可判定のクエリ（4.5）の
// 下限の目安にする。認可の判定は BenchmarkCheckMiss で測る。
func BenchmarkPointLookup(b *testing.B) {
	s := openTemp(b)
	defer s.Close()
	ctx := context.Background()
	var ids []string
	s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		for i := range 1000 {
			r := port.Realm{ID: id.New(id.Realm), Slug: "r" + id.New("x")[2:] + string(rune('a'+i%26)), Settings: []byte("{}"), CreatedAt: time.Now()}
			ids = append(ids, r.ID)
			if err := tx.Realms().Create(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	i := 0
	for b.Loop() {
		err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := tx.Realms().Get(ctx, ids[i%len(ids)])
			return err
		})
		if err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkAuditRecord は監査ログ1件の追記（ハッシュチェーン + outbox）を1トランザクションで行う。
func BenchmarkAuditRecord(b *testing.B) {
	s := openTemp(b)
	defer s.Close()
	ctx := context.Background()
	clk := clock.System{}
	realm := id.New(id.Realm)
	for b.Loop() {
		err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, clk, audit.Event{Type: "bench", Result: audit.ResultSuccess, RealmID: realm})
			return err
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCheckMiss は認可の判定を、判定の材料のキャッシュに外れた状態（毎回 DB から集める）で行う（design.md 4.5、ADR 0064）。
// 主体は realm の付与2件と、付与を持つ Group 2つに所属する。
func BenchmarkCheckMiss(b *testing.B) {
	s := openTemp(b)
	defer s.Close()
	ctx := context.Background()
	clk := clock.System{}
	realm := id.New(id.Realm)
	user := check.Principal{Type: port.PrincipalUser, ID: id.New(id.User)}
	err := s.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Realms().Create(ctx, port.Realm{ID: realm, Slug: "bench", Settings: []byte("{}"), CreatedAt: clk.Now()}); err != nil {
			return err
		}
		now := clk.Now()
		bind := func(roleKey string, t port.PrincipalType, pid string) error {
			return tx.RoleBindings().Create(ctx, port.RoleBinding{ID: id.New(id.RoleBinding), PublicID: id.NewExternal(id.RoleBinding), RealmID: realm,
				Role: roleKey, PrincipalType: t, PrincipalID: pid, CreatedAt: now})
		}
		for i := range 4 {
			r := port.Role{ID: id.New(id.Role), PublicID: id.NewExternal(id.Role), RealmID: realm, Name: "role" + string(rune('a'+i)),
				Permissions: []string{"doc:read", "doc:write", "project:" + string(rune('a'+i))}, CreatedAt: now, UpdatedAt: now}
			if err := tx.Roles().Create(ctx, r); err != nil {
				return err
			}
			if i < 2 {
				if err := bind(r.ID, user.Type, user.ID); err != nil {
					return err
				}
				continue
			}
			g := port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: realm, Name: r.Name, CreatedAt: now, UpdatedAt: now}
			if err := tx.Groups().Create(ctx, g); err != nil {
				return err
			}
			if err := tx.Groups().AddMember(ctx, realm, port.GroupMember{GroupID: g.ID, MemberType: user.Type, MemberID: user.ID, CreatedAt: now}); err != nil {
				return err
			}
			if err := bind(r.ID, port.PrincipalGroup, g.ID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	c := &check.Checker{Storage: s, Clock: clk}
	req := check.Request{Principal: user, Action: "project:d"}
	for b.Loop() {
		ok, err := c.Check(ctx, realm, req)
		if err != nil || !ok {
			b.Fatal(ok, err)
		}
	}
}
