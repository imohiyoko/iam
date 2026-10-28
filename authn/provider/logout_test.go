package provider_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// downStorage は Tx がいつも失敗する保存先（一時的な障害）。
type downStorage struct{ port.Storage }

func (downStorage) Tx(context.Context, func(context.Context, port.Tx) error) error {
	return errors.New("storage down")
}

// 読めないメッセージは送らずに終え、保存先の一時的な失敗は、あきらめるまで残して次の送出でまた試す。
func TestLogoutDelivererRetriesTransientErrors(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := clock.NewFake(now)
	d := &provider.LogoutDeliverer{Storage: downStorage{}, Clock: c, GiveUp: time.Hour}
	msgs := []port.OutboxMessage{
		{ID: "bad", Topic: provider.LogoutTopic, Payload: []byte("{"), CreatedAt: now},
		{ID: "ok", Topic: provider.LogoutTopic, Payload: []byte(`{}`), CreatedAt: now},
	}
	done, err := d.Deliver(context.Background(), msgs)
	if err != nil || !slices.Equal(done, []string{"bad"}) {
		t.Fatalf("done = %v, %v", done, err)
	}
	c.Advance(time.Hour)
	if done, err := d.Deliver(context.Background(), msgs[1:]); err != nil || !slices.Equal(done, []string{"ok"}) {
		t.Fatalf("after give up: %v, %v", done, err)
	}
}
