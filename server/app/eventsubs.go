package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// イベントの Webhook の購読（フィーチャー event_subscriptions。ADR 0100）。

type eventSubDelivery = struct {
	CursorSeq       int64      `json:"cursor_seq"`
	Failures        int        `json:"failures"`
	LastDeliveredAt *time.Time `json:"last_delivered_at,omitempty"`
	LastError       *string    `json:"last_error,omitempty"`
	NextAttemptAt   *time.Time `json:"next_attempt_at,omitempty"`
}

func eventSubOut(s port.EventSubscription) adminapi.EventSubscription {
	types := s.EventTypes
	if types == nil {
		types = []string{}
	}
	return adminapi.EventSubscription{Id: s.ID, Url: s.URL, EventTypes: types, Pii: adminapi.EventSubscriptionPii(s.PII), Enabled: s.Enabled,
		CreatedBy: strPtr(s.CreatedBy), CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
		Delivery: eventSubDelivery{CursorSeq: s.CursorSeq, Failures: s.Failures, LastDeliveredAt: s.LastDeliveredAt, LastError: strPtr(s.LastError),
			NextAttemptAt: s.NextAttemptAt}}
}

func eventSubWithSecret(s port.EventSubscription, secret string) adminapi.EventSubscriptionWithSecret {
	o := eventSubOut(s)
	return adminapi.EventSubscriptionWithSecret{Id: o.Id, Url: o.Url, EventTypes: o.EventTypes, Pii: adminapi.EventSubscriptionWithSecretPii(o.Pii),
		Enabled: o.Enabled, CreatedBy: o.CreatedBy, CreatedAt: o.CreatedAt, UpdatedAt: o.UpdatedAt, Delivery: o.Delivery, Secret: secret}
}

// eventSubsCall は権限とフィーチャーを確かめて fn を1つのトランザクションで実行する。成功なら status は 200。
func (s adminServer) eventSubsCall(ctx context.Context, fn func(ctx context.Context, tx port.Tx, a eventsub.Actor) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermEventSubscriptionsManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if s.a.eventSubs == nil {
		return failed(http.StatusNotFound, "event_subscriptions_disabled"), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return fn(ctx, tx, eventsub.Actor{Audit: p.Actor, RequestID: requestID(ctx)})
	})
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListEventSubscriptions(ctx context.Context, _ adminapi.ListEventSubscriptionsRequestObject) (adminapi.ListEventSubscriptionsResponseObject, error) {
	out := adminapi.ListEventSubscriptions200JSONResponse{Subscriptions: []adminapi.EventSubscription{}}
	o, err := s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, _ eventsub.Actor) error {
		subs, err := tx.EventSubscriptions().List(ctx, s.a.realm.ID)
		for _, sub := range subs {
			out.Subscriptions = append(out.Subscriptions, eventSubOut(sub))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return out, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListEventSubscriptions401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListEventSubscriptions403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListEventSubscriptions404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateEventSubscription(ctx context.Context, req adminapi.CreateEventSubscriptionRequestObject) (adminapi.CreateEventSubscriptionResponseObject, error) {
	var sub port.EventSubscription
	var secret string
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if b := req.Body; b != nil {
		in := eventsub.Input{URL: &b.Url, EventTypes: b.EventTypes, PII: (*string)(b.Pii), Enabled: b.Enabled}
		o, err = s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, a eventsub.Actor) error {
			sub, secret, err = s.a.eventSubs.Create(ctx, tx, s.a.realm.ID, in, a)
			return err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateEventSubscription201JSONResponse(eventSubWithSecret(sub, secret)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateEventSubscription400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateEventSubscription401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateEventSubscription403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateEventSubscription404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateEventSubscription409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetEventSubscription(ctx context.Context, req adminapi.GetEventSubscriptionRequestObject) (adminapi.GetEventSubscriptionResponseObject, error) {
	var sub port.EventSubscription
	o, err := s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, _ eventsub.Actor) error {
		var err error
		sub, err = tx.EventSubscriptions().Get(ctx, s.a.realm.ID, req.Id)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetEventSubscription200JSONResponse(eventSubOut(sub)), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetEventSubscription401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetEventSubscription403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetEventSubscription404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateEventSubscription(ctx context.Context, req adminapi.UpdateEventSubscriptionRequestObject) (adminapi.UpdateEventSubscriptionResponseObject, error) {
	var sub port.EventSubscription
	o := failed(http.StatusBadRequest, "invalid_request")
	var err error
	if b := req.Body; b != nil {
		in := eventsub.Input{URL: b.Url, EventTypes: b.EventTypes, PII: (*string)(b.Pii), Enabled: b.Enabled}
		o, err = s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, a eventsub.Actor) error {
			sub, err = s.a.eventSubs.Update(ctx, tx, s.a.realm.ID, req.Id, in, a)
			return err
		})
	}
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateEventSubscription200JSONResponse(eventSubOut(sub)), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateEventSubscription400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateEventSubscription401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateEventSubscription403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateEventSubscription404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteEventSubscription(ctx context.Context, req adminapi.DeleteEventSubscriptionRequestObject) (adminapi.DeleteEventSubscriptionResponseObject, error) {
	o, err := s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, a eventsub.Actor) error {
		return s.a.eventSubs.Delete(ctx, tx, s.a.realm.ID, req.Id, a)
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteEventSubscription204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteEventSubscription401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteEventSubscription403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteEventSubscription404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) RotateEventSubscriptionSecret(ctx context.Context, req adminapi.RotateEventSubscriptionSecretRequestObject) (adminapi.RotateEventSubscriptionSecretResponseObject, error) {
	var sub port.EventSubscription
	var secret string
	o, err := s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, a eventsub.Actor) error {
		var err error
		sub, secret, err = s.a.eventSubs.RotateSecret(ctx, tx, s.a.realm.ID, req.Id, a)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.RotateEventSubscriptionSecret200JSONResponse(eventSubWithSecret(sub, secret)), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.RotateEventSubscriptionSecret401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.RotateEventSubscriptionSecret403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.RotateEventSubscriptionSecret404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// TestEventSubscription は宛先にテストのイベントを送る。HTTP の要求はトランザクションの外で行う。
func (s adminServer) TestEventSubscription(ctx context.Context, req adminapi.TestEventSubscriptionRequestObject) (adminapi.TestEventSubscriptionResponseObject, error) {
	var sub port.EventSubscription
	var secret []byte
	var actor eventsub.Actor
	o, err := s.eventSubsCall(ctx, func(ctx context.Context, tx port.Tx, a eventsub.Actor) error {
		var err error
		if sub, err = tx.EventSubscriptions().Get(ctx, s.a.realm.ID, req.Id); err != nil {
			return err
		}
		actor = a
		secret, err = s.a.eventSubs.Secret(ctx, tx, sub)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusUnauthorized:
		return adminapi.TestEventSubscription401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.TestEventSubscription403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.TestEventSubscription404JSONResponse(o.body), nil
	case o.status != http.StatusOK:
		return nil, errUnexpected(o)
	}
	// 宛先への要求を繰り返させない（購読ごとの上限）。
	if err := s.a.eventSubTests.Allow(ctx, "evs-test:"+s.a.realm.ID+":"+sub.ID); err != nil {
		if _, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
			return adminapi.TestEventSubscription429JSONResponse(adminError(codeRateLimited, "")), nil
		}
		return nil, err
	}
	d := &eventsub.Deliverer{Storage: s.a.deps.Storage, Service: s.a.eventSubs, Clock: s.a.deps.Clock}
	res := d.Test(ctx, sub, secret)
	if err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return s.a.eventSubs.RecordTest(ctx, tx, sub, actor, res)
	}); err != nil {
		return nil, err
	}
	out := adminapi.TestEventSubscription200JSONResponse{Delivered: res.Delivered, Error: strPtr(res.Error)}
	if res.Status != 0 {
		out.Status = new(res.Status)
	}
	return out, nil
}
