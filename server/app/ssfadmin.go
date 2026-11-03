package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// SSF の管理 API（ADR 0118）：受信側が信頼する送信側の登録と、送信側のストリームの参照・削除。権限は ssf:manage。

// ssfOp は ssf:manage を確かめ、fn を1つのトランザクションで実行する。フィーチャーが動いていなければ 404 off。
func (s adminServer) ssfOp(ctx context.Context, active bool, off string, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, role.PermSSFManage)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if !active {
		return failed(http.StatusNotFound, off), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	if errors.Is(err, errs.Invalid) && errors.As(err, &e) {
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, "invalid_transmitter"), e.Msg)}, nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) rxOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	return s.ssfOp(ctx, s.a.ssfRx != nil && s.a.issuer != "", "ssf_receiver_disabled", fn)
}

func (s adminServer) txOp(ctx context.Context, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	return s.ssfOp(ctx, s.a.ssfTx != nil && s.a.issuer != "", "ssf_transmitter_disabled", fn)
}

func (s adminServer) ssfTransmitterOut(t port.SSFTransmitter, token string) adminapi.SSFTransmitter {
	cfg, _ := ssf.ConfigOf(t)
	out := adminapi.SSFTransmitter{Id: t.ID, Name: t.Name, Issuer: t.Issuer, Enabled: t.Enabled, Audience: nonNilStrings(cfg.Audience),
		AllowedActions: nonNilStrings(cfg.AllowedActions), PushEndpoint: s.a.issuer + ssfReceiverPrefix + t.ID, CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt, JwksUri: strPtr(cfg.JWKSURI), SubjectConnection: strPtr(cfg.SubjectConnection), PushToken: strPtr(token)}
	if len(cfg.JWKS) > 0 {
		var m map[string]any
		if json.Unmarshal(cfg.JWKS, &m) == nil {
			out.Jwks = &m
		}
	}
	return out
}

func ssfTransmitterIn(b *adminapi.SSFTransmitterInput) (ssf.TransmitterInput, error) {
	in := ssf.TransmitterInput{Name: b.Name, Issuer: b.Issuer, Enabled: b.Enabled == nil || *b.Enabled}
	in.Audience = b.Audience
	if b.JwksUri != nil {
		in.JWKSURI = *b.JwksUri
	}
	if b.Jwks != nil {
		raw, err := json.Marshal(*b.Jwks)
		if err != nil {
			return in, errs.WithCode(errs.KindInvalid, "invalid_transmitter", "jwks")
		}
		in.JWKS = raw
	}
	if b.AllowedActions != nil {
		for _, a := range *b.AllowedActions {
			in.AllowedActions = append(in.AllowedActions, string(a))
		}
	}
	if b.SubjectConnection != nil {
		in.SubjectConnection = *b.SubjectConnection
	}
	return in, nil
}

func (s adminServer) ListSSFTransmitters(ctx context.Context, _ adminapi.ListSSFTransmittersRequestObject) (adminapi.ListSSFTransmittersResponseObject, error) {
	out := adminapi.SSFTransmitters{Transmitters: []adminapi.SSFTransmitter{}}
	o, err := s.rxOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		ts, err := tx.SSFTransmitters().List(ctx, s.a.realm.ID)
		for _, t := range ts {
			out.Transmitters = append(out.Transmitters, s.ssfTransmitterOut(t, ""))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListSSFTransmitters200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListSSFTransmitters401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListSSFTransmitters403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListSSFTransmitters404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateSSFTransmitter(ctx context.Context, req adminapi.CreateSSFTransmitterRequestObject) (adminapi.CreateSSFTransmitterResponseObject, error) {
	var out adminapi.SSFTransmitter
	o, err := s.rxOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_transmitter", "body is required")
		}
		in, err := ssfTransmitterIn(req.Body)
		if err != nil {
			return err
		}
		t, tok, err := s.a.ssfRx.CreateTransmitter(ctx, tx, s.a.realm.ID, in, p.Actor, requestID(ctx))
		out = s.ssfTransmitterOut(t, tok)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateSSFTransmitter201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateSSFTransmitter400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateSSFTransmitter401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateSSFTransmitter403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateSSFTransmitter404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateSSFTransmitter409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetSSFTransmitter(ctx context.Context, req adminapi.GetSSFTransmitterRequestObject) (adminapi.GetSSFTransmitterResponseObject, error) {
	var out adminapi.SSFTransmitter
	o, err := s.rxOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		t, err := tx.SSFTransmitters().Get(ctx, s.a.realm.ID, req.Id)
		out = s.ssfTransmitterOut(t, "")
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetSSFTransmitter200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetSSFTransmitter401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetSSFTransmitter403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetSSFTransmitter404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateSSFTransmitter(ctx context.Context, req adminapi.UpdateSSFTransmitterRequestObject) (adminapi.UpdateSSFTransmitterResponseObject, error) {
	var out adminapi.SSFTransmitter
	o, err := s.rxOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_transmitter", "body is required")
		}
		in, err := ssfTransmitterIn(req.Body)
		if err != nil {
			return err
		}
		rotate := req.Body.RotatePushToken != nil && *req.Body.RotatePushToken
		t, tok, err := s.a.ssfRx.UpdateTransmitter(ctx, tx, s.a.realm.ID, req.Id, in, rotate, p.Actor, requestID(ctx))
		out = s.ssfTransmitterOut(t, tok)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateSSFTransmitter200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateSSFTransmitter400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateSSFTransmitter401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateSSFTransmitter403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateSSFTransmitter404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateSSFTransmitter409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteSSFTransmitter(ctx context.Context, req adminapi.DeleteSSFTransmitterRequestObject) (adminapi.DeleteSSFTransmitterResponseObject, error) {
	o, err := s.rxOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		return s.a.ssfRx.DeleteTransmitter(ctx, tx, s.a.realm.ID, req.Id, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteSSFTransmitter204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteSSFTransmitter401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteSSFTransmitter403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteSSFTransmitter404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func ssfStreamOut(x port.SSFStream) adminapi.SSFStream {
	out := adminapi.SSFStream{Id: x.ID, ServiceAccountId: x.ServiceAccountID, DeliveryMethod: adminapi.SSFStreamDeliveryMethod(x.DeliveryMethod),
		EventsDelivered: nonNilStrings(x.EventsDelivered), Description: strPtr(x.Description), Status: adminapi.SSFStreamStatus(x.Status),
		StatusReason: strPtr(x.StatusReason), CreatedAt: x.CreatedAt, UpdatedAt: x.UpdatedAt}
	if u, err := url.Parse(x.EndpointURL); err == nil && u.Host != "" {
		out.EndpointHost = &u.Host
	}
	out.Delivery.CursorSeq, out.Delivery.Failures, out.Delivery.LastError = x.CursorSeq, x.Failures, strPtr(x.LastError)
	out.Delivery.LastDeliveredAt, out.Delivery.NextAttemptAt = x.LastDeliveredAt, x.NextAttemptAt
	return out
}

func (s adminServer) ListSSFStreams(ctx context.Context, _ adminapi.ListSSFStreamsRequestObject) (adminapi.ListSSFStreamsResponseObject, error) {
	out := adminapi.SSFStreams{Streams: []adminapi.SSFStream{}}
	o, err := s.txOp(ctx, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		xs, err := tx.SSFStreams().List(ctx, s.a.realm.ID)
		for _, x := range xs {
			out.Streams = append(out.Streams, ssfStreamOut(x))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListSSFStreams200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListSSFStreams401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListSSFStreams403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListSSFStreams404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteSSFStream(ctx context.Context, req adminapi.DeleteSSFStreamRequestObject) (adminapi.DeleteSSFStreamResponseObject, error) {
	o, err := s.txOp(ctx, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		return s.a.ssfTx.AdminDelete(ctx, tx, s.a.realm.ID, req.Id, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteSSFStream204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteSSFStream401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteSSFStream403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteSSFStream404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}
