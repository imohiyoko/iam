package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/vci"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID4VCI の管理 API と本人の API（ADR 0119）。

func vciDisplaysIn(ds *[]adminapi.VCIDisplay) []vci.Display {
	if ds == nil {
		return nil
	}
	out := make([]vci.Display, 0, len(*ds))
	for _, d := range *ds {
		x := vci.Display{Name: d.Name}
		if d.Locale != nil {
			x.Locale = *d.Locale
		}
		out = append(out, x)
	}
	return out
}

func vciDisplaysOut(ds []vci.Display) []adminapi.VCIDisplay {
	out := make([]adminapi.VCIDisplay, 0, len(ds))
	for _, d := range ds {
		x := adminapi.VCIDisplay{Name: d.Name}
		if d.Locale != "" {
			x.Locale = &d.Locale
		}
		out = append(out, x)
	}
	return out
}

func vciIn(b *adminapi.VCICredentialConfigurationInput) (vci.Input, error) {
	in := vci.Input{ConfigurationID: b.ConfigurationId, Format: b.Format, VCT: b.Vct, Display: vciDisplaysIn(b.Display)}
	if b.Scope != nil {
		in.Scope = *b.Scope
	}
	if b.RequireTxCode != nil {
		in.RequireTxCode = *b.RequireTxCode
	}
	if b.Validity != nil {
		if *b.Validity <= 0 || *b.Validity > int64(vci.MaxValidity/time.Second) {
			return vci.Input{}, errs.WithCode(errs.KindInvalid, "invalid_credential_configuration", "validity is out of range")
		}
		in.Validity = time.Duration(*b.Validity) * time.Second
	}
	for _, c := range b.Claims {
		x := vci.ClaimInput{Name: c.Name, Source: c.Source, SelectivelyDisclosable: c.SelectivelyDisclosable, Display: vciDisplaysIn(c.Display)}
		if c.Mandatory != nil {
			x.Mandatory = *c.Mandatory
		}
		if c.Value != nil {
			v, err := json.Marshal(c.Value)
			if err != nil {
				return vci.Input{}, errs.WithCode(errs.KindInvalid, "invalid_credential_configuration", "value is not JSON")
			}
			x.Value = v
		}
		in.Claims = append(in.Claims, x)
	}
	return in, nil
}

func vciOut(c port.VCICredentialConfiguration) (adminapi.VCICredentialConfiguration, error) {
	cfg, err := vci.Parse(c)
	if err != nil {
		return adminapi.VCICredentialConfiguration{}, err
	}
	out := adminapi.VCICredentialConfiguration{Id: c.ID, ConfigurationId: c.ConfigurationID, Format: cfg.Format, Vct: cfg.VCT,
		Display: vciDisplaysOut(cfg.Display), Claims: []adminapi.VCIClaim{}, Validity: cfg.ValiditySecs, RequireTxCode: cfg.RequireTxCode,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	if c.Scope != "" {
		out.Scope = &c.Scope
	}
	for _, x := range cfg.Claims {
		cl := adminapi.VCIClaim{Name: x.Name, Source: x.Source, SelectivelyDisclosable: x.SelectivelyDisclosable, Mandatory: x.Mandatory}
		if len(x.Display) > 0 {
			d := vciDisplaysOut(x.Display)
			cl.Display = &d
		}
		if len(x.Value) > 0 {
			var v any
			if err := json.Unmarshal(x.Value, &v); err != nil {
				return adminapi.VCICredentialConfiguration{}, err
			}
			cl.Value = v
		}
		out.Claims = append(out.Claims, cl)
	}
	return out, nil
}

// vciOp は perm を確かめ、フィーチャーが動いていれば fn を1つのトランザクションで実行する。成功なら status は 200。
func (s adminServer) vciOp(ctx context.Context, perm string, fn func(ctx context.Context, tx port.Tx, p adminPrincipal) error) (outcome, error) {
	p, d, err := s.a.authorize(ctx, perm)
	if o, ok, err := outcomeOf(d, err); !ok {
		return o, err
	}
	if s.a.vci == nil {
		return failed(http.StatusNotFound, "openid4vci_disabled"), nil
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return fn(ctx, tx, p) })
	var e *errs.Error
	if errors.Is(err, errs.Invalid) && errors.As(err, &e) {
		return outcome{status: http.StatusBadRequest, body: adminError(errCodeOr(err, "invalid_credential_configuration"), e.Msg)}, nil
	}
	if o, ok, err := outcomeOf(nil, err); !ok {
		return o, err
	}
	return outcome{status: http.StatusOK}, nil
}

func (s adminServer) ListVCICredentialConfigurations(ctx context.Context, _ adminapi.ListVCICredentialConfigurationsRequestObject) (adminapi.ListVCICredentialConfigurationsResponseObject, error) {
	out := adminapi.VCICredentialConfigurations{Configurations: []adminapi.VCICredentialConfiguration{}}
	o, err := s.vciOp(ctx, role.PermClientsManage, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		cs, err := tx.VCI().ListConfigurations(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, c := range cs {
			v, err := vciOut(c)
			if err != nil {
				return err
			}
			out.Configurations = append(out.Configurations, v)
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListVCICredentialConfigurations200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListVCICredentialConfigurations401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListVCICredentialConfigurations403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListVCICredentialConfigurations404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) CreateVCICredentialConfiguration(ctx context.Context, req adminapi.CreateVCICredentialConfigurationRequestObject) (adminapi.CreateVCICredentialConfigurationResponseObject, error) {
	var out adminapi.VCICredentialConfiguration
	o, err := s.vciOp(ctx, role.PermClientsManage, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_credential_configuration", "body is required")
		}
		in, err := vciIn(req.Body)
		if err != nil {
			return err
		}
		c, err := s.a.vci.Create(ctx, tx, s.a.realm.ID, in, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = vciOut(c)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.CreateVCICredentialConfiguration201JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.CreateVCICredentialConfiguration400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.CreateVCICredentialConfiguration401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.CreateVCICredentialConfiguration403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.CreateVCICredentialConfiguration404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.CreateVCICredentialConfiguration409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) GetVCICredentialConfiguration(ctx context.Context, req adminapi.GetVCICredentialConfigurationRequestObject) (adminapi.GetVCICredentialConfigurationResponseObject, error) {
	var out adminapi.VCICredentialConfiguration
	o, err := s.vciOp(ctx, role.PermClientsManage, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		c, err := tx.VCI().GetConfiguration(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		out, err = vciOut(c)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.GetVCICredentialConfiguration200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.GetVCICredentialConfiguration401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.GetVCICredentialConfiguration403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.GetVCICredentialConfiguration404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) UpdateVCICredentialConfiguration(ctx context.Context, req adminapi.UpdateVCICredentialConfigurationRequestObject) (adminapi.UpdateVCICredentialConfigurationResponseObject, error) {
	var out adminapi.VCICredentialConfiguration
	o, err := s.vciOp(ctx, role.PermClientsManage, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		if req.Body == nil {
			return errs.WithCode(errs.KindInvalid, "invalid_credential_configuration", "body is required")
		}
		old, err := tx.VCI().GetConfiguration(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		in, err := vciIn(req.Body)
		if err != nil {
			return err
		}
		c, err := s.a.vci.Update(ctx, tx, old, in, p.Actor, requestID(ctx))
		if err != nil {
			return err
		}
		out, err = vciOut(c)
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.UpdateVCICredentialConfiguration200JSONResponse(out), nil
	case o.status == http.StatusBadRequest:
		return adminapi.UpdateVCICredentialConfiguration400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.UpdateVCICredentialConfiguration401JSONResponse(o.body), nil
	case o.status == http.StatusForbidden:
		return adminapi.UpdateVCICredentialConfiguration403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.UpdateVCICredentialConfiguration404JSONResponse(o.body), nil
	case o.status == http.StatusConflict:
		return adminapi.UpdateVCICredentialConfiguration409JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) DeleteVCICredentialConfiguration(ctx context.Context, req adminapi.DeleteVCICredentialConfigurationRequestObject) (adminapi.DeleteVCICredentialConfigurationResponseObject, error) {
	o, err := s.vciOp(ctx, role.PermClientsManage, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		c, err := tx.VCI().GetConfiguration(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.vci.Delete(ctx, tx, c, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.DeleteVCICredentialConfiguration204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.DeleteVCICredentialConfiguration401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.DeleteVCICredentialConfiguration403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.DeleteVCICredentialConfiguration404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func vciRecordOut(c port.VCIIssuedCredential) adminapi.VCIIssuedCredential {
	return adminapi.VCIIssuedCredential{Id: c.ID, ConfigurationId: c.ConfigurationID, StatusIndex: c.StatusIndex, IssuedAt: c.IssuedAt,
		ExpiresAt: c.ExpiresAt, RevokedAt: c.RevokedAt}
}

func (s adminServer) ListVCICredentials(ctx context.Context, req adminapi.ListVCICredentialsRequestObject) (adminapi.ListVCICredentialsResponseObject, error) {
	out := adminapi.VCIIssuedCredentials{Credentials: []adminapi.VCIIssuedCredential{}}
	o, err := s.vciOp(ctx, role.PermCredentialsRevoke, func(ctx context.Context, tx port.Tx, _ adminPrincipal) error {
		u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Params.UserId)
		if err != nil {
			return err
		}
		cs, err := tx.VCI().ListCredentialsByUser(ctx, s.a.realm.ID, u.ID)
		for _, c := range cs {
			out.Credentials = append(out.Credentials, vciRecordOut(c))
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.ListVCICredentials200JSONResponse(out), nil
	case o.status == http.StatusUnauthorized:
		return adminapi.ListVCICredentials401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.ListVCICredentials403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.ListVCICredentials404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

func (s adminServer) RevokeVCICredential(ctx context.Context, req adminapi.RevokeVCICredentialRequestObject) (adminapi.RevokeVCICredentialResponseObject, error) {
	o, err := s.vciOp(ctx, role.PermCredentialsRevoke, func(ctx context.Context, tx port.Tx, p adminPrincipal) error {
		c, err := tx.VCI().GetCredential(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		return s.a.vci.Revoke(ctx, tx, c, p.Actor, requestID(ctx))
	})
	switch {
	case err != nil:
		return nil, err
	case o.status == http.StatusOK:
		return adminapi.RevokeVCICredential204Response{}, nil
	case o.status == http.StatusUnauthorized:
		return adminapi.RevokeVCICredential401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case o.status == http.StatusForbidden:
		return adminapi.RevokeVCICredential403JSONResponse(o.body), nil
	case o.status == http.StatusNotFound:
		return adminapi.RevokeVCICredential404JSONResponse(o.body), nil
	}
	return nil, errUnexpected(o)
}

// ---------------------------------------------------------------------------
// 本人の API

func (s publicServer) ListMyVerifiableCredentialConfigurations(ctx context.Context, _ publicapi.ListMyVerifiableCredentialConfigurationsRequestObject) (publicapi.ListMyVerifiableCredentialConfigurationsResponseObject, error) {
	if _, ok := authFrom(ctx); !ok {
		return publicapi.ListMyVerifiableCredentialConfigurations401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.vci == nil {
		return publicapi.ListMyVerifiableCredentialConfigurations404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	out := []publicapi.VerifiableCredentialConfiguration{}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.VCI().ListConfigurations(ctx, s.a.realm.ID)
		if err != nil {
			return err
		}
		for _, c := range cs {
			cfg, err := vci.Parse(c)
			if err != nil {
				return err
			}
			x := publicapi.VerifiableCredentialConfiguration{ConfigurationId: c.ConfigurationID, Vct: cfg.VCT, RequireTxCode: cfg.RequireTxCode}
			x.Display = make([]struct {
				Locale *string `json:"locale,omitempty"`
				Name   string  `json:"name"`
			}, 0, len(cfg.Display))
			for _, d := range cfg.Display {
				e := struct {
					Locale *string `json:"locale,omitempty"`
					Name   string  `json:"name"`
				}{Name: d.Name}
				if d.Locale != "" {
					e.Locale = &d.Locale
				}
				x.Display = append(x.Display, e)
			}
			out = append(out, x)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return publicapi.ListMyVerifiableCredentialConfigurations200JSONResponse{Configurations: out}, nil
}

func (s publicServer) CreateMyVerifiableCredentialOffer(ctx context.Context, req publicapi.CreateMyVerifiableCredentialOfferRequestObject) (publicapi.CreateMyVerifiableCredentialOfferResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CreateMyVerifiableCredentialOffer401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.vci == nil {
		return publicapi.CreateMyVerifiableCredentialOffer404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.CreateMyVerifiableCredentialOffer400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	if !s.recent(ctx, au, role.ActionMeVerifiableCredentials) {
		return publicapi.CreateMyVerifiableCredentialOffer401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	var o vci.Offer
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		o, err = s.a.vci.CreateOffer(ctx, tx, vci.OfferRequest{RealmID: s.a.realm.ID, UserID: au.PrincipalID, SID: au.SID,
			ConfigurationIDs: req.Body.CredentialConfigurationIds, TxCode: req.Body.TxCode != nil && *req.Body.TxCode}, au.Actor(), requestID(ctx))
		return err
	})
	if errors.Is(err, errs.Invalid) {
		return publicapi.CreateMyVerifiableCredentialOffer400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{
			Error: errCodeOr(err, "invalid_request")}}, nil
	}
	if err != nil {
		return nil, err
	}
	byValue, err := o.ByValueURI()
	if err != nil {
		return nil, err
	}
	out := publicapi.CreateMyVerifiableCredentialOffer201JSONResponse{CredentialOffer: o.Object, CredentialOfferUri: byValue,
		CredentialOfferReferenceUri: s.a.vci.ByReferenceURI(o.ID), ExpiresAt: o.ExpiresAt}
	if o.TxCode != "" {
		out.TxCode = &o.TxCode
	}
	return out, nil
}

func (s publicServer) ListMyVerifiableCredentials(ctx context.Context, _ publicapi.ListMyVerifiableCredentialsRequestObject) (publicapi.ListMyVerifiableCredentialsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyVerifiableCredentials401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.vci == nil {
		return publicapi.ListMyVerifiableCredentials404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	out := []publicapi.VerifiableCredential{}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.VCI().ListCredentialsByUser(ctx, s.a.realm.ID, au.PrincipalID)
		for _, c := range cs {
			out = append(out, publicapi.VerifiableCredential{Id: c.ID, ConfigurationId: c.ConfigurationID, IssuedAt: c.IssuedAt,
				ExpiresAt: c.ExpiresAt, RevokedAt: c.RevokedAt})
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return publicapi.ListMyVerifiableCredentials200JSONResponse{Credentials: out}, nil
}

func (s publicServer) RevokeMyVerifiableCredential(ctx context.Context, req publicapi.RevokeMyVerifiableCredentialRequestObject) (publicapi.RevokeMyVerifiableCredentialResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.RevokeMyVerifiableCredential401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.vci == nil {
		return publicapi.RevokeMyVerifiableCredential404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		c, err := tx.VCI().GetCredential(ctx, s.a.realm.ID, req.Id)
		if err != nil {
			return err
		}
		if c.UserID != au.PrincipalID {
			return errs.New(errs.KindNotFound, "vci issued credential")
		}
		return s.a.vci.Revoke(ctx, tx, c, au.Actor(), requestID(ctx))
	})
	if errors.Is(err, errs.NotFound) {
		return publicapi.RevokeMyVerifiableCredential404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RevokeMyVerifiableCredential204Response{}, nil
}
