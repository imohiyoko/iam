package samlidp

import (
	"context"
	"encoding/base64"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/shared/port"
)

// IdP のメタデータ（SAML Metadata 2.4.3 の IDPSSODescriptor。ADR 0115）。

func (s *Service) metadata(id string, certs [][]byte) *etree.Element {
	ed := etree.NewElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("ID", id)
	ed.CreateAttr("entityID", s.Issuer)
	d := ed.CreateElement("md:IDPSSODescriptor")
	// 署名を求めるかは SP ごと（require_signed_requests）なので、IdP 全体では求めない。
	d.CreateAttr("WantAuthnRequestsSigned", "false")
	d.CreateAttr("protocolSupportEnumeration", nsProtocol)
	for _, c := range certs {
		kd := d.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		ki := kd.CreateElement("ds:KeyInfo")
		ki.CreateAttr("xmlns:ds", samlxml.NSDSig)
		ki.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(c))
	}
	for _, b := range []string{BindingRedirect, BindingPOST} {
		e := d.CreateElement("md:SingleLogoutService")
		e.CreateAttr("Binding", b)
		e.CreateAttr("Location", s.SLOURL())
	}
	for _, f := range []string{NameIDPersistent, NameIDEmail, NameIDTransient, NameIDUnspecified} {
		d.CreateElement("md:NameIDFormat").SetText(f)
	}
	for _, b := range []string{BindingRedirect, BindingPOST} {
		e := d.CreateElement("md:SingleSignOnService")
		e.CreateAttr("Binding", b)
		e.CreateAttr("Location", s.SSOURL())
	}
	return ed
}

// Metadata は IdP のメタデータ（署名付き）を返す。署名の鍵が無ければ作る。
func (s *Service) Metadata(ctx context.Context, realmID string) ([]byte, error) {
	mid, err := newID()
	if err != nil {
		return nil, err
	}
	var out []byte
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		key, certs, active, err := s.certificates(ctx, tx, realmID)
		if err != nil {
			return err
		}
		ed := s.metadata(mid, certs)
		if err := samlxml.SignAt(ed, key, active, "ID", 0); err != nil {
			return err
		}
		doc := etree.NewDocument()
		doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
		doc.SetRoot(ed)
		out, err = doc.WriteToBytes()
		return err
	})
	return out, err
}
