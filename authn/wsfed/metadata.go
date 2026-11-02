package wsfed

import (
	"context"
	"encoding/base64"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/shared/port"
)

// フェデレーションのメタデータ（WS-Federation 1.2 の 3.1。SAML 2.0 のメタデータに fed:SecurityTokenServiceType の
// RoleDescriptor を入れたもの。ADR 0110）。

const (
	nsMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsFed      = "http://docs.oasis-open.org/wsfed/federation/200706"
	nsXSI      = "http://www.w3.org/2001/XMLSchema-instance"
	nsDSig     = "http://www.w3.org/2000/09/xmldsig#"
)

// metadata はメタデータの XML を組み立てて署名する。certs は KeyDescriptor に載せる証明書（DER）。
func metadata(id, issuer, endpoint string, certs [][]byte) *etree.Element {
	ed := etree.NewElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("ID", id)
	ed.CreateAttr("entityID", issuer)
	rd := ed.CreateElement("md:RoleDescriptor")
	rd.CreateAttr("xmlns:xsi", nsXSI)
	rd.CreateAttr("xmlns:fed", nsFed)
	rd.CreateAttr("xsi:type", "fed:SecurityTokenServiceType")
	rd.CreateAttr("protocolSupportEnumeration", nsFed)
	for _, c := range certs {
		kd := rd.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		ki := kd.CreateElement("KeyInfo")
		ki.CreateAttr("xmlns", nsDSig)
		ki.CreateElement("X509Data").CreateElement("X509Certificate").SetText(base64.StdEncoding.EncodeToString(c))
	}
	tt := rd.CreateElement("fed:TokenTypesOffered")
	tt.CreateElement("fed:TokenType").CreateAttr("Uri", TokenTypeSAML11)
	tt.CreateElement("fed:TokenType").CreateAttr("Uri", TokenTypeSAML20)
	for _, name := range []string{"fed:SecurityTokenServiceEndpoint", "fed:PassiveRequestorEndpoint"} {
		epr := rd.CreateElement(name).CreateElement("wsa:EndpointReference")
		epr.CreateAttr("xmlns:wsa", nsAddress)
		epr.CreateElement("wsa:Address").SetText(endpoint)
	}
	return ed
}

// Metadata はフェデレーションのメタデータ（署名付き）を返す。署名の鍵が無ければ作る。
func (s *Service) Metadata(ctx context.Context, realmID string) ([]byte, error) {
	mid, err := newAssertionID()
	if err != nil {
		return nil, err
	}
	var out []byte
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		key, certs, active, err := s.certificates(ctx, tx, realmID)
		if err != nil {
			return err
		}
		ed := metadata(mid, s.Issuer, s.Endpoint(), certs)
		if err := signAt(ed, key, active, "ID", 0); err != nil {
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
