package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// IdP のメタデータの読み取りと、SP のメタデータの組み立て（SAML Metadata）。

const (
	maxMetadataBytes = 1 << 20
	maxIdPCerts      = 5
)

// IdPMetadata は IdP のメタデータのうち使うもの。
type IdPMetadata struct {
	EntityID string
	// SSOURL は HTTP-Redirect の SingleSignOnService。
	SSOURL string
	Certs  []*x509.Certificate
}

// mdNode はメタデータの要素（EntitiesDescriptor・EntityDescriptor と、その子）。
type mdNode struct {
	XMLName  xml.Name
	EntityID string     `xml:"entityID,attr"`
	IDPSSO   []mdIDPSSO `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	Children []mdNode   `xml:",any"`
}

type mdIDPSSO struct {
	Protocols string       `xml:"protocolSupportEnumeration,attr"`
	Keys      []mdKey      `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	SSO       []mdEndpoint `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
}

type mdKey struct {
	Use   string   `xml:"use,attr"`
	Certs []string `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo>X509Data>X509Certificate"`
}

type mdEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// ParseIdPMetadata は IdP のメタデータ（EntityDescriptor か、それを含む EntitiesDescriptor）を読む。
// entityID が空なら IdP の EntityDescriptor はちょうど 1 つであること。メタデータの署名は確かめない
// （登録する人が XML を渡すか、TLS で取得する。ADR 0098）。dev でなければ SSO の URL は https に限る。
func ParseIdPMetadata(raw []byte, entityID string, dev bool) (IdPMetadata, error) {
	if len(raw) > maxMetadataBytes {
		return IdPMetadata{}, errors.New("metadata too large")
	}
	if err := scanMetadata(raw); err != nil {
		return IdPMetadata{}, err
	}
	var root mdNode
	if err := xml.Unmarshal(raw, &root); err != nil {
		return IdPMetadata{}, fmt.Errorf("metadata: %w", err)
	}
	if root.XMLName.Space != nsMetadata || (root.XMLName.Local != "EntityDescriptor" && root.XMLName.Local != "EntitiesDescriptor") {
		return IdPMetadata{}, errors.New("metadata: not an EntityDescriptor")
	}
	var found []mdNode
	var walk func(e mdNode)
	walk = func(e mdNode) {
		if e.XMLName.Space != nsMetadata {
			return
		}
		switch e.XMLName.Local {
		case "EntityDescriptor":
			if len(e.IDPSSO) > 0 && (entityID == "" || e.EntityID == entityID) {
				found = append(found, e)
			}
		case "EntitiesDescriptor":
			for _, n := range e.Children {
				walk(n)
			}
		}
	}
	walk(root)
	if len(found) != 1 {
		return IdPMetadata{}, errors.New("metadata: specify entity_id; the metadata must describe exactly one IdP")
	}
	e := found[0]
	if e.EntityID == "" || len(e.EntityID) > 1024 {
		return IdPMetadata{}, errors.New("metadata: invalid entityID")
	}
	out := IdPMetadata{EntityID: e.EntityID}
	for _, d := range e.IDPSSO {
		if !slices.Contains(strings.Fields(d.Protocols), nsProtocol) {
			continue
		}
		for _, s := range d.SSO {
			if s.Binding == bindingRedirect && out.SSOURL == "" {
				out.SSOURL = s.Location
			}
		}
		for _, k := range d.Keys {
			if k.Use != "" && k.Use != "signing" {
				continue
			}
			for _, c := range k.Certs {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c), ""))
				if err != nil {
					return IdPMetadata{}, errors.New("metadata: invalid certificate")
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return IdPMetadata{}, fmt.Errorf("metadata: certificate: %w", err)
				}
				if !slices.ContainsFunc(out.Certs, cert.Equal) {
					out.Certs = append(out.Certs, cert)
				}
			}
		}
	}
	switch {
	case !okURL(out.SSOURL, dev):
		return IdPMetadata{}, errors.New("metadata: the IdP must have an https SingleSignOnService with the HTTP-Redirect binding")
	case len(out.Certs) == 0:
		return IdPMetadata{}, errors.New("metadata: the IdP has no signing certificate")
	case len(out.Certs) > maxIdPCerts:
		return IdPMetadata{}, errors.New("metadata: too many signing certificates")
	}
	return out, nil
}

// scanMetadata はメタデータの字句を確かめる（DOCTYPE を拒み、深さを限る）。
func scanMetadata(raw []byte) error {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("metadata: xml round trip: %w", err)
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	depth, elements := 0, 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("metadata: xml: %w", err)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			elements++
			if depth > maxDepth || elements > 4*maxElements {
				return errors.New("metadata: document too deep or too large")
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return errors.New("metadata: directives are not allowed")
		}
	}
}

func okURL(s string, dev bool) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && u.Fragment == "" && u.User == nil && len(s) <= 2048 && (u.Scheme == "https" || (dev && u.Scheme == "http"))
}

// SPMetadata は SP（この connection）のメタデータを組み立てる。
func SPMetadata(cfg Config) ([]byte, error) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDSig)
	ed.CreateAttr("entityID", cfg.SPEntityID)
	sp := ed.CreateElement("md:SPSSODescriptor")
	sp.CreateAttr("AuthnRequestsSigned", fmt.Sprint(cfg.SignRequests))
	sp.CreateAttr("WantAssertionsSigned", "true")
	sp.CreateAttr("protocolSupportEnumeration", nsProtocol)
	if len(cfg.SPCert) > 0 {
		kd := sp.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
			SetText(base64.StdEncoding.EncodeToString(cfg.SPCert))
	}
	if cfg.NameIDFormat != "" {
		sp.CreateElement("md:NameIDFormat").SetText(cfg.NameIDFormat)
	}
	acs := sp.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", bindingPOST)
	acs.CreateAttr("Location", cfg.ACSURL)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")
	doc.Indent(2)
	return doc.WriteToBytes()
}
