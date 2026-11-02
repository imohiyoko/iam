package saml

import (
	"testing"
)

// FuzzVerify は応答の解析と検証に任意の入力を与え、panic せず、受けたなら必要な値が揃っていることを確かめる（design.md 13 章）。
func FuzzVerify(f *testing.F) {
	f.Add(testIdP.Sign(goodResponse()))
	r := goodResponse()
	r.SignResponse = true
	f.Add(testIdP.Sign(r))
	f.Add([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE a [<!ENTITY b "c">]><a>&b;</a>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := Verify(raw, expect())
		if err == nil && (a.ID == "" || a.NameID == "" || a.Expires.IsZero()) {
			t.Fatalf("accepted an incomplete assertion: %+v", a)
		}
	})
}

// FuzzParseIdPMetadata は IdP のメタデータの解析に任意の入力を与え、panic せず、受けたなら必要な値が揃っていることを確かめる。
func FuzzParseIdPMetadata(f *testing.F) {
	f.Add(testIdP.Metadata())
	f.Add([]byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntitiesDescriptor>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		md, err := ParseIdPMetadata(raw, "", false)
		if err == nil && (md.EntityID == "" || md.SSOURL == "" || len(md.Certs) == 0) {
			t.Fatalf("accepted incomplete metadata: %+v", md)
		}
	})
}
