// Package api は OpenAPI の定義を置く。公開 API・管理 API の契約の正はここにある（ADR 0039）。
package api

//go:generate oapi-codegen -config oapi-public.yaml public.yaml
//go:generate oapi-codegen -config oapi-admin.yaml admin.yaml
