module github.com/imohiyoko/iam/cmd/iam

go 1.27.0

require (
	github.com/imohiyoko/iam v0.0.0
	github.com/imohiyoko/iam/adapters/storage/postgres v0.0.0
	github.com/imohiyoko/iam/adapters/storage/sqlite v0.0.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-chi/chi/v5 v5.3.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.18.2 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.11.0 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/jwx/v4 v4.6.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/muhlemmer/httpforwarded v0.1.0 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/oapi-codegen/runtime v1.8.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pressly/goose/v3 v3.29.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/sethvargo/go-retry v0.5.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zitadel/oidc/v3 v3.51.16 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.61.0 // indirect
)

replace (
	github.com/imohiyoko/iam => ../..
	github.com/imohiyoko/iam/adapters/storage/postgres => ../../adapters/storage/postgres
	github.com/imohiyoko/iam/adapters/storage/sqlite => ../../adapters/storage/sqlite
)
