package app

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/vci"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID4VCI の発行者（フィーチャー openid4vci。ADR 0119）。OIDC Provider のハンドラが受ける。
//
//	GET  /.well-known/openid-credential-issuer  発行者のメタデータ
//	GET  /.well-known/jwt-vc-issuer             JWT VC Issuer Metadata（ES256 の公開鍵）
//	POST /oauth2/vci/nonce                      c_nonce
//	POST /oauth2/vci/credential                 資格情報の発行（proof 付き）
//	GET  /oauth2/vci/offers/{id}                参照で渡す申し出
//	GET  /oauth2/vci/status-list                status list token
//	POST /oauth2/token                          grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code

const (
	wellKnownCredentialIssuer = vci.MetadataPath
	wellKnownJWTVCIssuer      = vci.IssuerMetadataPath
)

// isVCIPath は OpenID4VCI のエンドポイントか（CORS はどのオリジンにも許す。Cookie は使わない）。
func isVCIPath(path string) bool {
	return path == wellKnownCredentialIssuer || path == wellKnownJWTVCIssuer || strings.HasPrefix(path, "/oauth2/vci/")
}

// registerVCI は OIDC Provider の mux に OpenID4VCI のエンドポイントを足す。
func (s *oidcServer) registerVCI(mux *http.ServeMux) {
	mux.HandleFunc(wellKnownCredentialIssuer, s.vciMetadata)
	mux.HandleFunc(wellKnownJWTVCIssuer, s.vciIssuerMetadata)
	mux.HandleFunc(vci.NoncePath, s.vciNonce)
	mux.Handle(vci.CredentialPath, s.a.withDPoPNonce(http.HandlerFunc(s.vciCredential)))
	mux.HandleFunc(vci.OfferPath, s.vciOffer)
	mux.HandleFunc(vci.StatusListPath, s.vciStatusList)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *oidcServer) vciMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	var out map[string]any
	err := s.a.deps.Storage.Tx(r.Context(), func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.vci.Metadata(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, out)
}

func (s *oidcServer) vciIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	var out map[string]any
	err := s.a.deps.Storage.Tx(r.Context(), func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = s.a.vci.IssuerMetadata(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, out)
}

func (s *oidcServer) vciNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	n, err := s.a.vci.Nonce(r.Context(), s.a.realm.ID)
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"c_nonce": n})
}

func (s *oidcServer) vciOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	o, err := s.a.vci.LookupOffer(r.Context(), strings.TrimPrefix(r.URL.Path, vci.OfferPath))
	if errors.Is(err, errs.NotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *oidcServer) vciStatusList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	var token string
	err := s.a.deps.Storage.Tx(r.Context(), func(ctx context.Context, tx port.Tx) error {
		var err error
		token, err = s.a.vci.StatusList(ctx, tx, s.a.realm.ID)
		return err
	})
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(vci.StatusListTTL/time.Second)))
	_, _ = io.WriteString(w, token)
}

// vciError は credential エンドポイントのエラー（OpenID4VCI 8.3.1.2）。
func vciError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

// vciCredential は credential エンドポイント。アクセストークンは Pre-Authorized Code のもの（vci_）か、Authorization Code Flow の
// OIDC のアクセストークン（UserInfo と同じ確かめ。結び付けた DPoP・証明書を含む）。
func (s *oidcServer) vciCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	ctx := r.Context()
	scheme, token := authorization(r.Header.Get("Authorization"))
	var g vci.Grant
	var err error
	if vci.IsAccessToken(token) {
		if scheme != "Bearer" {
			err = provider.ErrInvalidToken
		} else if g, err = s.a.vci.Bearer(ctx, s.a.realm.ID, token); err != nil {
			if code, _ := vci.CodeOf(err); code == vci.CodeInvalidToken {
				err = provider.ErrInvalidToken
			}
		}
	} else {
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			a, err := s.a.tokens.Validate(ctx, tx, s.a.realm.ID, token)
			if err != nil {
				return err
			}
			if provider.ResourceBound(a.Grant) {
				return provider.ErrInvalidToken
			}
			if err := s.a.checkResourceBinding(ctx, r, scheme, token, provider.TokenBinding(a.Token), s.endpointURLs(vci.CredentialPath)); err != nil {
				return err
			}
			g = vci.AuthorizationGrant(s.a.realm.ID, a.Grant.UserID, a.Client.PublicID, a.Grant.Scopes)
			return nil
		})
	}
	if eb, ok := errors.AsType[*errBinding](err); ok {
		s.a.challenge(w, eb.Code, "")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": eb.Code})
		return
	}
	if token == "" || errors.Is(err, provider.ErrInvalidToken) {
		s.a.challenge(w, "invalid_token", "")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	if mt, _, perr := mime.ParseMediaType(r.Header.Get("Content-Type")); perr != nil || mt != "application/json" {
		vciError(w, vci.CodeInvalidCredentialRequest)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, vci.MaxRequestSize))
	if err != nil {
		vciError(w, vci.CodeInvalidCredentialRequest)
		return
	}
	out, err := s.a.vci.Issue(ctx, g, body, requestID(ctx))
	if code, _ := vci.CodeOf(err); code != "" {
		vciError(w, code)
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": []map[string]string{{"credential": out.Credential}}})
}

// withPreAuthorizedToken は token エンドポイントの Pre-Authorized Code の grant を op.Server の前で受ける（OpenID4VCI 6）。
func (s *oidcServer) withPreAuthorizedToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.ParseForm() == nil && r.PostForm.Get("grant_type") == vci.GrantTypePreAuthorized {
			s.preAuthorizedToken(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code})
}

// preAuthorizedToken は Pre-Authorized Code を引き換える。ウォレットの認証は受けない（匿名。認証の値があれば invalid_client）。
func (s *oidcServer) preAuthorizedToken(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	if _, _, ok := r.BasicAuth(); ok || f.Get("client_secret") != "" || f.Get("client_assertion") != "" {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	for _, k := range []string{"pre-authorized_code", "tx_code", "client_id"} {
		if len(f[k]) > 1 {
			tokenError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	_, hasTx := f["tx_code"]
	clientID := f.Get("client_id")
	if len(clientID) > 256 {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	t, err := s.a.vci.Redeem(r.Context(), vci.TokenRequest{RealmID: s.a.realm.ID, Code: f.Get("pre-authorized_code"), TxCode: f.Get("tx_code"),
		HasTxCode: hasTx, ClientID: clientID, RequestID: requestID(r.Context())})
	if code, _ := vci.CodeOf(err); code != "" {
		tokenError(w, http.StatusBadRequest, code)
		return
	}
	if err != nil {
		s.a.unavailable(w, r, err)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{"access_token": t.AccessToken, "token_type": "Bearer", "expires_in": int(t.ExpiresIn / time.Second)})
}

// credentialScopes は realm の定義の Authorization Code Flow のスコープ（認可要求で選べるようにする）。
func (s *oidcServer) credentialScopes(ctx context.Context) ([]string, error) {
	if s.a.vci == nil {
		return nil, nil
	}
	var out []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.VCI().ListConfigurations(ctx, s.a.realm.ID)
		for _, c := range cs {
			if c.Scope != "" {
				out = append(out, c.Scope)
			}
		}
		return err
	})
	return out, err
}
