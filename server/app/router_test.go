package app

import "testing"

func TestSplitVerb(t *testing.T) {
	for in, want := range map[string]string{
		"POST /v1/me/sessions/{id}:revoke": "POST /v1/me/sessions/{id}/:revoke",
		"/v1/me/sessions/ses_01ABC:revoke": "/v1/me/sessions/ses_01ABC/:revoke",
		"/v1/me/sessions":                  "/v1/me/sessions",
		"/v1/x/:revoke":                    "/v1/x/:revoke",
		"/v1/x/abc:":                       "/v1/x/abc:",
		"/healthz":                         "/healthz",
	} {
		if got := splitVerb(in); got != want {
			t.Errorf("splitVerb(%q) = %q, want %q", in, got, want)
		}
	}
}
