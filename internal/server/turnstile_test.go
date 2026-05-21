package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestTurnstileVerifierVerify(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{name: "success", statusCode: http.StatusOK, body: `{"success":true}`, want: true},
		{name: "failure", statusCode: http.StatusOK, body: `{"success":false}`, want: false},
		{
			name:       "bad status",
			statusCode: http.StatusBadGateway,
			body:       `{"success":true}`,
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						t.Fatalf("ParseForm() error: %v", err)
					}
					if got := r.Form.Get("response"); got != "token-1" {
						t.Fatalf("response = %q, want token-1", got)
					}
					w.WriteHeader(tc.statusCode)
					_, _ = w.Write([]byte(tc.body))
				}),
			)
			defer srv.Close()

			v := newTurnstileVerifier("site-key", "secret-key")
			v.verifyURL = srv.URL

			e := echo.New()
			req := httptest.NewRequest(
				http.MethodPost,
				"/",
				strings.NewReader("cf-turnstile-response=token-1"),
			)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if got := v.verify(c); got != tc.want {
				t.Fatalf("verify() = %v, want %v", got, tc.want)
			}
		})
	}
}
