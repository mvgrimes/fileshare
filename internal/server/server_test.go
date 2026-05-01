package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pressly/goose/v3"
	"github.com/labstack/echo/v4"

	"sharefile/internal/config"
	"sharefile/migrations"

	_ "modernc.org/sqlite"
)

func TestMain(m *testing.M) {
	_ = os.Remove("test.db")
	if err := migrateTestDB("test.db"); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.Remove("test.db")
	os.Exit(code)
}

func migrateTestDB(path string) error {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	goose.SetBaseFS(migrations.FS())
	if err := goose.Up(sqlDB, "."); err != nil {
		return err
	}

	return nil
}

func testConfig() *config.Config {
	return &config.Config{
		ServerAddress: "127.0.0.1",
		ServerPort:    0,
		Environment:   "test",
		LogLevel:      "debug",
		DatabaseURL:   "test.db",
		SessionSecret: "secret",
		JWTSecret:     "secret",
		SSOCookieName: "sso_jwt",
		SSOIssuer:     "issuer-1",
		SSOAudience:   "aud-1",
	}
}

func TestHealthz(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %q, want status ok json", rec.Body.String())
	}
}

func TestRouteGroupsRender(t *testing.T) {
	s := New(testConfig(), slog.Default())

	publicTests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{name: "public home", path: "/", wantStatus: http.StatusOK, wantBody: "ShareFile"},
	}

	for _, tc := range publicTests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()

			s.e.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body = %q, want to contain %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestProtectedRoutesRequireAuth(t *testing.T) {
	s := New(testConfig(), slog.Default())
	for _, path := range []string{"/user/dashboard", "/client/dashboard", "/admin/dashboard"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestSessionLoginAndActorAuthorization(t *testing.T) {
	s := New(testConfig(), slog.Default())

	userCookie := login(t, s, "user", "u-123", "")
	clientCookie := login(t, s, "client", "c-123", "")

	tests := []struct {
		name       string
		path       string
		cookie     *http.Cookie
		wantStatus int
		wantBody   string
	}{
		{name: "user to user dashboard", path: "/user/dashboard", cookie: userCookie, wantStatus: http.StatusOK, wantBody: "Actor ID: <code>u-123</code>"},
		{name: "client to client dashboard", path: "/client/dashboard", cookie: clientCookie, wantStatus: http.StatusOK, wantBody: "Actor ID: <code>c-123</code>"},
		{name: "client forbidden from user dashboard", path: "/user/dashboard", cookie: clientCookie, wantStatus: http.StatusForbidden, wantBody: "forbidden"},
		{name: "user forbidden from client dashboard", path: "/client/dashboard", cookie: userCookie, wantStatus: http.StatusForbidden, wantBody: "forbidden"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(tc.cookie)
			rec := httptest.NewRecorder()

			s.e.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body = %q, want to contain %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-logout", "")

	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	s.e.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", logoutRec.Code, http.StatusNoContent)
	}

	cleared := cookieByName(logoutRec.Result().Cookies(), "sharefile_session")
	if cleared == nil {
		t.Fatal("expected cleared sharefile_session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("logout cookie max-age = %d, want %d", cleared.MaxAge, -1)
	}
	if !cleared.HttpOnly {
		t.Fatal("logout cookie should be HttpOnly")
	}

	req := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestLogoutWithoutSessionCookieStillClearsCookie(t *testing.T) {
	s := New(testConfig(), slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	cleared := cookieByName(rec.Result().Cookies(), "sharefile_session")
	if cleared == nil {
		t.Fatal("expected cleared sharefile_session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("logout cookie max-age = %d, want %d", cleared.MaxAge, -1)
	}
}

func TestSSOLoginCreatesUserSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	sso := signedSSOToken(t, "secret", "issuer-1", "aud-1", "user-from-sso", "")

	req := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_jwt", Value: sso})
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	var appCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sharefile_session" {
			appCookie = c
			break
		}
	}
	if appCookie == nil {
		t.Fatal("expected sharefile_session cookie")
	}

	userReq := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	userReq.AddCookie(appCookie)
	userRec := httptest.NewRecorder()
	s.e.ServeHTTP(userRec, userReq)

	if userRec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want %d", userRec.Code, http.StatusOK)
	}
	if !strings.Contains(userRec.Body.String(), "Actor ID: <code>user-from-sso</code>") {
		t.Fatalf("body = %q, want actor id from sso", userRec.Body.String())
	}
}

func TestSSOLoginRejectsInvalidToken(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_jwt", Value: "bad-token"})
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMagicLinkRequestThrottled(t *testing.T) {
	s := New(testConfig(), slog.Default())
	body := bytes.NewBufferString("client_id=client-1")
	req1 := httptest.NewRequest(http.MethodPost, "/auth/magic/request", body)
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec1 := httptest.NewRecorder()
	s.e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("first request status = %d, want %d", rec1.Code, http.StatusNoContent)
	}

	body2 := bytes.NewBufferString("client_id=client-1")
	req2 := httptest.NewRequest(http.MethodPost, "/auth/magic/request", body2)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec2 := httptest.NewRecorder()
	s.e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d", rec2.Code, http.StatusTooManyRequests)
	}
}

func TestMagicLinkVerifyCreatesClientSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	token, _, err := s.magic.Create(context.Background(), "client-verify")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	body := bytes.NewBufferString(fmt.Sprintf("client_id=client-verify&token=%s", token))
	req := httptest.NewRequest(http.MethodPost, "/auth/magic/verify", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify status = %d, want %d, body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sharefile_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected sharefile_session cookie")
	}

	clientReq := httptest.NewRequest(http.MethodGet, "/client/dashboard", nil)
	clientReq.AddCookie(sessionCookie)
	clientRec := httptest.NewRecorder()
	s.e.ServeHTTP(clientRec, clientReq)
	if clientRec.Code != http.StatusOK {
		t.Fatalf("client dashboard status = %d, want %d", clientRec.Code, http.StatusOK)
	}
}

func TestRBACRoleGates(t *testing.T) {
	s := New(testConfig(), slog.Default())

	adminCookie := login(t, s, "user", "u-admin", "admin")
	managerCookie := login(t, s, "user", "u-manager", "account_manager")
	uploaderCookie := login(t, s, "user", "u-uploader", "uploader")

	tests := []struct {
		name       string
		path       string
		cookie     *http.Cookie
		wantStatus int
	}{
		{name: "admin users allowed", path: "/admin/users", cookie: adminCookie, wantStatus: http.StatusOK},
		{name: "manager users denied", path: "/admin/users", cookie: managerCookie, wantStatus: http.StatusForbidden},
		{name: "manager clients allowed", path: "/user/clients", cookie: managerCookie, wantStatus: http.StatusOK},
		{name: "uploader clients denied", path: "/user/clients", cookie: uploaderCookie, wantStatus: http.StatusForbidden},
		{name: "uploader uploads allowed", path: "/user/uploads", cookie: uploaderCookie, wantStatus: http.StatusOK},
		{name: "manager uploads denied", path: "/user/uploads", cookie: managerCookie, wantStatus: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(tc.cookie)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestMagicLinkVerifySingleUse(t *testing.T) {
	s := New(testConfig(), slog.Default())
	token, _, err := s.magic.Create(context.Background(), "client-once")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	for i := 0; i < 2; i++ {
		body := bytes.NewBufferString(fmt.Sprintf("client_id=client-once&token=%s", token))
		req := httptest.NewRequest(http.MethodPost, "/auth/magic/verify", body)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		s.e.ServeHTTP(rec, req)
		if i == 0 && rec.Code != http.StatusNoContent {
			t.Fatalf("first verify status = %d, want %d", rec.Code, http.StatusNoContent)
		}
		if i == 1 && rec.Code != http.StatusUnauthorized {
			t.Fatalf("second verify status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestMagicLinkRequestDeliveryFailure(t *testing.T) {
	s := New(testConfig(), slog.Default())
	s.magicSend = failingSender{}

	body := bytes.NewBufferString("client_id=client-fail")
	req := httptest.NewRequest(http.MethodPost, "/auth/magic/request", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestTemplateRendererAddsPath(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !strings.Contains(string(body), "Current path: <code>/</code>") {
		t.Fatalf("body = %q, want rendered request path", string(body))
	}
}

func login(t *testing.T, s *Server, actorType, actorID, roles string) *http.Cookie {
	t.Helper()
	body := bytes.NewBufferString(fmt.Sprintf("actor_type=%s&actor_id=%s&roles=%s", actorType, actorID, roles))
	req := httptest.NewRequest(http.MethodPost, "/auth/session", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want %d, body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if c := cookieByName(rec.Result().Cookies(), "sharefile_session"); c != nil {
		return c
	}
	t.Fatal("session cookie not set")
	return nil
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func signedSSOToken(t *testing.T, secret, issuer, audience, userID, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid": userID,
		"iss": issuer,
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": subject,
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() error: %v", err)
	}
	return signed
}

type failingSender struct{}

func (failingSender) SendMagicLink(_ context.Context, _ string, _ string) error {
	return errors.New("smtp down")
}
