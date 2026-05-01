package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/labstack/echo/v4"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"

	"sharefile/internal/config"
	"sharefile/internal/db"
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
		SessionTTL:    6,
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
		{name: "login page", path: "/login", wantStatus: http.StatusOK, wantBody: "Client Password Login"},
		{name: "request link page", path: "/request-link", wantStatus: http.StatusOK, wantBody: "Send Magic Link"},
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

func TestAuthPagesContainFormTargets(t *testing.T) {
	s := New(testConfig(), slog.Default())

	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	s.e.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("/login status = %d, want %d", loginRec.Code, http.StatusOK)
	}
	loginBody := loginRec.Body.String()
	if !strings.Contains(loginBody, "action=\"/auth/sso/login\"") || !strings.Contains(loginBody, "action=\"/auth/password/login\"") {
		t.Fatalf("/login body = %q, want auth form actions", loginBody)
	}

	requestReq := httptest.NewRequest(http.MethodGet, "/request-link", nil)
	requestRec := httptest.NewRecorder()
	s.e.ServeHTTP(requestRec, requestReq)
	if requestRec.Code != http.StatusOK {
		t.Fatalf("/request-link status = %d, want %d", requestRec.Code, http.StatusOK)
	}
	requestBody := requestRec.Body.String()
	if !strings.Contains(requestBody, "action=\"/auth/magic/request\"") || !strings.Contains(requestBody, "action=\"/auth/magic/verify\"") {
		t.Fatalf("/request-link body = %q, want magic-link form actions", requestBody)
	}
}

func TestAuthFormPostsRedirectForHTMLRequests(t *testing.T) {
	s := New(testConfig(), slog.Default())

	reqBody := bytes.NewBufferString("client_id=")
	req := httptest.NewRequest(http.MethodPost, "/auth/magic/request", reqBody)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	loc := rec.Result().Header.Get(echo.HeaderLocation)
	if !strings.HasPrefix(loc, "/request-link?error=") {
		t.Fatalf("location = %q, want request-link error redirect", loc)
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	rec = httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	loc = rec.Result().Header.Get(echo.HeaderLocation)
	if !strings.HasPrefix(loc, "/login?error=") {
		t.Fatalf("location = %q, want login error redirect", loc)
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

func TestProtectedHTMLRoutesRedirectToLoginWithoutSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	req.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get(echo.HeaderLocation); loc != "/login" {
		t.Fatalf("location = %q, want %q", loc, "/login")
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

func TestSessionLoginSetsCookieTTLFromConfig(t *testing.T) {
	cfg := testConfig()
	cfg.SessionTTL = 5
	s := New(cfg, slog.Default())

	body := bytes.NewBufferString("actor_type=user&actor_id=u-ttl")
	req := httptest.NewRequest(http.MethodPost, "/auth/session", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	cookie := cookieByName(rec.Result().Cookies(), "sharefile_session")
	if cookie == nil {
		t.Fatal("expected sharefile_session cookie")
	}
	if cookie.MaxAge != 5*60*60 {
		t.Fatalf("cookie max-age = %d, want %d", cookie.MaxAge, 5*60*60)
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
	sso := signedSSOToken(t, "secret", "issuer-1", "aud-1", "user-from-sso", "", "user-from-sso@example.com", "User From SSO")

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

func TestSSOLoginUpsertsLocalUser(t *testing.T) {
	s := New(testConfig(), slog.Default())

	first := signedSSOToken(t, "secret", "issuer-1", "aud-1", "user-upsert", "", "first@example.com", "First Name")
	req1 := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req1.AddCookie(&http.Cookie{Name: "sso_jwt", Value: first})
	rec1 := httptest.NewRecorder()
	s.e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("first login status = %d, want %d", rec1.Code, http.StatusNoContent)
	}

	second := signedSSOToken(t, "secret", "issuer-1", "aud-1", "user-upsert", "", "updated@example.com", "Updated Name")
	req2 := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req2.AddCookie(&http.Cookie{Name: "sso_jwt", Value: second})
	rec2 := httptest.NewRecorder()
	s.e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second login status = %d, want %d", rec2.Code, http.StatusNoContent)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	queries := db.New(sqlDB)
	user, err := queries.GetUserByID(context.Background(), "user-upsert")
	if err != nil {
		t.Fatalf("GetUserByID() unexpected error: %v", err)
	}
	if user.Email != "updated@example.com" {
		t.Fatalf("user email = %q, want %q", user.Email, "updated@example.com")
	}
	if user.FullName != "Updated Name" {
		t.Fatalf("user full_name = %q, want %q", user.FullName, "Updated Name")
	}
}

func TestSSOLoginRejectsMissingEmailClaim(t *testing.T) {
	s := New(testConfig(), slog.Default())
	sso := signedSSOToken(t, "secret", "issuer-1", "aud-1", "missing-email", "", "", "")
	req := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_jwt", Value: sso})
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

	logs := listAuditLogsByEventType(t, "auth.magic.request")
	if len(logs) < 2 {
		t.Fatalf("audit log count = %d, want at least 2", len(logs))
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

func TestClientDownloadAuthorization(t *testing.T) {
	s := New(testConfig(), slog.Default())

	createClientWithoutPassword(t, "client-download-direct", "client-download-direct@example.com", true)
	createClientWithoutPassword(t, "client-download-group", "client-download-group@example.com", true)
	createClientWithoutPassword(t, "client-download-denied", "client-download-denied@example.com", true)

	createFileForTests(t, "file-direct")
	createShareForTests(t, "share-direct", "file-direct", "client", "client-download-direct")

	createFileForTests(t, "file-group")
	createClientGroupForTests(t, "cg-download")
	addClientToGroupForTests(t, "cg-download", "client-download-group")
	createShareForTests(t, "share-group", "file-group", "client_group", "cg-download")

	directCookie := login(t, s, "client", "client-download-direct", "")
	groupCookie := login(t, s, "client", "client-download-group", "")
	deniedCookie := login(t, s, "client", "client-download-denied", "")

	tests := []struct {
		name       string
		fileID     string
		cookie     *http.Cookie
		wantStatus int
	}{
		{name: "direct share allowed", fileID: "file-direct", cookie: directCookie, wantStatus: http.StatusOK},
		{name: "group share allowed", fileID: "file-group", cookie: groupCookie, wantStatus: http.StatusOK},
		{name: "missing share denied", fileID: "file-direct", cookie: deniedCookie, wantStatus: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/client/files/"+tc.fileID+"/download", nil)
			req.AddCookie(tc.cookie)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}

	logs := listAuditLogsByEventType(t, "authz.client.download")
	if len(logs) < len(tests) {
		t.Fatalf("audit log count = %d, want at least %d", len(logs), len(tests))
	}
}

func TestClientUploadAuthorizationConstraints(t *testing.T) {
	s := New(testConfig(), slog.Default())

	createClientForUploadTests(t, "client-upload-enabled", "client-upload-enabled@example.com", true, true)
	createClientForUploadTests(t, "client-upload-disabled", "client-upload-disabled@example.com", true, false)
	createClientForUploadTests(t, "client-upload-inactive", "client-upload-inactive@example.com", false, true)

	createClientUploadPermissionForTests(t, "perm-enabled", "client-upload-enabled", "user", "u-target-1")

	enabledCookie := login(t, s, "client", "client-upload-enabled", "")
	disabledCookie := login(t, s, "client", "client-upload-disabled", "")
	inactiveCookie := login(t, s, "client", "client-upload-inactive", "")

	tests := []struct {
		name       string
		cookie     *http.Cookie
		body       string
		wantStatus int
	}{
		{name: "enabled and allowed target", cookie: enabledCookie, body: "target_type=user&target_id=u-target-1", wantStatus: http.StatusOK},
		{name: "enabled but disallowed target", cookie: enabledCookie, body: "target_type=user&target_id=u-target-2", wantStatus: http.StatusForbidden},
		{name: "disabled upload", cookie: disabledCookie, body: "target_type=user&target_id=u-target-1", wantStatus: http.StatusForbidden},
		{name: "inactive client", cookie: inactiveCookie, body: "target_type=user&target_id=u-target-1", wantStatus: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/client/uploads", bytes.NewBufferString(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			req.AddCookie(tc.cookie)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}

	logs := listAuditLogsByEventType(t, "authz.client.upload")
	if len(logs) < len(tests) {
		t.Fatalf("audit log count = %d, want at least %d", len(logs), len(tests))
	}

	allowedFound := false
	deniedFound := false
	for _, l := range logs {
		meta := map[string]any{}
		if !l.MetadataJson.Valid {
			continue
		}
		if err := json.Unmarshal([]byte(l.MetadataJson.String), &meta); err != nil {
			continue
		}
		if meta["outcome"] == "allowed" {
			allowedFound = true
		}
		if meta["outcome"] == "denied" {
			deniedFound = true
		}
	}
	if !allowedFound || !deniedFound {
		t.Fatalf("expected both allowed and denied upload authz audit events; got allowed=%v denied=%v", allowedFound, deniedFound)
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

	logs := listAuditLogsByEventType(t, "auth.magic.verify")
	if len(logs) < 2 {
		t.Fatalf("audit log count = %d, want at least 2", len(logs))
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

func TestClientPasswordLoginSuccess(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithPassword(t, "client-pass-1", "client-pass@example.com", "secret-pass", true)

	body := bytes.NewBufferString("email=client-pass@example.com&password=secret-pass")
	req := httptest.NewRequest(http.MethodPost, "/auth/password/login", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	cookie := cookieByName(rec.Result().Cookies(), "sharefile_session")
	if cookie == nil {
		t.Fatal("expected sharefile_session cookie")
	}

	clientReq := httptest.NewRequest(http.MethodGet, "/client/dashboard", nil)
	clientReq.AddCookie(cookie)
	clientRec := httptest.NewRecorder()
	s.e.ServeHTTP(clientRec, clientReq)
	if clientRec.Code != http.StatusOK {
		t.Fatalf("client dashboard status = %d, want %d", clientRec.Code, http.StatusOK)
	}
}

func TestClientPasswordLoginDisabledAndInvalidCredentials(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithoutPassword(t, "client-no-pass", "client-nopass@example.com", true)
	createClientWithPassword(t, "client-pass-2", "client-pass2@example.com", "secret-pass", true)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "password disabled", body: "email=client-nopass@example.com&password=secret-pass", wantStatus: http.StatusForbidden},
		{name: "wrong password", body: "email=client-pass2@example.com&password=wrong", wantStatus: http.StatusUnauthorized},
		{name: "missing user", body: "email=missing@example.com&password=secret-pass", wantStatus: http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/password/login", bytes.NewBufferString(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}

	logs := listAuditLogsByEventType(t, "auth.password.login")
	if len(logs) < len(tests) {
		t.Fatalf("audit log count = %d, want at least %d", len(logs), len(tests))
	}
}

func TestSSOInvalidTokenWritesAuditEvent(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_jwt", Value: "bad-token"})
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	logs := listAuditLogsByEventType(t, "auth.sso.login")
	if len(logs) == 0 {
		t.Fatal("expected auth.sso.login audit log")
	}
}

func TestSSOMissingCookieWritesAuditEvent(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	logs := listAuditLogsByEventType(t, "auth.sso.login")
	if len(logs) == 0 {
		t.Fatal("expected auth.sso.login audit log")
	}
}

func TestLogoutWritesAuditEventForActiveSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-audit-logout", "")

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	logs := listAuditLogsByEventType(t, "auth.logout")
	if len(logs) == 0 {
		t.Fatal("expected auth.logout audit log")
	}
}

func TestClientPasswordLoginSuccessWritesAuditEvent(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithPassword(t, "client-pass-audit", "client-pass-audit@example.com", "secret-pass", true)

	body := bytes.NewBufferString("email=client-pass-audit@example.com&password=secret-pass")
	req := httptest.NewRequest(http.MethodPost, "/auth/password/login", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	logs := listAuditLogsByEventType(t, "auth.password.login")
	if len(logs) == 0 {
		t.Fatal("expected auth.password.login audit log")
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
	if !strings.Contains(string(body), "href=\"/assets/app.css\"") {
		t.Fatalf("body = %q, want stylesheet link", string(body))
	}
	if !strings.Contains(string(body), "href=\"/user/dashboard\"") {
		t.Fatalf("body = %q, want shared nav links", string(body))
	}
}

func TestTemplateRendererRendersFlashPartials(t *testing.T) {
	s := New(testConfig(), slog.Default())
	s.e.GET("/_test/flash", func(c echo.Context) error {
		return c.Render(http.StatusOK, "home", map[string]any{
			"Title":           "Flash Test",
			"ContentTemplate": "home_content",
			"FlashSuccess":    "saved",
			"FlashError":      "validation failed",
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/_test/flash", nil)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "alert alert-success") || !strings.Contains(body, "saved") {
		t.Fatalf("body = %q, want success flash", body)
	}
	if !strings.Contains(body, "alert alert-error") || !strings.Contains(body, "validation failed") {
		t.Fatalf("body = %q, want error flash", body)
	}
}

func TestAssetsCSSIsServed(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/assets/app.css", nil)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty CSS body")
	}
	if !strings.Contains(string(body), ".btn") {
		t.Fatalf("body = %q, want daisyUI button styles", string(body))
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

func signedSSOToken(t *testing.T, secret, issuer, audience, userID, subject, email, name string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":   userID,
		"email": email,
		"name":  name,
		"iss":   issuer,
		"aud":   audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   subject,
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

func createClientWithPassword(t *testing.T, id, email, password string, active bool) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error: %v", err)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	isActive := int64(0)
	if active {
		isActive = 1
	}

	if err := db.New(sqlDB).CreateClient(context.Background(), db.CreateClientParams{
		ID:           id,
		Email:        email,
		DisplayName:  email,
		PasswordHash: sql.NullString{Valid: true, String: string(hash)},
		CanUpload:    0,
		IsActive:     isActive,
	}); err != nil {
		t.Fatalf("CreateClient() error: %v", err)
	}
}

func createClientWithoutPassword(t *testing.T, id, email string, active bool) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	isActive := int64(0)
	if active {
		isActive = 1
	}

	if err := db.New(sqlDB).CreateClient(context.Background(), db.CreateClientParams{
		ID:           id,
		Email:        email,
		DisplayName:  email,
		PasswordHash: sql.NullString{},
		CanUpload:    0,
		IsActive:     isActive,
	}); err != nil {
		t.Fatalf("CreateClient() error: %v", err)
	}
}

func createFileForTests(t *testing.T, fileID string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).CreateFile(context.Background(), db.CreateFileParams{
		ID:               fileID,
		UploaderType:     "user",
		UploaderID:       "u-seed",
		OriginalFilename: fileID + ".txt",
		StorageKey:       "s3/" + fileID,
		ContentType:      "text/plain",
		SizeBytes:        123,
		ExpiresAt:        sql.NullString{},
	}); err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}
}

func createShareForTests(t *testing.T, shareID, fileID, targetType, targetID string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).CreateShare(context.Background(), db.CreateShareParams{
		ID:           shareID,
		FileID:       fileID,
		SharedByType: "user",
		SharedByID:   "u-seed",
		TargetType:   targetType,
		TargetID:     targetID,
		Message:      sql.NullString{},
	}); err != nil {
		t.Fatalf("CreateShare() error: %v", err)
	}
}

func createClientGroupForTests(t *testing.T, groupID string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).CreateClientGroup(context.Background(), db.CreateClientGroupParams{
		ID:              groupID,
		Name:            "Download Group",
		CreatedByUserID: sql.NullString{},
	}); err != nil {
		t.Fatalf("CreateClientGroup() error: %v", err)
	}
}

func addClientToGroupForTests(t *testing.T, groupID, clientID string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).AddClientToGroup(context.Background(), db.AddClientToGroupParams{
		ClientGroupID: groupID,
		ClientID:      clientID,
	}); err != nil {
		t.Fatalf("AddClientToGroup() error: %v", err)
	}
}

func createClientForUploadTests(t *testing.T, id, email string, active, canUpload bool) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	isActive := int64(0)
	if active {
		isActive = 1
	}
	uploads := int64(0)
	if canUpload {
		uploads = 1
	}

	if err := db.New(sqlDB).CreateClient(context.Background(), db.CreateClientParams{
		ID:           id,
		Email:        email,
		DisplayName:  email,
		PasswordHash: sql.NullString{},
		CanUpload:    uploads,
		IsActive:     isActive,
	}); err != nil {
		t.Fatalf("CreateClient() error: %v", err)
	}
}

func createClientUploadPermissionForTests(t *testing.T, permissionID, clientID, targetType, targetID string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).CreateClientUploadPermission(context.Background(), db.CreateClientUploadPermissionParams{
		ID:         permissionID,
		OwnerType:  "client",
		OwnerID:    clientID,
		TargetType: targetType,
		TargetID:   targetID,
	}); err != nil {
		t.Fatalf("CreateClientUploadPermission() error: %v", err)
	}
}

func listAuditLogsByEventType(t *testing.T, eventType string) []db.AuditLog {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	logs, err := db.New(sqlDB).ListAuditLogsByEventType(context.Background(), db.ListAuditLogsByEventTypeParams{
		EventType: eventType,
		Limit:     100,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("ListAuditLogsByEventType() error: %v", err)
	}
	return logs
}
