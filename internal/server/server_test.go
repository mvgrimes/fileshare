package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"fileshare/internal/config"
	"fileshare/internal/db"
	"fileshare/migrations"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"

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
		ServerUrl:     "https://fileshare.test",
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
		{
			name:       "public home",
			path:       "/",
			wantStatus: http.StatusOK,
			wantBody:   "FileShare File Share",
		},
		{name: "login page", path: "/login", wantStatus: http.StatusOK, wantBody: "Password Login"},
		{
			name:       "request link page",
			path:       "/request-link",
			wantStatus: http.StatusOK,
			wantBody:   "Send Magic Link",
		},
		{
			name:       "verify token page",
			path:       "/verify-token",
			wantStatus: http.StatusOK,
			wantBody:   "Verify and Sign In",
		},
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

func TestHomeBrandingAssetsFromConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Branding = "Company, Inc."
	cfg.Favicon = "https://cdn.example.com/favicon.ico"
	cfg.Logo = "R0lGODlhAQABAAAAACw="
	cfg.LogoHero = "https://cdn.example.com/hero.svg"
	s := New(cfg, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<title>Company, Inc. File Share</title>") {
		t.Fatalf("body = %q, want branded page title", body)
	}
	if !strings.Contains(body, "rel=\"icon\" href=\"https://cdn.example.com/favicon.ico\"") {
		t.Fatalf("body = %q, want configured favicon", body)
	}
	if !strings.Contains(body, "src=\"data:image/png;base64,R0lGODlhAQABAAAAACw=\"") {
		t.Fatalf("body = %q, want normalized base64 header logo", body)
	}
	if !strings.Contains(body, "src=\"https://cdn.example.com/hero.svg\"") {
		t.Fatalf("body = %q, want configured hero logo", body)
	}
}

func TestHomeShowsLoginButtonWhenAnonymous(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "href=\"/login\"") ||
		!strings.Contains(rec.Body.String(), ">Login<") {
		t.Fatalf("body = %q, want login button", rec.Body.String())
	}
}

func TestHomeHidesLoginButtonWhenAuthenticated(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-home-authed", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if strings.Contains(body, "href=\"/login\"") || strings.Contains(body, ">Login<") {
		t.Fatalf("body = %q, should not include login button", body)
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
	if !strings.Contains(loginBody, "action=\"/auth/password/login\"") {
		t.Fatalf("/login body = %q, want password login form action", loginBody)
	}
	if !strings.Contains(loginBody, "action=\"/auth/magic/request\"") {
		t.Fatalf("/login body = %q, want magic link request form action", loginBody)
	}
	if !strings.Contains(loginBody, "<div class=\"divider\">OR</div>") {
		t.Fatalf("/login body = %q, want divider between login methods", loginBody)
	}
	if !strings.Contains(loginBody, "data-enhance=\"submission\"") ||
		!strings.Contains(loginBody, "data-pending-text=") {
		t.Fatalf("/login body = %q, want progressive enhancement hooks", loginBody)
	}

	requestReq := httptest.NewRequest(
		http.MethodGet,
		"/request-link?client_id=client%40example.com",
		nil,
	)
	requestRec := httptest.NewRecorder()
	s.e.ServeHTTP(requestRec, requestReq)
	if requestRec.Code != http.StatusOK {
		t.Fatalf("/request-link status = %d, want %d", requestRec.Code, http.StatusOK)
	}
	requestBody := requestRec.Body.String()
	if !strings.Contains(requestBody, "action=\"/auth/magic/request\"") ||
		strings.Contains(requestBody, "action=\"/auth/magic/verify\"") {
		t.Fatalf("/request-link body = %q, want request form only", requestBody)
	}
	if !strings.Contains(requestBody, "Email Address") ||
		!strings.Contains(requestBody, "name=\"client_id\" required value=\"client@example.com\"") {
		t.Fatalf(
			"/request-link body = %q, want email-address label and prefilled email",
			requestBody,
		)
	}

	verifyReq := httptest.NewRequest(
		http.MethodGet,
		"/verify-token?client_id=client%40example.com&token=tok-abc",
		nil,
	)
	verifyRec := httptest.NewRecorder()
	s.e.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("/verify-token status = %d, want %d", verifyRec.Code, http.StatusOK)
	}
	verifyBody := verifyRec.Body.String()
	if !strings.Contains(verifyBody, "action=\"/auth/magic/verify\"") ||
		strings.Contains(verifyBody, "action=\"/auth/magic/request\"") {
		t.Fatalf("/verify-token body = %q, want verify form only", verifyBody)
	}
	if !strings.Contains(verifyBody, "name=\"client_id\" required value=\"client@example.com\"") ||
		!strings.Contains(verifyBody, "name=\"token\" required value=\"tok-abc\"") {
		t.Fatalf("/verify-token body = %q, want prefilled verify values", verifyBody)
	}
}

func TestNavLogoutButtonVisibility(t *testing.T) {
	s := New(testConfig(), slog.Default())

	anonReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	anonRec := httptest.NewRecorder()
	s.e.ServeHTTP(anonRec, anonReq)
	if anonRec.Code != http.StatusOK {
		t.Fatalf("anonymous page status = %d, want %d", anonRec.Code, http.StatusOK)
	}
	if strings.Contains(anonRec.Body.String(), "action=\"/auth/logout\"") {
		t.Fatalf("anonymous nav should not render logout button: %q", anonRec.Body.String())
	}

	cookie := login(t, s, "user", "u-nav", "")
	authedReq := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	authedReq.AddCookie(cookie)
	authedRec := httptest.NewRecorder()
	s.e.ServeHTTP(authedRec, authedReq)
	if authedRec.Code != http.StatusOK {
		t.Fatalf("authenticated page status = %d, want %d", authedRec.Code, http.StatusOK)
	}
	authedBody := authedRec.Body.String()
	if !strings.Contains(authedBody, "action=\"/auth/logout\"") ||
		!strings.Contains(authedBody, ">Logout<") {
		t.Fatalf("authenticated nav should render logout button: %q", authedBody)
	}
	if !strings.Contains(authedBody, "href=\"/user/dashboard\"") ||
		!strings.Contains(authedBody, ">Dashboard<") {
		t.Fatalf("authenticated nav should render dashboard link: %q", authedBody)
	}
	if strings.Index(
		authedBody,
		"href=\"/user/dashboard\"",
	) > strings.Index(
		authedBody,
		"action=\"/auth/logout\"",
	) {
		t.Fatalf("dashboard link should be before logout button: %q", authedBody)
	}
}

func TestNavDashboardLinkTargetsRelevantDashboard(t *testing.T) {
	s := New(testConfig(), slog.Default())

	tests := []struct {
		name     string
		cookie   *http.Cookie
		path     string
		wantHref string
	}{
		{
			name:     "user dashboard link",
			cookie:   login(t, s, "user", "u-nav-user", ""),
			path:     "/user/dashboard",
			wantHref: "href=\"/user/dashboard\"",
		},
		{
			name:     "client dashboard link",
			cookie:   login(t, s, "client", "c-nav-client", ""),
			path:     "/client/dashboard",
			wantHref: "href=\"/client/dashboard\"",
		},
		{
			name:     "admin dashboard link",
			cookie:   login(t, s, "user", "u-nav-admin", "admin"),
			path:     "/admin/dashboard",
			wantHref: "href=\"/admin/dashboard\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(tc.cookie)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.wantHref) {
				t.Fatalf("body = %q, want dashboard href %q", body, tc.wantHref)
			}
			if strings.Index(body, tc.wantHref) > strings.Index(body, "action=\"/auth/logout\"") {
				t.Fatalf("dashboard link should be before logout button: %q", body)
			}
		})
	}
}

func TestProgressiveEnhancementScriptRenderedOnForms(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-enhance", "account_manager")

	req := httptest.NewRequest(http.MethodGet, "/user/clients", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "form[data-enhance='submission']") {
		t.Fatalf("body = %q, want enhancement script", body)
	}
	if !strings.Contains(body, "data-pending-text=\"Creating...\"") {
		t.Fatalf("body = %q, want submit pending text hooks", body)
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
			req.Header.Set(echo.HeaderAccept, "application/json")
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestUserUploadsRedirectsToLoginWithoutSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/user/uploads", nil)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get(echo.HeaderLocation); loc != "/login" {
		t.Fatalf("location = %q, want %q", loc, "/login")
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
		{
			name:       "user to user dashboard",
			path:       "/user/dashboard",
			cookie:     userCookie,
			wantStatus: http.StatusOK,
			wantBody:   "actor: u-123",
		},
		{
			name:       "client to client dashboard",
			path:       "/client/dashboard",
			cookie:     clientCookie,
			wantStatus: http.StatusOK,
			wantBody:   "actor: c-123",
		},
		{
			name:       "client forbidden from user dashboard",
			path:       "/user/dashboard",
			cookie:     clientCookie,
			wantStatus: http.StatusForbidden,
			wantBody:   "forbidden",
		},
		{
			name:       "user forbidden from client dashboard",
			path:       "/client/dashboard",
			cookie:     userCookie,
			wantStatus: http.StatusForbidden,
			wantBody:   "forbidden",
		},
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

func TestUserDashboardShowsOnlyAuthorizedActions(t *testing.T) {
	s := New(testConfig(), slog.Default())

	cookie := login(t, s, "user", "u-actions", "uploader")
	req := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Upload Files") {
		t.Fatalf("body = %q, want uploader action", body)
	}
	if strings.Index(body, "Received Files") > strings.Index(body, "Upload Files") {
		t.Fatalf("body = %q, want upload action after received files", body)
	}
	if strings.Contains(body, "Manage Clients") {
		t.Fatalf("body = %q, should not include manage clients action", body)
	}
	if strings.Contains(body, "Manage Users") {
		t.Fatalf("body = %q, should not include manage users action", body)
	}
}

func TestUserDashboardShowsEmptyStateWithoutRoles(t *testing.T) {
	s := New(testConfig(), slog.Default())

	cookie := login(t, s, "user", "u-empty", "")
	req := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Profile") || !strings.Contains(body, "href=\"/user/profile\"") {
		t.Fatalf("body = %q, want profile dashboard action", body)
	}
}

func TestClientDashboardShowsMagicLinkAction(t *testing.T) {
	s := New(testConfig(), slog.Default())

	cookie := login(t, s, "client", "c-actions", "")
	req := httptest.NewRequest(http.MethodGet, "/client/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Upload Files") ||
		!strings.Contains(body, "href=\"/client/uploads\"") {
		t.Fatalf("body = %q, want upload dashboard action", body)
	}
	if !strings.Contains(body, "Received Files") ||
		!strings.Contains(body, "href=\"/client/received\"") {
		t.Fatalf("body = %q, want shared files dashboard action", body)
	}
	if !strings.Contains(body, "Profile") || !strings.Contains(body, "href=\"/client/profile\"") {
		t.Fatalf("body = %q, want profile dashboard action", body)
	}
	if !strings.Contains(body, "Sent Files") || !strings.Contains(body, "href=\"/client/sent\"") {
		t.Fatalf("body = %q, want uploaded files dashboard action", body)
	}
	if !strings.Contains(body, "Browse files sent to your account.") {
		t.Fatalf("body = %q, want updated received files subtitle", body)
	}
	if !strings.Contains(body, "Submit files for review.") {
		t.Fatalf("body = %q, want updated upload files subtitle", body)
	}
}

func TestUserDashboardShowsStatsAndPrioritizesUnviewedSentFiles(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithoutPassword(t, "u-dashboard", "u-dashboard@example.com", true, 1)
	createClientWithoutPassword(t, "c-dashboard", "c-dashboard@example.com", true)
	createClientGroupForTests(t, "cg-dashboard")
	createFileWithUploader(t, "file-dashboard-unviewed", "u-dashboard")
	createFileWithUploader(t, "file-dashboard-viewed", "u-dashboard")
	createFileWithUploader(t, "file-dashboard-received", "c-dashboard")
	createShareForTests(
		t,
		"share-dashboard-unviewed",
		"file-dashboard-unviewed",
		"client",
		"c-dashboard",
	)
	createShareForTests(
		t,
		"share-dashboard-viewed",
		"file-dashboard-viewed",
		"client",
		"c-dashboard",
	)
	createShareForTests(
		t,
		"share-dashboard-group",
		"file-dashboard-unviewed",
		"client_group",
		"cg-dashboard",
	)
	createShareForTests(
		t,
		"share-dashboard-received",
		"file-dashboard-received",
		"user",
		"u-dashboard",
	)

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	queries := db.New(sqlDB)
	if err := queries.RecordShareDownload(
		context.Background(),
		db.RecordShareDownloadParams{
			ID:       "sd-dashboard",
			ShareID:  "share-dashboard-viewed",
			ClientID: "c-dashboard",
		},
	); err != nil {
		t.Fatalf("RecordShareDownload() error: %v", err)
	}

	cookie := login(t, s, "user", "u-dashboard", "uploader")
	req := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Your Sent Files") || !strings.Contains(body, "Client Sent Files") {
		t.Fatalf("body = %q, want dashboard stats labels", body)
	}
	if !strings.Contains(body, "file-dashboard-unviewed.dat") ||
		!strings.Contains(body, "file-dashboard-viewed.dat") {
		t.Fatalf("body = %q, want sent files table", body)
	}
	if !strings.Contains(body, "href=\"/user/sent/share-dashboard-unviewed\"") ||
		!strings.Contains(body, "href=\"/user/sent/share-dashboard-viewed\"") {
		t.Fatalf("body = %q, want sent file detail links", body)
	}
	if !strings.Contains(body, "href=\"/user/received/") {
		t.Fatalf("body = %q, want received file detail links", body)
	}
	if !strings.Contains(body, "Client: c-dashboard@example.com") ||
		!strings.Contains(body, "Client Group: Download Group cg-dashboard") {
		t.Fatalf("body = %q, want dashboard share labels", body)
	}
	if strings.Count(body, "<td>viewed</td>") != 1 {
		t.Fatalf("body = %q, want exactly one viewed share row in sent files", body)
	}
	if strings.Count(body, "<td>unviewed</td>") < 2 {
		t.Fatalf("body = %q, want unviewed badges for non-viewed sent shares", body)
	}
	if strings.Index(
		body,
		"file-dashboard-unviewed.dat",
	) > strings.Index(
		body,
		"file-dashboard-viewed.dat",
	) {
		t.Fatalf("body = %q, want unviewed file listed before viewed file", body)
	}
}

func TestClientDashboardShowsReceivedFilesAndUploadButton(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithoutPassword(t, "c-dashboard-files", "c-dashboard-files@example.com", true)
	createUserWithoutPassword(t, "u-dashboard-sender", "u-dashboard-sender@example.com", true, 1)
	createFileWithUploader(t, "file-client-dashboard", "u-dashboard-sender")
	createShareForTests(
		t,
		"share-client-dashboard",
		"file-client-dashboard",
		"client",
		"c-dashboard-files",
	)

	cookie := login(t, s, "client", "c-dashboard-files", "")
	req := httptest.NewRequest(http.MethodGet, "/client/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Upload a file") ||
		!strings.Contains(body, "href=\"/client/uploads\"") {
		t.Fatalf("body = %q, want upload button", body)
	}
	if !strings.Contains(body, "file-client-dashboard.dat") {
		t.Fatalf("body = %q, want received file listed", body)
	}
	if strings.Contains(body, "<th>Type</th>") {
		t.Fatalf("body = %q, should not show type column", body)
	}
	if strings.Contains(body, "<th>Shared Via</th>") {
		t.Fatalf("body = %q, should not show shared via column", body)
	}
	if !strings.Contains(body, "data-format-bytes=") {
		t.Fatalf("body = %q, want size formatting attribute", body)
	}
	if !strings.Contains(body, "data-format-datetime=") {
		t.Fatalf("body = %q, want shared at formatting attribute", body)
	}
}

func TestUserProfileUpdateNameAndPassword(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithPassword(t, "u-profile", "u-profile@example.com", "old-password-123", true, 3)
	cookie := login(t, s, "user", "u-profile", "uploader")

	getReq := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	getReq.AddCookie(cookie)
	getRec := httptest.NewRecorder()
	s.e.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("profile get status = %d, want %d", getRec.Code, http.StatusOK)
	}
	if !strings.Contains(getRec.Body.String(), "name=\"display_name\"") {
		t.Fatalf("profile body = %q, want display_name field", getRec.Body.String())
	}

	body := bytes.NewBufferString(
		"display_name=Updated+User&new_password=new-password-123&confirm_password=new-password-123",
	)
	postReq := httptest.NewRequest(http.MethodPost, "/user/profile", body)
	postReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	postReq.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	postReq.AddCookie(cookie)
	postRec := httptest.NewRecorder()
	s.e.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusSeeOther {
		t.Fatalf("profile post status = %d, want %d", postRec.Code, http.StatusSeeOther)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	updatedUser, err := db.New(sqlDB).GetUserByID(context.Background(), "u-profile")
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}
	if updatedUser.FullName != "Updated User" {
		t.Fatalf("full_name = %q, want %q", updatedUser.FullName, "Updated User")
	}

	loginReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString(
			"actor_type=user&email=u-profile@example.com&password=new-password-123",
		),
	)
	loginReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	loginRec := httptest.NewRecorder()
	s.e.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusNoContent {
		t.Fatalf("password login status = %d, want %d", loginRec.Code, http.StatusNoContent)
	}
}

func TestClientProfileUpdateNameAndPassword(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithPassword(t, "c-profile", "c-profile@example.com", "old-password-123", true)
	cookie := login(t, s, "client", "c-profile", "")

	getReq := httptest.NewRequest(http.MethodGet, "/client/profile", nil)
	getReq.AddCookie(cookie)
	getRec := httptest.NewRecorder()
	s.e.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("profile get status = %d, want %d", getRec.Code, http.StatusOK)
	}

	body := bytes.NewBufferString(
		"display_name=Updated+Client&new_password=new-password-123&confirm_password=new-password-123",
	)
	postReq := httptest.NewRequest(http.MethodPost, "/client/profile", body)
	postReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	postReq.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	postReq.AddCookie(cookie)
	postRec := httptest.NewRecorder()
	s.e.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusSeeOther {
		t.Fatalf("profile post status = %d, want %d", postRec.Code, http.StatusSeeOther)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	updatedClient, err := db.New(sqlDB).GetClientByID(context.Background(), "c-profile")
	if err != nil {
		t.Fatalf("GetClientByID() error: %v", err)
	}
	if updatedClient.DisplayName != "Updated Client" {
		t.Fatalf("display_name = %q, want %q", updatedClient.DisplayName, "Updated Client")
	}

	loginReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString(
			"actor_type=client&email=c-profile@example.com&password=new-password-123",
		),
	)
	loginReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	loginRec := httptest.NewRecorder()
	s.e.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusNoContent {
		t.Fatalf("password login status = %d, want %d", loginRec.Code, http.StatusNoContent)
	}
}

func TestUserProfileRejectsMismatchedConfirmPassword(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithPassword(
		t,
		"u-profile-mismatch",
		"u-profile-mismatch@example.com",
		"old-password-123",
		true,
		3,
	)
	cookie := login(t, s, "user", "u-profile-mismatch", "uploader")

	body := bytes.NewBufferString(
		"display_name=Updated+User&new_password=new-password-123&confirm_password=different-password-123",
	)
	postReq := httptest.NewRequest(http.MethodPost, "/user/profile", body)
	postReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	postReq.AddCookie(cookie)
	postRec := httptest.NewRecorder()
	s.e.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusBadRequest {
		t.Fatalf("profile post status = %d, want %d", postRec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(postRec.Body.String(), "passwords do not match") {
		t.Fatalf("body = %q, want mismatch validation error", postRec.Body.String())
	}
}

func TestClientProfileRejectsMismatchedConfirmPassword(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithPassword(
		t,
		"c-profile-mismatch",
		"c-profile-mismatch@example.com",
		"old-password-123",
		true,
	)
	cookie := login(t, s, "client", "c-profile-mismatch", "")

	body := bytes.NewBufferString(
		"display_name=Updated+Client&new_password=new-password-123&confirm_password=different-password-123",
	)
	postReq := httptest.NewRequest(http.MethodPost, "/client/profile", body)
	postReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	postReq.AddCookie(cookie)
	postRec := httptest.NewRecorder()
	s.e.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusBadRequest {
		t.Fatalf("profile post status = %d, want %d", postRec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(postRec.Body.String(), "passwords do not match") {
		t.Fatalf("body = %q, want mismatch validation error", postRec.Body.String())
	}
}

func TestClientUploadedFilesListAndDetail(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithoutPassword(
		t,
		"client-uploader-files",
		"client-uploader-files@example.com",
		true,
	)
	createClientWithoutPassword(
		t,
		"client-uploader-other",
		"client-uploader-other@example.com",
		true,
	)

	createFileWithUploaderType(t, "file-client-own", "client", "client-uploader-files")
	createFileWithUploaderType(t, "file-client-other", "client", "client-uploader-other")

	ownerCookie := login(t, s, "client", "client-uploader-files", "")
	otherCookie := login(t, s, "client", "client-uploader-other", "")

	listReq := httptest.NewRequest(http.MethodGet, "/client/sent", nil)
	listReq.AddCookie(ownerCookie)
	listRec := httptest.NewRecorder()
	s.e.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	if !strings.Contains(listRec.Body.String(), "file-client-own.dat") {
		t.Fatalf("list body = %q, want own uploaded file", listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "file-client-other.dat") {
		t.Fatalf("list body = %q, should not include other client uploads", listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "<th>Status</th>") {
		t.Fatalf("list body = %q, should not show status column", listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "<th>Shared At</th>") {
		t.Fatalf("list body = %q, should not show shared at column", listRec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/client/file/file-client-own", nil)
	detailReq.AddCookie(ownerCookie)
	detailRec := httptest.NewRecorder()
	s.e.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d", detailRec.Code, http.StatusOK)
	}
	if !strings.Contains(detailRec.Body.String(), "Uploaded At") {
		t.Fatalf("detail body = %q, want uploaded timestamp label", detailRec.Body.String())
	}

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/client/file/file-client-own", nil)
	forbiddenReq.AddCookie(otherCookie)
	forbiddenRec := httptest.NewRecorder()
	s.e.ServeHTTP(forbiddenRec, forbiddenReq)
	if forbiddenRec.Code != http.StatusForbidden {
		t.Fatalf("forbidden detail status = %d, want %d", forbiddenRec.Code, http.StatusForbidden)
	}
}

func TestClientSharedFilesListAndDetail(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithoutPassword(t, "client-files-direct", "client-files-direct@example.com", true)
	createClientWithoutPassword(t, "client-files-group", "client-files-group@example.com", true)
	createClientWithoutPassword(t, "client-files-denied", "client-files-denied@example.com", true)

	createFileForTests(t, "file-list-direct")
	createShareForTests(t, "share-list-direct", "file-list-direct", "client", "client-files-direct")
	createClientGroupForTests(t, "cg-files-direct")
	addClientToGroupForTests(t, "cg-files-direct", "client-files-direct")
	createShareForTests(
		t,
		"share-list-direct-group",
		"file-list-direct",
		"client_group",
		"cg-files-direct",
	)
	createFileForTests(t, "file-list-group")
	createClientGroupForTests(t, "cg-files")
	addClientToGroupForTests(t, "cg-files", "client-files-group")
	createShareForTests(t, "share-list-group", "file-list-group", "client_group", "cg-files")

	directCookie := login(t, s, "client", "client-files-direct", "")
	groupCookie := login(t, s, "client", "client-files-group", "")
	deniedCookie := login(t, s, "client", "client-files-denied", "")

	listReq := httptest.NewRequest(http.MethodGet, "/client/received", nil)
	listReq.AddCookie(directCookie)
	listRec := httptest.NewRecorder()
	s.e.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	if !strings.Contains(listRec.Body.String(), "file-list-direct.txt") {
		t.Fatalf("list body = %q, want direct shared file", listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), "Shared At") {
		t.Fatalf("list body = %q, want shared timestamp column", listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), "href=\"/client/file/file-list-direct/download\"") {
		t.Fatalf("list body = %q, want download link", listRec.Body.String())
	}
	if strings.Count(listRec.Body.String(), "file-list-direct.txt") != 2 {
		t.Fatalf(
			"list body = %q, want direct shared file listed for both shares",
			listRec.Body.String(),
		)
	}
	if strings.Contains(listRec.Body.String(), "<th>Shared Via</th>") {
		t.Fatalf("list body = %q, should not show shared via column", listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "<th>Status</th>") {
		t.Fatalf("list body = %q, should not show status column", listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "<th>Uploaded At</th>") {
		t.Fatalf("list body = %q, should not show uploaded at column", listRec.Body.String())
	}

	groupListReq := httptest.NewRequest(http.MethodGet, "/client/received", nil)
	groupListReq.AddCookie(groupCookie)
	groupListRec := httptest.NewRecorder()
	s.e.ServeHTTP(groupListRec, groupListReq)
	if groupListRec.Code != http.StatusOK {
		t.Fatalf("group list status = %d, want %d", groupListRec.Code, http.StatusOK)
	}
	if !strings.Contains(groupListRec.Body.String(), "file-list-group.txt") {
		t.Fatalf("group list body = %q, want group shared file", groupListRec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/client/received/share-list-direct", nil)
	detailReq.AddCookie(directCookie)
	detailRec := httptest.NewRecorder()
	s.e.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d", detailRec.Code, http.StatusOK)
	}
	if !strings.Contains(detailRec.Body.String(), "Shared At") {
		t.Fatalf("detail body = %q, want shared timestamp label", detailRec.Body.String())
	}
	if !strings.Contains(
		detailRec.Body.String(),
		"href=\"/client/file/file-list-direct/download\"",
	) {
		t.Fatalf("detail body = %q, want detail download link", detailRec.Body.String())
	}
	if !strings.Contains(detailRec.Body.String(), "Client: client-files-direct@example.com") {
		t.Fatalf("detail body = %q, want shared via display name", detailRec.Body.String())
	}
	if !strings.Contains(detailRec.Body.String(), "User: u-seed") {
		t.Fatalf("detail body = %q, want shared by display name", detailRec.Body.String())
	}
	if !strings.Contains(detailRec.Body.String(), "Back to Received Files") {
		t.Fatalf("detail body = %q, want back link near title", detailRec.Body.String())
	}

	deniedReq := httptest.NewRequest(http.MethodGet, "/client/received/share-list-direct", nil)
	deniedReq.AddCookie(deniedCookie)
	deniedRec := httptest.NewRecorder()
	s.e.ServeHTTP(deniedRec, deniedReq)
	if deniedRec.Code != http.StatusForbidden {
		t.Fatalf("denied detail status = %d, want %d", deniedRec.Code, http.StatusForbidden)
	}
}

func TestUserSharedFilesListAndDetail(t *testing.T) {
	s := New(testConfig(), slog.Default())
	ownerCookie := login(t, s, "user", "u-owner-files", "uploader")
	otherCookie := login(t, s, "user", "u-other-files", "uploader")
	createClientWithoutPassword(t, "c-shared-target", "c-shared-target@example.com", true)
	createClientGroupForTests(t, "cg-shared-target")

	createFileWithUploader(t, "file-owned", "u-owner-files")
	createFileWithUploader(t, "file-other", "u-other-files")
	createClientWithoutPassword(t, "c-viewer-owned", "c-viewer-owned@example.com", true)
	createShareForTests(t, "share-owned-view", "file-owned", "client", "c-viewer-owned")

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	if err := db.New(sqlDB).
		RecordShareDownload(context.Background(), db.RecordShareDownloadParams{ID: "download-owned-view", ShareID: "share-owned-view", ClientID: "c-viewer-owned"}); err != nil {
		t.Fatalf("RecordShareDownload() error: %v", err)
	}
	createShareForTests(t, "share-owned-client", "file-owned", "client", "c-shared-target")
	createShareForTests(t, "share-owned-group", "file-owned", "client_group", "cg-shared-target")

	listReq := httptest.NewRequest(http.MethodGet, "/user/sent", nil)
	listReq.AddCookie(ownerCookie)
	listRec := httptest.NewRecorder()
	s.e.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	body := listRec.Body.String()
	if !strings.Contains(body, "file-owned.dat") {
		t.Fatalf("list body = %q, want owned file", body)
	}
	if !strings.Contains(body, "Uploaded At") {
		t.Fatalf("list body = %q, want uploaded timestamp column", body)
	}
	if !strings.Contains(body, "href=\"/user/file/file-owned/download\"") {
		t.Fatalf("list body = %q, want download link", body)
	}
	if !strings.Contains(body, "Client: c-shared-target@example.com") ||
		!strings.Contains(body, "Client Group: Download Group cg-shared-target") {
		t.Fatalf("list body = %q, want share target labels", body)
	}
	if strings.Count(body, "badge badge-success badge-outline\">Viewed</span>") != 1 {
		t.Fatalf("list body = %q, want one viewed share row", body)
	}
	if strings.Count(body, "badge badge-warning badge-outline\">Unviewed</span>") < 2 {
		t.Fatalf("list body = %q, want unviewed badge for non-viewed share rows", body)
	}
	if strings.Count(body, "file-owned.dat") != 3 {
		t.Fatalf("list body = %q, want one row per share target", body)
	}
	if strings.Contains(body, "file-other.dat") {
		t.Fatalf("list body = %q, should not include other user's file", body)
	}

	ownerDetailReq := httptest.NewRequest(http.MethodGet, "/user/sent/share-owned-view", nil)
	ownerDetailReq.AddCookie(ownerCookie)
	ownerDetailRec := httptest.NewRecorder()
	s.e.ServeHTTP(ownerDetailRec, ownerDetailReq)
	if ownerDetailRec.Code != http.StatusOK {
		t.Fatalf("owner detail status = %d, want %d", ownerDetailRec.Code, http.StatusOK)
	}
	if !strings.Contains(ownerDetailRec.Body.String(), "Uploaded At") {
		t.Fatalf(
			"owner detail body = %q, want uploaded timestamp label",
			ownerDetailRec.Body.String(),
		)
	}
	if !strings.Contains(ownerDetailRec.Body.String(), "href=\"/user/file/file-owned/download\"") {
		t.Fatalf("owner detail body = %q, want detail download link", ownerDetailRec.Body.String())
	}
	if !strings.Contains(ownerDetailRec.Body.String(), "Open File Detail") ||
		!strings.Contains(ownerDetailRec.Body.String(), "Unshare") {
		t.Fatalf("owner detail body = %q, want share detail actions", ownerDetailRec.Body.String())
	}
	if !strings.Contains(ownerDetailRec.Body.String(), "Back to Sent Files") {
		t.Fatalf("owner detail body = %q, want back link near title", ownerDetailRec.Body.String())
	}
	if !strings.Contains(ownerDetailRec.Body.String(), "First Viewed") ||
		!strings.Contains(ownerDetailRec.Body.String(), "Last Viewed") ||
		!strings.Contains(ownerDetailRec.Body.String(), "View Count") {
		t.Fatalf(
			"owner detail body = %q, want expanded viewing history columns",
			ownerDetailRec.Body.String(),
		)
	}

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/user/sent/share-owned-client", nil)
	forbiddenReq.AddCookie(otherCookie)
	forbiddenRec := httptest.NewRecorder()
	s.e.ServeHTTP(forbiddenRec, forbiddenReq)
	if forbiddenRec.Code != http.StatusForbidden {
		t.Fatalf("forbidden detail status = %d, want %d", forbiddenRec.Code, http.StatusForbidden)
	}

	downloaderReq := httptest.NewRequest(http.MethodGet, "/user/file/file-owned/download", nil)
	downloaderReq.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	downloaderReq.AddCookie(ownerCookie)
	downloaderRec := httptest.NewRecorder()
	s.e.ServeHTTP(downloaderRec, downloaderReq)
	if downloaderRec.Code != http.StatusSeeOther {
		t.Fatalf("owner download status = %d, want %d", downloaderRec.Code, http.StatusSeeOther)
	}
	if downloaderRec.Result().Header.Get(echo.HeaderLocation) == "" {
		t.Fatalf("owner download redirect missing location")
	}

	forbiddenDownloadReq := httptest.NewRequest(
		http.MethodGet,
		"/user/file/file-owned/download",
		nil,
	)
	forbiddenDownloadReq.AddCookie(otherCookie)
	forbiddenDownloadRec := httptest.NewRecorder()
	s.e.ServeHTTP(forbiddenDownloadRec, forbiddenDownloadReq)
	if forbiddenDownloadRec.Code != http.StatusForbidden {
		t.Fatalf(
			"forbidden download status = %d, want %d",
			forbiddenDownloadRec.Code,
			http.StatusForbidden,
		)
	}
}

func TestUserReceivedFilesListAndDetail(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithoutPassword(t, "u-received", "u-received@example.com", true, 1)
	createClientWithoutPassword(t, "c-received-sender", "c-received-sender@example.com", true)
	createClientWithoutPassword(t, "c-received-other", "c-received-other@example.com", true)
	createFileWithUploaderType(t, "file-received-direct", "client", "c-received-sender")
	createFileWithUploaderType(t, "file-received-group", "client", "c-received-other")
	createFileWithUploaderType(t, "file-received-hidden", "client", "c-received-other")
	createShareForTests(t, "share-user-direct", "file-received-direct", "user", "u-received")

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	queries := db.New(sqlDB)
	if err := queries.CreateUserGroup(
		context.Background(),
		db.CreateUserGroupParams{
			ID:              "ug-received",
			Name:            "Received Group",
			CreatedByUserID: sql.NullString{},
		},
	); err != nil {
		t.Fatalf("CreateUserGroup() error: %v", err)
	}
	if err := queries.AddUserToGroup(
		context.Background(),
		db.AddUserToGroupParams{UserGroupID: "ug-received", UserID: "u-received"},
	); err != nil {
		t.Fatalf("AddUserToGroup() error: %v", err)
	}
	createShareForTests(t, "share-user-group", "file-received-group", "user_group", "ug-received")

	cookie := login(t, s, "user", "u-received", "")

	listReq := httptest.NewRequest(http.MethodGet, "/user/received", nil)
	listReq.AddCookie(cookie)
	listRec := httptest.NewRecorder()
	s.e.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	body := listRec.Body.String()
	if !strings.Contains(body, "file-received-direct.dat") ||
		!strings.Contains(body, "file-received-group.dat") {
		t.Fatalf("list body = %q, missing received files", body)
	}
	if !strings.Contains(body, "u-seed") {
		t.Fatalf("list body = %q, want sender name", body)
	}
	if strings.Contains(body, "file-received-hidden.dat") {
		t.Fatalf("list body = %q, should not include unrelated files", body)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/user/received/share-user-direct", nil)
	detailReq.AddCookie(cookie)
	detailRec := httptest.NewRecorder()
	s.e.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d", detailRec.Code, http.StatusOK)
	}
	if !strings.Contains(detailRec.Body.String(), "Back to Received Files") {
		t.Fatalf("detail body = %q, want back link near title", detailRec.Body.String())
	}
	if !strings.Contains(detailRec.Body.String(), "User: u-received") {
		t.Fatalf("detail body = %q, want shared via display name", detailRec.Body.String())
	}

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/user/received/share-hidden", nil)
	forbiddenReq.AddCookie(cookie)
	forbiddenRec := httptest.NewRecorder()
	s.e.ServeHTTP(forbiddenRec, forbiddenReq)
	if forbiddenRec.Code != http.StatusForbidden {
		t.Fatalf("forbidden detail status = %d, want %d", forbiddenRec.Code, http.StatusForbidden)
	}

	downloadReq := httptest.NewRequest(
		http.MethodGet,
		"/user/received/share-user-direct/download",
		nil,
	)
	downloadReq.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	downloadReq.AddCookie(cookie)
	downloadRec := httptest.NewRecorder()
	s.e.ServeHTTP(downloadRec, downloadReq)
	if downloadRec.Code != http.StatusSeeOther {
		t.Fatalf("received download status = %d, want %d", downloadRec.Code, http.StatusSeeOther)
	}
	if downloadRec.Result().Header.Get(echo.HeaderLocation) == "" {
		t.Fatalf("received download redirect missing location")
	}
}

func TestUserFileDetailManageShareRenameDeleteFlow(t *testing.T) {
	s := New(testConfig(), slog.Default())
	ownerCookie := login(t, s, "user", "u-manage-file", "uploader")

	createFileWithUploader(t, "file-manage", "u-manage-file")
	createClientWithoutPassword(t, "c-manage-target", "c-manage-target@example.com", true)
	createUserWithoutPassword(t, "u-manage-target", "u-manage-target@example.com", true, 1)

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	queries := db.New(sqlDB)
	if err := queries.CreateUserGroup(
		context.Background(),
		db.CreateUserGroupParams{
			ID:              "ug-manage",
			Name:            "Manage Group",
			CreatedByUserID: sql.NullString{},
		},
	); err != nil {
		t.Fatalf("CreateUserGroup() error: %v", err)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/user/file/file-manage", nil)
	detailReq.AddCookie(ownerCookie)
	detailRec := httptest.NewRecorder()
	s.e.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d", detailRec.Code, http.StatusOK)
	}
	body := detailRec.Body.String()
	if !strings.Contains(body, "Rename File") || !strings.Contains(body, "Current Shares") ||
		!strings.Contains(body, "Delete File") {
		t.Fatalf("detail body = %q, want file management controls", body)
	}

	renameReq := httptest.NewRequest(
		http.MethodPost,
		"/user/file/file-manage/rename",
		bytes.NewBufferString("filename=renamed-file.pdf"),
	)
	renameReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	renameReq.AddCookie(ownerCookie)
	renameRec := httptest.NewRecorder()
	s.e.ServeHTTP(renameRec, renameReq)
	if renameRec.Code != http.StatusNoContent {
		t.Fatalf("rename status = %d, want %d", renameRec.Code, http.StatusNoContent)
	}
	fileAfterRename, err := queries.GetFileByID(context.Background(), "file-manage")
	if err != nil {
		t.Fatalf("GetFileByID() error: %v", err)
	}
	if fileAfterRename.OriginalFilename != "renamed-file.pdf" {
		t.Fatalf("filename = %q, want %q", fileAfterRename.OriginalFilename, "renamed-file.pdf")
	}

	shareReq := httptest.NewRequest(
		http.MethodPost,
		"/user/file/file-manage/shares",
		bytes.NewBufferString("target_type=client&target_id=c-manage-target"),
	)
	shareReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	shareReq.AddCookie(ownerCookie)
	shareRec := httptest.NewRecorder()
	s.e.ServeHTTP(shareRec, shareReq)
	if shareRec.Code != http.StatusCreated {
		t.Fatalf("share status = %d, want %d", shareRec.Code, http.StatusCreated)
	}

	shareReq2 := httptest.NewRequest(
		http.MethodPost,
		"/user/file/file-manage/shares",
		bytes.NewBufferString("target_type=user_group&target_id=ug-manage"),
	)
	shareReq2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	shareReq2.AddCookie(ownerCookie)
	shareRec2 := httptest.NewRecorder()
	s.e.ServeHTTP(shareRec2, shareReq2)
	if shareRec2.Code != http.StatusCreated {
		t.Fatalf("share2 status = %d, want %d", shareRec2.Code, http.StatusCreated)
	}

	shares, err := queries.ListSharesByFileID(context.Background(), "file-manage")
	if err != nil {
		t.Fatalf("ListSharesByFileID() error: %v", err)
	}
	if len(shares) != 2 {
		t.Fatalf("share count = %d, want %d", len(shares), 2)
	}

	unshareReq := httptest.NewRequest(
		http.MethodPost,
		"/user/file/file-manage/shares/"+shares[0].ID+"/delete",
		nil,
	)
	unshareReq.AddCookie(ownerCookie)
	unshareRec := httptest.NewRecorder()
	s.e.ServeHTTP(unshareRec, unshareReq)
	if unshareRec.Code != http.StatusNoContent {
		t.Fatalf("unshare status = %d, want %d", unshareRec.Code, http.StatusNoContent)
	}

	sharesAfterUnshare, err := queries.ListSharesByFileID(context.Background(), "file-manage")
	if err != nil {
		t.Fatalf("ListSharesByFileID() error: %v", err)
	}
	if len(sharesAfterUnshare) != 1 {
		t.Fatalf("share count after unshare = %d, want %d", len(sharesAfterUnshare), 1)
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/user/file/file-manage/delete", nil)
	deleteReq.AddCookie(ownerCookie)
	deleteRec := httptest.NewRecorder()
	s.e.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", deleteRec.Code, http.StatusNoContent)
	}
	if _, err := queries.GetFileByID(context.Background(), "file-manage"); err != sql.ErrNoRows {
		t.Fatalf("GetFileByID() error = %v, want sql.ErrNoRows", err)
	}
}

func TestUploadFormsRenderForAuthorizedActors(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithoutPassword(t, "c-form-client", "c-form-client@example.com", true)
	createClientGroupForTests(t, "cg-form-group")

	uploaderCookie := login(t, s, "user", "u-form", "uploader")
	userReq := httptest.NewRequest(http.MethodGet, "/user/uploads", nil)
	userReq.AddCookie(uploaderCookie)
	userRec := httptest.NewRecorder()
	s.e.ServeHTTP(userRec, userReq)
	if userRec.Code != http.StatusOK {
		t.Fatalf("user upload form status = %d, want %d", userRec.Code, http.StatusOK)
	}
	userBody := userRec.Body.String()
	if !strings.Contains(userBody, "action=\"/user/uploads\"") ||
		!strings.Contains(userBody, "name=\"filename\"") {
		t.Fatalf("user upload form body = %q, want user form fields", userBody)
	}
	if !strings.Contains(userBody, "name=\"target_type\"") ||
		!strings.Contains(userBody, "<option value=\"client\" selected>Client</option>") {
		t.Fatalf("user upload form body = %q, want target type defaulting to client", userBody)
	}
	if !strings.Contains(userBody, "name=\"target_id\"") ||
		!strings.Contains(userBody, "c-form-client") ||
		!strings.Contains(userBody, "cg-form-group") {
		t.Fatalf(
			"user upload form body = %q, want target_id select options from clients and groups",
			userBody,
		)
	}
	if !strings.Contains(userBody, "enctype=\"multipart/form-data\"") {
		t.Fatalf("user upload form body = %q, want multipart form encoding", userBody)
	}
	if !strings.Contains(userBody, "<span class=\"label-text\">Message...</span>") ||
		!strings.Contains(userBody, "textarea textarea-bordered w-full") {
		t.Fatalf(
			"user upload form body = %q, want full-width message field with standard header",
			userBody,
		)
	}

	clientCookie := login(t, s, "client", "c-form", "")
	clientReq := httptest.NewRequest(http.MethodGet, "/client/uploads", nil)
	clientReq.AddCookie(clientCookie)
	clientRec := httptest.NewRecorder()
	s.e.ServeHTTP(clientRec, clientReq)
	if clientRec.Code != http.StatusOK {
		t.Fatalf("client upload form status = %d, want %d", clientRec.Code, http.StatusOK)
	}
	clientBody := clientRec.Body.String()
	if !strings.Contains(clientBody, "action=\"/client/uploads\"") ||
		!strings.Contains(clientBody, "name=\"filename\"") {
		t.Fatalf("client upload form body = %q, want client form with filename field", clientBody)
	}
	if !strings.Contains(clientBody, "name=\"upload_file\"") ||
		!strings.Contains(clientBody, "data-upload-dropzone") {
		t.Fatalf(
			"client upload form body = %q, want file input and drag-drop upload area",
			clientBody,
		)
	}
	if !strings.Contains(clientBody, "<option value=\"user\" selected>User</option>") ||
		!strings.Contains(clientBody, "<option value=\"user_group\">User Group</option>") {
		t.Fatalf("client upload form body = %q, want user and user_group target types", clientBody)
	}
	if strings.Contains(clientBody, "<option value=\"client\" selected>Client</option>") ||
		strings.Contains(clientBody, "<option value=\"client_group\">Client Group</option>") {
		t.Fatalf("client upload form body = %q, should not offer client target types", clientBody)
	}
}

func TestUserUploadSubmissionValidationAndSuccess(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-submit", "uploader")
	createClientWithoutPassword(t, "c-submit-target", "c-submit-target@example.com", true)

	badReq := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString("filename=&target_type=client&target_id="),
	)
	badReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	badReq.AddCookie(cookie)
	badRec := httptest.NewRecorder()
	s.e.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad submit status = %d, want %d", badRec.Code, http.StatusBadRequest)
	}

	okReq := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString("filename=report.pdf&target_type=client&target_id=c-submit-target"),
	)
	okReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	okReq.AddCookie(cookie)
	okRec := httptest.NewRecorder()
	s.e.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusCreated {
		t.Fatalf(
			"ok submit status = %d, want %d, body=%q",
			okRec.Code,
			http.StatusCreated,
			okRec.Body.String(),
		)
	}
	if !strings.Contains(okRec.Body.String(), "file shared") {
		t.Fatalf("ok submit body = %q, want file shared message", okRec.Body.String())
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("filename", "report-uploaded.pdf"); err != nil {
		t.Fatalf("WriteField(filename) error: %v", err)
	}
	if err := writer.WriteField("target_type", "client"); err != nil {
		t.Fatalf("WriteField(target_type) error: %v", err)
	}
	if err := writer.WriteField("target_id", "c-submit-target"); err != nil {
		t.Fatalf("WriteField(target_id) error: %v", err)
	}
	filePart, err := writer.CreateFormFile("upload_file", "report-uploaded.pdf")
	if err != nil {
		t.Fatalf("CreateFormFile() error: %v", err)
	}
	payload := []byte("hello uploaded file")
	if _, err := filePart.Write(payload); err != nil {
		t.Fatalf("filePart.Write() error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error: %v", err)
	}

	multipartReq := httptest.NewRequest(http.MethodPost, "/user/uploads", &body)
	multipartReq.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	multipartReq.AddCookie(cookie)
	multipartRec := httptest.NewRecorder()
	s.e.ServeHTTP(multipartRec, multipartReq)
	if multipartRec.Code != http.StatusCreated {
		t.Fatalf(
			"multipart submit status = %d, want %d, body=%q",
			multipartRec.Code,
			http.StatusCreated,
			multipartRec.Body.String(),
		)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	filesForUploader, err := db.New(sqlDB).
		ListFilesByUploader(context.Background(), db.ListFilesByUploaderParams{UploaderType: "user", UploaderID: "u-submit", Limit: 50, Offset: 0})
	if err != nil {
		t.Fatalf("ListFilesByUploader() error: %v", err)
	}
	var storedFile db.File
	found := false
	for _, f := range filesForUploader {
		if f.OriginalFilename == "report-uploaded.pdf" {
			storedFile = f
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("uploaded file not found in uploader list")
	}
	if storedFile.SizeBytes != int64(len(payload)) {
		t.Fatalf("stored file size_bytes = %d, want %d", storedFile.SizeBytes, len(payload))
	}
}

func TestUserShareToClientAndClientGroup(t *testing.T) {
	s := New(testConfig(), slog.Default())
	uploaderCookie := login(t, s, "user", "u-sharer", "uploader")

	createClientWithoutPassword(t, "c-share-target", "c-share-target@example.com", true)
	createClientGroupForTests(t, "cg-share-target")

	// Share to a direct client
	clientReq := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString(
			"filename=report.pdf&target_type=client&target_id=c-share-target&message=Here+is+your+file",
		),
	)
	clientReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	clientReq.AddCookie(uploaderCookie)
	clientRec := httptest.NewRecorder()
	s.e.ServeHTTP(clientRec, clientReq)
	if clientRec.Code != http.StatusCreated {
		t.Fatalf(
			"client share status = %d, want %d, body=%q",
			clientRec.Code,
			http.StatusCreated,
			clientRec.Body.String(),
		)
	}
	body := clientRec.Body.String()
	if !strings.Contains(body, "file shared") {
		t.Fatalf("client share body = %q, want file shared", body)
	}

	// The shared file should now be accessible to the target client
	clientViewCookie := login(t, s, "client", "c-share-target", "")
	filesReq := httptest.NewRequest(http.MethodGet, "/client/received", nil)
	filesReq.AddCookie(clientViewCookie)
	filesRec := httptest.NewRecorder()
	s.e.ServeHTTP(filesRec, filesReq)
	if filesRec.Code != http.StatusOK {
		t.Fatalf("client files status = %d, want %d", filesRec.Code, http.StatusOK)
	}
	if !strings.Contains(filesRec.Body.String(), "report.pdf") {
		t.Fatalf("client files body = %q, want shared file name", filesRec.Body.String())
	}

	// Share to a client group
	groupReq := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString(
			"filename=summary.docx&target_type=client_group&target_id=cg-share-target",
		),
	)
	groupReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	groupReq.AddCookie(uploaderCookie)
	groupRec := httptest.NewRecorder()
	s.e.ServeHTTP(groupRec, groupReq)
	if groupRec.Code != http.StatusCreated {
		t.Fatalf(
			"group share status = %d, want %d, body=%q",
			groupRec.Code,
			http.StatusCreated,
			groupRec.Body.String(),
		)
	}
	if !strings.Contains(groupRec.Body.String(), "file shared") {
		t.Fatalf("group share body = %q, want file shared", groupRec.Body.String())
	}

	// Audit log should record the share events
	logs := listAuditLogsByEventType(t, "file.share")
	if len(logs) < 2 {
		t.Fatalf("audit log count = %d, want at least 2 file.share events", len(logs))
	}
}

func TestUserShareInvalidTargetReturnsError(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-invalid-target", "uploader")

	// Non-existent client
	req := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString("filename=test.pdf&target_type=client&target_id=nonexistent-client"),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid client status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Non-existent client group
	req2 := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString(
			"filename=test.pdf&target_type=client_group&target_id=nonexistent-group",
		),
	)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	s.e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("invalid group status = %d, want %d", rec2.Code, http.StatusBadRequest)
	}

	// Invalid target type
	req3 := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString("filename=test.pdf&target_type=invalid&target_id=something"),
	)
	req3.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req3.AddCookie(cookie)
	rec3 := httptest.NewRecorder()
	s.e.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("invalid type status = %d, want %d", rec3.Code, http.StatusBadRequest)
	}
}

func TestUserShareHTMLRedirectsOnSuccess(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-html-share", "uploader")
	createClientWithoutPassword(t, "c-html-target", "c-html-target@example.com", true)

	req := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString("filename=doc.pdf&target_type=client&target_id=c-html-target"),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("html share status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	loc := rec.Result().Header.Get(echo.HeaderLocation)
	if !strings.HasPrefix(loc, "/user/uploads?success=") {
		t.Fatalf("html share redirect = %q, want success redirect", loc)
	}
}

func TestUserFileShareAppearsInUploaderList(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-list-sharer", "uploader")
	createClientWithoutPassword(t, "c-list-target", "c-list-target@example.com", true)

	// Upload and share a file
	shareReq := httptest.NewRequest(
		http.MethodPost,
		"/user/uploads",
		bytes.NewBufferString(
			"filename=listed-file.pdf&target_type=client&target_id=c-list-target",
		),
	)
	shareReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	shareReq.AddCookie(cookie)
	shareRec := httptest.NewRecorder()
	s.e.ServeHTTP(shareRec, shareReq)
	if shareRec.Code != http.StatusCreated {
		t.Fatalf(
			"share status = %d, want %d, body=%q",
			shareRec.Code,
			http.StatusCreated,
			shareRec.Body.String(),
		)
	}

	// The file should appear in the uploader's file list
	listReq := httptest.NewRequest(http.MethodGet, "/user/sent", nil)
	listReq.AddCookie(cookie)
	listRec := httptest.NewRecorder()
	s.e.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	if !strings.Contains(listRec.Body.String(), "listed-file.pdf") {
		t.Fatalf("list body = %q, want uploaded file name", listRec.Body.String())
	}
}

func TestClientsManagementPageRendersForManager(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-page", "account_manager")
	createClientGroupForTests(t, "cg-manager-page")

	req := httptest.NewRequest(http.MethodGet, "/user/clients", nil)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Create Client") {
		t.Fatalf("body = %q, want client creation form", body)
	}
	if strings.Contains(body, "Open Client Groups") {
		t.Fatalf("body = %q, should not include client groups article link", body)
	}
	if !strings.Contains(body, "name=\"group_ids\"") {
		t.Fatalf("body = %q, want optional group select on client form", body)
	}
	if strings.Contains(body, "(cg-manager-page)") {
		t.Fatalf("body = %q, should not show group id in select option label", body)
	}
}

func TestClientGroupsManagementPageRendersForManager(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-group-page", "account_manager")

	req := httptest.NewRequest(http.MethodGet, "/user/client-groups", nil)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Create Group") || !strings.Contains(body, "Add Client to Group") {
		t.Fatalf("body = %q, want client group management forms", body)
	}
}

func TestClientManagementCreateAndMembershipFlows(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-create", "account_manager")

	createClientReq := httptest.NewRequest(
		http.MethodPost,
		"/user/clients",
		bytes.NewBufferString(
			"email=flow-client@example.com&display_name=Flow+Client&can_upload=1&is_active=1",
		),
	)
	createClientReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createClientReq.AddCookie(managerCookie)
	createClientRec := httptest.NewRecorder()
	s.e.ServeHTTP(createClientRec, createClientReq)
	if createClientRec.Code != http.StatusCreated {
		t.Fatalf("create client status = %d, want %d", createClientRec.Code, http.StatusCreated)
	}

	createGroupReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups",
		bytes.NewBufferString("name=FlowGroup"),
	)
	createGroupReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createGroupReq.AddCookie(managerCookie)
	createGroupRec := httptest.NewRecorder()
	s.e.ServeHTTP(createGroupRec, createGroupReq)
	if createGroupRec.Code != http.StatusCreated {
		t.Fatalf("create group status = %d, want %d", createGroupRec.Code, http.StatusCreated)
	}

	clientID := lookupClientIDByEmail(t, "flow-client@example.com")
	groupID := latestClientGroupID(t)

	addMemberReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups/memberships",
		bytes.NewBufferString("group_id="+groupID+"&client_id="+clientID),
	)
	addMemberReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	addMemberReq.AddCookie(managerCookie)
	addMemberRec := httptest.NewRecorder()
	s.e.ServeHTTP(addMemberRec, addMemberReq)
	if addMemberRec.Code != http.StatusCreated {
		t.Fatalf("add membership status = %d, want %d", addMemberRec.Code, http.StatusCreated)
	}

	members := listGroupClientsForTests(t, groupID)
	if len(members) == 0 || members[0].ID != clientID {
		t.Fatalf("members = %+v, want client %s in group", members, clientID)
	}
}

func TestClientManagementGroupListShowsMemberCount(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-group-count", "account_manager")

	createClientReq := httptest.NewRequest(
		http.MethodPost,
		"/user/clients",
		bytes.NewBufferString(
			"email=count-client@example.com&display_name=Count+Client&can_upload=1&is_active=1",
		),
	)
	createClientReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createClientReq.AddCookie(managerCookie)
	createClientRec := httptest.NewRecorder()
	s.e.ServeHTTP(createClientRec, createClientReq)
	if createClientRec.Code != http.StatusCreated {
		t.Fatalf("create client status = %d, want %d", createClientRec.Code, http.StatusCreated)
	}

	createGroupReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups",
		bytes.NewBufferString("name=CountGroup"),
	)
	createGroupReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createGroupReq.AddCookie(managerCookie)
	createGroupRec := httptest.NewRecorder()
	s.e.ServeHTTP(createGroupRec, createGroupReq)
	if createGroupRec.Code != http.StatusCreated {
		t.Fatalf("create group status = %d, want %d", createGroupRec.Code, http.StatusCreated)
	}

	clientID := lookupClientIDByEmail(t, "count-client@example.com")
	groupID := latestClientGroupID(t)

	addMemberReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups/memberships",
		bytes.NewBufferString("group_id="+groupID+"&client_id="+clientID),
	)
	addMemberReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	addMemberReq.AddCookie(managerCookie)
	addMemberRec := httptest.NewRecorder()
	s.e.ServeHTTP(addMemberRec, addMemberReq)
	if addMemberRec.Code != http.StatusCreated {
		t.Fatalf("add membership status = %d, want %d", addMemberRec.Code, http.StatusCreated)
	}

	pageReq := httptest.NewRequest(http.MethodGet, "/user/client-groups", nil)
	pageReq.AddCookie(managerCookie)
	pageRec := httptest.NewRecorder()
	s.e.ServeHTTP(pageRec, pageReq)

	if pageRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", pageRec.Code, http.StatusOK)
	}
	body := pageRec.Body.String()
	if !strings.Contains(body, "CountGroup (1 members)") {
		t.Fatalf("body = %q, want group member count", body)
	}
}

func TestClientGroupDetailRouteSupportsUpdateAndMembershipManagement(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-group-detail", "account_manager")
	createClientWithoutPassword(t, "client-detail-a", "client-detail-a@example.com", true)
	createClientWithoutPassword(t, "client-detail-b", "client-detail-b@example.com", true)
	createClientGroupForTests(t, "cg-detail")
	addClientToGroupForTests(t, "cg-detail", "client-detail-a")

	listReq := httptest.NewRequest(http.MethodGet, "/user/client-groups", nil)
	listReq.AddCookie(managerCookie)
	listRec := httptest.NewRecorder()
	s.e.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	if !strings.Contains(listRec.Body.String(), "href=\"/user/client-groups/cg-detail\"") {
		t.Fatalf("list body = %q, want detail page link", listRec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/user/client-groups/cg-detail", nil)
	detailReq.AddCookie(managerCookie)
	detailRec := httptest.NewRecorder()
	s.e.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d", detailRec.Code, http.StatusOK)
	}
	if !strings.Contains(detailRec.Body.String(), "Remove from Group") ||
		!strings.Contains(detailRec.Body.String(), "client-detail-a@example.com") {
		t.Fatalf("detail body = %q, want member list and remove action", detailRec.Body.String())
	}
	if !strings.Contains(detailRec.Body.String(), "Back to Client Groups") {
		t.Fatalf("detail body = %q, want back link near title", detailRec.Body.String())
	}

	updateReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups/update",
		bytes.NewBufferString("group_id=cg-detail&name=Renamed+Detail+Group"),
	)
	updateReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	updateReq.AddCookie(managerCookie)
	updateRec := httptest.NewRecorder()
	s.e.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusNoContent {
		t.Fatalf(
			"update status = %d, want %d, body=%q",
			updateRec.Code,
			http.StatusNoContent,
			updateRec.Body.String(),
		)
	}

	addReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups/memberships/add",
		bytes.NewBufferString("group_id=cg-detail&client_id=client-detail-b"),
	)
	addReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	addReq.AddCookie(managerCookie)
	addRec := httptest.NewRecorder()
	s.e.ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusCreated {
		t.Fatalf("add membership status = %d, want %d", addRec.Code, http.StatusCreated)
	}

	removeReq := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups/memberships/remove",
		bytes.NewBufferString("group_id=cg-detail&client_id=client-detail-a"),
	)
	removeReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	removeReq.AddCookie(managerCookie)
	removeRec := httptest.NewRecorder()
	s.e.ServeHTTP(removeRec, removeReq)
	if removeRec.Code != http.StatusNoContent {
		t.Fatalf("remove membership status = %d, want %d", removeRec.Code, http.StatusNoContent)
	}

	updatedDetailReq := httptest.NewRequest(http.MethodGet, "/user/client-groups/cg-detail", nil)
	updatedDetailReq.AddCookie(managerCookie)
	updatedDetailRec := httptest.NewRecorder()
	s.e.ServeHTTP(updatedDetailRec, updatedDetailReq)
	if updatedDetailRec.Code != http.StatusOK {
		t.Fatalf("updated detail status = %d, want %d", updatedDetailRec.Code, http.StatusOK)
	}
	updatedBody := updatedDetailRec.Body.String()
	if !strings.Contains(updatedBody, "value=\"Renamed Detail Group\"") {
		t.Fatalf("updated detail body = %q, want updated group name", updatedBody)
	}
	if strings.Contains(updatedBody, "name=\"client_id\" value=\"client-detail-a\"") {
		t.Fatalf(
			"updated detail body = %q, should not include removed member in membership list",
			updatedBody,
		)
	}
	if !strings.Contains(updatedBody, "client-detail-b@example.com") {
		t.Fatalf("updated detail body = %q, want added member", updatedBody)
	}
}

func TestClientManagementHTMLValidationRedirect(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-html", "account_manager")

	req := httptest.NewRequest(
		http.MethodPost,
		"/user/clients",
		bytes.NewBufferString("email=&display_name="),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if !strings.HasPrefix(rec.Result().Header.Get(echo.HeaderLocation), "/user/clients?error=") {
		t.Fatalf(
			"location = %q, want user clients error redirect",
			rec.Result().Header.Get(echo.HeaderLocation),
		)
	}
}

func TestClientCreateAllowsOptionalNoGroupSelection(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-no-group", "account_manager")

	req := httptest.NewRequest(
		http.MethodPost,
		"/user/clients",
		bytes.NewBufferString(
			"email=nogroup-client@example.com&display_name=No+Group+Client&can_upload=1&is_active=1",
		),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create client status = %d, want %d", rec.Code, http.StatusCreated)
	}

	clientID := lookupClientIDByEmail(t, "nogroup-client@example.com")
	groups := listClientGroupsForClient(t, clientID)
	if len(groups) != 0 {
		t.Fatalf("groups = %+v, want no groups", groups)
	}
}

func TestClientCreateCanAssignMultipleGroups(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-multi-group", "account_manager")

	createGroupReqA := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups",
		bytes.NewBufferString("name=AlphaGroup"),
	)
	createGroupReqA.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createGroupReqA.AddCookie(managerCookie)
	createGroupRecA := httptest.NewRecorder()
	s.e.ServeHTTP(createGroupRecA, createGroupReqA)
	if createGroupRecA.Code != http.StatusCreated {
		t.Fatalf("create group A status = %d, want %d", createGroupRecA.Code, http.StatusCreated)
	}

	createGroupReqB := httptest.NewRequest(
		http.MethodPost,
		"/user/client-groups",
		bytes.NewBufferString("name=BetaGroup"),
	)
	createGroupReqB.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createGroupReqB.AddCookie(managerCookie)
	createGroupRecB := httptest.NewRecorder()
	s.e.ServeHTTP(createGroupRecB, createGroupReqB)
	if createGroupRecB.Code != http.StatusCreated {
		t.Fatalf("create group B status = %d, want %d", createGroupRecB.Code, http.StatusCreated)
	}

	groupA := lookupClientGroupIDByName(t, "AlphaGroup")
	groupB := lookupClientGroupIDByName(t, "BetaGroup")

	body := bytes.NewBufferString(
		"email=multigroup-client@example.com&display_name=Multi+Group+Client&is_active=1&group_ids=" + groupA + "&group_ids=" + groupB,
	)
	req := httptest.NewRequest(http.MethodPost, "/user/clients", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create client status = %d, want %d", rec.Code, http.StatusCreated)
	}

	clientID := lookupClientIDByEmail(t, "multigroup-client@example.com")
	groups := listClientGroupsForClient(t, clientID)
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
}

func TestClientManagementClientEditPageRenders(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-edit-page", "account_manager")
	createClientWithoutPassword(t, "c-edit-page", "c-edit-page@example.com", true)

	req := httptest.NewRequest(http.MethodGet, "/user/clients/c-edit-page", nil)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Save Changes") || !strings.Contains(body, "Reset Password") {
		t.Fatalf("body = %q, want client edit and reset forms", body)
	}
	if !strings.Contains(body, "Back to Clients") {
		t.Fatalf("body = %q, want back link near title", body)
	}
}

func TestClientManagementCanUpdateClientFromEditPage(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-edit", "account_manager")
	createClientWithoutPassword(t, "c-edit-update", "c-edit-update@example.com", true)

	req := httptest.NewRequest(
		http.MethodPost,
		"/user/clients/c-edit-update",
		bytes.NewBufferString("display_name=Updated+Client&can_upload=1"),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.AddCookie(managerCookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	client, err := db.New(sqlDB).GetClientByID(context.Background(), "c-edit-update")
	if err != nil {
		t.Fatalf("GetClientByID() error: %v", err)
	}
	if client.DisplayName != "Updated Client" {
		t.Fatalf("display_name = %q, want %q", client.DisplayName, "Updated Client")
	}
	if client.CanUpload != 1 {
		t.Fatalf("can_upload = %d, want 1", client.CanUpload)
	}
	if client.IsActive != 0 {
		t.Fatalf("is_active = %d, want 0 when unchecked", client.IsActive)
	}
}

func TestClientManagementCanResetClientPassword(t *testing.T) {
	s := New(testConfig(), slog.Default())
	managerCookie := login(t, s, "user", "u-manager-client-pass", "account_manager")
	createClientWithPassword(t, "c-edit-pass", "c-edit-pass@example.com", "old-password-123", true)

	resetReq := httptest.NewRequest(
		http.MethodPost,
		"/user/clients/c-edit-pass/reset-password",
		bytes.NewBufferString("new_password=new-password-123"),
	)
	resetReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	resetReq.AddCookie(managerCookie)
	resetRec := httptest.NewRecorder()
	s.e.ServeHTTP(resetRec, resetReq)

	if resetRec.Code != http.StatusNoContent {
		t.Fatalf("reset status = %d, want %d", resetRec.Code, http.StatusNoContent)
	}

	loginReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString(
			"actor_type=client&email=c-edit-pass@example.com&password=new-password-123",
		),
	)
	loginReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	loginRec := httptest.NewRecorder()
	s.e.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusNoContent {
		t.Fatalf("client login status = %d, want %d", loginRec.Code, http.StatusNoContent)
	}
}

func TestClientUploadHTMLRedirectsWithValidationAndOutcome(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientForUploadTests(
		t,
		"client-form-upload",
		"client-form-upload@example.com",
		true,
		true,
	)
	createClientUploadPermissionForTests(
		t,
		"perm-form-upload",
		"client-form-upload",
		"user",
		"u-allow",
	)
	cookie := login(t, s, "client", "client-form-upload", "")

	missingReq := httptest.NewRequest(
		http.MethodPost,
		"/client/uploads",
		bytes.NewBufferString("target_type=&target_id="),
	)
	missingReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	missingReq.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	missingReq.AddCookie(cookie)
	missingRec := httptest.NewRecorder()
	s.e.ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusSeeOther {
		t.Fatalf("missing status = %d, want %d", missingRec.Code, http.StatusSeeOther)
	}
	if !strings.HasPrefix(
		missingRec.Result().Header.Get(echo.HeaderLocation),
		"/client/uploads?error=",
	) {
		t.Fatalf(
			"missing redirect = %q, want error redirect",
			missingRec.Result().Header.Get(echo.HeaderLocation),
		)
	}

	okReq := httptest.NewRequest(
		http.MethodPost,
		"/client/uploads",
		bytes.NewBufferString("filename=upload.pdf&target_type=user&target_id=u-allow"),
	)
	okReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	okReq.Header.Set(echo.HeaderAccept, echo.MIMETextHTML)
	okReq.AddCookie(cookie)
	okRec := httptest.NewRecorder()
	s.e.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusSeeOther {
		t.Fatalf("ok status = %d, want %d", okRec.Code, http.StatusSeeOther)
	}
	if !strings.HasPrefix(
		okRec.Result().Header.Get(echo.HeaderLocation),
		"/client/uploads?success=",
	) {
		t.Fatalf(
			"ok redirect = %q, want success redirect",
			okRec.Result().Header.Get(echo.HeaderLocation),
		)
	}
}

func TestClientUploadStoresFileMetadataAndShare(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientForUploadTests(
		t,
		"client-upload-store",
		"client-upload-store@example.com",
		true,
		true,
	)
	createClientUploadPermissionForTests(
		t,
		"perm-upload-store",
		"client-upload-store",
		"user",
		"u-store-target",
	)
	cookie := login(t, s, "client", "client-upload-store", "")

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("filename", "client-uploaded.pdf"); err != nil {
		t.Fatalf("WriteField(filename) error: %v", err)
	}
	if err := writer.WriteField("target_type", "user"); err != nil {
		t.Fatalf("WriteField(target_type) error: %v", err)
	}
	if err := writer.WriteField("target_id", "u-store-target"); err != nil {
		t.Fatalf("WriteField(target_id) error: %v", err)
	}
	if err := writer.WriteField("message", "client uploaded file"); err != nil {
		t.Fatalf("WriteField(message) error: %v", err)
	}
	filePart, err := writer.CreateFormFile("upload_file", "client-uploaded.pdf")
	if err != nil {
		t.Fatalf("CreateFormFile() error: %v", err)
	}
	payload := []byte("hello from client upload")
	if _, err := filePart.Write(payload); err != nil {
		t.Fatalf("filePart.Write() error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/client/uploads", &body)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf(
			"upload status = %d, want %d, body=%q",
			rec.Code,
			http.StatusCreated,
			rec.Body.String(),
		)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	q := db.New(sqlDB)

	filesForUploader, err := q.ListFilesByUploader(
		context.Background(),
		db.ListFilesByUploaderParams{
			UploaderType: "client",
			UploaderID:   "client-upload-store",
			Limit:        50,
			Offset:       0,
		},
	)
	if err != nil {
		t.Fatalf("ListFilesByUploader() error: %v", err)
	}
	if len(filesForUploader) == 0 {
		t.Fatal("expected at least one uploaded file for client uploader")
	}
	storedFile := filesForUploader[0]
	if storedFile.OriginalFilename != "client-uploaded.pdf" {
		t.Fatalf(
			"stored filename = %q, want %q",
			storedFile.OriginalFilename,
			"client-uploaded.pdf",
		)
	}
	if storedFile.SizeBytes != int64(len(payload)) {
		t.Fatalf("stored file size_bytes = %d, want %d", storedFile.SizeBytes, len(payload))
	}

	shares, err := q.ListSharesByFileID(context.Background(), storedFile.ID)
	if err != nil {
		t.Fatalf("ListSharesByFileID() error: %v", err)
	}
	if len(shares) == 0 {
		t.Fatal("expected at least one share for uploaded file")
	}
	share := shares[0]
	if share.SharedByType != "client" || share.SharedByID != "client-upload-store" {
		t.Fatalf(
			"share actor = %s/%s, want client/client-upload-store",
			share.SharedByType,
			share.SharedByID,
		)
	}
	if share.TargetType != "user" || share.TargetID != "u-store-target" {
		t.Fatalf("share target = %s/%s, want user/u-store-target", share.TargetType, share.TargetID)
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

	cookie := cookieByName(rec.Result().Cookies(), "fileshare_session")
	if cookie == nil {
		t.Fatal("expected fileshare_session cookie")
	}
	if cookie.MaxAge != 5*60*60 {
		t.Fatalf("cookie max-age = %d, want %d", cookie.MaxAge, 5*60*60)
	}
}

func TestSessionLoginForbiddenOutsideTestEnvironment(t *testing.T) {
	s := New(testConfig(), slog.Default())
	s.cfg.Environment = "development"

	body := bytes.NewBufferString("actor_type=user&actor_id=u-forbidden")
	req := httptest.NewRequest(http.MethodPost, "/auth/session", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.TrimSpace(rec.Body.String()) != "forbidden: test-only endpoint" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "forbidden: test-only endpoint")
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

	cleared := cookieByName(logoutRec.Result().Cookies(), "fileshare_session")
	if cleared == nil {
		t.Fatal("expected cleared fileshare_session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("logout cookie max-age = %d, want %d", cleared.MaxAge, -1)
	}
	if !cleared.HttpOnly {
		t.Fatal("logout cookie should be HttpOnly")
	}

	req := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	req.Header.Set(echo.HeaderAccept, "application/json")
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

	cleared := cookieByName(rec.Result().Cookies(), "fileshare_session")
	if cleared == nil {
		t.Fatal("expected cleared fileshare_session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("logout cookie max-age = %d, want %d", cleared.MaxAge, -1)
	}
}

func TestLogoutHTMLRedirectsToLogin(t *testing.T) {
	s := New(testConfig(), slog.Default())
	cookie := login(t, s, "user", "u-logout-html", "")

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set(echo.HeaderAccept, "text/html")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got := rec.Header().Get(echo.HeaderLocation); got != "/login" {
		t.Fatalf("location = %q, want %q", got, "/login")
	}

	cleared := cookieByName(rec.Result().Cookies(), "fileshare_session")
	if cleared == nil {
		t.Fatal("expected cleared fileshare_session cookie")
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("logout cookie max-age = %d, want %d", cleared.MaxAge, -1)
	}
}

func TestSSOLoginCreatesUserSession(t *testing.T) {
	s := New(testConfig(), slog.Default())
	sso := signedSSOToken(
		t,
		"secret",
		"issuer-1",
		"aud-1",
		"user-from-sso",
		"",
		"user-from-sso@example.com",
		"User From SSO",
	)

	req := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_jwt", Value: sso})
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	var appCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "fileshare_session" {
			appCookie = c
			break
		}
	}
	if appCookie == nil {
		t.Fatal("expected fileshare_session cookie")
	}

	userReq := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	userReq.AddCookie(appCookie)
	userRec := httptest.NewRecorder()
	s.e.ServeHTTP(userRec, userReq)

	if userRec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want %d", userRec.Code, http.StatusOK)
	}
	if !strings.Contains(userRec.Body.String(), "actor: user-from-sso") {
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

	first := signedSSOToken(
		t,
		"secret",
		"issuer-1",
		"aud-1",
		"user-upsert",
		"",
		"first@example.com",
		"First Name",
	)
	req1 := httptest.NewRequest(http.MethodPost, "/auth/sso/login", nil)
	req1.AddCookie(&http.Cookie{Name: "sso_jwt", Value: first})
	rec1 := httptest.NewRecorder()
	s.e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("first login status = %d, want %d", rec1.Code, http.StatusNoContent)
	}

	second := signedSSOToken(
		t,
		"secret",
		"issuer-1",
		"aud-1",
		"user-upsert",
		"",
		"updated@example.com",
		"Updated Name",
	)
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
	createClientWithoutPassword(t, "client-1", "client-1@example.com", true)
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
	createClientWithoutPassword(t, "client-verify", "client-verify@example.com", true)
	createFileForTests(t, "file-magic-verify")
	createShareForTests(t, "share-magic-verify", "file-magic-verify", "client", "client-verify")

	token, _, err := s.magic.Create(context.Background(), "client-verify")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	body := bytes.NewBufferString(
		fmt.Sprintf("client_id=client-verify@example.com&token=%s", token),
	)
	req := httptest.NewRequest(http.MethodPost, "/auth/magic/verify", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf(
			"verify status = %d, want %d, body=%q",
			rec.Code,
			http.StatusNoContent,
			rec.Body.String(),
		)
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "fileshare_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected fileshare_session cookie")
	}

	clientReq := httptest.NewRequest(http.MethodGet, "/client/dashboard", nil)
	clientReq.AddCookie(sessionCookie)
	clientRec := httptest.NewRecorder()
	s.e.ServeHTTP(clientRec, clientReq)
	if clientRec.Code != http.StatusOK {
		t.Fatalf("client dashboard status = %d, want %d", clientRec.Code, http.StatusOK)
	}

	filesReq := httptest.NewRequest(http.MethodGet, "/client/received", nil)
	filesReq.AddCookie(sessionCookie)
	filesRec := httptest.NewRecorder()
	s.e.ServeHTTP(filesRec, filesReq)
	if filesRec.Code != http.StatusOK {
		t.Fatalf("client files status = %d, want %d", filesRec.Code, http.StatusOK)
	}
	if !strings.Contains(filesRec.Body.String(), "file-magic-verify") {
		t.Fatalf("client files body = %q, want shared file", filesRec.Body.String())
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
		{
			name:       "admin users allowed",
			path:       "/admin/users",
			cookie:     adminCookie,
			wantStatus: http.StatusOK,
		},
		{
			name:       "manager users denied",
			path:       "/admin/users",
			cookie:     managerCookie,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "manager clients allowed",
			path:       "/user/clients",
			cookie:     managerCookie,
			wantStatus: http.StatusOK,
		},
		{
			name:       "uploader clients denied",
			path:       "/user/clients",
			cookie:     uploaderCookie,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "uploader uploads allowed",
			path:       "/user/uploads",
			cookie:     uploaderCookie,
			wantStatus: http.StatusOK,
		},
		{
			name:       "manager uploads denied",
			path:       "/user/uploads",
			cookie:     managerCookie,
			wantStatus: http.StatusForbidden,
		},
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

func TestAdminUsersManagementFlow(t *testing.T) {
	s := New(testConfig(), slog.Default())
	adminCookie := login(t, s, "user", "u-admin-manage", "admin")

	getReq := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	getReq.AddCookie(adminCookie)
	getRec := httptest.NewRecorder()
	s.e.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("admin users get status = %d, want %d", getRec.Code, http.StatusOK)
	}
	if !strings.Contains(getRec.Body.String(), "Create User") {
		t.Fatalf("admin users body = %q, want create user form", getRec.Body.String())
	}

	createReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/users",
		bytes.NewBufferString(
			"email=admin-flow-user@example.com&full_name=Admin+Flow+User&role_id=3&is_active=1&new_password=admin-password-123",
		),
	)
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	s.e.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("admin users create status = %d, want %d", createRec.Code, http.StatusCreated)
	}

	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()
	queries := db.New(sqlDB)
	createdUser, err := queries.GetUserByEmail(context.Background(), "admin-flow-user@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error: %v", err)
	}
	if createdUser.FullName != "Admin Flow User" {
		t.Fatalf("created full_name = %q, want %q", createdUser.FullName, "Admin Flow User")
	}
	createdRoles, err := queries.ListRoleNamesByUserID(context.Background(), createdUser.ID)
	if err != nil {
		t.Fatalf("ListRoleNamesByUserID() error: %v", err)
	}
	if len(createdRoles) != 1 || createdRoles[0] != "uploader" {
		t.Fatalf("created roles = %v, want [uploader]", createdRoles)
	}

	updateReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/users/"+createdUser.ID,
		bytes.NewBufferString("full_name=Updated+Managed+User&role_id=2"),
	)
	updateReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	updateReq.AddCookie(adminCookie)
	updateRec := httptest.NewRecorder()
	s.e.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusNoContent {
		t.Fatalf("admin users update status = %d, want %d", updateRec.Code, http.StatusNoContent)
	}

	updatedUser, err := queries.GetUserByID(context.Background(), createdUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}
	if updatedUser.FullName != "Updated Managed User" {
		t.Fatalf("updated full_name = %q, want %q", updatedUser.FullName, "Updated Managed User")
	}
	if updatedUser.IsActive != 0 {
		t.Fatalf("updated is_active = %d, want %d", updatedUser.IsActive, 0)
	}
	updatedRoles, err := queries.ListRoleNamesByUserID(context.Background(), createdUser.ID)
	if err != nil {
		t.Fatalf("ListRoleNamesByUserID() error: %v", err)
	}
	if len(updatedRoles) != 1 || updatedRoles[0] != "account_manager" {
		t.Fatalf("updated roles = %v, want [account_manager]", updatedRoles)
	}

	resetReq := httptest.NewRequest(
		http.MethodPost,
		"/admin/users/"+createdUser.ID+"/reset-password",
		bytes.NewBufferString("new_password=reset-password-123"),
	)
	resetReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	resetReq.AddCookie(adminCookie)
	resetRec := httptest.NewRecorder()
	s.e.ServeHTTP(resetRec, resetReq)
	if resetRec.Code != http.StatusNoContent {
		t.Fatalf("admin users reset status = %d, want %d", resetRec.Code, http.StatusNoContent)
	}

	userAfterReset, err := queries.GetUserByID(context.Background(), createdUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID() after reset error: %v", err)
	}
	if err := queries.UpdateUser(
		context.Background(),
		db.UpdateUserParams{
			ID:           userAfterReset.ID,
			FullName:     userAfterReset.FullName,
			PasswordHash: userAfterReset.PasswordHash,
			IsActive:     1,
		},
	); err != nil {
		t.Fatalf("UpdateUser() error: %v", err)
	}
	loginReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString(
			"actor_type=user&email=admin-flow-user@example.com&password=reset-password-123",
		),
	)
	loginReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	loginRec := httptest.NewRecorder()
	s.e.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusNoContent {
		t.Fatalf("password login status = %d, want %d", loginRec.Code, http.StatusNoContent)
	}
}

func TestClientDownloadAuthorization(t *testing.T) {
	s := New(testConfig(), slog.Default())

	createClientWithoutPassword(
		t,
		"client-download-direct",
		"client-download-direct@example.com",
		true,
	)
	createClientWithoutPassword(
		t,
		"client-download-group",
		"client-download-group@example.com",
		true,
	)
	createClientWithoutPassword(
		t,
		"client-download-denied",
		"client-download-denied@example.com",
		true,
	)

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
		{
			name:       "direct share allowed",
			fileID:     "file-direct",
			cookie:     directCookie,
			wantStatus: http.StatusOK,
		},
		{
			name:       "group share allowed",
			fileID:     "file-group",
			cookie:     groupCookie,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing share denied",
			fileID:     "file-direct",
			cookie:     deniedCookie,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/client/file/"+tc.fileID+"/download", nil)
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

	createClientForUploadTests(
		t,
		"client-upload-enabled",
		"client-upload-enabled@example.com",
		true,
		true,
	)
	createClientForUploadTests(
		t,
		"client-upload-disabled",
		"client-upload-disabled@example.com",
		true,
		false,
	)
	createClientForUploadTests(
		t,
		"client-upload-inactive",
		"client-upload-inactive@example.com",
		false,
		true,
	)

	createClientUploadPermissionForTests(
		t,
		"perm-enabled",
		"client-upload-enabled",
		"user",
		"u-target-1",
	)

	enabledCookie := login(t, s, "client", "client-upload-enabled", "")
	disabledCookie := login(t, s, "client", "client-upload-disabled", "")
	inactiveCookie := login(t, s, "client", "client-upload-inactive", "")

	tests := []struct {
		name       string
		cookie     *http.Cookie
		body       string
		wantStatus int
	}{
		{
			name:       "enabled and allowed target",
			cookie:     enabledCookie,
			body:       "filename=allowed.pdf&target_type=user&target_id=u-target-1",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "enabled second user target",
			cookie:     enabledCookie,
			body:       "filename=forbidden.pdf&target_type=user&target_id=u-target-2",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "enabled invalid target type",
			cookie:     enabledCookie,
			body:       "filename=invalid.pdf&target_type=client&target_id=c-target-1",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "disabled upload",
			cookie:     disabledCookie,
			body:       "filename=disabled.pdf&target_type=user&target_id=u-target-1",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "inactive client",
			cookie:     inactiveCookie,
			body:       "filename=inactive.pdf&target_type=user&target_id=u-target-1",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/client/uploads",
				bytes.NewBufferString(tc.body),
			)
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
		t.Fatalf(
			"expected both allowed and denied upload authz audit events; got allowed=%v denied=%v",
			allowedFound,
			deniedFound,
		)
	}
}

func TestMagicLinkVerifySingleUse(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createClientWithoutPassword(t, "client-once", "client-once@example.com", true)
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
	createClientWithoutPassword(t, "client-fail", "client-fail@example.com", true)

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

	cookie := cookieByName(rec.Result().Cookies(), "fileshare_session")
	if cookie == nil {
		t.Fatal("expected fileshare_session cookie")
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
		{
			name:       "password disabled",
			body:       "email=client-nopass@example.com&password=secret-pass",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "wrong password",
			body:       "email=client-pass2@example.com&password=wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing user",
			body:       "email=missing@example.com&password=secret-pass",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/auth/password/login",
				bytes.NewBufferString(tc.body),
			)
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
	createClientWithPassword(
		t,
		"client-pass-audit",
		"client-pass-audit@example.com",
		"secret-pass",
		true,
	)

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

func TestUserPasswordLoginSuccess(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithPassword(t, "user-pass-1", "user-pass@example.com", "secret-pass", true, 1)

	body := bytes.NewBufferString("email=USER-pass@example.com&password=secret-pass")
	req := httptest.NewRequest(http.MethodPost, "/auth/password/login", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%q", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	cookie := cookieByName(rec.Result().Cookies(), "fileshare_session")
	if cookie == nil {
		t.Fatal("expected fileshare_session cookie")
	}

	userReq := httptest.NewRequest(http.MethodGet, "/user/dashboard", nil)
	userReq.AddCookie(cookie)
	userRec := httptest.NewRecorder()
	s.e.ServeHTTP(userRec, userReq)
	if userRec.Code != http.StatusOK {
		t.Fatalf("user dashboard status = %d, want %d", userRec.Code, http.StatusOK)
	}
}

func TestUserPasswordLoginDisabledAndInvalidCredentials(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithoutPassword(t, "user-no-pass", "user-nopass@example.com", true, 1)
	createUserWithPassword(t, "user-pass-2", "user-pass2@example.com", "secret-pass", true, 1)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "password disabled",
			body:       "email=user-nopass@example.com&password=secret-pass",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "wrong password",
			body:       "email=user-pass2@example.com&password=wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing user",
			body:       "email=missing-user@example.com&password=secret-pass",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/auth/password/login",
				bytes.NewBufferString(tc.body),
			)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			rec := httptest.NewRecorder()
			s.e.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestPasswordLoginRateLimited(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithPassword(t, "user-rate-limit", "user-rate-limit@example.com", "secret-pass", true, 1)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(
			http.MethodPost,
			"/auth/password/login",
			bytes.NewBufferString("email=user-rate-limit@example.com&password=wrong-pass"),
		)
		req.RemoteAddr = "203.0.113.10:54321"
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		s.e.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}

	blockedReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString("email=user-rate-limit@example.com&password=wrong-pass"),
	)
	blockedReq.RemoteAddr = "203.0.113.10:54321"
	blockedReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	blockedRec := httptest.NewRecorder()
	s.e.ServeHTTP(blockedRec, blockedReq)
	if blockedRec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked status = %d, want %d", blockedRec.Code, http.StatusTooManyRequests)
	}
}

func TestPasswordResetRequestRateLimited(t *testing.T) {
	s := New(testConfig(), slog.Default())

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(
			http.MethodPost,
			"/auth/password/reset/request",
			bytes.NewBufferString("email=missing@example.com"),
		)
		req.RemoteAddr = "203.0.113.11:54321"
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		s.e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("attempt %d status = %d, want %d", i+1, rec.Code, http.StatusNoContent)
		}
	}

	blockedReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/reset/request",
		bytes.NewBufferString("email=missing@example.com"),
	)
	blockedReq.RemoteAddr = "203.0.113.11:54321"
	blockedReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	blockedRec := httptest.NewRecorder()
	s.e.ServeHTTP(blockedRec, blockedReq)
	if blockedRec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked status = %d, want %d", blockedRec.Code, http.StatusTooManyRequests)
	}
}

func TestPasswordLoginRejectsInvalidActorType(t *testing.T) {
	s := New(testConfig(), slog.Default())
	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString("actor_type=admin&email=user@example.com&password=secret-pass"),
	)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestUserClientEmailUniquenessIsCaseInsensitive(t *testing.T) {
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	defer sqlDB.Close()

	queries := db.New(sqlDB)
	if err := queries.CreateClient(context.Background(), db.CreateClientParams{
		ID:          "client-email-unique",
		Email:       "person@example.com",
		DisplayName: "Person",
		PasswordHash: sql.NullString{
			Valid:  true,
			String: "$2a$10$VfDQFGvx6nWfJPA6RQ73AuoQaRnnz29xI8A4yiA4lp95raJ.4fwwG",
		},
		CanUpload: 0,
		IsActive:  1,
	}); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}

	err = queries.CreateUser(context.Background(), db.CreateUserParams{
		ID:       "user-email-unique",
		Email:    "PERSON@example.com",
		FullName: "Person User",
		PasswordHash: sql.NullString{
			Valid:  true,
			String: "$2a$10$VfDQFGvx6nWfJPA6RQ73AuoQaRnnz29xI8A4yiA4lp95raJ.4fwwG",
		},
		IsActive: 1,
	})
	if err == nil {
		t.Fatal("expected cross-table case-insensitive duplicate email to fail")
	}
}

func TestPasswordResetFlowForUserAndClient(t *testing.T) {
	s := New(testConfig(), slog.Default())
	createUserWithPassword(t, "user-reset", "user-reset@example.com", "old-password-123", true, 3)
	createClientWithPassword(
		t,
		"client-reset",
		"client-reset@example.com",
		"old-password-123",
		true,
	)

	for _, email := range []string{"user-reset@example.com", "client-reset@example.com", "missing-reset@example.com"} {
		req := httptest.NewRequest(
			http.MethodPost,
			"/auth/password/reset/request",
			bytes.NewBufferString("email="+email),
		)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		s.e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf(
				"reset request status for %s = %d, want %d",
				email,
				rec.Code,
				http.StatusNoContent,
			)
		}
	}

	insertPasswordResetForTests(
		t,
		"reset-user-1",
		"user",
		"user-reset",
		"user-reset@example.com",
		"tok-user",
		time.Now().Add(10*time.Minute),
	)
	insertPasswordResetForTests(
		t,
		"reset-client-1",
		"client",
		"client-reset",
		"client-reset@example.com",
		"tok-client",
		time.Now().Add(10*time.Minute),
	)

	confirmReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/reset/confirm",
		bytes.NewBufferString("token=tok-user&new_password=new-password-123"),
	)
	confirmReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	confirmRec := httptest.NewRecorder()
	s.e.ServeHTTP(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusNoContent {
		t.Fatalf("user confirm status = %d, want %d", confirmRec.Code, http.StatusNoContent)
	}

	confirmClientReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/reset/confirm",
		bytes.NewBufferString("token=tok-client&new_password=new-password-123"),
	)
	confirmClientReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	confirmClientRec := httptest.NewRecorder()
	s.e.ServeHTTP(confirmClientRec, confirmClientReq)
	if confirmClientRec.Code != http.StatusNoContent {
		t.Fatalf("client confirm status = %d, want %d", confirmClientRec.Code, http.StatusNoContent)
	}

	userLoginReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString(
			"actor_type=user&email=user-reset@example.com&password=new-password-123",
		),
	)
	userLoginReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	userLoginRec := httptest.NewRecorder()
	s.e.ServeHTTP(userLoginRec, userLoginReq)
	if userLoginRec.Code != http.StatusNoContent {
		t.Fatalf(
			"user login after reset status = %d, want %d",
			userLoginRec.Code,
			http.StatusNoContent,
		)
	}

	clientLoginReq := httptest.NewRequest(
		http.MethodPost,
		"/auth/password/login",
		bytes.NewBufferString(
			"actor_type=client&email=client-reset@example.com&password=new-password-123",
		),
	)
	clientLoginReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	clientLoginRec := httptest.NewRecorder()
	s.e.ServeHTTP(clientLoginRec, clientLoginReq)
	if clientLoginRec.Code != http.StatusNoContent {
		t.Fatalf(
			"client login after reset status = %d, want %d",
			clientLoginRec.Code,
			http.StatusNoContent,
		)
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
	if strings.Contains(string(body), "href=\"/user/dashboard\"") ||
		strings.Contains(string(body), "href=\"/client/dashboard\"") ||
		strings.Contains(string(body), "href=\"/admin/dashboard\"") {
		t.Fatalf("body = %q, should not render actor shortcut links", string(body))
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
	if !strings.Contains(body, "alert alert-error") ||
		!strings.Contains(body, "validation failed") {
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
	body := bytes.NewBufferString(
		fmt.Sprintf("actor_type=%s&actor_id=%s&roles=%s", actorType, actorID, roles),
	)
	req := httptest.NewRequest(http.MethodPost, "/auth/session", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()

	s.e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf(
			"login status = %d, want %d, body=%q",
			rec.Code,
			http.StatusNoContent,
			rec.Body.String(),
		)
	}
	if c := cookieByName(rec.Result().Cookies(), "fileshare_session"); c != nil {
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

func signedSSOToken(
	t *testing.T,
	secret, issuer, audience, userID, subject, email, name string,
) string {
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

func (failingSender) SendMagicLink(_ context.Context, _, _ string) error {
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

func createUserWithPassword(t *testing.T, id, email, password string, active bool, roleID int64) {
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

	queries := db.New(sqlDB)
	if err := queries.CreateUser(context.Background(), db.CreateUserParams{
		ID:           id,
		Email:        email,
		FullName:     email,
		PasswordHash: sql.NullString{Valid: true, String: string(hash)},
		IsActive:     isActive,
	}); err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}
	if err := queries.AddUserRole(
		context.Background(),
		db.AddUserRoleParams{UserID: id, RoleID: roleID},
	); err != nil {
		t.Fatalf("AddUserRole() error: %v", err)
	}
}

func insertPasswordResetForTests(
	t *testing.T,
	id, actorType, actorID, email, token string,
	expiresAt time.Time,
) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	_, err = sqlDB.Exec(`
INSERT INTO password_resets (id, actor_type, actor_id, email, token_hash, expires_at, consumed_at)
VALUES (?, ?, ?, ?, ?, ?, NULL)
`, id, actorType, actorID, email, hashTokenForTests(token), expiresAt.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("insert password reset failed: %v", err)
	}
}

func hashTokenForTests(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func createUserWithoutPassword(t *testing.T, id, email string, active bool, roleID int64) {
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

	queries := db.New(sqlDB)
	if err := queries.CreateUser(context.Background(), db.CreateUserParams{
		ID:           id,
		Email:        email,
		FullName:     email,
		PasswordHash: sql.NullString{},
		IsActive:     isActive,
	}); err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}
	if err := queries.AddUserRole(
		context.Background(),
		db.AddUserRoleParams{UserID: id, RoleID: roleID},
	); err != nil {
		t.Fatalf("AddUserRole() error: %v", err)
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

func createFileWithUploader(t *testing.T, fileID, uploaderID string) {
	createFileWithUploaderType(t, fileID, "user", uploaderID)
}

func createFileWithUploaderType(t *testing.T, fileID, uploaderType, uploaderID string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).CreateFile(context.Background(), db.CreateFileParams{
		ID:               fileID,
		UploaderType:     uploaderType,
		UploaderID:       uploaderID,
		OriginalFilename: fileID + ".dat",
		StorageKey:       "s3/" + fileID,
		ContentType:      "application/octet-stream",
		SizeBytes:        321,
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
		Name:            "Download Group " + groupID,
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

func createClientUploadPermissionForTests(
	t *testing.T,
	permissionID, clientID, targetType, targetID string,
) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	if err := db.New(sqlDB).
		CreateClientUploadPermission(context.Background(), db.CreateClientUploadPermissionParams{
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

	logs, err := db.New(sqlDB).
		ListAuditLogsByEventType(context.Background(), db.ListAuditLogsByEventTypeParams{
			EventType: eventType,
			Limit:     100,
			Offset:    0,
		})
	if err != nil {
		t.Fatalf("ListAuditLogsByEventType() error: %v", err)
	}
	return logs
}

func lookupClientIDByEmail(t *testing.T, email string) string {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	client, err := db.New(sqlDB).GetClientByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("GetClientByEmail() error: %v", err)
	}
	return client.ID
}

func latestClientGroupID(t *testing.T) string {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	groups, err := db.New(sqlDB).
		ListClientGroups(context.Background(), db.ListClientGroupsParams{Limit: 1, Offset: 0})
	if err != nil {
		t.Fatalf("ListClientGroups() error: %v", err)
	}
	if len(groups) == 0 {
		t.Fatal("expected at least one client group")
	}
	return groups[0].ID
}

func listGroupClientsForTests(t *testing.T, groupID string) []db.Client {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	clients, err := db.New(sqlDB).ListGroupClients(context.Background(), groupID)
	if err != nil {
		t.Fatalf("ListGroupClients() error: %v", err)
	}
	return clients
}

func lookupClientGroupIDByName(t *testing.T, name string) string {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	groups, err := db.New(sqlDB).
		ListClientGroups(context.Background(), db.ListClientGroupsParams{Limit: 200, Offset: 0})
	if err != nil {
		t.Fatalf("ListClientGroups() error: %v", err)
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID
		}
	}
	t.Fatalf("client group named %q not found", name)
	return ""
}

func listClientGroupsForClient(t *testing.T, clientID string) []db.ClientGroup {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", testConfig().DatabaseURL)
	if err != nil {
		t.Fatalf("sql.Open() unexpected error: %v", err)
	}
	defer sqlDB.Close()

	queries := db.New(sqlDB)
	groups, err := queries.ListClientGroups(
		context.Background(),
		db.ListClientGroupsParams{Limit: 200, Offset: 0},
	)
	if err != nil {
		t.Fatalf("ListClientGroups() error: %v", err)
	}
	out := make([]db.ClientGroup, 0)
	for _, g := range groups {
		clients, listErr := queries.ListGroupClients(context.Background(), g.ID)
		if listErr != nil {
			t.Fatalf("ListGroupClients() error: %v", listErr)
		}
		for _, c := range clients {
			if c.ID == clientID {
				out = append(out, g)
				break
			}
		}
	}
	return out
}
