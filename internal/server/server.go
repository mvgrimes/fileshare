package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"sharefile/internal/auth"
	"sharefile/internal/config"
	"sharefile/internal/db"
	"sharefile/internal/mail"
	webassets "sharefile/internal/web/assets"
	webtemplates "sharefile/internal/web/templates"
	"sharefile/migrations"

	_ "modernc.org/sqlite"
)

type Server struct {
	e         *echo.Echo
	cfg       *config.Config
	log       *slog.Logger
	sessions  *auth.Manager
	authz     *auth.AuthorizationService
	userSync  *auth.UserSyncer
	clientPwd *auth.ClientPasswordAuthenticator
	magic     *auth.MagicManager
	magicSend auth.MagicSender
}

type TemplateRenderer struct {
	templates *template.Template
}

type dashboardAction struct {
	Label       string
	Description string
	Path        string
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	viewData, ok := data.(map[string]any)
	if !ok {
		viewData = map[string]any{}
	}
	viewData["Path"] = c.Request().URL.Path
	return r.templates.ExecuteTemplate(w, name, viewData)
}

func New(cfg *config.Config, log *slog.Logger) *Server {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		_ = c.String(http.StatusInternalServerError, "internal server error")
	}

	t := template.Must(loadTemplates())
	e.Renderer = &TemplateRenderer{templates: t}
	assetsFS := mustSubFS(webassets.Files, "dist")
	e.StaticFS("/assets", assetsFS)

	e.Use(middleware.RequestID())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:    true,
		LogURI:       true,
		LogMethod:    true,
		LogLatency:   true,
		LogRequestID: true,
		HandleError:  true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			log.Info("http request",
				"request_id", v.RequestID,
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
				"latency", v.Latency.String(),
			)
			return nil
		},
	}))

	e.Use(middleware.Recover())
	e.Use(middleware.Secure())
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/auth/session" || c.Path() == "/auth/logout" || c.Path() == "/auth/sso/login" || c.Path() == "/auth/magic/request" || c.Path() == "/auth/magic/verify" || c.Path() == "/auth/password/login" || c.Path() == "/client/uploads"
		},
	}))
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))

	sqlDB, err := sql.Open("sqlite", cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	if err := verifySchemaUpToDate(sqlDB); err != nil {
		panic(err)
	}

	queries := db.New(sqlDB)
	sessionTTL := time.Duration(cfg.SessionTTL) * time.Hour
	sessions := auth.NewManager(queries, sessionTTL)
	authz := auth.NewAuthorizationService(queries, queries)
	userSync := auth.NewUserSyncer(queries)
	clientPwd := auth.NewClientPasswordAuthenticator(queries)
	magic := auth.NewMagicManager(queries, 15*time.Minute, 60*time.Second)
	magicSend := auth.MagicSender(auth.NoopSender{})
	if cfg.MailgunDomain != "" && cfg.MailgunAPIKey != "" && cfg.MailgunFromEmail != "" {
		sender, senderErr := mail.NewMailgunSender(cfg.MailgunAPIBaseURL, cfg.MailgunDomain, cfg.MailgunAPIKey, cfg.MailgunFromEmail, nil)
		if senderErr != nil {
			panic(senderErr)
		}
		magicSend = sender
	}
	srv := &Server{e: e, cfg: cfg, log: log, sessions: sessions, authz: authz, userSync: userSync, clientPwd: clientPwd, magic: magic, magicSend: magicSend}
	e.Use(auth.LoadSession(sessions))

	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	e.GET("/readyz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})

	public := e.Group("")
	public.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "home", map[string]any{
			"Title":           "ShareFile",
			"ContentTemplate": "home_content",
		})
	})
	public.GET("/login", func(c echo.Context) error {
		return c.Render(http.StatusOK, "auth", map[string]any{
			"Title":           "Login",
			"Subtitle":        "Sign in with SSO or client password.",
			"FlashError":      c.QueryParam("error"),
			"FlashSuccess":    c.QueryParam("success"),
			"ContentTemplate": "login_content",
		})
	})
	public.GET("/request-link", func(c echo.Context) error {
		return c.Render(http.StatusOK, "auth", map[string]any{
			"Title":           "Request Magic Link",
			"Subtitle":        "Request or verify a one-time login token.",
			"FlashError":      c.QueryParam("error"),
			"FlashSuccess":    c.QueryParam("success"),
			"ContentTemplate": "request_link_content",
		})
	})
	public.POST("/auth/session", func(c echo.Context) error {
		actorType := c.FormValue("actor_type")
		actorID := c.FormValue("actor_id")
		roles := parseRoles(c.FormValue("roles"))
		if actorType == "" || actorID == "" {
			return c.String(http.StatusBadRequest, "actor_type and actor_id are required")
		}
		if actorType != "user" && actorType != "client" {
			return c.String(http.StatusBadRequest, "actor_type must be user or client")
		}
		token, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: actorType, ActorID: actorID, Roles: roles})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		setSessionCookie(c, cfg.Environment, token, sessionTTL)
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/logout", func(c echo.Context) error {
		cookie, err := c.Cookie(auth.SessionCookieName)
		if err == nil {
			if session, loadErr := sessions.LoadSession(c.Request().Context(), cookie.Value); loadErr == nil {
				auditAuthEvent(c, queries, "auth.logout", session.Principal.ActorType, session.Principal.ActorID, "session", session.TokenHash, map[string]any{"outcome": "success"})
			}
			_ = sessions.RevokeSession(c.Request().Context(), cookie.Value)
		}
		c.SetCookie(&http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   sCookieSecure(cfg.Environment),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/sso/login", func(c echo.Context) error {
		ssoCookie, err := c.Cookie(cfg.SSOCookieName)
		if err != nil || ssoCookie.Value == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Missing SSO cookie"))
			}
			auditAuthEvent(c, queries, "auth.sso.login", "", "", "user", "", map[string]any{"outcome": "failure", "reason": "missing_cookie"})
			return c.String(http.StatusUnauthorized, "missing sso cookie")
		}

		validator := auth.NewSSOValidator(cfg.JWTSecret, cfg.SSOIssuer, cfg.SSOAudience)
		claims, err := validator.Validate(ssoCookie.Value)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Invalid SSO token"))
			}
			auditAuthEvent(c, queries, "auth.sso.login", "", "", "user", "", map[string]any{"outcome": "failure", "reason": "invalid_token"})
			return c.String(http.StatusUnauthorized, "invalid sso token")
		}

		actorID, err := srv.userSync.UpsertFromSSOClaims(c.Request().Context(), claims)
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Invalid SSO claims"))
			}
			auditAuthEvent(c, queries, "auth.sso.login", "", "", "user", "", map[string]any{"outcome": "failure", "reason": "invalid_claims"})
			return c.String(http.StatusUnauthorized, "invalid sso token")
		}

		token, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: "user", ActorID: actorID, Roles: claims.Roles})
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Unable to create session"))
			}
			auditAuthEvent(c, queries, "auth.sso.login", "user", actorID, "user", actorID, map[string]any{"outcome": "failure", "reason": "session_create_failed"})
			return c.String(http.StatusInternalServerError, "failed to create session")
		}

		auditAuthEvent(c, queries, "auth.sso.login", "user", actorID, "user", actorID, map[string]any{"outcome": "success"})
		setSessionCookie(c, cfg.Environment, token, sessionTTL)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/dashboard")
		}

		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/magic/request", func(c echo.Context) error {
		clientID := c.FormValue("client_id")
		if clientID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Client ID is required"))
			}
			auditAuthEvent(c, queries, "auth.magic.request", "", "", "client", "", map[string]any{"outcome": "failure", "reason": "missing_client_id"})
			return c.String(http.StatusBadRequest, "client_id is required")
		}

		token, _, err := magic.Create(c.Request().Context(), clientID)
		if err != nil {
			if err == auth.ErrMagicLinkThrottled {
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Magic link request throttled"))
				}
				auditAuthEvent(c, queries, "auth.magic.request", "", "", "client", clientID, map[string]any{"outcome": "failure", "reason": "throttled"})
				return c.String(http.StatusTooManyRequests, "magic link request throttled")
			}
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Unable to create magic link"))
			}
			auditAuthEvent(c, queries, "auth.magic.request", "", "", "client", clientID, map[string]any{"outcome": "failure", "reason": "create_failed"})
			return c.String(http.StatusInternalServerError, "failed to create magic link")
		}

		if err := srv.magicSend.SendMagicLink(c.Request().Context(), clientID, token); err != nil {
			log.Error("magic link delivery failed", "client_id", clientID, "error", err.Error())
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Failed to deliver magic link"))
			}
			auditAuthEvent(c, queries, "auth.magic.request", "", "", "client", clientID, map[string]any{"outcome": "failure", "reason": "delivery_failed"})
			return c.String(http.StatusBadGateway, "failed to deliver magic link")
		}

		auditAuthEvent(c, queries, "auth.magic.request", "", "", "client", clientID, map[string]any{"outcome": "success"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/request-link?success="+url.QueryEscape("Magic link sent"))
		}
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/magic/verify", func(c echo.Context) error {
		clientID := c.FormValue("client_id")
		token := c.FormValue("token")
		if clientID == "" || token == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Client ID and token are required"))
			}
			auditAuthEvent(c, queries, "auth.magic.verify", "", "", "client", clientID, map[string]any{"outcome": "failure", "reason": "missing_input"})
			return c.String(http.StatusBadRequest, "client_id and token are required")
		}

		_, err := magic.Consume(c.Request().Context(), clientID, token)
		if err != nil {
			switch err {
			case auth.ErrMagicLinkExpired, auth.ErrMagicLinkConsumed, auth.ErrMagicLinkNotFound:
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Invalid or expired magic link"))
				}
				auditAuthEvent(c, queries, "auth.magic.verify", "", "", "client", clientID, map[string]any{"outcome": "failure", "reason": "invalid_or_expired"})
				return c.String(http.StatusUnauthorized, "invalid or expired magic link")
			default:
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Failed to verify magic link"))
				}
				auditAuthEvent(c, queries, "auth.magic.verify", "", "", "client", clientID, map[string]any{"outcome": "failure", "reason": "verify_failed"})
				return c.String(http.StatusInternalServerError, "failed to verify magic link")
			}
		}

		sessionToken, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: "client", ActorID: clientID})
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/request-link?error="+url.QueryEscape("Unable to create session"))
			}
			auditAuthEvent(c, queries, "auth.magic.verify", "client", clientID, "client", clientID, map[string]any{"outcome": "failure", "reason": "session_create_failed"})
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		auditAuthEvent(c, queries, "auth.magic.verify", "client", clientID, "client", clientID, map[string]any{"outcome": "success"})
		setSessionCookie(c, cfg.Environment, sessionToken, sessionTTL)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/dashboard")
		}
		return c.NoContent(http.StatusNoContent)
	})
	public.POST("/auth/password/login", func(c echo.Context) error {
		email := c.FormValue("email")
		password := c.FormValue("password")
		client, err := srv.clientPwd.Authenticate(c.Request().Context(), email, password)
		if err != nil {
			switch err {
			case auth.ErrClientPasswordDisabled:
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Password auth disabled"))
				}
				auditAuthEvent(c, queries, "auth.password.login", "", "", "client", email, map[string]any{"outcome": "failure", "reason": "disabled"})
				return c.String(http.StatusForbidden, "password auth disabled")
			case auth.ErrInvalidClientCredentials:
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Invalid credentials"))
				}
				auditAuthEvent(c, queries, "auth.password.login", "", "", "client", email, map[string]any{"outcome": "failure", "reason": "invalid_credentials"})
				return c.String(http.StatusUnauthorized, "invalid credentials")
			default:
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Failed to authenticate"))
				}
				auditAuthEvent(c, queries, "auth.password.login", "", "", "client", email, map[string]any{"outcome": "failure", "reason": "auth_failed"})
				return c.String(http.StatusInternalServerError, "failed to authenticate")
			}
		}

		token, _, err := sessions.CreateSession(c.Request().Context(), auth.Principal{ActorType: "client", ActorID: client.ID})
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Unable to create session"))
			}
			auditAuthEvent(c, queries, "auth.password.login", "client", client.ID, "client", client.ID, map[string]any{"outcome": "failure", "reason": "session_create_failed"})
			return c.String(http.StatusInternalServerError, "failed to create session")
		}

		auditAuthEvent(c, queries, "auth.password.login", "client", client.ID, "client", client.ID, map[string]any{"outcome": "success"})
		setSessionCookie(c, cfg.Environment, token, sessionTTL)
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/dashboard")
		}
		return c.NoContent(http.StatusNoContent)
	})

	user := e.Group("/user")
	user.Use(auth.RequireAuth(), auth.RequireActorType("user"))
	user.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		actions := dashboardActions(principal)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "User Dashboard",
			"Role":            principal.ActorType,
			"Subtitle":        "Your available actions are based on assigned roles.",
			"ActorID":         principal.ActorID,
			"DashboardActions": actions,
			"HasActions":      len(actions) > 0,
			"ContentTemplate": "dashboard_content",
		})
	})
	user.GET("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := srv.authz.AuthorizeUploadFiles(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "uploader access granted")
	}, auth.RequireCapability(auth.CapabilityUploadFiles))
	user.GET("/clients", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := srv.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "account manager access granted")
	}, auth.RequireCapability(auth.CapabilityManageClients))

	client := e.Group("/client")
	client.Use(auth.RequireAuth(), auth.RequireActorType("client"))
	client.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		actions := []dashboardAction{{
			Label:       "Request a Magic Link",
			Description: "Need a fresh login token? Request and verify a new magic link.",
			Path:        "/request-link",
		}}
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Client Dashboard",
			"Role":            principal.ActorType,
			"Subtitle":        "Use secure links to access files and upload where permitted.",
			"ActorID":         principal.ActorID,
			"DashboardActions": actions,
			"HasActions":      true,
			"ContentTemplate": "dashboard_content",
		})
	})
	client.GET("/files/:fileID/download", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		if err := srv.authz.AuthorizeClientDownload(c.Request().Context(), principal, c.Param("fileID")); err != nil {
			auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "denied", "reason": "forbidden"})
			if err == auth.ErrForbidden {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return c.String(http.StatusInternalServerError, "failed to authorize download")
		}
		auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "allowed"})
		return c.String(http.StatusOK, "download access granted")
	})
	client.POST("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		targetType := strings.TrimSpace(c.FormValue("target_type"))
		targetID := strings.TrimSpace(c.FormValue("target_id"))
		if err := srv.authz.AuthorizeClientUpload(c.Request().Context(), principal, targetType, targetID); err != nil {
			auditAuthEvent(c, queries, "authz.client.upload", principal.ActorType, principal.ActorID, targetType, targetID, map[string]any{"outcome": "denied", "reason": "forbidden"})
			if err == auth.ErrForbidden {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return c.String(http.StatusInternalServerError, "failed to authorize upload")
		}
		auditAuthEvent(c, queries, "authz.client.upload", principal.ActorType, principal.ActorID, targetType, targetID, map[string]any{"outcome": "allowed"})
		return c.String(http.StatusOK, "upload access granted")
	})

	admin := e.Group("/admin")
	admin.Use(auth.RequireAuth(), auth.RequireActorType("user"), auth.RequireRole("admin"))
	admin.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":           "Admin Dashboard",
			"Role":            principal.ActorType,
			"ActorID":         principal.ActorID,
			"ContentTemplate": "dashboard_content",
		})
	})
	admin.GET("/users", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := srv.authz.AuthorizeManageUsers(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "admin access granted")
	}, auth.RequireCapability(auth.CapabilityManageUsers))

	return srv
}

func verifySchemaUpToDate(sqlDB *sql.DB) error {
	latest, err := migrations.LatestVersion()
	if err != nil {
		return fmt.Errorf("resolve latest migration version: %w", err)
	}

	var current int64
	row := sqlDB.QueryRow(`
SELECT version_id
FROM goose_db_version
WHERE is_applied = 1
ORDER BY id DESC
LIMIT 1;
`)
	if err := row.Scan(&current); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("database schema is not migrated: run `go run . migrate up`")
		}
		return fmt.Errorf("read goose version: %w", err)
	}

	if current < latest {
		return fmt.Errorf("database schema is out of date (current=%d, latest=%d): run `go run . migrate up`", current, latest)
	}

	return nil
}

func sCookieSecure(environment string) bool {
	return environment != "development"
}

func setSessionCookie(c echo.Context, environment, token string, ttl time.Duration) {
	c.SetCookie(&http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   sCookieSecure(environment),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func auditAuthEvent(c echo.Context, queries *db.Queries, eventType, actorType, actorID, entityType, entityID string, metadata map[string]any) {
	metadataJSON, _ := json.Marshal(metadata)
	_ = queries.CreateAuditLog(c.Request().Context(), db.CreateAuditLogParams{
		ID:           uuid.NewString(),
		ActorType:    nullableString(actorType),
		ActorID:      nullableString(actorID),
		EventType:    eventType,
		EntityType:   nullableString(entityType),
		EntityID:     nullableString(entityID),
		MetadataJson: sql.NullString{Valid: len(metadataJSON) > 0, String: string(metadataJSON)},
	})
}

func nullableString(v string) sql.NullString {
	v = strings.TrimSpace(v)
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{Valid: true, String: v}
}

func loadTemplates() (*template.Template, error) {
	return template.ParseFS(webtemplates.Files, "*.html")
}

func parseRoles(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	roles := make([]string, 0, len(parts))
	for _, p := range parts {
		r := strings.TrimSpace(p)
		if r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

func dashboardActions(principal auth.Principal) []dashboardAction {
	actions := make([]dashboardAction, 0, 3)
	if auth.HasCapability(principal, auth.CapabilityUploadFiles) {
		actions = append(actions, dashboardAction{
			Label:       "Upload Files",
			Description: "Submit files for sharing with approved recipients.",
			Path:        "/user/uploads",
		})
	}
	if auth.HasCapability(principal, auth.CapabilityManageClients) {
		actions = append(actions, dashboardAction{
			Label:       "Manage Clients",
			Description: "Create clients and manage client-group membership.",
			Path:        "/user/clients",
		})
	}
	if auth.HasCapability(principal, auth.CapabilityManageUsers) {
		actions = append(actions, dashboardAction{
			Label:       "Manage Users",
			Description: "Administer user access and user roles.",
			Path:        "/admin/users",
		})
	}
	return actions
}

func isHTMLRequest(c echo.Context) bool {
	accept := strings.ToLower(c.Request().Header.Get(echo.HeaderAccept))
	return strings.Contains(accept, "text/html")
}

func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ServerAddress, s.cfg.ServerPort)
	s.log.Info("starting server", "address", addr)
	return s.e.Start(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.e.Shutdown(ctx)
}
