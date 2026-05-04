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
	userPwd   *auth.UserPasswordAuthenticator
	clientPwd *auth.ClientPasswordAuthenticator
	magic     *auth.MagicManager
	magicSend auth.MagicSender
	notifier  *mail.Notifier
}

type TemplateRenderer struct {
	templates *template.Template
}

type dashboardAction struct {
	Label       string
	Description string
	Path        string
}

type fileListItem struct {
	ID          string
	Name        string
	ContentType string
	SizeBytes   int64
	SharedVia   string
}

type fileShareListItem struct {
	ID          string
	TargetType  string
	TargetID    string
	TargetLabel string
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	viewData, ok := data.(map[string]any)
	if !ok {
		viewData = map[string]any{}
	}
	viewData["Path"] = c.Request().URL.Path
	principal, isAuthenticated := auth.PrincipalFromContext(c)
	viewData["IsAuthenticated"] = isAuthenticated
	if isAuthenticated {
		viewData["DashboardPath"] = dashboardPathForPrincipal(principal)
	}
	return r.templates.ExecuteTemplate(w, name, viewData)
}

func dashboardPathForPrincipal(principal auth.Principal) string {
	if principal.ActorType == "client" {
		return "/client/dashboard"
	}
	for _, role := range principal.Roles {
		if role == "admin" {
			return "/admin/dashboard"
		}
	}
	return "/user/dashboard"
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
			return c.Path() == "/auth/session" || c.Path() == "/auth/logout" || c.Path() == "/auth/sso/login" || c.Path() == "/auth/magic/request" || c.Path() == "/auth/magic/verify" || c.Path() == "/auth/password/login" || c.Path() == "/client/uploads" || c.Path() == "/user/uploads" || c.Path() == "/user/clients" || c.Path() == "/user/client-groups" || c.Path() == "/user/client-groups/memberships" || c.Path() == "/user/files/:fileID/rename" || c.Path() == "/user/files/:fileID/delete" || c.Path() == "/user/files/:fileID/shares" || c.Path() == "/user/files/:fileID/shares/:shareID/delete"
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
	userPwd := auth.NewUserPasswordAuthenticator(queries)
	clientPwd := auth.NewClientPasswordAuthenticator(queries)
	magic := auth.NewMagicManager(queries, 15*time.Minute, 60*time.Second)
	magicSend := auth.MagicSender(auth.NoopSender{})
	renderer, renderErr := mail.NewHermesRenderer("ShareFile", "https://sharefile.local", "")
	if renderErr != nil {
		panic(renderErr)
	}
	eventStore := mail.NewEventStore(queries)
	notifier := mail.NewNotifier(renderer, mail.NoopMessageSender{}, eventStore)
	if cfg.MailgunDomain != "" && cfg.MailgunAPIKey != "" && cfg.MailgunFromEmail != "" {
		sender, senderErr := mail.NewMailgunSender(cfg.MailgunAPIBaseURL, cfg.MailgunDomain, cfg.MailgunAPIKey, cfg.MailgunFromEmail, nil, renderer)
		if senderErr != nil {
			panic(senderErr)
		}
		magicSend = sender
		notifier = mail.NewNotifier(renderer, sender, eventStore)
	}

	srv := &Server{e: e, cfg: cfg, log: log, sessions: sessions, authz: authz, userSync: userSync, userPwd: userPwd, clientPwd: clientPwd, magic: magic, magicSend: magicSend, notifier: notifier}
	e.Use(auth.LoadSession(sessions))

	srv.registerSystemRoutes()
	srv.registerPublicRoutes(queries, sessionTTL)
	srv.registerUserRoutes(queries)
	srv.registerClientRoutes(queries)
	srv.registerAdminRoutes(queries)

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

func resolveShareRecipientEmails(ctx context.Context, queries *db.Queries, targetType, targetID string) ([]string, error) {
	switch targetType {
	case "client":
		client, err := queries.GetClientByID(ctx, targetID)
		if err != nil {
			return nil, err
		}
		return []string{client.Email}, nil
	case "client_group":
		clients, err := queries.ListGroupClients(ctx, targetID)
		if err != nil {
			return nil, err
		}
		emails := make([]string, 0, len(clients))
		seen := map[string]struct{}{}
		for _, c := range clients {
			email := strings.TrimSpace(c.Email)
			if email == "" {
				continue
			}
			if _, ok := seen[email]; ok {
				continue
			}
			seen[email] = struct{}{}
			emails = append(emails, email)
		}
		return emails, nil
	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}
}

func resolveClientUploadRecipients(ctx context.Context, queries *db.Queries, targetType, targetID string) ([]string, error) {
	switch targetType {
	case "user":
		user, err := queries.GetUserByID(ctx, targetID)
		if err != nil {
			return nil, err
		}
		return []string{user.Email}, nil
	case "user_group":
		users, err := queries.ListGroupUsers(ctx, targetID)
		if err != nil {
			return nil, err
		}
		emails := make([]string, 0, len(users))
		seen := map[string]struct{}{}
		for _, u := range users {
			email := strings.TrimSpace(u.Email)
			if email == "" {
				continue
			}
			if _, ok := seen[email]; ok {
				continue
			}
			seen[email] = struct{}{}
			emails = append(emails, email)
		}
		return emails, nil
	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}
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
	if auth.HasCapability(principal, auth.CapabilityUploadFiles) {
		actions = append(actions, dashboardAction{
			Label:       "View Shared Files",
			Description: "Review files uploaded by your account.",
			Path:        "/user/files",
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
