package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/config"
	"fileshare/internal/db"
	"fileshare/internal/files"
	"fileshare/internal/mail"
	"fileshare/internal/monitoring"
	"fileshare/migrations"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	webassets "fileshare/internal/web/assets"
	webtemplates "fileshare/internal/web/templates"

	_ "modernc.org/sqlite"
)

type Server struct {
	e                    *echo.Echo
	cfg                  *config.Config
	log                  *slog.Logger
	sessions             *auth.Manager
	authz                *auth.AuthorizationService
	userSync             *auth.UserSyncer
	userPwd              *auth.UserPasswordAuthenticator
	clientPwd            *auth.ClientPasswordAuthenticator
	magic                *auth.MagicManager
	resetPwd             *auth.PasswordResetManager
	turnstile            *turnstileVerifier
	magicSend            auth.MagicSender
	notifier             *mail.Notifier
	uploadSvc            *files.UploadService
	downSvc              *files.DownloadService
	emailLogo            []byte
	emailLogoContentType string
}

const emailLogoPath = "/branding/logo"

type TemplateRenderer struct {
	templates        *template.Template
	environment      string
	brandingLabel    string
	faviconURL       string
	logoURL          string
	logoHeroURL      string
	turnstileEnabled bool
	turnstileSiteKey string
}

type dashboardAction struct {
	Label       string
	Description string
	Path        string
	Icon        string
	Active      bool
}

type fileListItem struct {
	ID          string
	FileID      string
	Name        string
	ContentType string
	SizeBytes   int64
	SharedVia   string
	SharedBy    string
	Message     string
	UploadedAt  string
	SharedAt    string
	ViewStatus  string
}

type fileShareListItem struct {
	ID          string
	FileID      string
	TargetType  string
	TargetID    string
	TargetLabel string
	Message     string
	SharedAt    string
	ViewStatus  string
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	viewData, ok := data.(map[string]any)
	if !ok {
		viewData = map[string]any{}
	}
	viewData["Path"] = c.Request().URL.Path
	viewData["BrandingLabel"] = r.brandingLabel
	viewData["BrandFavicon"] = template.URL(r.faviconURL)
	viewData["BrandLogo"] = template.URL(r.logoURL)
	viewData["BrandLogoHero"] = template.URL(r.logoHeroURL)
	viewData["TurnstileEnabled"] = r.turnstileEnabled
	viewData["TurnstileSiteKey"] = r.turnstileSiteKey
	principal, isAuthenticated := auth.PrincipalFromContext(c)
	viewData["IsAuthenticated"] = isAuthenticated
	if isAuthenticated {
		viewData["DashboardPath"] = dashboardPathForPrincipal(principal, c.Request().URL.Path)
		viewData["PrincipalActorType"] = principal.ActorType
		switch principal.ActorType {
		case "user":
			viewData["UseAppDrawer"] = true
			viewData["SidebarActions"] = markActiveSidebarActions(
				withDashboardAction(dashboardActions(principal), "/user/dashboard"),
				c.Request().URL.Path,
			)
		case "client":
			viewData["UseAppDrawer"] = true
			viewData["SidebarActions"] = markActiveSidebarActions(
				withDashboardAction(clientDashboardActions(), "/client/dashboard"),
				c.Request().URL.Path,
			)
		}
	}
	t := r.templates
	if r.environment == "development" {
		devTemplates, err := loadTemplates(r.environment)
		if err != nil {
			return err
		}
		t = devTemplates
	}

	return t.ExecuteTemplate(w, name, viewData)
}

func dashboardPathForPrincipal(principal auth.Principal, requestPath string) string {
	if strings.HasPrefix(requestPath, "/admin/") {
		return "/admin/dashboard"
	}
	if strings.HasPrefix(requestPath, "/client/") {
		return "/client/dashboard"
	}
	if principal.ActorType == "client" {
		return "/client/dashboard"
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
		status := http.StatusInternalServerError
		if httpErr, ok := err.(*echo.HTTPError); ok {
			status = httpErr.Code
		}
		if status < http.StatusInternalServerError {
			_ = c.String(status, http.StatusText(status))
			return
		}
		requestID := c.Response().Header().Get(echo.HeaderXRequestID)
		log.Error("http internal error",
			"request_id", requestID,
			"method", c.Request().Method,
			"uri", c.Request().RequestURI,
			"error", err,
		)
		monitoring.Report(
			monitoring.WrapHTTPError(err, requestID, c.Request().Method, c.Request().RequestURI),
			map[string]any{
				"request_id": requestID,
				"method":     c.Request().Method,
				"uri":        c.Request().RequestURI,
			},
		)
		_ = c.String(status, "internal server error")
	}

	t := template.Must(loadTemplates(cfg.Environment))
	brandingLabel := brandProductName(cfg.Branding)
	emailLogoURL, emailLogo, emailLogoContentType, logoErr := resolveEmailLogo(
		cfg.ServerUrl,
		cfg.Logo,
	)
	if logoErr != nil {
		log.Warn("email logo is not a valid image", "error", logoErr)
	}
	e.Renderer = &TemplateRenderer{
		templates:     t,
		environment:   cfg.Environment,
		brandingLabel: brandingLabel,
		faviconURL:    normalizeBrandAsset(cfg.Favicon),
		logoURL:       normalizeBrandAsset(cfg.Logo),
		logoHeroURL:   normalizeBrandAsset(cfg.LogoHero),
		turnstileEnabled: strings.TrimSpace(cfg.TurnstileSiteKey) != "" &&
			strings.TrimSpace(cfg.TurnstileSecretKey) != "",
		turnstileSiteKey: cfg.TurnstileSiteKey,
	}
	assetsFS := loadAssetsFS(cfg.Environment)
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
			log.Debug("http request",
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
			return c.Path() == "/auth/session" || c.Path() == "/auth/logout" ||
				c.Path() == "/auth/sso/login" ||
				c.Path() == "/auth/magic/request" ||
				c.Path() == "/auth/magic/verify" ||
				c.Path() == "/auth/password/login" ||
				c.Path() == "/auth/password/reset/request" ||
				c.Path() == "/auth/password/reset/confirm" ||
				c.Path() == "/client/uploads" ||
				c.Path() == "/client/profile" ||
				c.Path() == "/user/uploads" ||
				c.Path() == "/user/profile" ||
				c.Path() == "/user/clients" ||
				c.Path() == "/user/clients/:clientID" ||
				c.Path() == "/user/clients/:clientID/reset-password" ||
				c.Path() == "/user/client-groups" ||
				c.Path() == "/user/client-groups/memberships" ||
				c.Path() == "/user/client-groups/update" ||
				c.Path() == "/user/client-groups/memberships/add" ||
				c.Path() == "/user/client-groups/memberships/remove" ||
				c.Path() == "/user/file/:fileID/rename" ||
				c.Path() == "/user/file/:fileID/delete" ||
				c.Path() == "/user/file/:fileID/shares" ||
				c.Path() == "/user/file/:fileID/shares/:shareID/delete" ||
				c.Path() == "/user/sent/:shareID/delete" ||
				c.Path() == "/admin/users" ||
				c.Path() == "/admin/users/:userID" ||
				c.Path() == "/admin/users/:userID/reset-password"
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
	resetPwd := auth.NewPasswordResetManager(queries, 15*time.Minute, 60*time.Second, 12)
	turnstile := newTurnstileVerifier(cfg.TurnstileSiteKey, cfg.TurnstileSecretKey)
	magicSend := auth.MagicSender(auth.NoopSender{})
	renderer, renderErr := mail.NewHermesRenderer(brandingLabel, cfg.ServerUrl, emailLogoURL)
	if renderErr != nil {
		panic(renderErr)
	}
	eventStore := mail.NewEventStore(queries)
	notifier := mail.NewNotifier(renderer, mail.NoopMessageSender{}, eventStore)
	if cfg.MailgunDomain != "" && cfg.MailgunAPIKey != "" && cfg.MailgunFromEmail != "" {
		sender, senderErr := mail.NewMailgunSender(
			cfg.MailgunAPIBaseURL,
			cfg.MailgunDomain,
			cfg.MailgunAPIKey,
			cfg.MailgunFromEmail,
			nil,
			renderer,
		)
		if senderErr != nil {
			panic(senderErr)
		}
		magicSend = sender
		notifier = mail.NewNotifier(renderer, sender, eventStore)
	}

	bucket := strings.TrimSpace(cfg.S3Bucket)
	if bucket == "" {
		bucket = "fileshare-uploads"
	}
	var objectStore interface {
		files.ObjectStore
		files.ObjectDeleteStore
		files.URLSigner
	}
	if cfg.Environment == "test" {
		objectStore = files.NewMemoryObjectStore()
	} else {
		s3Store, s3Err := files.NewS3ObjectStore(context.Background(), files.S3BackendConfig{
			Region:          cfg.AWSRegion,
			Endpoint:        cfg.S3Endpoint,
			AccessKeyID:     cfg.AWSAccessKeyID,
			SecretAccessKey: cfg.AWSSecretAccessKey,
			SessionToken:    cfg.AWSSessionToken,
			UsePathStyle:    cfg.S3ForcePathStyle,
		})
		if s3Err != nil {
			panic(s3Err)
		}
		objectStore = s3Store
	}
	metadataSvc := files.NewMetadataService(queries)
	uploadSvc, uploadErr := files.NewUploadService(bucket, objectStore, metadataSvc)
	if uploadErr != nil {
		panic(uploadErr)
	}
	downSvc, downErr := files.NewDownloadService(bucket, 5*time.Minute, queries, authz, objectStore)
	if downErr != nil {
		panic(downErr)
	}

	srv := &Server{
		e:                    e,
		cfg:                  cfg,
		log:                  log,
		sessions:             sessions,
		authz:                authz,
		turnstile:            turnstile,
		userSync:             userSync,
		userPwd:              userPwd,
		clientPwd:            clientPwd,
		magic:                magic,
		resetPwd:             resetPwd,
		magicSend:            magicSend,
		notifier:             notifier,
		uploadSvc:            uploadSvc,
		downSvc:              downSvc,
		emailLogo:            emailLogo,
		emailLogoContentType: emailLogoContentType,
	}
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
		return fmt.Errorf(
			"database schema is out of date (current=%d, latest=%d): run `go run . migrate up`",
			current,
			latest,
		)
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

func auditAuthEvent(
	c echo.Context,
	queries *db.Queries,
	eventType, actorType, actorID, entityType, entityID string,
	metadata map[string]any,
) {
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

func (s *Server) logLoginFailed(method, actorType, identifier, reason string) {
	s.log.Info(
		"login failed",
		"method", method,
		"actor_type", actorType,
		"actor_identifier", identifier,
		"reason", reason,
	)
}

func nullableString(v string) sql.NullString {
	v = strings.TrimSpace(v)
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{Valid: true, String: v}
}

func loadTemplates(environment string) (*template.Template, error) {
	var (
		templatesFS fs.FS
		t           *template.Template
	)
	if environment == "development" {
		templatesFS = os.DirFS("internal/web/templates")
	} else {
		templatesFS = webtemplates.Files
	}

	funcs := template.FuncMap{
		"renderContent": func(name string, data any) (template.HTML, error) {
			name = strings.TrimSpace(name)
			if name == "" {
				return "", fmt.Errorf("missing content template name")
			}

			var b strings.Builder
			if err := t.ExecuteTemplate(&b, name, data); err != nil {
				return "", err
			}
			return template.HTML(b.String()), nil
		},
	}

	parsed, err := template.New("root").Funcs(funcs).ParseFS(templatesFS, "*/*.html")
	if err != nil {
		return nil, err
	}
	t = parsed
	return parsed, nil
}

func loadAssetsFS(environment string) fs.FS {
	if environment == "development" {
		return os.DirFS("internal/web/assets/dist")
	}
	return mustSubFS(webassets.Files, "dist")
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

func resolveShareRecipientEmails(
	ctx context.Context,
	queries *db.Queries,
	targetType, targetID string,
) ([]string, error) {
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

func resolveClientUploadRecipients(
	ctx context.Context,
	queries *db.Queries,
	targetType, targetID string,
) ([]string, error) {
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
	actions := make([]dashboardAction, 0, 6)
	if auth.HasCapability(principal, auth.CapabilityUploadFiles) {
		actions = append(actions, dashboardAction{
			Label:       "Sent Files",
			Description: "Review files sent from your account.",
			Path:        "/user/sent",
			Icon:        "paper-airplane",
		})
		actions = append(actions, dashboardAction{
			Label:       "Received Files",
			Description: "Browse files sent to your account.",
			Path:        "/user/received",
			Icon:        "inbox",
		})
		actions = append(actions, dashboardAction{
			Label:       "Upload Files",
			Description: "Submit files for sharing with approved recipients.",
			Path:        "/user/uploads",
			Icon:        "arrow-up-tray",
		})
	}
	if auth.HasCapability(principal, auth.CapabilityManageClients) {
		actions = append(actions, dashboardAction{
			Label:       "Manage Clients",
			Description: "Create clients and manage client-group membership.",
			Path:        "/user/clients",
			Icon:        "users",
		})
		actions = append(actions, dashboardAction{
			Label:       "Client Groups",
			Description: "Create groups and manage client memberships.",
			Path:        "/user/client-groups",
			Icon:        "users",
		})
	}
	if auth.HasCapability(principal, auth.CapabilityManageUsers) {
		actions = append(actions, dashboardAction{
			Label:       "Manage Users",
			Description: "Administer user access and user roles.",
			Path:        "/admin/users",
			Icon:        "shield-check",
		})
	}
	actions = append(actions, dashboardAction{
		Label:       "Profile",
		Description: "Manage your name and password.",
		Path:        "/user/profile",
		Icon:        "user-circle",
	})
	return actions
}

func clientDashboardActions() []dashboardAction {
	return []dashboardAction{
		{
			Label:       "Received Files",
			Description: "Browse files sent to your account.",
			Path:        "/client/received",
			Icon:        "inbox",
		},
		{
			Label:       "Sent Files",
			Description: "Review files sent from your client account.",
			Path:        "/client/sent",
			Icon:        "paper-airplane",
		},
		{
			Label:       "Upload Files",
			Description: "Submit files for review.",
			Path:        "/client/uploads",
			Icon:        "arrow-up-tray",
		},
		{
			Label:       "Profile",
			Description: "Manage your display name and password.",
			Path:        "/client/profile",
			Icon:        "user-circle",
		},
	}
}

func withDashboardAction(actions []dashboardAction, dashboardPath string) []dashboardAction {
	withDashboard := make([]dashboardAction, 0, len(actions)+1)
	withDashboard = append(
		withDashboard,
		dashboardAction{
			Label:       "Dashboard",
			Description: "Overview and recent file activity.",
			Path:        dashboardPath,
			Icon:        "home",
		},
	)
	withDashboard = append(withDashboard, actions...)
	return withDashboard
}

func markActiveSidebarActions(actions []dashboardAction, requestPath string) []dashboardAction {
	out := make([]dashboardAction, 0, len(actions))
	for _, action := range actions {
		a := action
		a.Active = requestPath == action.Path || strings.HasPrefix(requestPath, action.Path+"/")
		out = append(out, a)
	}
	return out
}

func normalizeBrandAsset(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(v, "/") {
		return v
	}
	return "data:image/png;base64," + v
}

func resolveEmailLogo(serverURL, raw string) (string, []byte, string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil, "", nil
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return v, nil, "", nil
	}
	if strings.HasPrefix(v, "/") {
		return strings.TrimRight(serverURL, "/") + v, nil, "", nil
	}

	encoded := v
	declaredContentType := ""
	if strings.HasPrefix(lower, "data:") {
		header, payload, ok := strings.Cut(v, ",")
		if !ok || !strings.HasSuffix(strings.ToLower(header), ";base64") {
			return "", nil, "", fmt.Errorf("logo data URI must be base64 encoded")
		}
		encoded = payload
		mediaType := strings.TrimSpace(strings.TrimSuffix(header[5:], ";base64"))
		if separator := strings.IndexByte(mediaType, ';'); separator >= 0 {
			mediaType = mediaType[:separator]
		}
		declaredContentType = strings.ToLower(mediaType)
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, "", fmt.Errorf("decode logo base64: %w", err)
	}
	contentType := http.DetectContentType(data)
	if strings.HasPrefix(declaredContentType, "image/") {
		contentType = declaredContentType
	}
	if !strings.HasPrefix(contentType, "image/") {
		return "", nil, "", fmt.Errorf("detected content type %q is not an image", contentType)
	}

	return strings.TrimRight(serverURL, "/") + emailLogoPath, data, contentType, nil
}

func brandProductName(raw string) string {
	base := strings.TrimSpace(raw)
	if base == "" {
		base = "FileShare"
	}
	if strings.Contains(strings.ToLower(base), "file share") {
		return base
	}
	return base + " File Share"
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
