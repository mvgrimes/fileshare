package server

import (
	"database/sql"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/labstack/echo/v4"

	"sharefile/internal/auth"
	"sharefile/internal/db"
	"sharefile/internal/mail"
)

func (s *Server) registerClientRoutes(queries *db.Queries) {
	client := s.e.Group("/client")
	client.Use(auth.RequireAuth(), auth.RequireActorType("client"))
	client.GET("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		return c.Render(http.StatusOK, "upload_share", map[string]any{"Title": "Client Upload", "Subtitle": "Submit upload targets permitted for your account.", "ActorID": principal.ActorID, "ContentTemplate": "upload_share_content", "FormAction": "/client/uploads", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	})
	client.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		actions := []dashboardAction{{Label: "Upload Files", Description: "Submit upload targets; permissions are validated per client.", Path: "/client/uploads"}, {Label: "View Shared Files", Description: "Browse files shared directly or through your client groups.", Path: "/client/files"}}
		return c.Render(http.StatusOK, "dashboard", map[string]any{"Title": "Client Dashboard", "Role": principal.ActorType, "Subtitle": "Use secure links to access files and upload where permitted.", "ActorID": principal.ActorID, "DashboardActions": actions, "HasActions": true, "ContentTemplate": "dashboard_content"})
	})
	client.GET("/files/:fileID/download", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		if err := s.authz.AuthorizeClientDownload(c.Request().Context(), principal, c.Param("fileID")); err != nil {
			auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "denied", "reason": "forbidden"})
			if err == auth.ErrForbidden {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return c.String(http.StatusInternalServerError, "failed to authorize download")
		}
		auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "allowed"})
		return c.String(http.StatusOK, "download access granted")
	})
	client.GET("/files", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		shares, err := queries.ListClientAccessibleShares(c.Request().Context(), db.ListClientAccessibleSharesParams{ClientID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load shared files")
		}
		items := make([]fileListItem, 0, len(shares))
		itemIndex := make(map[string]int, len(shares))
		fileVia := make(map[string]map[string]struct{}, len(shares))
		for _, sh := range shares {
			f, fileErr := queries.GetFileByID(c.Request().Context(), sh.FileID)
			if fileErr != nil {
				continue
			}
			viaSet, ok := fileVia[f.ID]
			if !ok {
				viaSet = map[string]struct{}{}
				fileVia[f.ID] = viaSet
			}
			viaSet[sh.TargetType] = struct{}{}

			if idx, exists := itemIndex[f.ID]; exists {
				items[idx].SharedVia = joinedShareTargets(viaSet)
				continue
			}

			itemIndex[f.ID] = len(items)
			items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: joinedShareTargets(viaSet)})
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Shared Files", "Subtitle": "Files currently accessible to your client account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No files are currently shared with your account.", "DetailBasePath": "/client/files"})
	})
	client.GET("/files/:fileID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		if err := s.authz.AuthorizeClientDownload(c.Request().Context(), principal, fileID); err != nil {
			if err == auth.ErrForbidden {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return c.String(http.StatusInternalServerError, "failed to authorize file")
		}
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Shared File Detail", "Subtitle": "File metadata and available actions.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "shared"}, "BackPath": "/client/files"})
	})
	client.POST("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		targetType := strings.TrimSpace(c.FormValue("target_type"))
		targetID := strings.TrimSpace(c.FormValue("target_id"))
		if targetType == "" || targetID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("target_type and target_id are required"))
			}
			return c.String(http.StatusBadRequest, "target_type and target_id are required")
		}
		if err := s.authz.AuthorizeClientUpload(c.Request().Context(), principal, targetType, targetID); err != nil {
			auditAuthEvent(c, queries, "authz.client.upload", principal.ActorType, principal.ActorID, targetType, targetID, map[string]any{"outcome": "denied", "reason": "forbidden"})
			if err == auth.ErrForbidden {
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("Upload target is not allowed"))
				}
				return c.String(http.StatusForbidden, "forbidden")
			}
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("Failed to authorize upload"))
			}
			return c.String(http.StatusInternalServerError, "failed to authorize upload")
		}
		auditAuthEvent(c, queries, "authz.client.upload", principal.ActorType, principal.ActorID, targetType, targetID, map[string]any{"outcome": "allowed"})
		recipients, recErr := resolveClientUploadRecipients(c.Request().Context(), queries, targetType, targetID)
		if recErr == nil {
			for _, recipient := range recipients {
				notifyErr := s.notifier.NotifyClientUpload(c.Request().Context(), mail.ClientUploadNotification{RecipientEmail: recipient, RecipientName: recipient, ClientLabel: principal.ActorID, TargetType: targetType, TargetID: targetID})
				if notifyErr != nil {
					s.log.Error("client upload notification failed", "recipient", recipient, "error", notifyErr.Error())
				}
			}
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/uploads?success="+url.QueryEscape("Upload submission accepted"))
		}
		return c.String(http.StatusOK, "upload access granted")
	})
}

func joinedShareTargets(viaSet map[string]struct{}) string {
	if len(viaSet) == 0 {
		return ""
	}
	types := make([]string, 0, len(viaSet))
	for targetType := range viaSet {
		types = append(types, targetType)
	}
	sort.Strings(types)
	return strings.Join(types, ", ")
}
