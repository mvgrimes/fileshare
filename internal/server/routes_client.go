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
		actions := []dashboardAction{{Label: "Upload Files", Description: "Submit upload targets; permissions are validated per client.", Path: "/client/uploads"}, {Label: "View Shared Files", Description: "Browse files shared directly or through your client groups.", Path: "/client/files"}, {Label: "View Uploaded Files", Description: "Review files uploaded from your client account.", Path: "/client/uploads/files"}}
		return c.Render(http.StatusOK, "dashboard", map[string]any{"Title": "Client Dashboard", "Role": principal.ActorType, "Subtitle": "Use secure links to access files and upload where permitted.", "ActorID": principal.ActorID, "DashboardActions": actions, "HasActions": true, "ContentTemplate": "dashboard_content"})
	})
	client.GET("/uploads/files", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		uploads, err := queries.ListFilesByUploader(c.Request().Context(), db.ListFilesByUploaderParams{UploaderType: "client", UploaderID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load uploaded files")
		}
		items := make([]fileListItem, 0, len(uploads))
		for _, f := range uploads {
			items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: "uploaded", UploadedAt: f.CreatedAt})
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Uploaded Files", "Subtitle": "Files uploaded by your client account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No uploaded files are available yet.", "DetailBasePath": "/client/uploads/files"})
	})
	client.GET("/uploads/files/:fileID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "client" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Uploaded File Detail", "Subtitle": "File metadata and details.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "uploaded", UploadedAt: file.CreatedAt}, "BackPath": "/client/uploads/files"})
	})
	client.GET("/files/:fileID/download", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		signedURL, err := s.downSvc.SignedDownloadURL(c.Request().Context(), principal, fileID)
		if err != nil {
			auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "denied", "reason": "forbidden"})
			if err == auth.ErrForbidden {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return c.String(http.StatusInternalServerError, "failed to authorize download")
		}
		auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "allowed"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, signedURL)
		}
		return c.String(http.StatusOK, signedURL)
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
		fileSharedAt := make(map[string]string, len(shares))
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
			if prev, exists := fileSharedAt[f.ID]; !exists || sh.CreatedAt > prev {
				fileSharedAt[f.ID] = sh.CreatedAt
			}

			if idx, exists := itemIndex[f.ID]; exists {
				items[idx].SharedVia = joinedShareTargets(viaSet)
				items[idx].SharedAt = fileSharedAt[f.ID]
				continue
			}

			itemIndex[f.ID] = len(items)
			items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: joinedShareTargets(viaSet), SharedAt: fileSharedAt[f.ID]})
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Shared Files", "Subtitle": "Files currently accessible to your client account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No files are currently shared with your account.", "DetailBasePath": "/client/files", "DownloadBasePath": "/client/files"})
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
		shares, err := queries.ListClientAccessibleShares(c.Request().Context(), db.ListClientAccessibleSharesParams{ClientID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load shared file details")
		}
		sharedAt := ""
		for _, sh := range shares {
			if sh.FileID == file.ID && (sharedAt == "" || sh.CreatedAt > sharedAt) {
				sharedAt = sh.CreatedAt
			}
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Shared File Detail", "Subtitle": "File metadata and available actions.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "shared", SharedAt: sharedAt}, "BackPath": "/client/files", "DownloadPath": "/client/files/" + file.ID + "/download"})
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
		if targetType != "user" && targetType != "user_group" {
			auditAuthEvent(c, queries, "authz.client.upload", principal.ActorType, principal.ActorID, targetType, targetID, map[string]any{"outcome": "denied", "reason": "invalid_target_type"})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("target_type must be user or user_group"))
			}
			return c.String(http.StatusBadRequest, "target_type must be user or user_group")
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
