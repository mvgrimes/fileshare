package server

import (
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"

	"sharefile/internal/auth"
	"sharefile/internal/db"
	"sharefile/internal/files"
	"sharefile/internal/mail"
)

func (s *Server) registerClientRoutes(queries *db.Queries) {
	client := s.e.Group("/client")
	client.Use(auth.RequireAuth(), auth.RequireActorType("client"))
	client.GET("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		users, userErr := queries.ListUsers(c.Request().Context(), db.ListUsersParams{Limit: 200, Offset: 0})
		if userErr != nil {
			return c.String(http.StatusInternalServerError, "failed to load users")
		}
		userGroups, groupErr := queries.ListUserGroups(c.Request().Context(), db.ListUserGroupsParams{Limit: 200, Offset: 0})
		if groupErr != nil {
			return c.String(http.StatusInternalServerError, "failed to load user groups")
		}
		return c.Render(http.StatusOK, "upload_share", map[string]any{"Title": "Client Upload", "Subtitle": "Submit upload targets permitted for your account.", "ActorID": principal.ActorID, "ContentTemplate": "upload_share_content", "FormAction": "/client/uploads", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success"), "ShowShareFields": true, "ClientUploadMode": true, "Users": users, "UserGroups": userGroups})
	})
	client.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		actions := clientDashboardActions()
		shares, err := queries.ListClientAccessibleShares(c.Request().Context(), db.ListClientAccessibleSharesParams{ClientID: principal.ActorID, Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load dashboard files")
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
		sort.SliceStable(items, func(i, j int) bool {
			return items[i].SharedAt > items[j].SharedAt
		})
		if len(items) > 10 {
			items = items[:10]
		}
		return c.Render(http.StatusOK, "dashboard", map[string]any{"Title": "Client Dashboard", "Role": principal.ActorType, "Subtitle": "Use secure links to access files and upload where permitted.", "ActorID": principal.ActorID, "DashboardActions": actions, "HasActions": true, "DashboardMainTemplate": "client_dashboard_main", "DashboardReceivedFiles": items, "ContentTemplate": "dashboard_content"})
	})
	client.GET("/profile", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		account, err := queries.GetClientByID(c.Request().Context(), principal.ActorID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "client not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load profile")
		}
		return c.Render(http.StatusOK, "profile", map[string]any{"Title": "Profile", "Subtitle": "Update your display name and password.", "ContentTemplate": "profile_content", "ProfileType": "client", "ActorID": principal.ActorID, "Email": account.Email, "DisplayName": account.DisplayName, "FormAction": "/client/profile", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	})
	client.POST("/profile", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		account, err := queries.GetClientByID(c.Request().Context(), principal.ActorID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "client not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load profile")
		}
		displayName := strings.TrimSpace(c.FormValue("display_name"))
		if displayName == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/profile?error="+url.QueryEscape("display_name is required"))
			}
			return c.String(http.StatusBadRequest, "display_name is required")
		}
		newPassword := strings.TrimSpace(c.FormValue("new_password"))
		confirmPassword := strings.TrimSpace(c.FormValue("confirm_password"))
		if newPassword != confirmPassword {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/profile?error="+url.QueryEscape("Passwords do not match"))
			}
			return c.String(http.StatusBadRequest, "passwords do not match")
		}
		if len(newPassword) > 0 && len(newPassword) < 12 {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/profile?error="+url.QueryEscape("Password must be at least 12 characters"))
			}
			return c.String(http.StatusBadRequest, "password must be at least 12 characters")
		}
		if err := queries.UpdateClient(c.Request().Context(), db.UpdateClientParams{ID: account.ID, DisplayName: displayName, CanUpload: account.CanUpload, IsActive: account.IsActive}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to update profile")
		}
		if newPassword != "" {
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if hashErr != nil {
				return c.String(http.StatusInternalServerError, "failed to update password")
			}
			if err := queries.UpdateClientPasswordHashByID(c.Request().Context(), account.ID, sql.NullString{Valid: true, String: string(hash)}); err != nil {
				return c.String(http.StatusInternalServerError, "failed to update password")
			}
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/profile?success="+url.QueryEscape("Profile updated"))
		}
		return c.NoContent(http.StatusNoContent)
	})
	client.GET("/sent", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		uploads, err := queries.ListFilesByUploader(c.Request().Context(), db.ListFilesByUploaderParams{UploaderType: "client", UploaderID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load uploaded files")
		}
		items := make([]fileListItem, 0, len(uploads))
		for _, f := range uploads {
			items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: "uploaded", UploadedAt: f.CreatedAt})
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Sent Files", "Subtitle": "Files sent from your client account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No sent files are available yet.", "DetailBasePath": "/client/sent", "HideStatusColumn": true, "HideSharedAtColumn": true})
	})
	client.GET("/sent/:fileID", func(c echo.Context) error {
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
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Sent File Detail", "Subtitle": "File metadata and details.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "sent", UploadedAt: file.CreatedAt}, "BackPath": "/client/sent"})
	})
	client.GET("/received/:fileID/download", func(c echo.Context) error {
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
		shares, sharesErr := queries.ListClientAccessibleShares(c.Request().Context(), db.ListClientAccessibleSharesParams{ClientID: principal.ActorID, Limit: 200, Offset: 0})
		if sharesErr != nil {
			return c.String(http.StatusInternalServerError, "failed to track download")
		}
		for _, sh := range shares {
			if sh.FileID != fileID {
				continue
			}
			if err := queries.RecordShareDownload(c.Request().Context(), db.RecordShareDownloadParams{ID: uuid.NewString(), ShareID: sh.ID, ClientID: principal.ActorID}); err != nil {
				return c.String(http.StatusInternalServerError, "failed to track download")
			}
		}
		auditAuthEvent(c, queries, "authz.client.download", principal.ActorType, principal.ActorID, "file", fileID, map[string]any{"outcome": "allowed"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, signedURL)
		}
		return c.String(http.StatusOK, signedURL)
	})
	client.GET("/received", func(c echo.Context) error {
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
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Received Files", "Subtitle": "Files sent to your client account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No files have been received yet.", "DetailBasePath": "/client/received", "DownloadBasePath": "/client/received", "HideStatusColumn": true, "HideUploadedAtColumn": true})
	})
	client.GET("/received/:fileID", func(c echo.Context) error {
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
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Received File Detail", "Subtitle": "File metadata and available actions.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "received", SharedAt: sharedAt}, "BackPath": "/client/received", "DownloadPath": "/client/received/" + file.ID + "/download"})
	})
	client.POST("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		filename := strings.TrimSpace(c.FormValue("filename"))
		targetType := strings.TrimSpace(c.FormValue("target_type"))
		targetID := strings.TrimSpace(c.FormValue("target_id"))
		message := strings.TrimSpace(c.FormValue("message"))
		if filename == "" || targetType == "" || targetID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("filename, target_type, and target_id are required"))
			}
			return c.String(http.StatusBadRequest, "filename, target_type, and target_id are required")
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

		contentType := "application/octet-stream"
		sizeBytes := int64(0)
		var bodyReader strings.Reader
		uploadBody := io.Reader(&bodyReader)

		uploadFile, uploadErr := c.FormFile("upload_file")
		if uploadErr == nil {
			opened, openErr := uploadFile.Open()
			if openErr != nil {
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("Failed to read uploaded file"))
				}
				return c.String(http.StatusBadRequest, "failed to read uploaded file")
			}
			defer opened.Close()
			uploadBody = opened
			sizeBytes = uploadFile.Size
			if filename == "" {
				filename = strings.TrimSpace(uploadFile.Filename)
			}
			if ct := strings.TrimSpace(uploadFile.Header.Get(echo.HeaderContentType)); ct != "" {
				contentType = ct
			}
		} else {
			bodyReader = *strings.NewReader("")
		}

		fileID, _, err := s.uploadSvc.Upload(c.Request().Context(), files.UploadInput{Uploader: principal, OriginalFilename: filename, ContentType: contentType, SizeBytes: sizeBytes, Body: uploadBody})
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("Failed to record file"))
			}
			return c.String(http.StatusInternalServerError, "failed to record file")
		}
		shareID := uuid.NewString()
		msgNull := sql.NullString{}
		if message != "" {
			msgNull = sql.NullString{Valid: true, String: message}
		}
		if err := queries.CreateShare(c.Request().Context(), db.CreateShareParams{ID: shareID, FileID: fileID, SharedByType: "client", SharedByID: principal.ActorID, TargetType: targetType, TargetID: targetID, Message: msgNull}); err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/client/uploads?error="+url.QueryEscape("Failed to create share"))
			}
			return c.String(http.StatusInternalServerError, "failed to create share")
		}
		auditAuthEvent(c, queries, "file.share", "client", principal.ActorID, targetType, targetID, map[string]any{"file_id": fileID, "share_id": shareID})

		recipients, recErr := resolveClientUploadRecipients(c.Request().Context(), queries, targetType, targetID)
		clientLabel := principal.ActorID
		if client, clientErr := queries.GetClientByID(c.Request().Context(), principal.ActorID); clientErr == nil {
			if name := strings.TrimSpace(client.DisplayName); name != "" {
				clientLabel = name
			} else if email := strings.TrimSpace(client.Email); email != "" {
				clientLabel = email
			}
		}
		if recErr == nil {
			for _, recipient := range recipients {
				notifyErr := s.notifier.NotifyClientUpload(c.Request().Context(), mail.ClientUploadNotification{RecipientEmail: recipient, RecipientName: recipient, ClientLabel: clientLabel, FileName: filename, Message: message, TargetType: targetType, TargetID: targetID})
				if notifyErr != nil {
					s.log.Error("client upload notification failed", "recipient", recipient, "error", notifyErr.Error())
				}
			}
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/client/uploads?success="+url.QueryEscape("Upload submission accepted"))
		}
		return c.String(http.StatusCreated, "file shared: "+fileID)
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
