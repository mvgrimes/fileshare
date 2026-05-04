package server

import (
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"sharefile/internal/auth"
	"sharefile/internal/db"
	"sharefile/internal/files"
	"sharefile/internal/mail"
)

func (s *Server) registerUserRoutes(queries *db.Queries) {
	user := s.e.Group("/user")
	user.Use(auth.RequireAuth(), auth.RequireActorType("user"))

	user.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		actions := dashboardActions(principal)
		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":            "User Dashboard",
			"Role":             principal.ActorType,
			"Subtitle":         "Your available actions are based on assigned roles.",
			"ActorID":          principal.ActorID,
			"DashboardActions": actions,
			"HasActions":       len(actions) > 0,
			"ContentTemplate":  "dashboard_content",
		})
	})

	user.GET("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeUploadFiles(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		clientGroups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		return c.Render(http.StatusOK, "upload_share", map[string]any{
			"Title":           "Upload and Share",
			"Subtitle":        "Upload metadata and sharing targets for processing.",
			"ActorID":         principal.ActorID,
			"ContentTemplate": "upload_share_content",
			"FormAction":      "/user/uploads",
			"FlashError":      c.QueryParam("error"),
			"FlashSuccess":    c.QueryParam("success"),
			"ShowShareFields": true,
			"Clients":         clients,
			"ClientGroups":    clientGroups,
		})
	}, auth.RequireCapability(auth.CapabilityUploadFiles))

	user.GET("/files", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		files, err := queries.ListFilesByUploader(c.Request().Context(), db.ListFilesByUploaderParams{UploaderType: "user", UploaderID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load files")
		}
		items := make([]fileListItem, 0, len(files))
		for _, f := range files {
			items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: "owned"})
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Shared Files", "Subtitle": "Files uploaded by your account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No files uploaded yet.", "DetailBasePath": "/user/files", "DownloadBasePath": "/user/files"})
	})

	user.GET("/files/:fileID/download", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusOK, "download access granted")
	})

	user.GET("/files/:fileID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		shares, err := queries.ListSharesByFileID(c.Request().Context(), fileID)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load shares")
		}
		shareItems := make([]fileShareListItem, 0, len(shares))
		for _, sh := range shares {
			shareItems = append(shareItems, fileShareListItem{ID: sh.ID, TargetType: sh.TargetType, TargetID: sh.TargetID, TargetLabel: sh.TargetType + ":" + sh.TargetID})
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		clientGroups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		users, err := queries.ListUsers(c.Request().Context(), db.ListUsersParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load users")
		}
		userGroups, err := queries.ListUserGroups(c.Request().Context(), db.ListUserGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load user groups")
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "File Detail", "Subtitle": "Detailed metadata for your uploaded file.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "owned"}, "BackPath": "/user/files", "DownloadPath": "/user/files/" + file.ID + "/download", "ManageFile": true, "ShareTargets": shareItems, "Clients": clients, "ClientGroups": clientGroups, "Users": users, "UserGroups": userGroups, "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	})

	user.POST("/files/:fileID/rename", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		name := strings.TrimSpace(c.FormValue("filename"))
		if name == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/files/"+fileID+"?error="+url.QueryEscape("filename is required"))
			}
			return c.String(http.StatusBadRequest, "filename is required")
		}
		if err := queries.UpdateFileNameByID(c.Request().Context(), db.UpdateFileNameByIDParams{ID: fileID, OriginalFilename: name}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to rename file")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/files/"+fileID+"?success="+url.QueryEscape("File renamed"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.POST("/files/:fileID/delete", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		if err := queries.DeleteFile(c.Request().Context(), fileID); err != nil {
			return c.String(http.StatusInternalServerError, "failed to delete file")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/files?success="+url.QueryEscape("File deleted"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.POST("/files/:fileID/shares", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		targetType := strings.TrimSpace(c.FormValue("target_type"))
		targetID := strings.TrimSpace(c.FormValue("target_id"))
		message := strings.TrimSpace(c.FormValue("message"))
		if targetType == "" || targetID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/files/"+fileID+"?error="+url.QueryEscape("target_type and target_id are required"))
			}
			return c.String(http.StatusBadRequest, "target_type and target_id are required")
		}
		switch targetType {
		case "client":
			_, err = queries.GetClientByID(c.Request().Context(), targetID)
		case "client_group":
			_, err = queries.GetClientGroupByID(c.Request().Context(), targetID)
		case "user":
			_, err = queries.GetUserByID(c.Request().Context(), targetID)
		case "user_group":
			_, err = queries.GetUserGroupByID(c.Request().Context(), targetID)
		default:
			err = sql.ErrNoRows
		}
		if err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/files/"+fileID+"?error="+url.QueryEscape("invalid share target"))
			}
			return c.String(http.StatusBadRequest, "invalid share target")
		}
		msgNull := sql.NullString{}
		if message != "" {
			msgNull = sql.NullString{Valid: true, String: message}
		}
		if err := queries.CreateShare(c.Request().Context(), db.CreateShareParams{ID: uuid.NewString(), FileID: fileID, SharedByType: "user", SharedByID: principal.ActorID, TargetType: targetType, TargetID: targetID, Message: msgNull}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to create share")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/files/"+fileID+"?success="+url.QueryEscape("Share added"))
		}
		return c.NoContent(http.StatusCreated)
	})

	user.POST("/files/:fileID/shares/:shareID/delete", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		if file.UploaderType != "user" || file.UploaderID != principal.ActorID {
			return c.String(http.StatusForbidden, "forbidden")
		}
		shareID := c.Param("shareID")
		share, err := queries.GetShareByID(c.Request().Context(), shareID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "share not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load share")
		}
		if share.FileID != fileID {
			return c.String(http.StatusBadRequest, "share does not belong to file")
		}
		if err := queries.DeleteShare(c.Request().Context(), shareID); err != nil {
			return c.String(http.StatusInternalServerError, "failed to remove share")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/files/"+fileID+"?success="+url.QueryEscape("Share removed"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.POST("/uploads", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeUploadFiles(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		filename := strings.TrimSpace(c.FormValue("filename"))
		targetType := strings.TrimSpace(c.FormValue("target_type"))
		targetID := strings.TrimSpace(c.FormValue("target_id"))
		message := strings.TrimSpace(c.FormValue("message"))
		if filename == "" || targetType == "" || targetID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("filename, target_type, and target_id are required"))
			}
			return c.String(http.StatusBadRequest, "filename, target_type, and target_id are required")
		}
		if targetType != "client" && targetType != "client_group" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("target_type must be client or client_group"))
			}
			return c.String(http.StatusBadRequest, "target_type must be client or client_group")
		}
		switch targetType {
		case "client":
			if _, err := queries.GetClientByID(c.Request().Context(), targetID); err != nil {
				if err == sql.ErrNoRows {
					if isHTMLRequest(c) {
						return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("Client not found"))
					}
					return c.String(http.StatusBadRequest, "client not found")
				}
				return c.String(http.StatusInternalServerError, "failed to validate target")
			}
		case "client_group":
			if _, err := queries.GetClientGroupByID(c.Request().Context(), targetID); err != nil {
				if err == sql.ErrNoRows {
					if isHTMLRequest(c) {
						return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("Client group not found"))
					}
					return c.String(http.StatusBadRequest, "client group not found")
				}
				return c.String(http.StatusInternalServerError, "failed to validate target")
			}
		}
		contentType := "application/octet-stream"
		sizeBytes := int64(0)
		var bodyReader strings.Reader
		uploadBody := io.Reader(&bodyReader)

		uploadFile, uploadErr := c.FormFile("upload_file")
		if uploadErr == nil {
			opened, openErr := uploadFile.Open()
			if openErr != nil {
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("Failed to read uploaded file"))
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
				return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("Failed to record file"))
			}
			return c.String(http.StatusInternalServerError, "failed to record file")
		}
		shareID := uuid.NewString()
		msgNull := sql.NullString{}
		if message != "" {
			msgNull = sql.NullString{Valid: true, String: message}
		}
		if err := queries.CreateShare(c.Request().Context(), db.CreateShareParams{ID: shareID, FileID: fileID, SharedByType: "user", SharedByID: principal.ActorID, TargetType: targetType, TargetID: targetID, Message: msgNull}); err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/uploads?error="+url.QueryEscape("Failed to create share"))
			}
			return c.String(http.StatusInternalServerError, "failed to create share")
		}
		recipients, recErr := resolveShareRecipientEmails(c.Request().Context(), queries, targetType, targetID)
		if recErr == nil {
			for _, recipient := range recipients {
				notifyErr := s.notifier.NotifyFileShared(c.Request().Context(), mail.FileSharedNotification{RecipientEmail: recipient, RecipientName: recipient, ActorLabel: principal.ActorID, FileName: filename, Message: message, TargetType: targetType, TargetID: targetID})
				if notifyErr != nil {
					s.log.Error("share notification failed", "recipient", recipient, "error", notifyErr.Error())
				}
			}
		}
		auditAuthEvent(c, queries, "file.share", "user", principal.ActorID, targetType, targetID, map[string]any{"file_id": fileID, "share_id": shareID})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/uploads?success="+url.QueryEscape("File shared successfully"))
		}
		return c.String(http.StatusCreated, "file shared: "+fileID)
	}, auth.RequireCapability(auth.CapabilityUploadFiles))

	user.GET("/clients", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		groups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		return c.Render(http.StatusOK, "clients_management", map[string]any{"Title": "Client Management", "Subtitle": "Create clients, groups, and memberships.", "ContentTemplate": "clients_management_content", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success"), "Clients": clients, "ClientGroups": groups})
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/clients", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		email := strings.TrimSpace(c.FormValue("email"))
		displayName := strings.TrimSpace(c.FormValue("display_name"))
		if email == "" || displayName == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("email and display_name are required"))
			}
			return c.String(http.StatusBadRequest, "email and display_name are required")
		}
		canUpload := int64(0)
		if c.FormValue("can_upload") == "1" {
			canUpload = 1
		}
		isActive := int64(0)
		if c.FormValue("is_active") == "1" {
			isActive = 1
		}
		if err := queries.CreateClient(c.Request().Context(), db.CreateClientParams{ID: uuid.NewString(), Email: email, DisplayName: displayName, PasswordHash: sql.NullString{}, CanUpload: canUpload, IsActive: isActive}); err != nil {
			auditAuthEvent(c, queries, "admin.client.create", principal.ActorType, principal.ActorID, "client", "", map[string]any{"outcome": "failure", "reason": "create_failed", "email": email})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("failed to create client"))
			}
			return c.String(http.StatusInternalServerError, "failed to create client")
		}
		auditAuthEvent(c, queries, "admin.client.create", principal.ActorType, principal.ActorID, "client", email, map[string]any{"outcome": "success"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/clients?success="+url.QueryEscape("Client created"))
		}
		return c.NoContent(http.StatusCreated)
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/client-groups", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		name := strings.TrimSpace(c.FormValue("name"))
		if name == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("name is required"))
			}
			return c.String(http.StatusBadRequest, "name is required")
		}
		if err := queries.CreateClientGroup(c.Request().Context(), db.CreateClientGroupParams{ID: uuid.NewString(), Name: name, CreatedByUserID: sql.NullString{Valid: true, String: principal.ActorID}}); err != nil {
			auditAuthEvent(c, queries, "admin.client_group.create", principal.ActorType, principal.ActorID, "client_group", "", map[string]any{"outcome": "failure", "reason": "create_failed", "name": name})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("failed to create client group"))
			}
			return c.String(http.StatusInternalServerError, "failed to create client group")
		}
		auditAuthEvent(c, queries, "admin.client_group.create", principal.ActorType, principal.ActorID, "client_group", name, map[string]any{"outcome": "success"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/clients?success="+url.QueryEscape("Client group created"))
		}
		return c.NoContent(http.StatusCreated)
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/client-groups/memberships", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		groupID := strings.TrimSpace(c.FormValue("group_id"))
		clientID := strings.TrimSpace(c.FormValue("client_id"))
		if groupID == "" || clientID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("group_id and client_id are required"))
			}
			return c.String(http.StatusBadRequest, "group_id and client_id are required")
		}
		if err := queries.AddClientToGroup(c.Request().Context(), db.AddClientToGroupParams{ClientGroupID: groupID, ClientID: clientID}); err != nil {
			auditAuthEvent(c, queries, "admin.client_group.membership.add", principal.ActorType, principal.ActorID, "client_group", groupID, map[string]any{"outcome": "failure", "reason": "add_failed", "client_id": clientID})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("failed to add membership"))
			}
			return c.String(http.StatusInternalServerError, "failed to add membership")
		}
		auditAuthEvent(c, queries, "admin.client_group.membership.add", principal.ActorType, principal.ActorID, "client_group", groupID, map[string]any{"outcome": "success", "client_id": clientID})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/clients?success="+url.QueryEscape("Membership added"))
		}
		return c.NoContent(http.StatusCreated)
	}, auth.RequireCapability(auth.CapabilityManageClients))
}
