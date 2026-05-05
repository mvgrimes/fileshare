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

func (s *Server) registerUserRoutes(queries *db.Queries) {
	type clientGroupListItem struct {
		ID          string
		Name        string
		MemberCount int
	}

	user := s.e.Group("/user")
	user.Use(auth.RequireAuth(), auth.RequireActorType("user"))

	user.GET("/dashboard", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		actions := dashboardActions(principal)

		sentUploads, err := queries.ListFilesByUploader(c.Request().Context(), db.ListFilesByUploaderParams{UploaderType: "user", UploaderID: principal.ActorID, Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load dashboard files")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 500, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load dashboard stats")
		}
		clientByID := make(map[string]db.Client, len(clients))
		for _, cl := range clients {
			clientByID[cl.ID] = cl
		}
		groups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 500, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load dashboard stats")
		}
		groupByID := make(map[string]db.ClientGroup, len(groups))
		for _, g := range groups {
			groupByID[g.ID] = g
		}

		sentItems := make([]fileListItem, 0, len(sentUploads))
		userSentViewed := 0
		for _, f := range sentUploads {
			viewed, viewErr := queries.FileHasAnyClientDownload(c.Request().Context(), f.ID)
			if viewErr != nil {
				return c.String(http.StatusInternalServerError, "failed to load dashboard file status")
			}
			status := "unviewed"
			if viewed {
				status = "viewed"
				userSentViewed++
			}
			shares, sharesErr := queries.ListSharesByFileID(c.Request().Context(), f.ID)
			if sharesErr != nil {
				return c.String(http.StatusInternalServerError, "failed to load dashboard shares")
			}
			if len(shares) == 0 {
				sentItems = append(sentItems, fileListItem{ID: f.ID, Name: f.OriginalFilename, UploadedAt: f.CreatedAt, ViewStatus: status, SharedVia: "Not shared"})
				continue
			}
			for _, sh := range shares {
				targetLabel := sh.TargetType + ":" + sh.TargetID
				switch sh.TargetType {
				case "client":
					if cl, ok := clientByID[sh.TargetID]; ok {
						targetLabel = "Client: " + strings.TrimSpace(cl.DisplayName)
					}
				case "client_group":
					if cg, ok := groupByID[sh.TargetID]; ok {
						targetLabel = "Client Group: " + strings.TrimSpace(cg.Name)
					}
				}
				sentItems = append(sentItems, fileListItem{ID: f.ID, Name: f.OriginalFilename, UploadedAt: f.CreatedAt, ViewStatus: status, SharedVia: targetLabel, SharedAt: sh.CreatedAt})
			}
		}
		sort.SliceStable(sentItems, func(i, j int) bool {
			if sentItems[i].ViewStatus != sentItems[j].ViewStatus {
				return sentItems[i].ViewStatus == "unviewed"
			}
			return sentItems[i].UploadedAt > sentItems[j].UploadedAt
		})
		if len(sentItems) > 10 {
			sentItems = sentItems[:10]
		}

		shares, err := queries.ListUserAccessibleShares(c.Request().Context(), db.ListUserAccessibleSharesParams{UserID: principal.ActorID, Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load dashboard shares")
		}
		receivedItems := make([]fileListItem, 0, len(shares))
		itemIndex := make(map[string]int, len(shares))
		fileSharedAt := make(map[string]string, len(shares))
		fileSharedBy := make(map[string]string, len(shares))
		for _, sh := range shares {
			f, fileErr := queries.GetFileByID(c.Request().Context(), sh.FileID)
			if fileErr != nil {
				continue
			}
			if prev, exists := fileSharedAt[f.ID]; !exists || sh.CreatedAt > prev {
				fileSharedAt[f.ID] = sh.CreatedAt
				if sh.SharedByType == "client" {
					if cl, ok := clientByID[sh.SharedByID]; ok {
						fileSharedBy[f.ID] = strings.TrimSpace(cl.DisplayName)
					} else {
						fileSharedBy[f.ID] = sh.SharedByID
					}
				} else if f.UploaderType == "client" {
					if cl, ok := clientByID[f.UploaderID]; ok {
						fileSharedBy[f.ID] = strings.TrimSpace(cl.DisplayName)
					} else {
						fileSharedBy[f.ID] = f.UploaderID
					}
				} else {
					fileSharedBy[f.ID] = sh.SharedByID
				}
			}
			if idx, exists := itemIndex[f.ID]; exists {
				receivedItems[idx].SharedVia = fileSharedBy[f.ID]
				receivedItems[idx].SharedAt = fileSharedAt[f.ID]
				continue
			}
			itemIndex[f.ID] = len(receivedItems)
			receivedItems = append(receivedItems, fileListItem{ID: f.ID, Name: f.OriginalFilename, SharedVia: fileSharedBy[f.ID], SharedAt: fileSharedAt[f.ID], ViewStatus: "unviewed"})
		}
		sort.SliceStable(receivedItems, func(i, j int) bool {
			if receivedItems[i].ViewStatus != receivedItems[j].ViewStatus {
				return receivedItems[i].ViewStatus == "unviewed"
			}
			return receivedItems[i].SharedAt > receivedItems[j].SharedAt
		})
		if len(receivedItems) > 10 {
			receivedItems = receivedItems[:10]
		}

		return c.Render(http.StatusOK, "dashboard", map[string]any{
			"Title":                  "User Dashboard",
			"Role":                   principal.ActorType,
			"Subtitle":               "Overview of sent and received files.",
			"ActorID":                principal.ActorID,
			"DashboardActions":       actions,
			"HasActions":             len(actions) > 0,
			"DashboardMainTemplate":  "user_dashboard_main",
			"DashboardSentFiles":     sentItems,
			"DashboardReceivedFiles": receivedItems,
			"Stats": map[string]int{
				"ClientCount":        len(clients),
				"UserSentTotal":      len(sentUploads),
				"UserSentViewed":     userSentViewed,
				"UserSentUnviewed":   len(sentUploads) - userSentViewed,
				"ClientSentTotal":    len(receivedItems),
				"ClientSentViewed":   0,
				"ClientSentUnviewed": len(receivedItems),
			},
			"ContentTemplate": "dashboard_content",
		})
	})

	user.GET("/profile", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		account, err := queries.GetUserByID(c.Request().Context(), principal.ActorID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "user not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load profile")
		}
		return c.Render(http.StatusOK, "profile", map[string]any{"Title": "Profile", "Subtitle": "Update your name and password.", "ContentTemplate": "profile_content", "ProfileType": "user", "ActorID": principal.ActorID, "Email": account.Email, "DisplayName": account.FullName, "FormAction": "/user/profile", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/profile", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		account, err := queries.GetUserByID(c.Request().Context(), principal.ActorID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "user not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load profile")
		}
		fullName := strings.TrimSpace(c.FormValue("display_name"))
		if fullName == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/profile?error="+url.QueryEscape("display_name is required"))
			}
			return c.String(http.StatusBadRequest, "display_name is required")
		}
		newPassword := strings.TrimSpace(c.FormValue("new_password"))
		confirmPassword := strings.TrimSpace(c.FormValue("confirm_password"))
		if newPassword != confirmPassword {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/profile?error="+url.QueryEscape("Passwords do not match"))
			}
			return c.String(http.StatusBadRequest, "passwords do not match")
		}
		if len(newPassword) > 0 && len(newPassword) < 12 {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/profile?error="+url.QueryEscape("Password must be at least 12 characters"))
			}
			return c.String(http.StatusBadRequest, "password must be at least 12 characters")
		}
		if err := queries.UpdateUser(c.Request().Context(), db.UpdateUserParams{ID: account.ID, FullName: fullName, PasswordHash: account.PasswordHash, IsActive: account.IsActive}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to update profile")
		}
		if newPassword != "" {
			hash, hashErr := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if hashErr != nil {
				return c.String(http.StatusInternalServerError, "failed to update password")
			}
			if err := queries.UpdateUserPasswordHashByID(c.Request().Context(), account.ID, sql.NullString{Valid: true, String: string(hash)}); err != nil {
				return c.String(http.StatusInternalServerError, "failed to update password")
			}
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/profile?success="+url.QueryEscape("Profile updated"))
		}
		return c.NoContent(http.StatusNoContent)
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

	user.GET("/sent", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		files, err := queries.ListFilesByUploader(c.Request().Context(), db.ListFilesByUploaderParams{UploaderType: "user", UploaderID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load files")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 500, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		clientByID := make(map[string]db.Client, len(clients))
		for _, cl := range clients {
			clientByID[cl.ID] = cl
		}
		groups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 500, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		groupByID := make(map[string]db.ClientGroup, len(groups))
		for _, g := range groups {
			groupByID[g.ID] = g
		}

		items := make([]fileListItem, 0, len(files))
		for _, f := range files {
			viewed, viewErr := queries.FileHasAnyClientDownload(c.Request().Context(), f.ID)
			if viewErr != nil {
				return c.String(http.StatusInternalServerError, "failed to load download status")
			}
			status := "unviewed"
			if viewed {
				status = "viewed"
			}
			shares, sharesErr := queries.ListSharesByFileID(c.Request().Context(), f.ID)
			if sharesErr != nil {
				return c.String(http.StatusInternalServerError, "failed to load shares")
			}
			if len(shares) == 0 {
				items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: "Not shared", UploadedAt: f.CreatedAt, ViewStatus: status})
				continue
			}
			for _, sh := range shares {
				targetLabel := sh.TargetType + ":" + sh.TargetID
				switch sh.TargetType {
				case "client":
					if cl, ok := clientByID[sh.TargetID]; ok {
						targetLabel = "Client: " + strings.TrimSpace(cl.DisplayName)
					}
				case "client_group":
					if cg, ok := groupByID[sh.TargetID]; ok {
						targetLabel = "Client Group: " + strings.TrimSpace(cg.Name)
					}
				}
				items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: targetLabel, UploadedAt: f.CreatedAt, ViewStatus: status, SharedAt: sh.CreatedAt})
			}
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Sent Files", "Subtitle": "Files sent from your account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No files sent yet.", "DetailBasePath": "/user/sent", "DownloadBasePath": "/user/sent", "ShowSharedViaColumn": true, "SharedViaColumnLabel": "Shared With"})
	})

	user.GET("/sent/:fileID/download", func(c echo.Context) error {
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
		signedURL, err := s.downSvc.SignedDownloadURL(c.Request().Context(), principal, fileID)
		if err != nil {
			if err == auth.ErrForbidden {
				return c.String(http.StatusForbidden, "forbidden")
			}
			return c.String(http.StatusInternalServerError, "failed to authorize download")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, signedURL)
		}
		return c.String(http.StatusOK, signedURL)
	})

	user.GET("/sent/:fileID", func(c echo.Context) error {
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
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		clientByID := make(map[string]db.Client, len(clients))
		for _, cl := range clients {
			clientByID[cl.ID] = cl
		}
		clientGroups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		clientGroupByID := make(map[string]db.ClientGroup, len(clientGroups))
		for _, cg := range clientGroups {
			clientGroupByID[cg.ID] = cg
		}
		users, err := queries.ListUsers(c.Request().Context(), db.ListUsersParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load users")
		}
		userByID := make(map[string]db.User, len(users))
		for _, u := range users {
			userByID[u.ID] = u
		}
		userGroups, err := queries.ListUserGroups(c.Request().Context(), db.ListUserGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load user groups")
		}
		userGroupByID := make(map[string]db.UserGroup, len(userGroups))
		for _, ug := range userGroups {
			userGroupByID[ug.ID] = ug
		}
		shareItems := make([]fileShareListItem, 0, len(shares))
		for _, sh := range shares {
			targetLabel := sh.TargetType + ":" + sh.TargetID
			switch sh.TargetType {
			case "client":
				if cl, ok := clientByID[sh.TargetID]; ok {
					targetLabel = "Client: " + strings.TrimSpace(cl.DisplayName)
				}
			case "client_group":
				if cg, ok := clientGroupByID[sh.TargetID]; ok {
					targetLabel = "Client Group: " + strings.TrimSpace(cg.Name)
				}
			case "user":
				if u, ok := userByID[sh.TargetID]; ok {
					if name := strings.TrimSpace(u.FullName); name != "" {
						targetLabel = "User: " + name
					} else {
						targetLabel = "User: " + strings.TrimSpace(u.Email)
					}
				}
			case "user_group":
				if ug, ok := userGroupByID[sh.TargetID]; ok {
					targetLabel = "User Group: " + strings.TrimSpace(ug.Name)
				}
			}
			shareItems = append(shareItems, fileShareListItem{ID: sh.ID, TargetType: sh.TargetType, TargetID: sh.TargetID, TargetLabel: targetLabel})
		}
		viewHistory, err := queries.ListFileViewHistory(c.Request().Context(), fileID)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load view history")
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Sent File Detail", "Subtitle": "Detailed metadata for your sent file.", "ContentTemplate": "user_sent_file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "sent", UploadedAt: file.CreatedAt}, "BackPath": "/user/sent", "DownloadPath": "/user/sent/" + file.ID + "/download", "ManageFile": true, "ManageBasePath": "/user/sent", "ShareTargets": shareItems, "Clients": clients, "ClientGroups": clientGroups, "Users": users, "UserGroups": userGroups, "ViewHistory": viewHistory, "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	})

	user.POST("/sent/:fileID/rename", func(c echo.Context) error {
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
				return c.Redirect(http.StatusSeeOther, "/user/sent/"+fileID+"?error="+url.QueryEscape("filename is required"))
			}
			return c.String(http.StatusBadRequest, "filename is required")
		}
		if err := queries.UpdateFileNameByID(c.Request().Context(), db.UpdateFileNameByIDParams{ID: fileID, OriginalFilename: name}); err != nil {
			return c.String(http.StatusInternalServerError, "failed to rename file")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/sent/"+fileID+"?success="+url.QueryEscape("File renamed"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.POST("/sent/:fileID/delete", func(c echo.Context) error {
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
			return c.Redirect(http.StatusSeeOther, "/user/sent?success="+url.QueryEscape("File deleted"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.POST("/sent/:fileID/shares", func(c echo.Context) error {
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
				return c.Redirect(http.StatusSeeOther, "/user/sent/"+fileID+"?error="+url.QueryEscape("target_type and target_id are required"))
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
				return c.Redirect(http.StatusSeeOther, "/user/sent/"+fileID+"?error="+url.QueryEscape("invalid share target"))
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
			return c.Redirect(http.StatusSeeOther, "/user/sent/"+fileID+"?success="+url.QueryEscape("Share added"))
		}
		return c.NoContent(http.StatusCreated)
	})

	user.POST("/sent/:fileID/shares/:shareID/delete", func(c echo.Context) error {
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
			return c.Redirect(http.StatusSeeOther, "/user/sent/"+fileID+"?success="+url.QueryEscape("Share removed"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.GET("/received", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		shares, err := queries.ListUserAccessibleShares(c.Request().Context(), db.ListUserAccessibleSharesParams{UserID: principal.ActorID, Limit: 50, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load received files")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 500, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		clientByID := make(map[string]db.Client, len(clients))
		for _, cl := range clients {
			clientByID[cl.ID] = cl
		}

		items := make([]fileListItem, 0, len(shares))
		itemIndex := make(map[string]int, len(shares))
		fileSharedAt := make(map[string]string, len(shares))
		fileSharedBy := make(map[string]string, len(shares))
		for _, sh := range shares {
			f, fileErr := queries.GetFileByID(c.Request().Context(), sh.FileID)
			if fileErr != nil {
				continue
			}
			if prev, exists := fileSharedAt[f.ID]; !exists || sh.CreatedAt > prev {
				fileSharedAt[f.ID] = sh.CreatedAt
				if sh.SharedByType == "client" {
					if cl, ok := clientByID[sh.SharedByID]; ok {
						fileSharedBy[f.ID] = strings.TrimSpace(cl.DisplayName)
					} else {
						fileSharedBy[f.ID] = sh.SharedByID
					}
				} else if f.UploaderType == "client" {
					if cl, ok := clientByID[f.UploaderID]; ok {
						fileSharedBy[f.ID] = strings.TrimSpace(cl.DisplayName)
					} else {
						fileSharedBy[f.ID] = f.UploaderID
					}
				} else {
					fileSharedBy[f.ID] = sh.SharedByID
				}
			}

			if idx, exists := itemIndex[f.ID]; exists {
				items[idx].SharedAt = fileSharedAt[f.ID]
				items[idx].SharedVia = fileSharedBy[f.ID]
				continue
			}

			itemIndex[f.ID] = len(items)
			items = append(items, fileListItem{ID: f.ID, Name: f.OriginalFilename, ContentType: f.ContentType, SizeBytes: f.SizeBytes, SharedVia: fileSharedBy[f.ID], SharedAt: fileSharedAt[f.ID]})
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Received Files", "Subtitle": "Files sent to your account.", "ContentTemplate": "shared_files_content", "Files": items, "EmptyMessage": "No files have been received yet.", "DetailBasePath": "/user/received", "DownloadBasePath": "/user/received", "ShowSharedViaColumn": true, "SharedViaColumnLabel": "Shared By"})
	})

	user.GET("/received/:fileID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		shares, err := queries.ListUserAccessibleShares(c.Request().Context(), db.ListUserAccessibleSharesParams{UserID: principal.ActorID, Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to authorize file")
		}
		allowed := false
		sharedAt := ""
		for _, sh := range shares {
			if sh.FileID == fileID {
				allowed = true
				if sharedAt == "" || sh.CreatedAt > sharedAt {
					sharedAt = sh.CreatedAt
				}
			}
		}
		if !allowed {
			return c.String(http.StatusForbidden, "forbidden")
		}
		file, err := queries.GetFileByID(c.Request().Context(), fileID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "file not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load file")
		}
		return c.Render(http.StatusOK, "shared_files", map[string]any{"Title": "Received File Detail", "Subtitle": "File metadata and available actions.", "ContentTemplate": "file_detail_content", "File": fileListItem{ID: file.ID, Name: file.OriginalFilename, ContentType: file.ContentType, SizeBytes: file.SizeBytes, SharedVia: "received", SharedAt: sharedAt}, "BackPath": "/user/received", "DownloadPath": "/user/received/" + file.ID + "/download"})
	})

	user.GET("/received/:fileID/download", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		fileID := c.Param("fileID")
		shares, err := queries.ListUserAccessibleShares(c.Request().Context(), db.ListUserAccessibleSharesParams{UserID: principal.ActorID, Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to authorize download")
		}
		for _, sh := range shares {
			if sh.FileID == fileID {
				signedURL, signedErr := s.downSvc.SignedDownloadURL(c.Request().Context(), principal, fileID)
				if signedErr != nil {
					if signedErr == auth.ErrForbidden {
						return c.String(http.StatusForbidden, "forbidden")
					}
					return c.String(http.StatusInternalServerError, "failed to authorize download")
				}
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, signedURL)
				}
				return c.String(http.StatusOK, signedURL)
			}
		}
		return c.String(http.StatusForbidden, "forbidden")
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
		actorLabel := principal.ActorID
		if user, userErr := queries.GetUserByID(c.Request().Context(), principal.ActorID); userErr == nil {
			if name := strings.TrimSpace(user.FullName); name != "" {
				actorLabel = name
			} else if email := strings.TrimSpace(user.Email); email != "" {
				actorLabel = email
			}
		}
		recipients, recErr := resolveShareRecipientEmails(c.Request().Context(), queries, targetType, targetID)
		if recErr == nil {
			for _, recipient := range recipients {
				notifyErr := s.notifier.NotifyFileShared(c.Request().Context(), mail.FileSharedNotification{RecipientEmail: recipient, RecipientName: recipient, ActorLabel: actorLabel, FileName: filename, Message: message, TargetType: targetType, TargetID: targetID})
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
		groups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		return c.Render(http.StatusOK, "clients_management", map[string]any{"Title": "Client Management", "Subtitle": "Create clients and manage client accounts.", "ContentTemplate": "clients_management_content", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success"), "Clients": clients, "ClientGroups": groups})
	})

	user.GET("/client-groups", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		groups, err := queries.ListClientGroups(c.Request().Context(), db.ListClientGroupsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client groups")
		}
		groupItems := make([]clientGroupListItem, 0, len(groups))
		for _, g := range groups {
			members, memberErr := queries.ListGroupClients(c.Request().Context(), g.ID)
			if memberErr != nil {
				return c.String(http.StatusInternalServerError, "failed to load client groups")
			}
			groupItems = append(groupItems, clientGroupListItem{ID: g.ID, Name: g.Name, MemberCount: len(members)})
		}
		return c.Render(http.StatusOK, "client_groups_management", map[string]any{"Title": "Client Groups", "Subtitle": "Create groups and add client memberships.", "ContentTemplate": "client_groups_management_content", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success"), "Clients": clients, "ClientGroups": groups, "ClientGroupItems": groupItems})
	})

	user.GET("/client-groups/:groupID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		groupID := strings.TrimSpace(c.Param("groupID"))
		group, err := queries.GetClientGroupByID(c.Request().Context(), groupID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "client group not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load client group")
		}
		members, err := queries.ListGroupClients(c.Request().Context(), groupID)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load client group members")
		}
		clients, err := queries.ListClients(c.Request().Context(), db.ListClientsParams{Limit: 200, Offset: 0})
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to load clients")
		}
		return c.Render(http.StatusOK, "client_group_detail", map[string]any{"Title": "Client Group Detail", "Subtitle": "Update group settings and memberships.", "ContentTemplate": "client_group_detail_content", "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success"), "ClientGroup": group, "GroupMembers": members, "Clients": clients})
	})

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
		clientID := uuid.NewString()
		if err := queries.CreateClient(c.Request().Context(), db.CreateClientParams{ID: clientID, Email: email, DisplayName: displayName, PasswordHash: sql.NullString{}, CanUpload: canUpload, IsActive: isActive}); err != nil {
			auditAuthEvent(c, queries, "admin.client.create", principal.ActorType, principal.ActorID, "client", "", map[string]any{"outcome": "failure", "reason": "create_failed", "email": email})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("failed to create client"))
			}
			return c.String(http.StatusInternalServerError, "failed to create client")
		}
		formParams, formErr := c.FormParams()
		if formErr != nil {
			return c.String(http.StatusBadRequest, "failed to parse form params")
		}
		groupIDs := formParams["group_ids"]
		for _, groupID := range groupIDs {
			groupID = strings.TrimSpace(groupID)
			if groupID == "" {
				continue
			}
			if err := queries.AddClientToGroup(c.Request().Context(), db.AddClientToGroupParams{ClientGroupID: groupID, ClientID: clientID}); err != nil {
				if isHTMLRequest(c) {
					return c.Redirect(http.StatusSeeOther, "/user/clients?error="+url.QueryEscape("failed to assign client group membership"))
				}
				return c.String(http.StatusInternalServerError, "failed to assign client group membership")
			}
		}
		auditAuthEvent(c, queries, "admin.client.create", principal.ActorType, principal.ActorID, "client", email, map[string]any{"outcome": "success"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/clients?success="+url.QueryEscape("Client created"))
		}
		return c.NoContent(http.StatusCreated)
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.GET("/clients/:clientID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		clientID := strings.TrimSpace(c.Param("clientID"))
		client, err := queries.GetClientByID(c.Request().Context(), clientID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "client not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load client")
		}
		return c.Render(http.StatusOK, "client_edit", map[string]any{"Title": "Edit Client", "Subtitle": "Update client access and reset password.", "ContentTemplate": "client_edit_content", "Client": client, "FlashError": c.QueryParam("error"), "FlashSuccess": c.QueryParam("success")})
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/clients/:clientID", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		clientID := strings.TrimSpace(c.Param("clientID"))
		client, err := queries.GetClientByID(c.Request().Context(), clientID)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.String(http.StatusNotFound, "client not found")
			}
			return c.String(http.StatusInternalServerError, "failed to load client")
		}
		displayName := strings.TrimSpace(c.FormValue("display_name"))
		if displayName == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients/"+client.ID+"?error="+url.QueryEscape("display_name is required"))
			}
			return c.String(http.StatusBadRequest, "display_name is required")
		}
		canUpload := int64(0)
		if c.FormValue("can_upload") == "1" {
			canUpload = 1
		}
		isActive := int64(0)
		if c.FormValue("is_active") == "1" {
			isActive = 1
		}
		if err := queries.UpdateClient(c.Request().Context(), db.UpdateClientParams{ID: client.ID, DisplayName: displayName, CanUpload: canUpload, IsActive: isActive}); err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients/"+client.ID+"?error="+url.QueryEscape("failed to update client"))
			}
			return c.String(http.StatusInternalServerError, "failed to update client")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/clients/"+client.ID+"?success="+url.QueryEscape("Client updated"))
		}
		return c.NoContent(http.StatusNoContent)
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/clients/:clientID/reset-password", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		clientID := strings.TrimSpace(c.Param("clientID"))
		newPassword := strings.TrimSpace(c.FormValue("new_password"))
		if len(newPassword) < 12 {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients/"+clientID+"?error="+url.QueryEscape("Password must be at least 12 characters"))
			}
			return c.String(http.StatusBadRequest, "password must be at least 12 characters")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to hash password")
		}
		if err := queries.UpdateClientPasswordHashByID(c.Request().Context(), clientID, sql.NullString{Valid: true, String: string(hash)}); err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/clients/"+clientID+"?error="+url.QueryEscape("failed to reset password"))
			}
			return c.String(http.StatusInternalServerError, "failed to reset password")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/clients/"+clientID+"?success="+url.QueryEscape("Password reset"))
		}
		return c.NoContent(http.StatusNoContent)
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/client-groups", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		name := strings.TrimSpace(c.FormValue("name"))
		if name == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups?error="+url.QueryEscape("name is required"))
			}
			return c.String(http.StatusBadRequest, "name is required")
		}
		if err := queries.CreateClientGroup(c.Request().Context(), db.CreateClientGroupParams{ID: uuid.NewString(), Name: name, CreatedByUserID: sql.NullString{Valid: true, String: principal.ActorID}}); err != nil {
			auditAuthEvent(c, queries, "admin.client_group.create", principal.ActorType, principal.ActorID, "client_group", "", map[string]any{"outcome": "failure", "reason": "create_failed", "name": name})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups?error="+url.QueryEscape("failed to create client group"))
			}
			return c.String(http.StatusInternalServerError, "failed to create client group")
		}
		auditAuthEvent(c, queries, "admin.client_group.create", principal.ActorType, principal.ActorID, "client_group", name, map[string]any{"outcome": "success"})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/client-groups?success="+url.QueryEscape("Client group created"))
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
				return c.Redirect(http.StatusSeeOther, "/user/client-groups?error="+url.QueryEscape("group_id and client_id are required"))
			}
			return c.String(http.StatusBadRequest, "group_id and client_id are required")
		}
		if err := queries.AddClientToGroup(c.Request().Context(), db.AddClientToGroupParams{ClientGroupID: groupID, ClientID: clientID}); err != nil {
			auditAuthEvent(c, queries, "admin.client_group.membership.add", principal.ActorType, principal.ActorID, "client_group", groupID, map[string]any{"outcome": "failure", "reason": "add_failed", "client_id": clientID})
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups?error="+url.QueryEscape("failed to add membership"))
			}
			return c.String(http.StatusInternalServerError, "failed to add membership")
		}
		auditAuthEvent(c, queries, "admin.client_group.membership.add", principal.ActorType, principal.ActorID, "client_group", groupID, map[string]any{"outcome": "success", "client_id": clientID})
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/client-groups?success="+url.QueryEscape("Membership added"))
		}
		return c.NoContent(http.StatusCreated)
	}, auth.RequireCapability(auth.CapabilityManageClients))

	user.POST("/client-groups/update", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		groupID := strings.TrimSpace(c.FormValue("group_id"))
		name := strings.TrimSpace(c.FormValue("name"))
		if name == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?error="+url.QueryEscape("name is required"))
			}
			return c.String(http.StatusBadRequest, "name is required")
		}
		if err := queries.UpdateClientGroup(c.Request().Context(), db.UpdateClientGroupParams{ID: groupID, Name: name}); err != nil {
			s.log.Error("update client group failed", "group_id", groupID, "name", name, "error", err.Error())
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?error="+url.QueryEscape("failed to update client group"))
			}
			return c.String(http.StatusInternalServerError, "failed to update client group")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?success="+url.QueryEscape("Client group updated"))
		}
		return c.NoContent(http.StatusNoContent)
	})

	user.POST("/client-groups/memberships/add", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		groupID := strings.TrimSpace(c.FormValue("group_id"))
		clientID := strings.TrimSpace(c.FormValue("client_id"))
		if clientID == "" {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?error="+url.QueryEscape("client_id is required"))
			}
			return c.String(http.StatusBadRequest, "client_id is required")
		}
		if err := queries.AddClientToGroup(c.Request().Context(), db.AddClientToGroupParams{ClientGroupID: groupID, ClientID: clientID}); err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?error="+url.QueryEscape("failed to add membership"))
			}
			return c.String(http.StatusInternalServerError, "failed to add membership")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?success="+url.QueryEscape("Membership added"))
		}
		return c.NoContent(http.StatusCreated)
	})

	user.POST("/client-groups/memberships/remove", func(c echo.Context) error {
		principal, _ := auth.PrincipalFromContext(c)
		if err := s.authz.AuthorizeManageClients(principal); err != nil {
			return c.String(http.StatusForbidden, "forbidden")
		}
		groupID := strings.TrimSpace(c.FormValue("group_id"))
		clientID := strings.TrimSpace(c.FormValue("client_id"))
		if err := queries.RemoveClientFromGroup(c.Request().Context(), db.RemoveClientFromGroupParams{ClientGroupID: groupID, ClientID: clientID}); err != nil {
			if isHTMLRequest(c) {
				return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?error="+url.QueryEscape("failed to remove membership"))
			}
			return c.String(http.StatusInternalServerError, "failed to remove membership")
		}
		if isHTMLRequest(c) {
			return c.Redirect(http.StatusSeeOther, "/user/client-groups/"+groupID+"?success="+url.QueryEscape("Membership removed"))
		}
		return c.NoContent(http.StatusNoContent)
	})
}
