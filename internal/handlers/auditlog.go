package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) GetAuditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int64
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query audit logs"})
		return
	}

	rows, err := db.AuditDB.Query(`
		SELECT id,
		       COALESCE(username, ''),
		       action,
		       COALESCE(resource,''),
		       COALESCE(detail,''),
		       COALESCE(ip_address,''),
		       created_at
		FROM audit_log
		ORDER BY id DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query audit logs"})
		return
	}
	defer rows.Close()

	type AuditLogEntry struct {
		ID          int    `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Action      string `json:"action"`
		Resource    string `json:"resource"`
		Detail      string `json:"detail"`
		IPAddress   string `json:"ip_address"`
		CreatedAt   string `json:"created_at"`
	}

	var logs []AuditLogEntry
	var tzStr string
	db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tzStr)
	loc, _ := time.LoadLocation(tzStr)
	if loc == nil {
		loc = time.UTC
	}
	usernames := map[string]struct{}{}
	for rows.Next() {
		var e AuditLogEntry
		var createdAt time.Time
		if err := rows.Scan(&e.ID, &e.Username, &e.Action, &e.Resource, &e.Detail, &e.IPAddress, &createdAt); err == nil {
			e.CreatedAt = createdAt.In(loc).Format("2006-01-02 15:04:05")
		}
		if e.Username != "" {
			usernames[e.Username] = struct{}{}
		}
		logs = append(logs, e)
	}
	if logs == nil {
		logs = []AuditLogEntry{}
	}
	if len(usernames) > 0 {
		args := make([]interface{}, 0, len(usernames))
		placeholders := make([]string, 0, len(usernames))
		for name := range usernames {
			placeholders = append(placeholders, "?")
			args = append(args, name)
		}
		userRows, err := db.DB.Query("SELECT username, COALESCE(NULLIF(TRIM(display_name), ''), username) FROM users WHERE username IN ("+strings.Join(placeholders, ",")+")", args...)
		if err == nil {
			displayNames := map[string]string{}
			for userRows.Next() {
				var username, displayName string
				if err := userRows.Scan(&username, &displayName); err == nil {
					displayNames[username] = displayName
				}
			}
			userRows.Close()
			for i := range logs {
				if displayName, ok := displayNames[logs[i].Username]; ok {
					logs[i].DisplayName = displayName
				} else {
					logs[i].DisplayName = logs[i].Username
				}
			}
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]interface{}{
		"list":      logs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	}})
}
