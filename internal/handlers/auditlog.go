package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// GetAuditLogOptions 返回筛选下拉的可选值：操作人/操作取自审计库去重
// （按出现次数排序），对象仅保留高频值（长尾由模糊输入覆盖）。
func (h *Handlers) GetAuditLogOptions(c *gin.Context) {
	type optionRow struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	}
	fetchDistinct := func(column string, limit int) []optionRow {
		rows, err := db.AuditDB.Query(`
			SELECT `+column+`, COUNT(*) AS cnt FROM audit_log
			WHERE `+column+` != ''
			GROUP BY `+column+`
			ORDER BY cnt DESC, `+column+`
			LIMIT ?`, limit)
		if err != nil {
			return []optionRow{}
		}
		defer rows.Close()
		out := []optionRow{}
		for rows.Next() {
			var o optionRow
			if err := rows.Scan(&o.Value, &o.Count); err == nil {
				out = append(out, o)
			}
		}
		return out
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]interface{}{
		"usernames": fetchDistinct("COALESCE(username,'')", 100),
		"actions":   fetchDistinct("action", 100),
		"resources": fetchDistinct("COALESCE(resource,'')", 50),
	}})
}

// buildAuditLogFilters 组装列筛选 WHERE 子句。时间参数按配置时区解析后
// 换算为 UTC 与 created_at 比较；日期-only 输入自动补全天/日边界。
func buildAuditLogFilters(c *gin.Context, loc *time.Location) (string, []interface{}) {
	like := func(column, value string) (string, interface{}) {
		return " AND " + column + " LIKE ?", "%" + value + "%"
	}
	var conds []string
	var args []interface{}
	if v := strings.TrimSpace(c.Query("username")); v != "" {
		c1, a1 := like("COALESCE(username,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("action")); v != "" {
		c1, a1 := like("action", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("resource")); v != "" {
		c1, a1 := like("COALESCE(resource,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("ip")); v != "" {
		c1, a1 := like("COALESCE(ip_address,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	if v := strings.TrimSpace(c.Query("keyword")); v != "" {
		c1, a1 := like("COALESCE(detail,'')", v)
		conds = append(conds, c1)
		args = append(args, a1)
	}
	parseBoundary := func(raw, endOfDay string) (time.Time, bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return time.Time{}, false
		}
		if len(raw) == 10 { // YYYY-MM-DD → 起点取 00:00:00，终点取 23:59:59
			raw += " " + endOfDay
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", raw, loc)
		if err != nil {
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	if t, ok := parseBoundary(c.Query("start_time"), "00:00:00"); ok {
		conds = append(conds, " AND datetime(created_at) >= datetime(?)")
		args = append(args, t.Format("2006-01-02 15:04:05"))
	}
	if t, ok := parseBoundary(c.Query("end_time"), "23:59:59"); ok {
		conds = append(conds, " AND datetime(created_at) <= datetime(?)")
		args = append(args, t.Format("2006-01-02 15:04:05"))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE 1=1" + strings.Join(conds, ""), args
}

func (h *Handlers) GetAuditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	// clamp 上限防 (page-1)*pageSize 整数溢出为负 → SQLite OFFSET 报错 500
	// （与 ListSecurityEvents security.go:815 同口径，R34 C）。
	if page > 100000 {
		page = 100000
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 列筛选：操作人/操作/对象/IP 模糊匹配，keyword 搜详情，
	// 时间范围为配置时区的本地时间（created_at 按 UTC 存储，比较前换算）。
	loc := time.UTC
	var tzStr string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tzStr); err != nil {
		log.Printf("GetAuditLogs: failed to read configured timezone, using UTC: %v", err)
	} else if l, lerr := time.LoadLocation(tzStr); lerr == nil {
		loc = l
	} else {
		log.Printf("GetAuditLogs: failed to load timezone %q, using UTC: %v", tzStr, lerr)
	}
	where, args := buildAuditLogFilters(c, loc)

	var total int64
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log"+where, args...).Scan(&total); err != nil {
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
		FROM audit_log`+where+`
		ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, pageSize, offset)...)
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
	usernames := map[string]struct{}{}
	for rows.Next() {
		var e AuditLogEntry
		var createdAt time.Time
		if err := rows.Scan(&e.ID, &e.Username, &e.Action, &e.Resource, &e.Detail, &e.IPAddress, &createdAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取操作日志失败: " + err.Error()})
			return
		}
		e.CreatedAt = createdAt.UTC().Format("2006-01-02 15:04:05")
		e.DisplayName = e.Username
		if e.Username != "" {
			usernames[e.Username] = struct{}{}
		}
		logs = append(logs, e)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "遍历操作日志失败: " + err.Error()})
		return
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
		if err != nil {
			log.Printf("GetAuditLogs: failed to enrich usernames, using usernames: %v", err)
		} else {
			displayNames := map[string]string{}
			for userRows.Next() {
				var username, displayName string
				if err := userRows.Scan(&username, &displayName); err != nil {
					log.Printf("GetAuditLogs: failed to scan username enrichment, using usernames: %v", err)
					break
				}
				displayNames[username] = displayName
			}
			if err := userRows.Err(); err != nil {
				log.Printf("GetAuditLogs: failed to iterate username enrichment, using available names: %v", err)
			}
			if err := userRows.Close(); err != nil {
				log.Printf("GetAuditLogs: failed to close username enrichment rows: %v", err)
			}
			for i := range logs {
				if displayName, ok := displayNames[logs[i].Username]; ok {
					logs[i].DisplayName = displayName
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
