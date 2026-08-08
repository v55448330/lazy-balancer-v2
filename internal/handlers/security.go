package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) ListSecurityPolicies(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id, name, description, mode, anomaly_threshold, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, enabled, created_at, updated_at
		FROM security_policies ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()

	var policies []models.SecurityPolicySummary
	for rows.Next() {
		var p models.SecurityPolicy
		if err := scanSecurityPolicy(rows, &p); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		var ipWL, ipBL []string
		json.Unmarshal(p.IPWhitelist, &ipWL)
		json.Unmarshal(p.IPBlacklist, &ipBL)
		var ruleCount int
		db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE policy_id=?", p.ID).Scan(&ruleCount)
		policies = append(policies, models.SecurityPolicySummary{
			ID: p.ID, Name: p.Name, Mode: p.Mode, Enabled: p.Enabled, RuleCount: ruleCount,
			HasWAF: p.Mode != "off", HasIPControl: len(ipWL) > 0 || len(ipBL) > 0, HasRateLimit: p.RateLimitEnabled,
		})
	}
	if policies == nil {
		policies = []models.SecurityPolicySummary{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: policies})
}

func (h *Handlers) GetSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	var p models.SecurityPolicy
	err := db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, enabled, created_at, updated_at
		FROM security_policies WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPWhitelist, &p.IPBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &p.CRSRuleGroups, &p.CRSExcludedRules, &p.CustomRules, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}

	var bindings []string
	rows, _ := db.DB.Query("SELECT rule_caddy_id FROM security_policy_bindings WHERE policy_id=?", id)
	for rows.Next() {
		var b string
		rows.Scan(&b)
		bindings = append(bindings, b)
	}
	rows.Close()
	if bindings == nil {
		bindings = []string{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"policy": p, "bindings": bindings}})
}

func (h *Handlers) CreateSecurityPolicy(c *gin.Context) {
	var req models.CreateSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if req.Mode == "" {
		req.Mode = "off"
	}
	if req.IPWhitelist == "" {
		req.IPWhitelist = "[]"
	}
	if req.IPBlacklist == "" {
		req.IPBlacklist = "[]"
	}
	if req.CRSRuleGroups == "" {
		req.CRSRuleGroups = "[]"
	}
	if req.CRSExcludedRules == "" {
		req.CRSExcludedRules = "[]"
	}
	if req.CustomRules == "" {
		req.CustomRules = "[]"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, description, mode, anomaly_threshold, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, enabled)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		req.Name, req.Description, req.Mode, max1(req.AnomalyThreshold, 5), req.IPWhitelist, req.IPBlacklist,
		req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst, req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules, enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	services.RecordAuditLog(getContextUserID(c), "创建", "安全策略", fmt.Sprintf("名称：%s（#%d）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略创建成功", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	var req models.UpdateSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	query := "UPDATE security_policies SET updated_at=datetime('now')"
	var args []interface{}
	addStr := func(field string, val *string) {
		if val != nil {
			query += fmt.Sprintf(", %s=?", field)
			args = append(args, *val)
		}
	}
	addInt := func(field string, val *int) {
		if val != nil {
			query += fmt.Sprintf(", %s=?", field)
			args = append(args, *val)
		}
	}
	addBool := func(field string, val *bool) {
		if val != nil {
			query += fmt.Sprintf(", %s=?", field)
			args = append(args, *val)
		}
	}
	addStr("name", req.Name)
	addStr("description", req.Description)
	addStr("mode", req.Mode)
	addInt("anomaly_threshold", req.AnomalyThreshold)
	addStr("ip_whitelist", req.IPWhitelist)
	addStr("ip_blacklist", req.IPBlacklist)
	addBool("rate_limit_enabled", req.RateLimitEnabled)
	addInt("rate_limit_rps", req.RateLimitRPS)
	addInt("rate_limit_burst", req.RateLimitBurst)
	addStr("crs_rule_groups", req.CRSRuleGroups)
	addStr("crs_excluded_rules", req.CRSExcludedRules)
	addStr("custom_rules", req.CustomRules)
	addBool("enabled", req.Enabled)
	query += " WHERE id=?"
	args = append(args, id)
	result, err := db.DB.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "安全策略", fmt.Sprintf("策略 #%s", id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略更新成功"})
}

func (h *Handlers) DeleteSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	db.DB.Exec("DELETE FROM security_policy_bindings WHERE policy_id=?", id)
	result, err := db.DB.Exec("DELETE FROM security_policies WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "删除", "安全策略", fmt.Sprintf("策略 #%s", id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略已删除"})
}

func (h *Handlers) BindRuleToPolicy(c *gin.Context) {
	policyID := c.Param("id")
	var req struct {
		RuleCaddyID string `json:"rule_caddy_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	_, err := db.DB.Exec("INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", req.RuleCaddyID, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已关联"})
}

func (h *Handlers) UnbindRuleFromPolicy(c *gin.Context) {
	policyID := c.Param("id")
	ruleCaddyID := c.Param("caddy_id")
	_, err := db.DB.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleCaddyID, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已取消关联"})
}

func (h *Handlers) GetSecurityPolicyBindings(c *gin.Context) {
	ruleCaddyID := c.Param("caddy_id")
	var policyID int
	err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=?", ruleCaddyID).Scan(&policyID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: nil})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	var p models.SecurityPolicy
	db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, enabled, created_at, updated_at
		FROM security_policies WHERE id=?`, policyID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPWhitelist, &p.IPBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &p.CRSRuleGroups, &p.CRSExcludedRules, &p.CustomRules, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: p})
}

func (h *Handlers) ListSecurityEvents(c *gin.Context) {
	page := 1
	pageSize := 20
	fmt.Sscanf(c.DefaultQuery("page", "1"), "%d", &page)
	fmt.Sscanf(c.DefaultQuery("page_size", "20"), "%d", &pageSize)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	where := " WHERE 1=1"
	var args []interface{}
	if action := c.Query("action"); action != "" {
		where += " AND action=?"
		args = append(args, action)
	}
	if ip := c.Query("ip"); ip != "" {
		where += " AND client_ip LIKE ?"
		args = append(args, "%"+ip+"%")
	}
	if ruleID := c.Query("rule_caddy_id"); ruleID != "" {
		where += " AND rule_caddy_id=?"
		args = append(args, ruleID)
	}

	var total int
	db.DB.QueryRow("SELECT COUNT(*) FROM security_events"+where, args...).Scan(&total)

	queryArgs := append(args, pageSize, offset)
	rows, err := db.DB.Query("SELECT id, event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, request_snippet, response_status FROM security_events"+where+" ORDER BY event_time DESC LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		rows.Scan(&e.ID, &e.EventTime, &e.RuleCaddyID, &e.PolicyID, &e.ClientIP, &e.Method, &e.URI, &e.EventType, &e.RuleTriggered, &e.RuleMsg, &e.Action, &e.AnomalyScore, &e.RequestSnippet, &e.ResponseStatus)
		events = append(events, e)
	}
	if events == nil {
		events = []models.SecurityEvent{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": events, "total": total, "page": page, "page_size": pageSize}})
}

func (h *Handlers) GetSecurityOverview(c *gin.Context) {
	var overview models.SecurityOverview
	db.DB.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='blocked' AND date(event_time)=date('now')").Scan(&overview.TodayBlocked)
	db.DB.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='logged' AND date(event_time)=date('now')").Scan(&overview.TodayDetected)
	db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE enabled=1 AND mode!='off'").Scan(&overview.ActivePolicies)
	overview.CRSVersion = "v4.14.0"
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: overview})
}

func (h *Handlers) GetCRSInfo(c *gin.Context) {
	info := models.CRSInfo{
		Version:    "v4.14.0",
		AutoUpdate: true,
		RuleCount:  832,
	}
	var dbInfo struct {
		Version    string
		AutoUpdate bool
	}
	db.DB.QueryRow("SELECT version, auto_update FROM security_crs_version WHERE id=1").Scan(&dbInfo.Version, &dbInfo.AutoUpdate)
	if dbInfo.Version != "" {
		info.Version = dbInfo.Version
		info.AutoUpdate = dbInfo.AutoUpdate
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func (h *Handlers) UpdateCRSAutoUpdate(c *gin.Context) {
	var req struct {
		AutoUpdate bool `json:"auto_update"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	db.DB.Exec("INSERT OR REPLACE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, ?)", "v4.14.0", req.AutoUpdate)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// GetSecurityPolicyForRule and BuildCorazaDirectives are in services/security.go
// to avoid circular dependency (services can't import handlers).

func (h *Handlers) GetAllSecurityBindings(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT b.rule_caddy_id, p.id, p.name, p.mode, p.enabled, p.ip_whitelist, p.ip_blacklist, p.rate_limit_enabled
		FROM security_policy_bindings b JOIN security_policies p ON b.policy_id = p.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	type BindingInfo struct {
		PolicyID    int             `json:"policy_id"`
		Name        string          `json:"name"`
		Mode        string          `json:"mode"`
		Enabled     bool            `json:"enabled"`
		IPWhitelist json.RawMessage `json:"ip_whitelist"`
		IPBlacklist json.RawMessage `json:"ip_blacklist"`
		RateLimit   bool            `json:"rate_limit_enabled"`
	}
	result := map[string]BindingInfo{}
	for rows.Next() {
		var ruleCaddyID string
		var b BindingInfo
		rows.Scan(&ruleCaddyID, &b.PolicyID, &b.Name, &b.Mode, &b.Enabled, &b.IPWhitelist, &b.IPBlacklist, &b.RateLimit)
		result[ruleCaddyID] = b
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func scanSecurityPolicy(rows *sql.Rows, p *models.SecurityPolicy) error {
	return rows.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPWhitelist, &p.IPBlacklist,
		&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &p.CRSRuleGroups, &p.CRSExcludedRules, &p.CustomRules, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
}

func max1(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}

func getContextUserID(c *gin.Context) string {
	if uid, exists := c.Get("user_id"); exists {
		switch v := uid.(type) {
		case float64:
			return fmt.Sprintf("%d", int(v))
		case int:
			return fmt.Sprintf("%d", v)
		}
	}
	return "0"
}

func init() {
	log.Println("Security handlers registered")
}

func (h *Handlers) ListCRSRules(c *gin.Context) {
	rulesDir := "/app/waf/crs/rules"
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"rules": []interface{}{}, "total": 0}})
		return
	}

	search := strings.ToLower(c.DefaultQuery("search", ""))
	page := 1
	pageSize := 50
	fmt.Sscanf(c.DefaultQuery("page", "1"), "%d", &page)
	fmt.Sscanf(c.DefaultQuery("page_size", "50"), "%d", &pageSize)
	if page < 1 {
		page = 1
	}

	type CRSRule struct {
		Filename string `json:"filename"`
		Category string `json:"category"`
		Size     int64  `json:"size"`
	}
	var allRules []CRSRule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		cat := categorizeCRSFile(entry.Name())
		if search != "" && !strings.Contains(strings.ToLower(entry.Name()), search) && !strings.Contains(strings.ToLower(cat), search) {
			continue
		}
		allRules = append(allRules, CRSRule{
			Filename: entry.Name(),
			Category: cat,
			Size:     info.Size(),
		})
	}
	sort.Slice(allRules, func(i, j int) bool { return allRules[i].Filename < allRules[j].Filename })

	total := len(allRules)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	paged := allRules[start:end]
	if paged == nil {
		paged = []CRSRule{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"rules": paged, "total": total, "page": page, "page_size": pageSize}})
}

func (h *Handlers) GetCRSRuleContent(c *gin.Context) {
	filename := c.Param("filename")
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的文件名"})
		return
	}
	filepath := filepath.Join("/app/waf/crs/rules", filename)
	content, err := os.ReadFile(filepath)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则文件不存在"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"filename": filename, "content": string(content), "size": len(content)}})
}

func (h *Handlers) GetCRSSetupConfig(c *gin.Context) {
	content, err := os.ReadFile("/app/waf/crs/crs-setup.conf")
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CRS 配置文件不存在"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": string(content)}})
}

func categorizeCRSFile(filename string) string {
	name := strings.ToUpper(filename)
	switch {
	case strings.Contains(name, "920-"):
		return "协议异常"
	case strings.Contains(name, "921-"):
		return "协议攻击"
	case strings.Contains(name, "930-"):
		return "路径穿越 (LFI)"
	case strings.Contains(name, "931-"):
		return "远程文件包含 (RFI)"
	case strings.Contains(name, "932-"):
		return "远程代码执行 (RCE)"
	case strings.Contains(name, "933-"):
		return "PHP 攻击"
	case strings.Contains(name, "934-"):
		return "Node.js 攻击"
	case strings.Contains(name, "941-"):
		return "XSS 跨站脚本"
	case strings.Contains(name, "942-"):
		return "SQL 注入"
	case strings.Contains(name, "943-"):
		return "会话固定"
	case strings.Contains(name, "944-"):
		return "Java 攻击"
	case strings.Contains(name, "949-"):
		return "请求阻断评估"
	case strings.Contains(name, "950-"):
		return "响应信息泄露"
	case strings.Contains(name, "951-"):
		return "响应 SQL 泄露"
	case strings.Contains(name, "953-"):
		return "响应 PHP 泄露"
	case strings.Contains(name, "959-"):
		return "响应阻断评估"
	case strings.Contains(name, "980-"):
		return "事件关联"
	case strings.Contains(name, "900-"):
		return "初始化/排除"
	case strings.Contains(name, "901-"):
		return "初始化"
	case strings.Contains(name, "905-"):
		return "通用异常"
	case strings.Contains(name, "911-"):
		return "方法限制"
	case strings.Contains(name, "912-"):
		return "文件上传"
	case strings.Contains(name, "913-"):
		return "爬虫检测"
	case strings.Contains(name, "915-"):
		return "请求体限制"
	default:
		return "其他"
	}
}
