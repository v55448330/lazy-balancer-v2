package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) ListSecurityCustomRules(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, description, conditions, action, score, enabled, created_at, updated_at, updated_by FROM security_custom_rules ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	var rules []models.SecurityCustomRule
	for rows.Next() {
		var r models.SecurityCustomRule
		var conditionsJSON string
		rows.Scan(&r.ID, &r.Name, &r.Description, &conditionsJSON, &r.Action, &r.Score, &r.Enabled, &r.CreatedAt, &r.UpdatedAt, &r.UpdatedBy)
		json.Unmarshal([]byte(conditionsJSON), &r.Conditions)
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []models.SecurityCustomRule{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

func validateSecurityCustomRule(rule *models.SecurityCustomRule) error {
	if rule.Name == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	if rule.Action != "block" && rule.Action != "log" && rule.Action != "pass" {
		return fmt.Errorf("动作必须为 block、log 或 pass，当前值 %s", rule.Action)
	}
	validScores := map[int]bool{1: true, 3: true, 5: true, 10: true, 20: true}
	if !validScores[rule.Score] {
		return fmt.Errorf("异常分值必须为 1/3/5/10/20 之一，当前值 %d", rule.Score)
	}
	if err := services.ValidateCustomRuleConditions(rule.Conditions); err != nil {
		return err
	}
	return nil
}

func (h *Handlers) CreateSecurityCustomRule(c *gin.Context) {
	var req models.SecurityCustomRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if err := validateSecurityCustomRule(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	conditionsJSON, _ := json.Marshal(req.Conditions)
	result, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, description, conditions, action, score, enabled, updated_by) VALUES (?,?,?,?,?,?,?)`,
		req.Name, req.Description, string(conditionsJSON), req.Action, req.Score, req.Enabled, getContextUserIDInt(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	services.RecordAuditLog(getContextUserID(c), "创建", "自定义规则", fmt.Sprintf("名称：%s（#%d）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则创建成功" + h.caddyApplyNote(), Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateSecurityCustomRule(c *gin.Context) {
	id := c.Param("id")
	var req models.SecurityCustomRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if err := validateSecurityCustomRule(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	conditionsJSON, _ := json.Marshal(req.Conditions)
	result, err := db.DB.Exec(`UPDATE security_custom_rules SET name=?, description=?, conditions=?, action=?, score=?, enabled=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		req.Name, req.Description, string(conditionsJSON), req.Action, req.Score, req.Enabled, getContextUserIDInt(c), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "自定义规则", fmt.Sprintf("名称：%s（#%s）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新" + h.caddyApplyNote()})
}

func (h *Handlers) DeleteSecurityCustomRule(c *gin.Context) {
	id := c.Param("id")
	result, err := db.DB.Exec("DELETE FROM security_custom_rules WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "删除", "自定义规则", fmt.Sprintf("规则 #%s", id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已删除" + h.caddyApplyNote()})
}

func (h *Handlers) ListSecurityBlockPages(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, description, content, is_default, created_by, created_at, updated_by, updated_at FROM security_block_pages ORDER BY is_default DESC, id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	var pages []models.SecurityBlockPage
	for rows.Next() {
		var p models.SecurityBlockPage
		rows.Scan(&p.ID, &p.Name, &p.Description, &p.Content, &p.IsDefault, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt)
		pages = append(pages, p)
	}
	if pages == nil {
		pages = []models.SecurityBlockPage{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: pages})
}

func (h *Handlers) CreateSecurityBlockPage(c *gin.Context) {
	var req models.SecurityBlockPage
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	result, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, is_default, created_by, updated_by) VALUES (?,?,?,?,?,?)`,
		req.Name, req.Description, req.Content, req.IsDefault, getContextUserIDInt(c), getContextUserIDInt(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	services.RecordAuditLog(getContextUserID(c), "创建", "拦截页面", fmt.Sprintf("名称：%s（#%d）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面创建成功" + h.caddyApplyNote(), Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateSecurityBlockPage(c *gin.Context) {
	id := c.Param("id")
	var req models.SecurityBlockPage
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	var isDefault bool
	db.DB.QueryRow("SELECT is_default FROM security_block_pages WHERE id=?", id).Scan(&isDefault)
	if isDefault {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "默认拦截页面不可编辑"})
		return
	}
	result, err := db.DB.Exec(`UPDATE security_block_pages SET name=?, description=?, content=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		req.Name, req.Description, req.Content, getContextUserIDInt(c), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "拦截页面", fmt.Sprintf("名称：%s（#%s）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面已更新" + h.caddyApplyNote()})
}

func (h *Handlers) DeleteSecurityBlockPage(c *gin.Context) {
	id := c.Param("id")
	var isDefault bool
	db.DB.QueryRow("SELECT is_default FROM security_block_pages WHERE id=?", id).Scan(&isDefault)
	if isDefault {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "默认拦截页面不可删除"})
		return
	}
	result, err := db.DB.Exec("DELETE FROM security_block_pages WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "删除", "拦截页面", fmt.Sprintf("页面 #%s", id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面已删除" + h.caddyApplyNote()})
}

func (h *Handlers) ListSecurityPolicies(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id, name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, updated_by, created_at, updated_at, geoip_countries, geoip_mode, waf_check_response
		FROM security_policies ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()

	var policies []models.SecurityPolicySummary
	bindingCounts := map[int]int{}
	bindingRows, err := db.DB.Query("SELECT policy_id, COUNT(*) FROM security_policy_bindings GROUP BY policy_id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	for bindingRows.Next() {
		var pid, cnt int
		bindingRows.Scan(&pid, &cnt)
		bindingCounts[pid] = cnt
	}
	bindingRows.Close()
	for rows.Next() {
		var p models.SecurityPolicy
		if err := scanSecurityPolicy(rows, &p); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		var ipACLEntries []string
		json.Unmarshal([]byte(p.IPACLList), &ipACLEntries)
		var crsExcluded []json.RawMessage
		json.Unmarshal(p.CRSExcludedRules, &crsExcluded)
		ruleCount := bindingCounts[p.ID]
		policies = append(policies, models.SecurityPolicySummary{
			ID: p.ID, Name: p.Name, Mode: p.Mode, Enabled: p.Enabled, RuleCount: ruleCount,
			HasWAF: p.Mode != "off", HasIPControl: services.SecurityPolicyHasIPControl(&p), HasRateLimit: p.RateLimitEnabled,
			AnomalyThreshold: p.AnomalyThreshold,
			IPACLMode:        p.IPACLMode,
			IPACLEnabled:     p.IPACLEnabled,
			IPACLList:        p.IPACLList,
			IPWhitelist:      rawJSONString(p.IPWhitelist),
			IPBlacklist:      rawJSONString(p.IPBlacklist),
			RateLimitRPS:     p.RateLimitRPS,
			RateLimitBurst:   p.RateLimitBurst,
			CRSExcludedCount: len(crsExcluded),
			CustomRulesCount: services.CountEnabledCustomRules(p.CustomRules),
			UpdatedBy:        p.UpdatedBy,
			UpdatedAt:        p.UpdatedAt,
			GeoIPCountries:   rawJSONString(p.GeoIPCountries),
			GeoIPMode:        p.GeoIPMode,
			WAFCheckResponse: p.WAFCheckResponse,
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
	err := scanSecurityPolicyRow(db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, updated_by, created_at, updated_at, geoip_countries, geoip_mode, waf_check_response
		FROM security_policies WHERE id=?`, id), &p)
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
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"policy": newSecurityPolicyDetail(&p), "bindings": bindings}})
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
	if req.IPACLList == "" {
		req.IPACLList = "[]"
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
	if req.GeoIPCountries == "" {
		req.GeoIPCountries = "[]"
	}
	if req.GeoIPMode == "" {
		req.GeoIPMode = "deny"
	}
	if err := validateGeoIPCountries(req.GeoIPCountries); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	for _, f := range []struct{ name, val string }{
		{"ip_acl_list", req.IPACLList},
		{"ip_whitelist", req.IPWhitelist},
		{"ip_blacklist", req.IPBlacklist},
	} {
		if err := validateIPCIDRList(f.name, f.val); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if err := validateSecurityPolicyEnums(req.Mode, req.IPACLMode, req.GeoIPMode, req.BlockStatusCode, req.AnomalyThreshold); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := services.ValidateCustomRulesJSON(req.CustomRules); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, geoip_countries, geoip_mode, waf_check_response, updated_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		req.Name, req.Description, req.Mode, max1(req.AnomalyThreshold, 5), req.IPACLMode, req.IPACLList, req.IPACLEnabled, req.IPWhitelist, req.IPBlacklist,
		req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst, req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules, req.BlockPageID, req.BlockStatusCode, enabled, req.GeoIPCountries, req.GeoIPMode, req.WAFCheckResponse, getContextUserIDInt(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	services.RecordAuditLog(getContextUserID(c), "创建", "安全策略", fmt.Sprintf("名称：%s（#%d）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略创建成功" + h.caddyApplyNote(), Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	var req models.UpdateSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"ip_acl_list", req.IPACLList},
		{"ip_whitelist", req.IPWhitelist},
		{"ip_blacklist", req.IPBlacklist},
	} {
		if f.val != nil {
			if err := validateIPCIDRList(f.name, *f.val); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
		}
	}
	var mode, ipACLMode, geoIPMode string
	if req.Mode != nil {
		mode = *req.Mode
	}
	if req.IPACLMode != nil {
		ipACLMode = *req.IPACLMode
	}
	if req.GeoIPMode != nil {
		geoIPMode = *req.GeoIPMode
	}
	blockStatusCode, anomalyThreshold := derefInt(req.BlockStatusCode), derefInt(req.AnomalyThreshold)
	if err := validateSecurityPolicyEnums(mode, ipACLMode, geoIPMode, blockStatusCode, anomalyThreshold); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if req.GeoIPCountries != nil {
		if err := validateGeoIPCountries(*req.GeoIPCountries); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if req.CustomRules != nil {
		if err := services.ValidateCustomRulesJSON(*req.CustomRules); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
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
	addStr("ip_acl_mode", req.IPACLMode)
	addStr("ip_acl_list", req.IPACLList)
	addBool("ip_acl_enabled", req.IPACLEnabled)
	addStr("ip_whitelist", req.IPWhitelist)
	addStr("ip_blacklist", req.IPBlacklist)

	addBool("rate_limit_enabled", req.RateLimitEnabled)
	addInt("rate_limit_rps", req.RateLimitRPS)
	addInt("rate_limit_burst", req.RateLimitBurst)
	addStr("crs_rule_groups", req.CRSRuleGroups)
	addStr("crs_excluded_rules", req.CRSExcludedRules)
	addStr("custom_rules", req.CustomRules)
	addStr("geoip_countries", req.GeoIPCountries)
	addStr("geoip_mode", req.GeoIPMode)
	addBool("waf_check_response", req.WAFCheckResponse)

	if req.BlockPageID != nil {
		query += ", block_page_id=?"
		args = append(args, *req.BlockPageID)
	}
	if req.BlockStatusCode != nil {
		query += ", block_status_code=?"
		args = append(args, *req.BlockStatusCode)
	}
	addBool("enabled", req.Enabled)
	query += ", updated_by=? WHERE id=?"
	args = append(args, getContextUserIDInt(c), id)
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
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略更新成功" + h.caddyApplyNote()})
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
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略已删除" + h.caddyApplyNote()})
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
	var policyExists int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE id=?", policyID).Scan(&policyExists); err != nil || policyExists == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	if _, err := db.DB.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id=?", req.RuleCaddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	_, err := db.DB.Exec("INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", req.RuleCaddyID, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "安全策略", fmt.Sprintf("绑定规则 %s 到策略 #%s", req.RuleCaddyID, policyID), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已关联" + h.caddyApplyNote()})
}

func (h *Handlers) UnbindRuleFromPolicy(c *gin.Context) {
	policyID := c.Param("id")
	ruleCaddyID := c.Param("caddy_id")
	_, err := db.DB.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleCaddyID, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "安全策略", fmt.Sprintf("解除规则 %s 与策略 #%s 的绑定", ruleCaddyID, policyID), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已取消关联" + h.caddyApplyNote()})
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
	if err := scanSecurityPolicyRow(db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, updated_by, created_at, updated_at, geoip_countries, geoip_mode, waf_check_response
		FROM security_policies WHERE id=?`, policyID), &p); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
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
	// 时间范围按配置时区解析（event_time 为 UTC），换算后比对；日期-only 补全天边界
	loc := services.CurrentLocation()
	parseBoundary := func(raw, endOfDay string) (string, bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return "", false
		}
		if len(raw) == 10 {
			raw += " " + endOfDay
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", raw, loc)
		if err != nil {
			return "", false
		}
		return t.UTC().Format("2006-01-02 15:04:05"), true
	}
	if v, ok := parseBoundary(c.Query("start_time"), "00:00:00"); ok {
		where += " AND datetime(event_time) >= datetime(?)"
		args = append(args, v)
	}
	if v, ok := parseBoundary(c.Query("end_time"), "23:59:59"); ok {
		where += " AND datetime(event_time) <= datetime(?)"
		args = append(args, v)
	}

	var total int
	db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events"+where, args...).Scan(&total)

	queryArgs := append(args, pageSize, offset)
	rows, err := db.MetricsDB.Query(`SELECT e.id, e.event_time, e.rule_caddy_id, e.policy_id, e.client_ip, e.method, e.uri, e.event_type, e.rule_triggered, e.rule_msg, e.action, e.anomaly_score,
		e.rule_name, e.policy_name
		FROM security_events e`+where+" ORDER BY e.event_time DESC LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		rows.Scan(&e.ID, &e.EventTime, &e.RuleCaddyID, &e.PolicyID, &e.ClientIP, &e.Method, &e.URI, &e.EventType, &e.RuleTriggered, &e.RuleMsg, &e.Action, &e.AnomalyScore, &e.RuleName, &e.PolicyName)
		events = append(events, e)
	}
	if events == nil {
		events = []models.SecurityEvent{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": events, "total": total, "page": page, "page_size": pageSize}})
}

func categorizeAttack(ruleTriggered, ruleMsg string) string {
	switch {
	case strings.HasPrefix(ruleTriggered, "942"):
		return "SQL注入"
	case strings.HasPrefix(ruleTriggered, "941"):
		return "XSS"
	case strings.HasPrefix(ruleTriggered, "930"):
		return "文件包含"
	case strings.HasPrefix(ruleTriggered, "931"):
		return "文件读取"
	case strings.HasPrefix(ruleTriggered, "932"):
		return "命令注入"
	case strings.HasPrefix(ruleTriggered, "933"):
		return "PHP注入"
	case strings.HasPrefix(ruleTriggered, "934"):
		return "Node.js 攻击"
	case strings.HasPrefix(ruleTriggered, "920"):
		return "协议异常"
	case strings.HasPrefix(ruleTriggered, "921"):
		return "协议攻击"
	case strings.HasPrefix(ruleTriggered, "911"):
		return "方法限制"
	case strings.HasPrefix(ruleTriggered, "912"):
		return "文件上传"
	case strings.HasPrefix(ruleTriggered, "915"):
		return "请求体限制"
	case strings.HasPrefix(ruleTriggered, "913"):
		return "扫描探测"
	case strings.HasPrefix(ruleTriggered, "943"):
		return "会话固定"
	case strings.HasPrefix(ruleTriggered, "944"):
		return "Java 攻击"
	case strings.HasPrefix(ruleTriggered, "950"):
		return "响应信息泄露"
	case strings.HasPrefix(ruleTriggered, "951"):
		return "响应 SQL 泄露"
	case strings.HasPrefix(ruleTriggered, "953"):
		return "响应 PHP 泄露"
	case strings.HasPrefix(ruleTriggered, "959"):
		return "响应阻断评估"
	case strings.HasPrefix(ruleTriggered, "949"):
		return "请求阻断评估"
	case strings.HasPrefix(ruleTriggered, "1") && len(ruleTriggered) == 5:
		return "自定义规则"
	case strings.Contains(ruleMsg, "IP 黑名单") || strings.Contains(ruleMsg, "IP 白名单") || strings.Contains(ruleMsg, "IP 访问控制") ||
		ruleTriggered == "2" || ruleTriggered == "3" || ruleTriggered == "4" || ruleTriggered == "5":
		return "IP 访问控制"
	default:
		return "其他"
	}
}

// joinDistinctFamilies renders a per-IP attack_type: distinct families ordered by
// frequency desc (name asc on ties), joined by 、. An empty map (no events) yields "".
func joinDistinctFamilies(counts map[string]int) string {
	families := make([]string, 0, len(counts))
	for family := range counts {
		families = append(families, family)
	}
	sort.Slice(families, func(i, j int) bool {
		if counts[families[i]] != counts[families[j]] {
			return counts[families[i]] > counts[families[j]]
		}
		return families[i] < families[j]
	})
	return strings.Join(families, "、")
}

func (h *Handlers) GetSecurityOverview(c *gin.Context) {
	// 日界按配置时区计算：event_time 为 UTC，「今日」与 7 日趋势桶均以
	// 配置时区的本地日期为准（printf modifier 将 UTC 事件时间平移到本地后取日期）。
	loc := services.CurrentLocation()
	_, offset := time.Now().In(loc).Zone()
	offsetMinutes := offset / 60
	now := time.Now().In(loc)
	todayStartUTC := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC().Format("2006-01-02 15:04:05")

	var overview models.SecurityOverview
	db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='blocked' AND event_time >= ?", todayStartUTC).Scan(&overview.TodayBlocked)
	db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='logged' AND event_time >= ?", todayStartUTC).Scan(&overview.TodayDetected)
	db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE enabled=1 AND mode!='off'").Scan(&overview.ActivePolicies)

	// 7-day trend: always the full today-6 … today slice (local dates), zero-filled.
	// 时区偏移在 Go 侧拼好（负偏移如 America/New_York 为 "-240 minutes"）；SQLite 的
	// printf('+%d', -240) 会产出非法修饰符 "+-240" 使 date() 返回 NULL，导致趋势全零。
	tzModifier := fmt.Sprintf("%+d minutes", offsetMinutes)
	trendByDate := map[string]models.SecurityTrendPoint{}
	trendRows, _ := db.MetricsDB.Query(`SELECT date(event_time, ?) as d, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b, SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY d`, tzModifier, todayStartUTC)
	for trendRows.Next() {
		var t models.SecurityTrendPoint
		trendRows.Scan(&t.Date, &t.Blocked, &t.Detected)
		trendByDate[t.Date] = t
	}
	trendRows.Close()
	overview.Trend = make([]models.SecurityTrendPoint, 0, 7)
	today := time.Now().In(loc)
	for i := 6; i >= 0; i-- {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		point := trendByDate[day]
		point.Date = day
		overview.Trend = append(overview.Trend, point)
	}

	// Top 10 IPs: counts + last time, then distinct attack families per IP
	type topIPRow struct {
		ip                string
		blocked, detected int
		lastTime          string
	}
	var topRows []topIPRow
	ipRows, _ := db.MetricsDB.Query(`SELECT client_ip, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b, SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l, MAX(event_time) as last_time FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY client_ip ORDER BY b + l DESC LIMIT 10`, todayStartUTC)
	for ipRows.Next() {
		var row topIPRow
		ipRows.Scan(&row.ip, &row.blocked, &row.detected, &row.lastTime)
		topRows = append(topRows, row)
	}
	ipRows.Close()
	familyCountsByIP := map[string]map[string]int{}
	famRows, _ := db.MetricsDB.Query(`SELECT client_ip, COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY client_ip, rule_triggered, rule_msg ORDER BY cnt DESC LIMIT 5000`, todayStartUTC)
	for famRows.Next() {
		var ip, ruleTriggered, ruleMsg string
		var cnt int
		famRows.Scan(&ip, &ruleTriggered, &ruleMsg, &cnt)
		counts := familyCountsByIP[ip]
		if counts == nil {
			counts = map[string]int{}
			familyCountsByIP[ip] = counts
		}
		counts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
	}
	famRows.Close()
	overview.TopIPs = make([]models.SecurityTopIP, 0, len(topRows))
	for _, row := range topRows {
		overview.TopIPs = append(overview.TopIPs, models.SecurityTopIP{
			IP:         row.ip,
			Blocked:    row.blocked,
			Detected:   row.detected,
			LastTime:   row.lastTime,
			AttackType: joinDistinctFamilies(familyCountsByIP[row.ip]),
		})
	}

	// Attack types grouped by family
	typeRows, _ := db.MetricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY rule_triggered, rule_msg`, todayStartUTC)
	familyCounts := map[string]int{}
	for typeRows.Next() {
		var ruleTriggered, ruleMsg string
		var cnt int
		typeRows.Scan(&ruleTriggered, &ruleMsg, &cnt)
		familyCounts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
	}
	typeRows.Close()
	attackTypes := make([]models.SecurityAttackType, 0, len(familyCounts))
	for name, value := range familyCounts {
		attackTypes = append(attackTypes, models.SecurityAttackType{Name: name, Value: value})
	}
	sort.Slice(attackTypes, func(i, j int) bool {
		if attackTypes[i].Value != attackTypes[j].Value {
			return attackTypes[i].Value > attackTypes[j].Value
		}
		return attackTypes[i].Name < attackTypes[j].Name
	})
	if len(attackTypes) > 10 {
		attackTypes = attackTypes[:10]
	}
	overview.AttackTypes = attackTypes

	overview.CRSVersion = services.CRSBundledVersion
	overview.UpdateStatus = "idle"
	var crsVersion, crsUpdateStatus string
	if err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,'idle') FROM security_crs_version WHERE id=1`).Scan(&crsVersion, &crsUpdateStatus); err == nil {
		if crsVersion != "" {
			overview.CRSVersion = crsVersion
		}
		overview.UpdateStatus = crsUpdateStatus
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: overview})
}

func (h *Handlers) GetCRSInfo(c *gin.Context) {
	info := models.CRSInfo{
		Version:       services.CRSBundledVersion,
		ServerVersion: getCaddyVersion(),
		AutoUpdate:    true,
		IsLatest:      true,
		UpdateStatus:  "idle",
	}
	var stored struct {
		version, updatedAt, updateStatus, message, nextUpdate, lastChecked, trigger string
		autoUpdate                                                                  bool
	}
	err := db.DB.QueryRow(`SELECT version, COALESCE(updated_at,''), COALESCE(update_status,'idle'),
		COALESCE(message,''), COALESCE(next_update,''), COALESCE(last_checked,''), COALESCE(trigger,''), auto_update
		FROM security_crs_version WHERE id=1`).
		Scan(&stored.version, &stored.updatedAt, &stored.updateStatus, &stored.message,
			&stored.nextUpdate, &stored.lastChecked, &stored.trigger, &stored.autoUpdate)
	if err == nil {
		if stored.version != "" {
			info.Version = stored.version
		}
		info.UpdatedAt = stored.updatedAt
		info.UpdateStatus = stored.updateStatus
		info.Message = stored.message
		info.LastChecked = stored.lastChecked
		info.Trigger = stored.trigger
		info.AutoUpdate = stored.autoUpdate
		if stored.autoUpdate {
			info.NextUpdate = stored.nextUpdate
		}
	}
	if mgr := services.GetCRSUpdateManager(); mgr != nil {
		if snap := mgr.StatusSnapshot(); services.IsActiveCRSStatus(snap.Status) {
			info.UpdateStatus = snap.Status
			info.Trigger = snap.Trigger
			info.Message = snap.Message
		}
		info.RuleCount = mgr.RuleCount()
		mgr.RefreshLatestAsync()
		if latest, known := mgr.LatestVersionCached(); known {
			if cmp, cmpErr := services.CompareCRSVersions(latest, info.Version); cmpErr == nil {
				info.IsLatest = cmp <= 0
			}
		}
	} else {
		if count, countErr := services.CountSecRulesLive(); countErr == nil {
			info.RuleCount = count
		}
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
	if err := services.SetCRSAutoUpdate(req.AutoUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	autoUpdateText := "关闭"
	if req.AutoUpdate {
		autoUpdateText = "开启"
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "CRS 规则库", fmt.Sprintf("自动更新已%s", autoUpdateText), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

func (h *Handlers) StartCRSUpdate(c *gin.Context) {
	mgr := services.GetCRSUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CRS 更新服务未初始化"})
		return
	}
	if err := mgr.StartUpdate("manual"); err != nil {
		if errors.Is(err, services.ErrCRSUpdateRunning) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "CRS 规则库", "手动更新 CRS 规则库", "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

func (h *Handlers) GetCRSUpdateStatus(c *gin.Context) {
	mgr := services.GetCRSUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CRS 更新服务未初始化"})
		return
	}
	snap := mgr.StatusSnapshot()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"status":      snap.Status,
		"trigger":     snap.Trigger,
		"started_at":  snap.StartedAt,
		"finished_at": snap.FinishedAt,
		"message":     snap.Message,
		"version":     snap.Version,
	}})
}

func (h *Handlers) GetCRSUpdateLogs(c *gin.Context) {
	logPath := services.CRSUpdateLogPath()
	content := readCertJobLogFile(logPath)
	if oldData := readCertJobLogFile(logPath + ".1"); oldData != "" {
		content = oldData + content
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

func (h *Handlers) GetIP2RegionInfo(c *gin.Context) {
	info := models.IP2RegionInfo{
		Version:      services.GetIP2RegionVersion(),
		DbSize:       services.GetIP2RegionEntryCount(),
		AutoUpdate:   false,
		UpdateStatus: "idle",
	}
	err := db.DB.QueryRow(`SELECT COALESCE(updated_at,''), COALESCE(update_status,'idle'), COALESCE(message,''), COALESCE(trigger,''), COALESCE(last_checked,''), COALESCE(next_update,''), auto_update
		FROM security_ip2region_version WHERE id=1`).
		Scan(&info.UpdatedAt, &info.UpdateStatus, &info.Message, &info.Trigger, &info.LastChecked, &info.NextUpdate, &info.AutoUpdate)
	if err == nil && info.Version == "" {
		info.Version = "unknown"
	}
	if mgr := services.GetIP2RegionUpdateManager(); mgr != nil {
		if snap := mgr.StatusSnapshot(); services.IsActiveIP2RegionStatus(snap.Status) {
			info.UpdateStatus = snap.Status
			info.Trigger = snap.Trigger
			info.Message = snap.Message
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func (h *Handlers) GetIP2RegionRegions(c *gin.Context) {
	regions := services.GetCachedProvinces()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: regions})
}

func (h *Handlers) UpdateIP2RegionAutoUpdate(c *gin.Context) {
	var req struct {
		AutoUpdate bool `json:"auto_update"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if err := services.SetIP2RegionAutoUpdate(req.AutoUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	autoUpdateText := "关闭"
	if req.AutoUpdate {
		autoUpdateText = "开启"
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "IP2Region 数据库", fmt.Sprintf("自动更新已%s", autoUpdateText), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

func (h *Handlers) StartIP2RegionUpdate(c *gin.Context) {
	mgr := services.GetIP2RegionUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "IP2Region 更新服务未初始化"})
		return
	}
	if err := mgr.StartUpdate("manual"); err != nil {
		if errors.Is(err, services.ErrIP2RegionUpdateRunning) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "IP2Region 数据库", "手动更新 IP2Region 数据库", "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

func (h *Handlers) GetIP2RegionUpdateStatus(c *gin.Context) {
	mgr := services.GetIP2RegionUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "IP2Region 更新服务未初始化"})
		return
	}
	snap := mgr.StatusSnapshot()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"status":      snap.Status,
		"trigger":     snap.Trigger,
		"started_at":  snap.StartedAt,
		"finished_at": snap.FinishedAt,
		"message":     snap.Message,
		"version":     snap.Version,
	}})
}

func (h *Handlers) GetIP2RegionUpdateLogs(c *gin.Context) {
	logPath := services.IP2RegionUpdateLogPath()
	content := readCertJobLogFile(logPath)
	if oldData := readCertJobLogFile(logPath + ".1"); oldData != "" {
		content = oldData + content
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

// GetSecurityPolicyForRule and BuildCorazaDirectives are in services/security.go
// to avoid circular dependency (services can't import handlers).

func (h *Handlers) GetAllSecurityBindings(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT b.rule_caddy_id, p.id, p.name, p.mode, p.enabled, p.rate_limit_enabled
		FROM security_policy_bindings b JOIN security_policies p ON b.policy_id = p.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	type BindingInfo struct {
		PolicyID  int    `json:"policy_id"`
		Name      string `json:"name"`
		Mode      string `json:"mode"`
		Enabled   bool   `json:"enabled"`
		RateLimit bool   `json:"rate_limit_enabled"`
	}
	result := map[string]BindingInfo{}
	for rows.Next() {
		var ruleCaddyID string
		var b BindingInfo
		rows.Scan(&ruleCaddyID, &b.PolicyID, &b.Name, &b.Mode, &b.Enabled, &b.RateLimit)
		result[ruleCaddyID] = b
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func scanSecurityPolicyRow(row *sql.Row, p *models.SecurityPolicy) error {
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &ipWhitelist, &ipBlacklist,
		&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse); err != nil {
		return err
	}
	p.IPWhitelist = json.RawMessage(ipWhitelist)
	p.IPBlacklist = json.RawMessage(ipBlacklist)
	p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
	p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
	p.CustomRules = json.RawMessage(customRules)
	p.GeoIPCountries = json.RawMessage(geoipCountries)
	return nil
}

func scanSecurityPolicy(rows *sql.Rows, p *models.SecurityPolicy) error {
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
	if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &ipWhitelist, &ipBlacklist,
		&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse); err != nil {
		return err
	}
	p.IPWhitelist = json.RawMessage(ipWhitelist)
	p.IPBlacklist = json.RawMessage(ipBlacklist)
	p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
	p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
	p.CustomRules = json.RawMessage(customRules)
	p.GeoIPCountries = json.RawMessage(geoipCountries)
	return nil
}

func max1(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}

func rawJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "[]"
	}
	return string(raw)
}

type securityPolicyDetail struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Mode             string `json:"mode"`
	AnomalyThreshold int    `json:"anomaly_threshold"`
	IPACLMode        string `json:"ip_acl_mode"`
	IPACLList        string `json:"ip_acl_list"`
	IPACLEnabled     bool   `json:"ip_acl_enabled"`
	IPWhitelist      string `json:"ip_whitelist"`
	IPBlacklist      string `json:"ip_blacklist"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPS     int    `json:"rate_limit_rps"`
	RateLimitBurst   int    `json:"rate_limit_burst"`
	CRSRuleGroups    string `json:"crs_rule_groups"`
	CRSExcludedRules string `json:"crs_excluded_rules"`
	CustomRules      string `json:"custom_rules"`
	BlockPageID      int    `json:"block_page_id"`
	BlockStatusCode  int    `json:"block_status_code"`
	Enabled          bool   `json:"enabled"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	GeoIPCountries   string `json:"geoip_countries"`
	GeoIPMode        string `json:"geoip_mode"`
	WAFCheckResponse bool   `json:"waf_check_response"`
}

func newSecurityPolicyDetail(p *models.SecurityPolicy) securityPolicyDetail {
	return securityPolicyDetail{
		ID:               p.ID,
		Name:             p.Name,
		Description:      p.Description,
		Mode:             p.Mode,
		AnomalyThreshold: p.AnomalyThreshold,
		IPACLMode:        p.IPACLMode,
		IPACLList:        p.IPACLList,
		IPACLEnabled:     p.IPACLEnabled,
		IPWhitelist:      rawJSONString(p.IPWhitelist),
		IPBlacklist:      rawJSONString(p.IPBlacklist),
		RateLimitEnabled: p.RateLimitEnabled,
		RateLimitRPS:     p.RateLimitRPS,
		RateLimitBurst:   p.RateLimitBurst,
		CRSRuleGroups:    rawJSONString(p.CRSRuleGroups),
		CRSExcludedRules: rawJSONString(p.CRSExcludedRules),
		CustomRules:      rawJSONString(p.CustomRules),
		BlockPageID:      p.BlockPageID,
		BlockStatusCode:  p.BlockStatusCode,
		Enabled:          p.Enabled,
		CreatedAt:        p.CreatedAt,
		UpdatedAt:        p.UpdatedAt,
		GeoIPCountries:   rawJSONString(p.GeoIPCountries),
		GeoIPMode:        p.GeoIPMode,
		WAFCheckResponse: p.WAFCheckResponse,
	}
}

func validateSecurityPolicyEnums(mode, ipACLMode, geoIPMode string, blockStatusCode, anomalyThreshold int) error {
	validBlockStatus := map[int]bool{400: true, 401: true, 403: true, 404: true, 429: true, 503: true}
	if blockStatusCode != 0 && !validBlockStatus[blockStatusCode] {
		return fmt.Errorf("拦截状态码必须为 400/401/403/404/429/503 之一，当前值 %d", blockStatusCode)
	}
	if anomalyThreshold != 0 {
		validThresholds := map[int]bool{1: true, 3: true, 5: true, 10: true, 20: true}
		if !validThresholds[anomalyThreshold] {
			return fmt.Errorf("异常阈值必须为 1/3/5/10/20 之一，当前值 %d", anomalyThreshold)
		}
	}
	switch mode {
	case "", "off", "detection", "blocking":
	default:
		return fmt.Errorf("mode 必须为 off、detection 或 blocking，当前值 %s", mode)
	}
	switch ipACLMode {
	case "", "allow", "deny", "bypass":
	default:
		return fmt.Errorf("ip_acl_mode 必须为 allow、deny 或 bypass，当前值 %s", ipACLMode)
	}
	switch geoIPMode {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("geoip_mode 必须为 allow 或 deny，当前值 %s", geoIPMode)
	}
	return nil
}

// validateGeoIPCountries ensures geoip_countries is a JSON array of non-empty province names / "海外".
func validateGeoIPCountries(raw string) error {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("geoip_countries 必须是 JSON 数组")
	}
	for _, entry := range entries {
		if strings.TrimSpace(entry) == "" {
			return fmt.Errorf("geoip_countries 不能包含空条目")
		}
	}
	return nil
}

func validateIPCIDRList(field, raw string) error {
	if raw == "" {
		return nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("%s 必须是 JSON 数组", field)
	}
	for _, entry := range entries {
		if _, err := netip.ParsePrefix(entry); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			return fmt.Errorf("%s 包含无效的 IP/CIDR 条目：%s", field, entry)
		}
	}
	return nil
}

func getContextUserIDInt(c *gin.Context) int {
	if uid, exists := c.Get("user_id"); exists {
		switch v := uid.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case int64:
			return int(v)
		}
	}
	return 0
}

func getContextUserID(c *gin.Context) string {
	if uid, exists := c.Get("user_id"); exists {
		switch v := uid.(type) {
		case float64:
			return fmt.Sprintf("%d", int(v))
		case int:
			return fmt.Sprintf("%d", v)
		case int64:
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
		Filename  string `json:"filename"`
		Category  string `json:"category"`
		Size      int64  `json:"size"`
		UpdatedAt string `json:"updated_at"`
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
			Filename:  entry.Name(),
			Category:  cat,
			Size:      info.Size(),
			UpdatedAt: info.ModTime().UTC().Format("2006-01-02 15:04:05"),
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
	f, err := os.Open(filepath)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则文件不存在"})
		return
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
