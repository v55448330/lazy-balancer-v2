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
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// crsRulesDir 是 CRS 规则文件目录；定义为变量以便测试注入临时目录。
var crsRulesDir = "/app/waf/crs/rules"

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
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &conditionsJSON, &r.Action, &r.Score, &r.Enabled, &r.CreatedAt, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		json.Unmarshal([]byte(conditionsJSON), &r.Conditions)
		rules = append(rules, r)
	}
	// 迭代失败显式报错（R40 F2）：对齐 ListSecurityPolicies/GetSecurityPolicy
	// 的既有标准，残缺列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rules == nil {
		rules = []models.SecurityCustomRule{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

func validateSecurityCustomRule(rule *models.SecurityCustomRule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	// 规则名进入 SecRule msg 引号串：控制字符会截断规则行，双引号会提前闭合动作，
	// 任一皆可致 coraza 拒绝整份配置。pattern 已有三重防护，name 对齐同口径。
	for _, r := range rule.Name {
		if r < 0x20 || r == 0x7f || r == '"' {
			return fmt.Errorf("规则名称不能包含控制字符或双引号")
		}
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
	// 引用检查与删除必须同事务：检查通过后、DELETE 之前并发的策略更新（启用引用
	// 策略）或新建引用策略会造成悬空引用，发射端仅日志跳过，WAF 规则静默丢失。
	// 写锁来自 DSN 的 _txlock=immediate（glebarez 驱动忽略 TxOptions.Isolation，
	// 非只读 BeginTx 一律 BEGIN IMMEDIATE）：引用检查的 SELECT 即持写锁，并发的
	// UpdateSecurityPolicy/CreateSecurityPolicy 无法在检查与 DELETE 之间提交（R37 I1）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	// 被启用策略引用的自定义规则不可删除：静默删除会产生悬空引用，发射阶段规则
	// 被跳过且无提示，必须先解除绑定。仅 ID 数组形态计入引用（内嵌对象随策略
	// 存储，删除单条规则不构成悬空）。
	if idInt, err := strconv.Atoi(id); err == nil && idInt > 0 {
		var referenced int
		rows, err := tx.QueryContext(c.Request.Context(), `SELECT custom_rules FROM security_policies WHERE enabled=1`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
				return
			}
			var ids []int
			if json.Unmarshal([]byte(raw), &ids) != nil {
				continue // 内嵌对象形状不构成 ID 引用
			}
			for _, rid := range ids {
				if rid == idInt {
					referenced++
					break
				}
			}
		}
		rows.Close()
		if rowsErr := rows.Err(); rowsErr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: rowsErr.Error()})
			return
		}
		if referenced > 0 {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该自定义规则正被 %d 个启用的安全策略使用，请先解除绑定", referenced)})
			return
		}
	}
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM security_custom_rules WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Content, &p.IsDefault, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		pages = append(pages, p)
	}
	// 迭代失败显式报错（R40 F2）：对齐 ListSecurityPolicies/GetSecurityPolicy
	// 的既有标准，残缺列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
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
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "拦截页面内容不能为空"})
		return
	}
	// API 不允许创建默认拦截页（R40 F3）：默认页仅 db 种子行，第二个
	// is_default=1 页面不可编辑（:243）不可删除（:283），且 branding 重渲染
	// 会覆盖全部默认页内容——产生不可管理的死行。
	if req.IsDefault {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "默认拦截页由系统管理，不允许创建"})
		return
	}
	result, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, is_default, created_by, updated_by) VALUES (?,?,?,?,?,?)`,
		req.Name, req.Description, req.Content, false, getContextUserIDInt(c), getContextUserIDInt(c))
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
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "拦截页面内容不能为空"})
		return
	}
	var isDefault bool
	// R41 B2: is_default 检查与 UPDATE 必须同事务（镜像 DeleteSecurityBlockPage
	// R37 I1）。非事务读 + 错误丢弃的旧实现存在并发窗口：导入路径可在 SELECT 与
	// UPDATE 之间把该页重建为默认页，使 UPDATE 绕过 403 契约改到默认页内容。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT is_default FROM security_block_pages WHERE id=?", id).Scan(&isDefault); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		}
		return
	}
	if isDefault {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "默认拦截页面不可编辑"})
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE security_block_pages SET name=?, description=?, content=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		req.Name, req.Description, req.Content, getContextUserIDInt(c), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "拦截页面", fmt.Sprintf("名称：%s（#%s）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面已更新" + h.caddyApplyNote()})
}

func (h *Handlers) DeleteSecurityBlockPage(c *gin.Context) {
	id := c.Param("id")
	// 默认页检查 + 引用检查与删除必须同事务：检查通过后、DELETE 之前并发的策略
	// 更新可把引用该页面的策略置 enabled=1，悬空引用会让拦截响应静默退化回
	// Caddy 默认页面。写锁来自 DSN 的 _txlock=immediate（非只读 BeginTx 一律
	// BEGIN IMMEDIATE）：首个 SELECT 即持写锁，并发的策略更新无法在检查与
	// DELETE 之间提交（R37 I1，同 DeleteSecurityCustomRule）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var isDefault bool
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT is_default FROM security_block_pages WHERE id=?", id).Scan(&isDefault); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		}
		return
	}
	if isDefault {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "默认拦截页面不可删除"})
		return
	}
	// 被启用策略引用的拦截页面不可删除：静默删除会让这些策略的拦截
	// 响应退化回 Caddy 默认页面，必须先解除绑定。
	var referenced int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_policies WHERE block_page_id=? AND enabled=1", id).Scan(&referenced); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if referenced > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该拦截页面正被 %d 个启用的安全策略使用，请先解除绑定", referenced)})
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), "DELETE FROM security_block_pages WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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
		if err := bindingRows.Scan(&pid, &cnt); err != nil {
			bindingRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		bindingCounts[pid] = cnt
	}
	bindingRows.Close()
	if err := bindingRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
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
			HasWAF: p.Mode != "off", HasIPControl: services.SecurityPolicyHasIPControl(&p), HasRateLimit: p.RateLimitEnabled && p.RateLimitRPS > 0,
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
	// 策略行迭代失败显式报错（R37 S1）：与 GetSecurityOverview 建立的「迭代失败
	// 显式 500」标准一致，部分列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
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
	rows, err := db.DB.Query("SELECT rule_caddy_id FROM security_policy_bindings WHERE policy_id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		bindings = append(bindings, b)
	}
	// 绑定迭代失败显式报错（R39 1.3）：对齐 ListSecurityPolicies/GetAllSecurityBindings
	// 的既有模式，残缺绑定列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if bindings == nil {
		bindings = []string{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"policy": newSecurityPolicyDetail(&p), "bindings": bindings}})
}

// policyQueryRower 抽象 *sql.DB 与 *sql.Tx 的单行查询，供引用校验在写事务内执行
// （R38 三-3：校验+写入同事务，镜像 R37 I1 的删除侧事务）。
type policyQueryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

// validateSecurityPolicyReferences 校验策略引用的拦截页面与自定义规则存在性：
// block_page_id 非 0 时必须在 security_block_pages 中存在，否则拦截响应静默退化
// 回 Caddy 默认页面；custom_rules 为 ID 数组时每个 ID 必须存在，悬空引用在发射
// 阶段被静默跳过。内嵌对象形状随策略存储，不在此校验。查询在调用方提供的
// 事务/连接上执行。返回非空 msg 表示校验失败（400），返回 err 表示数据库错误（500）。
func validateSecurityPolicyReferences(q policyQueryRower, blockPageID int, customRulesJSON string) (string, error) {
	if blockPageID != 0 {
		var exists int
		if err := q.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id=?", blockPageID).Scan(&exists); err != nil {
			return "", err
		}
		if exists == 0 {
			return fmt.Sprintf("拦截页面不存在（id=%d）", blockPageID), nil
		}
	}
	var ids []int
	if customRulesJSON != "" && json.Unmarshal([]byte(customRulesJSON), &ids) == nil {
		for _, id := range ids {
			var exists int
			if err := q.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE id=?", id).Scan(&exists); err != nil {
				return "", err
			}
			if exists == 0 {
				return fmt.Sprintf("自定义规则不存在（id=%d）", id), nil
			}
		}
	}
	return "", nil
}

func (h *Handlers) CreateSecurityPolicy(c *gin.Context) {
	var req models.CreateSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略名称不能为空"})
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
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"crs_rule_groups", &req.CRSRuleGroups},
		{"crs_excluded_rules", &req.CRSExcludedRules},
	} {
		if err := validateAndNormalizeCRSField(f.name, f.val); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
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
	// ip_acl_mode 与 geoip_mode 同口径归一（R50 B-#1）：启用态 ACL 携带空模式
	// 落库后，发射端仅 allow/deny 分支产出规则——零 ACL 生效而 UI 宣称已启用。
	if req.IPACLMode == "" {
		req.IPACLMode = "deny"
	}
	if err := services.ValidateGeoIPCountries(req.GeoIPCountries); err != nil {
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
	if err := validateRateLimitShape(req.Name, req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := services.ValidateCustomRulesJSON(req.CustomRules); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 引用校验与写入必须同事务（R38 三-3，R37 I1 的镜像方向）：校验通过后、
	// INSERT 之前并发的 DeleteSecurityCustomRule/DeleteSecurityBlockPage 提交（此时
	// 尚无启用策略引用，删除合法）会让写入的启用策略携带悬空引用，发射端仅日志
	// 跳过、WAF 规则静默丢失。写锁来自 DSN 的 _txlock=immediate（glebarez 驱动
	// 忽略 TxOptions.Isolation，非只读 BeginTx 一律 BEGIN IMMEDIATE）：校验 SELECT
	// 即持写锁，并发的删除无法在校验与 INSERT 之间提交。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	if msg, err := validateSecurityPolicyReferences(tx, req.BlockPageID, req.CustomRules); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	result, err := tx.ExecContext(c.Request.Context(), `INSERT INTO security_policies (name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, geoip_countries, geoip_mode, waf_check_response, updated_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		req.Name, req.Description, req.Mode, max1(req.AnomalyThreshold, 5), req.IPACLMode, req.IPACLList, req.IPACLEnabled, req.IPWhitelist, req.IPBlacklist,
		req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst, req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules, req.BlockPageID, req.BlockStatusCode, enabled, req.GeoIPCountries, req.GeoIPMode, req.WAFCheckResponse, getContextUserIDInt(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "创建", "安全策略", fmt.Sprintf("名称：%s（#%d）", req.Name, id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略创建成功" + h.caddyApplyNote(), Data: gin.H{"id": id}})
}

// validateAndNormalizeCRSField 统一 Create/Update 两条路径的 crs_* 形状校验：
// 空串按归一为 "[]"，非空必须是字符串数组 JSON（防发射端解析失败静默置空）。
// 条目内容同样受限：crs_rule_groups 组号恒为两位数字（进入 Include glob
// REQUEST-9<code>-*.conf），排除项进入 SecRuleRemoveById 参数，空白/引号/控制
// 字符都会生成非法配置行。
func validateAndNormalizeCRSField(name string, val *string) error {
	if val == nil {
		return nil
	}
	if strings.TrimSpace(*val) == "" {
		*val = "[]"
		return nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(*val), &entries); err != nil {
		return fmt.Errorf("%s 需为 JSON 数组字符串", name)
	}
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return fmt.Errorf("%s 条目不能为空", name)
		}
		for _, r := range trimmed {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
				continue
			}
			return fmt.Errorf("%s 条目含非法字符（仅允许字母、数字、.、_、-）: %q", name, entry)
		}
		// R46 B-F2：组号恒为两位数字（发射端拼接 REQUEST-9<code>-*.conf）。
		// "941"、"REQUEST-942" 这类写法会 glob 零匹配——coraza 对空 Include
		// 静默接受，blocking 模式将无任何 CRS 规则生效且无任何报错。
		if name == "crs_rule_groups" && (len(trimmed) != 2 || trimmed[0] < '0' || trimmed[0] > '9' || trimmed[1] < '0' || trimmed[1] > '9') {
			return fmt.Errorf("%s 条目必须是两位数字组号（如 942 组填 \"42\"）: %q", name, entry)
		}
		// R47 B-#1：首尾空白条目（" 42"/"\t42"）trim 后能通过以上检查，但发射端
		// 拼接 glob 用原始值会产生零匹配——校验与发射必须对同一形态达成一致。
		// 放在两位数字检查之后："942 " 这类条目仍报组号形态错误（R46 口径）。
		if trimmed != entry {
			return fmt.Errorf("%s 条目不能包含首尾空白: %q", name, entry)
		}
		// R59 B-N2：排除项是 coraza SecRuleRemoveById 的规则 ID（形如
		// "942100" 六位数字或含字母后缀的 "942100LEN"）。纯两位/三位短数字
		// （"94"/"933"）不是任何 CRS 规则 ID 形态——coraza v3.7.0 的
		// DeleteByID 对不存在的 ID 静默零删除，排除沦为无声 no-op。最小形态
		// 约束：crs_excluded_rules 条目至少 6 个字符。
		if name == "crs_excluded_rules" && len(trimmed) < 6 {
			return fmt.Errorf("%s 条目必须是 CRS 规则 ID（至少 6 位，如 \"942100\"）: %q", name, entry)
		}
	}
	return nil
}

func (h *Handlers) UpdateSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	var req models.UpdateSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略名称不能为空"})
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
	// 显式空串按 Create 口径归一为 "[]"，保持列形状一致，避免库内 "" 与 "[]"
	// 并存（Create 在 :411-419 归一，custom_rules 在下方同口径归一）。
	for _, val := range []**string{&req.IPACLList, &req.IPWhitelist, &req.IPBlacklist} {
		if *val != nil && strings.TrimSpace(**val) == "" {
			empty := "[]"
			*val = &empty
		}
	}
	// 显式空串会把枚举列清空：mode 为 "" 时汇总口径（mode!="off" 即计入 WAF）
	// 与发射口径（仅 blocking/detection 生效）随即漂移；geoip_mode 在创建时已
	// 归一为 allow/deny，空串属于域外值。不修改请直接省略字段，而不是传空串。
	// ip_acl_mode 同口径（R50 B-#1）：空串落库后发射端仅 allow/deny 分支产出
	// 规则、零 ACL 生效，而 SecurityPolicyHasIPControl 仍按 enabled+list 非空
	// 宣称 IP 访问控制已启用。
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"mode", req.Mode},
		{"geoip_mode", req.GeoIPMode},
		{"ip_acl_mode", req.IPACLMode},
	} {
		if f.val != nil && strings.TrimSpace(*f.val) == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("不修改请省略该字段，%s 不能为空串", f.name)})
			return
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
	// anomaly_threshold 显式 0 按创建侧口径归一为 5（R44 F3）：0 非合法枚举值，
	// 直接落库会让发射端 services/security.go:157 的 `AnomalyThreshold > 0` 判断
	// 跳过 SecAction id:900，CRS 回落到默认阈值 5，UI 显示 0 与实际行为不符。
	// 与 CreateSecurityPolicy 的 max1(req.AnomalyThreshold, 5) 同口径；nil 保持
	// 未提供语义，不参与写入。
	if req.AnomalyThreshold != nil && *req.AnomalyThreshold == 0 {
		*req.AnomalyThreshold = 5
	}
	blockStatusCode, anomalyThreshold := derefInt(req.BlockStatusCode), derefInt(req.AnomalyThreshold)
	if err := validateSecurityPolicyEnums(mode, ipACLMode, geoIPMode, blockStatusCode, anomalyThreshold); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validateRateLimitShape(fmt.Sprintf("id=%s", id), derefBool(req.RateLimitEnabled), derefInt(req.RateLimitRPS), derefInt(req.RateLimitBurst)); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if req.GeoIPCountries != nil {
		if err := services.ValidateGeoIPCountries(*req.GeoIPCountries); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if req.CustomRules != nil {
		if err := services.ValidateCustomRulesJSON(*req.CustomRules); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		// 显式空串按 Create 口径归一为 "[]"，保持列形状一致，避免库内出现 ""
		// 与 "[]" 并存（Create 在 :438-440 归一）。
		if strings.TrimSpace(*req.CustomRules) == "" {
			empty := "[]"
			req.CustomRules = &empty
		}
	}
	// 引用校验与写入必须同事务（R38 三-3，R37 I1 的镜像方向）：校验通过后、
	// UPDATE 之前并发的规则/拦截页删除提交会让写入的启用策略携带悬空引用，
	// 发射端仅日志跳过、WAF 规则静默丢失。写锁来自 DSN 的 _txlock=immediate
	// （非只读 BeginTx 一律 BEGIN IMMEDIATE）：校验 SELECT 即持写锁，并发的删除
	// 无法在校验与 UPDATE 之间提交（同 CreateSecurityPolicy）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	// 引用存在性校验：显式提供的 block_page_id / custom_rules（ID 数组）必须指向
	// 存在的拦截页/规则；未提供的字段不参与校验（保持存量列不变）。
	if msg, err := validateSecurityPolicyReferences(tx, derefInt(req.BlockPageID), derefStr(req.CustomRules)); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	// crs_rule_groups / crs_excluded_rules：显式空串按 Create 口径归一为 "[]"，
	// 非空值必须是字符串数组的 JSON，防止任意串直写列后在发射端解析失败。
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"crs_rule_groups", req.CRSRuleGroups},
		{"crs_excluded_rules", req.CRSExcludedRules},
	} {
		if err := validateAndNormalizeCRSField(f.name, f.val); err != nil {
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
	result, err := tx.ExecContext(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	services.RecordAuditLog(getContextUserID(c), "更新", "安全策略", fmt.Sprintf("策略 #%s", id), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略更新成功" + h.caddyApplyNote()})
}

func (h *Handlers) DeleteSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	// 绑定清理与策略删除必须同事务：绑定删除失败时回滚，避免留下
	// 指向已删策略的悬挂绑定（旧行为会静默忽略清理错误）。
	// 写锁来自 DSN 的 _txlock=immediate（glebarez 驱动对非只读 BeginTx 一律
	// BEGIN IMMEDIATE，忽略 TxOptions.Isolation）：COUNT/DELETE/清理之间不存在
	// 并发绑定插队的写窗口（R35 D1，R36 D1 澄清注释）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("DELETE FROM security_policies WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	if _, err := tx.Exec("DELETE FROM security_policy_bindings WHERE policy_id=?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理策略绑定失败: " + err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
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
	// 绑定/解绑必须同事务：存在性校验与写入同事务执行，避免检查与 INSERT 之间
	// 规则/策略被并发删除产生悬挂绑定（无 FK，经集群同步扩散，R34 D）；INSERT
	// 失败时旧绑定已被 DELETE 删除，需回滚恢复。
	// 写锁来自 DSN 的 _txlock=immediate（glebarez 驱动忽略 TxOptions.Isolation，
	// 非只读 BeginTx 一律 BEGIN IMMEDIATE）：COUNT 校验即持写锁，并发的策略删除
	// 无法在 COUNT 与 DELETE/INSERT 之间提交，闭合 R34 D 遗留的窄写窗口（R35 D1，
	// R36 D1 澄清注释）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer tx.Rollback()
	var policyExists int
	// 先判 err 再判 COUNT（R44 F2）：DB 瞬时故障（锁/IO）时 policyExists 未赋值，
	// 合并判断会把故障误报为「策略不存在」，前端无法区分重试与真 404——与
	// DeleteSecurityBlockPage 的 ErrNoRows 先判口径一致。
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_policies WHERE id=?", policyID).Scan(&policyExists); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if policyExists == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	// 绑定前校验规则真实存在：悬挂绑定虽在 JOIN 中不可见，但会经集群同步传播
	// 并污染 GetAllSecurityBindings 消费方（R33 F10）。与策略校验同口径先判
	// err 再判 COUNT（R45 F2-B）：DB 瞬时故障（锁/IO）时 ruleExists 未赋值，
	// 合并判断会把故障误报为「规则不存在」400，客户端无法区分重试与真 400。
	var ruleExists int
	var ruleProtocol string
	// R57 B-#3：取 protocol 同行校验——TCP 规则走 caddy-l4 构建链（buildTCPServer），
	// 该链从不消费安全策略，绑定成立即「UI 宣称受保护、实际零强制」的稳态漂移。
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*), COALESCE(MAX(protocol),'') FROM lb_rules WHERE caddy_id=?", req.RuleCaddyID).Scan(&ruleExists, &ruleProtocol); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if ruleExists == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "规则不存在"})
		return
	}
	if ruleProtocol != "http" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "安全策略仅支持绑定 HTTP 规则（TCP 规则不经过 WAF/IP 访问控制/限流链）"})
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(), "DELETE FROM security_policy_bindings WHERE rule_caddy_id=?", req.RuleCaddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", req.RuleCaddyID, policyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
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
	// clamp 上限防 (page-1)*pageSize 整数溢出为负 → SQLite OFFSET 报错 500（R33 F7）
	if page > 100000 {
		page = 100000
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
		// 前端输入为完整 IP：精确匹配，避免 LIKE 子串把 1.2.3.4 匹配到 11.2.3.40
		where += " AND client_ip = ?"
		args = append(args, ip)
	}
	if ruleID := c.Query("rule_caddy_id"); ruleID != "" {
		where += " AND rule_caddy_id=?"
		args = append(args, ruleID)
	}
	// 时间范围按配置时区解析（event_time 为 UTC），换算后比对；日期-only 补全天边界
	loc := services.CurrentLocation()
	parseBoundary := func(raw, endOfDay string) (string, bool, error) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return "", false, nil
		}
		if len(raw) == 10 {
			raw += " " + endOfDay
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", raw, loc)
		if err != nil {
			return "", false, errors.New("时间格式无效（需 YYYY-MM-DD[ HH:MM:SS]）")
		}
		return t.UTC().Format("2006-01-02 15:04:05"), true, nil
	}
	// 提供了时间参数却解析失败时直接拒绝：静默忽略会把拼写错误的区间
	// 当成「无边界」返回全量数据，误导排查方向。
	startBoundary, hasStart, err := parseBoundary(c.Query("start_time"), "00:00:00")
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	endBoundary, hasEnd, err := parseBoundary(c.Query("end_time"), "23:59:59")
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 同为合法时间且开始晚于结束时直接拒绝：语义错误的区间否则只会静默返回空页
	if hasStart && hasEnd && startBoundary > endBoundary {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "开始时间不能晚于结束时间"})
		return
	}
	// event_time 恒为 'YYYY-MM-DD HH:MM:SS' UTC 字符串，参数同形 —— 直接字符串比较
	// 即可走 idx_security_events_time 索引；两侧包 datetime() 会使索引失效（R28 修复）。
	if hasStart {
		where += " AND event_time >= ?"
		args = append(args, startBoundary)
	}
	if hasEnd {
		where += " AND event_time <= ?"
		args = append(args, endBoundary)
	}

	var total int
	if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events"+where, args...).Scan(&total); err != nil {
		log.Printf("security events: count query failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}

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
		// Scan 失败必须中止：否则部分零值的事件行会被当作真实事件返回（R35 D3）
		if err := rows.Scan(&e.ID, &e.EventTime, &e.RuleCaddyID, &e.PolicyID, &e.ClientIP, &e.Method, &e.URI, &e.EventType, &e.RuleTriggered, &e.RuleMsg, &e.Action, &e.AnomalyScore, &e.RuleName, &e.PolicyName); err != nil {
			log.Printf("security events: scan failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
			return
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("security events: rows iteration failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
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
	// 自定义规则触发 id 的两种形状：旧版内嵌规则 10000+id（5 位，10001-19999）
	// 与 R30 起无 id 规则的合成 id 1000000+n（7 位，1000000-1999999）。6 位
	// 1xxxxx 无归属源（CRS 保留段 100000-999999 的余数），保持"其他"。
	case strings.HasPrefix(ruleTriggered, "1") && (len(ruleTriggered) == 5 || len(ruleTriggered) >= 7):
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
	// 任一查询失败都必须在结束时显式报错：否则 metrics 库故障会静默返回
	// 全零面板，与「无攻击」不可区分（R35 D2）。
	var firstErr error
	trackErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	trackErr(db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='blocked' AND event_time >= ?", todayStartUTC).Scan(&overview.TodayBlocked))
	trackErr(db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='logged' AND event_time >= ?", todayStartUTC).Scan(&overview.TodayDetected))
	trackErr(db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE enabled=1 AND mode!='off'").Scan(&overview.ActivePolicies))

	// 7-day trend: always the full today-6 … today slice (local dates), zero-filled.
	// 时区偏移在 Go 侧拼好（负偏移如 America/New_York 为 "-240 minutes"）；SQLite 的
	// printf('+%d', -240) 会产出非法修饰符 "+-240" 使 date() 返回 NULL，导致趋势全零。
	tzModifier := fmt.Sprintf("%+d minutes", offsetMinutes)
	trendByDate := map[string]models.SecurityTrendPoint{}
	trendRows, err := db.MetricsDB.Query(`SELECT date(event_time, ?) as d, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b, SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY d`, tzModifier, todayStartUTC)
	trackErr(err)
	for trendRows != nil && trendRows.Next() {
		var t models.SecurityTrendPoint
		trackErr(trendRows.Scan(&t.Date, &t.Blocked, &t.Detected))
		trendByDate[t.Date] = t
	}
	if trendRows != nil {
		trackErr(trendRows.Err()) // 迭代中途失败同样显式报错，与 D3 标准一致（R36 F2）
		trendRows.Close()
	}
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
	ipRows, err := db.MetricsDB.Query(`SELECT client_ip, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b, SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l, MAX(event_time) as last_time FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY client_ip ORDER BY b + l DESC LIMIT 10`, todayStartUTC)
	trackErr(err)
	for ipRows != nil && ipRows.Next() {
		var row topIPRow
		trackErr(ipRows.Scan(&row.ip, &row.blocked, &row.detected, &row.lastTime))
		topRows = append(topRows, row)
	}
	if ipRows != nil {
		trackErr(ipRows.Err()) // 迭代中途失败同样显式报错，与 D3 标准一致（R36 F2）
		ipRows.Close()
	}
	familyCountsByIP := map[string]map[string]int{}
	famRows, err := db.MetricsDB.Query(`SELECT client_ip, COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY client_ip, rule_triggered, rule_msg ORDER BY cnt DESC LIMIT 5000`, todayStartUTC)
	trackErr(err)
	for famRows != nil && famRows.Next() {
		var ip, ruleTriggered, ruleMsg string
		var cnt int
		trackErr(famRows.Scan(&ip, &ruleTriggered, &ruleMsg, &cnt))
		counts := familyCountsByIP[ip]
		if counts == nil {
			counts = map[string]int{}
			familyCountsByIP[ip] = counts
		}
		counts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
	}
	if famRows != nil {
		trackErr(famRows.Err()) // 迭代中途失败同样显式报错，与 D3 标准一致（R36 F2）
		famRows.Close()
	}
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
	typeRows, err := db.MetricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY rule_triggered, rule_msg`, todayStartUTC)
	trackErr(err)
	familyCounts := map[string]int{}
	for typeRows != nil && typeRows.Next() {
		var ruleTriggered, ruleMsg string
		var cnt int
		trackErr(typeRows.Scan(&ruleTriggered, &ruleMsg, &cnt))
		familyCounts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
	}
	if typeRows != nil {
		trackErr(typeRows.Err()) // 迭代中途失败同样显式报错，与 D3 标准一致（R36 F2）
		typeRows.Close()
	}
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
	if firstErr != nil {
		log.Printf("security overview: query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全总览查询失败"})
		return
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
	// R57 B-#4：与 StartCRSUpdate 同口径主节点门（R46 B-F3）——从节点版本行
	// 在同步段内，本地写会被下次快照覆盖。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
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
	services.RecordAuditLog(getContextUserID(c), "更新", "CRS规则库", fmt.Sprintf("自动更新已%s", autoUpdateText), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

func (h *Handlers) StartCRSUpdate(c *gin.Context) {
	// R46 B-F3：手动更新仅限主节点（镜像 R41 A 域手动同步门控的直查口径，
	// 门控查询失败按非主节点拒绝）。从节点本地更新会造成磁盘/DB 分叉：主节点
	// 下次集群同步把 version 行覆盖回主节点口径，而从节点的启动对账是
	// master-only，分叉长期残留。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
		return
	}
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
	services.RecordAuditLog(getContextUserID(c), "更新", "CRS规则库", "手动更新 CRS规则库", "")
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
	// 与校验端（ValidateGeoIPCountries）同源：live searcher 优先、缓存兜底，
	// 避免带外替换 xdb 后两端分叉。
	regions := services.GetIP2RegionProvinceList()
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
	// R57 B-#4：与 StartIP2RegionUpdate 同口径主节点门。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
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
	services.RecordAuditLog(getContextUserID(c), "更新", "IP数据库", fmt.Sprintf("自动更新已%s", autoUpdateText), "")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

func (h *Handlers) StartIP2RegionUpdate(c *gin.Context) {
	// R46 B-F3：同 StartCRSUpdate——手动更新仅限主节点，从节点直接 403。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
		return
	}
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
	services.RecordAuditLog(getContextUserID(c), "更新", "IP数据库", "手动更新 IP数据库", "")
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
		if err := rows.Scan(&ruleCaddyID, &b.PolicyID, &b.Name, &b.Mode, &b.Enabled, &b.RateLimit); err != nil {
			// 单行扫描失败跳过：不写入零值绑定（policy_id=0/mode="" 会把该规则
			// 错误呈现为「已绑定到空策略」）；迭代错误由下方 rows.Err() 兜底（R37 S2）。
			continue
		}
		result[ruleCaddyID] = b
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
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

// validateRateLimitShape 限流字段与发射端同口径（R57 B-#2）：enabled=true 而
// rps<=0 时 caddy.go 发射分支直接跳过限流 handler，但汇总/绑定仍宣称已启用
// ——与 R50 ip_acl_mode / R52 三枚举的「UI 宣称启用、实际零强制」同型漂移，
// 在写入侧拒绝。
func validateRateLimitShape(name string, enabled bool, rps, burst int) error {
	if !enabled {
		return nil
	}
	if rps < 1 {
		return fmt.Errorf("策略 %q：启用限流时 rate_limit_rps 必须 ≥1（当前 %d）", name, rps)
	}
	if burst < 0 {
		return fmt.Errorf("策略 %q：启用限流时 rate_limit_burst 不能为负（当前 %d）", name, burst)
	}
	return nil
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
	entries, err := os.ReadDir(crsRulesDir)
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
	// clamp 上限防 (page-1)*pageSize 整数溢出为负 → 切片越界 panic（R33 F7）
	if page > 100000 {
		page = 100000
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
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
	// R62 B-NEW-3：对齐同域读端点的尺寸口径（GetCRSRuleContent 1MB、更新日志 128KB）。
	// crs-setup.conf 是运维可手改文件，超限时显式 413 拒绝而非静默截断——
	// 避免调用方把截断内容当作完整配置使用。
	f, err := os.Open("/app/waf/crs/crs-setup.conf")
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CRS 配置文件不存在"})
		return
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if len(content) > 1<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "CRS 配置文件超过 1MB 读取上限"})
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

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
