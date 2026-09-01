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
	rows, err := db.DB.Query("SELECT id, name, COALESCE(description,''), COALESCE(conditions,'[]'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1), COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(updated_by,0) FROM security_custom_rules ORDER BY id")
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
		// R63 B-N2：解析失败与下方 rows.Err 同口径显式 500（R40 F2「残缺列表不得
		// 以 200 返回」）——零值形态混入 200 会让该行在 UI 呈现「无条件规则」且
		// 不可编辑保存，发射端又整条跳过，等于一条规则被静默停用。
		if err := json.Unmarshal([]byte(conditionsJSON), &r.Conditions); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("自定义规则 %d 的条件解析失败: %v", r.ID, err)})
			return
		}
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
	recordAudit(c, "创建", "自定义规则", fmt.Sprintf("名称：%s（#%d）", req.Name, id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则创建成功" + h.caddyApplyNote(c), Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateSecurityCustomRule(c *gin.Context) {
	id := c.Param("id")
	var req models.UpdateCustomRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	// R66 B-N1：省略即保持现值（与 UpdateSecurityPolicy 同口径）——enabled 是本
	// 端点唯一「零值语义恰为禁用」的字段，MCP 无约束 body 的部分更新此前会把
	// 零值 false 直写落库，WAF 静默少一条拦截规则且审计无痕迹。先读现值合并为
	// 有效形态再过统一校验（校验规则不变，只是输入从「绑定零值」改为「现值」）。
	// R69 B69-N2：读-合并-写包进事务（DSN _txlock=immediate 使首个读即持写锁，
	// 与 UpdateSecurityPolicy 同机制）——此前裸连接读后合并再全列写，两个并发
	// 部分更新会互相静默覆盖（丢 enabled 翻转 = WAF 规则静默启/禁用）。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启事务失败"})
		return
	}
	defer tx.Rollback()
	var existing models.SecurityCustomRule
	var existingConditionsJSON string
	if err := tx.QueryRowContext(c.Request.Context(),
		`SELECT name, COALESCE(description,''), COALESCE(conditions,'[]'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1) FROM security_custom_rules WHERE id=?`, id,
	).Scan(&existing.Name, &existing.Description, &existingConditionsJSON, &existing.Action, &existing.Score, &existing.Enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败: " + err.Error()})
		return
	}
	// R69 B69-N1：存量条件「非空但解析失败」与「用户漏传条件」是不同故障——
	// 吞错会使损坏行走到「至少需要一个匹配条件」400，被误归因为用户输入
	//（与 R68 B-F5 / R63 B-N2 的 storage_corrupted 口径对齐）。
	if existingConditionsJSON != "" {
		if uerr := json.Unmarshal([]byte(existingConditionsJSON), &existing.Conditions); uerr != nil {
			recordAudit(c, "更新失败", "自定义规则", services.FormatAuditDetail(fmt.Sprintf("规则 #%s", id), services.AuditResultPart("storage_corrupted")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的自定义规则条件已损坏，请删除后重建"})
			return
		}
	}
	merged := models.SecurityCustomRule{
		Name:        existing.Name,
		Description: existing.Description,
		Conditions:  existing.Conditions,
		Action:      existing.Action,
		Score:       existing.Score,
		Enabled:     existing.Enabled,
	}
	if req.Name != nil {
		merged.Name = *req.Name
	}
	if req.Description != nil {
		merged.Description = *req.Description
	}
	if req.Conditions != nil {
		merged.Conditions = *req.Conditions
	}
	if req.Action != nil {
		merged.Action = *req.Action
	}
	if req.Score != nil {
		merged.Score = *req.Score
	}
	if req.Enabled != nil {
		merged.Enabled = *req.Enabled
	}
	if err := validateSecurityCustomRule(&merged); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	conditionsJSON, _ := json.Marshal(merged.Conditions)
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE security_custom_rules SET name=?, description=?, conditions=?, action=?, score=?, enabled=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		merged.Name, merged.Description, string(conditionsJSON), merged.Action, merged.Score, merged.Enabled, getContextUserIDInt(c), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return
	}
	recordAudit(c, "更新", "自定义规则", fmt.Sprintf("名称：%s（#%s）", merged.Name, id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新" + h.caddyApplyNote(c)})
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
		rows, err := tx.QueryContext(c.Request.Context(), `SELECT COALESCE(custom_rules,'[]') FROM security_policies WHERE enabled=1`)
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
	recordAudit(c, "删除", "自定义规则", fmt.Sprintf("规则 #%s", id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已删除" + h.caddyApplyNote(c)})
}

func (h *Handlers) ListSecurityBlockPages(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, COALESCE(description,''), COALESCE(content,''), COALESCE(is_default,0), COALESCE(created_by,0), COALESCE(created_at,''), COALESCE(updated_by,0), COALESCE(updated_at,'') FROM security_block_pages ORDER BY is_default DESC, id")
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
	recordAudit(c, "创建", "拦截页面", fmt.Sprintf("名称：%s（#%d）", req.Name, id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面创建成功" + h.caddyApplyNote(c), Data: gin.H{"id": id}})
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
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(is_default,0) FROM security_block_pages WHERE id=?", id).Scan(&isDefault); err != nil {
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
	recordAudit(c, "更新", "拦截页面", fmt.Sprintf("名称：%s（#%s）", req.Name, id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面已更新" + h.caddyApplyNote(c)})
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
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COALESCE(is_default,0) FROM security_block_pages WHERE id=?", id).Scan(&isDefault); err != nil {
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
	recordAudit(c, "删除", "拦截页面", fmt.Sprintf("页面 #%s", id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "拦截页面已删除" + h.caddyApplyNote(c)})
}

// securityPolicySelectColumns 是 ListSecurityPolicies/GetSecurityPolicy 共用的
// 27 表达式投影：与生成路径的 26 表达式 COALESCE 投影逐列同默认值、同相对顺序
// （canonical 副本：internal/services/security.go scanSecurityPolicyByID、
// internal/services/caddy.go loadSecurityPolicyContext 批量预载）。services/ 归
// 并行任务持有且两侧列集本就不同，此处按既定回退方案保持 handlers 本地副本——
// 改任一侧默认值时必须同步另一侧，勿单方面漂移。两点刻意差异：
//  1. 多 COALESCE(updated_by,0)（第 20 位）：PolicySummary/详情响应需要该列，
//     生成投影不含；
//  2. enabled 用 COALESCE(enabled,1)（schema 默认 TRUE）：List/Get 无 enabled
//     WHERE 过滤，NULL-enabled 行须按 schema 默认呈现启用态；生成路径以
//     WHERE enabled=1 守卫，NULL 行本就被过滤，故裸列即可。
const securityPolicySelectColumns = `id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,5), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_whitelist,'[]'), COALESCE(ip_blacklist,'[]'),
	COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0), COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'), COALESCE(block_page_id,0), COALESCE(block_status_code,0), COALESCE(enabled,1), COALESCE(updated_by,0), COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(waf_check_response,0), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]')`

func (h *Handlers) ListSecurityPolicies(c *gin.Context) {
	query := `SELECT ` + securityPolicySelectColumns + ` FROM security_policies`
	conditions := []string{}
	args := []any{}
	if enabled := c.Query("enabled"); enabled == "true" || enabled == "1" {
		conditions = append(conditions, "enabled=1")
	}
	// 按关联规则过滤（IP 归属地弹窗使用：只列出绑定到该规则的策略）
	if ruleCaddyID := c.Query("rule_caddy_id"); ruleCaddyID != "" {
		conditions = append(conditions, `id IN (SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=?)`)
		args = append(args, ruleCaddyID)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id"
	rows, err := db.DB.Query(query, args...)
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
		// R72 三十次追加 a：GeoIP/自定义规则的 has 计算（供 ruleProtections 显示行）。
		hasGeoIP := services.PolicyHasGeoIP(&p)
		policies = append(policies, models.SecurityPolicySummary{
			ID: p.ID, Name: p.Name, Mode: p.Mode, Enabled: p.Enabled, RuleCount: ruleCount,
			HasWAF: p.Mode != "off", HasIPControl: services.SecurityPolicyHasIPControl(&p), HasRateLimit: p.RateLimitEnabled && p.RateLimitRPS > 0,
			HasGeoIP: hasGeoIP, HasCustomRules: services.CountEnabledCustomRules(p.CustomRules) > 0,
			AnomalyThreshold:   p.AnomalyThreshold,
			IPACLMode:          p.IPACLMode,
			IPACLEnabled:       p.IPACLEnabled,
			IPWhitelistEnabled: p.IPWhitelistEnabled,
			IPACLList:          p.IPACLList,
			IPWhitelist:        rawJSONString(p.IPWhitelist),
			IPBlacklist:        rawJSONString(p.IPBlacklist),
			RateLimitRPS:       p.RateLimitRPS,
			RateLimitBurst:     p.RateLimitBurst,
			CRSExcludedCount:   len(crsExcluded),
			CRSRuleGroups:      p.CRSRuleGroups,
			CustomRulesCount:   services.CountEnabledCustomRules(p.CustomRules),
			UpdatedBy:          p.UpdatedBy,
			UpdatedAt:          p.UpdatedAt,
			GeoIPCountries:     rawJSONString(p.GeoIPCountries),
			GeoIPMode:          p.GeoIPMode,
			WAFCheckResponse:   p.WAFCheckResponse,
			IPACLListRefs:      p.IPACLListRefs,
			IPWhitelistRefs:    p.IPWhitelistRefs,
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
	err := scanSecurityPolicyRow(db.DB.QueryRow(`SELECT `+securityPolicySelectColumns+` FROM security_policies WHERE id=?`, id), &p)
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

// policyQueryRower 抽象 *sql.DB 与 *sql.Tx 的查询能力，供引用校验在写事务内执行
// （R38 三-3：校验+写入同事务，镜像 R37 I1 的删除侧事务）。Query 供
// IP 列表引用的批量 IN 存在性检查（单次查询判定整批 id）。
type policyQueryRower interface {
	Query(query string, args ...any) (*sql.Rows, error)
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

// policyWhitelistDefault：Create 缺省（含旧客户端不传）视为启用——保持存量
// 「名单非空即生效」语义不回退。
func policyWhitelistDefault(v *bool) bool {
	return v == nil || *v
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
	if req.IPACLListRefs == "" {
		req.IPACLListRefs = "[]"
	}
	if req.IPWhitelistRefs == "" {
		req.IPWhitelistRefs = "[]"
	}
	if req.GeoIPMode == "" {
		req.GeoIPMode = "deny"
	}
	// ip_acl_mode 与 geoip_mode 同口径归一（R50 B-#1）：启用态 ACL 携带空模式
	// 落库后，发射端仅 allow/deny 分支产出规则——零 ACL 生效而 UI 宣称已启用。
	if req.IPACLMode == "" {
		req.IPACLMode = "deny"
	}
	if err := services.ValidateGeoIPCountries(req.GeoIPCountries, req.GeoIPMode); err != nil {
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
	aclRefsIDs, err := parseIPListRefsPayload("ip_acl_list_refs", &req.IPACLListRefs)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	wlRefsIDs, err := parseIPListRefsPayload("ip_whitelist_refs", &req.IPWhitelistRefs)
	if err != nil {
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
	if msg, err := validateIPListRefsExistence(tx, aclRefsIDs, wlRefsIDs); err != nil {
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
	result, err := tx.ExecContext(c.Request.Context(), `INSERT INTO security_policies (name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_whitelist_enabled, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, geoip_countries, geoip_mode, waf_check_response, ip_acl_list_refs, ip_whitelist_refs, updated_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		req.Name, req.Description, req.Mode, max1(req.AnomalyThreshold, 5), req.IPACLMode, req.IPACLList, req.IPACLEnabled, req.IPWhitelist, policyWhitelistDefault(req.IPWhitelistEnabled), req.IPBlacklist,
		req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst, req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules, req.BlockPageID, req.BlockStatusCode, enabled, req.GeoIPCountries, req.GeoIPMode, req.WAFCheckResponse, req.IPACLListRefs, req.IPWhitelistRefs, getContextUserIDInt(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	id, _ := result.LastInsertId()
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "创建", "安全策略", fmt.Sprintf("名称：%s（#%d）", req.Name, id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略创建成功" + h.caddyApplyNote(c), Data: gin.H{"id": id}})
}

// validateAndNormalizeCRSField 统一 Create/Update 两条路径的 crs_* 形状校验：
// 空串按归一为 "[]"，非空必须是字符串数组 JSON（防发射端解析失败静默置空）。
// 条目内容同样受限：crs_rule_groups 组号恒为两位数字（进入 Include glob
// REQUEST-9<code>-*.conf），排除项进入 SecRuleRemoveById 参数，空白/引号/控制
// 字符都会生成非法配置行。
// geoipEntriesEqual（R72 二十九次 M1）：比较两个 geoip_countries JSON 数组的
// 集合相等性（顺序无关）——任一侧解析失败返回 false（保守走校验路径）。
func geoipEntriesEqual(a, b string) bool {
	parse := func(raw string) ([]string, bool) {
		var entries []string
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			return nil, false
		}
		sort.Strings(entries)
		return entries, true
	}
	ea, okA := parse(a)
	eb, okB := parse(b)
	if !okA || !okB {
		return false
	}
	if len(ea) != len(eb) {
		return false
	}
	for i := range ea {
		if ea[i] != eb[i] {
			return false
		}
	}
	return true
}

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
		// R59 B-N2 → R72 二十六次 W3-6 收紧：排除项必须是发射端实际会发射的
		// 形态（services.CRSExcludedEntryEffective——CRS 规则 ID「纯数字/
		// 数字-数字，900000-999999」或 CRS 文件名「REQUEST-9XX-*.conf」，文件
		// 名经 crsFilenameToRuleIDRange 映射为 ID 区间）。此前保存侧只查字符集
		// +长度，"942100L" 这类条目保存 200、发射时被形态门静默跳过（仅 warn
		// 日志）——用户以为排除生效实则没有。保存即拒绝，与发射同款门永不漂移。
		if name == "crs_excluded_rules" && !services.CRSExcludedEntryEffective(entry) {
			return fmt.Errorf("%s 条目必须是 CRS 规则 ID（如 \"942100\"）或规则文件名（如 \"REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"）: %q", name, entry)
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
	for _, val := range []**string{&req.IPACLList, &req.IPWhitelist, &req.IPBlacklist, &req.IPACLListRefs, &req.IPWhitelistRefs} {
		if *val != nil && strings.TrimSpace(**val) == "" {
			empty := "[]"
			*val = &empty
		}
	}
	var aclRefsIDs, wlRefsIDs []int64
	for _, f := range []struct {
		name string
		val  *string
		ids  *[]int64
	}{
		{"ip_acl_list_refs", req.IPACLListRefs, &aclRefsIDs},
		{"ip_whitelist_refs", req.IPWhitelistRefs, &wlRefsIDs},
	} {
		if f.val == nil {
			continue
		}
		ids, err := parseIPListRefsPayload(f.name, f.val)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		*f.ids = ids
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
		// R72 二十九次 M1：地域条目与存量完全相同的更新跳过 live 校验——N5 裁决
		// 语义是「缺库时不得启用」而非「缺库时不得编辑未变更字段」；条目真正变化
		// 时才落 fail-closed 门（缺库时改描述/开关不再 400）。
		// 校验口径取生效 mode：请求携带 geoip_mode 用请求值，否则用存量值——
		// off 态保留名单只做形状校验，不被可用性门卡死。
		skipGeoIPValidation := false
		var storedGeoIP, storedGeoIPMode string
		if err := db.DB.QueryRow("SELECT geoip_countries, geoip_mode FROM security_policies WHERE id=?", id).Scan(&storedGeoIP, &storedGeoIPMode); err == nil {
			skipGeoIPValidation = geoipEntriesEqual(*req.GeoIPCountries, storedGeoIP)
		}
		effectiveGeoIPMode := storedGeoIPMode
		if req.GeoIPMode != nil && *req.GeoIPMode != "" {
			effectiveGeoIPMode = *req.GeoIPMode
		}
		if !skipGeoIPValidation {
			if err := services.ValidateGeoIPCountries(*req.GeoIPCountries, effectiveGeoIPMode); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
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
	// 引用的 IP 地址列表同口径存在性校验（悬空 id → 400，仅校验显式提供的字段）。
	if msg, err := validateIPListRefsExistence(tx, aclRefsIDs, wlRefsIDs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	// R63 B-N1：重启用悬空引用门——仅含 {enabled:true} 的部分更新（REST 文档明示
	// 「只提交需要修改的字段」）不携带 block_page_id/custom_rules，derefInt/derefStr
	// 零值使上面的校验整体短路；禁用期间被删除的规则/拦截页（删除门只拦 enabled=1
	// 的策略）会随重启用静默激活：发射端仅 warn 跳过、WAF 规则静默丢失、拦截页
	// 退回 Caddy 默认错误页。指向启用的更新按「显式值 ?? 存量值」的有效形态过
	// 同一校验器；写锁已持（BEGIN IMMEDIATE），无 TOCTOU。
	if req.Enabled != nil && *req.Enabled {
		var storedBlockPageID int
		var storedCustomRules, storedACLRefs, storedWLRefs string
		if err := tx.QueryRow("SELECT COALESCE(block_page_id,0), COALESCE(custom_rules,'[]'), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]') FROM security_policies WHERE id=?", id).Scan(&storedBlockPageID, &storedCustomRules, &storedACLRefs, &storedWLRefs); err != nil {
			// R64 B-S1：策略不存在时归因 404（与下方 RowsAffected 分支同语义），
			// 其余读取错误保持 500——否则调用方无法区分「应停止重试」与「应重试」。
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
				return
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取策略当前引用失败: " + err.Error()})
			return
		}
		effectiveBlockPageID := derefInt(req.BlockPageID)
		if req.BlockPageID == nil {
			effectiveBlockPageID = storedBlockPageID
		}
		effectiveCustomRules := derefStr(req.CustomRules)
		if req.CustomRules == nil {
			effectiveCustomRules = storedCustomRules
		}
		if msg, err := validateSecurityPolicyReferences(tx, effectiveBlockPageID, effectiveCustomRules); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
		// IP 列表引用同口径：显式值 ?? 存量值的有效形态过同一校验器（禁用期间
		// 被删除的列表不得随重启用静默悬空）。
		effectiveACLRefs, effectiveWLRefs := aclRefsIDs, wlRefsIDs
		if req.IPACLListRefs == nil {
			effectiveACLRefs = parseIPListRefsIDs(storedACLRefs)
		}
		if req.IPWhitelistRefs == nil {
			effectiveWLRefs = parseIPListRefsIDs(storedWLRefs)
		}
		if msg, err := validateIPListRefsExistence(tx, effectiveACLRefs, effectiveWLRefs); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
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
	addBool("ip_whitelist_enabled", req.IPWhitelistEnabled)
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
	addStr("ip_acl_list_refs", req.IPACLListRefs)
	addStr("ip_whitelist_refs", req.IPWhitelistRefs)

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
	// 审计用 username（非数字 ID）+ 字段级变更详情——IP 弹窗一键操作和
	// 策略编辑页共用此端点，操作人/具体改了什么/IP 是什么必须在日志可追溯。
	var policyName string
	_ = db.DB.QueryRow("SELECT name FROM security_policies WHERE id=?", id).Scan(&policyName)
	auditDetail := fmt.Sprintf("策略「%s」(#%s)", policyName, id)
	var changedFields []string
	if req.IPACLList != nil {
		changedFields = append(changedFields, fmt.Sprintf("IP ACL 列表→%s", *req.IPACLList))
	}
	if req.IPACLMode != nil {
		changedFields = append(changedFields, fmt.Sprintf("ACL 模式→%s", *req.IPACLMode))
	}
	if req.IPACLEnabled != nil {
		changedFields = append(changedFields, fmt.Sprintf("ACL 启用→%v", *req.IPACLEnabled))
	}
	if req.IPWhitelist != nil {
		changedFields = append(changedFields, fmt.Sprintf("信任名单→%s", *req.IPWhitelist))
	}
	if req.IPBlacklist != nil {
		changedFields = append(changedFields, fmt.Sprintf("旧版黑名单→%s", *req.IPBlacklist))
	}
	if req.IPACLListRefs != nil {
		changedFields = append(changedFields, fmt.Sprintf("ACL 列表引用→%s", *req.IPACLListRefs))
	}
	if req.IPWhitelistRefs != nil {
		changedFields = append(changedFields, fmt.Sprintf("信任名单列表引用→%s", *req.IPWhitelistRefs))
	}
	if req.Name != nil {
		changedFields = append(changedFields, fmt.Sprintf("名称→%s", *req.Name))
	}
	if req.Mode != nil {
		changedFields = append(changedFields, fmt.Sprintf("WAF 模式→%s", *req.Mode))
	}
	if req.Enabled != nil {
		changedFields = append(changedFields, fmt.Sprintf("启用→%v", *req.Enabled))
	}
	if req.BlockPageID != nil {
		changedFields = append(changedFields, fmt.Sprintf("拦截页→#%d", *req.BlockPageID))
	}
	if req.Description != nil {
		changedFields = append(changedFields, fmt.Sprintf("描述→%s", *req.Description))
	}
	if req.AnomalyThreshold != nil {
		changedFields = append(changedFields, fmt.Sprintf("异常分阈值→%d", *req.AnomalyThreshold))
	}
	if req.BlockStatusCode != nil {
		changedFields = append(changedFields, fmt.Sprintf("拦截状态码→%d", *req.BlockStatusCode))
	}
	if req.GeoIPCountries != nil {
		changedFields = append(changedFields, fmt.Sprintf("GeoIP 名单→%s", *req.GeoIPCountries))
	}
	if req.GeoIPMode != nil {
		changedFields = append(changedFields, fmt.Sprintf("GeoIP 模式→%s", *req.GeoIPMode))
	}
	if req.RateLimitEnabled != nil {
		changedFields = append(changedFields, fmt.Sprintf("限流启用→%v", *req.RateLimitEnabled))
	}
	if req.RateLimitRPS != nil {
		changedFields = append(changedFields, fmt.Sprintf("限流 RPS→%d", *req.RateLimitRPS))
	}
	if req.RateLimitBurst != nil {
		changedFields = append(changedFields, fmt.Sprintf("限流突发→%d", *req.RateLimitBurst))
	}
	if req.CRSRuleGroups != nil {
		changedFields = append(changedFields, fmt.Sprintf("CRS 规则组→%s", *req.CRSRuleGroups))
	}
	if req.CRSExcludedRules != nil {
		changedFields = append(changedFields, fmt.Sprintf("CRS 排除→%s", *req.CRSExcludedRules))
	}
	if req.CustomRules != nil {
		changedFields = append(changedFields, fmt.Sprintf("自定义规则→%s", *req.CustomRules))
	}
	if req.WAFCheckResponse != nil {
		changedFields = append(changedFields, fmt.Sprintf("响应体检测→%v", *req.WAFCheckResponse))
	}
	if len(changedFields) > 0 {
		auditDetail += "；" + strings.Join(changedFields, "；")
	}
	recordAudit(c, "更新", "安全策略", auditDetail)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略更新成功" + h.caddyApplyNote(c)})
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
	recordAudit(c, "删除", "安全策略", fmt.Sprintf("策略 #%s", id))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全策略已删除" + h.caddyApplyNote(c)})
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
	// 上限守卫（B-I1）：POST additive 与 PUT 同上限——一规则最多绑定 5 条策略。
	// 重绑已存在的 (rule,policy) 对保持幂等 200（INSERT OR IGNORE 不产生新行），
	// 仅当该对尚未绑定且兄弟绑定已达 5 条时拒绝；COUNT 与 INSERT 同事务（写锁
	// 由 _txlock=immediate 在 BEGIN 处获取），并发绑定无法在校验与写入间插队。
	var alreadyBound int
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", req.RuleCaddyID, policyID).Scan(&alreadyBound); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if alreadyBound == 0 {
		var siblingCount int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?", req.RuleCaddyID).Scan(&siblingCount); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		if siblingCount >= 5 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "最多绑定 5 条策略"})
			return
		}
	}
	// v2.2.0 多策略绑定（T2）：POST bind 改为 additive——仅 INSERT OR IGNORE，不再
	// 清空 rule 的兄弟绑定；全量替换走 PUT /security/rules/:caddy_id/policies。
	// INSERT OR IGNORE 保留幂等（重复绑定同一 (rule,policy) 不报错、不重复行）。
	if _, err := tx.ExecContext(c.Request.Context(), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", req.RuleCaddyID, policyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "更新", "安全策略", fmt.Sprintf("绑定规则 %s 到策略 #%s", req.RuleCaddyID, policyID))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已关联" + h.caddyApplyNote(c)})
}

// SetRuleSecurityPolicies（v2.2.0 T2）：PUT /security/rules/:caddy_id/policies
// 原子替换一规则的全部策略绑定（单事务 DELETE + 按 policy_ids 顺序 INSERT）。
// 服务器强制上限 5 条；规则必须存在且为 HTTP；所有 policy_id 必须存在。
// 空数组（或缺省 policy_ids 字段）= 解除该规则全部绑定，与 apidocs/MCP 契约一致。
func (h *Handlers) SetRuleSecurityPolicies(c *gin.Context) {
	ruleCaddyID := c.Param("caddy_id")
	var req struct {
		PolicyIDs []int `json:"policy_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	// 上限判定须先去重（B-I2）：[1,1,2,3,4,5] 为 5 条唯一策略，不得因原始数组
	// 长度 6 误判超限。去重同时避免同一 id 重复计数导致存在性校验误判
	// （INSERT OR IGNORE 本来就会去重，但 COUNT 必须与去重后的集合对齐）。
	seen := map[int]struct{}{}
	uniqueIDs := make([]int, 0, len(req.PolicyIDs))
	for _, id := range req.PolicyIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}
	if len(uniqueIDs) > 5 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "最多绑定 5 条策略"})
		return
	}
	// 与 BindRuleToPolicy 同事务口径：存在性校验 + DELETE + 有序 INSERT 同事务，
	// 写锁由 _txlock=immediate 在 BEGIN 处获取，避免校验与写入之间规则/策略被
	// 并发删除产生悬挂绑定。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer tx.Rollback()
	var ruleExists int
	var ruleProtocol string
	if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*), COALESCE(MAX(protocol),'') FROM lb_rules WHERE caddy_id=?", ruleCaddyID).Scan(&ruleExists, &ruleProtocol); err != nil {
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
	if len(uniqueIDs) > 0 {
		placeholders := make([]string, len(uniqueIDs))
		args := make([]interface{}, len(uniqueIDs))
		for i, id := range uniqueIDs {
			placeholders[i] = "?"
			args[i] = id
		}
		var found int
		if err := tx.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM security_policies WHERE id IN ("+strings.Join(placeholders, ",")+")", args...).Scan(&found); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		if found != len(uniqueIDs) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "部分策略不存在"})
			return
		}
	}
	if _, err := tx.ExecContext(c.Request.Context(), "DELETE FROM security_policy_bindings WHERE rule_caddy_id=?", ruleCaddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	for _, id := range uniqueIDs {
		if _, err := tx.ExecContext(c.Request.Context(), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	idStrs := make([]string, len(uniqueIDs))
	for i, id := range uniqueIDs {
		idStrs[i] = strconv.Itoa(id)
	}
	summary := strings.Join(idStrs, ",")
	if summary == "" {
		summary = "全部解除"
	}
	recordAudit(c, "更新", "安全策略", fmt.Sprintf("设置规则 %s 的安全策略为 [%s]", ruleCaddyID, summary))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则安全策略已更新" + h.caddyApplyNote(c)})
}

func (h *Handlers) UnbindRuleFromPolicy(c *gin.Context) {
	policyID := c.Param("id")
	ruleCaddyID := c.Param("caddy_id")
	_, err := db.DB.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleCaddyID, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "更新", "安全策略", fmt.Sprintf("解除规则 %s 与策略 #%s 的绑定", ruleCaddyID, policyID))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已取消关联" + h.caddyApplyNote(c)})
}

func (h *Handlers) GetSecurityPolicyBindings(c *gin.Context) {
	ruleCaddyID := c.Param("caddy_id")
	// v2.2.0 T2：返回 []policy ASC（一规则可绑多策略）；无绑定时返回空数组而非 null，
	// 前端 `.length`/`.map` 不需要空值分支。
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	policyIDs := []int{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		policyIDs = append(policyIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	rows.Close()
	policies := make([]models.SecurityPolicy, 0, len(policyIDs))
	for _, policyID := range policyIDs {
		var p models.SecurityPolicy
		// C5 SUG-1：与 securityPolicySelectColumns 同 25 列同序投影（COALESCE 默认值），
		// 任一可空列 NULL 不再使整接口 500；WHERE enabled=1 语义不变（NULL-enabled
		// 仍被 SQL 过滤）。
		if err := scanSecurityPolicyRow(db.DB.QueryRow(`SELECT `+securityPolicySelectColumns+`
			FROM security_policies WHERE id=? AND enabled=1`, policyID), &p); err != nil {
			if err == sql.ErrNoRows {
				// 策略被并发删除或被禁用：跳过该项，保持数组与绑定表一致
				continue
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		policies = append(policies, p)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: policies})
}

// ip2RegionDisplaySuffixes 省市展示短名的后缀剥离表（长后缀优先匹配）：
// 广东省→广东、广西壮族自治区→广西、深圳市→深圳。
var ip2RegionDisplaySuffixes = []string{"壮族自治区", "回族自治区", "维吾尔自治区", "自治区", "特别行政区", "省", "市"}

// ip2RegionShortenName 剥离行政区后缀得到展示短名；无后缀或剥离后为空则原样返回。
func ip2RegionShortenName(name string) string {
	for _, suffix := range ip2RegionDisplaySuffixes {
		if strings.HasSuffix(name, suffix) && len(name) > len(suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

// formatIP2RegionLocation 把 ip2region 原始 region（"国家|省|市|ISP|国家代码"）
// 格式化为展示文本：中国 → "中国·广东·深圳"，海外国家 → "海外"，未知/畸形 → ""。
func formatIP2RegionLocation(region string) string {
	fields := strings.Split(region, "|")
	if len(fields) < 5 || fields[0] == "" || fields[0] == "0" {
		return ""
	}
	if fields[0] != "中国" {
		return "海外"
	}
	parts := []string{"中国"}
	for _, f := range fields[1:3] {
		f = strings.TrimSpace(f)
		if f == "" || f == "0" {
			continue
		}
		parts = append(parts, ip2RegionShortenName(f))
	}
	return strings.Join(parts, "·")
}

// enrichIPLocation 返回 IP 的归属地展示文本；xdb 未安装或查询失败返回 ""（前端
// 隐藏归属地标签），永不报错。
func enrichIPLocation(ip string) string {
	if ip == "" {
		return ""
	}
	return formatIP2RegionLocation(services.LookupRegion(ip))
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
	// R72 十九次（用户需求）：事件日志三列（负载规则/触发规则/策略）服务端筛选
	// ——r1 匹配事件时规则名快照（rule_name，跨删改名存活），policy 匹配策略名
	// 快照（policy_name）。快照列为摄取时落库的冗余文本，LIKE 子串即可（无索引，
	// 页级分页下可接受）。
	if ruleName := strings.TrimSpace(c.Query("rule_name")); ruleName != "" {
		where += " AND rule_name LIKE ?"
		args = append(args, "%"+ruleName+"%")
	}
	if policyName := strings.TrimSpace(c.Query("policy_name")); policyName != "" {
		where += " AND policy_name LIKE ?"
		args = append(args, "%"+policyName+"%")
	}
	// isAllDigits：CRS 规则 ID 判定（触发规则列对 CRS 显示纯数字 ID）。
	isAllDigits := func(v string) bool {
		for _, r := range v {
			if r < '0' || r > '9' {
				return false
			}
		}
		return len(v) > 0
	}

	// R72 二十次：rule_triggered 筛选对齐表格显示语义——列显示的是 family 标签
	//（IP 访问控制/请求阻断评估/协议异常/协议攻击/自定义规则）或原始 ID；用户按
	// 显示文本筛选时纯 ID LIKE 必然搜不到。输入按 family 标签映射为 ID 前缀集合
	// OR 匹配，否则退回 ID/消息子串（触发规则原文在 rule_msg，一并命中便于用
	// 'sqlmap' 这类消息关键词定位）。
	if ruleTriggered := strings.TrimSpace(c.Query("rule_triggered")); ruleTriggered != "" {
		familyPrefixes := map[string][]string{
			"IP 访问控制": {"2", "3", "4", "5", "7"},
			"地域拦截":    {"8"},
			"请求阻断评估":  {"949"},
			"协议异常":    {"920"},
			"协议攻击":    {"921"},
			"自定义规则":   {"10", "11", "12", "13", "14", "15", "16", "17", "18", "19"},
		}
		prefixes, isFamily := familyPrefixes[ruleTriggered]
		switch {
		case isFamily:
			ors := make([]string, 0, len(prefixes))
			for _, p := range prefixes {
				ors = append(ors, "rule_triggered LIKE ?")
				args = append(args, p+"%")
			}
			where += " AND (" + strings.Join(ors, " OR ") + ")"
		case strings.HasPrefix(ruleTriggered, "IP"), strings.HasPrefix(ruleTriggered, "请求阻断"), strings.HasPrefix(ruleTriggered, "协议"):
			// family 标签的部分输入：宽匹配（前缀命中任一 family 即可）。
			matched := false
			ors := make([]string, 0, 4)
			for label, ps := range familyPrefixes {
				if strings.HasPrefix(label, ruleTriggered) {
					matched = true
					for _, p := range ps {
						ors = append(ors, "rule_triggered LIKE ?")
						args = append(args, p+"%")
					}
				}
			}
			if matched {
				where += " AND (" + strings.Join(ors, " OR ") + ")"
			} else {
				where += " AND 1=0"
			}
		default:
			// R72 二十一次（性能优化）：纯数字输入（CRS 规则 ID，如 942100——即表格
			// 触发规则列对 CRS 显示的原文）改为「精确 OR 前缀」匹配，避免前后双 %
			// 全字段扫描；消息关键词输入保留双 LIKE（rule_msg 无结构可言）。
			// 10 万行实测：前缀匹配走 SCAN 但过滤更快，双列双 % 最重——能省则省。
			if isAllDigits(ruleTriggered) {
				where += " AND (rule_triggered = ? OR rule_triggered LIKE ? OR rule_msg LIKE ?)"
				args = append(args, ruleTriggered, ruleTriggered+"%", "%"+ruleTriggered+"%")
			} else {
				where += " AND (rule_triggered LIKE ? OR rule_msg LIKE ?)"
				args = append(args, "%"+ruleTriggered+"%", "%"+ruleTriggered+"%")
			}
		}
	}

	// R72 二十次（用户需求）：URI 筛选（子串）。
	if uri := strings.TrimSpace(c.Query("uri")); uri != "" {
		where += " AND uri LIKE ?"
		args = append(args, "%"+uri+"%")
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
		e.IPLocation = enrichIPLocation(e.ClientIP)
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
		return "通用攻击"
	case strings.HasPrefix(ruleTriggered, "920"):
		return "协议异常"
	case strings.HasPrefix(ruleTriggered, "921"):
		return "协议攻击"
	case strings.HasPrefix(ruleTriggered, "911"):
		return "方法限制"
	case strings.HasPrefix(ruleTriggered, "912"):
		return "协议攻击（CRS v3 遗留标签）"
	case strings.HasPrefix(ruleTriggered, "915"):
		return "请求体限制"
	case strings.HasPrefix(ruleTriggered, "913"):
		return "扫描探测"
	case strings.HasPrefix(ruleTriggered, "943"):
		return "会话固定"
	case strings.HasPrefix(ruleTriggered, "999"):
		return "通用排除（CRS 后）"
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
	case ruleTriggered == "8" || strings.Contains(ruleMsg, "GeoIP 区域拦截"):
		return "地域拦截"
	case strings.Contains(ruleMsg, "IP 黑名单") || strings.Contains(ruleMsg, "IP 白名单") || strings.Contains(ruleMsg, "IP 访问控制") ||
		ruleTriggered == "2" || ruleTriggered == "3" || ruleTriggered == "4" || ruleTriggered == "5" || ruleTriggered == "7":
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
	// R63 B-N3：全函数单点取时——此前趋势桶用第二次 time.Now()，跨午夜请求的
	// 「今日」计数与趋势末桶会锚定不同日期（毫秒级窗口、下次轮询自愈）。
	today := now
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
	// R63 B-N4：攻击族查询按 Top-10 结果收窄（替换原全量 GROUP BY + LIMIT 5000）——
	// 高基数攻击洪峰下组合数超限会使部分 Top-IP 的攻击类型标签静默缺失
	// （「数对、标签少」）；收窄后组合数有界（10 × 该 IP 的规则/消息数），无需截断。
	if len(topRows) > 0 {
		placeholders := make([]string, len(topRows))
		famArgs := make([]interface{}, 0, len(topRows)+1)
		famArgs = append(famArgs, todayStartUTC)
		for i, row := range topRows {
			placeholders[i] = "?"
			famArgs = append(famArgs, row.ip)
		}
		famRows, err := db.MetricsDB.Query(fmt.Sprintf(`SELECT client_ip, COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') AND client_ip IN (%s) GROUP BY client_ip, rule_triggered, rule_msg`, strings.Join(placeholders, ",")), famArgs...)
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
	}
	overview.TopIPs = make([]models.SecurityTopIP, 0, len(topRows))
	for _, row := range topRows {
		overview.TopIPs = append(overview.TopIPs, models.SecurityTopIP{
			IP:         row.ip,
			IPLocation: enrichIPLocation(row.ip),
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
	recordAudit(c, "更新", "CRS规则库", fmt.Sprintf("自动更新已%s", autoUpdateText))
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
	if _, err := mgr.StartUpdate("manual"); err != nil {
		if errors.Is(err, services.ErrCRSUpdateRunning) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "更新", "CRS规则库", "手动更新 CRS规则库")
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
		Version: services.GetIP2RegionVersion(),
		DbSize:  services.GetIP2RegionEntryCount(),
		// R72 二十六次 D2：行缺失兜底与 schema/种子默认对齐（TRUE）。
		AutoUpdate:   true,
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
	// R72 二十三次：返回级联结构——provinces 保持旧形态（数组，存量消费方
	// 兼容），cities 为省→城市集映射（区域精确到市；海外为一级条目无城市）。
	tree := services.GetIP2RegionRegionTree()
	if tree == nil {
		tree = &services.IP2RegionRegionTree{
			Provinces: services.GetIP2RegionProvinceList(),
			Cities:    map[string][]string{},
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: tree})
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
	recordAudit(c, "更新", "IP数据库", fmt.Sprintf("自动更新已%s", autoUpdateText))
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
	if _, err := mgr.StartUpdate("manual"); err != nil {
		if errors.Is(err, services.ErrIP2RegionUpdateRunning) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "更新", "IP数据库", "手动更新 IP数据库")
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

// GetAllSecurityBindings（v2.2.0 T2）：一规则可绑多策略——返回 map[string][]BindingInfo，
// 每规则的绑定按 policy_id ASC 排序；取代旧的 map[string]BindingInfo 单值覆盖形态。
func (h *Handlers) GetAllSecurityBindings(c *gin.Context) {
	// mode/enabled/rate_limit_enabled 与生成投影同默认值 COALESCE（I-3）：NULL 列
	// 修复前触发 Scan 报错静默丢绑定，而生成路径照常应用该策略。enabled 归一为 0
	// 而非 schema 默认 1——生成路径以 WHERE enabled=1 把 NULL 当禁用，UI 标签须
	// 与后端行为一致（区别于 List 详情的 COALESCE(enabled,1)：那里无 WHERE 过滤）。
	rows, err := db.DB.Query(`SELECT b.rule_caddy_id, p.id, p.name, COALESCE(p.mode,'off'), COALESCE(p.enabled,0), COALESCE(p.rate_limit_enabled,0), COALESCE(p.block_page_id, 0)
		FROM security_policy_bindings b JOIN security_policies p ON b.policy_id = p.id
		ORDER BY b.rule_caddy_id ASC, b.policy_id ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer rows.Close()
	// block_page_id（D-I1）：前端据此计算「首个启用且配置了拦截页面的策略」，
	// 与后端生成口径（首个 enabled 且 block_page_id>0）一致。
	type BindingInfo struct {
		PolicyID    int    `json:"policy_id"`
		Name        string `json:"name"`
		Mode        string `json:"mode"`
		Enabled     bool   `json:"enabled"`
		RateLimit   bool   `json:"rate_limit_enabled"`
		BlockPageID int    `json:"block_page_id"`
	}
	result := map[string][]BindingInfo{}
	for rows.Next() {
		var ruleCaddyID string
		var b BindingInfo
		if err := rows.Scan(&ruleCaddyID, &b.PolicyID, &b.Name, &b.Mode, &b.Enabled, &b.RateLimit, &b.BlockPageID); err != nil {
			// 单行扫描失败跳过：不写入零值绑定（policy_id=0/mode="" 会把该规则
			// 错误呈现为「已绑定到空策略」）；迭代错误由下方 rows.Err() 兜底（R37 S2）。
			services.Logf("warn", "security bindings: 跳过扫描失败行（规则绑定可能缺失）: %v", err)
			continue
		}
		result[ruleCaddyID] = append(result[ruleCaddyID], b)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func scanSecurityPolicyRow(row *sql.Row, p *models.SecurityPolicy) error {
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &p.IPWhitelistEnabled, &ipWhitelist, &ipBlacklist,
		&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse, &p.IPACLListRefs, &p.IPWhitelistRefs); err != nil {
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
	if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &p.IPWhitelistEnabled, &ipWhitelist, &ipBlacklist,
		&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse, &p.IPACLListRefs, &p.IPWhitelistRefs); err != nil {
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
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Mode               string `json:"mode"`
	AnomalyThreshold   int    `json:"anomaly_threshold"`
	IPACLMode          string `json:"ip_acl_mode"`
	IPACLList          string `json:"ip_acl_list"`
	IPACLEnabled       bool   `json:"ip_acl_enabled"`
	IPWhitelistEnabled bool   `json:"ip_whitelist_enabled"`
	IPWhitelist        string `json:"ip_whitelist"`
	IPBlacklist        string `json:"ip_blacklist"`
	RateLimitEnabled   bool   `json:"rate_limit_enabled"`
	RateLimitRPS       int    `json:"rate_limit_rps"`
	RateLimitBurst     int    `json:"rate_limit_burst"`
	CRSRuleGroups      string `json:"crs_rule_groups"`
	CRSExcludedRules   string `json:"crs_excluded_rules"`
	CustomRules        string `json:"custom_rules"`
	BlockPageID        int    `json:"block_page_id"`
	BlockStatusCode    int    `json:"block_status_code"`
	Enabled            bool   `json:"enabled"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	GeoIPCountries     string `json:"geoip_countries"`
	GeoIPMode          string `json:"geoip_mode"`
	WAFCheckResponse   bool   `json:"waf_check_response"`
	IPACLListRefs      string `json:"ip_acl_list_refs"`
	IPWhitelistRefs    string `json:"ip_whitelist_refs"`
}

func newSecurityPolicyDetail(p *models.SecurityPolicy) securityPolicyDetail {
	return securityPolicyDetail{
		ID:                 p.ID,
		Name:               p.Name,
		Description:        p.Description,
		Mode:               p.Mode,
		AnomalyThreshold:   p.AnomalyThreshold,
		IPACLMode:          p.IPACLMode,
		IPACLList:          p.IPACLList,
		IPACLEnabled:       p.IPACLEnabled,
		IPWhitelistEnabled: p.IPWhitelistEnabled,
		IPWhitelist:        rawJSONString(p.IPWhitelist),
		IPBlacklist:        rawJSONString(p.IPBlacklist),
		RateLimitEnabled:   p.RateLimitEnabled,
		RateLimitRPS:       p.RateLimitRPS,
		RateLimitBurst:     p.RateLimitBurst,
		CRSRuleGroups:      rawJSONString(p.CRSRuleGroups),
		CRSExcludedRules:   rawJSONString(p.CRSExcludedRules),
		CustomRules:        rawJSONString(p.CustomRules),
		BlockPageID:        p.BlockPageID,
		BlockStatusCode:    p.BlockStatusCode,
		Enabled:            p.Enabled,
		CreatedAt:          p.CreatedAt,
		UpdatedAt:          p.UpdatedAt,
		GeoIPCountries:     rawJSONString(p.GeoIPCountries),
		GeoIPMode:          p.GeoIPMode,
		WAFCheckResponse:   p.WAFCheckResponse,
		IPACLListRefs:      p.IPACLListRefs,
		IPWhitelistRefs:    p.IPWhitelistRefs,
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
	// R69 C-N2：渲染侧 buildRateLimitHandler 的 min-zone 用 rps*60、sec-zone 用
	// rps+burst（int64 运算）——与 request_body_max_size_mb 钳制（R57 C-7）同型的
	// 溢出防线：上界 1e9 使任何算术组合远离 int64 回绕。
	if rps > 1_000_000_000 {
		return fmt.Errorf("策略 %q：rate_limit_rps 过大（当前 %d，上限 1000000000）", name, rps)
	}
	if burst > 1_000_000_000 {
		return fmt.Errorf("策略 %q：rate_limit_burst 过大（当前 %d，上限 1000000000）", name, burst)
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
	// "off" 是区域控制关闭态（名单保留不清单），与 WAF mode/ip_acl 同为三态。
	case "", "off", "allow", "deny":
	default:
		return fmt.Errorf("geoip_mode 必须为 off、allow 或 deny，当前值 %s", geoIPMode)
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
		if !validIPOrCIDR(entry) {
			return fmt.Errorf("%s 包含无效的 IP/CIDR 条目：%s", field, entry)
		}
	}
	return nil
}

// validIPOrCIDR 是 IP/CIDR 条目的值级判定：接受 netip.ParsePrefix（CIDR）或
// netip.ParseAddr（裸 IP）双形态。validateIPCIDRList 与 IP 地址列表条目校验
// （securityiplists.go）共用，保证两处口径一致。
func validIPOrCIDR(entry string) bool {
	if _, err := netip.ParsePrefix(entry); err == nil {
		return true
	}
	_, err := netip.ParseAddr(entry)
	return err == nil
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
	// R66 B-N3：对齐 GetCRSSetupConfig 的 413 口径（R62 B-NEW-3）——超限显式
	// 拒绝而非静默截断，防消费方（UI 预览/MCP 抓取）把残缺内容当完整规则使用。
	content, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if len(content) > 1<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "规则文件超过 1MB 读取上限"})
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
	case strings.Contains(name, "922-"):
		return "multipart 攻击"
	case strings.Contains(name, "930-"):
		return "路径穿越 (LFI)"
	case strings.Contains(name, "931-"):
		return "远程文件包含 (RFI)"
	case strings.Contains(name, "932-"):
		return "远程代码执行 (RCE)"
	case strings.Contains(name, "933-"):
		return "PHP 攻击"
	case strings.Contains(name, "934-"):
		return "通用攻击"
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
	case strings.Contains(name, "952-"):
		return "响应 Java 泄露"
	case strings.Contains(name, "953-"):
		return "响应 PHP 泄露"
	case strings.Contains(name, "954-"):
		return "响应 IIS 泄露"
	case strings.Contains(name, "955-"):
		return "Webshell"
	case strings.Contains(name, "956-"):
		return "响应 Ruby 泄露"
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
	case strings.Contains(name, "913-"):
		return "爬虫检测"
	case strings.Contains(name, "915-"):
		return "请求体限制"
	case strings.Contains(name, "999-"):
		return "通用排除（CRS 后）"
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
