package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"

	"github.com/gin-gonic/gin"
)

// crsRulesDir 是 CRS 规则文件目录测试缝：空值=按 services.CRSLiveDir() 派生
// （ 单点派生——避免 services 写侧与 handlers 读侧各持一份 /app
// 硬编码，data_dir ≠ /app/data 时分叉）；测试注入临时目录。
var crsRulesDir = ""

// crsSetupConf 与 crsRulesDir 同款测试缝：空值=派生。
var crsSetupConf = ""

// crsRulesDirPath / crsSetupConfPath 解析当前 CRS 读取路径（测试缝优先）。
func crsRulesDirPath() string {
	if crsRulesDir != "" {
		return crsRulesDir
	}
	return filepath.Join(services.CRSLiveDir(), "rules")
}

func crsSetupConfPath() string {
	if crsSetupConf != "" {
		return crsSetupConf
	}
	return filepath.Join(services.CRSLiveDir(), "crs-setup.conf")
}

func (h *Handlers) ListSecurityCustomRules(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, name, COALESCE(description,''), COALESCE(conditions,'[]'), COALESCE(NULLIF(condition_logic,''),'and'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1), COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(updated_by,0) FROM security_custom_rules ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer rows.Close()
	var rules []models.SecurityCustomRule
	for rows.Next() {
		var r models.SecurityCustomRule
		var conditionsJSON string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &conditionsJSON, &r.ConditionLogic, &r.Action, &r.Score, &r.Enabled, &r.CreatedAt, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		// 解析失败与下方 rows.Err 同口径显式 500（「残缺列表不得
		// 以 200 返回」）——零值形态混入 200 会让该行在 UI 呈现「无条件规则」且
		// 不可编辑保存，发射端又整条跳过，等于一条规则被静默停用。
		if err := json.Unmarshal([]byte(conditionsJSON), &r.Conditions); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("自定义规则 %d 的条件解析失败: %v", r.ID, err)})
			return
		}
		rules = append(rules, r)
	}
	// 迭代失败显式报错：对齐 ListSecurityPolicies/GetSecurityPolicy
	// 的既有标准，残缺列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if rules == nil {
		rules = []models.SecurityCustomRule{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

const (
	securityNameMaxRunes        = 100
	securityDescriptionMaxRunes = 500
)

// validateBlockPagePayload 是拦截页创建/编辑共用的载荷门：名称/描述/内容
// 必填与长度、64KB 内容上限、内容类型默认值与白名单。空 ContentType 归一为
// 默认 html（原地写回）。错误文案沿用端点既有 400 语义。
func validateBlockPagePayload(page *models.SecurityBlockPage) error {
	if strings.TrimSpace(page.Name) == "" {
		return fmt.Errorf("拦截页面名称不能为空")
	}
	if utf8.RuneCountInString(page.Name) > securityNameMaxRunes {
		return fmt.Errorf("拦截页面名称不能超过 100 字符")
	}
	if utf8.RuneCountInString(page.Description) > securityDescriptionMaxRunes {
		return fmt.Errorf("拦截页面描述不能超过 500 字符")
	}
	if strings.TrimSpace(page.Content) == "" {
		return fmt.Errorf("拦截页面内容不能为空")
	}
	if len(page.Content) > 64<<10 {
		return fmt.Errorf("拦截页面内容不能超过 64KB")
	}
	if page.ContentType == "" {
		page.ContentType = models.DefaultBlockPageContentType
	}
	if !models.ValidBlockPageContentType(page.ContentType) {
		return fmt.Errorf("内容类型不支持，可选：text/html、application/json、application/xml、text/plain（均 UTF-8）")
	}
	return nil
}

func validateSecurityCustomRule(rule *models.SecurityCustomRule) error {
	// 负 ID 发射 id:crID+10000 会生成重复（id:10 撞
	// body processor）或负 SecRule id，整份 coraza 配置被拒——本函数是
	// Create/Update/导入三路径的单一收口点，在此拒绝（发射侧另有兜底跳过）。
	if rule.ID < 0 {
		return fmt.Errorf("规则 id 不能为负数")
	}
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
	// 规则名随 SecRule msg 发射,长度封顶 100 rune。
	if utf8.RuneCountInString(rule.Name) > securityNameMaxRunes {
		return fmt.Errorf("规则名称不能超过 100 字符")
	}
	// description 补封顶——
	// 对齐策略描述 500 rune 口径；DB 列无长度约束，超长串随列表响应/审计
	// 详情放大。本函数是 Create/Update/导入三路径的单一收口点。
	if utf8.RuneCountInString(rule.Description) > securityDescriptionMaxRunes {
		return fmt.Errorf("规则描述不能超过 500 字符")
	}
	if rule.ConditionLogic != "and" && rule.ConditionLogic != "or" {
		return fmt.Errorf("条件关系必须为 and 或 or，当前值 %s", rule.ConditionLogic)
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

// serverErrMsg 500 响应文案单源：错误原文写服务端日志（保留归因），响应只回
// 调用方给出的泛化文案——SQLite/驱动错误可含表名/列名/SQL 片段，不得外泄给
// 任意已登录用户（与 ListSecurityEvents「泛化文案 + 服务端留痕」同标准）。
// 400/404/409 等可判定错误不走此函数（那些文案本就是面向用户的校验结论）。
func serverErrMsg(publicMsg string, err error) string {
	// 与 system/crawler 同一装配实现（internalError）：本变体保留 string 返回，
	// 供 139 处「c.JSON(..., APIResponse{Message: serverErrMsg(...)})」调用点
	// 零改动收敛；语义（固定文案 + 服务端留痕 + err==nil 不重复日志）同源。
	return internalError("安全处理器", publicMsg, err).Message
}

// securityCustomRuleMaxGlobalCount 自定义规则全局数量上限
// 常量化——此前 200 以魔数散落在计数判定与文案两处）。与 IP 名单
// ipListMaxGlobalCount 同阈值的双限额口径。
const securityCustomRuleMaxGlobalCount = 200

// securityPolicyMaxGlobalCount 安全策略全局数量上限：策略行被列表/导入/绑定
// 逐行消费（列表每策略 N 次查询），写侧无上限时导入与 API 可无界增长。
// 与自定义规则/IP 名单 200 同族双限额口径，计数在写事务内 fail-closed。
const securityPolicyMaxGlobalCount = 200

// securityBlockPageMaxGlobalCount 拦截页面全局数量上限：列表每行回传全量
// content（单页上限 64KiB），无上限时一次列表可回传数十 MB。同族限额口径。
const securityBlockPageMaxGlobalCount = 200

// createSecurityCustomRulePreLockHook 测试屏障（生产恒 nil）：用于证明写请求
// 已到达共享 caddyOpMu 入口，避免负向锁测试依赖固定等待。
var createSecurityCustomRulePreLockHook func()

func (h *Handlers) CreateSecurityCustomRule(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行自定义规则写操作") {
		return
	}
	var req models.CreateCustomRuleRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	// 省略 enabled = 启用（零值陷阱家族）——
	// MCP/API 无需感知默认值，也不得因省略而创建静默禁用的 WAF 规则。
	rule := models.SecurityCustomRule{
		Name:           req.Name,
		Description:    req.Description,
		Conditions:     req.Conditions,
		ConditionLogic: "and",
		Action:         req.Action,
		Score:          req.Score,
		Enabled:        req.Enabled == nil || *req.Enabled,
	}
	if req.ConditionLogic != nil {
		rule.ConditionLogic = *req.ConditionLogic
	}
	if createSecurityCustomRulePreLockHook != nil {
		createSecurityCustomRulePreLockHook()
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if err := validateSecurityCustomRule(&rule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	conditionsJSON, _ := json.Marshal(rule.Conditions)
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启事务失败"})
		return
	}
	defer tx.Rollback()
	// 全局数量上限（对齐 IP 名单 ipListMaxGlobalCount=200
	// 双限额口径——曾无上限）。计数移入 BEGIN IMMEDIATE
	// 事务内与插入同锁（消除计数-插入间并发窗口），计数查询失败 fail-closed
	// 拒绝——此前 `err == nil &&` 判定使 DB 故障静默跳过上限继续创建。
	var ruleCount int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_custom_rules").Scan(&ruleCount); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计自定义规则数量失败"})
		return
	}
	if ruleCount >= securityCustomRuleMaxGlobalCount {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("自定义规则总数已达上限（%d 条），请先清理不再使用的规则", securityCustomRuleMaxGlobalCount)})
		return
	}
	result, err := tx.Exec(`INSERT INTO security_custom_rules (name, description, conditions, condition_logic, action, score, enabled, updated_by) VALUES (?,?,?,?,?,?,?,?)`,
		rule.Name, rule.Description, string(conditionsJSON), rule.ConditionLogic, rule.Action, rule.Score, rule.Enabled, int(contextUserID(c)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	id, _ := result.LastInsertId()
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "自定义规则", AuditAction: "创建",
		AuditDetail: fmt.Sprintf("名称：%s（#%d）", rule.Name, id),
		SuccessMsg:  "规则创建成功",
		Data:        gin.H{"id": id},
	})
}

func (h *Handlers) UpdateSecurityCustomRule(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行自定义规则写操作") {
		return
	}
	id := c.Param("id")
	if _, ok := parsePositiveNumericID(id); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "规则 ID 无效"})
		return
	}
	var req models.UpdateCustomRuleRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	// 省略即保持现值（与 UpdateSecurityPolicy 同口径）——enabled 是本
	// 端点唯一「零值语义恰为禁用」的字段，MCP 无约束 body 的部分更新此前会把
	// 零值 false 直写落库，WAF 静默少一条拦截规则且审计无痕迹。先读现值合并为
	// 有效形态再过统一校验（校验规则不变，只是输入从「绑定零值」改为「现值」）。
	// 读-合并-写包进事务（DSN _txlock=immediate 使首个读即持写锁，
	// 与 UpdateSecurityPolicy 同机制）——此前裸连接读后合并再全列写，两个并发
	// 部分更新会互相静默覆盖（丢 enabled 翻转 = WAF 规则静默启/禁用）。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启事务失败"})
		return
	}
	defer tx.Rollback()
	var existing models.SecurityCustomRule
	var existingConditionsJSON string
	if err := tx.QueryRowContext(caddyWriteCtx(c),
		`SELECT name, COALESCE(description,''), COALESCE(conditions,'[]'), COALESCE(NULLIF(condition_logic,''),'and'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1) FROM security_custom_rules WHERE id=?`, id,
	).Scan(&existing.Name, &existing.Description, &existingConditionsJSON, &existing.ConditionLogic, &existing.Action, &existing.Score, &existing.Enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取规则失败", err)})
		return
	}
	// 存量条件「非空但解析失败」与「用户漏传条件」是不同故障——
	// 吞错会使损坏行走到「至少需要一个匹配条件」400，被误归因为用户输入
	//（与 storage_corrupted 口径对齐）。
	if existingConditionsJSON != "" {
		if uerr := json.Unmarshal([]byte(existingConditionsJSON), &existing.Conditions); uerr != nil {
			recordAudit(c, "更新失败", "自定义规则", services.FormatAuditDetail(fmt.Sprintf("规则 #%s", id), services.AuditResultPart("storage_corrupted")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "存储的自定义规则条件已损坏，请删除后重建"})
			return
		}
	}
	merged := models.SecurityCustomRule{
		Name:           existing.Name,
		Description:    existing.Description,
		Conditions:     existing.Conditions,
		ConditionLogic: existing.ConditionLogic,
		Action:         existing.Action,
		Score:          existing.Score,
		Enabled:        existing.Enabled,
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
	if req.ConditionLogic != nil {
		merged.ConditionLogic = *req.ConditionLogic
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
	result, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE security_custom_rules SET name=?, description=?, conditions=?, condition_logic=?, action=?, score=?, enabled=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		merged.Name, merged.Description, string(conditionsJSON), merged.ConditionLogic, merged.Action, merged.Score, merged.Enabled, int(contextUserID(c)), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "规则不存在") {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "自定义规则", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）", merged.Name, id),
		SuccessMsg:  "规则已更新",
	})
}

func (h *Handlers) DeleteSecurityCustomRule(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行自定义规则写操作") {
		return
	}
	// 非规范数字 id 一律 400：SQLite 数值亲和使 '5.0' 等
	// 形态仍命中 id=5 行——Atoi 失败若放行会跳过下方引用检查后照常删除
	// （与 DeleteIPList 的 ParseInt 门同族口径）。
	listID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || listID <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的规则 ID"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	// 引用检查与删除必须同事务：检查通过后、DELETE 之前并发的策略更新（启用引用
	// 策略）或新建引用策略会造成悬空引用，发射端仅日志跳过，WAF 规则静默丢失。
	// 写锁来自 DSN 的 _txlock=immediate（glebarez 驱动忽略 TxOptions.Isolation，
	// 非只读 BeginTx 一律 BEGIN IMMEDIATE）：引用检查的 SELECT 即持写锁，并发的
	// UpdateSecurityPolicy/CreateSecurityPolicy 无法在检查与 DELETE 之间提交。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	// 被启用策略引用的自定义规则不可删除：静默删除会产生悬空引用，发射阶段规则
	// 被跳过且无提示，必须先解除绑定。仅 ID 数组形态计入引用（内嵌对象随策略
	// 存储，删除单条规则不构成悬空）。listID 已在上方 ParseInt 校验为规范数字
	// 且 >0，直接复用（删除原二次 Atoi 恒真分支）。
	var referenced int
	rows, err := tx.QueryContext(caddyWriteCtx(c), `SELECT COALESCE(custom_rules,'[]') FROM security_policies WHERE enabled=1`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		var ids []int
		if json.Unmarshal([]byte(raw), &ids) != nil {
			continue // 内嵌对象形状不构成 ID 引用
		}
		for _, rid := range ids {
			if rid == int(listID) {
				referenced++
				break
			}
		}
	}
	rows.Close()
	if rowsErr := rows.Err(); rowsErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", rowsErr)})
		return
	}
	if referenced > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该自定义规则正被 %d 个启用的安全策略使用，请先解除绑定", referenced)})
		return
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_custom_rules WHERE id=?", listID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "规则不存在") {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "自定义规则", AuditAction: "删除",
		AuditDetail: fmt.Sprintf("规则 #%d", listID),
		SuccessMsg:  "规则已删除",
	})
}

func (h *Handlers) ListSecurityBlockPages(c *gin.Context) {
	// 列表载荷含全量 content（单页 ≤64KiB，页面总数 ≤200，最坏约 12.8MiB）：
	// content 同时是编辑器的唯一数据源（无详情端点，PUT 为全量覆盖），
	// 截断会让「查看→保存」把页面内容写掉，因此不做逐行裁剪；上限由
	// securityBlockPageMaxGlobalCount（200）与 validateBlockPagePayload 的
	// 64KiB 共同界定，响应经 HTTP gzip 压缩传输。
	// 引用计数与 DeleteSecurityBlockPage 门同口径（有意设计，两种口径的
	// 取舍已裁定保留）：策略侧仅计启用（禁用策略的配页是休眠配置，删除后
	// 运行期 JOIN 容忍悬挂）；规则侧阶段页引用全量计（禁用规则重新启用即
	// 生效，静默丢失引用伤害更大）——两侧口径不同但与删除门逐一对应。
	rows, err := db.DB.Query(`SELECT bp.id, bp.name, COALESCE(bp.description,''), COALESCE(bp.content,''), COALESCE(bp.content_type,'text/html; charset=utf-8'), COALESCE(bp.is_default,0), COALESCE(bp.is_builtin,0), COALESCE(bp.created_by,0), COALESCE(bp.created_at,''), COALESCE(bp.updated_by,0), COALESCE(bp.updated_at,''),
		(SELECT COUNT(*) FROM (
			SELECT b.rule_caddy_id FROM security_policy_bindings b JOIN security_policies p ON p.id=b.policy_id WHERE p.block_page_id=bp.id AND p.enabled=1
			UNION SELECT r.caddy_id FROM lb_rules r WHERE r.block_page_stage1_id=bp.id OR r.block_page_stage3_id=bp.id
		)) AS rule_ref_count
		FROM security_block_pages bp ORDER BY bp.is_default DESC, bp.is_builtin DESC, bp.id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer rows.Close()
	var pages []models.SecurityBlockPage
	for rows.Next() {
		var p models.SecurityBlockPage
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Content, &p.ContentType, &p.IsDefault, &p.IsBuiltin, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt, &p.RuleRefCount); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		pages = append(pages, p)
	}
	// 迭代失败显式报错：对齐 ListSecurityPolicies/GetSecurityPolicy
	// 的既有标准，残缺列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if pages == nil {
		pages = []models.SecurityBlockPage{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: pages})
}

func (h *Handlers) CreateSecurityBlockPage(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行拦截页写操作") {
		return
	}
	var req models.SecurityBlockPage
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if err := validateBlockPagePayload(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// API 不允许创建默认拦截页：默认页仅 db 种子行，第二个
	// is_default=1 页面不可编辑（:243）不可删除（:283），且 branding 重渲染
	// 会覆盖全部默认页内容——产生不可管理的死行。
	if req.IsDefault {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "默认拦截页由系统管理，不允许创建"})
		return
	}
	// 内置页（is_builtin）与显式 id 同口径拒绝：INSERT 列清单不含这两列，
	// 静默丢弃会让调用方以为「已创建内置页/指定了 id」，实际落普通行。
	if req.IsBuiltin {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "内置拦截页由系统管理，不允许创建"})
		return
	}
	if req.ID != 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "拦截页 ID 由系统分配，不接受指定"})
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启事务失败"})
		return
	}
	defer tx.Rollback()
	// 全局数量上限（同族 200 双限额口径）：列表每行回传全量 content
	// （单页 ≤64KiB），无上限时一次列表可回传数十 MB。计数与插入同事务。
	var pageCount int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_block_pages").Scan(&pageCount); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计拦截页面数量失败"})
		return
	}
	if pageCount >= securityBlockPageMaxGlobalCount {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("拦截页面总数已达上限（%d 个），请先清理不再使用的页面", securityBlockPageMaxGlobalCount)})
		return
	}
	result, err := tx.Exec(`INSERT INTO security_block_pages (name, description, content, content_type, is_default, created_by, updated_by) VALUES (?,?,?,?,?,?,?)`,
		req.Name, req.Description, req.Content, req.ContentType, false, int(contextUserID(c)), int(contextUserID(c)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	id, _ := result.LastInsertId()
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "拦截页面", AuditAction: "创建",
		AuditDetail: fmt.Sprintf("名称：%s（#%d）", req.Name, id),
		SuccessMsg:  "拦截页面创建成功",
		Data:        gin.H{"id": id},
	})
}

func (h *Handlers) UpdateSecurityBlockPage(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行拦截页写操作") {
		return
	}
	id := c.Param("id")
	if _, ok := parsePositiveNumericID(id); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的拦截页面 ID"})
		return
	}
	// 指针合并语义（与 UpdateRule/PUT 同域口径）：省略字段保留库中原值，
	// 显式空串才清空。旧实现用值结构体全量替换——省略 description 会静默
	// 清空描述、省略 content_type 会把自定义类型重置为默认 text/html。
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Content     *string `json:"content"`
		ContentType *string `json:"content_type"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	var isDefault, isBuiltin bool
	// is_default 检查与 UPDATE 必须同事务（镜像 DeleteSecurityBlockPage
	// 非事务读 + 错误丢弃的旧实现存在并发窗口：导入路径可在 SELECT 与
	// UPDATE 之间把该页重建为默认页，使 UPDATE 绕过 403 契约改到默认页内容。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var page models.SecurityBlockPage
	if err := tx.QueryRowContext(caddyWriteCtx(c), `SELECT COALESCE(is_default,0), COALESCE(is_builtin,0), name, COALESCE(description,''), COALESCE(content,''), COALESCE(content_type,'') FROM security_block_pages WHERE id=?`, id).
		Scan(&isDefault, &isBuiltin, &page.Name, &page.Description, &page.Content, &page.ContentType); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		}
		return
	}
	// 合并省略字段（校验作用于合并后的终值：只传 content 的调用方不会被
	// 「name 为空」误拒）。校验仍在默认页/内置页 403 门之前执行——旧实现
	// 先校验后进门，载荷非法时恒 400（契约保持）。
	if req.Name != nil {
		page.Name = *req.Name
	}
	if req.Description != nil {
		page.Description = *req.Description
	}
	if req.Content != nil {
		page.Content = *req.Content
	}
	if req.ContentType != nil {
		page.ContentType = *req.ContentType
	}
	if err := validateBlockPagePayload(&page); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 内置备选页（限流/维护）与默认页同门禁（2026-09-25 用户裁定：不可编辑/删除）
	if isDefault {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "默认拦截页面不可编辑"})
		return
	}
	if isBuiltin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "内置拦截页面不可编辑"})
		return
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), `UPDATE security_block_pages SET name=?, description=?, content=?, content_type=?, updated_by=?, updated_at=datetime('now') WHERE id=?`,
		page.Name, page.Description, page.Content, page.ContentType, int(contextUserID(c)), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "拦截页面不存在") {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "拦截页面", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("名称：%s（#%s）", page.Name, id),
		SuccessMsg:  "拦截页面已更新",
	})
}

func (h *Handlers) DeleteSecurityBlockPage(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行拦截页写操作") {
		return
	}
	if _, ok := parsePositiveNumericID(c.Param("id")); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的拦截页面 ID"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	// 默认页检查 + 引用检查与删除必须同事务：检查通过后、DELETE 之前并发的策略
	// 更新可把引用该页面的策略置 enabled=1，悬空引用会让拦截响应静默退化回
	// Caddy 默认页面。写锁来自 DSN 的 _txlock=immediate（非只读 BeginTx 一律
	// BEGIN IMMEDIATE）：首个 SELECT 即持写锁，并发的策略更新无法在检查与
	// DELETE 之间提交（同 DeleteSecurityCustomRule）。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var isDefault, isBuiltin bool
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COALESCE(is_default,0), COALESCE(is_builtin,0) FROM security_block_pages WHERE id=?", id).Scan(&isDefault, &isBuiltin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "拦截页面不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		}
		return
	}
	if isDefault {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "默认拦截页面不可删除"})
		return
	}
	// 内置备选页（限流/维护）与默认页同门禁（2026-09-25 用户裁定：不可编辑/删除）
	if isBuiltin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "内置拦截页面不可删除"})
		return
	}
	// 被启用策略引用的拦截页面不可删除：静默删除会让这些策略的拦截
	// 响应退化回 Caddy 默认页面，必须先解除绑定。
	var referenced int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_policies WHERE block_page_id=? AND enabled=1", id).Scan(&referenced); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if referenced > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该拦截页面正被 %d 个启用的安全策略使用，请先解除绑定", referenced)})
		return
	}
	// 规则级阶段拦截页引用：lb_rules 的 block_page_stage1_id /
	// block_page_stage3_id 指向该页时，静默删除会让对应规则的阶段 1/3 拦截
	// 响应回落「跟随策略」或 Caddy 默认页面，必须先解除规则级引用。与策略
	// 引用检查同事务（写锁已持），并发绑定无法插到检查与 DELETE 之间。
	var ruleReferenced int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM lb_rules WHERE block_page_stage1_id=? OR block_page_stage3_id=?", id, id).Scan(&ruleReferenced); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if ruleReferenced > 0 {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("该拦截页面正被 %d 条规则的阶段拦截页引用，请先解除", ruleReferenced)})
		return
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_block_pages WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "拦截页面不存在") {
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "拦截页面", AuditAction: "删除",
		AuditDetail: fmt.Sprintf("页面 #%s", id),
		SuccessMsg:  "拦截页面已删除",
	})
}

// securityPolicySelectColumns 是 ListSecurityPolicies/GetSecurityPolicy 共用的
// 33 表达式投影:与 scanSecurityPolicyInto 逐列对应、同默认值、同相对顺序
// （canonical 副本：internal/services/security.go scanSecurityPolicyByID、
// internal/services/caddy.go loadSecurityPolicyContext 批量预载）。services/ 归
// 并行任务持有且两侧列集本就不同，此处按既定回退方案保持 handlers 本地副本——
// 改任一侧默认值时必须同步另一侧，勿单方面漂移。两点刻意差异：
//  1. 多 COALESCE(updated_by,0)（第 20 位）：PolicySummary/详情响应需要该列，
//     生成投影不含；
//  2. enabled 用 COALESCE(enabled,1)（schema 默认 TRUE）：List/Get 无 enabled
//     WHERE 过滤，NULL-enabled 行须按 schema 默认呈现启用态；生成路径以
//     WHERE enabled=1 守卫，NULL 行本就被过滤，故裸列即可。
//  3. 库值唯一真相（批 3）刻意第三差异：anomaly_threshold 此处保留
//     COALESCE(...,5)（展示层对带外 NULL 行按 Create 默认呈现，容忍遗留脏
//     行）；services 两条生成投影已改 COALESCE(...,0) 无效哨兵——NULL/<=0
//     在渲染层 fail-visible（BuildCorazaDirectives 显性报错），展示层不做
//     行为消费，无需同口径。
const securityPolicySelectColumns = `id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,5), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_whitelist,'[]'), COALESCE(ip_blacklist,'[]'),
	COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0), COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'), COALESCE(block_page_id,0), COALESCE(block_status_code,0), COALESCE(enabled,1), COALESCE(updated_by,0), COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(geoip_crawler_exempt,0), COALESCE(geoip_crawler_engines,'[]'), COALESCE(waf_check_response,0), COALESCE(log_request_body,0), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(policy_type,''), COALESCE(trust_detection,0)`

func (h *Handlers) ListSecurityPolicies(c *gin.Context) {
	// 过滤条件按「主查询列名」与「绑定计数查询的限定列名」成对给出：绑定计数
	// 复用同一条件集但作用于 `b JOIN p`（此前直接复用裸列名，一旦
	// security_policy_bindings 增列 enabled/id 即变 ambiguous column 500）。
	type policyFilter struct{ policy, bound string }
	var filters []policyFilter
	args := []any{}
	// enabled 三态：缺省=不过滤；true/1=仅启用；false/0=仅禁用（此前 false 被
	// 静默忽略返回全量，API/MCP 消费方无从察觉）。
	switch c.Query("enabled") {
	case "true", "1":
		filters = append(filters, policyFilter{"enabled=1", "p.enabled=1"})
	case "false", "0":
		filters = append(filters, policyFilter{"enabled=0", "p.enabled=0"})
	}
	// 按关联规则过滤（IP 归属地弹窗使用：只列出绑定到该规则的策略）
	if ruleCaddyID := c.Query("rule_caddy_id"); ruleCaddyID != "" {
		filters = append(filters, policyFilter{
			`id IN (SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=?)`,
			`p.id IN (SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=?)`,
		})
		args = append(args, ruleCaddyID)
	}
	query := `SELECT ` + securityPolicySelectColumns + ` FROM security_policies`
	if len(filters) > 0 {
		conditions := make([]string, len(filters))
		for i, f := range filters {
			conditions[i] = f.policy
		}
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id"
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer rows.Close()
	type policyListRow struct {
		p                models.SecurityPolicy
		crsExcludedCount int
	}
	loadedPolicies := make([]policyListRow, 0)
	for rows.Next() {
		var p models.SecurityPolicy
		if err := scanSecurityPolicy(rows, &p); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		var crsExcluded []json.RawMessage
		// 解析失败 500(与 ListIPLists 同款口径)——吞错时带外脏
		// 行显示 0 排除、实际 N 排除,观测缺口。
		if err := json.Unmarshal(p.CRSExcludedRules, &crsExcluded); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析策略 CRS 排除列表失败"})
			return
		}
		loadedPolicies = append(loadedPolicies, policyListRow{p: p, crsExcludedCount: len(crsExcluded)})
	}
	rows.Close()

	var policies []models.SecurityPolicySummary
	bindingCounts := map[int]int{}
	// 绑定计数限定于过滤结果集策略(与主查询同语义、列名加 p. 前缀)
	// ——此前无条件全表 GROUP BY,过滤结果为空也执行。
	bindingQuery := "SELECT b.policy_id, COUNT(*) FROM security_policy_bindings b JOIN security_policies p ON p.id=b.policy_id"
	if len(filters) > 0 {
		conditions := make([]string, len(filters))
		for i, f := range filters {
			conditions[i] = f.bound
		}
		bindingQuery += " WHERE " + strings.Join(conditions, " AND ")
	}
	bindingQuery += " GROUP BY b.policy_id"
	bindingRows, err := db.DB.Query(bindingQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	for bindingRows.Next() {
		var pid, cnt int
		if err := bindingRows.Scan(&pid, &cnt); err != nil {
			bindingRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		bindingCounts[pid] = cnt
	}
	bindingRows.Close()
	if err := bindingRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	// blocked_24h / trigger_24h：近 24h 每策略事件计数（metrics 库 security_events，
	// policy_id>0 归因行；走 idx_security_events_action_time 索引范围（action 等值 + event_time 范围），单趟扫描）。
	// blocked_24h 仅计 blocked；trigger_24h 计 blocked+logged（「24h 触发」列口径）。
	// 归因口径同 securityEventsAttributePolicy：多策略
	// CRS 重叠时按 policy_id ASC 首绑定归因——实际拦截引擎在审计数据中不可恢复，
	// 计数是归因记账口径而非引擎级判定。
	blockedCounts := map[int]int{}
	triggerCounts := map[int]int{}
	if db.MetricsDB != nil {
		counts, err := loadSecurityPolicy24hCounts(db.MetricsDB, time.Now())
		if err != nil {
			services.Logf("error", "security policies: 24h event count query failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		blockedCounts = counts.blocked
		triggerCounts = counts.trigger
	}
	policyPointers := make([]*models.SecurityPolicy, len(loadedPolicies))
	for i := range loadedPolicies {
		policyPointers[i] = &loadedPolicies[i].p
	}
	// HasIPControl 摘要与发射面同源需要引用名单的实际条目（引用的
	// 列表为空/缺失时不再虚报「IP 访问控制已启用」）——批次内一次批量查询。
	services.ResolvePolicyIPListRefsForSummary(policyPointers)
	customRuleCounts := services.CountEnabledCustomRulesBatch(policyPointers)
	// CRS 陈旧选择检测复用同一份索引（缓存命中零重建；索引键含目录+版本+
	// 聚合 stat，CRS 更替后自动重判）。
	crsIndex := services.GetCRSRuleIndex()
	for i := range loadedPolicies {
		p := loadedPolicies[i].p
		customRulesCount := customRuleCounts[i]
		hasGeoIP := services.PolicyHasGeoIP(&p)
		policies = append(policies, models.SecurityPolicySummary{
			ID: p.ID, Name: p.Name, Mode: p.Mode, Enabled: p.Enabled, RuleCount: bindingCounts[p.ID],
			HasWAF: p.Mode == "blocking" || p.Mode == "detection", HasIPControl: services.SecurityPolicyHasIPControl(&p), HasRateLimit: p.RateLimitEnabled && p.RateLimitRPS > 0,
			HasGeoIP: hasGeoIP, HasCustomRules: p.Mode != "off" && customRulesCount > 0,
			AnomalyThreshold:   p.AnomalyThreshold,
			IPACLMode:          p.IPACLMode,
			IPACLEnabled:       p.IPACLEnabled,
			TrustDetection:     p.TrustDetection,
			Blocked24h:         blockedCounts[p.ID],
			Trigger24h:         triggerCounts[p.ID],
			IPWhitelistEnabled: p.IPWhitelistEnabled,
			IPACLList:          p.IPACLList,
			IPWhitelist:        rawJSONString(p.IPWhitelist),
			IPBlacklist:        rawJSONString(p.IPBlacklist),
			RateLimitRPS:       p.RateLimitRPS,
			RateLimitBurst:     p.RateLimitBurst,
			CRSExcludedCount:   loadedPolicies[i].crsExcludedCount,
			CRSRuleGroups:      p.CRSRuleGroups,
			CRSStaleSelections: services.CRSStaleGroupSelections(p.CRSRuleGroups, crsIndex),
			CustomRulesCount:   customRulesCount,
			// 阶段 3 判定口径（引用非空，含禁用条目）——前端与 G3 逐字对齐。
			CustomRulesRefCount: models.CustomRulesRefCount(p.CustomRules),
			UpdatedBy:           p.UpdatedBy,
			UpdatedAt:           p.UpdatedAt,
			GeoIPCountries:      rawJSONString(p.GeoIPCountries),
			GeoIPMode:           p.GeoIPMode,
			// 摘要必须携带爬虫豁免两列——列表编辑入口按摘要渲染
			// 回写时若缺席会把豁免静默关闭（详情 DTO 同修）。
			GeoIPCrawlerExempt:  p.GeoIPCrawlerExempt,
			GeoIPCrawlerEngines: rawJSONString(p.GeoIPCrawlerEngines),
			WAFCheckResponse:    p.WAFCheckResponse,
			LogRequestBody:      p.LogRequestBody,
			IPACLListRefs:       p.IPACLListRefs,
			IPWhitelistRefs:     p.IPWhitelistRefs,
			PolicyType:          p.PolicyType,
		})
	}
	if policies == nil {
		policies = []models.SecurityPolicySummary{}
	}
	// 策略行迭代失败显式报错：与 GetSecurityOverview 建立的「迭代失败
	// 显式 500」标准一致，部分列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: policies})
}

func (h *Handlers) GetSecurityPolicy(c *gin.Context) {
	id := c.Param("id")
	// 读路径补齐非规范数字 ID 家族门（SQLite 数值亲和使 '5.0' 命中
	// id=5）——与 Update/Delete/Split/Bind/Unbind 全部写路径同口径 400。
	if _, ok := parsePositiveNumericID(id); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略 ID 无效"})
		return
	}
	var p models.SecurityPolicy
	err := scanSecurityPolicyRow(db.DB.QueryRow(`SELECT `+securityPolicySelectColumns+` FROM security_policies WHERE id=?`, id), &p)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}

	var bindings []string
	rows, err := db.DB.Query("SELECT rule_caddy_id FROM security_policy_bindings WHERE policy_id=? ORDER BY rule_caddy_id ASC", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		bindings = append(bindings, b)
	}
	// 绑定迭代失败显式报错：对齐 ListSecurityPolicies/GetAllSecurityBindings
	// 的既有模式，残缺绑定列表不得以 200 返回。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if bindings == nil {
		bindings = []string{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"policy": newSecurityPolicyDetail(&p), "bindings": bindings}})
}

// policyQueryRower 抽象 *sql.DB 与 *sql.Tx 的查询能力，供引用校验在写事务内执行
// （三-3：校验+写入同事务，镜像 删除侧事务）。Query 供
// IP 列表引用的批量 IN 存在性检查（单次查询判定整批 id）。
type policyQueryRower interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// policyRowQueryer 抽象 *sql.DB 与 *sql.Tx 的带上下文单行查询能力，供 mixed
// 判定（rejectMixedPolicies）在写事务内执行。
type policyRowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// rejectMixedPolicies 判定给定策略 id 集合是否含 mixed（兼容旧版形态）。混合
// 策略仅可更新迁移（2026-09-20 用户裁定）：不得新绑定到规则——存量混合绑定
// 保持有效，迁移入口=策略页「更新迁移」（拆分单职策略）。四个写路径
// （BindRuleToPolicy / setRulePoliciesInTx / BatchBindSecurityPolicies /
// BulkUpdatePolicyBindings）此前各持一份判定，历史 收敛为单一实现。
// 返回非 nil msg=拒绝（调用方映射 400 原文案）；返回 err=数据库错误（映射 500）。
func rejectMixedPolicies(ctx context.Context, q policyRowQueryer, ids []int) (*string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	var mixedCount int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_policies WHERE policy_type='mixed' AND id IN ("+strings.Join(placeholders, ",")+")", args...).Scan(&mixedCount); err != nil {
		return nil, err
	}
	if mixedCount > 0 {
		msg := "混合策略为兼容旧版形态，仅支持「更新迁移」，不允许绑定规则"
		return &msg, nil
	}
	return nil, nil
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
		// 去重+单次 IN(镜像 validateIPListRefsExistence)
		// ——此前逐 ID COUNT 在 BEGIN IMMEDIATE 写锁内串行,重复 ID 数组可持锁
		// 数秒阻塞全部并发写。
		seen := make(map[int]struct{}, len(ids))
		unique := make([]int, 0, len(ids))
		for _, id := range ids {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			unique = append(unique, id)
		}
		// 32766 绑定变量上限分块(与 validateIPListRefsExistence 同型;
		// fail-closed——分块查询失败整体 500)。
		const chunkLimit = 500
		found := make(map[int]struct{}, len(unique))
		for start := 0; start < len(unique); start += chunkLimit {
			end := start + chunkLimit
			if end > len(unique) {
				end = len(unique)
			}
			chunk := unique[start:end]
			placeholders := make([]string, len(chunk))
			args := make([]interface{}, len(chunk))
			for i, id := range chunk {
				placeholders[i] = "?"
				args[i] = id
			}
			rows, err := q.Query("SELECT id FROM security_custom_rules WHERE id IN ("+strings.Join(placeholders, ",")+")", args...)
			if err != nil {
				return "", err
			}
			for rows.Next() {
				var fid int
				if err := rows.Scan(&fid); err != nil {
					rows.Close()
					return "", err
				}
				found[fid] = struct{}{}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return "", err
			}
		}
		for _, id := range unique {
			if _, ok := found[id]; !ok {
				return fmt.Sprintf("自定义规则不存在（id=%d）", id), nil
			}
		}
	}
	return "", nil
}

// normalizeEmptyJSONList 把「显式空串/空白」的 JSON 列归一为 "[]"——Create
// （值语义）与 Update（指针语义）共用同一 helper 与同一张字段表，避免两处
// 归一清单漂移（漏一处即库内同时出现 "" 与 "[]"，扫描/渲染/去重口径分叉）。
func normalizeEmptyJSONList(val *string) {
	if val != nil && strings.TrimSpace(*val) == "" {
		*val = "[]"
	}
}

// policyWhitelistDefault：Create 缺省（含旧客户端不传）视为启用——保持存量
// 「名单非空即生效」语义不回退。
func policyWhitelistDefault(v *bool) bool {
	return v == nil || *v
}

// validatePolicyReferenceExistence 是策略「引用存在性」的单源门序列：拦截页 +
// 自定义规则（validateSecurityPolicyReferences）、IP 名单 refs（ACL/信任，
// validateIPListRefsExistence）、CRS 排除作用域引用的名单
// （crsExcludedListRefs）。创建、更新（有效形态）与拆分迁移三处同门——拆分
// 是「新建策略」路径，子策略要落库的引用面必须与 Create 一样逐一存在，否则
// 悬空引用会让 ACL/信任合并集静默缩窄为 inline-only。
// 内置威胁名单禁令（validateBuiltinThreatListRefs）需 mode 的有效形态，
// 由各调用方在拿到 ACL 模式后单独调用。
// 查询在调用方事务内执行（与写入同锁，无校验-写入间 TOCTOU）。
func validatePolicyReferenceExistence(q policyQueryRower, blockPageID int, customRules, crsExcluded string, aclRefs, wlRefs []int64) (string, error) {
	if msg, err := validateSecurityPolicyReferences(q, blockPageID, customRules); err != nil || msg != "" {
		return msg, err
	}
	if msg, err := validateIPListRefsExistence(q, aclRefs, wlRefs); err != nil || msg != "" {
		return msg, err
	}
	if crsRefs := crsExcludedListRefs(crsExcluded); len(crsRefs) > 0 {
		if msg, err := validateIPListRefsExistence(q, crsRefs, nil); err != nil || msg != "" {
			return msg, err
		}
	}
	return "", nil
}

func (h *Handlers) CreateSecurityPolicy(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略写操作") {
		return
	}
	var req models.CreateSecurityPolicyRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略名称不能为空"})
		return
	}
	// DB 列无长度约束,超长名/描述随审计与列表响应放大。
	if utf8.RuneCountInString(req.Name) > securityNameMaxRunes {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略名称不能超过 100 字符"})
		return
	}
	if utf8.RuneCountInString(req.Description) > securityDescriptionMaxRunes {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略描述不能超过 500 字符"})
		return
	}
	if req.Mode == "" {
		req.Mode = "off"
	}
	// JSON 列空串归一单源（与 Update 同一 helper、同一张字段表）——库内不出现
	// "" 与 "[]" 并存，扫描/渲染/去重口径单一。
	for _, val := range []*string{
		&req.IPACLList, &req.IPWhitelist, &req.IPBlacklist,
		&req.CRSRuleGroups, &req.CRSExcludedRules, &req.CustomRules,
		&req.GeoIPCountries, &req.IPACLListRefs, &req.IPWhitelistRefs,
	} {
		normalizeEmptyJSONList(val)
	}
	if req.GeoIPMode == "" {
		// 门（services.ValidateGeoIPCountries：非 off + 空名单 =
		// 「宣称启用但零强制」→ 400）下的缺省归一：未显式启用地域控制且名单为空
		// 时落 off（与渲染端 PolicyHasGeoIP「条目非空才发射」等价，行为不变）；
		// 带名单时沿用 deny 缺省（口径）。
		if geoIPCountriesEmpty(req.GeoIPCountries) {
			req.GeoIPMode = "off"
		} else {
			req.GeoIPMode = "deny"
		}
	}
	// ip_acl_mode 与 geoip_mode 同口径归一：启用态 ACL 携带空模式
	// 落库后，发射端仅 allow/deny 分支产出规则——零 ACL 生效而 UI 宣称已启用。
	if req.IPACLMode == "" {
		req.IPACLMode = "deny"
	}

	// 策略实体单职化（2026-09-20 用户裁定「实体拆分」）：policy_type 可选——
	// 显式 stage1/stage2/stage3 时阶段外字段归一零值（类型与内容不漂移，
	// 归一先于内容校验）；缺省按归一后内容推断（models.InferPolicyType）；
	// 显式 mixed 拒绝（存量兼容组不可新建）。类型仅作编辑约束与分组元数据，
	// 渲染侧仍按功能字段发射（行为零变化）。
	policyType, typeErr := resolveCreatePolicyType(&req)
	if typeErr != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: typeErr.Error()})
		return
	}
	// trust_detection 仅 stage0（信任名单）策略消费——
	// 非 stage0 类型（显式或内容推断）恒写 0，写侧强制 models.SecurityPolicy
	// 「仅 stage0 消费；其他类型恒 0」契约，防跨阶段字段漂移落库。
	if policyType != models.PolicyTypeStage0 {
		req.TrustDetection = false
	}
	// CRS 载荷校验必须位于类型归一**之后**（与 Update 同口径）：显式阶段
	// 类型的归零矩阵会把阶段外 CRS 字段改写为 "[]"，先校验会拿本应被丢弃的
	// 载荷报 400（旧实现顺序相反，同一输入 POST 400 / PUT 200）。
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"crs_rule_groups", &req.CRSRuleGroups},
		{"crs_excluded_rules", &req.CRSExcludedRules},
	} {
		if err := validateAndNormalizeCRSField(f.name, f.val, true); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if err := validatePolicyCrawlerExemption(req.GeoIPCrawlerExempt, req.GeoIPCrawlerEngines, req.GeoIPMode); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
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
	// allow 模式 + 空生效名单：渲染端把空 allow 集照常并入交集，交集为空即
	// 发射「@rx .* 恒拒」——空名单的运行时语义是**拒绝全部（fail-closed）**，
	// 不是放行。写入侧 400（与 UI 守卫同口径）是防「一次保存锁死全站」的
	// UX 门，不是渲染语义的前提：绕过本门落库的形态仍按恒拒渲染。
	// 判定口径为「内联 ∪ 引用名单**实际条目**并集」——引用一个空名单同样是
	// 空生效集合。
	// 门控读必须位于 BEGIN IMMEDIATE 事务内（此前在事务外，
	// ImportConfigBackup 不持 caddyOpMu，可在校验与 INSERT 之间清空被引用
	// 名单，于是请求被拒却没有任何写入）——与 Update 的同口径。
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
	// 引用校验与写入必须同事务：校验通过后、
	// INSERT 之前并发的 DeleteSecurityCustomRule/DeleteSecurityBlockPage 提交（此时
	// 尚无启用策略引用，删除合法）会让写入的启用策略携带悬空引用，发射端仅日志
	// 跳过、WAF 规则静默丢失。写锁来自 DSN 的 _txlock=immediate（glebarez 驱动
	// 忽略 TxOptions.Isolation，非只读 BeginTx 一律 BEGIN IMMEDIATE）：校验 SELECT
	// 即持写锁，并发的删除无法在校验与 INSERT 之间提交。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	// 全局数量上限（与自定义规则/IP 名单 200 同族双限额口径）：计数与插入
	// 同事务同锁（BEGIN IMMEDIATE），查询失败 fail-closed——无上限时导入/API
	// 可无界增长，列表按策略逐行消费（每策略 N 次查询 + 事件归因扫描）。
	var policyCount int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_policies").Scan(&policyCount); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计安全策略数量失败"})
		return
	}
	if policyCount >= securityPolicyMaxGlobalCount {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("安全策略总数已达上限（%d 条），请先清理不再使用的策略", securityPolicyMaxGlobalCount)})
		return
	}
	// 引用存在性单源门（拦截页 + 自定义规则 + IP 名单 refs + CRS 排除作用域
	// 名单）：校验与写入必须同事务，见下方 BEGIN IMMEDIATE 说明。
	if msg, err := validatePolicyReferenceExistence(tx, req.BlockPageID, req.CustomRules, req.CRSExcludedRules, aclRefsIDs, wlRefsIDs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	// 内置威胁名单引用门禁（2026-09-24 用户裁定）：system=1 名单仅允许
	// IP ACL 黑名单（deny）引用；信任名单/白名单模式/CRS 排除一律拒绝。
	if msg, err := validateBuiltinThreatListRefs(tx, aclRefsIDs, wlRefsIDs, crsExcludedListRefs(req.CRSExcludedRules), req.IPACLMode); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	// 门（事务内）：BEGIN IMMEDIATE 后读即持写锁，并发
	// ImportConfigBackup/名单清空无法在校验与 INSERT 之间提交。
	if req.IPACLEnabled && req.IPACLMode == "allow" {
		nonEmpty, gerr := allowEffectiveListNonEmpty(tx, req.IPACLList, req.IPACLListRefs)
		if gerr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("校验 IP 列表引用失败", gerr)})
			return
		}
		if !nonEmpty {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "白名单模式下生效 IP 列表不能为空（内联条目与所引用名单均无条目；空名单会拒绝所有请求、全站锁死）"})
			return
		}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	result, err := tx.ExecContext(caddyWriteCtx(c), `INSERT INTO security_policies (name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_whitelist_enabled, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, geoip_countries, geoip_mode, geoip_crawler_exempt, geoip_crawler_engines, waf_check_response, log_request_body, ip_acl_list_refs, ip_whitelist_refs, updated_by, policy_type, trust_detection)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		req.Name, req.Description, req.Mode, max1(req.AnomalyThreshold, 5), req.IPACLMode, req.IPACLList, req.IPACLEnabled, req.IPWhitelist, policyWhitelistDefault(req.IPWhitelistEnabled), req.IPBlacklist,
		req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst, req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules, req.BlockPageID, req.BlockStatusCode, enabled, req.GeoIPCountries, req.GeoIPMode, crawlerExemptBool(req.GeoIPCrawlerExempt, policyType != models.PolicyTypeStage0 && req.GeoIPMode != "off"), crawlerEnginesJSON(req.GeoIPCrawlerEngines), req.WAFCheckResponse, req.LogRequestBody, req.IPACLListRefs, req.IPWhitelistRefs, int(contextUserID(c)), policyType, req.TrustDetection)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	id, _ := result.LastInsertId()
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "创建",
		AuditDetail: fmt.Sprintf("名称：%s（#%d）", req.Name, id),
		SuccessMsg:  "安全策略创建成功",
		Data:        gin.H{"id": id},
	})
}

// geoipEntriesEqual：比较两个 geoip_countries JSON 数组的
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

// validateCRSLegacyEntryCharset 旧 []string 载荷的单条基础校验
// 空条目与字符集白名单（字母/数字/. /_/-）在 crs_rule_groups 与
// crs_excluded_rules 完全一致——此前两处循环逐字重复，新增字符规则需双改且
// 漏改即校验分叉。返回 trim 后的值供调用方做形态检查。
func validateCRSLegacyEntryCharset(fieldLabel, entry string) (string, error) {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return "", fmt.Errorf("%s 条目不能为空", fieldLabel)
	}
	for _, r := range trimmed {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("%s 条目含非法字符（仅允许字母、数字、.、_、-）: %q", fieldLabel, entry)
	}
	return trimmed, nil
}

// validateCRSLegacyEntryNoSurroundingSpace 首尾空白校验
// 调用方在形态检查之后调用，保持「942 」仍先报组号形态错误的既有报错优先级。
func validateCRSLegacyEntryNoSurroundingSpace(fieldLabel, entry, trimmed string) error {
	if trimmed != entry {
		return fmt.Errorf("%s 条目不能包含首尾空白: %q", fieldLabel, entry)
	}
	return nil
}

// validateAndNormalizeCRSField 统一 Create/Update 两条路径的 crs_* 形状校验：
// 空串按归一为 "[]"，非空必须是合法载荷（防发射端解析失败静默置空）。
// crs_rule_groups：两位组号（进入 Include glob REQUEST-9<code>-*.conf）∪ 6 位
// CRS 规则 ID（须存在于本地规则索引，陈旧 → 400）。crs_excluded_rules：双格式
// ——旧 []string 沿用既有门（现状兼容，不加索引校验），新 []对象走
// validateCRSExcludedRulesPayload（组号/ID 存在性、scope 互斥字段、≤50 条）。
// checkIndices=false 仅用于备份导入「本次同时替换 CRS 规则树」的场景
// 此时 live 索引与落地后的规则树不是同一代，
// 存在性校验会误拒可自愈的旧备份；形状/字符集/初始化组守卫照常执行。
func validateAndNormalizeCRSField(name string, val *string, checkIndices bool) error {
	if val == nil {
		return nil
	}
	if strings.TrimSpace(*val) == "" {
		*val = "[]"
		return nil
	}
	if name == "crs_excluded_rules" {
		return validateCRSExcludedRulesPayload(val, checkIndices)
	}
	var entries []string
	if err := json.Unmarshal([]byte(*val), &entries); err != nil {
		return fmt.Errorf("%s 需为 JSON 数组字符串", name)
	}
	// crs_rule_groups 条数上限（与 crs_excluded_rules 50 条同族限量）：
	// 超大数组放大配置体积与生成时间，UI 选择器真实规模远低于 200。
	if name == "crs_rule_groups" && len(entries) > services.CRSRuleGroupsMaxEntries {
		return fmt.Errorf("%s 条目不能超过 %d 条", name, services.CRSRuleGroupsMaxEntries)
	}
	var index *services.CRSRuleIndex
	for _, entry := range entries {
		trimmed, err := validateCRSLegacyEntryCharset(name, entry)
		if err != nil {
			return err
		}
		// / 混合选择：组号恒为两位数字（发射端拼接 REQUEST-9<code>-*.conf）
		// 或 6 位 CRS 规则 ID（经本地索引定位父文件 Include + 补删）。"941"、
		// "REQUEST-942" 这类写法会 glob 零匹配——coraza 对空 Include 静默接受，
		// blocking 模式将无任何 CRS 规则生效且无任何报错。
		if name == "crs_rule_groups" && !services.IsCRSGroupCode(trimmed) {
			if !services.IsCRSRuleIDTarget(trimmed) {
				return fmt.Errorf("%s 条目必须是两位数字组号（如 942 组填 \"42\"）或 6 位 CRS 规则 ID（如 \"942100\"）: %q", name, entry)
			}
			if checkIndices {
				if index == nil {
					index = services.GetCRSRuleIndex()
				}
				if !index.Has(trimmed) {
					return fmt.Errorf("规则 ID 不存在于当前 CRS: %q", entry)
				}
			}
		}
		// 首尾空白条目（" 42"/"\t42"）trim 后能通过以上检查，但发射端
		// 拼接 glob 用原始值会产生零匹配——校验与发射必须对同一形态达成一致。
		// 放在形态检查之后："942 " 这类条目仍报组号形态错误。
		if err := validateCRSLegacyEntryNoSurroundingSpace(name, entry, trimmed); err != nil {
			return err
		}
		if name == "crs_rule_groups" && services.IsCRSGroupCode(trimmed) && !services.IsCRSInfraGroupCode(trimmed) && checkIndices {
			if index == nil {
				index = services.GetCRSRuleIndex()
			}
			if !index.HasGroup(trimmed) {
				return fmt.Errorf("规则组不存在于当前 CRS: %q", entry)
			}
		}
	}
	// 写入面规范化（v2.2.3）：剥离基础设施组（901/949/959 组号及其文件内
	// 规则 ID）——它们由发射面强制包含，开放配置只会制造「忘选即静默失效」的
	// 陷阱；剥离即「始终生效」的诚实表达。剥离后为空等价显式空选（"[]"=全量
	// glob），至少是一个可工作的策略，优于「仅选初始化组」的空转配置。
	if name == "crs_rule_groups" {
		// 去重（与渲染面 seenGroup 同口径）：重复组号/ID 会产生重复
		// Include，coraza 对重复注册规则 ID 直接编译拒绝。
		entries = services.DedupeCRSGroupEntries(entries)
		kept := entries[:0]
		for _, entry := range entries {
			if services.IsCRSInfraGroupCode(entry) || services.IsCRSInfraRuleID(entry) {
				continue
			}
			kept = append(kept, entry)
		}
		normalized, err := json.Marshal(kept)
		if err != nil {
			return fmt.Errorf("%s 规范化失败: %w", name, err)
		}
		*val = string(normalized)
	}
	return nil
}

// validateCRSExcludedRulesPayload 校验 crs_excluded_rules 双格式载荷（空串已在
// 调用方归一为 "[]"）。旧 []string 走字符集 + 首尾空白 +
// services.CRSExcludedEntryEffective 发射门，与发射端 scope=all 路径同款；
// checkIndices=true 时两位组号/6 位 ID 与新格式同一道索引存在性门（陈旧
// 排除永不命中=过度拦截方向的静默失效）。新 []对象逐条校验 target/scope/
// ips/listRefs；完全相同条目由读侧归一去重，此处放行。引用的 IP 列表存在性
// 在同事务内由 validateIPListRefsExistence 单批校验（见 crsExcludedListRefs 调用点）。
func validateCRSExcludedRulesPayload(val *string, checkIndices bool) error {
	raw := *val
	var legacy []string
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil {
		// checkIndices=true 时旧格式与新格式同一门：两位组号/6 位 ID 必须
		// 存在于本地规则索引——陈旧 ID 落库后排除永不命中（用户以为已放行
		// 某类流量，实际仍被拦），属「过度拦截」方向的静默失效。文件名形态
		// 无法按组粒度核对存在性，维持形状门。checkIndices=false（导入同时
		// 替换 CRS 树）豁免通道承接可自愈的旧备份。
		var index *services.CRSRuleIndex
		for _, entry := range legacy {
			trimmed, err := validateCRSLegacyEntryCharset("crs_excluded_rules", entry)
			if err != nil {
				return err
			}
			// → 收紧：排除项必须是发射端实际会发射的
			// 形态（services.CRSExcludedEntryEffective——CRS 规则 ID「纯数字/
			// 数字-数字，900000-999999」或 CRS 文件名「REQUEST-9XX-*.conf」，文件
			// 名经 crsFilenameToRuleIDRange 映射为 ID 区间）。
			if err := validateCRSLegacyEntryNoSurroundingSpace("crs_excluded_rules", entry, trimmed); err != nil {
				return err
			}
			if !services.CRSExcludedEntryEffective(entry) {
				return fmt.Errorf("crs_excluded_rules 条目必须是 CRS 规则 ID（如 \"942100\"）或规则文件名（如 \"REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"）: %q", entry)
			}
			// 排除守卫：基础设施组（901 初始化/949 请求评估/959 响应评估）由
			// 发射面强制包含——排除初始化会让守卫按 0 整段跳过、策略空转；
			// 排除 949/959 会让拦截模式静默退化为仅记录。无合法用途，保存即拒。
			if services.CRSExclusionTargetRemovesInfra(entry) {
				return fmt.Errorf("crs_excluded_rules 条目 %q 命中基础设施规则组（901 初始化 / 949 请求评估 / 959 响应评估）：这些规则为系统强制加载，不能排除", entry)
			}
			if checkIndices {
				if index == nil {
					index = services.GetCRSRuleIndex()
				}
				if services.IsCRSGroupCode(trimmed) {
					if !index.HasGroup(trimmed) {
						return fmt.Errorf("规则组不存在于当前 CRS: %q", entry)
					}
				} else if services.IsCRSRuleIDTarget(trimmed) && !index.Has(trimmed) {
					return fmt.Errorf("规则 ID 不存在于当前 CRS: %q", entry)
				}
			}
		}
		return nil
	}
	var entries []services.CRSExcludedEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("crs_excluded_rules 需为 JSON 数组字符串")
	}
	if len(entries) > services.CRSExcludedRulesMaxEntries {
		return fmt.Errorf("crs_excluded_rules 条目不能超过 %d 条", services.CRSExcludedRulesMaxEntries)
	}
	var index *services.CRSRuleIndex
	for i, entry := range entries {
		target := strings.TrimSpace(entry.Target)
		if target == "" {
			return fmt.Errorf("crs_excluded_rules 条目 #%d 的 target 不能为空", i+1)
		}
		for _, r := range target {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
				continue
			}
			return fmt.Errorf("crs_excluded_rules 条目 #%d 的 target 含非法字符（仅允许字母、数字、.、_、-）: %q", i+1, entry.Target)
		}
		// 同口径：首尾空白在校验/发射两侧对同一形态达成一致。
		if target != entry.Target {
			return fmt.Errorf("crs_excluded_rules 条目 #%d 的 target 不能包含首尾空白: %q", i+1, entry.Target)
		}
		scope := entry.Scope
		if scope == "" {
			scope = "all"
		}
		switch scope {
		case "all", "ip", "list":
		default:
			return fmt.Errorf("crs_excluded_rules 条目 #%d 的 scope 无效：%q（可选：all、ip、list）", i+1, entry.Scope)
		}
		if services.IsCRSGroupCode(target) {
			if checkIndices {
				if index == nil {
					index = services.GetCRSRuleIndex()
				}
				if !index.HasGroup(target) {
					return fmt.Errorf("规则组不存在于当前 CRS: %q", entry.Target)
				}
			}
		} else if services.IsCRSRuleIDTarget(target) {
			if checkIndices {
				if index == nil {
					index = services.GetCRSRuleIndex()
				}
				if !index.Has(target) {
					return fmt.Errorf("规则 ID 不存在于当前 CRS: %q", entry.Target)
				}
			}
		} else if !services.CRSExcludedEntryEffective(target) {
			return fmt.Errorf("crs_excluded_rules 条目 #%d 必须是两位组号、CRS 规则 ID（如 \"942100\"）或规则文件名（如 \"REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"）: %q", i+1, entry.Target)
		} else if scope != "all" {
			// 作用域限定走运行时 ctl:ruleRemoveById 逐 ID 展开，遗留文件名/区间
			// 形态（映射为 ID 区间）无法展开——保存即拒，与发射端能力对齐。
			return fmt.Errorf("crs_excluded_rules 条目 #%d：target %q 为文件名/区间形态，仅支持 scope=all（作用域限定请使用两位组号或 6 位规则 ID）", i+1, entry.Target)
		}
		// 排除守卫：基础设施组（901 初始化/949 请求评估/959 响应评估）由发射面
		// 强制包含——排除初始化会让守卫按 0 整段跳过、策略空转；排除 949/959
		// 会让拦截模式静默退化为仅记录。无合法用途，保存即拒。
		if services.CRSExclusionTargetRemovesInfra(target) {
			return fmt.Errorf("crs_excluded_rules 条目 #%d 命中基础设施规则组（901 初始化 / 949 请求评估 / 959 响应评估）：这些规则为系统强制加载，不能排除", i+1)
		}
		ips := strings.TrimSpace(entry.IPs)
		switch scope {
		case "ip":
			if ips == "" {
				return fmt.Errorf("crs_excluded_rules 条目 #%d：scope=ip 必须填写 ips（逗号分隔的 IP/CIDR）", i+1)
			}
		case "list":
			if len(entry.ListRefs) == 0 {
				return fmt.Errorf("crs_excluded_rules 条目 #%d：scope=list 必须填写 listRefs（IP 地址列表 id）", i+1)
			}
		case "all":
			if ips != "" || len(entry.ListRefs) > 0 {
				return fmt.Errorf("crs_excluded_rules 条目 #%d：scope=all 不允许携带 ips/listRefs", i+1)
			}
		}
		for _, item := range strings.Split(entry.IPs, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !validIPOrCIDR(item) {
				return fmt.Errorf("crs_excluded_rules 条目 #%d 包含无效的 IP/CIDR：%s", i+1, item)
			}
		}
	}
	return nil
}

// crsExcludedListRefs 从 crs_excluded_rules 载荷收集全部引用的 IP 列表 id（去重；
// 旧格式/解析失败 → nil）。存在性校验与 ip_acl_list_refs 共用
// validateIPListRefsExistence（同事务单批 IN 查询）。
func crsExcludedListRefs(payload string) []int64 {
	var refs []int64
	seen := make(map[int64]struct{})
	for _, entry := range services.ParseCRSExcludedRules(payload) {
		for _, id := range entry.ListRefs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refs = append(refs, id)
		}
	}
	return refs
}

func (h *Handlers) UpdateSecurityPolicy(c *gin.Context) {
	// 导入窗口 fast-fail：security_policies 在导入全量替换清单内，且 Update
	// 取 caddyOpMu 只串行不 fast-fail——排队到导入提交后会按陈旧 id 把刚恢复
	// 的策略覆盖成本请求的旧表单（CRS 组/排除规则/限流/名单引用被静默弱化）。
	if rejectWriteDuringImport(c, "执行安全策略写操作") {
		return
	}
	id := c.Param("id")
	if _, ok := parsePositiveNumericID(id); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略 ID 无效"})
		return
	}
	var req models.UpdateSecurityPolicyRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略名称不能为空"})
		return
	}
	// 更新侧同封顶(指针字段仅在提供时校验)。
	if req.Name != nil && utf8.RuneCountInString(*req.Name) > securityNameMaxRunes {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略名称不能超过 100 字符"})
		return
	}
	if req.Description != nil && utf8.RuneCountInString(*req.Description) > securityDescriptionMaxRunes {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略描述不能超过 500 字符"})
		return
	}
	// 显式空串按 Create 口径归一为 "[]"，保持列形状一致，避免库内 "" 与
	// "[]" 并存。**必须先归一后校验**（与 Create 同序）：空白串/空串先被
	// 归一为 "[]" 才能通过 CIDR 与 CRS 形状校验，旧顺序让同一输入 POST 200 /
	// PUT 400。GeoIPCountries 同口径。
	for _, val := range []**string{&req.IPACLList, &req.IPWhitelist, &req.IPBlacklist, &req.IPACLListRefs, &req.IPWhitelistRefs, &req.GeoIPCountries} {
		if *val != nil {
			normalizeEmptyJSONList(*val)
		}
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
	// 显式空串会把枚举列清空：mode 为 "" 时汇总口径（mode!="off" 即计入 WAF）
	// 与发射口径（仅 blocking/detection 生效）随即漂移；geoip_mode 在创建时已
	// 归一为 allow/deny，空串属于域外值。不修改请直接省略字段，而不是传空串。
	// ip_acl_mode 同口径：空串落库后发射端仅 allow/deny 分支产出
	// 规则、零 ACL 生效，而 SecurityPolicyHasIPControl 仍按 enabled+list 非空
	// 宣称 IP 访问控制已启用。
	// 策略实体单职化（同 Create 口径）：显式 policy_type=stage1/2/3 → 阶段外
	// 字段指针强制设为类型零值（UPDATE 随之落零）；显式 mixed 拒绝；非法值
	// 拒绝。nil=按合并后内容重推断（Exec 后读合并行回写）。
	if req.PolicyType != nil {
		switch *req.PolicyType {
		case "":
			// 空串等价「未提供」：GET 详情对 '' 存量行（导入/旧快照遗留）回传
			// policy_type:""，机器客户端 GET→PUT 回写时不得被 400 拒绝。
			// 置 nil 后走下方「按合并后内容重推断」路径，与 Create 的
			// case "" 同口径（面板编辑器总提交显式类型，不受影响）。
			req.PolicyType = nil
		case models.PolicyTypeStage0, models.PolicyTypeStage1, models.PolicyTypeStage2, models.PolicyTypeStage3:
			// 矛盾载荷显式拒绝，先于归零（与 Create 同口径）：静默归零后 200
			// 会让调用方以为阶段外字段已生效。
			if msg := updateOutOfStageConflict(&req, *req.PolicyType); msg != "" {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
				return
			}
			// 阶段外字段归零矩阵单源（outOfStageZeroFamilies）——
			// Create/Update 共用同一份描述，逐字段赋值见 applyStageZerosToUpdate。
			applyStageZerosToUpdate(&req, *req.PolicyType)
		case models.PolicyTypeMixed:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "混合策略为存量兼容形态，不可显式设置"})
			return
		default:
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("无效的策略类型：%s（可选 stage1/stage2/stage3）", *req.PolicyType)})
			return
		}
	}
	// refs 派生 ID 必须在类型归一**之后**解析——显式类型切换会把
	// 阶段外 refs 指针改写为 "[]"，旧顺序仍用切换前的 ID 做存在性/内置名单
	// 校验，合法的类型转换会因已被合法删除的列表而 400。此处按归一后的
	// 请求值重算（nil 字段保持 nil→不参与校验）。
	var aclRefsIDs, wlRefsIDs []int64
	for _, f := range []struct {
		name string
		val  *string
		ids  *[]int64
	}{
		{"ip_acl_list_refs", req.IPACLListRefs, &aclRefsIDs},
		{"ip_whitelist_refs", req.IPWhitelistRefs, &wlRefsIDs},
	} {
		*f.ids = nil
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
	// anomaly_threshold 显式 0 按创建侧口径归一为 5：0 非合法枚举值。
	// 写侧归一即可——带外写入 <=0 的行由渲染层显性拒绝生成整份配置
	// （services/security.go buildCorazaDirectivesWithIndex 的
	// AnomalyThreshold <= 0 分支），
	// 不会静默回落到 CRS 默认阈值，也不会出现「UI 显示 0 但实际按 5 生效」。
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
	// 下方三处门控读(限流/ allow/GeoIP)原以裸连接
	// db.DB 读取,位于 BeginTx 之前——与同函数事务内读的标准漂移;
	// ImportConfigBackup 不持 caddyOpMu,构成并发写者, 窗口可落
	// allow+启用+空名单。三读移入 BEGIN IMMEDIATE 事务内,
	// 校验 SELECT 即持写锁,消除 TOCTOU(同三-3 镜像方向)。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	// 存量行单次读取：本端点在写锁内要拿同一策略行的六组字段（限流 / ACL /
	// GeoIP / 引用 / 类型 / 审计 delta 基准），此前按门逐列各读一遍——同一行
	// 读 10 次（含 3 次全列扫描），整段都在 BEGIN IMMEDIATE 写锁内。收敛为
	// 事务开头一次 33 列投影，写后只保留必需的终态读（重推断 / 状态码归一 /
	// 审计名）。写锁已持，单次读与后续校验、审计基准零竞态。
	var stored models.SecurityPolicy
	if err := scanSecurityPolicyRow(tx.QueryRowContext(caddyWriteCtx(c), `SELECT `+securityPolicySelectColumns+` FROM security_policies WHERE id=?`, id), &stored); err != nil {
		// 不存在 404 / 其余 500（各门吞错会把读取失败误报成 400）。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取策略现值失败"})
		}
		return
	}
	// 限流门改用有效值(请求缺失回落存量),与门同口径
	// ——此前 deref 裸值使部分重启用误报 400/rps=0 落库为宣称启用实际零强制。
	{
		effRLEnabled, effRPS, effBurst := stored.RateLimitEnabled, stored.RateLimitRPS, stored.RateLimitBurst
		if req.RateLimitEnabled != nil {
			effRLEnabled = *req.RateLimitEnabled
		}
		if req.RateLimitRPS != nil {
			effRPS = *req.RateLimitRPS
		}
		if req.RateLimitBurst != nil {
			effBurst = *req.RateLimitBurst
		}
		if err := validateRateLimitShape(fmt.Sprintf("id=%s", id), effRLEnabled, effRPS, effBurst); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	// 同 Create：生效配置（请求值缺失时回落存量）为 allow+启用+空合并名单时
	// 400——渲染端空 allow 集是恒拒（fail-closed），本门的作用是防止把「锁死
	// 全站」的策略存进库，属 UX 门而非渲染语义的前提。门控读与 Create 一样
	// 必须在 BEGIN IMMEDIATE 事务内（校验与写入之间被并发清空所引用名单同属
	// 该窗口）。
	{
		effEnabled := stored.IPACLEnabled
		if req.IPACLEnabled != nil {
			effEnabled = *req.IPACLEnabled
		}
		effMode := stored.IPACLMode
		if ipACLMode != "" {
			effMode = ipACLMode
		}
		if effEnabled && effMode == "allow" {
			effList, effRefs := stored.IPACLList, stored.IPACLListRefs
			if req.IPACLList != nil {
				effList = *req.IPACLList
			}
			if req.IPACLListRefs != nil {
				effRefs = *req.IPACLListRefs
			}
			// 生效集合 = 内联 ∪ 引用名单实际条目（引用空名单同样为空）。
			nonEmpty, gerr := allowEffectiveListNonEmpty(tx, effList, effRefs)
			if gerr != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("校验 IP 列表引用失败", gerr)})
				return
			}
			if !nonEmpty {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "白名单模式下生效 IP 列表不能为空（内联条目与所引用名单均无条目；空名单会拒绝所有请求、全站锁死）"})
				return
			}
		}
	}
	// 存量读取复用事务开头的单次投影——翻转门需要存量 mode,
	// 且「只改 mode 不带条目」的更新同样要过 GeoIP 可用性门。
	storedGeoIP := rawJSONString(stored.GeoIPCountries)
	storedGeoIPMode := stored.GeoIPMode
	storedCrawlerExempt := stored.GeoIPCrawlerExempt
	storedCrawlerEngines := rawJSONString(stored.GeoIPCrawlerEngines)
	effectiveGeoIPMode := storedGeoIPMode
	if req.GeoIPMode != nil && *req.GeoIPMode != "" {
		effectiveGeoIPMode = *req.GeoIPMode
	}
	// 翻转门:off→非 off 时无论条目是否随请求、是否变化,一律过
	// live 校验(缺库不得启用)——「缺库时不得启用」优先于「未变更字段可
	// 编辑」豁免;条目取请求值??存量值。
	modeFlippedOn := storedGeoIPMode == "off" && effectiveGeoIPMode != "off"
	skipGeoIPValidation := false
	if !modeFlippedOn && req.GeoIPCountries != nil {
		// 地域条目与存量完全相同的更新跳过 live 校验——裁决
		// 语义是「缺库时不得启用」而非「缺库时不得编辑未变更字段」;条目真正变化
		// 时才落 fail-closed 门(缺库时改描述/开关不再 400)。
		skipGeoIPValidation = geoipEntriesEqual(*req.GeoIPCountries, storedGeoIP)
	}
	if !skipGeoIPValidation && (req.GeoIPCountries != nil || modeFlippedOn) {
		effCountries := storedGeoIP
		if req.GeoIPCountries != nil {
			effCountries = *req.GeoIPCountries
		}
		if err := services.ValidateGeoIPCountries(effCountries, effectiveGeoIPMode); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	// v2.3.8 爬虫豁免（更新路径）：生效值=请求值覆盖存量（nil=保持）。
	// geoip 关闭且调用方未显式提交豁免位时，同步清除存量 orphan 位；
	// engines 单独提交也走注册表/JSON 校验，空串与 Create 同归一为默认集。
	effectiveCrawlerExempt := storedCrawlerExempt
	if req.GeoIPCrawlerExempt != nil {
		effectiveCrawlerExempt = *req.GeoIPCrawlerExempt
	}
	if effectiveGeoIPMode == "off" && req.GeoIPCrawlerExempt == nil && effectiveCrawlerExempt {
		falseVal := false
		req.GeoIPCrawlerExempt = &falseVal
		effectiveCrawlerExempt = false
	}
	if req.GeoIPCrawlerEngines != nil {
		normalized := crawlerEnginesJSON(*req.GeoIPCrawlerEngines)
		req.GeoIPCrawlerEngines = &normalized
	}
	if req.GeoIPCrawlerExempt != nil || req.GeoIPCrawlerEngines != nil || (req.GeoIPMode != nil && effectiveCrawlerExempt) {
		effEngines := storedCrawlerEngines
		if req.GeoIPCrawlerEngines != nil {
			effEngines = *req.GeoIPCrawlerEngines
		}
		if err := validatePolicyCrawlerExemption(effectiveCrawlerExempt, effEngines, effectiveGeoIPMode); err != nil {
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
	// 引用存在性校验：显式提供的 block_page_id / custom_rules / IP 名单 refs
	// 必须指向存在的目标；未提供的字段不参与校验（保持存量列不变）。
	// crs_excluded_rules 的作用域名单在下方按显式提供口径单独校验。
	if msg, err := validatePolicyReferenceExistence(tx, derefInt(req.BlockPageID), derefStr(req.CustomRules), "", aclRefsIDs, wlRefsIDs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	// 重启用悬空引用门——仅含 {enabled:true} 的部分更新（REST 文档明示
	// 「只提交需要修改的字段」）不携带 block_page_id/custom_rules，derefInt/derefStr
	// 零值使上面的校验整体短路；禁用期间被删除的规则/拦截页（删除门只拦 enabled=1
	// 的策略）会随重启用静默激活：发射端仅 warn 跳过、WAF 规则静默丢失、拦截页
	// 退回 Caddy 默认错误页。指向启用的更新按「显式值 ?? 存量值」的有效形态过
	// 同一校验器；写锁已持（BEGIN IMMEDIATE），无 TOCTOU。
	if req.Enabled != nil && *req.Enabled {
		effectiveBlockPageID := derefInt(req.BlockPageID)
		if req.BlockPageID == nil {
			effectiveBlockPageID = stored.BlockPageID
		}
		effectiveCustomRules := derefStr(req.CustomRules)
		if req.CustomRules == nil {
			effectiveCustomRules = rawJSONString(stored.CustomRules)
		}
		if msg, err := validateSecurityPolicyReferences(tx, effectiveBlockPageID, effectiveCustomRules); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
		// IP 列表引用同口径：显式值 ?? 存量值的有效形态过同一校验器（禁用期间
		// 被删除的列表不得随重启用静默悬空）。
		effectiveACLRefs, effectiveWLRefs := aclRefsIDs, wlRefsIDs
		if req.IPACLListRefs == nil {
			effectiveACLRefs = parseIPListRefsIDs(stored.IPACLListRefs)
		}
		if req.IPWhitelistRefs == nil {
			effectiveWLRefs = parseIPListRefsIDs(stored.IPWhitelistRefs)
		}
		if msg, err := validateIPListRefsExistence(tx, effectiveACLRefs, effectiveWLRefs); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
		// crs_excluded_rules 的 scope=ip/list 引用同属有效引用面
		// （DeleteIPList 的引用扫描已计入；重启用门此前漏查 → 禁用期间被删的
		// 列表随重启用静默悬空，发射端仅 warn 跳过）。
		effectiveCRSExcluded := rawJSONString(stored.CRSExcludedRules)
		if req.CRSExcludedRules != nil {
			effectiveCRSExcluded = *req.CRSExcludedRules
		}
		if msg, err := validateIPListRefsExistence(tx, crsExcludedListRefs(effectiveCRSExcluded), nil); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
	}
	// crs_rule_groups / crs_excluded_rules：显式空串按 Create 口径归一为 "[]"，
	// 非空值必须是合法载荷（组号/规则 ID/文件名或新格式对象数组），防止任意串
	// 直写列后在发射端解析失败。
	for _, f := range []struct {
		name string
		val  *string
	}{
		{"crs_rule_groups", req.CRSRuleGroups},
		{"crs_excluded_rules", req.CRSExcludedRules},
	} {
		if err := validateAndNormalizeCRSField(f.name, f.val, true); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	// crs_excluded_rules 作用域条目引用的 IP 列表存在性：仅校验显式提供的
	// 载荷（同事务单批，与上方 ip_acl_list_refs 同口径）；悬空引用的源头由
	// DeleteIPList 的引用扫描拦截。
	if req.CRSExcludedRules != nil {
		if msg, err := validateIPListRefsExistence(tx, crsExcludedListRefs(*req.CRSExcludedRules), nil); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
	}
	// 内置威胁名单引用门禁（2026-09-24 用户裁定，update 口径）：system=1 名单
	// 仅允许 IP ACL 黑名单（deny）引用。请求值 ?? 存量值合并后判定——只改模式
	// （deny→allow）而存量引用携带内置名单、或只改引用为内置名单而存量模式为
	// allow，都必须拦截。
	if req.IPACLListRefs != nil || req.IPWhitelistRefs != nil || req.IPACLMode != nil || req.CRSExcludedRules != nil {
		effMode := stored.IPACLMode
		if ipACLMode != "" {
			effMode = ipACLMode
		}
		effACLRefs, effWLRefs := aclRefsIDs, wlRefsIDs
		if req.IPACLListRefs == nil {
			effACLRefs = parseIPListRefsIDs(stored.IPACLListRefs)
		}
		if req.IPWhitelistRefs == nil {
			effWLRefs = parseIPListRefsIDs(stored.IPWhitelistRefs)
		}
		var effCRSRefs []int64
		if req.CRSExcludedRules != nil {
			effCRSRefs = crsExcludedListRefs(*req.CRSExcludedRules)
		} else {
			// 未提交 CRS 排除列表时按存量判定：只改 ip_acl_mode=allow 的请求
			// 仍须看到存量 scope=ip/list 引用的内置名单（否则「先存内置名单、
			// 后翻模式」可绕过禁令）。
			effCRSRefs = crsExcludedListRefs(rawJSONString(stored.CRSExcludedRules))
		}
		if msg, err := validateBuiltinThreatListRefs(tx, effACLRefs, effWLRefs, effCRSRefs, effMode); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
	}
	// 阶段外 ACL 启用门：显式 stage0/2/3 策略且自身阶段特征在位
	// （信任/限流/WAF 内容非空）时，PUT {ip_acl_enabled:true} 会使与原
	// 阶段特征并存→重推断把类型改写 mixed（类型与内容漂移）——UPDATE 前
	// 拒绝。空壳单职策略（无任何阶段特征，落推断零组桶 stage3）首次启用
	// ACL 走既有重推断路径（单组→stage1 或维持零组桶），不拦；stage1 是
	// ACL 所属阶段不拦；mixed/空串存量兼容态保持现状。指针语义：nil（缺省）
	// 与显式 false 均不拦；存量 ACL 已启用时真值为幂等不拦。
	if req.IPACLEnabled != nil && *req.IPACLEnabled {
		if !stored.IPACLEnabled {
			// 门条件按有效类型（effType=显式 policy_type ?? 存量类型）+「合并后
			// 终态特征」判定：特征集必须取「存量行叠加本请求」的合并模型——
			// 同一请求内关停自身阶段特征（如 stage2 限流 enabled:false/rps:0、
			// stage3 mode:off）再启用 ACL 时，合并终态只剩 G1，重推断落
			// stage1 不产生 mixed 漂移，按存量特征误拒会把一步合法转换卡死。
			// 显式切换 stage1 时阶段外字段已由归零矩阵落零（req 指针即零值，
			// 叠加后合并模型自然反映），一步「类型切换+启用 ACL」不误拒；
			// 自身阶段特征在合并后仍在位（缺省类型不动限流/WAF）才拦——
			// 该形态 UPDATE 后会重推断成 mixed（类型与内容漂移）。
			effType := stored.PolicyType
			if req.PolicyType != nil {
				effType = *req.PolicyType
			}
			merged := stored
			merged.IPACLEnabled = true // 本分支语义即「启用 ACL」
			if req.IPACLList != nil {
				merged.IPACLList = *req.IPACLList
			}
			if req.IPACLListRefs != nil {
				merged.IPACLListRefs = *req.IPACLListRefs
			}
			if req.IPWhitelistEnabled != nil {
				merged.IPWhitelistEnabled = *req.IPWhitelistEnabled
			}
			if req.IPWhitelist != nil {
				merged.IPWhitelist = json.RawMessage(*req.IPWhitelist)
			}
			if req.IPWhitelistRefs != nil {
				merged.IPWhitelistRefs = *req.IPWhitelistRefs
			}
			if req.IPBlacklist != nil {
				merged.IPBlacklist = json.RawMessage(*req.IPBlacklist)
			}
			if req.GeoIPMode != nil {
				merged.GeoIPMode = *req.GeoIPMode
			}
			if req.GeoIPCountries != nil {
				merged.GeoIPCountries = json.RawMessage(*req.GeoIPCountries)
			}
			if req.RateLimitEnabled != nil {
				merged.RateLimitEnabled = *req.RateLimitEnabled
			}
			if req.RateLimitRPS != nil {
				merged.RateLimitRPS = *req.RateLimitRPS
			}
			if req.Mode != nil {
				merged.Mode = *req.Mode
			}
			if req.CustomRules != nil {
				merged.CustomRules = json.RawMessage(*req.CustomRules)
			}
			fs := models.PolicyTypeFeatures(&merged)
			ownStageFeature := (effType == models.PolicyTypeStage0 && fs.G0) ||
				(effType == models.PolicyTypeStage2 && fs.G2) ||
				(effType == models.PolicyTypeStage3 && fs.G3)
			if ownStageFeature {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("阶段 %s 策略不支持启用 IP 访问控制，请创建阶段 1 策略或走更新迁移", strings.TrimPrefix(effType, "stage"))})
				return
			}
		}
	}
	// 审计真 delta 的存量基准（2026-09-25 用户裁定 A 方案）复用事务开头的
	// 单次投影：写锁已持、与写入零竞态——changedFields 只记「提交值≠存量值」。
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
	// v2.3.8 爬虫豁免（指针语义：nil=保持现值）
	addBool("geoip_crawler_exempt", req.GeoIPCrawlerExempt)
	addStr("geoip_crawler_engines", req.GeoIPCrawlerEngines)
	addBool("waf_check_response", req.WAFCheckResponse)
	addBool("log_request_body", req.LogRequestBody)
	addStr("ip_acl_list_refs", req.IPACLListRefs)
	addStr("ip_whitelist_refs", req.IPWhitelistRefs)
	addStr("policy_type", req.PolicyType)

	if req.BlockPageID != nil {
		query += ", block_page_id=?"
		args = append(args, *req.BlockPageID)
	}
	if req.BlockStatusCode != nil {
		query += ", block_status_code=?"
		args = append(args, *req.BlockStatusCode)
	}
	// 缺省类型提交按存量类型归一——存量 stage1/2/3 策略
	// 显式携带 trust_detection=true 时强制写 0（跨阶段漂移不落库；nil 缺省
	// 不强制写，保留现值语义不变）。mixed 与 ''（待推断存量态，mixed 语义）
	// 不在此归一：迁移拆分路径（insertChild）已显式传值，存量行由「更新迁移」
	// 或重推断收敛。
	if req.TrustDetection != nil && req.PolicyType == nil {
		switch stored.PolicyType {
		case models.PolicyTypeStage1, models.PolicyTypeStage2, models.PolicyTypeStage3:
			falseTD := false
			req.TrustDetection = &falseTD
		}
	}
	addBool("trust_detection", req.TrustDetection)
	addBool("enabled", req.Enabled)
	query += ", updated_by=? WHERE id=?"
	args = append(args, int(contextUserID(c)), id)
	result, err := tx.ExecContext(caddyWriteCtx(c), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "策略不存在") {
		return
	}
	// 缺省（nil）提交按合并后内容重推断 policy_type（类型与内容不漂移；
	// 显式提交已由上方归一携带，无需重推断）。同时兜住导入/旧快照落库的
	// '' 存量态——下次编辑即归一。重推断命中时 policy_type 列被改写，结果
	// 暂存并落审计 delta（「实际变动的字段都记」原则此前
	// 在此破例）。
	var reinferredFrom, reinferredTo string
	if req.PolicyType == nil {
		var merged models.SecurityPolicy
		if err := scanSecurityPolicyRow(tx.QueryRowContext(caddyWriteCtx(c), `SELECT `+securityPolicySelectColumns+` FROM security_policies WHERE id=?`, id), &merged); err == nil {
			inferred := models.InferPolicyType(&merged)
			// 单职策略的「顺手加别的阶段」部分更新（如给 stage1 再开限流/
			// WAF）会把类型静默升格为 mixed，随即锁死「可绑定新规则」资格
			// （mixed 仅支持更新迁移）——与 Create 侧同口径在落库前拒绝，
			// 而不是先写后改。mixed 与 ''（待推断存量态，mixed 语义）不拦：
			// 重推断对它们只做归一。此处尚未提交（失败即回滚），无中间态。
			if inferred == models.PolicyTypeMixed && merged.PolicyType != models.PolicyTypeMixed && merged.PolicyType != "" {
				// 存量内容本就跨阶段（旧的脏行/导入残留）时，重推断只是把类型
				// 归一到内容实际形态，不构成本次请求引入的漂移——放行（否则
				// 这类行永远只能靠整表单迁移修）。
				if models.InferPolicyType(&stored) != models.PolicyTypeMixed {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略内容跨多个阶段，请显式按阶段类型（信任名单/IP 访问控制/限流/WAF）分别创建；如需合并能力请使用现有混合策略的更新迁移或拆分"})
					return
				}
			}
			if inferred != merged.PolicyType {
				if _, err := tx.ExecContext(caddyWriteCtx(c), "UPDATE security_policies SET policy_type=? WHERE id=?", inferred, id); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新策略类型失败"})
					return
				}
				reinferredFrom, reinferredTo = merged.PolicyType, inferred
			}
		} else {
			// 重推断读失败不得静默跳过——policy_type 停留旧值（含 '' 存量态）
			// 且审计 delta 不含类型变更；告警留痕并披露「类型未校正」（不 500
			// 回滚：主更新已就绪，类型校正可下次编辑收敛——可用性优先 Ruling，
			// 与同函数审计名读取失败的留痕口径一致）。
			services.Logf("warn", "更新策略 #%s 后重推断读取失败（policy_type 未按合并内容校正，审计不含类型变更）: %v", id, err)
		}
	}
	// 写侧拦截状态码归一与 Create 同口径（单源 normalizeBlockStatusCode）：
	// 以写入后读回的终态判定——类型可能是本请求显式提交，也可能是上方按合并
	// 内容重推断的结果；页面 id 同理（显式提交 ?? 存量）。此前只有「显式
	// policy_type ∧ 显式 block_page_id=0」才归零，PUT {"block_status_code":404}
	// 这类部分更新会落库一个不会被渲染消费的值。读取失败只告警不阻断（主更新
	// 已就绪，下次编辑收敛；与同函数审计名读取失败的留痕口径一致）。
	var finalPolicyType string
	var finalBlockPageID, finalBlockStatus int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COALESCE(policy_type,''), COALESCE(block_page_id,0), COALESCE(block_status_code,0) FROM security_policies WHERE id=?", id).Scan(&finalPolicyType, &finalBlockPageID, &finalBlockStatus); err != nil {
		services.Logf("warn", "更新策略 #%s 后读取拦截状态码终态失败（未执行写侧归一）: %v", id, err)
	} else if normalized := normalizeBlockStatusCode(finalBlockStatus, finalPolicyType, finalBlockPageID); normalized != finalBlockStatus {
		if _, err := tx.ExecContext(caddyWriteCtx(c), "UPDATE security_policies SET block_status_code=? WHERE id=?", normalized, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新拦截状态码失败"})
			return
		}
		// 审计 delta 以实际落库值为准：归零同样是本次写入的真实变更。
		normalizedVal := normalized
		req.BlockStatusCode = &normalizedVal
	}
	// 审计用 username（非数字 ID）+ 真 delta 变更详情（2026-09-25 用户裁定
	// A 方案）：只记「提交值≠存量值」的字段（旧值→新值），IP 弹窗一键操作和
	// 策略编辑页共用此端点，操作人/具体改了什么/IP 是什么必须在日志可追溯；
	// 同值全量提交（编辑页未改点保存）落「（无字段变化）」而非全字段噪音。
	var policyName string
	// 策略名读取失败不得静默——审计详情会退化为
	// 「策略「」(#id)」，操作人/对象归因不可读；与同域失败留痕口径一致。
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT name FROM security_policies WHERE id=?", id).Scan(&policyName); err != nil {
		services.Logf("warn", "更新策略 #%s 审计名读取失败（审计详情以空名记录）: %v", id, err)
	}
	auditDetail := fmt.Sprintf("策略「%s」(#%s)", policyName, id)
	var changedFields []string
	if reinferredTo != "" {
		changedFields = append(changedFields, fmt.Sprintf("策略类型：%s→%s（按内容重推断）", reinferredFrom, reinferredTo))
	}
	clip := func(v string) string {
		if len(v) > 60 {
			return fmt.Sprintf("（%d 字节）", len(v))
		}
		return v
	}
	deltaStr := func(label string, nv *string, ov string) {
		if nv != nil && *nv != ov {
			changedFields = append(changedFields, fmt.Sprintf("%s：%s→%s", label, clip(ov), clip(*nv)))
		}
	}
	deltaInt := func(label string, nv *int, ov int) {
		if nv != nil && *nv != ov {
			changedFields = append(changedFields, fmt.Sprintf("%s：%d→%d", label, ov, *nv))
		}
	}
	deltaBool := func(label string, nv *bool, ov bool) {
		if nv != nil && *nv != ov {
			changedFields = append(changedFields, fmt.Sprintf("%s：%v→%v", label, ov, *nv))
		}
	}
	// ID 引用→名称（2026-09-25 用户裁定）：refs/自定义规则/拦截页在审计里
	// 以名称呈现。解析失败（JSON 畸形/查询失败）回落原始文本——审计可读性
	// 不阻断写路径。
	refNameCache := map[string]map[int]string{}
	loadRefNames := func(table string, ids []int) map[int]string {
		names := refNameCache[table]
		if names == nil {
			names = map[int]string{}
			refNameCache[table] = names
		}
		var missing []int
		for _, id := range ids {
			if _, ok := names[id]; !ok {
				missing = append(missing, id)
			}
		}
		if len(missing) == 0 {
			return names
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(missing)), ",")
		args := make([]interface{}, len(missing))
		for i, id := range missing {
			args[i] = id
		}
		rows, err := tx.QueryContext(caddyWriteCtx(c), `SELECT id, COALESCE(name,'') FROM `+table+` WHERE id IN (`+placeholders+`)`, args...)
		if err == nil {
			for rows.Next() {
				var id int
				var name string
				if rows.Scan(&id, &name) == nil {
					names[id] = name
				}
			}
			rows.Close()
		}
		for _, id := range missing {
			if _, ok := names[id]; !ok {
				names[id] = ""
			}
		}
		return names
	}
	namesOfRefs := func(table, refsJSON string) string {
		var ids []int
		if err := json.Unmarshal([]byte(refsJSON), &ids); err != nil {
			return clip(refsJSON)
		}
		if len(ids) == 0 {
			return "（空）"
		}
		names := loadRefNames(table, ids)
		out := make([]string, 0, len(ids))
		for _, refID := range ids {
			if name := names[refID]; name != "" {
				out = append(out, name)
			} else {
				out = append(out, fmt.Sprintf("#%d", refID))
			}
		}
		return strings.Join(out, "、")
	}
	deltaRefs := func(label, table string, nv *string, ov string) {
		if nv != nil && *nv != ov {
			changedFields = append(changedFields, fmt.Sprintf("%s：%s→%s", label, namesOfRefs(table, ov), namesOfRefs(table, *nv)))
		}
	}
	blockPageName := func(pageID int) string {
		if pageID == 0 {
			return "（无）"
		}
		var name string
		if err := tx.QueryRowContext(caddyWriteCtx(c), `SELECT COALESCE(name,'') FROM security_block_pages WHERE id=?`, pageID).Scan(&name); err != nil || name == "" {
			return fmt.Sprintf("#%d", pageID)
		}
		return name
	}
	deltaStr("名称", req.Name, stored.Name)
	deltaStr("描述", req.Description, stored.Description)
	deltaStr("WAF 模式", req.Mode, stored.Mode)
	deltaInt("异常分阈值", req.AnomalyThreshold, stored.AnomalyThreshold)
	deltaStr("ACL 模式", req.IPACLMode, stored.IPACLMode)
	deltaStr("IP ACL 列表", req.IPACLList, stored.IPACLList)
	deltaBool("ACL 启用", req.IPACLEnabled, stored.IPACLEnabled)
	deltaBool("信任名单启用", req.IPWhitelistEnabled, stored.IPWhitelistEnabled)
	deltaStr("策略类型", req.PolicyType, stored.PolicyType)
	deltaBool("信任检测", req.TrustDetection, stored.TrustDetection)
	deltaStr("信任名单", req.IPWhitelist, string(stored.IPWhitelist))
	deltaStr("旧版黑名单", req.IPBlacklist, string(stored.IPBlacklist))
	deltaRefs("ACL 列表引用", "security_ip_lists", req.IPACLListRefs, stored.IPACLListRefs)
	deltaRefs("信任名单列表引用", "security_ip_lists", req.IPWhitelistRefs, stored.IPWhitelistRefs)
	deltaBool("限流启用", req.RateLimitEnabled, stored.RateLimitEnabled)
	deltaInt("限流 RPS", req.RateLimitRPS, stored.RateLimitRPS)
	deltaInt("限流突发", req.RateLimitBurst, stored.RateLimitBurst)
	deltaStr("CRS 规则组", req.CRSRuleGroups, string(stored.CRSRuleGroups))
	deltaStr("CRS 排除", req.CRSExcludedRules, string(stored.CRSExcludedRules))
	deltaRefs("自定义规则", "security_custom_rules", req.CustomRules, string(stored.CustomRules))
	deltaStr("GeoIP 名单", req.GeoIPCountries, string(stored.GeoIPCountries))
	deltaStr("GeoIP 模式", req.GeoIPMode, stored.GeoIPMode)
	// v2.3.8 爬虫豁免审计（UPDATE 列集合 ↔ delta 覆盖集全等约束）
	deltaBool("爬虫豁免", req.GeoIPCrawlerExempt, stored.GeoIPCrawlerExempt)
	deltaStr("豁免引擎", req.GeoIPCrawlerEngines, string(stored.GeoIPCrawlerEngines))
	deltaBool("响应体检测", req.WAFCheckResponse, stored.WAFCheckResponse)
	deltaBool("请求体落日志", req.LogRequestBody, stored.LogRequestBody)
	if req.BlockPageID != nil && *req.BlockPageID != stored.BlockPageID {
		changedFields = append(changedFields, fmt.Sprintf("拦截页：%s→%s", blockPageName(stored.BlockPageID), blockPageName(*req.BlockPageID)))
	}
	deltaInt("拦截状态码", req.BlockStatusCode, stored.BlockStatusCode)
	deltaBool("启用", req.Enabled, stored.Enabled)
	if len(changedFields) > 0 {
		auditDetail += "；" + strings.Join(changedFields, "；")
	} else {
		auditDetail += "（无字段变化）"
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: auditDetail,
		SuccessMsg:  "安全策略更新成功",
	})
}

func (h *Handlers) DeleteSecurityPolicy(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略写操作") {
		return
	}
	if _, ok := parsePositiveNumericID(c.Param("id")); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的策略 ID"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	// 绑定清理与策略删除必须同事务：绑定删除失败时回滚，避免留下
	// 指向已删策略的悬挂绑定（旧行为会静默忽略清理错误）。
	// 写锁来自 DSN 的 _txlock=immediate（glebarez 驱动对非只读 BeginTx 一律
	// BEGIN IMMEDIATE，忽略 TxOptions.Isolation）：COUNT/DELETE/清理之间不存在
	// 并发绑定插队的写窗口。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("DELETE FROM security_policies WHERE id=?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !rowsAffectedOrRespond(c, result, "策略不存在") {
		return
	}
	if _, err := tx.Exec("DELETE FROM security_policy_bindings WHERE policy_id=?", id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("清理策略绑定失败", err)})
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "删除",
		AuditDetail: fmt.Sprintf("策略 #%s", id),
		SuccessMsg:  "安全策略已删除",
	})
}

// maxBindingsPerRule 单规则安全策略绑定上限（2026-09-21 用户裁定 5→8）：所有写
// 路径同源此常量——BindRuleToPolicy additive、SetRuleSecurityPolicies 原子替换、
// BatchBindSecurityPolicies 提交集与 merge 合并、SplitSecurityPolicy 重映射、
// BulkUpdatePolicyBindings 的 bind 侧（补齐——此前 bulk 缺此门）。
// 前端 SecurityBindingEditor/SecurityPolicies 的 MAX_POLICY_BINDINGS 与
// mcpserver schema maxItems 为镜像口径，调整时须同步。
const maxBindingsPerRule = 8

// maxBatchBindRules 批量绑定端点（POST /security/policies/batch-bind）单次规则
// 数上限：与 BulkUpdatePolicyBindings 的 100 同口径，
// 前端 SECURITY_BULK_LIMITS.policyBindings 为其镜像。判据按 normalizeRuleIDs
// 归一后集合计数（空白/重复 id 不占额度），超限 400 整体拒绝——不得带着写锁
// （BEGIN IMMEDIATE + caddyOpMu）逐规则执行 N×3~4 次查询。
const maxBatchBindRules = 100

func (h *Handlers) BindRuleToPolicy(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略绑定操作") {
		return
	}
	policyID := c.Param("id")
	// 规范数字 ID 门（同族删除/名单写路径一致）：SQLite INTEGER 亲和会让
	// "5.0" 命中行 5，而 Atoi("5.0") 失败得到 0 使 mixed 门禁失效。
	if _, ok := parsePositiveNumericID(policyID); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略 ID 无效"})
		return
	}
	var req struct {
		RuleCaddyID string `json:"rule_caddy_id" binding:"required"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	// 绑定/解绑必须同事务：存在性校验与写入同事务执行，避免检查与 INSERT 之间
	// 规则/策略被并发删除产生悬挂绑定（无 FK，经集群同步扩散）；INSERT
	// 失败时旧绑定已被 DELETE 删除，需回滚恢复。
	// 写锁来自 DSN 的 _txlock=immediate（glebarez 驱动忽略 TxOptions.Isolation，
	// 非只读 BeginTx 一律 BEGIN IMMEDIATE）：COUNT 校验即持写锁，并发的策略删除
	// 无法在 COUNT 与 DELETE/INSERT 之间提交，闭合 D 遗留的窄写窗口
	// 澄清注释）。
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer tx.Rollback()
	var policyExists int
	var policyType string
	// 先判 err 再判 COUNT：DB 瞬时故障（锁/IO）时 policyExists 未赋值，
	// 合并判断会把故障误报为「策略不存在」，前端无法区分重试与真 404——与
	// DeleteSecurityBlockPage 的 ErrNoRows 先判口径一致。
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*), COALESCE(MAX(policy_type),'') FROM security_policies WHERE id=?", policyID).Scan(&policyExists, &policyType); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if policyExists == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	// 混合策略仅可更新迁移（2026-09-20 用户裁定）：兼容旧版形态，不得新绑定到
	// 规则——存量混合绑定保持有效，迁移入口=策略页「更新迁移」（拆分单职策略）。
	// 判定与其余三个写路径共用 rejectMixedPolicies。
	policyIDInt, _ := strconv.Atoi(policyID)
	if msg, err := rejectMixedPolicies(caddyWriteCtx(c), tx, []int{policyIDInt}); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	} else if msg != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: *msg})
		return
	}
	// 限流策略唯一绑定（2026-09-20 用户裁定）：该规则已绑定其他 stage2 策略时
	// 拒绝第二条（幂等重绑同一条放行）。
	if policyType == models.PolicyTypeStage2 {
		var otherStage2 int
		if err := tx.QueryRowContext(caddyWriteCtx(c), `SELECT COUNT(*) FROM security_policy_bindings b JOIN security_policies p ON p.id=b.policy_id
			WHERE b.rule_caddy_id=? AND p.policy_type='stage2' AND p.id != ?`, req.RuleCaddyID, policyID).Scan(&otherStage2); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		if otherStage2 > 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "每条规则最多绑定一条限流策略，请先解绑现有限流策略"})
			return
		}
	}
	// 绑定前校验规则真实存在：悬挂绑定虽在 JOIN 中不可见，但会经集群同步传播
	// 并污染 GetAllSecurityBindings 消费方。与策略校验同口径先判
	// err 再判存在性：DB 瞬时故障（锁/IO）时不得把故障误报为「规则不存在」400，
	// 客户端无法区分重试与真 400。protocol 同行判定——TCP 规则走 caddy-l4
	// 构建链（buildTCPServer），该链从不消费安全策略，绑定成立即「UI 宣称受
	// 保护、实际零强制」的稳态漂移。
	target, err := loadRuleBindingTarget(caddyWriteCtx(c), tx, req.RuleCaddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if !target.exists {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "规则不存在"})
		return
	}
	if !target.http {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "安全策略仅支持绑定 HTTP 规则（TCP 规则不经过 WAF/IP 访问控制/限流链）"})
		return
	}
	// 上限守卫：POST additive 与 PUT 同上限——一规则最多绑定
	// maxBindingsPerRule 条策略。重绑已存在的 (rule,policy) 对保持幂等 200
	// （INSERT OR IGNORE 不产生新行），仅当该对尚未绑定且兄弟绑定已达上限时
	// 拒绝；COUNT 与 INSERT 同事务（写锁由 _txlock=immediate 在 BEGIN 处获取），
	// 并发绑定无法在校验与写入间插队。
	var alreadyBound int
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", req.RuleCaddyID, policyID).Scan(&alreadyBound); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if alreadyBound == 0 {
		var siblingCount int
		if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?", req.RuleCaddyID).Scan(&siblingCount); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		if siblingCount >= maxBindingsPerRule {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("最多绑定 %d 条策略", maxBindingsPerRule)})
			return
		}
	}
	// v2.2.0 多策略绑定：POST bind 改为 additive——仅 INSERT OR IGNORE，不再
	// 清空 rule 的兄弟绑定；全量替换走 PUT /security/rules/:caddy_id/policies。
	// INSERT OR IGNORE 保留幂等（重复绑定同一 (rule,policy) 不报错、不重复行）。
	if _, err := tx.ExecContext(caddyWriteCtx(c), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", req.RuleCaddyID, policyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("绑定规则 %s 到策略 #%s", req.RuleCaddyID, policyID),
		SuccessMsg:  "规则已关联",
	})
}

// SetRuleSecurityPolicies（v2.2.0）：PUT /security/rules/:caddy_id/policies
// 原子替换一规则的全部策略绑定。校验与替换核心在 setRulePoliciesInTx
// （与批量端点 /security/rules/policies/batch 同源——单实现）。
func (h *Handlers) SetRuleSecurityPolicies(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略绑定操作") {
		return
	}
	ruleCaddyID := c.Param("caddy_id")
	var req struct {
		PolicyIDs []int `json:"policy_ids"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer tx.Rollback()
	// 审计串与写入共用同一归一集合——此前审计用原始
	// req.PolicyIDs（重复项保留），提交 [1,1,2] 时审计记 [1,1,2] 而库内为
	// [1,2]，取证时无法从审计还原最终绑定集。
	policyIDs := normalizePolicyIDs(req.PolicyIDs)
	if msg, err := setRulePoliciesInTx(caddyWriteCtx(c), tx, ruleCaddyID, policyIDs); err != nil {
		// DB 故障（锁/IO）映射 500 而非 400 裸串外泄。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取/写入策略绑定失败"})
		return
	} else if msg != "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
		return
	}
	idStrs := make([]string, len(policyIDs))
	for i, id := range policyIDs {
		idStrs[i] = strconv.Itoa(id)
	}
	summary := strings.Join(idStrs, ",")
	if summary == "" {
		summary = "全部解除"
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("设置规则 %s 的安全策略为 [%s]", ruleCaddyID, summary),
		SuccessMsg:  "规则安全策略已更新",
	})
}

// normalizePolicyIDs 策略 ID 去重（保序）单实现
// 绑定上限判定、存在性校验、写入与审计串必须共用归一后集合——上限按原始长度
// 判定会让 [1,1,…] 重复项被误判超限，审计按原始数组判定则与库内终态分叉。
func normalizePolicyIDs(ids []int) []int {
	seen := make(map[int]struct{}, len(ids))
	unique := make([]int, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

// ruleBindingTarget 是「规则能否承载安全链绑定」的判定结论（单源判定，
// 呈现口径留在各入口）。
type ruleBindingTarget struct {
	exists   bool
	protocol string
	http     bool // protocol == "http"：安全链（WAF/ACL/限流）只挂在 HTTP 路由上
}

// loadRuleBindingTarget 读取规则绑定目标的存在性与协议（lb_rules 单行）：
// SetRuleSecurityPolicies / BindRuleToPolicy / BulkUpdatePolicyBindings /
// BatchBindSecurityPolicies 四个入口共用同一判定。呈现差异（400 文案 vs
// skipped 分项、unbind 对不存在规则的幂等放行）留在调用方。
func loadRuleBindingTarget(ctx context.Context, tx *sql.Tx, ruleCaddyID string) (ruleBindingTarget, error) {
	var exists int
	var protocol string
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(MAX(protocol),'') FROM lb_rules WHERE caddy_id=?", ruleCaddyID).Scan(&exists, &protocol); err != nil {
		return ruleBindingTarget{}, err
	}
	return ruleBindingTarget{exists: exists > 0, protocol: protocol, http: protocol == "http"}, nil
}

// bindingCountExcluding 统计单规则上「除 excludePolicyID 之外」的绑定数——
// 绑定上限判定与拆分重映射的合并判定单源（合并后是否超 maxBindingsPerRule）。
func bindingCountExcluding(ctx context.Context, tx *sql.Tx, ruleCaddyID string, excludePolicyID int) (int, error) {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id != ?", ruleCaddyID, excludePolicyID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// bindingCountsExcluding 是 bindingCountExcluding 的批量形态（策略侧批量绑定
// 一次取回 N 条规则的排他绑定数，避免逐规则往返）。
func bindingCountsExcluding(ctx context.Context, tx *sql.Tx, ruleCaddyIDs []string, excludePolicyID int) (map[string]int, error) {
	counts := make(map[string]int, len(ruleCaddyIDs))
	if len(ruleCaddyIDs) == 0 {
		return counts, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ruleCaddyIDs)), ",")
	args := make([]any, 0, len(ruleCaddyIDs)+1)
	for _, id := range ruleCaddyIDs {
		args = append(args, id)
	}
	args = append(args, excludePolicyID)
	rows, err := tx.QueryContext(ctx, "SELECT rule_caddy_id, COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id IN ("+placeholders+") AND policy_id != ? GROUP BY rule_caddy_id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ruleCaddyID string
		var count int
		if err := rows.Scan(&ruleCaddyID, &count); err != nil {
			return nil, err
		}
		counts[ruleCaddyID] = count
	}
	return counts, rows.Err()
}

// setRulePoliciesInTx 校验并原子替换单规则的策略绑定集（DELETE+按去重序
// INSERT OR IGNORE），供单条端点 SetRuleSecurityPolicies 使用
// 单实现）。返回 (userMsg, err)：userMsg 非空=面向用户的 400 校验消息；err
// 非 nil=数据库错误（调用方映射 500「读取/写入策略绑定失败」，不得把 DB
// 故障裸串当 400 外泄）。
// 校验族：规则存在且 HTTP、去重后 ≤maxBindingsPerRule、策略全部存在、
// 不含 mixed、stage2 至多一条。
func setRulePoliciesInTx(ctx context.Context, tx *sql.Tx, ruleCaddyID string, policyIDs []int) (string, error) {
	// 上限判定须先去重：[1,1,2,3,4,5] 为 5 条唯一策略，不得因原始数组
	// 长度 6 误判超限。去重同时避免同一 id 重复计数导致存在性校验误判
	// （INSERT OR IGNORE 本来就会去重，但 COUNT 必须与去重后的集合对齐）。
	uniqueIDs := normalizePolicyIDs(policyIDs)
	if len(uniqueIDs) > maxBindingsPerRule {
		return fmt.Sprintf("最多绑定 %d 条策略", maxBindingsPerRule), nil
	}
	// 与 BindRuleToPolicy 同事务口径：存在性校验 + DELETE + 有序 INSERT 同事务，
	// 写锁由 _txlock=immediate 在 BEGIN 处获取，避免校验与写入之间规则/策略被
	// 并发删除产生悬挂绑定。
	target, err := loadRuleBindingTarget(ctx, tx, ruleCaddyID)
	if err != nil {
		return "", err
	}
	if !target.exists {
		return "规则不存在", nil
	}
	if !target.http {
		return "安全策略仅支持绑定 HTTP 规则（TCP 规则不经过 WAF/IP 访问控制/限流链）", nil
	}
	if len(uniqueIDs) > 0 {
		placeholders := make([]string, len(uniqueIDs))
		args := make([]interface{}, len(uniqueIDs))
		for i, id := range uniqueIDs {
			placeholders[i] = "?"
			args[i] = id
		}
		var found int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_policies WHERE id IN ("+strings.Join(placeholders, ",")+")", args...).Scan(&found); err != nil {
			return "", err
		}
		if found != len(uniqueIDs) {
			return "部分策略不存在", nil
		}
	}
	// 混合策略仅可更新迁移（同上裁定）：绑定集含 mixed 即拒绝（历史
	// 共用 rejectMixedPolicies）。
	if msg, err := rejectMixedPolicies(ctx, tx, uniqueIDs); err != nil {
		return "", err
	} else if msg != nil {
		return *msg, nil
	}
	// 限流策略唯一绑定：提交集含 ≥2 条 stage2 即拒绝（存量多限流绑定不受影响，
	// 收敛后提交即可）。
	if len(uniqueIDs) > 0 {
		stage2Count, err := countStage2Policies(tx, ctx, uniqueIDs)
		if err != nil {
			return "", err
		}
		if stage2Count > 1 {
			return "每条规则最多绑定一条限流策略，请从提交集中移除多余的限流策略", nil
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM security_policy_bindings WHERE rule_caddy_id=?", ruleCaddyID); err != nil {
		return "", err
	}
	for _, id := range uniqueIDs {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, id); err != nil {
			return "", err
		}
	}
	return "", nil
}

// normalizeRuleIDs 归一规则 id 列表：TrimSpace + 去重 + 丢弃空串（历史
// bulk 绑定端点的 bind/unbind 列表经此归一后再进入校验与写入——
// 空白/重复 id 不得逐字进入 SQL 或审计计数。
func normalizeRuleIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// BulkUpdatePolicyBindings（用户裁定）：POST /security/policies/:id/bindings/bulk
// {"bind":["lb_a"],"unbind":["lb_c"]}——「策略保存/绑定规则弹框（策略模式）」
// 前端此前逐规则调 bind/unbind 单条端点，每条独立全链渲染+validate+/load
// （N×~500ms，后端配置锁串行化）。单事务批量增删**本策略**的绑定行，不触碰
// 兄弟绑定（并发安全语义：additive/精确删除），全程恰好一次
// finishTxApply（单渲染）。任一规则校验失败=400 整体拒绝且事务回滚；
// bind+unbind 合计上限 100；幂等（重复 bind/未绑定的 unbind 均无害）。
// bind 侧与单条 bind/batch-bind 端点同源两道规则级门：maxBindingsPerRule 上限、
// stage2 唯一绑定。
func (h *Handlers) BulkUpdatePolicyBindings(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略绑定操作") {
		return
	}
	policyID, err := strconv.Atoi(c.Param("id"))
	if err != nil || policyID <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的策略 ID"})
		return
	}
	const maxBulkBindings = 100
	var req struct {
		Bind   []string `json:"bind"`
		Unbind []string `json:"unbind"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	// 规则 id 归一（TrimSpace）+ 去重：空白/重复 id 不得进入
	// 校验与写入；去重后的集合同时作为两道规则级门与写入的输入。
	bindIDs := normalizeRuleIDs(req.Bind)
	unbindIDs := normalizeRuleIDs(req.Unbind)
	// 数量上限按**归一后**集合判定——同端点其余校验
	// （冲突检测、计数、规则级门）都用归一后集合；先按原始长度判定会让 101 个
	// 重复/空白项（归一后仅 1 条规则）被误拒。
	if len(bindIDs)+len(unbindIDs) > maxBulkBindings {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("单次最多提交 %d 条规则", maxBulkBindings)})
		return
	}
	// 禁止同一规则同时出现在 bind 与 unbind（语义冲突）。
	unbindSet := make(map[string]struct{}, len(unbindIDs))
	for _, id := range unbindIDs {
		unbindSet[id] = struct{}{}
	}
	for _, id := range bindIDs {
		if _, clash := unbindSet[id]; clash {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "同一规则不能同时出现在 bind 与 unbind: " + id})
			return
		}
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer tx.Rollback()
	// 策略存在性 + 类型（mixed 判定与 stage2 唯一门消费）。
	var policyExists int
	var policyType string
	if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*), COALESCE(MAX(policy_type),'') FROM security_policies WHERE id=?", policyID).Scan(&policyExists, &policyType); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if policyExists == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
		return
	}
	// 混合策略仅可更新迁移（与单条 bind 端点同口径；历史 共用判定）。
	if msg, err := rejectMixedPolicies(caddyWriteCtx(c), tx, []int{policyID}); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	} else if msg != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: *msg})
		return
	}
	// bind 侧补齐单条 bind / batch-bind 端点同源的两道规则级
	// 门——(a) 该规则现有绑定数（不含本策略）≥maxBindingsPerRule；(b) 本策略为
	// stage2 且该规则已绑其他 stage2。批量化预取：一次 IN 查询取全部涉及规则的
	// 「不含本策略」绑定计数，本策略为 stage2 时再一次 IN 查询取「已含其他
	// stage2 绑定」的规则集合——避免逐规则 2N 次查询（bulk 上限 100 条）。
	bindCounts := map[string]int{}
	boundToPolicy := map[string]struct{}{}
	otherStage2Rules := map[string]struct{}{}
	if len(bindIDs) > 0 {
		placeholders := make([]string, len(bindIDs))
		args := make([]interface{}, 0, len(bindIDs)+1)
		for i, id := range bindIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		args = append(args, policyID)
		// 已绑定本策略的规则集合：bind 上限门只对「新增绑定」生效——与单条
		// bind 端点同口径（已绑定即幂等 200）。存量超限规则（旧版本导入/历史
		// 数据，绑定数≥9）在 bulk 里重复提交本策略时不得 400，否则同批无关
		// 规则的变更也整体失败。
		boundRows, err := tx.QueryContext(caddyWriteCtx(c), "SELECT rule_caddy_id FROM security_policy_bindings WHERE rule_caddy_id IN ("+strings.Join(placeholders, ",")+") AND policy_id = ?", args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		for boundRows.Next() {
			var rid string
			if err := boundRows.Scan(&rid); err != nil {
				boundRows.Close()
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			boundToPolicy[rid] = struct{}{}
		}
		boundRows.Close()
		if err := boundRows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		bindCounts, err = bindingCountsExcluding(caddyWriteCtx(c), tx, bindIDs, policyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		if policyType == models.PolicyTypeStage2 {
			sibArgs := make([]interface{}, 0, len(bindIDs)+1)
			for _, id := range bindIDs {
				sibArgs = append(sibArgs, id)
			}
			sibArgs = append(sibArgs, policyID)
			sibRows, err := tx.QueryContext(caddyWriteCtx(c), "SELECT DISTINCT b.rule_caddy_id FROM security_policy_bindings b JOIN security_policies p ON p.id=b.policy_id WHERE b.rule_caddy_id IN ("+strings.Join(placeholders, ",")+") AND b.policy_id != ? AND p.policy_type='stage2'", sibArgs...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			for sibRows.Next() {
				var rid string
				if err := sibRows.Scan(&rid); err != nil {
					sibRows.Close()
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
					return
				}
				otherStage2Rules[rid] = struct{}{}
			}
			sibRows.Close()
			if err := sibRows.Err(); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
		}
	}
	// 审计计数以「实变行数」（INSERT/DELETE affected 汇总）为准，而非请求原始
	// 长度——重复 bind / 未绑定 unbind 不产生变化即不计入。
	boundChanged, unboundChanged := 0, 0
	// 逐规则校验存在且 HTTP（单条 bind 端点同口径），并即时执行增删。返回
	// (userMsg, err)：DB 故障→500，校验失败→400。
	applyOne := func(ruleCaddyID string, bind bool) (string, error) {
		target, err := loadRuleBindingTarget(caddyWriteCtx(c), tx, ruleCaddyID)
		if err != nil {
			return "", err
		}
		if !target.exists {
			if !bind {
				// unbind 目标规则已不存在=目标态（无该绑定）已达成——幂等放行
				//（bind 目标不存在仍是错误：无法达成）。
				return "", nil
			}
			return "规则不存在: " + ruleCaddyID, nil
		}
		if bind && !target.http {
			return ruleCaddyID + ": 安全策略仅支持绑定 HTTP 规则（TCP 规则不经过 WAF/IP 访问控制/限流链）", nil
		}
		if bind {
			if _, already := boundToPolicy[ruleCaddyID]; !already && bindCounts[ruleCaddyID] >= maxBindingsPerRule {
				return fmt.Sprintf("%s: 最多绑定 %d 条策略", ruleCaddyID, maxBindingsPerRule), nil
			}
			if policyType == models.PolicyTypeStage2 {
				if _, has := otherStage2Rules[ruleCaddyID]; has {
					return ruleCaddyID + ": 每条规则最多绑定一条限流策略，请先解绑现有限流策略", nil
				}
			}
			res, err := tx.ExecContext(caddyWriteCtx(c), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, policyID)
			if err != nil {
				return "", err
			}
			if n, err := res.RowsAffected(); err == nil {
				boundChanged += int(n)
			}
			return "", nil
		}
		res, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleCaddyID, policyID)
		if err != nil {
			return "", err
		}
		if n, err := res.RowsAffected(); err == nil {
			unboundChanged += int(n)
		}
		return "", nil
	}
	for _, ruleCaddyID := range bindIDs {
		msg, err := applyOne(ruleCaddyID, true)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取/写入策略绑定失败"})
			return
		}
		if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
	}
	for _, ruleCaddyID := range unbindIDs {
		msg, err := applyOne(ruleCaddyID, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取/写入策略绑定失败"})
			return
		}
		if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg})
			return
		}
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("策略 %d 批量更新绑定：绑定 %d 条、解绑 %d 条", policyID, boundChanged, unboundChanged),
		SuccessMsg:  "策略绑定批量更新完成",
	})
}

// BatchBindSecurityPolicies 批量绑定安全策略（规则列表多选浮动操作条）：
// {rule_ids:[], policy_ids:[], mode:"merge"|"replace"}。单事务：策略存在性
// 一次校验；逐规则存在且 protocol=http（否则进 skipped+reason）；merge=现有
// ∪请求去重后不超 maxBindingsPerRule（超限进 skipped）、replace=直接采用请求集
// （同上限）；逐规则
// DELETE（replace 或绑定变化时）+INSERT OR IGNORE；全程一次 finishTxApply
// （单渲染——批量绑定的成本模型与逐条调 PUT /security/rules/:id/policies
// N 次渲染对齐）。响应 {bound:n, skipped:[{rule_id,reason}]}。
// 历史 rule_ids 归一后上限 maxBatchBindRules（100），超限 400
// 整体拒绝——同族 BulkUpdatePolicyBindings / batch-block-pages 均有上限。
func (h *Handlers) BatchBindSecurityPolicies(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略绑定操作") {
		return
	}
	var req struct {
		RuleIDs   []string `json:"rule_ids"`
		PolicyIDs []int    `json:"policy_ids"`
		Mode      string   `json:"mode"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if req.Mode == "" {
		req.Mode = "merge"
	}
	if req.Mode != "merge" && req.Mode != "replace" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "mode 仅支持 merge 或 replace"})
		return
	}
	req.RuleIDs = normalizeRuleIDs(req.RuleIDs)
	if len(req.RuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "rule_ids 不能为空"})
		return
	}
	// 单次规则数上限与兄弟批量端点同口径（归一后计数）
	// ——无上限时数万条 rule_ids 会在写锁内逐规则查询/写入，阻塞全部主库配置写。
	if len(req.RuleIDs) > maxBatchBindRules {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("单次最多提交 %d 条规则（去重后计数）", maxBatchBindRules)})
		return
	}
	// 去重后上限判定（同 SetRuleSecurityPolicies 的口径）
	uniqueIDs := normalizePolicyIDs(req.PolicyIDs)
	if len(uniqueIDs) > maxBindingsPerRule {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("每条规则最多绑定 %d 条策略", maxBindingsPerRule)})
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer tx.Rollback()
	// 策略存在性一次校验（不全在→400 整体拒绝）
	if len(uniqueIDs) > 0 {
		placeholders := make([]string, len(uniqueIDs))
		args := make([]interface{}, len(uniqueIDs))
		for i, id := range uniqueIDs {
			placeholders[i] = "?"
			args[i] = id
		}
		var found int
		if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_policies WHERE id IN ("+strings.Join(placeholders, ",")+")", args...).Scan(&found); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		if found != len(uniqueIDs) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "部分策略不存在"})
			return
		}
	}
	// 混合策略仅可更新迁移（同 SetRuleSecurityPolicies 裁定）：批量绑定集含
	// mixed 即 400 整体拒绝（共用 rejectMixedPolicies）。
	if msg, err := rejectMixedPolicies(caddyWriteCtx(c), tx, uniqueIDs); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	} else if msg != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: *msg})
		return
	}
	// 限流策略唯一绑定：提交集含 ≥2 条 stage2 即 400（存量多限流绑定不受影响，
	// 收敛后提交即可）。
	if len(uniqueIDs) > 0 {
		stage2Count, err := countStage2Policies(tx, caddyWriteCtx(c), uniqueIDs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		if stage2Count > 1 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "每条规则最多绑定一条限流策略，请从提交集中移除多余的限流策略"})
			return
		}
	}
	type skippedRule struct {
		RuleID string `json:"rule_id"`
		Reason string `json:"reason"`
	}
	bound := 0
	unchanged := 0
	skipped := make([]skippedRule, 0)
	for _, ruleCaddyID := range req.RuleIDs {
		ruleCaddyID = strings.TrimSpace(ruleCaddyID)
		if ruleCaddyID == "" {
			continue
		}
		target, terr := loadRuleBindingTarget(caddyWriteCtx(c), tx, ruleCaddyID)
		if terr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", terr)})
			return
		}
		if !target.exists {
			skipped = append(skipped, skippedRule{ruleCaddyID, "规则不存在"})
			continue
		}
		if !target.http {
			skipped = append(skipped, skippedRule{ruleCaddyID, "TCP 规则不经过安全链"})
			continue
		}

		existingRows, err := tx.QueryContext(caddyWriteCtx(c), "SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id", ruleCaddyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		var existing []int
		for existingRows.Next() {
			var pid int
			if err := existingRows.Scan(&pid); err != nil {
				existingRows.Close()
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			existing = append(existing, pid)
		}
		// ⑬：迭代失败显式 500——漏查会把「部分
		// 读取（空 existing）」当成功继续 merge/写入，静默丢绑定差异。
		if err := existingRows.Err(); err != nil {
			existingRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		existingRows.Close()
		final := uniqueIDs
		if req.Mode == "merge" {
			merged := make([]int, 0, len(existing)+len(uniqueIDs))
			mergeSeen := map[int]struct{}{}
			for _, id := range append(append([]int{}, existing...), uniqueIDs...) {
				if _, dup := mergeSeen[id]; dup {
					continue
				}
				mergeSeen[id] = struct{}{}
				merged = append(merged, id)
			}
			if len(merged) > maxBindingsPerRule {
				skipped = append(skipped, skippedRule{ruleCaddyID, fmt.Sprintf("合并后超过 %d 条策略上限", maxBindingsPerRule)})
				continue
			}
			final = merged
		}
		// 限流策略唯一绑定（merge 路径）：合并后单规则含 ≥2 条 stage2 → 该规则
		// 进 skipped（保持原绑定不动，与绑定上限同口径；replace 已由提交集门拦截）。
		if req.Mode == "merge" {
			stage2Count, err := countStage2Policies(tx, caddyWriteCtx(c), final)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			if stage2Count > 1 {
				skipped = append(skipped, skippedRule{ruleCaddyID, "每条规则最多绑定一条限流策略"})
				continue
			}
		}
		// 绑定无变化（merge 幂等）时跳过写入；replace 恒重写（语义即全量替换）
		changed := req.Mode == "replace" || len(final) != len(existing)
		if !changed {
			for i, id := range final {
				if i >= len(existing) || existing[i] != id {
					changed = true
					break
				}
			}
		}
		if changed {
			if _, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_policy_bindings WHERE rule_caddy_id=?", ruleCaddyID); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			for _, id := range final {
				if _, err := tx.ExecContext(caddyWriteCtx(c), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, id); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
					return
				}
			}
		}
		// bound 只计真实写入（DELETE+INSERT 发生）；幂等 merge（目标集与现
		// 绑定逐条一致）零写入计 unchanged——与同族 batch-block-pages 的
		// bound/unchanged 双计数口径一致，取证时区分真实变更与零写入。
		if changed {
			bound++
		} else {
			unchanged++
		}
	}
	idStrs := make([]string, len(uniqueIDs))
	for i, id := range uniqueIDs {
		idStrs[i] = strconv.Itoa(id)
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("批量绑定安全策略 [%s]（%s）：成功 %d 条，不变 %d 条，跳过 %d 条", strings.Join(idStrs, ","), req.Mode, bound, unchanged, len(skipped)),
		SuccessMsg:  "批量绑定完成",
		Data:        gin.H{"bound": bound, "unchanged": unchanged, "skipped": skipped},
	})
}

// splitChildSpec 是一次「混合策略拆分」要落库的单职子策略：阶段、名称与
// insertChild 写入的全部业务列（爬虫豁免列在构造时按阶段归一）。
type splitChildSpec struct {
	policyType     string
	name           string
	mode           string
	aclMode        string
	aclList        string
	aclEnabled     bool
	whitelist      json.RawMessage
	wlEnabled      bool
	blacklist      json.RawMessage
	rlEnabled      bool
	rlRPS          int
	rlBurst        int
	crsGroups      string
	crsExcluded    string
	customRules    string
	blockPageID    int
	blockStatus    int
	geoCountries   json.RawMessage
	geoMode        string
	crawlerExempt  bool
	crawlerEngines string
	wafResp        bool
	logBody        bool
	aclRefs        string
	wlRefs         string
	trustDetection bool
}

// splitChildIdentity 是子策略的可比较身份：落库列全集，仅排除操作者痕迹
// （updated_by）与时间戳。重试拆分时「配置完全一致」才允许复用既有子策略。
// 全部为标量，可直接用 == 比较（Slice/Map 字段不进身份）。
type splitChildIdentity struct {
	policyType     string
	name           string
	description    string
	mode           string
	anomalyThr     int
	aclMode        string
	aclList        string
	aclEnabled     bool
	whitelist      string
	wlEnabled      bool
	blacklist      string
	rlEnabled      bool
	rlRPS          int
	rlBurst        int
	crsGroups      string
	crsExcluded    string
	customRules    string
	blockPageID    int
	blockStatus    int
	enabled        bool
	geoCountries   string
	geoMode        string
	crawlerExempt  bool
	crawlerEngines string
	wafResp        bool
	logBody        bool
	aclRefs        string
	wlRefs         string
	trustDetection bool
}

// errSplitChildConflict 表示已存在同名同阶段但配置不同的策略：拆分必须显式
// 冲突而不是静默复用（否则会把管理员另行创建/改动过的策略纳入本次迁移）。
var errSplitChildConflict = errors.New("同名同阶段策略配置不一致")

func splitChildIdentityOfSpec(p *models.SecurityPolicy, spec splitChildSpec) splitChildIdentity {
	return splitChildIdentity{
		policyType: spec.policyType, name: spec.name,
		description: p.Description, mode: spec.mode, anomalyThr: p.AnomalyThreshold,
		aclMode: spec.aclMode, aclList: spec.aclList, aclEnabled: spec.aclEnabled,
		whitelist: string(spec.whitelist), wlEnabled: spec.wlEnabled, blacklist: string(spec.blacklist),
		rlEnabled: spec.rlEnabled, rlRPS: spec.rlRPS, rlBurst: spec.rlBurst,
		crsGroups: spec.crsGroups, crsExcluded: spec.crsExcluded, customRules: spec.customRules,
		blockPageID: spec.blockPageID, blockStatus: spec.blockStatus, enabled: p.Enabled,
		geoCountries: string(spec.geoCountries), geoMode: spec.geoMode,
		crawlerExempt: spec.crawlerExempt, crawlerEngines: spec.crawlerEngines,
		wafResp: spec.wafResp, logBody: spec.logBody,
		aclRefs: spec.aclRefs, wlRefs: spec.wlRefs, trustDetection: spec.trustDetection,
	}
}

func splitChildIdentityOfPolicy(stored *models.SecurityPolicy) splitChildIdentity {
	return splitChildIdentity{
		policyType: stored.PolicyType, name: stored.Name,
		description: stored.Description, mode: stored.Mode, anomalyThr: stored.AnomalyThreshold,
		aclMode: stored.IPACLMode, aclList: stored.IPACLList, aclEnabled: stored.IPACLEnabled,
		whitelist: string(stored.IPWhitelist), wlEnabled: stored.IPWhitelistEnabled, blacklist: string(stored.IPBlacklist),
		rlEnabled: stored.RateLimitEnabled, rlRPS: stored.RateLimitRPS, rlBurst: stored.RateLimitBurst,
		crsGroups: string(stored.CRSRuleGroups), crsExcluded: string(stored.CRSExcludedRules), customRules: string(stored.CustomRules),
		blockPageID: stored.BlockPageID, blockStatus: stored.BlockStatusCode, enabled: stored.Enabled,
		geoCountries: string(stored.GeoIPCountries), geoMode: stored.GeoIPMode,
		crawlerExempt: stored.GeoIPCrawlerExempt, crawlerEngines: string(stored.GeoIPCrawlerEngines),
		wafResp: stored.WAFCheckResponse, logBody: stored.LogRequestBody,
		aclRefs: stored.IPACLListRefs, wlRefs: stored.IPWhitelistRefs, trustDetection: stored.TrustDetection,
	}
}

// resolveSplitChild 查找首轮拆分已创建的同名同阶段子策略：配置完全一致则返回
// 其 ID（复用，不再插入），配置不一致返回 errSplitChildConflict，无同名行返回
// 0。查询用 List/Get 同一列投影（COALESCE 口径一致），身份比较覆盖 insertChild
// 写入的全部业务列。
func resolveSplitChild(ctx context.Context, tx *sql.Tx, p *models.SecurityPolicy, spec splitChildSpec) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+securityPolicySelectColumns+` FROM security_policies WHERE name=? AND policy_type=? ORDER BY id`, spec.name, spec.policyType)
	if err != nil {
		return 0, fmt.Errorf("查询同名子策略: %w", err)
	}
	defer rows.Close()
	want := splitChildIdentityOfSpec(p, spec)
	conflict := false
	for rows.Next() {
		var stored models.SecurityPolicy
		if err := scanSecurityPolicy(rows, &stored); err != nil {
			return 0, fmt.Errorf("读取同名子策略: %w", err)
		}
		if splitChildIdentityOfPolicy(&stored) == want {
			return stored.ID, nil
		}
		conflict = true
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("遍历同名子策略: %w", err)
	}
	if conflict {
		return 0, errSplitChildConflict
	}
	return 0, nil
}

// SplitSecurityPolicy 混合策略一键拆分迁移（2026-09-20 用户裁定）：仅 mixed
// 策略可用——按特征组生成「原名（阶段 N）」单职子策略（空组不生成；阶段 1/3
// 子策略继承拦截页，阶段 2 恒 429、拦截页继承原策略——2026-09-25 用户裁
// 定可配），全量重映射绑定（每条规则删原绑定+插全部子策略绑定；协议门
// loadRuleBindingTarget 判非 HTTP 规则/规则不存在的进 skipped、合并后超
// maxBindingsPerRule 上限的规则进 skipped
// 并保留原绑定），无 skipped 才删除原策略（仍有规则引用时保留并在响应
// 标记）。单事务一次
// finishTxApply（单渲染）。
func (h *Handlers) SplitSecurityPolicy(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略写操作") {
		return
	}
	// 非规范数字 ID 家族门——SQLite INTEGER 亲和会让
	// "5.0" 命中行 5，使本端点绕过同族一致的输入门（Delete/Unbind/更新端点
	// 均在此 400）。
	if _, ok := parsePositiveNumericID(c.Param("id")); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的策略 ID"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	id := c.Param("id")
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	defer tx.Rollback()
	var p models.SecurityPolicy
	if err := scanSecurityPolicyRow(tx.QueryRowContext(caddyWriteCtx(c), `SELECT `+securityPolicySelectColumns+` FROM security_policies WHERE id=?`, id), &p); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "策略不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if p.PolicyType != models.PolicyTypeMixed {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "仅混合策略支持拆分迁移（单职策略无需拆分）"})
		return
	}
	features := models.PolicyTypeFeatures(&p)
	operator := int(contextUserID(c))
	type createdPolicy struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		PolicyType string `json:"policy_type"`
	}
	created := make([]createdPolicy, 0, 3)
	newIDs := make([]int, 0, 3)
	// 爬虫豁免同随子策略的阶段归一——仅地域拦截启用形态的子策略保留豁免位；
	// 阶段外子策略（geo_mode=off）恒 0/[]，避免拆分把开关复制给所有子策略、
	// 类型往返后静默复活。
	completeChild := func(spec splitChildSpec) splitChildSpec {
		geoipActive := spec.geoMode != "" && spec.geoMode != "off"
		spec.crawlerExempt = crawlerExemptBool(p.GeoIPCrawlerExempt, geoipActive)
		spec.crawlerEngines = "[]"
		if geoipActive {
			spec.crawlerEngines = string(p.GeoIPCrawlerEngines)
		}
		return spec
	}
	insertChild := func(spec splitChildSpec) (int, error) {
		result, err := tx.ExecContext(caddyWriteCtx(c), `INSERT INTO security_policies (name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_whitelist_enabled, ip_blacklist,
			rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, geoip_countries, geoip_mode, geoip_crawler_exempt, geoip_crawler_engines, waf_check_response, log_request_body, ip_acl_list_refs, ip_whitelist_refs, updated_by, policy_type, trust_detection)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			spec.name, p.Description, spec.mode, p.AnomalyThreshold, spec.aclMode, spec.aclList, spec.aclEnabled, spec.whitelist, spec.wlEnabled, spec.blacklist,
			spec.rlEnabled, spec.rlRPS, spec.rlBurst, spec.crsGroups, spec.crsExcluded, spec.customRules, spec.blockPageID, spec.blockStatus, p.Enabled, spec.geoCountries, spec.geoMode, spec.crawlerExempt, spec.crawlerEngines, spec.wafResp, spec.logBody, spec.aclRefs, spec.wlRefs, operator, spec.policyType, spec.trustDetection)
		if err != nil {
			return 0, err
		}
		childID, _ := result.LastInsertId()
		return int(childID), nil
	}
	stageSuffix := map[string]string{models.PolicyTypeStage0: "（阶段 0）", models.PolicyTypeStage1: "（阶段 1）", models.PolicyTypeStage2: "（阶段 2）", models.PolicyTypeStage3: "（阶段 3）"}
	// 信任名单 → 阶段 0 子策略（2026-09-20 用户裁定）：trust_detection 恒 1
	// （保留检测记录=迁移前 DetectionOnly 语义的行为保持；用户可在子策略上
	// 改直通）。阶段 1 子策略不再携带信任字段（信任已归属阶段 0）。
	// 2026-09-21 口径修正：拆分谓词按「条目非空」判定而非 features.G0（后者
	// 另含 ip_whitelist_enabled 门）——信任开关关闭的存量混合策略拆分时不
	// 再静默丢信任条目，stage0 子策略原样携带禁用态（前端预演 hasTrustEntries
	// 同口径）。类型推断/回填不受此影响（InferPolicyType 仍用启用门）。
	trustEntriesNonEmpty := func() bool {
		for _, raw := range []string{string(p.IPWhitelist), p.IPWhitelistRefs} {
			var entries []json.RawMessage
			if err := json.Unmarshal([]byte(raw), &entries); err == nil && len(entries) > 0 {
				return true
			}
		}
		return false
	}()
	if utf8.RuneCountInString(p.Name)+utf8.RuneCountInString(stageSuffix[models.PolicyTypeStage3]) > securityNameMaxRunes {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "拆分后的子策略名称将超过 100 字符，请先缩短原策略名称"})
		return
	}
	// 拆分的校验面（与 Create 共享的三门，非「完全同门」）：①按本次将落库的
	// 子策略字段并集做引用存在性校验（拦截页/自定义规则/IP 名单 refs/CRS 排除
	// 作用域名单）；②内置威胁名单禁令；③全局策略数量上限。Create 的语义校验
	// （枚举、GeoIP 条目、限流形状、CIDR 列表、自定义规则 JSON、爬虫豁免、
	// CRS 字段）在此不重复执行：子策略是原策略列值的原样复制，这些列在原始
	// 写入路径（Create/Update 写侧校验）已过同款门；历史/带外写入的脏值由
	// 渲染层 fail-visible 兜底。对复制值再跑一遍只会把这些存量脏值从
	// 「渲染层拒绝生成配置」升级成「拆分端点整体不可用」，把迁移通道也堵死。
	// 渲染层仍是最后闸门。
	// 禁用态混合策略的引用可悬空（删除门只拦启用策略，
	// security_regression_13 钉住），直接复制给子策略会让 ACL/信任合并集静默
	// 缩窄为 inline-only、自定义拦截/拦截页静默缺席，且归因困难（启用门在
	// 「另一次操作」才报错）。拒绝拆分并指引先修原策略——不产生半截子策略。
	// 子策略 ACL 模式归一：空 ip_acl_mode 为存量脏值，与 Create 的缺省归一
	// （deny）同口径。校验与落库共用同一形态——校验用归一值、写入用原值会让
	// 「存量为空」的策略拆出 ip_acl_mode='' 的子策略（写入形态与校验结论脱节）。
	childACLMode := "deny"
	if features.G1 && p.IPACLMode != "" {
		childACLMode = p.IPACLMode
	}
	if trustEntriesNonEmpty || features.G1 || features.G2 || features.G3 {
		childCustomRules := ""
		childCRSExcluded := ""
		childBlockPageID := 0
		var childACLRefs, childWLRefs []int64
		if features.G3 {
			childCustomRules = rawJSONString(p.CustomRules)
			childCRSExcluded = rawJSONString(p.CRSExcludedRules)
		}
		if features.G1 {
			childACLRefs = parseIPListRefsIDs(p.IPACLListRefs)
		}
		if trustEntriesNonEmpty {
			childWLRefs = parseIPListRefsIDs(p.IPWhitelistRefs)
		}
		// 拦截页只有阶段 1/2/3 子策略携带（阶段 0 子策略恒 0）——仅当相应子
		// 策略会落库时才校验原策略的拦截页引用。
		if features.G1 || features.G2 || features.G3 {
			childBlockPageID = p.BlockPageID
		}
		if msg, err := validatePolicyReferenceExistence(tx, childBlockPageID, childCustomRules, childCRSExcluded, childACLRefs, childWLRefs); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "拆分迁移中止：原策略" + msg + "，请先修正原策略的引用后重试"})
			return
		}
		if msg, err := validateBuiltinThreatListRefs(tx, childACLRefs, childWLRefs, crsExcludedListRefs(childCRSExcluded), childACLMode); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		} else if msg != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "拆分迁移中止：原策略" + msg + "，请先修正原策略的引用后重试"})
			return
		}
	}
	// 本次拆分要落库的子策略（阶段顺序）。先解析「首轮是否已创建同名同阶段
	// 子策略」再计数与插入，使拆分可重入：部分规则被跳过时原策略保留（明确的
	// 恢复契约），管理员腾出位置后重试必须接着使用首轮子策略——每轮复制一套
	// 会挤占 200 条策略额度，并让策略列表/绑定出现同名歧义。
	specs := make([]splitChildSpec, 0, 4)
	if trustEntriesNonEmpty {
		specs = append(specs, completeChild(splitChildSpec{
			policyType: models.PolicyTypeStage0, name: p.Name + stageSuffix[models.PolicyTypeStage0],
			mode: "off", aclMode: "deny", aclList: "[]",
			whitelist: p.IPWhitelist, wlEnabled: p.IPWhitelistEnabled,
			blacklist:    json.RawMessage("[]"),
			crsGroups:    "[]",
			crsExcluded:  "[]",
			customRules:  "[]",
			geoCountries: json.RawMessage("[]"), geoMode: "off",
			aclRefs: "[]", wlRefs: p.IPWhitelistRefs,
			trustDetection: true,
		}))
	}
	if features.G1 {
		specs = append(specs, completeChild(splitChildSpec{
			policyType: models.PolicyTypeStage1, name: p.Name + stageSuffix[models.PolicyTypeStage1],
			mode: "off", aclMode: childACLMode, aclList: p.IPACLList, aclEnabled: p.IPACLEnabled,
			whitelist: json.RawMessage("[]"), blacklist: p.IPBlacklist,
			crsGroups: "[]", crsExcluded: "[]", customRules: "[]",
			blockPageID: p.BlockPageID, blockStatus: p.BlockStatusCode,
			geoCountries: p.GeoIPCountries, geoMode: p.GeoIPMode,
			aclRefs: p.IPACLListRefs, wlRefs: "[]",
		}))
	}
	if features.G2 {
		// stage2 子策略继承原策略拦截页（用户裁定：2026-09-25
		// 起 stage2 可配拦截页，拆分不得丢页）；block_status_code 保持归一 0
		//（阶段 2 恒 429 自动语义，与 normalizeOutOfStageFields 同口径）。
		specs = append(specs, completeChild(splitChildSpec{
			policyType: models.PolicyTypeStage2, name: p.Name + stageSuffix[models.PolicyTypeStage2],
			mode: "off", aclMode: "deny", aclList: "[]",
			whitelist: json.RawMessage("[]"), blacklist: json.RawMessage("[]"),
			rlEnabled: p.RateLimitEnabled, rlRPS: p.RateLimitRPS, rlBurst: p.RateLimitBurst,
			crsGroups: "[]", crsExcluded: "[]", customRules: "[]",
			blockPageID:  p.BlockPageID,
			geoCountries: json.RawMessage("[]"), geoMode: "off",
			aclRefs: "[]", wlRefs: "[]",
		}))
	}
	if features.G3 {
		specs = append(specs, completeChild(splitChildSpec{
			policyType: models.PolicyTypeStage3, name: p.Name + stageSuffix[models.PolicyTypeStage3],
			mode: p.Mode, aclMode: "deny", aclList: "[]",
			whitelist: json.RawMessage("[]"), blacklist: json.RawMessage("[]"),
			crsGroups: rawJSONString(p.CRSRuleGroups), crsExcluded: rawJSONString(p.CRSExcludedRules), customRules: rawJSONString(p.CustomRules),
			blockPageID: p.BlockPageID, blockStatus: p.BlockStatusCode,
			geoCountries: json.RawMessage("[]"), geoMode: "off",
			wafResp: p.WAFCheckResponse, logBody: p.LogRequestBody,
			aclRefs: "[]", wlRefs: "[]",
		}))
	}
	// 解析既有子策略：配置完全一致 → 复用首轮 ID（不重复插入）；同名同阶段但
	// 配置不同 → 冲突 409，且在任何插入之前整体中止（不留半截子策略、不静默
	// 复用管理员另行创建/改动过的同名策略）。
	resolvedIDs := make([]int, len(specs))
	pendingInsert := 0
	for index, spec := range specs {
		existingID, err := resolveSplitChild(caddyWriteCtx(c), tx, &p, spec)
		if err != nil {
			if errors.Is(err, errSplitChildConflict) {
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: fmt.Sprintf("拆分迁移中止：已存在同名同阶段但配置不同的策略「%s」，请先处理该策略后再拆分", spec.name)})
				return
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		resolvedIDs[index] = existingID
		if existingID == 0 {
			pendingInsert++
		}
	}
	// 全局数量上限（与 Create 同口径）：一次拆分最多新建 4 条子策略，
	// 计数与插入同事务同锁（BEGIN IMMEDIATE），查询失败 fail-closed——否则
	// 「策略总数未到上限」的检查点可被拆分批量绕开（200 条混合策略一次拆成
	// 800 条子策略）。复用的首轮子策略已在库内计数，只对真正新增的行计入额度。
	if pendingInsert > 0 {
		var policyCount int
		if err := tx.QueryRowContext(caddyWriteCtx(c), "SELECT COUNT(*) FROM security_policies").Scan(&policyCount); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计安全策略数量失败"})
			return
		}
		if policyCount+pendingInsert > securityPolicyMaxGlobalCount {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("安全策略总数上限为 %d 条，本次拆分将新增 %d 条子策略（当前 %d 条），请先清理不再使用的策略", securityPolicyMaxGlobalCount, pendingInsert, policyCount)})
			return
		}
	}
	reusedCount := 0
	for index, spec := range specs {
		childID := resolvedIDs[index]
		if childID == 0 {
			insertedID, err := insertChild(spec)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			childID = insertedID
		} else {
			reusedCount++
		}
		created = append(created, createdPolicy{ID: childID, Name: spec.name, PolicyType: spec.policyType})
		newIDs = append(newIDs, childID)
	}
	// 全量重映射：逐规则删原绑定+插全部子策略绑定；合并后超上限进 skipped
	// （保留原绑定不动，防止静默丢防护）。
	boundRules := []string{}
	ruleRows, err := tx.QueryContext(caddyWriteCtx(c), "SELECT rule_caddy_id FROM security_policy_bindings WHERE policy_id=? ORDER BY rule_caddy_id", p.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	for ruleRows.Next() {
		var ruleID string
		if err := ruleRows.Scan(&ruleID); err != nil {
			ruleRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		boundRules = append(boundRules, ruleID)
	}
	// ⑬：迭代失败显式 500——漏查会以「零绑定
	// 规则」走完全量重映射并删除原策略，静默丢防护绑定。
	if err := ruleRows.Err(); err != nil {
		ruleRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	ruleRows.Close()
	if !trustEntriesNonEmpty && !features.G1 && !features.G2 && !features.G3 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该混合策略没有可拆分的特征组，无需拆分"})
		return
	}
	type skippedRule struct {
		RuleID string `json:"rule_id"`
		Reason string `json:"reason"`
	}
	remapped := 0
	skipped := make([]skippedRule, 0)
	for _, ruleID := range boundRules {
		// 协议门（与四个绑定写路径同一单源判定 loadRuleBindingTarget）：TCP
		// 规则不走 WAF/IP 访问控制/限流链（buildTCPServer 不消费安全策略），
		// 子策略复制绑定即「UI 宣称受保护、运行态零强制」+ 挤占
		// maxBindingsPerRule 额度——进 skipped 保留原绑定（与上限/stage2 门
		// 同口径）。带外形态：正常写路径已有协议门，非 HTTP 绑定行只能来自
		// 旧版本遗留/带外直写；规则行已删的悬挂绑定同门跳过，避免把悬挂行
		// 复制成 N 份子策略绑定污染绑定消费方。
		target, terr := loadRuleBindingTarget(caddyWriteCtx(c), tx, ruleID)
		if terr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", terr)})
			return
		}
		if !target.exists {
			skipped = append(skipped, skippedRule{ruleID, "规则不存在"})
			continue
		}
		if !target.http {
			skipped = append(skipped, skippedRule{ruleID, "安全策略仅支持绑定 HTTP 规则（TCP 规则不经过 WAF/IP 访问控制/限流链）"})
			continue
		}
		existingCount, cerr := bindingCountExcluding(caddyWriteCtx(c), tx, ruleID, p.ID)
		if cerr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", cerr)})
			return
		}
		if existingCount+len(newIDs) > maxBindingsPerRule {
			skipped = append(skipped, skippedRule{ruleID, fmt.Sprintf("合并后超过 %d 条策略上限（%d+%d）", maxBindingsPerRule, existingCount, len(newIDs))})
			continue
		}
		// 限流策略唯一门：拆分产出 stage2 子策略（features.G2）时，
		// 该规则现存的其他绑定若已含 stage2（mixed 存量 [mixed,stage2] 并存
		// 形态合法——BindRuleToPolicy 唯一门不追溯存量），直接重映射会出现
		// 单规则双限流——进 skipped 保留原绑定（与绑定上限同口径），解除现有
		// stage2 绑定后可重新拆分。
		if features.G2 {
			var otherStage2 int
			if err := tx.QueryRowContext(caddyWriteCtx(c), `SELECT COUNT(*) FROM security_policy_bindings b JOIN security_policies sp ON sp.id=b.policy_id
				WHERE b.rule_caddy_id=? AND sp.policy_type='stage2' AND b.policy_id != ?`, ruleID, p.ID).Scan(&otherStage2); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
			if otherStage2 > 0 {
				skipped = append(skipped, skippedRule{ruleID, "已有绑定的限流策略（每条规则最多一条限流策略）"})
				continue
			}
		}
		if _, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleID, p.ID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		for _, childID := range newIDs {
			if _, err := tx.ExecContext(caddyWriteCtx(c), "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleID, childID); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
				return
			}
		}
		remapped++
	}
	// 仍有规则引用时保留原策略（skipped 规则的原绑定仍在生效），否则删除。
	deletedOriginal := false
	if len(skipped) == 0 {
		if _, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_policies WHERE id=?", p.ID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		deletedOriginal = true
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("拆分迁移混合策略「%s」(#%d)：创建 %d 条单职策略（复用首轮 %d 条），重映射 %d 条规则，跳过 %d 条", p.Name, p.ID, len(created), reusedCount, remapped, len(skipped)),
		SuccessMsg:  "拆分迁移完成",
		Data:        gin.H{"created": created, "reused": reusedCount, "remapped": remapped, "skipped": skipped, "deleted_original": deletedOriginal},
	})
}

func (h *Handlers) UnbindRuleFromPolicy(c *gin.Context) {
	if rejectWriteDuringImport(c, "执行安全策略绑定操作") {
		return
	}
	policyID := c.Param("id")
	if _, ok := parsePositiveNumericID(policyID); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "策略 ID 无效"})
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	ruleCaddyID := c.Param("caddy_id")
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启事务失败"})
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(caddyWriteCtx(c), "DELETE FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=?", ruleCaddyID, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	affected, aerr := res.RowsAffected()
	if aerr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取写入结果失败", aerr)})
		return
	}
	if affected == 0 {
		// 幂等入口保留 200，但无变更不得写「已解除」审计：重复提交/并发解绑
		// 会制造一条未发生的绑定解除记录（审计是取证面，虚假变更为害）。
		_ = tx.Rollback()
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "该规则未与此策略建立绑定", Data: gin.H{"changed": false}})
		return
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "安全策略", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("解除规则 %s 与策略 #%s 的绑定", ruleCaddyID, policyID),
		SuccessMsg:  "已取消关联",
		Data:        gin.H{"changed": true},
	})
}

func (h *Handlers) GetSecurityPolicyBindings(c *gin.Context) {
	ruleCaddyID := c.Param("caddy_id")
	// v2.2.0：返回 []policy ASC（一规则可绑多策略）；无绑定时返回空数组而非 null，
	// 前端 `.length`/`.map` 不需要空值分支。
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	policyIDs := []int{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
			return
		}
		policyIDs = append(policyIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	rows.Close()
	policies := make([]models.SecurityPolicy, 0, len(policyIDs))
	for _, policyID := range policyIDs {
		var p models.SecurityPolicy
		// 与 securityPolicySelectColumns 同 33 列同序投影（COALESCE 默认值），
		// 任一可空列 NULL 不再使整接口 500；WHERE enabled=1 语义不变（NULL-enabled
		// 仍被 SQL 过滤）。
		if err := scanSecurityPolicyRow(db.DB.QueryRow(`SELECT `+securityPolicySelectColumns+`
			FROM security_policies WHERE id=? AND enabled=1`, policyID), &p); err != nil {
			if err == sql.ErrNoRows {
				// 策略被并发删除或被禁用：跳过该项，保持数组与绑定表一致
				continue
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
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
// 格式化为展示文本：中国 → "中国·广东·深圳·电信"（运营商有值且非 "0" 时追加，
// v4 xdb 第 4 段为 ISP——实测 114.114.114.114=中国|江苏省|南京市|0|CN、
// 180.101.245.246=中国|江苏省|南京市|电信|CN）；海外 → "国家·省州·城市·ISP(IDC)"
// 精确拼接（2026-09-13 用户裁定，弹框展示完整精度，列表侧由前端 compactLocation
// 精简；v2.3.7 修正起国家段经 geoipnames.CountryChinese 中文化——事件列表/
// 弹框显示「美国·California」，未收录国名回退英文原名）；Reserved → "保留地址"；
// 未知/畸形 → ""。
func formatIP2RegionLocation(region string) string {
	fields := strings.Split(region, "|")
	if len(fields) < 5 || fields[0] == "" || fields[0] == "0" {
		return ""
	}
	if fields[0] == "Reserved" {
		return "保留地址"
	}
	if fields[0] != "中国" {
		// 海外精确化(2026-09-13 用户裁定):与国内同构拼接非 0 段
		// 国家·省州·城市·ISP(IDC)——弹框展示完整精度;列表仍由前端
		// compactLocation 精简(海外取首段即国家)。国家段中文化
		// (v2.3.7 修正):仅展示层翻译,X-LB-GeoIP-Loc 发射链不动。
		parts := []string{geoipnames.CountryChinese(fields[0])}
		for _, f := range fields[1:4] {
			if f != "" && f != "0" {
				parts = append(parts, f)
			}
		}
		return strings.Join(parts, "·")
	}
	parts := []string{"中国"}
	for _, f := range fields[1:3] {
		f = strings.TrimSpace(f)
		if f == "" || f == "0" {
			continue
		}
		parts = append(parts, ip2RegionShortenName(f))
	}
	if isp := strings.TrimSpace(fields[3]); isp != "" && isp != "0" {
		parts = append(parts, isp)
	}
	return strings.Join(parts, "·")
}

// isReservedIP 判定保留/私网/回环/链路本地/未指定/组播及特殊用途地址
// （判据单源在 services.IsReservedClientIP：攻击光流环的入环过滤与本节
// 各消费面必须逐点相等，否则会出现「入口不排、出口才排」的配额挤占）。
func isReservedIP(ip string) bool { return services.IsReservedClientIP(ip) }

// isMissingOrReservedIP 统一威胁事件消费面的无地址/保留地址过滤：
// 空串与纯空白不是可归属的真实来源，且不得绕过保留地址排除口径。
func isMissingOrReservedIP(ip string) bool {
	return strings.TrimSpace(ip) == "" || isReservedIP(ip)
}

// ruleTriggeredFamilyPrefixes 触发规则筛选的 family 标签 → ID 精确值集合
// （单 ID 族全部由 legacyRuleFamilies 派生——族归属只有一处定义；
// 「WAF 规则（CRS）」为复合 GLOB 条件单独处理，不在此表；「自定义规则」无
// LIKE 前缀可表达长度约束，由 customRuleFamilyCondition 整体承载）。本表与
// ruleTriggeredFilterSQL 的单段解析、ruleTriggeredMultiFilterSQL 的逐段结构化
// 判定共用，改动需与前端筛选选项/triggeredLabel 显示标签、categorizeAttack
// 总览口径三侧同步。
var ruleTriggeredFamilyPrefixes = buildRuleTriggeredFamilyPrefixes()

func buildRuleTriggeredFamilyPrefixes() map[string][]string {
	// 形态条件族与多字符 CRS 前缀族保持手写；单 ID 族（信任名单/IP 访问
	// 控制/地域拦截/威胁情报库/请求体异常/限流）由 id→家族表派生。
	families := map[string][]string{
		// v2.3.8 触发类型扩展：爬虫Bot（810000-899999 全段）形态条件由
		// crawlerFamilyCondition 承载（互斥 6 位 GLOB）。旧两位前缀
		// "81"/"85" 生成 rule_triggered='81' 精确匹配，永不命中 6 位真实 id。
		"爬虫Bot": {},
		// WAF·自定义（customRuleFamilyCondition 复用）；「自定义规则」同条件。
		"WAF·自定义": {},
		"自定义规则":   {},
		"评分拦截":    {"949", "959"},
		"协议异常":    {"920"},
		"协议攻击":    {"921"},
	}
	ids := make([]int, 0, len(legacyRuleFamilies))
	for id := range legacyRuleFamilies {
		ids = append(ids, id)
	}
	// 排序保证生成的 SQL 条件与参数顺序稳定（映射遍历顺序随机）。
	sort.Ints(ids)
	for _, id := range ids {
		key := legacyRuleFamilies[id].key
		families[key] = append(families[key], strconv.Itoa(id))
	}
	return families
}

// customRuleFamilyCondition 自定义规则族的 ID 形态条件——与 attackFamilyClassOf
// 的自定义判定（收敛单一事实源，两个 Go 视图函数共用）严格同口径：5 位任意
// 数字 ID、6 位 1xxxxx-7xxxxx、≥7 位且以 1 开头的旧内嵌合成 ID，以及
// ≥7 位的 OR 条件分支 ID（当前首数字 3-6）。8xxxxx/9xxxxx 由地域爬虫与 CRS 段独占。
// appendFamilyPrefixCondition(2026-09-10 ):单数字族(id 2/3/4/5/7/8/11)
// 为精确匹配——LIKE 前缀会让自定义规则 5 位 ID(24567 等)交叉命中 IP/地域族;
// 多字符前缀(949/959/920/921)对应 6 位 CRS ID,保持前缀语义。
func appendFamilyPrefixCondition(ors *[]string, args *[]any, prefix string) {
	// 单数字族（2/3/4/5/7/8）与两位完整 id 族（14=威胁情报库）为精确匹配——
	// LIKE 前缀会让自定义规则 5 位 ID（24567/14xxxx 等）交叉命中 IP/威胁族。
	// 3 字符前缀不全是 CRS 族——「限流」是 429 精确 ID，
	// 旧实现无条件 prefix+"___" 生成 LIKE '429___'，永不命中。CRS 六位 ID
	// 恒以 9 开头（920/921/949/959 族），据此区分：9 开头仍长度锚定，其余
	// 3 字符按精确匹配。
	if len(prefix) == 1 || len(prefix) == 2 || (len(prefix) == 3 && !strings.HasPrefix(prefix, "9")) {
		*ors = append(*ors, "rule_triggered = ?")
		*args = append(*args, prefix)
		return
	}
	// 3 字符前缀族（920/921/949/959）恒对应 6 位 CRS id——LIKE 前缀不约束长度会
	// 交叉命中 5 位自定义规则发射 id（crID≥82000 时发射 92000-99999，历史
	// 与 categorizeAttack「len==5 先行归自定义」对齐）：追加三个下划线
	// 锚定总长 6 位。
	*ors = append(*ors, "rule_triggered LIKE ?")
	*args = append(*args, prefix+"___")
}

const customRuleFamilyCondition = "(rule_triggered GLOB '[0-9][0-9][0-9][0-9][0-9]' OR rule_triggered GLOB '[1-7][0-9][0-9][0-9][0-9][0-9]' OR rule_triggered GLOB '1[0-9][0-9][0-9][0-9][0-9][0-9]*' OR rule_triggered GLOB '[3-6][0-9][0-9][0-9][0-9][0-9][0-9]*')"

// geoipFamilyCondition 地域拦截族的预检精确段形态条件（阶段化模型：
// buildIPPrecheckDirectives 逐策略链 id=800000+policyID）——6 位 8xxxxx。
// 段界单一事实源=services.IsGeoIPPrecheckID；本 GLOB 为 SQL 文本形态,
// 段基址调整时须与谓词同步修订。
// 旧共享 id:8 由 ruleTriggeredFamilyPrefixes「地域拦截」表单值精确匹配覆盖。
const geoipFamilyCondition = "rule_triggered GLOB '80[0-9][0-9][0-9][0-9]'"

// crawlerFamilyCondition 爬虫两族（豁免 [810000,850000) + 伪装 [850000,900000)）
// 的 SQL 形态：6 位 8 开头且第二位非 0——与 geoipFamilyCondition('80....') 互斥，
// 与 services 侧 encode/decodePrecheckRuleID 段界单一事实源同步。
const crawlerFamilyCondition = "rule_triggered GLOB '8[1-9][0-9][0-9][0-9][0-9]'"

// ruleTriggeredPartStructured 报告一段筛选输入是否可按结构化路径解析（family
// 精确/family 部分前缀/WAF 规则（CRS）或其前缀/纯数字）——只能走消息关键词
// 路径（含逗号的消息词）的段返回 false，多值拆分据此决定整串回退。
func ruleTriggeredPartStructured(input string) bool {
	if input == "" {
		return false
	}
	if input == "WAF 规则（CRS）" || strings.HasPrefix("WAF 规则（CRS）", input) {
		return true
	}
	// 前端事件页多选筛选值为「WAF·CRS」（SecurityEvents.vue
	// 筛选项/triggeredLabel），旧实现只识别显示标签「WAF 规则（CRS）」——多值任一段
	// 不可结构化即整串回退字面量 LIKE，而 rule_triggered 只存规则 ID，查询恒空
	// （正向）/排除失效（反向）。两个标签必须同等结构化。
	if input == "WAF·CRS" || strings.HasPrefix("WAF·CRS", input) {
		return true
	}
	if _, ok := ruleTriggeredFamilyPrefixes[input]; ok {
		return true
	}
	for label := range ruleTriggeredFamilyPrefixes {
		if strings.HasPrefix(label, input) {
			return true
		}
	}
	for _, r := range input {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ruleTriggeredMultiFilterSQL 逗号多值筛选：单值与 ruleTriggeredFilterSQL 逐字节
// 一致；多值逐段复用单段解析后以 OR 连接（args 顺序保持段序）。任一段只能走消息
// 关键词路径时整串回退单输入（保护「sqlmap, brute force」这类含逗号消息词）。
// 正/反向共用：反向由调用方对返回片段套 NOT。
func ruleTriggeredMultiFilterSQL(input string, args *[]any) string {
	if !strings.Contains(input, ",") {
		return ruleTriggeredFilterSQL(input, args)
	}
	// 尾随/连续逗号产生的空段必须先剔除——空段不可
	// 结构化会令整串回退字面量 LIKE（静默错结果），而不是按剩余有效段 OR。
	rawParts := strings.Split(input, ",")
	parts := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ruleTriggeredFilterSQL(input, args)
	}
	for _, p := range parts {
		if !ruleTriggeredPartStructured(p) {
			return ruleTriggeredFilterSQL(input, args)
		}
	}
	ors := make([]string, 0, len(parts))
	for _, p := range parts {
		ors = append(ors, ruleTriggeredFilterSQL(p, args))
	}
	if len(ors) == 0 {
		return ruleTriggeredFilterSQL(input, args)
	}
	return "(" + strings.Join(ors, " OR ") + ")"
}

// ruleTriggeredFilterSQL 构建触发规则筛选条件：family 标签（含部分输入）映射为
// ID 前缀/形态集合 OR 匹配，否则退回「精确/前缀/消息」子串。返回的片段自带外层
// 括号，正向用 AND 拼接、反向由调用方套 NOT（rule_triggered_exclude 复用同映射）。
// family 口径与前端筛选选项/triggeredLabel 显示标签一一对应，改动需三侧同步。
func ruleTriggeredFilterSQL(input string, args *[]any) string {
	// WAF 规则（CRS）：全部 6 位 CRS 规则 ID（恒 9xxxxx——含 920/921 协议族与
	// 949/959 评估族——用户心智模型「CRS 即 WAF 规则」；细分仍可输入细标签
	// （评分拦截/协议异常）或规则 ID 前缀过滤，family 映射全部保留）。GLOB
	// 限 9 开头：GeoIP 预检段 800xxx 同为 6 位数字，不限会被本族误吞。
	const wafCRSCondition = "rule_triggered GLOB '9[0-9][0-9][0-9][0-9][0-9]'"
	if input == "WAF 规则（CRS）" || input == "WAF·CRS" {
		return "(" + wafCRSCondition + ")"
	}
	if prefixes, isFamily := ruleTriggeredFamilyPrefixes[input]; isFamily {
		ors := make([]string, 0, len(prefixes)+1)
		for _, p := range prefixes {
			appendFamilyPrefixCondition(&ors, args, p)
		}
		// 自定义规则族无 LIKE 前缀（表内为空集），以长度约束条件整体并入；
		// 地域拦截族并入预检精确段形态条件（800xxx，旧 id:8 由前缀表精确覆盖）。
		if input == "自定义规则" || input == "WAF·自定义" {
			ors = append(ors, customRuleFamilyCondition)
		}
		if input == "地域拦截" {
			ors = append(ors, geoipFamilyCondition)
		}
		if input == "爬虫Bot" {
			ors = append(ors, crawlerFamilyCondition)
		}
		return "(" + strings.Join(ors, " OR ") + ")"
	}
	// family 标签的部分输入：宽匹配（前缀命中任一 family 即并入其前缀集合）。
	matched := false
	ors := make([]string, 0, 6)
	for label, ps := range ruleTriggeredFamilyPrefixes {
		if strings.HasPrefix(label, input) {
			matched = true
			for _, p := range ps {
				appendFamilyPrefixCondition(&ors, args, p)
			}
		}
	}
	// 两个 WAF 标签（显示标签 + 紧凑标签）任一前缀命中即并入同一条 CRS 形态
	// 条件——各自 append 会让输入 "W" 这类同时命中两者的前缀拼出重复谓词
	// `((GLOB '9…') OR (GLOB '9…'))`。
	if strings.HasPrefix("WAF 规则（CRS）", input) || strings.HasPrefix("WAF·CRS", input) {
		matched = true
		ors = append(ors, wafCRSCondition)
	}
	if matched {
		if strings.HasPrefix("自定义规则", input) || strings.HasPrefix("WAF·自定义", input) {
			ors = append(ors, customRuleFamilyCondition)
		}
		if strings.HasPrefix("地域拦截", input) {
			ors = append(ors, geoipFamilyCondition)
		}
		if strings.HasPrefix("爬虫Bot", input) {
			ors = append(ors, crawlerFamilyCondition)
		}
		if len(ors) > 0 {
			return "(" + strings.Join(ors, " OR ") + ")"
		}
		// 前缀命中的 family 前缀集为空且无可并入的形态条件：不得返回 "()"，
		// 落到下方消息关键词路径（保守但语法合法）。
	}
	// 纯数字输入（CRS 规则 ID）：「精确 OR 前缀」匹配避免双 % 全字段扫描；
	// 其余按消息关键词双 LIKE（rule_msg 无结构可言）。
	allDigits := len(input) > 0
	for _, r := range input {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		*args = append(*args, input, input+"%", "%"+escapeLikePattern(input)+"%")
		return "(rule_triggered = ? OR rule_triggered LIKE ? OR rule_msg LIKE ? ESCAPE '\\')"
	}
	*args = append(*args, "%"+escapeLikePattern(input)+"%", "%"+escapeLikePattern(input)+"%")
	return "(rule_triggered LIKE ? ESCAPE '\\' OR rule_msg LIKE ? ESCAPE '\\')"
}

// GetIPEventCount 返回指定 IP 近 N 天(默认 30)的安全事件计数——IP 弹框
// 快捷拉黑时的上下文展示(用户批准)。走 idx_security_events_ip_time
// 索引范围 COUNT,单 IP 时间窗毫秒级;权限与事件列表一致(business 组)。
func (h *Handlers) GetIPEventCount(c *gin.Context) {
	ip := strings.TrimSpace(c.Query("ip"))
	if ip == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "缺少 ip 参数"})
		return
	}
	days := 30
	if raw := strings.TrimSpace(c.Query("days")); raw != "" {
		// 与分页参数同口径：非整数显式 400（静默回落会让拼写错误无信号），
		// <1 沿用默认、>365 钳到上限。
		v, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "days 参数无效"})
			return
		}
		if v >= 1 {
			if v > 365 {
				v = 365
			}
			days = v
		}
	}
	var count int
	if db.MetricsDB == nil {
		// MetricsDB 未装配（测试/嵌入形态）：按 0 返回而非 panic
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]int{"count": 0}})
		return
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE client_ip=? AND event_time >= datetime('now', '-' || ? || ' days')`, ip, days).Scan(&count); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询事件计数失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]int{"count": count}})
}

// geoIPCountriesEmpty 报告 geoip_countries 载荷是否为空名单（非法 JSON 视为空，
// 形状错误随后由 ValidateGeoIPCountries 显式 400）。
func geoIPCountriesEmpty(raw string) bool {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return true
	}
	return len(entries) == 0
}

// parsePaginationParam 是分页列表的统一解析口径（安全事件/CRS 列表、审计日志、
// 证书任务共用）：缺省或数值 <1 时沿用默认值；给出但非整数时 400（静默回落
// 会让调用方拼写错误完全无信号）；超上限钳到上限（防 *pageSize 溢出为负致
// SQLite OFFSET 报错，也让「page_size 传大」有可预期结果而非退回默认值）。
// 深翻页另有显式拒绝的端点（审计日志 page 超阈值 400），属该端点自身策略。
func parsePaginationParam(c *gin.Context, name string, def, cap int) (int, bool) {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return def, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "分页参数无效"})
		return 0, false
	}
	if v < 1 {
		return def, true
	}
	if v > cap {
		v = cap
	}
	return v, true
}

func (h *Handlers) ListSecurityEvents(c *gin.Context) {
	// page 上限 1000：SQLite OFFSET 线性丢弃，page_size=100 × page=100000 的
	// 深翻页单请求扫近千万行（秒级 CPU/IO，任意登录用户可触发且无端点级
	// 限流）。1000 页 × 100 条 = 覆盖最近 10 万事件，足够「跳末页」交互；
	// 更深的历史翻查走筛选/导出语义而非深 OFFSET。
	page, ok := parsePaginationParam(c, "page", 1, 1000)
	if !ok {
		return
	}
	pageSize, ok := parsePaginationParam(c, "page_size", 20, 100)
	if !ok {
		return
	}
	// 解析器已保证 1≤page≤cap、1≤pageSize≤cap（<1 回默认值，>cap 钳到
	// cap——契约见 TestListSecurityEvents_pageSizeClampsToCap）。
	offset := (page - 1) * pageSize

	where := " WHERE 1=1"
	var args []interface{}
	if action := c.Query("action"); action != "" {
		where += " AND action=?"
		args = append(args, action)
	}
	if ip := strings.TrimSpace(c.Query("ip")); ip != "" {
		// 前端输入为完整 IP：精确匹配，避免 LIKE 子串把 1.2.3.4 匹配到 11.2.3.40
		// TrimSpace 与同级过滤器同口径(复制粘贴首尾空格不再静默空页)。
		where += " AND client_ip = ?"
		args = append(args, ip)
	}
	if ruleID := c.Query("rule_caddy_id"); ruleID != "" {
		where += " AND rule_caddy_id=?"
		args = append(args, ruleID)
	}
	// （用户需求）：事件日志三列（负载规则/触发规则/策略）服务端筛选
	// ——r1 匹配事件时规则名快照（rule_name，跨删改名存活），policy 匹配策略名
	// 快照（policy_name）。快照列为摄取时落库的冗余文本，LIKE 子串即可（无索引，
	// 页级分页下可接受）。
	if ruleName := strings.TrimSpace(c.Query("rule_name")); ruleName != "" {
		where += " AND rule_name LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escapeLikePattern(ruleName)+"%")
	}
	if policyName := strings.TrimSpace(c.Query("policy_name")); policyName != "" {
		where += " AND policy_name LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escapeLikePattern(policyName)+"%")
	}

	// rule_triggered 筛选对齐表格显示语义——列显示的是 family 标签
	// 或原始 ID；用户按显示文本筛选时纯 ID LIKE 必然搜不到。输入按 family 标签
	// 映射为 ID 前缀集合 OR 匹配，否则退回 ID/消息子串。rule_triggered_exclude
	// 复用同一映射整体取反（大多数事件为单一类型时筛掉它看其余）。
	if ruleTriggered := strings.TrimSpace(c.Query("rule_triggered")); ruleTriggered != "" {
		where += " AND " + ruleTriggeredMultiFilterSQL(ruleTriggered, &args)
	}
	if exclude := strings.TrimSpace(c.Query("rule_triggered_exclude")); exclude != "" {
		// rule_triggered 允许 NULL；NOT(NULL) 仍为 NULL 会把行从「排除」
		// 结果里吞掉。仅在反向条件内按空串比较，
		// 正向筛选 SQL 保持原形状（既有钉测/索引口径不变）。
		cond := strings.ReplaceAll(ruleTriggeredMultiFilterSQL(exclude, &args), "rule_triggered", "COALESCE(rule_triggered,'')")
		where += " AND NOT (" + cond + ")"
	}

	// （用户需求）：URI 筛选（子串）。
	if uri := strings.TrimSpace(c.Query("uri")); uri != "" {
		where += " AND uri LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escapeLikePattern(uri)+"%")
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
	if db.MetricsDB == nil {
		// MetricsDB 未装配：返回空列表而非 panic。键与成功
		// 路径同形状（events——历史修正，此前误用 list 键）；
		// page/page_size 回显请求值（与成功路径一致，前端/Agent 的分页
		// 字段假设不因降级失真）。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]any{"events": []any{}, "total": 0, "page": page, "page_size": pageSize, "includes_reserved": true, "ingestion": services.SecurityEventsIngestionHealthSnapshot()}})
		return
	}
	// event_time 恒为 'YYYY-MM-DD HH:MM:SS' UTC 字符串，参数同形 —— 直接字符串比较
	// 即可走 idx_security_events_time 索引；两侧包 datetime() 会使索引失效。
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
		services.Logf("error", "security events: count query failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}

	queryArgs := append(args, pageSize, offset)
	// 事件表这些列 schema 可空（仅 DEFAULT、无 NOT NULL），
	// 带外/异常写入显式 NULL 会让整页 500——列表投影统一 COALESCE，与策略/拦截页/
	// 自定义规则的 NULL 容忍口径一致（security_null_coalesce_test.go）。
	// request_body / request_headers 在 SQL 侧只取截断上限（+1 探针）——
	// 此前整列（上行落库上限 64KB/字段）取回再在 Go 侧截到 16KB，
	// 100 行 × 2 字段最多传输 ~12.8MB 只为返回 ≤1.6MB；列表弹框只消费截断内容。
	// request_headers 是 map[string][]string 的 JSON 文本，超限行的前缀必然
	// 是半截 JSON：Go 侧只重序列化前缀中**完整**的成员（见
	// truncateEventListHeaders），被切断的键数由 securityEventListHeadersTotalSQL
	// 在 SQL 侧数出总键数后相减得出——前端仍按 _lb_list_dropped_headers 展示
	// 「已隐藏 N 个头」。
	rows, err := db.MetricsDB.Query(`SELECT e.id, e.event_time, COALESCE(e.rule_caddy_id,''), COALESCE(e.policy_id,0), COALESCE(e.client_ip,''), COALESCE(e.method,''), COALESCE(e.uri,''), COALESCE(e.event_type,''), COALESCE(e.rule_triggered,''), COALESCE(e.rule_msg,''), COALESCE(e.action,''), COALESCE(e.anomaly_score, 0),
		COALESCE(e.rule_name,''), COALESCE(e.policy_name,''), COALESCE(e.duration_us,0), COALESCE(e.precheck_us,0), `+securityEventListFieldSQL("e.request_headers")+`, `+securityEventListHeadersTotalSQL("e.request_headers")+`, `+securityEventListFieldSQL("e.request_body")+`
		FROM security_events e`+where+" ORDER BY e.event_time DESC, e.id DESC LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		// 与计数/扫描分支同口径：泛化文案 + 服务端留痕（不向登录用户泄露
		// 存储层错误文本）。
		services.Logf("error", "security events: list query failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		// headersTotalKeys 是该行 request_headers 的全部键数（SQL 侧数出）；
		// 前缀被切断时用它减去已解码键数得到被隐藏的键数。
		var headersTotalKeys int
		// Scan 失败必须中止：否则部分零值的事件行会被当作真实事件返回
		if err := rows.Scan(&e.ID, &e.EventTime, &e.RuleCaddyID, &e.PolicyID, &e.ClientIP, &e.Method, &e.URI, &e.EventType, &e.RuleTriggered, &e.RuleMsg, &e.Action, &e.AnomalyScore, &e.RuleName, &e.PolicyName, &e.DurationUs, &e.PrecheckUs, &e.RequestHeaders, &headersTotalKeys, &e.RequestBody); err != nil {
			services.Logf("error", "security events: scan failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
			return
		}
		e.IPLocation = enrichIPLocation(e.ClientIP)
		// 触发类型必须在 Scan 成功后、append 前接线——
		// 旧实现把赋值放在错误分支里，成功路径恒为空串（前端列全空）。
		e.TriggerType = triggerTypeForRule(e.RuleTriggered)
		// 列表响应字节上限：100 行 × 64KB 头/体可 >15MB。
		// 列表侧二次截断到 16KB/字段（详情弹框仍可看到截断标记）。
		// 头只重序列化前缀中完整的成员（被切断的键计入隐藏数）；体按 base64 4 对齐。
		e.RequestHeaders = truncateEventListHeaders(e.RequestHeaders, headersTotalKeys)
		e.RequestBody = truncateEventListBody(e.RequestBody)
		// 请求头/体含凭证明文（Cookie/Authorization/请求体），
		// 此前对任意登录用户/只读 Key 原样返回，掩码仅在前端——服务端脱敏。
		maskSecurityEventRequestContextIfNeeded(c, &e)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		services.Logf("error", "security events: rows iteration failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	if events == nil {
		events = []models.SecurityEvent{}
	}
	// includes_reserved 披露口径：事件列表 total/events 含私网/保留地址
	//（与安全总览同键披露；威胁大屏 rollup 排除——三面口径对称可见，
	// 跨面比数不等时该字段即解释）。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": events, "total": total, "page": page, "page_size": pageSize, "includes_reserved": true, "ingestion": services.SecurityEventsIngestionHealthSnapshot()}})
}

// escapeLikePattern 使用户筛选输入在 SQL LIKE 中保持字面量子串语义；
// 调用方负责包裹 % 并在 SQL 中声明 ESCAPE '\\'。
func escapeLikePattern(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

const securityEventListFieldCap = 16 * 1024

// securityEventListFieldSQL 事件列表的大字段投影：SQL 侧只取截断上限 +1 个
// **字节**（CAST AS BLOB 让 SUBSTR 按字节计）。+1 是超限探针——
// truncateEventListField 据此判定「原值更长」并追加截断标记；Go 侧再按 rune
// 边界回退到整字符，响应形态与「整列取回再截断」一致。
// 不用字符口径（SUBSTR 直接作用于 TEXT）：多字节内容会按 16K 字符取回最多
// ~64KB，而响应只保留 16KB 字节，4× 无谓传输随页面行数放大。
func securityEventListFieldSQL(column string) string {
	return "COALESCE(SUBSTR(CAST(" + column + " AS BLOB),1," + strconv.Itoa(securityEventListFieldCap+1) + "),'')"
}

func truncateEventListField(value string) string {
	if len(value) <= securityEventListFieldCap {
		return value
	}
	cut := securityEventListFieldCap
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut] + "\n...[TRUNCATED]"
}

// securityEventListHeadersTotalSQL 与 securityEventListFieldSQL 配套：只在
// 该列超限且为合法 JSON 时数出全部键数（否则 0）。被切断的键数 = 总键数 −
// Go 侧从前缀解出的键数——SQL 侧不传输键内容，只回一个整数。
// 超限判定必须与截断同口径（字节）：length(TEXT) 是字符数，多字节头值
// （非 ASCII 自定义头/未编码中文 Referer）会「字节超限而字符不超限」——
// 用字符口径判定就返回 0，列表弹框丢弃被切断的成员却不写隐藏计数。
func securityEventListHeadersTotalSQL(column string) string {
	capText := strconv.Itoa(securityEventListFieldCap)
	return "CASE WHEN length(CAST(COALESCE(" + column + ",'') AS BLOB)) > " + capText +
		" AND json_valid(" + column + ") THEN (SELECT COUNT(*) FROM json_each(" + column + ")) ELSE 0 END"
}

// truncateEventListHeaders 请求头列表侧截断：request_headers 是
// map[string][]string 的 JSON 文本。SQL 侧只取 securityEventListFieldCap+1 字节
// ——超限行的入参必然是被切断的前缀。这里把前缀中**完整**的成员逐个解出后
// 重新序列化（前端仍拿到合法 JSON 头表），被切断的键数按
// totalKeys − 已解出键数记入 securityEventListDroppedHeadersKey（列表 16KB
// 裁剪计数）——与采集 64KB 裁剪的 securityEventDroppedHeadersKey 分离，前端
// 按来源展示不同文案。
// 前缀本身解不出任何完整成员（首个值就超限）或非 JSON 形态（带外写入/历史
// 脏行）时退回字节截断 + 截断标记——前端降级为原文展示并亮截断横幅。
func truncateEventListHeaders(value string, totalKeys int) string {
	if len(value) <= securityEventListFieldCap {
		return value
	}
	headers, ok := decodeCompleteHeaderMembers(value)
	if !ok {
		return truncateEventListField(value)
	}
	// 前缀本身已用满 cap，追加丢弃计数会溢出——按体积降序丢条目直到放得下
	// （保留最多信息量；通常只需丢 1 个）。丢不下的键数并入丢弃计数。
	marshalWithinCap := func(headers map[string][]string) (string, bool) {
		payload := make(map[string][]string, len(headers)+1)
		for key, values := range headers {
			payload[key] = values
		}
		if dropped := totalKeys - len(headers); dropped > 0 {
			payload[securityEventListDroppedHeadersKey] = []string{strconv.Itoa(dropped)}
		}
		raw, err := json.Marshal(payload)
		if err != nil || len(raw) > securityEventListFieldCap {
			return "", false
		}
		return string(raw), true
	}
	if raw, ok := marshalWithinCap(headers); ok {
		return raw
	}
	type sizedKey struct {
		key  string
		size int
	}
	// 采集/列表侧计数键不参与丢弃（它们是写侧保留键，丢了对前端毫无信息量）。
	order := make([]sizedKey, 0, len(headers))
	for key, values := range headers {
		if key == securityEventDroppedHeadersKey || key == securityEventListDroppedHeadersKey {
			continue
		}
		keyJSON, _ := json.Marshal(key)
		valueJSON, _ := json.Marshal(values)
		order = append(order, sizedKey{key: key, size: len(keyJSON) + len(valueJSON) + 2})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].size != order[j].size {
			return order[i].size > order[j].size
		}
		return order[i].key < order[j].key
	})
	for _, entry := range order {
		delete(headers, entry.key)
		if raw, ok := marshalWithinCap(headers); ok {
			return raw
		}
	}
	// 连只剩计数键都超限（病态形态）：退回字节截断。
	return truncateEventListField(value)
}

// decodeCompleteHeaderMembers 流式解出 JSON 对象前缀中完整的 key→[]string
// 成员：截断点落在成员中间时，json.Decoder 在该成员处报错，此前的完整成员
// 保留。ok=false 表示未解出任何成员（含非对象/脏行），调用方退回字节截断。
func decodeCompleteHeaderMembers(prefix string) (map[string][]string, bool) {
	dec := json.NewDecoder(strings.NewReader(prefix))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	headers := make(map[string][]string)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			break
		}
		key, ok := keyTok.(string)
		if !ok {
			break
		}
		var values []string
		if err := dec.Decode(&values); err != nil {
			break
		}
		headers[key] = values
	}
	if len(headers) == 0 {
		return nil, false
	}
	return headers, true
}

// securityEventDroppedHeadersKey 与摄取侧写侧的丢弃计数合成键同源（采集
// 64KB 上限：快照插件与落库裁剪共用）——引用 services 导出常量，跨包字符串
// 契约不得各写一份字面量（改一侧另一边会静默漂移，列表裁剪会把采集计数键
// 当普通头统计/丢弃且不会编译失败）。
const securityEventDroppedHeadersKey = services.SecurityEventsDroppedHeadersKey

// securityEventListDroppedHeadersKey 是列表侧 16KB 裁剪的丢弃计数合成键——
// 与采集 64KB 的 securityEventDroppedHeadersKey 分离：头数多但总量 <64KB
// 的事件在列表弹框同样会被裁剪，并入同一键会让前端把 16KB 列表裁剪误标为
// 「超出 64KB 采集上限」。
const securityEventListDroppedHeadersKey = "_lb_list_dropped_headers"

// truncateEventListBody 请求体列表侧截断：base64/base64-truncated
// 载荷必须按 4 字符对齐切分（否则前端 atob 抛错、正文整块退化为原文），
// 切分后统一前缀为 base64-truncated: 让展示层渲染「已截断」横幅；文本
// （含 utf8: 转义前缀）沿用 rune 边界截断 + 尾部标记。
func truncateEventListBody(value string) string {
	if len(value) <= securityEventListFieldCap {
		return value
	}
	if payload, ok := strings.CutPrefix(value, "base64:"); ok {
		return truncateEventBase64Payload(payload)
	}
	if payload, ok := strings.CutPrefix(value, "base64-truncated:"); ok {
		return truncateEventBase64Payload(payload)
	}
	return truncateEventListField(value)
}

func truncateEventBase64Payload(payload string) string {
	const prefix = "base64-truncated:"
	budget := securityEventListFieldCap - len(prefix)
	if budget < 4 {
		budget = 4
	}
	cut := budget - budget%4
	if cut > len(payload) {
		cut = len(payload) - len(payload)%4
	}
	return prefix + payload[:cut]
}

// securityEventSensitiveHeaderNames 与前端 CTX_SENSITIVE_HEADERS 同源。
// 名单覆盖常见第三方凭据头（API Key/访问令牌/CSRF/上游透传令牌）——
// 仅 4 个经典头会让被拦请求携带的上游凭据对非管理员与只读 API Key 原样可读。
var securityEventSensitiveHeaderNames = map[string]struct{}{
	"cookie":                    {},
	"authorization":             {},
	"set-cookie":                {},
	"proxy-authorization":       {},
	"x-api-key":                 {},
	"x-auth-token":              {},
	"x-csrf-token":              {},
	"x-xsrf-token":              {},
	"x-forwarded-access-token":  {},
	"x-amz-security-token":      {},
	"x-goog-api-key":            {},
	"x-ms-authentication-token": {},
}

// maskSecurityEventRequestContextIfNeeded 服务端脱敏：非管理员会话
// 与非管理员读写 API Key 之外（只读 Key 同样）不返回请求头敏感值原文，请求体
// 整体置空——事件详情弹框的掩码此前只在前端，业务组任意登录用户可直接取原始
// JSON（与 DNS 凭证/TLS 私钥对非 admin 掩码的既有口径分叉）。
// 头的键集合与 `_lb_dropped_headers` 合成项保留（前端仍显示头名与丢弃计数）。
func maskSecurityEventRequestContextIfNeeded(c *gin.Context, e *models.SecurityEvent) {
	if c.GetString("role") == "admin" && !(c.GetString("auth_type") == "api_key" && c.GetBool("api_key_read_only")) {
		return
	}
	e.RequestBody = ""
	if strings.TrimSpace(e.RequestHeaders) == "" {
		return
	}
	var headers map[string]any
	if err := json.Unmarshal([]byte(e.RequestHeaders), &headers); err != nil {
		// 不可解析时不返回原文（防御性 fail-closed）。
		e.RequestHeaders = "{}"
		return
	}
	for name := range headers {
		if _, sensitive := securityEventSensitiveHeaderNames[strings.ToLower(name)]; !sensitive {
			continue
		}
		headers[name] = []string{"••••••"}
	}
	masked, err := json.Marshal(headers)
	if err != nil {
		e.RequestHeaders = "{}"
		return
	}
	e.RequestHeaders = string(masked)
}

// attackFamilyClass 攻击族 ID 形态分类——收敛的单一事实源
// categorizeAttack（概览具体分类）与 stageCategorizeAttack（阶段五桶）此前各
// 复写同一组形态谓词（5 位自定义/≥7 位 1 开头合成/11/14/8/2/4/5/7/3/12/msg
// 关键词门），判定顺序分叉已出过一次事故；固定 id 的族归属统一由
// legacyRuleFamilies 一张表提供（筛选表与触发类型映射同源派生）。
// SQL 筛选侧（ruleTriggeredFamilyPrefixes/customRuleFamilyCondition/
// geoipFamilyCondition）为 GLOB 文本形态，受引擎约束保持独立（同步义务不变）。
//
// 判定顺序即两视图既有同构顺序：5 位自定义先行（防 9 前缀遮蔽）→ ≥7 位
// 1 开头合成 → 精确 id/msg 族（msg 门先于信任分支）。9 开头 CRS
// 段不在此判定——概览视图需按 3 位前缀细分（crsAttackLabel）且未列名前缀须
// 继续落 msg/id 门，由调用侧承载（语义钉见
// TestCategorizeAttack_familyMapping / TestStageCategorizeAttack_buckets 的
// 960100 用例对）。
type attackFamilyClass int

const (
	attackFamilyOther       attackFamilyClass = iota
	attackFamilyCustomRule                    // 自定义规则：5 位任意数字 / ≥7 位 1 开头合成
	attackFamilyBodyAnomaly                   // id 11 请求体异常
	attackFamilyThreatIntel                   // id 14 / msg「威胁情报库拦截」
	attackFamilyGeoIP                         // id 8 / 6 位 80xxxx / msg「GeoIP 区域拦截」
	attackFamilyCrawler                       // 6 位 8[1-9]xxxx（爬虫豁免/伪装）
	attackFamilyIPACL                         // msg「IP 黑/白名单/访问控制」/ id 2/4/7
	attackFamilyTrust                         // id 3/5/12 信任名单
	attackFamilyRateLimit                     // id 429 限流（状态码精确匹配，防御性分支）
)

// legacyRuleFamily 阶段化模型之前的固定 SecRule id 的族归属。
type legacyRuleFamily struct {
	// key 是事件列表触发类型/筛选族键的权威词（triggerTypeForRule 与
	// ruleTriggeredFamilyPrefixes 的 map 键同词）。
	key   string
	class attackFamilyClass
}

// legacyRuleFamilies 固定 SecRule id → 族 的单一事实源：事件列表触发类型
// （triggerTypeForRule）、总览攻击族分桶（attackFamilyClassOf）、事件页族
// 筛选（ruleTriggeredFamilyPrefixes 由本表派生）、大屏命中规则标签
// （describeThreatRuleNameWithNames）四处口径均由此派生。此前四处各自
// 复写 id 字面量，id:5（绕过模式占位的信任名单 DetectionOnly 规则，发射
// 动作恒 pass,nolog）在三处被记成 IP 访问控制。
var legacyRuleFamilies = map[int]legacyRuleFamily{
	2:   {key: "IP 访问控制", class: attackFamilyIPACL},
	3:   {key: "信任名单", class: attackFamilyTrust},
	4:   {key: "IP 访问控制", class: attackFamilyIPACL},
	5:   {key: "信任名单", class: attackFamilyTrust},
	7:   {key: "IP 访问控制", class: attackFamilyIPACL},
	8:   {key: "地域拦截", class: attackFamilyGeoIP},
	11:  {key: "请求体异常", class: attackFamilyBodyAnomaly},
	12:  {key: "信任名单", class: attackFamilyTrust},
	14:  {key: "威胁情报库", class: attackFamilyThreatIntel},
	429: {key: "限流", class: attackFamilyRateLimit},
}

// legacyRuleFamilyOf 返回固定 id 的族归属（表外 id 得零值：key ""、
// class attackFamilyOther）。
func legacyRuleFamilyOf(id int) legacyRuleFamily { return legacyRuleFamilies[id] }

// attackFamilyClassOf 共享形态谓词——两个 Go 视图函数的唯一分类入口。
// 预检 8xxxxx 段的家族/边界经 services.DecodePrecheckRuleID 单一事实源
// 解码（段界字面量禁止在 handlers 复写——历史分叉：n>800000 vs n>=800000）。
func attackFamilyClassOf(ruleTriggered, ruleMsg string) attackFamilyClass {
	// 预检家族经 services.PrecheckRuleFamilyOf 单一事实源判定（段界字面量
	// 禁止在 handlers 复写——历史分叉：n>800000 vs n>=800000）；非数字/段外
	// ID 得 Unknown，不影响后续形态分支。
	precheckFamily := services.PrecheckRuleFamilyUnknown
	legacyFamily := legacyRuleFamily{}
	customORBranch := false
	if n, perr := strconv.Atoi(ruleTriggered); perr == nil {
		precheckFamily = services.PrecheckRuleFamilyOf(n)
		legacyFamily = legacyRuleFamilyOf(n)
		customORBranch = n >= services.CustomRuleORConditionIDBase
	}
	switch {
	case len(ruleTriggered) == 5:
		// 5 位 ID 恒为自定义规则(发射 id=crID+10000 落 10000-99999;
		// CRS 恒 6 位)——先于 9 前缀判定,crID≥82000 发射 92000-99999 时不再被
		// 遮蔽误标;与 customRuleFamilyCondition长度判据同口径。
		return attackFamilyCustomRule
	case len(ruleTriggered) == 6 && ruleTriggered[0] >= '1' && ruleTriggered[0] <= '7':
		// DB 自定义规则 id 10000-789999 发射为 id+10000，6 位 1xxxxx-7xxxxx
		// 是真实可达形态；8xxxxx/9xxxxx 分别由地域爬虫与 CRS 分支独占。
		return attackFamilyCustomRule
	case customORBranch:
		// OR 条件分支使用独立高段，展示与筛选仍归同一自定义规则族。
		return attackFamilyCustomRule
	case strings.HasPrefix(ruleTriggered, "1") && len(ruleTriggered) >= 7:
		// 自定义规则触发 id 的第二种形状：自此无 id 规则的合成 id 1000000+n
		// （7 位，1000000-1999999）。6 位自定义 ID 已由上方分支覆盖；本分支
		// 仅判无 id 规则的合成 ID。本口径是「自定义规则」ID 形态的
		// 权威：SQL 筛选族 customRuleFamilyCondition 与前端
		// triggeredLabel 须与本分支保持一致。
		return attackFamilyCustomRule
	case legacyFamily.class == attackFamilyRateLimit:
		// 429 精确命中（限流由 caddy-ratelimit 直接返回、无审计行，见
		// categorizeAttack 的生产者声明）。
		return attackFamilyRateLimit
	case legacyFamily.class == attackFamilyBodyAnomaly:
		return attackFamilyBodyAnomaly
	case legacyFamily.class == attackFamilyThreatIntel || strings.Contains(ruleMsg, "威胁情报库拦截"):
		// 14 = 威胁情报库预检拦截（阶段 1，v2.3.x）。精确匹配——LIKE 前缀
		// 会误并自定义规则发射 id 14xxxx（emit=DB id+10000）。
		return attackFamilyThreatIntel
	case precheckFamily == services.PrecheckRuleFamilyCrawlerExempt || precheckFamily == services.PrecheckRuleFamilyCrawlerSpoof:
		// 爬虫两族 [810000,900000) 与地域段 [800000,810000) 互斥（段界由
		// services 单一事实源保证）。
		return attackFamilyCrawler
	case legacyFamily.class == attackFamilyGeoIP || precheckFamily == services.PrecheckRuleFamilyGeoIP || strings.Contains(ruleMsg, "GeoIP 区域拦截"):
		// 8 = 旧共享 GeoIP id（策略引擎时代历史事件）；预检 GeoIP 族 = 逐策略
		// 精确段 800000+policyID（阶段化模型，buildIPPrecheckDirectives 逐策略链）。
		return attackFamilyGeoIP
	case strings.Contains(ruleMsg, "IP 黑名单") || strings.Contains(ruleMsg, "IP 白名单") || strings.Contains(ruleMsg, "IP 访问控制") ||
		legacyFamily.class == attackFamilyIPACL:
		return attackFamilyIPACL
	case legacyFamily.class == attackFamilyTrust:
		// 信任预检 id:3/5/12（id→家族单一事实源）——置于 msg 门之后：带
		// 「IP 黑/白名单」消息的历史行仍归 IP 访问控制（既有钉），裸 id 形态
		//（当前发射为 pass,nolog 永不产事件——防御性归族）归信任名单。
		return attackFamilyTrust
	default:
		return attackFamilyOther
	}
}

// crsAttackLabel CRS 段按 3 位规则组前缀的具体分类标签；未列名前缀返回 ""
// （调用侧继续走共享形态门——概览视图 fall-through 语义）。调用前须先排除
// 5 位自定义 ID（categorizeAttack 的 len==5 先行分支）。
func crsAttackLabel(ruleTriggered string) string {
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
	case strings.HasPrefix(ruleTriggered, "922"):
		// 已装 CRS v4 组补具体分类——
		// REQUEST-922-MULTIPART-ATTACK（922100/922110 等，waf/crs/rules/ 实证），
		// 此前落兜底「其他」。
		return "Multipart 攻击"
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
	// 已装 CRS v4 响应侧四组补具体分类——
	// REQUEST-952/954/956 族（952011/954012/956011 等）与
	// RESPONSE-955-WEB-SHELLS（955011 等），waf/crs/rules/ 目录实证，
	// 此前均落兜底「其他」。
	case strings.HasPrefix(ruleTriggered, "952"):
		return "响应 Java 泄露"
	case strings.HasPrefix(ruleTriggered, "953"):
		return "响应 PHP 泄露"
	case strings.HasPrefix(ruleTriggered, "954"):
		return "响应 IIS 泄露"
	case strings.HasPrefix(ruleTriggered, "955"):
		return "Web Shell"
	case strings.HasPrefix(ruleTriggered, "956"):
		return "响应 Ruby 泄露"
	case strings.HasPrefix(ruleTriggered, "959"):
		return "响应阻断评估"
	case strings.HasPrefix(ruleTriggered, "949"):
		return "请求阻断评估"
	default:
		return ""
	}
}

func categorizeAttack(ruleTriggered, ruleMsg string) string {
	// 限流拦截（rule_triggered=429）与事件列表「限流」族/筛选同口径：此前
	// 429 落 attackFamilyOther（「其他」），纯限流站点于是显示「拦截很多但
	// 攻击类型几乎全是其他」。429 是精确 ID，无前缀歧义。
	//
	// 生产者声明（防御性分支）：caddy-ratelimit 直接返回 caddyhttp.Error(429)，
	// 不经 coraza 事务 → security_events 里没有 rule_triggered=429 的行，本
	// 分支当前不可达（前端筛选项已同步移除「限流」）。保留它是因为限流计数走
	// Prometheus 指标，一旦将来把 429 也落审计行，此处即为正确归类点；
	// 改动本函数会改变 rollup 固化口径——必须同步递增
	// threatRollupClassifierVersion（见 security_threat_screen.go 代际注释）。
	// 5 位 ID 恒为自定义规则——先于 3 位前缀判定,crID≥82000
	// 发射 92000-99999 时不再被 9 前缀遮蔽误标。
	if len(ruleTriggered) == 5 {
		return "自定义规则"
	}
	if label := crsAttackLabel(ruleTriggered); label != "" {
		return label
	}
	// 9 开头但未列名 3 位前缀的 CRS 段：继续走共享形态门（收敛前
	// fall-through 同口径——历史脏数据 msg 命中 IP 黑白名单仍归 IP 访问控制）。
	switch attackFamilyClassOf(ruleTriggered, ruleMsg) {
	case attackFamilyRateLimit:
		return "限流"
	case attackFamilyCustomRule:
		return "自定义规则"
	case attackFamilyBodyAnomaly:
		return "请求体异常"
	case attackFamilyThreatIntel:
		return "威胁情报库"
	case attackFamilyGeoIP:
		return "地域拦截"
	case attackFamilyCrawler:
		return "爬虫Bot"
	case attackFamilyIPACL:
		return "IP 访问控制"
	case attackFamilyTrust:
		return "信任名单"
	default:
		return "其他"
	}
}

// stageCategorizeAttack 阶段五桶归并（用户裁定：攻击类型分布默认按
// 阶段展示，取消勾选切回 categorizeAttack 具体分类）——与触发阶段口径一致：
//
//	信任名单（id 3/12）/ IP 访问控制（黑白名单 2/4/5/7 + 地域 8/8xxxxx +
//	威胁库 14/msg）/ WAF（CRS 9xxxxx + 自定义 5 位与 1 开头 ≥7 位合成）/
//	请求体异常（id 11）/ 限流（429 精确）/ 其他。
//
// ID 形态判定收敛至 attackFamilyClassOf 单一事实源，
// 本函数只做类→桶映射。与概览视图的唯一有意分叉：9 开头 CRS 段整段归 WAF
// （含未列名前缀，不 fall-through 到 msg 门）；概览视图未列名前缀继续走
// msg/id 门。与 family 筛选表（ruleTriggeredFamilyPrefixes/
// customRuleFamilyCondition/geoipFamilyCondition）SQL 侧口径同步义务不变。
func stageCategorizeAttack(ruleTriggered, ruleMsg string) string {
	// 限流（429）独立成桶：与事件列表「限流」族、429 筛选及限流卡片同口径，
	// 此前落「其他」——同一事件在列表与总览口径分叉。
	// 生产者声明同 categorizeAttack：当前无 429 审计行（限流不经 coraza），
	// 属防御性分支；分类口径变更须递增 threatRollupClassifierVersion。
	class := attackFamilyClassOf(ruleTriggered, ruleMsg)
	// WAF=自定义规则类+CRS 9 前缀段（categorizeAttack 的 crsAttackLabel 细分段
	// 此处整段归一）。msg 门命中的 9 开头形态同样归 WAF（不 fall-through）。
	if class == attackFamilyCustomRule || strings.HasPrefix(ruleTriggered, "9") {
		return "WAF"
	}
	switch class {
	case attackFamilyRateLimit:
		return "限流"
	case attackFamilyBodyAnomaly:
		return "请求体异常"
	case attackFamilyThreatIntel, attackFamilyGeoIP, attackFamilyCrawler, attackFamilyIPACL:
		return "IP 访问控制"
	case attackFamilyTrust:
		return "信任名单"
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

func overlayCRSOverviewUpdateStatus(stored string, snapshot *services.CRSUpdateStatusSnapshot) string {
	if snapshot != nil && services.IsActiveCRSStatus(snapshot.Status) {
		return snapshot.Status
	}
	// 库值直读面与 status 快照面同口径：活动态只属执行进程，从节点上的
	// 残留活动态按角色投影为 failed（单源 services.ProjectActiveUpdateStatusForLocalRole，
	// 不写库）。不投影时总览徽标与「更新」弹框对同一行给出相反结论。
	projected, _ := services.ProjectActiveUpdateStatusForLocalRole(stored, "")
	return projected
}

// securityOverviewSevenDayStartUTC 返回近 7 天窗口起点（UTC 规范串）：
// 覆盖判定用「本地日界逐日回退 6 天」而非「UTC 时刻 −6×24h」——DST 周界上
// 两者差 1h，单一平移会让 backfill_incomplete（窗口前段不可重建提示）在切换
// 周误报/漏报。与 loadSecurityOverviewAggregates 的日桶构造同口径。
func securityOverviewSevenDayStartUTC(todayStart time.Time) string {
	return todayStart.AddDate(0, 0, -6).UTC().Format("2006-01-02 15:04:05")
}

func (h *Handlers) GetSecurityOverview(c *gin.Context) {
	// 日界按配置时区计算：event_time 为 UTC，「今日」与 7 日趋势桶均以
	// 配置时区的本地日期为准（printf modifier 将 UTC 事件时间平移到本地后取日期）。
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	todayStartUTC := todayStart.UTC().Format("2006-01-02 15:04:05")
	sevenDayStartUTC := securityOverviewSevenDayStartUTC(todayStart)
	rawCoverageFrom := ""
	backfillIncomplete := false

	var overview models.SecurityOverview
	overview.CRSAvailable, overview.IP2RegionAvailable = services.SecurityLibraryStatus()
	// 任一查询失败都必须在结束时显式报错：否则 metrics 库故障会静默返回
	// 全零面板，与「无攻击」不可区分。
	var firstErr error
	trackErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	todayFromRollup := false
	if db.MetricsDB != nil {
		// 今日计数与威胁大屏同源（分钟 rollup）：行帽触顶时原始表只剩
		// 最近若干分钟，直算静默少计；rollup 覆盖不足/固化陈旧时回退
		// 原始表直算（fromRollup=false → includes_reserved 披露含私网）。
		blocked, detected, fromRollup, err := securityOverviewTodayCounts(db.MetricsDB, todayStart, now)
		trackErr(err)
		overview.TodayBlocked, overview.TodayDetected, todayFromRollup = blocked, detected, fromRollup
		coverageFrom, err := threatRawCoverageStart(db.MetricsDB)
		trackErr(err)
		rawCoverageFrom = coverageFrom
		backfillIncomplete = rawCoverageFrom != "" && rawCoverageFrom > sevenDayStartUTC
	}
	// 活跃策略=启用且任一阶段特征非空：旧口径
	// `mode!='off'` 滞留阶段化前语义——stage1/stage2 策略 mode 恒归一 off，
	// 纯 stage1/2 部署显示 0。空策略（无任何特征）不计。
	// 谓词 enabled=1 与生成路径一致：正常写入路径恒显式落 enabled（schema
	// 默认 TRUE），enabled IS NULL 只可能来自带外改库/旧备份还原。这类行在
	// 生成路径不发射、在绑定视图按禁用呈现，而列表/详情投影按 schema 默认
	// 呈现启用——口径差异系带外边角，不在本查询折算 NULL 行（避免为一条
	// 不可达路径引入三面新口径）。
	policyRows, perr := db.DB.Query("SELECT " + securityPolicySelectColumns + " FROM security_policies WHERE enabled=1")
	if perr != nil {
		trackErr(perr)
	} else {
		active := 0
		for policyRows.Next() {
			var p models.SecurityPolicy
			if err := scanSecurityPolicy(policyRows, &p); err != nil {
				// 行 scan 失败不得静默跳行——计入
				// firstErr 走显式报错口径（全零面板与「无攻击」不可区分）。
				trackErr(err)
				continue
			}
			fs := models.PolicyTypeFeatures(&p)
			if fs.G0 || fs.G1 || fs.G2 || fs.G3 {
				active++
			}
		}
		trackErr(policyRows.Err()) // 迭代失败显式报错
		policyRows.Close()
		overview.ActivePolicies = active
	}

	overview.CRSVersion = services.CRSBundledVersion
	overview.UpdateStatus = "idle"
	var crsVersion, crsUpdateStatus string
	// 查询失败纳入 trackErr（对齐 ActivePolicies 口径与本函数
	// 自述标准「任一查询失败都必须显式报错」）。无行（ErrNoRows）是全新安装的
	// 合法状态，保持 200 捆绑版本回落（fallsBackToBundledCRSVersion 钉住），
	// 不计入故障。
	if err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,'idle') FROM security_crs_version WHERE id=1`).Scan(&crsVersion, &crsUpdateStatus); err == nil {
		if crsVersion != "" {
			overview.CRSVersion = crsVersion
		}
		overview.UpdateStatus = crsUpdateStatus
	} else if !errors.Is(err, sql.ErrNoRows) {
		trackErr(err)
	}
	var crsSnapshot *services.CRSUpdateStatusSnapshot
	if mgr := services.GetCRSUpdateManager(); mgr != nil {
		snapshot := mgr.StatusSnapshot()
		crsSnapshot = &snapshot
	}
	overview.UpdateStatus = overlayCRSOverviewUpdateStatus(overview.UpdateStatus, crsSnapshot)

	// 7-day trend: always the full today-6 … today slice (local dates), zero-filled.
	// 日桶由 loadSecurityOverviewAggregates 按 today 携带的时区逐日本地边界
	// 构造（DST 正确），本函数只传 loc.String() 作缓存键身份，不拼偏移。
	// MetricsDB 未装配：主库字段（活跃策略/库状态）照常返回，metrics 面板零值
	// 200 而非 panic（对齐家族：ListSecurityEvents/
	// GetIPEventCount/GetRuleStageStats 同口径）。
	if db.MetricsDB == nil {
		overview.Trend = []models.SecurityTrendPoint{}
		overview.TopIPs = []models.SecurityTopIP{}
		overview.AttackTypes = []models.SecurityAttackType{}
		overview.AttackTypesStage = []models.SecurityAttackType{}
		if firstErr != nil {
			services.Logf("error", "security overview: query failed: %v", firstErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全总览查询失败"})
			return
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: securityOverviewResponse{
			SecurityOverview:   overview,
			RawCoverageFrom:    rawCoverageFrom,
			BackfillIncomplete: backfillIncomplete,
			RawCoverageLimited: backfillIncomplete,
			IncludesReserved:   true,
			Ingestion:          services.SecurityEventsIngestionHealthSnapshot(),
		}})
		return
	}
	// 近 7 天聚合（趋势/Top10 IP/攻击族）走 30s 进程内缓存，
	// 避免每次 30s 轮询对原始表执行 4 趟 7 天全窗口扫描。
	agg, aggErr := loadSecurityOverviewAggregates(db.MetricsDB, now, todayStartUTC, loc.String())
	trackErr(aggErr)
	overview.Trend = agg.trend
	overview.TopIPs = agg.topIPs
	overview.AttackTypes = agg.attackTypes
	overview.AttackTypesStage = agg.attackTypesStage

	if firstErr != nil {
		services.Logf("error", "security overview: query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全总览查询失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: securityOverviewResponse{
		SecurityOverview:   overview,
		RawCoverageFrom:    rawCoverageFrom,
		BackfillIncomplete: backfillIncomplete,
		RawCoverageLimited: backfillIncomplete,
		// 今日计数走 rollup 时与大屏同口径排除私网/保留地址（false）；
		// 回退原始表直算时含私网（true，旧口径）。
		IncludesReserved: !todayFromRollup,
		Ingestion:        services.SecurityEventsIngestionHealthSnapshot(),
	}})
}

func (h *Handlers) GetCRSInfo(c *gin.Context) {
	crsOK, _ := services.SecurityLibraryStatus()
	info := models.CRSInfo{
		Version:       services.CRSBundledVersion,
		ServerVersion: getCaddyVersion(),
		AutoUpdate:    true,
		Available:     crsOK,
		// 默认 nil=未知(latest 缓存未知/版本解析失败时三态化,
		// 不再 fail-open 宣称「已是最新」)。
		UpdateStatus: "idle",
	}
	var stored struct {
		version, updatedAt, updateStatus, message, nextUpdate, lastChecked, trigger string
		autoUpdate                                                                  bool
	}
	err := db.DB.QueryRow(`SELECT version, COALESCE(updated_at,''), COALESCE(update_status,'idle'),
		COALESCE(message,''), COALESCE(next_update,''), COALESCE(last_checked,''), COALESCE(trigger,''), COALESCE(auto_update,1)
		FROM security_crs_version WHERE id=1`).
		Scan(&stored.version, &stored.updatedAt, &stored.updateStatus, &stored.message,
			&stored.nextUpdate, &stored.lastChecked, &stored.trigger, &stored.autoUpdate)
	// 仅行缺失(新安装)合法回落默认;真实 DB 故障 500
	// 可见——此前一律吞错,用户看到假默认值。
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 CRS 版本信息失败"})
		return
	}
	if err == nil {
		if stored.version != "" {
			info.Version = stored.version
		}
		info.UpdatedAt = stored.updatedAt
		// 库值按角色投影（与 crsstatus 读侧快照单源同函数）：从节点上的
		// 活动态残留不改写库，只在本端点呈现 failed + 归属文案，避免规则库
		// 卡片显示「更新中」而「立即更新」弹框显示「本节点不执行该任务」。
		info.UpdateStatus, info.Message = services.ProjectActiveUpdateStatusForLocalRole(stored.updateStatus, stored.message)
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
				latestFlag := cmp <= 0
				info.IsLatest = &latestFlag
			}
		}
	} else {
		if count, countErr := services.CountSecRulesLive(); countErr == nil {
			info.RuleCount = count
		}
	}
	info.ScheduleDays, info.ScheduleTime = services.CRSSchedule()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func (h *Handlers) UpdateCRSAutoUpdate(c *gin.Context) {
	// 版本表 auto_update 在导入全量替换范围内（security_crs_version 等四表）：
	// 窗口内写会被导入覆盖或撞写锁 500——与同族 global_config/版本表写者
	// 同口径 409 fast-fail（见 libAutoUpdate，先于 body 解析）。
	autoUpdate, ok := h.libAutoUpdate(c, libAutoUpdateSpec{
		ImportAction:   "修改规则库自动更新设置（配置导入进行中）",
		InvalidMessage: "请求参数无效",
	}, services.SetCRSAutoUpdate)
	if !ok {
		return
	}
	recordAudit(c, "更新", "CRS规则库", "自动更新已"+enabledStateLabel(autoUpdate))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// updateLibSchedule 三库定时调度端点共享骨架：载荷校验（星期集去重后非空、
// HH:MM）→ 主节点门（与 UpdateCRSAutoUpdate 同口径）→ 保存即重排
// next_update。成功返回归一后的星期集与时间；审计与 200 响应由各端点自行
// 完成——recordAudit 的事件对象须字面量（audit_vocabulary_test 卡口）。
func (h *Handlers) updateLibSchedule(c *gin.Context, save func([]int, string) error) ([]int, string, bool) {
	// 三库排程（CRS/IP2Region/威胁库/爬虫库共用骨架）写版本表/源表的排程列，
	// 均在导入全量替换范围内——窗口内保存会被导入覆盖（用户以为已改排程）
	// 或撞写锁 500，与同族写端点同口径 409 fast-fail。
	if rejectWriteDuringImport(c, "修改任务排程（配置导入进行中）") {
		return nil, "", false
	}
	var req struct {
		Days []int  `json:"days"`
		Time string `json:"time"`
	}
	if !guardConfiguredJSONBody(c) {
		return nil, "", false
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return nil, "", false
	}
	days := services.NormalizeScheduleDays(req.Days)
	if len(days) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "至少选择一天"})
		return nil, "", false
	}
	if !services.ValidScheduleHHMM(req.Time) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "时间格式无效（HH:MM）"})
		return nil, "", false
	}
	if !requireMasterNode(c) {
		return nil, "", false
	}
	if err := save(days, req.Time); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return nil, "", false
	}
	return days, req.Time, true
}

// libAutoUpdateSpec 三库「自动更新」开关端点的差异面：导入写门文案、审计
// 对象/明细、错误响应前缀与非法载荷文案。骨架（导入 409 → body 解析 →
// 主节点门 → 保存 → 审计 → 200）单源，差异全部经此结构表达。
type libAutoUpdateSpec struct {
	// ImportAction 导入窗口内的 409 文案动作（「修改…（配置导入进行中）」）。
	ImportAction string
	// InvalidMessage body 解析失败/缺字段的 400 文案。
	InvalidMessage string
}

// libAutoUpdate 执行三库「自动更新」开关写入的共享骨架，返回已落库的开关值
// （ok=false 表示已写好响应）。审计与 200 响应由各端点自行完成——recordAudit
// 的事件对象须字面量（audit_vocabulary 门禁不认动态对象）。
//
// 导入门必须先于 body 解析：三张表（security_crs_version /
// security_ip2region_version / security_threat_sources）都在导入全量替换
// 清单内，窗口内写入要么被导入静默覆盖、要么撞写锁 500，两者都比 409 差。
func (h *Handlers) libAutoUpdate(c *gin.Context, spec libAutoUpdateSpec, save func(bool) error) (bool, bool) {
	if rejectWriteDuringImport(c, spec.ImportAction) {
		return false, false
	}
	var req struct {
		// 指针语义——缺字段/null 绑定成功时得到 nil（显式 400），
		// 非指针 bool 会静默取 false 并写库（脚本/MCP 部分更新或键名漂移
		// 可无提示停止安全规则自动更新，审计却记录为用户主动关闭）。
		AutoUpdate *bool `json:"auto_update"`
	}
	if !guardConfiguredJSONBody(c) {
		return false, false
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AutoUpdate == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: spec.InvalidMessage})
		return false, false
	}
	// 与 Start*Update 同口径主节点门——从节点版本行/源行在同步段内，
	// 本地写会被下次快照覆盖。
	if !requireMasterNode(c) {
		return false, false
	}
	if err := save(*req.AutoUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("更新失败", err)})
		return false, false
	}
	return *req.AutoUpdate, true
}

// startLibUpdate 三库手动更新触发端点共享骨架（主节点门 → 任务引擎装配门 →
// 单飞 409 → 引擎受理）。执行体由任务引擎注册的执行器承载，端点零旁路。
func (h *Handlers) startLibUpdate(c *gin.Context, taskID, family, displayName string) {
	// 手动更新仅限主节点（从节点本地更新会造成磁盘/DB 分叉：主节点下次集群
	// 同步把状态行覆盖回主节点口径，而从节点的启动对账是 master-only）。
	if !requireMasterNode(c) {
		return
	}
	te := services.TaskEngine()
	if te == nil {
		respondTaskEngineUnavailable(c)
		return
	}
	if te.IsTaskInFlight(taskID) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
		return
	}
	op := auditOperator(c)
	// 响应前同步预占位；暂停/停止/角色/单飞拒绝不得伪报 200 running。
	// 任务体审计仍按自记族单记口径。
	if err := services.TriggerTaskAsync(te, taskID, services.TriggerAuditContext{
		Operator: op, Family: family, Name: displayName,
	}); err != nil {
		respondTaskTriggerAdmissionError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// libUpdateStatus 三库「更新状态」端点共享骨架：manager 未装配 → 500；否则按
// project 把快照投影为响应体。三库快照类型不同（威胁库为任务级状态对象），
// 差异只体现在投影函数，端点壳、nil 门与响应包装单源。
func libUpdateStatus[S any](c *gin.Context, serviceLabel string, mgr *S, project func(*S) any) {
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serviceLabel + " 更新服务未初始化"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: project(mgr)})
}

// libUpdateLogs 三库更新日志端点共享骨架：单一日志数据源（2026-09-29 用户
// 裁定）——任务日志文件即更新日志，规则集页弹框与任务监控日志弹框同文件同
// 内容（含生命周期行）。
func libUpdateLogs(c *gin.Context, taskID string) {
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": readUpdateLogWithRotation(taskengine.TaskLogPath(taskID))}})
}

var scheduleWeekdayLabels = []string{"", "一", "二", "三", "四", "五", "六", "日"}

func scheduleDaysLabel(days []int) string {
	parts := make([]string, 0, len(days))
	for _, d := range days {
		if d >= 1 && d <= 7 {
			parts = append(parts, scheduleWeekdayLabels[d])
		}
	}
	return strings.Join(parts, "、")
}

// UpdateCRSSchedule 保存 CRS 定时更新排程（星期多选 + 时间；保存即重排）。
func (h *Handlers) UpdateCRSSchedule(c *gin.Context) {
	days, hhmm, ok := h.updateLibSchedule(c, services.SetCRSSchedule)
	if !ok {
		return
	}
	recordAudit(c, "更新", "CRS规则库", fmt.Sprintf("定时更新设置：每周%s %s", scheduleDaysLabel(days), hhmm))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

func (h *Handlers) StartCRSUpdate(c *gin.Context) {
	// V2（用户裁定）：手动触发统一经任务引擎——task_runs/单飞/历史归一
	// （曾直调 manager.StartUpdate rc.RunID=0，历史零记录、引擎旁路）。
	h.startLibUpdate(c, "crs", "CRS规则库", "CRS 更新")
}

func (h *Handlers) GetCRSUpdateStatus(c *gin.Context) {
	libUpdateStatus(c, "CRS", services.GetCRSUpdateManager(), func(mgr *services.CRSUpdateManager) any {
		snap := mgr.StatusSnapshot()
		return gin.H{
			"status":      snap.Status,
			"trigger":     snap.Trigger,
			"started_at":  snap.StartedAt,
			"finished_at": snap.FinishedAt,
			"message":     snap.Message,
			"version":     snap.Version,
		}
	})
}

// updateLogMaxBytes 更新日志响应体上限（单代）。两代拼接后同受此上限约束，
// 否则「.1 副本 + 当前文件」会把响应体放大到两倍（各代独立 128KiB 截断）。
const updateLogMaxBytes = 128 * 1024

// truncateLogTail 保留文本末尾 maxBytes 字节（日志看的是最近输出）。截断点
// 回退到 UTF-8 字符边界，避免把多字节字符切成半个（前端按文本渲染）。
func truncateLogTail(text string, maxBytes int) string {
	if maxBytes <= 0 || len(text) <= maxBytes {
		return text
	}
	cut := len(text) - maxBytes
	for cut < len(text) && text[cut]&0xC0 == 0x80 {
		cut++
	}
	return text[cut:]
}

// readUpdateLogWithRotation 读更新日志（含上一代 .1 轮转副本，旧代在前）——
// CRS/IP2Region/威胁三库更新日志端点共用。单份读取失败留 warn（文件不存在
// 不算错误），不因历史副本不可读丢掉当前文件内容。
func readUpdateLogWithRotation(path string) string {
	content, err := readCertJobLogFile(path)
	if err != nil {
		services.Logf("warn", "读取更新日志失败（%s）: %v", path, err)
	}
	oldData, oldErr := readCertJobLogFile(path + ".1")
	if oldErr != nil {
		services.Logf("warn", "读取更新日志轮转副本失败（%s.1）: %v", path, oldErr)
	}
	if oldData != "" {
		content = oldData + content
	}
	return truncateLogTail(content, updateLogMaxBytes)
}

func (h *Handlers) GetCRSUpdateLogs(c *gin.Context) {
	libUpdateLogs(c, "crs")
}

func (h *Handlers) GetIP2RegionInfo(c *gin.Context) {
	_, ipOK := services.SecurityLibraryStatus()
	ipVersion, _ := services.GetIP2RegionVersion()
	info := models.IP2RegionInfo{
		Available: ipOK,
		Version:   ipVersion,
		DbSize:    services.GetIP2RegionEntryCount(),
		// 行缺失兜底与 schema/种子默认对齐（TRUE）。
		AutoUpdate:   true,
		UpdateStatus: "idle",
	}
	err := db.DB.QueryRow(`SELECT COALESCE(updated_at,''), COALESCE(update_status,'idle'), COALESCE(message,''), COALESCE(trigger,''), COALESCE(last_checked,''), COALESCE(next_update,''), COALESCE(auto_update,1)
		FROM security_ip2region_version WHERE id=1`).
		Scan(&info.UpdatedAt, &info.UpdateStatus, &info.Message, &info.Trigger, &info.LastChecked, &info.NextUpdate, &info.AutoUpdate)
	// 同 GetCRSInfo——真实 DB 故障 500,仅缺行回落。
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 IP2Region 版本信息失败"})
		return
	}
	// 同 GetCRSInfo：库值活动态按角色投影（读侧单源、不写库）——从节点的
	// 残留活动态不得让 IP 库卡片显示「更新中」。
	info.UpdateStatus, info.Message = services.ProjectActiveUpdateStatusForLocalRole(info.UpdateStatus, info.Message)
	if err == nil && info.Version == "" {
		info.Version = "unknown"
	}
	// 与 GetCRSInfo 同口径：自动更新关闭时不回传残留的未来排程——否则 UI
	// 显示「下次更新」时间却永不触发（排程只在 auto_update=1 时武装）。
	if err == nil && !info.AutoUpdate {
		info.NextUpdate = ""
	}
	if mgr := services.GetIP2RegionUpdateManager(); mgr != nil {
		if snap := mgr.StatusSnapshot(); services.IsActiveIP2RegionStatus(snap.Status) {
			info.UpdateStatus = snap.Status
			info.Trigger = snap.Trigger
			info.Message = snap.Message
		}
	}
	info.ScheduleDays, info.ScheduleTime = services.IP2RegionSchedule()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

// ip2RegionRegionsResponse regions 响应体：地域树 + country_names_cn 并行
// 字段。树结构（provinces/cities/countries）保持旧形态（存量消费方零破坏）；
// zh 映射是 geoipnames 二进制静态表（非 xdb 派生态），在响应层透传而不入树
// ——regions.json 缓存体积与重建逻辑零改动。
type ip2RegionRegionsResponse struct {
	services.IP2RegionRegionTree
	// CountryNamesCN：海外国家英文→中文映射（单源 geoipnames.CountryNamesCN
	// 全表透传，v2.3.7 修正）——前端级联「海外国家」子节点中文标签；缺失时
	// 前端回退英文标签（向后兼容）。
	CountryNamesCN map[string]string `json:"country_names_cn"`
}

func (h *Handlers) GetIP2RegionRegions(c *gin.Context) {
	// 与校验端（ValidateGeoIPCountries）同源：live searcher 优先、缓存兜底，
	// 避免带外替换 xdb 后两端分叉。
	// 返回级联结构——provinces 保持旧形态（数组，存量消费方
	// 兼容），cities 为省→城市集映射（区域精确到市；海外为一级条目无城市）。
	tree := services.GetIP2RegionRegionTree()
	if tree == nil {
		tree = &services.IP2RegionRegionTree{
			Provinces: services.GetIP2RegionProvinceList(),
			Cities:    map[string][]string{},
			Countries: []string{},
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: ip2RegionRegionsResponse{
		IP2RegionRegionTree: *tree,
		CountryNamesCN:      geoipnames.CountryNamesCN,
	}})
}

func (h *Handlers) UpdateIP2RegionAutoUpdate(c *gin.Context) {
	// 版本表 auto_update 在导入全量替换范围内（security_ip2region_version 在
	// configBackupTables）：窗口内写会被导入静默覆盖（用户以为已关，实际仍
	// 自动更新，或反之）或撞写锁 30s 后 500——与 CRS/威胁库同族 409 fast-fail。
	autoUpdate, ok := h.libAutoUpdate(c, libAutoUpdateSpec{
		ImportAction:   "修改 IP 地址库自动更新设置",
		InvalidMessage: "请求参数无效",
	}, services.SetIP2RegionAutoUpdate)
	if !ok {
		return
	}
	recordAudit(c, "更新", "IP数据库", "自动更新已"+enabledStateLabel(autoUpdate))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// UpdateIP2RegionSchedule 保存 IP2Region 定时更新排程（星期多选 + 时间；
// 保存即重排）。
func (h *Handlers) UpdateIP2RegionSchedule(c *gin.Context) {
	days, hhmm, ok := h.updateLibSchedule(c, services.SetIP2RegionSchedule)
	if !ok {
		return
	}
	recordAudit(c, "更新", "IP数据库", fmt.Sprintf("定时更新设置：每周%s %s", scheduleDaysLabel(days), hhmm))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

func (h *Handlers) StartIP2RegionUpdate(c *gin.Context) {
	// 同 StartCRSUpdate——手动更新仅限主节点，统一经任务引擎。
	h.startLibUpdate(c, "ip2region", "IP数据库", "IP2Region 更新")
}

func (h *Handlers) GetIP2RegionUpdateStatus(c *gin.Context) {
	libUpdateStatus(c, "IP2Region", services.GetIP2RegionUpdateManager(), func(mgr *services.IP2RegionUpdateManager) any {
		snap := mgr.StatusSnapshot()
		return gin.H{
			"status":      snap.Status,
			"trigger":     snap.Trigger,
			"started_at":  snap.StartedAt,
			"finished_at": snap.FinishedAt,
			"message":     snap.Message,
			"version":     snap.Version,
		}
	})
}

func (h *Handlers) GetIP2RegionUpdateLogs(c *gin.Context) {
	libUpdateLogs(c, "ip2region")
}

// BuildCorazaDirectives is in services/security.go to avoid circular dependency
// (services can't import handlers).

// GetAllSecurityBindings（v2.2.0）：一规则可绑多策略——返回 map[string][]BindingInfo，
// 每规则的绑定按 policy_id ASC 排序；取代旧的 map[string]BindingInfo 单值覆盖形态。
func (h *Handlers) GetAllSecurityBindings(c *gin.Context) {
	// mode/enabled/rate_limit_enabled 与生成投影同默认值 COALESCE：NULL 列
	// 修复前触发 Scan 报错静默丢绑定，而生成路径照常应用该策略。enabled 归一为 0
	// 而非 schema 默认 1——生成路径以 WHERE enabled=1 把 NULL 当禁用，UI 标签须
	// 与后端行为一致（区别于 List 详情的 COALESCE(enabled,1)：那里无 WHERE 过滤）。
	rows, err := db.DB.Query(`SELECT b.rule_caddy_id, p.id, p.name, COALESCE(p.mode,'off'), COALESCE(p.enabled,0), COALESCE(p.rate_limit_enabled,0), COALESCE(p.block_page_id, 0), CASE WHEN p.block_status_code > 0 THEN p.block_status_code ELSE 403 END
		FROM security_policy_bindings b JOIN security_policies p ON b.policy_id = p.id
		ORDER BY b.rule_caddy_id ASC, b.policy_id ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	defer rows.Close()
	// block_page_id：前端据此计算「首个启用且配置了拦截页面的策略」，
	// 与后端生成口径（首个 enabled 且 block_page_id>0）一致。block_status_code
	//（拦截页归因）：前端冲突提示与 Rules 页锁形弹框展示「页名(状态码)」，
	// NULL/0 归一 403（CASE WHEN，非 COALESCE——库存未设置为 0 非 NULL）与
	// 生成路径（buildBlockPageAttributionRoute 的 0→403）同口径。
	type BindingInfo struct {
		PolicyID        int    `json:"policy_id"`
		Name            string `json:"name"`
		Mode            string `json:"mode"`
		Enabled         bool   `json:"enabled"`
		RateLimit       bool   `json:"rate_limit_enabled"`
		BlockPageID     int    `json:"block_page_id"`
		BlockStatusCode int    `json:"block_status_code"`
	}
	result := map[string][]BindingInfo{}
	for rows.Next() {
		var ruleCaddyID string
		var b BindingInfo
		if err := rows.Scan(&ruleCaddyID, &b.PolicyID, &b.Name, &b.Mode, &b.Enabled, &b.RateLimit, &b.BlockPageID, &b.BlockStatusCode); err != nil {
			// 单行扫描失败跳过：不写入零值绑定（policy_id=0/mode="" 会把该规则
			// 错误呈现为「已绑定到空策略」）；迭代错误由下方 rows.Err() 兜底。
			services.Logf("warn", "security bindings: 跳过扫描失败行（规则绑定可能缺失）: %v", err)
			continue
		}
		result[ruleCaddyID] = append(result[ruleCaddyID], b)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

// scanSecurityPolicyInto 是 Row/Rows 两形态的唯一扫描实现（历史
// 此前双份拷贝,加列疏漏成为静默错位扫描而非编译错误)。
func scanSecurityPolicyInto(scan func(dest ...any) error, p *models.SecurityPolicy) error {
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries, crawlerEnginesJSON string
	if err := scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &p.IPWhitelistEnabled, &ipWhitelist, &ipBlacklist,
		&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.GeoIPCrawlerExempt, &crawlerEnginesJSON, &p.WAFCheckResponse, &p.LogRequestBody, &p.IPACLListRefs, &p.IPWhitelistRefs, &p.PolicyType, &p.TrustDetection); err != nil {
		return err
	}
	p.IPWhitelist = json.RawMessage(ipWhitelist)
	p.IPBlacklist = json.RawMessage(ipBlacklist)
	p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
	p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
	p.CustomRules = json.RawMessage(customRules)
	p.GeoIPCountries = json.RawMessage(geoipCountries)
	p.GeoIPCrawlerEngines = json.RawMessage(crawlerEnginesJSON)
	return nil
}

func scanSecurityPolicyRow(row *sql.Row, p *models.SecurityPolicy) error {
	return scanSecurityPolicyInto(row.Scan, p)
}

func scanSecurityPolicy(rows *sql.Rows, p *models.SecurityPolicy) error {
	return scanSecurityPolicyInto(rows.Scan, p)
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
	// 爬虫豁免两列必须出现在详情 DTO——前端编辑策略时读取并按此
	// 回写；缺席会恒回写 false/默认三引擎，静默关闭豁免。
	GeoIPCrawlerExempt  bool   `json:"geoip_crawler_exempt"`
	GeoIPCrawlerEngines string `json:"geoip_crawler_engines"`
	WAFCheckResponse    bool   `json:"waf_check_response"`
	LogRequestBody      bool   `json:"log_request_body"`
	IPACLListRefs       string `json:"ip_acl_list_refs"`
	IPWhitelistRefs     string `json:"ip_whitelist_refs"`
	PolicyType          string `json:"policy_type"`
	TrustDetection      bool   `json:"trust_detection"`
}

func newSecurityPolicyDetail(p *models.SecurityPolicy) securityPolicyDetail {
	return securityPolicyDetail{
		ID:                  p.ID,
		Name:                p.Name,
		Description:         p.Description,
		Mode:                p.Mode,
		AnomalyThreshold:    p.AnomalyThreshold,
		IPACLMode:           p.IPACLMode,
		IPACLList:           p.IPACLList,
		IPACLEnabled:        p.IPACLEnabled,
		IPWhitelistEnabled:  p.IPWhitelistEnabled,
		IPWhitelist:         rawJSONString(p.IPWhitelist),
		IPBlacklist:         rawJSONString(p.IPBlacklist),
		RateLimitEnabled:    p.RateLimitEnabled,
		RateLimitRPS:        p.RateLimitRPS,
		RateLimitBurst:      p.RateLimitBurst,
		CRSRuleGroups:       rawJSONString(p.CRSRuleGroups),
		CRSExcludedRules:    rawJSONString(p.CRSExcludedRules),
		CustomRules:         rawJSONString(p.CustomRules),
		BlockPageID:         p.BlockPageID,
		BlockStatusCode:     p.BlockStatusCode,
		Enabled:             p.Enabled,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
		GeoIPCountries:      rawJSONString(p.GeoIPCountries),
		GeoIPMode:           p.GeoIPMode,
		GeoIPCrawlerExempt:  p.GeoIPCrawlerExempt,
		GeoIPCrawlerEngines: rawJSONString(p.GeoIPCrawlerEngines),
		WAFCheckResponse:    p.WAFCheckResponse,
		LogRequestBody:      p.LogRequestBody,
		IPACLListRefs:       p.IPACLListRefs,
		IPWhitelistRefs:     p.IPWhitelistRefs,
		PolicyType:          p.PolicyType,
		TrustDetection:      p.TrustDetection,
	}
}

// validateRateLimitShape 限流字段与发射端同口径：enabled=true 而
// rps<=0 时 caddy.go 发射分支直接跳过限流 handler，但汇总/绑定仍宣称已启用
// 与 ip_acl_mode / 三枚举的「UI 宣称启用、实际零强制」同型漂移，
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
	// 渲染侧 buildRateLimitHandler 的用 rps*60、用
	// rps+burst（int64 运算）——与 request_body_max_size_mb 钳制同型的
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
	// 429 剔除——拦截语义 429 保留给限流(overviewmetrics.go
	// 限流卡片按 code=429 计数),WAF 拦截页 429 会混入限流指标口径;存量 429
	// 行由 services 侧 legacySecurityEnumBackfills 归一为 403。
	validBlockStatus := map[int]bool{400: true, 401: true, 403: true, 404: true, 503: true}
	if blockStatusCode != 0 && !validBlockStatus[blockStatusCode] {
		return fmt.Errorf("拦截状态码必须为 400/401/403/404/503 之一，当前值 %d", blockStatusCode)
	}
	if anomalyThreshold != 0 {
		// 2026-09-09:新增 15 档(3 条严重命中);1/3 保留兼容存量(UI 已改按
		// 命中条数语义呈现 5/10/15/20)。CRS 计分:严重+5/错误+4/警告+3。
		validThresholds := map[int]bool{1: true, 3: true, 5: true, 10: true, 15: true, 20: true}
		if !validThresholds[anomalyThreshold] {
			return fmt.Errorf("异常阈值必须为 1/3/5/10/15/20 之一，当前值 %d", anomalyThreshold)
		}
	}
	switch mode {
	// custom_only(2026-09-09 裁定):CRS 不生效,仅自定义规则。
	case "", "off", "detection", "blocking", "custom_only":
	default:
		return fmt.Errorf("mode 必须为 off、detection、blocking 或 custom_only，当前值 %s", mode)
	}
	switch ipACLMode {
	case "", "allow", "deny", "绕过":
	default:
		return fmt.Errorf("ip_acl_mode 必须为 allow、deny 或 绕过，当前值 %s", ipACLMode)
	}
	switch geoIPMode {
	// "off" 是区域控制关闭态（名单保留不清单），与 WAF mode/ip_acl 同为三态。
	case "", "off", "allow", "deny":
	default:
		return fmt.Errorf("geoip_mode 必须为 off、allow 或 deny，当前值 %s", geoIPMode)
	}
	return nil
}

// resolveCreatePolicyType 解析创建请求的策略类型（策略实体单职化）：显式
// stage1/stage2/stage3 合法；缺省（""）按归一后内容推断（models.InferPolicyType

// 单一事实源）；显式 mixed 与非法值报错（mixed 为存量兼容组，不可新建）。
// 显式类型时由本函数内部调用 normalizeOutOfStageFields 归一阶段外字段。
func resolveCreatePolicyType(req *models.CreateSecurityPolicyRequest) (string, error) {
	switch req.PolicyType {
	case "":
		policyType := models.InferPolicyType(&models.SecurityPolicy{
			Mode: req.Mode, AnomalyThreshold: req.AnomalyThreshold,
			IPACLMode: req.IPACLMode, IPACLList: req.IPACLList, IPACLEnabled: req.IPACLEnabled,
			IPWhitelistEnabled: policyWhitelistDefault(req.IPWhitelistEnabled), IPWhitelist: json.RawMessage(req.IPWhitelist),
			IPBlacklist:      json.RawMessage(req.IPBlacklist),
			RateLimitEnabled: req.RateLimitEnabled, RateLimitRPS: req.RateLimitRPS, RateLimitBurst: req.RateLimitBurst,
			CustomRules: json.RawMessage(req.CustomRules),
			GeoIPMode:   req.GeoIPMode, GeoIPCountries: json.RawMessage(req.GeoIPCountries),
			IPACLListRefs: req.IPACLListRefs, IPWhitelistRefs: req.IPWhitelistRefs,
		})
		if policyType == models.PolicyTypeMixed {
			return "", fmt.Errorf("策略内容跨多个阶段，请显式按阶段类型（信任名单/IP 访问控制/限流/WAF）分别创建")
		}
		// 缺省类型推断路径与显式类型路径同口径归一拦截状态码：无页策略的
		// deny 恒 403、stage2 限流恒 429，落库非零值会让详情/列表宣称一个
		// 不生效的状态码（旧实现只对显式类型调用归一，API/MCP 省略
		// policy_type 即可落 404）。
		req.BlockStatusCode = normalizeBlockStatusCode(req.BlockStatusCode, policyType, req.BlockPageID)
		return policyType, nil
	case models.PolicyTypeStage0, models.PolicyTypeStage1, models.PolicyTypeStage2, models.PolicyTypeStage3:
		// 创建路径的显式类型 = 「按该阶段类型落库」的全量归一契约（编辑器提交
		// 完整表单、单测按全字段建策略均依赖它）；矛盾载荷的显式拒绝只落在
		// 更新路径（那里部分更新 + 显式类型才会出现「保留旧值 vs 静默丢弃」的
		// 二义），见 updateOutOfStageConflict。
		normalizeOutOfStageFields(req, req.PolicyType)
		return req.PolicyType, nil
	case models.PolicyTypeMixed:
		return "", fmt.Errorf("混合策略为存量兼容形态，请按阶段类型（信任名单/IP 访问控制/限流/WAF）创建")
	default:
		return "", fmt.Errorf("无效的策略类型：%s（可选 stage0/stage1/stage2/stage3）", req.PolicyType)
	}
}

// normalizeOutOfStageFields 显式类型提交时把阶段外字段归一为零值（类型与
// 内容不漂移；归一先于内容校验，归一后的空内容天然通过各形状校验）。
// stage0 仅保留信任名单+trust_detection（直通/保留检测二选一，无拦截页）；
// stage1 保留 IP ACL/黑名单/GeoIP+拦截页（信任已归属阶段 0，一律清除）；
// stage2 仅保留限流（恒 429、拦截页保留——2026-09-25 用户裁定可配）；
// stage3 保留 WAF+拦截页。
// mode 归 off（阶段 0/1/2 策略无 WAF 引擎面）。
func normalizeOutOfStageFields(req *models.CreateSecurityPolicyRequest, policyType string) {
	applyStageZerosToCreate(req, policyType)
}

// stageZeroFamily 是「阶段外字段归零」矩阵的元素。Create 与
// Update 两条写路径共用同一份矩阵描述，字段族的具体赋值由各自 applier 完成——
// 新增阶段字段只需在族定义与该族 applier 落一处，不再维护两份逐字段 switch
// （IPWhitelistEnabled nil/false 漂移即双份实现产物）。
type stageZeroFamily int

const (
	stageZeroModeOff         stageZeroFamily = iota // mode → off（阶段 0/1/2 无 WAF 引擎面）
	stageZeroCRSText                                // crs_rule_groups / crs_excluded_rules / custom_rules
	stageZeroRateLimit                              // rate_limit_enabled / rps / burst
	stageZeroWAFFlags                               // waf_check_response / log_request_body
	stageZeroIPACL                                  // ip_acl_enabled / list / list_refs
	stageZeroIPWhitelist                            // ip_whitelist_enabled / list / refs
	stageZeroIPBlacklist                            // ip_blacklist
	stageZeroGeoIP                                  // geoip_mode / geoip_countries
	stageZeroGeoIPCrawler                           // geoip_crawler_exempt / geoip_crawler_engines
	stageZeroBlockPageAll                           // block_page_id + block_status_code
	stageZeroBlockStatusCode                        // 仅 block_status_code（stage2 限流恒 429）
	stageZeroTrustDetection                         // trust_detection（stage0 专属）
)

// outOfStageZeroFamilies 返回该阶段必须归零的字段族——矩阵唯一出处：
// stage0 仅保留信任名单 + trust_detection（直通/保留检测，无拦截页）；
// stage1 保留 IP ACL/黑名单/GeoIP/爬虫豁免/拦截页（信任已归属阶段 0）；
// stage2 仅保留限流 + 拦截页（2026-09-25 用户裁定：页面可配、状态码恒 429）；
// stage3 保留 WAF + 拦截页。
func outOfStageZeroFamilies(policyType string) []stageZeroFamily {
	switch policyType {
	case models.PolicyTypeStage0:
		return []stageZeroFamily{stageZeroModeOff, stageZeroCRSText, stageZeroRateLimit, stageZeroWAFFlags, stageZeroIPACL, stageZeroIPBlacklist, stageZeroGeoIP, stageZeroGeoIPCrawler, stageZeroBlockPageAll}
	case models.PolicyTypeStage1:
		return []stageZeroFamily{stageZeroModeOff, stageZeroCRSText, stageZeroRateLimit, stageZeroWAFFlags, stageZeroIPWhitelist, stageZeroTrustDetection}
	case models.PolicyTypeStage2:
		return []stageZeroFamily{stageZeroModeOff, stageZeroCRSText, stageZeroWAFFlags, stageZeroIPACL, stageZeroIPWhitelist, stageZeroIPBlacklist, stageZeroGeoIP, stageZeroGeoIPCrawler, stageZeroBlockStatusCode, stageZeroTrustDetection}
	case models.PolicyTypeStage3:
		return []stageZeroFamily{stageZeroIPACL, stageZeroIPWhitelist, stageZeroIPBlacklist, stageZeroGeoIP, stageZeroGeoIPCrawler, stageZeroRateLimit, stageZeroTrustDetection}
	}
	return nil
}

// normalizeBlockStatusCode 写侧拦截状态码归一口径（Create/Update 单一事实源）：
// 状态码只在「非 stage2 ∧ 已绑定自定义拦截页」时被渲染消费——stage2 限流拦截
// 恒 429（状态码列无意义），无页策略的 deny 恒 403（blockStatusForPolicy 仅对
// 有有效页的策略分配合成码）。其余形态落零，避免详情/列表宣称一个不生效的值。
func normalizeBlockStatusCode(statusCode int, policyType string, blockPageID int) int {
	if policyType == models.PolicyTypeStage2 || blockPageID == 0 {
		return 0
	}
	return statusCode
}

// applyStageZerosToCreate 按矩阵把创建请求的阶段外字段赋为类型零值。
// IPWhitelistEnabled 赋 &falseVal 而非 nil——nil 经
// policyWhitelistDefault 落默认 1，与 Update 路径（false → 0）形状漂移。
func applyStageZerosToCreate(req *models.CreateSecurityPolicyRequest, policyType string) {
	falseVal := false
	for _, family := range outOfStageZeroFamilies(policyType) {
		switch family {
		case stageZeroModeOff:
			req.Mode = "off"
		case stageZeroCRSText:
			req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules = "[]", "[]", "[]"
		case stageZeroRateLimit:
			req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst = false, 0, 0
		case stageZeroWAFFlags:
			req.WAFCheckResponse, req.LogRequestBody = false, false
		case stageZeroIPACL:
			req.IPACLEnabled = false
			req.IPACLList, req.IPACLListRefs = "[]", "[]"
		case stageZeroIPWhitelist:
			req.IPWhitelistEnabled = &falseVal
			req.IPWhitelist, req.IPWhitelistRefs = "[]", "[]"
		case stageZeroIPBlacklist:
			req.IPBlacklist = "[]"
		case stageZeroGeoIP:
			req.GeoIPMode, req.GeoIPCountries = "off", "[]"
		case stageZeroGeoIPCrawler:
			req.GeoIPCrawlerExempt, req.GeoIPCrawlerEngines = false, "[]"
		case stageZeroBlockPageAll:
			req.BlockPageID, req.BlockStatusCode = 0, 0
		case stageZeroBlockStatusCode:
			req.BlockStatusCode = 0
		case stageZeroTrustDetection:
			req.TrustDetection = false
		}
	}
	// 无自定义页面时状态码不被渲染消费；写侧归一，避免 UI 宣称生效
	// （与 Update 的写后归一单源，见 normalizeBlockStatusCode）。
	req.BlockStatusCode = normalizeBlockStatusCode(req.BlockStatusCode, policyType, req.BlockPageID)
}

// applyStageZerosToUpdate 按同一矩阵把更新请求的阶段外字段指针赋为零值
// （UPDATE 随之落零）。只有矩阵描述的族被触碰，未列字段保持调用方原值。
// 每字段一次 new(expr) 分配独立变量：归零矩阵各字段不得共享同一局部变量
// （别名会让将来任何 `*req.X = v` 形态的归一同时改写多个落库字段，且在
// review 中不可见）。
func applyStageZerosToUpdate(req *models.UpdateSecurityPolicyRequest, policyType string) {
	for _, family := range outOfStageZeroFamilies(policyType) {
		switch family {
		case stageZeroModeOff:
			req.Mode = new("off")
		case stageZeroCRSText:
			req.CRSRuleGroups, req.CRSExcludedRules, req.CustomRules = new("[]"), new("[]"), new("[]")
		case stageZeroRateLimit:
			req.RateLimitEnabled, req.RateLimitRPS, req.RateLimitBurst = new(false), new(0), new(0)
		case stageZeroWAFFlags:
			req.WAFCheckResponse, req.LogRequestBody = new(false), new(false)
		case stageZeroIPACL:
			req.IPACLEnabled = new(false)
			req.IPACLList, req.IPACLListRefs = new("[]"), new("[]")
		case stageZeroIPWhitelist:
			req.IPWhitelistEnabled = new(false)
			req.IPWhitelist, req.IPWhitelistRefs = new("[]"), new("[]")
		case stageZeroIPBlacklist:
			req.IPBlacklist = new("[]")
		case stageZeroGeoIP:
			req.GeoIPMode, req.GeoIPCountries = new("off"), new("[]")
		case stageZeroGeoIPCrawler:
			req.GeoIPCrawlerExempt, req.GeoIPCrawlerEngines = new(false), new("[]")
		case stageZeroBlockPageAll:
			req.BlockPageID, req.BlockStatusCode = new(0), new(0)
		case stageZeroBlockStatusCode:
			req.BlockStatusCode = new(0)
		case stageZeroTrustDetection:
			req.TrustDetection = new(false)
		}
	}
}

// stageZeroFamilyConflictHint 返回「阶段外字段显式生效」提示中的字段描述。
func stageZeroFamilyConflictHint(f stageZeroFamily) string {
	switch f {
	case stageZeroModeOff:
		return "WAF 模式（mode）"
	case stageZeroCRSText:
		return "CRS 规则组/排除规则/自定义规则"
	case stageZeroRateLimit:
		return "限流（rate_limit_enabled）"
	case stageZeroWAFFlags:
		return "WAF 响应检查/请求体记录"
	case stageZeroIPACL:
		return "IP 访问控制（ip_acl_enabled）"
	case stageZeroIPWhitelist:
		return "信任名单（ip_whitelist_enabled）"
	case stageZeroIPBlacklist:
		return "IP 黑名单（ip_blacklist）"
	case stageZeroGeoIP:
		return "地域控制（geoip_mode/geoip_countries）"
	case stageZeroGeoIPCrawler:
		return "爬虫豁免（geoip_crawler_exempt）"
	case stageZeroTrustDetection:
		return "保留检测记录（trust_detection）"
	}
	return ""
}

// stageZeroFamilyOwnerStage 返回该字段族所属策略阶段（提示「请改用阶段 N 策略」）。
func stageZeroFamilyOwnerStage(f stageZeroFamily) string {
	switch f {
	case stageZeroRateLimit:
		return "2"
	case stageZeroIPACL, stageZeroIPBlacklist, stageZeroGeoIP, stageZeroGeoIPCrawler:
		return "1"
	case stageZeroIPWhitelist, stageZeroTrustDetection:
		return "0"
	}
	return "3"
}

// outOfStageConflictMessage 按「阶段外字段显式生效」矩阵生成 400 文案。
//
// 显式 policy_type 下阶段外字段被静默归一为零值（applyStageZerosTo*）：API/MCP
// 调用方无法从 200 区分「已生效」与「被忽略」，审计 delta 也不含该字段——
// 与缺省类型路径（校验门给出的 400）形成同一意图两种结果。显式生效即 400。
//
// 惰性默认值不算冲突：编辑器对不呈现的字段仍回传默认值（限流 rps/burst
// 100/50、爬虫引擎清单、关闭开关下保留的名单），它们在该阶段不产生行为面。
// 拦截页/状态码两族不参与判定：阶段 0 的页面字段是纯展示残留，阶段 2 的页面
// 本就保留（状态码恒 429）——归零不改变可观测行为。
func outOfStageConflictMessage(policyType string, active func(stageZeroFamily) bool) string {
	for _, family := range outOfStageZeroFamilies(policyType) {
		if !active(family) {
			continue
		}
		return fmt.Sprintf("阶段 %s 策略不支持%s，请改用阶段 %s 策略或清除该字段",
			strings.TrimPrefix(policyType, "stage"),
			stageZeroFamilyConflictHint(family),
			stageZeroFamilyOwnerStage(family))
	}
	return ""
}

// jsonListPayloadNonEmpty 报告 JSON 数组载荷是否有条目（""/"[]"/畸形视为空）。
func jsonListPayloadNonEmpty(raw string) bool {
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return false
	}
	return len(entries) > 0
}

// updateOutOfStageConflict 判定更新请求在显式类型下的阶段外「显式生效」字段
// （只看显式提供的指针，nil=不修改不算冲突）。
func updateOutOfStageConflict(req *models.UpdateSecurityPolicyRequest, policyType string) string {
	strNonEmpty := func(p *string) bool { return p != nil && jsonListPayloadNonEmpty(*p) }
	return outOfStageConflictMessage(policyType, func(family stageZeroFamily) bool {
		switch family {
		case stageZeroModeOff:
			return req.Mode != nil && *req.Mode != "" && *req.Mode != "off"
		case stageZeroCRSText:
			return strNonEmpty(req.CRSRuleGroups) || strNonEmpty(req.CRSExcludedRules) || strNonEmpty(req.CustomRules)
		case stageZeroRateLimit:
			return req.RateLimitEnabled != nil && *req.RateLimitEnabled
		case stageZeroWAFFlags:
			return (req.WAFCheckResponse != nil && *req.WAFCheckResponse) || (req.LogRequestBody != nil && *req.LogRequestBody)
		case stageZeroIPACL:
			return req.IPACLEnabled != nil && *req.IPACLEnabled
		case stageZeroIPWhitelist:
			return req.IPWhitelistEnabled != nil && *req.IPWhitelistEnabled
		case stageZeroIPBlacklist:
			return strNonEmpty(req.IPBlacklist)
		case stageZeroGeoIP:
			return (req.GeoIPMode != nil && *req.GeoIPMode != "" && *req.GeoIPMode != "off") || strNonEmpty(req.GeoIPCountries)
		case stageZeroGeoIPCrawler:
			return req.GeoIPCrawlerExempt != nil && *req.GeoIPCrawlerExempt
		case stageZeroTrustDetection:
			return req.TrustDetection != nil && *req.TrustDetection
		}
		return false
	})
}

// countStage2Policies 统计给定策略 id 集合中 stage2（限流）策略的数量——限流
// 策略唯一绑定（2026-09-20 用户裁定：一条规则最多绑定一条限流策略，多限流
// 叠加无意义且配置面误导；存量多限流绑定保持可运行，写路径收敛到一条）。
func countStage2Policies(tx *sql.Tx, ctx context.Context, ids []int) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_policies WHERE policy_type='stage2' AND id IN ("+strings.Join(placeholders, ",")+")", args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func validateIPCIDRList(field, raw string) error {
	if raw == "" {
		return nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("%s 必须是 JSON 数组", field)
	}
	// 条数封顶：内联名单原样随策略列表/详情回传，并在每次渲染时逐条展开
	// （全局请求体上限默认 128MB，拦不住十万级条目的写入）。阈值与 IP 名单
	// 条目上限（ipListMaxEntries）同源——同一份 IP 集合不应因写入口不同而
	// 出现两种上限。
	if len(entries) > ipListMaxEntries {
		return fmt.Errorf("%s 条目数量不能超过 %d 条", field, ipListMaxEntries)
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
	// netip.ParseAddr 接受 zone 形态(fe80::1%eth0),
	// 但 coraza @ipMatch 静默丢弃(引擎 ip_match.go 不识别 zone)——零留痕
	// 落库即失效。此处拒绝:带 zone 的地址不视为有效条目。
	addr, err := netip.ParseAddr(entry)
	return err == nil && addr.Zone() == ""
}

// user-id 三 helper 已合一为 rule_features.go 的
// contextUserID(int64)——原 getContextUserIDInt(→int)/getContextUserID
// (→string) 删除,调用点按需 int()/strconv.FormatInt 型转换。

func (h *Handlers) ListCRSRules(c *gin.Context) {
	entries, err := os.ReadDir(crsRulesDirPath())
	if err != nil {
		// 降级空列表 200 与「确实无规则」不可区分——
		// 同域标准对齐,改 500。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("CRS 规则目录不可读", err)})
		return
	}

	search := strings.ToLower(c.DefaultQuery("search", ""))
	// 分页参数与事件列表共用严格解析（非整数 400）：旧实现丢弃 fmt.Sscanf
	// 错误静默回落第 1 页/50 条，同面板两类列表对错误输入行为不一致。
	page, ok := parsePaginationParam(c, "page", 1, 100000)
	if !ok {
		return
	}
	// 上限收紧 100→50（与默认页大小/前端单页渲染边界一致）；低于 1 回默认。
	pageSize, ok := parsePaginationParam(c, "page_size", 50, 50)
	if !ok {
		return
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
			// 静默跳过会把残缺列表以 200 返回（与同域「列表故障必须显式
			// 500」口径冲突）。
			services.Logf("error", "CRS 规则文件 stat 失败 %q: %v", entry.Name(), err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CRS 规则文件读取失败: " + entry.Name()})
			return
		}
		cat := services.CategorizeCRSFile(entry.Name())
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

// GetCRSRuleIndex 返回结构化 CRS 规则索引（id/msg/file/category，按 id 升序）。
// 消费方：保存侧 6 位规则 ID/两位组号的存在性校验与前端规则选择器；缓存与
// BuildCorazaDirectives 的混合展开/陈旧过滤共享同一实例（services.GetCRSRuleIndex）。
func (h *Handlers) GetCRSRuleIndex(c *gin.Context) {
	index := services.GetCRSRuleIndex()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"version": index.Version, "rules": index.Rules}})
}

func (h *Handlers) GetCRSRuleContent(c *gin.Context) {
	filename := c.Param("filename")
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的文件名"})
		return
	}
	// 经 crsRulesDir 测试缝解析（与 ListCRSRules 同源），消除硬编码路径与
	// 局部变量对 filepath 包名的遮蔽；上方路径穿越门（../ 与 /）原样保留。
	path := filepath.Join(crsRulesDirPath(), filename)
	f, err := os.Open(path)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则文件不存在"})
		return
	}
	defer f.Close()
	// 对齐 GetCRSSetupConfig 的 413 口径——超限显式
	// 拒绝而非静默截断，防消费方（UI 预览/MCP 抓取）把残缺内容当完整规则使用。
	// 只读查看端点：rules/*.conf 带外手改不受支持（裁定，见 GetCRSSetupConfig
	// 注释），规则变更须经 CRS 更新流程。
	content, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if len(content) > 1<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "规则文件超过 1MB 读取上限"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"filename": filename, "content": string(content), "size": len(content)}})
}

func (h *Handlers) GetCRSSetupConfig(c *gin.Context) {
	// 对齐同域读端点的尺寸口径（GetCRSRuleContent 1MB、更新日志 128KB），
	// 超限时显式 413 拒绝而非静默截断——避免调用方把截断内容当作完整配置使用。
	// （2026-09 用户裁定）：带外手改 crs-setup.conf / rules/*.conf 不受支持——
	// coraza 池指纹（crsPoolFingerprint，internal/services/security.go）只覆盖
	// 「CRS 版本行 + zz-user-overrides.conf 的 mtime+size」两类变化向量，不含
	// crs-setup.conf / rules/*.conf；带外手改后池键不变、新配置 Provision 复用
	// 旧 WAF，手改静默不生效（直到进程重启或下一次 CRS 版本变更）。CRS 配置
	// 变更必须经 CRS 更新流程；本端点仅为只读查看。
	f, err := os.Open(crsSetupConfPath())
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CRS 配置文件不存在"})
		return
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("服务器内部错误", err)})
		return
	}
	if len(content) > 1<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "CRS 配置文件超过 1MB 读取上限"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": string(content)}})
}

func parsePositiveNumericID(raw string) (int64, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil && id > 0
}

// rowsAffectedOrRespond 统一写后存在性判定：RowsAffected
// 返回错误时必须显式 500——此前 8 处 `if rows, _ := result.RowsAffected(); rows
// == 0` 把驱动层错误吞成「0 行」，真实故障被误报为 404（重试语义误导）。
// 返回 false 表示已写出响应，调用方直接 return。
func rowsAffectedOrRespond(c *gin.Context, result sql.Result, notFoundMsg string) bool {
	rows, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取写入结果失败", err)})
		return false
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: notFoundMsg})
		return false
	}
	return true
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

// crawlerEnginesJSON（v2.3.8 爬虫豁免）：请求 engines 原样或空串→默认勾选集；
// 逐项校验 geoipnames 注册表（非法 ID 400 由调用方 validatePolicyCrawlerExemption
// 前置完成，此处仅归一空值形态）。
func crawlerEnginesJSON(raw string) string {
	if strings.TrimSpace(raw) == "" {
		b, _ := json.Marshal(geoipnames.DefaultCrawlerEngines())
		return string(b)
	}
	return raw
}

// crawlerExemptBool：INSERT 侧豁免位归一——开关关闭或 geoip 非启用形态恒 0
// （防 orphan 配置：geoip off 时留下豁免位，重开时意外生效）。
func crawlerExemptBool(exempt bool, geoipActive bool) bool {
	return exempt && geoipActive
}

// validatePolicyCrawlerExemption（v2.3.8）：爬虫豁免字段校验——豁免开启时
// geoip 须为启用形态、engines 逐项 geoipnames 注册表白名单。
func validatePolicyCrawlerExemption(exempt bool, engines string, geoipMode string) error {
	if exempt && (geoipMode == "" || geoipMode == "off") {
		return fmt.Errorf("开启爬虫豁免要求地域拦截为启用形态（当前 geoip_mode=%q）", geoipMode)
	}
	raw := strings.TrimSpace(engines)
	if raw == "" {
		return nil // 空=全部引擎（生成侧同语义）
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return fmt.Errorf("geoip_crawler_engines 必须是引擎 ID 数组: %v", err)
	}
	for _, id := range list {
		if !geoipnames.ValidCrawlerEngineID(id) {
			return fmt.Errorf("未知爬虫引擎 ID: %q（须来自内置引擎注册表）", id)
		}
	}
	return nil
}
