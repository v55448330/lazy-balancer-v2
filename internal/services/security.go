package services

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// crsDirectivesDir is a test seam (mirroring crsLiveDir in crsupdate.go);
// emitted Include directives always use the container path.
var crsDirectivesDir = "/app/waf/crs"

func GetSecurityPolicyForRule(ruleCaddyID string) *models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	var policyID int
	err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id DESC LIMIT 1", ruleCaddyID).Scan(&policyID)
	if err != nil {
		return nil
	}
	var p models.SecurityPolicy
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
	err = db.DB.QueryRow(`SELECT id, name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst, crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled, created_at, updated_at, geoip_countries, geoip_mode, waf_check_response
		FROM security_policies WHERE id=? AND enabled=1`, policyID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &ipWhitelist, &ipBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse)
	if err != nil {
		return nil
	}
	p.IPWhitelist = json.RawMessage(ipWhitelist)
	p.IPBlacklist = json.RawMessage(ipBlacklist)
	p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
	p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
	p.CustomRules = json.RawMessage(customRules)
	p.GeoIPCountries = json.RawMessage(geoipCountries)
	return &p
}

// geoipCountries parses the policy's geoip_countries JSON array, skipping
// blank entries. A missing or malformed payload yields nil.
func geoipCountries(p *models.SecurityPolicy) []string {
	if p == nil || len(p.GeoIPCountries) == 0 {
		return nil
	}
	var entries []string
	if err := json.Unmarshal(p.GeoIPCountries, &entries); err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// PolicyHasGeoIP reports whether the policy configures any geoip countries.
func PolicyHasGeoIP(p *models.SecurityPolicy) bool {
	return len(geoipCountries(p)) > 0
}

func BuildCorazaDirectives(p *models.SecurityPolicy) string {
	var sb strings.Builder
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)

	// IP-level control (ACL / trust list / legacy bypass & blacklist) runs
	// independently of the WAF mode so that "关闭 WAF" never disables IP control.
	emitIPControl := len(ipWL) > 0 || len(ipBL) > 0 || (p.IPACLEnabled && len(ipACLList) > 0)
	customRules := resolvePolicyCustomRules(p.CustomRules)
	hasCustomRules := false
	for _, cr := range customRules {
		if cr.Enabled {
			hasCustomRules = true
			break
		}
	}

	switch {
	case p.Mode == "blocking":
		sb.WriteString("SecRuleEngine On\n")
	case p.Mode == "detection":
		// 检测模式仍保持 IP 控制与自定义规则强制生效：引擎以 On 启动，使下方的
		// IP ACL deny 规则与自定义拦截规则（在 DetectionOnly 切换之前发出）真实
		// 阻断；随后通过 phase:1 的 SecAction 仅将 CRS 规则集切换为
		// DetectionOnly（该切换在 CRS Include 之前生效），自定义拦截规则与 IP
		// ACL 不受影响，仍在检测模式下强制阻断。
		sb.WriteString("SecRuleEngine On\n")
	case emitIPControl || hasCustomRules:
		// WAF (CRS) off, but IP control / custom rules still need the engine.
		sb.WriteString("SecRuleEngine On\n")
	default:
		return ""
	}
	sb.WriteString("SecRequestBodyAccess On\n")
	if p.WAFCheckResponse {
		sb.WriteString("SecResponseBodyAccess On\n")
	} else {
		sb.WriteString("SecResponseBodyAccess Off\n")
	}
	sb.WriteString("SecAuditEngine RelevantOnly\nSecAuditLog /app/waf/audit/audit.log\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHKZ\n")

	// SecRule id map: 2 = ACL allow/deny, 3 = bypass-mode (legacy), 4 = legacy
	// blacklist, 5 = trust list. The trust list keeps the historical id:3 unless
	// a bypass-mode rule already owns it. ctl:ruleEngine=Off short-circuits are
	// emitted first so bypassed and trusted clients never reach the ACL denies.
	bypassEmitted := false
	if p.IPACLEnabled && p.IPACLMode == "bypass" && len(ipACLList) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(ipACLList, ",")))
		bypassEmitted = true
	}
	if len(ipWL) > 0 {
		trustID := 3
		if bypassEmitted {
			trustID = 5
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(ipWL, ","), trustID))
	}
	if p.IPACLEnabled && len(ipACLList) > 0 {
		if p.IPACLMode == "allow" {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝'\"\n", strings.Join(ipACLList, ",")))
		} else if p.IPACLMode == "deny" {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'\"\n", strings.Join(ipACLList, ",")))
		}
	}
	if len(ipBL) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:4,phase:1,deny,status:403,log,msg:'IP 黑名单'\"\n", strings.Join(ipBL, ",")))
	}

	emitCustomRules(&sb, customRules)

	if p.Mode == "detection" {
		sb.WriteString("SecAction \"id:6,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly\"\n")
	}

	if p.Mode == "blocking" || p.Mode == "detection" {
		var groups []string
		json.Unmarshal(p.CRSRuleGroups, &groups)
		sb.WriteString("Include /app/waf/crs/crs-setup.conf\n")
		if _, err := os.Stat(filepath.Join(crsDirectivesDir, "zz-user-overrides.conf")); err == nil {
			sb.WriteString("Include /app/waf/crs/zz-user-overrides.conf\n")
		}
		if p.AnomalyThreshold > 0 {
			sb.WriteString(fmt.Sprintf("SecAction \"id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", p.AnomalyThreshold))
		}
		if len(groups) == 0 {
			if p.WAFCheckResponse {
				sb.WriteString("Include /app/waf/crs/rules/*.conf\n")
			} else {
				sb.WriteString("Include /app/waf/crs/rules/REQUEST-*.conf\n")
			}
		} else {
			for _, g := range groups {
				sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/REQUEST-9%[1]s-*.conf\n", g))
				if p.WAFCheckResponse {
					sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/RESPONSE-9%[1]s-*.conf\n", g))
				}
			}
		}

		var excludedRules []string
		json.Unmarshal(p.CRSExcludedRules, &excludedRules)
		for _, ruleID := range excludedRules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID != "" {
				sb.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", crsFilenameToRuleIDRange(ruleID)))
			}
		}
	}

	return sb.String()
}

// customRuleTargets / customRuleOperators 是自定义规则条件允许的目标与运算符
// 映射；emitCustomRules 与校验函数共用同一份，避免两处硬编码漂移。
var (
	customRuleTargets   = map[string]string{"uri": "REQUEST_URI", "args": "ARGS", "body": "REQUEST_BODY", "headers": "REQUEST_HEADERS", "user_agent": "REQUEST_HEADERS:User-Agent"}
	customRuleOperators = map[string]string{"contains": "@contains", "regex": "@rx", "equals": "@pm", "starts_with": "@beginsWith"}
)

// conditionsEmissionIssue 返回条件列表不可安全发射的原因（"含尾部反斜杠"/"空条件"/
// "非法 target 或 operator"），无问题时返回空串。供发射防御与集群同步预检共用，
// 避免两处判定漂移。target/operator 必须在允许集合内，否则发射循环会因映射不到
// 对应变量而产出缺 ID 的畸形 SecRule（链式规则还会留下悬空 chain），导致 coraza
// 整体拒绝配置。
func conditionsEmissionIssue(conditions []models.CustomRuleCondition) string {
	if len(conditions) == 0 {
		return "空条件"
	}
	for _, cond := range conditions {
		if strings.HasSuffix(cond.Pattern, `\`) {
			return "含尾部反斜杠"
		}
		if customRuleTargets[cond.Target] == "" {
			return "非法 target 或 operator"
		}
		if customRuleOperators[cond.Operator] == "" {
			return "非法 target 或 operator"
		}
	}
	return ""
}

// customRuleEmissionIssue 在 conditionsEmissionIssue 基础上兼容旧版单目标内嵌形状
// （无 conditions、靠 target/operator/pattern 发射），并对该形状同样校验 target/
// operator 合法性。
func customRuleEmissionIssue(cr models.CustomRule) string {
	// 规则名进入 msg 引号串：控制字符/双引号会截断规则行或提前闭合动作。
	for _, r := range cr.Name {
		if r < 0x20 || r == 0x7f || r == '"' {
			return "规则名称含控制字符或双引号"
		}
	}
	if len(cr.Conditions) > 0 {
		return conditionsEmissionIssue(cr.Conditions)
	}
	if strings.HasSuffix(cr.Pattern, `\`) {
		return "含尾部反斜杠"
	}
	if cr.Target == "" || cr.Operator == "" {
		return "空条件"
	}
	if customRuleTargets[cr.Target] == "" || customRuleOperators[cr.Operator] == "" {
		return "非法 target 或 operator"
	}
	return ""
}

// emitCustomRules writes user rules ahead of any DetectionOnly switch so a
// rule-level "拦截" action always blocks regardless of the policy WAF mode,
// mirroring how IP control behaves. 动作语义与前端编辑器一致：拦截=命中即阻断；
// 仅记录=只记录事件、不向异常分累加；放行计分=记录并向异常分累加，由 949
// 评估（受 WAF 模式约束）统一裁决。
// customRulePhase 按规则目标选择 coraza 相位：条件或旧版单目标形状命中 body
// （REQUEST_BODY，仅 phase:2 可读）时返回 2，否则返回 1；链式规则所有条目共用
// 该相位。
func customRulePhase(cr models.CustomRule) int {
	if cr.Target == "body" {
		return 2
	}
	for _, cond := range cr.Conditions {
		if cond.Target == "body" {
			return 2
		}
	}
	return 1
}

func emitCustomRules(sb *strings.Builder, customRules []models.CustomRule) {
	for _, cr := range customRules {
		if !cr.Enabled {
			continue
		}
		// 发射侧防御：单条含尾部反斜杠或空条件的规则只跳过自身并告警，绝不让整份
		// 配置生成失败——一条坏规则不得拖垮所有站点；存量脏规则与集群同步绕过的规则
		// 均在此兜底。
		if issue := customRuleEmissionIssue(cr); issue != "" {
			log.Printf("自定义规则 %d(%s) %s，已跳过发射，请修正或禁用", cr.ID, cr.Name, issue)
			continue
		}
		safeName := strings.ReplaceAll(cr.Name, "'", "")
		// CRS v4 blocking evaluation reads tx.inbound_anomaly_score_pl1..4 —
		// never the legacy tx.anomaly_score.
		// 默认动作 pass（放行计分）：记录事件并向异常分累加。
		action := fmt.Sprintf("pass,log,setvar:tx.inbound_anomaly_score_pl1=+%d,msg:'自定义规则 %s 命中'", cr.Score, safeName)
		if cr.Action == "block" {
			// 统一所有拦截走 coraza 默认 403 → 策略 errors.routes → 拦截页面配置的状态码
			action = fmt.Sprintf("deny,log,setvar:tx.inbound_anomaly_score_pl1=+%d,msg:'自定义规则 %s 命中'", cr.Score, safeName)
		} else if cr.Action == "log" {
			// 仅记录：不累加异常分，避免在拦截/检测模式下因该规则误伤。
			action = fmt.Sprintf("pass,log,msg:'自定义规则 %s 命中'", safeName)
		}
		// 相位选择：任一条件以请求体为目标时整条链发射 phase:2（REQUEST_BODY 仅在
		// phase:2 可读，phase:1 发射的 body 规则永远不匹配）；其余一律 phase:1，保持
		// 拦截规则先于 DetectionOnly 切换（id:6，phase:1）执行的检测模式保障。
		// body 规则的检测模式限制说明：DetectionOnly 在 phase:1 切换，body 只能
		// phase:2 —— 检测模式下 body 拦截规则仅记录不阻断，属 coraza 相位约束。
		phase := customRulePhase(cr)
		if len(cr.Conditions) > 0 {
			for idx, cond := range cr.Conditions {
				// 非法 target/operator 已在上方 customRuleEmissionIssue 整条跳过，
				// 此处不再静默丢弃单条条件，避免链式规则产生缺 ID 起始条或悬空 chain。
				target := customRuleTargets[cond.Target]
				op := customRuleOperators[cond.Operator]
				// 链式规则仅起始条携带 id/phase/disruptive/msg；coraza v3 拒绝非起始条上的 disruptive 动作
				// 链上所有条目共用同一相位（coraza 以起始条相位执行整条链）
				var actions string
				if idx == 0 {
					actions = fmt.Sprintf("id:%d,phase:%d,%s", cr.ID+10000, phase, action)
				} else {
					actions = fmt.Sprintf("phase:%d", phase)
				}
				if idx < len(cr.Conditions)-1 {
					actions += ",chain"
				}
				sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"%s\"\n", target, op, escapeCorazaPattern(cond.Pattern), actions))
			}
		} else {
			target := customRuleTargets[cr.Target]
			op := customRuleOperators[cr.Operator]
			sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"id:%d,phase:%d,%s\"\n", target, op, escapeCorazaPattern(cr.Pattern), cr.ID+10000, phase, action))
		}
	}

}

// SecurityPolicyHasIPControl reports whether the policy applies any IP-level
// control, mirroring the emission condition in BuildCorazaDirectives: a
// non-empty trust list (ip_whitelist) or legacy blacklist (ip_blacklist)
// always applies, while the ACL list (allow/deny/bypass) only applies when
// ip_acl_enabled is on. This keeps the summary from claiming a capability the
// emission would never produce.
func SecurityPolicyHasIPControl(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	if len(ipWL) > 0 {
		return true
	}
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	if len(ipBL) > 0 {
		return true
	}
	return p.IPACLEnabled && len(ipACLList) > 0
}

// CountEnabledCustomRules returns how many of the policy's referenced custom
// rules are enabled, mirroring emission (emitCustomRules skips disabled rules).
// The summary's custom_rules_count must not count disabled rules, otherwise the
// policy list would advertise rules the WAF never emits.
func CountEnabledCustomRules(raw json.RawMessage) int {
	count := 0
	for _, cr := range resolvePolicyCustomRules(raw) {
		if cr.Enabled {
			count++
		}
	}
	return count
}

// buildWafHandler returns the coraza WAF handler, or nil when the rule is not HTTP or has no active bound policy.
func buildWafHandler(ruleCaddyID string) map[string]interface{} {
	if db.DB == nil {
		return nil
	}
	var protocol string
	if err := db.DB.QueryRow("SELECT protocol FROM lb_rules WHERE caddy_id=?", ruleCaddyID).Scan(&protocol); err != nil || protocol != "http" {
		return nil
	}
	policy := GetSecurityPolicyForRule(ruleCaddyID)
	if policy == nil {
		return nil
	}
	directives := BuildCorazaDirectives(policy)
	if directives == "" {
		return nil
	}
	return map[string]interface{}{
		"handler":    "waf",
		"directives": directives,
	}
}

// resolvePolicyCustomRules 解析策略的自定义规则引用：当前端存储为规则 ID 数组时
// 从 security_custom_rules 表解析为完整规则；兼容早期的对象内嵌形状。
func resolvePolicyCustomRules(raw json.RawMessage) []models.CustomRule {
	if len(raw) == 0 {
		return nil
	}
	var ids []int
	if err := json.Unmarshal(raw, &ids); err == nil {
		if len(ids) == 0 || db.DB == nil {
			return nil
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		args := make([]interface{}, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		rows, err := db.DB.Query("SELECT id, name, conditions, action, score, enabled FROM security_custom_rules WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		var rules []models.CustomRule
		for rows.Next() {
			var cr models.CustomRule
			var conditionsJSON string
			if err := rows.Scan(&cr.ID, &cr.Name, &conditionsJSON, &cr.Action, &cr.Score, &cr.Enabled); err != nil {
				continue
			}
			json.Unmarshal([]byte(conditionsJSON), &cr.Conditions)
			rules = append(rules, cr)
		}
		// 悬空引用（规则已被删除）不改变解析行为，仅记录日志便于排查
		if dropped := len(ids) - len(rules); dropped > 0 {
			log.Printf("策略引用的自定义规则有 %d 个不存在，已跳过", dropped)
		}
		return rules
	}
	var embedded []models.CustomRule
	if err := json.Unmarshal(raw, &embedded); err == nil {
		return embedded
	}
	return nil
}

func crsFilenameToRuleIDRange(s string) string {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) >= 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil && n >= 100 && n <= 999 {
			return fmt.Sprintf("%d000-%d999", n, n)
		}
	}
	return s
}

// ValidateCustomRuleConditions 校验单条规则的匹配条件：至少需要一个条件；target/
// operator 必须在允许集合内，pattern 不得包含会截断 SecRule 行的控制字符或以反
// 斜杠结尾；否则 emitCustomRules 会静默跳过未知条件导致链式规则断裂或生成畸形
// SecRule。
func ValidateCustomRuleConditions(conditions []models.CustomRuleCondition) error {
	if len(conditions) == 0 {
		return fmt.Errorf("自定义规则至少需要一个匹配条件")
	}
	for i, cond := range conditions {
		if _, ok := customRuleTargets[cond.Target]; !ok {
			return fmt.Errorf("自定义规则条件 %d 的 target 无效：%q（可选：uri、args、body、headers、user_agent）", i+1, cond.Target)
		}
		if _, ok := customRuleOperators[cond.Operator]; !ok {
			return fmt.Errorf("自定义规则条件 %d 的 operator 无效：%q（可选：contains、regex、equals、starts_with）", i+1, cond.Operator)
		}
		if err := validateCustomRulePattern(cond.Operator, cond.Pattern); err != nil {
			return fmt.Errorf("自定义规则条件 %d：%w", i+1, err)
		}
	}
	return nil
}

// ValidateCustomRulesJSON 校验策略 custom_rules 载荷，兼容规则 ID 数组与内嵌
// 规则对象两种形状；内嵌形状逐条校验条件的目标/运算符/模式。
func ValidateCustomRulesJSON(customRulesJSON string) error {
	if strings.TrimSpace(customRulesJSON) == "" {
		return nil
	}
	var ids []int
	if err := json.Unmarshal([]byte(customRulesJSON), &ids); err == nil {
		return nil
	}
	var rules []models.CustomRule
	if err := json.Unmarshal([]byte(customRulesJSON), &rules); err != nil {
		return fmt.Errorf("custom_rules 必须是规则 ID 数组或规则对象数组")
	}
	for i, r := range rules {
		// 占位规则（无条件且无单目标）在发射阶段无任何可用条件，与单条件校验一致按空条件拒绝
		if len(r.Conditions) == 0 && r.Target == "" && r.Operator == "" {
			return fmt.Errorf("自定义规则 #%d：自定义规则至少需要一个匹配条件", i+1)
		}
		if len(r.Conditions) > 0 {
			if err := ValidateCustomRuleConditions(r.Conditions); err != nil {
				return fmt.Errorf("自定义规则 #%d：%w", i+1, err)
			}
			continue
		}
		if _, ok := customRuleTargets[r.Target]; !ok {
			return fmt.Errorf("自定义规则 #%d 的 target 无效：%q（可选：uri、args、body、headers、user_agent）", i+1, r.Target)
		}
		if _, ok := customRuleOperators[r.Operator]; !ok {
			return fmt.Errorf("自定义规则 #%d 的 operator 无效：%q（可选：contains、regex、equals、starts_with）", i+1, r.Operator)
		}
		if err := validateCustomRulePattern(r.Operator, r.Pattern); err != nil {
			return fmt.Errorf("自定义规则 #%d：%w", i+1, err)
		}
	}
	return nil
}

// validateCustomRulePattern 拒绝三类会破坏 SecRule 行的模式：
//  1. 空/纯空白模式——@contains "" 之类对空模式的匹配等于匹配一切请求，全员命中；
//  2. 真实控制字符（含换行/回车/NUL/制表符等）会截断 SecRule 行；
//  3. 以反斜杠结尾的模式——coraza 的 UnescapeQuotedString 仅反转义 \"，其余
//     反斜杠序列原样保留，末尾的反斜杠会与结尾引号组合成转义引号，使 SecRule
//     行畸形并被 coraza 拒绝，进而导致之后所有配置重生成失败。
func validateCustomRulePattern(operator, pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("匹配内容不能为空")
	}
	for _, r := range pattern {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("匹配内容不能包含控制字符（含制表符）")
		}
	}
	if strings.HasSuffix(pattern, `\`) {
		if operator == "regex" {
			return fmt.Errorf("正则匹配内容不能以反斜杠结尾：末尾反斜杠会与结尾引号组合成转义引号导致规则失效。正则可用 `\\$` 结尾锚定或末尾追加 `(?:)` 空组表达尾部反斜杠")
		}
		return fmt.Errorf("该运算符不支持以反斜杠结尾的匹配内容，请改用正则运算符（如 `\\$`）表达")
	}
	return nil
}

func escapeCorazaPattern(pattern string) string {
	// coraza UnescapeQuotedString only unescapes \" — every other backslash
	// sequence (e.g. regex \d) must pass through verbatim, so only quotes are
	// escaped here. 额外的防御：真实的控制字符（换行/回车/NUL 等）会截断 SecRule
	// 行，替换为空格；仅处理真实控制 rune，字面的 `\n` 两字符序列保持原样。
	var sb strings.Builder
	sb.Grow(len(pattern))
	for _, r := range pattern {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r < 0x20 || r == 0x7f:
			sb.WriteByte(' ')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
