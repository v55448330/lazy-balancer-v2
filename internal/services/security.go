package services

import (
	"encoding/json"
	"fmt"
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

// scanSecurityPolicyByID 按主键加载一条 enabled 策略行，并把 JSON 文本列转为
// json.RawMessage；行缺失或 disabled 时返回 nil。GetSecurityPolicyForRule 与
// GetSecurityPoliciesForRule 共用本扫描，保证两条读路径字段级一致。
func scanSecurityPolicyByID(policyID int) *models.SecurityPolicy {
	var p models.SecurityPolicy
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
	err := db.DB.QueryRow(`SELECT id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,5), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist,'[]'), COALESCE(ip_blacklist,'[]'),
		COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0), COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'), COALESCE(block_page_id,0), COALESCE(block_status_code,0), enabled, COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(waf_check_response,0)
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

// GetSecurityPolicyForRule 返回 v2.2.0 单策略语义下的规则生效策略：最高
// policy_id 绑定生效，最高绑定指向禁用策略时返回 nil（不回退次高）。必须与
// loadSecurityPolicyContext（caddy.go 批量预载，Round 34 F-5）保持同构。
// 多策略消费方应改用 GetSecurityPoliciesForRule；待生成路径遍历完整策略列表
// 后，本函数再退化为该列表的薄包装（取首元素）。
func GetSecurityPolicyForRule(ruleCaddyID string) *models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	var policyID int
	err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id DESC LIMIT 1", ruleCaddyID).Scan(&policyID)
	if err != nil {
		return nil
	}
	return scanSecurityPolicyByID(policyID)
}

// GetSecurityPoliciesForRule returns all enabled policies bound to a rule,
// ordered by policy_id ASC (R72 v2.2.0 multi-policy binding).
func GetSecurityPoliciesForRule(ruleCaddyID string) []*models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var policies []*models.SecurityPolicy
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			return nil
		}
		// 禁用策略在策略查询处过滤（与单查的 WHERE enabled=1 同口径）。
		if p := scanSecurityPolicyByID(policyID); p != nil {
			policies = append(policies, p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil
	}
	return policies
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

// crsPoolFingerprint（R72 三十次 F1）：coraza-caddy v2.5.0 的 computePoolKey()
// = hash(directives + include + crs flag)——directives 只含固定 Include 路径，
// CRS 文件替换/手动改 zz-user-overrides.conf 后池键不变，新 Caddy 配置 Provision
// 复用旧 WAF（LoadOrNew refcount++），旧规则静默继续生效直到进程重启。在
// directives 里嵌内容指纹（CRS 版本 + overrides mtime+size，每次配置生成仅
// 2 个 stat + 1 个 db 查询，远低于 tarGzDirSum 的整树遍历成本），指纹变 →
// 池键变 → 新 WAF 真正编译新规则。Coraza 把 '#' 当注释行，不影响语义。
func crsPoolFingerprint() string {
	var version string
	if db.DB == nil {
		version = "unknown"
	} else if err := db.DB.QueryRow("SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1").Scan(&version); err != nil {
		version = "unknown"
	}
	var mtime, size int64
	if st, err := os.Stat(filepath.Join(crsDirectivesDir, "zz-user-overrides.conf")); err == nil {
		mtime, size = st.ModTime().UnixNano(), st.Size()
	}
	return fmt.Sprintf("%s-%d-%d", version, mtime, size)
}

func BuildCorazaDirectives(p *models.SecurityPolicy, store caddyConfigStore) string {
	var sb strings.Builder
	// R72 三十次 F1：嵌 coraza 池键指纹（见 crsPoolFingerprint）——CRS 文件
	// 替换/手动改 overrides 后池键必须变化，否则新 Caddy 配置复用旧 WAF
	//（旧规则静默继续生效）。
	sb.WriteString(fmt.Sprintf("# crs-pool=%s\n", crsPoolFingerprint()))
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)

	// IP-level control (ACL / trust list / legacy bypass & blacklist) runs
	// independently of the WAF mode so that "关闭 WAF" never disables IP control.
	emitIPControl := len(ipWL) > 0 || len(ipBL) > 0 || (p.IPACLEnabled && len(ipACLList) > 0)
	customRules := resolvePolicyCustomRules(p.CustomRules, store)
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
		// 例外（R65 B-S5）：body 目标的自定义拦截规则发射为 phase:2（REQUEST_BODY
		// 仅 phase:2 可读），而 DetectionOnly ctl 是事务级指令持续到 phase:2——
		// 该类规则在检测模式下仅记录不阻断（见 emitCustomRules 相位说明）。
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
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off\"\n", strings.Join(ipACLList, ",")))
		bypassEmitted = true
	}
	if len(ipWL) > 0 {
		trustID := 3
		if bypassEmitted {
			trustID = 5
		}
		// ctl:auditEngine=Off 同步关闭审计引擎——规则引擎关闭后 SecAuditEngine
		// 仍会记录该事务到 audit.log（审计引擎独立于规则引擎），摄入管线拾取
		// 后误产信任 IP 的检测事件。两 ctl 并用才能让信任 IP 完全静默。
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off\"\n", strings.Join(ipWL, ","), trustID))
	}
	if p.IPACLEnabled && len(ipACLList) > 0 {
		if p.IPACLMode == "allow" {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END\"\n", strings.Join(ipACLList, ",")))
		} else if p.IPACLMode == "deny" {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END\"\n", strings.Join(ipACLList, ",")))
		}
	}
	if len(ipBL) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:4,phase:1,deny,status:403,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END\"\n", strings.Join(ipBL, ",")))
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
				// R47 B-#1：历史遗留行可能含首尾空白（旧校验曾放行），trim 后拼接，
				// 保证 glob 恒为 REQUEST-9<code>-*.conf 的合法形态（镜像下方排除项的 trim）。
				g = strings.TrimSpace(g)
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
			if ruleID == "" {
				continue
			}
			mapped := crsFilenameToRuleIDRange(ruleID)
			// R60 B-新1：SecRuleRemoveById 发射前形态门。历史行/API/备份可携带
			// 过校验门但 coraza 语义非法的条目（"ABCDEF"、"942100-abc"、
			// "REQUEST-942.conf"）——coraza directiveSecRuleRemoveByID 对
			// 非「纯数字或数字-数字」形态 Atoi 失败即 return err → 整个
			// directives 串编译失败 → Caddy /load 400，含启动初始加载在内
			// 的全部配置加载失败（配置自锁）。合法形态之外跳过该条目并留痕
			// （custom rules customRuleEmissionIssue 同哲学：发射侧防御，
			// 校验漏洞不升级为全局限摆）。越过界的合法 range（"1-999999"）
			// 会静默删除 IP ACL(2-5)/自定义(10000+)/全部 CRS 规则——上限
			// 999999 一并钳制。
			if !validSecRuleRemoveTarget(mapped) {
				// R61 B-R61-02：用分级日志（Logf warn）而非裸 log.Printf——后者无
				// WARN 前缀，应用日志级别调至 warn/error 时会被过滤出文件日志。
				Logf("warn", "跳过非法 SecRuleRemoveById 条目 %q（策略 %q）：非数字/区间形态或区间越界，coraza 会拒绝编译", ruleID, p.Name)
				continue
			}
			sb.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", mapped))
		}
	}

	// skipAfter 终点标记——IP ACL deny / 自定义 block 规则的 skipAfter
	// 引用此标记跳过后续全部规则（DetectionOnly/CRS），deny 在阶段末执行。
	// 标记必须无条件发射（即使无规则引用），否则 skipAfter 引用不存在标记
	// 会导致 coraza 编译失败。
	sb.WriteString("SecMarker SECURITY_RULES_END\n")

	return sb.String()
}

// customRuleTargets / customRuleOperators 是自定义规则条件允许的目标与运算符
// 映射；emitCustomRules 与校验函数共用同一份，避免两处硬编码漂移。
var (
	customRuleTargets   = map[string]string{"uri": "REQUEST_URI", "args": "ARGS", "body": "REQUEST_BODY", "headers": "REQUEST_HEADERS", "user_agent": "REQUEST_HEADERS:User-Agent"}
	customRuleOperators = map[string]string{"contains": "@contains", "regex": "@rx", "equals": "@pm", "starts_with": "@beginsWith"}
	// customRuleValidScores / customRuleValidActions 是内嵌自定义规则允许的分值与
	// 动作集合，与 handlers 侧 validateSecurityCustomRule 的独立规则口径一致。
	customRuleValidScores  = map[int]bool{1: true, 3: true, 5: true, 10: true, 20: true}
	customRuleValidActions = map[string]bool{"block": true, "log": true, "pass": true}
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
// mirroring how IP control behaves（例外：body 目标规则发射为 phase:2，检测模式
// 的 DetectionOnly 事务级切换对其生效，仅记录不阻断——R65 B-S5）。
// 动作语义与前端编辑器一致：拦截=命中即阻断；
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
	// 旧版内嵌规则可能没有 id（0）：全部发射 id:10000 会在同一份 coraza 配置中
	// 产生重复 SecRule id，按序分配唯一合成 id（1000000+序号，避开 CRS 的
	// 100000-999999 保留段）。synthetic 只在无 id 规则上递增，保证彼此唯一。
	synthetic := 0
	for _, cr := range customRules {
		if !cr.Enabled {
			continue
		}
		// 发射侧防御：单条含尾部反斜杠或空条件的规则只跳过自身并告警，绝不让整份
		// 配置生成失败——一条坏规则不得拖垮所有站点；存量脏规则与集群同步绕过的规则
		// 均在此兜底。
		if issue := customRuleEmissionIssue(cr); issue != "" {
			// R62 B-NEW-4：分级日志——裸 log.Printf 无级别前缀，日志级别调至 warn/error
			// 时会被过滤出文件日志（与 R61 B-R61-02 修复口径一致）。
			Logf("warn", "自定义规则 %d(%s) %s，已跳过发射，请修正或禁用", cr.ID, cr.Name, issue)
			continue
		}
		emitID := cr.ID + 10000
		if cr.ID == 0 {
			synthetic++
			emitID = 1000000 + synthetic
		}
		safeName := strings.ReplaceAll(cr.Name, "'", "")
		// CRS v4 blocking evaluation reads tx.inbound_anomaly_score_pl1..4 —
		// never the legacy tx.anomaly_score.
		// 默认动作 pass（放行计分）：记录事件并向异常分累加。
		scoreVar := fmt.Sprintf("setvar:tx.inbound_anomaly_score_pl1=+%d", cr.Score)
		action := fmt.Sprintf("pass,log,%s,msg:'自定义规则 %s 命中'", scoreVar, safeName)
		if cr.Action == "block" {
			// 统一所有拦截走 coraza 默认 403 → 策略 errors.routes → 拦截页面配置的状态码
			action = fmt.Sprintf("deny,log,%s,msg:'自定义规则 %s 命中',skipAfter:SECURITY_RULES_END", scoreVar, safeName)
		} else if cr.Action == "log" {
			// 仅记录：不累加异常分，避免在拦截/检测模式下因该规则误伤。
			action = fmt.Sprintf("pass,log,msg:'自定义规则 %s 命中'", safeName)
		}
		// N15-F1：多条件链式规则的 setvar 绑定到链条末条。coraza v3 在单条规则
		// 算子命中时立即执行其非破坏性动作（internal/corazawaf/rule.go matchVariable
		// 「We run non-disruptive actions even if there is no chain match」）——
		// 起始条命中而后续条件未命中时链条整体不匹配，但起始条上的 setvar 已把
		// 异常分累加进事务（幽灵异常分 → 可能触发 949 误拦）。末条命中即整条链
		// 命中，分数只在链整体匹配时累加；deny/skipAfter 是破坏性/流控动作，
		// coraza 仅在整条链匹配后才执行，留在起始条无泄漏。单条件规则起始条即
		// 末条，发射形状不变。
		starterAction := action
		tailVar := ""
		if len(cr.Conditions) > 1 && cr.Action != "log" {
			starterAction = strings.Replace(action, scoreVar+",", "", 1)
			tailVar = "," + scoreVar
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
					actions = fmt.Sprintf("id:%d,phase:%d,%s", emitID, phase, starterAction)
				} else {
					actions = fmt.Sprintf("phase:%d", phase)
				}
				if idx == len(cr.Conditions)-1 {
					actions += tailVar
				}
				if idx < len(cr.Conditions)-1 {
					actions += ",chain"
				}
				sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"%s\"\n", target, op, escapeCorazaPattern(cond.Pattern), actions))
			}
		} else {
			target := customRuleTargets[cr.Target]
			op := customRuleOperators[cr.Operator]
			sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"id:%d,phase:%d,%s\"\n", target, op, escapeCorazaPattern(cr.Pattern), emitID, phase, action))
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
	for _, cr := range resolvePolicyCustomRules(raw, nil) {
		if cr.Enabled {
			count++
		}
	}
	return count
}

// buildWafHandlerWithPolicy returns the coraza WAF handler for the given policy,
// or nil when the policy is nil or emits no directives. Callers pass a policy
// from the batch-preloaded context so generation stays on the store/tx channel.
// store 与策略预载同源（A-I1）：自定义规则读取必须沿同一 store——tx 内生成
// 时 db.DB 看不到未提交的 security_custom_rules 行，会静默丢失 WAF 规则。
// store=nil 时由 resolvePolicyCustomRules 回退 db.DB（非批量路径保持现状）。
func buildWafHandlerWithPolicy(ruleCaddyID string, policy *models.SecurityPolicy, store caddyConfigStore) map[string]interface{} {
	if policy == nil {
		return nil
	}
	directives := BuildCorazaDirectives(policy, store)
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
// store 必须与策略预载同源（A-I1）：v2 导入事务内重插的 security_custom_rules
// 在已提交 db.DB 视角中不存在，走 db.DB 会让新规则在渲染期静默丢失（WAF 削弱）。
// store=nil 回退 db.DB，保留 handlers/summary 等非事务调用点现状。
// policyCustomRuleChunkSize bounds each IN (...) placeholder batch:
// SQLite caps bound variables at 32766, and an oversized IN previously
// failed the whole query so custom rules were silently lost (WAF weakened).
var policyCustomRuleChunkSize = 500

func resolvePolicyCustomRules(raw json.RawMessage, store caddyConfigStore) []models.CustomRule {
	if len(raw) == 0 {
		return nil
	}
	var ids []int
	if err := json.Unmarshal(raw, &ids); err == nil {
		if len(ids) == 0 {
			return nil
		}
		// A-I1：store=nil 时回退全局 db.DB——非事务调用点（summary、handlers）
		// 语义与修复前一致；tx 调用点必须显式传 tx，否则会读到已提交旧快照。
		effective := store
		if effective == nil {
			effective = db.DB
		}
		if effective == nil {
			return nil
		}
		var rules []models.CustomRule
		queriedIDs := make(map[int]struct{}, len(ids))
		for start := 0; start < len(ids); start += policyCustomRuleChunkSize {
			end := start + policyCustomRuleChunkSize
			if end > len(ids) {
				end = len(ids)
			}
			chunk := ids[start:end]
			placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
			args := make([]interface{}, len(chunk))
			for i, id := range chunk {
				args[i] = id
			}
			rows, err := effective.Query("SELECT id, name, COALESCE(conditions,'[]'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1) FROM security_custom_rules WHERE id IN ("+placeholders+")", args...)
			if err != nil {
				// Round 34 G: 单块失败只丢该块并留痕，其余块照常解析；
				// 此前整查询失败静默返回 nil，WAF 规则全部丢失且无日志。
				Logf("warn", "解析策略自定义规则分块查询失败（id 段 %d-%d）: %v", chunk[0], chunk[len(chunk)-1], err)
				continue
			}
			for _, id := range chunk {
				queriedIDs[id] = struct{}{}
			}
			for rows.Next() {
				var cr models.CustomRule
				var conditionsJSON string
				if err := rows.Scan(&cr.ID, &cr.Name, &conditionsJSON, &cr.Action, &cr.Score, &cr.Enabled); err != nil {
					continue
				}
				json.Unmarshal([]byte(conditionsJSON), &cr.Conditions)
				rules = append(rules, cr)
			}
			rows.Close()
		}
		// 悬空引用（规则已被删除）不改变解析行为，仅记录日志便于排查；
		// 只统计查询成功分块内未找到的 id——查询失败的分块已单独留痕，
		// 其 id 从未读回，计入悬空会把「查询失败」误报为「规则已删除」。
		// R65 B-S6：queried 按去重后的 id 计数——custom_rules 数组含重复 id 时
		// IN 只返回一行，不去重会把「重复引用」误报为「N-1 个不存在」。
		if dropped := len(queriedIDs) - len(rules); dropped > 0 {
			Logf("warn", "策略引用的自定义规则有 %d 个不存在，已跳过", dropped)
		}
		return rules
	}
	var embedded []models.CustomRule
	if err := json.Unmarshal(raw, &embedded); err == nil {
		return embedded
	}
	return nil
}

// validSecRuleRemoveTarget 判定 SecRuleRemoveById 目标是否为 coraza 可编译
// 且不越界的形态：纯数字，或 a-b 区间。边界依据：本地规则 ID 空间为 IP ACL
// 2-5 与自定义规则 10000+，CRS 规则 ID 恒为 9xxxxx（六位、首位 9）——
// 下界 <900000 或上界 >999999 的区间会静默删除本地/自定义规则或全部 CRS
// 规则，与"合法但删除一切"的越界形态同等拒绝。
func validSecRuleRemoveTarget(s string) bool {
	if n, err := strconv.Atoi(s); err == nil {
		return n >= 900000 && n <= 999999
	}
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return false
	}
	loN, loErr := strconv.Atoi(lo)
	hiN, hiErr := strconv.Atoi(hi)
	return loErr == nil && hiErr == nil && loN >= 900000 && hiN >= loN && hiN <= 999999
}

// CRSExcludedEntryEffective 判定排除条目是否会被发射端实际发射（R72 二十六次
// W3-6）：与发射链同款门——文件名先经 crsFilenameToRuleIDRange 映射为 ID 区间，
// 再过 validSecRuleRemoveTarget 形态/边界门。保存侧复用本门可在保存时拒绝
// 「保存 200、发射静默跳过」的条目（如字母后缀 "942100L"），同时不误伤合法的
// CRS 文件名形态（"REQUEST-942-*.conf" → 942000-942999）。
func CRSExcludedEntryEffective(entry string) bool {
	return validSecRuleRemoveTarget(crsFilenameToRuleIDRange(strings.TrimSpace(entry)))
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

// ValidateGeoIPCountries 校验 geoip_countries 载荷：必须是 JSON 数组且条目非空；
// ip2region 已加载（live 或缓存）时条目必须属于已知省份或"海外"，未知省份在
// 发射端永不匹配，会静默削弱地域控制。ip2region 未加载且无缓存时同样拒绝未知
// 省份（fail-closed）：启动期放行任意省份会让 deny 模式的地域拦截静默失效，
// 提示未加载而非放行。
func ValidateGeoIPCountries(raw string) error {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("geoip_countries 必须是 JSON 数组")
	}
	// R72 二十七次 N5（裁决）：IP 库未装载时拒绝启用任何地域条目（含海外——
	// 海外拦截同样依赖 live searcher 设置占位变量，缺库时 CEL 全部恒假、
	// 地域拦截静默零强制）。用户语义：缺库 = IP 相关规则不可启用，待自动/
	// 手动更新 IP 库后恢复；「IP 库」卡片的「未安装」标签提供常态可见性。
	if len(entries) > 0 && len(GetIP2RegionProvinces()) <= 1 {
		return fmt.Errorf("IP 库未安装或未加载：地域相关规则不可启用，请先在「安全规则」页更新 IP 库后重试")
	}
	// R57 B-#1：loaded 判据必须取 live searcher 而非缓存兜底列表——xdb 损坏/
	// 带外替换后 live 已死但省份缓存仍在，用缓存判 loaded 会放行 deny+省份
	// 策略，而发射端占位变量从未设置（CEL 恒假）→ 地域拦截静默零强制。缓存
	// 兜底仅服务于 UI 列表（GetIP2RegionRegions），校验侧以 live 为准。
	liveProvinces := GetIP2RegionProvinces()
	provincesLoaded := len(liveProvinces) > 1
	// R72 三十次 F2（第 40 轮审计核心发现，主线亲证 tree=35 sampled=28 missing=
	// [山西/广西/海南/澳门/西藏/青海]）：known 集必须从全扫描树构建而非 336 点
	// 采样子集（GetIP2RegionProvinceList）——采样网格（42 个 /8 块 × 第二字节
	// {0,32,64,96,128,160,192,224}）漏掉了不与网格相交的省，而 UI
	//（GetIP2RegionRegions 全扫描树）提供全部省份 → 用户能选但保存被「未知
	// 省份」400 拒绝（约 1/6 省份可用性受损）。校验器 known 集改用全扫描树
	// 省份（regionTreeFromXDB 的 Provinces，已含「海外」），与 UI 严格一致。
	known := make(map[string]bool, 36)
	knownCities := map[string]map[string]bool{}
	// 树为 nil（无 xdb 且无缓存兜底）时 known 仅含「海外」——非海外条目由
	// N5 门（live 未装载）先行拒绝，不会走到这里；空条目则允许通过。
	// N+13 H2-F1：单次取树复用 known 集与城市集两处——原实现两次背靠背
	// GetIP2RegionRegionTree 各做一次 xdb 全量扫描（~220ms×2）；两次调用间
	// 无任何状态变更（仅纯 map 构建），单次快照语义等价。
	tree := GetIP2RegionRegionTree()
	if tree != nil {
		for _, p := range tree.Provinces {
			known[p] = true
		}
		// R72 二十三次：城市树供「省/市」条目校验（市必须在省的城市集内——防
		// 拼写错误生成 CEL 恒假死条目）。
		for prov, cities := range tree.Cities {
			set := make(map[string]bool, len(cities))
			for _, city := range cities {
				set[city] = true
			}
			knownCities[prov] = set
		}
	}
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return fmt.Errorf("geoip_countries 不能包含空条目")
		}
		if trimmed == "海外" {
			continue
		}
		if !provincesLoaded {
			// live searcher 未加载：即便缓存里有该省份也拒绝——发射端
			// 占位变量从未设置，放行即为静默零强制（fail-closed）。
			return fmt.Errorf("ip2region 未加载，暂无法使用非海外省份（geoip_countries 包含 %q）", trimmed)
		}
		// 「省/市」双形态：省须已知且市须在省的城市集内。
		if province, city, found := strings.Cut(trimmed, "/"); found {
			if !known[province] {
				return fmt.Errorf("geoip_countries 包含未知省份：%q", province)
			}
			if knownCities[province] == nil || !knownCities[province][city] {
				return fmt.Errorf("geoip_countries 条目 %q 的城市不在该省城市列表中", trimmed)
			}
			continue
		}
		if !known[trimmed] {
			return fmt.Errorf("geoip_countries 包含未知省份：%q", trimmed)
		}
	}
	return nil
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
		// 内嵌形状的分值与动作直接进入发射动作串：score=-5 会生成
		// setvar:...=+-5 被 coraza 拒绝，未知 action 会被发射端静默按 pass 处理；
		// 0/空串视为旧版内嵌数据未提供，发射端按 pass/+0 处理无破坏性，保持放行。
		if r.Score != 0 && !customRuleValidScores[r.Score] {
			return fmt.Errorf("自定义规则 #%d 的异常分值无效：%d（可选：1/3/5/10/20）", i+1, r.Score)
		}
		if r.Action != "" && !customRuleValidActions[r.Action] {
			return fmt.Errorf("自定义规则 #%d 的动作无效：%q（可选：block、log、pass）", i+1, r.Action)
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
