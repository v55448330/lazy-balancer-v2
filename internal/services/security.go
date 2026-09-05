package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	err := db.DB.QueryRow(`SELECT id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,5), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_whitelist,'[]'), COALESCE(ip_blacklist,'[]'),
		COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0), COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'), COALESCE(block_page_id,0), COALESCE(block_status_code,0), enabled, COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(waf_check_response,0), COALESCE(log_request_body,0), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]')
		FROM security_policies WHERE id=? AND enabled=1`, policyID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &p.IPWhitelistEnabled, &ipWhitelist, &ipBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse, &p.LogRequestBody, &p.IPACLListRefs, &p.IPWhitelistRefs)
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
	policy := scanSecurityPolicyByID(policyID)
	if policy == nil {
		return nil
	}
	// 引用的 IP 列表在此解析（单策略一次批量查询），发射端经 Merged* 消费。
	resolvePolicyIPListRefs([]*models.SecurityPolicy{policy}, nil)
	return policy
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
	// 批次引用解析：跨全部已加载策略收集列表 id，一次批量查询（预算：与策略数
	// 无关的常数一次），合并集附加到各策略的 Merged* 字段供发射端消费。
	resolvePolicyIPListRefs(policies, nil)
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

// PolicyHasGeoIP reports whether geoip region control is active: mode must not
// be "off" (the persisted off-state; countries are retained, not cleared) and
// the country list must be non-empty. Gates caddygeoip handler insertion.
func PolicyHasGeoIP(p *models.SecurityPolicy) bool {
	return p.GeoIPMode != "off" && len(geoipCountries(p)) > 0
}

// crsPoolFingerprint（R72 三十次 F1）：coraza-caddy v2.5.0 的 computePoolKey()
// = hash(directives + include + crs flag)——directives 只含固定 Include 路径，
// CRS 文件替换/手动改 zz-user-overrides.conf 后池键不变，新 Caddy 配置 Provision
// 复用旧 WAF（LoadOrNew refcount++），旧规则静默继续生效直到进程重启。在
// directives 里嵌内容指纹（CRS 版本 + overrides mtime+size，每次配置生成仅
// 2 个 stat + 1 个 db 查询，远低于 tarGzDirSum 的整树遍历成本），指纹变 →
// 池键变 → 新 WAF 真正编译新规则。Coraza 把 '#' 当注释行，不影响语义。
// crsPoolFingerprintForChain 是批量链构建入口的一次性指纹取值点（审计 B5-F2）。
func crsPoolFingerprintForChain() string {
	return crsPoolFingerprint()
}

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

// prefetchedCRSFingerprint 可选参数：批量生成方按链计算一次并透传，避免
// 逐 (规则×策略) 对重复执行 DB 查询+stat（审计 B5-F2）；空串回退自算。
func BuildCorazaDirectives(p *models.SecurityPolicy, store caddyConfigStore, prefetchedCRSFingerprint ...string) string {
	var sb strings.Builder
	// R72 三十次 F1：嵌 coraza 池键指纹（见 crsPoolFingerprint）——CRS 文件
	// 替换/手动改 overrides 后池键必须变化，否则新 Caddy 配置复用旧 WAF
	//（旧规则静默继续生效）。
	crsFp := ""
	if len(prefetchedCRSFingerprint) > 0 {
		crsFp = prefetchedCRSFingerprint[0]
	}
	if crsFp == "" {
		crsFp = crsPoolFingerprint()
	}
	sb.WriteString(fmt.Sprintf("# crs-pool=%s\n", crsFp))
	// Merged* 为策略加载路径附加的「inline ∪ 引用 IP 列表条目」合并集；未经
	// 解析的策略（直接构造/非生成路径）由 helper 回退 inline-only。
	ipWL := mergedWhitelist(p)
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	ipACLList := mergedACLList(p)

	// IP-level control (ACL / trust list / legacy bypass & blacklist) runs
	// independently of the WAF mode so that "关闭 WAF" never disables IP control.
	// GeoIP 地域拦截同阵营（v2.2.0 改走 coraza 后必须有引擎才能评估）。
	// 信任名单三态门（对齐 ip_acl_enabled/geoip_mode）：关闭保留名单零发射。
	emitIPControl := (p.IPWhitelistEnabled && len(ipWL) > 0) || len(ipBL) > 0 || (p.IPACLEnabled && len(ipACLList) > 0)
	// mode=off 是关闭态（名单保留不清单）：不为已关闭的区域控制发射空转 coraza handler
	geoipActive := p.GeoIPMode != "off" && len(geoipCountries(p)) > 0
	customRules := policyCustomRulesCached(p, store)
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
	case emitIPControl || hasCustomRules || geoipActive:
		// WAF (CRS) off, but IP control / custom rules / GeoIP still need the engine.
		sb.WriteString("SecRuleEngine On\n")
	default:
		return ""
	}
	sb.WriteString("SecRequestBodyAccess On\n")
	if p.WAFCheckResponse {
		sb.WriteString("SecResponseBodyAccess On\n")
		// SecResponseBodyMimeType 必须显式发射：coraza 的 ResponseBodyMimeTypes
		// 零值是空集（不像 ModSecurity 有 text/plain|html|xml 默认），不发射则
		// IsResponseBodyProcessable 恒 false、响应体永不进规则——响应检查空转。
		// 在 ModSecurity 默认三类之上补 application/json（API 错误泄漏的现代形态）。
		sb.WriteString("SecResponseBodyMimeType text/plain text/html text/xml application/json\n")
	} else {
		sb.WriteString("SecResponseBodyAccess Off\n")
	}
	// F2（v2.2.3）：策略级「记录请求体」开关——开启时审计 parts 加 C，coraza
	// 在事件事务（RelevantOnly 门控）输出 transaction.request.body，摄入落库
	// request_body（64KB 截断）。body access 恒 On 不变，仅审计输出面扩展。
	auditParts := "ABIJDEFHKZ"
	if p.LogRequestBody {
		auditParts = "ABCIJDEFHKZ"
	}
	sb.WriteString(fmt.Sprintf("SecAuditEngine RelevantOnly\nSecAuditLog /app/waf/audit/audit.log\nSecAuditLogFormat JSON\nSecAuditLogParts %s\n", auditParts))

	// SecRule id map: 2 = ACL allow/deny, 3 = bypass-mode (legacy), 4 = legacy
	// blacklist, 5 = trust list, 8 = GeoIP 地域拦截. The trust list keeps the
	// historical id:3 unless a bypass-mode rule already owns it. ctl:ruleEngine=Off
	// short-circuits are emitted first so bypassed and trusted clients never reach
	// the ACL denies（信任/免检测名单因此也跳过 GeoIP 规则——「跳过检查」语义
	// 随 v2.2.0 GeoIP 并入 coraza 一并覆盖地域拦截）.
	bypassEmitted := false
	if p.IPACLEnabled && p.IPACLMode == "bypass" && len(ipACLList) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off\"\n", strings.Join(ipACLList, ",")))
		bypassEmitted = true
	}
	if p.IPWhitelistEnabled && len(ipWL) > 0 {
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

	// GeoIP 区域拦截（v2.2.0 改走 coraza：被拦请求产生 audit.log → 安全事件
	// 管线 → 总览/事件日志可统计。此前走 Caddy 原生路由（CEL+static_response）
	// 完全绕过 coraza，事件盲区）。caddygeoip pass route 先执行并剥离客户端
	// 伪造头、设置 X-GeoIP-Loc（海外/省/省-市 规范键），coraza 在 phase:1
	// 读取该头匹配策略 geoip_countries 列表（geoipLocOperator 编译）。
	// 链首 REMOTE_ADDR !@ipMatch 内网段保留「内网放行」语义（geoipPrivateRanges
	// 与既有拦截链同款）。deny 不带 status：coraza 默认 403 + "interruption
	// triggered" → 策略 errors.routes → 拦截页按配置状态码渲染（与自定义规则
	// 拦截统一口径）；无拦截页时回落 Caddy 默认 403 页。检测/关闭模式下仍强制
	// 生效（规则先于 DetectionOnly 切换发出，mode=off 由上方 switch 门保引擎）。
	// geoip_mode='off' 是区域控制关闭态（名单保留不清单），与 PolicyHasGeoIP
	// 同门：开关关闭即零发射。
	if geoCountries := geoipCountries(p); p.GeoIPMode != "off" && len(geoCountries) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:8,phase:1,deny,log,msg:'GeoIP 区域拦截',skipAfter:SECURITY_RULES_END,chain\"\n", strings.Join(geoipPrivateRanges, ",")))
		sb.WriteString(fmt.Sprintf(" SecRule REQUEST_HEADERS:X-GeoIP-Loc \"%s\" \"t:none\"\n", escapeCorazaPattern(geoipLocOperator(geoCountries, p.GeoIPMode == "allow"))))
	}

	emitCustomRules(&sb, customRules)

	if p.Mode == "detection" {
		sb.WriteString("SecAction \"id:6,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly\"\n")
	}

	if p.Mode == "blocking" || p.Mode == "detection" {
		var groups []string
		json.Unmarshal(p.CRSRuleGroups, &groups)
		// M3（读取面兜底）：存量/带外数据（写入面剥离生效前落库、集群同步旧快照）
		// 可能仍含基础设施组号——按数组原位发射 REQUEST-901/949/959-*.conf glob
		// 会破坏 901 最前/949、959 殿后的强制序（偏执级守卫空转、阻断静默漏拦）。
		// 与写入面 validateAndNormalizeCRSField 同口径剥离；剥离后为空落入全量
		// glob 分支（同写入面「[]」=全量语义）。
		if kept, stripped := stripInfraCRSGroupCodes(groups); len(stripped) > 0 {
			Logf("debug", "策略 %q 的 crs_rule_groups 含基础设施组号 %v，发射时已剥离（由强制 Include 按正确次序补齐）", p.Name, stripped)
			groups = kept
		}
		// M4：索引取值链级惰性一次——下方三个消费点（crsCoveredInfraGroupCodes/
		// emitCRSRuleGroupSelection/emitScopedCRSExclusions）各自直调 GetCRSRuleIndex
		// 会各付一次缓存键计算（ReadDir+全量 stat），全量生成时数百次纯浪费。
		chainIndex := lazyCRSRuleIndex()
		// 审计 V-CRITICAL-1（第五轮）：SecRuleRemoveById（配置期删除）与
		// ctl:ruleRemoveById（运行时跳过）需要**相反**的发射顺序——
		//   配置期：必须在 Include 之后（coraza 单遍解析，DeleteByID 只删已注册规则，
		//           放在 Include 前是空集 no-op——emitCRSRuleGroupSelection 的补删
		//           即正确先例：先 Include 父文件再逐 ID RemoveById）
		//   运行时：必须在 Include 之前（phase:1 按插入序执行，ctl 规则先于被禁
		//           规则才能在其求值前标记 tx.ruleRemoveByID——coraza ctl.go:85）
		// 第四轮 U1-F1 把整个块搬到 Include 前修好了 ctl 却弄坏了配置期。
		// 作用域限定（ip/list）条目收集后统一发射：列表引用需单批解析，合并去重。
		var scoped []CRSExcludedEntry
		var scopeAllTargets []string
		for _, entry := range ParseCRSExcludedRules(string(p.CRSExcludedRules)) {
			// F0 存量兜底：命中 901 初始化组的排除一律跳过——初始化组已由下方
			// 去重强制包含，排除若放行会在 Include 后（scope=all）或运行时
			//（scoped ctl）将其删除，守卫按 0 处理、策略空转。写入面对新提交
			// 已 400 硬拒（CRSExclusionTargetRemovesInit），此处拦存量老数据。
			if CRSExclusionTargetRemovesInit(entry.Target) {
				Logf("warn", "跳过命中初始化组的 CRS 排除条目 %q（策略 %q）：初始化规则为系统强制加载，排除不生效", entry.Target, p.Name)
				continue
			}
			if entry.Scope == "ip" || entry.Scope == "list" {
				scoped = append(scoped, entry)
				continue
			}
			ruleID := strings.TrimSpace(entry.Target)
			if ruleID == "" {
				continue
			}
			mapped := crsFilenameToRuleIDRange(ruleID)
			if IsCRSGroupCode(ruleID) {
				mapped = "9" + ruleID + "000-9" + ruleID + "999"
			}
			if !validSecRuleRemoveTarget(mapped) {
				Logf("warn", "跳过非法 SecRuleRemoveById 条目 %q（策略 %q）：非数字/区间形态或区间越界，coraza 会拒绝编译", ruleID, p.Name)
				continue
			}
			scopeAllTargets = append(scopeAllTargets, mapped)
		}
		// 运行时 ctl 规则：Include 之前（先于被禁规则插入 phase:1 序列）
		if len(scoped) > 0 {
			emitScopedCRSExclusions(&sb, p, scoped, store, chainIndex)
		}
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
			// 基础设施组强制包含（去重，F0）：901 提供偏执级默认值与评分初始化——
			// 缺失时偏执级守卫把未初始化变量按 0 处理、整段 skipAfter，策略空转
			// 且 980099 每事务打 ERROR；949/959 是评分阈值拦截的唯一执行者——缺失
			// 时拦截模式静默退化为仅记录。两者均属静默失效，不开放用户配置
			//（写入层剥离 + 交互层隐藏，此处为最终兜底）。去重判定覆盖两位组号与
			// 6 位 ID 的父文件，避免重复注册同规则 ID 触发 coraza 编译失败。
			// 序：901 必须先于被选组注册（phase:1 默认值），949/959 必须在检测
			// 规则之后（插入序=执行序）。
			// 存在性门（CRS 更新风险排查）：coraza 对缺失的精确路径 Include 是致命
			// 错误（seclang parser.go ReadFile → 配置加载失败、全站停摆）——CRS 更新
			// 若移除/改名基础设施文件，跳过+告警也不允许拖垮配置加载（glob 形态
			// 空匹配本就仅 warn，无需门）。
			emitInfraInclude := func(name string) {
				full := filepath.Join(crsDirectivesDir, "rules", name)
				if _, err := os.Stat(full); err == nil {
					sb.WriteString("Include /app/waf/crs/rules/" + name + "\n")
				} else {
					Logf("warn", "CRS 基础设施规则文件缺失，跳过强制 Include（%s，策略 %q）", name, p.Name)
				}
			}
			covered := crsCoveredInfraGroupCodes(chainIndex, groups)
			if _, ok := covered["01"]; !ok {
				emitInfraInclude("REQUEST-901-INITIALIZATION.conf")
			}
			emitCRSRuleGroupSelection(&sb, p, groups, chainIndex)
			if _, ok := covered["49"]; !ok {
				emitInfraInclude("REQUEST-949-BLOCKING-EVALUATION.conf")
			}
			if p.WAFCheckResponse {
				if _, ok := covered["59"]; !ok {
					emitInfraInclude("RESPONSE-959-BLOCKING-EVALUATION.conf")
				}
			}
		}
		// 配置期 SecRuleRemoveById：Include 之后（此时 CRS 规则已注册，
		// DeleteByID 能命中；发射前的形态门注释见 scopeAllTargets 收集段）
		for _, mapped := range scopeAllTargets {
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

// geoipLocOverseas 是 X-GeoIP-Loc 的海外哨兵值：caddygeoip 对国家列非「中国」
// （含空/0/海外国名，fail-closed）的客户端发射此值。
const geoipLocOverseas = "海外"

// geoipLocOperator 把策略 geoip_countries 条目编译为 REQUEST_HEADERS:X-GeoIP-Loc
// 的 coraza 匹配算子。锚定正则（^(?:...)$）做全值匹配：X-GeoIP-Loc 的空串形态
// （国内段省份不可解析）恒不命中（deny 模式不误伤）；allow 模式取反后空串反向
// 命中 → 拦截（fail-closed，与既有 CEL 语义逐案等价）。条目形态与
// caddygeoip 发射的 X-GeoIP-Loc 同构：海外 → 字面「海外」；省 → 整省，附加
// (?:/.*)? 使省内城市段（省/市 形态）同样命中；省/市 → 精确省市联值。
// 条目经 QuoteMeta 转义——集群同步/历史行可携带绕过校验的特殊字符，未转义会
// 注入正则元字符（ReDoS/越权匹配）。
func geoipLocOperator(countries []string, allowMode bool) string {
	alts := make([]string, 0, len(countries))
	for _, entry := range countries {
		quoted := regexp.QuoteMeta(entry)
		if entry == geoipLocOverseas || strings.Contains(entry, "/") {
			alts = append(alts, quoted)
			continue
		}
		alts = append(alts, quoted+"(?:/.*)?")
	}
	op := "@rx ^(?:" + strings.Join(alts, "|") + ")$"
	if allowMode {
		return "!" + op
	}
	return op
}

// customRuleTargets / customRuleOperators 是自定义规则条件允许的目标与运算符
// 映射；emitCustomRules 与校验函数共用同一份，避免两处硬编码漂移。
// equals → @streq（审计 H1）：@pm 是短语匹配（大小写不敏感+空格分词），
// 与 UI「等于」承诺不符，收紧为大小写敏感精确匹配，存量规则行为随之收紧。
var (
	customRuleTargets   = map[string]string{"uri": "REQUEST_URI", "args": "ARGS", "body": "REQUEST_BODY", "headers": "REQUEST_HEADERS", "user_agent": "REQUEST_HEADERS:User-Agent"}
	customRuleOperators = map[string]string{"contains": "@contains", "regex": "@rx", "equals": "@streq", "starts_with": "@beginsWith"}
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
// ip_acl_enabled is on. Referenced IP lists count the same as inline entries
// (refs-only policies still advertise IP control)——仅解析 refs JSON 本身，
// 无需加载数据库（摘要/绑定路径与生成路径同判定）。
func SecurityPolicyHasIPControl(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	if p.IPWhitelistEnabled && len(ipWL) > 0 {
		return true
	}
	if p.IPWhitelistEnabled && ipListRefsNonEmpty(p.IPWhitelistRefs) {
		return true
	}
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	if len(ipBL) > 0 {
		return true
	}
	return p.IPACLEnabled && (len(ipACLList) > 0 || ipListRefsNonEmpty(p.IPACLListRefs))
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
func buildWafHandlerWithPolicy(ruleCaddyID string, policy *models.SecurityPolicy, store caddyConfigStore, crsFp string) map[string]interface{} {
	if policy == nil {
		return nil
	}
	directives := BuildCorazaDirectives(policy, store, crsFp)
	if directives == "" {
		return nil
	}
	return map[string]interface{}{
		"handler":    "waf",
		"directives": directives,
	}
}

// ipPrecheckAllowRuleID 是多策略 IP 预检中 allow 模式（白名单交集外拒绝）规则
// 的 SecRule id。本地 id 空间：2=ACL deny、3=bypass/trust、4=遗留黑名单、5=trust
// （bypass 占 3 时）、6=DetectionOnly 切换、8=GeoIP 地域拦截（BuildCorazaDirectives
// 内，不在预检）、900=异常分阈值；7 专用于预检 allow 规则（预检内 deny 并集沿用
// id:2、黑名单并集沿用 id:4，保持 security events 归因口径；allow 模式事件本就
// 回退归到首启用策略，id:7 不改变归因结果）。
const ipPrecheckAllowRuleID = 7

// intersectIPLists 返回多个名单的交集（保持首名单出现顺序）；空集返回 nil。
// 哈希集实现 O(n+m)：多策略 allow 模式合并集可达 10 万条目级，逐对线性
// 扫描会把配置生成（持 CaddyService 互斥锁）拖至分钟级。
func intersectIPLists(lists [][]string) []string {
	if len(lists) == 0 {
		return nil
	}
	candidate := make(map[string]struct{}, len(lists[0]))
	for _, entry := range lists[0] {
		if entry != "" {
			candidate[entry] = struct{}{}
		}
	}
	for _, rest := range lists[1:] {
		next := make(map[string]struct{}, len(candidate))
		for _, entry := range rest {
			if entry == "" {
				continue
			}
			if _, ok := candidate[entry]; ok {
				next[entry] = struct{}{}
			}
		}
		candidate = next
		if len(candidate) == 0 {
			return nil
		}
	}
	var intersection []string
	emitted := make(map[string]struct{}, len(candidate))
	for _, entry := range lists[0] {
		if entry == "" {
			continue
		}
		if _, ok := candidate[entry]; ok {
			if _, dup := emitted[entry]; dup {
				continue
			}
			emitted[entry] = struct{}{}
			intersection = append(intersection, entry)
		}
	}
	return intersection
}

// buildIPPrecheckDirectives 合并全部绑定启用策略的 deny 侧 IP 控制（deny 模式
// ACL 并集 id:2、allow 模式 ACL 交集外拒绝 id:7、遗留黑名单并集 id:4）为一个
// 极简 coraza 配置。多策略绑定时该预检查器置于处理器链最前（先于全部
// rate_limit/waf）：被拒 IP 在任何策略的 CRS/自定义规则评估前即中断——修复
// `[coraza_P1, coraza_P2]` 链中 P1 的 CRS 先评估产生检测事件、P2 的 IP ACL 才
// 拦截的双重检测问题（IP ACL 最高优先级）。预检仍是 coraza 拒绝：audit log
// 留痕供安全事件管线归因（id:2/id:4 归因口径不变），deny 403 → errors 路由 →
// 拦截页。信任名单/免检测不并入预检（deny 优先于信任，且信任仅豁免所属策略
// 的检查、限流仍生效的语义保持不变）。无 deny 侧控制时返回空串（不发射）。
func buildIPPrecheckDirectives(policies []*models.SecurityPolicy) string {
	var denyUnion, blacklistUnion []string
	var allowLists [][]string
	for _, p := range policies {
		if p == nil {
			continue
		}
		aclList := mergedACLList(p)
		if p.IPACLEnabled && len(aclList) > 0 {
			switch p.IPACLMode {
			case "deny":
				denyUnion = append(denyUnion, aclList...)
			case "allow":
				allowLists = append(allowLists, aclList)
			}
		}
		var blacklist []string
		json.Unmarshal(p.IPBlacklist, &blacklist)
		blacklistUnion = append(blacklistUnion, blacklist...)
	}
	if len(denyUnion) == 0 && len(blacklistUnion) == 0 && len(allowLists) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("SecRuleEngine On\n")
	// 预检仅含 phase:1 的 REMOTE_ADDR 规则，无需请求体/响应体访问。
	sb.WriteString("SecRequestBodyAccess Off\n")
	sb.WriteString("SecResponseBodyAccess Off\n")
	// 与 BuildCorazaDirectives 同款审计配置：IP 拒绝事件经 audit log 进入
	// 安全事件管线（ RelevantOnly + deny 中断 = relevant）。
	sb.WriteString("SecAuditEngine RelevantOnly\nSecAuditLog /app/waf/audit/audit.log\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHKZ\n")
	if len(allowLists) > 0 {
		intersection := intersectIPLists(allowLists)
		// 多条 allow 名单互不相交（交集为空）= 逐策略顺序评估下任意 IP 都会被
		// 某个名单拒绝：恒拒规则等价表达（REMOTE_ADDR 恒非空）。
		if len(intersection) == 0 {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@rx .*\" \"id:%d,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END\"\n", ipPrecheckAllowRuleID))
		} else {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:%d,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END\"\n", strings.Join(intersection, ","), ipPrecheckAllowRuleID))
		}
	}
	if len(denyUnion) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END\"\n", strings.Join(denyUnion, ",")))
	}
	if len(blacklistUnion) > 0 {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:4,phase:1,deny,status:403,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END\"\n", strings.Join(blacklistUnion, ",")))
	}
	sb.WriteString("SecMarker SECURITY_RULES_END\n")
	return sb.String()
}

// buildIPPrecheckHandler returns the consolidated IP precheck coraza handler for
// a multi-policy bound rule, or nil when no bound policy contributes deny-side
// IP control.
func buildIPPrecheckHandler(policies []*models.SecurityPolicy) map[string]interface{} {
	directives := buildIPPrecheckDirectives(policies)
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

// policyCustomRulesCached 以策略为粒度缓存自定义规则解析（审计 I-4）：批量
// 生成期由 loadSecurityPolicyContext 对每个去重策略解析一次，替代逐
// (规则×策略) 对的重复 IN 查询；非批量路径首次调用即缓存，语义不变。
func policyCustomRulesCached(p *models.SecurityPolicy, store caddyConfigStore) []models.CustomRule {
	if p.CustomRulesCached {
		return p.CustomRulesCache
	}
	rules := resolvePolicyCustomRules(p.CustomRules, store)
	p.CustomRulesCache = rules
	p.CustomRulesCached = true
	return rules
}

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

// CRSExcludedRulesMaxEntries 新格式 crs_excluded_rules 的条目上限（旧 []string
// 格式无上限，保持现状兼容；50 条上限口径）。
const CRSExcludedRulesMaxEntries = 50

// CRSExcludedEntry 是 crs_excluded_rules 列的归一化单条：Target 为两位组号
// （"42"）、6 位 CRS 规则 ID（"942100"）或遗留文件名/区间形态（仅 scope=all）；
// Scope 为 "all"（全量排除，走 SecRuleRemoveById 现状路径）或 "ip"/"list"
// （作用域限定，仅命中 IPs ∪ ListRefs 条目的客户端跳过排除）；IPs 为逗号
// 分隔的 IP/CIDR；ListRefs 引用 security_ip_lists id。
type CRSExcludedEntry struct {
	Target   string  `json:"target"`
	Scope    string  `json:"scope"`
	IPs      string  `json:"ips"`
	ListRefs []int64 `json:"listRefs"`
}

// UnmarshalJSON/MarshalJSON 双向兼容 ips 形态（v2.2.2 契约漂移修复）：
// 前端 tag 输入天然产生数组（["1.2.3.4"]），向导/快捷排除两侧统一以数组
// 收发；后端内部存储/发射仍用逗号串。收：string|array 均可；发：数组。
func (e *CRSExcludedEntry) UnmarshalJSON(data []byte) error {
	type alias CRSExcludedEntry
	var a alias
	if err := json.Unmarshal(data, &a); err == nil {
		*e = CRSExcludedEntry(a)
		return nil
	}
	type arrayForm struct {
		Target   string   `json:"target"`
		Scope    string   `json:"scope"`
		IPs      []string `json:"ips"`
		ListRefs []int64  `json:"listRefs"`
	}
	var b arrayForm
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	*e = CRSExcludedEntry{Target: b.Target, Scope: b.Scope, IPs: strings.Join(b.IPs, ","), ListRefs: b.ListRefs}
	return nil
}

func (e CRSExcludedEntry) MarshalJSON() ([]byte, error) {
	var ips []string
	for _, item := range strings.Split(e.IPs, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			ips = append(ips, trimmed)
		}
	}
	if ips == nil {
		ips = []string{}
	}
	return json.Marshal(map[string]interface{}{
		"target":   e.Target,
		"scope":    e.Scope,
		"ips":      ips,
		"listRefs": e.ListRefs,
	})
}

// IsCRSRuleIDTarget 报告 s 是否为 6 位 CRS 规则 ID 形态（^9\d{5}$）。
func IsCRSRuleIDTarget(s string) bool {
	return len(s) == 6 && s[0] == '9' && allDigits(s[1:])
}

// IsCRSGroupCode 报告 s 是否为两位数字组号形态。
func IsCRSGroupCode(s string) bool {
	return len(s) == 2 && allDigits(s)
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ParseCRSExcludedRules 读侧双格式归一：旧 []string（文件名/6 位 ID/区间）每条
// 归一为 {target, scope:"all"}（保留原始条目顺序与重复，发射等价于旧实现）；
// 新 []对象 缺省 scope 补 "all"、完全相同 {target,scope,ips,listRefs} 条目去重。
// 空串/纯空白与任何解析失败均按空处理（nil）——防御旧/坏数据（集群同步/带外
// 改库/降级版本写入的载荷），绝不让策略发射失败。
func ParseCRSExcludedRules(raw string) []CRSExcludedEntry {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	var legacy []string
	if err := json.Unmarshal([]byte(trimmed), &legacy); err == nil {
		out := make([]CRSExcludedEntry, 0, len(legacy))
		for _, entry := range legacy {
			if strings.TrimSpace(entry) == "" {
				continue
			}
			out = append(out, CRSExcludedEntry{Target: entry, Scope: "all"})
		}
		return out
	}
	var entries []CRSExcludedEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return nil
	}
	out := make([]CRSExcludedEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Target) == "" {
			continue
		}
		if entry.Scope == "" {
			entry.Scope = "all"
		}
		out = append(out, entry)
	}
	return dedupeCRSExcludedEntries(out)
}

// dedupeCRSExcludedEntries 按 {target,scope,ips,listRefs} 完全一致去重（保序，
// 首见保留）；listRefs 以排序后的序列参与键（[1,2] 与 [2,1] 视为同条）。
func dedupeCRSExcludedEntries(entries []CRSExcludedEntry) []CRSExcludedEntry {
	seen := make(map[string]struct{}, len(entries))
	out := make([]CRSExcludedEntry, 0, len(entries))
	for _, entry := range entries {
		refs := append([]int64{}, entry.ListRefs...)
		sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
		key := entry.Target + "\x00" + entry.Scope + "\x00" + entry.IPs + "\x00" + fmt.Sprint(refs)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	return out
}

// crsScopedExclusionIDBase 是作用域限定排除 ctl 规则的 SecRule id 基值：首条
// 2000001，单次 BuildCorazaDirectives 调用内递增（n 顺序唯一）。与 CRS 9xxxxx /
// 自定义规则 cr.ID+10000 / 无 id 合成 1000000+ 段互不冲突。
const crsScopedExclusionIDBase = 2000000

// emitScopedCRSExclusions 发射作用域限定（scope=ip/list）的排除条目：每条先解析
// 匹配集（ips 逗号条目 ∪ 全部 listRefs 的列表条目，跨条目去重保序；ListRefs 跨
// 条目汇总后单批 LoadIPListEntriesByID），合并为空 → 跳过+warn（列表被清空/
// 引用悬空时不发射空 ipMatch）；target 经 expandCRSScopedExclusionTargets 展开
// 为逐 ID（ctl:ruleRemoveById 不支持区间），每 ID 一条 phase:1 运行时 ctl 规则。
// emitScopedCRSExclusions 发射作用域限定 ctl 规则。store 非-nil 时经其解析列表引用
// （v2 导入事务视图——A-I1 不变式，审计 U1-F3）；nil 回退 db.DB（测试/直调路径）。
// chainIndex 为链级惰性索引取值闭包（M4）——单次 BuildCorazaDirectives 内与其他
// 消费点共享一次缓存键计算。
func emitScopedCRSExclusions(sb *strings.Builder, p *models.SecurityPolicy, entries []CRSExcludedEntry, store caddyConfigStore, chainIndex func() *CRSRuleIndex) {
	var refIDs []int64
	seenRef := make(map[int64]struct{})
	for _, entry := range entries {
		for _, id := range entry.ListRefs {
			if _, dup := seenRef[id]; dup {
				continue
			}
			seenRef[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
	}
	listsByID, err := loadIPListEntriesVia(store, refIDs)
	if err != nil {
		Logf("warn", "解析作用域排除引用的 IP 列表失败（策略 %q）: %v", p.Name, err)
		listsByID = map[int64][]string{}
	}
	index := GetCRSRuleIndex()
	seq := 0
	for _, entry := range entries {
		match := make([]string, 0, 4)
		seenIP := make(map[string]struct{})
		addMatch := func(value string) {
			value = strings.TrimSpace(value)
			if value == "" {
				return
			}
			if _, dup := seenIP[value]; dup {
				return
			}
			seenIP[value] = struct{}{}
			match = append(match, value)
		}
		for _, ip := range strings.Split(entry.IPs, ",") {
			addMatch(ip)
		}
		for _, ref := range entry.ListRefs {
			for _, value := range listsByID[ref] {
				addMatch(value)
			}
		}
		if len(match) == 0 {
			Logf("warn", "跳过作用域排除条目 %q（策略 %q）：ips/引用列表合并后为空", entry.Target, p.Name)
			continue
		}
		for _, id := range expandCRSScopedExclusionTargets(entry.Target, index, p) {
			seq++
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%s\"\n",
				strings.Join(match, ","), crsScopedExclusionIDBase+seq, id))
		}
	}
}

// expandCRSScopedExclusionTargets 把作用域限定条目的 target 展开为逐规则 ID：
// 两位组号 → 索引内该组全部 ID（升序）；6 位 ID → 索引存在时单元素，否则视为
// 陈旧（CRS 更替后规则消失，多经集群同步等带外通道落库）跳过+warn；其余形态
// （遗留文件名/区间）不支持作用域限定（保存侧已拒，此处防御跳过+warn）。
func expandCRSScopedExclusionTargets(target string, index *CRSRuleIndex, p *models.SecurityPolicy) []string {
	target = strings.TrimSpace(target)
	if IsCRSRuleIDTarget(target) {
		if !index.Has(target) {
			Logf("warn", "跳过陈旧排除规则 ID %q（策略 %q）：不存在于本地 CRS 规则索引", target, p.Name)
			return nil
		}
		return []string{target}
	}
	if IsCRSGroupCode(target) {
		ids := index.RuleIDsByGroup(target)
		if len(ids) == 0 {
			Logf("warn", "跳过陈旧排除规则组 %q（策略 %q）：不存在于本地 CRS 规则索引", target, p.Name)
		}
		return ids
	}
	Logf("warn", "跳过作用域排除条目 %q（策略 %q）：该 target 形态仅支持 scope=all", target, p.Name)
	return nil
}

// crsFileGroupPattern 从 CRS 规则文件名提取两位组号（REQUEST-942-…/RESPONSE-951-…
// → "42"/"51"）；不匹配常见形态时返回空串（永不命中任何已选组 → 走父文件补删）。
var crsFileGroupPattern = regexp.MustCompile(`^(?:REQUEST|RESPONSE)-9([0-9]{2})-`)

// crsInfraGroupCodes 基础设施组：901 初始化（偏执级默认值/评分初始化）、
// 949 请求评估、959 响应评估。缺失任一都会静默失效（守卫按 0 跳过/拦截退化），
// 因此对用户配置面隐藏、写入面剥离、发射面强制包含。
var crsInfraGroupCodes = map[string]struct{}{"01": {}, "49": {}, "59": {}}

// IsCRSInfraGroupCode 报告两位组号是否基础设施组。
func IsCRSInfraGroupCode(code string) bool {
	_, ok := crsInfraGroupCodes[code]
	return ok
}

// IsCRSInfraRuleID 报告 6 位规则 ID 是否落在基础设施组的 ID 区间
// （901000-901999 / 949000-949999 / 959000-959999）。写入面据此剥离——
// 单选基础设施文件内的个别规则是无意义配置（缺省值/评估需整文件在场）。
func IsCRSInfraRuleID(id string) bool {
	if !IsCRSRuleIDTarget(id) {
		return false
	}
	return strings.HasPrefix(id, "901") || strings.HasPrefix(id, "949") || strings.HasPrefix(id, "959")
}

// CRSExclusionTargetRemovesInit 报告排除目标与初始化组（901000-901999）是否
// 相交：组号 "01"、组内规则 ID、REQUEST-901-*.conf 文件名、或与之相交的数字
// 区间（含跨界区间如 900500-902000）。排除初始化规则无合法用途——偏执级默认
// 值与评分初始化缺失会让守卫按 0 处理整段跳过、策略静默空转，写入面据此拒绝。
func CRSExclusionTargetRemovesInit(target string) bool {
	target = strings.TrimSpace(target)
	if IsCRSGroupCode(target) {
		return target == "01"
	}
	if IsCRSRuleIDTarget(target) {
		return strings.HasPrefix(target, "901")
	}
	mapped := crsFilenameToRuleIDRange(target)
	lo, hi, ok := crsNumericIDRange(mapped)
	if !ok {
		return false
	}
	return lo <= 901999 && hi >= 901000
}

func crsNumericIDRange(s string) (int, int, bool) {
	loStr, hiStr, hasDash := strings.Cut(s, "-")
	lo, err := strconv.Atoi(loStr)
	if err != nil {
		return 0, 0, false
	}
	hi := lo
	if hasDash {
		if hi, err = strconv.Atoi(hiStr); err != nil {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

// crsCoveredInfraGroupCodes 计算混合选择已覆盖的组号集合：两位组号直接计入；
// 6 位 ID 条目经索引定位父文件后其父文件组号同样计入（emitCRSRuleGroupSelection
// 会 Include 该父文件）。陈旧 ID（索引不存在）与 emit 同口径跳过。chainIndex
// 为链级惰性索引取值闭包（M4），仅在遇到 6 位 ID 时才真正取值。
func crsCoveredInfraGroupCodes(chainIndex func() *CRSRuleIndex, groups []string) map[string]struct{} {
	covered := make(map[string]struct{}, len(groups))
	var index *CRSRuleIndex
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if IsCRSRuleIDTarget(g) {
			if index == nil {
				index = chainIndex()
			}
			if entry := index.Find(g); entry != nil {
				if m := crsFileGroupPattern.FindStringSubmatch(entry.File); m != nil {
					covered[m[1]] = struct{}{}
				}
			}
			continue
		}
		covered[g] = struct{}{}
	}
	return covered
}

// stripInfraCRSGroupCodes（M3 读取面兜底）从 crs_rule_groups 载荷剥离基础设施
// 组号（01/49/59）及其文件内规则 ID，返回（保留条目, 被剥条目）。判定复用
// IsCRSInfraGroupCode/IsCRSInfraRuleID——与写入面 validateAndNormalizeCRSField
// 的剥离同口径；条目 trim 后判定以覆盖 R47 B-#1 历史空白行，保留条目原样交由
// 发射端既有 trim 逻辑。
func stripInfraCRSGroupCodes(groups []string) (kept, stripped []string) {
	kept = make([]string, 0, len(groups))
	for _, g := range groups {
		trimmed := strings.TrimSpace(g)
		if IsCRSInfraGroupCode(trimmed) || IsCRSInfraRuleID(trimmed) {
			stripped = append(stripped, trimmed)
			continue
		}
		kept = append(kept, g)
	}
	return kept, stripped
}

// emitCRSRuleGroupSelection 发射 crs_rule_groups 混合选择：两位组号条目走现状
// Include glob 路径（逐条、trim 后拼接，含 WAFCheckResponse 的 RESPONSE 侧）；
// 6 位 ID 条目经本地索引定位父文件——父文件组未被选中时 Include 该文件，并对
// 文件内索引已知、未被选中的其余 ID 逐条 SecRuleRemoveById（ctl 不适用于配置期
// 整组剔除，补删必须逐 ID，不能用区间以免误删同文件被选 ID）。陈旧 ID（索引
// 不存在）跳过+warn。纯组号载荷的输出与既有实现逐行一致（等价回归锁定）。
func emitCRSRuleGroupSelection(sb *strings.Builder, p *models.SecurityPolicy, groups []string, chainIndex func() *CRSRuleIndex) {
	groupSet := make(map[string]struct{}, len(groups))
	var idTargets []string
	seenID := make(map[string]struct{})
	for _, g := range groups {
		// R47 B-#1：历史遗留行可能含首尾空白（旧校验曾放行），trim 后拼接，
		// 保证 glob 恒为 REQUEST-9<code>-*.conf 的合法形态（镜像下方排除项的 trim）。
		g = strings.TrimSpace(g)
		if IsCRSRuleIDTarget(g) {
			if _, dup := seenID[g]; !dup {
				seenID[g] = struct{}{}
				idTargets = append(idTargets, g)
			}
			continue
		}
		groupSet[g] = struct{}{}
		sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/REQUEST-9%[1]s-*.conf\n", g))
		if p.WAFCheckResponse {
			sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/RESPONSE-9%[1]s-*.conf\n", g))
		}
	}
	if len(idTargets) == 0 {
		return
	}
	index := chainIndex()
	selected := make(map[string]struct{}, len(idTargets))
	for _, id := range idTargets {
		selected[id] = struct{}{}
	}
	var parentFiles []string
	included := make(map[string]struct{})
	for _, id := range idTargets {
		entry := index.Find(id)
		if entry == nil {
			Logf("warn", "跳过陈旧 CRS 规则组 ID %q（策略 %q）：不存在于本地规则索引", id, p.Name)
			continue
		}
		if group := crsFileGroupPattern.FindStringSubmatch(entry.File); group != nil {
			if _, covered := groupSet[group[1]]; covered {
				continue
			}
		}
		if _, dup := included[entry.File]; dup {
			continue
		}
		included[entry.File] = struct{}{}
		parentFiles = append(parentFiles, entry.File)
		sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/%s\n", entry.File))
	}
	if len(parentFiles) == 0 {
		return
	}
	idsByFile := index.RuleIDsByFile()
	for _, file := range parentFiles {
		for _, id := range idsByFile[file] {
			if _, keep := selected[id]; keep {
				continue
			}
			sb.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", id))
		}
	}
}

// ValidateGeoIPCountries 校验 geoip_countries 载荷：必须是 JSON 数组且条目非空；
// ip2region 已加载（live 或缓存）时条目必须属于已知省份或"海外"，未知省份在
// 发射端永不匹配，会静默削弱地域控制。ip2region 未加载且无缓存时同样拒绝未知
// 省份（fail-closed）：启动期放行任意省份会让 deny 模式的地域拦截静默失效，
// 提示未加载而非放行。
// geoipMode="off" 是区域控制关闭态：名单仅为保留数据（开关重开即复用），
// 跳过可用性门（缺库时关闭/保留名单的保存不得被 400 卡死），仅做形状校验。
func ValidateGeoIPCountries(raw string, geoipMode string) error {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("geoip_countries 必须是 JSON 数组")
	}
	if geoipMode == "off" {
		return nil
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
