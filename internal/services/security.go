package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lazy-balancer-v2/geoipnames"
	"net"
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
// json.RawMessage；行缺失或 disabled 时返回 nil。GetSecurityPoliciesForRule 与
// 测试辅助 GetSecurityPolicyForRule（security_policy_helpers_test.go）共用本扫描，
// 保证两条读路径字段级一致。
//
// 库值唯一真相（批 3）：anomaly_threshold 列 COALESCE(...,0) 是「无效哨兵」
// 而非默认值——NULL→0 与带外 <=0 同归渲染层显性报错（BuildCorazaDirectives
// fail-visible），不再是旧口径的 COALESCE(...,5) 写死兜底。速率/状态列的
// COALESCE(...,0) 是类型②省略型/条件消费的规范化（0=未启用/未设置）。
func scanSecurityPolicyByID(policyID int) *models.SecurityPolicy {
	var p models.SecurityPolicy
	var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries, crawlerEnginesRaw string
	err := db.DB.QueryRow(`SELECT id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,0), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_whitelist,'[]'), COALESCE(ip_blacklist,'[]'),
		COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0), COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'), COALESCE(block_page_id,0), COALESCE(block_status_code,0), enabled, COALESCE(created_at,''), COALESCE(updated_at,''), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(geoip_crawler_exempt,0), COALESCE(geoip_crawler_engines,'[]'), COALESCE(waf_check_response,0), COALESCE(log_request_body,0), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(policy_type,''), COALESCE(trust_detection,0)
		FROM security_policies WHERE id=? AND enabled=1`, policyID).
		Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold, &p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &p.IPWhitelistEnabled, &ipWhitelist, &ipBlacklist,
			&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst, &crsRuleGroups, &crsExcludedRules, &customRules, &p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.CreatedAt, &p.UpdatedAt, &geoipCountries, &p.GeoIPMode, &p.GeoIPCrawlerExempt, &crawlerEnginesRaw, &p.WAFCheckResponse, &p.LogRequestBody, &p.IPACLListRefs, &p.IPWhitelistRefs, &p.PolicyType, &p.TrustDetection)
	if err != nil {
		return nil
	}
	p.IPWhitelist = json.RawMessage(ipWhitelist)
	p.IPBlacklist = json.RawMessage(ipBlacklist)
	p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
	p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
	p.CustomRules = json.RawMessage(customRules)
	p.GeoIPCountries = json.RawMessage(geoipCountries)
	p.GeoIPCrawlerEngines = json.RawMessage(crawlerEnginesRaw)
	return &p
}

// GetSecurityPoliciesForRule returns all enabled policies bound to a rule,
// ordered by policy_id ASC (R72 v2.2.0 multi-policy binding).
func GetSecurityPoliciesForRule(ruleCaddyID string) []*models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		Logf("error", "GetSecurityPoliciesForRule: 查询规则 %s 的安全策略绑定失败: %v", ruleCaddyID, err)
		return nil
	}
	defer rows.Close()
	var policies []*models.SecurityPolicy
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			Logf("error", "GetSecurityPoliciesForRule: 扫描规则 %s 的安全策略绑定行失败: %v", ruleCaddyID, err)
			return nil
		}
		// 禁用策略在策略查询处过滤（与单查的 WHERE enabled=1 同口径）。
		if p := scanSecurityPolicyByID(policyID); p != nil {
			policies = append(policies, p)
		}
	}
	if err := rows.Err(); err != nil {
		Logf("error", "GetSecurityPoliciesForRule: 迭代规则 %s 的安全策略绑定失败: %v", ruleCaddyID, err)
		return nil
	}
	// 批次引用解析：跨全部已加载策略收集列表 id，一次批量查询（预算：与策略数
	// 无关的常数一次），合并集附加到各策略的 Merged* 字段供发射端消费。
	resolvePolicyIPListRefs(policies, nil)
	return policies
}

// geoipCountries parses the policy's geoip_countries JSON array, skipping
// blank entries. A missing or malformed payload yields nil.
// D7（第 74 轮）：畸形 JSON 不再静默——WARN 留痕后按无地域规则渲染。
// 不 fail-visible 的推演披露：geoip_countries 是单策略 TEXT 列，fail-visible
// 会让一份带外脏行阻断整份配置生成（全部规则重载失败），与 D3 受信代理
// 裁定同向（可用性优先+降级可见）；写侧/导入门已拒绝该形态，WARN 面向
// 带外直写/旧备份绕过残留。
func geoipCountries(p *models.SecurityPolicy) []string {
	if p == nil || len(p.GeoIPCountries) == 0 {
		return nil
	}
	var entries []string
	if err := json.Unmarshal(p.GeoIPCountries, &entries); err != nil {
		Logf("warn", "策略 %q（#%d）geoip_countries 畸形 JSON，渲染按无地域规则处理: %v", p.Name, p.ID, err)
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
// 覆盖边界（SEC-B-2 第 72 轮核实，维持设计）：crs-setup.conf 与 rules/*.conf 的
// 直接手改不进池指纹（指纹只含版本行+overrides mtime/size）——标准变更链路
// （CRS 更新器/导入）必改版本行触发指纹翻转；绕过链路的手改需重启进程生效，
// 属已声明的成本权衡。
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

// crsFingerprint：批量生成方按链计算一次并透传，避免逐 (规则×策略) 对重复
// 执行 DB 查询+stat（审计 B5-F2）；空串回退自算。multiPolicy（SECLB32-1）：
// 预检存在时策略层 IP ACL 链式自排除本策略信任集。blockStatus：拦截页按触发
// 策略归因的合成中断码（481+，securityPolicyContext.policySynthetic 按策略
// 身份分配）；>0 时段内全部 deny 显式抬码（IP ACL/GeoIP/自定义规则/CRS
// 949110），0 时逐字节保持现状（403 或缺省，单策略/无页路径回归形状）。
// stage0DetectionTrust（第 7 参，可选变参）：发射面 flag 与内容二合一——变参
// 出现即「存在 stage0 信任名单保留检测策略（trust_detection=1）」（恒发射
// id:12；并集可空=空文件算子永不命中，与无规则等价，空↔非空纯内容变化走
// 热路径，2026-10-15 始终发射收敛）；缺省=无此类策略（不发射）。并集元素为
// 按规则绑定的信任地址（直通形态 trust_detection=0 由路由层 subroute 短路，
// 不进本参数）。
// ruleCaddyID（第 6 参，第 76 轮 HP-1）：id:12 的 u-trust12 投影 scope 编入
// 规则身份（u-trust12-<ruleCaddyID>）——stage0DetectionTrust 是逐规则并集
// （policiesForRule），全局单文件名下异策略集多规则后渲染覆盖前者=信任集
// 串染。空值显性报错（fail-loud）。
//
// HP77-3（第 77 轮裁定，维持 fail-loud 不收窄）：空身份的爆炸半径=整份配置
// 被拒（保存失败/重载失败）。已裁定豁免不修——生产路径 ruleCaddyID 恒非空
// （两个渲染入口都由规则身份驱动），空值=数据损坏/调用错位的显性信号；收窄
// 为「跳过该规则+告警」会让受影响规则的 IP 控制面静默缺失（安全面静默缺口），
// 比整份配置拒绝（fail-closed、横幅可见）更危险。本注释即裁定载体。
func BuildCorazaDirectives(p *models.SecurityPolicy, store caddyConfigStore, crsFingerprint string, multiPolicy bool, blockStatus int, ruleCaddyID string, stage0DetectionTrust ...[]string) (string, error) {
	if ruleCaddyID == "" {
		return "", fmt.Errorf("u-trust12 引擎投影缺少规则身份（ruleCaddyID 为空）——id:12 逐规则渲染，scope 必须编入规则身份（第 76 轮 HP-1）")
	}
	var sb strings.Builder
	// R72 三十次 F1：嵌 coraza 池键指纹（见 crsPoolFingerprint）——CRS 文件
	// 替换/手动改 overrides 后池键必须变化，否则新 Caddy 配置复用旧 WAF
	//（旧规则静默继续生效）。
	crsFp := crsFingerprint
	if crsFp == "" {
		crsFp = crsPoolFingerprint()
	}
	sb.WriteString(fmt.Sprintf("# crs-pool=%s\n", crsFp))
	// Merged* 为策略加载路径附加的「inline ∪ 引用 IP 列表条目」合并集；未经
	// 解析的策略（直接构造/非生成路径）由 helper 回退 inline-only。
	ipWL := mergedWhitelist(p)
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	ipBL = aggregateIPEntries(ipBL)
	ipACLList := mergedACLList(p)

	// IP-level control (ACL / trust list / legacy bypass & blacklist) runs
	// independently of the WAF mode so that "关闭 WAF" never disables IP control.
	// 信任名单三态门（对齐 ip_acl_enabled/geoip_mode）：关闭保留名单零发射。
	// GeoIP 地域拦截已迁出策略引擎（阶段化模型：阶段 1 预检 800000+ 段承接），
	// 不再构成开引擎理由——纯 GeoIP 策略产空串不出 handler。stage0 信任名单
	// 策略的信任不属于本引擎（直通=路由层 subroute 短路零事件；保留检测=
	// id:12 由预检与其他策略引擎承载）——stage0 策略产空串不出 handler。
	// 始终发射收敛（2026-10-15 用户裁定）：deny·bypass ACL 开启即算 IP 控制
	//（空名单恒发射空文件算子，永不命中=与无规则等价，空↔非空纯内容变化走
	// 热路径）。信任名单不收敛：ip_whitelist_enabled 表默认值即 1（非刻意
	// opt-in，flag 门控会使全部默认策略凭空获得引擎/信任规则——发射面膨胀，
	// 门禁钉测实证），维持内容门控；allow ACL（否定算子）与遗留黑名单同理
	// 维持内容门控（见下 ipListRuleOperand 调用点注释）。
	emitIPControl := (p.IPWhitelistEnabled && p.PolicyType != models.PolicyTypeStage0 && len(ipWL) > 0) || len(ipBL) > 0 || (p.IPACLEnabled && (p.IPACLMode != "allow" || len(ipACLList) > 0))
	customRules := policyCustomRulesCached(p, store)
	hasCustomRules := false
	for _, cr := range customRules {
		if cr.Enabled {
			hasCustomRules = true
			break
		}
	}

	// 2026-09-09 裁定:WAF 模式四态化。
	//   off:CRS 与自定义规则均不生效(引擎仅为 IP 控制而开;GeoIP 已迁预检);
	//   custom_only:CRS 不加载,仅自定义规则(计分动作无 949 评估链,退化为检测计分);
	//   detection:CRS 检测不拦,自定义 deny 仍拦(下方 DetectionOnly 切换只作用于
	//             CRS——切换在自定义规则之后、CRS Include 之前发出);
	//   blocking:CRS 拦截,自定义规则按规则内动作执行。
	crsActive := p.Mode == "blocking" || p.Mode == "detection"
	customActive := p.Mode == "custom_only" || crsActive
	switch {
	case crsActive:
		if p.Mode == "detection" {
			// 检测模式仍保持 IP 控制与自定义规则强制生效:引擎以 On 启动,使下方的
			// IP ACL deny 规则与自定义拦截规则(在 DetectionOnly 切换之前发出)真实
			// 阻断;随后通过 phase:1 的 SecAction 仅将 CRS 规则集切换为
			// DetectionOnly(该切换在 CRS Include 之前生效),自定义拦截规则与 IP
			// ACL 不受影响,仍在检测模式下强制阻断。
			// 例外(R65 B-S5):body 目标的自定义拦截规则发射为 phase:2(REQUEST_BODY
			// 仅 phase:2 可读),而 DetectionOnly ctl 是事务级指令持续到 phase:2——
			// 该类规则在检测模式下仅记录不阻断(见 emitCustomRules 相位说明)。
		}
		sb.WriteString("SecRuleEngine On\n")
	case p.Mode == "custom_only" && (hasCustomRules || emitIPControl):
		// 仅自定义:CRS 不加载,引擎为自定义规则/IP 控制而开;空策略
		// (无启用规则且无 IP 控制)落入 default 不产空转 handler。
		sb.WriteString("SecRuleEngine On\n")
	case emitIPControl:
		// mode=off(2026-09-09 裁定后):自定义规则不再生效,引擎仅为 IP 控制开。
		sb.WriteString("SecRuleEngine On\n")
	default:
		return "", nil
	}
	// SLB12-P2-1 + SLB13-N1/新-3(第 13 轮收紧):仅存在 body 消费者时开启
	// 请求体访问——coraza-caddy v2.6.0 的 body 缓冲唯一门控是
	// RequestBodyAccess(无惰性检查)。消费者精确枚举:
	//   ① CRS(phase:2 规则集,blocking/detection);
	//   ② 自定义规则可发射的模式(custom_only)且存在已启用规则(可有 body 目标;
	//      规则启停经 finishTxApply 重渲染,收紧零滞后)。off 态停放启用规则
	//      不发射,不计入(SLB14-N1:R13 形态在 off+停放规则形状反向回归)。
	// 第 12 轮的第三条件 log_request_body 经引擎源码验证在 mode=off 不可消费
	// (phase:1 中断先于 body 读、C 段恒空)——移除;对照同型 IP 预检正确用
	// Off+无 C 段。
	if crsActive || (customActive && hasCustomRules) {
		sb.WriteString("SecRequestBodyAccess On\n")
	} else {
		sb.WriteString("SecRequestBodyAccess Off\n")
	}
	if p.WAFCheckResponse && crsActive {
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
	// request_body（64KB 截断）。请求体 access 由上方 crsActive/customActive
	// 门控决定（SLB12-P2-1 后 :214-218 条件发射，不再恒 On）；本开关
	// （LogRequestBody）仅扩展审计输出面（加 C 段）。
	auditParts := "ABIJDEFHKZ"
	if p.LogRequestBody {
		auditParts = "ABCIJDEFHKZ"
	}
	// SecAuditLogType lbfile：审计写插件（caddygeoip auditwriter.go，xcaddy
	// 链入）——异步有界队列+bufio 批量落盘，刷盘前把进程内计时注册表的分段
	// 耗时注入审计行顶层 lb_timing 字段（第 76 轮：侧车退役，摄取管道改读
	// 行内嵌字段）。零丢弃：队列满时阻塞等消化（退化价=
	// serial 同步写）。coraza NewWAF 时 Init 打开文件（目录缺失=配置拒绝，
	// SECLB23-P1-1 语义不变）；轮转=copytruncate，长生命周期 fd 恒有效。
	sb.WriteString(fmt.Sprintf("SecAuditEngine RelevantOnly\nSecAuditLog %s\nSecAuditLogType lbfile\nSecAuditLogFormat JSON\nSecAuditLogParts %s\n", auditLogPath, auditParts))

	// SecRule id map: 2 = ACL allow/deny, 3 = bypass-mode (legacy), 4 = legacy
	// blacklist, 5 = trust list, 9 = JSON body processor 激活,
	// 10 = XML body processor 激活, 11 = 请求体解析失败守卫. The trust list keeps
	// the historical id:3 unless a bypass-mode rule already owns it.
	// 2026-09-15 用户裁定:bypass(IP ACL bypass 模式)保持 ctl:ruleEngine=Off 短路;
	// 信任名单改 ctl:ruleEngine=DetectionOnly——信任流量全评估不拦但全记录
	// (动作=检测),不再是「never reach ACL denies」的静默跳过。
	// v2.3.x：策略名单不再内联展开（配置体积 + coraza 64KiB 单行静默截断
	// 悬崖），统一投影为 @ipListFast 稳定命名文件（<scope>.txt，写失败=渲染
	// 报错=保存回滚，fail-closed；内容变化同路径原子换内容=配置字节不变，
	// 名单写路径得以零 /load 收敛——2026-10-15 热路径改造）。同一策略的信任
	// 名单文件被 id:3/5、id:2/4 链续段、GeoIP 预检第三续段共用（同 scope =
	// 同一文件）。
	trustScope := fmt.Sprintf("p%d-trust", p.ID)
	aclOperand := ""
	trustOperand := ""
	negTrustOperand := ""
	// 信任名单维持内容门控（不收敛，2026-10-15：ip_whitelist_enabled 表默认
	// 值=1 非刻意 opt-in，flag 门控会使全部默认策略凭空获得信任规则——门禁
	// 钉测实证；空↔非空仍走全量链）。allow 模式的 ACL 规则为 !@ipListFast
	//（否定算子）：空集=恒命中=全拒，与「无规则=全放」语义不等价且有全站
	// 锁死风险——同样维持内容门控。遗留黑名单为内联字段，仅经策略保存（全
	// 量链）变化，维持内容门控。
	if p.IPACLEnabled && (p.IPACLMode != "allow" || len(ipACLList) > 0) {
		operand, err := ipListRuleOperand(fmt.Sprintf("p%d-acl", p.ID), ipACLList, p.IPACLMode == "allow")
		if err != nil {
			return "", err
		}
		aclOperand = operand
	}
	if p.IPWhitelistEnabled && len(ipWL) > 0 {
		operand, err := ipListRuleOperand(trustScope, ipWL, false)
		if err != nil {
			return "", err
		}
		trustOperand = operand
		negTrustOperand = "!" + operand
	}
	bypassEmitted := false
	if p.IPACLEnabled && p.IPACLMode == "bypass" {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off\"\n", aclOperand))
		bypassEmitted = true
	}
	if p.PolicyType != models.PolicyTypeStage0 && p.IPWhitelistEnabled && len(ipWL) > 0 {
		trustID := 3
		if bypassEmitted {
			trustID = 5
		}
		// 2026-09-15 用户裁定:信任名单从「完全静默」改「可见放行」——
		// ctl:ruleEngine=DetectionOnly(全评估不拦,事件动作=检测);
		// 删 ctl:auditEngine=Off(原为实现信任完全静默同步关审计,现反向需求:
		// 信任流量必须进事件日志可见)。
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", trustOperand, trustID))
	}
	// 阶段 0 保留检测（2026-09-20 用户裁定）：信任名单策略 trust_detection=1
	// 时,绑定规则的每个策略引擎发射 id:12 DetectionOnly——信任 IP 全评估全
	// 记录不拦（事件动作=检测）。直通形态（trust_detection=0）由路由层
	// subroute 短路,不经任何引擎。
	if len(stage0DetectionTrust) > 0 {
		operand, err := ipListRuleOperand(precheckProjectionScope("trust12", ruleCaddyID), stage0DetectionTrust[0], false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", operand))
	}

	// SECLB32-1(第 32 轮审计,P1,取代 SECLB31-2 抑制方案):多策略(预检存在)
	// 时策略层 id:2/4 改链式自排除本策略信任集——
	//   · 本策略信任 IP:预检信任并集 DetectionOnly 统一记录(去重保持,
	//     SECLB31-2 目标),策略层链第二段 !@ipListFast 信任集 不命中→链整体
	//     不触发→不重复;
	//   · 他策略信任 IP(∉本策略信任集):链两段全命中→首段 deny 执行
	//     403——恢复「信任仅豁免所属策略」裁定边界(抑制方案下 P2 层无拦截
	//     点击穿);
	//   · 无信任名单的策略:无排除项→平原 id:2/4(与单策略形状一致);
	//   · 单策略(无预检):同实例信任 DetectionOnly 已正确处理,平原形态。
	// SECLB33-1(第 33 轮审计,P0,引擎约束):coraza「disruptive 动作仅允许
	// 链首段」(rule_parser.go:421)——deny/status/log/msg/skipAfter 必须在
	// 首段并以 ,chain 收尾,续段仅 t:none(GeoIP id:8 同款生产形状);
	// deny 在续段的形状被解析器整体拒绝(v2.2.11 出厂事故)。
	// multiPolicyTrustExclusion 维持内容门控（信任名单不收敛，2026-10-15：
	// ip_whitelist_enabled 表默认值=1 非刻意 opt-in——空信任会使链段凭空
	// 增减且全部默认策略发射面膨胀，门禁钉测实证）。
	multiPolicyTrustExclusion := multiPolicy && p.IPWhitelistEnabled && len(ipWL) > 0
	// 拦截页按触发策略归因：blockStatus>0（本策略分配了合成中断码）时段内
	// 全部 deny 显式抬码；==0 时逐字节保持现状（403 或缺省）——单策略/无页
	// 路径回归形状由既有钉测试锁定。自定义规则 block 动作的抬码在
	// emitCustomRules 内按 blockStatus 条件拼接（禁止无条件改写）。
	aclDenyStatus := 403
	if blockStatus > 0 {
		aclDenyStatus = blockStatus
	}
	if p.IPACLEnabled && aclOperand != "" && (p.IPACLMode == "allow" || p.IPACLMode == "deny") {
		msg := "IP 黑名单拒绝"
		if p.IPACLMode == "allow" {
			msg = "IP 白名单拒绝"
		}
		if multiPolicyTrustExclusion {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:2,phase:1,deny,status:%d,log,msg:'%s',skipAfter:SECURITY_RULES_END,chain\"\n", aclOperand, aclDenyStatus, msg))
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"t:none\"\n", negTrustOperand))
		} else {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:2,phase:1,deny,status:%d,log,msg:'%s',skipAfter:SECURITY_RULES_END\"\n", aclOperand, aclDenyStatus, msg))
		}
	}
	if len(ipBL) > 0 {
		blOperand, err := ipListRuleOperand(fmt.Sprintf("p%d-bl", p.ID), ipBL, false)
		if err != nil {
			return "", err
		}
		if multiPolicyTrustExclusion {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:4,phase:1,deny,status:%d,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END,chain\"\n", blOperand, aclDenyStatus))
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"t:none\"\n", negTrustOperand))
		} else {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:4,phase:1,deny,status:%d,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END\"\n", blOperand, aclDenyStatus))
		}
	}

	// GeoIP 区域拦截已迁出策略引擎（阶段化执行模型）：阶段 1 合并预检
	// （buildIPPrecheckDirectives，id=800000+policyID 精确归因段）在全部
	// rate_limit/waf 之前统一评估——单/多策略链形状同构，事件归因从共享
	// id:8（「首个 geoip 启用策略」）精确化为直接解码属主策略。caddygeoip
	// pass route 门不变（PolicyHasGeoIP 保留），X-LB-GeoIP-Loc 头由 pass route
	// 设置、预检 phase:1 读取。

	// 自定义规则仅在 custom_only/detection/blocking 发射(2026-09-09 裁定:
	// off=全关)。计分动作(pass+setvar)只给分:检测/拦截模式下由 CRS 949 阈值
	// 评估统一裁决是否拦截,custom_only 无 949 → 退化为检测计分(仅留事件)。
	if customActive {
		emitCustomRules(&sb, customRules, blockStatus)
	}

	if p.Mode == "detection" {
		sb.WriteString("SecAction \"id:6,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly\"\n")
	}

	// 仅自定义模式同样需要 body processor 激活:自定义 body 条件规则依赖解析
	// (SEC-REVIEW-03 随四态化一并解决);id:11 守卫计分在本模式无 949 消费,
	// 仅留事件——与计分动作的检测计分退化口径一致。
	// SEC-B-1（第 72 轮）：门收紧 hasCustomRules——custom_only+仅 IP 控制
	// 形状下上方 SecRequestBodyAccess 恒 Off（BodyAccessTruthTable 已钉），
	// id:9/10/11 无消费者，发射即死指令。
	if p.Mode == "custom_only" && hasCustomRules {
		emitBodyProcessorRules(&sb)
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
			if err := emitScopedCRSExclusions(&sb, p, scoped, store, chainIndex); err != nil {
				return "", err
			}
		}
		emitBodyProcessorRules(&sb)
		sb.WriteString("Include /app/waf/crs/crs-setup.conf\n")
		if _, err := os.Stat(filepath.Join(crsDirectivesDir, "zz-user-overrides.conf")); err == nil {
			sb.WriteString("Include /app/waf/crs/zz-user-overrides.conf\n")
		}
		// 库值唯一真相（批 3）：anomaly_threshold 类型①值型列——写侧 400
		// （枚举 1/3/5/10/15/20）+ 启动回填（<=0→5）保证库恒有效，直读无条件
		// 发射 id:900。无效值（NULL 读作哨兵 0/带外直写负值）在此显性报错
		// （fail-visible），废除原 `>0` 守卫——它让脏行静默跳过 SecAction、
		// CRS 回落引擎默认阈值，UI 宣称与实际行为漂移。
		if p.AnomalyThreshold <= 0 {
			return "", fmt.Errorf("策略 %q 异常阈值无效（anomaly_threshold=%d <=0）：该列为类型①值型列（写侧枚举 1/3/5/10/15/20+启动回填报证），疑似带外直写或旧备份绕过导入门", p.Name, p.AnomalyThreshold)
		}
		sb.WriteString(fmt.Sprintf("SecAction \"id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", p.AnomalyThreshold))
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
		// 拦截页按触发策略归因：blockStatus>0 时把 CRS 入站拦截评估规则
		// 949110 的 deny 抬为合成码（SecRuleUpdateActionById 真实抬码已经
		// 引擎行为实证——interruption.Status==合成码）。发射门=949 评估文件
		// 存在：指令在规则不存在时编译报错（directives.go:1262-1266），无论
		// 全量 glob 还是选组+基础设施强制包含路径，文件存在即必然被 Include
		// 覆盖；缺失时禁发（不拖垮整份配置加载，与 emitInfraInclude 存在性门
		// 同格）。位置=Include 之后、配置期 RemoveById 之前——排除条目若
		// 针对 949110，先抬码后删除不致「规则不存在」编译错误。
		if blockStatus > 0 {
			if _, err := os.Stat(filepath.Join(crsDirectivesDir, "rules", "REQUEST-949-BLOCKING-EVALUATION.conf")); err == nil {
				sb.WriteString(fmt.Sprintf("SecRuleUpdateActionById 949110 \"deny,status:%d\"\n", blockStatus))
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

	// 单行护栏（v2.3.x）：coraza seclang 解析器 bufio.Scanner 64KiB 行上限
	// 且静默截断（scanner.Err() 未检查）——渲染层 fail-loud 兜底。
	if err := assertDirectiveLines(sb.String()); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// assertDirectiveLines 逐行检查渲染产物：单行超过 48KiB 即报错——coraza
// seclang 用 bufio.NewScanner（默认 64KiB 行上限）且不检查 scanner.Err()，
// 超限行与其后全部指令会被静默丢弃（NewWAF 返回 nil）。48KiB 留 16KiB
// 余量给拼接侧后续追加（msg/status 等尾巴）。
func assertDirectiveLines(directives string) error {
	for i, line := range strings.Split(directives, "\n") {
		if len(line) > 48*1024 {
			return fmt.Errorf("渲染产物存在超过 48KiB 的单行（第 %d 行，%d 字节）——coraza 单行上限 64KiB 内会被静默截断；请改用「IP 地址列表」引用或拆分策略", i+1, len(line))
		}
	}
	return nil
}

// stage0TrustSets 汇总绑定策略中 stage0 信任名单策略的信任并集（inline ∪
// 引用去重）：detection=保留检测（trust_detection=1——经 id:12 DetectionOnly
// 全评估全记录不拦）；passthrough=直通（trust_detection=0——路由层 subroute
// 短路，零安全事件）。
func stage0TrustSets(policies []*models.SecurityPolicy) (detection, passthrough []string) {
	seenDetection, seenPassthrough := map[string]struct{}{}, map[string]struct{}{}
	for _, p := range policies {
		if p == nil || p.PolicyType != models.PolicyTypeStage0 || !p.IPWhitelistEnabled {
			continue
		}
		for _, trusted := range mergedWhitelist(p) {
			if trusted == "" {
				continue
			}
			if p.TrustDetection {
				if _, dup := seenDetection[trusted]; !dup {
					seenDetection[trusted] = struct{}{}
					detection = append(detection, trusted)
				}
			} else {
				if _, dup := seenPassthrough[trusted]; !dup {
					seenPassthrough[trusted] = struct{}{}
					passthrough = append(passthrough, trusted)
				}
			}
		}
	}
	return aggregateIPEntries(detection), aggregateIPEntries(passthrough)
}

// hasStage0TrustDetection 报告绑定策略中是否存在 stage0 信任保留检测策略
// （trust_detection=1）——id:12 的发射面 flag。始终发射收敛（2026-10-15 用户
// 裁定）：与名单内容解耦，空并集投影空文件恒发射（空集永不命中=与无规则
// 等价），空↔非空纯内容变化走热路径。
func hasStage0TrustDetection(policies []*models.SecurityPolicy) bool {
	for _, p := range policies {
		if p != nil && p.PolicyType == models.PolicyTypeStage0 && p.IPWhitelistEnabled && p.TrustDetection {
			return true
		}
	}
	return false
}

// emitBodyProcessorRules 发射 JSON/XML body processor 激活与畸形 body 守卫
// (id:9/10/11)。coraza 不按 Content-Type 自动启用 JSON/XML processor(与
// ModSecurity 连接器不同,须 ctl 显式激活),否则 body 被兜底按 URLENCODED
// 解析——JSON/XML 整串成为单个参数名:ARGS_NAMES 规则(942550/941100)在原始
// 文本上误报,ARGS 值规则对 body 失明(2026-09-09 942550 误报排查裁定)。
// 在 CRS 模式下先于 Include 发射(文档化意图;运行时 ctl 于 phase:1 全部生效,
// 先后均等价);custom_only 模式为自定义 body 规则提供解析。正则 (?i):
// Content-Type 值大小写不受控(coraza 仅小写化 header 名,SEC-REVIEW-01)。
// id:11(SEC-REVIEW-02):畸形 JSON/XML 解析失败后所有 body 集合为空且 901340
// 不再 force,CRS 4.29 无任何规则消费 REQBODY_PROCESSOR_ERROR(grep 实证)——
// 「声明 JSON + 发非法 JSON」可对全部 body 规则隐身;守卫计满临界异常分
// (阈值 5:拦截模式 949 即拦,检测模式仅记录),与 coraza ctl.go 文档建议的
// 使用者自检口径一致。
func emitBodyProcessorRules(sb *strings.Builder) {
	sb.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/(?:[\w.+-]+?\+)?json(?:\s*;|$)" "id:9,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	sb.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^(?:application|text)/(?:[\w.+-]+?\+)?xml(?:\s*;|$)" "id:10,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"` + "\n")
	sb.WriteString(`SecRule REQBODY_PROCESSOR_ERROR "@eq 1" "id:11,phase:2,pass,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'请求体解析失败'"` + "\n")
}

// geoipLocOverseas 是 X-LB-GeoIP-Loc 的海外哨兵值：caddygeoip 对解析失败/
// 库缺失/国家列非国家值（空/0/Reserved）的客户端发射此值（fail-closed 兜底；
// 域 G 起已解析海外行发射归一化国名）。
const geoipLocOverseas = "海外"

// geoipLocOperator 把策略 geoip_countries 条目编译为 REQUEST_HEADERS:X-LB-GeoIP-Loc
// 的 coraza 匹配算子。锚定正则（^(?:...)$）做全值匹配：X-LB-GeoIP-Loc 的空串形态
// （国内段省份不可解析）恒不命中（deny 模式不误伤）；allow 模式取反后空串反向
// 命中 → 拦截（fail-closed，与既有 CEL 语义逐案等价）。条目形态与
// caddygeoip 发射的 X-LB-GeoIP-Loc 同构：海外 → 字面「海外」；省 → 整省，附加
// (?:/.*)? 使省内城市段（省/市 形态）同样命中；省/市 → 精确省市联值；国名
// （域 G，第 73 轮裁定）→ 精确匹配（exactSet 含树 Countries 集时），与「海外」
// 同款不加后缀——caddygeoip 对海外行只发国名单值，精确匹配杜绝未来复合形态
// 误命中。exactSet 为空（树缺失/无国名）时国名条目退回后缀形态（(?:/.*)?
// 可选，国名单值仍命中，不放大拦截面）。
// 条目经 QuoteMeta 转义——集群同步/历史行可携带绕过校验的特殊字符，未转义会
// 注入正则元字符（ReDoS/越权匹配）。
func geoipLocOperator(countries []string, allowMode bool, exactSet map[string]bool) string {
	// F73-G 兼容补丁（2026-10-14 用户裁定）：「海外」条目语义展开——发射端
	// 改造后已解析海外行发国名，存量「禁止海外」规则的「海外」条目必须覆盖
	// 「哨兵 ∪ 树 Countries 全集」，否则已解析海外流量漏放（deny）/误拒（allow）。
	// exactSet 为空（树缺失）时仅保留哨兵（fail-safe 不产生死条目）。
	// G1+B1-7（第 74 轮）：展开集先收集后 sort.Strings 定序——exactSet map
	// 迭代序非确定，内联展开会让同 DB 视图两次渲染产出不同算子字节，
	// errSameConfig 同字节短路门失效（每次写路径真重载+预检池键漂移）；
	// 混选「海外+国名」时展开集与显式国名条目按全 alternative 去重。
	expanded := make([]string, 0, len(exactSet))
	for country := range exactSet {
		expanded = append(expanded, regexp.QuoteMeta(country))
	}
	sort.Strings(expanded)

	seen := make(map[string]bool, len(countries)+len(expanded))
	alts := make([]string, 0, len(countries)+len(expanded))
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			alts = append(alts, a)
		}
	}
	for _, entry := range countries {
		quoted := regexp.QuoteMeta(entry)
		if entry == geoipLocOverseas {
			add(quoted)
			for _, alt := range expanded {
				add(alt)
			}
			continue
		}
		if strings.Contains(entry, "/") || exactSet[entry] {
			add(quoted)
			continue
		}
		add(quoted + "(?:/.*)?")
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
	customRuleTargets   = map[string]string{"uri": "REQUEST_URI", "args": "ARGS", "body": "REQUEST_BODY|ARGS_POST|ARGS_POST_NAMES|XML:/*|XML://@*", "headers": "REQUEST_HEADERS", "user_agent": "REQUEST_HEADERS:User-Agent"}
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

func emitCustomRules(sb *strings.Builder, customRules []models.CustomRule, blockStatus int) {
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
		// SEC40-B1-2（阶段化模型收紧 890000→790000）:DB id ≥790000 经发射偏移
		// +10000 后撞入 GeoIP 预检段(800000-899999,geoipPrecheckRuleBase 起)——
		// 同 id 冲突会使整份 coraza 配置编译失败;≥890000 仍撞 CRS 保留段
		// (900000+)。发射侧跳过并告警(镜像上方坏规则兜底同款)。
		if cr.ID >= 790000 {
			Logf("warn", "自定义规则 %d(%s) 发射 id 将撞入 GeoIP 预检段/CRS 保留空间，已跳过发射", cr.ID, cr.Name)
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
			// 拦截统一经 errors.routes 渲染拦截页：blockStatus>0（策略分得合成
			// 中断码）时显式抬码归因到本策略，==0 保持缺省 403（回归形状）。
			denyStatus := ""
			if blockStatus > 0 {
				denyStatus = fmt.Sprintf(",status:%d", blockStatus)
			}
			action = fmt.Sprintf("deny%s,log,%s,msg:'自定义规则 %s 命中',skipAfter:SECURITY_RULES_END", denyStatus, scoreVar, safeName)
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
// control, mirroring the emission condition in BuildCorazaDirectives. 始终发射
// 收敛（2026-10-15）：deny·bypass ACL 的开启 flag 即发射面（空名单恒发射空
// 文件算子，永不命中=与无规则等价），镜像与内容解耦；信任名单（ip_whitelist_
// enabled 表默认值=1 非刻意 opt-in）、allow 模式（否定算子）与遗留黑名单
// 维持内容门控。Referenced IP lists count the same as inline entries
// (refs-only policies still advertise IP control)——仅解析 refs JSON 本身，
// 无需加载数据库（摘要/绑定路径与生成路径同判定）。
func SecurityPolicyHasIPControl(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	var ipWL []string
	json.Unmarshal(p.IPWhitelist, &ipWL)
	if p.IPWhitelistEnabled && len(ipWL) > 0 {
		return true
	}
	if p.IPWhitelistEnabled && ipListRefsNonEmpty(p.IPWhitelistRefs) {
		return true
	}
	if p.IPACLEnabled && p.IPACLMode != "allow" {
		return true
	}
	var ipACLList []string
	json.Unmarshal([]byte(p.IPACLList), &ipACLList)
	if p.IPACLEnabled && (len(ipACLList) > 0 || ipListRefsNonEmpty(p.IPACLListRefs)) {
		return true
	}
	var ipBL []string
	json.Unmarshal(p.IPBlacklist, &ipBL)
	return len(ipBL) > 0
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
// stage0DetectionTrust 契约（始终发射收敛，2026-10-15）：nil=无 stage0 保留
// 检测策略（不发射 id:12）；非 nil（可空切片）=存在——恒发射 id:12（空集
// 文件算子永不命中=与无规则等价，空↔非空纯内容变化走热路径）。
func buildWafHandlerWithPolicy(ruleCaddyID string, policy *models.SecurityPolicy, store caddyConfigStore, crsFp string, multiPolicy bool, blockStatus int, bodyLimitMB int, stage0DetectionTrust []string) (map[string]interface{}, error) {
	if policy == nil {
		return nil, nil
	}
	var directives string
	var err error
	if stage0DetectionTrust == nil {
		directives, err = BuildCorazaDirectives(policy, store, crsFp, multiPolicy, blockStatus, ruleCaddyID)
	} else {
		directives, err = BuildCorazaDirectives(policy, store, crsFp, multiPolicy, blockStatus, ruleCaddyID, stage0DetectionTrust)
	}
	if err != nil {
		return nil, err
	}
	if directives == "" {
		return nil, nil
	}
	// R4-Render-1/2(第 4 轮审计):coraza 默认 RequestBodyLimit=128MiB,
	// 用户限额>128MiB 时 WAF 活跃规则 body 在 128MiB 处被拦(用户限额不可达);
	// 413 语义被 coraza-caddy 压平为 500。D40-2-1:WAF 活跃恒发射
	// SecRequestBodyLimit(有效值经 resolveRuleOverrides 归一恒>0,
	// min(用户值,1GiB) 与 coraza Validate 上限对齐)。
	if bodyLimitMB > 0 {
		limitBytes := int64(bodyLimitMB) * 1024 * 1024
		const corazaMax = int64(1073741824) // 1GiB
		if limitBytes > corazaMax {
			limitBytes = corazaMax
		}
		directives += fmt.Sprintf("SecRequestBodyLimit %d\n", limitBytes)
	}
	return map[string]interface{}{
		"handler":    "waf",
		"directives": directives,
	}, nil
}

// ipPrecheckAllowRuleID 是多策略 IP 预检中 allow 模式（白名单交集外拒绝）规则
// 的 SecRule id。本地 id 空间：2=ACL deny、3=bypass/trust、4=遗留黑名单、5=trust
// （bypass 占 3 时）、6=DetectionOnly 切换、8=GeoIP 地域拦截（BuildCorazaDirectives
// 内，不在预检）、900=异常分阈值；7 专用于预检 allow 规则（预检内 deny 并集沿用
// id:2、黑名单并集沿用 id:4，保持 security events 归因口径；allow 模式事件本就
// 回退归到首启用策略，id:7 不改变归因结果）。
const ipPrecheckAllowRuleID = 7

// ipPrecheckAllowExemptRuleID 是 allow 白名单命中豁免规则（第 58 轮用户裁定）：
// allow 交集命中的 IP 以 pass+nolog+skipAfter 跳过后续 GeoIP 逐策略链——白名单
// 作为「VIP 豁免」语义；显式 deny（id:2/4）先于本规则评估，命中照常拦截。
// nolog：豁免本身不产生安全事件。无 allow 名单时不发射（避免恒真跳过）。
const ipPrecheckAllowExemptRuleID = 13

// geoipPrecheckRuleBase 是 GeoIP 预检链的 SecRule id 段基址（阶段化执行模型：
// GeoIP 从策略引擎 id:8 迁入阶段 1 合并预检）。逐策略链 id=800000+policyID——
// 事件归因从共享 id:8（「首个 geoip 启用策略」非精确）精确化为直接解码属主
// （securityEventsPolicyContainsRule 800xxx case）。emitCustomRules 发射守卫
// （DB id ≥790000 跳过）保证自定义规则 emit id（DB id+10000）不撞入本段。
const geoipPrecheckRuleBase = 800000

const (
	geoipCrawlerRuleBase      = 810000 // 爬虫豁免规则基址（+policyID*16+引擎序号）
	geoipCrawlerSpoofRuleBase = 850000 // 爬虫伪装事件规则基址（+policyID）
)

// IsGeoIPPrecheckID 报告 n 是否落在阶段 1 GeoIP 预检归因段
// [geoipPrecheckRuleBase, geoipPrecheckRuleBase+100000)。段界单一事实源——
// 事件归因、stage-stats 分桶、筛选族条件等消费方一律经本谓词取段界,
// 禁止各自复写字面量(U2-1:字面量散布六处,段基址调整时漏改即静默分叉)。
func IsGeoIPPrecheckID(n int) bool {
	return n >= geoipPrecheckRuleBase && n < geoipPrecheckRuleBase+100000
}

// IsStage1PrecheckID 判定事件触发 id 是否属阶段 1 预检族（第 59 轮 R59-P5
// 收敛：{2,4,7,8,14} 五元组此前在 services 谓词与 handlers/security_overview
// 两处独立字面量维护——阶段 1 新增预检 id 时两处漏改即分叉。单一事实源在此，
// 消费方改调本函数）。
func IsStage1PrecheckID(n int) bool {
	switch n {
	case 2, 4, 7, 8, 14:
		return true
	}
	return IsGeoIPPrecheckID(n)
}

// Stage1PrecheckIDSQLList 是预检段固定规则 ID 的 SQL 字面量清单（8 项）——
// 与 IsStage1PrecheckID 同文件维护（R73 LBH-F8：原居 securityevents.go，
// 与 Go 谓词分居两文件，阶段 1 新增预检 id 时易漏改）。3/5/12 为防御性包含
// ——当前 nolog pass 不产事件（第 62 轮 F62-40 三处字面量收敛沿用）。
const Stage1PrecheckIDSQLList = "('2','3','4','5','7','8','12','14')"

// Stage1PrecheckSegmentSQL 是阶段 1 预检段（IP 访问控制/威胁情报库/地域拦截）
// 事件归因的完整 SQL 谓词单一事实源——rule_triggered（文本 id）落在本段即
// 阶段 1：固定 ID 清单 Stage1PrecheckIDSQLList ∪ GeoIP 预检归因段
// [geoipPrecheckRuleBase, +100000) 的 6 位文本形态（8 开头 6 位）。
// 消费方：handlers.GetRuleStageStats 分段耗时归因（第 73 轮 LBH-F8 收敛：原
// 内联 "IN %s OR (LENGTH=6 AND LIKE '8%%')" 与 ID 清单分居两文件两处字面量）。
// 与 IsStage1PrecheckID 同文件维护，一致性由 security_stage1_segment_test.go 钉死。
const Stage1PrecheckSegmentSQL = "rule_triggered IN " + Stage1PrecheckIDSQLList +
	" OR (LENGTH(rule_triggered)=6 AND rule_triggered LIKE '8%')"

// intersectIPLists 返回多组 IP/CIDR 名单的网络感知交集（裁定 2026-09-07 S2）：
// 对每对条目判断 CIDR 包含关系，保留更具体的一方（10.0.0.0/8 ∩ 10.1.0.5
// = 10.1.0.5）。字符串精确匹配兼容（相同文本=同网络）。空交集返回 nil。
func intersectIPLists(lists [][]string) []string {
	if len(lists) == 0 {
		return nil
	}
	// F62-20(第 62 轮):预解析缓存——原实现每对条目都重新 ParseCIDR/ParseIP,
	// 64 份满额 allow 名单最坏 ~1575 万次解析;缓存后每唯一条目只解析一次。
	cache := make(map[string]*parsedEntry, 512)
	candidate := make(map[string]struct{}, len(lists[0]))
	for _, entry := range lists[0] {
		if entry != "" {
			candidate[entry] = struct{}{}
		}
	}
	for _, rest := range lists[1:] {
		next := make(map[string]struct{}, len(candidate))
		for outer := range candidate {
			for _, inner := range rest {
				if inner == "" {
					continue
				}
				if hit := cidrIntersectParsed(parseEntryCached(outer, cache), parseEntryCached(inner, cache)); hit != "" {
					next[hit] = struct{}{}
				}
			}
		}
		candidate = next
		if len(candidate) == 0 {
			return nil
		}
	}
	// CIDR 感知交集的结果可能来自任意列表（更具体的一方），不能仅从 lists[0]
	// 过滤——直接收集 candidate 并排序保证确定性。
	intersection := make([]string, 0, len(candidate))
	for entry := range candidate {
		intersection = append(intersection, entry)
	}
	sort.Strings(intersection)
	return intersection
}

// parsedEntry 是 IP/CIDR 条目的一次解析结果(F62-20 预解析缓存条目)。
type parsedEntry struct {
	raw   string     // 原始条目串(交集结果须返回原始形态)
	ip    net.IP     // 非 nil = 纯 IP 条目
	net   *net.IPNet // 非 nil = CIDR 条目
	ones  int        // CIDR 掩码长度
	valid bool       // 合法条目(IP 或 CIDR)
}

// parseEntryCached 带缓存解析(同一条目在整次交集内只解析一次)。
func parseEntryCached(s string, cache map[string]*parsedEntry) *parsedEntry {
	if p, ok := cache[s]; ok {
		return p
	}
	p := &parsedEntry{raw: s}
	if ip := net.ParseIP(s); ip != nil {
		p.ip = ip
		p.valid = true
	} else if _, ipnet, err := net.ParseCIDR(s); err == nil {
		p.net = ipnet
		p.ones, _ = ipnet.Mask.Size()
		p.valid = true
	}
	cache[s] = p
	return p
}

// cidrIntersectParsed 判断两个预解析 IP/CIDR 条目的网络包含关系，返回更具体
// 一方（SEC-D1 第 69 轮起为唯一实现——旧字符串入参变体 cidrIntersectEntry 在
// F62-20 预解析缓存改造后生产零调用，已删除，语义钉迁至 cidrIntersectParsed）。
// a 保留原串供返回（交集结果须是原始字符串形态）。
func cidrIntersectParsed(pa, b *parsedEntry) string {
	if !pa.valid || !b.valid {
		return ""
	}
	// 字面相等且合法（R59-P3 合法性门同口径：bad 条目字面相等不得顶出交集）
	if pa.raw == b.raw {
		return pa.raw
	}
	if pa.net != nil && b.net != nil {
		if pa.net.Contains(b.net.IP) && pa.ones <= b.ones {
			return b.raw
		}
		if b.net.Contains(pa.net.IP) && b.ones <= pa.ones {
			return pa.raw
		}
		return ""
	}
	if pa.net != nil && b.ip != nil {
		if pa.net.Contains(b.ip) {
			return b.raw
		}
		return ""
	}
	if pa.ip != nil && b.net != nil {
		if b.net.Contains(pa.ip) {
			return pa.raw
		}
		return ""
	}
	return ""
}

// precheckProjectionScope 把规则身份编入预检/引擎层 u-* 投影 scope（第 76 轮
// HP-1）：scope 形态 u-<kind>-<ruleCaddyID>（如 u-deny-lb_2r8dosptk1）——投影
// 实例身份=调用方规则，异策略集多规则各得独立文件（互不覆盖）。kind 取
// deny/trust/trust12/bl/allow/allow-exempt。空 ruleCaddyID 由两个渲染入口
// （buildIPPrecheckDirectives/BuildCorazaDirectives）统一显性报错（fail-loud
// ——静默退回全局名会原样重建覆盖冲突），本 helper 纯拼接。
func precheckProjectionScope(kind, ruleCaddyID string) string {
	return "u-" + kind + "-" + ruleCaddyID
}

// buildIPPrecheckDirectives 合并全部绑定启用策略的 deny 侧 IP 控制（deny 模式
// ACL 并集 id:2、allow 模式 ACL 交集外拒绝 id:7、遗留黑名单并集 id:4）与逐策略
// GeoIP 链（800000+policyID）为一个极简 coraza 配置（阶段 1）。预检查器置于
// 处理器链最前（先于全部 rate_limit/waf）：被拒 IP/区域在任何策略的 CRS/自定义
// 规则评估前即中断——修复 `[coraza_P1, coraza_P2]` 链中 P1 的 CRS 先评估产生
// 检测事件、P2 的 IP ACL 才拦截的双重检测问题（IP ACL 最高优先级）。预检仍是
// coraza 拒绝：audit log 留痕供安全事件管线归因（id:2/id:4 归因口径不变）。
// 2026-09-15 用户裁定:信任最高优先——预检信任 ctl:ruleEngine=
// DetectionOnly 先行(id:3,取代「deny 优先于信任」与「并入 allow 放行集」),
// 信任 IP 经 DetectionOnly 后 deny/黑名单/GeoIP 全评估不拦但全记录;跨策略
// 边界=信任仅豁免所属策略(其他策略引用同一信任地址列表即可);限流仍生效。
// 归因边界（拦截页按触发策略归因）：预检是多策略**合并**段，deny 无法归因
// 到单策略，故 denyStatus=0 时保持 status:403 不抬码——其中断落首绑定有页
// 策略的 403 兜底错误路由（buildBlockPageErrorRoute）；规则配了阶段 1 拦截页
// 时调用方传 denyStatus=481，全部 deny 抬码落 481 阶段路由（阶段化模型）。
// 无 deny 侧控制且无 GeoIP 策略时返回空串（不发射）。
//
// ruleCaddyID（第 76 轮 HP-1）：本函数逐规则渲染（policiesForRule——每条规则
// 的绑定策略集不同，u-* 并集内容是调用方规则的函数），u-* 投影 scope 必须编入
// 规则身份（u-deny-<ruleCaddyID> 等）；全局单文件名下异策略集多规则的后渲染
// 会覆盖前者=漏拦+误拦（热路径稳定命名粒度教训的预检形态）。空值显性报错
// （fail-loud，禁止静默退回全局名重建冲突）。爆炸半径=整份配置被拒——HP77-3
// （第 77 轮）已裁定维持 fail-loud 不收窄（跳过+告警=IP 控制面静默缺失，
// fail-closed 整拒更安全），载体见 BuildCorazaDirectives 同名注释。
func buildIPPrecheckDirectives(policies []*models.SecurityPolicy, denyStatus int, ruleCaddyID string) (string, error) {
	if ruleCaddyID == "" {
		return "", fmt.Errorf("u-* 预检投影缺少规则身份（ruleCaddyID 为空）——预检逐规则渲染，scope 必须编入规则身份（第 76 轮 HP-1）")
	}
	var denyUnion, blacklistUnion []string
	var allowLists [][]string
	// 始终发射收敛（2026-10-15 用户裁定）：deny ACL 开启即计入发射面（并集可
	// 空=空文件算子永不命中，空↔非空纯内容变化走热路径）；allow 为否定算子
	//（空集=恒命中=全拒，语义不等价）维持内容门控；黑名单为内联字段维持
	// 内容门控。
	hasDenyACL := false
	for _, p := range policies {
		if p == nil {
			continue
		}
		aclList := mergedACLList(p)
		if p.IPACLEnabled {
			switch p.IPACLMode {
			case "deny":
				hasDenyACL = true
				if len(aclList) > 0 {
					denyUnion = append(denyUnion, aclList...)
				}
			case "allow":
				if len(aclList) > 0 {
					allowLists = append(allowLists, aclList)
				}
			}
		}
		var blacklist []string
		json.Unmarshal(p.IPBlacklist, &blacklist)
		blacklistUnion = append(blacklistUnion, blacklist...)
	}
	hasGeoIP := false
	for _, p := range policies {
		if PolicyHasGeoIP(p) {
			hasGeoIP = true
			break
		}
	}
	detectionTrust, _ := stage0TrustSets(policies)
	hasStage0Detection := hasStage0TrustDetection(policies)
	// 早退条件以发射面 flag/内容表达：deny ACL 收敛到 flag（始终发射，
	// 2026-10-15）；stage0 保留检测收敛到 flag（空并集恒发射 id:12）；信任
	// 并集维持内容门控（ip_whitelist_enabled 表默认值=1 非刻意 opt-in，flag
	// 门控会使全部默认站点凭空获得预检，门禁钉测实证）。
	if !hasDenyACL && len(blacklistUnion) == 0 && len(allowLists) == 0 && !hasGeoIP && !hasStage0Detection && len(detectionTrust) == 0 {
		return "", nil
	}
	var sb strings.Builder
	sb.WriteString("SecRuleEngine On\n")
	// 预检仅含 phase:1 的 REMOTE_ADDR 规则，无需请求体/响应体访问。
	sb.WriteString("SecRequestBodyAccess Off\n")
	sb.WriteString("SecResponseBodyAccess Off\n")
	// 与 BuildCorazaDirectives 同款审计配置：IP 拒绝事件经 audit log 进入
	// 安全事件管线（ RelevantOnly + deny 中断 = relevant）；写插件同 lbfile
	// （第 76 轮侧车退役，耗时注入审计行——见 BuildCorazaDirectives 的 lbfile
	// 注释）。
	sb.WriteString(fmt.Sprintf("SecAuditEngine RelevantOnly\nSecAuditLog %s\nSecAuditLogType lbfile\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHKZ\n", auditLogPath))
	// 2026-09-15 用户裁定:信任最高优先(任何规则不拦)+检测事件全记录——
	// 预检层信任改 ctl:ruleEngine=DetectionOnly 先行(取代 S1 的「并入 allow
	// 放行集」):信任 IP 经 DetectionOnly 后,deny/黑名单/GeoIP/CRS 全评估
	// 不拦但全记录(动作=检测);并入 allow 会使信任 IP 根本不触发规则=
	// 无检测事件,与新语义(可见放行)冲突。
	var trustUnion []string
	for _, p := range policies {
		// stage0 策略的信任不进 id:3 并集——直通（trust_detection=0）由路由层
		// subroute 短路、保留检测由下方 id:12 承载；mixed 存量信任维持 id:3 并集。
		if p == nil || p.PolicyType == models.PolicyTypeStage0 || !p.IPWhitelistEnabled {
			continue
		}
		for _, trusted := range mergedWhitelist(p) {
			if trusted != "" {
				trustUnion = append(trustUnion, trusted)
			}
		}
	}
	// 信任并集维持内容门控（不收敛，2026-10-15：ip_whitelist_enabled 表默认
	// 值=1 非刻意 opt-in，flag 门控会使全部默认站点凭空获得预检 id:3——门禁
	// 钉测实证；空↔非空仍走全量链）。
	if len(trustUnion) > 0 {
		operand, err := ipListRuleOperand(precheckProjectionScope("trust", ruleCaddyID), trustUnion, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", operand))
	}
	// 阶段 0 保留检测（trust_detection=1）：预检同形 id:12 DetectionOnly——
	// 与策略引擎的 id:12 同集（各自 coraza 事务独立生效）。发射面 flag 与内容
	// 解耦（始终发射收敛，2026-10-15）：空并集投影空文件恒发射。
	if hasStage0Detection {
		operand, err := ipListRuleOperand(precheckProjectionScope("trust12", ruleCaddyID), detectionTrust, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", operand))
	}

	// denyStatus<=0 归一 403（兜底归因边界）；>0（阶段 1 页已配=481）全部 deny
	// 显式抬码落 481 阶段路由。
	if denyStatus <= 0 {
		denyStatus = 403
	}
	if hasDenyACL {
		operand, err := ipListRuleOperand(precheckProjectionScope("deny", ruleCaddyID), denyUnion, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:2,phase:1,deny,status:%d,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END\"\n", operand, denyStatus))
	}
	if len(blacklistUnion) > 0 {
		operand, err := ipListRuleOperand(precheckProjectionScope("bl", ruleCaddyID), blacklistUnion, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:4,phase:1,deny,status:%d,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END\"\n", operand, denyStatus))
	}
	var allowIntersection []string
	// allow 交集外拒绝（id:7，第 59 轮 R59-P5 后移）：置于 deny 并集/黑名单之后
	// ——同在 deny 名单与 allow 交集外的 IP 先被 id:2/4 拒绝，事件归因「IP 黑名单
	// 拒绝」（deny 侧精确语义）；id:7 只对「未被显式 deny 且不在 allow 交集」的
	// IP 生效。拦截结果与既有语义等价（同 deny+status+skipAfter）。
	if len(allowLists) > 0 {
		allowIntersection = aggregateIPEntries(intersectIPLists(allowLists))
		// 多条 allow 名单互不相交（交集为空）= 逐策略顺序评估下任意 IP 都会被
		// 某个名单拒绝：恒拒规则等价表达（REMOTE_ADDR 恒非空）。
		if len(allowIntersection) == 0 {
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"@rx .*\" \"id:%d,phase:1,deny,status:%d,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END\"\n", ipPrecheckAllowRuleID, denyStatus))
		} else {
			operand, err := ipListRuleOperand(precheckProjectionScope("allow", ruleCaddyID), allowIntersection, true)
			if err != nil {
				return "", err
			}
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:%d,phase:1,deny,status:%d,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END\"\n", operand, ipPrecheckAllowRuleID, denyStatus))
		}
	}
	// allow 白名单豁免（第 58 轮用户裁定）：交集命中 = pass + 跳过后续 GeoIP
	// 逐策略链（VIP 豁免语义）。置于 deny/blacklist 之后——显式 deny 命中照常
	// 拦截（其 skipAfter 先行短路，豁免规则不参与评估）；置于 GeoIP 链之前——
	// 白名单成员不再被区域拦截。交集为空（恒拒形态）时无成员可豁免，不发射。
	if len(allowIntersection) > 0 {
		operand, err := ipListRuleOperand(precheckProjectionScope("allow-exempt", ruleCaddyID), allowIntersection, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:%d,phase:1,pass,nolog,skipAfter:SECURITY_RULES_END\"\n", operand, ipPrecheckAllowExemptRuleID))
	}
	// 逐策略 GeoIP 链（阶段 1：GeoIP 自策略引擎 id:8 迁入预检，id=800000+policyID
	// 精确归因段）。链首 deny+skipAfter+chain（disruptive 动作仅允许链首段，
	// SECLB33-1），续段 X-LB-GeoIP-Loc 匹配策略 geoip_countries（caddygeoip pass
	// route 先于本预检设置该头）；策略有启用信任名单时追加第三续段——预检信任∪
	// DetectionOnly 是事务级全局的（2026-09-20 用户裁定：信任 IP 对全部策略的
	// GeoIP 全局放行，取代旧引擎层「跨策略信任不豁免」边界），此续段仅抑制
	// 本策略链对自有信任 IP 的自欺事件。R48-SEC-1（第 48 轮审计）：在 id:3
	// （非 stage0 信任并集）/id:12（stage0 保留检测）已把信任 IP 的事务级引擎
	// 切为 DetectionOnly 的前提下，该续段对判定结果不产生差异（信任 IP 本就不
	// 拦）——属防御性冗余，保留为纵深层；删除它同样安全，但若未来收窄
	// DetectionOnly 的适用范围，此续段是唯一的链内自抑制，勿视作死代码清理。
	// denyStatus=403（阶段 1 页未配）时不带
	// status：默认 403 → 403 兜底错误路由（跟随策略的默认层，回归形状）；
	// =481 时链首显式抬码（disruptive 动作仅允许链首段，SECLB33-1）。
	geoipStatusFragment := ""
	if denyStatus != 403 {
		geoipStatusFragment = fmt.Sprintf(",status:%d", denyStatus)
	}
	// 域 G（第 73 轮）：国名条目精确匹配集——树 Countries（live 优先、缓存
	// 兜底，与 ValidateGeoIPCountries 同源）；树缺失（无库且无缓存）时空集，
	// 国名条目退回后缀形态（geoipLocOperator 注释）。单次取树供全部策略链
	// 复用（N+13 H2-F1 同款：避免循环内重复全量扫描；树扫描本身有 memo）。
	geoipCountryExact := map[string]bool{}
	if tree := GetIP2RegionRegionTree(); tree != nil {
		for _, c := range tree.Countries {
			geoipCountryExact[c] = true
		}
	}
	for _, p := range policies {
		if p == nil || !PolicyHasGeoIP(p) {
			continue
		}
		// U1-3（第 45 轮审计）：policyID 过大使 800000+policyID 落入 CRS 保留段
		// （900000+）时跳过该策略链并告警（镜像 emitCustomRules ≥790000 跳过+告警
		// 先例）。危害是归因/分桶错位——securityEventsPolicyContainsRule 的 800xxx
		// case 与 stage-stats 的 800xxx 分桶都不再命中，而非编译失败（预检是独立
		// coraza 配置，段内 id 彼此唯一，无同 id 冲突）。
		if geoipPrecheckRuleBase+p.ID >= 900000 {
			Logf("warn", "策略 %d 的 GeoIP 预检链 id %d 将撞入 CRS 保留段，已跳过发射", p.ID, geoipPrecheckRuleBase+p.ID)
			continue
		}
		// v2.3.8 爬虫豁免（用户裁定方案 B）：已验证爬虫（caddygeoip handler 双跳
		// PTR/官方 IP 段验证后注入 X-LB-Crawler-Verified=引擎 ID）逐引擎放行——
		// ctl 移除本策略 GeoIP 链；伪装（UA 声称引擎但验证失败，handler 置
		// X-LB-Crawler-Spoof=1）独立事件族显式拒绝。规则 id=810000+policyID*16+
		// 引擎序号（超 900000 CRS 保留段跳过+告警，镜像 800xxx 家族先例）。
		if p.GeoIPCrawlerExempt {
			for i, engine := range geoipnames.CrawlerEngines() {
				if !crawlerEngineSelected(p, engine.ID) {
					continue
				}
				crawlerRuleID := geoipCrawlerRuleBase + p.ID*16 + i
				if crawlerRuleID >= 900000 {
					Logf("warn", "策略 %d 的爬虫豁免规则 id %d 将撞入 CRS 保留段，已跳过发射", p.ID, crawlerRuleID)
					continue
				}
				sb.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:X-LB-Crawler-Verified \"@streq %s\" \"id:%d,phase:1,pass,log,msg:'搜索引擎爬虫放行（已验证）',ctl:ruleRemoveById=%d\"\n", engine.ID, crawlerRuleID, geoipPrecheckRuleBase+p.ID))
			}
			spoofRuleID := geoipCrawlerSpoofRuleBase + p.ID
			if spoofRuleID < 900000 {
				sb.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:X-LB-Crawler-Spoof \"@eq 1\" \"id:%d,phase:1,deny%s,log,msg:'搜索引擎爬虫伪装（PTR 验证失败）',skipAfter:SECURITY_RULES_END\"\n", spoofRuleID, geoipStatusFragment))
			}
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:%d,phase:1,deny%s,log,msg:'GeoIP 区域拦截',skipAfter:SECURITY_RULES_END,chain\"\n", strings.Join(geoipPrivateRanges, ","), geoipPrecheckRuleBase+p.ID, geoipStatusFragment))
		sb.WriteString(fmt.Sprintf(" SecRule REQUEST_HEADERS:X-LB-GeoIP-Loc \"%s\" \"t:none\"\n", escapeCorazaPattern(geoipLocOperator(geoipCountries(p), p.GeoIPMode == "allow", geoipCountryExact))))
		if p.IPWhitelistEnabled {
			// 信任维持内容门控（不收敛，2026-10-15：ip_whitelist_enabled 表
			// 默认值=1 非刻意 opt-in，flag 门控会使每条 GeoIP 链凭空获得恒真
			// 续段——门禁钉测实证）。
			if trusted := mergedWhitelist(p); len(trusted) > 0 {
				operand, err := ipListRuleOperand(fmt.Sprintf("p%d-trust", p.ID), trusted, true)
				if err != nil {
					return "", err
				}
				sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"t:none\"\n", operand))
			}
		}
	}
	sb.WriteString("SecMarker SECURITY_RULES_END\n")
	if err := assertDirectiveLines(sb.String()); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// buildIPPrecheckHandler returns the consolidated stage-1 precheck coraza handler
func buildIPPrecheckHandler(policies []*models.SecurityPolicy, denyStatus int, ruleCaddyID string) (map[string]interface{}, error) {
	directives, err := buildIPPrecheckDirectives(policies, denyStatus, ruleCaddyID)
	if err != nil {
		return nil, err
	}
	if directives == "" {
		return nil, nil
	}
	return map[string]interface{}{
		"handler":    "waf",
		"directives": directives,
	}, nil
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
		seenIDs := make(map[int]struct{}, len(ids))
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
				// SLB12-P3-5:跨 500 分块重复引用查重——同 ID 双 SecRule 会被
				// coraza 编译拒绝,毒化策略无法落库。
				// SEC25-5(第 25 轮审计):O(m²) 线性扫→map 判重(queriedIDs
				// 是「已查」集,入列判重需独立 seen 集)。
				if _, dup := seenIDs[cr.ID]; dup {
					continue
				}
				seenIDs[cr.ID] = struct{}{}
				json.Unmarshal([]byte(conditionsJSON), &cr.Conditions)
				rules = append(rules, cr)
			}
			// SR18-1(第 18 轮):迭代错误检查——与同函数 Round 34 G 口径一致,
			// 迭代中途失败静默截断自定义规则会致 WAF 削弱无留痕。
			if rerr := rows.Err(); rerr != nil {
				Logf("warn", "解析策略自定义规则迭代失败（本块可能被截断）: %v", rerr)
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
// 引用悬空时不发射空匹配）；target 经 expandCRSScopedExclusionTargets 展开
// 为逐 ID（ctl:ruleRemoveById 不支持区间），每 ID 一条 phase:1 运行时 ctl 规则。
// emitScopedCRSExclusions 发射作用域限定 ctl 规则。store 非-nil 时经其解析列表引用
// （v2 导入事务视图——A-I1 不变式，审计 U1-F3）；nil 回退 db.DB（测试/直调路径）。
// chainIndex 为链级惰性索引取值闭包（M4）——单次 BuildCorazaDirectives 内与其他
// 消费点共享一次缓存键计算。
//
// 第 76 轮 SEC-1：匹配集不再内联 @ipMatch 展开——引用名单是大名单时单行撞
// 48KiB 护栏（assertDirectiveLines 拒绝=整份配置无法保存），且与「策略名单
// 统一投影 @ipListFast」的架构总述矛盾。改投影 @ipListFast（同族单源
// writeIPListFile/ipListRuleOperand：稳定命名、原子写、同字节跳写、写失败沿
// 渲染链路上报）。投影 scope 按匹配集**组合键哈希**编入（p<policyID>-crsxc-<sha256[:12]>，
// 第 77 轮 HP77-4 由「组合首次出现序 n」改哈希：序号是位置身份，条目增删/
// 重排使 seq 重编号→旧文件名承载另一条目的匹配集（正常路径字节变化走
// Fallback 自愈仅毫秒窗，与 HP77-1 拒绝不回滚叠加才持续）；组合键=ips 字面+
// 排序后 listRefs，同名必同键、异键必异名，键不变则文件名稳定（名单条目
// 内容变化热路径原位重写，@ipListFast ≤1s stat 热感知），键变化才换名（旧
// 文件由 24h GC 回收）。同组合多条目共享一份投影（配置字节恒定）。
func emitScopedCRSExclusions(sb *strings.Builder, p *models.SecurityPolicy, entries []CRSExcludedEntry, store caddyConfigStore, chainIndex func() *CRSRuleIndex) error {
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
	listsByID, _, err := loadIPListEntriesVia(store, refIDs)
	if err != nil {
		Logf("warn", "解析作用域排除引用的 IP 列表失败（策略 %q）: %v", p.Name, err)
		listsByID = map[int64][]string{}
	}
	index := chainIndex() // 复审：M4 惰性化漏改，改用链级一次取值
	seq := 0
	operandByMatchKey := make(map[string]string)
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
		// 组合键与解析内容无关（名单条目变化不换名）——ips 字面 + 排序后
		// listRefs；同组合条目共享一份投影文件。scope=组合键 sha256[:12]
		//（HP77-4：位置序号改内容身份——同名必同键，重排/增删不使旧名承载
		// 他条目匹配集）。
		sortedRefs := append([]int64(nil), entry.ListRefs...)
		sort.Slice(sortedRefs, func(i, j int) bool { return sortedRefs[i] < sortedRefs[j] })
		matchKey := entry.IPs + "\x00" + fmt.Sprint(sortedRefs)
		operand, ok := operandByMatchKey[matchKey]
		if !ok {
			keySum := sha256.Sum256([]byte(matchKey))
			var err error
			operand, err = ipListRuleOperand(fmt.Sprintf("p%d-crsxc-%s", p.ID, hex.EncodeToString(keySum[:])[:12]), match, false)
			if err != nil {
				return err
			}
			operandByMatchKey[matchKey] = operand
		}
		for _, id := range expandCRSScopedExclusionTargets(entry.Target, index, p) {
			seq++
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%s\"\n",
				operand, crsScopedExclusionIDBase+seq, id))
		}
	}
	return nil
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
// ip2region 已加载（live 或缓存）时条目必须属于已知省份、"海外"或海外国家集
// （域 G：树 Countries 并入 known），未知条目在发射端永不匹配，会静默削弱地域
// 控制。ip2region 未加载且无缓存时同样拒绝未知条目（fail-closed）：启动期放行
// 任意省份会让 deny 模式的地域拦截静默失效，提示未加载而非放行。
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
		// 域 G（第 73 轮）：海外国家并入 known 集——国名条目与省份条目同校验
		// 口径（未知国名在发射端永不匹配，静默削弱地域控制）。
		for _, c := range tree.Countries {
			known[c] = true
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
			return fmt.Errorf("geoip_countries 包含未知省份或国家：%q", trimmed)
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

// crawlerEngineSelected（v2.3.8 爬虫豁免）：策略勾选引擎集合判定——空集视为
// 全部引擎（向后兼容豁免开启但未存 engines 的形态）。
func crawlerEngineSelected(p *models.SecurityPolicy, engineID string) bool {
	var engines []string
	if err := json.Unmarshal(p.GeoIPCrawlerEngines, &engines); err != nil || len(engines) == 0 {
		return true
	}
	for _, e := range engines {
		if e == engineID {
			return true
		}
	}
	return false
}
