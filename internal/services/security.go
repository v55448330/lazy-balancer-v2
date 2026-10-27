package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lazy-balancer-v2/geoipnames"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// crsDirectivesDir is a test seam (mirroring crsLiveDir in crsupdate.go);
// emitted Include directives always use the container path.
var crsDirectivesDir = defaultCRSLiveDir

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
		if !errors.Is(err, sql.ErrNoRows) {
			Logf("error", "scanSecurityPolicyByID: 读取安全策略 #%d 失败: %v", policyID, err)
		}
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
// ordered by policy_id ASC ( v2.2.0 multi-policy binding).
// 先收集 policy_id 并关闭 rows，再做逐条策略
// 加载与引用解析——旧实现在 rows 打开期间嵌套 QueryRow/批量查询，db.DB
// 连接池（上限 10）打满即互相等待永久阻塞（无 context 超时）。
func GetSecurityPoliciesForRule(ruleCaddyID string) []*models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", ruleCaddyID)
	if err != nil {
		Logf("error", "GetSecurityPoliciesForRule: 查询规则 %s 的安全策略绑定失败: %v", ruleCaddyID, err)
		return nil
	}
	var policyIDs []int
	for rows.Next() {
		var policyID int
		if err := rows.Scan(&policyID); err != nil {
			rows.Close()
			Logf("error", "GetSecurityPoliciesForRule: 扫描规则 %s 的安全策略绑定行失败: %v", ruleCaddyID, err)
			return nil
		}
		policyIDs = append(policyIDs, policyID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		Logf("error", "GetSecurityPoliciesForRule: 迭代规则 %s 的安全策略绑定失败: %v", ruleCaddyID, err)
		return nil
	}
	rows.Close()
	var policies []*models.SecurityPolicy
	for _, policyID := range policyIDs {
		// 禁用策略在策略查询处过滤（与单查的 WHERE enabled=1 同口径）。
		if p := scanSecurityPolicyByID(policyID); p != nil {
			policies = append(policies, p)
		}
	}
	// 批次引用解析：跨全部已加载策略收集列表 id，一次批量查询（预算：与策略数
	// 无关的常数一次），合并集附加到各策略的 Merged* 字段供发射端消费。
	resolvePolicyIPListRefs(policies, nil)
	// RDB 严格模式：引用的威胁库文件缺失（IPRefMissing）的策略在生产批量生成
	// 路径被跳过（loadSecurityPolicyContext），单规则路径此前不过滤——规则保存
	// 前置校验用的正是这条路径，校验通过 ≠ 生产发射形态。三处同源。
	emitted := policies[:0]
	for _, p := range policies {
		if p != nil && !p.IPRefMissing {
			emitted = append(emitted, p)
		}
	}
	return emitted
}

// geoipCountries parses the policy's geoip_countries JSON array, skipping
// blank entries. A missing or malformed payload yields nil.
// 畸形 JSON 不再静默——WARN 留痕后按无地域规则渲染。
// 不 fail-visible 的推演披露：geoip_countries 是单策略 TEXT 列，fail-visible
// 会让一份带外脏行阻断整份配置生成（全部规则重载失败），与受信代理
// 裁定同向（可用性优先+降级可见）；写侧/导入门已拒绝该形态，WARN 面向
// 带外直写/旧备份绕过残留。
func geoipCountries(p *models.SecurityPolicy) []string {
	if p == nil || len(p.GeoIPCountries) == 0 {
		return nil
	}
	var entries []string
	if err := json.Unmarshal(p.GeoIPCountries, &entries); err != nil {
		// 与同族三处（内联/引用名单、crawlerEngineSelected）同口径：60s 限流
		// 留痕——渲染按「规则×绑定策略」粒度执行，脏行存续期逐条刷 WARN 会
		// 淹没同窗口真实告警。
		msg := fmt.Sprintf("策略 %q（#%d）geoip_countries 畸形 JSON，渲染按无地域规则处理: %v", p.Name, p.ID, err)
		if auditFailureShouldLog(msg) {
			Logf("warn", "%s", msg)
		}
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
	if p == nil {
		return false
	}
	return p.GeoIPMode != "off" && len(geoipCountries(p)) > 0
}

// crsPoolFingerprint：coraza-caddy v2.5.0 的 computePoolKey()
// = hash(directives + include + crs flag)——directives 只含固定 Include 路径，
// CRS 文件替换/手动改 zz-user-overrides.conf 后池键不变，新 Caddy 配置 Provision
// 复用旧 WAF（LoadOrNew refcount++），旧规则静默继续生效直到进程重启。在
// directives 里嵌内容指纹（CRS 版本 + overrides mtime+size，每次配置生成仅
// 2 个 stat + 1 个 db 查询，远低于 tarGzDirSum 的整树遍历成本），指纹变 →
// 池键变 → 新 WAF 真正编译新规则。Coraza 把 '#' 当注释行，不影响语义。
// 覆盖边界：crs-setup.conf 与 rules/*.conf 的
// 直接手改不进池指纹（指纹只含版本行+overrides mtime/size）——标准变更链路
// （CRS 更新器/导入）必改版本行触发指纹翻转；绕过链路的手改需重启进程生效，
// 属已声明的成本权衡。
// crsPoolFingerprintForChain 是批量链构建入口的一次性指纹取值点（审计）。
func crsPoolFingerprintForChain() string {
	return crsPoolFingerprint()
}

// crsPoolFingerprintEvals 是测试可观察的指纹求值计数器：批次级缓存的钉测
// 断言同一轮全量渲染只求值一次（生产零消费，仅原子自增）。
var crsPoolFingerprintEvals atomic.Int64

func crsPoolFingerprint() string {
	crsPoolFingerprintEvals.Add(1)
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
// 执行 DB 查询+stat（审计）；空串回退自算。multiPolicy
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
// ruleCaddyID（第 6 参）：id:12 的 u-trust12 投影 scope 编入
// 规则身份（u-trust12-<ruleCaddyID>）——stage0DetectionTrust 是逐规则并集
// （policiesForRule），全局单文件名下异策略集多规则后渲染覆盖前者=信任集
// 串染。空值显性报错。
//
// （裁定，维持 fail-loud 不收窄）：空身份的爆炸半径=整份配置
// 被拒（保存失败/重载失败）。已裁定豁免不修——生产路径 ruleCaddyID 恒非空
// （两个渲染入口都由规则身份驱动），空值=数据损坏/调用错位的显性信号；收窄
// 为「跳过该规则+告警」会让受影响规则的 IP 控制面静默缺失（安全面静默缺口），
// 比整份配置拒绝（fail-closed、横幅可见）更危险。本注释即裁定载体。
type scopedCRSListResult struct {
	lists map[int64][]string
	err   error
}

type scopedCRSListCache map[string]scopedCRSListResult

// chainIndex 为 CRS 规则索引的取值函数（nil=本策略自建惰性链）。批量生成
// 路径传入生成上下文级实例：索引指纹键（ReadDir+全量 stat+版本查询）每轮
// 只算一次，而不是逐（规则×策略）一次。
func BuildCorazaDirectives(p *models.SecurityPolicy, store caddyConfigStore, crsFingerprint string, multiPolicy bool, blockStatus int, ruleCaddyID string, stage0DetectionTrust ...[]string) (string, error) {
	return buildCorazaDirectivesWithScopedCache(p, store, crsFingerprint, multiPolicy, blockStatus, ruleCaddyID, nil, stage0DetectionTrust...)
}

func buildCorazaDirectivesWithScopedCache(p *models.SecurityPolicy, store caddyConfigStore, crsFingerprint string, multiPolicy bool, blockStatus int, ruleCaddyID string, scopedCache scopedCRSListCache, stage0DetectionTrust ...[]string) (string, error) {
	var trust []string
	if len(stage0DetectionTrust) > 0 {
		trust = stage0DetectionTrust[0]
	}
	return buildCorazaDirectivesWithIndex(p, store, crsFingerprint, multiPolicy, blockStatus, ruleCaddyID, scopedCache, nil, trust)
}

// buildCorazaDirectivesWithIndex 同上，另接受生成上下文级的 CRS 规则索引取值
// 函数（nil=本策略自建惰性链）。批量路径用它避免逐（规则×策略）重算索引
// 指纹键；单规则/校验路径走上方无索引变体。
func buildCorazaDirectivesWithIndex(p *models.SecurityPolicy, store caddyConfigStore, crsFingerprint string, multiPolicy bool, blockStatus int, ruleCaddyID string, scopedCache scopedCRSListCache, chainIndex func() *CRSRuleIndex, stage0DetectionTrust []string) (string, error) {
	if ruleCaddyID == "" {
		return "", fmt.Errorf("u-trust12 引擎投影缺少规则身份（ruleCaddyID 为空）——id:12 逐规则渲染，scope 必须编入规则身份（历史 HP-1）")
	}
	// 渲染守卫（带外直写/旧快照残留）：mode 非四态枚举时下方 switch 静默落入
	// 「仅 IP 控制/空串」分支——blocking 宣称与实际零 WAF 发射漂移。写侧/导入
	// 已 400、启动归一把枚举外全集收敛为 off，此处为两窗口之间的带外脏行留痕
	// （60s 限流与同族 geoip_countries/crs_rule_groups 同口径，不 fail-visible：
	// 一行脏数据不得拖垮整份配置生成）。
	switch p.Mode {
	case "off", "custom_only", "detection", "blocking":
	default:
		msg := fmt.Sprintf("策略 %q（#%d）mode 非枚举值 %q，WAF 面按无模式渲染（疑似带外直写/旧快照，启动归一将收敛为 off）", p.Name, p.ID, p.Mode)
		if auditFailureShouldLog(msg) {
			Logf("warn", "%s", msg)
		}
	}
	var sb strings.Builder
	// 嵌 coraza 池键指纹（见 crsPoolFingerprint）——CRS 文件
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
	if err := json.Unmarshal(p.IPBlacklist, &ipBL); err != nil {
		logMalformedInlineIPList(p.ID, "ip_blacklist", err)
	}
	ipBL = aggregateIPEntries(ipBL)
	ipACLList := mergedACLList(p)

	// IP-level control (ACL / trust list / legacy 绕过 & blacklist) runs
	// independently of the WAF mode so that "关闭 WAF" never disables IP control.
	// 信任名单三态门（对齐 ip_acl_enabled/geoip_mode）：关闭保留名单零发射。
	// GeoIP 地域拦截已迁出策略引擎（阶段化模型：阶段 1 预检 800000+ 段承接），
	// 不再构成开引擎理由——纯 GeoIP 策略产空串不出 handler。stage0 信任名单
	// 策略的信任不属于本引擎（直通=路由层 subroute 短路零事件；保留检测=
	// id:12 由预检与其他策略引擎承载）——stage0 策略产空串不出 handler。
	// 始终发射收敛（2026-10-15 用户裁定）：deny·绕过 ACL 开启即算 IP 控制
	//（空名单恒发射空文件算子，永不命中=与无规则等价，空↔非空纯内容变化走
	// 热路径）。信任名单不收敛：ip_whitelist_enabled 表默认值即 1（非刻意
	// opt-in，flag 门控会使全部默认策略凭空获得引擎/信任规则——发射面膨胀，
	// 门禁钉测实证），维持内容门控；allow ACL（否定算子）与遗留黑名单同理
	// 维持内容门控（见下 ipListRuleOperand 调用点注释）。
	// 启用 allow 时即使合并后有效条目为空也必须发射
	// 否定算子（空文件 = 全不匹配 = 恒拒），覆盖备份导入、带外改库和条目
	// 自然到期三条路径；内容门只用于语义不等价的信任/黑名单/deny。
	hasNonTrustIPControl := len(ipBL) > 0 || p.IPACLEnabled
	emitTrustControl := p.IPWhitelistEnabled && p.PolicyType != models.PolicyTypeStage0 && len(ipWL) > 0
	customRules := policyCustomRulesCached(p, store)
	// 与摘要（CountEnabledCustomRules）同判据：启用 ∧ 无发射缺陷 ∧ id 不撞
	// 预检/保留段。仅判 Enabled 会把「引擎为一条永不发射的规则而开」当成
	// 有自定义规则（摘要已按 customRuleEmittable 报 false → 列表徽标少报
	// IP 控制能力，与引擎实际发射的信任规则分叉）。
	hasCustomRules := false
	for _, cr := range customRules {
		if customRuleEmittable(cr) {
			hasCustomRules = true
			break
		}
	}
	// 空转引擎收窄：信任名单本身只在已有引擎承载的形态里发射——off/custom_only
	// 且无其他发射内容（无自定义规则/ACL/黑名单）时不单为信任起引擎。
	// blocking/detection 恒有 CRS、custom_only 有自定义规则、或存在 ACL/
	// 黑名单时保留信任规则与原引擎判定。
	emitIPControl := hasNonTrustIPControl || (emitTrustControl && (p.Mode != "off" && p.Mode != "custom_only" || p.Mode == "custom_only" && hasCustomRules))

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
		// 检测模式仍保持 IP 控制与自定义规则强制生效:引擎以 On 启动,使下方的
		// IP ACL deny 规则与自定义拦截规则(在 DetectionOnly 切换之前发出)真实
		// 阻断;随后通过 phase:1 的 SecAction 仅将 CRS 规则集切换为
		// DetectionOnly(该切换在 CRS Include 之前生效),自定义拦截规则与 IP
		// ACL 不受影响,仍在检测模式下强制阻断。
		// 例外:body 目标的自定义拦截规则发射为 phase:2(REQUEST_BODY
		// 仅 phase:2 可读),而 DetectionOnly ctl 是事务级指令持续到 phase:2——
		// 该类规则在检测模式下仅记录不阻断(见 emitCustomRules 相位说明)。
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
	// + /新-3:仅存在 body 消费者时开启
	// 请求体访问——coraza-caddy v2.6.0 的 body 缓冲唯一门控是
	// RequestBodyAccess(无惰性检查)。消费者精确枚举:
	//   ① CRS(phase:2 规则集,blocking/detection);
	//   ② 自定义规则可发射的模式(custom_only)且存在已启用规则(可有 body 目标;
	//      规则启停经 finishTxApply 重渲染,收紧零滞后)。off 态停放启用规则
	//      不发射,不计入（形态在 off+停放规则形状反向回归)。
	// 历史的第三条件 log_request_body 经引擎源码验证在 mode=off 不可消费
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
	// （v2.2.3）：策略级「记录请求体」开关——开启时审计 parts 加 C，coraza
	// 在事件事务（RelevantOnly 门控）输出 transaction.request.body，摄入落库
	// request_body（64KB 截断）。请求体 access 由上方 crsActive/customActive
	// 门控决定（后:214-218 条件发射，不再恒 On）；本开关
	// （LogRequestBody）仅扩展审计输出面（加 C 段）。
	auditParts := "ABIJDEFHKZ"
	if p.LogRequestBody {
		auditParts = "ABCIJDEFHKZ"
	}
	// SecAuditLogType lbfile：审计写插件（caddygeoip auditwriter.go，xcaddy
	// 链入）——异步有界队列+bufio 批量落盘，刷盘前把进程内计时注册表的分段
	// 耗时注入审计行顶层 lb_timing 字段（侧车退役，摄取管道改读
	// 行内嵌字段）。有界背压：队列满时请求路径最多等待 2s，超时丢弃该条并
	// 计数告警（drain 沉陷不再拖住数据面；丢弃计数见 auditwriter dropped）。
	// coraza NewWAF 时 Init 打开文件（目录缺失=配置拒绝，
	// 语义不变）；轮转=copytruncate，长生命周期 fd 恒有效。
	sb.WriteString(fmt.Sprintf("SecAuditEngine RelevantOnly\nSecAuditLog %s\nSecAuditLogType lbfile\nSecAuditLogFormat JSON\nSecAuditLogParts %s\n", auditLogPath, auditParts))

	// SecRule id map: 2 = ACL allow/deny, 3 = 绕过-mode (legacy), 4 = legacy
	// blacklist, 5 = trust list, 9 = JSON body processor 激活,
	// 10 = XML body processor 激活, 11 = 请求体解析失败守卫. The trust list keeps
	// the historical id:3 unless a 绕过-mode rule already owns it.
	// 2026-09-15 用户裁定:绕过(IP ACL 绕过 模式)保持 ctl:ruleEngine=Off 短路;
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
	// 锁死风险——因此 allow 侧不设内容门（见下方无条件发射）。遗留黑名单为
	// 内联字段，仅经策略保存（全量链）变化，维持内容门控。
	// allow 内容的空集不是“无规则”：否定算子空文件=恒拒。删除内容门，
	// 让条目全部过期/备份导入空引用时仍发射 deny。
	if p.IPACLEnabled {
		operand, err := ipListRuleOperand(fmt.Sprintf("p%d-acl", p.ID), ipACLList, p.IPACLMode == "allow")
		if err != nil {
			return "", err
		}
		aclOperand = operand
		// 渲染守卫：ip_acl_mode 非三态枚举时 ACL 开关已开但下方发射 switch
		// 零规则——「已启用 IP 访问控制」静默零强制。写侧/导入 400、启动归一
		// 收敛为 deny，此处为带外脏行留痕（60s 限流，可用性优先不 fail-visible）。
		switch p.IPACLMode {
		case "allow", "deny", "绕过":
		default:
			msg := fmt.Sprintf("策略 %q（#%d）ip_acl_mode 非枚举值 %q，ACL 已启用但无规则发射（疑似带外直写/旧快照，启动归一将收敛为 deny）", p.Name, p.ID, p.IPACLMode)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
	}
	if p.IPWhitelistEnabled && len(ipWL) > 0 {
		operand, err := ipListRuleOperand(trustScope, ipWL, false)
		if err != nil {
			return "", err
		}
		trustOperand = operand
		negTrustOperand = "!" + operand
	}
	// 发射序（绕过优先于信任的终态保证）：coraza ctl 同相位后写覆盖前写——
	// 信任名单 DetectionOnly 必须先发、绕过 Off 后发，同一 IP 同列两名册时
	// 绕过（Off 短路，2026-09-15 裁定语义）才是事务终态；反之绕过被降级为
	// 「全评估仅记录」，与文档语义不符。
	绕过WillEmit := p.IPACLEnabled && p.IPACLMode == "绕过"
	if p.PolicyType != models.PolicyTypeStage0 && p.IPWhitelistEnabled && len(ipWL) > 0 {
		trustID := 3
		if 绕过WillEmit {
			trustID = 5
		}
		// 2026-09-15 用户裁定:信任名单从「完全静默」改「可见放行」——
		// ctl:ruleEngine=DetectionOnly(全评估不拦,事件动作=检测);
		// 删 ctl:auditEngine=Off(原为实现信任完全静默同步关审计,现反向需求:
		// 信任流量必须进事件日志可见)。
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", trustOperand, trustID))
	}
	if 绕过WillEmit {
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off\"\n", aclOperand))
	}
	// 阶段 0 保留检测（2026-09-20 用户裁定）：信任名单策略 trust_detection=1
	// 时,绑定规则的每个策略引擎发射 id:12 DetectionOnly——信任 IP 全评估全
	// 记录不拦（事件动作=检测）。直通形态（trust_detection=0）由路由层
	// subroute 短路,不经任何引擎。
	if stage0DetectionTrust != nil {
		operand, err := ipListRuleOperand(precheckProjectionScope("trust12", ruleCaddyID), stage0DetectionTrust, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", operand))
	}

	// （取代抑制方案):多策略(预检存在)
	// 时策略层 id:2/4 改链式自排除本策略信任集——
	//   · 本策略信任 IP:预检信任并集 DetectionOnly 统一记录(去重保持,
	//     目标),策略层链第二段!@ipListFast 信任集 不命中→链整体
	//     不触发→不重复;
	//   · 他策略信任 IP(∉本策略信任集):链两段全命中→首段 deny 执行
	//     403——恢复「信任仅豁免所属策略」裁定边界(抑制方案下层无拦截
	//     点击穿);
	//   · 无信任名单的策略:无排除项→平原 id:2/4(与单策略形状一致);
	//   · 单策略(无预检):同实例信任 DetectionOnly 已正确处理,平原形态。
	// coraza「disruptive 动作仅允许
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
	// ;id:11 守卫计分在本模式无 949 消费,
	// 仅留事件——与计分动作的检测计分退化口径一致。
	// 门收紧 hasCustomRules——custom_only+仅 IP 控制
	// 形状下上方 SecRequestBodyAccess 恒 Off（BodyAccessTruthTable 已钉），
	// id:9/10/11 无消费者，发射即死指令。
	if p.Mode == "custom_only" && hasCustomRules {
		emitBodyProcessorRules(&sb, p.AnomalyThreshold)
	}

	if p.Mode == "blocking" || p.Mode == "detection" {
		var groups []string
		if err := json.Unmarshal(p.CRSRuleGroups, &groups); err != nil {
			// D7 同族（geoip_countries 先例）：畸形列不 fail-visible，按空=全量
			// 发射；WARN 留痕供带外改库/旧备份残留诊断，60s 限流与同族三处一致
			// （渲染按规则×策略粒度执行，脏行存续期逐条刷会淹没真实告警）。
			msg := fmt.Sprintf("策略 %q（#%d）crs_rule_groups 畸形 JSON，渲染按空=全量规则组处理: %v", p.Name, p.ID, err)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
		// （读取面兜底）：存量/带外数据（写入面剥离生效前落库、集群同步旧快照）
		// 可能仍含基础设施组号——按数组原位发射 REQUEST-901/949/959-*.conf glob
		// 会破坏 901 最前/949、959 殿后的强制序（偏执级守卫空转、阻断静默漏拦）。
		// 与写入面 validateAndNormalizeCRSField 同口径剥离；剥离后为空落入全量
		// glob 分支（同写入面「[]」=全量语义）。
		if kept, stripped := stripInfraCRSGroupCodes(groups); len(stripped) > 0 {
			Logf("debug", "策略 %q 的 crs_rule_groups 含基础设施组号 %v，发射时已剥离（由强制 Include 按正确次序补齐）", p.Name, stripped)
			groups = kept
		}
		// 索引取值链级惰性一次——下方消费点（emitCRSRuleGroupSelection/
		// emitScopedCRSExclusions）各自直调 GetCRSRuleIndex 会各付一次缓存键
		// 计算（ReadDir+全量 stat），全量生成时数百次纯浪费。批量生成路径经
		// buildCorazaDirectivesWithIndex 传入生成级实例（每轮一次）。
		if chainIndex == nil {
			chainIndex = lazyCRSRuleIndex()
		}
		// SecRuleRemoveById（配置期删除）与
		// ctl:ruleRemoveById（运行时跳过）需要**相反**的发射顺序——
		//   配置期：必须在 Include 之后（coraza 单遍解析，DeleteByID 只删已注册规则，
		//           放在 Include 前是空集 no-op——emitCRSRuleGroupSelection 的补删
		//           即正确先例：先 Include 父文件再逐 ID RemoveById）
		//   运行时：必须在 Include 之前（phase:1 按插入序执行，ctl 规则先于被禁
		//           规则才能在其求值前标记 tx.ruleRemoveByID——coraza ctl.go:85）
		// 第四轮把整个块搬到 Include 前修好了 ctl 却弄坏了配置期。
		// 作用域限定（ip/list）条目收集后统一发射：列表引用需单批解析，合并去重。
		var scoped []CRSExcludedEntry
		var scopeAllTargets []string
		excludedEntries := ParseCRSExcludedRules(string(p.CRSExcludedRules))
		if len(excludedEntries) == 0 {
			if raw := strings.TrimSpace(string(p.CRSExcludedRules)); raw != "" && raw != "[]" {
				// 与同族（geoip_countries/crs_rule_groups/custom_rules）同口径：
				// 非空载荷解析为空 = 用户配置的排除项全部消失（方向是过度拦截
				// fail-safe，但零留痕会让排障无从下手）。60s 限流 WARN。
				msg := fmt.Sprintf("渲染: 策略 %q（#%d）crs_excluded_rules 载荷无法解析（%d 字节），排除项按空集处理: %q", p.Name, p.ID, len(p.CRSExcludedRules), clipForLog(raw, 120))
				if auditFailureShouldLog(msg) {
					Logf("warn", "%s", msg)
				}
			}
		}
		// 渲染侧同口径截断（防御深度，与 crs_rule_groups 的
		// emitCRSRuleGroupSelection 同构）：带外直写/集群旧快照/lbbak 旧格式
		// 可绕过写入面 50 条上限，逐条发射会放大配置体积与生成耗时。
		if len(excludedEntries) > CRSExcludedRulesMaxEntries {
			// 结构性 skip 告警统一走 60s 限流（与畸形组/解析失败同口径）：渲染按
			// 规则×策略粒度执行，脏行存续期逐条刷会淹没真实告警。
			if msg := fmt.Sprintf("策略 %q 的 crs_excluded_rules 条目数 %d 超过上限 %d（疑似带外/旧快照写入），已截断渲染", p.Name, len(excludedEntries), CRSExcludedRulesMaxEntries); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			excludedEntries = excludedEntries[:CRSExcludedRulesMaxEntries]
		}
		for _, entry := range excludedEntries {
			// 存量兜底：命中基础设施组（901 初始化/949 请求评估/959 响应评估）的
			// 排除一律跳过——这些文件已由下方强制包含，排除若放行会在 Include 后
			//（scope=all）或运行时（scoped ctl）摘除评估组，守卫按 0 空转 /
			// blocking 退化为仅记录。写入面对新提交
			// 已 400 硬拒（CRSExclusionTargetRemovesInfra），此处拦存量老数据。
			if CRSExclusionTargetRemovesInfra(entry.Target) {
				if msg := fmt.Sprintf("跳过命中基础设施组（901/949/959）的 CRS 排除条目 %q（策略 %q）：这些规则为系统强制加载，排除不生效", entry.Target, p.Name); auditFailureShouldLog(msg) {
					Logf("warn", "%s", msg)
				}
				continue
			}
			if entry.Scope == "ip" || entry.Scope == "list" {
				scoped = append(scoped, entry)
				continue
			}
			// 渲染守卫：未知 scope（带外直写/旧版快照可绕过写侧白名单）不得
			// 静默降级为 scope=all——那是「对所有客户端删除该规则」，WAF 保护面
			// 静默扩大。跳过方向安全（排除减少=拦截更多）。
			if entry.Scope != "all" {
				if msg := fmt.Sprintf("跳过未知 scope 的 CRS 排除条目 %q（scope=%q，策略 %q）：未知 scope 不降级为全局排除", entry.Target, entry.Scope, p.Name); auditFailureShouldLog(msg) {
					Logf("warn", "%s", msg)
				}
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
				if msg := fmt.Sprintf("跳过非法 SecRuleRemoveById 条目 %q（策略 %q）：非数字/区间形态或区间越界，coraza 会拒绝编译", ruleID, p.Name); auditFailureShouldLog(msg) {
					Logf("warn", "%s", msg)
				}
				continue
			}
			scopeAllTargets = append(scopeAllTargets, mapped)
		}
		// 运行时 ctl 规则：Include 之前（先于被禁规则插入 phase:1 序列）
		if len(scoped) > 0 {
			if err := emitScopedCRSExclusions(&sb, p, scoped, store, chainIndex, scopedCache); err != nil {
				return "", err
			}
		}
		emitBodyProcessorRules(&sb, p.AnomalyThreshold)
		// 部署契约（唯一支持形态=Go 进程与 Caddy 同容器共享文件系统、
		// data_dir=/app/data）：Include 根硬编码 /app/waf/crs——渲染产物写给
		// Caddy 进程消费，路径必须是 Caddy 视角的绝对路径；存在性门/索引/
		// 指纹读侧走 crsDirectivesDir（ConfigureWafDirs 按 data_dir 派生）。
		// 容器默认形态下两者同树（/app/waf）；自定义 data_dir 的非容器部署
		// 中派生树与 /app/waf 分叉——该形态不在支持矩阵内（仅容器默认
		// data_dir 为正式支持）。
		// 与 infra 文件同格的存在性门：coraza 对缺失的精确路径 Include 是致命
		// 错误（seclang ReadFile → 整份配置加载失败、全站停摆）。crs-setup.conf
		// 被带外删除/部分挂载/恢复流程只还原 rules 时，无条件 Include 会让保存
		// 永久失败、Caddy 重启无法加载 autosave 配置；跳过时 901 初始化仍提供
		// 偏执级默认（语义可运行），仅告警。
		if _, err := os.Stat(filepath.Join(crsDirectivesDir, "crs-setup.conf")); err == nil {
			sb.WriteString("Include /app/waf/crs/crs-setup.conf\n")
		} else {
			if msg := fmt.Sprintf("CRS 基线配置 crs-setup.conf 缺失，跳过 Include（策略 %q）：请重新安装/恢复规则库", p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
		if _, err := os.Stat(filepath.Join(crsDirectivesDir, "zz-user-overrides.conf")); err == nil {
			sb.WriteString("Include /app/waf/crs/zz-user-overrides.conf\n")
		}
		// 库值唯一真相（批 3）：anomaly_threshold 类型①值型列——写侧 400
		// （枚举 1/3/5/10/15/20）+ 启动回填（<=0→5）保证库恒有效，直读无条件
		// 发射 id:900。无效值（NULL 读作哨兵 0/带外直写负值）在此显性报错
		// ，废除原 `>0` 守卫——它让脏行静默跳过 SecAction、
		// CRS 回落引擎默认阈值，UI 宣称与实际行为漂移。
		if p.AnomalyThreshold <= 0 {
			return "", fmt.Errorf("策略 %q 异常阈值无效（anomaly_threshold=%d <=0）：该列为类型①值型列（写侧枚举 1/3/5/10/15/20+启动回填报证），疑似带外直写或旧备份绕过导入门", p.Name, p.AnomalyThreshold)
		}
		sb.WriteString(fmt.Sprintf("SecAction \"id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", p.AnomalyThreshold))
		if len(groups) == 0 {
			// 树交换探针二次采样（发射点）：生成入口的采样之后还要付库探测、
			// 索引惰性构建与逐（规则×策略）渲染（百毫秒级以上），窗口可能在此
			// 间开启。glob Include 的规则文件集在此刻读树——命中窗口即整份
			// 配置拒绝（调用方重试），不发布「可编译但规则文件只到一半」的弱
			// 安全链配置。
			if crsTreeSwapInFlightNow() {
				return "", errCRSTreeSwapInFlight
			}
			if p.WAFCheckResponse {
				sb.WriteString("Include /app/waf/crs/rules/*.conf\n")
			} else {
				sb.WriteString("Include /app/waf/crs/rules/REQUEST-*.conf\n")
			}
		} else {
			// 基础设施组强制包含（去重）：901 提供偏执级默认值与评分初始化——
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
					if msg := fmt.Sprintf("CRS 基础设施规则文件缺失，跳过强制 Include（%s，策略 %q）", name, p.Name); auditFailureShouldLog(msg) {
						Logf("warn", "%s", msg)
					}
				}
			}
			// infra 组号/规则 ID 已在上游 stripInfraCRSGroupCodes 剥离，故此处
			// 无条件强制 Include（不再做「用户是否已选覆盖」判定——剥离后该判定
			// 恒为空、属不可达的虚假防线）。序：901 先于被选组（phase:1 默认值），
			// 949/959 在检测规则之后（插入序=执行序）。
			emitInfraInclude("REQUEST-901-INITIALIZATION.conf")
			if err := emitCRSRuleGroupSelection(&sb, p, groups, chainIndex); err != nil {
				return "", err
			}
			emitInfraInclude("REQUEST-949-BLOCKING-EVALUATION.conf")
			if p.WAFCheckResponse {
				emitInfraInclude("RESPONSE-959-BLOCKING-EVALUATION.conf")
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
			// 出站同款：响应体检查开启时 RESPONSE-959 被强制 Include，其评估
			// 规则 959100 的 deny 不抬码会把出站拦截落到 host 兜底页/Caddy
			// 默认 403 而非配置的阶段 3/属主策略页——与 949110 同门（文件存在
			// 门）同位（Include 之后、配置期 RemoveById 之前）抬码。
			if p.WAFCheckResponse {
				if _, err := os.Stat(filepath.Join(crsDirectivesDir, "rules", "RESPONSE-959-BLOCKING-EVALUATION.conf")); err == nil {
					sb.WriteString(fmt.Sprintf("SecRuleUpdateActionById 959100 \"deny,status:%d\"\n", blockStatus))
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
// (id:9/10/11)。coraza 不按自动启用 JSON/XML processor(与
// ModSecurity 连接器不同,须 ctl 显式激活),否则 body 被兜底按 URLENCODED
// 解析——JSON/XML 整串成为单个参数名:ARGS_NAMES 规则(942550/941100)在原始
// 文本上误报,ARGS 值规则对 body 失明(2026-09-09 942550 误报排查裁定)。
// 在 CRS 模式下先于 Include 发射(文档化意图;运行时 ctl 于 phase:1 全部生效,
// 先后均等价);custom_only 模式为自定义 body 规则提供解析。正则 (?i):
// 值大小写不受控(coraza 仅小写化 header 名）。
// id:11:畸形 JSON/XML 解析失败后所有 body 集合为空且 901340
// 不再 force,CRS 4.29 无任何规则消费 REQBODY_PROCESSOR_ERROR(grep 实证)——
// 「声明 JSON + 发非法 JSON」可对全部 body 规则隐身;守卫计分=策略异常阈值
// （anomalyThreshold 形参）：固定 +5 在阈值 10/15/20 时达不到 949 拦截线，
// body-processor 逃逸仅留事件不阻断，与守卫目的（阻止 body 规则隐身）不符；
// 计满阈值后任意阈值配置下 949 评估即拦（拦截模式；检测模式仅记录，语义不变）。
// custom_only 模式无 949 消费者，计分退化为事件留痕（与既有口径一致）。
func emitBodyProcessorRules(sb *strings.Builder, anomalyThreshold int) {
	sb.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/(?:[\w.+-]+?\+)?json(?:\s*;|$)" "id:9,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	sb.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^(?:application|text)/(?:[\w.+-]+?\+)?xml(?:\s*;|$)" "id:10,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"` + "\n")
	sb.WriteString(fmt.Sprintf(`SecRule REQBODY_PROCESSOR_ERROR "@eq 1" "id:11,phase:2,pass,log,setvar:tx.inbound_anomaly_score_pl1=+%d,msg:'请求体解析失败'"`, anomalyThreshold) + "\n")
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
// （域 G，历史裁定）→ 精确匹配（exactSet 含树 Countries 集时），与「海外」
// 同款不加后缀——caddygeoip 对海外行只发国名单值，精确匹配杜绝未来复合形态
// 误命中。exactSet 为空（树缺失/无国名）时国名条目退回后缀形态（(?:/.*)?
// 可选，国名单值仍命中，不放大拦截面）。
// 条目经 QuoteMeta 转义——集群同步/历史行可携带绕过校验的特殊字符，未转义会
// 注入正则元字符（ReDoS/越权匹配）。
func geoipLocOperator(countries []string, allowMode bool, exactSet map[string]bool) string {
	// 兼容补丁（2026-10-14 用户裁定）：「海外」条目语义展开——发射端
	// 改造后已解析海外行发国名，存量「禁止海外」规则的「海外」条目必须覆盖
	// 「哨兵 ∪ 树 Countries 全集」，否则已解析海外流量漏放（deny）/误拒（allow）。
	// exactSet 为空（树缺失）时仅保留哨兵（fail-safe 不产生死条目）。
	// +：展开集先收集后 sort.Strings 定序——exactSet map
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

// 自定义规则与策略引用的字段级上限（与全局请求体上限分离）
// 安全域各写端点的唯一体积门此前是全局 request_body_max_size_mb（默认
// 128MB）——单条策略可提交十万级内联名单/引用 ID 或超长 pattern，随后被策略
// 列表/详情原样回传、并在每次 Caddy 渲染时解析，把响应与解析成本放大到
// 不可用。以下阈值与本域既有同族封顶口径一致（名单条目 2000、自定义规则
// 全局 200），在写侧 fail-closed（400 并给出数值），导入/集群快照等带外
// 形状仍由发射侧兜底。
const (
	// customRuleMaxRefs：策略 custom_rules 引用的规则 ID 去重后上限
	// （与 securityCustomRuleMaxGlobalCount 同值：引用的上限不应超过可存
	// 在的规则总数）。
	customRuleMaxRefs = 200
	// customRuleMaxConditions：单条自定义规则的匹配条件数上限。
	customRuleMaxConditions = 64
	// customRuleMaxPatternBytes：单条条件 pattern 的字节上限。
	customRuleMaxPatternBytes = 4 << 10
)

// validateCustomRulePatternLength 是写侧 pattern 字节上限，刻意与发射侧的
// 结构校验 validateCustomRulePattern 分离：后者被 conditionsEmissionIssue
// 共用（集群 apply / 带外旧库的兜底门），在那里拒绝超长 pattern 会把
// 「50KB 规则渲染出超 48KiB 单行 → assertDirectiveLines 护栏报错」降级为
// 「静默跳过该规则」，反而弱化渲染护栏；写侧封顶即可阻断新载荷的放大通道。
func validateCustomRulePatternLength(pattern string) error {
	if len(pattern) > customRuleMaxPatternBytes {
		return fmt.Errorf("匹配内容不能超过 %d 字节", customRuleMaxPatternBytes)
	}
	return nil
}

// customRuleTargets / customRuleOperators 是自定义规则条件允许的目标与运算符
// 映射；emitCustomRules 与校验函数共用同一份，避免两处硬编码漂移。
// equals → @streq：@pm 是短语匹配（大小写不敏感+空格分词），
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
		if customRuleTargets[cond.Target] == "" || customRuleOperators[cond.Operator] == "" {
			return "非法 target 或 operator"
		}
		// 模式内容（空/纯空白、控制字符、尾部反斜杠）与
		// 保存/导入侧共用 validateCustomRulePattern 单一实现——集群 apply 等
		// 绕过保存校验的路径在这里兜底；空模式 @contains "" 等于匹配一切，
		// 绝不能发射成无条件 deny。
		if err := validateCustomRulePattern(cond.Operator, cond.Pattern); err != nil {
			return err.Error()
		}
	}
	return ""
}

// customRuleEmissionIssue 在 conditionsEmissionIssue 基础上兼容旧版单目标内嵌形状
// （无 conditions、靠 target/operator/pattern 发射），并对该形状同样校验 target/
// operator 合法性。
func customRuleEmissionIssue(cr models.CustomRule) string {
	// 负 ID 不受下方 ≥790000 门约束——cr.ID=-9990
	// 发射 id:10 与引擎 body processor 冲突，cr.ID<=-10000 产出负 SecRule id；
	// 二者均使 coraza 拒绝整份配置（违背「单条坏规则不得拖垮整站」的守卫契约）。
	if cr.ID < 0 {
		return "规则 id 为负数"
	}
	if cr.ConditionLogic != "" && cr.ConditionLogic != "and" && cr.ConditionLogic != "or" {
		return "条件关系无效"
	}
	// 带外旧库/集群快照可能绕过写侧校验；非法分值会产出 "+-5" 等整份
	// 配置级编译错误，非法动作会静默改变语义。0 分与空动作保留旧版缺省形状。
	if cr.Score != 0 && !customRuleValidScores[cr.Score] {
		return "异常分值无效"
	}
	if cr.Action != "" && !customRuleValidActions[cr.Action] {
		return "动作无效"
	}
	// 规则名进入 msg 引号串：控制字符/双引号会截断规则行或提前闭合动作。
	for _, r := range cr.Name {
		if r < 0x20 || r == 0x7f || r == '"' {
			return "规则名称含控制字符或双引号"
		}
	}
	if len(cr.Conditions) > customRuleMaxConditions {
		return fmt.Sprintf("条件数超过 %d 条上限", customRuleMaxConditions)
	}
	if len(cr.Conditions) > 0 {
		return conditionsEmissionIssue(cr.Conditions)
	}
	if cr.Target == "" || cr.Operator == "" {
		return "空条件"
	}
	if customRuleTargets[cr.Target] == "" || customRuleOperators[cr.Operator] == "" {
		return "非法 target 或 operator"
	}
	if err := validateCustomRulePattern(cr.Operator, cr.Pattern); err != nil {
		return err.Error()
	}
	return ""
}

// emitCustomRules writes user rules ahead of any DetectionOnly switch so a
// rule-level "拦截" action always blocks regardless of the policy WAF mode,
// mirroring how IP control behaves（例外：body 目标规则发射为 phase:2，检测模式
// 的 DetectionOnly 事务级切换对其生效，仅记录不阻断）。
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

// CustomRuleORConditionIDBase 是 OR 条件分支的独立发射段。分支 id 由父规则
// emit id 与条件序号可逆编码，避开普通自定义段、GeoIP/CRS、合成段与 2000000 排除段。
const CustomRuleORConditionIDBase = 3000000

func customRuleORConditionEmitID(parentEmitID, conditionIndex int) int {
	return CustomRuleORConditionIDBase + parentEmitID*customRuleMaxConditions + conditionIndex
}

// DecodeCustomRuleEmitID 将普通或 OR 分支 emit id 回解为同一父规则 DB id。
// 无 id 的旧内嵌合成规则没有 DB 父行，返回 false。
func DecodeCustomRuleEmitID(emitID int) (int, bool) {
	if emitID > 10000 && emitID < geoipPrecheckRuleBase {
		return emitID - 10000, true
	}
	if emitID >= CustomRuleORConditionIDBase {
		parentEmitID := (emitID - CustomRuleORConditionIDBase) / customRuleMaxConditions
		if parentEmitID > 10000 && parentEmitID < geoipPrecheckRuleBase {
			return parentEmitID - 10000, true
		}
	}
	return 0, false
}

func emitCustomRules(sb *strings.Builder, customRules []models.CustomRule, blockStatus int) {
	// 旧版内嵌规则可能没有 id（0）：全部发射 id:10000 会在同一份 coraza 配置中
	// 产生重复 SecRule id，按序分配唯一合成 id（1000000+序号——本地合成段，
	// 避开 800000+ GeoIP 预检段与 9xxxxx CRS 规则段）。synthetic 只在无 id
	// 规则上递增，保证彼此唯一。
	synthetic := 0
	for _, cr := range customRules {
		if !cr.Enabled {
			continue
		}
		// 发射侧防御：单条含尾部反斜杠或空条件的规则只跳过自身并告警，绝不让整份
		// 配置生成失败——一条坏规则不得拖垮所有站点；存量脏规则与集群同步绕过的规则
		// 均在此兜底。
		if issue := customRuleEmissionIssue(cr); issue != "" {
			// 分级日志——裸 log.Printf 无级别前缀，日志级别调至 warn/error
			// 时会被过滤出文件日志（与修复口径一致）。结构性跳过走 60s 限流：
			// 渲染按规则×策略粒度执行，存量坏规则存续期逐条刷会淹没真实告警。
			if msg := fmt.Sprintf("自定义规则 %d(%s) %s，已跳过发射，请修正或禁用", cr.ID, cr.Name, issue); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		// （阶段化模型收紧 890000→790000）:DB id ≥790000 经发射偏移
		// +10000 后撞入 GeoIP 预检段(800000-899999,geoipPrecheckRuleBase 起)——
		// 同 id 冲突会使整份 coraza 配置编译失败;≥890000 仍撞 CRS 保留段
		// (900000+)。发射侧跳过并告警(镜像上方坏规则兜底同款)。
		if cr.ID >= customRuleEmitIDBound {
			if msg := fmt.Sprintf("自定义规则 %d(%s) 发射 id 将撞入 GeoIP 预检段/CRS 保留空间，已跳过发射", cr.ID, cr.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
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
		if cr.ConditionLogic == "or" {
			conditions := cr.Conditions
			if len(conditions) == 0 {
				conditions = []models.CustomRuleCondition{{Target: cr.Target, Operator: cr.Operator, Pattern: cr.Pattern}}
			}
			for idx, cond := range conditions {
				phase := 1
				if cond.Target == "body" {
					phase = 2
				}
				branchID := customRuleORConditionEmitID(emitID, idx)
				sb.WriteString(fmt.Sprintf("SecRule %s \"%s %s\" \"id:%d,phase:%d,%s\"\n",
					customRuleTargets[cond.Target], customRuleOperators[cond.Operator], escapeCorazaPattern(cond.Pattern), branchID, phase, action))
			}
			continue
		}
		// 多条件链式规则的 setvar 绑定到链条末条。coraza v3 在单条规则
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
// 收敛（2026-10-15）：ACL 的开启 flag 即发射面（allow+空名单是否定空集，
// 语义为拒绝全部；deny/绕过 空名单不命中），镜像与内容解耦；信任名单
// （ip_whitelist_enabled 表默认值=1 非刻意 opt-in）与遗留黑名单维持内容门控。Referenced IP lists count the same as inline entries
// (refs-only policies still advertise IP control)——仅解析 refs JSON 本身，
// 无需加载数据库（摘要/绑定路径与生成路径同判定）。
func SecurityPolicyHasIPControl(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	// 摘要必须与发射面同判定，不再按「refs 非空」虚报。
	// 严格模式装载失败（IPRefMissing）时发射端整条跳过渲染 → false。
	if p.IPRefMissing {
		return false
	}
	// 信任名单：stage0 策略的信任不属于本引擎（路由层直通/预检承载）；
	// 内容门取合并集（inline ∪ 已解析引用条目）——引用的列表为空/已被删除
	// 时发射面零信任规则，摘要同步 false。
	emitTrustControl := p.IPWhitelistEnabled && p.PolicyType != models.PolicyTypeStage0 && policyWhitelistHasEntries(p)
	// 空转收窄：off/custom_only 且仅信任名单时，只有 custom_only 同时存在
	// 启用自定义规则才由该引擎承载信任规则；其余模式（blocking/detection）
	// 恒有 CRS 引擎。摘要与 BuildCorazaDirectives 的 emitIPControl 同式。
	if emitTrustControl && p.Mode != "off" && p.Mode != "custom_only" {
		return true
	}
	// ACL：开启即发射（allow 空集=否定空集恒拒；deny/绕过 空集不命中但
	// 引擎仍开）——与 emitIPControl 的 p.IPACLEnabled 项一致。
	if p.IPACLEnabled {
		return true
	}
	var ipBL []string
	if err := json.Unmarshal(p.IPBlacklist, &ipBL); err != nil {
		logMalformedInlineIPList(p.ID, "ip_blacklist", err)
	}
	if len(aggregateIPEntries(ipBL)) > 0 {
		return true
	}
	return emitTrustControl && p.Mode == "custom_only" && CountEnabledCustomRules(p.CustomRules) > 0
}

// policyWhitelistHasEntries 报告信任名单在发射面是否非空（与 mergedWhitelist
// 同判定，另支持摘要的轻量路径）。
//   - 渲染路径：MergedWhitelist 已携带「inline ∪ 引用条目」的合并集，直接判空；
//   - 摘要路径：引用的名单只做了「是否含未到期条目」判定（
//     IPWhitelistRefsNonEmpty，由 loadIPListRefPresenceVia 按 autobanEntryExpired
//     同源过滤），不搬条目内容——此时 inline 与引用非空判定取并集。
func policyWhitelistHasEntries(p *models.SecurityPolicy) bool {
	if p.MergedWhitelist != nil {
		return len(p.MergedWhitelist) > 0
	}
	if p.IPWhitelistRefsNonEmpty {
		return true
	}
	var inline []string
	if err := json.Unmarshal(p.IPWhitelist, &inline); err != nil {
		logMalformedInlineIPList(p.ID, "ip_whitelist", err)
		return false
	}
	return len(aggregateIPEntries(inline)) > 0
}

// CountEnabledCustomRules returns how many of the policy's referenced custom
// rules are enabled, mirroring emission (emitCustomRules skips disabled rules).
// The summary's custom_rules_count must not count disabled rules, otherwise the
// policy list would advertise rules the WAF never emits.
func CountEnabledCustomRules(raw json.RawMessage) int {
	count := 0
	for _, cr := range resolvePolicyCustomRules(raw, nil) {
		if customRuleEmittable(cr) {
			count++
		}
	}
	return count
}

// clipForLog 截断日志里的用户载荷（避免整列 JSON 刷屏；按 rune 截断不切坏
// 多字节字符）。
func clipForLog(raw string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(raw)
	if len(runes) <= limit {
		return raw
	}
	return string(runes[:limit]) + "…"
}

// customRuleEmitIDBound 是自定义规则 DB id 的发射上界：id+10000 偏移后不得撞入
// GeoIP 预检段（800000+）与 CRS 保留段（900000+）。发射与摘要计数共用本常量。
const customRuleEmitIDBound = 790000

// customRuleEmittable 是「该自定义规则会真实发射」的单一判据（= 发射侧跳过
// 条件的反面）：启用 ∧ 无发射缺陷 ∧ id 不撞预检/保留段。摘要计数必须复用
// 同一判据，否则列表宣称「已启用 N 条自定义规则」而引擎实际零发射。
func customRuleEmittable(cr models.CustomRule) bool {
	if !cr.Enabled {
		return false
	}
	if cr.ID >= customRuleEmitIDBound {
		return false
	}
	return customRuleEmissionIssue(cr) == ""
}

// CountEnabledCustomRulesBatch 批量统计策略的自定义规则引用：所有 ID 引用合并
// 为分块 IN 查询，避免列表逐策略 N+1；内嵌对象形态回退单条纯解析。仅用于已
// 提交库视图（列表摘要），事务内渲染仍走 resolvePolicyCustomRules(store)。
func CountEnabledCustomRulesBatch(policies []*models.SecurityPolicy) []int {
	counts := make([]int, len(policies))
	idSets := make([]map[int]struct{}, len(policies))
	all := make(map[int]struct{})
	for i, p := range policies {
		if p == nil {
			continue
		}
		var ids []int
		if err := json.Unmarshal(p.CustomRules, &ids); err != nil {
			counts[i] = CountEnabledCustomRules(p.CustomRules)
			continue
		}
		set := make(map[int]struct{}, len(ids))
		for _, id := range ids {
			set[id] = struct{}{}
			all[id] = struct{}{}
		}
		idSets[i] = set
	}
	if len(all) == 0 || db.DB == nil {
		return counts
	}
	ids := make([]int, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	// 与单策略路径同判据（customRuleEmittable）：只查 enabled 会把「存在但
	// 发射侧必跳过」的规则计进摘要，UI 宣称 N 条而引擎零发射。列集与
	// resolvePolicyCustomRules 同一查询形态，判据单一。
	emittable := make(map[int]bool, len(ids))
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
		rows, err := db.DB.Query("SELECT id, name, COALESCE(conditions,'[]'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1) FROM security_custom_rules WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			Logf("warn", "策略列表: 批量读取自定义规则失败（该块计数为 0）: %v", err)
			continue
		}
		for rows.Next() {
			var id int
			var name, conditionsJSON, action string
			var score int
			var on bool
			if err := rows.Scan(&id, &name, &conditionsJSON, &action, &score, &on); err != nil {
				Logf("warn", "策略列表: 自定义规则行扫描失败（该行丢弃）: %v", err)
				continue
			}
			var conditions []models.CustomRuleCondition
			if err := json.Unmarshal([]byte(conditionsJSON), &conditions); err != nil {
				// 畸形条件 = 发射侧同样无法发射（skip+warn），计数不计入。
				emittable[id] = false
				continue
			}
			emittable[id] = customRuleEmittable(models.CustomRule{
				ID: id, Name: name, Conditions: conditions, Action: action, Score: score, Enabled: on,
			})
		}
		if err := rows.Err(); err != nil {
			Logf("warn", "策略列表: 自定义规则迭代失败（该块计数可能不完整）: %v", err)
		}
		rows.Close()
	}
	for i, set := range idSets {
		for id := range set {
			if emittable[id] {
				counts[i]++
			}
		}
	}
	return counts
}

// buildWafHandlerWithPolicy returns the coraza WAF handler for the given policy,
// or nil when the policy is nil or emits no directives. Callers pass a policy
// from the batch-preloaded context so generation stays on the store/tx channel.
// store 与策略预载同源：自定义规则读取必须沿同一 store——tx 内生成
// 时 db.DB 看不到未提交的 security_custom_rules 行，会静默丢失 WAF 规则。
// store=nil 时由 resolvePolicyCustomRules 回退 db.DB（非批量路径保持现状）。
// stage0DetectionTrust 契约（始终发射收敛，2026-10-15）：nil=无 stage0 保留
// 检测策略（不发射 id:12）；非 nil（可空切片）=存在——恒发射 id:12（空集
// 文件算子永不命中=与无规则等价，空↔非空纯内容变化走热路径）。
func buildWafHandlerWithPolicy(ruleCaddyID string, policy *models.SecurityPolicy, store caddyConfigStore, crsFp string, multiPolicy bool, blockStatus int, bodyLimitMB int, stage0DetectionTrust []string, scopedCaches ...scopedCRSListCache) (map[string]interface{}, error) {
	var scopedCache scopedCRSListCache
	if len(scopedCaches) > 0 {
		scopedCache = scopedCaches[0]
	}
	return buildWafHandlerWithIndex(ruleCaddyID, policy, store, crsFp, multiPolicy, blockStatus, bodyLimitMB, stage0DetectionTrust, nil, scopedCache)
}

// buildWafHandlerWithIndex 是带生成上下文级 CRS 规则索引的变体（批量生成
// 路径专用）：索引指纹键每轮只算一次，而不是逐（规则×策略）一次。
func buildWafHandlerWithIndex(ruleCaddyID string, policy *models.SecurityPolicy, store caddyConfigStore, crsFp string, multiPolicy bool, blockStatus int, bodyLimitMB int, stage0DetectionTrust []string, chainIndex func() *CRSRuleIndex, scopedCache scopedCRSListCache) (map[string]interface{}, error) {
	if policy == nil {
		return nil, nil
	}
	if chainIndex == nil {
		chainIndex = lazyCRSRuleIndex()
	}
	var directives string
	var err error
	if stage0DetectionTrust == nil {
		directives, err = buildCorazaDirectivesWithIndex(policy, store, crsFp, multiPolicy, blockStatus, ruleCaddyID, scopedCache, chainIndex, nil)
	} else {
		directives, err = buildCorazaDirectivesWithIndex(policy, store, crsFp, multiPolicy, blockStatus, ruleCaddyID, scopedCache, chainIndex, stage0DetectionTrust)
	}
	if err != nil {
		return nil, err
	}
	if directives == "" {
		return nil, nil
	}
	// /2:coraza 默认 RequestBodyLimit=128MiB,
	// 用户限额>128MiB 时 WAF 活跃规则 body 在 128MiB 处被拦(用户限额不可达);
	// 413 语义被压平为 500。WAF 活跃恒发射
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
// 的 SecRule id。本地 id 空间的**权威来源是各发射函数**（encode*/Decode* 的
// 段界常量 + emitBodyProcessorRules 等），本注释只列预检段与引擎段的固定 id
// 归属，段界/新增 id 一律以代码为准，禁止按本清单复写判断：
// 预检段固定 id：2=ACL deny、3=绕过/trust、4=遗留黑名单、5=trust（绕过占 3
// 时）、6=DetectionOnly 切换、7=预检 allow 规则（本常量）、12=阶段 0 保留检测
// 的 DetectionOnly、13=allow 命中全豁免（skipAfter）；
// 引擎段另发：8=GeoIP（历史 id，现代引擎已不发）、9/10/11=body processor
// 守卫（emitBodyProcessorRules）、900=异常分阈值；
// 合成 id：2000001+ 为策略作用域排除（scope 段），800000+policyID 为阶段化
// GeoIP 链（geoipPrecheckRuleBase）。7 专用于预检 allow 规则（预检内 deny 并集
// 沿用 id:2、黑名单并集沿用 id:4，保持 security events 归因口径；allow 模式
// 事件本就回退归到首启用策略，id:7 不改变归因结果）。
const ipPrecheckAllowRuleID = 7

// ipPrecheckAllowExemptRuleID 是 allow 白名单命中豁免规则（用户裁定）：
// allow 交集命中的 IP 以 pass+nolog+skipAfter 跳过预检段内其后的一切规则。
// 语义边界（必须与本规则的实际位置一致，勿按「只豁免 GeoIP」理解）：
//   - 显式 deny（id:2 ACL deny、id:4 遗留黑名单）在本规则之前发射——命中
//     照常拦截，白名单不豁免显式黑名单；
//   - 本规则之后的一切预检规则对白名单成员不再评估：逐策略 GeoIP 链（区域
//     拦截）、爬虫伪装 deny（850000+policyID，含它策略的伪装族）、以及预检
//     段内后续任何新增规则。即「白名单=该客户端被人工信任」的全豁免口径。
//   - 预检段之外的处理面不受影响：限流、WAF/CRS、自定义规则等独立处理器
//     照常评估（skipAfter 只跳到本段的 SECURITY_RULES_END 标记）。
//
// nolog：豁免本身不产生安全事件。无 allow 名单时不发射（避免恒真跳过）。
// 顺序不变量由 geoip_precheck_exempt_test.go 的三段发射序断言钉住。
const ipPrecheckAllowExemptRuleID = 13

// geoipPrecheckRuleBase 是 GeoIP 预检链的 SecRule id 段基址（阶段化执行模型：
// GeoIP 从策略引擎 id:8 迁入阶段 1 合并预检）。逐策略链 id=800000+policyID——
// 事件归因从共享 id:8（「首个 geoip 启用策略」非精确）精确化为直接解码属主。
// emitCustomRules 发射守卫（DB id ≥790000 跳过）保证自定义规则 emit id
// （DB id+10000）不撞入本段。
//
// 三个家族的段界与编码收敛到本文件的 encode/decode
// 函数（单一事实源）。族划分互斥且编码越界即拒绝——此前三段各自只守
// 「<900000」，爬虫豁免 id（810000+policyID*16+引擎序号）在 policyID≥2500 时
// 溢入伪装段 [850000,900000)，既与伪装 id 碰撞（p=2666, i=10 → 852666）又被
// 评分/归因当成伪装族。
const (
	geoipPrecheckRuleBase     = 800000 // 普通 GeoIP 预检段 [800000,810000)
	geoipCrawlerRuleBase      = 810000 // 爬虫豁免段 [810000,850000)（+policyID*16+引擎序号）
	geoipCrawlerSpoofRuleBase = 850000 // 爬虫伪装段 [850000,900000)（+policyID）
	geoipPrecheckRuleLimit    = 900000 // CRS 保留段起点（预检段右开界）
	// geoipCrawlerEngineSlots 每策略爬虫豁免槽位（编码位移 16；当前引擎 15 个，
	// 留 1 槽余量——引擎表扩容到 16 个以内不需要改段界）。
	geoipCrawlerEngineSlots = 16
)

// precheckRuleFamily 预检规则 ID 家族（三族互斥）。
type precheckRuleFamily uint8

const (
	precheckRuleFamilyUnknown precheckRuleFamily = iota
	precheckRuleFamilyGeoIP
	precheckRuleFamilyCrawlerExempt
	precheckRuleFamilyCrawlerSpoof
)

// encodeGeoIPPrecheckRuleID 普通 GeoIP 预检 id（policyID ∈ [1,9999]）。
func encodeGeoIPPrecheckRuleID(policyID int) (int, bool) {
	if policyID <= 0 {
		return 0, false
	}
	id := geoipPrecheckRuleBase + policyID
	if id <= geoipPrecheckRuleBase || id >= geoipCrawlerRuleBase {
		return 0, false
	}
	return id, true
}

// encodeCrawlerExemptRuleID 爬虫豁免 id（policyID*16+engineIndex 必须落在
// 豁免段内；越界返回 false，调用方跳过+告警）。
func encodeCrawlerExemptRuleID(policyID, engineIndex int) (int, bool) {
	if policyID <= 0 || engineIndex < 0 || engineIndex >= geoipCrawlerEngineSlots {
		return 0, false
	}
	id := geoipCrawlerRuleBase + policyID*geoipCrawlerEngineSlots + engineIndex
	if id < geoipCrawlerRuleBase || id >= geoipCrawlerSpoofRuleBase {
		return 0, false
	}
	return id, true
}

// encodeCrawlerSpoofRuleID 爬虫伪装 id（policyID ∈ [1,49999]）。
func encodeCrawlerSpoofRuleID(policyID int) (int, bool) {
	if policyID <= 0 {
		return 0, false
	}
	id := geoipCrawlerSpoofRuleBase + policyID
	if id < geoipCrawlerSpoofRuleBase || id >= geoipPrecheckRuleLimit {
		return 0, false
	}
	return id, true
}

// decodePrecheckRuleID 把 rule_triggered 文本解码为家族+属主策略（+引擎序号）。
// 唯一解码是归因与评分的共同前提：越界/无法唯一解码（行、p=0 边界值）
// 返回 ok=false，消费方走能力 fallback，禁止用 n-800000 猜属主。
func decodePrecheckRuleID(ruleID string) (precheckRuleFamily, int, int, bool) {
	n, err := strconv.Atoi(ruleID)
	if err != nil {
		return precheckRuleFamilyUnknown, 0, 0, false
	}
	switch {
	case n > geoipPrecheckRuleBase && n < geoipCrawlerRuleBase:
		return precheckRuleFamilyGeoIP, n - geoipPrecheckRuleBase, 0, true
	case n >= geoipCrawlerRuleBase && n < geoipCrawlerSpoofRuleBase:
		pid := (n - geoipCrawlerRuleBase) / geoipCrawlerEngineSlots
		idx := (n - geoipCrawlerRuleBase) % geoipCrawlerEngineSlots
		if pid <= 0 {
			return precheckRuleFamilyUnknown, 0, 0, false
		}
		return precheckRuleFamilyCrawlerExempt, pid, idx, true
	case n >= geoipCrawlerSpoofRuleBase && n < geoipPrecheckRuleLimit:
		pid := n - geoipCrawlerSpoofRuleBase
		if pid <= 0 {
			return precheckRuleFamilyUnknown, 0, 0, false
		}
		return precheckRuleFamilyCrawlerSpoof, pid, 0, true
	}
	return precheckRuleFamilyUnknown, 0, 0, false
}

// IsGeoIPPrecheckID 报告 n 是否落在阶段 1 预检的 8xxxxx 段
// [geoipPrecheckRuleBase, geoipPrecheckRuleLimit)——含普通 GeoIP（800xxx 属主
// 精确段）与爬虫豁免/伪装两族。段界单一事实源——事件归因、stage-stats 分桶、
// 筛选族条件等消费方一律经本谓词取段界, 禁止各自复写字面量（字面量散布
// 六处,段基址调整时漏改即静默分叉)。逐策略属主解码请用 decodePrecheckRuleID
// （本谓词只判「是否预检 8 段」，不区分家族）。
func IsGeoIPPrecheckID(n int) bool {
	return n >= geoipPrecheckRuleBase && n < geoipPrecheckRuleLimit
}

// —— 展示层导出（handlers 大屏/事件列表消费的单一事实源入口）——
// 段界字面量曾在 handlers 复写多处并出现边界口径分叉（n>800000 vs
// n>=800000）；下列导出是展示侧唯一合法取径，禁止再复写字面量。

// PrecheckRuleFamily 是 precheckRuleFamily 的导出别名（展示层家族判定用）。
type PrecheckRuleFamily = precheckRuleFamily

// 预检家族枚举的导出名（与内部常量同值同点维护）。
const (
	PrecheckRuleFamilyUnknown       = precheckRuleFamilyUnknown
	PrecheckRuleFamilyGeoIP         = precheckRuleFamilyGeoIP
	PrecheckRuleFamilyCrawlerExempt = precheckRuleFamilyCrawlerExempt
	PrecheckRuleFamilyCrawlerSpoof  = precheckRuleFamilyCrawlerSpoof
)

// 展示层段界导出：预检段 [800000,900000) 的起止与合成自定义 ID 基址
// （1000000+，即 CRS 段 [900000,1000000) 的右开界）。值与 emit/decode
// 同点维护，段基址调整时只改本块。
const (
	GeoIPPrecheckSegmentBase  = geoipPrecheckRuleBase
	GeoIPPrecheckSegmentLimit = geoipPrecheckRuleLimit
	SyntheticCustomRuleIDBase = 1000000
)

// DecodePrecheckRuleID 是 decodePrecheckRuleID 的导出版：事件展示层
// （大屏命中规则/触发类型/攻击族分类）取预检家族与属主策略的唯一入口。
// 非预检 ID 或不可唯一解码（p=0 边界值，发射侧已拒绝）返回 ok=false。
func DecodePrecheckRuleID(ruleID string) (family PrecheckRuleFamily, policyID, engineIndex int, ok bool) {
	return decodePrecheckRuleID(ruleID)
}

// PrecheckRuleFamilyOf 报告 n 落在哪个预检家族段（展示层类型分桶用，
// 不校验属主可解码性——p=0 边界值发射侧不可达，展示按段归类即可，
// 与 IsGeoIPPrecheckID 同含端点语义）。归因/属主解码仍须用
// DecodePrecheckRuleID（禁止用 n-800000 猜属主）。
func PrecheckRuleFamilyOf(n int) PrecheckRuleFamily {
	switch {
	case n >= geoipPrecheckRuleBase && n < geoipCrawlerRuleBase:
		return precheckRuleFamilyGeoIP
	case n >= geoipCrawlerRuleBase && n < geoipCrawlerSpoofRuleBase:
		return precheckRuleFamilyCrawlerExempt
	case n >= geoipCrawlerSpoofRuleBase && n < geoipPrecheckRuleLimit:
		return precheckRuleFamilyCrawlerSpoof
	}
	return precheckRuleFamilyUnknown
}

// IsStage1PrecheckID 判定事件触发 id 是否属阶段 1 预检族
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
// 与 IsStage1PrecheckID 同文件维护（原居 securityevents.go，
// 与 Go 谓词分居两文件，阶段 1 新增预检 id 时易漏改）。3/5/12 为防御性包含
// 当前 nolog pass 不产事件。
const Stage1PrecheckIDSQLList = "('2','3','4','5','7','8','12','14')"

// IsStage1PrecheckEventID 是「事件层面阶段 1 预检段」判定的单一事实源：
// IsStage1PrecheckID（固定族 {2,4,7,8,14}+GeoIP 预检段）∪ 防御性包含集
// {3,5,12}——与 Stage1PrecheckIDSQLList 同集合。SQL 归因清单、事件分段
// 耗时选值（securityEventsIsPrecheckRule）一律消费本谓词，禁止复写字面量
// （新增/删除预检 id 时字面量分叉即静默漂移；一致性由
// security_stage1_segment_test.go 三集合对账钉死）。
func IsStage1PrecheckEventID(n int) bool {
	if IsStage1PrecheckID(n) {
		return true
	}
	switch n {
	case 3, 5, 12: // 防御性包含（nolog pass 不产事件，同 SQL 清单口径）
		return true
	}
	return false
}

// Stage1PrecheckSegmentSQL 是阶段 1 预检段（IP 访问控制/威胁情报库/地域拦截）
// 事件归因的完整 SQL 谓词单一事实源——rule_triggered（文本 id）落在本段即
// 阶段 1：固定 ID 清单 Stage1PrecheckIDSQLList ∪ GeoIP 预检归因段
// [geoipPrecheckRuleBase, +100000) 的 6 位文本形态（8 开头 6 位）。
// 消费方：handlers.GetRuleStageStats 分段耗时归因（收敛：原
// 内联 "IN %s OR (LENGTH=6 AND LIKE '8%%')" 与 ID 清单分居两文件两处字面量）。
// 与 IsStage1PrecheckID 同文件维护，一致性由 security_stage1_segment_test.go 钉死。
const Stage1PrecheckSegmentSQL = "rule_triggered IN " + Stage1PrecheckIDSQLList +
	" OR (LENGTH(rule_triggered)=6 AND rule_triggered LIKE '8%')"

// allowPolicySetSignature 返回规则绑定的 allow 模式策略身份签名（升序 id，
// 逗号分隔）。签名只用于生成轮内的交集缓存键：同一轮内策略的合并名单不可变，
// 因此身份集相同即交集相同。无 allow 策略返回空串（不走缓存）。
func allowPolicySetSignature(policies []*models.SecurityPolicy) string {
	var ids []string
	for _, p := range policies {
		if p == nil || !p.IPACLEnabled || p.IPACLMode != "allow" {
			continue
		}
		ids = append(ids, strconv.Itoa(p.ID))
	}
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, ",")
}

// intersectIPLists 返回多组 IP/CIDR 名单的网络感知交集（裁定 2026-09-07）
// 对每对条目判断 CIDR 包含关系，保留更具体的一方（10.0.0.0/8 ∩ 10.1.0.5
// = 10.1.0.5）。字符串精确匹配兼容（相同文本=同网络）。空交集返回 nil。
func intersectIPLists(lists [][]string) []string {
	if len(lists) == 0 {
		return nil
	}
	// 预解析缓存——原实现每对条目都重新 ParseCIDR/ParseIP,
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

// parsedEntry 是 IP/CIDR 条目的一次解析结果。
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
// 一方（自此为唯一实现——旧字符串入参变体 cidrIntersectEntry 在
// 预解析缓存改造后生产零调用，已删除，语义钉迁至 cidrIntersectParsed）。
// a 保留原串供返回（交集结果须是原始字符串形态）。
func cidrIntersectParsed(pa, b *parsedEntry) string {
	if !pa.valid || !b.valid {
		return ""
	}
	// 字面相等且合法（合法性门同口径：bad 条目字面相等不得顶出交集）
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

// precheckProjectionScope 把规则身份编入预检/引擎层 u-* 投影 scope（历史
// scope 形态 u-<kind>-<ruleCaddyID>（如 u-deny-lb_2r8dosptk1）——投影
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
// 规则评估前即中断——修复 `[coraza_, coraza_]` 链中 CRS 先评估产生
// 检测事件、IP ACL 才拦截的双重检测问题（IP ACL 最高优先级）。预检仍是
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
// ruleCaddyID：本函数逐规则渲染（policiesForRule——每条规则
// 的绑定策略集不同，u-* 并集内容是调用方规则的函数），u-* 投影 scope 必须编入
// 规则身份（u-deny-<ruleCaddyID> 等）；全局单文件名下异策略集多规则的后渲染
// 会覆盖前者=漏拦+误拦（热路径稳定命名粒度教训的预检形态）。空值显性报错
// （fail-loud，禁止静默退回全局名重建冲突）。爆炸半径=整份配置被拒——
// 已裁定维持 fail-loud 不收窄（跳过+告警=IP 控制面静默缺失，
// fail-closed 整拒更安全），载体见 BuildCorazaDirectives 同名注释。
func buildIPPrecheckDirectives(policies []*models.SecurityPolicy, denyStatus int, ruleCaddyID string, securityCtxs ...*securityPolicyContext) (string, error) {
	var securityCtx *securityPolicyContext
	if len(securityCtxs) > 0 {
		securityCtx = securityCtxs[0]
	}
	if ruleCaddyID == "" {
		return "", fmt.Errorf("u-* 预检投影缺少规则身份（ruleCaddyID 为空）——预检逐规则渲染，scope 必须编入规则身份（历史 HP-1）")
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
				// 空集也加入 allowLists：交集为空 → 下方发射恒拒规则，
				// 不得因内容门静默 fail-open。
				allowLists = append(allowLists, aclList)
			}
		}
		var blacklist []string
		if err := json.Unmarshal(p.IPBlacklist, &blacklist); err != nil {
			logMalformedInlineIPList(p.ID, "ip_blacklist", err)
		}
		blacklistUnion = append(blacklistUnion, blacklist...)
	}
	hasGeoIP := false
	for _, p := range policies {
		if PolicyHasGeoIP(p) {
			hasGeoIP = true
			break
		}
	}
	// allow+空名单守卫必须在早退之前：PolicyHasGeoIP 为 false 时该策略零
	// GeoIP 特征，若无其他预检内容函数会提前返回空串——allow+空的渲染语义
	// 是放行全部请求（fail-open，最危险方向），写侧 400 的形状经带外直写
	// 绕过时必须 fail-visible 拒绝生成。
	for _, p := range policies {
		if p != nil && p.GeoIPMode == "allow" && len(geoipCountries(p)) == 0 {
			return "", fmt.Errorf("策略 %q（#%d）geoip_mode=allow 但地域名单为空：渲染语义为放行全部请求（fail-open），疑似带外直写绕过写侧校验——拒绝生成，请修正策略或关闭地域控制", p.Name, p.ID)
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
	// （侧车退役，耗时注入审计行——见 BuildCorazaDirectives 的 lbfile
	// 注释）。
	sb.WriteString(fmt.Sprintf("SecAuditEngine RelevantOnly\nSecAuditLog %s\nSecAuditLogType lbfile\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHKZ\n", auditLogPath))
	// 2026-09-15 用户裁定:信任最高优先(任何规则不拦)+检测事件全记录——
	// 预检层信任改 ctl:ruleEngine=DetectionOnly 先行(取代 「并入 allow
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
	// allow 交集外拒绝（id:7，后移）：置于 deny 并集/黑名单之后
	// ——同在 deny 名单与 allow 交集外的 IP 先被 id:2/4 拒绝，事件归因「IP 黑名单
	// 拒绝」（deny 侧精确语义）；id:7 只对「未被显式 deny 且不在 allow 交集」的
	// IP 生效。拦截结果与既有语义等价（同 deny+status+skipAfter）。
	if len(allowLists) > 0 {
		// allow 交集只依赖「绑定的 allow 策略集合」（同一生成轮内名单内容固定）：
		// 按策略身份签名在同轮内复用，避免同策略集的多条规则重复计算。
		signature := allowPolicySetSignature(policies)
		allowIntersection = aggregateIPEntries(securityCtx.allowIntersectionCached(signature, func() []string {
			return intersectIPLists(allowLists)
		}))
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
	// allow 白名单豁免（用户裁定）：交集命中 = pass + 跳过预检段内其后的一切
	// 规则（VIP 全豁免语义，语义边界见 ipPrecheckAllowExemptRuleID 注释）。
	// 置于 deny/blacklist 之后——显式 deny 命中照常拦截（其 skipAfter 先行
	// 短路，豁免规则不参与评估）；置于 GeoIP 链与爬虫伪装族之前——白名单
	// 成员不再被区域拦截、也不被爬虫伪装规则拦截（含他策略的伪装族）。
	// 交集为空（恒拒形态）时无成员可豁免，不发射。
	if len(allowIntersection) > 0 {
		operand, err := ipListRuleOperand(precheckProjectionScope("allow-exempt", ruleCaddyID), allowIntersection, false)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"id:%d,phase:1,pass,nolog,skipAfter:SECURITY_RULES_END\"\n", operand, ipPrecheckAllowExemptRuleID))
	}
	// 逐策略 GeoIP 链（阶段 1：GeoIP 自策略引擎 id:8 迁入预检，id=800000+policyID
	// 精确归因段）。链首 deny+skipAfter+chain（disruptive 动作仅允许链首段，
	// 续段 X-LB-GeoIP-Loc 匹配策略 geoip_countries（caddygeoip pass
	// route 先于本预检设置该头）；策略有启用信任名单时追加第三续段——预检信任∪
	// DetectionOnly 是事务级全局的（2026-09-20 用户裁定：信任 IP 对全部策略的
	// GeoIP 全局放行，取代旧引擎层「跨策略信任不豁免」边界），此续段仅抑制
	// 本策略链对自有信任 IP 的自欺事件。在 id:3
	// （非 stage0 信任并集）/id:12（stage0 保留检测）已把信任 IP 的事务级引擎
	// 切为 DetectionOnly 的前提下，该续段对判定结果不产生差异（信任 IP 本就不
	// 拦）——属防御性冗余，保留为纵深层；删除它同样安全，但若未来收窄
	// DetectionOnly 的适用范围，此续段是唯一的链内自抑制，勿视作死代码清理。
	// denyStatus=403（阶段 1 页未配）时不带
	// status：默认 403 → 403 兜底错误路由（跟随策略的默认层，回归形状）；
	// =481 时链首显式抬码（disruptive 动作仅允许链首段）。
	geoipStatusFragment := ""
	if denyStatus != 403 {
		geoipStatusFragment = fmt.Sprintf(",status:%d", denyStatus)
	}
	// 域 G：国名条目精确匹配集——树 Countries（live 优先、缓存
	// 兜底，与 ValidateGeoIPCountries 同源）；树缺失（无库且无缓存）时空集，
	// 国名条目退回后缀形态（geoipLocOperator 注释）。单次取树供全部策略链
	// 复用（同款：避免循环内重复全量扫描；树扫描本身有 memo）。
	geoipCountryExact := map[string]bool{}
	if tree := GetIP2RegionRegionTree(); tree != nil {
		for _, c := range tree.Countries {
			geoipCountryExact[c] = true
		}
	}
	// precheckRuleIDs 本函数已发射的 SecRule id：跨家族唯一性硬错误（历史
	// 编码函数已保证族内唯一且互斥，本表是防御层：任何未来改动
	// 让两族产生同 id 时渲染直接失败，而不是把碰撞送进引擎/事件归因。
	precheckRuleIDs := map[int]bool{}
	claimRuleID := func(id int, desc string) error {
		if precheckRuleIDs[id] {
			return fmt.Errorf("预检规则 id 冲突：%s 与已发射规则同为 id:%d（请检查策略编号与爬虫族段界）", desc, id)
		}
		precheckRuleIDs[id] = true
		return nil
	}
	for _, p := range policies {
		if p == nil {
			continue
		}
		// 渲染守卫（写侧 ValidateGeoIPCountries/枚举门之外的最后一道，
		// 面向带外直写/旧快照残留）：
		// - geoip_mode 非枚举值：geoipLocOperator 的 allowMode=false 默认分支
		//   会把脏值按 deny 方向静默执行（与 UI 宣称可能相反）——按关闭处理
		//   +60s 限流 WARN（可用性优先，启动归一将把枚举外全集收敛为 deny）。
		//   空串为历史兼容形态：启动归一 ''→deny 与下方分支一致，即空串 +
		//   非空名单**会拦截**（PolicyHasGeoIP 对 mode!='off' 且名单非空返回
		//   true，链首发射 !@ipMatch deny）。
		// - allow+空名单：PolicyHasGeoIP 为 false 时整链不发射=全放行
		//   （fail-open，最危险方向）——fail-visible 拒绝生成。
		switch p.GeoIPMode {
		case "", "off", "allow", "deny":
		default:
			msg := fmt.Sprintf("策略 %q（#%d）geoip_mode 非枚举值 %q，地域控制按关闭处理（疑似带外直写/旧快照）", p.Name, p.ID, p.GeoIPMode)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		if p.GeoIPMode == "allow" && len(geoipCountries(p)) == 0 {
			return "", fmt.Errorf("策略 %q（#%d）geoip_mode=allow 但地域名单为空：渲染语义为放行全部请求（fail-open），疑似带外直写绕过写侧校验——拒绝生成，请修正策略或关闭地域控制", p.Name, p.ID)
		}
		if !PolicyHasGeoIP(p) {
			continue
		}
		// 策略编号越出普通 GeoIP 段 [800001,810000) 时
		// 跳过该策略链并告警（自此段界由编码函数单一裁决；
		// 旧实现只守 <900000，policyID≥10000 会溢入爬虫段）。危害是归因/分桶
		// 错位而非编译失败（预检是独立 coraza 配置）。
		geoipRuleID, ok := encodeGeoIPPrecheckRuleID(p.ID)
		if !ok {
			Logf("warn", "策略 %d 的 GeoIP 预检链 id 越出普通 GeoIP 段 [%d,%d)，已跳过发射", p.ID, geoipPrecheckRuleBase+1, geoipCrawlerRuleBase)
			continue
		}
		if err := claimRuleID(geoipRuleID, fmt.Sprintf("策略 %d GeoIP 链", p.ID)); err != nil {
			return "", err
		}
		// v2.3.8 爬虫豁免（用户裁定方案 B）：已验证爬虫（caddygeoip handler 双跳
		// PTR/官方 IP 段验证后注入 X-LB-Crawler-Verified=引擎 ID）逐引擎放行——
		// ctl 移除本策略 GeoIP 链；伪装（UA 声称引擎但验证**确定否定**，
		// handler 置 X-LB-Crawler-Spoof=引擎 ID，旧注释的「=1」与发射值矛盾）
		// 独立事件族显式拒绝。验证三态化后瞬态（DNS 抖动/并发饱和/快照不可用）
		// 不置伪装头——本规则只对确定性伪装生效，不误封真爬虫、不产生伪事件。
		// id 编码见
		// encodeCrawlerExemptRuleID/encodeCrawlerSpoofRuleID（豁免 id
		// 越出 [810000,850000) 时跳过+告警，不再溢出伪装段）。
		if p.GeoIPCrawlerExempt {
			// 伪装头改为携带引擎 ID（与 Verified 对称），规则条件
			// 收窄到「本策略已勾选的引擎集合」——旧实现 @eq 1 对任何引擎的
			// 伪装都 deny（仅勾选 googlebot 的策略会把 bingbot 失败也拦下）。
			selectedEngines := make([]string, 0, 4)
			for i, engine := range geoipnames.CrawlerEngines() {
				if !crawlerEngineSelected(p, engine.ID) {
					continue
				}
				selectedEngines = append(selectedEngines, engine.ID)
				crawlerRuleID, ok := encodeCrawlerExemptRuleID(p.ID, i)
				if !ok {
					Logf("warn", "策略 %d 的爬虫豁免规则（引擎 %s，序号 %d）id 越出豁免段 [%d,%d)，已跳过发射", p.ID, engine.ID, i, geoipCrawlerRuleBase, geoipCrawlerSpoofRuleBase)
					continue
				}
				if err := claimRuleID(crawlerRuleID, fmt.Sprintf("策略 %d 爬虫豁免(%s)", p.ID, engine.ID)); err != nil {
					return "", err
				}
				sb.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:X-LB-Crawler-Verified \"@streq %s\" \"id:%d,phase:1,pass,log,msg:'搜索引擎爬虫放行（已验证）',ctl:ruleRemoveById=%d\"\n", engine.ID, crawlerRuleID, geoipRuleID))
			}
			if len(selectedEngines) == 0 {
				// 引擎集非空但没有任何条目命中注册表（注册表更替/导入脏值）：
				// 豁免块整块不发射，UI 仍显示「爬虫豁免已启用」——静默漂移。
				// 方向 fail-closed（更多拦截），仅留痕。
				if raw := strings.TrimSpace(string(p.GeoIPCrawlerEngines)); raw != "" && raw != "[]" {
					msg := fmt.Sprintf("渲染: 策略 %q（#%d）的爬虫豁免引擎集 %s 未命中任何已知引擎，豁免与伪装规则均不发射", p.Name, p.ID, clipForLog(raw, 120))
					if auditFailureShouldLog(msg) {
						Logf("warn", "%s", msg)
					}
				}
			}
			if len(selectedEngines) > 0 {
				if spoofRuleID, ok := encodeCrawlerSpoofRuleID(p.ID); !ok {
					Logf("warn", "策略 %d 的爬虫伪装规则 id 越出伪装段 [%d,%d)，已跳过发射", p.ID, geoipCrawlerSpoofRuleBase, geoipPrecheckRuleLimit)
				} else {
					if err := claimRuleID(spoofRuleID, fmt.Sprintf("策略 %d 爬虫伪装", p.ID)); err != nil {
						return "", err
					}
					spoofPattern := escapeCorazaPattern("^(?:" + strings.Join(selectedEngines, "|") + ")$")
					sb.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:X-LB-Crawler-Spoof \"@rx %s\" \"id:%d,phase:1,deny%s,log,msg:'搜索引擎爬虫伪装（PTR 验证失败）',skipAfter:SECURITY_RULES_END\"\n", spoofPattern, spoofRuleID, geoipStatusFragment))
				}
			}
		}
		trusted := mergedWhitelist(p)
		trustContinuation := p.IPWhitelistEnabled && len(trusted) > 0
		locationActions := "t:none"
		if trustContinuation {
			// 中段仅在第三段（信任续段）存在时续链；无信任时以 t:none 终止，
			// 避免悬空 chain 使引擎拒绝整份预检配置。
			locationActions = "t:none,chain"
		}
		sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"!@ipMatch %s\" \"id:%d,phase:1,deny%s,log,msg:'GeoIP 区域拦截',skipAfter:SECURITY_RULES_END,chain\"\n", strings.Join(geoipPrivateRanges, ","), geoipRuleID, geoipStatusFragment))
		sb.WriteString(fmt.Sprintf(" SecRule REQUEST_HEADERS:X-LB-GeoIP-Loc \"%s\" \"%s\"\n", escapeCorazaPattern(geoipLocOperator(geoipCountries(p), p.GeoIPMode == "allow", geoipCountryExact)), locationActions))
		if trustContinuation {
			// 信任维持内容门控（不收敛，2026-10-15：ip_whitelist_enabled 表
			// 默认值=1 非刻意 opt-in，flag 门控会使每条 GeoIP 链凭空获得恒真
			// 续段——门禁钉测实证）。
			operand, err := ipListRuleOperand(fmt.Sprintf("p%d-trust", p.ID), trusted, true)
			if err != nil {
				return "", err
			}
			sb.WriteString(fmt.Sprintf("SecRule REMOTE_ADDR \"%s\" \"t:none\"\n", operand))
		}
	}
	sb.WriteString("SecMarker SECURITY_RULES_END\n")
	if err := assertDirectiveLines(sb.String()); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// buildIPPrecheckHandler returns the consolidated stage-1 precheck coraza handler。
// securityCtx 供生成级缓存（allow 交集按策略集签名复用）：同一策略集绑定的
// 多条规则此前各自重算多名单交集（64 份满额名单 × 5000 条最坏 2500 万次比较/
// 对，且全程持 CaddyOpLock）。nil=非批量路径（单规则生成），照常自算。
func buildIPPrecheckHandler(policies []*models.SecurityPolicy, denyStatus int, ruleCaddyID string, securityCtxs ...*securityPolicyContext) (map[string]interface{}, error) {
	directives, err := buildIPPrecheckDirectives(policies, denyStatus, ruleCaddyID, securityCtxs...)
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
// store 必须与策略预载同源：v2 导入事务内重插的 security_custom_rules
// 在已提交 db.DB 视角中不存在，走 db.DB 会让新规则在渲染期静默丢失（WAF 削弱）。
// store=nil 回退 db.DB，保留 handlers/summary 等非事务调用点现状。
// policyCustomRuleChunkSize bounds each IN (...) placeholder batch:
// SQLite caps bound variables at 32766, and an oversized IN previously
// failed the whole query so custom rules were silently lost (WAF weakened).
var policyCustomRuleChunkSize = 500

// policyCustomRulesCached 以策略为粒度缓存自定义规则解析（审计）：批量
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
		// 空串载荷（列默认值/写侧归一恒为 "[]"，空串只能来自带外直写）——
		// 与同族（geoip_countries/crs_rule_groups/内联名单）同口径 60s 限流
		// WARN：自定义拦截规则静默全丢必须留痕。
		if auditFailureShouldLog("custom_rules 空串载荷") {
			Logf("warn", "策略 custom_rules 为空串载荷（疑似带外直写），自定义规则按空处理")
		}
		return nil
	}
	var ids []int
	if err := json.Unmarshal(raw, &ids); err == nil {
		if len(ids) == 0 {
			return nil
		}
		// store=nil 时回退全局 db.DB——非事务调用点（summary、handlers）
		// 语义与修复前一致；tx 调用点必须显式传 tx，否则会读到已提交旧快照。
		effective := store
		if effective == nil {
			// db.DB 是具体指针：nil 直接装入接口会得到“非 nil 接口 + nil 接收者”，
			// 随后的 Query 会 panic。必须先判具体指针。
			if db.DB == nil {
				return nil
			}
			effective = db.DB
		}
		var rules []models.CustomRule
		queriedIDs := make(map[int]struct{}, len(ids))
		scanFailedIDs := make(map[int]struct{}, 0)
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
			// ORDER BY id：跨分块的追加顺序此前依赖 SQLite 未定义返回序，
			// 而发射顺序决定 coraza 的执行顺序（skipAfter/链语义）——显式
			// 排序让「同载荷必得同产物」成为契约，测试也才有稳定期望。
			rows, err := effective.Query("SELECT id, name, COALESCE(conditions,'[]'), COALESCE(NULLIF(condition_logic,''),'and'), COALESCE(action,'block'), COALESCE(score,5), COALESCE(enabled,1) FROM security_custom_rules WHERE id IN ("+placeholders+") ORDER BY id ASC", args...)
			if err != nil {
				// 历史 G: 单块失败只丢该块并留痕，其余块照常解析；
				// 此前整查询失败静默返回 nil，WAF 规则全部丢失且无日志。
				Logf("warn", "解析策略自定义规则分块查询失败（id 段 %d-%d）: %v", chunk[0], chunk[len(chunk)-1], err)
				continue
			}
			for _, id := range chunk {
				queriedIDs[id] = struct{}{}
			}
			for rows.Next() {
				var rowID int
				var cr models.CustomRule
				var conditionsJSON string
				// 先单独接收 id——Scan 中途失败时该
				// 列已赋值，可把本行从「悬空引用」计数中排除（行存在但解析失败
				// 不是「规则已删除」，旧实现把它计入 N 个不存在）。
				if err := rows.Scan(&rowID, &cr.Name, &conditionsJSON, &cr.ConditionLogic, &cr.Action, &cr.Score, &cr.Enabled); err != nil {
					if rowID != 0 {
						scanFailedIDs[rowID] = struct{}{}
					}
					msg := fmt.Sprintf("解析策略自定义规则行扫描失败（规则 id=%d）: %v", rowID, err)
					if auditFailureShouldLog(msg) {
						Logf("warn", "%s", msg)
					}
					continue
				}
				cr.ID = rowID
				// 跨 500 分块重复引用查重——同 ID 双 SecRule 会被
				// coraza 编译拒绝,毒化策略无法落库。
				// O(m²) 线性扫→map 判重(queriedIDs
				// 是「已查」集,入列判重需独立 seen 集)。
				if _, dup := seenIDs[cr.ID]; dup {
					continue
				}
				seenIDs[cr.ID] = struct{}{}
				json.Unmarshal([]byte(conditionsJSON), &cr.Conditions)
				rules = append(rules, cr)
			}
			// 迭代错误检查——与同函数 历史 G 口径一致,
			// 迭代中途失败静默截断自定义规则会致 WAF 削弱无留痕。
			if rerr := rows.Err(); rerr != nil {
				Logf("warn", "解析策略自定义规则迭代失败（本块可能被截断）: %v", rerr)
			}
			rows.Close()
		}
		// 悬空引用（规则已被删除）不改变解析行为，仅记录日志便于排查；
		// 只统计查询成功分块内未找到的 id——查询失败的分块已单独留痕，
		// 其 id 从未读回，计入悬空会把「查询失败」误报为「规则已删除」。
		// queried 按去重后的 id 计数——custom_rules 数组含重复 id 时
		// IN 只返回一行，不去重会把「重复引用」误报为「 个不存在」。
		// 行扫描失败（行存在、内容不可解析）不得
		// 计入「不存在」——按 queried∩未成功∩非 scan 失败 逐 id 判定。
		dropped := 0
		for id := range queriedIDs {
			if _, ok := seenIDs[id]; ok {
				continue
			}
			if _, failed := scanFailedIDs[id]; failed {
				continue
			}
			dropped++
		}
		if dropped > 0 {
			Logf("warn", "策略引用的自定义规则有 %d 个不存在，已跳过", dropped)
		}
		return rules
	}
	var embedded []models.CustomRule
	if err := json.Unmarshal(raw, &embedded); err == nil {
		return embedded
	}
	// 两种载荷形态（ID 数组/内嵌对象数组）均不可解析——自定义规则静默全丢
	// 必须留痕（与同族畸形列 WARN 同口径，60s 限流防脏行逐策略刷日志）。
	msg := fmt.Sprintf("策略 custom_rules 载荷不可解析（%d 字节），自定义规则按空处理: %.80s", len(raw), string(raw))
	if auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
	return nil
}

// validSecRuleRemoveTarget 判定 SecRuleRemoveById 目标是否为 coraza 可编译
// 且不越界的形态：纯数字，或 a-b 区间。边界依据：本地规则 ID 空间为 IP ACL
// 2-5 与自定义规则 10000+，CRS 规则 ID 恒为 9xxxxx（六位、首位 9）——
// 下界 <900000 或上界 >999999 的区间会静默删除本地/自定义规则，一律拒绝。
// 注意：界内宽区间（如 902000-999999）可通过本门——它删除除 901 段外的
// 全部 CRS 规则，属管理员的显式选择（与 901 初始化组相交的区间由
// CRSExclusionTargetRemovesInfra 另一道守卫拒绝），本门只管「不越界出
// 9xxxxx CRS 空间」。
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

// CRSExcludedEntryEffective 判定排除条目是否会被发射端实际发射
// 与发射链同款门——两位组号（发射侧映射为 9xx000-9xx999）直接有效；其余
// 条目先经 crsFilenameToRuleIDRange 映射为 ID 区间，再过
// validSecRuleRemoveTarget 形态/边界门。保存侧复用本门可在保存时拒绝
// 「保存 200、发射静默跳过」的条目（如字母后缀 "942100L"），同时不误伤合法的
// CRS 文件名形态（"REQUEST-942-*.conf" → 942000-942999）。基础设施组号
// （01/49/59）另由 CRSExclusionTargetRemovesInfra 拒绝，不在本门。
func CRSExcludedEntryEffective(entry string) bool {
	trimmed := strings.TrimSpace(entry)
	if IsCRSGroupCode(trimmed) {
		return true
	}
	return validSecRuleRemoveTarget(crsFilenameToRuleIDRange(trimmed))
}

// crsFilenameToRuleIDRange 仅把真实 CRS 文件名形态（REQUEST-9XX-…/
// RESPONSE-9XX-…）映射为规则 ID 区间；纯数字的「数字-数字」段（如
// "101-942"）不是文件名——若按 parts[1] 映射会把用户输入静默解释为另一个
// CRS 组并整组删除，与字面语义不符（纯数字区间由 validSecRuleRemoveTarget
// 的 6 位边界门独立裁决）。
func crsFilenameToRuleIDRange(s string) string {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) >= 2 && (parts[0] == "REQUEST" || parts[0] == "RESPONSE") {
		if n, err := strconv.Atoi(parts[1]); err == nil && n >= 900 && n <= 999 {
			return fmt.Sprintf("%d000-%d999", n, n)
		}
	}
	return s
}

// CRSExcludedRulesMaxEntries 新格式 crs_excluded_rules 的条目上限（旧 []string
// 格式无上限，保持现状兼容；50 条上限口径）。
const CRSExcludedRulesMaxEntries = 50

// crsScopedExclusionMaxDirectives 是单策略作用域排除（scope=ip/list）的
// ctl:ruleRemoveById 发射行预算。条目数上限挡不住组号展开：每条两位组号
// target 会展开为该组全部规则 ID（CRS 一组数百条），50 条组号条目即可产出
// 数万行。行预算按展开后的真实行数截断——带外/旧快照写入不得把生成期行数
// 放大到百万级（生成全程持 CaddyOpLock，配置体积与 /load 都随之失控）。
// var 供测试缩小预算构造边界。截断方向安全：排除被少发=拦截更多。
var crsScopedExclusionMaxDirectives = 20000

// CRSRuleGroupsMaxEntries crs_rule_groups 的条目上限（按原始条目数计，去重
// 之前）。与 crs_excluded_rules 同族限量：每条 6 位 ID 触发索引 Find 与一行
// SecRuleRemoveById 输出，超大数组放大配置体积/生成时间。200 远高于 UI
// 选择器真实可达规模（CRS 组约 20 个 + 少量单规则 ID），只挡带外畸形载荷。
const CRSRuleGroupsMaxEntries = 200

// DedupeCRSGroupEntries 按首见保序去重（trim 后判定，保留原条目形态）——
// 写入面归一与渲染面共用同一去重口径：重复组号会产生重复 Include，coraza
// 对重复注册规则 ID 直接编译拒绝（duplicated rule id）。
func DedupeCRSGroupEntries(entries []string) []string {
	seen := make(map[string]struct{}, len(entries))
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		key := strings.TrimSpace(entry)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	return out
}

// CRSStaleGroupSelections 报告 crs_rule_groups 载荷是否含本地规则索引中已
// 不存在的组号/规则 ID（CRS 更替后的陈旧选择——该部分保护静默失效，摘要
// 层暴露供 UI 标注；渲染侧仍按 skip+WARN 保持可用性，不 fail-loud）。
// 解析失败/空载荷/索引不可用均按无陈旧处理（畸形与存在性是两条正交防线）。
func CRSStaleGroupSelections(raw json.RawMessage, index *CRSRuleIndex) bool {
	if index == nil {
		return false
	}
	var groups []string
	if err := json.Unmarshal(raw, &groups); err != nil {
		return false
	}
	for _, g := range groups {
		trimmed := strings.TrimSpace(g)
		switch {
		case IsCRSRuleIDTarget(trimmed):
			if !index.Has(trimmed) {
				return true
			}
		case IsCRSGroupCode(trimmed):
			if !index.HasGroup(trimmed) {
				return true
			}
		}
	}
	return false
}

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
// 自定义规则普通、旧版合成及 OR 条件分支段互不冲突。
const crsScopedExclusionIDBase = 2000000

// emitScopedCRSExclusions 发射作用域限定（scope=ip/list）的排除条目：每条先解析
// 匹配集（ips 逗号条目 ∪ 全部 listRefs 的列表条目，跨条目去重保序；ListRefs 跨
// 条目汇总后单批 LoadIPListEntriesByID），合并为空 → 跳过+warn（列表被清空/
// 引用悬空时不发射空匹配）；target 经 expandCRSScopedExclusionTargets 展开
// 为逐 ID（ctl:ruleRemoveById 不支持区间），每 ID 一条 phase:1 运行时 ctl 规则。
// emitScopedCRSExclusions 发射作用域限定 ctl 规则。store 非-nil 时经其解析列表引用
// （v2 导入事务视图——不变式，审计）；nil 回退 db.DB（测试/直调路径）。
// chainIndex 为链级惰性索引取值闭包——单次 BuildCorazaDirectives 内与其他
// 消费点共享一次缓存键计算。
//
// 历史 匹配集不再内联 @ipMatch 展开——引用名单是大名单时单行撞
// 48KiB 护栏（assertDirectiveLines 拒绝=整份配置无法保存），且与「策略名单
// 统一投影 @ipListFast」的架构总述矛盾。改投影 @ipListFast（同族单源
// writeIPListFile/ipListRuleOperand：稳定命名、原子写、同字节跳写、写失败沿
// 渲染链路上报）。投影 scope 按匹配集**组合键哈希**编入（p<policyID>-crsxc-<sha256[:12]>，
// 由「组合首次出现序 n」改哈希：序号是位置身份，条目增删/
// 重排使 seq 重编号→旧文件名承载另一条目的匹配集（正常路径字节变化走
// Fallback 自愈仅毫秒窗，与拒绝不回滚叠加才持续）；组合键=ips 字面+
// 排序后 listRefs，同名必同键、异键必异名，键不变则文件名稳定（名单条目
// 内容变化热路径原位重写，@ipListFast ≤1s stat 热感知），键变化才换名（旧
// 文件由 24h GC 回收）。同组合多条目共享一份投影（配置字节恒定）。
func emitScopedCRSExclusions(sb *strings.Builder, p *models.SecurityPolicy, entries []CRSExcludedEntry, store caddyConfigStore, chainIndex func() *CRSRuleIndex, cache scopedCRSListCache) error {
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
	var listsByID map[int64][]string
	var err error
	if cache != nil {
		sorted := append([]int64(nil), refIDs...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		var key strings.Builder
		for _, id := range sorted {
			key.WriteString(strconv.FormatInt(id, 10))
			key.WriteByte(',')
		}
		if cached, ok := cache[key.String()]; ok {
			listsByID, err = cached.lists, cached.err
		} else {
			listsByID, _, err = loadIPListEntriesVia(store, refIDs)
			cache[key.String()] = scopedCRSListResult{lists: listsByID, err: err}
		}
	} else {
		listsByID, _, err = loadIPListEntriesVia(store, refIDs)
	}
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
			if msg := fmt.Sprintf("跳过作用域排除条目 %q（策略 %q）：ips/引用列表合并后为空", entry.Target, p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		// 组合键与解析内容无关（名单条目变化不换名）——ips 字面 + 排序后
		// listRefs；同组合条目共享一份投影文件。scope=组合键 sha256[:12]
		//（位置序号改内容身份——同名必同键，重排/增删不使旧名承载
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
			if seq >= crsScopedExclusionMaxDirectives {
				if msg := fmt.Sprintf("策略 %q 的作用域排除展开行数达到上限 %d，其余排除不再发射（少排除=拦截更多，方向安全）", p.Name, crsScopedExclusionMaxDirectives); auditFailureShouldLog(msg) {
					Logf("warn", "%s", msg)
				}
				return nil
			}
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
			if msg := fmt.Sprintf("跳过陈旧排除规则 ID %q（策略 %q）：不存在于本地 CRS 规则索引", target, p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			return nil
		}
		return []string{target}
	}
	if IsCRSGroupCode(target) {
		ids := index.RuleIDsByGroup(target)
		if len(ids) == 0 {
			if msg := fmt.Sprintf("跳过陈旧排除规则组 %q（策略 %q）：不存在于本地 CRS 规则索引", target, p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
		return ids
	}
	if msg := fmt.Sprintf("跳过作用域排除条目 %q（策略 %q）：该 target 形态仅支持 scope=all", target, p.Name); auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
	return nil
}

// crsFileGroupPattern 从 CRS 规则文件名提取两位组号（REQUEST-942-…/-…
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

// crsInfraRuleIDRanges 基础设施组的规则 ID 区间（与 crsInfraGroupCodes 同源：
// 901 初始化 / 949 请求评估 / 959 响应评估）。
var crsInfraRuleIDRanges = [][2]int{{901000, 901999}, {949000, 949999}, {959000, 959999}}

// CRSExclusionTargetRemovesInfra 报告排除目标是否触及基础设施组：两位组号
// ("01"/"49"/"59")、组内规则 ID、REQUEST/RESPONSE-9xx-*.conf 文件名、或与之
// 相交的数字区间（含跨界区间如 900500-902000）。排除基础设施规则无合法用途
// ——偏执级默认值与评分初始化缺失会让守卫按 0 整段跳过、策略静默空转；949/
// 959 评估组缺失会让拦截模式静默退化为仅记录。写入面据此 400，发射面据此
// 跳过 + WARN（与 crs_rule_groups 的剥离口径一致）。
func CRSExclusionTargetRemovesInfra(target string) bool {
	target = strings.TrimSpace(target)
	if IsCRSGroupCode(target) {
		return IsCRSInfraGroupCode(target)
	}
	if IsCRSRuleIDTarget(target) {
		return IsCRSInfraRuleID(target)
	}
	mapped := crsFilenameToRuleIDRange(target)
	lo, hi, ok := crsNumericIDRange(mapped)
	if !ok {
		return false
	}
	for _, infra := range crsInfraRuleIDRanges {
		if lo <= infra[1] && hi >= infra[0] {
			return true
		}
	}
	return false
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

// stripInfraCRSGroupCodes从 crs_rule_groups 载荷剥离基础设施
// 组号（01/49/59）及其文件内规则 ID，返回（保留条目, 被剥条目）。判定复用
// IsCRSInfraGroupCode/IsCRSInfraRuleID——与写入面 validateAndNormalizeCRSField
// 的剥离同口径；条目 trim 后判定以覆盖空白行，保留条目原样交由
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
//
// 树交换探针二次采样（发射点）：本函数是选组路径下规则文件集的实际消费点
// ——入口采样之后到此处可能已过百毫秒（库探测+索引构建+逐策略渲染），窗口
// 若在此间开启，逐条 Include 会指向缺失/半拷贝的规则文件。命中即返回
// errCRSTreeSwapInFlight，由调用方按「整份配置拒绝 + 重试」处理。
func emitCRSRuleGroupSelection(sb *strings.Builder, p *models.SecurityPolicy, groups []string, chainIndex func() *CRSRuleIndex) error {
	if crsTreeSwapInFlightNow() {
		return errCRSTreeSwapInFlight
	}
	// 渲染侧同样按写入侧上限截断（防御深度）：带外/旧快照写入 1 万条组号时，
	// 逐条 HasGroup（O(规则数)）与上万行 Include 会放大配置体积与生成耗时。
	// 写入 API 已 400，此门只对绕过写侧的数据生效。
	if len(groups) > CRSRuleGroupsMaxEntries {
		if msg := fmt.Sprintf("策略 %q 的 crs_rule_groups 条目数 %d 超过上限 %d（疑似带外/旧快照写入），已截断渲染", p.Name, len(groups), CRSRuleGroupsMaxEntries); auditFailureShouldLog(msg) {
			Logf("warn", "%s", msg)
		}
		groups = groups[:CRSRuleGroupsMaxEntries]
	}
	groupSet := make(map[string]struct{}, len(groups))
	var idTargets []string
	seenID := make(map[string]struct{})
	// 组号同样去重（此前仅 6 位 ID 去重）：重复组号渲染出两条同 glob
	// Include，coraza 对重复注册规则 ID 直接编译拒绝（duplicated rule id）。
	seenGroup := make(map[string]struct{})
	for _, g := range groups {
		// 历史遗留行可能含首尾空白（旧校验曾放行），trim 后拼接，
		// 保证 glob 恒为 REQUEST-9<code>-*.conf 的合法形态（镜像下方排除项的 trim）。
		g = strings.TrimSpace(g)
		if IsCRSRuleIDTarget(g) {
			if _, dup := seenID[g]; !dup {
				seenID[g] = struct{}{}
				idTargets = append(idTargets, g)
			}
			continue
		}
		// 渲染侧组号形态门（写侧/导入门之外的最后一道）：集群 apply 与旧
		// 快照通道可绕过写侧校验直写库值，任意字符串会被直拼进 Include
		// glob——注入载荷（含换行的条目）可渲染出独立 coraza 指令行，零匹配
		// glob 则静默失效。仅接受两位数字组号，其余跳过+限流 WARN（skip
		// 保持可用性，与陈旧 ID 的现有 skip 语义一致）。
		if !IsCRSGroupCode(g) {
			msg := fmt.Sprintf("跳过非法 CRS 规则组号条目 %q（策略 %q）：非两位数字组号/6 位规则 ID 形态，疑似带外直写或旧快照残留", g, p.Name)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		if _, dup := seenGroup[g]; dup {
			continue
		}
		seenGroup[g] = struct{}{}
		if !chainIndex().HasGroup(g) {
			if msg := fmt.Sprintf("CRS 规则组 %q（策略 %q）不存在于本地规则索引，Include 可能零匹配", g, p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
		groupSet[g] = struct{}{}
		sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/REQUEST-9%[1]s-*.conf\n", g))
		if p.WAFCheckResponse {
			sb.WriteString(fmt.Sprintf("Include /app/waf/crs/rules/RESPONSE-9%[1]s-*.conf\n", g))
		}
	}
	if len(idTargets) == 0 {
		return nil
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
			if msg := fmt.Sprintf("跳过陈旧 CRS 规则组 ID %q（策略 %q）：不存在于本地规则索引", id, p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
			continue
		}
		// 响应侧规则与响应检查开关联动：waf_check_response=off 时
		// SecResponseBodyAccess Off，RESPONSE 父文件的规则永不消费响应体——
		// 选择零效果。跳过+WARN（保持兼容不 400），UI/摘要侧另有可见性。
		if !p.WAFCheckResponse && strings.HasPrefix(entry.File, "RESPONSE-") {
			if msg := fmt.Sprintf("跳过响应侧 CRS 规则 ID %q（策略 %q）：waf_check_response=off 时响应规则零效果，请开启「检查响应体」或移除该选择", id, p.Name); auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
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
		return nil
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
	return nil
}

// ValidateGeoIPCountries 校验 geoip_countries 载荷：必须是 JSON 数组且条目非空；
// ip2region 已加载（live 或缓存）时条目必须属于已知省份、"海外"或海外国家集
// （域 G：树 Countries 并入 known），未知条目在发射端永不匹配，会静默削弱地域
// 控制。ip2region 未加载且无缓存时同样拒绝未知条目：启动期放行
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
	// allow 模式空名单 = 声称「仅允许所选地域」但渲染端 PolicyHasGeoIP
	// 整链跳过 = 全部放行。deny 空名单是历史「未配置」语义，
	// PolicyHasGeoIP 同样不发射；其与 off 等价，保留兼容（导入/存量）。
	if geoipMode == "allow" && len(entries) == 0 {
		return fmt.Errorf("地域控制为仅允许模式时区域名单不能为空（空名单会拒绝所有请求）")
	}
	// 省份列表单次快照：可用性门与 loaded 判据共用同一取值（冷启动首次
	// 调用会真正执行 336 次采样搜索，两次背靠背调用在多规则校验下放大成本；
	// 且两次调用间若 searcher 热换会读出不同代际）。
	liveProvinces := GetIP2RegionProvinces()
	// （裁决）：IP 库未装载时拒绝启用任何地域条目（含海外——
	// 海外拦截同样依赖 live searcher 设置占位变量，缺库时 CEL 全部恒假、
	// 地域拦截静默零强制）。用户语义：缺库 = IP 相关规则不可启用，待自动/
	// 手动更新 IP 库后恢复；「IP 库」卡片的「未安装」标签提供常态可见性。
	if len(entries) > 0 && len(liveProvinces) <= 1 {
		return fmt.Errorf("IP 库未安装或未加载：地域相关规则不可启用，请先在「安全规则」页更新 IP 库后重试")
	}
	// loaded 判据必须取 live searcher 而非缓存兜底列表——xdb 损坏/
	// 带外替换后 live 已死但省份缓存仍在，用缓存判 loaded 会放行 deny+省份
	// 策略，而发射端占位变量从未设置（CEL 恒假）→ 地域拦截静默零强制。缓存
	// 兜底仅服务于 UI 列表（GetIP2RegionRegions），校验侧以 live 为准。
	provincesLoaded := len(liveProvinces) > 1
	// （核心发现，主线亲证 tree=35 sampled=28 missing=
	// [山西/广西/海南/澳门/西藏/青海]）：known 集必须从全扫描树构建而非 336 点
	// 采样子集（GetIP2RegionProvinceList）——采样网格（42 个 /8 块 × 第二字节
	// {0,32,64,96,128,160,192,224}）漏掉了不与网格相交的省，而 UI
	//（GetIP2RegionRegions 全扫描树）提供全部省份 → 用户能选但保存被「未知
	// 省份」400 拒绝（约 1/6 省份可用性受损）。校验器 known 集改用全扫描树
	// 省份（regionTreeFromXDB 的 Provinces，已含「海外」），与 UI 严格一致。
	known := make(map[string]bool, 36)
	knownCities := map[string]map[string]bool{}
	// 树为 nil（无 xdb 且无缓存兜底）时 known 仅含「海外」——非海外条目由
	// 门（live 未装载）先行拒绝，不会走到这里；空条目则允许通过。
	// 单次取树复用 known 集与城市集两处——原实现两次背靠背
	// GetIP2RegionRegionTree 各做一次 xdb 全量扫描（~220ms×2）；两次调用间
	// 无任何状态变更（仅纯 map 构建），单次快照语义等价。
	tree := GetIP2RegionRegionTree()
	if tree != nil {
		for _, p := range tree.Provinces {
			known[p] = true
		}
		// 域 G：海外国家并入 known 集——国名条目与省份条目同校验
		// 口径（未知国名在发射端永不匹配，静默削弱地域控制）。
		for _, c := range tree.Countries {
			known[c] = true
		}
		// 城市树供「省/市」条目校验（市必须在省的城市集内——防
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
			// 占位变量从未设置，放行即为静默零强制。
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
	// 条件数封顶：每条条件都会发射成一条链式 SecRule 片段，条件数无上限时
	// 单条规则即可把配置体积与编译成本线性放大（全局 128MB 体上限拦不住）。
	if len(conditions) > customRuleMaxConditions {
		return fmt.Errorf("自定义规则最多支持 %d 个匹配条件", customRuleMaxConditions)
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
		if err := validateCustomRulePatternLength(cond.Pattern); err != nil {
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
		// 引用数封顶（去重后计数）：策略列表每次请求都会解析该数组并构建 ID
		// 集合、渲染端逐条解析引用规则——十万级 ID 数组会让列表页解析成本
		// 达到秒级；重复 ID 不放大集合，按去重后口径判定。
		seen := make(map[int]struct{}, len(ids))
		unique := 0
		for _, id := range ids {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			unique++
		}
		if unique > customRuleMaxRefs {
			return fmt.Errorf("custom_rules 引用的自定义规则数量不能超过 %d 条", customRuleMaxRefs)
		}
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
		if r.ConditionLogic != "" && r.ConditionLogic != "and" && r.ConditionLogic != "or" {
			return fmt.Errorf("自定义规则 #%d 的条件关系无效：%q（可选：and、or）", i+1, r.ConditionLogic)
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
		if err := validateCustomRulePatternLength(r.Pattern); err != nil {
			return fmt.Errorf("自定义规则 #%d：%w", i+1, err)
		}
	}
	return nil
}

// validateCustomRulePattern 拒绝四类会破坏 SecRule 行的模式：
//  1. 空/纯空白模式——@contains "" 之类对空模式的匹配等于匹配一切请求，全员命中；
//  2. 真实控制字符（含换行/回车/NUL/制表符等）会截断 SecRule 行；
//  3. 以反斜杠结尾的模式——coraza 的 UnescapeQuotedString 仅反转义 \"，其余
//     反斜杠序列原样保留，末尾的反斜杠会与结尾引号组合成转义引号，使 SecRule
//     行畸形并被 coraza 拒绝，进而导致之后所有配置重生成失败；
//  4. 含「反斜杠+双引号」序列（`\"`）的模式——发射侧只转义双引号、其余反斜杠
//     逐字透传（见 escapeCorazaPattern），该序列渲染成 `\\"`：coraza 先把 `\\`
//     反转义为一个反斜杠，随后的引号提前闭合算子串，整行动作解析失败（保存被
//     Caddy 校验拒绝，提示指向引擎内部而非内容写法）。
func validateCustomRulePattern(operator, pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("匹配内容不能为空")
	}
	for _, r := range pattern {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("匹配内容不能包含控制字符（含制表符）")
		}
	}
	if strings.Contains(pattern, `\"`) {
		// 合法写法：只写引号本身（发射时自动转义）；regex 需匹配「反斜杠+引号」
		// 两个字符时用 \x5c\x22（十六进制转义不受发射期引号转义影响）。
		if operator == "regex" {
			return fmt.Errorf(`匹配内容不能包含「反斜杠+双引号」序列：发射时双引号会被转义，前导反斜杠会让引号提前闭合。匹配双引号请直接写「"」；匹配字面反斜杠用「\\」；需匹配反斜杠+引号两个字符时请用「\x5c\x22」`)
		}
		return fmt.Errorf(`匹配内容不能包含「反斜杠+双引号」序列：发射时双引号会被转义，前导反斜杠会让引号提前闭合。匹配双引号请直接写「"」；匹配字面反斜杠请用「\\」`)
	}
	// coraza 的 @contains/@streq/@beginsWith 会把参数包成 Macro 并做
	// %{VAR} 宏展开；@rx 不展开。非 regex 运算符里的宏会让规则语义静默
	// 动态化，畸形宏还会让 NewWAF 拒绝整份配置。
	if operator != "regex" && strings.Contains(pattern, "%{") {
		return fmt.Errorf("该运算符不支持 %%{...} 宏语法；如需匹配字面量请使用正则运算符并转义 %%")
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
// 全部引擎（向后兼容豁免开启但未存 engines 的形态；空串/`[]` 均属未配置）。
// 畸形非空 JSON 与空集分流——旧实现失败即返回
// true，勾选面被静默放大成「全部引擎」且零告警。保留向后兼容的「全部引擎」
// 语义，但按同文件畸形 JSON 既定口径（auditFailureShouldLog）留痕。
func crawlerEngineSelected(p *models.SecurityPolicy, engineID string) bool {
	if p == nil {
		return true
	}
	var engines []string
	if raw := strings.TrimSpace(string(p.GeoIPCrawlerEngines)); raw != "" {
		if err := json.Unmarshal([]byte(raw), &engines); err != nil {
			msg := fmt.Sprintf("渲染: 策略 #%d 爬虫豁免引擎 geoip_crawler_engines 解析失败（按全部引擎处理）: %v", p.ID, err)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
	}
	if len(engines) == 0 {
		return true
	}
	for _, e := range engines {
		if e == engineID {
			return true
		}
	}
	return false
}
