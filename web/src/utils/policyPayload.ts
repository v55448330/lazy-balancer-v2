// 安全策略保存载荷组装（单源纯函数）。
//
// 载荷组装原先内联在 SecurityPolicies.handleSave，只能靠源码文本钉；
// 字段语义（阶段外字段裁剪、引用列表随开关释放、stage0 信任恒启用、空名单保留）
// 都是后端契约，抽成纯函数后由 policyPayload.spec.ts 行为钉住。
//
// 契约要点（与 internal/models/security.go UpdateSecurityPolicyRequest 对齐）：
//  - 显式 policy_type 提交后服务端把阶段外字段归一为零值；mixed 不显式提交
//  （兼容组仅存量可编辑，省略=后端按内容推断）。
//  - ip_acl_list_refs / ip_whitelist_refs 与内联名单同口径保留（开关关闭不释放）
//    ——关闭开关只影响生效判定，再打开不丢配置；唯一释放路径=用户在引用选择器
//    里显式清空。引用保留期间该名单在列表页仍计为被引用（删除守卫按启用的策略
//    计），用户可先解除引用再删除。
//  - geoip_enabled 是编辑器本地派生开关，后端无此字段，不下发；geoip_mode 关闭时
//    提交 'off'（后端零发射）。
//  - 空名单不清空（关闭开关再打开不丢配置）。

export interface PolicyPayloadInput {
  name: string
  description: string
  enabled: boolean
  mode: string
  anomalyThreshold: number
  ipAclEnabled: boolean
  ipAclMode: string
  ipAclList: readonly string[]
  ipAclListRefs: readonly number[]
  ipWhitelist: readonly string[]
  ipWhitelistRefs: readonly number[]
  /** 编辑器三态开关（stage0 恒启用——见 policyType 分支） */
  ipWhitelistEnabled: boolean
  rateLimitEnabled: boolean
  rateLimitRps: number
  rateLimitBurst: number
  crsRuleGroups: readonly string[]
  /** 已归一（去空行/去重/按 scope 剥离残留）的排除规则对象数组 */
  crsExcludedRules: readonly unknown[]
  customRuleIds: readonly number[]
  blockPageId: number
  blockStatusCode: number
  /** 拦截响应方式：auto=按请求头自动，html=仅 HTML，json=仅 JSON */
  blockResponseMode: string
  geoipCountries: readonly string[]
  geoipEnabled: boolean
  /** geoip_enabled 为真时提交的生效模式（deny/allow；'off' 归一为 deny） */
  geoipMode: string
  geoipCrawlerExempt: boolean
  geoipCrawlerEngines: readonly string[]
  wafCheckResponse: boolean
  logRequestBody: boolean
  trustDetection: boolean
  /** 编辑器类型（mixed 不显式提交） */
  policyType: string
  // —— 阶段 3 人机验证（2026-11-12）——
  /** off/auto/force；仅 stage3 类型提交非 off 值，其余类型强制 off */
  humanVerifyMode: string
  /** slider/js */
  humanVerifyType: string
  /** 通过有效期（分钟） */
  humanVerifyTtl: number
  /** 豁免路径（前缀/通配），JSON 数组文本下发。IP 级放行唯一入口=阶段 0 信任名单 */
  humanExemptPaths: readonly string[]
  // —— 挑战页 CC 触发（同一阶段 3 节点）——
  ccDetectEnabled: boolean
  ccRpsLimit: number
  ccRpsWindow: number
  cc4xxRatio: number
  ccSessionAnomaly: boolean
  ccSessionUaThreshold: number
}

interface PolicyPayload {
  name: string
  description: string
  enabled: boolean
  mode: string
  anomaly_threshold: number
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  ip_whitelist_enabled: boolean
  ip_acl_list_refs: string
  ip_whitelist_refs: string
  rate_limit_enabled: boolean
  rate_limit_rps: number
  rate_limit_burst: number
  crs_rule_groups: string
  crs_excluded_rules: string
  custom_rules: string
  block_page_id: number
  block_status_code: number
  block_response_mode: string
  geoip_countries: string
  geoip_mode: string
  geoip_crawler_exempt: boolean
  geoip_crawler_engines: string
  waf_check_response: boolean
  log_request_body: boolean
  trust_detection: boolean
  policy_type?: string
  human_verify_mode: string
  human_verify_type: string
  human_verify_ttl: number
  human_exempt_paths: string
  cc_detect_enabled: boolean
  cc_rps_limit: number
  cc_rps_window: number
  cc_4xx_ratio: number
  cc_session_anomaly: boolean
  cc_session_ua_threshold: number
}

/**
 * 信任名单生效判定（编辑器口径单源）：阶段 0 恒启用（名单非空即生效），其余类型
 * 按三态开关。保存载荷、向导冲突告警与阶段预览必须共用本谓词——告警/预览各自
 * 读取开关会在「新建阶段 0」时把恒启用的信任条目判成零生效（ipWhitelistEnabled
 * 初值 false 且向导内无开关控件）。
 */
export const trustEnabledForPolicyType = (policyType: string, ipWhitelistEnabled: boolean): boolean =>
  policyType === 'stage0' || ipWhitelistEnabled

export const buildPolicyPayload = (input: PolicyPayloadInput): PolicyPayload => {
  const trustEnabled = trustEnabledForPolicyType(input.policyType, input.ipWhitelistEnabled)
  return {
    name: input.name,
    description: input.description,
    enabled: input.enabled,
    mode: input.mode,
    anomaly_threshold: input.anomalyThreshold,
    ip_acl_enabled: input.ipAclEnabled,
    ip_acl_mode: input.ipAclMode,
    ip_acl_list: JSON.stringify(input.ipAclList),
    ip_whitelist: JSON.stringify(input.ipWhitelist),
    // 阶段 0 信任名单策略：名单非空即生效（恒启用）；其余类型按开关三态语义
    ip_whitelist_enabled: trustEnabled,
    // 引用列表与内联名单同口径保留：开关关闭只影响生效判定（后端按启用位决定
    // 是否消费），不得静默释放已配置的引用——否则「关掉开关再打开」丢配置。
    // 唯一释放路径=用户在引用选择器里显式清空（此时入参已是空数组）。
    ip_acl_list_refs: JSON.stringify(input.ipAclListRefs),
    ip_whitelist_refs: JSON.stringify(input.ipWhitelistRefs),
    rate_limit_enabled: input.rateLimitEnabled,
    rate_limit_rps: input.rateLimitRps,
    rate_limit_burst: input.rateLimitBurst,
    crs_rule_groups: JSON.stringify(input.crsRuleGroups),
    crs_excluded_rules: JSON.stringify(input.crsExcludedRules),
    custom_rules: JSON.stringify(input.customRuleIds),
    block_page_id: input.blockPageId,
    block_status_code: input.blockStatusCode,
    block_response_mode: input.blockResponseMode,
    geoip_countries: JSON.stringify(input.geoipCountries),
    // geoip_enabled=false → 'off'（后端零发射）；开启但模式为 off 的中间态归一为 deny
    geoip_mode: input.geoipEnabled ? (input.geoipMode === 'off' ? 'deny' : input.geoipMode) : 'off',
    geoip_crawler_exempt: input.geoipEnabled && input.geoipCrawlerExempt,
    geoip_crawler_engines: JSON.stringify(input.geoipCrawlerEngines),
    waf_check_response: input.wafCheckResponse,
    log_request_body: input.logRequestBody,
    // 阶段 0：保留检测记录开关（false=直通上游零安全事件；true=事件动作=检测）
    trust_detection: input.trustDetection,
    // mixed 不允许显式提交（省略=后端按内容推断）
    policy_type: input.policyType === 'mixed' ? undefined : input.policyType,
    // 阶段 3 人机验证：仅 stage3 类型承载；其余类型按后端「非本阶段能力归零」
    // 同口径强制 off/0/关，避免类型切换后残留配置在别的阶段误发射。
    human_verify_mode: isHumanStage(input.policyType) ? input.humanVerifyMode : 'off',
    human_verify_type: input.humanVerifyType,
    human_verify_ttl: input.humanVerifyTtl,
    human_exempt_paths: JSON.stringify(isHumanStage(input.policyType) ? input.humanExemptPaths : []),
    cc_detect_enabled: isHumanStage(input.policyType) && input.ccDetectEnabled,
    cc_rps_limit: input.ccRpsLimit,
    cc_rps_window: input.ccRpsWindow,
    cc_4xx_ratio: input.cc4xxRatio,
    cc_session_anomaly: isHumanStage(input.policyType) && input.ccSessionAnomaly,
    cc_session_ua_threshold: input.ccSessionUaThreshold,
  }
}

/** 阶段 3（人机验证）能力域；mixed 可能含 WAF 但不含人机验证阶段（后端同口径归零） */
const isHumanStage = (policyType: string): boolean => policyType === 'stage3'

/**
 * 爬虫豁免「空引擎」守卫。
 *
 * 后端渲染器 `crawlerEngineSelected` 对空集返回 true（空集 = 全部引擎，为兼容
 * 存量不允许改语义：internal/services/caddy.go）；而 UI 复选框「全不选」的直觉
 * 语义是「不豁免任何引擎」。两者相反——豁免开启且未勾选任何引擎时必须阻断保存，
 * 否则用户以为已收紧、实际放宽到全部 15 个引擎。
 *
 * 返回 true 表示该形态不可保存。
 */
export const crawlerExemptionNeedsEngines = (state: {
  geoipEnabled: boolean
  crawlerExempt: boolean
  engines: readonly string[]
}): boolean => state.geoipEnabled && state.crawlerExempt && state.engines.length === 0
