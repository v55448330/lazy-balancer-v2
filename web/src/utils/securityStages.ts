// 阶段化安全流水线共享投影（v2.3.1 阶段化重构）。
// 锁弹框 / 规则向导「安全防护」步骤 / 规则流程抽屉三处消费同一分组模型，避免第二数据源。
// 阶段词汇：阶段 1 = IP 访问控制 + 地域拦截（预检）；阶段 2 = 限流（恒 429）；
// 阶段 3 = WAF（自定义 + CRS）。规则可为阶段 1/3 配拦截页覆盖（0 = 跟随策略，
// 即 v2.3.1 逐策略归因默认层）。

export interface SecurityStageIPListEntry { value: string; remark?: string }
export interface SecurityStageIPList {
  id: number
  name?: string
  entries?: SecurityStageIPListEntry[]
}

export interface SecurityStageBlockPage {
  id: number
  name: string
  content?: string
}

// 策略摘要（GET /security/policies 返回形状的消费面）
export interface SecurityStagePolicy {
  id: number
  name: string
  mode: string
  enabled: boolean
  has_ip_control: boolean
  has_rate_limit: boolean
  has_geoip: boolean
  has_custom_rules: boolean
  geoip_countries: string
  custom_rules_count: number
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  rate_limit_rps: number
  rate_limit_burst: number
  ip_blacklist?: string
  ip_acl_list_refs?: string
  ip_whitelist_refs?: string
  ip_whitelist_enabled?: boolean
  ip_acl_enabled?: boolean
  geoip_mode?: string
  // 实体类型列（后端并行新增）；缺省时由 inferPolicyType 按内容推断
  policy_type?: string
  has_waf?: boolean
  // 阶段 0 信任名单策略：false=直通上游（零安全事件）；true=保留检测记录（事件动作=检测）
  trust_detection?: boolean
  // CRS 规则组选择（摘要原生数组或 JSON 文本；阶段 3 概览「CRS 组 N」计数用）
  crs_rule_groups?: string | string[]
}

// 规则-策略绑定（GET /security/bindings 值数组元素）
export interface SecurityStageBinding {
  policy_id: number
  name: string
  mode: string
  enabled: boolean
  rate_limit_enabled: boolean
  block_page_id?: number
  block_status_code?: number
}

// 规则级阶段拦截页覆盖（0 = 跟随策略）
export interface RuleStagePages {
  block_page_stage1_id?: number
  block_page_stage1_status?: number
  block_page_stage3_id?: number
  block_page_stage3_status?: number
}

export interface StageRow { label: string; detail: string }

export interface StagePolicyGroup {
  key: number
  order: number
  name: string
  enabled: boolean
  rows: StageRow[]
  // 明细懒加载模型：仅流程抽屉展开时由 attachStageDetails 附着；锁弹框/策略页投影恒 undefined
  details?: StagePolicyDetails
}

// ── 明细懒加载模型（决策 C：现有只读端点前端拼装，不新增后端端点） ──

export interface StageDetailEntry {
  value: string
  remark?: string
  source?: string // '内联' | '列表：名称'
}

export interface StageCustomRuleDetail {
  id: number
  name: string
  action: string
  targets: string
  score: number
  enabled: boolean
}

export interface StageRateLimitDetail {
  rps: number
  burst: number
  caption: string
}

export interface StagePolicyDetails {
  aclEntries?: StageDetailEntry[]
  trustEntries?: StageDetailEntry[]
  geoipRegions?: string[]
  rateLimit?: StageRateLimitDetail
  customRules?: StageCustomRuleDetail[]
  crsGroups?: string[]
}

export interface CrsRuleFileOption { filename: string; category: string }

// GET /security/rules/:caddy_id/policy 直接序列化 models.SecurityPolicy——json.RawMessage
// 字段以原生 JSON（id 数组/组码数组）出现，按 unknown 接收再解析
export interface SecurityStagePolicyDetail {
  id: number
  custom_rules?: unknown
  crs_rule_groups?: unknown
}

export interface SecurityStageCustomRule {
  id: number
  name: string
  action?: string
  score?: number
  enabled?: boolean
  conditions?: Array<{ target: string; operator?: string; pattern?: string }>
}

export interface StageDetailSources {
  fullPolicies?: ReadonlyMap<number, SecurityStagePolicyDetail>
  customRules?: readonly SecurityStageCustomRule[]
  crsFiles?: readonly CrsRuleFileOption[]
}

// 规则阶段页覆盖徽标（页已删/内容空 = broken，渲染侧等同未配）
export interface StageOverride {
  pageId: number
  pageName: string
  status: number
  broken: boolean
}

export interface StageGroup {
  stage: 0 | 1 | 2 | 3
  title: string
  enabled: boolean
  override: StageOverride | null
  groups: StagePolicyGroup[]
  footnote?: string
}

export interface RuleStageModel {
  hasAnyPolicy: boolean
  stages: [StageGroup, StageGroup, StageGroup, StageGroup]
}

// 流程弹框的展示目标（规则行入口；caddyId 存在时才拉取阶段计数与证书信息）
export interface RuleFlowUpstream {
  host: string
  port: number
  protocol: string
  weight: number
  max_connections: number
  enabled: boolean
}

export interface RuleFlowTarget {
  caddyId?: string
  name: string
  protocol: 'http' | 'tcp'
  listenPort: number
  enableTls: boolean
  // 接入卡富化：规则全部域名（chips 展示，逗号分隔解析由调用方完成）
  domains?: string[]
  // 接入卡富化：TLS 来源（manual/acme_dns）与 ACME 配置名（调用方从证书配置列表解析）
  tlsSource?: string
  acmeConfigName?: string
  // 上游卡富化：后端域名（空 = 透传原始 Host）与上游明细行
  hostHeader?: string
  upstreamSummary: string
  upstreams?: RuleFlowUpstream[]
  // 健康口径：规则级计数 + 逐上游状态映射（host:port 键）；无探针数据时调用方不传
  health?: { healthy: number; unhealthy: number; degraded: number; unknown: number; na: number; total: number }
  upstreamHealth?: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; dynamic?: boolean }>
}

// 阶段编号体系：阶段 0 · 信任名单 → 阶段 1 · IP 访问控制 → 阶段 2 · 限流 → 阶段 3 · WAF
export const STAGE_SHORT_TITLES: Record<0 | 1 | 2 | 3, string> = {
  0: '阶段 0 · 信任名单',
  1: '阶段 1 · IP 访问控制',
  2: '阶段 2 · 限流',
  3: '阶段 3 · WAF',
}

// 阶段页状态码选项（与策略表单返回状态码同集；0 = 跟随策略不在此列出，由调用方单独提供）
export const STAGE_BLOCK_STATUS_OPTIONS: ReadonlyArray<{ value: number; label: string }> = [
  { value: 400, label: '400 Bad Request' },
  { value: 401, label: '401 Unauthorized' },
  { value: 403, label: '403 Forbidden' },
  { value: 404, label: '404 Not Found' },
  { value: 503, label: '503 Service Unavailable' },
]

export const STAGE_TITLES: Record<0 | 1 | 2 | 3, string> = {
  0: '阶段 0 · 信任名单',
  1: '阶段 1 · IP 访问控制',
  2: '阶段 2 · 限流',
  3: '阶段 3 · WAF',
}

export const wafModeLabel = (mode: string): string => {
  if (mode === 'blocking') return '拦截'
  if (mode === 'detection') return '检测'
  if (mode === 'custom_only') return '仅自定义'
  return '关闭'
}

export const wafModeTagType = (mode: string): 'danger' | 'warning' | 'info' => {
  if (mode === 'blocking') return 'danger'
  if (mode === 'detection') return 'warning'
  return 'info'
}

// ip 名单 JSON 文本 → 字符串数组（坏数据回退空数组，不得炸渲染路径）
export const parseIPList = (raw: string | undefined): string[] => {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

// refs 字段为 JSON 数字数组文本（如 "[1,5]"）——字符串过滤会丢弃数字 id，需独立解析
export const parseRefIds = (raw: string | undefined): number[] => {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.map(Number).filter((n) => Number.isInteger(n) && n > 0)
  } catch { return [] }
}

// GeoIP 区域 JSON 文本 → 区域数（同 parseIPList 守卫口径）
export const parseGeoipCountryCount = (raw: string): number => {
  if (!raw) return 0
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.length : 0
  } catch {
    return 0
  }
}

// 合并内联 + 引用列表条目（按精确字符串去重），缺失的引用列表跳过（防御性回退为仅内联）
export const mergeIpEntries = (
  ipLists: readonly SecurityStageIPList[],
  inline: readonly string[],
  refs: readonly number[],
): string[] => {
  const set = new Set(inline.map((v) => v.trim()).filter((v) => v !== ''))
  for (const id of refs) {
    const list = ipLists.find((l) => l.id === id)
    if (!list) continue
    for (const entry of list.entries ?? []) {
      const v = entry.value.trim()
      if (v !== '') set.add(v)
    }
  }
  return [...set]
}

// 阶段页覆盖解析：pageId<=0 → null（跟随策略）；页已删/内容空 → broken
export const resolveStageOverride = (
  pageId: number | undefined,
  status: number | undefined,
  blockPages: readonly SecurityStageBlockPage[],
): StageOverride | null => {
  const id = pageId ?? 0
  if (id <= 0) return null
  const page = blockPages.find((p) => p.id === id)
  const broken = !page || (page.content ?? '') === ''
  return {
    pageId: id,
    pageName: page?.name ?? `页面 #${id}`,
    status: status && status > 0 ? status : 403,
    broken,
  }
}
// 信任名单非空谓词（阶段 0 能力：内联 ∪ 引用，内联/引用任一非空即算）
export const hasTrustEntries = (p: { ip_whitelist?: string; ip_whitelist_refs?: string }): boolean =>
  parseIPList(p.ip_whitelist).length > 0 || parseRefIds(p.ip_whitelist_refs).length > 0

// 阶段 1 · IP 访问控制谓词（信任除外——2026-09-21 用户裁定：信任恒归独立阶段 0）：
// ACL 启用且（内联∪引用非空），或遗留黑名单非空。has_ip_control 摘要标志含信任
// （镜像后端发射语义），阶段归属判定不得直接消费它——否则纯信任策略会在阶段 1
// 投出「列表 0 条 · 黑名单 0 条」空行并被误判为 mixed。
export const hasIPACLControl = (p: {
  has_ip_control?: boolean
  ip_acl_enabled?: boolean
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_blacklist?: string
}): boolean => {
  // 原始字段齐备时按定义判定；缺失（如精简绑定载荷）回退摘要标志
  if (p.ip_acl_enabled !== undefined || p.ip_blacklist !== undefined || p.ip_acl_list !== undefined) {
    return (
      (p.ip_acl_enabled === true && (parseIPList(p.ip_acl_list).length > 0 || parseRefIds(p.ip_acl_list_refs).length > 0)) ||
      parseIPList(p.ip_blacklist).length > 0
    )
  }
  return p.has_ip_control === true
}

// 阶段 0 · 信任名单行：条目数（空=未配置，任务 G 口径）+ 直通/保留检测模式
const buildStage0Rows = (policy: SecurityStagePolicy | undefined, ipLists: readonly SecurityStageIPList[]): StageRow[] => {
  const rows: StageRow[] = []
  if (!policy || !hasTrustEntries(policy)) return rows
  const trustCount = mergeIpEntries(ipLists, parseIPList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs)).length
  rows.push({ label: '信任名单', detail: trustCount === 0 ? '未配置' : `${trustCount} 条${policy.ip_whitelist_enabled === false ? '（未启用）' : ''}` })
  rows.push({ label: '模式', detail: policy.trust_detection === true ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）' })
  return rows
}

const buildStage1Rows = (policy: SecurityStagePolicy | undefined, ipLists: readonly SecurityStageIPList[]): StageRow[] => {
  const rows: StageRow[] = []
  if (policy && hasIPACLControl(policy)) {
    // 阶段 1 不再承载信任名单（阶段 0 独立；契约：阶段 1 策略创建/显式切换时服务端归一清除）
    const modeLabel = policy.ip_acl_mode === 'allow' ? '白名单模式' : (policy.ip_acl_mode === 'bypass' ? '免检测模式' : '黑名单模式')
    const aclCount = mergeIpEntries(ipLists, parseIPList(policy.ip_acl_list), parseRefIds(policy.ip_acl_list_refs)).length
    const blCount = parseIPList(policy.ip_blacklist).length
    rows.push({ label: 'IP 访问控制', detail: `${modeLabel} · 列表 ${aclCount} 条 · 黑名单 ${blCount} 条` })
  }
  // 地域拦截（启用态）：启用 → 区域数；关闭但保留区域 → 已关闭（保留 N 区域）
  const geoCount = parseGeoipCountryCount(policy?.geoip_countries ?? '')
  if (policy?.has_geoip || geoCount > 0) {
    const geoModeLabel = policy?.geoip_mode === 'allow' ? '仅允许所选区域' : '拦截所选区域'
    rows.push({ label: '地域拦截', detail: policy?.has_geoip ? `${geoModeLabel} · ${geoCount} 区域` : `已关闭（保留 ${geoCount} 区域）` })
  }
  return rows
}

const buildStage3Rows = (
  binding: SecurityStageBinding,
  policy: SecurityStagePolicy | undefined,
  blockPages: readonly SecurityStageBlockPage[],
): StageRow[] => {
  const rows: StageRow[] = []
  const mode = policy ? policy.mode : binding.mode
  // WAF 全关（off）= CRS 与自定义规则均不生效，阶段 3 引擎不为该策略渲染——
  // 拦截页归因无从谈起，整组不出组（实体单职化后阶段外能力同此裁剪）
  if (mode === 'off') return rows
  if (mode === 'blocking') rows.push({ label: 'WAF（拦截）', detail: '命中即阻断' })
  else if (mode === 'detection') rows.push({ label: 'WAF（检测）', detail: '仅记录不阻断' })
  else if (mode === 'custom_only') rows.push({ label: 'WAF（仅自定义）', detail: 'CRS 不生效，自定义规则按规则内动作执行' })
  // 「CRS 规则组」行（blocking/detection 才有 CRS 评估；0=全部默认）
  if (mode === 'blocking' || mode === 'detection') {
    const crsRaw = policy?.crs_rule_groups
    const crsCount = Array.isArray(crsRaw) ? crsRaw.length : parseIPList(typeof crsRaw === 'string' ? crsRaw : undefined).length
    rows.push({ label: 'CRS 规则组', detail: crsCount > 0 ? `${crsCount} 组` : '全部（默认）' })
  }
  if (policy?.has_custom_rules) rows.push({ label: '自定义规则', detail: `${policy.custom_rules_count} 条` })
  // 「拦截页」行（v2.3.1 归因口径）：配置了页 → <页名>(状态码 XXX)；block_page_id=0 →
  // 默认 403；页已删/内容空 → 已失效(回落首策略)
  const pageId = binding.block_page_id ?? 0
  const page = pageId > 0 ? blockPages.find((p) => p.id === pageId) : undefined
  const pageBroken = pageId > 0 && (!page || (page.content ?? '') === '')
  if (pageId <= 0) rows.push({ label: '拦截页', detail: '默认 403' })
  else if (pageBroken) rows.push({ label: '拦截页', detail: '已失效（回落首策略）' })
  else rows.push({ label: '拦截页', detail: `${page?.name}（状态码 ${binding.block_status_code || 403}）` })
  return rows
}

// 三阶段分组投影：bindings 顺序（policy_id ASC）即执行顺序；禁用策略保留显示（灰态由消费方渲染）
export const buildStageModel = (
  bindings: readonly SecurityStageBinding[],
  policies: readonly SecurityStagePolicy[],
  ipLists: readonly SecurityStageIPList[],
  blockPages: readonly SecurityStageBlockPage[],
  stagePages?: RuleStagePages | null,
): RuleStageModel => {
  const stage0Groups: StagePolicyGroup[] = []
  const stage1Groups: StagePolicyGroup[] = []
  const stage2Groups: StagePolicyGroup[] = []
  const stage3Groups: StagePolicyGroup[] = []

  bindings.forEach((binding, index) => {
    const policy = policies.find((p) => p.id === binding.policy_id)
    const base = { key: binding.policy_id, order: index + 1, name: binding.name, enabled: binding.enabled }

    const s0rows = buildStage0Rows(policy, ipLists)
    if (s0rows.length > 0) stage0Groups.push({ ...base, rows: s0rows })

    const s1rows = buildStage1Rows(policy, ipLists)
    if (s1rows.length > 0) stage1Groups.push({ ...base, rows: s1rows })

    // 阶段 2：限流（全部策略的限流集中在 WAF 之前，拦截恒 429）
    if (policy?.has_rate_limit) {
      stage2Groups.push({ ...base, rows: [{ label: '速率限制', detail: `${policy.rate_limit_rps} 次/秒 · 突发 ${policy.rate_limit_burst} 次` }] })
    }

    const s3rows = buildStage3Rows(binding, policy, blockPages)
    if (s3rows.length > 0) stage3Groups.push({ ...base, rows: s3rows })
  })

  return {
    hasAnyPolicy: bindings.length > 0,
    stages: [
      {
        stage: 0,
        title: STAGE_TITLES[0],
        enabled: stage0Groups.length > 0,
        override: null,
        groups: stage0Groups,
      },
      {
        stage: 1,
        title: STAGE_TITLES[1],
        enabled: stage1Groups.length > 0,
        override: resolveStageOverride(stagePages?.block_page_stage1_id, stagePages?.block_page_stage1_status, blockPages),
        groups: stage1Groups,
      },
      {
        stage: 2,
        title: STAGE_TITLES[2],
        enabled: stage2Groups.length > 0,
        override: null,
        groups: stage2Groups,
        footnote: '限流拦截恒为 429',
      },
      {
        stage: 3,
        title: STAGE_TITLES[3],
        enabled: stage3Groups.length > 0,
        override: resolveStageOverride(stagePages?.block_page_stage3_id, stagePages?.block_page_stage3_status, blockPages),
        groups: stage3Groups,
      },
    ],
  }
}

// 向导「安全防护」步骤的实时投影输入：选中策略 id → 合成绑定视图（页/状态码未绑时按默认口径）
export const bindingsFromPolicyIds = (
  policyIds: readonly number[],
  policies: readonly SecurityStagePolicy[],
): SecurityStageBinding[] =>
  policies
    .filter((p) => policyIds.includes(p.id))
    .map((p) => ({
      policy_id: p.id,
      name: p.name,
      mode: p.mode,
      enabled: p.enabled,
      rate_limit_enabled: p.has_rate_limit,
      block_page_id: 0,
      block_status_code: 403,
    }))

// ── 明细拼装（流程抽屉首次展开时调用；纯函数，不持有缓存） ──

// 内联 ∪ 引用逐条明细（精确字符串去重，内联优先；引用条目携带 remark 与来源列表名）
export const mergeIpEntryDetails = (
  ipLists: readonly SecurityStageIPList[],
  inline: readonly string[],
  refs: readonly number[],
): StageDetailEntry[] => {
  const seen = new Set<string>()
  const out: StageDetailEntry[] = []
  for (const raw of inline) {
    const v = raw.trim()
    if (v === '' || seen.has(v)) continue
    seen.add(v)
    out.push({ value: v, source: '内联' })
  }
  for (const id of refs) {
    const list = ipLists.find((l) => l.id === id)
    if (!list) continue
    for (const entry of list.entries ?? []) {
      const v = entry.value.trim()
      if (v === '' || seen.has(v)) continue
      seen.add(v)
      out.push({ value: v, remark: entry.remark || undefined, source: `列表：${list.name ?? `#${id}`}` })
    }
  }
  return out
}

// CRS 组码 → 「请求 · 942 · SQL 注入」式标签（与安全策略页组名表同口径，由规则文件列表推导；
// 列表未加载/组已消失时回退裸组码，不阻断明细区）
export const crsGroupLabel = (groupCode: string, crsFiles: readonly CrsRuleFileOption[]): string => {
  const file = crsFiles.find((r) => new RegExp(`^(?:REQUEST|RESPONSE)-9${groupCode}-`, 'i').test(r.filename))
  if (!file) return groupCode
  const phase = /^RESPONSE-/i.test(file.filename) ? '响应' : '请求'
  return `${phase} · 9${groupCode} · ${file.category}`
}

// 限流口径文案（与后端 buildRateLimitHandler 双 zone 语义一致）：
// burst > 0 → 1s 窗口封顶 rps+burst（瞬时），60s 窗口封顶 rps×60（持续）；burst=0 → 单 1s 窗口
export const rateLimitDetailCaption = (rps: number, burst: number): string =>
  burst > 0
    ? `1s 窗口上限 ${rps + burst} 次（含突发）· 60s 窗口上限 ${rps * 60} 次（持续 ${rps} 次/秒）`
    : `1s 窗口上限 ${rps} 次`

// 原生 JSON（/security/rules/:id/policy 的 RawMessage 字段）→ 数字 id 数组
//（兼容对象形态 [{id:…}]，与 SecurityPolicies.parseCustomRuleIds 同守卫）
const parseUnknownIds = (raw: unknown): number[] => {
  if (!Array.isArray(raw)) return []
  return raw.map((item) => {
    if (typeof item === 'number') return item
    if (typeof item === 'object' && item !== null && 'id' in item) {
      // 'id' in 收窄后 TS 推为 unknown，再经 typeof 判定——不做未校验断言
      return typeof item.id === 'number' ? item.id : 0
    }
    return 0
  }).filter((n) => Number.isInteger(n) && n > 0)
}

const parseUnknownStrings = (raw: unknown): string[] => {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string')
  if (typeof raw === 'string') return parseIPList(raw)
  return []
}

const buildGroupDetails = (
  policy: SecurityStagePolicy | undefined,
  stage: 0 | 1 | 2 | 3,
  ipLists: readonly SecurityStageIPList[],
  sources: StageDetailSources | undefined,
): StagePolicyDetails | undefined => {
  if (!policy) return undefined
  // 阶段 0 · 信任名单：条目逐条（内联∪引用带 source/remark）
  if (stage === 0) {
    if (!hasTrustEntries(policy)) return undefined
    return { trustEntries: mergeIpEntryDetails(ipLists, parseIPList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs)) }
  }
  if (stage === 1) {
    const details: StagePolicyDetails = {}
    if (policy.has_ip_control) {
      details.aclEntries = mergeIpEntryDetails(ipLists, parseIPList(policy.ip_acl_list), parseRefIds(policy.ip_acl_list_refs))
    }
    const regions = parseIPList(policy.geoip_countries)
    if (policy.has_geoip || regions.length > 0) details.geoipRegions = regions
    return details
  }
  if (stage === 2) {
    if (!policy.has_rate_limit) return undefined
    return { rateLimit: { rps: policy.rate_limit_rps, burst: policy.rate_limit_burst, caption: rateLimitDetailCaption(policy.rate_limit_rps, policy.rate_limit_burst) } }
  }
  // 阶段 3：自定义规则逐条（按策略 custom_rules id 引用 join 自定义规则库）+ CRS 组 chips
  const details: StagePolicyDetails = {}
  const full = sources?.fullPolicies?.get(policy.id)
  if (full) {
    const customIds = parseUnknownIds(full.custom_rules)
    if (customIds.length > 0) {
      details.customRules = customIds.map((id) => {
        const rule = sources?.customRules?.find((r) => r.id === id)
        return rule
          ? { id, name: rule.name, action: rule.action || 'block', targets: (rule.conditions ?? []).map((c) => c.target).join(' / '), score: rule.score ?? 0, enabled: rule.enabled !== false }
          : { id, name: `规则 #${id}`, action: '-', targets: '', score: 0, enabled: true }
      })
    }
    const groups = parseUnknownStrings(full.crs_rule_groups)
    if (groups.length > 0) details.crsGroups = groups.map((code) => crsGroupLabel(code, sources?.crsFiles ?? []))
  }
  return details
}

// 明细附着：在既有投影模型上按策略回填逐条明细（不重建模型——键 = policy_id + 阶段，
// 调用方在抽屉展开且数据源就绪后调用一次，结果直接替换展示模型）
export const attachStageDetails = (
  model: RuleStageModel,
  input: {
    policies: readonly SecurityStagePolicy[]
    ipLists: readonly SecurityStageIPList[]
    sources?: StageDetailSources
  },
): RuleStageModel => {
  // map 产出 StageGroup[]，而 stages 是定长三元组——逐阶段一一对应不增不减，
  // 属「结构相同但推断无法合一」的合法断言（先落命名常量再整体返回）
  const stages = model.stages.map((stage) => ({
    ...stage,
    groups: stage.groups.map((group) => ({
      ...group,
      details: buildGroupDetails(input.policies.find((p) => p.id === group.key), stage.stage, input.ipLists, input.sources),
    })),
  })) as [StageGroup, StageGroup, StageGroup, StageGroup]
  return { ...model, stages }
}

// ── 策略类型（实体单职化：policy_type 列由后端携带；缺省时按内容推断兜底，前后端同一份逻辑形状） ──

export type SecurityPolicyType = 'stage0' | 'stage1' | 'stage2' | 'stage3' | 'mixed'

export const POLICY_TYPE_LABELS: Record<SecurityPolicyType, string> = {
  stage0: '阶段 0 · 信任名单',
  stage1: '阶段 1 · IP 访问控制',
  stage2: '阶段 2 · 限流',
  stage3: '阶段 3 · WAF',
  mixed: '混合策略（兼容旧版）',
}

export const POLICY_TYPE_SHORT_LABELS: Record<SecurityPolicyType, string> = {
  stage0: '阶段 0',
  stage1: '阶段 1',
  stage2: '阶段 2',
  stage3: '阶段 3',
  mixed: '混合',
}

// 推断输入形状（策略类型组件/列表/抽屉共用；SecurityStagePolicy 与策略页 PolicySummary 均结构满足）
export interface SecurityPolicyTypeInput {
  policy_type?: string
  has_ip_control: boolean
  has_geoip?: boolean
  has_rate_limit: boolean
  has_waf?: boolean
  has_custom_rules: boolean
  mode?: string
  // 阶段 0 推断（g0=信任名单非空）：内联 JSON 文本或引用 id 数组文本
  ip_whitelist?: string
  ip_whitelist_refs?: string
  // 阶段 1 信任除外判定（可选原始字段；缺省时回退 has_ip_control 摘要标志）
  ip_acl_enabled?: boolean
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_blacklist?: string
}

// 推断形状：阶段 0 = 信任名单非空；阶段 1 = IP 访问控制或地域拦截；阶段 2 = 限流；
// 阶段 3 = WAF 或自定义规则。恰好一个阶段 → 该类型；跨阶段 → mixed（存量混合兼容组）；
// 零能力 → stage3（存量空策略的 mode 字段定义其为 WAF 策略关闭态）。
export const inferPolicyType = (p: SecurityPolicyTypeInput): SecurityPolicyType => {
  if (p.policy_type === 'stage0' || p.policy_type === 'stage1' || p.policy_type === 'stage2' || p.policy_type === 'stage3' || p.policy_type === 'mixed') {
    return p.policy_type
  }
  const s0 = hasTrustEntries(p)
  const s1 = hasIPACLControl(p) || p.has_geoip === true
  const s2 = p.has_rate_limit
  const s3 = (p.has_waf ?? (p.mode !== undefined && p.mode !== 'off')) || p.has_custom_rules
  const stageCount = [s0, s1, s2, s3].filter(Boolean).length
  if (stageCount > 1) return 'mixed'
  if (s0) return 'stage0'
  if (s1) return 'stage1'
  if (s2) return 'stage2'
  return 'stage3'
}
