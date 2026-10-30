// 阶段化安全流水线共享投影（v2.3.1 阶段化重构）。
// 锁弹框 / 流程抽屉 / 策略向导预览 / SecurityBindingEditor 四处消费同一分组模型，避免第二数据源。
// 阶段词汇：阶段 1 = IP 访问控制 + 地域拦截（预检）；阶段 2 = 限流（恒 429）；
// 阶段 3 = WAF（自定义 + CRS）。规则可为阶段 1/3 配拦截页覆盖（0 = 跟随策略，
// 即 v2.3.1 逐策略归因默认层）。
import type { RuleFlowPathRule } from '@/types/rules'
import { hasOwn } from './hasOwn.ts'
import { toV4Long, toV6BigInt } from './ipAddress.ts'

interface SecurityStageIPListEntry { value: string; remark?: string }
export interface SecurityStageIPList {
  id: number
  name?: string
  entry_count?: number
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
  geoip_crawler_exempt?: boolean
  geoip_crawler_engines?: string
  // 实体类型列（后端并行新增）；缺省时由 inferPolicyType 按内容推断
  policy_type?: string
  has_waf?: boolean
  // 阶段 0 信任名单策略：false=直通上游（零安全事件）；true=保留检测记录（事件动作=检测）
  trust_detection?: boolean
  // CRS 规则组选择（摘要原生数组或 JSON 文本；阶段 3 概览「CRS 组 N」计数用）
  crs_rule_groups?: string | string[]
  // 策略级拦截页（2026-09-25 裁定 stage1/stage2 均可配；投影面此前未呈现）
  block_page_id?: number
  block_status_code?: number
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
interface RuleStagePages {
  block_page_stage1_id?: number
  block_page_stage1_status?: number
  block_page_stage3_id?: number
  block_page_stage3_status?: number
}

interface StageRow { label: string; detail: string }

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

interface StageDetailEntry {
  value: string
  remark?: string
  source?: string // '内联' | '列表：名称'
}

interface StageCustomRuleDetail {
  id: number
  name: string
  action: string
  targets: string
  score: number
  enabled: boolean
}

interface StageRateLimitDetail {
  rps: number
  burst: number
  caption: string
}

interface StagePolicyDetails {
  // aclLists=引用名单汇总（名称+条数，entry_count 口径，不拉条目值）；
  // aclInlineCount=内联去重条数。两者替代原逐条 aclEntries。
  aclLists?: Array<{ name: string; count: number }>
  aclInlineCount?: number
  // 遗留独立黑名单（ip_blacklist）条目：与 ACL 开关无关、恒参与阶段 1 拒绝
  // 判定；摘要「独立黑名单 N 条仍生效」必须能在明细则对账。
  blacklistEntries?: string[]
  trustEntries?: StageDetailEntry[]
  geoipRegions?: string[]
  rateLimit?: StageRateLimitDetail
  customRules?: StageCustomRuleDetail[]
  crsGroups?: string[]
}

export interface CrsRuleFileOption { filename: string; category: string }

/**
 * CRS 规则文件名 → 阶段与两位组码（如 REQUEST-942-… / RESPONSE-955-…）。
 * 存储契约用两位组码（'42'），展示用 '9' 前缀（'942'）；文件名不符合
 * REQUEST|RESPONSE + '-9<dd>-' 形态时返回 null，由调用方决定回退。
 * 文件名解析（组码/相位）在全仓只此一份——向导选项、级联叶、ghost 标签、
 * 阶段明细标签共用，避免外部命名契约变更时多点漏改。
 */
interface CrsFilenameInfo { readonly phase: '请求' | '响应'; readonly code: string }

export const parseCrsFilename = (filename: string): CrsFilenameInfo | null => {
  const match = /^(REQUEST|RESPONSE)-9(\d{2})-/i.exec(filename)
  if (!match) return null
  return { phase: match[1].toUpperCase() === 'RESPONSE' ? '响应' : '请求', code: match[2] }
}

/**
 * CRS 规则源码片段定位（只读排障展示）：按 `id:<ruleId>` 精确 ID 边界匹配，
 * 取命中行上下文 ±contextLines 行；未命中返回空串。
 *
 * 边界为何必须：`id:942100` 是 `id:9421000` 的子串，纯 includes 会把片段中心
 * 落到更长的 ID 行上（CRS 短 ID 与长 ID 混存时展示的不是触发规则）。ID 后
 * 不得再接数字——可选引号先吞掉再判边界，兼容 `id:942100,` / `id:'942100'` /
 * `id:"942100"` 三种写法。
 */
export const extractCrsRuleSnippet = (content: string, ruleId: string, contextLines = 10): string => {
  const id = (ruleId ?? '').trim()
  if (id === '' || content === '') return ''
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const pattern = new RegExp(`\\bid\\s*:\\s*["']?${escaped}["']?(?!\\d)`)
  const lines = content.split('\n')
  const idx = lines.findIndex((line) => pattern.test(line))
  if (idx === -1) return ''
  return lines.slice(Math.max(0, idx - contextLines), Math.min(lines.length, idx + contextLines + 1)).join('\n')
}

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
  condition_logic?: 'and' | 'or'
  conditions?: Array<{ target: string; operator?: string; pattern?: string }>
}

export interface StageDetailSources {
  fullPolicies?: ReadonlyMap<number, SecurityStagePolicyDetail>
  customRules?: readonly SecurityStageCustomRule[]
  crsFiles?: readonly CrsRuleFileOption[]
}

// 规则阶段页覆盖徽标（页已删/内容空 = broken，渲染侧等同未配）
interface StageOverride {
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
  // 规则已禁用：控制面不为 enabled=0 的规则渲染任何路由（安全链不进入运行
  // 配置），锁摘要/流程弹框必须显式降级——否则巡检得到「四阶段在位」的结论
  // 而实际该域名零 listener（误判方向是高估防护）。
  ruleDisabled: boolean
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
  // 自定义路径规则分发（流程弹框「路由分发」节点）；缺省/空 = 仅主路由，流程图不出该节点
  pathRules?: RuleFlowPathRule[]
}

// 阶段编号体系：阶段 0 · 信任名单 → 阶段 1 · IP 访问控制 → 阶段 2 · 限流 → 阶段 3 · WAF
// （STAGE_SHORT_TITLES 与本常量曾逐字同值双源，已合并为单一份）
export const STAGE_TITLES: Record<0 | 1 | 2 | 3, string> = {
  0: '阶段 0 · 信任名单',
  1: '阶段 1 · IP 访问控制',
  2: '阶段 2 · 限流',
  3: '阶段 3 · WAF',
}

// 阶段副标题（流程弹框节点）与阶段 1 脚注：渲染链语义的唯一文案源。
// 阶段 1 副标题/脚注此前漏列 v2.3.8 爬虫校验（豁免 id 810000-849999 /
// 伪装拦截 850000-899999），脚注另漏列遗留黑名单字段 ip_blacklist（id:4 仍由
// security.go 发射）。链序按发射顺序：信任(id:3/5/12) → 黑名单(id:2) → 遗留黑名单
// (id:4) → 白名单外拒绝(id:7) → 白名单豁免 → 爬虫校验 → 地域拦截(id:800000+)。
// id:5 只在「IP ACL 绕过模式占用 id:3」时承载同一信任名单并集
// （security.go trustID 分支）——归信任族，不是白名单外拒绝。
export const stageSubLabel = (stage: 1 | 2 | 3): string => {
  if (stage === 1) return 'IP 名单 · 爬虫校验 · 地域 · 威胁库'
  if (stage === 2) return '速率限制'
  return '自定义 · CRS'
}

/**
 * 阶段 1 脚注；`trustDetectionBound` = 绑定了「保留检测」信任策略（命中降级为检测）。
 *
 * 白名单豁免面必须写成「其后全部预检」：引擎发射的豁免规则是
 * `pass,nolog,skipAfter:SECURITY_RULES_END`，命中后跳过预检段内其后的一切规则
 * （逐策略 GeoIP 链与爬虫伪装族一并跳过）。旧文案「豁免地域拦截」会让读者以为
 * 白名单成员仍会被爬虫校验拦下，排障时误判「规则失效」。
 */
export const stage1FootnoteText = (trustDetectionBound: boolean): string => {
  const base = '多策略合并预检：信任（阶段 0）→ 黑名单 → 遗留黑名单（旧字段）→ 白名单外拒绝（白名单命中豁免其后全部预检，含爬虫校验与地域拦截）→ 爬虫校验 → 地域拦截；未通过即终止'
  return trustDetectionBound ? `${base}；绑定「保留检测」信任策略时命中降级为检测事件，不终止` : base
}

// 阶段页状态码选项（与策略表单返回状态码同集；0 = 跟随策略不在此列出，由调用方单独提供）
export const STAGE_BLOCK_STATUS_OPTIONS: ReadonlyArray<{ value: number; label: string }> = [
  { value: 400, label: '400 Bad Request' },
  { value: 401, label: '401 Unauthorized' },
  { value: 403, label: '403 Forbidden' },
  { value: 404, label: '404 Not Found' },
  { value: 503, label: '503 Service Unavailable' },
]

// 带外/导入 JSON 的字符串数组统一 trim；空项与非字符串一律丢弃。
export const normalizeStringEntries = (raw: unknown): string[] => {
  if (!Array.isArray(raw)) return []
  return raw
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter((item) => item !== '')
}

// ip 名单 JSON 文本 → 字符串数组（坏数据回退空数组，不得炸渲染路径）
export const parseIPList = (raw: string | undefined): string[] => {
  if (!raw) return []
  try {
    return normalizeStringEntries(JSON.parse(raw) as unknown)
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
const parseGeoipCountryCount = (raw: string): number => {
  if (!raw) return 0
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.length : 0
  } catch {
    return 0
  }
}

// 条数-only 合并口径（列表载荷不内联 entries 后的计数面——锁摘要/流程弹框
// 标题条数）：内联去重数 + Σ引用名单 entry_count。与 mergeIpEntries 的去重
// 合计在「内联与引用重叠」时略有出入；仅作展示计数，精确明细由
// mergeIpEntryDetails（按需详情拉取后）承担。
export const mergeIpEntryCount = (
  ipLists: readonly SecurityStageIPList[],
  inline: readonly string[],
  refs: readonly number[],
): number => {
  const inlineCount = new Set(inline.map((v) => v.trim()).filter((v) => v !== '')).size
  return refs.reduce((sum, id) => sum + (ipLists.find((l) => l.id === id)?.entry_count ?? 0), inlineCount)
}

// 生效条目合并内核：内联 ∪ 引用条目组（每项 trim 后按精确字符串去重，空串剔除）。
// 三处调用方（本文件 / SecurityPolicies 向导 / IPLocationAction 处置页）数据源
// 成形不同，各自薄包装后共用本内核。
export const mergeIpEntryValues = (
  inline: readonly string[],
  refEntryGroups: Iterable<readonly string[]>,
): string[] => {
  const set = new Set(inline.map((v) => v.trim()).filter((v) => v !== ''))
  for (const entries of refEntryGroups) {
    for (const v of entries) {
      const trimmed = v.trim()
      if (trimmed !== '') set.add(trimmed)
    }
  }
  return [...set]
}

// 合并内联 + 引用列表条目（按精确字符串去重），缺失的引用列表跳过（防御性回退为仅内联）
export const mergeIpEntries = (
  ipLists: readonly SecurityStageIPList[],
  inline: readonly string[],
  refs: readonly number[],
): string[] =>
  mergeIpEntryValues(
    inline,
    refs.map((id) => (ipLists.find((l) => l.id === id)?.entries ?? []).map((e) => e.value)),
  )

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
// 能力口径以 **`ip_acl_enabled && (内联 ∪ 引用非空)`，或遗留黑名单非空** 为准
// （与后端 models.PolicyTypeFeatures 同源）；原始字段缺失时回退 `has_ip_control`
// 摘要标志。摘要标志含信任（镜像后端发射语义），阶段归属判定不得直接消费它，
// 否则纯信任策略会在阶段 1 投出空行并被误判为 mixed。
//
// （分层命名，有意分歧，勿「统一」）：本函数是**内容门**（类型推断 +
// 阶段能力投影），不是摘要展示口径。deny/绕过 + 空名单不产生拦截，内容门排除
// 空组与后端效果等价；allow + 空名单则是引擎否定空集、**fail-closed 恒拒**。
// Create/Update/备份导入三门均拒绝 allow 空名单，仅带外改库/旧版本遗留可达；
// 本函数仍不为该形态虚增空组，但不得再把所有空名单统称为「零渲染安全等价」。
export const hasIPACLControl = (p: {
  has_ip_control?: boolean
  ip_acl_enabled?: boolean
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_blacklist?: string
}): boolean => {
  // 原始字段齐备时按定义判定（对齐后端：ACL 启用 ∧
  // 内联∪引用非空，或黑名单非空——旧形态只按启用位判定，会使启用但空名单
  // 的策略在兜底推断路径归 stage1、后端归 stage3，SecurityBindingEditor 组位
  // 分叉）；缺失（如精简绑定载荷）回退摘要标志。
  if (p.ip_acl_enabled !== undefined || p.ip_blacklist !== undefined || p.ip_acl_list !== undefined) {
    const hasEntries = parseIPList(p.ip_acl_list ?? '').length > 0 || parseRefIds(p.ip_acl_list_refs ?? '').length > 0
    return (p.ip_acl_enabled === true && hasEntries) || parseIPList(p.ip_blacklist ?? '').length > 0
  }
  return p.has_ip_control === true
}

// 阶段 1 · 地域拦截谓词（同后端 services.PolicyHasGeoIP：mode≠off 且区域非空）：
// 原始字段齐备时按定义判定；缺失（如精简绑定载荷）回退 has_geoip 摘要标志。
export const hasGeoIPControl = (p: {
  has_geoip?: boolean
  geoip_mode?: string
  geoip_countries?: string
}): boolean => {
  if (p.geoip_mode !== undefined || p.geoip_countries !== undefined) {
    return p.geoip_mode !== '' && p.geoip_mode !== 'off' && parseGeoipCountryCount(p.geoip_countries ?? '') > 0
  }
  return p.has_geoip === true
}

/**
 * 阶段 3 · WAF 谓词——与后端 models.PolicyTypeFeatures 的 G3 逐字对齐：
 * mode ∈ {blocking, detection, custom_only} ∪ custom_rules 引用非空（不看
 * mode=off、不看规则启用态）。customRuleRefs 必须是「引用条目数」；
 * 摘要接口的 custom_rules_count 只数启用规则，仅在该边界形态下略窄。
 */
export const hasStage3Features = (mode: string, customRuleRefs: number): boolean =>
  mode === 'blocking' || mode === 'detection' || mode === 'custom_only' || customRuleRefs > 0

// 信任命中语义单源：阶段 0 策略按 trust_detection 决定「直通上游 / 保留检测」；
// **任何非阶段 0 策略**的信任名单在引擎侧恒发 DetectionOnly（services/security.go
// id:3），与 trust_detection 无关（该字段仅阶段 0 有语义）——展示与豁免归因必须
// 共用本谓词，不得各自读取 trust_detection。
// policyType 缺省（精简载荷/旧摘要）时回落 trust_detection 旧口径。
type TrustHitMode = 'passthrough' | 'detection'
export const trustHitMode = (policyType: string | undefined, trustDetection: boolean | undefined): TrustHitMode => {
  if (policyType !== undefined && policyType !== '' && policyType !== 'stage0') return 'detection'
  return trustDetection === true ? 'detection' : 'passthrough'
}

/**
 * 阶段 1 脚注的「信任命中降级为检测」判定（绑定链口径）。
 * 命中条件 = 该策略被本规则绑定 ∧ 策略启用 ∧ 信任名单启用且条目非空（否则
 * 引擎不发射信任规则）∧ trustHitMode 为检测（阶段 0 看 trust_detection；mixed
 * 存量信任恒 DetectionOnly，见 security.go 的 id:3 并集）。判定必须与阶段 0
 * 模式行同源，不得退回 policy_type === 'stage0' 等值判断——mixed 策略的信任
 * 同样降级但不满足该等值。
 */
export const hasTrustDetectionBinding = (
  boundIds: ReadonlySet<number>,
  policies: readonly Pick<SecurityStagePolicy, 'id' | 'enabled' | 'ip_whitelist_enabled' | 'ip_whitelist' | 'ip_whitelist_refs' | 'policy_type' | 'trust_detection'>[],
): boolean =>
  policies.some((p) =>
    boundIds.has(p.id)
    && p.enabled
    && p.ip_whitelist_enabled === true
    && hasTrustEntries(p)
    && trustHitMode(p.policy_type, p.trust_detection) === 'detection')

// 阶段 0 · 信任名单行：条目数（空=未配置，任务 G 口径）+ 直通/保留检测模式
const buildStage0Rows = (policy: SecurityStagePolicy | undefined, ipLists: readonly SecurityStageIPList[]): StageRow[] => {
  const rows: StageRow[] = []
  if (!policy || !hasTrustEntries(policy)) return rows
  const trustCount = mergeIpEntryCount(ipLists, parseIPList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs))
  rows.push({ label: '信任名单', detail: trustCount === 0 ? '未配置' : `${trustCount} 条${policy.ip_whitelist_enabled === false ? '（未启用）' : ''}` })
  rows.push({ label: '模式', detail: trustHitMode(policy.policy_type, policy.trust_detection) === 'detection' ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）' })
  return rows
}

// 阶段 1 · IP 访问控制摘要（2026-09-24 用户裁定「所有统计类型数据必须是真实
// 数据」）：deny 模式的生效黑名单 = 名单侧（内联 ∪ 引用，须 ip_acl_enabled）
// + 独立 ip_blacklist 字段，两源合计如实呈现。锁摘要/流程弹框/策略列表共用。
// 收窄：①名单侧计数必须过 ip_acl_enabled
// 门——ACL 已关闭（保留名单）时名单不生效（渲染 buildIPPrecheckDirectives
// security.go:996 同门）；②独立黑名单无模式/开关门（security.go:1004-1006，
// 既有有意裁定）——allow/绕过 模式下摘要不得隐去它仍在拦截的事实。
// 全仓零外部消费——以下六个仅模块内使用的实现去掉 export
// （parseGeoipCountryCount/aclEffectiveCounts/mergeIpEntryDetails/crsGroupLabel/
// rateLimitDetailCaption/ipInCidr），消费面复核记录在修复报告
const aclEffectiveCounts = (
  ipLists: readonly SecurityStageIPList[],
  policy: { ip_acl_enabled?: boolean; ip_acl_mode?: string; ip_acl_list?: string; ip_acl_list_refs?: string; ip_blacklist?: string },
): { aclCount: number; blCount: number; effective: number; inlineCount: number; refCount: number } => {
  const inline = policy.ip_acl_enabled === false ? [] : parseIPList(policy.ip_acl_list)
  const refs = policy.ip_acl_enabled === false ? [] : parseRefIds(policy.ip_acl_list_refs)
  const inlineCount = new Set(inline.map((v) => v.trim()).filter((v) => v !== '')).size
  const refCount = refs.reduce((sum, id) => sum + (ipLists.find((l) => l.id === id)?.entry_count ?? 0), 0)
  const aclCount = policy.ip_acl_enabled === false ? 0 : inlineCount + refCount
  const blCount = parseIPList(policy.ip_blacklist).length
  return { aclCount, blCount, effective: policy.ip_acl_mode === 'deny' ? aclCount + blCount : aclCount, inlineCount, refCount }
}

export const formatAclModeDetail = (
  ipLists: readonly SecurityStageIPList[],
  policy: { ip_acl_enabled?: boolean; ip_acl_mode?: string; ip_acl_list?: string; ip_acl_list_refs?: string; ip_blacklist?: string },
): string => {
  const { aclCount, blCount, effective, inlineCount, refCount } = aclEffectiveCounts(ipLists, policy)
  // 独立黑名单无模式门——非 deny 模式下如实追告「仍在生效」（渲染侧照常拦截）
  const blAlive = blCount > 0 && policy.ip_acl_mode !== 'deny' ? `；独立黑名单 ${blCount} 条仍生效` : ''
  // 计数分解（2026-09-25 用户裁定，通俗口径）：直接填写 vs 引用列表——只给一个
  // 总数时用户无法对账「我只加了 1 个 IP 为什么显示上万条」（引用列表含内置威胁
  // 名单，条目量巨大）。仅当两个来源同时存在时才展开；纯引用时标注来源；纯内联
  // 无歧义保持原形。
  const breakdown = inlineCount > 0 && refCount > 0
    ? `（直接填写 ${inlineCount} + 引用列表 ${refCount}）`
    : inlineCount === 0 && refCount > 0
      ? '（全部来自引用列表）'
      : ''
  const total = breakdown !== '' ? `共 ${effective} 条${breakdown}` : `${effective} 条`
  // allow 空生效集 = 引擎否定算子空集（恒拒）：带外直写/旧快照可达该形态，
  // 摘要必须显性警示，否则用户看到「0 条」不会察觉全站被拒。但该告警以
  // 「ACL 在渲染」为前提——ip_acl_enabled=false 时渲染侧整块不发射
  // （security.go 的 IPACLEnabled 门），名单只是保留态，告警在此形态是误报；
  // 两条结论（恒拒 / 独立黑名单仍生效）互不替代，零生效集分支同样要追告。
  if (policy.ip_acl_mode === 'allow') {
    if (policy.ip_acl_enabled === false) return `白名单模式 · 未启用 ACL${blAlive}`
    return effective === 0 ? `白名单模式 · ${total}（将拒绝所有请求）${blAlive}` : `白名单模式 · ${total}${blAlive}`
  }
  if (policy.ip_acl_mode === '绕过') return `免检测模式 · ${total}${blAlive}`
  // 空/未知模式：名单存在但渲染侧不发射任何拒绝规则（空模式 ACL 零发射）——
  // 如实显示「未配置模式」而非「黑名单模式」，免误导用户以为名单在拦截。
  if (policy.ip_acl_mode !== 'deny' && aclCount > 0) return `未配置模式 · ${total}${blAlive}`
  if (aclCount > 0 && blCount > 0) return `黑名单模式 · ${effective} 条（名单 ${aclCount} + 独立 ${blCount}）`
  return `黑名单模式 · ${total}`
}

// IP 快捷弹框「加入名单」动作的模式门控：ip_acl_list_refs 是黑/白
// 共用字段——名单本身没有黑白属性，语义完全由 ip_acl_mode 决定（渲染侧
// security.go:414-423 仅 allow/deny 发射拒绝规则；绕过 为免检测、空模式不发射）。
// 因此在共用字段上同时提供「拦截」「放行」两个动作会反转用户意图：
//   · allow 策略上点「拦截」→ 条目进入白名单，ACL 一启用即变成放行；
//   · deny 策略上点「放行」→ 条目进入黑名单，变成拦截。
// 动作集合按当前模式收窄：deny→仅拦截；allow→仅放行；绕过/空/未知→不给动作
// （绕过 条目语义是免检测，空模式 ACL 不发射任何拒绝规则）。
// 拦截页回落文案（i18n 单源）：渲染侧的真实回落不是「默认 403」——403/429 错误
// 路由取**绑定链中首个「启用且有非空页」的策略**（internal/services/caddy.go
// buildBlockPageErrorRoute / buildRateLimitErrorRoute），可能正是同链其他策略；
// 逐策略归因由 resolveBlockPageAttribution 单源计算。行文案不得断言「回落默认」，
// 否则多策略绑定下会显示错误目标（排障时误判用户看到哪张拦截页）。
const BLOCK_PAGE_UNSET_403 = '未配置（跟随绑定链首个有效页，无则默认 403）'
const BLOCK_PAGE_BROKEN_403 = '已失效（回落绑定链首个有效页）'
const BLOCK_PAGE_BROKEN_429 = '已失效（回落绑定链首个有效页，无则默认 429）'

const buildStage1Rows = (
  policy: SecurityStagePolicy | undefined,
  ipLists: readonly SecurityStageIPList[],
  blockPages: readonly SecurityStageBlockPage[],
  stagePages?: RuleStagePages | null,
): StageRow[] => {
  const rows: StageRow[] = []
  // 内容门：deny/绕过 + 空名单不产生拦截，故不出空组；allow + 空名单虽 fail-closed
  // 恒拒，但正常写门不可达，此处同样维持已裁定的内容投影分层。
  if (policy && hasIPACLControl(policy)) {
    // 阶段 1 不再承载信任名单（阶段 0 独立；契约：阶段 1 策略创建/显式切换时服务端归一清除）
    rows.push({ label: 'IP 访问控制', detail: formatAclModeDetail(ipLists, policy) })
  }
  // 地域拦截（启用态）：启用 → 区域数；关闭但保留区域 → 已关闭（保留 N 区域）
  const geoCount = parseGeoipCountryCount(policy?.geoip_countries ?? '')
  if (policy?.has_geoip || geoCount > 0) {
    const geoModeLabel = policy?.geoip_mode === 'allow' ? '仅允许所选区域' : '拦截所选区域'
    rows.push({ label: '地域拦截', detail: policy?.has_geoip ? `${geoModeLabel} · ${geoCount} 区域` : `已关闭（保留 ${geoCount} 区域）` })
  }
  // 爬虫豁免属于阶段 1 真实渲染面：仅在存在阶段 1 能力时显示「未启用」，
  // 避免给纯阶段 2/3 策略虚增阶段 1 组；显式空引擎集=全部引擎。
  if (policy && (policy.geoip_crawler_exempt === true || rows.length > 0)) {
    const engineCount = parseIPList(policy.geoip_crawler_engines ?? '').length
    const detail = policy.geoip_crawler_exempt === true
      ? `已启用 · ${engineCount > 0 ? `豁免 ${engineCount} 个引擎` : '全部引擎'}`
      : '未启用'
    rows.push({ label: '爬虫豁免', detail })
  }
  // 策略级拦截页行（2026-09-25 起 stage1 可配策略页，投影补呈现）
  const s1PageId = policy?.block_page_id ?? 0
  if (s1PageId > 0) {
    const page = blockPages.find((p) => p.id === s1PageId)
    const broken = !page || (page.content ?? '') === ''
    rows.push({ label: '拦截页（策略页）', detail: broken ? BLOCK_PAGE_BROKEN_403 : `${page?.name}（状态码 ${policy?.block_status_code || 403}）` })
  }
  // 规则级阶段页覆盖行（v2.3.1 逐策略归因默认层 = 403）：
  // 已配 → 规则覆盖；页已删/内容空 → 失效；未配 → 回落绑定链首个有效页
  // （无则默认 403，见 BLOCK_PAGE_UNSET_403）。
  // 失效措辞必须与 BLOCK_PAGE_BROKEN_403 一致：阶段 1 的覆盖页失效后，引擎由
  // buildBlockPageErrorRoute 取「绑定链首个启用且内容非空」策略的页面——可能
  // 不是本策略，写「回落跟随策略」会让排障定位到错误策略。
  // 仅携带于有能力行的策略组——空能力不虚增阶段 1 组（未启用判定不受影响）
  if (rows.length > 0) {
    const override = resolveStageOverride(stagePages?.block_page_stage1_id, stagePages?.block_page_stage1_status, blockPages)
    if (override === null) rows.push({ label: '拦截页', detail: BLOCK_PAGE_UNSET_403 })
    else if (override.broken) rows.push({ label: '拦截页', detail: BLOCK_PAGE_BROKEN_403 })
    else rows.push({ label: '拦截页', detail: `规则覆盖：${override.pageName}（状态码 ${override.status}）` })
  }
  return rows
}

// WAF 模式展示词单源：策略列表摘要 / 触发详情策略行 / 阶段 3 流程投影三处共用。
// 此前三份实现措辞互斥（拦截 vs 阻断、仅自定义 vs 仅自定义规则），同一策略在
// 列表、事件详情、流程弹框需要人工翻译；未登记的新 mode 回落原文 token
// （fail-visible：不会静默显示空串）。
export const WAF_MODE_TEXT: Readonly<Record<string, string>> = {
  blocking: '拦截',
  detection: '检测',
  custom_only: '仅自定义',
  off: '关闭',
}

/**
 * WAF 模式展示词（未登记 mode 回落原文；空值回落空串，由调用方决定占位符）。
 *
 * 查表键可能来自库值（带外改库/备份还原可产生 `constructor`/`toString` 形态），
 * 裸下标会命中原型链上的函数——`??` 兜底被绕过、模板渲染出函数源码；故先经
 * `hasOwn` 守卫（视图侧一律调用本函数，不得自行裸下标查表）。
 */
export const wafModeLabel = (mode: string | null | undefined): string =>
  mode ? (hasOwn(WAF_MODE_TEXT, mode) ? WAF_MODE_TEXT[mode] : mode) : ''

const buildStage3Rows = (
  binding: SecurityStageBinding,
  policy: SecurityStagePolicy | undefined,
  blockPages: readonly SecurityStageBlockPage[],
  stagePages?: RuleStagePages | null,
): StageRow[] => {
  const rows: StageRow[] = []
  const mode = policy ? policy.mode : binding.mode
  // WAF 全关（off）= CRS 与自定义规则均不生效，阶段 3 引擎不为该策略渲染——
  // 拦截页归因无从谈起，整组不出组（实体单职化后阶段外能力同此裁剪）
  if (mode === 'off') return rows
  // 模式行词取 WAF_MODE_TEXT（与列表摘要/触发详情同源），明细行各模式专属
  const modeWord = wafModeLabel(mode)
  if (mode === 'blocking') rows.push({ label: `WAF（${modeWord}）`, detail: '命中即阻断' })
  else if (mode === 'detection') rows.push({ label: `WAF（${modeWord}）`, detail: '仅记录不阻断' })
  // 仅自定义：CRS 不参与评估由模式名承载，明细行保持短句不折行（2026-09-21 用户裁定）
  else if (mode === 'custom_only') rows.push({ label: `WAF（${modeWord}）`, detail: '自定义规则按动作执行' })
  // 「CRS 规则组」行（blocking/detection 才有 CRS 评估；0=全部默认）
  if (mode === 'blocking' || mode === 'detection') {
    const crsRaw = policy?.crs_rule_groups
    const crsCount = Array.isArray(crsRaw) ? crsRaw.length : parseIPList(typeof crsRaw === 'string' ? crsRaw : undefined).length
    rows.push({ label: 'CRS 规则组', detail: crsCount > 0 ? `${crsCount} 组` : '全部（默认）' })
  }
  if (policy?.has_custom_rules) rows.push({ label: '自定义规则', detail: `${policy.custom_rules_count} 条` })
  // 「拦截页」行（v2.3.1 归因口径）：规则级覆盖与策略级页并存展示，措辞区分——
  // 规则覆盖已配 → 「拦截页（规则覆盖）：页名（状态码 X）」（渲染语义=覆盖优先）；
  // 覆盖页已删/内容空 → 已失效（回落跟随策略 = 下方策略级行生效）；
  // 未配 → 仅现有策略级行（binding.block_page_id → 页名 / BLOCK_PAGE_UNSET_403 /
  // BLOCK_PAGE_BROKEN_403——真实回落目标由绑定链决定，见 BLOCK_PAGE_* 注释）；
  // 未配置措辞与阶段 1 统一（2026-09-21 用户裁定），失效措辞保留差异：回落目标不同（首策略 vs 跟随策略）
  const pageId = binding.block_page_id ?? 0
  const page = pageId > 0 ? blockPages.find((p) => p.id === pageId) : undefined
  const pageBroken = pageId > 0 && (!page || (page.content ?? '') === '')
  const policyPageDetail = pageId <= 0 ? BLOCK_PAGE_UNSET_403
    : pageBroken ? BLOCK_PAGE_BROKEN_403
    : `${page?.name}（状态码 ${binding.block_status_code || 403}）`
  const ruleOverride = resolveStageOverride(stagePages?.block_page_stage3_id, stagePages?.block_page_stage3_status, blockPages)
  if (ruleOverride === null) {
    rows.push({ label: '拦截页', detail: policyPageDetail })
  } else {
    rows.push({
      label: '拦截页（规则覆盖）',
      detail: ruleOverride.broken ? '已失效（回落跟随策略）' : `${ruleOverride.pageName}（状态码 ${ruleOverride.status}）`,
    })
    rows.push({ label: '拦截页（策略页）', detail: policyPageDetail })
  }
  return rows
}

// 三阶段分组投影：bindings 顺序（policy_id ASC）即执行顺序；禁用策略保留显示（灰态由消费方渲染）。
// ruleEnabled：规则自身的启用态（false=控制面不渲染任何路由，安全链未进入
// 运行配置）。缺省视为启用——未知态不得宣称「已禁用」。
export const buildStageModel = (
  bindings: readonly SecurityStageBinding[],
  policies: readonly SecurityStagePolicy[],
  ipLists: readonly SecurityStageIPList[],
  blockPages: readonly SecurityStageBlockPage[],
  stagePages?: RuleStagePages | null,
  ruleEnabled?: boolean,
): RuleStageModel => {
  const stage0Groups: StagePolicyGroup[] = []
  const stage1Groups: StagePolicyGroup[] = []
  const stage2Groups: StagePolicyGroup[] = []
  const stage3Groups: StagePolicyGroup[] = []

  bindings.forEach((binding, index) => {
    const policy = policies.find((p) => p.id === binding.policy_id)
    const base = { key: binding.policy_id, order: index + 1, name: binding.name, enabled: binding.enabled }

    const s0rows = buildStage0Rows(policy, ipLists)
    if (s0rows.length > 0) {
      stage0Groups.push({ ...base, rows: s0rows })
    } else if (policy && inferPolicyType(policy) === 'stage0') {
      // 阶段 0 启用判定=「绑定链上存在阶段 0 策略」（binding 口径，与阶段 1/2/3
      // 对齐）：名单为空的阶段 0 策略只能经 API/带外导入形成，内容门会把它判成
      // 「未启用」，与「绑定链上存在该策略」矛盾。仍出灰态行，不虚报信任面。
      stage0Groups.push({
        ...base,
        rows: [
          { label: '信任名单', detail: '未配置' },
          { label: '模式', detail: trustHitMode(policy.policy_type, policy.trust_detection) === 'detection' ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）' },
        ],
      })
    }

    const s1rows = buildStage1Rows(policy, ipLists, blockPages, stagePages)
    if (s1rows.length > 0) stage1Groups.push({ ...base, rows: s1rows })

    // 阶段 2：限流（全部策略的限流集中在 WAF 之前，拦截恒 429）
    if (policy?.has_rate_limit) {
      const s2rows = [{ label: '速率限制', detail: `${policy.rate_limit_rps} 次/秒 · 突发 ${policy.rate_limit_burst} 次` }]
      // 策略级拦截页（stage2 可配策略页，429 时渲染；未配不虚增行）
      const s2PageId = binding.block_page_id ?? policy?.block_page_id ?? 0
      if (s2PageId > 0) {
        const page = blockPages.find((p) => p.id === s2PageId)
        // 与阶段 1/3 同口径——页已删/内容空不得静默省略，须显示
        // 失效文案（BLOCK_PAGE_BROKEN_429），否则用户看不到回落目标（与同抽屉
        // 其余阶段分裂）。
        const broken = !page || (page.content ?? '') === ''
        s2rows.push({
          label: '拦截页（策略页）',
          detail: broken ? BLOCK_PAGE_BROKEN_429 : `${page.name}（429 时渲染）`,
        })
      }
      stage2Groups.push({ ...base, rows: s2rows })
    }

    const s3rows = buildStage3Rows(binding, policy, blockPages, stagePages)
    if (s3rows.length > 0) stage3Groups.push({ ...base, rows: s3rows })
  })

  return {
    hasAnyPolicy: bindings.length > 0,
    ruleDisabled: ruleEnabled === false,
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
        footnote: '限流拦截恒为 429（不产生安全事件，计数见规则指标）',
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

// ── 明细拼装（流程抽屉首次展开时调用；纯函数，不持有缓存） ──

// 内联 ∪ 引用逐条明细（精确字符串去重，内联优先；引用条目携带 remark 与来源列表名）
const mergeIpEntryDetails = (
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
const crsGroupLabel = (groupCode: string, crsFiles: readonly CrsRuleFileOption[]): string => {
  // 组码逐字比较（原实现把组码拼进 RegExp，畸形存量组码含元字符会抛错崩溃抽屉；
  // 解析走 parseCrsFilename，不再构造正则）
  const file = crsFiles.find((r) => parseCrsFilename(r.filename)?.code === groupCode)
  if (!file) return groupCode
  const info = parseCrsFilename(file.filename)
  return `${info?.phase ?? '请求'} · 9${groupCode} · ${file.category}`
}

// 限流口径文案（与后端 buildRateLimitHandler 双 zone 语义一致）：
// burst > 0 → 1s 窗口封顶 rps+burst（瞬时），60s 窗口封顶 rps×60（持续）；burst=0 → 单 1s 窗口
const rateLimitDetailCaption = (rps: number, burst: number): string =>
  burst > 0
    ? `1s 窗口上限 ${rps + burst} 次（含突发）· 60s 窗口上限 ${rps * 60} 次（持续 ${rps} 次/秒）`
    : `1s 窗口上限 ${rps} 次`

// 原生 JSON（/security/rules/:id/policy 的 RawMessage 字段）→ 数字 id 数组
//（兼容对象形态 [{id:…}]；自此导出为单源——SecurityPolicies 的
// custom_rules 文本解析 JSON.parse 后同样走本守卫，不再各持一份同构实现）
export const parseUnknownIds = (raw: unknown): number[] => {
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

// 字符串数组字段的宽松解析（原生数组 / JSON 文本两形态）：RawMessage 字段按
// unknown 接收后统一走本入口；空项与非字符串丢弃，坏 JSON 回退空数组。
export const parseUnknownStrings = (raw: unknown): string[] => {
  if (Array.isArray(raw)) return normalizeStringEntries(raw)
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
    // 同门：ACL 已关闭（保留名单）时名单
    // 不生效——明细与摘要（aclEffectiveCounts:355）及渲染（security.go:996）
    // 共用同一 ip_acl_enabled 门，否则「黑名单 1 条」摘要旁挂「合计 100 条」明细。
    if (policy.has_ip_control && policy.ip_acl_enabled !== false) {
      const inline = new Set(parseIPList(policy.ip_acl_list).map((v) => v.trim()).filter((v) => v !== ''))
      if (inline.size > 0) details.aclInlineCount = inline.size
      const refs = parseRefIds(policy.ip_acl_list_refs)
      const lists = refs.map((id) => {
        const l = ipLists.find((x) => x.id === id)
        return { name: l?.name ?? `列表 #${id}`, count: l?.entry_count ?? 0 }
      })
      if (lists.length > 0) details.aclLists = lists
    }
    // 遗留独立黑名单：不受 ip_acl_enabled 门控（ip_blacklist 恒参与阶段 1 拒绝
    // 判定），摘要对非 deny 模式提示的「独立黑名单 N 条仍生效」在此对账。
    const blacklist = [...new Set(parseIPList(policy.ip_blacklist).map((v) => v.trim()).filter((v) => v !== ''))]
    if (blacklist.length > 0) details.blacklistEntries = blacklist
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
  // map 产出 StageGroup[]，而 stages 是定长四元组（阶段 0/1/2/3）——逐阶段一一对应不增不减，
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

// 追加：阶段文案单一事实源=STAGE_TITLES——合并后
// 的遗留双源消除，阶段措辞微调不再需双处同步
export const POLICY_TYPE_LABELS: Record<SecurityPolicyType, string> = {
  stage0: STAGE_TITLES[0],
  stage1: STAGE_TITLES[1],
  stage2: STAGE_TITLES[2],
  stage3: STAGE_TITLES[3],
  mixed: '混合策略（兼容旧版）',
}

export const POLICY_TYPE_SHORT_LABELS: Record<SecurityPolicyType, string> = {
  stage0: '阶段 0',
  stage1: '阶段 1',
  stage2: '阶段 2',
  stage3: '阶段 3',
  mixed: '混合',
}

// 策略列表默认 tab：按阶段顺序取第一个有条目的类型（阶段 0 → 1 → 2 → 3 → 混合），
// 全空回落阶段 1（列表初始态）。首屏/保存后/迁移后共用本谓词——硬编码阶段 1 会让
// 只部署其他类型策略的站点看到空表 +「暂无安全策略」，把「策略存在」误读为「保存失败」。
export const pickDefaultPolicyTab = (counts: Readonly<Partial<Record<SecurityPolicyType, number>>>): SecurityPolicyType => {
  const order: readonly SecurityPolicyType[] = ['stage0', 'stage1', 'stage2', 'stage3', 'mixed']
  for (const type of order) {
    if ((counts[type] ?? 0) > 0) return type
  }
  return 'stage1'
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
  // 阶段 0 推断（g0=信任名单启用且非空）：内联 JSON 文本或引用 id 数组文本
  ip_whitelist?: string
  ip_whitelist_refs?: string
  ip_whitelist_enabled?: boolean
  // 阶段 1 信任除外判定（可选原始字段；缺省时回退 has_ip_control 摘要标志）
  ip_acl_enabled?: boolean
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_blacklist?: string
  // 阶段 1 地域拦截（可选原始字段；缺省时回退 has_geoip 摘要标志）
  geoip_mode?: string
  geoip_crawler_exempt?: boolean
  geoip_crawler_engines?: string
  geoip_countries?: string
  // 阶段 3 自定义规则（可选原始计数；缺省时回退 has_custom_rules 摘要标志）
  custom_rules_count?: number
}

// 推断形状：阶段 0 = 信任名单非空；阶段 1 = IP 访问控制或地域拦截；阶段 2 = 限流；
// 阶段 3 = WAF 或自定义规则。恰好一个阶段 → 该类型；跨阶段 → mixed（存量混合兼容组）；
// 零能力 → stage3（存量空策略的 mode 字段定义其为 WAF 策略关闭态）。
export const inferPolicyType = (p: SecurityPolicyTypeInput): SecurityPolicyType => {
  if (p.policy_type === 'stage0' || p.policy_type === 'stage1' || p.policy_type === 'stage2' || p.policy_type === 'stage3' || p.policy_type === 'mixed') {
    return p.policy_type
  }
  // 兜底推断与后端 models.PolicyTypeFeatures 逐条同形（收敛，
  // 原两处口径差异已消除）：=信任名单启用且内联∪引用非空；=IP ACL 启用且
  // 非空 / 黑名单非空 / 地域拦截生效；=限流启用且 rps>0；=mode∈三态或
  // 自定义规则非空。原始字段齐备时按定义判定，缺失（如精简绑定载荷）回退摘要
  // 标志：不可直接用 has_waf（仅 blocking|detection，漏 custom_only），自定义
  // 规则不可直接用 has_custom_rules（含 off=全关口径，比窄）。
  const s0 =
    p.ip_whitelist_enabled === undefined ? hasTrustEntries(p) : p.ip_whitelist_enabled && hasTrustEntries(p)
  // s1 用内容门：与后端 PolicyTypeFeatures/ 同形；摘要标志
  // has_ip_control 开启即 true 且含信任，直接消费会把空 ACL 策略误归阶段 1。
  const s1 = hasIPACLControl(p) || hasGeoIPControl(p)
  const s2 = p.has_rate_limit
  const s3 =
    p.mode === 'blocking' || p.mode === 'detection' || p.mode === 'custom_only'
      ? true
      : p.custom_rules_count !== undefined
        ? p.custom_rules_count > 0
        : p.has_custom_rules
  const stageCount = [s0, s1, s2, s3].filter(Boolean).length
  if (stageCount > 1) return 'mixed'
  if (s0) return 'stage0'
  if (s1) return 'stage1'
  if (s2) return 'stage2'
  return 'stage3'
}

// compareVersion 语义化版本比较：日期形态（2026.09.24）与
// semver（v2.3.3）均可——逐段数值比较，非数值段字典序兜底；缺段与空段按 0
// （1.2 与 1.2.0 等价）——Go compareLibraryVersion 同口径，双方测试同读
// web/tests/fixtures/version-compare.tsv（跨栈夹具，改语义两栈同时红）。
// 注意：预发布段（如 -beta vs 空）按字典序判 beta > 正式版（semver 反直觉）——
// 当前消费方只比较日期/纯数字形态，无预发布版本号，无实际影响（声明）。
export const compareVersion = (a: string, b: string): number => {
  const pa = a.replace(/^v/, '').split(/[.-]/)
  const pb = b.replace(/^v/, '').split(/[.-]/)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const rawA = pa[i]; const rawB = pb[i]
    const na = rawA === undefined ? 0 : Number(rawA)
    const nb = rawB === undefined ? 0 : Number(rawB)
    if (!Number.isNaN(na) && !Number.isNaN(nb)) {
      if (na !== nb) return na - nb
    } else {
      const sa = rawA ?? ''; const sb = rawB ?? ''
      if (sa !== sb) return sa < sb ? -1 : 1
    }
  }
  return 0
}

// —— CIDR 感知 IP 匹配（用户验收：威胁库条目为 CIDR，精确串匹配漏报） ——
// 地址解析单源 in utils/ipAddress：事件侧需要 %zone 宽容与「按数值收前导零」
// 的历史口径（引擎上报形态），由 toV4Long / toV6BigInt 显式表达。

// 补正：IPv6 CIDR 按前 N 位比较——此前仅 IPv4，IPv6 CIDR
// 条目在命中定位/残余信任判定侧恒漏报（取消信任后 CIDR 仍信任却报「已恢复拦截」）。
type ParsedCidr =
  | { readonly family: 4; readonly base: number; readonly bits: number }
  | { readonly family: 6; readonly base: bigint; readonly bits: number }

const parseCidrUncached = (cidr: string): ParsedCidr | null => {
  const idx = cidr.indexOf('/')
  if (idx < 0) return null
  const base = cidr.slice(0, idx).trim()
  const bits = Number(cidr.slice(idx + 1).trim())
  if (!Number.isInteger(bits) || bits < 0) return null
  if (base.includes(':')) {
    if (bits > 128) return null
    const baseLong = toV6BigInt(base)
    if (baseLong === null) return null
    return { family: 6, base: baseLong, bits }
  }
  if (bits > 32) return null
  const baseLong = toV4Long(base)
  if (baseLong < 0) return null
  return { family: 4, base: baseLong, bits }
}

// CIDR 解析缓存：命中判定对同一批名单条目重复执行（事件详情多结论扫描），
// 逐条目即时重解析 BigInt/正则在数万条内置威胁名单上是主线程卡顿源。
// cidr 串 → 解析结果是纯函数（不随条目内容失效），缓存只需上限防内存膨胀；
// invalidateSharedEntriesCache 时一并清空（名单内容换代，保持同生命周期语义）。
const CIDR_PARSE_CACHE_MAX = 50_000
const cidrParseCache = new Map<string, ParsedCidr | null>()
const parseCidr = (cidr: string): ParsedCidr | null => {
  const cached = cidrParseCache.get(cidr)
  if (cached !== undefined) return cached
  const parsed = parseCidrUncached(cidr)
  if (cidrParseCache.size >= CIDR_PARSE_CACHE_MAX) cidrParseCache.clear()
  cidrParseCache.set(cidr, parsed)
  return parsed
}

const parsedCidrContains = (parsed: ParsedCidr, ip: string): boolean => {
  if (parsed.family === 4) {
    const ipLong = toV4Long(ip.trim())
    if (ipLong < 0) return false
    const mask = parsed.bits === 0 ? 0 : (~0 << (32 - parsed.bits)) >>> 0
    return (ipLong & mask) === (parsed.base & mask)
  }
  const ipLong = toV6BigInt(ip)
  if (ipLong === null) return false
  if (parsed.bits === 0) return true
  const shift = BigInt(128 - parsed.bits)
  return (ipLong >> shift) === (parsed.base >> shift)
}

const ipInCidr = (ip: string, cidr: string): boolean => {
  const parsed = parseCidr(cidr)
  return parsed !== null && parsedCidrContains(parsed, ip)
}

/**
 * 预解析 IP 的批量命中判定器：同一 IP 对 N 条名单条目判定时，IP 侧只解析一次
 * （CIDR 侧走 parseCidr 缓存）。事件详情弹框的多结论扫描必须走此入口——
 * 逐条 entryMatchesIp 会把 IP 解析重复 N 次。
 */
export const createIpMatcher = (ip: string): ((entry: string) => boolean) => {
  const trimmed = ip.trim()
  const v4 = toV4Long(trimmed)
  const v6 = v4 < 0 ? toV6BigInt(trimmed) : null
  return (entry) => {
    if (entry === trimmed) return true
    if (!entry.includes('/')) return false
    const parsed = parseCidr(entry)
    if (parsed === null) return false
    if (parsed.family === 4) {
      if (v4 < 0) return false
      const mask = parsed.bits === 0 ? 0 : (~0 << (32 - parsed.bits)) >>> 0
      return (v4 & mask) === (parsed.base & mask)
    }
    if (v6 === null) return false
    if (parsed.bits === 0) return true
    const shift = BigInt(128 - parsed.bits)
    return (v6 >> shift) === (parsed.base >> shift)
  }
}

/** 条目匹配：精确 IP 或 CIDR 包含（IPv4/IPv6 双栈，CIDR 仅作用于同族） */
export const entryMatchesIp = (entry: string, ip: string): boolean => {
  if (entry === ip) return true
  if (entry.includes('/')) return ipInCidr(ip, entry)
  return false
}

// —— 跨组件共享条目缓存：IPLocationAction 与 TriggerDetailDialog
// 共用，写入动作（useTrustAssociation/useIpListAdd 链路）调用 invalidate 清空 ——
// invalidate 同时通知订阅者（已打开弹框的本地副本即时
// 失效重拷——曾失效触不到本地 ref，开放窗口叠开 IP 处置后徽标滞留旧值）。
export const sharedEntriesCache: Record<number, string[]> = {}
// 条目年龄：缓存值由本页写入动作失效，但**外部**变更（另一标签页/另一管理员
// 增删条目）不会触达本页——只靠写动作失效会让本页事件详情/「取消信任」计划
// 长期陈旧。给每条名单记加载时刻，超过 TTL 即视为缺失并在下次 ensure 重拉。
// 恢复可见时把已缓存条目标记为陈旧（见下方 visibilitychange 绑定）。
const SHARED_ENTRIES_TTL_MS = 60_000
const sharedEntriesLoadedAt = new Map<number, number>()
// 缓存代际。invalidate 递增代际，在途 loader 落地时校验代际——
// 写动作后旧请求的返回值不得回填缓存（否则后续 ensure 命中失效前的旧条目）。
let entriesCacheGeneration = 0
type EntriesCacheListener = () => void
const entriesCacheListeners = new Set<EntriesCacheListener>()
function notifyEntriesCache(): void {
  for (const fn of entriesCacheListeners) fn()
}
export const subscribeSharedEntriesCache = (fn: EntriesCacheListener): (() => void) => {
  entriesCacheListeners.add(fn)
  return () => entriesCacheListeners.delete(fn)
}
const inflightEntries = new Map<number, { generation: number; promise: Promise<void> }>()

/** 该 id 的缓存值是否仍在 TTL 内（无加载时刻=陈旧，按缺失重取）。 */
const isSharedEntryFresh = (id: number): boolean => {
  if (!(id in sharedEntriesCache)) return false
  const loadedAt = sharedEntriesLoadedAt.get(id)
  return loadedAt !== undefined && Date.now() - loadedAt < SHARED_ENTRIES_TTL_MS
}

/** 写入单名单条目并通知订阅者（加载完成/IP 处置后回写共用）。
 *  模块内私有——缓存写只允许经 loadSharedEntry / invalidate 路径，
 *  外泄第二写入口会绕开代际守卫（零外部消费即去 export）。 */
function writeSharedEntries(id: number, values: string[]): void {
  sharedEntriesCache[id] = values
  sharedEntriesLoadedAt.set(id, Date.now())
  notifyEntriesCache()
}

/** 以当前代际发起一次加载（并发同代际调用方复用同一条 in-flight 请求）。 */
async function loadSharedEntry(id: number, loader: (id: number) => Promise<string[]>): Promise<void> {
  const generation = entriesCacheGeneration
  const pending = (async () => {
    try {
      const values = await loader(id)
      // 代际已变（期间发生写动作 invalidate）→ 丢弃迟到结果，保持未缓存待重取。
      if (generation !== entriesCacheGeneration) return
      writeSharedEntries(id, values)
    } catch {
      /* 单名单失败：保持未缓存，下一次调用重试 */
    }
  })()
  const entry = { generation, promise: pending }
  inflightEntries.set(id, entry)
  try {
    await pending
  } finally {
    // 仅清自己的条目：代际更替后可能已有更晚的加载接管（勿误删其 in-flight）。
    if (inflightEntries.get(id) === entry) inflightEntries.delete(id)
  }
}

/**
 * 缺失条目的名单 id：`ensureSharedEntries` 对单名单失败保持「未缓存」而不抛出
 * （下次调用可重试），调用方据此把加载失败显性化——否则条目缺失会退化成
 * 「未命中名单」的业务结论。非正 id、已缓存且在 TTL 内的 id 均不计入；
 * 超过 TTL 的缓存按缺失处理（外部变更不经本页写入失效，必须按期重拉）。
 */
export const missingSharedEntryIds = (ids: Iterable<number>): number[] =>
  [...new Set(ids)].filter((id) => id > 0 && !isSharedEntryFresh(id))

/**
 * 按需补齐名单条目：只对「不在缓存」的 id 发请求，
 * 并发调用去重（in-flight 复用）；单名单失败不阻塞其他名单且不留失败缓存
 * （下次调用可重试）。loader 由调用方注入（axios 请求），本模块保持纯状态机。
 *
 * 代际守卫必须覆盖「复用方」——原实现只让发起者校验代际，写动作
 * invalidate 后紧随的 ensure 会命中原 in-flight，唤醒后发现代际已变、结果被丢弃
 * 且自身不补取，调用方返回时缓存仍为空（IP 处置弹框把该 IP 显示为「未在名单」）。
 * 现口径：
 * - 复用的 in-flight 必须与**本次调用时代际**一致；跨代际在途请求不复用（其结果
 *   按守卫必被丢弃），直接按当前代际发起；
 * - 等待同代际请求期间再次失效 → 按新代际补取一次（有界，单次）。
 * 发起者自己的请求被丢弃时不自动重取（保持 「丢弃、待重取」语义）。
 */
export async function ensureSharedEntries(ids: Iterable<number>, loader: (id: number) => Promise<string[]>): Promise<void> {
  const todo = missingSharedEntryIds(ids)
  if (todo.length === 0) return
  const generation = entriesCacheGeneration
  await Promise.all(todo.map(async (id) => {
    // 过期缓存先丢弃（不发通知）：失败后该 id 回到「未缓存」，调用方的失败
    // 判定（missingSharedEntryIds）与既有的「失败不缓存」契约才能成立；
    // 成功后 writeSharedEntries 立刻回填并通知。
    if (id in sharedEntriesCache) {
      delete sharedEntriesCache[id]
      sharedEntriesLoadedAt.delete(id)
    }
    const existing = inflightEntries.get(id)
    if (existing && existing.generation === generation) {
      await existing.promise
      // 等待期间发生写动作：复用的结果被代际守卫丢弃，本调用方不会自行重取，
      // 必须在此按新代际补取一次——否则「await 返回即已缓存」契约断裂。
      if (!isSharedEntryFresh(id) && entriesCacheGeneration !== generation) {
        await loadSharedEntry(id, loader)
      }
      return
    }
    await loadSharedEntry(id, loader)
  }))
}

/**
 * 补齐条目并回报**补齐后**仍未就绪的名单 id（空数组 = 全部就绪）。
 *
 * `ensureSharedEntries` 对单名单失败保持「未缓存」而不抛出——调用方必须把这种
 * 缺失显性化为失败（禁用动作/拒绝出结论），否则条目缺失会退化成「未命中名单」
 * 或「无残余信任」的业务结论。本函数是该失败判定的单源：命中展示
 * （IPLocationAction 加载态）与写后核对两条通路共用，避免各自
 * 手写 `!(id in sharedEntriesCache)` 时的口径漂移。
 *
 * 注意：这里判的是「补齐后仍不新鲜」而不只是「不在缓存里」——过期缓存同样不可
 * 用于结论（TTL 到期即按缺失重拉，见 ensureSharedEntries）。
 */
export async function ensureSharedEntriesMissing(ids: Iterable<number>, loader: (id: number) => Promise<string[]>): Promise<number[]> {
  await ensureSharedEntries(ids, loader)
  return missingSharedEntryIds(ids)
}

export const invalidateSharedEntriesCache = (): void => {
  entriesCacheGeneration++
  for (const k of Object.keys(sharedEntriesCache)) delete sharedEntriesCache[Number(k)]
  sharedEntriesLoadedAt.clear()
  cidrParseCache.clear()
  notifyEntriesCache()
}

/**
 * 把已缓存条目标记为陈旧（保留值、不通知订阅者）：恢复可见时调用——期间他页
 * /他人可能已增删条目，但正在展示的弹框不应突然变成「空名单」（那会把未命中
 * 渲染成业务结论）。下次 `ensureSharedEntries` 按 TTL 判定重拉。
 */
const markSharedEntriesStale = (): void => {
  sharedEntriesLoadedAt.clear()
}

// 跨标签页/外部变更的可见性入口：不可轮询，只能在「离开后回来」时感知。
// 与 stores/auth 的 visible 补查同范式（单次绑定；node 单测无 document 时跳过）。
if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) markSharedEntriesStale()
  })
}

/**
 * 事件详情弹框需要预取的地址列表 id：属主策略的 ACL refs（命中列表/
 * 内联判定只读本策略）+ 信任 refs（本策略命中/跨策略豁免判定）。
 * 消费方按事件类别与动作传入 scope 收窄预取面（WAF/请求体/爬虫事件的
 * ACL 条目零消费，属主策略引用威胁库时曾每次无谓下载数百 KB）。
 * 省略 scope = 全集（既有调用/测试口径不变）。
 */
interface EventDetailRefScope {
  /** 属主策略 ACL 引用（命中列表与内联判定，仅 kind∈{acl,geo,threat} 消费） */
  ownerAcl?: boolean
  /** 属主策略信任引用（信任命中展示 + 豁免归因） */
  ownerTrust?: boolean
  /** 其他启用策略的信任引用（跨策略豁免归因，仅未拦截事件需要） */
  otherTrust?: boolean
}

export const eventDetailRefIds = (
  policy: { ip_acl_list_refs?: string; ip_whitelist_refs?: string } | null,
  otherPolicies: ReadonlyArray<{ ip_whitelist_refs?: string }>,
  scope?: EventDetailRefScope,
): number[] => {
  // 逐项 `?? true`：spread 会把显式 `ownerAcl: undefined` 当「已提供」覆写掉
  // 默认全集——省略语义必须只对「键缺席」成立。
  const use = {
    ownerAcl: scope?.ownerAcl ?? true,
    ownerTrust: scope?.ownerTrust ?? true,
    otherTrust: scope?.otherTrust ?? true,
  }
  const ids: number[] = []
  const seen = new Set<number>()
  const add = (raw: string | undefined): void => {
    for (const id of parseRefIds(raw)) {
      if (id <= 0 || seen.has(id)) continue
      seen.add(id)
      ids.push(id)
    }
  }
  if (policy) {
    if (use.ownerAcl) add(policy.ip_acl_list_refs)
    if (use.ownerTrust) add(policy.ip_whitelist_refs)
  }
  if (use.otherTrust) {
    for (const p of otherPolicies) add(p.ip_whitelist_refs)
  }
  return ids
}

// —— 后端批量端点上限（与 internal/handlers 同口径）：前端按上限分片提交 ——
// /security/policies/:id/bindings/bulk 的 bind+unbind 合计 ≤100；
// /rules/batch-block-pages 的 rule_ids ≤500。超限整批 400，原样重试仍失败。
export const SECURITY_BULK_LIMITS = { policyBindings: 100, ruleBlockPages: 500 } as const

// 单规则可绑定的策略条数上限（后端 maxBindingsPerRule=8 的前端单源镜像）：
// SecurityBindingEditor（规则侧计数/选择器上限）与 SecurityPolicies（向导
// 冲突检测注释/夹紧）共用，前两份本地常量各写一遍，后端调整时易漏改。
export const MAX_POLICIES_PER_RULE = 8

// ── TCP（L4）绑定阶段门（阶段 0/1 放开） ──
// TCP 规则仅可绑定阶段 0（信任名单）/阶段 1（IP 访问控制/地域拦截）单职策略；
// 限流（stage2）/WAF（stage3）/混合（mixed）含 TCP 不支持的能力（L4 无请求语义，
// 无 429/WAF 引擎面）。与后端绑定校验同源（400 文案同款），拒绝动作=断连。
// SecurityBindingEditor（规则侧分区置灰 + 策略侧选择器）与 SecurityPolicies
// （向导关联规则选择器）共用本谓词，禁止第二份类型清单。
export const TCP_BIND_UNSUPPORTED_REASON = '该策略含 TCP 不支持的能力（限流/WAF）'
export const policySupportsTcp = (type: SecurityPolicyType | undefined): boolean =>
  type === 'stage0' || type === 'stage1'

/** 绑定行的最小形状（策略类型由策略摘要推断，精简载荷缺摘要时回退限流标志）。
 *  仅作本文件 hasOtherStage2Binding 的入参约束——形状不外泄，故不导出
 *  （谓词本身由规则侧编辑器与策略向导两处导入）。 */
interface PolicyBindingRef {
  policy_id: number
  rate_limit_enabled?: boolean
}

/**
 * 每条规则最多绑定一条限流策略——后端 bulk 端点对冲突整批 400（不是逐条跳过），
 * 故所有选择/提交入口都必须在发送前用本谓词置灰或拦截。
 * 返回该规则是否已绑定「本策略之外」的限流策略；`typeOf` 由调用方用
 * inferPolicyType 建表（与后端 policy_type 列同口径），摘要缺失时回退绑定的
 * rate_limit_enabled 标志。
 */
export const hasOtherStage2Binding = (
  bindings: readonly PolicyBindingRef[],
  selfPolicyId: number | null,
  typeOf: (policyId: number) => SecurityPolicyType | undefined,
): boolean => bindings.some((binding) =>
  binding.policy_id !== selfPolicyId
  && (typeOf(binding.policy_id) ?? (binding.rate_limit_enabled ? 'stage2' : 'stage3')) === 'stage2')

/** 按单次上限切分待提交项（顺序保持；空数组→空切分）。 */
export function chunkForBulk<T>(items: readonly T[], limit: number): T[][] {
  if (limit <= 0) return []
  const chunks: T[][] = []
  for (let i = 0; i < items.length; i += limit) chunks.push(items.slice(i, i + limit))
  return chunks
}

/** 数组求交（按 a 顺序、去重）：Set 查表替代 includes——万级名单下避免 O(A×D)。 */
export function entriesIntersect(a: readonly string[], b: ReadonlySet<string>): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const entry of a) {
    if (!b.has(entry) || seen.has(entry)) continue
    seen.add(entry)
    out.push(entry)
  }
  return out
}

// formatDurationUs 安全处理耗时格式化(微秒→人类可读,分级精度):
// <1ms 用微秒精度(0.042ms);1-10ms 一位小数(1.5ms);≥10ms 整数毫秒(42ms/329ms)。
export const formatDurationUs = (us: number | undefined): string => {
  const v = us ?? 0
  if (v <= 0) return '—'
  if (v < 1000) return (v / 1000).toFixed(3) + 'ms'
  if (v < 10000) return (v / 1000).toFixed(1) + 'ms'
  return Math.round(v / 1000) + 'ms'
}

// IP 地址列表分类预设——SecurityRules「提取为列表」与 SecurityPolicies 分类
// 选择共用同一组选项。
export const IP_LIST_CATEGORIES = ['搜索引擎爬虫', 'CDN 节点', '云服务商', '办公网络', '数据中心', '可信地址', '恶意 IP', '其他'] as const

// triggerStageFamily 触发 id→阶段族归类（收敛：TriggerDetailDialog kind 与
// SecurityEvents stageCategory 的平行实现统一改引本函数）。
//
// 映射必须与后端 v2.3.8 权威分类同步——
//   ① attackFamilyClassOf（internal/handlers/security.go）——ID 形态族：
//      5 位任意 = 自定义（发射 id=crID+10000 落 10000-99999；CRS 恒 6 位）；
//      6 位 1-7 开头 = DB 自定义规则 id 10000-789999 发射 id+10000；
//      7 位+ 1 开头 = 无 id 规则合成 id 1000000+n；更高独立段 = OR 条件分支。
//      OR 分支由 customRuleEventDbID 回解同一 DB 父规则，不归 CRS。
//      原实现只认 5 位与 1 开头≥7 位 → 6 位自定义（100000-799999）落 other，
//      详情弹框按 default 误归 ACL。
//   ② triggerTypeForRule（internal/handlers/security_threat_screen.go）——数值段：
//      爬虫两族 [810000,900000)（豁免 [810000,850000) + 伪装 [850000,900000)）
//      独立于地域 [800000,810000)；原实现把整段 800000-899999 归 geoip，
//      爬虫事件详情显示「地域拦截规则（区域：…）」。
//   ③ 固定 SecRule id 的族归属单一事实源 = handlers 的 legacyRuleFamilies 表
//      （id:2/4/7 IP 访问控制、3/5/12 信任名单、8 地域拦截、11 请求体异常、
//      14 威胁情报库、429 限流）。id:5 是「IP ACL 绕过模式占用 id:3 时的信任
//      名单并集」（services/security.go trustID 分支，pass,nolog）——归信任族；
//      曾按白名单外拒绝记账，与本表及发射侧语义分叉。
// 返回（细粒度，消费方各自投影）:
//   'trust'|'ipAcl'|'geoip'|'crawler'|'threat'|'wafCustom'|'wafCrs'|'body'|'other'
// 视图投影：SecurityEvents —— trust→trust，crawler→crawler（独立阶段标签「爬虫
// 校验」），ipAcl/geoip/threat→acl（阶段 1 合并口径：黑白名单、地域、威胁情报
// 同列），wafCrs/wafCustom→waf，body→body；TriggerDetailDialog —— geoip→geo、
// crawler→crawler、threat→threat、wafCrs→waf-crs、wafCustom→waf-custom。
//   合成自定义 id 上界段 [900000,1000000)（DB 规则 id
//   ≥90000 → 触发 id ≥910000，会与 9\d{5} CRS 段重叠）——自定义规则 id 达 9 万
//   不现实（不可达），边界不修，仅登记留痕。
//   限流 id 429 后端归「限流」族，但该族无 sec_events 数据源、列表层不设筛选/
//   阶段桶（见 triggeredFilter 的类别清单）——本函数归 other。
// （有意设计，勿"统一"）：id '8' 例外——本函数归 ipAcl，而后端权威分类
// （attackFamilyClassOf）把 8 归 GeoIP。这是 历史共享 id 口径，现代引擎
// 地域事件已改发 800xxx、不再走 id 8，无现实影响；triggerFamily.spec.ts 与
// TriggerDetailDialog 注释已显式钉住该例外，不得按「与后端同步」改回 geoip。
export type TriggerStageFamily = 'trust' | 'ipAcl' | 'geoip' | 'crawler' | 'threat' | 'wafCustom' | 'wafCrs' | 'body' | 'other'

const CUSTOM_RULE_OR_CONDITION_ID_BASE = 3000000
const CUSTOM_RULE_MAX_CONDITIONS = 64

// 普通 emit id 与 OR 条件分支 emit id 都回解到同一 DB 父规则；旧内嵌合成 id 无父行。
export const customRuleEventDbID = (ruleTriggered: string): number => {
  const n = Number((ruleTriggered ?? '').trim())
  if (!Number.isInteger(n)) return Number.NaN
  if (n > 10000 && n < 800000) return n - 10000
  if (n >= CUSTOM_RULE_OR_CONDITION_ID_BASE) {
    const parentEmitID = Math.floor((n - CUSTOM_RULE_OR_CONDITION_ID_BASE) / CUSTOM_RULE_MAX_CONDITIONS)
    if (parentEmitID > 10000 && parentEmitID < 800000) return parentEmitID - 10000
  }
  return Number.NaN
}

export const triggerStageFamily = (ruleTriggered: string): TriggerStageFamily => {
  const t = (ruleTriggered ?? '').trim()
  if (!t) return 'other'
  if (t === '11') return 'body'
  // ① 自定义规则 ID 形态（与后端 attackFamilyClassOf 分支同序）
  if (/^\d{5}$/.test(t)) return 'wafCustom'
  if (/^[1-7]\d{5}$/.test(t)) return 'wafCustom'
  if (/^1\d{6,}$/.test(t)) return 'wafCustom'
  // CRS 恒 6 位 9 开头（5 位 9xxxx 已由上方自定义分支覆盖）
  if (/^9\d{5}$/.test(t)) return 'wafCrs'
  const n = Number(t)
  if (!Number.isFinite(n)) return 'other'
  if (n >= CUSTOM_RULE_OR_CONDITION_ID_BASE) return 'wafCustom'
  // ② 固定 id 族（后端 legacyRuleFamilies 表派生口径）
  if (n === 3 || n === 5 || n === 12) return 'trust'
  if (n === 14) return 'threat'
  // ③ 数值段：爬虫两族与地域段互斥（后端口径）
  if (n >= 810000 && n < 900000) return 'crawler'
  if (n >= 800000 && n < 810000) return 'geoip'
  if (n === 2 || n === 4 || n === 7 || n === 8) return 'ipAcl'
  return 'other'
}

/**
 * 「所属策略为检测模式（命中只记录）」能否解释本类事件的 logged 动作。
 * 后端 detection 的 ctl:ruleEngine=DetectionOnly（security.go:453-454 id:6）在
 * IP ACL/遗留黑名单/自定义规则之后、CRS 与请求体规则之前发射——所以只有 WAF 族
 * （CRS/自定义含 body 目标）的 logged 可由检测模式解释；阶段 1 族（IP ACL/地域/
 * 威胁/爬虫）的 denial 与模式无关，logged 的真实成因是信任保留检测
 * （security.go:374-386），必须走跨策略信任豁免文案，不能归因「检测模式」。
 * 信任族事件本身不展示该说明（kind='trust' 由调用方先短路）。
 */
export const detectionModeExplains = (kind: string): boolean => kind === 'waf-crs' || kind === 'waf-custom'

/**
 * WAF 族「耗时加和」判定（事件列表请求上下文弹框 / 触发详情弹框共用）：
 * WAF 段独立计时，事件行 duration_us = WAF 段耗时，precheck_us = 预检耗时，
 * 展示时二者加和并分解；预检族（IP ACL/信任/地域/威胁/爬虫）duration_us
 * ≡ precheck_us 单值，加和会翻倍。
 * 与 detectionModeExplains 的集合有意不同（后者不含 body——请求体异常不归因
 * 检测模式），两处集合差异必须各自命名，不得合并。
 */
export const isWafDurationFamily = (family: TriggerStageFamily): boolean =>
  family === 'wafCrs' || family === 'wafCustom' || family === 'body'

/**
 * 跨策略信任豁免判定的候选策略：事件详情端点不过滤 enabled，属主
 * 策略可能事后被禁用——禁用策略不渲染、不可能放行，不得参与豁免归因。
 * 判定按 trustHitMode：非阶段 0 存量信任引擎恒 DetectionOnly（可产生 logged
 * 事件 → 可解释豁免）；阶段 0 直通模式不产生后续阶段事件，故不参与归因。
 */
export const isTrustExemptionCandidate = (p: {
  enabled?: boolean
  ip_whitelist_enabled?: boolean
  trust_detection?: boolean
  policy_type?: string
}): boolean => p.enabled !== false && !!p.ip_whitelist_enabled && trustHitMode(p.policy_type, p.trust_detection) === 'detection'

// ── 拦截页归因 ─────────────────────────────────────────────
// 后端渲染事实（internal/services/caddy.go）：
//  - 阶段 3：每策略恒得合成码 483+（policySynthetic），页面归属=触发策略自身；
//    若规则级 stage3 覆盖（id>0 ∧ 内容非空）在场 → 全规则恒 482，逐策略归因不可达。
//  - 阶段 1：预检合并决策 403（'interruption triggered'），错误路由取绑定链
//    （policy_id ASC、仅启用）中首个「有非空页」策略；规则级 stage1 覆盖在场 → 481。
//  - 阶段 2：429 错误路由取绑定链首个「有非空页」策略（且至少一条启用策略开启限流）。
// 本函数把上述口径收敛为单源判定（前端只消费结果，不得另写第三份归因）。
export type BlockPageStage = 1 | 2 | 3
type BlockPageEffective = 'self' | 'peer' | 'rule-override' | 'none'

export interface BlockPageChainPolicy {
  policyId: number | null
  name: string
  enabled: boolean
  /** 链中是否为本策略（编辑中的策略以表单实时值参与） */
  isSelf?: boolean
  /** 策略配置的拦截页 id（0=不使用自定义页面） */
  blockPageId?: number
  /** 该页是否存在且内容非空（后端 blockPageByID 非空才算有效页） */
  pageHasContent?: boolean
  /** 仅阶段 2 使用：该策略是否启用限流（429 才能产生） */
  rateLimitEnabled?: boolean
}

export interface BlockPageAttribution {
  stage: BlockPageStage
  effective: BlockPageEffective
  /** effective === 'peer' 时：实际显示页面的策略名 */
  winnerName?: string
}

/** 有效页 = 页 id>0 且页内容非空（后端对空内容页视为无页）。 */
const chainHasValidPage = (p: BlockPageChainPolicy): boolean => (p.blockPageId ?? 0) > 0 && p.pageHasContent === true

/**
 * 「该阶段在当前配置下能否产生拦截」能力门。
 *
 * resolveBlockPageAttribution 只判「页有效 + 绑定链位置」，不看阶段是否有
 * 拒绝规则——stage3 默认 mode=off、stage1 无 ACL/地域/黑名单时永远不会触发
 * 拦截，页面配置得再好也不会显示。向导注记必须先过本门，否则会与同页
 * 「WAF 关闭」「未启用 ACL」的摘要自相矛盾。
 *
 * 引擎口径：
 *  - 阶段 2：429 由绑定链任一启用限流策略产生（本谓词不承担限流门，
 *    归因侧 rateLimitEnabled 已门控），恒 true。
 *  - 阶段 3：mode=off 无 deny；detection/custom_only 只有自定义规则动作为
 *    block 时才阻断（CRS 在检测模式仅记录）。
 *  - 阶段 1：ACL（非绕过且有条目）/独立黑名单/地域任一成立才发射预检 deny。
 */
interface BlockPageStageCapability {
  stage: BlockPageStage
  /** 阶段 3 WAF 模式（off/detection/blocking/custom_only） */
  mode?: string
  /** 阶段 3：至少一条启用且动作为 block 的自定义规则 */
  hasBlockingCustomRule?: boolean
  /** 阶段 1：ACL 已启用且有效条目非空（绕过模式不拦截） */
  hasAclEntries?: boolean
  /** 阶段 1：独立遗留黑名单非空 */
  hasBlacklistEntries?: boolean
  /** 阶段 1：地域拦截启用且区域非空 */
  hasGeoip?: boolean
}

export const blockPageStageCanIntercept = (input: BlockPageStageCapability): boolean => {
  if (input.stage === 2) return true
  if (input.stage === 3) {
    const mode = input.mode ?? 'off'
    if (mode === 'off') return false
    return mode === 'blocking' || input.hasBlockingCustomRule === true
  }
  return input.hasAclEntries === true || input.hasBlacklistEntries === true || input.hasGeoip === true
}

/** 自定义规则是否能在指定 WAF 模式下产生真实阻断；detection 的 phase 2 body 规则仅记录。 */
export const customRuleCanBlockInMode = (mode: string, rule: SecurityStageCustomRule): boolean => {
  if (rule.enabled === false || (rule.action ?? 'block') !== 'block') return false
  return mode !== 'detection' || !(rule.conditions ?? []).some((condition) => condition.target === 'body')
}

/** 地址级允许×拒绝提示：阶段 0 信任全局优先；ACL 与存量非阶段 0 信任仍属策略本地。 */
export const addressAllowDenyConflictText = (input: {
  kind: 'acl' | 'trust'
  policyType?: string
  trustDetection?: boolean
  denyPolicyName: string
}): string => {
  if (input.kind === 'trust' && input.policyType === 'stage0') {
    return input.trustDetection === true
      ? '阶段 0 信任跨策略优先生效：保留检测模式仅记录、不拦截'
      : '阶段 0 信任跨策略优先生效：直通模式跳过全部安全检测'
  }
  const allowance = input.kind === 'trust' ? '信任' : '允许'
  return `${allowance}不跨策略生效，该地址仍会被「${input.denyPolicyName}」拦截`
}

/**
 * 「拦截页缺失/内容为空」判定。
 *
 * loaded=false（拦截页列表尚未成功落地过一次）时**不得判定缺失**——辅助端点部分
 * 失败会让所有启用策略挂上「页面已删除或内容为空」的假警告。pageId<=0（未配置
 * 自定义页）不是缺失。
 *
 * 同时是归因与空页预告的共用谓词（单一真相，避免两处各写一份）。
 */
export const blockPageMissing = (
  pageId: number,
  pages: readonly { id: number; content?: string }[],
  loaded: boolean,
): boolean => {
  if (!loaded || pageId <= 0) return false
  const page = pages.find((p) => p.id === pageId)
  return !page || (page.content ?? '') === ''
}

/**
 * 计算「本策略配置的拦截页在某个阶段是否真的会显示」，与 caddy.go 逐条对齐。
 *
 * chain 顺序不重要：函数内部按后端绑定序（policy_id ASC，未保存策略 id=null 视作
 * 最大）排序——视图侧传入的是「按阶段 rank 排序的展示链」，与渲染序不同，故不能
 * 依赖入参顺序。
 */
export const resolveBlockPageAttribution = (
  stage: BlockPageStage,
  chain: readonly BlockPageChainPolicy[],
  ruleOverride: { pageId: number; pageHasContent: boolean } | null = null,
): BlockPageAttribution => {
  const bindOrder = (p: BlockPageChainPolicy): number => p.policyId ?? Number.MAX_SAFE_INTEGER
  const enabled = chain.filter((p) => p.enabled).slice().sort((a, b) => bindOrder(a) - bindOrder(b))
  // 规则级覆盖：仅阶段 1/3 存在（阶段 2 状态码恒 429，无规则级覆盖层）
  if (stage !== 2 && ruleOverride && ruleOverride.pageId > 0 && ruleOverride.pageHasContent) {
    return { stage, effective: 'rule-override' }
  }
  // 阶段 3：逐策略合成码 → 本策略有有效页即本策略页
  if (stage === 3) {
    const self = chain.find((p) => p.isSelf)
    if (self && self.enabled && chainHasValidPage(self)) return { stage, effective: 'self' }
    const fallback = enabled.find((p) => !p.isSelf && chainHasValidPage(p))
    return fallback
      ? { stage, effective: 'peer', winnerName: fallback.name }
      : { stage, effective: 'none' }
  }
  // 阶段 2：无启用限流策略 → 不产生 429，页面永不显示
  if (stage === 2 && !enabled.some((p) => p.rateLimitEnabled === true)) return { stage, effective: 'none' }
  // 阶段 1/2：渲染侧取绑定链首个有有效页的启用策略
  const winner = enabled.find(chainHasValidPage)
  if (!winner) return { stage, effective: 'none' }
  return winner.isSelf ? { stage, effective: 'self' } : { stage, effective: 'peer', winnerName: winner.name }
}
