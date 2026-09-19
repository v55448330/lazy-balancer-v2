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
  geoip_mode?: string
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
}

// 规则阶段页覆盖徽标（页已删/内容空 = broken，渲染侧等同未配）
export interface StageOverride {
  pageId: number
  pageName: string
  status: number
  broken: boolean
}

export interface StageGroup {
  stage: 1 | 2 | 3
  title: string
  enabled: boolean
  override: StageOverride | null
  groups: StagePolicyGroup[]
  footnote?: string
}

export interface RuleStageModel {
  hasAnyPolicy: boolean
  stages: [StageGroup, StageGroup, StageGroup]
}

// 流程抽屉的展示目标（规则行 / 向导预览共用；caddyId 存在时才拉取阶段计数）
export interface RuleFlowTarget {
  caddyId?: string
  name: string
  protocol: 'http' | 'tcp'
  listenPort: number
  enableTls: boolean
  upstreamSummary: string
}

// 流程图节点内的短标题（完整标题过长，128px 节点放不下，面板内仍用 STAGE_TITLES）
export const STAGE_SHORT_TITLES: Record<1 | 2 | 3, string> = {
  1: '阶段 1 · 预检',
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

export const STAGE_TITLES: Record<1 | 2 | 3, string> = {
  1: '阶段 1 · 预检（IP 访问控制 / 地域拦截）',
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

const buildStage1Rows = (policy: SecurityStagePolicy | undefined, ipLists: readonly SecurityStageIPList[]): StageRow[] => {
  const rows: StageRow[] = []
  if (policy?.has_ip_control) {
    // 摘要口径与安全策略页「IP 控制」明细行一致：合并计数（内联 ∪ 引用列表）+ 黑名单计数 + 信任名单（含启用态）
    const modeLabel = policy.ip_acl_mode === 'allow' ? '白名单模式' : (policy.ip_acl_mode === 'bypass' ? '免检测模式' : '黑名单模式')
    const aclCount = mergeIpEntries(ipLists, parseIPList(policy.ip_acl_list), parseRefIds(policy.ip_acl_list_refs)).length
    const blCount = parseIPList(policy.ip_blacklist).length
    rows.push({ label: 'IP 访问控制', detail: `${modeLabel} · 列表 ${aclCount} 条 · 黑名单 ${blCount} 条` })
    rows.push({ label: '信任名单', detail: `${mergeIpEntries(ipLists, parseIPList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs)).length} 条（${policy.ip_whitelist_enabled !== false ? '已启用' : '已关闭'}）` })
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
  if (mode === 'blocking') rows.push({ label: 'WAF（拦截）', detail: '命中即阻断' })
  else if (mode === 'detection') rows.push({ label: 'WAF（检测）', detail: '仅记录不阻断' })
  else if (mode === 'custom_only') rows.push({ label: 'WAF（仅自定义）', detail: 'CRS 不生效，自定义规则按规则内动作执行' })
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
  const stage1Groups: StagePolicyGroup[] = []
  const stage2Groups: StagePolicyGroup[] = []
  const stage3Groups: StagePolicyGroup[] = []

  bindings.forEach((binding, index) => {
    const policy = policies.find((p) => p.id === binding.policy_id)
    const base = { key: binding.policy_id, order: index + 1, name: binding.name, enabled: binding.enabled }

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
