<template>
  <el-popover v-if="canManage" ref="popoverRef" :width="400" trigger="click" popper-class="ip-location-popper" :popper-options="popperViewportSafe" @before-enter="onPopoverShow">
    <template #reference>
      <span
        class="ip-cell ip-clickable"
        role="button"
        tabindex="0"
        :aria-label="`IP 处置：${ip}`"
        :title="location ? `${ip} · ${location}` : ip"
        @keydown.enter.prevent="openPopover"
        @keydown.space.prevent="openPopover"
      >
        <span class="ip-text">{{ ip }}</span>
        <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
      </span>
    </template>

    <div class="ipo-head">
      <div class="ipo-ip-row">
        <span class="ipo-ip">{{ ip }}</span>
        <el-tooltip v-if="eventCount !== null" content="统计窗口：近 30 天（安全总览 Top 10 卡片为近 7 天口径）" placement="top">
          <el-tag size="small" :type="eventCount > 0 ? 'warning' : 'success'" effect="plain" round>
            30天事件 {{ eventCount }}
          </el-tag>
        </el-tooltip>
      </div>
      <div v-if="location" class="ipo-loc-line">{{ location }}</div>
    </div>

    <div v-if="policiesLoading" class="ipo-tip">策略加载中…</div>
    <div v-else-if="policiesError" class="info-note-bar"><span class="info-note-desc">策略列表加载失败</span></div>
    <template v-else-if="rows.length > 0">
      <div v-if="groupedRows.offstage > 0" class="ipo-tip">另有 {{ groupedRows.offstage }} 条限流/WAF 策略不涉及 IP 管控</div>
      <!-- 阶段 0 空态（第 60 轮用户裁定：提示创建，不自动代建） -->
      <div v-if="groupedRows.stage0.length === 0 && rows.length > 0" class="ipo-sec">
        <div class="ipo-sec-title">阶段 0 · 信任名单</div>
        <div class="ipo-tip">未绑定信任策略——到「安全防护 → 安全策略」创建并绑定后可信任此 IP</div>
      </div>
      <div v-for="group in visibleGroups" :key="group.key" class="ipo-sec">
        <div class="ipo-sec-title">{{ group.title }}</div>
        <div v-for="row in group.rows" :key="row.policy.id" class="ipo-card">
          <div class="ipo-card-head">
            <span class="ipo-name" :title="row.policy.name">{{ row.policy.name }}</span>
            <span class="ipo-card-meta">
              <el-tag size="small" :type="row.tagType" effect="plain">{{ row.tagLabel }}</el-tag>
              <span v-if="row.countLabel" class="ipo-count">{{ row.countLabel }}</span>
            </span>
          </div>
          <div v-if="group.key === 'stage0'" class="ipo-mode-line">{{ row.trustDetectionLabel }}</div>
          <div class="ipo-status" :class="row.statusClass">{{ row.statusLabel }}</div>
          <!-- 区域+列表组合（第 59 轮枚举补全）：ACL 评估之外地域拦截同样在链上，
               名单未命中不代表放行（区域命中仍拦）——卡片显式列出区域维度 -->
          <div v-if="row.geoActive && group.key !== 'stage0'" class="ipo-mode-line">另启用地域拦截 · {{ row.policy.geoip_mode === 'allow' ? '仅允许' : '拦截' }}区域：{{ row.geoRegions }}</div>
          <div v-if="row.inLegacy && group.key !== 'stage0'" class="ipo-legacy">该 IP 还存在于旧版独立黑名单字段，可经 API 更新策略（ip_blacklist）清理</div>
          <div v-if="group.key === 'mixed'" class="ipo-legacy">混合策略（兼容旧版）· 仅可更新迁移——到「安全防护 → 安全策略」页对该策略执行「更新迁移」拆分为单职策略</div>
          <div v-if="row.trustDead" class="ipo-legacy">该 IP 的信任条目存在，但策略的信任名单已关闭——条目暂不生效</div>
          <div v-if="rowActions(row).length > 0" class="ipo-acts">
            <template v-for="act in rowActions(row)" :key="act.key">
              <span v-if="!act.run" class="ipo-act-hint">{{ act.label }}</span>
              <el-tooltip v-else-if="act.tip" :content="act.tip" placement="top">
                <el-button size="small" :type="act.type" plain :loading="act.loading" @click="act.run()">{{ act.label }}</el-button>
              </el-tooltip>
              <el-button v-else size="small" :type="act.type" plain :loading="act.loading" @click="act.run()">{{ act.label }}</el-button>
            </template>
          </div>
        </div>
      </div>
    </template>
    <div v-else class="ipo-tip">暂无启用的安全策略</div>
  </el-popover>

  <span v-else class="ip-cell" :title="location ? `${ip} · ${location}` : ip">
    <span class="ip-text">{{ ip }}</span>
    <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { useAuthStore } from '@/stores/auth'
import { useTrustAssociation } from '@/composables/useTrustAssociation'
import type { IpListOption } from '@/composables/useIpListAdd'
// 分组类型路由（U8-2）：inferPolicyType 为策略类型单一实现（securityStages 导出，禁第二实现）
import { inferPolicyType, parseIPList, parseRefIds, entryMatchesIp, invalidateSharedEntriesCache } from '@/utils/securityStages'
import { popperViewportSafe } from '@/utils/popper'
import type { SecurityPolicyType, SecurityPolicyTypeInput } from '@/utils/securityStages'
import type { APIResponse } from '@/types'

// 列表接口与详情接口共用同一组 SELECT 列，列表行直接携带完整 ACL 字段
interface PolicyRow {
  id: number
  name: string
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  // 引用的可复用地址列表（JSON 数字数组文本）——生效口径 = 内联 ∪ 引用条目
  ip_acl_list_refs?: string
  ip_whitelist: string
  ip_whitelist_refs?: string
  ip_blacklist: string
  // 审计 W-S2（第六轮）：信任三态开关——加入名单前须提示「当前关闭=零生效」
  ip_whitelist_enabled?: boolean
  // 分组路由字段（U8-2）：policy_type 由列表/详情接口携带；'' 为存量待推断态。
  // 摘要标志仅列表摘要携带（详情接口无）——refreshRow 以合并方式保留
  policy_type?: string
  trust_detection?: boolean
  mode?: string
  rate_limit_enabled?: boolean
  geoip_enabled?: boolean
  geoip_mode?: string
  geoip_countries?: string
  has_geoip?: boolean
  has_rate_limit?: boolean
  has_waf?: boolean
  has_custom_rules?: boolean
}

interface PolicyDetail {
  id: number
  name: string
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  ip_acl_list_refs?: string
  ip_whitelist: string
  ip_whitelist_refs?: string
  ip_blacklist?: string
  policy_type?: string
  trust_detection?: boolean
}



const props = defineProps<{ ip: string; location: string; ruleCaddyId?: string }>()

// 紧凑归属地：国内只显市/海外恒「海外」/保留地址原样，弹窗/悬浮显示完整
const compactLocation = computed(() => {
  if (!props.location) return ''
  const parts = props.location.split('·').map(s => s.trim()).filter(Boolean)
  // 分类先行（用户裁定 2026-09-13）：海外列表恒显「海外」（不显示国家/城市/
  // ISP，完整精度仅弹框）；保留地址原样；国内只显市（下方细分）
  if (parts[0] === '保留地址') return '保留地址'
  if (parts[0] !== '中国') return '海外'
  // 国内只显市(用户裁定 2026-09-13):三段+取第三段市(如「中国·广东·深圳」→
  // 「深圳」;自治区「中国·新疆·乌鲁木齐」→「乌鲁木齐」);两段取第二段省
  // (「中国·山东」→「山东」;「中国·新疆」→「新疆」);单段「中国」保持(防空标签)
  if (parts.length === 1) return '中国'
  if (parts.length === 2) return parts[1]
  return parts[2]
})

const authStore = useAuthStore()
// 仅主节点管理员可操作（从节点/非管理员只展示 IP 与归属地）——与全局只读口径一致
const canManage = computed(() => authStore.readOnlyReason === null)

const eventCount = ref<number | null>(null)
let eventCountSeq = 0
const loadEventCount = async (): Promise<void> => {
  const seq = ++eventCountSeq
  try {
    const res = await request.get<APIResponse<{ count: number }>>('/security/events/count', { params: { ip: props.ip, days: 30 }, silent: true })
    if (seq === eventCountSeq) eventCount.value = res.data?.count ?? 0
  } catch {
    if (seq === eventCountSeq) eventCount.value = null
  }
}

const onPopoverShow = (): void => { void loadPolicies(); void loadEventCount() }

// 键盘激活（第 60 轮 P3）：Enter/Space 不仅要预取数据，还须真正打开弹层——
// trigger=click 的 el-popover 在非原生 button 上不合成 click，须持 ref 调 open。
// FE-P5a（第 69 轮）：中置二次导入并入文件头 :79 的 `import { computed, ref }`。
const popoverRef = ref<{ open: () => void } | null>(null)
const openPopover = (): void => {
  onPopoverShow()
  popoverRef.value?.open()
}

// —— 信任直接动作（第 58 轮统一模型）：与触发详情弹框共享实现。
// 信任此 IP 不再依赖顶部列表选择：策略已有信任用途列表→直接加入；
// 没有→自动创建「{策略名}-信任」并关联+加入。
const trustApi = useTrustAssociation({
  getList: () => ipLists.value,
  // 第 60 轮验收：写入后必须清条目缓存——loadIpLists 只拉缓存缺失 ID（B3-P5
  // 优化），已缓存列表的新增条目不可见导致「拦截此 IP」按钮在加入后仍显示
  onChanged: () => {
    ipListEntries.value = {}
    invalidateSharedEntriesCache() // 第 61 轮 P2-2：同步清空 TriggerDetailDialog 共享缓存
    return loadPolicies()
  },
})
const { busyTrust, creating: trustCreating, resolveSideLists, joinSpecificList, removeFromSideRef } = trustApi

const policies = ref<PolicyRow[]>([])
const policiesLoading = ref(false)
const policiesError = ref(false)
const busyKeys = ref<Set<string>>(new Set())

// —— 显式存入地址列表：与策略名单动作同口径（确认弹框 + 全局 MFA 428 守卫 +
// 明确反馈），不再作为名单写入后的隐式自动追加；确认/幂等 POST/反馈复用
// useIpListAdd 共享实现（与 SecurityEvents 事件弹框「加入列表」同一链路） ——
const ipLists = ref<IpListOption[]>([])

// 引用列表条目缓存：v2.3.2 起 /security/ip-lists 列表载荷不再内联 entries
// （大名单 460KB/行），条目值按需经 GET /security/ip-lists/:id 拉取——
// 仅拉取在案策略引用到的名单，避免为 refs 背全量条目
interface IpListWithEntries extends IpListOption {
  entries?: Array<{ value: string; remark?: string }>
}
const ipListEntries = ref<Record<number, string[]>>({})

const loadIpLists = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<IpListWithEntries[]>>('/security/ip-lists')
    ipLists.value = res.data || []
    // 在案策略引用到的名单按需拉条目（成员判定/合并口径的真实值来源）
    const refIds = new Set<number>()
    for (const p of policies.value) {
      for (const id of parseRefIds(p.ip_acl_list_refs)) refIds.add(id)
      for (const id of parseRefIds(p.ip_whitelist_refs)) refIds.add(id)
    }
    // 会话内条目缓存（第 55 轮 B3-P5：原实现每次 @show 对全部引用名单整表
    // 重拉，三源全引 1.5-2MB/次）——仅拉取缓存缺失的名单 id；存入名单成功后
    // 由调用方把新 IP 写回缓存，成员判定保持即时正确
    const map: Record<number, string[]> = { ...ipListEntries.value }
    const missing = [...refIds].filter((id) => !(id in map))
    const results = await Promise.allSettled(
      missing.map((id) => request.get<APIResponse<{ id: number; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`)),
    )
    results.forEach((r) => {
      if (r.status === 'fulfilled' && r.value.data) {
        map[r.value.data.id] = (r.value.data.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
      }
    })
    ipListEntries.value = map
  } catch {
    ipLists.value = []
    ipListEntries.value = {}
  }
}







// 生效名单 = 内联 ∪ 引用列表条目（精确字符串去重，与向导 mergeIpEntries 同口径）；
// 缓存中缺失的引用列表跳过（防御性回退为仅内联）
const mergeIpEntries = (inline: string[], refs: number[]): string[] => {
  const set = new Set(inline.map((v) => v.trim()).filter((v) => v !== ''))
  for (const id of refs) {
    const entries = ipListEntries.value[id]
    if (!entries) continue
    for (const v of entries) set.add(v)
  }
  return [...set]
}

// 每策略生效 ACL / 信任名单（内联 ∪ 引用），状态展示与语义反转守卫共用
const mergedAclEntries = (policy: PolicyRow): string[] =>
  mergeIpEntries(parseIPList(policy.ip_acl_list), parseRefIds(policy.ip_acl_list_refs))

const mergedTrustEntries = (policy: PolicyRow): string[] =>
  mergeIpEntries(parseIPList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs))

const normalizeRow = (p: PolicyRow): PolicyRow => ({
  id: p.id,
  name: p.name,
  ip_acl_enabled: !!p.ip_acl_enabled,
  ip_acl_mode: p.ip_acl_mode || '',
  ip_acl_list: p.ip_acl_list || '[]',
  ip_acl_list_refs: p.ip_acl_list_refs || '[]',
  ip_whitelist: p.ip_whitelist || '[]',
  ip_whitelist_refs: p.ip_whitelist_refs || '[]',
  ip_blacklist: p.ip_blacklist || '[]',
  ip_whitelist_enabled: p.ip_whitelist_enabled,
  policy_type: p.policy_type,
  trust_detection: p.trust_detection,
  mode: p.mode,
  rate_limit_enabled: p.rate_limit_enabled,
  geoip_enabled: p.geoip_enabled,
  geoip_mode: p.geoip_mode || 'off', // F64-B1-1:F63 修复字段被本投影白名单遗漏(geoActive 恒 false 回归)
  geoip_countries: p.geoip_countries || '[]',
  has_geoip: p.has_geoip,
  has_rate_limit: p.has_rate_limit,
  has_waf: p.has_waf,
  has_custom_rules: p.has_custom_rules,
})

// 分组类型路由（U8-2 四组）：有效 policy_type 交由 inferPolicyType 单一实现直通
// （其首分支对合法值短路，内容字段不参与）；''/缺省（存量待推断态）按裁定归
// 「混合（兼容）」组双能力照旧——后端 ACL 启用门对 ''/mixed 存量态不拦，写路径兼容
const policyTypeOf = (p: PolicyRow): SecurityPolicyType =>
  inferPolicyType({
    policy_type: p.policy_type || 'mixed',
    has_ip_control: false,
    has_rate_limit: false,
    has_custom_rules: false,
  } satisfies SecurityPolicyTypeInput)

let loadPoliciesSeq = 0
const loadPolicies = async (): Promise<void> => {
  // 每次 @show 都强制重新拉取——同一策略绑定多条规则时，从规则 A 弹窗
  // 加入黑名单后，打开规则 B 弹窗需要看到最新 ACL 状态（无陈旧缓存）。
  // 地址列表选项同节奏刷新（含引用条目缓存）；等两者就绪后再渲染行，
  // 避免「内联 ∪ 引用」口径在条目到达前短暂退化为仅内联
  // FE18-3(第 18 轮):seq 守卫——弹层快速关开产生并发 GET 时,
  // 先发晚到不再覆盖新状态(与 wizardOpenSeq 同仓模式)。
  // 注:loadIpLists 内部写 ipLists ref 未纳入本 seq(独立加载面,
  // 亚秒级关开竞态的展示瞬态;若需彻底,可在该函数加同款守卫)。
  const seq = ++loadPoliciesSeq
  policiesLoading.value = true
  try {
    const url = props.ruleCaddyId
      ? `/security/policies?enabled=true&rule_caddy_id=${encodeURIComponent(props.ruleCaddyId)}`
      : '/security/policies?enabled=true'
    const res = await request.get<APIResponse<PolicyRow[]>>(url)
    if (seq !== loadPoliciesSeq) return
    policies.value = (res.data || []).map(normalizeRow)
    // 名单条目按需拉取依赖 policies 的引用清单（列表载荷不含 entries）——
    // 须在 policies 就位后执行
    await loadIpLists()
    policiesError.value = false
  } catch {
    if (seq !== loadPoliciesSeq) return
    policiesError.value = true
  } finally {
    if (seq === loadPoliciesSeq) policiesLoading.value = false
  }
}

// —— 每行视图状态：模式标签 / 该 IP 的归属状态 / 可用动作 ——

interface RowView {
  policy: PolicyRow
  inTrust: boolean
  inTrustInline: boolean
  inTrustInlineExact: boolean
  trustEnabled: boolean
  trustCount: number
  trustDetectionLabel: string
  trustDead: boolean
  canAddTrust: boolean
  canRemoveTrust: boolean
  canClearDeadTrust: boolean
  inLegacy: boolean
  tagType: 'danger' | 'success' | 'info' | 'warning'
  tagLabel: string
  statusClass: 'is-ok' | 'is-warn' | ''
  statusLabel: string
  countLabel: string
  canAssociate: boolean
  canAssociateAllow: boolean
  canRemove: boolean
  removableRefLists: Array<{ id: number; name: string }>
  removableTrustRefLists: Array<{ id: number; name: string }>
  aclHitSourceLabel: string
  trustHitSourceLabel: string
  geoActive: boolean
  geoRegions: string
}

const rowView = (policy: PolicyRow): RowView => {
  // 信任口径（内联 ∪ 引用）先行计算——阶段 0 行整行语义即信任，ACL 行也要渲染信任动作。
  // U9-68-P4-1：信任成员判定与 ACL 侧同为 CIDR 感知（entryMatchesIp）——内联/引用
  // 信任名单的 CIDR 条目在引擎侧本就豁免该 IP，精确串匹配会漏报「已信任」状态；
  // 移除动作仍收窄为精确条目（inTrustInlineExact，与 U9-1 ACL 侧同口径——CIDR
  // 覆盖的 IP 无法由 PUT 精确剔除）
  const trustEntries = mergedTrustEntries(policy)
  const trustInlineEntries = parseIPList(policy.ip_whitelist)
  const inTrustInlineExact = trustInlineEntries.includes(props.ip.trim())
  const view: RowView = {
    policy,
    inTrust: trustEntries.some((e) => entryMatchesIp(e, props.ip.trim())),
    inTrustInline: trustInlineEntries.some((e) => entryMatchesIp(e, props.ip.trim())),
    inTrustInlineExact,
    trustEnabled: policy.ip_whitelist_enabled !== false,
    trustCount: trustEntries.length,
    // 与 securityStages.buildStage0Rows 模式行同文案
    trustDetectionLabel: policy.trust_detection === true ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）',
    trustDead: false,
    canAddTrust: false,
    canRemoveTrust: false,
    canClearDeadTrust: false,
    inLegacy: parseIPList(policy.ip_blacklist).includes(props.ip),
    tagType: 'info',
    tagLabel: '未启用',
    statusClass: '',
    statusLabel: 'IP ACL 未启用',
    countLabel: '',
    canAssociate: false,
    canAssociateAllow: false,
    canRemove: false,
    removableRefLists: [] as Array<{ id: number; name: string }>,
    aclHitSourceLabel: '',
    trustHitSourceLabel: '',
    removableTrustRefLists: [] as Array<{ id: number; name: string }>,
    geoActive: false,
    geoRegions: '',
  }
  // 第 59 轮验收复查：信任豁免为全局生效（预检 DetectionOnly 事务级）——IP 已被
  // 任一策略信任时，「信任此 IP」按钮冗余（再加只是重复豁免，且会使策略类型
  // 内容漂移），不再显示；主动作归「取消信任」（豁免方策略卡上）。
  const isStage0OrMixed = policyTypeOf(policy) === 'stage0' || policyTypeOf(policy) === 'mixed'
  view.canAddTrust = isStage0OrMixed && !view.inTrust
    && !policies.value.some((p) => mergedTrustEntries(p).some((e) => entryMatchesIp(e, props.ip.trim())))
  view.canRemoveTrust = view.inTrust && view.trustEnabled && view.inTrustInlineExact
  view.trustDead = view.inTrust && !view.trustEnabled
  view.canClearDeadTrust = view.trustDead && view.inTrustInlineExact
  // 信任引用命中（全类型行）：信任 refs 中包含此 IP 的非系统列表 → 可移除。
  // 条目来源 = ipListEntries 缓存（loadPolicies 拉取 acl+whitelist 全部 refs）。
  const trustRefIds = parseRefIds(policy.ip_whitelist_refs)
  view.removableTrustRefLists = ipLists.value
    .filter((l) => trustRefIds.includes(l.id) && !l.system)
    .filter((l) => (ipListEntries.value[l.id] ?? []).some((e) => entryMatchesIp(e, props.ip.trim())))
    .map((l) => ({ id: l.id, name: l.name }))
  // ACL 引用命中（第 58 轮补）：黑/白名单状态行标注具体来源名单名
  const aclRefIds = parseRefIds(policy.ip_acl_list_refs)
  const aclHitNames = ipLists.value
    .filter((l) => aclRefIds.includes(l.id) && !l.system)
    .filter((l) => (ipListEntries.value[l.id] ?? []).some((e) => entryMatchesIp(e, props.ip.trim())))
    .map((l) => l.name)
  const srcTag = (names: string[]): string =>
    names.length > 0 ? `（来自引用列表「${names.join('」「')}」）` : '（来自引用列表）'
  view.aclHitSourceLabel = srcTag(aclHitNames)
  view.trustHitSourceLabel = srcTag(view.removableTrustRefLists.map((l) => l.name))

  // 阶段 0 行（U8-2 分组②）：信任名单状态即整行语义，无 ACL 面；
  // 模式行（直通/保留检测）由模板按组渲染
  if (policyTypeOf(policy) === 'stage0') {
    view.tagType = view.trustEnabled ? 'success' : 'info'
    view.tagLabel = view.trustEnabled ? '信任启用' : '信任停用'
    view.countLabel = view.trustCount > 0 ? `${view.trustCount} 条` : ''
    if (view.inTrust) {
      view.statusClass = view.trustEnabled ? 'is-ok' : 'is-warn'
      // 内联 CIDR 覆盖（非精确条目）与 ACL 侧同文案标注——来源不再误指引用列表
      const cidrNote = view.inTrustInline && !view.inTrustInlineExact ? '（来自内联 CIDR 条目，请到策略编辑中移除）' : ''
      const hit = view.inTrustInline ? `✅ 已在信任名单中${cidrNote}` : `✅ 已在信任名单中${view.trustHitSourceLabel}`
      view.statusLabel = view.trustEnabled ? hit : `${hit}——信任名单未启用，暂不生效`
    } else {
      view.statusLabel = view.trustCount === 0 ? '信任名单未配置' : `信任名单 ${view.trustCount} 条${view.trustEnabled ? '' : '（未启用）'}`
    }
    return view
  }

  // 地域拦截维度（第 57 轮：GeoIP 策略不再误标「未启用」——明确展示地域维度）
  let regionCount = 0
  try {
    const regions: unknown = JSON.parse(policy.geoip_countries ?? '[]')
    if (Array.isArray(regions)) regionCount = regions.length
  } catch { /* 畸形按 0 处理 */ }
  // F63-B1-1:geoip_enabled 后端不下发(接口零处),恒 undefined→false;
  // 改用 geoip_mode !== 'off' 判定(后端实际下发)
  const geoActive = (policy.geoip_mode ?? 'off') !== 'off' && regionCount > 0
  view.geoActive = geoActive
  view.geoRegions = regionCount > 0 ? (JSON.parse(policy.geoip_countries ?? '[]') as string[]).join('、') : '' 
  if (!policy.ip_acl_enabled) {
    // ACL 未启用：如地域拦截在用则明示「地域拦截在用（本事件可来自地域）」；
    // 关联地址列表动作仍可用（关联后随 ACL 启用生效）
    if (geoActive) {
      view.tagType = 'warning'
      view.tagLabel = '地域拦截'
      view.statusLabel = `地域拦截已启用 · 拦截区域：${view.geoRegions}（IP ACL 未启用）`
      view.canAssociate = true
      view.canAssociateAllow = true
    }
    return view
  }

  // 生效名单 = 内联 ∪ 引用列表条目；引用命中的条目无法在本弹窗移除
  // （PUT 仅写内联 ip_acl_list）。展示口径 CIDR 感知（第 62 轮 F62-9：内联
  // CIDR 条目命中实际 IP）；U9-1：移除动作收窄为精确条目（inInlineExact）——
  // 内联 CIDR 覆盖的 IP 无法由 PUT 精确剔除（剔除整条 CIDR 会波及其他 IP），
  // 不再亮「移除」，状态行改标「来自内联 CIDR」引导到策略编辑。
  const list = mergedAclEntries(policy)
  const aclInlineEntries = parseIPList(policy.ip_acl_list)
  const inInlineExact = aclInlineEntries.includes(props.ip.trim())
  const inInline = aclInlineEntries.some((e) => entryMatchesIp(e, props.ip.trim()))
  const inList = list.some((e) => entryMatchesIp(e, props.ip.trim()))

  view.removableRefLists = ipLists.value
    .filter((l) => !l.system && parseRefIds(policy.ip_acl_list_refs).includes(l.id))
    .filter((l) => (ipListEntries.value[l.id] ?? []).some((e) => entryMatchesIp(e, props.ip.trim())))
    .map((l) => ({ id: l.id, name: l.name }))
  // 信任豁免组合态（第 59 轮组合语义复查）：预检信任 DetectionOnly 是事务级
  // 全局——但后缀只对「实际命中」形态有意义（deny 命中 / allow 交集外被 id:7
  // 拒），未命中本来就不拦、allow 名单内本来合法放行，挂后缀反而误导；同时
  // 点名豁免策略（跨策略时用户需要知道去哪取消）。
  const td1Owner = policies.value.find((p) => p.ip_whitelist_enabled && p.trust_detection === true && mergedTrustEntries(p).some((e) => entryMatchesIp(e, props.ip.trim())))
  const td0Owner = policies.value.find((p) => p.ip_whitelist_enabled && p.trust_detection === false && mergedTrustEntries(p).some((e) => entryMatchesIp(e, props.ip.trim())))
  const exemptHitSuffix = td1Owner ? ` · 信任豁免中（由「${td1Owner.name}」放行）：命中不拦截，事件记为检测` : ''
  const passthruSuffix = !td1Owner && td0Owner ? ' · 信任直通中：跳过全部安全阶段，不产生事件' : ''
  if (policy.ip_acl_mode === 'deny') {
    view.tagType = 'danger'
    view.tagLabel = '黑名单'
    view.countLabel = `${list.length} 条`
    if (inList) {
      view.statusClass = td1Owner ? 'is-warn' : 'is-ok'
      const cidrNote = inInline && !inInlineExact ? '（来自内联 CIDR 条目，请到策略编辑中移除）' : ''
      view.statusLabel = (inInline ? `✅ 已在黑名单中${cidrNote}` : `✅ 已在黑名单中${view.aclHitSourceLabel}`) + exemptHitSuffix + passthruSuffix
      view.canRemove = inInlineExact
    } else {
      view.statusLabel = `黑名单 · ${list.length} 条`
      view.canAssociate = true
    }
  } else if (policy.ip_acl_mode === 'allow') {
    view.tagType = 'success'
    view.tagLabel = '白名单'
    view.countLabel = `${list.length} 条`
    if (inList) {
      view.statusClass = 'is-ok'
      const cidrNote = inInline && !inInlineExact ? '（来自内联 CIDR 条目，请到策略编辑中移除）' : ''
      view.statusLabel = (inInline ? `✅ 已在白名单中${cidrNote}` : `✅ 已在白名单中${view.aclHitSourceLabel}`) + exemptHitSuffix + passthruSuffix
      view.canRemove = inInlineExact
    } else {
      view.statusClass = 'is-warn'
      // allow 交集外 = id:7 拒绝形态：无信任时确实无法访问；信任豁免中放行（记检测）
      view.statusLabel = (td1Owner || td0Owner ? '⚠️ 不在白名单中' : '⚠️ 不在白名单中（当前无法访问）') + exemptHitSuffix + passthruSuffix
      view.canAssociateAllow = true
    }
  } else if (policy.ip_acl_mode === 'bypass') {
    view.tagLabel = '免检测'
    view.statusLabel = '免检测模式'
    if (list.length > 0) view.countLabel = `${list.length} 条`
  } else {
    // 未知模式兜底：仅展示，不提供 ACL 动作
    view.tagLabel = policy.ip_acl_mode || '未知'
  }
  return view
}

// 取消信任（组合语义主动作）：从策略信任侧全部位置移除该 IP——内联名单 PUT
// 剔除 + 逐个引用列表 remove-ip；随后整行刷新（状态即时翻转为名单/规则拦截）。
const cancelTrustAll = async (row: RowView): Promise<void> => {
  if (!lockBusy(row.policy.id, 'untrust')) return
  const ip = props.ip.trim()
  // U9-1 对齐：信任生效仅由本弹窗不可移除的条目（内联 CIDR 覆盖 / 系统名单精确
  // 条目）提供时，「取消信任」是空操作——不再弹确认框走流程后谎报成功，直接
  // 指引到对应编辑面。
  const inlineExact = parseIPList(row.policy.ip_whitelist).includes(ip)
  const exactRefLists = row.removableTrustRefLists.filter((m) => (ipListEntries.value[m.id] ?? []).some((e) => e === ip))
  if (!inlineExact && exactRefLists.length === 0) {
    if (parseIPList(row.policy.ip_whitelist).some((e) => entryMatchesIp(e, ip))) {
      ElMessage.info('该 IP 由内联 CIDR 提供信任，请在策略编辑中移除对应条目')
    } else if (row.removableTrustRefLists.some((m) => (ipListEntries.value[m.id] ?? []).some((e) => entryMatchesIp(e, ip)))) {
      ElMessage.info('该 IP 由引用列表中的 CIDR 条目提供信任，请编辑对应列表移除条目')
    } else {
      ElMessage.warning('该 IP 的信任条目不可在本弹窗移除，请到「安全防护 → 安全策略」编辑该策略处理')
    }
    unlockBusy(row.policy.id, 'untrust')
    return
  }
  try {
    try {
      await ElMessageBox.confirm(
        `将把 ${props.ip} 从策略「${row.policy.name}」的信任名单（内联与全部引用列表）移除，黑名单/规则命中即恢复拦截。是否继续？`,
        '取消信任',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
      )
    } catch { return }
    const detail = await fetchDetail(row.policy.id)
    if (detail) {
      const inline = parseIPList(detail.ip_whitelist).filter((v) => v !== props.ip.trim())
      if (inline.length !== parseIPList(detail.ip_whitelist).length) {
        await request.put(`/security/policies/${row.policy.id}`, { ip_whitelist: JSON.stringify(inline) })
      }
    }
    for (const m of exactRefLists) {
      await request.post(`/security/ip-lists/${m.id}/remove-ip`, { value: props.ip })
    }
    ElMessage.success(`已取消 ${props.ip} 对「${row.policy.name}」的信任`)
    ipListEntries.value = {}
    await loadPolicies()
  } catch {
    // 失败提示由全局拦截器弹出；部分移除也刷新到实际状态（第 60 轮 P5）
    ipListEntries.value = {}
    await loadPolicies()
  } finally {
    unlockBusy(row.policy.id, 'untrust')
  }
}

const rows = computed<RowView[]>(() => policies.value.map(rowView))

// 行内上下文动作（第 58 轮交互重构）：按行状态只出现该出现的动作。
// 顺序 = 信任（绿）→ 黑名单移除（红）→ 关联拦截/放行（红/蓝）→ 信任移除（绿）。
interface RowAction { key: string; label: string; type: 'primary' | 'success' | 'warning' | 'danger' | 'info'; loading?: boolean; tip?: string; run?: () => void }


const rowActions = (row: RowView): RowAction[] => {
  const acts: RowAction[] = []
  const pid = row.policy.id
  // 第 60 轮用户裁定：信任动作只出现在 stage0/mixed 卡——单职模型下信任归
  // 阶段 0，阶段 1 卡出信任按钮会导致类型内容漂移且语义混乱
  const trustAllowed = policyTypeOf(row.policy) === 'stage0' || policyTypeOf(row.policy) === 'mixed'
  if (trustAllowed && row.inTrust && row.trustEnabled) {
    // 组合语义（第 59 轮）：信任生效中——唯一动作=取消信任（从全部位置移除）；
    // 逐列表/内联移除按钮在此形态下冗余且有歧义（第 60 轮用户验收裁定）
    acts.push({
      key: 'cancel-trust',
      label: '取消信任（恢复拦截）',
      type: 'warning',
      tip: '将把该 IP 从本策略信任名单（内联与全部引用列表）移除；黑名单/规则命中即恢复拦截',
      loading: isBusy(pid, 'untrust'),
      run: () => { void cancelTrustAll(row) },
    })
  }
  // 逐列表/内联信任移除仅在「无取消信任按钮」时出现（trustDead 条目清理场景
  // 或信任关闭时的残留清理——cancel-trust 不覆盖这些形态）
  const granularTrustRemove = trustAllowed && !(row.inTrust && row.trustEnabled)
  if (trustAllowed && row.canAddTrust) {
    const trustLists = resolveSideLists(row.policy, 'trust')
    if (trustLists.length > 0) {
      // 逐列表出按钮（第 60 轮用户验收：多列表绑定时各出一个，不再只取第一个）
      for (const list of trustLists) {
        acts.push({
          key: `trust-${list.id}`,
          label: `信任此 IP（加入「${list.name}」）`,
          type: 'success',
          loading: busyTrust.value || trustCreating.value,
          tip: row.trustEnabled ? undefined : '该策略信任名单已关闭：加入后暂不生效，启用后自动生效',
          run: () => { void joinSpecificList(list, props.ip.trim(), '信任') },
        })
      }
    } else {
      acts.push({
        key: 'trust-hint',
        label: '该策略未关联信任地址列表——请到「安全防护 → 安全策略」编辑该策略并添加信任列表后操作',
        type: 'info',
      })
    }
  }
  if (row.canRemove) {
    acts.push({ key: 'rm-inline', label: `从内联${row.policy.ip_acl_mode === 'allow' ? '白' : '黑'}名单移除`, type: 'danger', loading: isBusy(pid, 'remove'), run: () => { void removeFromAcl(row.policy) } })
  }
  for (const m of row.removableRefLists) {
    acts.push({ key: `rm-${m.id}`, label: `从「${m.name}」移除`, type: 'danger', loading: isBusy(pid, `remove-ref-${m.id}`), run: () => { void removeFromSideRef(m, props.ip.trim()) } })
  }
  const aclOffTip = row.policy.ip_acl_enabled === false ? '该策略 IP 访问控制未启用：加入后暂不拦截，启用后生效' : undefined
  if (row.canAssociate) {
    const denyLists = resolveSideLists(row.policy, 'deny')
    if (denyLists.length > 0) {
      for (const list of denyLists) {
        acts.push({
          key: `assoc-${list.id}`,
          label: `拦截此 IP（加入「${list.name}」）`,
          type: 'danger',
          loading: isBusy(pid, `associate-${list.id}`),
          tip: aclOffTip,
          run: () => {
            if (!lockBusy(pid, `associate-${list.id}`)) return
            void joinSpecificList(list, props.ip.trim(), '拦截').finally(() => unlockBusy(pid, `associate-${list.id}`))
          },
        })
      }
    } else {
      acts.push({
        key: 'deny-hint',
        label: '该策略未关联黑名单地址列表——请到「安全防护 → 安全策略」编辑该策略并添加黑名单列表后操作',
        type: 'info',
      })
    }
  }
  if (row.canAssociateAllow) {
    const allowLists = resolveSideLists(row.policy, 'allow')
    if (allowLists.length > 0) {
      for (const list of allowLists) {
        acts.push({
          key: `assoc-a-${list.id}`,
          label: `放行此 IP（加入「${list.name}」）`,
          type: 'primary',
          loading: isBusy(pid, `associate-a-${list.id}`),
          tip: aclOffTip,
          run: () => {
            if (!lockBusy(pid, `associate-a-${list.id}`)) return
            void joinSpecificList(list, props.ip.trim(), '放行').finally(() => unlockBusy(pid, `associate-a-${list.id}`))
          },
        })
      }
    } else {
      acts.push({
        key: 'allow-hint',
        label: '该策略未关联白名单地址列表——请到「安全防护 → 安全策略」编辑该策略并添加白名单列表后操作',
        type: 'info',
      })
    }
  }
  if (granularTrustRemove) for (const m of row.removableTrustRefLists) {
    acts.push({ key: `unt-${m.id}`, label: `从「${m.name}」移除信任`, type: 'success', run: () => { void removeFromSideRef(m, props.ip.trim()) } })
  }
  if (granularTrustRemove && row.canRemoveTrust) {
    acts.push({ key: 'unt-in', label: '从内联信任移除', type: 'success', loading: isBusy(pid, 'untrust'), run: () => { void removeTrust(row.policy) } })
  }
  if (trustAllowed && row.canClearDeadTrust) {
    acts.push({ key: 'dead', label: '清除条目', type: 'success', tip: '该 IP 的信任条目存在但信任名单已关闭，可一键清除', loading: isBusy(pid, 'untrust'), run: () => { void removeTrust(row.policy) } })
  }
  return acts
}

// —— U8-2 四组分组：阶段 1（ACL）/ 阶段 0（信任）/ 混合（兼容）/ 阶段 2·3 不涉 IP 管控 ——

type IpGroupKey = 'stage0' | 'stage1' | 'mixed'
interface IpRowGroup { key: IpGroupKey; title: string; rows: RowView[] }

const groupedRows = computed(() => {
  const stage1: RowView[] = []
  const stage0: RowView[] = []
  const mixed: RowView[] = []
  let offstage = 0
  for (const row of rows.value) {
    switch (policyTypeOf(row.policy)) {
      case 'stage1': stage1.push(row); break
      case 'stage0': stage0.push(row); break
      case 'stage2': case 'stage3': offstage++; break
      default: mixed.push(row)
    }
  }
  return { stage1, stage0, mixed, offstage }
})

// 展示顺序（用户裁定）：阶段 1 → 阶段 0 → 混合（兼容）；空组不出标题
const visibleGroups = computed<IpRowGroup[]>(() => {
  const g = groupedRows.value
  const out: IpRowGroup[] = []
  if (g.stage1.length > 0) out.push({ key: 'stage1', title: '阶段 1 · IP 访问控制', rows: g.stage1 })
  if (g.stage0.length > 0) out.push({ key: 'stage0', title: '阶段 0 · 信任名单', rows: g.stage0 })
  if (g.mixed.length > 0) out.push({ key: 'mixed', title: '混合（兼容）', rows: g.mixed })
  return out
})

// —— 动作执行 ——

const isBusy = (id: number, kind: string): boolean => busyKeys.value.has(`${id}:${kind}`)

const lockBusy = (id: number, kind: string): boolean => {
  const key = `${id}:${kind}`
  if (busyKeys.value.has(key)) return false
  busyKeys.value = new Set(busyKeys.value).add(key)
  return true
}

const unlockBusy = (id: number, kind: string): void => {
  const next = new Set(busyKeys.value)
  next.delete(`${id}:${kind}`)
  busyKeys.value = next
}

const fetchDetail = async (id: number): Promise<PolicyRow | null> => {
  const res = await request.get<APIResponse<{ policy: PolicyDetail }>>(`/security/policies/${id}`)
  const d = res.data?.policy
  return d ? normalizeRow({ ...d, ip_blacklist: d.ip_blacklist || '[]' }) : null
}

// 写入成功后拉取最新详情，弹窗内状态即时翻转（✅/⚠️）。
// 详情接口不携带列表摘要标志（has_rate_limit 等）——按字段合并而非整行替换，
// 避免刷新后分组路由字段退化
const refreshRow = async (id: number): Promise<void> => {
  try {
    const fresh = await fetchDetail(id)
    if (fresh) {
      // 第 61 轮 P2-5：详情接口不携带摘要标志——直接 spread 会用 undefined 覆写
      // 列表摘要值使分组路由退化；逐字段只合并非 undefined
      policies.value = policies.value.map((x) => {
        if (x.id !== fresh.id) return x
        const merged = { ...x } as Record<string, unknown>
        for (const [k, v] of Object.entries(fresh as unknown as Record<string, unknown>)) {
          if (v !== undefined) merged[k] = v
        }
        return merged as typeof x
      })
    }
  } catch {
    // 刷新失败保持现有展示，下次打开弹窗会重新加载
  }
}


// 统一入口：黑/白名单均写 ip_acl_list + ip_acl_mode（局部更新，仅发送变更字段）
const removeFromAcl = async (policy: PolicyRow): Promise<void> => {
  if (!lockBusy(policy.id, 'remove')) return
  try {
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const list = parseIPList(detail.ip_acl_list)
    if (!list.includes(props.ip)) {
      ElMessage.info(`该 IP 已不在策略「${policy.name}」的访问控制列表中`)
      return
    }
    const mode = detail.ip_acl_mode
    const listLabel = mode === 'allow' ? '白名单' : '黑名单'  // 与按钮/标签同词（原「拒绝列表」口径不一）
    let tip: string
    if (!detail.ip_acl_enabled) {
      tip = 'IP 访问控制当前未启用，仅清理列表条目。'
    } else if (mode === 'allow') {
      tip = `当前为白名单模式，移除后 ${props.ip} 将不在允许名单中、无法访问。`
    } else {
      tip = `移除后 ${props.ip} 将恢复正常访问。`
    }
    try {
      await ElMessageBox.confirm(
        `将把 ${props.ip} 从策略「${policy.name}」的${listLabel}中移除，${tip}是否继续？`,
        '移除 IP',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: mode === 'allow' && detail.ip_acl_enabled ? 'warning' : 'info' },
      )
    } catch {
      return
    }
    const res = await request.put(`/security/policies/${policy.id}`, { ip_acl_list: JSON.stringify(list.filter((entry) => entry !== props.ip)) })
    showSaveResult(res as unknown as { message?: string }, `已从策略「${policy.name}」的${listLabel}移除 ${props.ip}`)
    await refreshRow(policy.id)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    unlockBusy(policy.id, 'remove')
  }
}

// 移除/清除信任条目：PUT 同款 ip_whitelist 去条目（U8-7 一键清除同路径，仅内联——
// 引用列表命中的条目本组件不可清）。死条目（信任开关关闭）与生效条目共用入口，
// 确认文案按开关状态分支
const removeTrust = async (policy: PolicyRow): Promise<void> => {
  if (!lockBusy(policy.id, 'untrust')) return
  try {
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const list = parseIPList(detail.ip_whitelist)
    if (!list.includes(props.ip)) {
      ElMessage.info(`该 IP 已不在策略「${policy.name}」的信任名单中`)
      return
    }
    const trustEnabled = detail.ip_whitelist_enabled !== false
    try {
      await ElMessageBox.confirm(
        trustEnabled
          ? `将把 ${props.ip} 从策略「${policy.name}」的信任名单移除，该 IP 将恢复常规评估。是否继续？`
          : `策略「${policy.name}」的信任名单当前为关闭状态，该条目暂不生效；将把 ${props.ip} 从信任名单条目中清除。是否继续？`,
        trustEnabled ? '移除信任' : '清除未生效条目',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: trustEnabled ? 'warning' : 'info' },
      )
    } catch {
      return
    }
    const res = await request.put(`/security/policies/${policy.id}`, { ip_whitelist: JSON.stringify(list.filter((entry) => entry !== props.ip)) })
    showSaveResult(res as unknown as { message?: string }, `已从策略「${policy.name}」的信任名单移除 ${props.ip}`)
    await refreshRow(policy.id)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    unlockBusy(policy.id, 'untrust')
  }
}
</script>

<style scoped>
.ip-cell { display: inline-flex; align-items: center; gap: 4px; max-width: 100%; vertical-align: middle; }
.ip-clickable { cursor: pointer; border-radius: 3px; padding: 1px 3px; margin: -1px -3px; transition: background 0.15s, color 0.15s; }
.ip-clickable:hover { background: var(--el-color-primary-light-9, #ecf5ff); }
.ip-clickable:hover .ip-text { color: var(--el-color-primary, #409eff); }
.ip-clickable:active { background: var(--el-color-primary-light-8, #d9ecff); }
.ip-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ip-loc { font-size: 11px; color: var(--text-secondary, #909399); white-space: nowrap; max-width: 72px; overflow: hidden; text-overflow: ellipsis; flex-shrink: 1; }
</style>

<style>
.ip-location-popper { padding: 12px 14px; }
/* 头部：IP 大字等宽 + 事件徽标 + 归属地行 */
.ip-location-popper .ipo-head { margin-bottom: 10px; }
.ip-location-popper .ipo-ip-row { display: flex; align-items: center; gap: 8px; }
.ip-location-popper .ipo-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 15px; font-weight: 700; letter-spacing: .3px; }
.ip-location-popper .ipo-loc-line { font-size: 12px; color: var(--text-secondary, #909399); margin-top: 3px; }
/* 分区：标题 + 卡片流 */
.ip-location-popper .ipo-sec { margin-top: 12px; }
.ip-location-popper .ipo-sec-title { font-size: 12px; font-weight: 600; color: var(--el-text-color-regular, #606266); padding-bottom: 6px; border-bottom: 1px solid var(--el-border-color-lighter, #ebeef5); margin-bottom: 8px; }
/* 快速处置：存入一行 + 新建一行 */
/* 策略生效卡 */
.ip-location-popper .ipo-card { border: 1px solid var(--el-border-color-lighter, #ebeef5); border-radius: 8px; padding: 8px 10px; margin-top: 8px; background: var(--el-fill-color-blank, #fff); }
.ip-location-popper .ipo-card-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.ip-location-popper .ipo-name { min-width: 0; font-size: 13px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ip-location-popper .ipo-card-meta { display: flex; align-items: center; gap: 6px; flex-shrink: 0; }
.ip-location-popper .ipo-count { font-size: 11px; color: var(--text-secondary, #909399); font-variant-numeric: tabular-nums; }
.ip-location-popper .ipo-mode-line { font-size: 11px; color: var(--text-secondary, #909399); margin-top: 4px; }
.ip-location-popper .ipo-status { font-size: 12px; color: var(--text-secondary, #909399); margin-top: 6px; }
.ip-location-popper .ipo-status.is-ok { color: var(--el-color-success, #67c23a); }
.ip-location-popper .ipo-status.is-warn { color: var(--el-color-warning, #e6a23c); }
.ip-location-popper .ipo-legacy { font-size: 11px; color: var(--el-color-warning, #e6a23c); margin-top: 4px; }
/* 动作区：语义配色按钮流 */
.ip-location-popper .ipo-acts { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.ip-location-popper .ipo-acts .el-button { margin-left: 0; }
.ip-location-popper .ipo-act-hint { font-size: 11px; color: var(--el-text-color-secondary); flex-basis: 100%; }
.ip-location-popper .ipo-tip { font-size: 12px; color: var(--text-secondary, #909399); padding: 4px 0; }
</style>
