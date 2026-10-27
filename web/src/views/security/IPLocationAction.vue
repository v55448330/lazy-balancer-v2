<template>
  <el-popover v-if="canManage" :width="400" trigger="click" popper-class="ip-location-popper" :popper-options="popperViewportSafe" @before-enter="onPopoverShow">
    <template #reference>
      <span
        class="ip-cell ip-clickable"
        role="button"
        tabindex="0"
        :aria-label="`IP 处置：${ip}`"
        :title="location ? `${ip} · ${location}` : ip"
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

    <!-- 策略筛选（用户裁定）：有 IP 管控面且未被隐藏的策略数 >1 才出；
         选择后仅渲染该策略卡片，会话级记忆上次选择；加载中禁用（与 seq 守卫/
         加载态兼容）。teleported="false" 把下拉面板留在弹层内——teleport 到
         body 后的面板点击会被 el-popover 判为 outside 而关闭整个弹框（实测 bug） -->
    <div v-if="filterablePolicies.length > 1" class="ipo-filter">
      <el-select v-model="lastPolicyFilter" size="small" :disabled="policiesLoading" placeholder="筛选策略" :teleported="false" fit-input-width>
        <el-option label="全部策略" value="all" />
        <el-option v-for="p in filterablePolicies" :key="p.id" :label="p.name" :value="p.id" />
      </el-select>
    </div>

    <div v-if="policiesLoading" class="ipo-tip">策略加载中…</div>
    <div v-else-if="policiesError" class="info-note-bar"><span class="info-note-desc">策略列表加载失败</span></div>
    <div v-else-if="!hasInterceptPolicy" class="info-note-bar">
      <span class="info-note-desc">尚未创建 IP 访问控制（黑名单）策略；请先到「安全防护 → 安全策略」创建并绑定到规则，再使用快捷拦截。</span>
    </div>
    <template v-else-if="rows.length > 0">
      <!-- 名单/引用条目加载失败：命中判定退化为仅内联（「已在名单」会被误显示为未命中），
           依据不可靠——处置动作禁用，横幅给出重试 -->
      <div v-if="listsError" class="info-note-bar">
        <span class="info-note-desc">地址列表加载失败：引用名单的命中状态不可见，处置动作已暂停</span>
        <el-button size="small" type="primary" plain :loading="policiesLoading" @click="retryLists">重新加载</el-button>
      </div>
      <div v-if="groupedRows.offstage > 0" class="ipo-tip">另有 {{ groupedRows.offstage }} 条限流/WAF 策略不涉及 IP 管控</div>
      <!-- 阶段 0 空态（用户裁定：提示创建，不自动代建）。判定基于全部
           策略（不受下方筛选影响）——绑定存在但被筛掉时不出该引导 -->
      <div v-if="!stage0BoundAny && rows.length > 0" class="ipo-sec">
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
          <!-- 区域+列表组合（枚举补全）：ACL 评估之外地域拦截同样在链上，
               名单未命中不代表放行（区域命中仍拦）——卡片显式列出区域维度 -->
          <div v-if="row.geoActive && group.key !== 'stage0'" class="ipo-mode-line">另启用地域拦截 · {{ row.policy.geoip_mode === 'allow' ? '仅允许' : '拦截' }}区域：{{ row.geoRegions }}</div>
          <div v-if="row.inLegacy && group.key !== 'stage0'" class="ipo-legacy">该 IP 还存在于旧版独立黑名单字段，可经 API 更新策略（ip_blacklist）清理</div>
          <div v-if="group.key === 'mixed'" class="ipo-legacy">混合策略（兼容旧版）· 仅可更新迁移——到「安全防护 → 安全策略」页对该策略执行「更新迁移」拆分为单职策略</div>
          <div v-if="row.trustDead" class="ipo-legacy">该 IP 的信任条目存在，但策略的信任名单已关闭——条目暂不生效</div>
          <div v-if="rowActions(row).length > 0" class="ipo-acts">
            <template v-for="act in rowActions(row)" :key="act.key">
              <el-tooltip v-if="act.tip" :content="act.tip" placement="top">
                <el-button size="small" :type="act.type" plain :loading="act.loading" :disabled="act.disabled" @click="act.run()">{{ act.label }}</el-button>
              </el-tooltip>
              <el-button v-else size="small" :type="act.type" plain :loading="act.loading" :disabled="act.disabled" @click="act.run()">{{ act.label }}</el-button>
            </template>
          </div>
        </div>
      </div>
    </template>
    <!-- 全部策略被系统名单接管（裁定①隐藏）时如实说明，不误报「暂无策略」 -->
    <div v-else-if="policies.length > 0 && hasAclPolicy" class="ipo-tip">启用策略的 IP 名单均由系统内置名单管理，本弹窗无快捷处置入口</div>
  </el-popover>

  <span v-else class="ip-cell" :title="location ? `${ip} · ${location}` : ip">
    <span class="ip-text">{{ ip }}</span>
    <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
  </span>
</template>

<script lang="ts">
// 独立 <script> 块 = 模块作用域；ref 别名导入避免与 setup 块的 vue 导入重名
import { ref as moduleRef } from 'vue'

// 策略筛选会话级记忆（用户裁定）：模块级 ref——弹层多次开关/跨入口
// （安全日志/安全总览/观察建议）间保留上次选择，不落库；选中策略被删除时由
// loadPolicies 复位为「全部策略」。
const lastPolicyFilter = moduleRef<number | 'all'>('all')
</script>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { useAuthStore } from '@/stores/auth'
import { useTrustAssociation } from '@/composables/useTrustAssociation'
import { useCountryNamesCn, countryLabel } from '@/composables/useCountryNamesCn'
import type { IpListOption } from '@/composables/useIpListAdd'
// 分组类型路由：inferPolicyType 为策略类型单一实现（securityStages 导出，禁第二实现）
import { aclAssociateSides, inferPolicyType, parseIPList, parseRefIds, entryMatchesIp, invalidateSharedEntriesCache, ensureSharedEntriesMissing, sharedEntriesCache, subscribeSharedEntriesCache, mergeIpEntryValues, trustHitMode } from '@/utils/securityStages'
import { popperViewportSafe } from '@/utils/popper'
import type { SecurityPolicyType, SecurityPolicyTypeInput } from '@/utils/securityStages'
import { planTrustRemoval, classifyTrustRemovalVerification } from '@/utils/trustRemoval'
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
  // 信任三态开关——加入名单前须提示「当前关闭=零生效」
  ip_whitelist_enabled?: boolean
  // 分组路由字段：policy_type 由列表/详情接口携带；'' 为存量待推断态。
  // 摘要标志仅列表摘要携带（详情接口无）——refreshRow 以合并方式保留
  policy_type?: string
  trust_detection?: boolean
  mode?: string
  rate_limit_enabled?: boolean
  // X5：geoip_enabled 死字段删除——后端零下发，
  // 启用判定唯一口径 geoip_mode !== 'off'。
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

// client_ip 可能带首尾空白（导入/带外数据）。parseIPList 内部已 trim，
// 而移除/legacy 判定曾用未 trim 的原始 props.ip——状态显示「已信任/已拦截」却在
// 移除时提示「已不在名单」或过滤不生效。全流程统一读本 computed。
const trimmedIp = computed(() => props.ip.trim())

// 紧凑归属地：国内只显市/海外显国家（2026-10-13 用户裁定确认，覆盖 2026-09-13
// 「海外恒显海外」旧裁定——GeoIP 海外国家细化配套）/保留地址原样，弹窗/悬浮
// 显示完整
const compactLocation = computed(() => {
  if (!props.location) return ''
  const parts = props.location.split('·').map(s => s.trim()).filter(Boolean)
  if (parts[0] === '保留地址') return '保留地址'
  if (parts[0] !== '中国') return parts[0]
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
    const res = await request.get<APIResponse<{ count: number }>>('/security/events/count', { params: { ip: trimmedIp.value, days: 30 }, silent: true })
    if (seq === eventCountSeq) eventCount.value = res.data?.count ?? 0
  } catch {
    if (seq === eventCountSeq) eventCount.value = null
  }
}

const onPopoverShow = (): void => {
  // 先清空计数：el-table 刷新数据时单元格实例按索引复用，props.ip 可能已换，
  // 不清空会在新 IP 上先显示上一行 IP 的「30 天事件」数（亚秒级但会误导）。
  eventCount.value = null
  void loadPolicies()
  void loadEventCount()
}

// —— 信任直接动作（统一模型）：与触发详情弹框共享实现。
// 信任此 IP 不再依赖顶部列表选择：策略已有信任用途列表→直接加入；
// 没有→自动创建「{策略名}-信任」并关联+加入。
const trustApi = useTrustAssociation({
  getList: () => ipLists.value,
  // 历史验收：写入后必须清条目缓存——loadIpLists 只拉缓存缺失 ID
  // 优化），已缓存列表的新增条目不可见导致「拦截此 IP」按钮在加入后仍显示
  onChanged: () => {
    // 写入后失效共享缓存（含 TriggerDetailDialog 订阅方），再按需重拉
    invalidateSharedEntriesCache()
    return loadPolicies()
  },
})
const { busyTrust, creating: trustCreating, resolveSideLists, joinSpecificList, ensureListAndJoin, removeFromSideRef } = trustApi

const policies = ref<PolicyRow[]>([])
const policiesLoading = ref(false)
const policiesError = ref(false)
// 地址列表/引用条目加载失败态：失败时 rowView 的 inList/inTrust 只剩内联口径，
// 引用名单命中会被误显示为「未命中」（与真实未命中无法区分）——必须显性暴露
// 并提供重试，同时禁用处置动作（依据不可靠时不得写入）。
const listsError = ref(false)
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
// 与 TriggerDetailDialog 共用模块级缓存：原为组件内 ref，
// 每事件行一个实例 → 同一 IP 弹层多次打开/多行弹层各自整批下载条目。
const ipListEntries = ref<Record<number, string[]>>({ ...sharedEntriesCache })
// 「取消信任」决策前刷新条目期间抑制缓存中间态回写本地副本：ensure 对过期 id
// 先静默删除、再逐个回填，每次回填都会通知一次——若中间态照抄进显示，其余仍在
// 拉取的名单会瞬时显示成「未在该名单」（空态闪烁）。刷新由调用方在结束时整体
// 替换副本，故中间态一律跳过。
let entriesRefreshInFlight = false
let unregisterEntriesCache: (() => void) | null = null
onMounted(() => {
  unregisterEntriesCache = subscribeSharedEntriesCache(() => {
    if (entriesRefreshInFlight) return
    ipListEntries.value = { ...sharedEntriesCache }
  })
})
onUnmounted(() => {
  unregisterEntriesCache?.()
  unregisterEntriesCache = null
})

// 单名单条目加载器：loadIpLists 的按需拉取与「取消信任」的决策前强制刷新共用
// 同一实现（两处各写一份会在请求形态/归一规则变化时漂移）。
const loadListEntries = async (id: number): Promise<string[]> => {
  const res = await request.get<APIResponse<{ id: number; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`)
  return (res.data?.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
}

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
    // 仅拉取共享缓存缺失的名单 id：跨组件/跨实例共享，
    // 写入动作经 invalidate 清空后自动重拉；成员判定保持即时正确
    const missing = await ensureSharedEntriesMissing(refIds, loadListEntries)
    ipListEntries.value = { ...sharedEntriesCache }
    // 单名单失败保持「未缓存」且过期缓存按缺失计（securityStages 契约：下次可
    // 重试）——引用条目缺失即成员判定不完整，与列表接口失败同口径暴露。
    listsError.value = missing.length > 0
  } catch {
    // 单弹层加载失败不清全局共享缓存：其它组件可能仍持有有效条目；
    // 下次 ensureSharedEntries 会按名单 ID 自行重拉。
    ipLists.value = []
    listsError.value = true
  }
}







// 生效名单 = 内联 ∪ 引用列表条目（精确字符串去重，与向导同口径）；缓存中缺失的
// 引用列表跳过（防御性回退为仅内联）。内核统一在 utils/securityStages
// mergeIpEntryValues，本处仅适配 ipListEntries 数据源成形。
const mergeIpEntries = (inline: string[], refs: number[]): string[] =>
  mergeIpEntryValues(inline, refs.map((id) => ipListEntries.value[id] ?? []))

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
  geoip_mode: p.geoip_mode || 'off', // F63 修复字段被本投影白名单遗漏(geoActive 恒 false 回归);X5:geoip_enabled 死字段随行删除
  geoip_countries: p.geoip_countries || '[]',
  has_geoip: p.has_geoip,
  has_rate_limit: p.has_rate_limit,
  has_waf: p.has_waf,
  has_custom_rules: p.has_custom_rules,
})

// 分组类型路由：有效 policy_type 交由 inferPolicyType 单一实现直通
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
  // seq 守卫——弹层快速关开产生并发 GET 时,
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
    // 策略筛选：选中策略已不在下拉池（被删/停用/refs 转为全系统
    // 名单/纯 WAF 限流）→ 复位「全部」，避免筛选视图渲染空卡片流。
    // 置于 loadIpLists 之后——「refs 全系统名单」判定依赖本轮名单 system 标记
    if (lastPolicyFilter.value !== 'all' && !filterablePolicies.value.some((p) => p.id === lastPolicyFilter.value)) {
      lastPolicyFilter.value = 'all'
    }
    policiesError.value = false
  } catch {
    if (seq !== loadPoliciesSeq) return
    policiesError.value = true
  } finally {
    if (seq === loadPoliciesSeq) policiesLoading.value = false
  }
}

// 加载失败横幅的重试入口：名单与条目同轮重取（loadPolicies 内串接 loadIpLists）
const retryLists = (): void => { void loadPolicies() }

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

// 海外国家中文映射（模块级缓存，regions API 单源；setup 期
// 触发一次拉取，rows computed 内读 .value 注册响应依赖）。
const countryZh = useCountryNamesCn()

// 收敛：rowView 原三处「全策略×全条目」扫描在 rows
// computed 内逐行重算（O(策略²×条目)，每次开弹层全量重跑）——提升为共享
// computed：本 IP 是否被任一策略信任 + 命中本 IP 的非系统引用名单集合，
// rowView 内退化为布尔读取/Set 查询（O(策略×条目) 一次）。
const trustHitSummary = computed(() => {
  const ip = trimmedIp.value
  let trusted = false
  let detectionOwner: PolicyRow | undefined
  let passthroughOwner: PolicyRow | undefined
  for (const policy of policies.value) {
    if (!mergedTrustEntries(policy).some((entry) => entryMatchesIp(entry, ip))) continue
    if (!policy.ip_whitelist_enabled) continue
    trusted = true
    // 语义单源：非阶段 0 存量信任引擎恒 DetectionOnly（与 trust_detection 无关）
    if (trustHitMode(policy.policy_type, policy.trust_detection) === 'detection') detectionOwner ??= policy
    else passthroughOwner ??= policy
  }
  return { trusted, detectionOwner, passthroughOwner }
})
const ipTrustedAnywhere = computed(() => trustHitSummary.value.trusted)
const ipHitListIds = computed(() => {
  const hit = new Set<number>()
  for (const l of ipLists.value) {
    if (l.system) continue
    if ((ipListEntries.value[l.id] ?? []).some((e) => entryMatchesIp(e, trimmedIp.value))) hit.add(l.id)
  }
  return hit
})
// remove-ip 只删除精确 value；CIDR 覆盖命中仅用于状态展示，不产生移除按钮。
const ipExactListIds = computed(() => {
  const hit = new Set<number>()
  const ip = trimmedIp.value
  for (const l of ipLists.value) {
    if (l.system) continue
    if ((ipListEntries.value[l.id] ?? []).includes(ip)) hit.add(l.id)
  }
  return hit
})

// 可移除的信任引用列表（本 IP 在其中恰有精确条目、且非系统名单）——键为给定
// refs，而不是弹层挂载时的策略快照：取消信任的决策与写回都必须用最新 refs。
const trustListsForRefs = (refIds: readonly number[]): Array<{ id: number; name: string }> =>
  ipLists.value
    .filter((l) => refIds.includes(l.id) && ipExactListIds.value.has(l.id))
    .map((l) => ({ id: l.id, name: l.name }))

const rowView = (policy: PolicyRow): RowView => {
  // 信任口径（内联 ∪ 引用）先行计算——阶段 0 行整行语义即信任，ACL 行也要渲染信任动作。
  // 信任成员判定与 ACL 侧同为 CIDR 感知（entryMatchesIp）——内联/引用
  // 信任名单的 CIDR 条目在引擎侧本就豁免该 IP，精确串匹配会漏报「已信任」状态；
  // 移除动作仍收窄为精确条目（inTrustInlineExact，与 ACL 侧同口径——CIDR
  // 覆盖的 IP 无法由 PUT 精确剔除）
  const trustEntries = mergedTrustEntries(policy)
  const trustInlineEntries = parseIPList(policy.ip_whitelist)
  const inTrustInlineExact = trustInlineEntries.includes(trimmedIp.value)
  const view: RowView = {
    policy,
    inTrust: trustEntries.some((e) => entryMatchesIp(e, trimmedIp.value)),
    inTrustInline: trustInlineEntries.some((e) => entryMatchesIp(e, trimmedIp.value)),
    inTrustInlineExact,
    trustEnabled: policy.ip_whitelist_enabled !== false,
    trustCount: trustEntries.length,
    // 与 securityStages.buildStage0Rows 模式行同文案（按策略类型单源）
    trustDetectionLabel: trustHitMode(policy.policy_type, policy.trust_detection) === 'detection' ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）',
    trustDead: false,
    canAddTrust: false,
    canClearDeadTrust: false,
    inLegacy: parseIPList(policy.ip_blacklist).includes(trimmedIp.value),
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
  // 历史验收复查：信任豁免为全局生效（预检 DetectionOnly 事务级）——IP 已被
  // 任一策略信任时，「信任此 IP」按钮冗余（再加只是重复豁免，且会使策略类型
  // 内容漂移），不再显示；主动作归「取消信任」（豁免方策略卡上）。
  const isStage0OrMixed = policyTypeOf(policy) === 'stage0' || policyTypeOf(policy) === 'mixed'
  view.canAddTrust = isStage0OrMixed && !view.inTrust
    && !ipTrustedAnywhere.value
  view.trustDead = view.inTrust && !view.trustEnabled
  view.canClearDeadTrust = view.trustDead && view.inTrustInlineExact
  // 信任引用命中（全类型行）：信任 refs 中包含此 IP 的非系统列表 → 可移除。
  // 条目来源 = ipListEntries 缓存（loadPolicies 拉取 acl+whitelist 全部 refs）；
  // 命中判定走共享 ipHitListIds。
  const trustRefIds = parseRefIds(policy.ip_whitelist_refs)
  view.removableTrustRefLists = trustListsForRefs(trustRefIds)
  // ACL 引用命中（补）：黑/白名单状态行标注具体来源名单名
  const aclRefIds = parseRefIds(policy.ip_acl_list_refs)
  const aclHitNames = ipLists.value
    .filter((l) => aclRefIds.includes(l.id) && ipHitListIds.value.has(l.id))
    .map((l) => l.name)
  const trustHitNames = ipLists.value
    .filter((l) => trustRefIds.includes(l.id) && ipHitListIds.value.has(l.id))
    .map((l) => l.name)
  const srcTag = (names: string[]): string =>
    names.length > 0 ? `（来自引用列表「${names.join('」「')}」）` : '（来自引用列表）'
  view.aclHitSourceLabel = srcTag(aclHitNames)
  view.trustHitSourceLabel = srcTag(trustHitNames)

  // 阶段 0 行：信任名单状态即整行语义，无 ACL 面；
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

  // 地域拦截维度（GeoIP 策略不再误标「未启用」——明确展示地域维度）
  const regions = parseIPList(policy.geoip_countries)
  const regionCount = regions.length
  // geoip_enabled 死字段已删（X5）——启用判定唯一口径
  // geoip_mode !== 'off'（后端实际下发）
  const geoActive = (policy.geoip_mode ?? 'off') !== 'off' && regionCount > 0
  view.geoActive = geoActive
  // 区域清单展示层翻译——country_names_cn 单源映射（useCountryNamesCn
  // 模块级缓存），未命中（省份/省市联值/海外哨兵/新国名）回退原文；geoip_countries
  // 值本身零改动。
  const zh = countryZh.value
  view.geoRegions = regionCount > 0 ? regions.map((r) => countryLabel(zh, r)).join('、') : ''
  if (!policy.ip_acl_enabled) {
    // ACL 未启用：如地域拦截在用则明示「地域拦截在用（本事件可来自地域）」；
    // 关联地址列表动作仍可用（条目落库后随 ACL 启用生效），且启用/未启用两态
    // 动作门控一致。黑白共用 ip_acl_list_refs，动作必须按当前 ip_acl_mode
    // 门控——同时给「拦截」「放行」会把条目写进同一字段，ACL 启用后按模式
    // 生效，用户意图被反转。
    const sides = aclAssociateSides(policy.ip_acl_mode)
    view.canAssociate = sides.deny
    view.canAssociateAllow = sides.allow
    // 模式如实展示：动作集合被模式门控（绕过/空模式不给动作），用户需要
    // 知道当前生效语义，才不会把「放行/拦截」理解成对两种模式都成立。
    const modeLabel = policy.ip_acl_mode === 'deny' ? ' · 黑名单模式'
      : policy.ip_acl_mode === 'allow' ? ' · 白名单模式'
        : policy.ip_acl_mode === '绕过' ? ' · 免检测模式'
          : ' · 模式未配置'
    if (geoActive) {
      view.tagType = 'warning'
      view.tagLabel = '地域拦截'
      view.statusLabel = `地域拦截已启用 · 拦截区域：${view.geoRegions}（IP ACL 未启用${modeLabel}）`
    } else if (sides.deny || sides.allow) {
      // 动作在场时状态行带模式，指明条目会写入哪一侧；无动作（绕过/空模式）
      // 保持默认「IP ACL 未启用」文案
      view.statusLabel = `IP ACL 未启用${modeLabel}`
    }
    return view
  }

  // 生效名单 = 内联 ∪ 引用列表条目；引用命中的条目无法在本弹窗移除
  // （PUT 仅写内联 ip_acl_list）。展示口径 CIDR 感知（内联
  // CIDR 条目命中实际 IP）；移除动作收窄为精确条目（inInlineExact）——
  // 内联 CIDR 覆盖的 IP 无法由 PUT 精确剔除（剔除整条 CIDR 会波及其他 IP），
  // 不再亮「移除」，状态行改标「来自内联 CIDR」引导到策略编辑。
  const list = mergedAclEntries(policy)
  const aclInlineEntries = parseIPList(policy.ip_acl_list)
  const inInlineExact = aclInlineEntries.includes(trimmedIp.value)
  const inInline = aclInlineEntries.some((e) => entryMatchesIp(e, trimmedIp.value))
  const inList = list.some((e) => entryMatchesIp(e, trimmedIp.value))

  view.removableRefLists = ipLists.value
    .filter((l) => !l.system && parseRefIds(policy.ip_acl_list_refs).includes(l.id))
    .filter((l) => ipExactListIds.value.has(l.id))
    .map((l) => ({ id: l.id, name: l.name }))
  // 信任豁免组合态（组合语义复查）：预检信任 DetectionOnly 是事务级
  // 全局——但后缀只对「实际命中」形态有意义（deny 命中 / allow 交集外被 id:7
  // 拒），未命中本来就不拦、allow 名单内本来合法放行，挂后缀反而误导；同时
  // 点名豁免策略（跨策略时用户需要知道去哪取消）。
  const { detectionOwner: td1Owner, passthroughOwner: td0Owner } = trustHitSummary.value
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
  } else if (policy.ip_acl_mode === '绕过') {
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
  const ip = trimmedIp.value
  // 对齐：信任生效仅由本弹窗不可移除的条目（内联 CIDR 覆盖 / 系统名单精确
  // 条目）提供时，「取消信任」是空操作——不再弹确认框走流程后谎报成功，直接
  // 指引到对应编辑面。
  // 处置计划单源（utils/trustRemoval）——可移除条目（内联精确 +
  // 命中引用列表精确条目）与不可移除的残余 CIDR 信任一次算清。原实现仅在
  // 「无内联精确条目」时守卫；IP 同时由内联精确条目与引用 CIDR 信任时跳过
  // 守卫，移除后仍持续信任却弹「已取消信任 / 恢复拦截」的谎报。
  // 安全结论不得读陈旧快照：弹层可长开，期间他人/另一标签页可能新增覆盖该 IP
  // 的引用列表或内联 CIDR——挂载时快照既漏判新来源、也不会去移除它们。故决策
  // 前先取最新策略，一切判定（内联/refs/可移除列表/残余来源）都基于它。
  let policy: PolicyRow | null = null
  try {
    policy = await fetchDetail(row.policy.id)
  } catch {
    policy = null
  }
  if (!policy) {
    ElMessage.error('策略最新状态读取失败，无法给出可靠的取消信任结论，请重试')
    unlockBusy(row.policy.id, 'untrust')
    return
  }
  // 引用列表条目按 TTL 强制补齐（仍在 TTL 内即零请求，过期才重拉，不闪空态：
  // 本地副本只在补齐返回后整体替换）。返回补齐失败的 id 清单（空 = 可出结论）；
  // 条目缺失会让残余信任判定漏报，与 listsError 同口径拒绝出结论。
  const refreshTrustEntries = async (refIds: readonly number[]): Promise<readonly number[]> => {
    if (refIds.length === 0) return []
    entriesRefreshInFlight = true
    const missing = await ensureSharedEntriesMissing(refIds, loadListEntries)
      .finally(() => { entriesRefreshInFlight = false })
    ipListEntries.value = { ...sharedEntriesCache }
    return missing
  }
  const trustRefIds = parseRefIds(policy.ip_whitelist_refs)
  const missingTrustIds = await refreshTrustEntries(trustRefIds)
  if (missingTrustIds.length > 0) {
    listsError.value = true
    ElMessage.error('信任名单的最新条目加载失败，无法给出可靠的取消信任结论，请重试')
    unlockBusy(row.policy.id, 'untrust')
    return
  }
  const removableTrustLists = trustListsForRefs(trustRefIds)
  const buildPlan = (target: PolicyRow) => planTrustRemoval({
    ip,
    inlineWhitelist: target.ip_whitelist,
    whitelistRefs: target.ip_whitelist_refs,
    lists: ipLists.value,
    removableListIds: trustListsForRefs(parseRefIds(target.ip_whitelist_refs)).map((m) => m.id),
    listEntries: (id) => ipListEntries.value[id] ?? [],
  })
  const plan = buildPlan(policy)
  const residualTrustSources = plan.residualSources
  const exactRefLists = removableTrustLists.filter((m) => plan.exactRefListIds.includes(m.id))
  const residualNote = residualTrustSources.length > 0
    ? `；该 IP 仍由${residualTrustSources.join('、')}提供信任，需到策略/列表编辑中移除后才恢复拦截`
    : ''
  if (!plan.hasRemovable) {
    if (parseIPList(policy.ip_whitelist).some((e) => entryMatchesIp(e, ip))) {
      ElMessage.info('该 IP 由内联 CIDR 提供信任，请在策略编辑中移除对应条目')
    } else if (parseRefIds(policy.ip_whitelist_refs).some((id) => ipHitListIds.value.has(id))) {
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
        `将把 ${trimmedIp.value} 从策略「${policy.name}」的信任名单可移除条目（内联精确条目与命中引用列表的精确条目）移除${residualNote}。是否继续？`,
        '取消信任',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
      )
    } catch { return }
    // 确认框可长开：写入前再取一次最新策略，避免用决策时的内联快照覆盖期间
    // 他人新增的条目（lost update）。读失败时跳过内联 PUT（旧行为同款），
    // 引用列表的精确条目移除照常进行。
    const latest = await fetchDetail(policy.id).catch(() => null)
    if (latest) {
      const latestInline = parseIPList(latest.ip_whitelist)
      const inline = latestInline.filter((v) => v !== trimmedIp.value)
      if (inline.length !== latestInline.length) {
        await request.put(`/security/policies/${policy.id}`, { ip_whitelist: JSON.stringify(inline) })
      }
    }
    for (const m of exactRefLists) {
      await request.post(`/security/ip-lists/${m.id}/remove-ip`, { value: trimmedIp.value })
    }
    // 结论按写入后的最新策略复算：本轮写入期间并发的编辑也可能引入新的信任
    // 来源，沿用决策时的快照会再次把「仍被信任」报成「已取消信任」。
    const afterWrite = await fetchDetail(policy.id).catch(() => null)
    const afterMissing = afterWrite ? await refreshTrustEntries(parseRefIds(afterWrite.ip_whitelist_refs)) : []
    const afterPlan = afterWrite && afterMissing.length === 0 ? buildPlan(afterWrite) : null
    const verification = classifyTrustRemovalVerification({
      detailLoaded: afterWrite !== null,
      missingListIds: afterMissing,
      residualSources: afterPlan?.residualSources ?? [],
    })
    if (verification === 'unknown') {
      ElMessage.warning('移除请求已提交，但最新信任状态核对失败，请刷新确认')
    } else if (verification === 'residual') {
      ElMessage.warning(`已移除 ${trimmedIp.value} 的可移除信任条目；但该 IP 仍由${(afterPlan?.residualSources ?? []).join('、')}提供信任，拦截尚未恢复`)
    } else {
      mfaAwareSuccess(`已取消 ${trimmedIp.value} 对「${policy.name}」的信任`)
    }
    invalidateSharedEntriesCache()
    await loadPolicies()
  } catch {
    // 失败提示由全局拦截器弹出；部分移除也刷新到实际状态
    invalidateSharedEntriesCache()
    await loadPolicies()
  } finally {
    unlockBusy(row.policy.id, 'untrust')
  }
}

// 历史策略筛选：选中具体策略时仅渲染其卡片（rowView 计算随之收窄）；
// 「全部策略」= 全量。陈旧选中项（策略被删/出下拉池）由 loadPolicies 复位。
// 历史实测裁定①：ACL refs 全部指向系统内置名单（威胁库/自动封禁）的策略
// 卡整体隐藏——IP 管控职能已由系统名单承担，「创建 X-黑名单」是重复入口；
// 无同侧引用（如纯地域策略）保留自动创建出口；引用含用户名单照旧逐列表按钮。
const aclRefsAllSystem = (p: PolicyRow): boolean => {
  const refs = parseRefIds(p.ip_acl_list_refs)
  if (refs.length === 0) return false
  // 内联 ACL 非空时保留卡片：原谓词只看 refs 全 system，
  // 「内联 2 IP + 引用威胁库」的策略被整卡隐藏——用户无法移除内联条目。
  if (parseIPList(p.ip_acl_list ?? '').length > 0) return false
  if (!refs.every((id) => Boolean(ipLists.value.find((l) => l.id === id)?.system))) return false
  // 本 IP 在该策略信任侧（内联 ∪ 引用）仍有命中时不得隐藏：隐藏卡的
  // 「取消信任」入口随之消失，而 ipTrustedAnywhere 又抑制其他卡的信任动作——
  // 该 IP 的豁免将只能去策略页处理（混合策略还是只读面）。信任名单关闭时同样
  // 不得整卡隐藏（隐藏条件=信任侧无命中，与启用态无关）：该形态正是「条目存在
  // 但未生效」提示与「清除条目」动作的唯一入口。
  return !mergedTrustEntries(p).some((e) => entryMatchesIp(e, trimmedIp.value))
}
// 筛选下拉选项池（实测裁定③①）：仅「有 IP 管控面」（stage0/stage1/
// mixed）且未被隐藏的策略；纯 WAF/限流（stage2/3）不入池（底部「另有 N 条」
// 提示语承担其存在感）
// 是否存在可承载“拦截此 IP”的 IP 访问控制策略（阶段 1 或混合兼容）。
// 没有时弹框必须显性提示用户先去建策略/绑定规则——否则用户只会看到
// “暂无数据”，误以为快捷拦截故障。
const hasAclPolicy = computed(() => policies.value.some((p) => {
  const t = policyTypeOf(p)
  return t === 'stage1' || t === 'mixed'
}))
// 白名单/免检测模式没有“拦截此 IP”落点——只有黑名单侧可写才拿出入口提示。
const hasInterceptPolicy = computed(() => policies.value.some((p) => {
  const t = policyTypeOf(p)
  if (t !== 'stage1' && t !== 'mixed') return false
  return aclAssociateSides(p.ip_acl_mode).deny
}))

const filterablePolicies = computed(() => policies.value.filter((p) => {
  const t = policyTypeOf(p)
  return t !== 'stage2' && t !== 'stage3' && !aclRefsAllSystem(p)
}))

const rows = computed<RowView[]>(() => policies.value
  .filter((p) => !aclRefsAllSystem(p))
  .filter((p) => lastPolicyFilter.value === 'all' || p.id === lastPolicyFilter.value)
  .map(rowView))

// 阶段 0 绑定存在性（全量口径，不受筛选影响）——驱动「未绑定信任策略」引导
const stage0BoundAny = computed(() => policies.value.some((p) => policyTypeOf(p) === 'stage0'))

// 行内上下文动作（交互重构）：按行状态只出现该出现的动作。
// 顺序 = 信任（绿）→ 黑名单移除（红）→ 关联拦截/放行（红/蓝）→ 信任移除（绿）。
// 历史裁定：「未关联…」死提示退役——无同侧非系统列表时一律出自动创建
// 动作（run 必备，动作区只渲染可执行动作；无动作→整区不渲染）。
interface RowAction { key: string; label: string; type: 'primary' | 'success' | 'warning' | 'danger' | 'info'; loading?: boolean; disabled?: boolean; tip?: string; run: () => void }


const rowActions = (row: RowView): RowAction[] => {
  const acts: RowAction[] = []
  const pid = row.policy.id
  // 历史用户裁定：信任动作只出现在 stage0/mixed 卡——单职模型下信任归
  // 阶段 0，阶段 1 卡出信任按钮会导致类型内容漂移且语义混乱
  const trustAllowed = policyTypeOf(row.policy) === 'stage0' || policyTypeOf(row.policy) === 'mixed'
  if (trustAllowed && row.inTrust && row.trustEnabled) {
    // 组合语义：信任生效中——唯一动作=取消信任（从全部位置移除）；
    // 逐列表/内联移除按钮在此形态下冗余且有歧义（用户验收裁定）
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
      // 逐列表出按钮（用户验收：多列表绑定时各出一个，不再只取第一个）
      for (const list of trustLists) {
        acts.push({
          key: `trust-${list.id}`,
          label: `信任此 IP（加入「${list.name}」）`,
          type: 'success',
          loading: busyTrust.value || trustCreating.value,
          tip: row.trustEnabled ? undefined : '该策略信任名单已关闭：加入后暂不生效，启用后自动生效',
          run: () => { void joinSpecificList(list, trimmedIp.value, '信任') },
        })
      }
    } else {
      // 历史裁定：无同侧非系统列表时出「自动创建并加入」出口（系统名单零
      // 暴露），不再渲染「未关联」死提示
      acts.push({
        key: 'trust-create',
        label: `信任此 IP（创建「${row.policy.name}-信任」并加入）`,
        type: 'success',
        loading: busyTrust.value || trustCreating.value,
        tip: row.trustEnabled ? undefined : '该策略信任名单已关闭：加入后暂不生效，启用后自动生效',
        run: () => { void ensureListAndJoin(row.policy, trimmedIp.value, 'trust') },
      })
    }
  }
  if (row.canRemove) {
    acts.push({ key: 'rm-inline', label: `从内联${row.policy.ip_acl_mode === 'allow' ? '白' : '黑'}名单移除`, type: 'danger', loading: isBusy(pid, 'remove'), run: () => { void removeFromAcl(row.policy) } })
  }
  for (const m of row.removableRefLists) {
    acts.push({ key: `rm-${m.id}`, label: `从「${m.name}」移除`, type: 'danger', loading: isBusy(pid, `remove-ref-${m.id}`), run: () => { void removeFromSideRef(m, trimmedIp.value) } })
  }
  // 动作文案按模式区分——放行入白名单与拦截入黑名单的「未启用」后果描述
  // 不同（原两者都说「暂不拦截」）。
  const aclOffTip = row.policy.ip_acl_enabled === false
    ? (row.policy.ip_acl_mode === 'allow'
        ? '该策略 IP 访问控制未启用：加入白名单后暂不放行，启用后生效'
        : '该策略 IP 访问控制未启用：加入后暂不拦截，启用后生效')
    : undefined
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
            void joinSpecificList(list, trimmedIp.value, '拦截').finally(() => unlockBusy(pid, `associate-${list.id}`))
          },
        })
      }
    } else {
      acts.push({
        key: 'deny-create',
        label: `拦截此 IP（创建「${row.policy.name}-黑名单」并加入）`,
        type: 'danger',
        loading: isBusy(pid, 'associate-new'),
        tip: aclOffTip,
        run: () => {
          if (!lockBusy(pid, 'associate-new')) return
          void ensureListAndJoin(row.policy, trimmedIp.value, 'deny').finally(() => unlockBusy(pid, 'associate-new'))
        },
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
            void joinSpecificList(list, trimmedIp.value, '放行').finally(() => unlockBusy(pid, `associate-a-${list.id}`))
          },
        })
      }
    } else {
      acts.push({
        key: 'allow-create',
        label: `放行此 IP（创建「${row.policy.name}-白名单」并加入）`,
        type: 'primary',
        loading: isBusy(pid, 'associate-a-new'),
        tip: aclOffTip,
        run: () => {
          if (!lockBusy(pid, 'associate-a-new')) return
          void ensureListAndJoin(row.policy, trimmedIp.value, 'allow').finally(() => unlockBusy(pid, 'associate-a-new'))
        },
      })
    }
  }
  if (granularTrustRemove) for (const m of row.removableTrustRefLists) {
    acts.push({ key: `unt-${m.id}`, label: `从「${m.name}」移除信任`, type: 'success', run: () => { void removeFromSideRef(m, trimmedIp.value) } })
  }
  if (trustAllowed && row.canClearDeadTrust) {
    acts.push({ key: 'dead', label: '清除条目', type: 'success', tip: '该 IP 的信任条目存在但信任名单已关闭，可一键清除', loading: isBusy(pid, 'untrust'), run: () => { void removeTrust(row.policy) } })
  }
  // 名单未就绪（加载失败）时动作依据不可靠（inList/inTrust 只剩内联口径，
  // resolveSideLists 看不到真实列表集）——整区禁用，由横幅的重试恢复。
  return listsError.value ? acts.map((act) => ({ ...act, disabled: true })) : acts
}

// 四组分组：阶段 1（ACL）/ 阶段 0（信任）/ 混合（兼容）/ 阶段 2·3 不涉 IP 管控 ——

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
      // 详情接口不携带摘要标志——直接 spread 会用 undefined 覆写
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
    if (!list.includes(trimmedIp.value)) {
      ElMessage.info(`该 IP 已不在策略「${policy.name}」的访问控制列表中`)
      return
    }
    const mode = detail.ip_acl_mode
    const listLabel = mode === 'allow' ? '白名单' : '黑名单'  // 与按钮/标签同词（原「拒绝列表」口径不一）
    let tip: string
    if (!detail.ip_acl_enabled) {
      tip = 'IP 访问控制当前未启用，仅清理列表条目。'
    } else if (mode === 'allow') {
      tip = `当前为白名单模式，移除后 ${trimmedIp.value} 将不在允许名单中、无法访问。`
    } else {
      tip = `移除后 ${trimmedIp.value} 将恢复正常访问。`
    }
    try {
      await ElMessageBox.confirm(
        `将把 ${trimmedIp.value} 从策略「${policy.name}」的${listLabel}中移除，${tip}是否继续？`,
        '移除 IP',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: mode === 'allow' && detail.ip_acl_enabled ? 'warning' : 'info' },
      )
    } catch {
      return
    }
    const res = await request.put(`/security/policies/${policy.id}`, { ip_acl_list: JSON.stringify(list.filter((entry) => entry !== trimmedIp.value)) })
    showSaveResult(res as unknown as { message?: string }, `已从策略「${policy.name}」的${listLabel}移除 ${trimmedIp.value}`)
    await refreshRow(policy.id)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    unlockBusy(policy.id, 'remove')
  }
}

// 移除/清除信任条目：PUT 同款 ip_whitelist 去条目（一键清除同路径，仅内联——
// 引用列表命中的条目本组件不可清）。死条目（信任开关关闭）与生效条目共用入口，
// 确认文案按开关状态分支
const removeTrust = async (policy: PolicyRow): Promise<void> => {
  if (!lockBusy(policy.id, 'untrust')) return
  try {
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const list = parseIPList(detail.ip_whitelist)
    if (!list.includes(trimmedIp.value)) {
      ElMessage.info(`该 IP 已不在策略「${policy.name}」的信任名单中`)
      return
    }
    const trustEnabled = detail.ip_whitelist_enabled !== false
    try {
      await ElMessageBox.confirm(
        trustEnabled
          ? `将把 ${trimmedIp.value} 从策略「${policy.name}」的信任名单移除，该 IP 将恢复常规评估。是否继续？`
          : `策略「${policy.name}」的信任名单当前为关闭状态，该条目暂不生效；将把 ${trimmedIp.value} 从信任名单条目中清除。是否继续？`,
        trustEnabled ? '移除信任' : '清除未生效条目',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: trustEnabled ? 'warning' : 'info' },
      )
    } catch {
      return
    }
    const res = await request.put(`/security/policies/${policy.id}`, { ip_whitelist: JSON.stringify(list.filter((entry) => entry !== trimmedIp.value)) })
    showSaveResult(res as unknown as { message?: string }, `已从策略「${policy.name}」的信任名单移除 ${trimmedIp.value}`)
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
.ip-location-popper .ipo-tip { font-size: 12px; color: var(--text-secondary, #909399); padding: 4px 0; }
/* 策略筛选：头部通栏下拉，收窄多策略弹框*/
.ip-location-popper .ipo-filter { margin-bottom: 8px; }
.ip-location-popper .ipo-filter .el-select { width: 100%; }
</style>
