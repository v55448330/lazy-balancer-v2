<template>
  <el-popover v-if="canManage" :width="400" trigger="click" popper-class="ip-location-popper" @before-enter="onPopoverShow">
    <template #reference>
      <span class="ip-cell ip-clickable" :title="location ? `${ip} · ${location}` : ip">
        <span class="ip-text">{{ ip }}</span>
        <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
      </span>
    </template>

    <div class="ipo-head">
      <div class="ipo-ip-row">
        <span class="ipo-ip">{{ ip }}</span>
        <el-tag v-if="eventCount !== null" size="small" :type="eventCount > 0 ? 'warning' : 'success'" effect="plain" round>
          30天事件 {{ eventCount }}
        </el-tag>
      </div>
      <div v-if="location" class="ipo-loc-line">{{ location }}</div>
    </div>

    <div class="ipo-sec">
      <div class="ipo-sec-title">存入地址列表</div>
      <div class="ipo-save-row">
        <el-select
          v-model="selectedListId"
          filterable
          clearable
          :teleported="false"
          placeholder="选择列表"
          size="small"
          class="ipo-list-select"
        >
          <el-option v-for="list in ipLists" :key="list.id" :label="ipListOptionLabel(list)" :value="list.id" />
        </el-select>
        <el-button
          size="small"
          type="primary"
          plain
          :disabled="selectedListId === undefined || savingToList"
          :loading="savingToList"
          @click="saveToListAction"
        >存入</el-button>
      </div>
      <div class="ipo-save-new">
        <el-input
          v-model="newListName"
          size="small"
          placeholder="新建列表名"
          :disabled="creatingList"
          @keyup.enter="createListInline"
        >
          <template #append><el-button size="small" :loading="creatingList" @click="createListInline">新建</el-button></template>
        </el-input>
      </div>
    </div>

    <div v-if="policiesLoading" class="ipo-tip">策略加载中…</div>
    <el-alert v-else-if="policiesError" type="error" :closable="false" title="策略列表加载失败" />
    <template v-else-if="rows.length > 0">
      <div v-if="groupedRows.offstage > 0" class="ipo-tip">另有 {{ groupedRows.offstage }} 条限流/WAF 策略不涉及 IP 管控</div>
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
          <div v-if="row.inLegacy && group.key !== 'stage0'" class="ipo-legacy">该 IP 还存在于旧版独立黑名单字段，可经 API 更新策略（ip_blacklist）清理</div>
          <div v-if="group.key === 'mixed'" class="ipo-legacy">混合策略（兼容旧版）· 仅可更新迁移——到「安全防护 → 安全策略」页对该策略执行「更新迁移」拆分为单职策略</div>
          <div v-if="row.trustDead" class="ipo-legacy">该 IP 的信任条目存在，但策略的信任名单已关闭——条目暂不生效</div>
          <div v-if="rowActions(row).length > 0" class="ipo-acts">
            <template v-for="act in rowActions(row)" :key="act.key">
              <el-tooltip v-if="act.tip" :content="act.tip" placement="top">
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
import { ipListOptionLabel, useIpListAdd } from '@/composables/useIpListAdd'
import { useTrustAssociation } from '@/composables/useTrustAssociation'
import type { IpListOption } from '@/composables/useIpListAdd'
// 分组类型路由（U8-2）：inferPolicyType 为策略类型单一实现（securityStages 导出，禁第二实现）
import { inferPolicyType, parseIPList, parseRefIds } from '@/utils/securityStages'
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

// —— 信任直接动作（第 58 轮统一模型）：与触发详情弹框共享实现。
// 信任此 IP 不再依赖顶部列表选择：策略已有信任用途列表→直接加入；
// 没有→自动创建「{策略名}-信任」并关联+加入。
const trustApi = useTrustAssociation({
  getList: () => ipLists.value,
  onChanged: () => loadPolicies(),
})
const { busyTrust, creating: trustCreating, resolveTrustList, joinTrust, removeFromTrustRef } = trustApi

const policies = ref<PolicyRow[]>([])
const policiesLoading = ref(false)
const policiesError = ref(false)
const busyKeys = ref<Set<string>>(new Set())

// —— 显式存入地址列表：与策略名单动作同口径（确认弹框 + 全局 MFA 428 守卫 +
// 明确反馈），不再作为名单写入后的隐式自动追加；确认/幂等 POST/反馈复用
// useIpListAdd 共享实现（与 SecurityEvents 事件弹框「加入列表」同一链路） ——
const ipLists = ref<IpListOption[]>([])
const selectedListId = ref<number | undefined>(undefined)
const { adding: savingToList, addIpToList } = useIpListAdd()

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
  // 列表已在别处删除时清理悬空选择，避免静默写往不存在的列表
  if (selectedListId.value !== undefined && !ipLists.value.some((l) => l.id === selectedListId.value)) {
    selectedListId.value = undefined
  }
}


const topListSelected = computed(() => selectedListId.value !== undefined)
const selectedListName = computed(() => ipLists.value.find((l) => l.id === selectedListId.value)?.name ?? '')

const newListName = ref('')
const creatingList = ref(false)
const createListInline = async (): Promise<void> => {
  const name = newListName.value.trim()
  if (name === '' || creatingList.value) return
  creatingList.value = true
  try {
    const res = await request.post<APIResponse<{ id: number }>>('/security/ip-lists', { name, entries: '[]' })
    const newId = (res.data as unknown as { id: number } | undefined)?.id
    if (newId) {
      await loadIpLists()
      selectedListId.value = newId
      newListName.value = ''
      ElMessage.success(`已创建列表「${name}」，可存入 IP 并关联到策略`)
    }
  } finally {
    creatingList.value = false
  }
}

// 关联所选列表到策略对应用途的引用字段，并存入此 IP（第 57 轮统一模型）
const associateListAndAdd = async (policy: PolicyRow): Promise<void> => {
  if (selectedListId.value === undefined || !lockBusy(policy.id, 'associate')) return
  try {
    const kind: 'deny' | 'allow' = policy.ip_acl_mode === 'allow' ? 'allow' : 'deny'
    const kindLabel = kind === 'allow' ? '白名单' : '黑名单'
    const refField = kind === 'allow' ? 'ip_whitelist_refs' : 'ip_acl_list_refs'
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const refs = parseRefIds(detail[refField as 'ip_acl_list_refs' | 'ip_whitelist_refs'])
    if (refs.includes(selectedListId.value)) {
      ElMessage.info(`列表已关联到策略「${policy.name}」`)
      return
    }
    await ElMessageBox.confirm(
      `将把地址列表「${selectedListName.value}」关联到策略「${policy.name}」的${kindLabel}，并加入 ${props.ip}。是否继续？`,
      '关联地址列表',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
    )
    const res = await request.put(`/security/policies/${policy.id}`, { [refField]: JSON.stringify([...refs, selectedListId.value]) })
    showSaveResult(res as unknown as { message?: string }, `已关联并加入 ${props.ip}`)
    await addIpToRefList(selectedListId.value)
    await refreshRow(policy.id)
  } finally {
    unlockBusy(policy.id, 'associate')
  }
}

// 从引用列表移除单条 IP（POST remove-ip，幂等）并刷新策略行状态
const removeFromRefList = async (policy: PolicyRow, list: { id: number; name: string }): Promise<void> => {
  if (!lockBusy(policy.id, 'remove-ref-' + list.id)) return
  try {
    await ElMessageBox.confirm(
      `将从地址列表「${list.name}」移除 ${props.ip}。该列表可能被多条策略引用，移除全局生效。是否继续？`,
      '从地址列表移除',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
    )
    await request.post(`/security/ip-lists/${list.id}/remove-ip`, { value: props.ip })
    ElMessage.success(`已从「${list.name}」移除`)
    const next = { ...ipListEntries.value, [list.id]: (ipListEntries.value[list.id] ?? []).filter((v) => v !== props.ip.trim()) }
    ipListEntries.value = next
    await refreshRow(policy.id)
  } finally {
    unlockBusy(policy.id, 'remove-ref-' + list.id)
  }
}

const addIpToRefList = async (listId: number): Promise<void> => {
  try {
    await request.post(`/security/ip-lists/${listId}/ips`, { value: props.ip })
    const next = { ...ipListEntries.value, [listId]: [...(ipListEntries.value[listId] ?? []), props.ip.trim()] }
    ipListEntries.value = next
  } catch { /* 全局拦截器已提示 */ }
}

const saveToListAction = async (): Promise<void> => {
  if (selectedListId.value === undefined || savingToList.value) return
  const list = ipLists.value.find((l) => l.id === selectedListId.value)
  if (!list) return
  const done = await addIpToList(props.ip, list, { verb: '存入', successText: `已存入列表「${list.name}」` })
  if (done) {
    // 条目缓存写回：会话内缓存后新存 IP 必须即时反映在成员判定上
    const merged = new Set([...(ipListEntries.value[list.id] ?? []), props.ip.trim()])
    ipListEntries.value = { ...ipListEntries.value, [list.id]: [...merged] }
    await loadIpLists()
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
  geoActive: boolean
  geoRegions: string
}

const rowView = (policy: PolicyRow): RowView => {
  // 信任口径（内联 ∪ 引用）先行计算——阶段 0 行整行语义即信任，ACL 行也要渲染信任动作
  const trustEntries = mergedTrustEntries(policy)
  const view: RowView = {
    policy,
    inTrust: trustEntries.includes(props.ip),
    inTrustInline: parseIPList(policy.ip_whitelist).includes(props.ip),
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
    removableTrustRefLists: [] as Array<{ id: number; name: string }>,
    geoActive: false,
    geoRegions: '',
  }
  view.canAddTrust = !view.inTrust
  view.canRemoveTrust = view.inTrust && view.trustEnabled && view.inTrustInline
  view.trustDead = view.inTrust && !view.trustEnabled
  view.canClearDeadTrust = view.trustDead && view.inTrustInline

  // 信任引用命中（全类型行）：信任 refs 中包含此 IP 的非系统列表 → 可移除。
  // 条目来源 = ipListEntries 缓存（loadPolicies 拉取 acl+whitelist 全部 refs）。
  const trustRefIds = parseRefIds(policy.ip_whitelist_refs)
  view.removableTrustRefLists = ipLists.value
    .filter((l) => trustRefIds.includes(l.id) && !l.system)
    .filter((l) => (ipListEntries.value[l.id] ?? []).includes(props.ip.trim()))
    .map((l) => ({ id: l.id, name: l.name }))

  // 阶段 0 行（U8-2 分组②）：信任名单状态即整行语义，无 ACL 面；
  // 模式行（直通/保留检测）由模板按组渲染
  if (policyTypeOf(policy) === 'stage0') {
    view.tagType = view.trustEnabled ? 'success' : 'info'
    view.tagLabel = view.trustEnabled ? '信任启用' : '信任停用'
    view.countLabel = view.trustCount > 0 ? `${view.trustCount} 条` : ''
    if (view.inTrust) {
      view.statusClass = view.trustEnabled ? 'is-ok' : 'is-warn'
      const hit = view.inTrustInline ? '✅ 已在信任名单中' : '✅ 已在信任名单中（来自引用列表）'
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
  const geoActive = (policy.geoip_enabled ?? false) && regionCount > 0
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
  // （PUT 仅写内联 ip_acl_list），移除按钮仅对内联命中开放
  const list = mergedAclEntries(policy)
  const inInline = parseIPList(policy.ip_acl_list).includes(props.ip)
  const inList = list.includes(props.ip)

  view.removableRefLists = ipLists.value
    .filter((l) => !l.system && parseRefIds(policy.ip_acl_list_refs).includes(l.id))
    .filter((l) => (ipListEntries.value[l.id] ?? []).includes(props.ip.trim()))
    .map((l) => ({ id: l.id, name: l.name }))
  if (policy.ip_acl_mode === 'deny') {
    view.tagType = 'danger'
    view.tagLabel = '黑名单'
    view.countLabel = `${list.length} 条`
    if (inList) {
      view.statusClass = 'is-ok'
      view.statusLabel = inInline ? '✅ 已在黑名单中' : '✅ 已在黑名单中（来自引用列表）'
      view.canRemove = inInline
    } else {
      view.statusLabel = `拒绝列表 · ${list.length} 条`
      view.canAssociate = true
    }
  } else if (policy.ip_acl_mode === 'allow') {
    view.tagType = 'success'
    view.tagLabel = '白名单'
    view.countLabel = `${list.length} 条`
    if (inList) {
      view.statusClass = 'is-ok'
      view.statusLabel = inInline ? '✅ 已在白名单中' : '✅ 已在白名单中（来自引用列表）'
      view.canRemove = inInline
    } else {
      view.statusClass = 'is-warn'
      view.statusLabel = '⚠️ 不在白名单中（当前无法访问）'
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

const rows = computed<RowView[]>(() => policies.value.map(rowView))

// 行内上下文动作（第 58 轮交互重构）：按行状态只出现该出现的动作。
// 顺序 = 信任（绿）→ 黑名单移除（红）→ 关联拦截/放行（红/蓝）→ 信任移除（绿）。
interface RowAction { key: string; label: string; type: 'primary' | 'success' | 'warning' | 'danger' | 'info'; loading?: boolean; tip?: string; run: () => void }
const rowActions = (row: RowView): RowAction[] => {
  const acts: RowAction[] = []
  const pid = row.policy.id
  if (row.canAddTrust) {
    const list = resolveTrustList(row.policy)
    acts.push({
      key: 'trust',
      label: list ? `信任此 IP（加入「${list.name}」）` : `信任此 IP（创建「${row.policy.name}-信任」）`,
      type: 'success',
      loading: busyTrust.value || trustCreating.value,
      tip: row.trustEnabled ? undefined : '该策略信任名单已关闭：加入后暂不生效，启用后自动生效',
      run: () => { void joinTrust(row.policy, props.ip.trim()) },
    })
  }
  if (row.canRemove) {
    acts.push({ key: 'rm-inline', label: '从内联黑名单移除', type: 'danger', loading: isBusy(pid, 'remove'), run: () => { void removeFromAcl(row.policy) } })
  }
  for (const m of row.removableRefLists) {
    acts.push({ key: `rm-${m.id}`, label: `从「${m.name}」移除`, type: 'danger', loading: isBusy(pid, `remove-ref-${m.id}`), run: () => { void removeFromRefList(row.policy, m) } })
  }
  if (row.canAssociate && topListSelected.value) {
    acts.push({ key: 'assoc', label: `关联「${selectedListName.value}」并拦截此 IP`, type: 'danger', loading: isBusy(pid, 'associate'), run: () => { void associateListAndAdd(row.policy) } })
  }
  if (row.canAssociateAllow && topListSelected.value) {
    acts.push({ key: 'assoc-a', label: `关联「${selectedListName.value}」并加入白名单`, type: 'primary', loading: isBusy(pid, 'associate-allow'), run: () => { void associateListAndAdd(row.policy) } })
  }
  for (const m of row.removableTrustRefLists) {
    acts.push({ key: `unt-${m.id}`, label: `从「${m.name}」移除信任`, type: 'success', run: () => { void removeFromTrustRef(m, props.ip.trim()) } })
  }
  if (row.canRemoveTrust) {
    acts.push({ key: 'unt-in', label: '从内联信任移除', type: 'success', loading: isBusy(pid, 'untrust'), run: () => { void removeTrust(row.policy) } })
  }
  if (row.canClearDeadTrust) {
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
    if (fresh) policies.value = policies.value.map((p) => (p.id === fresh.id ? { ...p, ...fresh } : p))
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
    const listLabel = mode === 'allow' ? '白名单' : '拒绝列表'
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
.ip-location-popper .ipo-save-row { display: flex; align-items: center; gap: 8px; }
.ip-location-popper .ipo-list-select { flex: 1; min-width: 0; }
.ip-location-popper .ipo-save-new { display: flex; margin-top: 8px; }
.ip-location-popper .ipo-save-new .el-input { flex: 1; }
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
</style>
