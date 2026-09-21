<template>
  <el-popover v-if="canManage" :width="400" trigger="click" popper-class="ip-location-popper" @show="onPopoverShow">
    <template #reference>
      <span class="ip-cell ip-clickable" :title="location ? `${ip} · ${location}` : ip">
        <span class="ip-text">{{ ip }}</span>
        <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
      </span>
    </template>

    <div class="ipo-header">
      <span class="ipo-ip">{{ ip }}</span>
      <!-- 事件数标签位于原归属地位置(用户裁定 2026-09-13);30 天窗口,索引 COUNT,弹框打开才查 -->
      <el-tag v-if="eventCount !== null" size="small" :type="eventCount > 0 ? 'warning' : 'success'" effect="plain">
        30天事件 {{ eventCount }}
      </el-tag>
    </div>
    <!-- 详细归属地换行到 IP 下方(不与 IP 同行) -->
    <div v-if="location" class="ipo-loc-line">{{ location }}</div>

    <div class="ipo-list-row">
      <span class="ipo-list-label">存入地址列表</span>
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
        :disabled="ipLists.length === 0 || selectedListId === undefined"
        :loading="savingToList"
        @click="saveToListAction"
      >存入</el-button>
      <span v-if="ipLists.length === 0" class="ipo-list-empty">暂无列表，可在 规则集→IP 地址列表 创建</span>
    </div>

    <div v-if="policiesLoading" class="ipo-tip">策略加载中…</div>
    <el-alert v-else-if="policiesError" type="error" :closable="false" title="策略列表加载失败" />
    <template v-else-if="rows.length > 0">
      <!-- U8-2 分组④：阶段 2/3（限流/WAF）不渲染操作行，顶部汇总一行 -->
      <div v-if="groupedRows.offstage > 0" class="ipo-tip">另有 {{ groupedRows.offstage }} 条限流/WAF 策略不涉及 IP 管控</div>
      <template v-if="visibleGroups.length > 0">
        <div class="ipo-tip">各策略当前 IP 名单状态，按管辖阶段分组：</div>
        <div v-for="group in visibleGroups" :key="group.key" class="ipo-group">
          <div class="ipo-group-title">{{ group.title }}</div>
          <div v-for="row in group.rows" :key="row.policy.id" class="ipo-row">
            <div class="ipo-row-head">
              <span class="ipo-name" :title="row.policy.name">{{ row.policy.name }}</span>
              <el-tag size="small" :type="row.tagType">{{ row.tagLabel }}</el-tag>
              <span v-if="row.countLabel" class="ipo-count">{{ row.countLabel }}</span>
            </div>
            <!-- 阶段 0 组行内模式：直通上游 / 保留检测记录（与 buildStage0Rows 同文案） -->
            <div v-if="group.key === 'stage0'" class="ipo-status">{{ row.trustDetectionLabel }}</div>
            <div class="ipo-status" :class="row.statusClass">{{ row.statusLabel }}</div>
            <div v-if="row.inLegacy && group.key !== 'stage0'" class="ipo-legacy">该 IP 还存在于旧版独立黑名单字段中，可经 API 更新策略（ip_blacklist 字段）清理</div>
            <!-- 混合（兼容）组迁移入口提示 -->
            <div v-if="group.key === 'mixed'" class="ipo-legacy">混合策略（兼容旧版）· 仅可更新迁移——到「安全防护 → 安全策略」页对该策略执行「更新迁移」拆分为单职策略</div>
            <div class="ipo-actions">
              <!-- ACL 动作：阶段 1 / 混合组（阶段 0 策略无 ACL 面；stage2/3 不渲染行） -->
              <template v-if="group.key !== 'stage0'">
                <el-button v-if="row.canAddDeny" size="small" type="danger" plain :loading="isBusy(row.policy.id, 'deny')" @click="applyAcl(row.policy, 'deny')">加入黑名单</el-button>
                <el-button v-if="row.canAddAllow" size="small" type="primary" plain :loading="isBusy(row.policy.id, 'allow')" @click="applyAcl(row.policy, 'allow')">加入白名单</el-button>
                <el-button v-if="row.canEnableDeny" size="small" type="danger" plain :loading="isBusy(row.policy.id, 'deny')" @click="applyAcl(row.policy, 'deny')">启用并加入黑名单</el-button>
                <el-button v-if="row.canEnableAllow" size="small" type="primary" plain :loading="isBusy(row.policy.id, 'allow')" @click="applyAcl(row.policy, 'allow')">启用并加入白名单</el-button>
                <el-button v-if="row.canRemove" size="small" plain :loading="isBusy(row.policy.id, 'remove')" @click="removeFromAcl(row.policy)">移除</el-button>
              </template>
              <!-- 信任动作：阶段 0 / 混合组（stage1/2/3 组不出现信任操作）。
                   U8-7：死条目（信任开关关闭）灰显「未生效」+一键清除，不再出禁用按钮 -->
              <template v-if="group.key !== 'stage1'">
                <el-tooltip v-if="row.trustDead" content="该 IP 的信任条目存在，但策略的信任名单已关闭（未启用）——条目暂不生效" placement="top">
                  <el-tag size="small" type="info" effect="plain">未生效</el-tag>
                </el-tooltip>
                <el-button v-if="row.canAddTrust" size="small" type="warning" plain :loading="isBusy(row.policy.id, 'trust')" @click="addTrust(row.policy)">加入信任名单</el-button>
                <el-button v-if="row.canRemoveTrust" size="small" plain :loading="isBusy(row.policy.id, 'untrust')" @click="removeTrust(row.policy)">移除信任</el-button>
                <el-button v-if="row.canClearDeadTrust" size="small" plain :loading="isBusy(row.policy.id, 'untrust')" @click="removeTrust(row.policy)">清除条目</el-button>
              </template>
            </div>
          </div>
        </div>
      </template>
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
import type { IpListOption } from '@/composables/useIpListAdd'
// 分组类型路由（U8-2）：inferPolicyType 为策略类型单一实现（securityStages 导出，禁第二实现）
import { inferPolicyType } from '@/utils/securityStages'
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

// 黑/白名单统一写入 ip_acl_list，目标仅由模式决定；信任名单独立走 ip_whitelist
type AclTarget = 'deny' | 'allow'
type BusyKind = AclTarget | 'remove' | 'trust' | 'untrust'

const ACL_LABELS: Record<AclTarget, string> = { deny: '黑名单', allow: '白名单' }

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

// 引用列表条目缓存：/security/ip-lists 响应本身携带 entries，选项下拉与
// 「内联 ∪ 引用」合并口径共用同一次拉取，避免为 refs 引入第二次请求
interface IpListWithEntries extends IpListOption {
  entries?: Array<{ value: string; remark?: string }>
}
const ipListEntries = ref<Record<number, string[]>>({})

const loadIpLists = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<IpListWithEntries[]>>('/security/ip-lists')
    const lists = res.data || []
    ipLists.value = lists
    const map: Record<number, string[]> = {}
    for (const l of lists) {
      map[l.id] = (l.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
    }
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

const saveToListAction = async (): Promise<void> => {
  if (selectedListId.value === undefined || savingToList.value) return
  const list = ipLists.value.find((l) => l.id === selectedListId.value)
  if (!list) return
  const done = await addIpToList(props.ip, list, { verb: '存入', successText: `已存入列表「${list.name}」` })
  if (done) await loadIpLists()
}

const parseList = (raw: string): string[] => {
  try {
    const parsed: unknown = JSON.parse(raw || '[]')
    if (!Array.isArray(parsed)) return []
    return parsed.filter((entry): entry is string => typeof entry === 'string')
  } catch {
    return []
  }
}

// refs 字段为 JSON 数字数组文本（如 "[1,5]"）——与 SecurityPolicies 向导同口径
// 解析（parseRefIds）：字符串过滤会丢弃数字 id，这里显式 map(Number)
const parseRefIds = (raw: string | undefined): number[] => {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.map(Number).filter((n) => Number.isInteger(n) && n > 0)
  } catch {
    return []
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
  mergeIpEntries(parseList(policy.ip_acl_list), parseRefIds(policy.ip_acl_list_refs))

const mergedTrustEntries = (policy: PolicyRow): string[] =>
  mergeIpEntries(parseList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs))

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
  const listsPromise = loadIpLists()
  policiesLoading.value = true
  try {
    const url = props.ruleCaddyId
      ? `/security/policies?enabled=true&rule_caddy_id=${encodeURIComponent(props.ruleCaddyId)}`
      : '/security/policies?enabled=true'
    const [res] = await Promise.all([request.get<APIResponse<PolicyRow[]>>(url), listsPromise])
    if (seq !== loadPoliciesSeq) return
    policies.value = (res.data || []).map(normalizeRow)
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
  tagType: 'danger' | 'success' | 'info'
  tagLabel: string
  statusClass: 'is-ok' | 'is-warn' | ''
  statusLabel: string
  countLabel: string
  canAddDeny: boolean
  canAddAllow: boolean
  canEnableDeny: boolean
  canEnableAllow: boolean
  canRemove: boolean
}

const rowView = (policy: PolicyRow): RowView => {
  // 信任口径（内联 ∪ 引用）先行计算——阶段 0 行整行语义即信任，ACL 行也要渲染信任动作
  const trustEntries = mergedTrustEntries(policy)
  const view: RowView = {
    policy,
    inTrust: trustEntries.includes(props.ip),
    inTrustInline: parseList(policy.ip_whitelist).includes(props.ip),
    trustEnabled: policy.ip_whitelist_enabled !== false,
    trustCount: trustEntries.length,
    // 与 securityStages.buildStage0Rows 模式行同文案
    trustDetectionLabel: policy.trust_detection === true ? '保留检测记录（事件动作=检测）' : '直通上游（不产生安全事件）',
    trustDead: false,
    canAddTrust: false,
    canRemoveTrust: false,
    canClearDeadTrust: false,
    inLegacy: parseList(policy.ip_blacklist).includes(props.ip),
    tagType: 'info',
    tagLabel: '未启用',
    statusClass: '',
    statusLabel: 'IP ACL 未启用',
    countLabel: '',
    canAddDeny: false,
    canAddAllow: false,
    canEnableDeny: false,
    canEnableAllow: false,
    canRemove: false,
  }
  view.canAddTrust = !view.inTrust
  view.canRemoveTrust = view.inTrust && view.trustEnabled && view.inTrustInline
  view.trustDead = view.inTrust && !view.trustEnabled
  view.canClearDeadTrust = view.trustDead && view.inTrustInline

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

  if (!policy.ip_acl_enabled) {
    // 阶段 1/混合行 ACL 未启用 → 「启用并加入」动作（原逻辑）
    view.canEnableDeny = true
    view.canEnableAllow = true
    return view
  }

  // 生效名单 = 内联 ∪ 引用列表条目；引用命中的条目无法在本弹窗移除
  // （PUT 仅写内联 ip_acl_list），移除按钮仅对内联命中开放
  const list = mergedAclEntries(policy)
  const inInline = parseList(policy.ip_acl_list).includes(props.ip)
  const inList = list.includes(props.ip)

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
      view.canAddDeny = true
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
      view.canAddAllow = true
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

const isBusy = (id: number, kind: BusyKind): boolean => busyKeys.value.has(`${id}:${kind}`)

const lockBusy = (id: number, kind: BusyKind): boolean => {
  const key = `${id}:${kind}`
  if (busyKeys.value.has(key)) return false
  busyKeys.value = new Set(busyKeys.value).add(key)
  return true
}

const unlockBusy = (id: number, kind: BusyKind): void => {
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

const modeLabel = (mode: string): string =>
  mode === 'deny' ? '黑名单模式' : mode === 'allow' ? '白名单模式' : mode === 'bypass' ? '免检测模式' : `「${mode}」模式`

// 统一入口：黑/白名单均写 ip_acl_list + ip_acl_mode（局部更新，仅发送变更字段）
const applyAcl = async (policy: PolicyRow, target: AclTarget): Promise<void> => {
  if (!lockBusy(policy.id, target)) return
  try {
    // 先取最新详情，避免用弹窗快照覆盖他人并发修改
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const list = parseList(detail.ip_acl_list)
    // 语义反转守卫按生效名单（内联 ∪ 引用）判定——内联为空但引用非空时，
    // 切换模式同样会反转全部引用条目的语义，必须走强确认分支
    const mergedList = mergeIpEntries(list, parseRefIds(detail.ip_acl_list_refs))

    let body: Record<string, unknown>
    let successMsg: string

    if (!detail.ip_acl_enabled) {
      // 未启用 → 启用 + 设定模式 + 加入：启用访问控制是行为变更，与其他动作
      // 同口径先经确认框说明后果；模式与目标一致时保留既有条目，不一致则清空
      // 重建，避免启用即语义反转
      try {
        await ElMessageBox.confirm(
          `将启用策略「${policy.name}」的 IP 访问控制并设为${modeLabel(target)}（${ACL_LABELS[target]}），同时加入 ${props.ip}。是否继续？`,
          `启用并加入${ACL_LABELS[target]}`,
          { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
        )
      } catch {
        return
      }
      const nextList = detail.ip_acl_mode === target
        ? [...list.filter((entry) => entry !== props.ip), props.ip]
        : [props.ip]
      body = { ip_acl_enabled: true, ip_acl_mode: target, ip_acl_list: JSON.stringify(nextList) }
      successMsg = `已启用策略「${policy.name}」的 IP 访问控制并加入${ACL_LABELS[target]}`
    } else if (detail.ip_acl_mode === target) {
      // 模式一致 → 确认后追加；命中判定用生效名单口径，避免把引用列表
      // 已覆盖的 IP 重复写入内联条目
      if (mergedList.includes(props.ip)) {
        ElMessage.info(`该 IP 已在策略「${policy.name}」的${ACL_LABELS[target]}中`)
        return
      }
      try {
        await ElMessageBox.confirm(
          `将把 ${props.ip} 加入策略「${policy.name}」的${ACL_LABELS[target]}。是否继续？`,
          `加入${ACL_LABELS[target]}`,
          { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
        )
      } catch {
        return
      }
      body = { ip_acl_list: JSON.stringify([...list, props.ip]) }
      successMsg = `已加入策略「${policy.name}」的${ACL_LABELS[target]}`
    } else if (mergedList.length > 0) {
      // 模式切换且生效名单已有条目（K3 语义反转守卫，内联 ∪ 引用口径）：原条目
      // 语义将整体反转，必须经确认框说明后果；确认后仅清空内联条目、仅保留该 IP——
      // 引用列表条目随引用保留（本组件不写 refs），但其语义随模式一并反转，须点名
      const refOnlyCount = mergedList.filter((v) => !list.includes(v)).length
      const countDesc = refOnlyCount > 0
        ? `生效名单共 ${mergedList.length} 条 IP（内联 ${list.length} 条 + 引用列表 ${refOnlyCount} 条）`
        : `列表中已有 ${list.length} 条 IP`
      const refSurviveTip = refOnlyCount > 0
        ? `引用列表的 ${refOnlyCount} 条会随引用保留、但语义随模式一并反转；`
        : ''
      const targetTip = target === 'allow'
        ? `加入白名单会把访问控制切换为「仅允许名单内 IP」，原条目语义将反转，内联条目将被清空、仅保留 ${props.ip}；${refSurviveTip}其余所有 IP 将无法访问。`
        : `加入黑名单会把访问控制切换为「拒绝名单内 IP」，原条目语义将反转，内联条目将被清空、仅保留 ${props.ip}（该 IP 将被直接拦截）；${refSurviveTip}`
      try {
        await ElMessageBox.confirm(
          `策略「${policy.name}」当前为${modeLabel(detail.ip_acl_mode)}，${countDesc}。${targetTip}是否继续？`,
          '切换访问控制模式',
          { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
        )
      } catch {
        return
      }
      body = { ip_acl_mode: target, ip_acl_list: JSON.stringify([props.ip]) }
      successMsg = `已切换为${ACL_LABELS[target]}模式并加入 ${props.ip}`
    } else {
      // 模式不同但列表为空：无数据可反转，但仍属模式切换，与其他动作同口径确认
      try {
        await ElMessageBox.confirm(
          `策略「${policy.name}」的访问控制将从${modeLabel(detail.ip_acl_mode)}切换为${modeLabel(target)}，并加入 ${props.ip}。是否继续？`,
          '切换访问控制模式',
          { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
        )
      } catch {
        return
      }
      body = { ip_acl_mode: target, ip_acl_list: JSON.stringify([props.ip]) }
      successMsg = `已切换为${ACL_LABELS[target]}模式并加入 ${props.ip}`
    }

    const res = await request.put(`/security/policies/${policy.id}`, body)
    showSaveResult(res as unknown as { message?: string }, successMsg)
    await refreshRow(policy.id)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    unlockBusy(policy.id, target)
  }
}

const removeFromAcl = async (policy: PolicyRow): Promise<void> => {
  if (!lockBusy(policy.id, 'remove')) return
  try {
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const list = parseList(detail.ip_acl_list)
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

const addTrust = async (policy: PolicyRow): Promise<void> => {
  if (!lockBusy(policy.id, 'trust')) return
  try {
    try {
      await ElMessageBox.confirm(
        `将把 ${props.ip} 加入策略「${policy.name}」的信任名单，该 IP 将全评估不拦截，检测事件全记录（限流仍然生效；信任仅豁免所属策略——其他策略引用同一信任地址列表即可）。是否继续？`,
        '加入信任名单',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
      )
    } catch {
      return
    }
    const detail = await fetchDetail(policy.id)
    if (!detail) return
    const list = parseList(detail.ip_whitelist)
    if (list.includes(props.ip)) {
      ElMessage.info(`该 IP 已在策略「${policy.name}」的信任名单中`)
      return
    }
    // 审计 W-S2（第六轮）：信任开关关闭时明确告知零生效——成功 toast 不再误导
    const trustEnabled = detail.ip_whitelist_enabled !== false
    const res = await request.put(`/security/policies/${policy.id}`, { ip_whitelist: JSON.stringify([...list, props.ip]) })
    if (trustEnabled) {
      showSaveResult(res as unknown as { message?: string }, `已加入策略「${policy.name}」的信任名单`)
    } else {
      showSaveResult(res as unknown as { message?: string }, `已加入策略「${policy.name}」的信任名单——注意：该策略的信任名单当前为关闭状态，此 IP 暂不生效（需在策略向导中开启信任名单）`)
    }
    await refreshRow(policy.id)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    unlockBusy(policy.id, 'trust')
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
    const list = parseList(detail.ip_whitelist)
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
.ip-location-popper .ipo-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 8px; }
.ip-location-popper .ipo-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; }
.ip-location-popper .ipo-loc-line { font-size: 12px; color: var(--text-secondary, #909399); margin: -4px 0 8px; }
.ip-location-popper .ipo-list-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding-bottom: 8px; margin-bottom: 4px; border-bottom: 1px solid var(--el-border-color-lighter, #ebeef5); }
.ip-location-popper .ipo-list-label { font-size: 12px; color: var(--text-secondary, #909399); white-space: nowrap; }
.ip-location-popper .ipo-list-select { width: 168px; }
.ip-location-popper .ipo-list-empty { font-size: 12px; color: var(--text-secondary, #909399); }
.ip-location-popper .ipo-tip { font-size: 12px; color: var(--text-secondary, #909399); padding: 4px 0; }
.ip-location-popper .ipo-group { margin-top: 2px; }
.ip-location-popper .ipo-group-title { font-size: 12px; font-weight: 600; color: var(--el-text-color-regular, #606266); margin: 6px 0 0; }
.ip-location-popper .ipo-row { padding: 8px 0; border-top: 1px solid var(--el-border-color-lighter, #ebeef5); }
.ip-location-popper .ipo-row-head { display: flex; align-items: center; gap: 6px; }
.ip-location-popper .ipo-name { flex: 1; min-width: 0; font-size: 13px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ip-location-popper .ipo-count { font-size: 11px; color: var(--text-secondary, #909399); white-space: nowrap; }
.ip-location-popper .ipo-status { font-size: 12px; color: var(--text-secondary, #909399); margin: 4px 0 6px; }
.ip-location-popper .ipo-status.is-ok { color: var(--el-color-success, #67c23a); }
.ip-location-popper .ipo-status.is-warn { color: var(--el-color-warning, #e6a23c); }
.ip-location-popper .ipo-legacy { font-size: 11px; color: var(--el-color-warning, #e6a23c); margin: -2px 0 6px; }
.ip-location-popper .ipo-actions { display: flex; flex-wrap: wrap; gap: 0; }
.ip-location-popper .ipo-actions .el-button + .el-button { margin-left: 8px; }
</style>
