<template>
  <el-popover v-if="canManage" :width="400" trigger="click" popper-class="ip-location-popper" @show="loadPolicies">
    <template #reference>
      <span class="ip-cell ip-clickable" :title="location ? `${ip} · ${location}` : ip">
        <span class="ip-text">{{ ip }}</span>
        <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
      </span>
    </template>

    <div class="ipo-header">
      <span class="ipo-ip">{{ ip }}</span>
      <span v-if="location" class="ipo-loc">{{ location }}</span>
    </div>

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
        <el-option v-for="list in ipLists" :key="list.id" :label="`${list.name}（${list.entry_count} 条）`" :value="list.id" />
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
      <div class="ipo-tip">各策略当前 IP 访问控制状态，按需加入名单：</div>
      <div v-for="row in rows" :key="row.policy.id" class="ipo-row">
        <div class="ipo-row-head">
          <span class="ipo-name" :title="row.policy.name">{{ row.policy.name }}</span>
          <el-tag size="small" :type="row.tagType">{{ row.tagLabel }}</el-tag>
          <span v-if="row.countLabel" class="ipo-count">{{ row.countLabel }}</span>
        </div>
        <div class="ipo-status" :class="row.statusClass">{{ row.statusLabel }}</div>
        <div v-if="row.inLegacy" class="ipo-legacy">该 IP 还存在于旧版独立黑名单字段中，可在策略编辑中清理</div>
        <div class="ipo-actions">
          <el-button v-if="row.canAddDeny" size="small" type="danger" plain :loading="isBusy(row.policy.id, 'deny')" @click="applyAcl(row.policy, 'deny')">加入黑名单</el-button>
          <el-button v-if="row.canAddAllow" size="small" type="primary" plain :loading="isBusy(row.policy.id, 'allow')" @click="applyAcl(row.policy, 'allow')">加入白名单</el-button>
          <el-button v-if="row.canEnableDeny" size="small" type="danger" plain :loading="isBusy(row.policy.id, 'deny')" @click="applyAcl(row.policy, 'deny')">启用并加入黑名单</el-button>
          <el-button v-if="row.canEnableAllow" size="small" type="primary" plain :loading="isBusy(row.policy.id, 'allow')" @click="applyAcl(row.policy, 'allow')">启用并加入白名单</el-button>
          <el-button v-if="row.canRemove" size="small" plain :loading="isBusy(row.policy.id, 'remove')" @click="removeFromAcl(row.policy)">移除</el-button>
          <el-button size="small" type="warning" plain :disabled="row.inTrust" :loading="isBusy(row.policy.id, 'trust')" @click="addTrust(row.policy)">{{ row.inTrust ? '已在信任名单' : '加入信任名单' }}</el-button>
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
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse } from '@/types'

// 列表接口与详情接口共用同一组 SELECT 列，列表行直接携带完整 ACL 字段
interface PolicyRow {
  id: number
  name: string
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  ip_blacklist: string
}

interface PolicyDetail {
  id: number
  name: string
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  ip_blacklist?: string
}

// 黑/白名单统一写入 ip_acl_list，目标仅由模式决定；信任名单独立走 ip_whitelist
type AclTarget = 'deny' | 'allow'
type BusyKind = AclTarget | 'remove' | 'trust'

const ACL_LABELS: Record<AclTarget, string> = { deny: '黑名单', allow: '白名单' }

const props = defineProps<{ ip: string; location: string; ruleCaddyId?: string }>()

// 紧凑归属地：截取前两段（如「广东·深圳」），弹窗/悬浮显示完整
const compactLocation = computed(() => {
  if (!props.location) return ''
  const parts = props.location.split('·').map(s => s.trim()).filter(Boolean)
  if (parts.length <= 2) return parts.join('·')
  // 国内取省+市（跳过国家前缀），海外取国家+首城市
  const start = parts[0] === '中国' || parts[0] === '海外' ? 1 : 0
  return parts.slice(start, start + 2).join('·')
})

const authStore = useAuthStore()
// 仅主节点管理员可操作（从节点/非管理员只展示 IP 与归属地）——与全局只读口径一致
const canManage = computed(() => authStore.readOnlyReason === null)

const policies = ref<PolicyRow[]>([])
const policiesLoading = ref(false)
const policiesError = ref(false)
const busyKeys = ref<Set<string>>(new Set())

// —— 显式存入地址列表：与策略名单动作同口径（确认弹框 + 全局 MFA 428 守卫 +
// 明确反馈），不再作为名单写入后的隐式自动追加 ——
interface IPListOption { id: number; name: string; entry_count: number }
const ipLists = ref<IPListOption[]>([])
const selectedListId = ref<number | undefined>(undefined)
const savingToList = ref(false)

const loadIpLists = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<IPListOption[]>>('/security/ip-lists')
    ipLists.value = res.data || []
  } catch {
    ipLists.value = []
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
  try {
    await ElMessageBox.confirm(
      `将把 ${props.ip} 存入地址列表「${list.name}」（幂等，已存在时不会重复添加）。是否继续？`,
      '存入地址列表',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
    )
  } catch { return }
  savingToList.value = true
  try {
    // 非 silent：错误走全局拦截器提示，428 时全局 MFA step-up 弹码链完整生效
    const res = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${list.id}/ips`, { value: props.ip })
    if (res.data?.added) mfaAwareSuccess(`已存入列表「${list.name}」`)
    else ElMessage.info(`该 IP 已在列表「${list.name}」中`)
    await loadIpLists()
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    savingToList.value = false
  }
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

const normalizeRow = (p: PolicyRow): PolicyRow => ({
  id: p.id,
  name: p.name,
  ip_acl_enabled: !!p.ip_acl_enabled,
  ip_acl_mode: p.ip_acl_mode || '',
  ip_acl_list: p.ip_acl_list || '[]',
  ip_whitelist: p.ip_whitelist || '[]',
  ip_blacklist: p.ip_blacklist || '[]',
})

const loadPolicies = async (): Promise<void> => {
  // 每次 @show 都强制重新拉取——同一策略绑定多条规则时，从规则 A 弹窗
  // 加入黑名单后，打开规则 B 弹窗需要看到最新 ACL 状态（无陈旧缓存）。
  // 地址列表选项同节奏刷新（含 entry_count 展示）。
  void loadIpLists()
  policiesLoading.value = true
  try {
    const url = props.ruleCaddyId
      ? `/security/policies?enabled=true&rule_caddy_id=${encodeURIComponent(props.ruleCaddyId)}`
      : '/security/policies?enabled=true'
    const res = await request.get<APIResponse<PolicyRow[]>>(url)
    policies.value = (res.data || []).map(normalizeRow)
    policiesError.value = false
  } catch {
    policiesError.value = true
  } finally {
    policiesLoading.value = false
  }
}

// —— 每行视图状态：模式标签 / 该 IP 的归属状态 / 可用动作 ——

interface RowView {
  policy: PolicyRow
  inTrust: boolean
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
  const view: RowView = {
    policy,
    inTrust: parseList(policy.ip_whitelist).includes(props.ip),
    inLegacy: parseList(policy.ip_blacklist).includes(props.ip),
    tagType: 'info',
    tagLabel: '未启用',
    statusClass: '',
    statusLabel: 'IP ACL 未启用',
    countLabel: '',
    canAddDeny: false,
    canAddAllow: false,
    canEnableDeny: true,
    canEnableAllow: true,
    canRemove: false,
  }
  if (!policy.ip_acl_enabled) return view

  const list = parseList(policy.ip_acl_list)
  const inList = list.includes(props.ip)
  view.canEnableDeny = false
  view.canEnableAllow = false

  if (policy.ip_acl_mode === 'deny') {
    view.tagType = 'danger'
    view.tagLabel = '黑名单'
    view.countLabel = `${list.length} 条`
    if (inList) {
      view.statusClass = 'is-ok'
      view.statusLabel = '✅ 已在黑名单中'
      view.canRemove = true
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
      view.statusLabel = '✅ 已在白名单中'
      view.canRemove = true
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

// 写入成功后拉取最新详情，弹窗内状态即时翻转（✅/⚠️）
const refreshRow = async (id: number): Promise<void> => {
  try {
    const fresh = await fetchDetail(id)
    if (fresh) policies.value = policies.value.map((p) => (p.id === fresh.id ? fresh : p))
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
      // 模式一致 → 确认后追加
      if (list.includes(props.ip)) {
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
    } else if (list.length > 0) {
      // 模式切换且已有条目（K3 语义反转守卫）：原条目语义将整体反转，
      // 必须经确认框说明后果；确认后清空原列表、仅保留该 IP
      const targetTip = target === 'allow'
        ? `加入白名单会把访问控制切换为「仅允许名单内 IP」，原条目语义将反转，现有 ${list.length} 条将被清空、列表仅保留 ${props.ip}，其余所有 IP 将无法访问。`
        : `加入黑名单会把访问控制切换为「拒绝名单内 IP」，原条目语义将反转，现有 ${list.length} 条将被清空、列表仅保留 ${props.ip}（该 IP 将被直接拦截）。`
      try {
        await ElMessageBox.confirm(
          `策略「${policy.name}」当前为${modeLabel(detail.ip_acl_mode)}，列表中已有 ${list.length} 条 IP。${targetTip}是否继续？`,
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

    await request.put(`/security/policies/${policy.id}`, body)
    mfaAwareSuccess(successMsg)
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
    await request.put(`/security/policies/${policy.id}`, { ip_acl_list: JSON.stringify(list.filter((entry) => entry !== props.ip)) })
    mfaAwareSuccess(`已从策略「${policy.name}」的${listLabel}移除 ${props.ip}`)
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
        `将把 ${props.ip} 加入策略「${policy.name}」的信任名单，该 IP 将跳过 WAF 与访问控制检测（限流仍然生效）。是否继续？`,
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
    await request.put(`/security/policies/${policy.id}`, { ip_whitelist: JSON.stringify([...list, props.ip]) })
    mfaAwareSuccess(`已加入策略「${policy.name}」的信任名单`)
    await refreshRow(policy.id)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    unlockBusy(policy.id, 'trust')
  }
}
</script>

<style scoped>
.ip-cell { display: inline-flex; align-items: center; gap: 4px; max-width: 100%; vertical-align: middle; }
.ip-clickable { cursor: pointer; border-radius: 3px; padding: 1px 3px; margin: -1px -3px; transition: background 0.15s, color 0.15s; }
.ip-clickable:hover { background: var(--el-color-primary-light-9, #ecf5ff); }
.ip-clickable:hover .ip-text { color: var(--el-color-primary, #409eff); }
.ip-clickable:active { background: var(--el-color-primary-light-8, #d9ecff); }
.ip-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.ip-loc { font-size: 11px; color: var(--text-secondary, #909399); white-space: nowrap; max-width: 72px; overflow: hidden; text-overflow: ellipsis; flex-shrink: 1; }
</style>

<style>
.ip-location-popper .ipo-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 8px; }
.ip-location-popper .ipo-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; }
.ip-location-popper .ipo-loc { font-size: 12px; color: var(--text-secondary, #909399); }
.ip-location-popper .ipo-list-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding-bottom: 8px; margin-bottom: 4px; border-bottom: 1px solid var(--el-border-color-lighter, #ebeef5); }
.ip-location-popper .ipo-list-label { font-size: 12px; color: var(--text-secondary, #909399); white-space: nowrap; }
.ip-location-popper .ipo-list-select { width: 168px; }
.ip-location-popper .ipo-list-empty { font-size: 12px; color: var(--text-secondary, #909399); }
.ip-location-popper .ipo-tip { font-size: 12px; color: var(--text-secondary, #909399); padding: 4px 0; }
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
