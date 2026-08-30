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

    <div v-if="policiesLoading" class="ipo-tip">策略加载中…</div>
    <el-alert v-else-if="policiesError" type="error" :closable="false" title="策略列表加载失败" />
    <template v-else-if="policies.length > 0">
      <div class="ipo-tip">选择要加入的策略与名单：</div>
      <div v-for="policy in policies" :key="policy.id" class="ipo-row">
        <div class="ipo-name" :title="policy.name">{{ policy.name }}</div>
        <div class="ipo-actions">
          <el-button size="small" type="primary" plain :loading="isBusy(policy.id, 'whitelist')" @click="addTo(policy, 'whitelist')">加入白名单</el-button>
          <el-button size="small" type="danger" plain :loading="isBusy(policy.id, 'blacklist')" @click="addTo(policy, 'blacklist')">加入黑名单</el-button>
          <el-button size="small" type="warning" plain :loading="isBusy(policy.id, 'trust')" @click="addTo(policy, 'trust')">加入信任名单</el-button>
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
import { useAuthStore } from '@/stores/auth'
import type { APIResponse } from '@/types'

interface PolicySummary {
  id: number
  name: string
}

interface PolicyDetail {
  id: number
  name: string
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  ip_blacklist: string
}

type ListKind = 'whitelist' | 'blacklist' | 'trust'

const kindLabels: Record<ListKind, string> = {
  whitelist: '白名单',
  blacklist: '黑名单',
  trust: '信任名单',
}

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

const policies = ref<PolicySummary[]>([])
const policiesLoading = ref(false)
const policiesError = ref(false)
const busyKeys = ref<Set<string>>(new Set())

const loadPolicies = async (): Promise<void> => {
  if (policiesLoading.value) return
  policiesLoading.value = true
  try {
    const url = props.ruleCaddyId
      ? `/security/policies?enabled=true&rule_caddy_id=${encodeURIComponent(props.ruleCaddyId)}`
      : '/security/policies?enabled=true'
    const res = await request.get<APIResponse<PolicySummary[]>>(url)
    policies.value = (res.data || []).map((p) => ({ id: p.id, name: p.name }))
    policiesError.value = false
  } catch {
    policiesError.value = true
  } finally {
    policiesLoading.value = false
  }
}

const isBusy = (id: number, kind: ListKind): boolean => busyKeys.value.has(`${id}:${kind}`)

const parseList = (raw: string): string[] => {
  try {
    const parsed: unknown = JSON.parse(raw || '[]')
    if (!Array.isArray(parsed)) return []
    return parsed.filter((entry): entry is string => typeof entry === 'string')
  } catch {
    return []
  }
}

const confirmText = (policy: PolicySummary, kind: ListKind): string => {
  switch (kind) {
    case 'whitelist':
      return `将把 ${props.ip} 加入策略「${policy.name}」的白名单：IP 访问控制切换为「仅允许名单内 IP」，名单内 IP 仍会经过 WAF 检测。是否继续？`
    case 'blacklist':
      return `将把 ${props.ip} 加入策略「${policy.name}」的黑名单，该 IP 的请求将被直接拦截。是否继续？`
    case 'trust':
      return `将把 ${props.ip} 加入策略「${policy.name}」的信任名单，该 IP 将跳过 WAF 与访问控制检测（限流仍然生效）。是否继续？`
  }
}

const addTo = async (policy: PolicySummary, kind: ListKind): Promise<void> => {
  const busyKey = `${policy.id}:${kind}`
  if (busyKeys.value.has(busyKey)) return
  try {
    await ElMessageBox.confirm(confirmText(policy, kind), '加入IP名单', { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' })
  } catch {
    return
  }
  busyKeys.value = new Set(busyKeys.value).add(busyKey)
  try {
    const detailRes = await request.get<APIResponse<{ policy: PolicyDetail }>>(`/security/policies/${policy.id}`)
    const detail = detailRes.data?.policy
    if (!detail) return

    let body: Record<string, unknown>
    if (kind === 'blacklist') {
      const list = parseList(detail.ip_blacklist)
      if (list.includes(props.ip)) {
        ElMessage.info(`该 IP 已在策略「${policy.name}」的${kindLabels[kind]}中`)
        return
      }
      body = { ip_blacklist: JSON.stringify([...list, props.ip]) }
    } else if (kind === 'trust') {
      const list = parseList(detail.ip_whitelist)
      if (list.includes(props.ip)) {
        ElMessage.info(`该 IP 已在策略「${policy.name}」的${kindLabels[kind]}中`)
        return
      }
      body = { ip_whitelist: JSON.stringify([...list, props.ip]) }
    } else {
      const list = parseList(detail.ip_acl_list)
      if (detail.ip_acl_mode === 'allow' && list.includes(props.ip)) {
        ElMessage.info(`该 IP 已在策略「${policy.name}」的${kindLabels[kind]}中`)
        return
      }
      body = { ip_acl_list: JSON.stringify([...list, props.ip]), ip_acl_mode: 'allow', ip_acl_enabled: true }
    }

    await request.put(`/security/policies/${policy.id}`, body)
    ElMessage.success(`已添加到策略 ${policy.name} 的${kindLabels[kind]}`)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    const next = new Set(busyKeys.value)
    next.delete(busyKey)
    busyKeys.value = next
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
.ip-location-popper .ipo-loc { font-size: 12px; color: #909399; }
.ip-location-popper .ipo-tip { font-size: 12px; color: #909399; padding: 4px 0; }
.ip-location-popper .ipo-row { padding: 6px 0; border-top: 1px solid var(--el-border-color-lighter, #ebeef5); }
.ip-location-popper .ipo-name { font-size: 13px; font-weight: 500; margin-bottom: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ip-location-popper .ipo-actions { display: flex; gap: 0; }
.ip-location-popper .ipo-actions .el-button + .el-button { margin-left: 8px; }
</style>
