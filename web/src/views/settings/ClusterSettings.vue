<template>
  <div class="cluster-settings">
    <ClusterStatusCard :status="status" :loading="initialLoading" />
    <ClusterModeCard
      :status="status"
      :loading="clusterModeChanging"
      :registration-request="registrationRequest"
      :read-only="isNonAdminReadOnly"
      :interval-saving="intervalSaving"
      @register="registerAsSlave"
      @promote="promoteToMaster"
      @update-interval="updateSyncInterval"
    />

    <ClusterMasterPanel
      v-if="status?.node_mode === 'master'"
      :status="status"
      :nodes="nodes"
      :loading="nodesLoading"
      :token-loading="tokenLoading"
      :settings-loading="settingsLoading"
      :pending-node-id="pendingNodeId"
      :login-node-id="loginNodeId"
      :access-url-saving="accessUrlSaving"
      :read-only="isNonAdminReadOnly"
      @generate-token="generateRegisterToken"
      @update-sync="updateSyncSetting"
      @approve="approveNode"
      @reject="rejectNode"
      @remove="removeNode"
      @login="loginNode"
      @edit-access-url="openAccessUrlDialog"
    />

    <ClusterSlavePanel
      v-else-if="status"
      :status="status"
      :syncing="syncing"
      :promoting="promoting"
      :read-only="isNonAdminReadOnly"
      @sync="syncNow"
      @promote="promoteToMaster"
      @reregister="requestRegistration"
    />

    <ClusterAccessUrlDialog
      :visible="accessUrlDialogVisible"
      :node="editingAccessUrlNode"
      :saving="accessUrlSaving"
      @close="closeAccessUrlDialog"
      @save="updateAccessUrl"
    />

    <el-dialog v-model="tokenDialogVisible" title="一次性注册令牌" width="min(560px, 92vw)" :close-on-click-modal="false">
      <el-alert title="仅展示一次，请立即复制并妥善保存" type="warning" :closable="false" show-icon />
      <div class="token-box">
        <code>{{ registerToken?.token }}</code>
        <el-button type="primary" @click="copyRegisterToken">
          <el-icon><CopyDocument /></el-icon>复制令牌
        </el-button>
      </div>
      <div class="form-tip">有效期至：{{ formatDate(registerToken?.expires_at ?? '') || '-' }}</div>
      <template #footer><el-button type="primary" @click="tokenDialogVisible = false">我已保存</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { CopyDocument } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import type {
  ApiResponse,
  ClusterModeResult,
  ClusterNode,
  ClusterRegisterToken,
  ClusterRegistrationInput,
  ClusterStatus,
  ClusterSyncResult,
} from '@/types'
import ClusterMasterPanel from './cluster/ClusterMasterPanel.vue'
import ClusterAccessUrlDialog from './cluster/ClusterAccessUrlDialog.vue'
import ClusterModeCard from './cluster/ClusterModeCard.vue'
import ClusterSlavePanel from './cluster/ClusterSlavePanel.vue'
import ClusterStatusCard from './cluster/ClusterStatusCard.vue'

interface ActionResponse {
  readonly code: number
  readonly message: string
}

interface LoginTicketResponse {
  readonly ticket: string
  readonly url: string
}

const authStore = useAuthStore()
const abortController = new AbortController()
let disposed = false
let requestSequence = 0
const status = ref<ClusterStatus | null>(null)
const nodes = ref<readonly ClusterNode[]>([])
const initialLoading = ref(true)
const nodesLoading = ref(false)
const modeLoading = ref(false)
const tokenLoading = ref(false)
const settingsLoading = ref(false)
const syncing = ref(false)
const promoting = ref(false)
const intervalSaving = ref(false)
const pendingNodeId = ref<number | null>(null)
const loginNodeId = ref<number | null>(null)
const accessUrlDialogVisible = ref(false)
const editingAccessUrlNode = ref<ClusterNode | null>(null)
const accessUrlSaving = ref(false)
const registrationRequest = ref(0)
const tokenDialogVisible = ref(false)
const registerToken = ref<ClusterRegisterToken | null>(null)
const isNonAdminReadOnly = computed(() => authStore.readOnlyReason === 'non-admin')
const clusterModeChanging = computed(() => syncing.value || promoting.value || modeLoading.value)
let refreshTimer: ReturnType<typeof setInterval> | null = null

const fetchStatus = async (): Promise<ClusterStatus> => {
  const requestSeq = requestSequence
  const response = await request.get<ApiResponse<ClusterStatus>>('/cluster/status', { signal: abortController.signal })
  if (!disposed && requestSeq === requestSequence) {
    status.value = response.data
    authStore.setNodeMode(response.data.node_mode)
  }
  return response.data
}

const fetchNodes = async (): Promise<void> => {
  if (disposed) return
  const requestSeq = requestSequence
  nodesLoading.value = true
  try {
    const response = await request.get<ApiResponse<readonly ClusterNode[]>>('/cluster/nodes', { signal: abortController.signal })
    if (!disposed && requestSeq === requestSequence) nodes.value = response.data
  } finally {
    if (!disposed && requestSeq === requestSequence) nodesLoading.value = false
  }
}

let refreshInFlight: Promise<void> | null = null
let refreshPending = false
const refreshCluster = async (): Promise<void> => {
  if (disposed) return
  if (refreshInFlight) {
    refreshPending = true
    await refreshInFlight
    return
  }
  refreshPending = false
  refreshInFlight = (async () => {
    const currentStatus = await fetchStatus()
    if (disposed) return
    if (currentStatus.node_mode === 'master') {
      await fetchNodes()
    } else {
      nodes.value = []
    }
  })()
  try {
    await refreshInFlight
  } finally {
    const shouldDrain = !disposed && refreshPending
    refreshPending = false
    refreshInFlight = null
    if (shouldDrain) {
      queueMicrotask(() => {
        void refreshCluster().catch(() => undefined)
      })
    }
  }
}

const confirmAction = async (message: string, title: string): Promise<boolean> => {
  try {
    await ElMessageBox.confirm(message, title, {
      confirmButtonText: '确认',
      cancelButtonText: '取消',
      type: 'warning',
    })
    return true
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return false
    throw error
  }
}

const registerAsSlave = async (input: ClusterRegistrationInput): Promise<void> => {
  if (isNonAdminReadOnly.value || clusterModeChanging.value) return
  modeLoading.value = true
  try {
    const confirmed = await confirmAction('切换后本地数据将被主节点全覆盖，是否继续？', '确认切换为从节点')
    if (!confirmed) return
    await request.post<ApiResponse<ClusterModeResult>>('/cluster/mode', { mode: 'slave', ...input })
    ElMessage.success('注册请求已提交，等待主节点审批')
    await refreshCluster()
  } finally {
    modeLoading.value = false
  }
}

const promoteToMaster = async (): Promise<void> => {
  if (isNonAdminReadOnly.value || clusterModeChanging.value) return
  promoting.value = true
  try {
    const confirmed = await confirmAction('将脱离集群，当前数据成为权威数据', '确认提升为主节点')
    if (!confirmed) return
    await request.post<ActionResponse>('/cluster/promote')
    ElMessage.success('已提升为主节点')
    await refreshCluster()
  } finally {
    promoting.value = false
  }
}

const syncNow = async (): Promise<void> => {
  if (isNonAdminReadOnly.value || clusterModeChanging.value) return
  syncing.value = true
  try {
    const response = await request.post<ApiResponse<ClusterSyncResult>>('/cluster/sync/pull')
    ElMessage.success(response.data.changed ? `同步完成，已应用版本 ${response.data.applied_version}` : '当前已是最新配置')
    await fetchStatus()
  } finally {
    syncing.value = false
  }
}

const generateRegisterToken = async (): Promise<void> => {
  if (isNonAdminReadOnly.value) return
  tokenLoading.value = true
  try {
    const response = await request.post<ApiResponse<ClusterRegisterToken>>('/cluster/register-tokens')
    registerToken.value = response.data
    tokenDialogVisible.value = true
  } finally {
    tokenLoading.value = false
  }
}

const copyRegisterToken = async (): Promise<void> => {
  const token = registerToken.value?.token
  if (!token) return
  try {
    await navigator.clipboard.writeText(token)
    ElMessage.success('注册令牌已复制')
  } catch (error: unknown) {
    if (error instanceof Error) {
      ElMessage.error('复制失败，请手动复制注册令牌')
      return
    }
    throw error
  }
}

const updateSyncSetting = async (value: boolean): Promise<void> => {
  if (isNonAdminReadOnly.value) return
  settingsLoading.value = true
  try {
    await request.put<ActionResponse>('/cluster/settings', { sync_caddy_config: value })
    ElMessage.success('同步设置已更新')
    await fetchStatus()
  } finally {
    settingsLoading.value = false
  }
}

const updateSyncInterval = async (value: number): Promise<void> => {
  if (isNonAdminReadOnly.value) return
  intervalSaving.value = true
  try {
    await request.put<ActionResponse>('/cluster/settings', { sync_interval: value })
    ElMessage.success('同步间隔已更新')
    await fetchStatus()
  } finally {
    intervalSaving.value = false
  }
}

const runNodeAction = async (node: ClusterNode, action: 'approve' | 'reject' | 'remove'): Promise<void> => {
  if (isNonAdminReadOnly.value || pendingNodeId.value !== null) return
  pendingNodeId.value = node.id
  try {
    if (action === 'approve') {
      await request.post<ActionResponse>(`/cluster/nodes/${node.id}/approve`)
      ElMessage.success('节点已确认')
    } else if (action === 'reject') {
      await request.post<ActionResponse>(`/cluster/nodes/${node.id}/reject`)
      ElMessage.success('节点已拒绝')
    } else {
      await request.delete<ActionResponse>(`/cluster/nodes/${node.id}`)
      ElMessage.success('节点已删除')
    }
    await refreshCluster()
  } finally {
    pendingNodeId.value = null
  }
}

const approveNode = (node: ClusterNode): Promise<void> => runNodeAction(node, 'approve')

const requestRegistration = (): void => {
  if (isNonAdminReadOnly.value) return
  registrationRequest.value += 1
}

const rejectNode = async (node: ClusterNode): Promise<void> => {
  const confirmed = await confirmAction(`确定拒绝节点“${node.name}”吗？`, '拒绝确认')
  if (confirmed) await runNodeAction(node, 'reject')
}

const removeNode = async (node: ClusterNode): Promise<void> => {
  const confirmed = await confirmAction(`确定删除节点“${node.name}”吗？删除后该节点将无法继续同步。`, '删除确认')
  if (confirmed) await runNodeAction(node, 'remove')
}

const loginNode = async (node: ClusterNode): Promise<void> => {
  if (isNonAdminReadOnly.value || node.status !== 'online' || loginNodeId.value !== null) return
  const loginWindow = window.open('', '_blank')
  if (!loginWindow) {
    ElMessage.warning('浏览器阻止了新窗口，请允许弹出窗口后重试')
    return
  }
  loginWindow.opener = null
  loginNodeId.value = node.id
  try {
    const response = await request.post<LoginTicketResponse>(`/cluster/nodes/${node.id}/login-ticket`)
    const target = new URL(response.url)
    target.hash = `login_ticket=${encodeURIComponent(response.ticket)}`
    loginWindow.location.replace(target.toString())
  } catch (error: unknown) {
    loginWindow.close()
    throw error
  } finally {
    loginNodeId.value = null
  }
}

const openAccessUrlDialog = (node: ClusterNode): void => {
  if (isNonAdminReadOnly.value || accessUrlSaving.value) return
  editingAccessUrlNode.value = node
  accessUrlDialogVisible.value = true
}

const closeAccessUrlDialog = (): void => {
  if (accessUrlSaving.value) return
  accessUrlDialogVisible.value = false
  editingAccessUrlNode.value = null
}

const updateAccessUrl = async (accessUrl: string): Promise<void> => {
  const node = editingAccessUrlNode.value
  if (!node || isNonAdminReadOnly.value || accessUrlSaving.value) return
  accessUrlSaving.value = true
  try {
    await request.put<ActionResponse>(`/cluster/nodes/${node.id}/access-url`, { access_url: accessUrl })
    ElMessage.success('访问地址已更新')
    accessUrlDialogVisible.value = false
    editingAccessUrlNode.value = null
    await fetchNodes()
  } finally {
    accessUrlSaving.value = false
  }
}

onMounted(async () => {
  try {
    await refreshCluster().catch(() => undefined)
  } finally {
    if (!disposed) initialLoading.value = false
  }
  if (disposed) return
  refreshTimer = setInterval(() => {
    void refreshCluster().catch(() => undefined)
  }, 15000)
})

onUnmounted(() => {
  disposed = true
  requestSequence++
  abortController.abort()
  refreshPending = false
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.cluster-settings { display: flex; flex-direction: column; gap: 20px; }
.token-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; padding: 12px; border-radius: var(--radius-md); background: var(--bg-secondary); }
.token-box code { flex: 1; min-width: 0; color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; word-break: break-all; }
.form-tip { margin-top: 12px; color: var(--text-muted); font-size: 12px; }

@media (max-width: 768px) {
  .token-box { align-items: stretch; flex-direction: column; }
}
</style>
