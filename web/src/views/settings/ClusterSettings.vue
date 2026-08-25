<template>
  <div class="cluster-settings">
    <ClusterStatusCard :status="status" :loading="initialLoading" />
    <el-row :gutter="16" class="equal-height-row">
      <el-col :xs="24" :sm="24" :md="12">
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
      </el-col>
      <el-col :xs="24" :sm="24" :md="12">
        <ClusterMasterPanel
          v-if="status"
          settings-only
          :status="status"
          :nodes="nodes"
          :loading="nodesLoading"
          :token-loading="tokenLoading"
          :settings-loading="settingsLoading"
          :pending-node-id="pendingNodeId"
          :login-node-id="loginNodeId"
          :access-url-saving="accessUrlSaving"
          :read-only="isNonAdminReadOnly || status?.node_mode === 'slave'"
          @generate-token="generateRegisterToken"
          @update-sync-field="updateSyncField"
          @approve="approveNode"
          @reject="rejectNode"
          @remove="removeNode"
          @login="loginNode"
          @edit-access-url="openAccessUrlDialog"
        />
      </el-col>
    </el-row>

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
      @update-sync-field="updateSyncField"
      @approve="approveNode"
      @reject="rejectNode"
      @remove="removeNode"
      @login="loginNode"
      @edit-access-url="openAccessUrlDialog"
    />

    <ClusterSlavePanel
      v-if="status && status.node_mode !== 'master'"
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
      <div class="form-tip-line">有效期至：{{ formatDate(registerToken?.expires_at ?? '') || '-' }}</div>
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
  APIResponse,
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
import { usePollingTask } from '@/composables/usePollingTask'

type SyncErrorCode = 'schema_too_new' | 'schema_too_old' | 'signature_invalid' | 'pin_mismatch' | 'validation_failed' | 'apply_failed' | 'transport_error'
type ClusterNodeWithSyncError = Omit<ClusterNode, 'health'> & {
	readonly health: (NonNullable<ClusterNode['health']> & { readonly sync_error_code?: SyncErrorCode }) | null
}

interface ActionResponse {
  readonly code: number
  readonly message: string
}

interface LoginTicketResponse {
  readonly ticket: string
  readonly url: string
}

const authStore = useAuthStore()
let disposed = false
let requestSequence = 0
const status = ref<ClusterStatus | null>(null)
const nodes = ref<readonly ClusterNodeWithSyncError[]>([])
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
const fetchStatus = async (): Promise<ClusterStatus> => {
  const requestSeq = ++requestSequence
  const response = await request.get<APIResponse<ClusterStatus>>('/cluster/status', { signal: clusterPolling.signal, silent: true })
  const data = response.data
  if (!data) throw new Error('集群状态响应缺少数据')
  if (!disposed && requestSeq === requestSequence) {
    status.value = data
    authStore.setNodeMode(data.node_mode)
  }
  return data
}

const fetchNodes = async (): Promise<void> => {
  if (disposed) return
  const requestSeq = ++requestSequence
  nodesLoading.value = true
  try {
  const response = await request.get<APIResponse<readonly ClusterNodeWithSyncError[]>>('/cluster/nodes', { signal: clusterPolling.signal, silent: true })
    if (!disposed && requestSeq === requestSequence) nodes.value = response.data ?? []
  } catch (error: unknown) {
    // Silent request: no toast from the interceptor, keep the only diagnostics in console
    // and prevent unhandled rejections on fire-and-forget refresh paths.
    console.error('Failed to fetch cluster nodes:', error)
  } finally {
    if (!disposed && requestSeq === requestSequence) nodesLoading.value = false
  }
}

const refreshCluster = async (): Promise<void> => {
  if (disposed) return
  const currentStatus = await fetchStatus()
  if (disposed) return
  if (currentStatus.node_mode === 'master') {
    await fetchNodes()
  } else {
    nodes.value = []
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
    // MessageBox 仅以 'cancel'/'close' 字符串 reject（取消语义）；其余值同样按未确认
    // 处理并记录——confirmAction 保证自身不抛出，使 syncNow 等在 try 外调用它的
    // 调用方不会收到 unhandled rejection。
    if (error === 'cancel' || error === 'close') return false
    console.error('Unexpected MessageBox rejection:', error)
    return false
  }
}

const registerAsSlave = async (input: ClusterRegistrationInput): Promise<void> => {
  if (isNonAdminReadOnly.value || clusterModeChanging.value) return
  modeLoading.value = true
  try {
    const confirmed = await confirmAction('切换后本地数据将被主节点全覆盖，是否继续？', '确认切换为从节点')
    if (!confirmed) return
    await request.post<APIResponse<ClusterModeResult>>('/cluster/mode', { mode: 'slave', ...input })
    ElMessage.success('注册请求已提交，等待主节点审批')
    await clusterPolling.run()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to register as slave:', error)
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
    await clusterPolling.run()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to promote to master:', error)
  } finally {
    promoting.value = false
  }
}

const syncNow = async (): Promise<void> => {
  if (isNonAdminReadOnly.value || clusterModeChanging.value) return
  const ok = await confirmAction('立即从主节点拉取并应用最新配置？', '手动同步')
  if (!ok) return
  syncing.value = true
  try {
    const response = await request.post<APIResponse<ClusterSyncResult>>('/cluster/sync/pull')
    const result = response.data
    if (result) ElMessage.success(result.changed ? `同步完成，已应用版本 ${result.applied_version}` : '当前已是最新配置')
    // fetchStatus 为 silent 请求，失败仅记录日志，避免逃逸为未处理的 rejection
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to sync now:', error)
  } finally {
    syncing.value = false
  }
}

const generateRegisterToken = async (): Promise<void> => {
  if (isNonAdminReadOnly.value) return
  tokenLoading.value = true
  try {
    const response = await request.post<APIResponse<ClusterRegisterToken>>('/cluster/register-tokens')
    if (response.data) {
      registerToken.value = response.data
      tokenDialogVisible.value = true
    }
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to generate register token:', error)
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
    // clipboard 仅 reject Error 子类；其余值同样按复制失败提示，不再向上抛。
    console.error('Failed to copy register token:', error)
    ElMessage.error('复制失败，请手动复制注册令牌')
  }
}

const syncSwitchLabels: Record<string, string> = {
  sync_global_config: '全局配置',
  sync_users: '系统数据',
  sync_rules: '负载均衡规则',
  sync_waf_files: '规则库数据库',
  sync_security: '安全策略规则',
}

const updateSyncField = async (field: string, value: boolean): Promise<void> => {
  if (isNonAdminReadOnly.value) return
  const label = syncSwitchLabels[field] ?? field
  const action = value ? '开启' : '关闭'
  try {
    await ElMessageBox.confirm(
      `确定要${action}「${label}」的集群同步吗？${value ? '开启后主节点该类变更将同步到所有从节点。' : '关闭后从节点将保留本地数据，不再接收主节点该类变更。'}`,
      '同步设置确认',
      { confirmButtonText: action, cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
    return
  }
  settingsLoading.value = true
  try {
    await request.put<ActionResponse>('/cluster/settings', { [field]: value })
    ElMessage.success('同步设置已更新')
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update sync field:', error)
    await fetchStatus().catch((refreshError: unknown) => console.error('Failed to refresh cluster status:', refreshError))
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
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update sync interval:', error)
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
    await clusterPolling.run()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to run node action:', error)
  } finally {
    pendingNodeId.value = null
  }
}

// R63 D-N1：审批是三个节点操作中安全面最大的「信任授予」动作（确认后外部节点
// 入集群并开始同步），与拒绝/删除对称补二次确认，防 pending 列表误点。
const approveNode = async (node: ClusterNode): Promise<void> => {
  try {
    const confirmed = await confirmAction(`确定确认节点“${node.name}”加入集群吗？确认后该节点将开始同步。`, '审批确认')
    if (confirmed) await runNodeAction(node, 'approve')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to approve node:', error)
  }
}

const requestRegistration = (): void => {
  if (isNonAdminReadOnly.value) return
  registrationRequest.value += 1
}

const rejectNode = async (node: ClusterNode): Promise<void> => {
  try {
    const confirmed = await confirmAction(`确定拒绝节点“${node.name}”吗？`, '拒绝确认')
    if (confirmed) await runNodeAction(node, 'reject')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to reject node:', error)
  }
}

const removeNode = async (node: ClusterNode): Promise<void> => {
  try {
    const confirmed = await confirmAction(`确定删除节点“${node.name}”吗？删除后该节点将无法继续同步。`, '删除确认')
    if (confirmed) await runNodeAction(node, 'remove')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to remove node:', error)
  }
}

const loginNode = async (node: ClusterNode): Promise<void> => {
  if (isNonAdminReadOnly.value || node.status !== 'online' || loginNodeId.value !== null) return
  // R72 六次：403（未启用 MFA）预检——文案指向正确入口（用户管理）。
  if (!authStore.user?.mfa_enabled) {
    ElMessage.warning('登录从节点需先启用 MFA（在「系统设置 → 用户管理」中对自己的账号绑定）')
    return
  }
  loginNodeId.value = node.id
  try {
    // R72 九次（用户反馈：先弹验证码再开页面）：票据请求先行、开窗后置——
    // 此前先 window.open 再 POST，428（每次都要求 MFA）时验证码弹框期间
    // 空白页已挂在旁边且取消后不一定关闭。现在 428 由全局拦截器弹码（无窗
    // 口），验证成功 → 拦截器自动重试 → 成功后才开窗导航；失败/取消则根本
    // 不开窗。MFA 弹框「验证」点击本身是用户手势，紧随其后的 window.open
    // 通常被浏览器放行；被拦时给出可重试提示兜底。
    const response = await request.post<LoginTicketResponse>(`/cluster/nodes/${node.id}/login-ticket`, undefined, { silent: true })
    const target = new URL(response.url)
    target.hash = `login_ticket=${encodeURIComponent(response.ticket)}`
    const loginWindow = window.open(target.toString(), '_blank')
    if (!loginWindow) {
      ElMessage.warning('浏览器阻止了新窗口，请允许弹出窗口后重试')
      return
    }
    loginWindow.opener = null
  } catch (error: unknown) {
    // 取消弹码的场景已由全局拦截器统一提示「已取消 MFA 验证，操作未执行」，
    // 这里只处理其余错误（网络/节点不可达等）。
    if (!(error instanceof Error && (error.message.includes('MFA') || error.message.includes('取消')))) {
      ElMessage.error(error instanceof Error ? error.message : '登录从节点失败')
    }
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
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update access url:', error)
  } finally {
    accessUrlSaving.value = false
  }
}

const clusterPolling = usePollingTask(async () => refreshCluster(), {
  interval: 15000,
  onError: (error) => console.error('Failed to poll cluster status:', error),
})

onMounted(async () => {
  try {
    await clusterPolling.run()
  } finally {
    if (!disposed) initialLoading.value = false
  }
  if (disposed) return
  clusterPolling.start()
})

onUnmounted(() => {
  disposed = true
  requestSequence++
})
</script>

<style scoped>
.cluster-settings { display: flex; flex-direction: column; gap: 20px; }
.token-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; padding: 12px; border-radius: var(--radius-md); background: var(--bg-secondary); }
.token-box code { flex: 1; min-width: 0; color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; word-break: break-all; }

@media (max-width: 768px) {
  .token-box { align-items: stretch; flex-direction: column; }
}
</style>
