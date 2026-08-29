<template>
  <div class="cluster-settings">
    <el-alert v-if="clusterPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert">
      <template #title>
        <div class="polling-error-title">
          <span>集群状态加载失败：{{ clusterPollingError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="clusterRetrying" @click="retryClusterPolling">立即重试</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ clusterPollingErrorDescription }}</div>
    </el-alert>
    <ClusterStatusCard :status="status" :loading="initialLoading" :error="!!clusterPollingError.errorMessage.value" />
    <el-row :gutter="16" class="equal-height-row">
      <el-col :xs="24" :sm="24" :md="12">
        <ClusterModeCard
          :status="status"
          :loading="clusterModeChanging"
          :registration-request="registrationRequest"
          :read-only="isReadOnlyProp"
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
          :read-only="isReadOnlyProp || status?.node_mode === 'slave'"
          @generate-token="generateRegisterToken"
          @update-sync-field="updateSyncField"
          @approve="approveNode"
          @reject="rejectNode"
          @remove="removeNode"
          @login="loginNode"
          @service-control="openServiceControlDialog"
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
      :read-only="isReadOnlyProp"
      @generate-token="generateRegisterToken"
      @update-sync-field="updateSyncField"
      @approve="approveNode"
      @reject="rejectNode"
      @remove="removeNode"
      @login="loginNode"
      @service-control="openServiceControlDialog"
      @edit-access-url="openAccessUrlDialog"
    />

    <ClusterSlavePanel
      v-if="status && status.node_mode !== 'master'"
      :status="status"
      :syncing="syncing"
      :promoting="promoting"
      :read-only="isReadOnlyProp"
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

    <el-dialog v-model="serviceControlDialogVisible" width="min(520px, 92vw)" :close-on-click-modal="false" class="service-control-dialog">
      <template #header>
        <div class="service-control-header">
          <div class="service-control-title">
            <el-icon :size="18"><Monitor /></el-icon>
            <span>服务控制</span>
          </div>
          <div v-if="serviceControlNode" class="service-control-node">
            <el-tag :type="serviceControlNode.status === 'online' ? 'success' : 'info'" size="small">{{ serviceControlNode.status === 'online' ? '在线' : '离线' }}</el-tag>
            <span class="service-control-node-name">{{ serviceControlNode.name }}</span>
            <span class="service-control-node-url">{{ serviceControlNode.access_url || `${serviceControlNode.ip_address}:${serviceControlNode.port}` }}</span>
          </div>
        </div>
      </template>

      <div class="service-control-grid">
        <div
          v-for="item in serviceControlOptions"
          :key="item.value"
          class="service-control-card"
          :class="{ 'is-active': serviceControlAction === item.value, [`is-${item.tone}`]: true }"
          @click="serviceControlAction = item.value"
        >
          <div class="service-control-card-icon">
            <el-icon :size="22"><component :is="item.icon" /></el-icon>
          </div>
          <div class="service-control-card-body">
            <div class="service-control-card-title">{{ item.label }}</div>
            <div class="service-control-card-desc">{{ item.description }}</div>
          </div>
          <div class="service-control-card-check">
            <el-icon v-if="serviceControlAction === item.value"><Select /></el-icon>
          </div>
        </div>
      </div>

      <transition name="el-fade-in">
        <el-alert
          v-if="serviceControlWarnings[serviceControlAction]"
          :title="serviceControlWarnings[serviceControlAction]"
          type="warning"
          :closable="false"
          show-icon
          class="service-control-warning"
        />
      </transition>

      <template #footer>
        <el-button @click="serviceControlDialogVisible = false">取消</el-button>
        <el-button
          :type="serviceControlAction === 'stop_caddy' || serviceControlAction === 'restart_app' ? 'danger' : 'primary'"
          :loading="serviceControlLoading"
          :disabled="!serviceControlAction"
          @click="executeServiceControl"
        >
          {{ serviceControlLoading ? '正在执行…' : '执行操作' }}
        </el-button>
      </template>
    </el-dialog>
   </div>
 </template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { CopyDocument, Monitor, RefreshRight, Select, VideoPause, VideoPlay } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { request, mfaAwareSuccess } from '@/utils/api'
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
import { usePollingErrorState } from '@/composables/usePollingErrorState'

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

const serviceControlDialogVisible = ref(false)
const serviceControlNode = ref<ClusterNode | null>(null)
const serviceControlAction = ref('')
const serviceControlLoading = ref(false)

const serviceControlOptions = [
  { value: 'start_caddy', label: '启动 Caddy', description: '启动负载均衡引擎并应用当前配置', icon: VideoPlay, tone: 'success' },
  { value: 'stop_caddy', label: '停止 Caddy', description: '停止负载均衡引擎，流量将中断', icon: VideoPause, tone: 'danger' },
  { value: 'restart_caddy', label: '重启 Caddy', description: '重启负载均衡引擎并重放权威配置', icon: RefreshRight, tone: 'warning' },
  { value: 'restart_app', label: '重启应用', description: '重启 Lazy Balancer 服务进程（约数秒）', icon: Monitor, tone: 'danger' },
] as const

const serviceControlWarnings: Record<string, string> = {
  stop_caddy: '停止后该节点的负载均衡服务将不可用，请及时启动',
  restart_app: '重启应用将短暂中断该节点的全部服务（约数秒）',
}

const openServiceControlDialog = (node: ClusterNode): void => {
  serviceControlNode.value = node
  serviceControlAction.value = ''
  serviceControlDialogVisible.value = true
}

const executeServiceControl = async (): Promise<void> => {
  if (!serviceControlNode.value || !serviceControlAction.value) return
  serviceControlLoading.value = true
  try {
    await request.post(`/cluster/nodes/${serviceControlNode.value.id}/service`, { action: serviceControlAction.value })
    serviceControlDialogVisible.value = false
  } catch (error: unknown) {
    // 全局拦截器已弹 toast；428 MFA 重试也由全局处理
    console.error('service control failed', error)
  } finally {
    serviceControlLoading.value = false
  }
}
const registerToken = ref<ClusterRegisterToken | null>(null)
// A6-S3：readOnlyReason 为 unknown（token 有效但 /users/me 尚未拉取成功）时同样
// fail-closed——集群操作在该窗口期按只读呈现。slave 除外照旧：从节点管理员仍可
// 操作集群管理（含「提升为主节点」），不随本项收紧。
const isReadOnlyProp = computed(() => {
  const reason = authStore.readOnlyReason
  return reason === 'non-admin' || reason === 'unknown'
})
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
  if (isReadOnlyProp.value || clusterModeChanging.value) return
  modeLoading.value = true
  try {
    const confirmed = await confirmAction('切换后本地数据将被主节点全覆盖，是否继续？', '确认切换为从节点')
    if (!confirmed) return
    await request.post<APIResponse<ClusterModeResult>>('/cluster/mode', { mode: 'slave', ...input })
    mfaAwareSuccess('注册请求已提交，等待主节点审批')
    await clusterPolling.run()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to register as slave:', error)
  } finally {
    modeLoading.value = false
  }
}

const promoteToMaster = async (): Promise<void> => {
  if (isReadOnlyProp.value || clusterModeChanging.value) return
  promoting.value = true
  try {
    const confirmed = await confirmAction('将脱离集群，当前数据成为权威数据', '确认提升为主节点')
    if (!confirmed) return
    await request.post<ActionResponse>('/cluster/promote')
    mfaAwareSuccess('已提升为主节点')
    await clusterPolling.run()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to promote to master:', error)
  } finally {
    promoting.value = false
  }
}

const syncNow = async (): Promise<void> => {
  if (isReadOnlyProp.value || clusterModeChanging.value) return
  const ok = await confirmAction('立即从主节点拉取并应用最新配置？', '手动同步')
  if (!ok) return
  syncing.value = true
  try {
    const response = await request.post<APIResponse<ClusterSyncResult>>('/cluster/sync/pull')
    const result = response.data
    if (result) mfaAwareSuccess(result.changed ? `同步完成，已应用版本 ${result.applied_version}` : '当前已是最新配置')
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
  if (isReadOnlyProp.value) return
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
    mfaAwareSuccess('注册令牌已复制')
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
  if (isReadOnlyProp.value) return
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
    mfaAwareSuccess('同步设置已更新')
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
  if (isReadOnlyProp.value) return
  intervalSaving.value = true
  try {
    await request.put<ActionResponse>('/cluster/settings', { sync_interval: value })
    mfaAwareSuccess('同步间隔已更新')
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update sync interval:', error)
  } finally {
    intervalSaving.value = false
  }
}

const runNodeAction = async (node: ClusterNode, action: 'approve' | 'reject' | 'remove'): Promise<void> => {
  if (isReadOnlyProp.value || pendingNodeId.value !== null) return
  pendingNodeId.value = node.id
  try {
    if (action === 'approve') {
      await request.post<ActionResponse>(`/cluster/nodes/${node.id}/approve`)
      mfaAwareSuccess('节点已确认')
    } else if (action === 'reject') {
      await request.post<ActionResponse>(`/cluster/nodes/${node.id}/reject`)
      mfaAwareSuccess('节点已拒绝')
    } else {
      await request.delete<ActionResponse>(`/cluster/nodes/${node.id}`)
      mfaAwareSuccess('节点已删除')
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
  if (isReadOnlyProp.value) return
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
  if (isReadOnlyProp.value || node.status !== 'online' || loginNodeId.value !== null) return
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
  if (isReadOnlyProp.value || accessUrlSaving.value) return
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
  if (!node || isReadOnlyProp.value || accessUrlSaving.value) return
  accessUrlSaving.value = true
  try {
    await request.put<ActionResponse>(`/cluster/nodes/${node.id}/access-url`, { access_url: accessUrl })
    mfaAwareSuccess('访问地址已更新')
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

const clusterPollingError = usePollingErrorState()
const clusterPollingErrorDescription = computed(() => {
  const lastError = formatDate(clusterPollingError.lastErrorAt.value)
  const retryAt = formatDate(clusterPollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const clusterRetrying = ref(false)
const clusterPolling = usePollingTask(async () => {
  if (!clusterPollingError.canRun()) return
  await refreshCluster()
  clusterPollingError.clear()
}, {
  interval: 15000,
  onError: (error) => {
    console.error('Failed to poll cluster status:', error)
    clusterPollingError.recordError(error)
  },
})

const retryClusterPolling = async (): Promise<void> => {
  if (clusterRetrying.value) return
  clusterRetrying.value = true
  clusterPollingError.resetBackoff()
  try {
    await clusterPolling.run()
  } finally {
    clusterRetrying.value = false
  }
}

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
.polling-error-alert { align-self: stretch; }
.polling-error-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%; }
.polling-error-meta { font-size: 12px; }
.token-box { display: flex; align-items: center; gap: 12px; margin-top: 20px; padding: 12px; border-radius: var(--radius-md); background: var(--bg-secondary); }
.token-box code { flex: 1; min-width: 0; color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; word-break: break-all; }

/* ── 服务控制弹框 ── */
.service-control-header { display: flex; flex-direction: column; gap: 6px; }
.service-control-title { display: flex; align-items: center; gap: 8px; font-size: 16px; font-weight: 600; color: var(--text-primary); }
.service-control-node { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text-secondary); }
.service-control-node-name { font-weight: 500; color: var(--text-primary); }
.service-control-node-url { color: var(--text-tertiary); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 280px; }

.service-control-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 16px; }
.service-control-card {
  display: flex; align-items: flex-start; gap: 12px; padding: 14px;
  border: 1px solid var(--border-color, #dcdfe6); border-radius: 8px;
  cursor: pointer; transition: all 0.2s ease; position: relative; background: var(--bg-primary, #fff);
}
.service-control-card:hover { border-color: var(--el-color-primary-light-5, #a0cfff); box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.service-control-card.is-active { border-color: var(--el-color-primary, #409eff); background: var(--el-color-primary-light-9, #ecf5ff); }
.service-control-card.is-active.is-success { border-color: var(--el-color-success, #67c23a); background: var(--el-color-success-light-9, #f0f9eb); }
.service-control-card.is-active.is-danger { border-color: var(--el-color-danger, #f56c6c); background: var(--el-color-danger-light-9, #fef0f0); }
.service-control-card.is-active.is-warning { border-color: var(--el-color-warning, #e6a23c); background: var(--el-color-warning-light-9, #fdf6ec); }

.service-control-card-icon { flex-shrink: 0; display: flex; align-items: center; justify-content: center; width: 40px; height: 40px; border-radius: 8px; }
.is-success .service-control-card-icon { color: var(--el-color-success, #67c23a); background: var(--el-color-success-light-9, #f0f9eb); }
.is-danger .service-control-card-icon { color: var(--el-color-danger, #f56c6c); background: var(--el-color-danger-light-9, #fef0f0); }
.is-warning .service-control-card-icon { color: var(--el-color-warning, #e6a23c); background: var(--el-color-warning-light-9, #fdf6ec); }

.service-control-card-body { flex: 1; min-width: 0; }
.service-control-card-title { font-size: 14px; font-weight: 500; color: var(--text-primary); line-height: 1.4; }
.service-control-card-desc { font-size: 12px; color: var(--text-tertiary, #909399); line-height: 1.4; margin-top: 2px; }

.service-control-card-check { position: absolute; top: 8px; right: 8px; color: var(--el-color-primary, #409eff); font-size: 14px; }
.is-success .service-control-card-check { color: var(--el-color-success, #67c23a); }
.is-danger .service-control-card-check { color: var(--el-color-danger, #f56c6c); }
.is-warning .service-control-card-check { color: var(--el-color-warning, #e6a23c); }

.service-control-warning { margin-top: 14px; }

@media (max-width: 560px) {
  .service-control-grid { grid-template-columns: 1fr; }
}

@media (max-width: 768px) {
  .token-box { align-items: stretch; flex-direction: column; }
}
</style>
