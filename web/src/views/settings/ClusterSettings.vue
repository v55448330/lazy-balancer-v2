<template>
  <div class="cluster-settings">
    <el-alert v-if="clusterPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
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
          :registration-succeeded="registrationSucceeded"
          :read-only="isReadOnlyProp"
          :interval-saving="clusterSettingsSaving"
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
          :settings-loading="clusterSettingsSaving"
          :pending-node-id="pendingNodeId"
          :login-node-id="loginNodeId"
          :read-only="isReadOnlyProp || status?.node_mode === 'slave'"
          @generate-token="generateRegisterToken"
          @update-sync-field="updateSyncField"
          @approve="approveNode"
          @reject="rejectNode"
          @remove="removeNode"
          @login="loginNode"
          @service-control="openServiceControlDialog"
          @edit-config="openNodeConfigDialog"
        />
      </el-col>
    </el-row>

    <ClusterMasterPanel
      v-if="status?.node_mode === 'master'"
      :status="status"
      :nodes="nodes"
      :loading="nodesLoading"
      :token-loading="tokenLoading"
      :settings-loading="clusterSettingsSaving"
      :pending-node-id="pendingNodeId"
      :login-node-id="loginNodeId"
      :read-only="isReadOnlyProp"
      @generate-token="generateRegisterToken"
      @update-sync-field="updateSyncField"
      @approve="approveNode"
      @reject="rejectNode"
      @remove="removeNode"
      @login="loginNode"
      @service-control="openServiceControlDialog"
      @edit-config="openNodeConfigDialog"
    />

    <ClusterSlavePanel
      v-if="status && status.node_mode !== 'master'"
      :status="status"
      :syncing="syncing"
      :promoting="promoting"
      :forgetting-pins="forgettingPins"
      :read-only="isReadOnlyProp"
      @sync="syncNow"
      @promote="promoteToMaster"
      @reregister="requestRegistration"
      @forget-pins="forgetPins"
    />

    <ClusterNodeConfigDialog
      :visible="nodeConfigDialogVisible"
      :node="editingNodeConfigLive"
      :saving="nodeConfigSaving"
      @close="closeNodeConfigDialog"
      @save="updateNodeConfig"
    />

    <el-dialog v-model="tokenDialogVisible" width="min(560px, 92vw)" :close-on-click-modal="false" :before-close="closeTokenDialog" @closed="registerToken = null" class="register-token-dialog">
      <template #header>
        <DialogHeader :icon="Key" title="一次性注册令牌" subtitle="仅展示一次，请立即复制并妥善保存" tone="warning" />
      </template>
      <div class="dialog-panel token-box">
        <code>{{ registerToken?.token }}</code>
        <el-button type="primary" @click="copyRegisterToken">
          <el-icon><CopyDocument /></el-icon>复制令牌
        </el-button>
      </div>
      <div class="form-tip-line token-expiry">有效期至：{{ formatDate(registerToken?.expires_at ?? '') || '-' }}</div>
      <template #footer><el-button type="primary" @click="tokenDialogVisible = false">我已保存</el-button></template>
    </el-dialog>

    <el-dialog v-model="serviceControlDialogVisible" class="service-control-dialog dialog-body-inset" width="min(520px, 92vw)" :close-on-click-modal="false" :close-on-press-escape="!serviceControlLoading" :show-close="!serviceControlLoading">
      <template #header>
        <div class="service-control-header">
          <DialogHeader
            :icon="Monitor"
            title="服务控制"
            :subtitle="serviceControlNodeLive ? `${serviceControlNodeLive.name} · ${serviceControlNodeLive.access_url || `${serviceControlNodeLive.ip_address}:${serviceControlNodeLive.port}`}` : undefined"
          />
          <el-tag v-if="serviceControlNodeLive" class="service-control-status" :type="serviceControlNodeLive.status === 'online' ? 'success' : 'info'" size="small">{{ serviceControlNodeLive.status === 'online' ? '在线' : '离线' }}</el-tag>
        </div>
      </template>

      <div class="service-control-grid" role="radiogroup" aria-label="服务控制操作">
        <div
          v-for="item in serviceControlOptions"
          :key="item.value"
          class="service-control-card"
          :class="{ 'is-active': serviceControlAction === item.value, [`is-${item.tone}`]: true }"
          role="radio"
          :aria-checked="serviceControlAction === item.value"
          :tabindex="serviceControlTabindex(item.value)"
          :ref="(el: unknown) => setServiceCardRef(item.value, el)"
          @click="selectServiceAction(item.value)"
          @keydown="onServiceCardKeydown($event)"
          @keydown.enter.prevent="activateOnce($event, () => selectServiceAction(item.value))"
          @keydown.space.prevent="activateOnce($event, () => selectServiceAction(item.value))"
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
        <div v-if="hasOwn(serviceControlWarnings, serviceControlAction)" class="info-note-bar service-control-warning"><span class="info-note-desc">{{ serviceControlWarnings[serviceControlAction] }}</span></div>
      </transition>

      <!-- 服务控制返回证书指纹不匹配时提供按节点重钉通道（与从节点侧
           forget-pins 补救对称）；确认后调用 POST /cluster/nodes/:id/forget-pin。 -->
      <transition name="el-fade-in">
        <div v-if="serviceControlPinMismatch" class="info-note-bar service-control-warning">
          <span class="info-note-desc">从节点证书指纹不匹配</span>
          <span class="info-note-sub">该节点管理面板证书可能已更换。清除本节点对其的证书指纹钉后，下次服务控制将按其当前证书重新验证。</span>
          <span class="info-note-sub"><el-button type="danger" plain size="small" :loading="nodePinForgetting" :disabled="nodePinForgetting" @click="forgetNodePin">清除该节点证书指纹</el-button></span>
        </div>
      </transition>

      <template #footer>
        <el-button :disabled="serviceControlLoading" @click="serviceControlDialogVisible = false">取消</el-button>
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
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { CopyDocument, Key, Monitor, RefreshRight, Select, VideoPause, VideoPlay } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { request, mfaAwareSuccess } from '@/utils/api'
import { copyText } from '@/utils/copy'
import { CLUSTER_SYNC_SWITCHES } from '@/utils/clusterSyncSwitches'
import { clusterWriteBlocked } from '@/utils/clusterWriteGate'
import { createOneTimeSecretCloseGuard } from '@/utils/oneTimeSecretGuard'
import { formatDate } from '@/utils/date'
import type {
  APIResponse,
  ClusterModeResult,
  ClusterNode,
  ClusterNodeWithSyncError,
  ClusterRegisterToken,
  ClusterRegistrationInput,
  ClusterStatus,
  ClusterSyncResult,
} from '@/types'
import ClusterMasterPanel from './cluster/ClusterMasterPanel.vue'
import ClusterNodeConfigDialog from './cluster/ClusterNodeConfigDialog.vue'
import ClusterModeCard from './cluster/ClusterModeCard.vue'
import ClusterSlavePanel from './cluster/ClusterSlavePanel.vue'
import ClusterStatusCard from './cluster/ClusterStatusCard.vue'
import { usePollingTask } from '@/composables/usePollingTask'
import { usePollingErrorState } from '@/composables/usePollingErrorState'
import { activateOnce } from '@/utils/keyboardActivate'
import { hasOwn } from '@/utils/hasOwn'
import { nextRadioValue, rovingTabindex } from '@/utils/rovingRadio'

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
// fetchNodes 独立计数器——updateNodeConfig 的手动刷新若与 fetchStatus 共享
// requestSequence，会顶掉轮询在途 fetchStatus 的序列号，导致状态响应被当作过期丢弃
let nodesRequestSequence = 0
const status = ref<ClusterStatus | null>(null)
const nodes = ref<readonly ClusterNodeWithSyncError[]>([])
const initialLoading = ref(true)
const nodesLoading = ref(false)
const modeLoading = ref(false)
const tokenLoading = ref(false)
// 同步设置写通道单飞：开关（updateSyncField）与间隔（updateSyncInterval）都写
// PUT /cluster/settings——共用一个 saving 态，二者在途时互斥且 loading 同源。
const clusterSettingsSaving = ref(false)
const syncing = ref(false)
const promoting = ref(false)
const pendingNodeId = ref<number | null>(null)
const loginNodeId = ref<number | null>(null)
const nodeConfigDialogVisible = ref(false)
const editingNodeConfig = ref<ClusterNode | null>(null)
// 弹框基线随 15s 轮询更新：按 id 回查最新节点行；查不到（刚被删除）再退回
// 打开时快照，避免弹框瞬间清空。子组件只在字段未被编辑时回填，不覆盖用户输入。
const editingNodeConfigLive = computed<ClusterNode | null>(() => {
  const snapshot = editingNodeConfig.value
  if (!snapshot) return null
  return nodes.value.find((node) => node.id === snapshot.id) ?? snapshot
})
const nodeConfigSaving = ref(false)
const registrationRequest = ref(0)
// 注册请求被主节点受理后递增——子组件据此清空已消耗的一次性令牌
//（取消确认或请求失败时令牌仍可能有效，必须保留）。
const registrationSucceeded = ref(0)
const tokenDialogVisible = ref(false)

const serviceControlDialogVisible = ref(false)
const serviceControlNode = ref<ClusterNode | null>(null)
const serviceControlAction = ref('')
const serviceControlLoading = ref(false)
const serviceControlPinMismatch = ref(false)
const nodePinForgetting = ref(false)

// serviceControlNode 是打开弹框时的快照；15s 轮询会整体替换 nodes 数组，
// 快照里的 status/name 会逐渐失真（典型：节点已恢复在线仍显示「离线」）。
// computed 按 id 回查最新行，查不到（节点刚被删除等）再退回快照兜底。
const serviceControlNodeLive = computed<ClusterNode | null>(() => {
  if (!serviceControlNode.value) return null
  const live = nodes.value.find(n => n.id === serviceControlNode.value?.id)
  return live ?? serviceControlNode.value
})

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

// 服务控制卡片是自定义单选组（role=radiogroup + role=radio）：整组只有一个
// tab stop（roving tabindex），方向键移动并切换——原生 radio 组/APG 语义，
// 不再要求四张卡片逐个 Tab 且方向键无效。
const serviceCardRefs = new Map<string, HTMLElement>()
const setServiceCardRef = (value: string, el: unknown): void => {
  if (el instanceof HTMLElement) serviceCardRefs.set(value, el)
  else serviceCardRefs.delete(value)
}
const serviceControlTabindex = (value: string): number =>
  rovingTabindex(serviceControlOptions.map((item) => item.value), serviceControlAction.value, () => false, value)
const selectServiceAction = (value: string): void => {
  if (serviceControlLoading.value) return // 指令在途时冻结选择，避免与已下发动作错位
  serviceControlAction.value = value
}
const onServiceCardKeydown = (event: KeyboardEvent): void => {
  if (event.repeat) return
  const next = nextRadioValue(serviceControlOptions.map((item) => item.value), serviceControlAction.value, () => false, event.key)
  if (next === null) return
  event.preventDefault()
  selectServiceAction(next)
  serviceCardRefs.get(next)?.focus()
}

const openServiceControlDialog = (node: ClusterNode): void => {
  serviceControlNode.value = node
  serviceControlAction.value = ''
  serviceControlPinMismatch.value = false
  serviceControlDialogVisible.value = true
}

const executeServiceControl = async (): Promise<void> => {
  if (isReadOnlyProp.value) return
  if (!serviceControlNode.value || !serviceControlAction.value) return
  // 占位先于确认——双击「执行操作」不再叠加两个确认框/重复下发。
  if (serviceControlLoading.value) {
    ElMessage.warning('服务控制请求正在执行，请稍候')
    return
  }
  serviceControlLoading.value = true
  try {
    // 2026-09-20 用户裁定:执行服务控制前必须二次确认(停止 Caddy/重启应用
    // 会中断从节点服务),复用本文件 confirmAction(与清除指纹钉同格)。
    const option = serviceControlOptions.find((o) => o.value === serviceControlAction.value)
    const nodeName = serviceControlNodeLive.value?.name ?? `#${serviceControlNode.value.id}`
    const confirmed = await confirmAction(
      `确定对节点“${nodeName}”执行「${option?.label ?? serviceControlAction.value}」吗？${option?.description ?? ''}`,
      '服务控制确认',
    )
    if (!confirmed) return
    await request.post(`/cluster/nodes/${serviceControlNode.value.id}/service`, { action: serviceControlAction.value })
    serviceControlDialogVisible.value = false
    serviceControlPinMismatch.value = false
    mfaAwareSuccess('服务控制指令已下发')
  } catch (error: unknown) {
    // 全局拦截器已弹 toast；428 MFA 重试也由全局处理。
    // 指纹不匹配（后端 502 专属文案）在弹框内提供按节点重钉通道。
    if (error instanceof Error && error.message.includes('证书指纹不匹配')) {
      serviceControlPinMismatch.value = true
    }
    console.error('service control failed', error)
  } finally {
    serviceControlLoading.value = false
  }
}

// 清除该节点的 TOFU 证书指纹钉（POST /cluster/nodes/:id/forget-pin），
// 成功后留在弹框内便于直接重试服务控制。
const forgetNodePin = async (): Promise<void> => {
  const node = serviceControlNodeLive.value
  if (isReadOnlyProp.value || !node || nodePinForgetting.value) return
  // 占位先于确认（原确认后才置位——双击叠加确认框/重复请求）
  nodePinForgetting.value = true
  try {
    const confirmed = await confirmAction(
      `确定清除对节点“${node.name}”的证书指纹钉吗？下次服务控制将按该节点当前证书重新验证并钉扎。`,
      '清除节点证书指纹',
    )
    if (!confirmed) return
    const response = await request.post<ActionResponse>(`/cluster/nodes/${node.id}/forget-pin`)
    mfaAwareSuccess(response.message || '已清除该节点的证书指纹，下次服务控制将按其当前证书重新钉扎')
    serviceControlPinMismatch.value = false
    await fetchNodes().catch((error: unknown) => console.error('Failed to refresh cluster nodes:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast；这里仅记录避免 unhandled rejection
    console.error('Failed to forget node pin:', error)
  } finally {
    nodePinForgetting.value = false
  }
}
const registerToken = ref<ClusterRegisterToken | null>(null)
/** 注册令牌仅此一次下发：ESC / 右上角 X 不得静默关闭（与 API 密钥明文、
 *  MFA 恢复码同一守卫单源）。确认后才关闭，@closed 清空内存里的令牌。 */
const closeTokenDialog = createOneTimeSecretCloseGuard({
  message: '注册令牌仅此一次显示，关闭后将无法再次查看。已复制并妥善保存？',
  title: '保存注册令牌',
})

// 同一设置页跨账号复用时，一次性凭据不得留给下一位登录用户；
// watch 仅在 user.id 实际变化时触发，同账号资料刷新不影响已打开弹框。
watch(() => authStore.user?.id, () => {
  registerToken.value = null
  tokenDialogVisible.value = false
})
// 写门单源在 utils/clusterWriteGate（角色独立参与）：stores/auth 的
// readOnlyReason 先判节点模式，从节点上任何角色都只得到 'slave'——只按 reason
// 集合判会漏掉「从节点 + 非管理员」，把破坏性按钮呈现为可写（点击 403）。
// unknown（信息未就绪）fail-closed；从节点 admin 仍可操作集群管理。
const isReadOnlyProp = computed(() => clusterWriteBlocked({
  readOnlyReason: authStore.readOnlyReason,
  role: authStore.user?.role,
}))
const clusterModeChanging = computed(() => syncing.value || promoting.value || modeLoading.value)
const fetchStatus = async (roundSignal?: AbortSignal): Promise<ClusterStatus> => {
  const requestSeq = ++requestSequence
  const response = await request.get<APIResponse<ClusterStatus>>('/cluster/status', { signal: roundSignal ?? clusterPolling.signal, silent: true })
  const data = response.data
  // 协议违例用 TypeError（Error 保留给业务失败）。
  if (!data) throw new TypeError('集群状态响应缺少数据')
  if (!disposed && requestSeq === requestSequence) {
    status.value = data
    authStore.setNodeMode(data.node_mode)
  }
  return data
}

const fetchNodes = async (roundSignal?: AbortSignal): Promise<void> => {
  if (disposed) return
  const requestSeq = ++nodesRequestSequence
  nodesLoading.value = true
  try {
    const response = await request.get<APIResponse<readonly ClusterNodeWithSyncError[]>>('/cluster/nodes', { signal: roundSignal ?? clusterPolling.signal, silent: true })
    if (!disposed && requestSeq === nodesRequestSequence) nodes.value = response.data ?? []
  } finally {
    if (!disposed && requestSeq === nodesRequestSequence) nodesLoading.value = false
  }
}

const refreshCluster = async (roundSignal?: AbortSignal): Promise<void> => {
  if (disposed) return
  const currentStatus = await fetchStatus(roundSignal)
  if (disposed) return
  if (currentStatus.node_mode === 'master') {
    await fetchNodes(roundSignal)
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
    registrationSucceeded.value += 1
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
    // Promote 在途同步排空(含 apply+Caddy 重载)可超默认 30s——
    // 放大至 120s,防前端超时误报失败诱导重复点击(后端随后实际成功)。
    await request.post<ActionResponse>('/cluster/promote', undefined, { timeout: 120000 })
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
  if (isReadOnlyProp.value) return
  // 占位先于确认——双击「立即同步」不再叠加确认框或重复拉取。
  if (syncing.value) {
    ElMessage.warning('同步请求正在执行，请稍候')
    return
  }
  if (clusterModeChanging.value) return
  syncing.value = true
  try {
    const ok = await confirmAction('立即从主节点拉取并应用最新配置？', '手动同步')
    if (!ok) return
    // /cluster/sync/pull 同样含「拉快照 → 应用 → Caddy 重载」，与
    // Promote 同口径放大到 120s——沿用全局 30s 会在后端成功时先超时误报失败，
    // 诱导用户重复点击（后端可能仍在应用）。
    const response = await request.post<APIResponse<ClusterSyncResult>>('/cluster/sync/pull', undefined, { timeout: 120000 })
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

// PinMismatch 补救入口——主节点更换管理面板证书后从节点同步持续指纹不匹配，
// 「重新注册」复用同一 TOFU transport 无法自救；清空本节点 TOFU 指纹钉
// （POST /cluster/forget-pins）后，下一同步周期按主节点当前证书重新验证并钉扎。
const forgettingPins = ref(false)
const forgetPins = async (): Promise<void> => {
  if (isReadOnlyProp.value) return
  // 占位先于确认（原确认后才置位——双击叠加确认框/重复请求）
  if (forgettingPins.value) {
    ElMessage.warning('清除指纹请求正在执行，请稍候')
    return
  }
  forgettingPins.value = true
  try {
    if (!(await confirmAction(
      '将清除本节点保存的全部主节点 TLS 证书指纹钉（TOFU），下一同步周期将按主节点当前证书重新验证并钉扎。是否继续？',
      '清除证书指纹',
    ))) return
    await request.post<ActionResponse>('/cluster/forget-pins')
    mfaAwareSuccess('已清除全部主节点证书指纹，下次同步将按当前证书重新钉扎')
    // 刷新状态：last_sync_error 的 pin_mismatch 将随下一同步周期成功而自清
    await clusterPolling.run()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast；这里仅记录避免 unhandled rejection
    console.error('Failed to forget cluster pins:', error)
  } finally {
    forgettingPins.value = false
  }
}

const generateRegisterToken = async (): Promise<void> => {
  // 重入守卫：同一 tick 内的双击不会等渲染出 loading —— 每枚令牌独立入库且
  // 一次性有效，两次请求会留下第二枚界面再也查不到的令牌（凭据卫生）。
  // 「占位先于确认」与本文件其余写入口同构。
  if (isReadOnlyProp.value || tokenLoading.value) return
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
  // 复用 utils/copy 的 copyText（降级路径/类型收口与全站一致）。
  const ok = await copyText(token)
  if (ok) {
    mfaAwareSuccess('注册令牌已复制')
  } else {
    ElMessage.error('复制失败，请手动复制注册令牌')
  }
}

// 三分类标签单源 utils/clusterSyncSwitches（与 ClusterMasterPanel 开关行同源，
// 原父子各持一份字面量，改名/新增必漏一侧致确认文案与实际开关不符）。
const syncSwitchLabels: Record<string, string> = Object.fromEntries(
  CLUSTER_SYNC_SWITCHES.map((item) => [item.key, item.label]),
)

const updateSyncField = async (field: string, value: boolean): Promise<void> => {
  if (isReadOnlyProp.value) return
  // 占位先于确认（双击开关不再叠加确认框/重复 PUT）；取消路径回读状态
  // 复位开关显示。
  if (clusterSettingsSaving.value) {
    ElMessage.warning('同步设置正在保存，请稍候')
    return
  }
  const label = hasOwn(syncSwitchLabels, field) ? syncSwitchLabels[field] : field
  const action = value ? '开启' : '关闭'
  clusterSettingsSaving.value = true
  try {
    const confirmed = await confirmAction(
      `确定要${action}「${label}」的集群同步吗？${value ? '开启后主节点该类变更将同步到所有从节点。' : '关闭后从节点将保留本地数据，不再接收主节点该类变更。'}`,
      '同步设置确认',
    )
    if (!confirmed) {
      await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
      return
    }
    await request.put<ActionResponse>('/cluster/settings', { [field]: value })
    mfaAwareSuccess('同步设置已更新')
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update sync field:', error)
    await fetchStatus().catch((refreshError: unknown) => console.error('Failed to refresh cluster status:', refreshError))
  } finally {
    clusterSettingsSaving.value = false
  }
}

const updateSyncInterval = async (value: number | null | undefined): Promise<void> => {
  if (isReadOnlyProp.value) return
  // 空值不得直发：后端把缺失的 sync_interval 当成「未提供」（保持现值）并回
  // 200——界面会提示「同步间隔已更新」而实际未改。写侧与卡片提交门同口径拒绝。
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    ElMessage.warning('请输入 10–86400 之间的同步间隔')
    return
  }
  // 与开关保存共用同一写通道门（并发落库会互相覆盖 sync_interval/开关字段）
  if (clusterSettingsSaving.value) {
    ElMessage.warning('同步设置正在保存，请稍候')
    return
  }
  clusterSettingsSaving.value = true
  try {
    await request.put<ActionResponse>('/cluster/settings', { sync_interval: value })
    mfaAwareSuccess('同步间隔已更新')
    await fetchStatus().catch((error: unknown) => console.error('Failed to refresh cluster status:', error))
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update sync interval:', error)
  } finally {
    clusterSettingsSaving.value = false
  }
}

// 「入口取占位 → 确认 → 请求 → finally 释放」。占位（pendingNodeId）必须
// 先于确认弹框取得——原实现在确认之后才占位，双击审批/拒绝/删除会叠加两个确认框，
// 确认第二个时动作被静默丢弃（用户以为已处理）。与 TaskMonitor.runTaskAction
// 同范式。
const runNodeAction = async (node: ClusterNode, action: 'approve' | 'reject' | 'remove'): Promise<void> => {
  // 占位已由调用方取得；本函数只负责请求与释放。
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
    if (pendingNodeId.value === node.id) pendingNodeId.value = null
  }
}

const confirmAndRunNodeAction = async (
  node: ClusterNode,
  action: 'approve' | 'reject' | 'remove',
  message: string,
  title: string,
): Promise<void> => {
  if (isReadOnlyProp.value) return
  if (pendingNodeId.value !== null) {
    ElMessage.warning('节点操作正在进行，请稍候')
    return
  }
  pendingNodeId.value = node.id
  try {
    if (!(await confirmAction(message, title))) return
    await runNodeAction(node, action)
  } finally {
    if (pendingNodeId.value === node.id) pendingNodeId.value = null
  }
}

// 审批是三个节点操作中安全面最大的「信任授予」动作（确认后外部节点
// 入集群并开始同步），与拒绝/删除对称补二次确认，防 pending 列表误点。
const approveNode = (node: ClusterNode): Promise<void> =>
  confirmAndRunNodeAction(node, 'approve', `确定确认节点“${node.name}”加入集群吗？确认后该节点将开始同步。`, '审批确认')

const requestRegistration = (): void => {
  if (isReadOnlyProp.value) return
  registrationRequest.value += 1
}

const rejectNode = (node: ClusterNode): Promise<void> =>
  confirmAndRunNodeAction(node, 'reject', `确定拒绝节点“${node.name}”吗？`, '拒绝确认')

const removeNode = (node: ClusterNode): Promise<void> =>
  confirmAndRunNodeAction(node, 'remove', `确定删除节点“${node.name}”吗？删除后该节点将无法继续同步。`, '删除确认')

const loginNode = async (node: ClusterNode): Promise<void> => {
  if (isReadOnlyProp.value || node.status !== 'online' || loginNodeId.value !== null) return
  // 403（未启用 MFA）预检——文案指向正确入口（用户管理）。
  // v2.3.0:OIDC 会话豁免(与后端 cluster_ticket 两道门同口径)——二因子
  // 由 IdP 承担,本地 MFA 概念不适用。
  if (!authStore.user?.mfa_enabled && authStore.user?.auth_provider !== 'oidc') {
    ElMessage.warning('登录从节点需先启用 MFA（在「系统设置 → 用户管理」中对自己的账号绑定）')
    return
  }
  loginNodeId.value = node.id
  try {
    // （用户反馈：先弹验证码再开页面）：票据请求先行、开窗后置——
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

const openNodeConfigDialog = (node: ClusterNode): void => {
  if (isReadOnlyProp.value || nodeConfigSaving.value) return
  editingNodeConfig.value = node
  nodeConfigDialogVisible.value = true
}

const closeNodeConfigDialog = (): void => {
  if (nodeConfigSaving.value) return
  nodeConfigDialogVisible.value = false
  editingNodeConfig.value = null
}

const updateNodeConfig = async (payload: { accessUrl: string; lat: number; lon: number; siteChanged: boolean }): Promise<void> => {
  const node = editingNodeConfigLive.value
  if (!node || isReadOnlyProp.value || nodeConfigSaving.value) return
  nodeConfigSaving.value = true
  try {
    // 两个写端点在权限/MFA 上同构；顺序提交，任一失败保留弹框与已完成项，
    // 重试时同值写入为 no-op（站点坐标仅在真实变更时提交，不 bump 集群版本）。
    const accessChanged = payload.accessUrl !== (node.access_url ?? '')
    if (accessChanged) {
      await request.put<ActionResponse>(`/cluster/nodes/${node.id}/access-url`, { access_url: payload.accessUrl })
    }
    if (payload.siteChanged) {
      await request.put<ActionResponse>(`/cluster/nodes/${node.id}/site`, {
        server_map_lat: payload.lat,
        server_map_lon: payload.lon,
      })
    }
    if (accessChanged && payload.siteChanged) {
      mfaAwareSuccess('节点配置已更新，站点坐标下一同步周期生效')
    } else if (accessChanged) {
      mfaAwareSuccess('访问地址已更新')
    } else {
      mfaAwareSuccess('节点站点坐标已保存，下一同步周期生效')
    }
    nodeConfigDialogVisible.value = false
    editingNodeConfig.value = null
    await fetchNodes()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to update node config:', error)
  } finally {
    nodeConfigSaving.value = false
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
const clusterPolling = usePollingTask(async (task) => {
  if (!clusterPollingError.canRun()) return
  await refreshCluster(task.signal)
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
  nodesRequestSequence++
})
</script>

<style scoped>
/* el-card 高度由全局 .equal-height-row（main.css）供给，此处不重复声明 */
.equal-height-row :deep(.el-card__body) { height: 100%; box-sizing: border-box; }
.cluster-settings { display: flex; flex-direction: column; gap: 20px; }
.polling-error-alert { align-self: stretch; }
/* .polling-error-title/.polling-error-meta 已收敛 main.css*/
.token-box { display: flex; align-items: center; gap: 12px; margin-top: 4px; }
.token-expiry { margin-top: 10px; }

.token-box code { flex: 1; min-width: 0; color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; word-break: break-all; }

/* ── 服务控制弹框 ── */
.service-control-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.service-control-status { flex: none; }

.service-control-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 16px; }
.service-control-card {
  display: flex; align-items: flex-start; gap: 12px; padding: 14px;
  border: 1px solid var(--border-color, #dcdfe6); border-radius: 8px;
  cursor: pointer; transition: all 0.2s ease; position: relative; background: var(--bg-primary, #fff);
}
.service-control-card:hover { border-color: var(--el-color-primary-light-5, #a0cfff); box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.service-control-card:focus-visible { border-color: var(--el-color-primary, #409eff); outline: none; }
.service-control-card.is-active { border-color: var(--el-color-primary, #409eff); background: var(--el-color-primary-light-9, #ecf5ff); }
.service-control-card.is-active.is-success { border-color: var(--el-color-success, #67c23a); background: var(--el-color-success-light-9, #f0f9eb); }
.service-control-card.is-active.is-danger { border-color: var(--el-color-danger, #f56c6c); background: var(--el-color-danger-light-9, #fef0f0); }
.service-control-card.is-active.is-warning { border-color: var(--el-color-warning, #e6a23c); background: var(--el-color-warning-light-9, #fdf6ec); }

.service-control-card-icon { flex-shrink: 0; display: flex; align-items: center; justify-content: center; width: 40px; height: 40px; border-radius: 0; }
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
