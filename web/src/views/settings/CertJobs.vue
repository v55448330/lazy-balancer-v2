<template>
  <el-alert v-if="jobsPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert">
    <template #title>
      <div class="polling-error-title">
        <span>证书任务加载失败：{{ jobsPollingError.errorMessage.value }}</span>
        <el-button link type="danger" :loading="loading" @click="retryJobsPolling">立即重试</el-button>
      </div>
    </template>
    <div class="polling-error-meta">{{ jobsPollingErrorDescription }}</div>
  </el-alert>
  <el-table
    v-if="loading || jobs.length > 0"
    :data="jobs"
    row-key="id"
    size="small"
    v-loading="loading"
    class="cert-jobs-table"
    :fit="true"
  >
    <el-table-column prop="rule_id" label="规则 ID" min-width="110" show-overflow-tooltip />
    <el-table-column prop="domain" label="域名" min-width="180" show-overflow-tooltip />
    <el-table-column prop="status" label="状态" width="90" align="center">
      <template #default="{ row }">
        <el-tag :type="statusType(row.status)" size="small">{{ certJobStatusLabel(row.status) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="颁发者" width="110" show-overflow-tooltip>
      <template #default="{ row }">
        <span :class="row.issuer ? 'cell-text' : 'cell-empty'">{{ row.issuer || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column label="过期时间" width="180">
      <template #default="{ row }">
        <span v-if="row.status === 'issued' && row.expires_at" class="cell-text">{{ formatDate(row.expires_at) || '-' }}</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="更新时间" width="180">
      <template #default="{ row }">
        <span class="cell-text">{{ formatDate(row.updated_at) || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column label="自动重签时间" width="180">
      <template #default="{ row }">
        <span v-if="row.status === 'issued' && row.expires_at" class="cell-text">{{ renewalInfo(row).renewalDate || '-' }}</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="重试次数" width="80" align="center">
      <template #default="{ row }">
        <span v-if="row.renewal_attempts && row.renewal_attempts > 0" class="cell-text">{{ row.renewal_attempts }}</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="冷却时间" min-width="140" show-overflow-tooltip>
      <template #default="{ row }">
        <span v-if="row.status === 'waiting_ca' && row.ca_available_after" class="cell-text">{{ formatCoolingTime(row.ca_available_after) }}</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="剩余天数" width="90">
      <template #default="{ row }">
        <!-- R66 D-N4：过期证书不渲染裸负数——色弱/黑白场景下「-1 天」无文字语义 -->
        <span v-if="row.status === 'issued' && row.expires_at" :class="['cert-days', certificateStatus(row)]">
          {{ certificateStatus(row) === 'expired' ? `已过期 ${Math.abs(row.days_remaining)} 天` : `${row.days_remaining} 天` }}
        </span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="操作" width="120" align="center">
      <template #default="{ row }">
        <el-button link type="primary" size="small" @click="viewLogs(row)">日志</el-button>
        <el-tooltip :disabled="!retryDisabledReason(row)" :content="retryDisabledReason(row)">
          <span>
            <el-button link type="primary" size="small" :loading="retryingJobIds.has(row.id)" :disabled="isReadOnly || !canRetry(row) || retryingJobIds.has(row.id)" @click="retryJob(row)">重签</el-button>
          </span>
        </el-tooltip>
      </template>
    </el-table-column>
  </el-table>
  <el-empty v-if="!loading && jobs.length === 0" description="暂无签发任务" :image-size="60" />
  <div v-if="jobs.length > 0 || currentPage > 1" class="cert-jobs-pagination">
    <el-pagination
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :page-sizes="[10, 20, 50, 100]"
      :total="total"
      layout="total, sizes, prev, pager, next"
      @current-change="jobsPolling.run"
      @size-change="onPageSizeChange"
    />
  </div>

  <el-dialog
    v-model="logDialogVisible"
    :title="`证书日志 - ${currentJob?.domain || ''}`"
    width="min(1100px, 94vw)"
    class="cert-log-dialog"
    destroy-on-close
    @opened="onLogDialogOpened"
    @closed="onLogDialogClosed"
  >
    <div ref="logContainerRef" class="log-container">
      <pre v-if="logHtml" class="log-content" v-html="logHtml" />
      <el-empty v-else description="暂无日志" :image-size="60" />
    </div>
    <template #footer>
      <div style="display: flex; align-items: center;">
        <LogStorageBar v-if="currentJob" :key="currentJob.rule_id" log-key="certjob" :caddy-id="String(currentJob.rule_id)" style="margin-right: auto" />
        <el-button @click="logDialogVisible = false">关闭</el-button>
        <el-button type="primary" :loading="logLoading" @click="refreshLogs">刷新</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue'
import { request } from '@/utils/api'
import LogStorageBar from '@/components/LogStorageBar.vue'
import { formatDate } from '@/utils/date'
import { escapeHtml } from '@/utils/ansi'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse, CertJobsPage } from '@/types'
import { certJobStatusLabel } from '@/utils/certJobStatus'
import type { CertJobStatus } from '@/utils/certJobStatus'
import { usePollingTask } from '@/composables/usePollingTask'
import { usePollingErrorState } from '@/composables/usePollingErrorState'

interface CertJob {
  id: number
  rule_id: string
  domain: string
  status: CertJobStatus
  message: string
  expires_at?: string | null
  updated_at?: string | null
  issuer?: string
  days_remaining: number
  certificate_status: CertificateStatus
  ca_provider_name?: string
  renewal_attempts?: number
  ca_available_after?: string | null
  last_error_code?: string
}

type CertificateStatus = 'expired' | 'expiring' | 'unknown' | 'valid'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
let disposed = false
// （R69 过度修复审查 REMOVE：jobsRequestSeq 已删——入口 loading 门 + disposed
// 析取使其作为裁决条件永不为真，且全部调用经 jobsPolling drain 串行。）

const jobs = ref<CertJob[]>([])
const loading = ref(false)
const certRenewalDays = ref(30)
const currentPage = ref(1)
const pageSize = ref(20)
const total = ref(0)
const retryingJobIds = ref(new Set<number>())

const logDialogVisible = ref(false)
const logLoading = ref(false)
const logContent = ref('')
const currentJob = ref<CertJob | null>(null)
let logRequestSeq = 0
let lastLogErrorToastAt = 0
const logContainerRef = ref<HTMLDivElement | null>(null)
let logPollTimer: ReturnType<typeof setInterval> | null = null

const logHtml = computed(() => {
  if (!logContent.value) return ''
  return escapeHtml(logContent.value)
    .replace(/\[INFO\]/g, '<span style="color:#3b82f6">$&</span>')
    .replace(/\[WARN\]/g, '<span style="color:#eab308">$&</span>')
    .replace(/\[ERROR\]/g, '<span style="color:#ef4444">$&</span>')
    .replace(/\[DEBUG\]/g, '<span style="color:#a855f7">$&</span>')
})

const scrollToBottom = async () => {
  await nextTick()
  if (disposed) return
  if (logContainerRef.value) {
    logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight
  }
}

const statusType = (status: CertJobStatus) => {
  switch (status) {
    case 'issued': return 'success'
    case 'failed': return 'danger'
    case 'disabled': return 'info'
    case 'queued': return 'info'
    case 'waiting_ca': return 'warning'
    case 'pending':
    case 'processing':
    case 'creating_account':
    case 'creating_order':
    case 'order_created':
    case 'waiting_order_ready':
    case 'order_ready':
    case 'cleanup_dns':
    case 'cleanup_warning':
    case 'presenting_dns':
    case 'waiting_propagation':
    case 'dns_propagated':
    case 'accepting_challenge':
    case 'waiting_order_valid':
    case 'order_valid':
    case 'validating':
    case 'validated':
    case 'finalizing':
    case 'finalized':
    case 'downloading':
    case 'downloaded':
      return 'warning'
    // Round 35 I-24: assertNever 在运行时 throw，后端未来新增状态会导致组件崩溃。
    // 改为返回 'info' + console.warn，保证表格始终可渲染。
    default:
      console.warn('Unknown cert job status:', status)
      return 'info'
  }
}

const retryCooldownMinutes = (status: CertJobStatus): number | null => {
  switch (status) {
    case 'disabled': return null
    case 'issued':
    case 'waiting_ca':
      return 0
    case 'queued': return 15
    case 'failed': return 5
    case 'pending':
    case 'processing':
    case 'creating_account':
    case 'creating_order':
    case 'order_created':
    case 'waiting_order_ready':
    case 'order_ready':
    case 'cleanup_dns':
    case 'cleanup_warning':
    case 'presenting_dns':
    case 'waiting_propagation':
    case 'dns_propagated':
    case 'accepting_challenge':
    case 'waiting_order_valid':
    case 'order_valid':
    case 'validating':
    case 'validated':
    case 'finalizing':
    case 'finalized':
    case 'downloading':
    case 'downloaded':
      return 2
    // Round 35 I-24: 同 statusType，避免运行时 throw。
    default:
      console.warn('Unknown cert job status:', status)
      return 0
  }
}

const canRetry = (row: CertJob): boolean => {
  const cooldownMinutes = retryCooldownMinutes(row.status)
  if (cooldownMinutes === null) return false
  if (cooldownMinutes === 0) return true
  const updatedAtValue = row.updated_at
  if (!updatedAtValue) return true
  const updatedAt = new Date(updatedAtValue).getTime()
  if (Number.isNaN(updatedAt)) return true
  return Date.now() - updatedAt >= cooldownMinutes * 60 * 1000
}

const retryDisabledReason = (row: CertJob): string => {
  if (isReadOnly.value) return authStore.readOnlyMessage
  if (row.status === 'disabled') return '已禁用的任务无法重签'
  if (canRetry(row)) return ''
  const cooldownMinutes = retryCooldownMinutes(row.status)
  return `当前状态需等待 ${cooldownMinutes ?? 0} 分钟后重签`
}

const renewalInfo = (row: CertJob): { renewalDate?: string } => {
  if (!row.expires_at) return {}
  const expiry = new Date(row.expires_at)
  if (isNaN(expiry.getTime())) return {}
  const renewal = new Date(expiry.getTime() - certRenewalDays.value * 24 * 60 * 60 * 1000)
  return { renewalDate: formatDate(renewal.toISOString()) }
}

const certificateStatus = (row: CertJob): CertificateStatus => row.certificate_status

const formatCoolingTime = (iso: string): string => {
  const t = new Date(iso)
  const now = new Date()
  const diff = t.getTime() - now.getTime()
  if (diff <= 0) return '可重试'
  const hours = Math.floor(diff / (1000 * 60 * 60))
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
  return `${hours}小时${minutes}分钟后`
}

const fetchJobs = async () => {
  if (disposed || loading.value) return
  loading.value = true
  try {
    const jobsRes = await request.get<APIResponse<CertJobsPage<CertJob>>>('/certificates/jobs', {
      params: { page: currentPage.value, page_size: pageSize.value },
      signal: jobsPolling.signal,
      silent: true,
    })
    if (disposed) return
    if (!jobsRes.data) throw new TypeError('证书任务分页响应缺少 data')
    jobs.value = [...jobsRes.data.list]
    total.value = jobsRes.data.total
    const lastPage = Math.max(1, Math.ceil(total.value / pageSize.value))
    if (currentPage.value > lastPage) {
      currentPage.value = lastPage
      queueMicrotask(() => void jobsPolling.run())
    }
  } finally {
    if (!disposed) loading.value = false
  }
}

const onPageSizeChange = (): void => {
  currentPage.value = 1
  void jobsPolling.run()
}

const retryJob = async (row: CertJob) => {
  if (isReadOnly.value || !canRetry(row) || retryingJobIds.value.has(row.id)) return
  const isWaitingCA = row.status === 'waiting_ca'
  const message = isWaitingCA
    ? '任务当前处于"等待 CA"状态（可能仍在频率冷却中）。确定要立即重新签发吗？如果使用同一 CA 且冷却未到，可能再次被拒绝。'
    : `确定要对域名 ${row.domain} 重新签发证书吗？`
  try {
    await ElMessageBox.confirm(message, '重签确认', { type: isWaitingCA ? 'warning' : 'info' })
  } catch {
    return
  }
  if (disposed || retryingJobIds.value.has(row.id)) return
  retryingJobIds.value = new Set(retryingJobIds.value).add(row.id)
  try {
    await request.post(`/certificates/jobs/${row.id}/retry`, undefined, { signal: jobsPolling.signal })
    if (disposed) return
    ElMessage.success('重新签发已触发')
    await jobsPolling.run()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    if (!disposed) console.error('Failed to retry cert job:', error)
  } finally {
    if (!disposed) {
      const nextRetryingIds = new Set(retryingJobIds.value)
      nextRetryingIds.delete(row.id)
      retryingJobIds.value = nextRetryingIds
    }
  }
}

const viewLogs = async (row: CertJob) => {
  logRequestSeq++
  logLoading.value = false
  currentJob.value = row
  logDialogVisible.value = true
}

const onLogDialogOpened = async () => {
  await refreshLogs()
  startLogPolling()
}

const onLogDialogClosed = () => {
  logRequestSeq++
  stopLogPolling()
  currentJob.value = null
  logContent.value = ''
}

const startLogPolling = () => {
  stopLogPolling()
  logPollTimer = setInterval(refreshLogs, 3000)
}

const stopLogPolling = () => {
  if (logPollTimer) {
    clearInterval(logPollTimer)
    logPollTimer = null
  }
}

const refreshLogs = async () => {
  if (disposed || !currentJob.value || logLoading.value) return
  const jobId = currentJob.value.id
  const requestSeq = ++logRequestSeq
  logLoading.value = true
  try {
    const res = await request.get<APIResponse<{ content: string }>>(`/certificates/jobs/${jobId}/logs`, { signal: jobsPolling.signal, silent: true })
    if (disposed || !logDialogVisible.value || currentJob.value?.id !== jobId || requestSeq !== logRequestSeq) return
    logContent.value = res.data?.content || ''
    await scrollToBottom()
  } catch (error) {
    if (!disposed && logDialogVisible.value && currentJob.value?.id === jobId && requestSeq === logRequestSeq) {
      console.error('Failed to fetch cert job logs:', error)
      // R66 D-N5：toast 节流（对齐 usePollingErrorState 的 30s 语义）——弹窗内
      // 3s 轮询持续失败时不再每 tick 叠加一条「获取日志失败」刷屏。
      const now = Date.now()
      if (now - lastLogErrorToastAt > 30_000) {
        lastLogErrorToastAt = now
        ElMessage.error('获取日志失败')
      }
    }
  } finally {
    if (!disposed && requestSeq === logRequestSeq) logLoading.value = false
  }
}

const jobsPollingError = usePollingErrorState()
const jobsPollingErrorDescription = computed(() => {
  const lastError = formatDate(jobsPollingError.lastErrorAt.value)
  const retryAt = formatDate(jobsPollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const jobsPolling = usePollingTask(async () => {
  if (!jobsPollingError.canRun()) return
  await fetchJobs()
  jobsPollingError.clear()
}, {
  interval: 5000,
  onError: (error) => {
    console.error('Failed to poll certificate jobs:', error)
    jobsPollingError.recordError(error)
  },
})

const retryJobsPolling = async (): Promise<void> => {
  jobsPollingError.resetBackoff()
  await jobsPolling.run()
}

onMounted(async () => {
  try {
    const configRes = await request.get('/config', { signal: jobsPolling.signal })
    if (!disposed) certRenewalDays.value = configRes.data?.cert_renewal_days ?? 30
  } catch (error: unknown) {
    if (!disposed) console.error('Failed to fetch certificate config:', error)
  } finally {
    void jobsPolling.run()
    jobsPolling.start()
  }
})

onUnmounted(() => {
  disposed = true
  logRequestSeq++
  stopLogPolling()
})
</script>

<style scoped>
.log-container {
  max-height: 520px;
  overflow: auto;
  background: #0f172a;
  border-radius: 8px;
  padding: 16px;
  border: 1px solid #1e293b;
}
.log-content {
  margin: 0;
  color: #e2e8f0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
}

.cell-text {
  line-height: 1;
}
.cell-empty {
  color: #9ca3af;
  line-height: 1;
}
.cert-days {
  line-height: 1;
  font-weight: 500;
}
.cert-days.valid {
  color: #10b981;
}
.cert-days.expiring {
  color: #f59e0b;
}
.cert-days.expired {
  color: #ef4444;
}
.cert-jobs-table {
  width: 100%;
}
.cert-jobs-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
.polling-error-alert { margin-bottom: 16px; }
.polling-error-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%; }
.polling-error-meta { font-size: 12px; }
.cert-jobs-table :deep(.el-table__cell) {
  vertical-align: middle;
}
.cert-jobs-table :deep(.el-table__cell .cell) {
  text-align: left;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.cert-jobs-table :deep(.el-table__cell.is-center .cell) {
  text-align: center;
}
.cert-jobs-table :deep(.el-button + .el-button) {
  margin-left: 6px;
}
</style>
