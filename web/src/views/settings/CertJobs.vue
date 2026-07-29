<template>
  <el-table
    v-if="loading || jobs.length > 0"
    :data="jobs"
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
        <span :class="row.ca_provider_name ? 'cell-text' : 'cell-empty'">{{ row.ca_provider_name || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column label="过期时间" width="180">
      <template #default="{ row }">
        <span v-if="row.status === 'issued' && certInfoMap[row.id]" class="cell-text">{{ certInfoMap[row.id].not_after || '-' }}</span>
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
        <span v-if="row.status === 'issued' && certInfoMap[row.id]" class="cell-text">{{ renewalInfo(row).renewalDate || '-' }}</span>
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
        <span v-if="row.status === 'issued' && certInfoMap[row.id]" :class="['cert-days', certInfoMap[row.id].status]">{{ certInfoMap[row.id].days_remaining }} 天</span>
        <span v-else class="cell-empty">-</span>
      </template>
    </el-table-column>
    <el-table-column label="操作" width="120" align="center">
      <template #default="{ row }">
        <el-button link type="primary" size="small" @click="viewLogs(row)">日志</el-button>
        <el-tooltip :disabled="!isReadOnly && !isQueued(row.status)" :content="isReadOnly ? authStore.readOnlyMessage : '排队中的任务无法重签，请等待调度执行'">
          <span>
            <el-button link type="primary" size="small" :disabled="isReadOnly || !canRetry(row.status)" @click="retryJob(row)">重签</el-button>
          </span>
        </el-tooltip>
      </template>
    </el-table-column>
  </el-table>
  <el-empty v-if="!loading && jobs.length === 0" description="暂无签发任务" :image-size="60" />

  <el-dialog
    v-model="logDialogVisible"
    :title="`证书日志 - ${currentJob?.domain || ''}`"
    width="70%"
    :style="{ maxWidth: '70vw' }"
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
      <el-button @click="logDialogVisible = false">关闭</el-button>
      <el-button type="primary" :loading="logLoading" @click="refreshLogs">刷新</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { escapeHtml } from '@/utils/ansi'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import * as pkijs from 'pkijs'
import * as asn1js from 'asn1js'
import type { APIResponse } from '@/types'
import { certJobStatusLabel } from '@/utils/certJobStatus'
import type { CertJobStatus } from '@/utils/certJobStatus'

interface CertJob {
  id: number
  rule_id: string
  domain: string
  status: CertJobStatus
  message: string
  expires_at?: string
  updated_at?: string
  cert_pem?: string
  ca_provider_name?: string
  renewal_attempts?: number
  ca_available_after?: string
  last_error_code?: string
}

interface CertInfo {
  issuer: string
  not_after: string
  days_remaining: number
  status: string
}

const props = defineProps<{
  ruleId?: string
}>()

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const jobs = ref<CertJob[]>([])
const loading = ref(false)
const certInfoMap = ref<Record<number, CertInfo>>({})
const certRenewalDays = ref(30)
let pollTimer: ReturnType<typeof setInterval> | null = null

const logDialogVisible = ref(false)
const logLoading = ref(false)
const logContent = ref('')
const currentJob = ref<CertJob | null>(null)
let logRequestSeq = 0
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
    default: return 'info'
  }
}

const canRetry = (status: CertJobStatus) => {
  return status !== 'queued' && status !== 'pending' && status !== 'disabled'
}

const isQueued = (status: CertJobStatus) => status === 'queued'

const renewalInfo = (row: CertJob): { renewalDate?: string } => {
  const info = certInfoMap.value[row.id]
  if (!info) return {}
  const expiry = new Date(info.not_after)
  if (isNaN(expiry.getTime())) return {}
  const renewal = new Date(expiry.getTime() - certRenewalDays.value * 24 * 60 * 60 * 1000)
  return { renewalDate: formatDate(renewal.toISOString()) }
}

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
  if (loading.value) return
  loading.value = true
  try {
    const [jobsRes, configRes] = await Promise.all([
      request.get('/certificates/jobs', { params: props.ruleId ? { rule_id: props.ruleId } : {} }),
      request.get('/config'),
    ])
    jobs.value = jobsRes.data || []
    certRenewalDays.value = configRes.data?.cert_renewal_days ?? 30
    await fetchCertInfo()
  } catch (error) {
    console.error('Failed to fetch cert jobs:', error)
  } finally {
    loading.value = false
  }
}

const parseCertInfo = (certPEM: string): CertInfo | null => {
  if (!certPEM) return null
  try {
    const match = certPEM.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/)
    if (!match) return null
    const base64 = match[1].replace(/\s/g, '')
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    const asn1 = asn1js.fromBER(bytes.buffer)
    const cert = new pkijs.Certificate({ schema: asn1.result })
    const notAfterValue = cert.notAfter.value as Date
    const notAfter = notAfterValue.toISOString ? notAfterValue.toISOString() : String(notAfterValue)
    const now = new Date()
    const expiry = new Date(notAfterValue)
    const daysRemaining = Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
    const issuerValues: string[] = []
    for (const rdn of cert.issuer.typesAndValues) {
      const value = rdn.value?.valueBlock?.value
      if (value) issuerValues.push(String(value))
    }
    return {
      issuer: issuerValues.join(', ') || '-',
      not_after: formatDate(notAfter),
      days_remaining: daysRemaining,
      status: daysRemaining <= 0 ? 'expired' : (daysRemaining <= 30 ? 'expiring' : 'valid'),
    }
  } catch (e) {
    return null
  }
}

const fetchCertInfo = async () => {
  const issuedJobs = jobs.value.filter(j => j.status === 'issued' && j.cert_pem)
  const newMap: Record<number, CertInfo> = {}
  for (const job of issuedJobs) {
    const info = parseCertInfo(job.cert_pem || '')
    if (info) {
      newMap[job.id] = info
    }
  }
  certInfoMap.value = newMap
}

const retryJob = async (row: CertJob) => {
  if (isReadOnly.value) return
  const isWaitingCA = row.status === 'waiting_ca'
  const message = isWaitingCA
    ? '任务当前处于"等待 CA"状态（可能仍在频率冷却中）。确定要立即重新签发吗？如果使用同一 CA 且冷却未到，可能再次被拒绝。'
    : `确定要对域名 ${row.domain} 重新签发证书吗？`
  try {
    await ElMessageBox.confirm(message, '重签确认', { type: isWaitingCA ? 'warning' : 'info' })
  } catch {
    return
  }
  try {
    await request.post(`/certificates/jobs/${row.id}/retry`)
    ElMessage.success('重新签发已触发')
    fetchJobs()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to retry cert job:', error)
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
  if (!currentJob.value || logLoading.value) return
  const jobId = currentJob.value.id
  const requestSeq = ++logRequestSeq
  logLoading.value = true
  try {
    const res = await request.get<APIResponse<{ content: string }>>(`/certificates/jobs/${jobId}/logs`)
    if (!logDialogVisible.value || currentJob.value?.id !== jobId || requestSeq !== logRequestSeq) return
    logContent.value = res.data?.content || ''
    await scrollToBottom()
  } catch (error) {
    if (logDialogVisible.value && currentJob.value?.id === jobId && requestSeq === logRequestSeq) {
      console.error('Failed to fetch cert job logs:', error)
      ElMessage.error('获取日志失败')
    }
  } finally {
    if (requestSeq === logRequestSeq) logLoading.value = false
  }
}

onMounted(() => {
  fetchJobs()
  pollTimer = setInterval(fetchJobs, 5000)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
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
