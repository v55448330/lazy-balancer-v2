<template>
  <el-table v-if="loading || jobs.length > 0" :data="jobs" size="small" v-loading="loading">
    <el-table-column prop="rule_id" label="规则 ID" width="120" show-overflow-tooltip />
    <el-table-column prop="domain" label="域名" min-width="180" show-overflow-tooltip />
    <el-table-column prop="status" label="状态" width="100" align="center">
      <template #default="{ row }">
        <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="证书信息" min-width="260" show-overflow-tooltip>
      <template #default="{ row }">
        <div v-if="row.status === 'issued' && certInfoMap[row.id]" class="cert-info-cell">
          <div class="cert-info-line">
            <span class="cert-info-label">颁发者</span>
            <span class="cert-info-value" :title="certInfoMap[row.id].issuer">{{ certInfoMap[row.id].issuer || '-' }}</span>
          </div>
          <div class="cert-info-line">
            <span class="cert-info-label">过期时间</span>
            <span class="cert-info-value">{{ certInfoMap[row.id].not_after || '-' }}</span>
          </div>
          <div class="cert-info-line">
            <span class="cert-info-label">更新时间</span>
            <span class="cert-info-value">{{ formatDate(row.updated_at) }}</span>
          </div>
          <div class="cert-info-line">
            <span class="cert-info-label">剩余天数</span>
            <span :class="['cert-days', certInfoMap[row.id].status]">{{ certInfoMap[row.id].days_remaining }} 天</span>
          </div>
        </div>
        <span v-else-if="row.status === 'failed'" class="cert-error">{{ row.message }}</span>
        <span v-else class="text-secondary">{{ row.message || statusLabel(row.status) }}</span>
      </template>
    </el-table-column>
    <el-table-column label="操作" width="160" align="center">
      <template #default="{ row }">
        <el-button link type="primary" size="small" @click="viewLogs(row)">查看日志</el-button>
        <el-button link type="primary" size="small" @click="retryJob(row)">重试</el-button>
        <el-button link type="danger" size="small" @click="deleteJob(row)">删除</el-button>
      </template>
    </el-table-column>
  </el-table>
  <el-empty v-if="!loading && jobs.length === 0" description="暂无签发任务" :image-size="60" />

  <el-dialog
    v-model="logDialogVisible"
    :title="`证书日志 - ${currentJob?.domain || ''}`"
    width="900px"
    destroy-on-close
    @opened="onLogDialogOpened"
    @closed="onLogDialogClosed"
  >
    <div ref="logContainerRef" class="log-container">
      <pre v-if="formattedLogs" class="log-content">{{ formattedLogs }}</pre>
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
import { ElMessage, ElMessageBox } from 'element-plus'
import * as pkijs from 'pkijs'
import * as asn1js from 'asn1js'

interface CertJob {
  id: number
  rule_id: string
  domain: string
  status: string
  message: string
  expires_at?: string
  updated_at?: string
  cert_pem?: string
}

interface CertInfo {
  issuer: string
  not_after: string
  days_remaining: number
  status: string
}

interface CertJobLog {
  id: number
  job_id: number
  level: string
  message: string
  created_at: string
}

const props = defineProps<{
  ruleId?: string
}>()

const jobs = ref<CertJob[]>([])
const loading = ref(false)
const certInfoMap = ref<Record<number, CertInfo>>({})
let pollTimer: ReturnType<typeof setInterval> | null = null

const logDialogVisible = ref(false)
const logLoading = ref(false)
const logLines = ref<CertJobLog[]>([])
const currentJob = ref<CertJob | null>(null)
const logContainerRef = ref<HTMLDivElement | null>(null)
let logPollTimer: ReturnType<typeof setInterval> | null = null

const ansiRegex = /[\u001B\u009B][[\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\d\/#&.:=?%@~_]+)*|[a-zA-Z\d]+(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g

const formatLogLine = (log: CertJobLog) => {
  const ts = log.created_at ? formatDate(log.created_at) : '-'
  return `[${ts}] [${log.level.toUpperCase()}] ${log.message}`
}

const formattedLogs = computed(() => {
  return logLines.value
    .map(formatLogLine)
    .map(line => line.replace(ansiRegex, '').trimEnd())
    .join('\n')
})

const scrollToBottom = async () => {
  await nextTick()
  if (logContainerRef.value) {
    logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight
  }
}

const statusType = (status: string) => {
  switch (status) {
    case 'issued': return 'success'
    case 'failed': return 'danger'
    case 'pending':
    case 'creating_account':
    case 'creating_order':
    case 'order_created':
    case 'presenting_dns':
    case 'dns_propagated':
    case 'validating':
    case 'finalizing':
    case 'downloading':
      return 'warning'
    default: return 'info'
  }
}

const statusLabel = (status: string) => {
  switch (status) {
    case 'issued': return '已签发'
    case 'failed': return '失败'
    case 'pending': return '待处理'
    case 'creating_account': return '创建账户'
    case 'creating_order': return '创建订单'
    case 'order_created': return '订单已创建'
    case 'presenting_dns': return '设置 DNS'
    case 'dns_propagated': return 'DNS 已传播'
    case 'validating': return '验证中'
    case 'finalizing': return '最终化'
    case 'downloading': return '下载证书'
    default: return status
  }
}

const fetchJobs = async () => {
  loading.value = true
  try {
    const params: any = {}
    if (props.ruleId) params.rule_id = props.ruleId
    const res = await request.get('/certificates/jobs', { params })
    jobs.value = res.data || []
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
    const notAfterValue = cert.notAfter.value
    const notAfter = notAfterValue.toLocaleString ? notAfterValue.toLocaleString() : notAfterValue
    const now = new Date()
    const expiry = new Date(notAfter)
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
  try {
    await request.post(`/certificates/jobs/${row.id}/retry`)
    ElMessage.success('重试已触发')
    fetchJobs()
  } catch (error) {
    console.error('Failed to retry cert job:', error)
  }
}

const deleteJob = async (row: CertJob) => {
  try {
    await ElMessageBox.confirm(`确定要删除任务 "${row.domain}" 吗？`, '删除确认', { type: 'warning' })
    await request.delete(`/certificates/jobs/${row.id}`)
    ElMessage.success('任务已删除')
    fetchJobs()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('Failed to delete cert job:', error)
    }
  }
}

const viewLogs = async (row: CertJob) => {
  currentJob.value = row
  logDialogVisible.value = true
}

const onLogDialogOpened = async () => {
  await refreshLogs()
  startLogPolling()
}

const onLogDialogClosed = () => {
  stopLogPolling()
  currentJob.value = null
  logLines.value = []
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
  if (!currentJob.value) return
  logLoading.value = true
  try {
    const res = await request.get(`/certificates/jobs/${currentJob.value.id}/logs`, { params: { limit: 500 } })
    const logs = Array.isArray(res.data) ? res.data : (res.data?.lines || [])
    logLines.value = logs
    await scrollToBottom()
  } catch (error) {
    console.error('Failed to fetch cert job logs:', error)
    ElMessage.error('获取日志失败')
  } finally {
    logLoading.value = false
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
  word-break: break-all;
}
</style>
