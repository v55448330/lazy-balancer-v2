<template>
  <el-table v-if="loading || jobs.length > 0" :data="jobs" size="small" v-loading="loading">
    <el-table-column prop="rule_id" label="规则 ID" width="120" show-overflow-tooltip />
    <el-table-column prop="domain" label="域名" min-width="180" show-overflow-tooltip />
    <el-table-column prop="status" label="状态" width="100" align="center">
      <template #default="{ row }">
        <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column prop="message" label="消息" min-width="200" show-overflow-tooltip />
    <el-table-column prop="expires_at" label="过期时间" width="160">
      <template #default="{ row }">
        {{ row.expires_at ? formatDate(row.expires_at) : '-' }}
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

interface CertJob {
  id: number
  rule_id: string
  domain: string
  status: string
  message: string
  expires_at?: string
}

const props = defineProps<{
  ruleId?: string
}>()

const jobs = ref<CertJob[]>([])
const loading = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

const logDialogVisible = ref(false)
const logLoading = ref(false)
const logLines = ref<string[]>([])
const currentJob = ref<CertJob | null>(null)
const logContainerRef = ref<HTMLDivElement | null>(null)
let logPollTimer: ReturnType<typeof setInterval> | null = null

const ansiRegex = /[\u001B\u009B][[\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\d\/#&.:=?%@~_]+)*|[a-zA-Z\d]+(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g

const formattedLogs = computed(() => {
  return logLines.value
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
    case 'issuing': return 'warning'
    case 'failed': return 'danger'
    default: return 'info'
  }
}

const statusLabel = (status: string) => {
  switch (status) {
    case 'issued': return '已签发'
    case 'issuing': return '签发中'
    case 'failed': return '失败'
    case 'pending': return '待处理'
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
  } catch (error) {
    console.error('Failed to fetch cert jobs:', error)
  } finally {
    loading.value = false
  }
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
    logLines.value = res.data?.lines || []
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
