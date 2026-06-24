<template>
  <el-table :data="jobs" size="small" v-loading="loading">
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
    <el-table-column label="操作" width="120" align="center">
      <template #default="{ row }">
        <el-button link type="primary" size="small" @click="retryJob(row)">重试</el-button>
        <el-button link type="danger" size="small" @click="deleteJob(row)">删除</el-button>
      </template>
    </el-table-column>
  </el-table>
  <el-empty v-if="!loading && jobs.length === 0" description="暂无签发任务" :image-size="60" />
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
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

onMounted(() => {
  fetchJobs()
  pollTimer = setInterval(fetchJobs, 5000)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>
