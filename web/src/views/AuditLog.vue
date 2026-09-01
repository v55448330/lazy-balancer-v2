<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Document /></el-icon>
          操作日志
        </h2>
        <p class="page-desc">记录系统中所有写操作和配置变更</p>
      </div>
    </div>

    <el-card>
      <div class="filter-bar">
        <el-date-picker
          v-model="filters.timeRange"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="filter-date-range"
        />
        <el-select v-model="filters.username" placeholder="操作人" clearable filterable style="width: 130px">
          <el-option v-for="o in usernameOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-select v-model="filters.action" placeholder="操作" clearable filterable style="width: 120px">
          <el-option v-for="o in actionOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-select v-model="filters.resource" placeholder="对象" clearable filterable allow-create style="width: 150px">
          <el-option v-for="o in resourceOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-input v-model="filters.ip" placeholder="IP" clearable style="width: 120px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.keyword" placeholder="详情关键词" clearable style="width: 160px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>
      <el-table :data="logs" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" :tooltip-options="{ popperClass: 'log-overflow-popper' }">
        <template #empty>
          <el-empty description="暂无操作日志" :image-size="60" />
        </template>
        <el-table-column prop="created_at" label="时间" width="190" :formatter="(row: AuditLogEntry) => formatDate(row.created_at)" />
        <el-table-column label="操作人" width="150">
          <template #default="{ row }">
            <span v-if="row.display_name && row.display_name !== row.username">{{ row.display_name }}（{{ row.username }}）</span>
            <span v-else>{{ row.username || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="action" label="操作" width="90">
          <template #default="{ row }">
            <el-tag :type="actionTagType(row.action)" size="small">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="resource" label="对象" width="160" />
        <el-table-column prop="detail" label="详情" show-overflow-tooltip />
        <el-table-column prop="ip_address" label="IP" width="160" show-overflow-tooltip />
      </el-table>

      <div style="margin-top: 16px; display: flex; align-items: center;">
        <LogStorageBar log-key="audit" style="margin-right: auto" />
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="applyFilters"
          @current-change="fetchLogs"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { Document } from '@element-plus/icons-vue'
import LogStorageBar from '@/components/LogStorageBar.vue'

interface AuditLogEntry {
  id: number
  username?: string | null
  display_name?: string | null
  action: string
  resource: string
  detail: string
  ip_address: string
  created_at: string
}

const logs = ref<AuditLogEntry[]>([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
let requestSeq = 0

const filters = ref({
  timeRange: null as [string, string] | null,
  username: '',
  action: '',
  resource: '',
  ip: '',
  keyword: '',
})

const usernameOptions = ref<string[]>([])
const actionOptions = ref<string[]>([])
const resourceOptions = ref<string[]>([])

const fetchOptions = async () => {
  try {
    const res = await request.get<{ data?: { usernames?: { value: string }[]; actions?: { value: string }[]; resources?: { value: string }[] } }>('/audit-logs/options')
    const d = res.data
    usernameOptions.value = (d?.usernames || []).map((o) => o.value)
    actionOptions.value = (d?.actions || []).map((o) => o.value)
    resourceOptions.value = (d?.resources || []).map((o) => o.value)
  } catch (e) {
    console.error('Failed to fetch audit log options:', e)
  }
}

const buildParams = () => {
  const params: Record<string, string | number> = { page: page.value, page_size: pageSize.value }
  const f = filters.value
  if (f.timeRange?.[0]) params.start_time = f.timeRange[0]
  if (f.timeRange?.[1]) params.end_time = f.timeRange[1]
  for (const key of ['username', 'action', 'resource', 'ip', 'keyword'] as const) {
    if (f[key].trim()) params[key] = f[key].trim()
  }
  return params
}

const applyFilters = () => {
  page.value = 1
  fetchLogs()
}

const resetFilters = () => {
  filters.value = { timeRange: null, username: '', action: '', resource: '', ip: '', keyword: '' }
  page.value = 1
  fetchLogs()
}

const actionTagType = (action: string) => {
  if (action === '创建' || action === '启用' || action === '审批' || action === '签发成功' || action === '测试成功' || action === '登录成功' || action === '恢复' || action === '配置恢复' || action === '载入' || action === '校验成功') return 'success'
  if (action === '重置') return 'warning'
  if (action === '删除' || action === '禁用' || action === '停止' || action === '重启' || action === '拒绝' || action === '签发失败' || action === '测试失败' || action === '登录失败' || action === '同步失败' || action === '重载失败' || action === '写入失败' || action === '恢复失败' || action === '切换失败' || action === '注册失败' || action === '上报失败' || action === '导入失败' || action === '配置漂移' || action === '清理失败' || action === '部分失败' || action === '应用失败' || action === '部署失败' || action === '认证拒绝' || action === '提升失败' || action === '校验失败' || action === '更新失败') return 'danger'
  if (action === '更新' || action === '更新信息' || action === '修改状态' || action === '重置密码' || action === '重载' || action === '续签' || action === '重试' || action === '签发限流' || action === '切换' || action === '提升' || action === '同步' || action === '同步下发' || action === '手动同步' || action === '同步自愈' || action === '同步警告' || action === '注册' || action === '生成' || action === '导出' || action === '导入' || action === '导入警告' || action === '复制' || action === '触发签发' || action === '写入' || action === '恢复排队' || action === '续签排队' || action === '重新排队' || action === '重试排队' || action === '更新地址' || action === '校验告警' || action === '下载校验' || action === '清理' || action === '启动' || action === '启动警告' || action === '同步应用' || action === '同步跳过' || action === '登出' || action === '重建' || action === '启动迁移' || action === '警告' || action === '脱离' || action === '服务控制') return 'warning'
  return 'info'
}

const fetchLogs = async () => {
  const targetPage = page.value
  const targetPageSize = pageSize.value
  const currentRequestSeq = ++requestSeq
  loading.value = true
  try {
    const res = await request.get<{ data?: { list?: AuditLogEntry[]; total?: number } }>('/audit-logs', { params: buildParams() })
    if (currentRequestSeq !== requestSeq || page.value !== targetPage || pageSize.value !== targetPageSize) return
    logs.value = res.data?.list || []
    total.value = res.data?.total || 0
  } catch (e) {
    console.error('Failed to fetch audit logs:', e)
  } finally {
    if (currentRequestSeq === requestSeq) loading.value = false
  }
}

onMounted(() => {
  fetchLogs()
  fetchOptions()
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.header-left { flex: 1; }
.page-title { display: flex; align-items: center; gap: 8px; font-size: 18px; font-weight: 600; color: #111827; margin: 0; }
.title-icon { color: #3b82f6; font-size: 20px; }
.page-desc { font-size: 13px; color: #6b7280; margin: 4px 0 0 28px; }
.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: center; }
.filter-actions { display: flex; gap: 0; margin-left: 8px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
</style>

<style>
.filter-date-range.el-date-editor {
  --el-date-editor-width: 360px;
  width: 360px;
  flex: 0 0 auto;
}
</style>

<style>
.log-overflow-popper { max-width: 420px; word-break: break-all; }
.log-overflow-popper .el-tooltip__popper { max-width: 420px; }
</style>
