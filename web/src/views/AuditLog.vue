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
      <el-table :data="logs" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty>
          <el-empty description="暂无操作日志" :image-size="60" />
        </template>
        <el-table-column prop="created_at" label="时间" width="190" />
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

      <div style="margin-top: 16px; display: flex; justify-content: flex-end;">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="fetchLogs"
          @current-change="fetchLogs"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { Document } from '@element-plus/icons-vue'

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

const actionTagType = (action: string) => {
  if (action === '创建' || action === '启用' || action === '审批' || action === '签发成功' || action === '测试成功' || action === '登录成功' || action === '恢复') return 'success'
  if (action === '删除' || action === '禁用' || action === '停止' || action === '重启' || action === '拒绝' || action === '签发失败' || action === '测试失败' || action === '登录失败' || action === '同步失败' || action === '重载失败' || action === '写入失败' || action === '恢复失败' || action === '切换失败' || action === '注册失败' || action === '上报失败' || action === '导入失败' || action === '手动同步失败') return 'danger'
  if (action === '更新' || action === '更新资料' || action === '修改状态' || action === '重置密码' || action === '重载' || action === '续签' || action === '重试' || action === 'CA限流' || action === '切换' || action === '提升' || action === '同步' || action === '同步下发' || action === '手动同步' || action === '注册' || action === '生成' || action === '导出' || action === '导入' || action === '复制' || action === '触发签发' || action === '写入' || action === '恢复排队' || action === '续签排队' || action === '重新排队' || action === '测试') return 'warning'
  return 'info'
}

const fetchLogs = async () => {
  const targetPage = page.value
  const targetPageSize = pageSize.value
  const currentRequestSeq = ++requestSeq
  loading.value = true
  try {
    const res = await request.get<{ data?: { list?: AuditLogEntry[]; total?: number } }>('/audit-logs', { params: { page: targetPage, page_size: targetPageSize } })
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
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.header-left { flex: 1; }
.page-title { display: flex; align-items: center; gap: 8px; font-size: 18px; font-weight: 600; color: #111827; margin: 0; }
.title-icon { color: #3b82f6; font-size: 20px; }
.page-desc { font-size: 13px; color: #6b7280; margin: 4px 0 0 28px; }
</style>
