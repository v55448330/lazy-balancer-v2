<template>
  <el-card v-loading="loading" class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Monitor /></el-icon>
          <span>当前节点状态</span>
        </div>
      </div>
    </template>

    <el-descriptions v-if="status" :column="3" border class="status-descriptions">
      <el-descriptions-item label="节点角色">
        <el-tag :type="status.node_mode === 'master' ? 'success' : 'warning'" size="small">
          {{ status.node_mode === 'master' ? '主节点' : '从节点' }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="集群状态">
        <el-tag :type="status.cluster_active ? 'success' : 'warning'" size="small">
          {{ status.cluster_active ? '已激活' : '未激活' }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item :label="status.node_mode === 'master' ? '配置版本' : '已应用版本'">
        {{ status.node_mode === 'master' ? status.cluster_version : status.applied_version }}
      </el-descriptions-item>

      <template v-if="status.node_mode === 'master'">
        <el-descriptions-item label="待确认节点">{{ status.pending_count }}</el-descriptions-item>
        <el-descriptions-item label="已批准节点">{{ status.approved_count }}</el-descriptions-item>
        <el-descriptions-item label="同步间隔">{{ status.sync_interval }} 秒</el-descriptions-item>
      </template>

      <template v-else>
        <el-descriptions-item label="主节点地址" :span="2">
          <span class="mono-value">{{ status.master_url || '-' }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="最近同步">{{ formatTime(status.last_sync_at) }}</el-descriptions-item>
        <el-descriptions-item v-if="status.last_sync_error" label="同步错误" :span="3">
          <span class="error-text">{{ status.last_sync_error }}</span>
        </el-descriptions-item>
      </template>
    </el-descriptions>
    <el-empty v-else description="暂无节点状态" :image-size="60" />
  </el-card>
</template>

<script setup lang="ts">
import { formatDate } from '@/utils/date'
import { Monitor } from '@element-plus/icons-vue'
import type { ClusterStatus } from '@/types'

defineProps<{
  readonly status: ClusterStatus | null
  readonly loading: boolean
}>()

const formatTime = (value: string): string => formatDate(value) || '-'
</script>

<style scoped>
.card-header { display: flex; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.status-descriptions { width: 100%; }
.mono-value { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; word-break: break-all; }
.error-text { color: var(--danger); word-break: break-word; }

@media (max-width: 768px) {
  .status-descriptions :deep(.el-descriptions__body) { overflow-x: auto; }
}
</style>
