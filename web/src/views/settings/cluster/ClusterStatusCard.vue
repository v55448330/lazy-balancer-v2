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
        <el-descriptions-item label="最近同步">{{ formatDate(status.last_sync_at) || '-' }}</el-descriptions-item>
        <el-descriptions-item v-if="status.last_sync_error" label="同步错误" :span="3">
          <span class="error-text">{{ syncErrorDisplay }}</span>
        </el-descriptions-item>
      </template>
    </el-descriptions>
    <!-- A6-S5：拉取失败且无数据时改「加载失败」，与父级错误横幅口径一致。 -->
    <el-empty v-else :description="error ? '加载失败' : '暂无节点状态'" :image-size="60" />
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { formatDate } from '@/utils/date'
import { Monitor } from '@element-plus/icons-vue'
import type { ClusterStatus } from '@/types'

const props = defineProps<{
  readonly status: ClusterStatus | null
  readonly loading: boolean
  /** A6-S5：父级轮询错误态——无数据时的空态文案据此切「加载失败」。 */
  readonly error?: boolean
}>()

// 后端 cluster_sync.go 的 syncReloadFailureMarkerPrefix 字面值：快照已应用但
// Caddy 重载失败时写入 last_sync_error 的机内标记前缀（仅展示层翻译用）。
const RELOAD_FAILURE_MARKER_PREFIX = 'apply_ok_reload_failed'
// 后端 syncFailureCountPrefix/Suffix 构成的「已连续 N 次」计数段。
const FAILURE_COUNT_PATTERN = /已连续 (\d+) 次/

// C-4：apply_failed + 标记前缀的消息翻译为用户语义（保留首段原因供排障）；
// 其余消息原样展示。仅展示层，不改动存储内容。
const syncErrorDisplay = computed<string>(() => {
  const message = props.status?.last_sync_error ?? ''
  if (!props.status || props.status.sync_error_code !== 'apply_failed' || !message.includes(RELOAD_FAILURE_MARKER_PREFIX)) {
    return message
  }
  const countMatch = message.match(FAILURE_COUNT_PATTERN)
  const retryPart = countMatch ? `（第 ${countMatch[1]} 次）` : ''
  const reasonSegment = message.split(' | ')[0] ?? message
  const reason = reasonSegment
    .replace(`${RELOAD_FAILURE_MARKER_PREFIX}: `, '')
    .replace(RELOAD_FAILURE_MARKER_PREFIX, '')
    .trim()
  return `配置已同步但 Caddy 重载失败，系统将自动重试${retryPart}${reason ? `：${reason}` : ''}`
})
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
