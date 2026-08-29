<template>
  <el-card v-if="settingsOnly" class="settings-card controls-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Setting /></el-icon>
          <span>主节点同步设置</span>
        </div>
        <el-button type="primary" size="small" :loading="tokenLoading" :disabled="readOnly" @click="$emit('generate-token')">生成注册令牌</el-button>
      </div>
    </template>
    <el-form label-width="120px" class="settings-form" :disabled="readOnly">
      <el-form-item v-for="item in syncSwitchItems" :key="item.key" :label="item.label">
        <el-switch :model-value="status[item.key]" :loading="settingsLoading" @change="(v: string | number | boolean) => handleSwitchChange(item.key, v)" />
        <span class="form-tip-inline" :title="item.tip">{{ item.tip }}</span>
        <el-tooltip :content="syncSwitchFreezeHint" placement="top">
          <el-icon class="switch-freeze-hint"><QuestionFilled /></el-icon>
        </el-tooltip>
      </el-form-item>
    </el-form>
  </el-card>

  <el-card v-if="!settingsOnly" class="settings-card settings-list-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><List /></el-icon>
          <span>节点列表</span>
        </div>
        <span class="card-tip">每 15 秒自动刷新</span>
      </div>
    </template>

    <el-table :data="nodes" row-key="id" v-loading="loading" stripe :header-cell-style="{ background: 'var(--bg-secondary)' }" empty-text="">
      <el-table-column prop="name" label="名称" min-width="130" />
      <el-table-column label="地址" min-width="200" show-overflow-tooltip>
        <template #default="{ row }"><span class="mono-value">{{ row.ip_address }}:{{ row.port }}</span></template>
      </el-table-column>
      <el-table-column label="访问地址" min-width="220" show-overflow-tooltip>
        <template #default="{ row }">
          <el-link class="access-url-link" type="primary" :disabled="readOnly || accessUrlSaving" @click="$emit('edit-access-url', row)">
            {{ row.access_url || '-' }}
          </el-link>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="110" align="center">
        <template #default="{ row }">
          <el-tooltip v-if="versionIncompatibilityError(row)" :content="versionIncompatibilityError(row)" placement="top">
            <el-tag type="danger" size="small">版本不兼容</el-tag>
          </el-tooltip>
          <el-tag v-else :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          <div v-if="row.status === 'offline'" class="offline-duration">离线 {{ offlineDuration(row.last_seen) }}</div>
        </template>
      </el-table-column>
      <el-table-column label="配置版本" min-width="170">
        <template #default="{ row }">
          <div class="version-cell">
            <span>已应用 {{ row.reported_version }} / 当前 {{ row.current_version }}</span>
            <el-tag v-if="row.reported_version < row.current_version" type="warning" size="small">待同步</el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="健康" width="90" align="center">
        <template #default="{ row }">
          <el-tooltip v-if="row.health" :content="healthSummary(row.health)" placement="top">
            <el-tag :type="row.health.caddy_ok ? 'success' : 'danger'" size="small">
              {{ row.health.caddy_ok ? '正常' : '异常' }}
            </el-tag>
          </el-tooltip>
          <span v-else class="form-tip-line">暂无</span>
        </template>
      </el-table-column>
      <el-table-column label="最后上报时间" min-width="170">
        <template #default="{ row }">{{ formatDate(row.last_seen) || '-' }}</template>
      </el-table-column>
      <el-table-column label="操作" width="130" :fixed="operationColumnFixed" align="center">
        <template #default="{ row }">
          <template v-if="row.status === 'pending' || !row.is_approved">
            <el-button link type="primary" size="small" :loading="pendingNodeId === row.id" :disabled="readOnly || pendingNodeId !== null" @click="$emit('approve', row)">确认</el-button>
            <el-button link type="danger" size="small" :disabled="readOnly || pendingNodeId !== null" @click="$emit('reject', row)">拒绝</el-button>
          </template>
          <template v-else>
            <el-button v-if="!readOnly" link type="primary" size="small" :loading="loginNodeId === row.id" :disabled="row.status !== 'online' || loginNodeId !== null" @click="$emit('login', row)">登录</el-button>
            <el-button v-if="!readOnly && row.status === 'online'" link type="warning" size="small" @click="$emit('service-control', row)">服务</el-button>
            <el-button link type="danger" size="small" :loading="pendingNodeId === row.id" :disabled="readOnly || pendingNodeId !== null" @click="$emit('remove', row)">删除</el-button>
          </template>
        </template>
      </el-table-column>
      <template #empty><el-empty description="暂无集群节点" :image-size="60" /></template>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useWindowSize } from '@vueuse/core'
import { formatDate } from '@/utils/date'
import { List, QuestionFilled, Setting } from '@element-plus/icons-vue'
import type { ClusterHealth, ClusterNode, ClusterNodeStatus, ClusterStatus } from '@/types'

type SyncErrorCode = 'schema_too_new' | 'schema_too_old' | 'signature_invalid' | 'pin_mismatch' | 'validation_failed' | 'apply_failed' | 'transport_error'
type ClusterHealthWithSyncError = ClusterHealth & { readonly sync_error_code?: SyncErrorCode }
type ClusterNodeWithSyncError = Omit<ClusterNode, 'health'> & { readonly health: ClusterHealthWithSyncError | null }

const props = defineProps<{
  settingsOnly?: boolean
  readonly status: ClusterStatus
  readonly nodes: readonly ClusterNodeWithSyncError[]
  readonly loading: boolean
  readonly tokenLoading: boolean
  readonly settingsLoading: boolean
  readonly pendingNodeId: number | null
  readonly loginNodeId: number | null
  readonly accessUrlSaving: boolean
  readonly readOnly: boolean
}>()

const emit = defineEmits<{
  (event: 'generate-token'): void
  (event: 'update-sync-field', field: string, value: boolean): void
  (event: 'approve', node: ClusterNode): void
  (event: 'reject', node: ClusterNode): void
  (event: 'remove', node: ClusterNode): void
  (event: 'login', node: ClusterNode): void
  (event: 'service-control', node: ClusterNode): void
  (event: 'edit-access-url', node: ClusterNode): void
}>()

const { width: viewportWidth } = useWindowSize()
const operationColumnFixed = computed<'right' | false>(() => viewportWidth.value > 1440 ? 'right' : false)

const syncSwitchItems = [
  { key: 'sync_global_config', label: '全局配置', tip: '日志级别、时区、Caddy 全局超时与日志等全局设置' },
  { key: 'sync_users', label: '系统数据', tip: '用户账号与 API 密钥' },
  { key: 'sync_rules', label: '负载均衡规则', tip: '规则、上游、路径规则与证书任务' },
  { key: 'sync_waf_files', label: '规则库数据库', tip: 'CRS 规则文件与 IP2Region GeoIP 数据库（哈希一致时跳过传输）' },
  { key: 'sync_security', label: '安全策略规则', tip: '安全策略、绑定关系、自定义规则与拦截页面' },
] as const

const syncSwitchFreezeHint = '关闭后从节点保留最近一次同步内容，不自动删除'

const handleSwitchChange = (field: string, value: string | number | boolean): void => {
  if (props.readOnly) return
  if (typeof value === 'boolean') emit('update-sync-field', field, value)
}

const statusType = (status: ClusterNodeStatus): 'success' | 'info' | 'warning' => {
  if (status === 'online') return 'success'
  if (status === 'pending') return 'warning'
  return 'info'
}

const statusLabel = (status: ClusterNodeStatus): string => {
  if (status === 'online') return '在线'
  if (status === 'pending') return '待确认'
  return '离线'
}

const healthSummary = (health: ClusterHealth): string => {
  const summary = `Caddy ${health.caddy_ok ? '正常' : '异常'} · 规则 ${health.rules_count} · 30 天内到期 ${health.certs_expiring_30d}`
  return health.last_sync_error ? `${summary} · ${health.last_sync_error}` : summary
}

const offlineDuration = (lastSeen: string | null | undefined): string => {
  if (!lastSeen) return ''
  const last = new Date(lastSeen).getTime()
  if (Number.isNaN(last)) return ''
  const elapsed = Math.max(0, Math.floor((Date.now() - last) / 1000))
  if (elapsed < 60) return `${elapsed}s`
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)}m`
  if (elapsed < 86400) return `${Math.floor(elapsed / 3600)}h`
  return `${Math.floor(elapsed / 86400)}d`
}

const versionIncompatibilityError = (node: ClusterNodeWithSyncError): string => {
	const error = node.health?.last_sync_error.trim() ?? ''
	if (!error) return ''
	const code = node.health?.sync_error_code
	if (code) {
		return code === 'schema_too_new' || code === 'schema_too_old' ? error : ''
	}
	const normalized = error.toLowerCase()
  const isSnapshotError = normalized.includes('快照') || normalized.includes('snapshot')
  const hasVersionMismatch = normalized.includes('版本过旧')
    || normalized.includes('version incompatible')
    || normalized.includes('version mismatch')
    || (normalized.includes('schema') && (
      normalized.includes('过旧')
      || normalized.includes('要求')
      || normalized.includes('支持')
      || normalized.includes('upgrade')
      || normalized.includes('incompatible')
    ))
  return isSnapshotError && hasVersionMismatch ? error : ''
}

</script>

<style scoped>
.card-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
:deep(.el-card__body), .el-card { height: 100%; }
.card-tip { font-size: 12px; color: #9ca3af; white-space: nowrap; flex-shrink: 0; }
.settings-form :deep(.el-form-item__label) { white-space: nowrap; }
.settings-form :deep(.el-form-item__content) { flex-wrap: nowrap; }
.settings-form .form-tip-inline { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
.switch-freeze-hint { color: #9ca3af; font-size: 14px; flex-shrink: 0; cursor: help; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.mono-value { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
.access-url-link { display: inline-flex; max-width: 100%; vertical-align: middle; }
.access-url-link :deep(.el-link__inner) { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.version-cell { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.offline-duration { font-size: 12px; color: #9ca3af; margin-top: 2px; }

@media (max-width: 768px) {
  .card-header { align-items: flex-start; flex-direction: column; }
}
</style>
