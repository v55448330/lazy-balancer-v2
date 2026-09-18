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
        <el-switch
          :model-value="item.key === 'sync_users' ? true : status[item.key]"
          :disabled="item.key === 'sync_users'"
          :loading="settingsLoading"
          @change="(v: string | number | boolean) => handleSwitchChange(item.key, v)"
        />
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
      <el-table-column label="状态" width="110" align="center" class-name="node-status-col">
        <template #default="{ row }">
          <el-tooltip v-if="versionIncompatibilityError(row)" :content="versionIncompatibilityError(row)" placement="top">
            <el-tag type="danger" size="small">版本不兼容</el-tag>
          </el-tooltip>
          <!-- v2.3.0:状态 hover 展示从节点规则库版本(跟随主节点同步,用户裁定) -->
          <el-tooltip v-else-if="row.health?.crs_version || row.health?.ip2region_version" placement="top">
            <template #content>
              <div>CRS：{{ row.health?.crs_version || '—' }}</div>
              <div>IP2Region：{{ row.health?.ip2region_version || '—' }}</div>
            </template>
            <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </el-tooltip>
          <el-tag v-else :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          <div v-if="row.status === 'offline'" class="offline-duration">离线 {{ offlineDuration(row.last_seen) }}</div>
        </template>
      </el-table-column>
      <el-table-column label="配置版本" min-width="170">
        <template #default="{ row }">
          <el-popover v-if="row.section_sync?.length" placement="top" trigger="hover" :width="460" :show-after="150">
            <template #reference>
              <div class="version-cell">
                <span class="version-nums">{{ row.reported_version }}<template v-if="row.reported_version < row.current_version"> → {{ row.current_version }}</template></span>
                <!-- UI(第 20 轮用户裁定):合并状态标签消除换行——分区滞后优先
                     (节级哈希不一致蕴含版本待同步,hover 明细见 popover 分区列表);
                     两者同现时不再双标签叠行,单标签+数字紧凑呈现。 -->
                <el-tag v-if="laggingSectionCount(row) > 0" type="warning" size="small" effect="plain">分区滞后 {{ laggingSectionCount(row) }}</el-tag>
                <el-tag v-else-if="row.reported_version < row.current_version" type="warning" size="small" effect="plain">待同步</el-tag>
                <el-tag v-else-if="row.reported_version === row.current_version" type="success" size="small" effect="plain">已同步</el-tag>
                <!-- F8:reported>current 罕见形态(主版本回退)——不误显已同步 -->
                <el-tag v-else type="info" size="small" effect="plain">版本异常</el-tag>
              </div>
            </template>
            <div class="section-sync-panel">
              <div class="section-sync-title">分区同步状态</div>
              <div v-for="section in row.section_sync" :key="section.section" class="section-sync-row">
                <div class="section-sync-head">
                  <span class="section-sync-label">{{ section.label }}</span>
                  <el-tag v-if="!section.synced" type="warning" size="small">滞后</el-tag>
                  <el-tag v-else type="success" size="small">已同步</el-tag>
                </div>
                <!-- 全量哈希(2026-09-19 用户裁定):宽度有富裕,完整展示便于
                     与对端 DB/节点比对取证;滞后行追加主端哈希行。 -->
                <div class="section-sync-hash mono-value">{{ section.hash || '无记录' }}</div>
                <div v-if="!section.synced" class="section-sync-hash section-sync-hash-master">主端 {{ section.master_hash }}</div>
              </div>
            </div>
          </el-popover>
          <div v-else class="version-cell version-cell-wrap">
            <span class="version-nums">{{ row.reported_version }}<template v-if="row.reported_version < row.current_version"> → {{ row.current_version }}</template></span>
            <el-tag v-if="row.reported_version < row.current_version" type="warning" size="small" effect="plain">待同步</el-tag>
            <el-tag v-else-if="row.reported_version === row.current_version" type="success" size="small" effect="plain">已同步</el-tag>
            <!-- F8:reported>current 罕见形态(主版本回退)——不误显已同步 -->
            <el-tag v-else type="info" size="small" effect="plain">版本异常</el-tag>
            <span v-if="row.is_approved" class="section-sync-stale">暂无分区上报</span>
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
      <el-table-column label="操作" width="200" :fixed="operationColumnFixed" align="center">
        <template #default="{ row }">
          <template v-if="row.status === 'pending' || !row.is_approved">
            <el-button link type="primary" size="small" :loading="pendingNodeId === row.id" :disabled="readOnly || pendingNodeId !== null" @click="$emit('approve', row)">确认</el-button>
            <el-button link type="danger" size="small" :disabled="readOnly || pendingNodeId !== null" @click="$emit('reject', row)">拒绝</el-button>
          </template>
          <template v-else>
            <div class="op-buttons">
              <el-button v-if="!readOnly" link type="primary" size="small" :loading="loginNodeId === row.id" :disabled="row.status !== 'online' || loginNodeId !== null" @click="$emit('login', row)">登录</el-button>
              <el-button v-if="!readOnly && row.status === 'online'" link type="warning" size="small" @click="$emit('service-control', row)">服务</el-button>
              <el-button link type="danger" size="small" :loading="pendingNodeId === row.id" :disabled="readOnly || pendingNodeId !== null" @click="$emit('remove', row)">删除</el-button>
            </div>
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
  // 系统数据排第一且恒同步(2026-09-11 裁定):用户/密钥/ACME 与全局配置
  // (三分类合并:全局配置并入系统数据节)确保系统基本运行的数据不可禁用同步。
  { key: 'sync_users', label: '系统数据', tip: '用户账号、API 密钥、ACME 配置与全局设置（恒同步，不可禁用；证书文件随负载规则开关同步）' },
  { key: 'sync_rules', label: '负载均衡规则', tip: '规则、上游、路径规则与证书任务' },
  // 三分类合并:规则库文件差量通道并入安全防护开关(单开关统策略行与文件)。
  { key: 'sync_security', label: '安全防护', tip: '安全策略、自定义规则与 CRS/IP2Region 规则库（文件哈希一致时跳过传输）' },
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

const laggingSectionCount = (node: ClusterNodeWithSyncError): number => node.section_sync?.filter(section => !section.synced).length ?? 0


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
/* SYSRENDER33-2(第 33 轮审计,P2)+ 2026-09-17 用户实证修正:原豁免覆盖
   全表所有含标签列(配置版本/健康同被压成块级,单行标签失去垂直居中)。
   精确化为「仅状态列且离线时长存在时」才块级叠行——在线(单标签)与
   配置版本/健康列回全局 inline-flex 居中规则。 */
:deep(.el-table td.node-status-col .cell:has(.offline-duration)) { display: block; }

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
.version-cell { display: flex; align-items: center; gap: 6px; flex-wrap: nowrap; min-width: 0; }
.version-cell-wrap { flex-wrap: wrap; }
/* F3(第 20.5 轮):stale 分支三元素可超 170px——该分支恢复 wrap,主分支
   (两元素版本号+标签)保持 nowrap 消除换行。 */
.version-nums { font-variant-numeric: tabular-nums; white-space: nowrap; }
.offline-duration { font-size: 12px; color: #9ca3af; margin-top: 2px; }
.section-sync-stale { font-size: 12px; color: #9ca3af; }
.section-sync-panel { display: flex; flex-direction: column; gap: 6px; }
.section-sync-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.section-sync-row { display: flex; flex-direction: column; gap: 2px; font-size: 12px; padding: 4px 0; }
.section-sync-row + .section-sync-row { border-top: 1px dashed var(--el-border-color-lighter); }
.section-sync-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.section-sync-label { color: var(--text-primary); }
.section-sync-hash { font-size: 11px; color: #9ca3af; word-break: break-all; line-height: 1.5; }
.section-sync-hash-master { color: var(--el-color-warning); }
.op-buttons { display: inline-flex; align-items: center; }
.op-buttons .el-button + .el-button { margin-left: 4px; }
.op-buttons .el-button { padding-left: 6px; padding-right: 6px; }

@media (max-width: 768px) {
  .card-header { align-items: flex-start; flex-direction: column; }
}
</style>
