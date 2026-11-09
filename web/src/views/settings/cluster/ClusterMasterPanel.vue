<template>
  <el-card v-if="settingsOnly" class="settings-card controls-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Setting /></el-icon>
          <span>{{ status.node_mode === 'slave' ? t('common.app.views.cluster.syncSettingsSlaveTitle') : t('common.app.views.cluster.syncSettingsMasterTitle') }}</span>
        </div>
        <el-button type="primary" size="small" :loading="tokenLoading" :disabled="readOnly" @click="$emit('generate-token')">{{ t('common.app.views.cluster.generateToken') }}</el-button>
      </div>
    </template>
    <el-form label-width="auto" class="settings-form" :disabled="readOnly">
      <el-form-item v-for="item in syncSwitchItems" :key="item.key" :label="item.label">
        <el-switch
          :model-value="item.locked ? true : status[item.key]"
          :disabled="readOnly || item.locked === true"
          :loading="settingsLoading"
          @change="(v: string | number | boolean) => handleSwitchChange(item.key, v)"
        />
        <span class="form-tip-inline switch-tip-nowrap" :title="item.tip">{{ item.tip }}</span>
        <FieldHelpIcon :content="syncSwitchFreezeHint" />
      </el-form-item>
    </el-form>
  </el-card>

  <el-card v-if="!settingsOnly" class="settings-card settings-list-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><List /></el-icon>
          <span>{{ t('common.app.views.cluster.nodeList') }}</span>
        </div>
        <span class="card-tip">{{ t('common.app.views.cluster.autoRefreshTip') }}</span>
      </div>
    </template>

    <!-- el-table 的 data 只接受可变数组；这里只读投影（组件不会写回），断言仅抹平 readonly 修饰 -->
      <el-table :data="nodes as ClusterNodeWithSyncError[]" row-key="id" v-loading="loading" stripe :header-cell-style="{ background: 'var(--bg-secondary)' }" empty-text="">
      <el-table-column prop="name" :label="t('common.app.views.cluster.colName')" min-width="90" show-overflow-tooltip />
      <el-table-column :label="t('common.app.views.cluster.colAddress')" min-width="130" show-overflow-tooltip>
        <template #default="{ row }"><span class="mono-value">{{ row.ip_address }}:{{ row.port }}</span></template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.cluster.colStatus')" width="70" align="center" class-name="node-status-col">
        <template #default="{ row }">
          <el-tooltip v-if="versionIncompatibilityError(row as ClusterNodeWithSyncError)" :content="versionIncompatibilityError(row as ClusterNodeWithSyncError)" placement="top">
            <el-tag type="danger" size="small">{{ t('common.app.views.cluster.versionIncompatible') }}</el-tag>
          </el-tooltip>
          <!-- 状态 hover 展示从节点四个规则库版本（跟随主节点同步，名称与
               规则库列表严格一致；缺失显示「—」） -->
          <el-tooltip v-else-if="nodeLibraryVersions(row as ClusterNodeWithSyncError)" placement="top">
            <template #content>
              <div v-for="item in nodeLibraryVersions(row as ClusterNodeWithSyncError)" :key="item.label">{{ item.label }}：{{ item.version }}</div>
            </template>
            <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </el-tooltip>
          <el-tag v-else :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          <div v-if="row.status === 'offline'" class="offline-duration">{{ t('common.app.views.cluster.offlineFor', { duration: offlineDuration(row.last_seen) }) }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.cluster.colConfigVersion')" min-width="110">
        <template #default="{ row }">
          <el-popover v-if="row.section_sync?.length" placement="top" trigger="hover" :width="460" :show-after="150" :popper-options="popperViewportSafe">
            <template #reference>
              <div class="version-cell">
                <span class="version-nums">{{ row.reported_version }}<template v-if="row.reported_version < row.current_version"> → {{ row.current_version }}</template></span>
                <!-- UI(用户裁定):合并状态标签消除换行——分区滞后优先
                     (节级哈希不一致蕴含版本待同步,hover 明细见 popover 分区列表);
                     两者同现时不再双标签叠行,单标签+数字紧凑呈现。 -->
                <el-tag v-if="laggingSectionCount(row as ClusterNodeWithSyncError) > 0" type="warning" size="small" effect="plain">{{ t('common.app.views.cluster.sectionLagging', { count: laggingSectionCount(row as ClusterNodeWithSyncError) }) }}</el-tag>
                <el-tag v-else-if="row.reported_version < row.current_version" type="warning" size="small" effect="plain">{{ t('common.app.views.cluster.pendingSync') }}</el-tag>
                <el-tag v-else-if="row.reported_version === row.current_version" type="success" size="small" effect="plain">{{ t('common.app.views.cluster.synced') }}</el-tag>
                <!-- reported>current 罕见形态(主版本回退)——不误显已同步-->
                <el-tag v-else type="info" size="small" effect="plain">{{ t('common.app.views.cluster.versionAbnormal') }}</el-tag>
              </div>
            </template>
            <div class="section-sync-panel">
              <div class="popover-title">{{ t('common.app.views.cluster.sectionSyncTitle') }}</div>
              <div v-for="section in row.section_sync" :key="section.section" class="section-sync-row">
                <div class="section-sync-head">
                  <span class="section-sync-label">{{ section.label }}</span>
                  <el-tag v-if="!section.synced" type="warning" size="small">{{ t('common.app.views.cluster.lagging') }}</el-tag>
                  <el-tag v-else type="success" size="small">{{ t('common.app.views.cluster.synced') }}</el-tag>
                </div>
                <!-- 全量哈希(2026-09-19 用户裁定):宽度有富裕,完整展示便于
                     与对端 DB/节点比对取证;滞后行追加主端哈希行。 -->
                <div class="section-sync-hash mono-value">{{ section.hash || t('common.app.views.cluster.noRecord') }}</div>
                <div v-if="!section.synced" class="section-sync-hash section-sync-hash-master">{{ t('common.app.views.cluster.masterHash', { hash: section.master_hash }) }}</div>
              </div>
            </div>
          </el-popover>
          <div v-else class="version-cell version-cell-wrap">
            <span class="version-nums">{{ row.reported_version }}<template v-if="row.reported_version < row.current_version"> → {{ row.current_version }}</template></span>
            <el-tag v-if="row.reported_version < row.current_version" type="warning" size="small" effect="plain">{{ t('common.app.views.cluster.pendingSync') }}</el-tag>
            <el-tag v-else-if="row.reported_version === row.current_version" type="success" size="small" effect="plain">{{ t('common.app.views.cluster.synced') }}</el-tag>
            <!-- reported>current 罕见形态(主版本回退)——不误显已同步-->
            <el-tag v-else type="info" size="small" effect="plain">{{ t('common.app.views.cluster.versionAbnormal') }}</el-tag>
            <span v-if="row.is_approved" class="section-sync-stale">{{ t('common.app.views.cluster.noSectionReport') }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column v-if="showHealthColumn" :label="t('common.app.views.cluster.colHealth')" width="64" align="center">
        <template #default="{ row }">
          <el-tooltip v-if="row.health" :content="healthSummary(row.health)" placement="top">
            <el-tag :type="row.health.caddy_ok ? 'success' : 'danger'" size="small">
              {{ row.health.caddy_ok ? t('common.app.views.cluster.healthy') : t('common.app.views.cluster.abnormal') }}
            </el-tag>
          </el-tooltip>
          <span v-else class="form-tip-line">{{ t('common.app.views.cluster.notAvailable') }}</span>
        </template>
      </el-table-column>
      <el-table-column v-if="showLastSeenColumn" :label="t('common.app.views.cluster.colLastSeen')" min-width="130">
        <template #default="{ row }">{{ formatDate(row.last_seen) || '-' }}</template>
      </el-table-column>
      <el-table-column :label="t('common.app.views.cluster.colActions')" width="190" :fixed="operationColumnFixed" align="center">
        <template #default="{ row }">
          <template v-if="row.status === 'pending' || !row.is_approved">
            <el-button link type="primary" size="small" :loading="pendingNodeId === row.id" :disabled="readOnly || pendingNodeId !== null" @click="$emit('approve', row as ClusterNodeWithSyncError)">{{ t('common.app.views.cluster.approve') }}</el-button>
            <el-button link type="danger" size="small" :disabled="readOnly || pendingNodeId !== null" @click="$emit('reject', row as ClusterNodeWithSyncError)">{{ t('common.app.views.cluster.reject') }}</el-button>
          </template>
          <template v-else>
            <div class="op-buttons">
              <el-button v-if="!readOnly" link type="primary" size="small" @click="$emit('edit-config', row as ClusterNodeWithSyncError)">{{ t('common.app.views.cluster.configure') }}</el-button>
              <el-button v-if="!readOnly" link type="primary" size="small" :loading="loginNodeId === row.id" :disabled="row.status !== 'online' || loginNodeId !== null" @click="$emit('login', row as ClusterNodeWithSyncError)">{{ t('common.app.views.cluster.login') }}</el-button>
              <el-button v-if="!readOnly && row.status === 'online'" link type="warning" size="small" @click="$emit('service-control', row as ClusterNodeWithSyncError)">{{ t('common.app.views.cluster.service') }}</el-button>
              <el-button link type="danger" size="small" :loading="pendingNodeId === row.id" :disabled="readOnly || pendingNodeId !== null" @click="$emit('remove', row as ClusterNodeWithSyncError)">{{ t('common.app.views.cluster.remove') }}</el-button>
            </div>
          </template>
        </template>
      </el-table-column>
      <template #empty><el-empty :description="t('common.app.views.cluster.emptyNodes')" :image-size="60" /></template>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useWindowSize } from '@vueuse/core'
import { useI18n } from 'vue-i18n'
import { formatDate } from '@/utils/date'
import { CLUSTER_SYNC_SWITCHES } from '@/utils/clusterSyncSwitches'
import { popperViewportSafe } from '@/utils/popper'
import { List, Setting } from '@element-plus/icons-vue'
import FieldHelpIcon from '@/components/common/FieldHelpIcon.vue'
import type { ClusterHealth, ClusterNode, ClusterNodeStatus, ClusterNodeWithSyncError, ClusterStatus } from '@/types'

// 面板文案走 i18n(批次 D cluster 域,common.app.views.cluster.*)。
const { t } = useI18n()

const props = defineProps<{
  settingsOnly?: boolean
  readonly status: ClusterStatus
  readonly nodes: readonly ClusterNodeWithSyncError[]
  readonly loading: boolean
  readonly tokenLoading: boolean
  readonly settingsLoading: boolean
  readonly pendingNodeId: number | null
  readonly loginNodeId: number | null
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
  (event: 'edit-config', node: ClusterNode): void
}>()

const { width: viewportWidth } = useWindowSize()
const operationColumnFixed = computed<'right' | false>(() => viewportWidth.value > 1440 ? 'right' : false)
// 窄屏优先保留业务列，隐藏健康/最后上报，避免水平滚动。
const showHealthColumn = computed(() => viewportWidth.value >= 1380)
const showLastSeenColumn = computed(() => viewportWidth.value >= 1580)
// 三分类单源 utils/clusterSyncSwitches（父级确认文案同源）；行内注释记录的
// 合并裁定（全局配置并入系统数据、证书文件随 rules 开关、文件差量并入安全
// 防护）随单源一并保留。
const syncSwitchItems = CLUSTER_SYNC_SWITCHES

const syncSwitchFreezeHint = t('common.app.views.cluster.syncFreezeHint')

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
  if (status === 'online') return t('common.app.views.cluster.statusOnline')
  if (status === 'pending') return t('common.app.views.cluster.statusPending')
  return t('common.app.views.cluster.statusOffline')
}

const healthSummary = (health: ClusterHealth): string => {
  const summary = t('common.app.views.cluster.healthSummary', {
    caddy: health.caddy_ok ? t('common.app.views.cluster.healthy') : t('common.app.views.cluster.abnormal'),
    rules: health.rules_count,
    certs: health.certs_expiring_30d,
  })
  return health.last_sync_error ? `${summary} · ${health.last_sync_error}` : summary
}

// 规则库版本行——名称与 SecurityRules 规则库列表严格一致（单源语义：
// CRS 规则库 / IP 地理库 / 威胁情报库 / 爬虫地址库），缺失显示「—」。
// 名称走 i18n（批次 D cluster 域）：tooltip 内容在渲染时解析。
const NODE_LIBRARY_FIELDS = [
  { label: t('common.app.views.cluster.libCrs'), key: 'crs_version' },
  { label: t('common.app.views.cluster.libIpGeo'), key: 'ip2region_version' },
  { label: t('common.app.views.cluster.libThreat'), key: 'threat_version' },
  { label: t('common.app.views.cluster.libCrawler'), key: 'crawler_version' },
] as const satisfies readonly { readonly label: string; readonly key: keyof ClusterHealth }[]

const nodeLibraryVersions = (node: ClusterNodeWithSyncError): { label: string; version: string }[] | null => {
  const health = node.health
  if (!health) return null
  const rows = NODE_LIBRARY_FIELDS.map(({ label, key }) => ({ label, version: health[key] || '—' }))
  // 四个版本全缺失时不挂 tooltip（与服务端未上报版本同形，避免空 tooltip）
  return rows.some(row => row.version !== '—') ? rows : null
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
	const error = (node.health?.last_sync_error ?? '').trim()
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
/* + 2026-09-17 用户实证修正:原豁免覆盖
   全表所有含标签列(配置版本/健康同被压成块级,单行标签失去垂直居中)。
   精确化为「仅状态列且离线时长存在时」才块级叠行——在线(单标签)与
   配置版本/健康列回全局 inline-flex 居中规则。 */
:deep(.el-table td.node-status-col .cell:has(.offline-duration)) { display: block; }

.card-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
:deep(.el-card__body), .el-card { height: 100%; }
.card-tip { font-size: 12px; color: #9ca3af; white-space: nowrap; flex-shrink: 0; }
.settings-form :deep(.el-form-item__label) { white-space: nowrap; }
.settings-form :deep(.el-form-item__content) { flex-wrap: nowrap; }
/* 不换行截断由本页专用修饰类承载——全局 .form-tip-inline 不得在 scoped 中重定义。 */
.settings-form .switch-tip-nowrap { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.mono-value { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
.version-cell { display: flex; align-items: center; gap: 6px; flex-wrap: nowrap; min-width: 0; }
.version-cell-wrap { flex-wrap: wrap; }
/* stale 分支三元素可超 170px——该分支恢复 wrap,主分支
   (两元素版本号+标签)保持 nowrap 消除换行。 */
.version-nums { font-variant-numeric: tabular-nums; white-space: nowrap; }
.offline-duration { font-size: 12px; color: #9ca3af; margin-top: 2px; }
.section-sync-stale { font-size: 12px; color: #9ca3af; }
.section-sync-panel { display: flex; flex-direction: column; gap: 6px; }
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
