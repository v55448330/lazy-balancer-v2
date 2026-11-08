<template>
  <el-card v-loading="loading" class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Monitor /></el-icon>
          <span>{{ t('common.app.views.cluster.currentNodeStatus') }}</span>
        </div>
      </div>
    </template>

    <el-descriptions v-if="status" :column="3" border class="status-descriptions">
      <el-descriptions-item :label="t('common.app.views.cluster.roleLabel')">
        <el-tag :type="status.node_mode === 'master' ? 'success' : 'warning'" size="small">
          {{ status.node_mode === 'master' ? t('common.app.views.cluster.master') : t('common.app.views.cluster.slave') }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item :label="t('common.app.views.cluster.clusterStatusLabel')">
        <el-tag :type="status.cluster_active ? 'success' : 'warning'" size="small">
          {{ status.cluster_active ? t('common.app.views.cluster.activated') : t('common.app.views.cluster.notActivated') }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item :label="status.node_mode === 'master' ? t('common.app.views.cluster.colConfigVersion') : t('common.app.views.cluster.appliedVersion')">
        {{ status.node_mode === 'master' ? status.cluster_version : status.applied_version }}
      </el-descriptions-item>

      <template v-if="status.node_mode === 'master'">
        <el-descriptions-item :label="t('common.app.views.cluster.pendingNodes')">{{ status.pending_count }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.cluster.approvedNodes')">{{ status.approved_count }}</el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.cluster.syncIntervalLabel')">{{ t('common.app.views.cluster.intervalSecondsValue', { count: status.sync_interval }) }}</el-descriptions-item>
      </template>

      <template v-else>
        <el-descriptions-item :label="t('common.app.views.cluster.masterUrlLabel')" :span="2">
          <span class="mono-value">{{ status.master_url || '-' }}</span>
        </el-descriptions-item>
        <el-descriptions-item :label="t('common.app.views.cluster.lastSyncLabel')">{{ formatDate(status.last_sync_at) || '-' }}</el-descriptions-item>
        <!-- 明文链路常驻提示（注册时刻的一次性审计之外，稳态也要可见）-->
        <el-descriptions-item v-if="status.transport_insecure" :label="t('common.app.views.cluster.transportLabel')" :span="3">
          <span class="error-text">{{ t('common.app.views.cluster.plainHttpWarning') }}</span>
        </el-descriptions-item>
        <el-descriptions-item v-if="status.last_sync_error" :label="t('common.app.views.cluster.syncErrorLabel')" :span="3">
          <span class="error-text">{{ syncErrorDisplay }}</span>
        </el-descriptions-item>
      </template>
    </el-descriptions>
    <!-- 拉取失败且无数据时改「加载失败」，与父级错误横幅口径一致。-->
    <el-empty v-else :description="error ? t('common.app.views.cluster.loadFailed') : t('common.app.views.cluster.noNodeStatus')" :image-size="60" />
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatDate } from '@/utils/date'
import { formatSyncErrorDisplay } from '@/utils/syncErrorDisplay'
import { Monitor } from '@element-plus/icons-vue'
import type { ClusterStatus } from '@/types'

// 卡片文案走 i18n(批次 D cluster 域,common.app.views.cluster.*)。
const { t } = useI18n()

const props = defineProps<{
  readonly status: ClusterStatus | null
  readonly loading: boolean
  /** 父级轮询错误态——无数据时的空态文案据此切「加载失败」。*/
  readonly error?: boolean
}>()

// apply_ok_reload_failed 机内标记的展示翻译已收敛至 utils/syncErrorDisplay.ts。
const syncErrorDisplay = computed<string>(() => formatSyncErrorDisplay(props.status))
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
