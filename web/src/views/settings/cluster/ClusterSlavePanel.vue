<template>
  <el-card class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Refresh /></el-icon>
          <span>{{ t('common.app.views.cluster.slaveActionsTitle') }}</span>
        </div>
      </div>
    </template>

    <!-- 注册终止（confirm 连败/轮询被拒清空 cluster_token）时 last_sync_error
         携带终止文案，优先渲染错误/终止态——registration_id 已清，「等待主节点审批」
         的自动激活不会发生，不能再按无错误时的分支误导用户。 -->
    <el-alert
      v-if="!status.cluster_active && !status.last_sync_error"
      :title="t('common.app.views.cluster.awaitingApprovalTitle')"
      :description="t('common.app.views.cluster.awaitingApprovalDesc')"
      type="warning"
      :closable="false"
      show-icon
      class="state-alert"
    />
    <el-alert
      v-else-if="status.last_sync_error"
      :title="t('common.app.views.cluster.lastSyncFailedTitle')"
      :description="syncErrorDisplay"
      type="error"
      :closable="false"
      show-icon
      class="state-alert"
    />

    <div class="actions">
      <el-button type="primary" :loading="syncing" :disabled="readOnly || !status.cluster_active || promoting" @click="$emit('sync')">
        <el-icon><Refresh /></el-icon>{{ t('common.app.views.cluster.syncNow') }}
      </el-button>
      <!-- PinMismatch 补救——主节点更换管理面板证书后同步持续指纹不匹配，
           「重新注册」复用同一 TOFU transport 无法自救；清空本节点 TOFU 指纹钉
           （POST /cluster/forget-pins）后，下一同步周期按主节点当前证书重新钉扎。 -->
      <el-button v-if="status.sync_error_code === 'pin_mismatch'" type="danger" plain :loading="forgettingPins" :disabled="readOnly || forgettingPins" @click="$emit('forget-pins')">
        {{ t('common.app.views.cluster.forgetPinsAndReregister') }}
      </el-button>
      <el-button :disabled="readOnly || syncing || promoting" @click="$emit('reregister')">{{ t('common.app.views.cluster.reregister') }}</el-button>
      <el-button type="danger" plain :loading="promoting" :disabled="readOnly || syncing" @click="$emit('promote')">{{ t('common.app.views.cluster.promoteToMaster') }}</el-button>
      <span class="promote-tip">{{ t('common.app.views.cluster.promoteTip') }}</span>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatSyncErrorDisplay } from '@/utils/syncErrorDisplay'
import { Refresh } from '@element-plus/icons-vue'
import type { ClusterStatus } from '@/types'

// 面板文案走 i18n(批次 D cluster 域,common.app.views.cluster.*)。
const { t } = useI18n()

const props = defineProps<{
  readonly status: ClusterStatus
  readonly syncing: boolean
  readonly promoting: boolean
  readonly forgettingPins: boolean
  readonly readOnly: boolean
}>()


defineEmits<{
  (event: 'sync'): void
  (event: 'promote'): void
  (event: 'reregister'): void
  (event: 'forget-pins'): void
}>()

// apply_ok_reload_failed 机内标记的展示翻译已收敛至 utils/syncErrorDisplay.ts。
const syncErrorDisplay = computed<string>(() => formatSyncErrorDisplay(props.status))
</script>

<style scoped>
.card-header { display: flex; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.state-alert { margin-bottom: 16px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.promote-tip { font-size: 12px; color: var(--el-text-color-secondary); line-height: 1; }
.actions :deep(.el-button + .el-button) { margin-left: 0; }
</style>
