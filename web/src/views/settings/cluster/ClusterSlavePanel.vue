<template>
  <el-card class="settings-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Refresh /></el-icon>
          <span>从节点操作</span>
        </div>
      </div>
    </template>

    <el-alert
      v-if="!status.cluster_active"
      title="等待主节点审批"
      description="主节点确认后将自动激活同步。您也可以重新注册或提升为主节点。"
      type="warning"
      :closable="false"
      show-icon
      class="state-alert"
    />
    <el-alert
      v-else-if="status.last_sync_error"
      title="最近同步失败"
      :description="status.last_sync_error"
      type="error"
      :closable="false"
      show-icon
      class="state-alert"
    />

    <div class="actions">
      <el-button type="primary" :loading="syncing" :disabled="readOnly || !status.cluster_active || promoting" @click="$emit('sync')">
        <el-icon><Refresh /></el-icon>立即同步
      </el-button>
      <el-button :disabled="readOnly || syncing || promoting" @click="$emit('reregister')">重新注册</el-button>
      <el-button type="danger" plain :loading="promoting" :disabled="readOnly || syncing" @click="$emit('promote')">提升为主节点</el-button>
    </div>
    <div class="form-tip-line">提升后将脱离当前集群，本地数据将成为权威数据。</div>
  </el-card>
</template>

<script setup lang="ts">
import { Refresh } from '@element-plus/icons-vue'
import type { ClusterStatus } from '@/types'

defineProps<{
  readonly status: ClusterStatus
  readonly syncing: boolean
  readonly promoting: boolean
  readonly readOnly: boolean
}>()

defineEmits<{
  (event: 'sync'): void
  (event: 'promote'): void
  (event: 'reregister'): void
}>()
</script>

<style scoped>
.card-header { display: flex; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: var(--text-primary); }
.state-alert { margin-bottom: 16px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
.actions :deep(.el-button + .el-button) { margin-left: 0; }
</style>
