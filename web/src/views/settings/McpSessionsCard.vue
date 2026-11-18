<template>
  <el-card class="list-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon class="title-icon"><Connection /></el-icon>
          <span>{{ t('app.notification.keysSessions.title') }}</span>
        </div>
        <div class="header-side">
          <el-button size="small" :loading="loading" @click="fetchSessions">
            {{ t('app.notification.deliveries.refresh') }}
          </el-button>
        </div>
      </div>
    </template>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.notification.keysSessions.loadFailed') }}</span>
          <el-button link type="danger" @click="fetchSessions">{{ t('common.app.views.audit.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-table v-loading="loading" :data="sessions" stripe :header-cell-style="{ background: '#f9fafb' }" :empty-text="t('app.notification.keysSessions.emptyText')">
      <el-table-column prop="username" :label="t('app.notification.keysSessions.colUser')" min-width="130" show-overflow-tooltip />
      <el-table-column prop="key_name" :label="t('app.notification.keysSessions.colKey')" min-width="140" show-overflow-tooltip />
      <el-table-column prop="ip" label="IP" width="140" show-overflow-tooltip />
      <el-table-column prop="user_agent" label="User-Agent" min-width="180" show-overflow-tooltip />
      <el-table-column :label="t('app.notification.keysSessions.colStatus')" width="100" align="center">
        <template #default="scope">
          <el-tag :type="scope.row.online ? 'success' : 'info'" size="small">
            {{ scope.row.online ? t('app.notification.keysSessions.online') : t('app.notification.keysSessions.offline') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.keysSessions.colLastSeen')" width="170">
        <template #default="scope">{{ formatDate(scope.row.last_seen) || '-' }}</template>
      </el-table-column>
      <el-table-column v-if="isAdmin" :label="t('app.notification.deliveries.colAction')" width="120" align="center">
        <template #default="scope">
          <el-button
            size="small"
            type="danger"
            plain
            :loading="disconnectingId === scope.row.session_id"
            @click="disconnect(scope.row as McpSession)"
          >
            {{ t('app.notification.keysSessions.disconnect') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessageBox } from 'element-plus'
import { Connection } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import type { McpSession, McpSessionsResponse } from '@/types/notifications.ts'

const { t } = useI18n()
const authStore = useAuthStore()

const isAdmin = computed(() => authStore.user?.role === 'admin')
// 会话强制断开是管理员写路径；非管理员固定 ?mine=1 只看自己的会话
const writeBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')

const sessions = ref<McpSession[]>([])
const loading = ref(false)
const loadError = ref(false)
const disconnectingId = ref<string | null>(null)
let sessionsRequestSeq = 0

const fetchSessions = async (): Promise<void> => {
  const seq = ++sessionsRequestSeq
  loading.value = true
  try {
    // 契约：管理员无参数=全平台；非管理员 ?mine=1 仅自己。无 mine=0 参数，
    // 管理员不提供范围切换。
    const query = isAdmin.value ? '' : '?mine=1'
    const res = await request.get<McpSessionsResponse>(`/security/mcp-sessions${query}`)
    if (seq === sessionsRequestSeq) {
      sessions.value = res.data?.sessions ?? []
      loadError.value = false
    }
  } catch (error: unknown) {
    console.error('Failed to fetch MCP sessions:', error)
    if (seq === sessionsRequestSeq) loadError.value = true
  } finally {
    if (seq === sessionsRequestSeq) loading.value = false
  }
}


const disconnect = async (row: McpSession): Promise<void> => {
  if (disconnectingId.value !== null || !isAdmin.value || writeBlocked.value) return
  disconnectingId.value = row.session_id
  try {
    try {
      await ElMessageBox.confirm(
        t('app.notification.keysSessions.disconnectConfirm', { user: row.username }),
        t('app.notification.keysSessions.disconnect'),
        {
          type: 'warning',
          confirmButtonText: t('common.app.views.keys.confirmDelete'),
          cancelButtonText: t('common.app.views.keys.cancel'),
        },
      )
    } catch { return }
    await request.post(`/security/mcp-sessions/${encodeURIComponent(row.session_id)}/disconnect`)
    mfaAwareSuccess(t('app.notification.keysSessions.disconnectSuccess'))
    await fetchSessions()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('Failed to disconnect MCP session:', error)
  } finally {
    disconnectingId.value = null
  }
}

onMounted(() => {
  void fetchSessions()
})

defineExpose({ fetchSessions })
</script>

<style scoped>
.el-card { --el-card-border-color: #ebeef5; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.header-side { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
</style>
