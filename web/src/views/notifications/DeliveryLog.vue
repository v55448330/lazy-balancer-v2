<template>
  <el-card shadow="never">
    <template #header>
      <div class="card-header-row">
        <div class="delivery-filters">
          <el-select v-model="statusFilter" size="small" class="status-select" :placeholder="t('app.notification.deliveries.statusLabel')">
            <el-option value="" :label="t('app.notification.deliveries.statusAll')" />
            <el-option v-for="st in STATUSES" :key="st" :value="st" :label="statusLabel(st)" />
          </el-select>
          <template v-if="isAdmin">
            <el-switch v-model="allScope" :active-text="t('app.notification.deliveries.allScope')" />
            <span class="scope-hint">{{ t('app.notification.deliveries.allScopeHint') }}</span>
          </template>
        </div>
        <el-button size="small" :loading="loading" @click="fetchDeliveries">
          {{ t('app.notification.deliveries.refresh') }}
        </el-button>
      </div>
    </template>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.notification.deliveries.loadFailed') }}</span>
          <el-button link type="danger" @click="fetchDeliveries">{{ t('common.app.views.audit.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-table
      v-loading="loading"
      :data="deliveries"
      stripe
      :empty-text="t('app.notification.deliveries.emptyText')"
    >
      <el-table-column :label="t('app.notification.deliveries.colTime')" width="170">
        <template #default="scope">
          {{ formatDate(scope.row.created_at) || '-' }}
        </template>
      </el-table-column>
      <el-table-column v-if="isAdmin && allScope" :label="t('app.notification.deliveries.colUser')" width="90" align="center">
        <template #default="scope">#{{ scope.row.user_id }}</template>
      </el-table-column>
      <el-table-column prop="event_type" label="Event" min-width="170" show-overflow-tooltip />
      <el-table-column :label="t('app.notification.deliveries.colEvent')" min-width="200" show-overflow-tooltip>
        <template #default="scope">{{ scope.row.title || scope.row.event_type }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colLevel')" width="100" align="center">
        <template #default="scope">
          <el-tag :type="levelTagType(scope.row.level)" size="small">
            {{ t(`app.notification.subs.levels.${scope.row.level}`) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colStatus')" width="110" align="center">
        <template #default="scope">
          <el-tag :type="statusTagType(scope.row.status)" size="small">{{ statusLabel(scope.row.status) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="#" width="70" align="center">
        <template #default="scope">{{ scope.row.attempts }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colError')" min-width="200" show-overflow-tooltip>
        <template #default="scope">{{ scope.row.error || '-' }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colAction')" width="110" align="center">
        <template #default="scope">
          <el-button
            v-if="isResendable(scope.row as NotificationDelivery)"
            size="small"
            type="warning"
            plain
            :loading="resendingId === scope.row.id"
            @click="resend(scope.row as NotificationDelivery)"
          >
            {{ t('app.notification.deliveries.resend') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/utils/date'
import type {
  DeliveryStatus,
  NotificationDeliveriesResponse,
  NotificationDelivery,
} from '@/types/notifications.ts'

const { t } = useI18n()
const authStore = useAuthStore()

const isAdmin = computed(() => authStore.user?.role === 'admin')
// 契约：limit 默认 50 上限 200；?status= 过滤；管理员 ?all=1 全平台。
const DELIVERY_LIMIT = 50
const STATUSES: readonly DeliveryStatus[] = ['pending', 'sent', 'failed', 'dead']
/** 失败态（failed / dead）提供重发入口；pending 由投递任务接管、sent 无需重发。 */
const RESENDABLE: readonly DeliveryStatus[] = ['failed', 'dead']

const deliveries = ref<NotificationDelivery[]>([])
const loading = ref(false)
const loadError = ref(false)
const statusFilter = ref<DeliveryStatus | ''>('')
const allScope = ref(false)
const resendingId = ref<number | null>(null)
let deliveriesRequestSeq = 0

const statusLabel = (status: DeliveryStatus): string => {
  switch (status) {
    case 'pending': return t('app.notification.deliveries.statusPending')
    case 'sent': return t('app.notification.deliveries.statusSent')
    case 'failed': return t('app.notification.deliveries.statusFailed')
    case 'dead': return t('app.notification.deliveries.statusDead')
  }
}

const statusTagType = (status: DeliveryStatus): 'info' | 'success' | 'warning' | 'danger' => {
  switch (status) {
    case 'pending': return 'info'
    case 'sent': return 'success'
    case 'failed': return 'warning'
    case 'dead': return 'danger'
  }
}

const levelTagType = (level: NotificationDelivery['level']): 'info' | 'warning' | 'danger' => {
  switch (level) {
    case 'info': return 'info'
    case 'warn': return 'warning'
    case 'critical': return 'danger'
  }
}

const isResendable = (row: NotificationDelivery): boolean => RESENDABLE.includes(row.status)

const fetchDeliveries = async (): Promise<void> => {
  const seq = ++deliveriesRequestSeq
  loading.value = true
  try {
    const params = new URLSearchParams()
    params.set('limit', String(DELIVERY_LIMIT))
    if (statusFilter.value) params.set('status', statusFilter.value)
    if (isAdmin.value && allScope.value) params.set('all', '1')
    const res = await request.get<NotificationDeliveriesResponse>(`/notification/deliveries?${params.toString()}`)
    if (seq === deliveriesRequestSeq) {
      deliveries.value = res.data?.deliveries ?? []
      loadError.value = false
    }
  } catch (error: unknown) {
    console.error('Failed to fetch notification deliveries:', error)
    if (seq === deliveriesRequestSeq) loadError.value = true
  } finally {
    if (seq === deliveriesRequestSeq) loading.value = false
  }
}

const resend = async (row: NotificationDelivery): Promise<void> => {
  if (resendingId.value !== null) return
  resendingId.value = row.id
  try {
    await request.post(`/notification/deliveries/${row.id}/resend`)
    mfaAwareSuccess(t('app.notification.deliveries.resendSuccess'))
    await fetchDeliveries()
  } catch (error: unknown) {
    console.error('Failed to resend notification delivery:', error)
  } finally {
    resendingId.value = null
  }
}

// 过滤条件变化立即重查（状态过滤/全平台开关都是廉价 GET）
watch([statusFilter, allScope], () => {
  void fetchDeliveries()
})

onMounted(() => {
  void fetchDeliveries()
})

defineExpose({ fetchDeliveries })
</script>

<style scoped>
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.delivery-filters { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.status-select { width: 130px; }
.scope-hint { font-size: 12px; color: var(--text-secondary, #6b7280); }
</style>
