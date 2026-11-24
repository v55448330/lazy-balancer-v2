<template>
  <el-card class="list-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon class="title-icon"><List /></el-icon>
          <span>{{ t('app.notification.rules.deliveriesTab') }}</span>
        </div>
        <div class="card-header-actions">
          <el-select v-model="statusFilter" size="small" class="status-select" :placeholder="t('app.notification.deliveries.statusLabel')">
            <el-option value="" :label="t('app.notification.deliveries.statusAll')" />
            <el-option v-for="st in STATUSES" :key="st" :value="st" :label="statusLabel(st)" />
          </el-select>
          <el-button size="small" :loading="loading" @click="fetchDeliveries">
            {{ t('app.notification.deliveries.refresh') }}
          </el-button>
        </div>
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
      :header-cell-style="{ background: '#f9fafb' }"
      :empty-text="t('app.notification.deliveries.emptyText')"
    >
      <!-- 展开行：分通道投递结果（失败原因与通道一一对应，替代仅 tooltip 的弱关联） -->
      <el-table-column type="expand" width="36">
        <template #default="scope">
          <div class="ch-expand">
            <div v-for="ch in scope.row.channels" :key="ch.channel_id" class="ch-expand-row">
              <el-tag :type="ch.status === 'sent' ? 'success' : 'danger'" size="small" effect="plain" class="ch-expand-name">{{ ch.channel_name }}</el-tag>
              <el-tag :type="channelStatusTagType(ch.status)" size="small">{{ channelStatusLabel(ch.status) }}</el-tag>
              <span class="ch-expand-error" :class="{ 'ch-expand-error-failed': ch.status !== 'sent' }">{{ channelErrorText(ch) }}</span>
              <span class="ch-expand-dur">{{ ch.duration_ms ? ch.duration_ms + ' ms' : '—' }}</span>
            </div>
            <span v-if="!scope.row.channels?.length" class="ev-more">{{ t('app.notification.deliveries.expandEmpty') }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colReqTime')" width="170">
        <template #default="scope">
          {{ formatDate(scope.row.created_at) || '-' }}
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colSentTime')" width="170">
        <template #default="scope">
          {{ formatDate(scope.row.sent_at) || '—' }}
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colUser')" width="130" show-overflow-tooltip>
        <template #default="scope">{{ scope.row.username || ('#' + scope.row.user_id) }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colEvent')" min-width="240" show-overflow-tooltip>
        <template #default="scope">{{ deliveryEventTitle(scope.row) }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colResult')" width="110">
        <template #default="scope">
          <span v-if="scope.row.channels?.length" class="ch-result">
            <span class="ch-ok">{{ channelCount(scope.row, true) }}</span><span class="ch-sep">/</span><span class="ch-fail">{{ channelCount(scope.row, false) }}</span>
          </span>
          <span v-else class="ev-more">—</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colLevel')" width="100">
        <template #default="scope">
          <el-tag :type="levelTagType(scope.row.level)" size="small">
            {{ t(`app.notification.subs.levels.${scope.row.level}`) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colStatus')" width="110">
        <template #default="scope">
          <el-tag :type="statusTagType(scope.row.status)" size="small">{{ statusLabel(scope.row.status) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colAttempts')" width="70">
        <template #default="scope">{{ scope.row.attempts }}</template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colNote')" width="100">
        <template #default="scope">
          <el-tag v-if="scope.row.is_test" size="small" type="info" effect="plain">{{ t('app.notification.deliveries.noteTest') }}</el-tag>
          <span v-else class="ev-more">—</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colAction')" width="110">
        <template #default="scope">
          <el-button
            v-if="isResendable(scope.row as NotificationDelivery)"
            size="small"
            link
            type="primary"
            :loading="resendingId === scope.row.id"
            @click="resend(scope.row as NotificationDelivery)"
          >
            {{ t('app.notification.deliveries.resend') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="deliveries-footer">
      <el-pagination
        class="deliveries-pagination"
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        :page-sizes="[20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @size-change="handleSizeChange"
        @current-change="fetchDeliveries"
      />
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { List } from '@element-plus/icons-vue'
import { ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { hasOwn } from '@/utils/hasOwn'
import { latestChannelResults, channelErrorKind, channelStatusMessageKey, channelStatusTagType } from '@/utils/deliveryLog'
import type {
  DeliveryStatus,
  NotificationDeliveriesResponse,
  NotificationDelivery,
} from '@/types/notifications.ts'

const { t, tm } = useI18n()

// 契约：page_size 默认 50 上限 200；?status= 过滤；恒全量（投递记录不区分用户视角）。
const DELIVERY_PAGE_SIZE = 50
const STATUSES: readonly DeliveryStatus[] = ['pending', 'sent', 'partial', 'failed', 'dead']
/** 失败态（failed / dead）重发全部通道；partial 仅重发失败通道（failed_only）。
 *  pending 由投递任务接管、sent 无需重发。 */
const RESENDABLE: readonly DeliveryStatus[] = ['failed', 'dead']

const deliveries = ref<NotificationDelivery[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(DELIVERY_PAGE_SIZE)
const loading = ref(false)
const loadError = ref(false)
const statusFilter = ref<DeliveryStatus | ''>('')
const resendingId = ref<number | null>(null)
let deliveriesRequestSeq = 0

// 事件可读标题多语言（tm 原始对象索引，键含点号不走 t 路径解析）；
// 回退后端 event_title（catalog 中文单源），再回退事件键。日报标题同此渲染。
const deliveryEventTitle = (raw: unknown): string => {
  const row = raw as NotificationDelivery
  const m = (tm('app.notification.eventTitles') || {}) as Record<string, string>
  if (hasOwn(m, row.event_type)) return m[row.event_type]
  return row.event_title || row.title || row.event_type
}

const statusLabel = (status: DeliveryStatus): string => {
  switch (status) {
    case 'pending': return t('app.notification.deliveries.statusPending')
    case 'sent': return t('app.notification.deliveries.statusSent')
    case 'partial': return t('app.notification.deliveries.statusPartial')
    case 'failed': return t('app.notification.deliveries.statusFailed')
    case 'dead': return t('app.notification.deliveries.statusDead')
  }
}

const statusTagType = (status: DeliveryStatus): 'info' | 'success' | 'warning' | 'danger' => {
  switch (status) {
    case 'pending': return 'info'
    case 'sent': return 'success'
    case 'partial': return 'warning'
    case 'failed': return 'danger'
    case 'dead': return 'danger'
  }
}

// 分通道状态标签（行内通道 status 为 string）：已知状态走词条，未知状态原样
// 回显（不得伪装成「失败」——见 utils/deliveryLog 契约）。
const channelStatusLabel = (status: string): string => {
  const key = channelStatusMessageKey(status)
  return key ? t(`app.notification.deliveries.${key}`) : status
}

// 展开行错误文案：失败但无错误时不得显示「无错误」（与红色失败标签自相矛盾）。
const channelErrorText = (ch: { status: string; error?: string | null }): string => {
  switch (channelErrorKind(ch)) {
    case 'error': return (ch.error ?? '').trim()
    case 'missing': return t('app.notification.deliveries.expandErrorMissing')
    default: return t('app.notification.deliveries.expandNoError')
  }
}

// channelCount 通道结果计数（success=sent 数；否则=非 sent 数）。表格「成功/失败」列。
const channelCount = (row: { channels?: { status: string }[] }, success: boolean): number => {
  const chs = row.channels ?? []
  return chs.filter(ch => (ch.status === 'sent') === success).length
}

const levelTagType = (level: NotificationDelivery['level']): 'info' | 'warning' | 'danger' => {
  switch (level) {
    case 'info': return 'info'
    case 'warn': return 'warning'
    case 'critical': return 'danger'
  }
}

const isResendable = (row: NotificationDelivery): boolean => RESENDABLE.includes(row.status) || row.status === 'partial'

const fetchDeliveries = async (): Promise<void> => {
  const seq = ++deliveriesRequestSeq
  loading.value = true
  try {
    const params = new URLSearchParams()
    params.set('page', String(page.value))
    params.set('page_size', String(pageSize.value))
    if (statusFilter.value) params.set('status', statusFilter.value)
    const res = await request.get<NotificationDeliveriesResponse>(`/notification/deliveries?${params.toString()}`)
    if (seq === deliveriesRequestSeq) {
      // 同通道重试会追加多行结果（每次尝试一行）：装载即收敛为最新行，
      // 否则展开列表重复、成功/失败计数被历史重试放大。
      deliveries.value = (res.data?.deliveries ?? []).map(d => ({
        ...d,
        channels: latestChannelResults(d.channels ?? []),
      }))
      total.value = res.data?.total ?? 0
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
  // 重发为写操作需确认；partial 仅重发失败通道（failed_only），其余重发全部。
  const partial = row.status === 'partial'
  try {
    await ElMessageBox.confirm(
      partial ? t('app.notification.deliveries.resendPartialConfirm') : t('app.notification.deliveries.resendConfirm'),
      t('app.notification.deliveries.confirmTitle'), { type: 'warning' })
  } catch { return }
  resendingId.value = row.id
  try {
    if (partial) await request.post(`/notification/deliveries/${row.id}/resend`, { failed_only: true })
    else await request.post(`/notification/deliveries/${row.id}/resend`)
    mfaAwareSuccess(t('app.notification.deliveries.resendSuccess'))
    await fetchDeliveries()
  } catch (error: unknown) {
    console.error('Failed to resend notification delivery:', error)
  } finally {
    resendingId.value = null
  }
}

// 过滤条件变化立即重查并回到首页（状态过滤是廉价 GET）
watch(statusFilter, () => {
  page.value = 1
  void fetchDeliveries()
})

// 页容量变化回到首页（避免越界空页）
const handleSizeChange = (): void => {
  page.value = 1
  void fetchDeliveries()
}

onMounted(() => {
  void fetchDeliveries()
})

defineExpose({ fetchDeliveries })
</script>

<style scoped>
.el-card { --el-card-border-color: #ebeef5; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.status-select { width: 130px; }
.deliveries-footer { margin-top: 16px; display: flex; align-items: center; justify-content: flex-end; gap: 16px; flex-wrap: nowrap; }
.deliveries-pagination { flex: 0 0 auto; white-space: nowrap; }
.ch-result { font-size: 13px; font-weight: 600; }
.ch-result .ch-ok { color: #10b981; }
.ch-result .ch-sep { color: #9ca3af; margin: 0 2px; }
.ch-result .ch-fail { color: #ef4444; }
.ev-more { font-size: 11px; color: #6b7280; }
/* 展开行：分通道投递结果（通道-状态-错误一一对应） */
.ch-expand { padding: 4px 12px 8px 36px; display: flex; flex-direction: column; gap: 6px; }
.ch-expand-row { display: flex; align-items: center; gap: 8px; min-height: 24px; }
.ch-expand-name { flex: none; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
.ch-expand-dur { flex: none; color: #6b7280; font-size: 12px; font-variant-numeric: tabular-nums; }
.ch-expand-error { font-size: 12px; line-height: 1.5; color: #6b7280; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.ch-expand-error-failed { color: #dc2626; }
</style>
