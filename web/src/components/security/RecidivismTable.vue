<template>
  <!-- 累犯前科表格（共享组件）：总览下钻弹框与事件页「封禁与累犯」合并弹框
       tab2 共用。数据面=useRecidivismList 服务端分页单源；处置双通道：
       IP 快捷弹框（加名单即中断累犯）+ 操作列移除（封禁中禁用）；
       重置=清空全部历史记账（不动已生效封禁条目）。
       active 由宿主控制（弹框可见/tab 选中）：true 复位筛选拉取，false 作废在途。 -->
  <div v-if="loadError" class="info-note-bar autoban-warn-bar">
    <span class="info-note-desc">{{ t('app.security.overview.autoban.recidivismLoadFailed') }}</span>
    <el-button size="small" type="primary" plain @click="fetchRecords">{{ t('app.security.overview.autoban.recidivismRetry') }}</el-button>
  </div>
  <template v-else>
    <!-- 筛选工具行：默认隐藏永久封禁 + IP 子串搜索（左）；定期清理披露（右） -->
    <div class="recid-toolbar">
      <div class="recid-filters">
        <span class="recid-toggle">
          <el-switch v-model="hidePermanent" size="small" />
          <span>{{ t('app.security.overview.autoban.recidivismHidePermanent') }}</span>
        </span>
        <el-input v-model="ipQuery" class="recid-ip-input" size="small" :prefix-icon="Search" clearable :placeholder="t('app.security.overview.autoban.recidivismIpPlaceholder')" @keyup.enter="fetchRecords" />
      </div>
      <div class="recid-cleanup">
        <el-icon><InfoFilled /></el-icon>
        <span>{{ t('app.security.overview.autoban.recidivismCleanupNote') }}</span>
      </div>
    </div>
    <el-table v-loading="loading" :data="records" size="small" :height="TABLE_HEIGHT" :header-cell-style="{ background: '#f9fafb' }">
      <template #empty><el-empty :description="t('app.security.overview.autoban.recidivismEmpty')" :image-size="60" /></template>
      <!-- IP 地址列：身份键 CIDR 形态单源 + IP 快捷弹框处置（popover teleport
           到 body 无嵌套冲突）；changed 回调重取列表并 emit('reset') 联动宿主。 -->
      <el-table-column :label="t('app.security.overview.autoban.recidivismColIdentity')" min-width="240">
        <template #default="{ row }">
          <IPLocationAction :ip="autobanIdentityDisplay(row.identity)" :location="row.ip_location || ''" @changed="onIpActionChanged" />
        </template>
      </el-table-column>
      <!-- 当前状态列：join 名单生效条目三态；限时 tooltip 披露到期时刻。 -->
      <el-table-column :label="t('app.security.overview.autoban.recidivismColStatus')" width="150" align="center">
        <template #default="{ row }">
          <el-tag v-if="row.ban_status === 'permanent'" type="danger" size="small" effect="light">{{ t('app.security.ipLocation.autoban.permanent') }}</el-tag>
          <el-tooltip v-else-if="row.ban_status === 'timed'" :content="formatDate(row.ban_expires_at)" placement="top">
            <el-tag type="warning" size="small" effect="light">{{ t('app.security.ipLocation.autoban.stateActive') }} · {{ autobanEntryRemaining(row.ban_expires_at || '') }}</el-tag>
          </el-tooltip>
          <el-tag v-else type="info" size="small" effect="plain">{{ t('app.security.overview.autoban.recidivismStatusNone') }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.security.overview.autoban.recidivismColHits24h')" width="90" align="center">
        <template #default="{ row }">{{ row.hits_24h ?? 0 }}</template>
      </el-table-column>
      <el-table-column :label="t('app.security.overview.autoban.recidivismColOffenses')" width="100" align="center">
        <template #default="{ row }">{{ row.offense_count }} {{ t('app.security.overview.autoban.times') }}</template>
      </el-table-column>
      <el-table-column :label="t('app.security.overview.autoban.recidivismColLastBan')" width="160">
        <template #default="{ row }">{{ row.last_ban_at ? formatDate(row.last_ban_at) : '—' }}</template>
      </el-table-column>
      <!-- 「下次封禁」=当前档位+累计次数推算（autobanNextBanDuration 单源）；
           tooltip 披露上次实际执法时长。 -->
      <el-table-column :label="t('app.security.overview.autoban.recidivismColNextBan')" width="110" align="center">
        <template #default="{ row }">
          <el-tooltip :content="t('app.security.overview.autoban.recidivismLastDurationTip', { duration: autobanDurationLabel(row.escalated_duration) })" placement="top">
            <span class="recid-next-duration">{{ autobanDurationLabel(nextBanDurationOf(row as RecidivismRecord)) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.security.overview.autoban.recidivismColLastEvent')" width="160">
        <template #default="{ row }">{{ row.last_event_at ? formatDate(row.last_event_at) : '—' }}</template>
      </el-table-column>
      <!-- 操作列：移除单条记账（封禁中禁用，须先取消封禁）。 -->
      <el-table-column :label="t('app.security.overview.autoban.recidivismColActions')" width="100" align="center">
        <template #default="{ row }">
          <el-tooltip :content="row.ban_status && row.ban_status !== 'none' ? t('app.security.overview.autoban.recidivismRemoveBannedTip') : blockedReason" :disabled="writable && (!row.ban_status || row.ban_status === 'none')" placement="top">
            <span>
              <el-button size="small" type="danger" plain :disabled="!writable || (row.ban_status && row.ban_status !== 'none') || removingIdentity !== null" :loading="removingIdentity === row.identity" @click="removeRecord(row as RecidivismRecord)">{{ t('app.security.overview.autoban.recidivismRemove') }}</el-button>
            </span>
          </el-tooltip>
        </template>
      </el-table-column>
    </el-table>
    <div class="recid-bottom">
      <!-- 破坏性操作（重置）左对齐分离，分页右对齐（弹框 footer 惯例内联化）。 -->
      <el-tooltip :content="blockedReason" :disabled="writable" placement="top">
        <span>
          <el-button type="danger" plain size="small" :disabled="!writable || resetting" :loading="resetting" @click="resetRecords">{{ t('app.security.overview.autoban.recidivismReset') }}</el-button>
        </span>
      </el-tooltip>
      <!-- 翻页/改页大小由 composable 的 watch([hidePermanent,page,pageSize]) 统一携参
           重取（含首页回夹）——不再挂 @current-change，否则翻页会双发请求。 -->
      <el-pagination v-model:current-page="page" v-model:page-size="pageSize" :total="total" :page-sizes="[20, 50, 100]" layout="total, sizes, prev, pager, next" small @size-change="onPageSizeChange" />
    </div>
  </template>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Search, InfoFilled } from '@element-plus/icons-vue'
import { ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatDate, parseDbTimeMs } from '@/utils/date'
import { autobanEntryRemaining } from '@/utils/autobanEntry'
import { autobanDurationLabel, autobanIdentityDisplay, autobanNextBanDuration } from '@/utils/autobanStatus'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import { useRecidivismList, type RecidivismRecord } from '@/composables/useRecidivismList'
import type { APIResponse } from '@/types'

// 宿主契约：writable/blockedReason 与宿主 autoban 写门同口径；duration/escalation
// 为当前配置实态（「下次封禁」预期按此推算）；active=宿主可见性（弹框开关/tab
// 切换）；重置/快捷弹框写动作成功后 emit('reset') 由宿主刷新状态卡。
const props = defineProps<{
  readonly active: boolean
  readonly writable: boolean
  readonly blockedReason: string
  readonly duration: string
  readonly escalation?: string
}>()
const emit = defineEmits<{
  (e: 'reset'): void
}>()

const { t } = useI18n()

// 数据面=服务端分页单源（useRecidivismList）。
const { records, total, loading, loadError, hidePermanent, ipQuery, page, pageSize, fetchRecords, open, invalidate } = useRecidivismList(async ({ hidePermanent: hide, ip, page: p, pageSize: size }) => {
  const params = new URLSearchParams({ hide_permanent: String(hide), page: String(p), page_size: String(size) })
  if (ip) params.set('ip', ip)
  const res = await request.get<APIResponse<{ records: RecidivismRecord[]; total: number }>>(`/security/autoban/recidivism?${params}`, { silent: true })
  return { records: res.data?.records || [], total: res.data?.total || 0 }
})

// 固定表高：行多表格内垂直滚动，行少留白尺寸恒定。
const TABLE_HEIGHT = 480
const resetting = ref(false)
const removingIdentity = ref<string | null>(null)

// active 翻转：true 复位筛选拉取最新；false 作废在途响应。
watch(() => props.active, (visible) => { if (visible) open(); else invalidate() }, { immediate: true })
const onPageSizeChange = (): void => { page.value = 1 }

const onIpActionChanged = (): void => {
  void fetchRecords()
  emit('reset')
}

const nextBanDurationOf = (row: RecidivismRecord): string =>
  autobanNextBanDuration(
    { duration: props.duration, escalation: props.escalation },
    row,
    Date.now(),
    row.last_ban_at ? parseDbTimeMs(row.last_ban_at) : null,
  )

const resetRecords = async (): Promise<void> => {
  if (resetting.value || !props.writable) return
  try {
    await ElMessageBox.confirm(
      t('app.security.overview.autoban.recidivismResetConfirm'),
      t('app.security.overview.autoban.recidivismResetTitle'),
      { confirmButtonText: t('app.security.overview.autoban.recidivismResetConfirmBtn'), cancelButtonText: t('app.security.events.cancel'), type: 'warning' },
    )
  } catch { return }
  resetting.value = true
  try {
    await request.delete('/security/autoban/recidivism')
    mfaAwareSuccess(t('app.security.overview.autoban.recidivismResetDone'))
    void fetchRecords()
    emit('reset')
  } catch { /* 错误已由全局拦截器 toast */ }
  finally { resetting.value = false }
}

const removeRecord = async (row: RecidivismRecord): Promise<void> => {
  if (removingIdentity.value !== null || !props.writable) return
  if (row.ban_status && row.ban_status !== 'none') return
  try {
    await ElMessageBox.confirm(
      t('app.security.overview.autoban.recidivismRemoveConfirm', { ip: autobanIdentityDisplay(row.identity) }),
      t('app.security.overview.autoban.recidivismRemoveTitle'),
      { confirmButtonText: t('app.security.overview.autoban.recidivismRemoveConfirmBtn'), cancelButtonText: t('app.security.events.cancel'), type: 'warning' },
    )
  } catch { return }
  removingIdentity.value = row.identity
  try {
    await request.delete(`/security/autoban/recidivism/${encodeURIComponent(row.identity)}`)
    mfaAwareSuccess(t('app.security.overview.autoban.recidivismRemoveDone'))
    void fetchRecords()
    emit('reset')
  } catch { /* 错误已由全局拦截器 toast */ }
  finally { removingIdentity.value = null }
}
</script>

<style scoped>
/* 工具行：筛选（左）/ 定期清理披露（右），窄视口换行不挤压。 */
.recid-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.recid-filters { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.recid-toggle { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-regular); white-space: nowrap; }
.recid-ip-input { width: 220px; }
.recid-cleanup { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-secondary); min-width: 0; line-height: 1.5; }
.recid-cleanup .el-icon { flex: none; }
.recid-next-duration { cursor: help; border-bottom: 1px dashed #c0c4cc; }
.recid-bottom { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
@media (max-width: 768px) {
  .recid-toolbar { align-items: flex-start; }
  .recid-ip-input { width: 100%; }
}
</style>
