<template>
  <!-- 累犯历史弹框（总览「累犯升级」统计与事件页 autoban 卡共用）：
       参照仪表盘连接弹框的宽体形态——1280px + 筛选工具行 + 固定表高 + 分页。
       GET /security/autoban/recidivism（offense_count 降序、identity 升序，后端
       单源排序）。处置双通道：IP 快捷弹框（加黑/白/信任名单即中断累犯）+
       操作列移除（删行+清桶/建议打断累犯流程；封禁中禁用，须先取消封禁）；
       重置=清空全部历史（DELETE 同端点，二次确认，只清历史记账、
       不动已生效封禁条目）。写门与事件页 autobanWritable 同口径：只读契约/
       从节点/状态未就绪一律禁用（writable/blockedReason 由宿主传入）。 -->
  <el-dialog :model-value="modelValue" width="min(1280px, 96vw)" top="5vh" append-to-body class="dialog-body-inset" :close-on-click-modal="false" @update:model-value="emit('update:modelValue', $event)">
    <template #header>
      <DialogHeader :icon="Lock" :title="t('app.security.overview.autoban.recidivismDialogTitle')" :subtitle="t('app.security.overview.autoban.recidivismDialogSubtitle')" />
    </template>
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
        <!-- IP 地址列：身份键展示 CIDR 形态（单源 autobanIdentityDisplay），并复用
             IP 快捷弹框（IPLocationAction）做黑/白/信任处置——popover teleport 到
             body，层级高于本弹框，无嵌套冲突。加名单成功后端同步清该身份累犯记账，
             changed 回调重取列表并联动宿主状态卡。 -->
        <el-table-column :label="t('app.security.overview.autoban.recidivismColIdentity')" min-width="240">
          <template #default="{ row }">
            <IPLocationAction :ip="autobanIdentityDisplay(row.identity)" :location="row.ip_location || ''" @changed="onIpActionChanged" />
          </template>
        </el-table-column>
        <!-- 当前状态列：join 自动封禁名单生效条目（后端 ban_status 三态），
             一眼看出该累犯是否正在被封；限时封禁 tooltip 披露到期时刻，剩余
             时长走名单条目展示单源（autobanEntryRemaining）。 -->
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
        <!-- 「下次封禁」=按当前档位+累计次数推算的预期时长（单源
             autobanNextBanDuration，与后端档位映射对表）；tooltip 披露上次实际
             执法时长（历史留痕，配置变更后可能与当前档位不同） -->
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
        <!-- 操作列：移除单条累犯身份（DELETE /:identity，二次确认；后端同步
             清计数桶/观察建议打断累犯流程）。封禁中（ban_status timed/permanent）
             禁用——须先从 IP 快捷弹框取消封禁（hover 提示）；写门同重置
             （writable/blockedReason 由宿主传入）。 -->
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
      <div class="recid-pagination">
        <el-pagination v-model:current-page="page" v-model:page-size="pageSize" :total="total" :page-sizes="[20, 50, 100]" layout="total, sizes, prev, pager, next" small @size-change="onPageSizeChange" @current-change="fetchRecords" />
      </div>
    </template>
    <!-- footer 统一惯例：破坏性操作（重置）左对齐分离，关闭右对齐
         （与配置弹框 cancel→save 的右对齐主操作同体系） -->
    <template #footer>
      <div class="recidivism-footer">
        <el-tooltip :content="blockedReason" :disabled="writable" placement="top">
          <span>
            <el-button type="danger" plain :disabled="!writable || resetting" :loading="resetting" @click="resetRecords">{{ t('app.security.overview.autoban.recidivismReset') }}</el-button>
          </span>
        </el-tooltip>
        <el-button @click="emit('update:modelValue', false)">{{ t('app.security.overview.autoban.recidivismClose') }}</el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Lock, Search, InfoFilled } from '@element-plus/icons-vue'
import { ElMessageBox } from 'element-plus'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatDate, parseDbTimeMs } from '@/utils/date'
import { autobanEntryRemaining } from '@/utils/autobanEntry'
import { autobanDurationLabel, autobanIdentityDisplay, autobanNextBanDuration } from '@/utils/autobanStatus'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import { useRecidivismList, type RecidivismRecord } from '@/composables/useRecidivismList'
import type { APIResponse } from '@/types'

// 宿主契约：writable/blockedReason 与宿主 autoban 写门同口径；duration/escalation
// 为当前配置实态（「下次封禁」预期按此推算）；重置/快捷弹框写动作成功后
// emit('reset') 由宿主刷新自身状态卡（escalated_count 联动）。
const props = defineProps<{
  readonly modelValue: boolean
  readonly writable: boolean
  readonly blockedReason: string
  readonly duration: string
  readonly escalation?: string
}>()
const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'reset'): void
}>()

const { t } = useI18n()

// 数据面=服务端分页单源（useRecidivismList）：fetchRecords 携
// hide_permanent/ip/page/page_size 参数，total 取响应（筛选后总数），
// 页码越界回夹同口径；ip_location 为后端富化字段（enrichIPLocation 单源；
// 无 xdb/旧后端缺省空串），缺失时归属地段不渲染。
const { records, total, loading, loadError, hidePermanent, ipQuery, page, pageSize, fetchRecords, open, invalidate } = useRecidivismList(async ({ hidePermanent: hide, ip, page: p, pageSize: size }) => {
  const params = new URLSearchParams({ hide_permanent: String(hide), page: String(p), page_size: String(size) })
  if (ip) params.set('ip', ip)
  const res = await request.get<APIResponse<{ records: RecidivismRecord[]; total: number }>>(`/security/autoban/recidivism?${params}`, { silent: true })
  return { records: res.data?.records || [], total: res.data?.total || 0 }
})

// 固定表高（参照连接弹框）：行多表格内垂直滚动，行少留白尺寸恒定。
const TABLE_HEIGHT = 480
// 全量重置在途锁：防重入，驱动重置按钮 loading。
const resetting = ref(false)
// 单条移除在途身份：占位防重入，同时驱动该行按钮 loading。
const removingIdentity = ref<string | null>(null)

// 打开即复位筛选并拉取（每次打开取最新历史；关闭再开不沿用陈旧快照）；
// 关闭作废在途响应（快速关开时旧响应不得写回新会话）。
watch(() => props.modelValue, (visible) => { if (visible) open(); else invalidate() })
// 页大小变化回首页（与事件页 handleSizeChange 同口径）；watch 合并同一
// tick 的回首页写入，只发一次携参请求。
const onPageSizeChange = (): void => { page.value = 1 }

// 快捷弹框写动作完成（加黑/白/信任名单）：后端 AddIPToList 已同步清该身份的
// 累犯记账——重取列表让该行消失，并 emit('reset') 由宿主刷新状态卡
// （escalated_count 联动，与重置同一刷新出口）。
const onIpActionChanged = (): void => {
  void fetchRecords()
  emit('reset')
}

// 「下次封禁」预期：now/last_ban_at 经 DB 墙钟单源解析（配置时区口径与
// formatDate 一致）；解析失败不做衰减推算（与后端同口径）。
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

// 单条移除：DELETE /:identity（identity 经 URL 编码，兼容 IPv6/带斜杠形态）。
// 后端同步清计数桶/观察建议（打断累犯流程）；封禁中身份后端 400 拒绝
// （前端按钮已禁用，此处为 API 面兜底）。成功后重取列表+emit('reset')
// 联动宿主状态卡（与重置/快捷弹框同一刷新出口）。
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
/* IP 列身份形态（CIDR/等宽/截断）与快捷弹框内单元同源（IPLocationAction 的
   ip-cell/ip-text/ip-loc），此处不再重复一套展示样式。 */
.recid-next-duration { cursor: help; border-bottom: 1px dashed #c0c4cc; }
.recid-pagination { display: flex; justify-content: flex-end; margin-top: 12px; }
.recidivism-footer { display: flex; align-items: center; justify-content: space-between; }
@media (max-width: 768px) {
  .recid-toolbar { align-items: flex-start; }
  .recid-ip-input { width: 100%; }
}
</style>
