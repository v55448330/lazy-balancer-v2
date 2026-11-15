<template>
  <!-- 累犯历史弹框（总览「累犯升级」统计与事件页 autoban 卡共用）：
       GET /security/autoban/recidivism（offense_count 降序、identity 升序，
       后端单源排序）；重置=清空全部历史（DELETE 同端点，二次确认，只清历史
       记账、不动已生效封禁条目）。写门与事件页 autobanWritable 同口径：
       只读契约/从节点/状态未就绪一律禁用（writable/blockedReason 由宿主传入）。 -->
  <el-dialog :model-value="modelValue" width="min(720px, 94vw)" top="6vh" append-to-body class="dialog-body-inset" @update:model-value="emit('update:modelValue', $event)">
    <template #header>
      <DialogHeader :icon="Lock" :title="t('app.security.overview.autoban.recidivismDialogTitle')" :subtitle="t('app.security.overview.autoban.recidivismDialogSubtitle')" />
    </template>
    <div v-if="loadError" class="info-note-bar autoban-warn-bar">
      <span class="info-note-desc">{{ t('app.security.overview.autoban.recidivismLoadFailed') }}</span>
      <el-button size="small" type="primary" plain @click="fetchRecords">{{ t('app.security.overview.autoban.recidivismRetry') }}</el-button>
    </div>
    <el-table v-else v-loading="loading" :data="records" size="small" max-height="420" :header-cell-style="{ background: '#f9fafb' }">
      <template #empty><el-empty :description="t('app.security.overview.autoban.recidivismEmpty')" :image-size="60" /></template>
      <!-- 身份列：IPv6 /64 身份键展示 CIDR 形态（与封禁条目同口径，单源
           autobanIdentityDisplay）；等宽字体便于逐位核对地址 -->
      <el-table-column :label="t('app.security.overview.autoban.recidivismColIdentity')" min-width="180" show-overflow-tooltip>
        <template #default="{ row }"><span class="recidivism-identity">{{ autobanIdentityDisplay(row.identity) }}</span></template>
      </el-table-column>
      <el-table-column :label="t('app.security.overview.autoban.recidivismColOffenses')" width="100" align="center">
        <template #default="{ row }">{{ row.offense_count }} {{ t('app.security.overview.autoban.times') }}</template>
      </el-table-column>
      <el-table-column :label="t('app.security.overview.autoban.recidivismColLastBan')" width="170">
        <template #default="{ row }">{{ row.last_ban_at ? formatDate(row.last_ban_at) : '—' }}</template>
      </el-table-column>
      <!-- 「下次封禁」=按当前档位+累计次数推算的预期时长（单源
           autobanNextBanDuration，与后端档位映射对表）；tooltip 披露上次实际
           执法时长（历史留痕，配置变更后可能与当前档位不同） -->
      <el-table-column :label="t('app.security.overview.autoban.recidivismColNextBan')" width="120" align="center">
        <template #default="{ row }">
          <el-tooltip :content="t('app.security.overview.autoban.recidivismLastDurationTip', { duration: autobanDurationLabel(row.escalated_duration) })" placement="top">
            <span class="recidivism-next-duration">{{ autobanDurationLabel(nextBanDurationOf(row as RecidivismRecord)) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
    </el-table>
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
import { Lock } from '@element-plus/icons-vue'
import { ElMessageBox } from 'element-plus'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatDate, parseDbTimeMs } from '@/utils/date'
import { autobanDurationLabel, autobanIdentityDisplay, autobanNextBanDuration } from '@/utils/autobanStatus'
import type { APIResponse } from '@/types'

// 宿主契约：writable/blockedReason 与宿主 autoban 写门同口径；duration/escalation
// 为当前配置实态（「下次封禁」预期按此推算）；重置成功后 emit('reset') 由宿主
// 刷新自身状态卡（escalated_count 归零）。
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

interface RecidivismRecord { identity: string; offense_count: number; last_ban_at: string; escalated_duration: string }
const records = ref<RecidivismRecord[]>([])
const loading = ref(false)
const loadError = ref(false)
const resetting = ref(false)
// 弹框会话序号：快速关开时旧响应不得写回新会话（与事件页状态读取同范式）。
let seq = 0
const fetchRecords = async (): Promise<void> => {
  const requestSeq = ++seq
  loading.value = true
  loadError.value = false
  try {
    const res = await request.get<APIResponse<{ records: RecidivismRecord[] }>>('/security/autoban/recidivism', { silent: true })
    if (requestSeq !== seq) return
    records.value = res.data?.records || []
  } catch {
    if (requestSeq !== seq) return
    records.value = []
    loadError.value = true
  } finally {
    if (requestSeq === seq) loading.value = false
  }
}
// 打开即拉取（每次打开取最新历史；关闭再开不沿用陈旧快照）。
watch(() => props.modelValue, (visible) => { if (visible) void fetchRecords() })

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
</script>

<style scoped>
.recidivism-footer { display: flex; align-items: center; justify-content: space-between; }
.recidivism-identity { font-family: monospace; font-size: 12px; }
.recidivism-next-duration { cursor: help; border-bottom: 1px dashed #c0c4cc; }
</style>