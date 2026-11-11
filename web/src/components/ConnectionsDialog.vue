<template>
  <el-dialog
    :model-value="visible"
    width="min(960px, 96vw)"
    class="connections-dialog dialog-body-inset"
    align-center
    :close-on-click-modal="false"
    @update:model-value="() => emit('close')"
  >
    <template #header>
      <DialogHeader :icon="Connection" :title="t('app.dashboard.connTitle')" :subtitle="t('app.dashboard.connSubtitle')" />
    </template>

    <!-- 自动刷新开关+手动刷新：头部右侧 -->
    <div class="conn-toolbar">
      <div class="conn-toolbar-left">
        <span class="conn-toolbar-label">{{ t('app.dashboard.connAutoRefresh') }}</span>
        <el-switch v-model="autoRefresh" size="small" :disabled="loading" />
        <el-button link type="primary" size="small" :icon="Refresh" :disabled="loading" @click="fetchOnce">{{ t('app.dashboard.connRefreshNow') }}</el-button>
      </div>
      <span v-if="lastUpdated" class="conn-toolbar-updated">{{ t('app.dashboard.connections.updatedAt', { time: lastUpdated }) }}</span>
    </div>

    <!-- 统计行 -->
    <div class="conn-stats">
      <div v-for="s in statCards" :key="s.key" class="conn-stat" :class="{ 'is-active': category === s.key }" @click="category = s.key">
        <span class="conn-stat-num">{{ counts[s.key] ?? 0 }}</span>
        <span class="conn-stat-label">{{ s.label }}</span>
      </div>
      <div class="conn-stat">
        <span class="conn-stat-num">{{ wafBlockedTotal }}</span>
        <span class="conn-stat-label">{{ t('app.dashboard.connWafBlocked') }}</span>
      </div>
    </div>

    <!-- 分类分段（任务监控同款 el-radio-group） -->
    <div class="conn-filter">
      <el-radio-group v-model="category" size="small">
        <el-radio-button value="all">{{ t('app.dashboard.connCatAll') }}</el-radio-button>
        <el-radio-button value="established">{{ t('app.dashboard.connCatEstablished') }}</el-radio-button>
        <el-radio-button value="time_wait">{{ t('app.dashboard.connCatTimeWait') }}</el-radio-button>
        <el-radio-button value="closed">{{ t('app.dashboard.connCatClosed') }}</el-radio-button>
      </el-radio-group>
    </div>

    <!-- 表格 -->
    <el-table :data="pagedEntries" size="small" class="conn-table" :max-height="380" :empty-text="t('app.dashboard.connEmpty')">
      <el-table-column :label="t('app.dashboard.connColProto')" width="70" prop="proto" />
      <el-table-column :label="t('app.dashboard.connColLocal')" min-width="150" prop="local" show-overflow-tooltip />
      <el-table-column :label="t('app.dashboard.connColRemote')" min-width="150" prop="remote" show-overflow-tooltip />
      <el-table-column :label="t('app.dashboard.connColState')" width="120" prop="state" show-overflow-tooltip />
      <el-table-column :label="t('app.dashboard.connColCountry')" min-width="110" prop="country" show-overflow-tooltip />
      <el-table-column :label="t('app.dashboard.connColWaf')" width="130" align="center">
        <template #default="{ row }">
          <span v-if="row.waf_blocked || row.waf_detected" class="conn-waf">
            <el-tag size="small" type="danger" effect="plain" v-if="row.waf_blocked">{{ row.waf_blocked }}</el-tag>
            <el-tag size="small" type="warning" effect="plain" v-if="row.waf_detected">{{ row.waf_detected }}</el-tag>
          </span>
          <span v-else class="conn-waf-none">—</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.dashboard.connColLastRule')" min-width="130" prop="last_rule" show-overflow-tooltip />
    </el-table>
    <div class="conn-pagination">
      <el-pagination v-model:current-page="page" :page-size="pageSize" :total="filteredEntries.length" layout="prev, pager, next, total" small />
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Connection, Refresh } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { request } from '@/utils/api'

const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{ (e: 'close'): void }>()

const { t } = useI18n()

interface ConnEntry {
  proto: string
  local: string
  remote: string
  state: string
  category: string
  country: string
  waf_blocked: number
  waf_detected: number
  last_rule: string
}

const loading = ref(false)
const autoRefresh = ref(true)
const lastUpdated = ref('')
const counts = ref<Record<string, number>>({})
const entries = ref<ConnEntry[]>([])
const category = ref('all')
const page = ref(1)
const pageSize = 50
let timer: number | undefined

const statCards = computed(() => [
  { key: 'established', label: t('app.dashboard.connCatEstablished') },
  { key: 'time_wait', label: t('app.dashboard.connCatTimeWait') },
  { key: 'closed', label: t('app.dashboard.connCatClosed') },
  { key: 'all', label: t('app.dashboard.connCatAll') },
])

const filteredEntries = computed(() =>
  category.value === 'all' ? entries.value : entries.value.filter((e) => e.category === category.value),
)
const pagedEntries = computed(() => filteredEntries.value.slice((page.value - 1) * pageSize, page.value * pageSize))
const wafBlockedTotal = computed(() => {
  const seen = new Set<string>()
  let sum = 0
  for (const e of entries.value) {
    if (seen.has(e.remote)) continue
    seen.add(e.remote)
    sum += e.waf_blocked
  }
  return sum
})

const fetchOnce = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<{ data: { counts: Record<string, number>; entries: ConnEntry[]; generated_at: string } }>('/metrics/connections/list', { silent: true })
    counts.value = res.data?.counts ?? {}
    entries.value = res.data?.entries ?? []
    lastUpdated.value = new Date().toLocaleTimeString()
  } catch {
    /* 静默：弹框保留上次数据 */
  } finally {
    loading.value = false
  }
}

const tick = async (): Promise<void> => {
  if (!autoRefresh.value || !props.visible) return
  await fetchOnce()
}

const startPolling = (): void => {
  stopPolling()
  timer = window.setInterval(() => void tick(), 2000)
}
const stopPolling = (): void => {
  if (timer !== undefined) {
    window.clearInterval(timer)
    timer = undefined
  }
}

watch(
  () => props.visible,
  (v) => {
    if (v) {
      void fetchOnce()
      startPolling()
    } else {
      stopPolling()
    }
  },
)
onUnmounted(stopPolling)

defineExpose({ fetchOnce })
</script>

<style scoped>
.conn-toolbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.conn-toolbar-left { display: flex; align-items: center; gap: 8px; }
.conn-toolbar-label { font-size: 12px; color: var(--text-secondary); }
.conn-toolbar-updated { font-size: 11px; color: var(--text-secondary); font-variant-numeric: tabular-nums; }

.conn-stats { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.conn-stat {
  display: flex; flex-direction: column; align-items: center; gap: 2px; cursor: pointer;
  background: var(--el-fill-color-light); border-radius: 8px; padding: 8px 14px; min-width: 84px;
  border: 1px solid transparent;
}
.conn-stat.is-active { border-color: var(--el-color-primary); }
.conn-stat-num { font-size: 20px; font-weight: 700; color: var(--el-color-primary); line-height: 1.1; font-variant-numeric: tabular-nums; }
.conn-stat-label { font-size: 12px; color: var(--text-regular); }

.conn-filter { margin-bottom: 10px; }
.conn-table { width: 100%; }
.conn-waf { display: inline-flex; gap: 4px; }
.conn-waf-none { color: var(--text-secondary); }
.conn-pagination { display: flex; justify-content: flex-end; margin-top: 8px; }
</style>
