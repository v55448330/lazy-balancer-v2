<template>
  <el-dialog
    :model-value="visible"
    width="min(1280px, 96vw)"
    top="5vh"
    class="connections-dialog dialog-body-inset"
    align-center
    :close-on-click-modal="false"
    @update:model-value="() => emit('close')"
  >
    <template #header>
      <DialogHeader :icon="Connection" :title="t('app.dashboard.connTitle')" :subtitle="t('app.dashboard.connSubtitle')" />
    </template>

    <!-- 统计行：四卡等宽满行，左色条锚定语义 -->
    <div class="conn-stats">
      <div class="conn-stat is-active"><span class="conn-stat-label">{{ t('app.dashboard.connCatEstablished') }}</span><span class="conn-stat-num">{{ statCounts.active }}</span></div>
      <div class="conn-stat is-closing"><span class="conn-stat-label">{{ t('app.dashboard.connCatTimeWait') }}</span><span class="conn-stat-num">{{ statCounts.closing }}</span></div>
      <div class="conn-stat is-closed"><span class="conn-stat-label">{{ t('app.dashboard.connCatClosed') }}</span><span class="conn-stat-num">{{ statCounts.closed }}</span></div>
      <div class="conn-stat is-waf"><span class="conn-stat-label">{{ t('app.dashboard.connTotalReq') }}</span><span class="conn-stat-num">{{ totalReq }}</span></div>
    </div>

    <!-- 工具行：筛选（左）/ 域名聚合+自动刷新+更新时间（右） -->
    <div class="conn-toolbar">
      <div class="conn-filter">
        <button
          v-for="c in filterCats" :key="c.key"
          type="button"
          class="conn-filter-btn" :class="{ 'is-active': category === c.key }"
          @click="category = c.key; page = 1"
        >{{ c.label }}</button>
      </div>
      <div class="conn-toolbar-right">
        <span v-if="domains.length" class="conn-domain-pager">
          <button type="button" class="conn-domain-arrow" :disabled="domainPage === 0" @click="domainPage--" :aria-label="t('app.dashboard.connDomainPrev')">
            <el-icon><CaretLeft /></el-icon>
          </button>
          <span v-for="d in pagedDomains" :key="d.host" class="conn-domain-chip" :title="t('app.dashboard.connDomainTip', { requests: d.requests, flight: d.in_flight })">
            {{ d.host }} <b>{{ d.requests }}</b>
          </span>
          <button type="button" class="conn-domain-arrow" :disabled="domainPageMax" @click="domainPage++" :aria-label="t('app.dashboard.connDomainNext')">
            <el-icon><CaretRight /></el-icon>
          </button>
          <span v-if="domainPageCount > 1" class="conn-domain-pageinfo">{{ domainPage + 1 }}/{{ domainPageCount }}</span>
        </span>
        <span class="conn-toolbar-divider"></span>
        <span class="conn-toolbar-label">{{ t('app.dashboard.connAutoRefresh') }}</span>
        <el-switch v-model="autoRefresh" size="small" />
        <el-button size="small" text type="primary" :icon="Refresh" :loading="loading" class="conn-refresh-btn" @click="fetchOnce">{{ t('app.dashboard.connRefreshNow') }}</el-button>
        <span v-if="lastUpdated" class="conn-toolbar-updated">{{ t('app.dashboard.connUpdatedAt', { time: lastUpdated }) }}</span>
      </div>
    </div>

    <!-- 请求视图（lb_reqmon 内存观测，恒可用） -->
    <template v-if="reqMon">
      <el-table :data="pagedEntries" size="small" class="conn-table" :height="TABLE_HEIGHT" :empty-text="t('app.dashboard.connEmpty')">
        <el-table-column :label="t('app.dashboard.connColTime')" width="140">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColClient')" width="125">
          <template #header="{ column }"><span :title="t('app.dashboard.connColCountry')">{{ column.label }}</span></template>
          <template #default="{ row }">
            <span class="conn-mono conn-ip" :title="[row.client_ip, row.country].filter(Boolean).join(' · ')">{{ row.client_ip }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="method" :label="t('app.dashboard.connColMethod')" width="65" />
        <el-table-column prop="host" :label="t('app.dashboard.connColHost')" min-width="120" />
        <el-table-column prop="uri" :label="t('app.dashboard.connColUri')" min-width="150" show-overflow-tooltip>
          <template #default="{ row }"><span class="conn-mono">{{ row.uri }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColStatus')" width="70">
          <template #default="{ row }"><span class="conn-status" :class="statusClass(row.status)">{{ row.status }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColDuration')" width="70">
          <template #default="{ row }">{{ fmtDuration(row.duration_ms) }}</template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColCat')" width="70">
          <template #default="{ row }"><span class="conn-cat-badge" :class="'is-' + row.category">{{ catLabel(row.category) }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColProto2')" width="70">
          <template #default="{ row }"><span class="conn-mono">{{ schemeShort(row.scheme) }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColVer')" width="90">
          <template #default="{ row }"><span class="conn-mono">{{ row.proto }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColRule')" min-width="100" show-overflow-tooltip>
          <template #default="{ row }">{{ row.rule_name || '—' }}</template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColUa')" min-width="140" show-overflow-tooltip>
          <template #default="{ row }"><span class="conn-mono conn-ua">{{ generalizeUA(row.ua) }}</span></template>
        </el-table-column>
      </el-table>
    </template>

    <!-- 连接视图（Caddy 反代连接） -->
    <el-table v-else :data="pagedEntries" size="small" class="conn-table" :height="TABLE_HEIGHT" :empty-text="t('app.dashboard.connEmpty')">
      <el-table-column prop="proto" :label="t('app.dashboard.connColProto')" width="64" />
      <el-table-column prop="local" :label="t('app.dashboard.connColLocal')" width="140">
        <template #default="{ row }"><span class="conn-mono">{{ row.local }}</span></template>
      </el-table-column>
      <el-table-column :label="t('app.dashboard.connColRemote')" min-width="160">
        <template #default="{ row }">
          <span class="conn-mono">{{ row.remote }}</span>
          <span v-if="row.country" class="conn-country">{{ row.country }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="state" :label="t('app.dashboard.connColState')" width="110">
        <template #default="{ row }"><span class="conn-mono">{{ row.state }}</span></template>
      </el-table-column>
    </el-table>

    <div class="conn-pagination">
      <el-pagination v-model:current-page="page" :page-size="pageSize" :total="filteredEntries.length" layout="prev, pager, next, total" small />
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Connection, Refresh, CaretLeft, CaretRight } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { request } from '@/utils/api'
import { generalizeUA } from '@/utils/uaGeneralize'

const props = defineProps<{ visible: boolean }>()
const emit = defineEmits<{ (e: 'close'): void }>()

const { t } = useI18n()

interface ReqEntry {
  ts: number
  category: string
  client_ip: string
  country: string
  method: string
  proto: string
  scheme: string
  rule_name: string
  host: string
  uri: string
  status: number
  duration_ms: number
  size: number
  req_size: number
}
interface ConnEntry {
  proto: string
  local: string
  remote: string
  state: string
  category: string
  country: string
}
interface DomainStat { host: string; requests: number; in_flight: number; status_5xx: number }

// 表格固定高度（用户裁定：固定定值、可表格内垂直滚动、杜绝水平滚动与
// 弹框高度超出屏幕）——520px 定值，行多表格内滚动，行少留白尺寸恒定。
const TABLE_HEIGHT = 520

const loading = ref(false)
const autoRefresh = ref(true)
const lastUpdated = ref('')
const connCounts = ref<Record<string, number>>({})
const counts = ref<Record<string, number>>({})
const connections = ref<ConnEntry[]>([])
const requests = ref<ReqEntry[]>([])
const reqMon = ref(false)
const domains = ref<DomainStat[]>([])
const category = ref('active')
const page = ref(1)
const pageSize = 50
let timer: number | undefined

// 四分类（默认活跃）：请求窗口语义，文案保留原四分类。
const filterCats = computed(() => [
  { key: 'active', label: t('app.dashboard.connCatEstablished') },
  { key: 'closing', label: t('app.dashboard.connCatTimeWait') },
  { key: 'closed', label: t('app.dashboard.connCatClosed') },
  { key: 'all', label: t('app.dashboard.connCatAll') },
])

// 域名聚合条（用户裁定：攻击类型分布卡 legend type:'scroll' 同款左右翻页，
// 不用省略号/popover）——每页 3 个 chip，‹ › 翻页+页码指示；域名数量多时
// 工具行占宽恒定不换行错乱。域名变化时页码钳制（刷新/聚合变化安全）。
const DOMAIN_PAGE_SIZE = 3
const domainPage = ref(0)
const domainPageCount = computed(() => Math.max(1, Math.ceil(domains.value.length / DOMAIN_PAGE_SIZE)))
const domainPageMax = computed(() => domainPage.value >= domainPageCount.value - 1)
const pagedDomains = computed(() => {
  const start = Math.min(domainPage.value, domainPageCount.value - 1) * DOMAIN_PAGE_SIZE
  return domains.value.slice(start, start + DOMAIN_PAGE_SIZE)
})

// 时间列含年月日（用户裁定）：YYYY-MM-DD HH:mm:ss。
const fmtTime = (ts: number): string => {
  if (!ts) return ''
  const d = new Date(ts)
  const p2 = (n: number): string => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`
}
const fmtDuration = (ms: number): string => (ms >= 100 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(ms < 10 ? 2 : 0)}ms`)
// 协议两列（用户裁定：传输层/HTTP 版本分开；版本保留完整 HTTP/1.1 等原文）。
const schemeShort = (scheme: string): string => (scheme || 'http').toUpperCase()

const statusClass = (s: number): string => (s >= 500 ? 'is-5xx' : s >= 400 ? 'is-4xx' : s >= 300 ? 'is-3xx' : 'is-2xx')

// 统计卡数字：reqMon 时用请求窗口计数（counts）；否则连接态计数映射。
const statCounts = computed(() => {
  if (reqMon.value) return { active: counts.value.active ?? 0, closing: counts.value.closing ?? 0, closed: counts.value.closed ?? 0 }
  return { active: connCounts.value.established ?? 0, closing: connCounts.value.time_wait ?? 0, closed: connCounts.value.closed ?? 0 }
})

const rows = computed<Array<{ category: string }>>(() => (reqMon.value ? requests.value : connections.value))
const filteredEntries = computed(() =>
  category.value === 'all' ? rows.value : rows.value.filter((e) => e.category === category.value),
)
const pagedEntries = computed(() => filteredEntries.value.slice((page.value - 1) * pageSize, page.value * pageSize))

// 第四卡=总请求（请求视图：窗口内全部请求数；连接视图：Caddy 相关连接总数）。
const totalReq = computed(() => (reqMon.value ? requests.value.length : connections.value.length))

// 逐行状态徽标（用户裁定：「全部」分类下逐行区分窗口归属）。
const catLabel = (c: string): string => {
  const found = filterCats.value.find((f) => f.key === c)
  return found ? found.label : c
}

const fetchOnce = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<{
      data: {
        counts: Record<string, number>
        conn_counts: Record<string, number>
        requests: ReqEntry[]
        connections: ConnEntry[]
        domains: DomainStat[]
        req_mon: boolean
        generated_at: string
      }
    }>('/metrics/connections/list', { silent: true })
    const d = res.data
    counts.value = d?.counts ?? {}
    connCounts.value = d?.conn_counts ?? {}
    requests.value = d?.requests ?? []
    connections.value = d?.connections ?? []
    domains.value = d?.domains ?? []
    reqMon.value = d?.req_mon ?? false
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
      category.value = 'active'
      page.value = 1
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
/* 全站直角口径：本弹框所有块 border-radius 0 */

/* 统计行：四卡等宽满行，卡内纵排左对齐（标签上/数字下），左色条锚定语义 */
.conn-stats { display: flex; gap: 12px; margin-bottom: 14px; }
.conn-stat {
  flex: 1; display: flex; flex-direction: column; align-items: flex-start; gap: 4px;
  background: var(--el-fill-color-light); border-radius: 0; padding: 12px 16px;
  border: 1px solid var(--el-border-color-lighter); border-left: 3px solid var(--el-border-color);
}
.conn-stat.is-active { border-left-color: var(--el-color-primary); }
.conn-stat.is-closing { border-left-color: var(--el-color-warning); }
.conn-stat.is-closed { border-left-color: var(--el-color-info); }
.conn-stat.is-waf { border-left-color: var(--el-color-danger); }
.conn-stat-num { font-size: 24px; font-weight: 700; color: var(--el-color-primary); line-height: 1; font-variant-numeric: tabular-nums; }
.conn-stat.is-closing .conn-stat-num { color: var(--el-color-warning); }
.conn-stat.is-closed .conn-stat-num { color: var(--text-secondary); }
.conn-stat.is-waf .conn-stat-num { color: var(--el-color-danger); }
.conn-stat-label { font-size: 12px; color: var(--text-regular); }

/* 工具行：筛选（左）/ 域名聚合+刷新+更新时间（右），单行 space-between */
.conn-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
.conn-filter { flex-shrink: 0; }
.conn-toolbar-right { flex: 1; min-width: 0; display: flex; align-items: center; justify-content: flex-end; gap: 10px; overflow: hidden; }
.conn-toolbar-label { font-size: 12px; color: var(--text-secondary); }
.conn-toolbar-updated { font-size: 11px; color: var(--text-secondary); font-variant-numeric: tabular-nums; }
.conn-toolbar-divider { width: 1px; height: 14px; background: var(--el-border-color); }
.conn-refresh-btn { padding: 0 4px; }

.conn-domain-chip {
  font-size: 11px; color: var(--text-regular); background: var(--el-fill-color-lighter);
  border: 1px solid var(--el-border-color-lighter); border-radius: 0; padding: 2px 8px;
  font-variant-numeric: tabular-nums; white-space: nowrap;
  max-width: 160px; overflow: hidden; text-overflow: ellipsis;
}
.conn-domain-pager { display: inline-flex; align-items: center; gap: 4px; max-width: 46%; min-width: 0; overflow: hidden; }
.conn-domain-pager .conn-domain-chip { max-width: 140px; flex-shrink: 1; }
.conn-domain-arrow {
  display: inline-flex; align-items: center; justify-content: center;
  width: 20px; height: 20px; border: 1px solid var(--el-border-color); border-radius: 0;
  background: transparent; color: var(--text-regular); cursor: pointer; padding: 0;
}
.conn-domain-arrow:disabled { color: var(--el-border-color); cursor: not-allowed; }
.conn-domain-arrow:not(:disabled):hover { color: var(--el-color-primary); border-color: var(--el-color-primary); }
.conn-domain-pageinfo { font-size: 11px; color: var(--text-secondary); font-variant-numeric: tabular-nums; margin-left: 2px; }
.conn-domain-chip b { color: var(--el-color-primary); font-weight: 600; margin-left: 2px; }

.conn-filter { display: flex; gap: 0; }
.conn-filter-btn {
  border: 1px solid var(--el-border-color); border-left-width: 0; border-radius: 0;
  background: transparent; color: var(--text-regular); font-size: 12px;
  padding: 5px 14px; cursor: pointer; line-height: 1.4;
}
.conn-filter-btn:first-child { border-left-width: 1px; }
.conn-filter-btn.is-active { background: var(--el-color-primary); border-color: var(--el-color-primary); color: #fff; }

.conn-table { width: 100%; }
.conn-mono { font-family: var(--el-font-family-mono, monospace); font-size: 12px; }
.conn-country { margin-left: 6px; font-size: 11px; color: var(--text-secondary); }
.conn-ip { white-space: nowrap; }
.conn-ua { font-size: 11px; color: var(--text-secondary); }
.conn-cat-badge { font-size: 11px; padding: 1px 8px; border: 1px solid var(--el-border-color); white-space: nowrap; }
.conn-cat-badge.is-active { color: var(--el-color-primary); border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.conn-cat-badge.is-closing { color: var(--el-color-warning); border-color: var(--el-color-warning); background: var(--el-color-warning-light-9); }
.conn-cat-badge.is-closed { color: var(--text-secondary); border-color: var(--el-border-color); background: var(--el-fill-color-light); }
.conn-status { font-weight: 600; font-variant-numeric: tabular-nums; }
.conn-status.is-2xx { color: var(--el-color-success); }
.conn-status.is-3xx { color: var(--el-color-info); }
.conn-status.is-4xx { color: var(--el-color-warning); }
.conn-status.is-5xx { color: var(--el-color-danger); }
.conn-pagination { display: flex; justify-content: flex-end; margin-top: 8px; }
</style>
