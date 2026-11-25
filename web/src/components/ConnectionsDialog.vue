<template>
  <el-dialog
    :model-value="visible"
    width="min(1200px, 94vw)"
    class="connections-dialog dialog-body-inset"
    align-center
    :close-on-click-modal="false"
    @update:model-value="() => emit('close')"
  >
    <template #header>
      <DialogHeader :icon="Connection" :title="t('app.dashboard.connTitle')" :subtitle="t('app.dashboard.connSubtitle')" />
    </template>

    <!-- 取数失败：保留上次数据并明示（失败不得显示成空列表），带手动重试 -->
    <el-alert v-if="loadError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.dashboard.connLoadFailPrefix') }}{{ loadError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="loading" @click="refreshNow">{{ t('app.dashboard.retryNow') }}</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ loadFailMeta }}</div>
    </el-alert>

    <!-- 统计行：四卡等宽满行，左色条锚定语义；分类文案随视图（请求=窗口区间，连接=socket 状态族） -->
    <div class="conn-stats">
      <div class="conn-stat is-active"><span class="conn-stat-label">{{ catLabel('active') }}</span><span class="conn-stat-num">{{ statCounts.active }}</span></div>
      <div class="conn-stat is-closing"><span class="conn-stat-label">{{ catLabel('closing') }}</span><span class="conn-stat-num">{{ statCounts.closing }}</span></div>
      <div class="conn-stat is-closed"><span class="conn-stat-label">{{ catLabel('closed') }}</span><span class="conn-stat-num">{{ statCounts.closed }}</span></div>
      <div class="conn-stat is-waf">
        <span class="conn-stat-label">{{ reqMon ? t('app.dashboard.connTotalReq') : t('app.dashboard.connTotalConn') }}</span>
        <span class="conn-stat-num" :title="totalReqTitle">{{ totalReqText }}</span>
      </div>
    </div>

    <!-- 封顶口径：请求明细触达 500 行上限时总数/分类计数都是封顶值，必须说明 -->
    <div v-if="reqMon && requestsTruncated" class="form-tip-line">{{ t('app.dashboard.connReqTruncatedNote', { cap: REQ_ROWS }) }}</div>
    <div v-else-if="!reqMon && connTruncated" class="form-tip-line">{{ t('app.dashboard.connTruncatedNote', { cap: REQ_ROWS }) }}</div>

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
          <button type="button" class="conn-domain-arrow" :disabled="domainPage <= 1" @click="domainPage--" :aria-label="t('app.dashboard.connDomainPrev')">
            <el-icon><CaretLeft /></el-icon>
          </button>
          <span v-for="d in pagedDomains" :key="d.host" class="conn-domain-chip" :title="t('app.dashboard.connDomainTip', { requests: d.requests, flight: d.in_flight, s5xx: d.status_5xx })">
            {{ d.host }} <b>{{ d.requests }}</b>
          </span>
          <button type="button" class="conn-domain-arrow" :disabled="domainPageMax" @click="domainPage++" :aria-label="t('app.dashboard.connDomainNext')">
            <el-icon><CaretRight /></el-icon>
          </button>
          <span v-if="domainPageCount > 1" class="conn-domain-pageinfo">{{ domainPage }}/{{ domainPageCount }}</span>
        </span>
        <span class="conn-toolbar-divider"></span>
        <span class="conn-toolbar-label">{{ t('app.dashboard.connAutoRefresh') }}</span>
        <el-switch v-model="autoRefresh" size="small" />
        <el-button size="small" text type="primary" :icon="Refresh" :loading="loading" class="conn-refresh-btn" @click="refreshNow">{{ t('app.dashboard.connRefreshNow') }}</el-button>
        <span v-if="lastUpdated" class="conn-toolbar-updated">{{ t('app.dashboard.connUpdatedAt', { time: lastUpdated }) }}</span>
      </div>
    </div>

    <!-- 请求视图（lb_reqmon 内存观测，恒可用） -->
    <template v-if="reqMon">
      <el-table :data="pagedEntries" size="small" class="conn-table" :height="TABLE_HEIGHT" :empty-text="t('app.dashboard.connEmptyReq')">
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
        <el-table-column :label="t('app.dashboard.connColHost')" min-width="170" show-overflow-tooltip>
          <template #default="{ row }"><span class="conn-mono conn-host" :title="row.host">{{ row.host }}</span></template>
        </el-table-column>
        <el-table-column prop="uri" :label="t('app.dashboard.connColUri')" min-width="110" show-overflow-tooltip>
          <template #default="{ row }"><span class="conn-mono">{{ row.uri }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColStatus')" width="70">
          <template #default="{ row }"><span class="conn-status" :class="statusClass(row.status)">{{ row.status }}</span></template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColDuration')" width="70">
          <template #default="{ row }">{{ fmtDuration(row.duration_ms) }}</template>
        </el-table-column>
        <el-table-column :label="t('app.dashboard.connColWindow')" width="70">
          <template #default="{ row }"><span class="conn-cat-badge" :class="'is-' + rowCat(row)">{{ catLabel(rowCat(row)) }}</span></template>
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
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Connection, Refresh, CaretLeft, CaretRight } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { request } from '@/utils/api'
import { generalizeUA } from '@/utils/uaGeneralize'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { usePollingTask } from '@/composables/usePollingTask'
import { formatDate, formatChartTimeInConfigTz } from '@/utils/date'
import { usePollingErrorState } from '@/composables/usePollingErrorState'
import {
  REQUEST_VIEW_MAX_ROWS as REQ_ROWS,
  connectionFilterCategories,
  filterKeyOf,
  filterRows,
  requestFilterCategories,
  totalRequestsText,
} from '@/utils/connectionsView.ts'

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
// 封顶披露：请求明细触达 500 行上限（requests/counts 都只是这 500 条的
// 口径）与连接明细截断（计数仍是截断前全集）分别来自后端标志。
const requestsTruncated = ref(false)
const connTruncated = ref(false)
const category = ref('active')
const page = ref(1)
const pageSize = 50
const loadError = usePollingErrorState()

// 四分类文案随视图（请求窗口区间 vs socket 状态族），差异集中在
// web/src/utils/connectionsView.ts 单源。
const filterCats = computed(() => (reqMon.value ? requestFilterCategories(t) : connectionFilterCategories(t)))

// 域名聚合条（用户裁定：攻击类型分布卡 legend type:'scroll' 同款左右翻页，
// 不用省略号/popover）——每页 3 个 chip，‹ › 翻页+页码指示；域名数量多时
// 工具行占宽恒定不换行错乱。域名变化时页码钳制（刷新/聚合变化安全）。
const DOMAIN_PAGE_SIZE = 3
const domainPage = ref(1)
const domainPageSize = ref(DOMAIN_PAGE_SIZE)
// 分页夹紧+切片单源（useClampedPagination）：domains 收缩（刷新后聚合变化）时
// 页码自动回夹——原实现只在 slice 内 Math.min，页码指示仍显示越界的「5/2」。
const { pagedItems: pagedDomains } = useClampedPagination(domains, domainPage, domainPageSize)
const domainPageCount = computed(() => Math.max(1, Math.ceil(domains.value.length / DOMAIN_PAGE_SIZE)))
const domainPageMax = computed(() => domainPage.value >= domainPageCount.value)

// 时间列含年月日（用户裁定）：YYYY-MM-DD HH:mm:ss——经配置时区单源（utils/date），
// 与图表轴/其余时间列同口径，跨时区管理员不再看到浏览器本地钟面。
const fmtTime = (ts: number): string => (ts ? formatDate(new Date(ts)) : '')
const fmtDuration = (ms: number): string => (ms >= 100 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(ms < 10 ? 2 : 0)}ms`)
// 协议两列（用户裁定：传输层/HTTP 版本分开；版本保留完整 HTTP/1.1 等原文）。
const schemeShort = (scheme: string): string => (scheme || 'http').toUpperCase()

const statusClass = (s: number): string => (s >= 500 ? 'is-5xx' : s >= 400 ? 'is-4xx' : s >= 300 ? 'is-3xx' : 'is-2xx')

// 统计卡数字：reqMon 时用请求窗口计数（counts）；否则连接态计数映射。
const statCounts = computed(() => {
  if (reqMon.value) return { active: counts.value.active ?? 0, closing: counts.value.closing ?? 0, closed: counts.value.closed ?? 0 }
  return { active: connCounts.value.established ?? 0, closing: connCounts.value.time_wait ?? 0, closed: connCounts.value.closed ?? 0 }
})

const rows = computed<Array<ReqEntry | ConnEntry>>(() => (reqMon.value ? requests.value : connections.value))
// 行分类 → 筛选键同源映射：连接视图行是 socket 状态族（established/time_wait），
// 请求视图行已是 active/closing（映射幂等）。不映射时默认 active 恒匹配不到。
const rowCat = (row: unknown): string => {
  const category = (row as { category?: unknown } | null | undefined)?.category
  return filterKeyOf(typeof category === 'string' ? category : '')
}
const filteredEntries = computed(() => filterRows(rows.value, category.value))
const pagedEntries = computed(() => filteredEntries.value.slice((page.value - 1) * pageSize, page.value * pageSize))

// 第四卡=总请求（请求视图：窗口内请求数；连接视图：Caddy 相关连接总数）。
// 请求视图触达 500 行展示上限时真实窗口总数未知——写「500+」并由上方说明行
// 交代口径，不得把封顶值当总数。
const totalReqText = computed(() =>
  reqMon.value ? totalRequestsText(requests.value.length, requestsTruncated.value) : String(connections.value.length),
)
const totalReqTitle = computed(() =>
  reqMon.value && requestsTruncated.value ? t('app.dashboard.connReqTruncatedNote', { cap: REQ_ROWS }) : '',
)

// 失败横幅副行：明确当前显示的是哪一帧旧数据（首次失败尚无数据时写「—」）。
const loadFailMeta = computed(() => t('app.dashboard.connLoadFailMeta', { time: lastUpdated.value || '—' }))

// 逐行状态徽标（用户裁定：「全部」分类下逐行区分窗口归属）。
const catLabel = (c: string): string => {
  const found = filterCats.value.find((f) => f.key === c)
  return found ? found.label : c
}

// 单飞 + 会话序号守卫由 usePollingTask 承担：慢响应乱序到达时 isCurrent()
// 失配即丢弃，不再覆写新帧（原裸 setInterval 无守卫，瞬时陈旧帧下 tick 自愈）。
// 轮次 signal 透传请求：关闭弹框/暂停自动刷新即取消在途，不再空跑完成。
const fetchOnce = async (roundSignal?: AbortSignal, isCurrent?: () => boolean): Promise<void> => {
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
        truncated: boolean
        requests_truncated: boolean
        generated_at: string
      }
    }>('/metrics/connections/list', { silent: true, signal: roundSignal })
    if (isCurrent && !isCurrent()) return // 会话已换代：迟到响应不得写回
    const d = res.data
    counts.value = d?.counts ?? {}
    connCounts.value = d?.conn_counts ?? {}
    requests.value = d?.requests ?? []
    connections.value = d?.connections ?? []
    domains.value = d?.domains ?? []
    reqMon.value = d?.req_mon ?? false
    connTruncated.value = d?.truncated ?? false
    requestsTruncated.value = d?.requests_truncated ?? false
    loadError.clear()
    lastUpdated.value = formatChartTimeInConfigTz(Date.now())
  } catch (error: unknown) {
    // 轮次取消（关闭弹框/暂停自动刷新）不是取数失败：不得把 abort 当故障上屏。
    // 真实失败置失败态并保留上次数据（首次失败时表格为空，但横幅明示失败原因）。
    if (roundSignal?.aborted) return
    loadError.recordError(error)
  } finally {
    loading.value = false
  }
}

// 弹框级轮询：pause/resume 非终态（关闭重开可反复），stop 终态清理由
// usePollingTask 内置 onUnmounted 兜底。autoRefresh 关闭只 pause 定时器。
const polling = usePollingTask(async ({ signal, isCurrent }) => { await fetchOnce(signal, isCurrent) }, { interval: 2000 })

watch(
  () => props.visible,
  (v) => {
    if (v) {
      category.value = 'active'
      page.value = 1
      loadError.clear() // 重开弹框重新判定：上次会话的失败态不带到新一次查看
      if (autoRefresh.value) polling.resume() // 恢复即刷新（首帧立即取数）
    } else {
      polling.pause()
    }
  },
)
watch(autoRefresh, (on) => {
  if (!props.visible) return
  if (on) polling.resume()
  else polling.pause()
})
// 视图切换（lb_reqmon 端点上下线）后旧筛选键可能不存在于新视图（如请求视图
// 独有的 5xx），回落到默认活跃，避免筛选器无激活项且表格恒空。
watch(filterCats, (cats) => {
  if (!cats.some((c) => c.key === category.value)) {
    category.value = 'active'
    page.value = 1
  }
})

// 手动「立即刷新」：经 run() 与在途轮次去重（单飞），不另起裸请求。
const refreshNow = (): void => { void polling.run() }

defineExpose({ refreshNow })
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
.conn-table :deep(.cell) { white-space: nowrap; }
.conn-host { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
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
