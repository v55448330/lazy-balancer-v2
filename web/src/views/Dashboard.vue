<template>
  <div class="dashboard">
    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card class="system-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Monitor /></el-icon>
                <span>系统概览</span>
              </div>
              <el-tag :type="isSlave ? 'warning' : 'success'" size="small" effect="plain">
                {{ isSlave ? '从节点' : '主节点' }}
              </el-tag>
            </div>
          </template>
          <el-descriptions :column="6" border>
            <el-descriptions-item label="主机名">
              <span class="text-primary">{{ systemInfo?.hostname || '-' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="操作系统">{{ systemInfo?.os_info || '-' }}</el-descriptions-item>
            <el-descriptions-item label="内核">{{ systemInfo?.kernel || '-' }}</el-descriptions-item>
            <el-descriptions-item label="架构">{{ systemInfo?.architecture || '-' }}</el-descriptions-item>
            <el-descriptions-item label="Caddy版本">
              <el-tag type="info" size="small">{{ systemInfo?.caddy_version || '-' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="运行时间">{{ formatUptime(systemInfo?.uptime) }}</el-descriptions-item>
          </el-descriptions>
          <div v-if="ipList.length > 0" class="network-section">
            <div class="section-label">网络接口</div>
            <div class="network-tags">
              <el-tag v-for="item in ipList" :key="item.iface" size="small" effect="plain" class="network-tag">
                {{ item.iface }}: {{ item.ip }}
              </el-tag>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card class="caddy-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon caddy-icon"><Cpu /></el-icon>
                <span>Caddy 服务状态</span>
                <el-tooltip v-if="caddyApplyError" placement="bottom" :content="caddyApplyError">
                  <el-tag type="danger" size="small" effect="plain" style="margin-left: 8px">配置应用失败</el-tag>
                </el-tooltip>
              </div>
              <div class="header-actions">
                <el-tag 
                  :type="caddyStatus === 'running' ? 'success' : caddyStatus === 'stopped' ? 'danger' : 'info'" 
                  size="small" 
                  effect="plain"
                  :class="['status-tag', caddyStatus]"
                >
                  {{ caddyStatus === 'running' ? '运行中' : caddyStatus === 'stopped' ? '已停止' : '未知' }}
                </el-tag>
                <div v-if="authStore.readOnlyReason === null" class="caddy-actions">
                  <el-button v-if="caddyStatus === 'running'" type="warning" size="small" @click="controlCaddy('restart')" :loading="caddyLoading">
                    重启
                  </el-button>
                  <el-button v-if="caddyStatus === 'running'" type="danger" size="small" @click="controlCaddy('stop')" :loading="caddyLoading">
                    停止
                  </el-button>
                  <el-button v-if="caddyStatus === 'stopped'" type="success" size="small" @click="controlCaddy('start')" :loading="caddyLoading">
                    启动
                  </el-button>
                </div>
              </div>
            </div>
          </template>
          <el-row :gutter="16">
            <el-col :span="8">
              <div class="stat-item">
                <div class="stat-icon stat-blue">
                  <el-icon><Document /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ caddyMetricsUnavailable ? '采集失败' : caddyMetrics ? caddyMetrics.requests_total.toLocaleString() : '-' }}</div>
                  <div class="stat-label">总请求数</div>
                </div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Loading /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ caddyMetricsUnavailable ? '采集失败' : caddyMetrics ? caddyMetrics.requests_in_flight : '-' }}</div>
                  <div class="stat-label">进行中请求</div>
                </div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-item">
                <div class="stat-icon stat-green">
                  <el-icon><CircleCheck /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ hostMetricsUnavailable ? '采集失败' : hostMetrics ? hostMetrics.length : '-' }}</div>
                  <div class="stat-label">域名统计</div>
                </div>
              </div>
            </el-col>
          </el-row>
          <el-row :gutter="16" style="margin-top: 16px;">
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-blue">
                  <el-icon><TrendCharts /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? overview.requests_per_sec.toFixed(2) : '-' }}</div>
                  <div class="stat-label">请求速率 /s</div>
                </div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Odometer /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? `${overview.latency_p50}ms` : '-' }}</div>
                  <div class="stat-label">延迟 P50</div>
                </div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Odometer /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? `${overview.latency_p95}ms` : '-' }}</div>
                  <div class="stat-label">延迟 P95</div>
                </div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Odometer /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? `${overview.latency_p99}ms` : '-' }}</div>
                  <div class="stat-label">延迟 P99</div>
                </div>
              </div>
            </el-col>
          </el-row>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card class="resource-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon resource-icon"><Odometer /></el-icon>
                <span>系统资源</span>
              </div>
            </div>
          </template>
          <el-skeleton v-if="initialLoading" :rows="2" animated />
          <div v-else-if="systemMetricsUnavailable" class="collection-state">采集失败</div>
          <el-row v-else-if="systemMetrics" :gutter="32">
            <el-col :span="8">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">CPU 使用率</span>
                  <span class="resource-value text-blue">{{ systemMetrics.cpu_percent.toFixed(1) }}%</span>
                </div>
                <el-progress :percentage="Math.min(systemMetrics.cpu_percent, 100)" :stroke-width="6" color="#3b82f6" :show-text="false" />
              </div>
            </el-col>
            <el-col :span="8">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">内存使用</span>
                  <span class="resource-value text-purple">
                    {{ formatBytes(systemMetrics.memory_used) }}
                    <span class="resource-total">/ {{ formatBytes(systemMetrics.memory_total) }}</span>
                  </span>
                </div>
                <el-progress :percentage="Math.min(systemMetrics.memory_percent, 100)" :stroke-width="6" color="#8b5cf6" :show-text="false" />
              </div>
            </el-col>
            <el-col :span="8">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">磁盘使用</span>
                  <span class="resource-value text-cyan">
                    {{ formatBytes(systemMetrics.disk_used) }}
                    <span class="resource-total">/ {{ formatBytes(systemMetrics.disk_total) }}</span>
                  </span>
                </div>
                <el-progress :percentage="Math.min(systemMetrics.disk_percent, 100)" :stroke-width="6" color="#06b6d4" :show-text="false" />
              </div>
            </el-col>
          </el-row>
          <div v-else class="collection-state">-</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon chart-icon"><TrendCharts /></el-icon>
                <span>流量监控</span>
              </div>
            </div>
          </template>
          <el-skeleton v-if="initialLoading" :rows="4" animated class="chart-skeleton" />
          <div v-else-if="trafficUnavailable" class="chart-container collection-state">采集失败</div>
          <div v-else class="chart-container">
            <v-chart :option="trafficChartOption" autoresize />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon chart-icon"><DataLine /></el-icon>
                <span>连接统计</span>
              </div>
            </div>
          </template>
          <el-skeleton v-if="initialLoading" :rows="4" animated class="chart-skeleton" />
          <div v-else-if="connectionsUnavailable" class="chart-container collection-state">采集失败</div>
          <div v-else class="chart-container">
            <v-chart :option="connChartOption" autoresize />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20">
      <el-col :span="24">
        <el-card class="rules-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon rules-icon"><List /></el-icon>
                <span>负载均衡规则</span>
              </div>
              <div class="card-header-actions">
                <el-radio-group v-model="rankBy" size="small">
                  <el-radio-button value="requests">按请求数</el-radio-button>
                  <el-radio-button value="bytes">按流量</el-radio-button>
                </el-radio-group>
                <el-badge :value="rankableRules.length" type="primary" />
              </div>
            </div>
          </template>
          <el-table
            v-loading="initialLoading"
            element-loading-text="加载中"
            :data="sortedRules"
            row-key="caddy_id"
            stripe
            :header-cell-style="{ background: '#f9fafb' }"
          >
            <el-table-column prop="name" label="规则名称" min-width="150">
              <template #default="{ row }">
                <el-link type="primary" :underline="false" role="button" tabindex="0" @click.prevent="openRuleHistory(row)" @keydown.enter.prevent="openRuleHistory(row)" @keydown.space.prevent="openRuleHistory(row)">{{ row.name }}</el-link>
              </template>
            </el-table-column>
            <el-table-column label="协议" width="90">
              <template #default="{ row }">
                <el-tag :type="getRuleProtocolTagType(row)" size="small" effect="plain">
                  {{ getRuleProtocolLabel(row) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="listen_port" label="端口" width="70" align="center" />
            <el-table-column label="负载策略" width="100">
              <template #default="{ row }">
                <span class="text-secondary">{{ getStrategyLabel(row.strategy) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="70" align="center">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="plain">
                  {{ row.enabled ? '启用' : '禁用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="请求数" width="90" align="right">
              <template #default="{ row }">
                <span class="text-primary">{{ isRuleDisabled(row) ? '已禁用' : ruleMetricsUnavailable[row.caddy_id] ? '采集失败' : ruleMetrics[row.caddy_id]?.requests_total?.toLocaleString() ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="状态码" width="220" align="center">
              <template #default="{ row }">
                <span v-if="isRuleDisabled(row)" class="text-secondary">已禁用</span>
                <div v-else-if="row.protocol === 'tcp'" class="text-secondary">-</div>
                <span v-else-if="ruleMetricsUnavailable[row.caddy_id]" class="text-secondary">采集失败</span>
                <div v-else-if="hasRuleRequests(row.caddy_id)" class="status-codes">
                  <span class="status-code status-2xx" title="成功">2xx {{ ruleMetrics[row.caddy_id].status_2xx }}</span>
                  <span class="status-code status-3xx" title="重定向">3xx {{ ruleMetrics[row.caddy_id].status_3xx }}</span>
                  <span class="status-code status-4xx" title="客户端错误">4xx {{ ruleMetrics[row.caddy_id].status_4xx }}</span>
                  <span class="status-code status-5xx" title="服务器错误">5xx {{ ruleMetrics[row.caddy_id].status_5xx }}</span>
                </div>
                <span v-else class="text-secondary">-</span>
              </template>
            </el-table-column>
            <el-table-column label="入站流量" width="100" align="right">
              <template #default="{ row }">
                <span v-if="isRuleDisabled(row)" class="text-secondary">已禁用</span>
                <span v-else-if="row.protocol === 'tcp'" class="text-secondary">-</span>
                <span v-else-if="ruleMetricsUnavailable[row.caddy_id]" class="text-secondary">采集失败</span>
                <span v-else class="text-secondary">{{ ruleMetrics[row.caddy_id] ? formatBytes(ruleMetrics[row.caddy_id].bytes_in) : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="出站流量" width="100" align="right">
              <template #default="{ row }">
                <span v-if="isRuleDisabled(row)" class="text-secondary">已禁用</span>
                <span v-else-if="row.protocol === 'tcp'" class="text-secondary">-</span>
                <span v-else-if="ruleMetricsUnavailable[row.caddy_id]" class="text-secondary">采集失败</span>
                <span v-else class="text-secondary">{{ ruleMetrics[row.caddy_id] ? formatBytes(ruleMetrics[row.caddy_id].bytes_out) : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="处理中" width="70" align="center">
              <template #default="{ row }">
                <span class="text-secondary">{{ isRuleDisabled(row) ? '已禁用' : ruleMetricsUnavailable[row.caddy_id] ? '采集失败' : ruleMetrics[row.caddy_id]?.requests_in_flight ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="健康状态" width="80" align="center">
              <template #default="{ row }">
                <el-tag v-if="!row.enabled" type="info" size="small" effect="plain">-</el-tag>
                <el-tag v-else-if="ruleHealthUnavailable || !ruleHealth[row.caddy_id] || ruleHealth[row.caddy_id] === 'unknown'" type="info" size="small" effect="plain">-</el-tag>
                <el-tag v-else-if="ruleHealth[row.caddy_id] === 'unhealthy'" type="danger" size="small" effect="plain">异常</el-tag>
                <el-tag v-else-if="ruleHealth[row.caddy_id] === 'degraded'" type="warning" size="small" effect="plain">降级</el-tag>
                <el-tag v-else type="success" size="small" effect="plain">健康</el-tag>
              </template>
            </el-table-column>
            <template #empty>
              <el-empty :description="rulesEmptyText" :image-size="80" />
            </template>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog v-model="ruleHistoryVisible" width="min(900px, 92vw)" destroy-on-close class="history-dialog">
      <template #header>
        <div class="dialog-title">
          <el-icon class="dialog-title-icon"><TrendCharts /></el-icon>
          <span class="dialog-title-main">历史统计</span>
          <el-text type="info" size="small" class="dialog-title-sub">{{ ruleHistoryRule?.name }} · {{ ruleHistoryRule ? getRuleProtocolLabel(ruleHistoryRule) : '' }} · :{{ ruleHistoryRule?.listen_port }}</el-text>
        </div>
      </template>
      <div class="history-toolbar">
        <el-radio-group v-model="ruleHistoryRange" size="small" @change="fetchRuleHistory">
          <el-radio-button value="1h">近 1 小时</el-radio-button>
          <el-radio-button value="6h">近 6 小时</el-radio-button>
          <el-radio-button value="24h">近 24 小时</el-radio-button>
          <el-radio-button value="7d">近 7 天</el-radio-button>
        </el-radio-group>
      </div>
      <el-empty v-if="ruleHistoryUnsupported" description="TCP 规则暂无历史流量统计（四层代理无流量计数指标）" :image-size="60" />
      <template v-else>
        <el-empty v-if="!ruleHistoryLoading && ruleHistoryRows.length === 0" description="该时间范围内暂无数据" :image-size="60" />
        <div v-else v-loading="ruleHistoryLoading">
          <el-card shadow="never" class="history-card">
            <template #header>
              <div class="history-card-header">
                <el-icon><Odometer /></el-icon>
                <span>请求数与状态码</span>
              </div>
            </template>
            <v-chart :option="ruleRequestsChartOption" autoresize style="height: 260px;" />
          </el-card>
          <el-card shadow="never" class="history-card">
            <template #header>
              <div class="history-card-header">
                <el-icon><DataLine /></el-icon>
                <span>流量（入站 / 出站）</span>
              </div>
            </template>
            <v-chart :option="ruleBytesChartOption" autoresize style="height: 260px;" />
          </el-card>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { formatDate, formatChartTimeInConfigTz } from '@/utils/date'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import type { EChartsOption, LineSeriesOption, TooltipComponentFormatterCallbackParams } from 'echarts'
import VChart from 'vue-echarts'
import { useAuthStore } from '@/stores/auth'
import { request, formatBytes } from '@/utils/api'
import { ElMessageBox } from 'element-plus'
import { Monitor, Cpu, Document, Loading, CircleCheck, Odometer, TrendCharts, DataLine, List } from '@element-plus/icons-vue'
import type { APIResponse, SystemInfo, SystemMetrics, CaddyMetrics, Rule, RuleMetrics, HostMetrics, MetricsOverview } from '@/types'
import { usePollingTask } from '@/composables/usePollingTask'

use([CanvasRenderer, LineChart, GridComponent, TooltipComponent, LegendComponent])

const authStore = useAuthStore()

const formatUptime = (seconds?: number): string => {
  if (!seconds || seconds < 0) return '-'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d} 天 ${h} 小时`
  if (h > 0) return `${h} 小时 ${m} 分`
  if (m > 0) return `${m} 分 ${Math.floor(seconds % 60)} 秒`
  return `${Math.floor(seconds)} 秒`
}

const formatChartTime = (ms: number): string => formatChartTimeInConfigTz(ms)

const systemInfo = ref<SystemInfo | null>(null)
const systemMetrics = ref<SystemMetrics | null>(null)
const caddyMetrics = ref<CaddyMetrics | null>(null)
const caddyStatus = ref('unknown')
const caddyApplyError = ref('')
const caddyLoading = ref(false)
const rules = ref<Rule[]>([])
interface DashboardRuleMetrics extends RuleMetrics {
  enabled?: boolean
}
const ruleMetrics = ref<Record<string, DashboardRuleMetrics>>({})
const ruleMetricsUnavailable = ref<Record<string, boolean>>({})
const rankBy = ref<'requests' | 'bytes'>('requests')
type RuleHealth = 'unknown' | 'unhealthy' | 'degraded' | 'healthy'
const ruleHealth = ref<Record<string, RuleHealth>>({})
const ruleHealthUnavailable = ref(false)
const hostMetrics = ref<HostMetrics[] | null>(null)
const overview = ref<MetricsOverview | null>(null)
const systemMetricsUnavailable = ref(false)
const caddyMetricsUnavailable = ref(false)
const hostMetricsUnavailable = ref(false)
const overviewUnavailable = ref(false)
const trafficUnavailable = ref(false)
const connectionsUnavailable = ref(false)
const rulesUnavailable = ref(false)
const initialLoading = ref(true)

const trafficInHistory = ref<number[]>([])
const trafficOutHistory = ref<number[]>([])
const trafficTimestamps = ref<number[]>([])
const connEstablishedHistory = ref<number[]>([])
const connTimeWaitHistory = ref<number[]>([])
const connTimestamps = ref<number[]>([])

const isSlave = computed(() => authStore.nodeMode === 'slave')

interface RuleHistoryRow {
  timestamp: string
  requests_total: number
  requests_2xx: number
  requests_3xx: number
  requests_4xx: number
  requests_5xx: number
  bytes_in: number
  bytes_out: number
}

interface RuleHistoryDelta {
  requests: number
  status2xx: number
  status3xx: number
  status4xx: number
  status5xx: number
  bytesIn: number
  bytesOut: number
}

interface RuleHistoryResponse {
  supported?: boolean
  bucket_interval_seconds?: number
  rows?: RuleHistoryRow[]
}

interface DashboardMetricsResponse {
  global: CaddyMetrics
  hosts: HostMetrics[]
  overview: MetricsOverview
  rules: Record<string, DashboardRuleMetrics>
}

interface UpstreamHealth {
  healthy?: boolean
  unknown?: boolean
  degraded?: boolean
}

type HealthResponse = Record<string, Record<string, UpstreamHealth>>

const ruleHistoryVisible = ref(false)
const ruleHistoryRule = ref<Rule | null>(null)
const ruleHistoryRange = ref('24h')
const ruleHistoryRows = ref<RuleHistoryRow[]>([])
const ruleHistoryBucketSeconds = ref(0)
const ruleHistoryLoading = ref(false)
const ruleHistoryUnsupported = ref(false)

const openRuleHistory = (rule: Rule) => {
  ruleHistoryRule.value = rule
  ruleHistoryVisible.value = true
  ruleHistoryRange.value = '24h'
  fetchRuleHistory()
}

let ruleHistorySeq = 0

const fetchRuleHistory = async () => {
  if (disposed || !ruleHistoryRule.value) return
  const seq = ++ruleHistorySeq
  ruleHistoryLoading.value = true
  ruleHistoryUnsupported.value = false
  ruleHistoryRows.value = []
  ruleHistoryBucketSeconds.value = 0
  try {
    const res = await request.get<APIResponse<RuleHistoryResponse>>(`/rules/${ruleHistoryRule.value.caddy_id}/metrics-history`, {
      params: { range: ruleHistoryRange.value },
      signal: dashboardPolling.signal,
    })
    if (disposed || seq !== ruleHistorySeq) return
    if (res.data?.supported === false) {
      ruleHistoryUnsupported.value = true
      ruleHistoryRows.value = []
    } else {
      ruleHistoryRows.value = res.data?.rows || []
      ruleHistoryBucketSeconds.value = res.data?.bucket_interval_seconds || 0
    }
  } catch (error: unknown) {
    if (!disposed && seq === ruleHistorySeq) {
      console.error('Failed to fetch rule history:', error)
      ruleHistoryRows.value = []
    }
  } finally {
    if (!disposed && seq === ruleHistorySeq) {
      ruleHistoryLoading.value = false
    }
  }
}

const diffCounters = (previous: RuleHistoryRow, current: RuleHistoryRow): RuleHistoryDelta | null => {
  const reset = current.requests_total < previous.requests_total
    || current.requests_2xx < previous.requests_2xx
    || current.requests_3xx < previous.requests_3xx
    || current.requests_4xx < previous.requests_4xx
    || current.requests_5xx < previous.requests_5xx
    || current.bytes_in < previous.bytes_in
    || current.bytes_out < previous.bytes_out
  if (reset) return null
  return {
    requests: current.requests_total - previous.requests_total,
    status2xx: current.requests_2xx - previous.requests_2xx,
    status3xx: current.requests_3xx - previous.requests_3xx,
    status4xx: current.requests_4xx - previous.requests_4xx,
    status5xx: current.requests_5xx - previous.requests_5xx,
    bytesIn: current.bytes_in - previous.bytes_in,
    bytesOut: current.bytes_out - previous.bytes_out,
  }
}

const ruleHistoryDeltas = computed(() => {
  const labels: string[] = []
  const deltas: Array<RuleHistoryDelta | null> = []
  for (let index = 1; index < ruleHistoryRows.value.length; index += 1) {
    const previous = ruleHistoryRows.value[index - 1]
    const current = ruleHistoryRows.value[index]
    if (!previous || !current) continue
    // 缺 timestamp 的行给空标签而非抛 TypeError（S-02）：formatDate 恒返回 string，
    // 原 `?.slice(5,16) || current.timestamp.slice(5,16)` 在行缺 timestamp 时触发 undefined.slice。
    labels.push(current.timestamp ? (formatDate(current.timestamp).slice(5, 16) || '') : '')
    deltas.push(diffCounters(previous, current))
  }
  return { labels, deltas }
})

const historyChartBase = (legend: string[], series: LineSeriesOption[], valueFormatter?: (value: number) => string): EChartsOption => ({
  tooltip: { trigger: 'axis', backgroundColor: 'rgba(255,255,255,0.95)', borderColor: '#e5e7eb', textStyle: { color: '#374151', fontSize: 12 } },
  legend: { data: legend, bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 55, right: 15, top: 15, bottom: 40 },
  xAxis: { type: 'category', data: ruleHistoryDeltas.value.labels, axisLine: { lineStyle: { color: '#e5e7eb' } }, axisLabel: { fontSize: 10, color: '#9ca3af', interval: ruleHistoryBucketSeconds.value >= 900 ? 'auto' : undefined } },
  yAxis: { type: 'value', axisLine: { show: false }, axisLabel: { fontSize: 10, color: '#9ca3af', ...(valueFormatter ? { formatter: valueFormatter } : {}) }, splitLine: { lineStyle: { color: '#f3f4f6' } } },
  series,
})

const ruleRequestsChartOption = computed<EChartsOption>(() => {
  const mk = (name: string, key: keyof RuleHistoryDelta, color: string): LineSeriesOption => ({ name, type: 'line', data: ruleHistoryDeltas.value.deltas.map((row) => row === null ? null : row[key]), sampling: 'lttb', connectNulls: false, smooth: true, showSymbol: false, lineStyle: { color, width: 2 }, areaStyle: { color: `${color}1a` } })
  return historyChartBase(['总请求', '2xx', '3xx', '4xx', '5xx'], [
    mk('总请求', 'requests', '#3b82f6'),
    mk('2xx', 'status2xx', '#10b981'),
    mk('3xx', 'status3xx', '#f59e0b'),
    mk('4xx', 'status4xx', '#f97316'),
    mk('5xx', 'status5xx', '#ef4444'),
  ])
})

const ruleBytesChartOption = computed<EChartsOption>(() => {
  const mk = (name: string, key: 'bytesIn' | 'bytesOut', color: string): LineSeriesOption => ({ name, type: 'line', data: ruleHistoryDeltas.value.deltas.map((row) => row === null ? null : row[key]), sampling: 'lttb', connectNulls: false, smooth: true, showSymbol: false, lineStyle: { color, width: 2 }, areaStyle: { color: `${color}1a` } })
  return historyChartBase(['入站', '出站'], [mk('入站', 'bytesIn', '#3b82f6'), mk('出站', 'bytesOut', '#10b981')], formatBytes)
})

const ruleRankValue = (caddyId: string): number => {
  const metrics = ruleMetrics.value[caddyId]
  if (!metrics) return 0
  return rankBy.value === 'requests' ? (metrics.requests_total ?? 0) : (metrics.bytes_in ?? 0) + (metrics.bytes_out ?? 0)
}

const rankableRules = computed(() =>
  rules.value
    .filter((rule) => ruleRankValue(rule.caddy_id) > 0)
    .sort((a, b) => ruleRankValue(b.caddy_id) - ruleRankValue(a.caddy_id)),
)

const sortedRules = computed(() => rankableRules.value.slice(0, 10))

const rulesEmptyText = computed(() => {
  if (rulesUnavailable.value) return '采集失败'
  if (rules.value.length === 0) return '暂无负载均衡规则'
  return rankBy.value === 'bytes' ? '暂无流量数据' : '暂无请求数据'
})

const hasRuleRequests = (caddyId: string): boolean => {
  const requests = ruleMetrics.value[caddyId]?.requests_total
  return requests !== undefined && requests > 0
}

const isRuleDisabled = (rule: Rule): boolean => !rule.enabled || ruleMetrics.value[rule.caddy_id]?.enabled === false

const ipList = computed(() => {
  const ips = systemInfo.value?.network_ips
  if (!ips || typeof ips !== 'object') return []
  return Object.entries(ips).map(([iface, ip]) => ({ iface, ip }))
})

const getStrategyLabel = (strategy: string) => {
  const labels: Record<string, string> = {
    round_robin: '轮询',
    weighted_round_robin: '轮询',
    least_conn: '最少连接',
    ip_hash: 'IP 哈希',
    cookie: 'Cookie 粘滞',
  }
  return labels[strategy] || strategy
}

const getRuleProtocolLabel = (rule: Rule): 'HTTP' | 'HTTPS' | 'TCP' => {
  if (rule.protocol === 'tcp') return 'TCP'
  return rule.enable_tls ? 'HTTPS' : 'HTTP'
}

const getRuleProtocolTagType = (rule: Rule): 'primary' | 'success' | 'warning' => {
  if (rule.protocol === 'tcp') return 'warning'
  return rule.enable_tls ? 'success' : 'primary'
}

const trafficChartOption = computed<EChartsOption>(() => ({
  tooltip: { 
    trigger: 'axis', 
    backgroundColor: 'rgba(255,255,255,0.95)', 
    borderColor: '#e5e7eb', 
    textStyle: { color: '#374151', fontSize: 12 },
    formatter: (params: TooltipComponentFormatterCallbackParams) => {
      const items = Array.isArray(params) ? params : [params]
      let result = `${items[0]?.name ?? ''}<br/>`
      items.forEach((item) => {
        const value = typeof item.value === 'number' ? item.value : Number(item.value ?? 0)
        result += `${item.marker} ${item.seriesName}: ${formatBytes(value)}<br/>`
      })
      return result
    }
  },
  legend: { data: ['入站', '出站'], bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 45, right: 15, top: 15, bottom: 40 },
  xAxis: { 
    type: 'category', 
     data: trafficTimestamps.value.map(t => formatChartTime(t)),
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisLabel: { fontSize: 10, color: '#9ca3af' }
  },
  yAxis: { 
    type: 'value', 
    axisLine: { show: false },
    axisLabel: { fontSize: 10, color: '#9ca3af', formatter: (v: number) => formatBytes(v) },
    splitLine: { lineStyle: { color: '#f3f4f6' } }
  },
  series: [
    { name: '入站', type: 'line', color: '#3b82f6', data: trafficInHistory.value, smooth: true, showSymbol: trafficInHistory.value.length < 2, lineStyle: { color: '#3b82f6', width: 2 }, areaStyle: { color: 'rgba(59,130,246,0.1)' } },
    { name: '出站', type: 'line', color: '#10b981', data: trafficOutHistory.value, smooth: true, showSymbol: trafficOutHistory.value.length < 2, lineStyle: { color: '#10b981', width: 2 }, areaStyle: { color: 'rgba(16,185,129,0.1)' } },
  ],
}))

const connChartOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'axis', backgroundColor: 'rgba(255,255,255,0.95)', borderColor: '#e5e7eb', textStyle: { color: '#374151', fontSize: 12 } },
  legend: { data: ['已建立', '等待释放'], bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 45, right: 15, top: 15, bottom: 40 },
  xAxis: { 
    type: 'category', 
     data: connTimestamps.value.map(t => formatChartTime(t)),
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisLabel: { fontSize: 10, color: '#9ca3af' }
  },
  yAxis: { 
    type: 'value', 
    axisLine: { show: false },
    axisLabel: { fontSize: 10, color: '#9ca3af' },
    splitLine: { lineStyle: { color: '#f3f4f6' } }
  },
  series: [
    { name: '已建立', type: 'line', color: '#10b981', data: connEstablishedHistory.value, smooth: true, showSymbol: connEstablishedHistory.value.length < 2, lineStyle: { color: '#10b981', width: 2 } },
    { name: '等待释放', type: 'line', color: '#f59e0b', data: connTimeWaitHistory.value, smooth: true, showSymbol: connTimeWaitHistory.value.length < 2, lineStyle: { color: '#f59e0b', width: 2 } },
  ],
}))

let statusRefreshTimer: number | null = null
let statusConfirmTimer: number | null = null
let disposed = false
let fetchAllDataPromise: Promise<void> | null = null
let isFetchingRuleHealth = false
let rulesVersion = 0

const fetchAllData = (): Promise<void> => {
  if (disposed) return Promise.resolve()
  if (fetchAllDataPromise) return fetchAllDataPromise

  const headers = { Authorization: `Bearer ${authStore.token}` }
  const config = { headers, signal: dashboardPolling.signal, silent: true }
  fetchAllDataPromise = Promise.allSettled([
    request.get('/system/info', config).then((res) => {
      if (disposed) return
      if (res.data) systemInfo.value = res.data
    }),
    request.get('/system/metrics', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        systemMetricsUnavailable.value = true
        return
      }
      systemMetrics.value = res.data
      systemMetricsUnavailable.value = false
    }).catch(() => { if (!disposed) systemMetricsUnavailable.value = true }),
    request.get('/metrics/realtime', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        trafficUnavailable.value = true
        return
      }
      const data = res.data
      const now = Date.now()
      trafficInHistory.value = [...trafficInHistory.value, data.bytes_in].slice(-60)
      trafficOutHistory.value = [...trafficOutHistory.value, data.bytes_out].slice(-60)
      trafficTimestamps.value = [...trafficTimestamps.value, now].slice(-60)
      trafficUnavailable.value = false
    }).catch(() => { if (!disposed) trafficUnavailable.value = true }),
    request.get<APIResponse<DashboardMetricsResponse>>('/metrics/dashboard', config).then((res) => {
      if (disposed) return
      const data = res.data
      if (!data) {
        caddyMetricsUnavailable.value = true
        hostMetricsUnavailable.value = true
        overviewUnavailable.value = true
        return
      }
      caddyMetrics.value = data.global
      hostMetrics.value = data.hosts
      overview.value = data.overview
      ruleMetrics.value = data.rules
      ruleMetricsUnavailable.value = Object.fromEntries(rules.value.map((rule) => [rule.caddy_id, rule.enabled && data.rules[rule.caddy_id] === undefined]))
      caddyMetricsUnavailable.value = false
      hostMetricsUnavailable.value = false
      overviewUnavailable.value = false
    }).catch(() => {
      if (disposed) return
      caddyMetricsUnavailable.value = true
      hostMetricsUnavailable.value = true
      overviewUnavailable.value = true
      // Round 36 I-4: 移除 rulesUnavailable.value = true（与 /rules then 竞态）。
      // rulesUnavailable 由 /rules 自己的 then/catch 管理，避免双 setter 竞态。
      ruleMetricsUnavailable.value = Object.fromEntries(rules.value.map((rule) => [rule.caddy_id, rule.enabled]))
    }),
    request.get('/rules', config).then(async (res) => {
      if (disposed) return
      if (!res.data) {
        rulesUnavailable.value = true
        return
      }
      rules.value = res.data || []
      rulesUnavailable.value = false
      const version = ++rulesVersion
      const currentRules = rules.value
       await fetchRuleHealth(currentRules, version)
     }).catch(() => { if (!disposed) rulesUnavailable.value = true }),
    request.get('/metrics/connections', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        connectionsUnavailable.value = true
        return
      }
      const connData = res.data
      const now = Date.now()
      connEstablishedHistory.value = [...connEstablishedHistory.value, connData.established].slice(-60)
      connTimeWaitHistory.value = [...connTimeWaitHistory.value, connData.time_wait].slice(-60)
      connTimestamps.value = [...connTimestamps.value, now].slice(-60)
      connectionsUnavailable.value = false
    }).catch(() => { if (!disposed) connectionsUnavailable.value = true }),
    request.get('/caddy/status', config).then((res) => {
      if (disposed) return
      if (res.data) {
        caddyStatus.value = res.data.status || 'unknown'
        caddyApplyError.value = res.data.apply_error || ''
      }
    }),
  ]).then(() => undefined).finally(() => {
    if (!disposed) initialLoading.value = false
    fetchAllDataPromise = null
  })

  return fetchAllDataPromise
}

const fetchRuleHealth = async (currentRules: Rule[], version: number) => {
  if (disposed || currentRules.length === 0 || isFetchingRuleHealth) return
  isFetchingRuleHealth = true
  try {
    const res = await request.get<APIResponse<HealthResponse>>('/config/health', { signal: dashboardPolling.signal, silent: true })
    if (disposed || version !== rulesVersion) return
    const healthData = res.data || {}
    const nextRuleHealth: Record<string, RuleHealth> = {}
    currentRules.forEach((rule: Rule) => {
      const enabledUpstreams = rule.upstreams?.filter((upstream) => upstream.enabled !== false) || []
      let status: RuleHealth = 'unknown'
      if (rule.enabled && enabledUpstreams.length) {
        let hasUnknown = false
        let hasUnhealthy = false
        let hasDegraded = false

        enabledUpstreams.forEach((u) => {
          const key = `${u.host}:${u.port}`
          let found = false
          for (const serverHealth of Object.values(healthData)) {
            const upHealth = serverHealth?.[key]
            if (upHealth) {
              found = true
              if (upHealth.unknown) {
                hasUnknown = true
              } else if (!upHealth.healthy) {
                hasUnhealthy = true
              } else if (upHealth.degraded) {
                hasDegraded = true
              }
              break
            }
          }
          if (!found) hasUnknown = true
        })

        if (hasUnhealthy) status = 'unhealthy'
        else if (hasDegraded) status = 'degraded'
        else if (hasUnknown) status = 'unknown'
        else status = 'healthy'
      }
      nextRuleHealth[rule.caddy_id] = status
    })
    if (!disposed && version === rulesVersion) {
      ruleHealth.value = nextRuleHealth
      ruleHealthUnavailable.value = false
    }
  } catch (e) {
    if (!disposed) {
      ruleHealthUnavailable.value = true
      console.error('Failed to fetch rule health:', e)
    }
  } finally {
    isFetchingRuleHealth = false
  }
}

const controlCaddy = async (action: 'start' | 'stop' | 'restart') => {
  if (authStore.readOnlyReason !== null) return
  
  const actionText = { start: '启动', stop: '停止', restart: '重启' }[action]
  const actionDesc = {
    start: '确定要启动 Caddy 服务吗？',
    stop: '确定要停止 Caddy 服务吗？停止后网站将无法访问。',
    restart: '确定要重启 Caddy 服务吗？'
  }[action]
  
  try {
    await ElMessageBox.confirm(actionDesc, `${actionText} Caddy 服务`, {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning',
    })
    if (disposed) return
    
    caddyLoading.value = true
    await request.post(`/caddy/${action}`, undefined, { signal: dashboardPolling.signal })
    if (disposed) return
    
    // After start or restart, reload config from database
    if (action === 'start' || action === 'restart') {
      await request.post('/config/reload', undefined, { signal: dashboardPolling.signal })
      if (disposed) return
    }
    
    // Optimistic update - show the expected status immediately
    if (action === 'stop') {
      caddyStatus.value = 'stopped'
    } else if (action === 'start' || action === 'restart') {
      caddyStatus.value = 'running'
    }
    
    authStore.showToast('success', `Caddy ${actionText}成功`)
    
    // Also fetch actual status to confirm
    if (statusRefreshTimer) clearTimeout(statusRefreshTimer)
    if (statusConfirmTimer) clearTimeout(statusConfirmTimer)
    statusRefreshTimer = window.setTimeout(() => {
      void fetchAllData().then(() => {
        if (disposed) return
        statusConfirmTimer = window.setTimeout(fetchAllData, 1500)
      })
    }, 1000)
  } catch (error: unknown) {
    if (disposed) return
    if (error === 'cancel') return
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to control Caddy:', error)
  } finally {
    if (!disposed) caddyLoading.value = false
  }
}

const dashboardPolling = usePollingTask(async () => fetchAllData(), {
  interval: 5000,
  onError: (error) => console.error('Failed to poll dashboard:', error),
})

onMounted(() => {
  void dashboardPolling.run()
  dashboardPolling.start()
})

onUnmounted(() => {
  disposed = true
  if (statusRefreshTimer) clearTimeout(statusRefreshTimer)
  if (statusConfirmTimer) clearTimeout(statusConfirmTimer)
})
</script>

<style scoped>
.dashboard { max-width: 1500px; margin: 0 auto; }


.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}

.title-icon {
  font-size: 16px;
  color: #3b82f6;
}

.caddy-icon { color: #10b981; }
.resource-icon { color: #8b5cf6; }
.chart-icon { color: #f59e0b; }
.rules-icon { color: #3b82f6; }

.header-actions { display: flex; align-items: center; gap: 12px; }

.status-tag {
  min-width: 56px;
  text-align: center;
  font-weight: 500;
}

.status-tag.running { background: #ecfdf5; border-color: #a7f3d0; }
.status-tag.stopped { background: #fef2f2; border-color: #fecaca; }
.status-tag.info { background: #f3f4f6; border-color: #e5e7eb; }

.caddy-actions { display: flex; gap: 2px; }

.caddy-actions :deep(.el-button) {
  margin: 0;
  padding: 8px 12px;
}

.network-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid #f3f4f6; }
.section-label { font-size: 13px; color: #6b7280; margin-bottom: 10px; }
.network-tags { display: flex; flex-wrap: wrap; gap: 8px; }
.network-tag { background: #f3f4f6; }

.stat-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px;
  background: #f9fafb;
  border-radius: 8px;
}

.stat-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
}

.stat-blue { background: #eff6ff; color: #3b82f6; }
.stat-purple { background: #f5f3ff; color: #8b5cf6; }
.stat-green { background: #ecfdf5; color: #10b981; }

.stat-value { font-size: 20px; font-weight: 600; color: #111827; line-height: 1.2; }
.stat-label { font-size: 12px; color: #6b7280; margin-top: 2px; }

.resource-item { padding: 4px 0; }
.resource-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.resource-label { color: #4b5563; font-size: 13px; }
.resource-value { font-size: 14px; font-weight: 500; }
.text-blue { color: #3b82f6; }
.text-purple { color: #8b5cf6; }
.text-cyan { color: #0891b2; }
.resource-total { font-size: 12px; color: #9ca3af; font-weight: 400; }

.chart-card :deep(.el-card__body) { height: 240px; padding: 16px; box-sizing: border-box; }
.chart-container { height: 200px; }
.chart-skeleton { height: 200px; }
.collection-state { display: flex; align-items: center; justify-content: center; min-height: 80px; color: #909399; }

.text-primary { color: #111827; }
.text-secondary { color: #6b7280; }

.status-codes {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 4px;
}
.status-code {
  font-size: 10px;
  padding: 1px 4px;
  border-radius: 4px;
  font-weight: 500;
}
.status-2xx { background: #ecfdf5; color: #059669; }
.status-3xx { background: #eff6ff; color: #2563eb; }
.status-4xx { background: #fffbeb; color: #d97706; }
.status-5xx { background: #fef2f2; color: #dc2626; }
.dialog-title { display: inline-flex; align-items: center; white-space: nowrap; overflow: hidden; }
.dialog-title > * { line-height: 1; }
.dialog-title-icon { font-size: 20px; color: var(--el-color-primary); flex-shrink: 0; margin-right: 12px; }
.dialog-title-main { font-size: 16px; font-weight: 600; color: #111827; margin-right: 16px; }
.dialog-title-sub { overflow: hidden; text-overflow: ellipsis; line-height: 1; padding-top: 3px; }
.history-toolbar { display: flex; justify-content: flex-end; margin-top: 8px; padding-bottom: 16px; border-bottom: 1px solid var(--border-lighter); margin-bottom: 20px; }
.history-card { margin-bottom: 24px; border: 1px solid var(--border-lighter); border-radius: 8px; }
.history-card:last-child { margin-bottom: 0; }
.history-card :deep(.el-card__header) { padding: 8px 14px; background: #f9fafb; }
.history-card :deep(.el-card__body) { padding: 10px 14px; }
.history-card-header { display: flex; align-items: center; font-size: 14px; font-weight: 600; color: #374151; line-height: 1; }
.history-card-header .el-icon { color: var(--el-color-primary); font-size: 16px; margin-right: 8px; }

</style>
