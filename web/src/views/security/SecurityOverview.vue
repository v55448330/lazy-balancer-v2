<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><DataAnalysis /></el-icon>
          安全总览
        </h2>
        <p class="page-desc">WAF 防护统计概览</p>
      </div>
    </div>

    <el-alert
      v-if="overviewError"
      title="安全总览数据加载失败，请稍后刷新"
      type="error"
      show-icon
      :closable="false"
      class="mb-5"
    />

    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><TrendCharts /></el-icon>
                <span>防护概览</span>
              </div>
            </div>
          </template>
          <el-row :gutter="16">
            <el-col :span="5">
              <div class="stat-box stat-box--danger">
                <div class="stat-box__icon"><el-icon><CircleClose /></el-icon></div>
                <div class="stat-box__body">
                  <div class="stat-box__value">{{ overview.today_blocked }}</div>
                  <div class="stat-box__label">今日拦截</div>
                </div>
              </div>
            </el-col>
            <el-col :span="5">
              <div class="stat-box stat-box--warning">
                <div class="stat-box__icon"><el-icon><Warning /></el-icon></div>
                <div class="stat-box__body">
                  <div class="stat-box__value">{{ overview.today_detected }}</div>
                  <div class="stat-box__label">今日检测</div>
                </div>
              </div>
            </el-col>
            <el-col :span="5">
              <div class="stat-box stat-box--primary">
                <div class="stat-box__icon"><el-icon><Lock /></el-icon></div>
                <div class="stat-box__body">
                  <div class="stat-box__value">{{ overview.active_policies }}</div>
                  <div class="stat-box__label">活跃策略</div>
                </div>
              </div>
            </el-col>
            <el-col :span="5">
              <div class="stat-box stat-box--success">
                <div class="stat-box__icon"><el-icon><Files /></el-icon></div>
                <div class="stat-box__body">
                  <div class="stat-box__value">{{ overview.crs_version }}</div>
                  <div class="stat-box__label">CRS 规则集</div>
                  <el-tag v-if="overview.update_status" :type="statusTagType(overview.update_status)" size="small" effect="plain" style="margin-top: 4px">{{ statusLabel(overview.update_status) }}</el-tag>
                </div>
              </div>
            </el-col>
            <el-col :span="4">
              <div class="stat-box stat-box--success">
                <div class="stat-box__icon"><el-icon><Location /></el-icon></div>
                <div class="stat-box__body">
                  <div class="stat-box__value">{{ ip2regionVersion === 'unknown' ? '未安装' : ip2regionVersion === 'bundled' ? '内置版本' : ip2regionVersion }}</div>
                  <div class="stat-box__label">IP 地理库</div>
                  <el-tag v-if="ip2regionError" type="danger" size="small" effect="plain" style="margin-top: 4px">加载失败</el-tag>
                  <el-tag v-else-if="ip2regionVersion === 'unknown'" type="info" size="small" effect="plain" style="margin-top: 4px">未安装</el-tag>
                  <el-tag v-else-if="ip2regionStatus" :type="statusTagType(ip2regionStatus)" size="small" effect="plain" style="margin-top: 4px">{{ statusLabel(ip2regionStatus) }}</el-tag>
                </div>
              </div>
            </el-col>
          </el-row>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="16">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><TrendCharts /></el-icon>
                <span>7 天拦截趋势</span>
              </div>
            </div>
          </template>
          <div class="chart-container">
            <v-chart v-if="overview.trend.length > 0" :option="trendChartOption" autoresize style="height: 260px" />
            <el-empty v-else description="暂无趋势数据" :image-size="80" style="height: 260px; display: flex; align-items: center; justify-content: center" />
          </div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><PieChart /></el-icon>
                <span>攻击类型分布</span>
              </div>
            </div>
          </template>
          <div class="chart-container">
            <v-chart v-if="overview.attack_types.length > 0" :option="attackChartOption" autoresize style="height: 260px" />
            <el-empty v-else description="暂无攻击数据" :image-size="80" style="height: 260px; display: flex; align-items: center; justify-content: center" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5 events-row">
      <el-col :span="16">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Warning /></el-icon>
                <span>最近拦截事件</span>
              </div>
              <el-link type="primary" @click="goToEvents">查看全部</el-link>
            </div>
          </template>
          <el-alert v-if="blockedEventsError" title="最近拦截事件加载失败" type="error" show-icon :closable="false" />
          <el-table v-else :data="blockedEvents" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty><el-empty description="暂无拦截事件" :image-size="60" /></template>
            <el-table-column prop="event_time" label="时间" width="170" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
            <el-table-column prop="client_ip" label="来源 IP" min-width="130" />
            <el-table-column label="规则" min-width="160" show-overflow-tooltip>
              <template #default="{ row }">{{ row.rule_name || row.rule_caddy_id || '—' }}</template>
            </el-table-column>
            <el-table-column label="策略" min-width="140" show-overflow-tooltip>
              <template #default="{ row }">{{ row.policy_name || '—' }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Odometer /></el-icon>
                <span>限流拦截</span>
              </div>
              <el-tag type="info" size="small" effect="plain">按 429 响应计（含上游自返 429）</el-tag>
            </div>
          </template>
          <el-alert v-if="rateLimitError" title="限流拦截数据加载失败" type="error" show-icon :closable="false" />
          <template v-else>
            <div class="rate-limit-total">
              <div class="stat-label">累计拦截次数</div>
              <div class="stat-value" style="color: #f56c6c">{{ rateLimitBlocks.total }}</div>
            </div>
            <el-table v-if="rateLimitBlocks.hosts.length > 0" :data="rateLimitBlocks.hosts" stripe size="small" :header-cell-style="{ background: '#f9fafb' }" empty-text="">
              <el-table-column prop="host" label="域名" min-width="120" show-overflow-tooltip />
              <el-table-column prop="count" label="拦截次数" width="90" align="center">
                <template #default="{ row }"><el-tag type="danger" size="small" effect="plain">{{ row.count }}</el-tag></template>
              </el-table-column>
            </el-table>
            <el-empty v-else description="暂无限流拦截" :image-size="60" />
          </template>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="always">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Location /></el-icon>
            <span>Top 10 源 IP</span>
          </div>
        </div>
      </template>
      <el-table :data="overview.top_ips" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty description="暂无数据" :image-size="60" /></template>
        <el-table-column label="IP 地址" min-width="200">
          <template #default="{ row }">
            <IPLocationAction :ip="row.ip" :location="row.ip_location" />
          </template>
        </el-table-column>
        <el-table-column prop="blocked" label="拦截" width="80" align="center">
          <template #default="{ row }"><el-tag type="danger" size="small" effect="plain">{{ row.blocked }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="detected" label="检测" width="80" align="center">
          <template #default="{ row }"><el-tag type="warning" size="small" effect="plain">{{ row.detected }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="attack_type" label="攻击类型" min-width="180" show-overflow-tooltip />
        <el-table-column prop="last_time" label="最后攻击" width="170" :formatter="(row: TopIP) => formatDate(row.last_time)" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { DataAnalysis, TrendCharts, PieChart, Location, Warning, Odometer, CircleClose, Lock, Files } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import { formatDate } from '@/utils/date'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, PieChart as PieSeries } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import VChart from 'vue-echarts'
import type { APIResponse } from '@/types'

use([CanvasRenderer, BarChart, PieSeries, GridComponent, TooltipComponent, LegendComponent])

interface TrendPoint { date: string; blocked: number; detected: number }
interface TopIP { ip: string; ip_location: string; blocked: number; detected: number; last_time: string; attack_type: string }
interface AttackType { name: string; value: number }
interface Overview { today_blocked: number; today_detected: number; active_policies: number; crs_version: string; update_status?: string; trend: TrendPoint[]; top_ips: TopIP[]; attack_types: AttackType[] }
interface SecurityEvent { id: number; event_time: string; client_ip: string; rule_caddy_id: string; rule_name: string; policy_name: string }
interface RateLimitBlockHost { host: string; count: number }
interface RateLimitBlocks { total: number; hosts: RateLimitBlockHost[] }

type TagType = 'success' | 'warning' | 'danger' | 'info'

function statusLabel(status: string): string {
  switch (status) {
    case 'idle':
    case 'success':
      return '已最新'
    case 'checking':
      return '检查中'
    case 'downloading':
      return '下载中'
    case 'installing':
      return '安装中'
    case 'reloading':
      return '重载中'
    case 'failed':
      return '更新失败'
    default:
      return status
  }
}

function statusTagType(status: string): TagType {
  switch (status) {
    case 'idle':
    case 'success':
      return 'success'
    case 'checking':
    case 'downloading':
    case 'installing':
    case 'reloading':
      return 'warning'
    case 'failed':
      return 'danger'
    default:
      return 'info'
  }
}

const overview = ref<Overview>({ today_blocked: 0, today_detected: 0, active_policies: 0, crs_version: '', trend: [], top_ips: [], attack_types: [] })
// 总览加载失败（如 metrics 库故障导致后端 500）时置位：避免把全零面板
// 误当「无攻击」，用户目标与 R35 D2 的后端显式报错对齐（R36 F1）。
const overviewError = ref(false)

const trendChartOption = computed(() => {
  const dates = overview.value.trend.map(t => t.date)
  const blocked = overview.value.trend.map(t => t.blocked)
  const detected = overview.value.trend.map(t => t.detected)
  return {
    tooltip: { trigger: 'axis' },
    legend: { data: ['拦截', '检测'], top: 0, itemGap: 24 },
    grid: { left: 40, right: 20, top: 36, bottom: 30, containLabel: false },
    xAxis: { type: 'category', data: dates },
    yAxis: { type: 'value' },
    series: [
      { name: '拦截', type: 'bar', data: blocked, itemStyle: { color: '#f56c6c' }, stack: 'total' },
      { name: '检测', type: 'bar', data: detected, itemStyle: { color: '#e6a23c' }, stack: 'total' },
    ],
  }
})

const attackChartOption = computed(() => ({
  tooltip: { trigger: 'item' },
  legend: { bottom: 0, type: 'scroll' },
  series: [{
    type: 'pie', radius: ['40%', '65%'], center: ['50%', '42%'],
    data: overview.value.attack_types.map(a => ({ name: a.name, value: a.value })),
    itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
    label: { show: true, formatter: '{b}: {c}' },
  }],
}))

const fetchData = async () => {
  try {
    const res = await request.get<APIResponse<Overview>>('/security/overview')
    if (res.data) {
      overview.value = res.data
      overviewError.value = false
    }
  } catch {
    // 后端 500（如 metrics 库故障）不再静默吞掉：置错误状态展示提示条，
    // 全零面板不再冒充「无攻击」（R36 F1）。
    overviewError.value = true
  }
}

const blockedEvents = ref<SecurityEvent[]>([])
// 面板级错误态：请求失败时面板内显示「加载失败」，不再静默降级为「暂无」，
// 与 overviewError 的 R36 F1 口径一致（R37 S4）。
const blockedEventsError = ref(false)

const fetchBlockedEvents = async () => {
  try {
    const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number }>>('/security/events?action=blocked&page_size=5')
    blockedEvents.value = res.data?.events || []
    blockedEventsError.value = false
  } catch {
    blockedEvents.value = []
    blockedEventsError.value = true
  }
}

const goToEvents = () => { window.open('/?page=security-events', '_blank') }

const rateLimitBlocks = ref<RateLimitBlocks>({ total: 0, hosts: [] })
const rateLimitError = ref(false)
const ip2regionVersion = ref('—')
const ip2regionStatus = ref('')
const ip2regionError = ref(false)

const fetchRateLimitBlocks = async () => {
  try {
    const res = await request.get<APIResponse<RateLimitBlocks>>('/security/rate-limit-blocks')
    if (res.data) rateLimitBlocks.value = res.data
    rateLimitError.value = false
  } catch {
    rateLimitError.value = true
  }
}

const fetchIP2RegionInfo = async () => {
  try {
    const res = await request.get<APIResponse<{ version: string; update_status: string }>>('/security/ip2region')
    ip2regionVersion.value = res.data?.version || '—'
    ip2regionStatus.value = res.data?.update_status || ''
    ip2regionError.value = false
  } catch {
    ip2regionVersion.value = '—'
    ip2regionStatus.value = ''
    ip2regionError.value = true
  }
}

onMounted(() => { fetchData(); fetchBlockedEvents(); fetchRateLimitBlocks(); fetchIP2RegionInfo() })
</script>

<style scoped>
.card-header { display: flex; justify-content: space-between; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }

.stat-box {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
  height: 100%;
  box-sizing: border-box;
  transition: border-color 0.2s;
}
.stat-box:hover { border-color: #d0d0d0; }
.stat-box__icon {
  flex-shrink: 0;
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
}
.stat-box__body { flex: 1; min-width: 0; }
.stat-box__value { font-size: 22px; font-weight: 700; line-height: 1.3; }
.stat-box__label { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

.stat-box--danger .stat-box__icon { background: #fef0f0; color: #f56c6c; }
.stat-box--danger .stat-box__value { color: #f56c6c; }
.stat-box--warning .stat-box__icon { background: #fdf6ec; color: #e6a23c; }
.stat-box--warning .stat-box__value { color: #e6a23c; }
.stat-box--primary .stat-box__icon { background: #ecf5ff; color: #409eff; }
.stat-box--primary .stat-box__value { color: #409eff; }
.stat-box--success .stat-box__icon { background: #f0f9eb; color: #67c23a; }
.stat-box--success .stat-box__value { color: #67c23a; }

.chart-container { height: 260px; }
.events-row .el-card { height: 100%; }
.rate-limit-total { text-align: center; padding: 4px 0 12px; }
.rate-limit-total .stat-label { font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }
.rate-limit-total .stat-value { font-size: 28px; font-weight: 600; }
</style>
