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
          <el-descriptions :column="5" border>
            <el-descriptions-item label="主机名">
              <span class="text-primary">{{ systemInfo?.hostname || '-' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="操作系统">{{ systemInfo?.os_info || '-' }}</el-descriptions-item>
            <el-descriptions-item label="内核">{{ systemInfo?.kernel || '-' }}</el-descriptions-item>
            <el-descriptions-item label="架构">{{ systemInfo?.architecture || '-' }}</el-descriptions-item>
            <el-descriptions-item label="Caddy版本">
              <el-tag type="info" size="small">{{ systemInfo?.caddy_version || '-' }}</el-tag>
            </el-descriptions-item>
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
                <div v-if="!isSlave" class="caddy-actions">
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
                  <div class="stat-value">{{ (caddyMetrics?.requests_total || 0).toLocaleString() }}</div>
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
                  <div class="stat-value">{{ caddyMetrics?.requests_in_flight || 0 }}</div>
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
                  <div class="stat-value">{{ hostMetrics.length }}</div>
                  <div class="stat-label">域名统计</div>
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
          <el-row :gutter="32">
            <el-col :span="8">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">CPU 使用率</span>
                  <span class="resource-value text-blue">{{ (systemMetrics?.cpu_percent || 0).toFixed(1) }}%</span>
                </div>
                <el-progress :percentage="Math.min(systemMetrics?.cpu_percent || 0, 100)" :stroke-width="6" color="#3b82f6" :show-text="false" />
              </div>
            </el-col>
            <el-col :span="8">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">内存使用</span>
                  <span class="resource-value text-purple">
                    {{ formatBytes(systemMetrics?.memory_used || 0) }}
                    <span class="resource-total">/ {{ formatBytes(systemMetrics?.memory_total || 0) }}</span>
                  </span>
                </div>
                <el-progress :percentage="Math.min(systemMetrics?.memory_percent || 0, 100)" :stroke-width="6" color="#8b5cf6" :show-text="false" />
              </div>
            </el-col>
            <el-col :span="8">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">磁盘使用</span>
                  <span class="resource-value text-cyan">
                    {{ formatBytes(systemMetrics?.disk_used || 0) }}
                    <span class="resource-total">/ {{ formatBytes(systemMetrics?.disk_total || 0) }}</span>
                  </span>
                </div>
                <el-progress :percentage="Math.min(systemMetrics?.disk_percent || 0, 100)" :stroke-width="6" color="#06b6d4" :show-text="false" />
              </div>
            </el-col>
          </el-row>
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
          <div class="chart-container">
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
          <div class="chart-container">
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
              <el-badge :value="rules.length" type="primary" />
            </div>
          </template>
          <el-table :data="rules" stripe :header-cell-style="{ background: '#f9fafb' }">
            <el-table-column prop="name" label="规则名称" min-width="150">
              <template #default="{ row }">
                <span class="text-primary font-medium">{{ row.name }}</span>
              </template>
            </el-table-column>
            <el-table-column label="协议" width="90">
              <template #default="{ row }">
                <el-tag :type="row.protocol === 'https' ? 'success' : row.protocol === 'http' ? 'primary' : 'warning'" size="small" effect="plain">
                  {{ row.protocol?.toUpperCase() }}
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
                <span class="text-primary">{{ (ruleMetrics[row.caddy_id]?.requests_total ?? 0).toLocaleString() }}</span>
              </template>
            </el-table-column>
            <el-table-column label="状态码" width="220" align="center">
              <template #default="{ row }">
                <div v-if="(ruleMetrics[row.caddy_id]?.requests_total ?? 0) > 0" class="status-codes">
                  <span class="status-code status-2xx" title="成功">2xx {{ ruleMetrics[row.caddy_id]?.status_2xx ?? 0 }}</span>
                  <span class="status-code status-3xx" title="重定向">3xx {{ ruleMetrics[row.caddy_id]?.status_3xx ?? 0 }}</span>
                  <span class="status-code status-4xx" title="客户端错误">4xx {{ ruleMetrics[row.caddy_id]?.status_4xx ?? 0 }}</span>
                  <span class="status-code status-5xx" title="服务器错误">5xx {{ ruleMetrics[row.caddy_id]?.status_5xx ?? 0 }}</span>
                </div>
                <span v-else class="text-secondary">-</span>
              </template>
            </el-table-column>
            <el-table-column label="入站流量" width="100" align="right">
              <template #default="{ row }">
                <span class="text-secondary">{{ formatBytes(ruleMetrics[row.caddy_id]?.bytes_in ?? 0) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="出站流量" width="100" align="right">
              <template #default="{ row }">
                <span class="text-secondary">{{ formatBytes(ruleMetrics[row.caddy_id]?.bytes_out ?? 0) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="处理中" width="70" align="center">
              <template #default="{ row }">
                <span class="text-secondary">{{ ruleMetrics[row.caddy_id]?.requests_in_flight ?? 0 }}</span>
              </template>
            </el-table-column>
            <el-table-column label="健康状态" width="80" align="center">
              <template #default="{ row }">
                <el-tag v-if="!row.enabled" type="info" size="small" effect="plain">-</el-tag>
                <el-tag v-else-if="ruleMetrics[row.caddy_id]?.healthy === undefined" type="info" size="small" effect="plain">-</el-tag>
                <el-tag v-else :type="ruleMetrics[row.caddy_id]?.healthy ? 'success' : 'danger'" size="small" effect="plain">
                  {{ ruleMetrics[row.caddy_id]?.healthy ? '健康' : '异常' }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="rules.length === 0" description="暂无负载均衡规则" :image-size="80" />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import VChart from 'vue-echarts'
import { useAuthStore } from '@/stores/auth'
import { request, formatBytes } from '@/utils/api'
import { ElMessageBox } from 'element-plus'
import { Monitor, Cpu, Document, Loading, CircleCheck, Odometer, TrendCharts, DataLine, List } from '@element-plus/icons-vue'
import type { SystemInfo, SystemMetrics, CaddyMetrics, RealtimeTraffic, ConnectionStats, Rule, RuleMetrics, HostMetrics } from '@/types'

use([CanvasRenderer, LineChart, GridComponent, TooltipComponent, LegendComponent])

const authStore = useAuthStore()

const systemInfo = ref<SystemInfo | null>(null)
const systemMetrics = ref<SystemMetrics | null>(null)
const caddyMetrics = ref<CaddyMetrics | null>(null)
const realtimeTraffic = ref<RealtimeTraffic | null>(null)
const connectionStats = ref<ConnectionStats | null>(null)
const caddyStatus = ref('unknown')
const caddyLoading = ref(false)
const rules = ref<Rule[]>([])
const ruleMetrics = ref<Record<number, RuleMetrics>>({})
const hostMetrics = ref<HostMetrics[]>([])

const trafficInHistory = ref<number[]>([])
const trafficOutHistory = ref<number[]>([])
const trafficTimestamps = ref<number[]>([])
const connEstablishedHistory = ref<number[]>([])
const connTimeWaitHistory = ref<number[]>([])
const connTimestamps = ref<number[]>([])

const isSlave = computed(() => authStore.nodeMode === 'slave')

const ipList = computed(() => {
  if (!systemInfo.value?.ip_addresses) return []
  try {
    return JSON.parse(systemInfo.value.ip_addresses)
  } catch {
    return []
  }
})

const getStrategyLabel = (strategy: string) => {
  const labels: Record<string, string> = {
    round_robin: '轮询',
    least_conn: '最少连接',
    ip_hash: 'IP 哈希',
  }
  return labels[strategy] || strategy
}

const trafficChartOption = computed(() => ({
  tooltip: { 
    trigger: 'axis', 
    backgroundColor: 'rgba(255,255,255,0.95)', 
    borderColor: '#e5e7eb', 
    textStyle: { color: '#374151', fontSize: 12 },
    formatter: (params: any) => {
      let result = params[0].name + '<br/>'
      params.forEach((item: any) => {
        result += `${item.marker} ${item.seriesName}: ${formatBytes(item.value)}<br/>`
      })
      return result
    }
  },
  legend: { data: ['入站', '出站'], bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 45, right: 15, top: 15, bottom: 40 },
  xAxis: { 
    type: 'category', 
    data: trafficTimestamps.value.map(t => new Date(t).toLocaleTimeString()),
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
    { name: '入站', type: 'line', data: trafficInHistory.value, smooth: true, showSymbol: false, lineStyle: { color: '#3b82f6', width: 2 }, areaStyle: { color: 'rgba(59,130,246,0.1)' } },
    { name: '出站', type: 'line', data: trafficOutHistory.value, smooth: true, showSymbol: false, lineStyle: { color: '#10b981', width: 2 }, areaStyle: { color: 'rgba(16,185,129,0.1)' } },
  ],
}))

const connChartOption = computed(() => ({
  tooltip: { trigger: 'axis', backgroundColor: 'rgba(255,255,255,0.95)', borderColor: '#e5e7eb', textStyle: { color: '#374151', fontSize: 12 } },
  legend: { data: ['已建立', '等待释放'], bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 45, right: 15, top: 15, bottom: 40 },
  xAxis: { 
    type: 'category', 
    data: connTimestamps.value.map(t => new Date(t).toLocaleTimeString()),
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
    { name: '已建立', type: 'line', data: connEstablishedHistory.value, smooth: true, showSymbol: false, lineStyle: { color: '#10b981', width: 2 } },
    { name: '等待释放', type: 'line', data: connTimeWaitHistory.value, smooth: true, showSymbol: false, lineStyle: { color: '#f59e0b', width: 2 } },
  ],
}))

let timer: number | null = null

const fetchAllData = async () => {
  try {
    const headers = { Authorization: `Bearer ${authStore.token}` }
    const results = await Promise.allSettled([
      request.get('/system/info', { headers }),
      request.get('/system/metrics', { headers }),
      request.get('/metrics/realtime', { headers }),
      request.get('/caddy/metrics', { headers }),
      request.get('/caddy/host-metrics', { headers }),
      request.get('/rules', { headers }),
      request.get('/metrics/connections', { headers }),
      request.get('/caddy/status', { headers }),
    ])

    const getData = (index: number) => results[index].status === 'fulfilled' ? results[index].value : null

    const sysInfoRes = getData(0)
    const sysMetricsRes = getData(1)
    const trafficRes = getData(2)
    const caddyMetricsRes = getData(3)
    const hostMetricsRes = getData(4)
    const rulesRes = getData(5)
    const connStatsRes = getData(6)
    const caddyStatusRes = getData(7)

    if (sysInfoRes?.data) systemInfo.value = sysInfoRes.data
    if (sysMetricsRes?.data) systemMetrics.value = sysMetricsRes.data
    if (caddyMetricsRes?.data) caddyMetrics.value = caddyMetricsRes.data
    if (hostMetricsRes?.data) hostMetrics.value = hostMetricsRes.data || []
    if (caddyStatusRes?.data) caddyStatus.value = caddyStatusRes.data?.status || 'unknown'

    if (trafficRes?.data) {
      const data = trafficRes.data
      realtimeTraffic.value = data
      const now = Date.now()
      trafficInHistory.value = [...trafficInHistory.value, data?.bytes_in || 0].slice(-60)
      trafficOutHistory.value = [...trafficOutHistory.value, data?.bytes_out || 0].slice(-60)
      trafficTimestamps.value = [...trafficTimestamps.value, now].slice(-60)
    }

    if (connStatsRes?.data) {
      const connData = connStatsRes.data
      connectionStats.value = connData
      const now = Date.now()
      connEstablishedHistory.value = [...connEstablishedHistory.value, connData?.established || 0].slice(-60)
      connTimeWaitHistory.value = [...connTimeWaitHistory.value, connData?.time_wait || 0].slice(-60)
      connTimestamps.value = [...connTimestamps.value, now].slice(-60)
    }

    if (rulesRes?.data) {
      rules.value = rulesRes.data || []
    }
  } catch (e) {
    console.error(e)
  }
}

const fetchRuleMetrics = async () => {
  if (rules.value.length === 0) return
  const headers = { Authorization: `Bearer ${authStore.token}` }
  const metricsPromises = rules.value.map((rule: Rule) =>
    request.get(`/metrics/rule/${rule.caddy_id}`, { headers })
  )
  const metricsResults = await Promise.allSettled(metricsPromises)
  const newRuleMetrics: Record<string, RuleMetrics> = {}
  metricsResults.forEach((result: any, index: number) => {
    if (result.status === 'fulfilled' && result.value?.data) {
      newRuleMetrics[rules.value[index].caddy_id] = result.value.data
    }
  })
  ruleMetrics.value = newRuleMetrics
}

const controlCaddy = async (action: 'start' | 'stop' | 'restart') => {
  if (isSlave.value) return
  
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
    
    caddyLoading.value = true
    await request.post(`/caddy/${action}`)
    
    // After start or restart, reload config from database
    if (action === 'start' || action === 'restart') {
      await request.post('/config/reload')
    }
    
    // Optimistic update - show the expected status immediately
    if (action === 'stop') {
      caddyStatus.value = 'stopped'
    } else if (action === 'start' || action === 'restart') {
      caddyStatus.value = 'running'
    }
    
    authStore.showToast('success', `Caddy ${actionText}成功`)
    
    // Also fetch actual status to confirm
    setTimeout(fetchAllData, 1000)
    setTimeout(fetchAllData, 2500)
  } catch (e: any) {
    if (e === 'cancel') return
    const msg = e?.response?.data?.message || e?.message || '操作失败'
    authStore.showToast('error', msg)
  } finally {
    caddyLoading.value = false
  }
}

onMounted(() => {
  fetchAllData()
  fetchRuleMetrics()
  timer = window.setInterval(() => {
    fetchAllData()
    fetchRuleMetrics()
  }, 5000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.dashboard { max-width: 1500px; margin: 0 auto; }
.mb-5 { margin-bottom: 20px; }

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
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

.text-primary { color: #111827; }
.text-secondary { color: #6b7280; }
.font-medium { font-weight: 500; }

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
</style>