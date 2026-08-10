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

    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card shadow="always" class="stat-card-wrapper">
          <el-row :gutter="20">
            <el-col :span="6" class="stat-card-col">
              <div class="stat-label">今日拦截</div>
              <div class="stat-value" style="color: #f56c6c">{{ overview.today_blocked }}</div>
            </el-col>
            <el-col :span="6" class="stat-card-col">
              <div class="stat-label">今日检测</div>
              <div class="stat-value" style="color: #e6a23c">{{ overview.today_detected }}</div>
            </el-col>
            <el-col :span="6" class="stat-card-col">
              <div class="stat-label">活跃策略</div>
              <div class="stat-value" style="color: #409eff">{{ overview.active_policies }}</div>
            </el-col>
            <el-col :span="6" class="stat-card-col">
              <div class="stat-label">CRS 版本</div>
              <div class="stat-value" style="color: #67c23a">{{ overview.crs_version }}</div>
            </el-col>
          </el-row>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="16">
        <el-card shadow="always">
          <template #header>
            <div class="flex items-center gap-2">
              <el-icon><TrendCharts /></el-icon>
              <span class="font-medium">7 天拦截趋势</span>
            </div>
          </template>
          <div class="chart-container">
            <v-chart :option="trendChartOption" autoresize style="height: 260px" />
          </div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="always">
          <template #header>
            <div class="flex items-center gap-2">
              <el-icon><PieChart /></el-icon>
              <span class="font-medium">攻击类型分布</span>
            </div>
          </template>
          <div class="chart-container">
            <v-chart :option="attackChartOption" autoresize style="height: 260px" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="always">
      <template #header>
        <div class="flex items-center gap-2">
          <el-icon><Location /></el-icon>
          <span class="font-medium">Top 10 源 IP</span>
        </div>
      </template>
      <el-table :data="overview.top_ips" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty description="暂无数据" :image-size="60" /></template>
        <el-table-column prop="ip" label="IP 地址" min-width="130" />
        <el-table-column prop="blocked" label="拦截" width="80" align="center">
          <template #default="{ row }"><el-tag type="danger" size="small" effect="plain">{{ row.blocked }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="detected" label="检测" width="80" align="center">
          <template #default="{ row }"><el-tag type="warning" size="small" effect="plain">{{ row.detected }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="attack_type" label="攻击类型" min-width="180" show-overflow-tooltip />
        <el-table-column prop="last_time" label="最后攻击" width="170" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { DataAnalysis, TrendCharts, PieChart, Location } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import VChart from 'vue-echarts'

interface APIResponse<T> { code: number; message: string; data: T }
interface TrendPoint { date: string; blocked: number; detected: number }
interface TopIP { ip: string; blocked: number; detected: number; last_time: string; attack_type: string }
interface AttackType { name: string; value: number }
interface Overview { today_blocked: number; today_detected: number; active_policies: number; crs_version: string; trend: TrendPoint[]; top_ips: TopIP[]; attack_types: AttackType[] }

const overview = ref<Overview>({ today_blocked: 0, today_detected: 0, active_policies: 0, crs_version: '', trend: [], top_ips: [], attack_types: [] })

const trendChartOption = computed(() => {
  const dates = overview.value.trend.map(t => t.date)
  const blocked = overview.value.trend.map(t => t.blocked)
  const detected = overview.value.trend.map(t => t.detected)
  return {
    tooltip: { trigger: 'axis' },
    legend: { data: ['拦截', '检测'] },
    grid: { left: 40, right: 20, top: 40, bottom: 30 },
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
  legend: { bottom: 0 },
  series: [{
    type: 'pie', radius: ['40%', '70%'], center: ['50%', '45%'],
    data: overview.value.attack_types.map(a => ({ name: a.name, value: a.value })),
    itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
    label: { show: true, formatter: '{b}: {c}' },
  }],
}))

const fetchData = async () => {
  try {
    const res = await request.get<APIResponse<Overview>>('/security/overview')
    if (res.data) overview.value = res.data
  } catch { /* silent */ }
}

onMounted(fetchData)
</script>

<style scoped>
.stat-card-wrapper { padding: 8px 0; }
.stat-card-col { text-align: center; padding: 12px 0; }
.stat-label { font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }
.stat-value { font-size: 28px; font-weight: 600; }
.chart-container { height: 260px; }
</style>
