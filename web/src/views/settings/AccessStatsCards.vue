<template>
  <div class="access-dashboard">
    <!-- 统计卡（Dashboard 同构：el-card + card-header + stat-item 网格） -->
    <el-card class="access-stats-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><DataAnalysis /></el-icon>
            <span>{{ t('app.notification.keysAccess.statsCardTitle') }}</span>
          </div>
          <span class="card-subtitle">{{ t('app.notification.keysAccess.statsAsof') }}</span>
        </div>
      </template>
      <el-row :gutter="16">
        <el-col :xs="12" :sm="8" :md="4">
          <div class="stat-item">
            <div class="stat-icon stat-blue"><el-icon><Pointer /></el-icon></div>
            <div class="stat-content">
              <div class="stat-value">{{ restStats?.today_calls ?? 0 }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }} (REST)</div>
            </div>
          </div>
        </el-col>
        <el-col :xs="12" :sm="8" :md="4">
          <div class="stat-item">
            <div class="stat-icon stat-purple"><el-icon><Connection /></el-icon></div>
            <div class="stat-content">
              <div class="stat-value">{{ mcpStats?.today_calls ?? 0 }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }} (MCP)</div>
            </div>
          </div>
        </el-col>
        <el-col :xs="12" :sm="8" :md="4">
          <div class="stat-item">
            <div class="stat-icon stat-blue"><el-icon><Key /></el-icon></div>
            <div class="stat-content">
              <div class="stat-value">{{ apiKeyStats.active7d }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statActive7d') }}</div>
            </div>
          </div>
        </el-col>
        <el-col :xs="12" :sm="8" :md="4">
          <div class="stat-item">
            <div class="stat-icon stat-purple"><el-icon><Monitor /></el-icon></div>
            <div class="stat-content">
              <div class="stat-value">{{ mcpStats?.active_sessions ?? 0 }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statActiveSessions') }}</div>
            </div>
          </div>
        </el-col>
        <el-col :xs="12" :sm="8" :md="4">
          <div class="stat-item">
            <div class="stat-icon" :class="(restStats?.error_rate ?? 0) > 0.05 ? 'stat-red' : 'stat-green'"><el-icon><CircleCheck /></el-icon></div>
            <div class="stat-content">
              <div class="stat-value">{{ fmtRate(restStats?.error_rate ?? 0) }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }} (REST)</div>
            </div>
          </div>
        </el-col>
        <el-col :xs="12" :sm="8" :md="4">
          <div class="stat-item">
            <div class="stat-icon" :class="(mcpStats?.error_rate ?? 0) > 0.05 ? 'stat-red' : 'stat-green'"><el-icon><Warning /></el-icon></div>
            <div class="stat-content">
              <div class="stat-value">{{ fmtRate(mcpStats?.error_rate ?? 0) }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }} (MCP)</div>
            </div>
          </div>
        </el-col>
      </el-row>
    </el-card>

    <!-- 趋势双图（REST/MCP 7 天调用，Dashboard chart-card 同构） -->
    <el-row :gutter="16" class="access-charts">
      <el-col :xs="24" :md="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon chart-icon"><TrendCharts /></el-icon>
                <span>{{ t('app.notification.keysAccess.restTrendTitle') }}</span>
              </div>
            </div>
          </template>
          <div class="chart-container">
            <v-chart v-if="restTrend.length" :option="restTrendOption" autoresize />
            <el-empty v-else :description="t('app.notification.keysAccess.trendEmpty')" :image-size="60" />
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon chart-icon"><TrendCharts /></el-icon>
                <span>{{ t('app.notification.keysAccess.mcpTrendTitle') }}</span>
              </div>
            </div>
          </template>
          <div class="chart-container">
            <v-chart v-if="mcpTrend.length" :option="mcpTrendOption" autoresize />
            <el-empty v-else :description="t('app.notification.keysAccess.trendEmpty')" :image-size="60" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 明细并排：REST 最近调用 | MCP TOP 工具 -->
    <el-row :gutter="16">
      <el-col :xs="24" :md="14">
        <el-card class="list-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><List /></el-icon>
                <span>{{ t('app.notification.keysAccess.recentCallsTitle') }}</span>
              </div>
            </div>
          </template>
          <el-table v-if="restStats?.recent_calls?.length" :data="restStats.recent_calls" size="small" max-height="260" stripe :header-cell-style="{ background: '#f9fafb' }">
            <el-table-column prop="time" :label="t('app.notification.deliveries.colTime')" width="105" />
            <el-table-column prop="key_name" :label="t('app.notification.keysSessions.colKey')" min-width="100" show-overflow-tooltip />
            <el-table-column prop="method" :label="t('common.app.views.keys.colMethod')" width="76" />
            <el-table-column prop="path" :label="t('common.app.views.keys.colPath')" min-width="160" show-overflow-tooltip />
            <el-table-column prop="ip" :label="t('common.app.views.keys.colSourceIp')" width="120" show-overflow-tooltip />
            <el-table-column :label="t('common.app.views.keys.colStatusCode')" width="70" align="center">
              <template #default="scope">
                <el-tag :type="scope.row.status < 400 ? 'success' : 'danger'" size="small" effect="dark">{{ scope.row.status }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else :description="t('app.notification.keysAccess.recentCallsEmpty')" :image-size="60" />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="10">
        <el-card class="list-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon pie-icon"><Histogram /></el-icon>
                <span>{{ t('app.notification.keysAccess.topToolsTitle') }}</span>
              </div>
            </div>
          </template>
          <el-table v-if="mcpStats?.top_tools?.length" :data="mcpStats.top_tools" size="small" max-height="260" stripe :header-cell-style="{ background: '#f9fafb' }">
            <el-table-column type="index" width="40" align="center" />
            <el-table-column prop="tool" :label="t('app.notification.keysUsage.colTool')" min-width="160" show-overflow-tooltip />
            <el-table-column prop="calls" :label="t('app.notification.keysUsage.colCalls')" width="80" align="right" />
          </el-table>
          <el-empty v-else :description="t('app.notification.keysAccess.topToolsEmpty')" :image-size="60" />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { CircleCheck, Connection, DataAnalysis, Histogram, Key, List, Monitor, Pointer, TrendCharts, Warning } from '@element-plus/icons-vue'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import { axisChartBase, lineSeries, chartColors } from '@/utils/chartBase'
import type { McpStats } from '@/types/notifications.ts'

const props = defineProps<{
  apiKeyStats: { total: number; enabled: number; active7d: number }
  mcpStats: McpStats | null
  restStats: { today_calls: number; error_rate: number; recent_calls: { time: string; key_name: string; method: string; path: string; ip: string; status: number }[]; trend: { date: string; calls: number }[] } | null
}>()

const { t } = useI18n()

const restTrend = computed(() => props.restStats?.trend ?? [])
const mcpTrend = computed(() => props.mcpStats?.trend ?? [])
const fmtRate = (rate: number): string => `${(rate * 100).toFixed(1)}%`

const trendOption = (rows: { date: string; calls: number }[], color: string): EChartsOption => {
  const name = t('app.notification.keysAccess.trendCalls')
  return axisChartBase([name], rows.map(p => p.date.slice(5)), [
    lineSeries(name, color, rows.map(p => p.calls), { showSymbol: rows.length < 2 }),
  ], { yExtra: { minInterval: 1 } })
}
const restTrendOption = computed<EChartsOption>(() => trendOption(restTrend.value, chartColors.blue))
const mcpTrendOption = computed<EChartsOption>(() => trendOption(mcpTrend.value, chartColors.purple))
</script>

<style scoped>
/* Dashboard 卡片规范同构（DESIGN_SPEC.md §2：边框 #ebeef5） */
.el-card { --el-card-border-color: #ebeef5; }
.access-dashboard { display: flex; flex-direction: column; gap: 16px; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.chart-icon { color: #f59e0b; }
.pie-icon { color: #8b5cf6; }
.card-subtitle { font-size: 12px; color: #6b7280; font-weight: 400; }
.stat-item { display: flex; align-items: center; gap: 14px; padding: 16px; background: #f9fafb; border-radius: 8px; }
.stat-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; flex: none; }
.stat-blue { background: #eff6ff; color: #3b82f6; }
.stat-purple { background: #f5f3ff; color: #8b5cf6; }
.stat-green { background: #ecfdf5; color: #10b981; }
.stat-red { background: #fef2f2; color: #ef4444; }
.stat-value { font-size: 20px; font-weight: 600; color: #111827; line-height: 1.2; }
.stat-label { font-size: 12px; color: #6b7280; margin-top: 2px; }
.chart-card :deep(.el-card__body) { height: 260px; padding: 16px; box-sizing: border-box; }
.chart-container { height: 228px; }
.chart-container .echarts { height: 100%; }
</style>