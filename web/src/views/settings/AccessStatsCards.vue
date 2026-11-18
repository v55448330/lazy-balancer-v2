<template>
  <el-card shadow="never" class="access-stats-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon class="title-icon"><DataAnalysis /></el-icon>
          <span>{{ t('app.notification.keysAccess.statsCardTitle') }}</span>
        </div>
        <span class="card-subtitle">{{ t('app.notification.keysAccess.statsAsof') }}</span>
      </div>
    </template>

    <!-- REST API 三指标（Dashboard stat-item 同构：彩色图标+大数字+标签） -->
    <div class="stats-row">
      <div class="stat-item">
        <div class="stat-icon stat-blue">
          <el-icon><Pointer /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ restStats?.today_calls ?? 0 }}</div>
          <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }} (REST)</div>
        </div>
      </div>
      <div class="stat-item">
        <div class="stat-icon stat-purple">
          <el-icon><Key /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ apiKeyStats.active7d }}</div>
          <div class="stat-label">{{ t('app.notification.keysAccess.statActive7d') }}</div>
        </div>
      </div>
      <div class="stat-item">
        <div class="stat-icon" :class="(restStats?.error_rate ?? 0) > 0.05 ? 'stat-red' : 'stat-green'">
          <el-icon><CircleCheck /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ fmtRate(restStats?.error_rate ?? 0) }}</div>
          <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }} (REST)</div>
        </div>
      </div>
    </div>

    <el-divider class="stats-divider" />

    <!-- MCP 三指标 -->
    <div class="stats-row">
      <div class="stat-item">
        <div class="stat-icon stat-blue">
          <el-icon><Connection /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ mcpStats?.today_calls ?? 0 }}</div>
          <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }} (MCP)</div>
        </div>
      </div>
      <div class="stat-item">
        <div class="stat-icon stat-purple">
          <el-icon><Monitor /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ mcpStats?.active_sessions ?? 0 }}</div>
          <div class="stat-label">{{ t('app.notification.keysUsage.statActiveSessions') }}</div>
        </div>
      </div>
      <div class="stat-item">
        <div class="stat-icon" :class="(mcpStats?.error_rate ?? 0) > 0.05 ? 'stat-red' : 'stat-green'">
          <el-icon><Warning /></el-icon>
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ fmtRate(mcpStats?.error_rate ?? 0) }}</div>
          <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }} (MCP)</div>
        </div>
      </div>
    </div>

    <!-- 明细并排：REST 最近调用 | MCP 趋势+TOP -->
    <el-divider class="stats-divider" content-position="left">
      {{ t('app.notification.keysAccess.recentCallsTitle') }} · {{ t('app.notification.keysUsage.trendTitle') }}
    </el-divider>
    <el-row :gutter="24">
      <el-col :xs="24" :md="12">
        <el-table v-if="restStats?.recent_calls?.length" :data="restStats.recent_calls" size="small" max-height="220" stripe>
          <el-table-column prop="time" :label="t('app.notification.deliveries.colTime')" width="105" />
          <el-table-column prop="key_name" :label="t('app.notification.keysSessions.colKey')" min-width="100" show-overflow-tooltip />
          <el-table-column prop="method" label="M" width="58" />
          <el-table-column prop="path" :label="t('app.notification.keysUsage.colTool')" min-width="180" show-overflow-tooltip />
          <el-table-column label="⇄" width="58" align="center">
            <template #default="scope">
              <el-tag :type="scope.row.status < 400 ? 'success' : 'danger'" size="small" effect="dark">{{ scope.row.status }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        <el-empty v-else :description="t('app.notification.keysAccess.recentCallsEmpty')" :image-size="48" />
      </el-col>
      <el-col :xs="24" :md="12">
        <template v-if="mcpStats?.top_tools?.length">
          <el-table :data="mcpStats.top_tools" size="small" max-height="100" stripe>
            <el-table-column type="index" width="40" align="center" />
            <el-table-column prop="tool" :label="t('app.notification.keysUsage.topToolsTitle')" min-width="160" show-overflow-tooltip />
            <el-table-column prop="calls" :label="t('app.notification.keysUsage.colCalls')" width="70" align="right" />
          </el-table>
        </template>
        <div v-if="trendRows.length" class="trend-list">
          <div v-for="point in trendRows" :key="point.date" class="trend-row">
            <span class="trend-date">{{ point.date.slice(5) }}</span>
            <span class="trend-bar-track">
              <span class="trend-bar" :style="{ width: trendWidth(point.calls) }" />
            </span>
            <span class="trend-calls">{{ point.calls }}</span>
          </div>
        </div>
        <el-empty v-if="!mcpStats && !(restStats?.recent_calls?.length)" :description="t('app.notification.keysUsage.emptyText')" :image-size="48" />
      </el-col>
    </el-row>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { CircleCheck, Connection, DataAnalysis, Key, Monitor, Pointer, Warning } from '@element-plus/icons-vue'
import type { McpStats } from '@/types/notifications.ts'

const props = defineProps<{
  apiKeyStats: { total: number; enabled: number; active7d: number }
  mcpStats: McpStats | null
  restStats: { today_calls: number; error_rate: number; recent_calls: { time: string; key_name: string; method: string; path: string; ip: string; status: number }[]; trend: { date: string; calls: number }[] } | null
}>()

const { t } = useI18n()

const trendRows = computed(() => props.mcpStats?.trend ?? [])
const trendMax = computed(() => Math.max(1, ...trendRows.value.map((p) => p.calls)))
const trendWidth = (calls: number): string => `${Math.max(2, Math.round((calls / trendMax.value) * 100))}%`
const fmtRate = (rate: number): string => `${(rate * 100).toFixed(1)}%`
</script>

<style scoped>
/* Dashboard 统计卡同构视觉（stat-item+彩色图标） */
.access-stats-card { margin-bottom: 16px; }
.card-header { display: flex; align-items: center; justify-content: space-between; }
.card-title { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 15px; }
.title-icon { color: var(--el-color-primary); font-size: 18px; }
.card-subtitle { font-size: 12px; color: var(--text-secondary, #6b7280); font-weight: 400; }

.stats-row { display: flex; gap: 24px; flex-wrap: wrap; padding: 4px 0; }
.stat-item { display: flex; align-items: center; gap: 12px; flex: 1; min-width: 160px; }
.stat-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; flex: none; }
.stat-blue { background: #eff6ff; color: #3b82f6; }
.stat-purple { background: #f5f3ff; color: #8b5cf6; }
.stat-green { background: #ecfdf5; color: #10b981; }
.stat-red { background: #fef2f2; color: #ef4444; }
.stat-value { font-size: 20px; font-weight: 600; color: #111827; line-height: 1.2; }
.stat-label { font-size: 12px; color: #6b7280; margin-top: 2px; }

.stats-divider { margin: 14px 0 10px; }

.trend-list { display: flex; flex-direction: column; gap: 5px; }
.trend-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.trend-date { flex: none; width: 48px; color: var(--text-secondary, #6b7280); }
.trend-bar-track { flex: 1; background: var(--bg-secondary, #f3f4f6); border-radius: 3px; height: 14px; overflow: hidden; }
.trend-bar { display: block; height: 100%; background: var(--el-color-primary); border-radius: 3px; opacity: 0.7; }
.trend-calls { flex: none; width: 44px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-secondary, #6b7280); }
</style>
