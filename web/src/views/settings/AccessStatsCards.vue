<template>
  <!-- 接入统计（单卡双协议，指标对称）：REST 与 MCP 各三指标（今日调用/
       活跃维度/错误率）；明细并排（REST 最近调用 | MCP 趋势+TOP），无空列 -->
  <el-card shadow="never" class="access-stats-card">
    <template #header>
      <div class="stats-header">
        <span>{{ t('app.notification.keysAccess.statsCardTitle') }}</span>
        <span class="stats-asof">{{ t('app.notification.keysAccess.statsAsof') }}</span>
      </div>
    </template>

    <el-row :gutter="16" class="proto-grid">
      <!-- REST API 列：调用/使用/健康三指标（与 MCP 对称） -->
      <el-col :xs="24" :md="12" class="proto-col">
        <div class="proto-head">
          <el-icon class="proto-icon"><Key /></el-icon>
          <span class="proto-name">{{ t('app.notification.keysAccess.protoRest') }}</span>
          <el-tag size="small" type="info" effect="plain">{{ t('app.notification.keysAccess.protoRestTag') }}</el-tag>
        </div>
        <el-row :gutter="12">
          <el-col :span="8">
            <div class="stat-tile">
              <div class="stat-value">{{ restStats?.today_calls ?? 0 }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="stat-tile">
              <div class="stat-value">{{ apiKeyStats.active7d }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statActive7d') }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="stat-tile">
              <div class="stat-value">{{ formatErrorRate(restStats?.error_rate ?? 0) }}</div>
              <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }}</div>
            </div>
          </el-col>
        </el-row>
        <div class="proto-foot">{{ t('app.notification.keysAccess.protoRestFoot') }}</div>
      </el-col>

      <!-- MCP 列：调用/会话/健康 -->
      <el-col :xs="24" :md="12" class="proto-col proto-col-mcp">
        <div class="proto-head">
          <el-icon class="proto-icon"><Connection /></el-icon>
          <span class="proto-name">{{ t('app.notification.keysAccess.protoMcp') }}</span>
          <el-tag size="small" type="info" effect="plain">{{ t('app.notification.keysAccess.protoMcpTag') }}</el-tag>
        </div>
        <template v-if="mcpStats">
          <el-row :gutter="12">
            <el-col :span="8">
              <div class="stat-tile">
                <div class="stat-value">{{ mcpStats.today_calls }}</div>
                <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }}</div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-tile">
                <div class="stat-value">{{ mcpStats.active_sessions }}</div>
                <div class="stat-label">{{ t('app.notification.keysUsage.statActiveSessions') }}</div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-tile">
                <div class="stat-value">{{ formatErrorRate(mcpStats.error_rate) }}</div>
                <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }}</div>
              </div>
            </el-col>
          </el-row>
          <div class="proto-foot">{{ t('app.notification.keysAccess.protoMcpFoot') }}</div>
        </template>
        <el-empty v-else :description="t('app.notification.keysUsage.emptyText')" :image-size="48" />
      </el-col>
    </el-row>

    <!-- 明细并排（常显：空态走 el-empty 框架）：REST 最近调用 | MCP 趋势+TOP 工具 -->
    <el-row :gutter="24" class="detail-row">
      <el-col :xs="24" :md="12">
        <div class="usage-block-title">{{ t('app.notification.keysAccess.recentCallsTitle') }}</div>
        <el-table v-if="restStats && restStats.recent_calls.length" :data="restStats.recent_calls" size="small" max-height="220" class="recent-table">
          <el-table-column prop="time" :label="t('app.notification.deliveries.colTime')" width="110" />
          <el-table-column prop="key_name" :label="t('app.notification.keysSessions.colKey')" min-width="110" show-overflow-tooltip />
          <el-table-column prop="method" label="Method" width="70" />
          <el-table-column prop="path" :label="t('app.notification.keysUsage.colTool')" min-width="200" show-overflow-tooltip />
          <el-table-column :label="t('app.notification.keysUsage.colCalls')" width="70" align="center">
            <template #default="scope">
              <el-tag :type="scope.row.status < 400 ? 'success' : 'danger'" size="small">{{ scope.row.status }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        <el-empty v-else :description="t('app.notification.keysAccess.recentCallsEmpty')" :image-size="48" />
      </el-col>
      <el-col :xs="24" :md="restStats && restStats.recent_calls.length ? 12 : 24">
        <template v-if="mcpStats && trendRows.length">
          <div class="usage-block-title">{{ t('app.notification.keysUsage.trendTitle') }}</div>
          <div class="trend-list">
            <div v-for="point in trendRows" :key="point.date" class="trend-row">
              <span class="trend-date">{{ point.date }}</span>
              <span class="trend-bar-track">
                <span class="trend-bar" :style="{ width: trendBarWidth(point.calls) }" />
              </span>
              <span class="trend-calls">{{ point.calls }}</span>
            </div>
          </div>
        </template>
        <template v-if="mcpStats && mcpStats.top_tools.length">
          <div class="usage-block-title">{{ t('app.notification.keysUsage.topToolsTitle') }}</div>
          <el-table :data="mcpStats.top_tools" size="small" max-height="200">
            <el-table-column type="index" width="46" align="center" />
            <el-table-column prop="tool" :label="t('app.notification.keysUsage.colTool')" min-width="180" show-overflow-tooltip />
            <el-table-column prop="calls" :label="t('app.notification.keysUsage.colCalls')" width="90" align="right" />
          </el-table>
        </template>
      </el-col>
    </el-row>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Connection, Key } from '@element-plus/icons-vue'
import type { McpStats } from '@/types/notifications.ts'

// REST 列指标来自 /api-keys/access-overview（内存环形采集：今日调用/错误率/
// 最近调用）；近 7 天活跃密钥为资产使用维度（api_keys 现成字段）。
// MCP 列沿用 /notification/mcp/stats。
const props = defineProps<{
  apiKeyStats: { total: number; enabled: number; active7d: number }
  mcpStats: McpStats | null
  restStats: { today_calls: number; error_rate: number; recent_calls: { time: string; key_name: string; method: string; path: string; ip: string; status: number }[]; trend: { date: string; calls: number }[] } | null
}>()

const { t } = useI18n()

const trendRows = computed(() => props.mcpStats?.trend ?? [])

const trendMax = computed(() => Math.max(1, ...trendRows.value.map((p) => p.calls)))

const trendBarWidth = (calls: number): string => `${Math.max(2, Math.round((calls / trendMax.value) * 100))}%`

const formatErrorRate = (rate: number): string => `${(rate * 100).toFixed(1)}%`
</script>

<style scoped>
.access-stats-card { margin-bottom: 16px; }
.stats-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.stats-asof { font-size: 12px; color: var(--text-secondary, #6b7280); font-weight: 400; }
.proto-col { position: relative; }
.proto-col + .proto-col-mcp { margin-top: 4px; }
@media (min-width: 992px) {
  .proto-col:first-child { padding-right: 16px; }
  .proto-col-mcp { padding-left: 16px; border-left: 1px solid var(--el-border-color-lighter); margin-top: 0 !important; }
}
.proto-head { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.proto-icon { color: var(--el-color-primary); font-size: 16px; }
.proto-name { font-weight: 600; font-size: 14px; }
.proto-foot { margin-top: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); line-height: 1.5; }
.stat-tile { background: var(--bg-secondary, #f9fafb); border-radius: 6px; padding: 12px 8px; text-align: center; }
.stat-value { font-size: 22px; font-weight: 700; line-height: 1.3; font-variant-numeric: tabular-nums; }
.stat-label { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
.detail-row { margin-top: 16px; }
.usage-block-title { font-weight: 600; margin: 0 0 8px; font-size: 13px; color: var(--text-secondary, #6b7280); }
.recent-table { width: 100%; }
.trend-list { display: flex; flex-direction: column; gap: 6px; }
.trend-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.trend-date { flex: none; width: 86px; color: var(--text-secondary, #6b7280); }
.trend-bar-track { flex: 1; background: var(--bg-secondary, #f3f4f6); border-radius: 2px; height: 12px; overflow: hidden; }
.trend-bar { display: block; height: 100%; background: var(--el-color-primary); border-radius: 2px; }
.trend-calls { flex: none; width: 56px; text-align: right; font-variant-numeric: tabular-nums; }
</style>
