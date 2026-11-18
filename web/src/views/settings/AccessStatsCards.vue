<template>
  <!-- 接入统计（单卡双协议）：REST API 与 MCP 两列同构对齐——指标网格
       统一规格，MCP 专属明细（TOP 工具/调用趋势）收进卡内下半区，
       不再以两张「看似同构、维度异构」的卡并列 -->
  <el-card shadow="never" class="access-stats-card">
    <template #header>
      <div class="stats-header">
        <span>{{ t('app.notification.keysAccess.title') }}</span>
        <span class="stats-asof">{{ t('app.notification.keysAccess.statsAsof') }}</span>
      </div>
    </template>

    <el-row :gutter="16" class="proto-grid">
      <!-- REST API 列：资产 + 使用（调用计数无逐日数据，不虚报） -->
      <el-col :xs="24" :md="12" class="proto-col">
        <div class="proto-head">
          <el-icon class="proto-icon"><Key /></el-icon>
          <span class="proto-name">{{ t('app.notification.keysAccess.protoRest') }}</span>
          <el-tag size="small" type="info" effect="plain">{{ t('app.notification.keysAccess.protoRestTag') }}</el-tag>
        </div>
        <el-row :gutter="12">
          <el-col :span="8">
            <div class="stat-tile">
              <div class="stat-value">{{ apiKeyStats.total }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statTotal') }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="stat-tile">
              <div class="stat-value">{{ apiKeyStats.enabled }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statEnabled') }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="stat-tile">
              <div class="stat-value">{{ apiKeyStats.active7d }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statActive7d') }}</div>
            </div>
          </el-col>
        </el-row>
        <div class="proto-foot">{{ t('app.notification.keysAccess.protoRestFoot') }}</div>
      </el-col>

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

    <!-- MCP 使用明细（协议专属：TOP 工具 + 7 天趋势） -->
    <template v-if="mcpStats && (mcpStats.top_tools.length || trendRows.length)">
      <el-divider class="detail-divider" content-position="left">
        <span class="detail-title">{{ t('app.notification.keysUsage.title') }}</span>
      </el-divider>
      <el-row :gutter="24">
        <el-col v-if="mcpStats.top_tools.length" :xs="24" :md="12">
          <div class="usage-block-title">{{ t('app.notification.keysUsage.topToolsTitle') }}</div>
          <el-table :data="mcpStats.top_tools" size="small" class="top-tools-table" max-height="200">
            <el-table-column type="index" width="46" align="center" />
            <el-table-column prop="tool" :label="t('app.notification.keysUsage.colTool')" min-width="180" show-overflow-tooltip />
            <el-table-column prop="calls" :label="t('app.notification.keysUsage.colCalls')" width="90" align="right" />
          </el-table>
        </el-col>
        <el-col v-if="trendRows.length" :xs="24" :md="12">
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
        </el-col>
      </el-row>
    </template>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Connection, Key } from '@element-plus/icons-vue'
import type { McpStats } from '@/types/notifications.ts'

// API 侧三指标由 Keys.vue 从密钥列表现算（总数/启用数/近 7 天活跃）；
// MCP 侧为管理员统计端点数据（tiles + TOP 工具表 + 调用趋势）。
const props = defineProps<{
  apiKeyStats: { total: number; enabled: number; active7d: number }
  mcpStats: McpStats | null
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
/* 双协议列：左列右侧分隔线（md 及以上），xs 堆叠时退化为下边距 */
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
/* 指标块：两列统一规格 */
.stat-tile { background: var(--bg-secondary, #f9fafb); border-radius: 6px; padding: 12px 8px; text-align: center; }
.stat-value { font-size: 22px; font-weight: 700; line-height: 1.3; font-variant-numeric: tabular-nums; }
.stat-label { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
.detail-divider { margin: 16px 0 12px; }
.detail-title { font-weight: 600; font-size: 13px; }
.usage-block-title { font-weight: 600; margin: 0 0 8px; font-size: 13px; color: var(--text-secondary, #6b7280); }
.top-tools-table { margin-top: 0; }
.trend-list { display: flex; flex-direction: column; gap: 6px; }
.trend-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.trend-date { flex: none; width: 86px; color: var(--text-secondary, #6b7280); }
.trend-bar-track { flex: 1; background: var(--bg-secondary, #f3f4f6); border-radius: 2px; height: 12px; overflow: hidden; }
.trend-bar { display: block; height: 100%; background: var(--el-color-primary); border-radius: 2px; }
.trend-calls { flex: none; width: 56px; text-align: right; font-variant-numeric: tabular-nums; }
</style>
