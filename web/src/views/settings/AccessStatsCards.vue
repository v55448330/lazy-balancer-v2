<template>
  <el-row :gutter="16">
    <!-- API 密钥统计：数据全部来自 /users/me/api-keys 现成字段（总数/启用数/
         近 7 天活跃），不虚报调用计数——与 MCP 统计卡同形态并列 -->
    <el-col :xs="24" :lg="12" class="stats-col">
      <el-card shadow="never" class="stats-card">
        <template #header>
          <span>{{ t('app.notification.keysAccess.apiStatsTitle') }}</span>
        </template>
        <el-row :gutter="12">
          <el-col :span="8">
            <div class="stat-card">
              <div class="stat-value">{{ apiKeyStats.total }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statTotal') }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="stat-card">
              <div class="stat-value">{{ apiKeyStats.enabled }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statEnabled') }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="stat-card">
              <div class="stat-value">{{ apiKeyStats.active7d }}</div>
              <div class="stat-label">{{ t('app.notification.keysAccess.statActive7d') }}</div>
            </div>
          </el-col>
        </el-row>
      </el-card>
    </el-col>

    <!-- MCP 统计：/notification/mcp/stats（管理员；无数据空态） -->
    <el-col :xs="24" :lg="12" class="stats-col">
      <el-card shadow="never" class="stats-card">
        <template #header>
          <span>{{ t('app.notification.keysUsage.title') }}</span>
        </template>
        <template v-if="mcpStats">
          <el-row :gutter="12">
            <el-col :span="8">
              <div class="stat-card">
                <div class="stat-value">{{ mcpStats.today_calls }}</div>
                <div class="stat-label">{{ t('app.notification.keysUsage.statTodayCalls') }}</div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-card">
                <div class="stat-value">{{ mcpStats.active_sessions }}</div>
                <div class="stat-label">{{ t('app.notification.keysUsage.statActiveSessions') }}</div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-card">
                <div class="stat-value">{{ formatErrorRate(mcpStats.error_rate) }}</div>
                <div class="stat-label">{{ t('app.notification.keysUsage.statErrorRate') }}</div>
              </div>
            </el-col>
          </el-row>
          <el-table v-if="mcpStats.top_tools.length" :data="mcpStats.top_tools" size="small" class="top-tools-table" max-height="200">
            <el-table-column type="index" width="46" align="center" />
            <el-table-column prop="tool" :label="t('app.notification.keysUsage.colTool')" min-width="180" show-overflow-tooltip />
            <el-table-column prop="calls" :label="t('app.notification.keysUsage.colCalls')" width="90" align="right" />
          </el-table>
          <template v-if="trendRows.length">
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
        </template>
        <el-empty v-else :description="t('app.notification.keysUsage.emptyText')" :image-size="60" />
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
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
.stats-col { margin-bottom: 16px; }
.stats-card { height: 100%; }
.stat-card { background: var(--bg-secondary, #f9fafb); border-radius: 4px; padding: 12px 16px; text-align: center; }
.stat-value { font-size: 22px; font-weight: 700; line-height: 1.3; }
.stat-label { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
.top-tools-table { margin-top: 12px; }
.usage-block-title { font-weight: 600; margin: 12px 0 8px; font-size: 13px; color: var(--text-secondary, #6b7280); }
.trend-list { display: flex; flex-direction: column; gap: 6px; }
.trend-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.trend-date { flex: none; width: 86px; color: var(--text-secondary, #6b7280); }
.trend-bar-track { flex: 1; background: var(--bg-secondary, #f3f4f6); border-radius: 2px; height: 12px; overflow: hidden; }
.trend-bar { display: block; height: 100%; background: var(--el-color-primary); border-radius: 2px; }
.trend-calls { flex: none; width: 56px; text-align: right; }
</style>
