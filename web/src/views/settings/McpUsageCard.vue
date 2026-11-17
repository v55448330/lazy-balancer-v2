<template>
  <el-card shadow="never">
    <template #header>
      <span>{{ t('app.notification.keysUsage.title') }}</span>
    </template>

    <template v-if="stats">
      <div class="usage-grid">
        <div class="usage-block">
          <div class="usage-block-title">{{ t('app.notification.keysUsage.topToolsTitle') }}</div>
          <el-table :data="stats.top_tools" size="small" :empty-text="t('app.notification.keysUsage.emptyText')" max-height="260">
            <el-table-column type="index" width="50" align="center" />
            <el-table-column prop="tool" :label="t('app.notification.keysUsage.colTool')" min-width="200" show-overflow-tooltip />
            <el-table-column prop="calls" :label="t('app.notification.keysUsage.colCalls')" width="110" align="right" />
          </el-table>
        </div>
        <div class="usage-block">
          <div class="usage-block-title">{{ t('app.notification.keysUsage.trendTitle') }}</div>
          <div v-if="trendRows.length" class="trend-list">
            <div v-for="point in trendRows" :key="point.date" class="trend-row">
              <span class="trend-date">{{ point.date }}</span>
              <span class="trend-bar-track">
                <span class="trend-bar" :style="{ width: trendBarWidth(point.calls) }" />
              </span>
              <span class="trend-calls">{{ point.calls }}</span>
            </div>
          </div>
          <el-empty v-else :description="t('app.notification.keysUsage.emptyText')" :image-size="60" />
        </div>
      </div>
    </template>
    <el-empty v-else :description="t('app.notification.keysUsage.emptyText')" :image-size="60" />
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { McpStats } from '@/types/notifications.ts'

// 统计数据由 Keys.vue 单次拉取（管理员），本卡只做投影
const props = defineProps<{ stats: McpStats | null }>()

const { t } = useI18n()

const trendRows = computed(() => props.stats?.trend ?? [])

const trendMax = computed(() => Math.max(1, ...trendRows.value.map((p) => p.calls)))

const trendBarWidth = (calls: number): string => `${Math.max(2, Math.round((calls / trendMax.value) * 100))}%`
</script>

<style scoped>
.usage-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.usage-block-title { font-weight: 600; margin-bottom: 10px; font-size: 13px; color: var(--text-secondary, #6b7280); }
.trend-list { display: flex; flex-direction: column; gap: 6px; }
.trend-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.trend-date { flex: none; width: 86px; color: var(--text-secondary, #6b7280); }
.trend-bar-track { flex: 1; background: var(--bg-secondary, #f3f4f6); border-radius: 2px; height: 12px; overflow: hidden; }
.trend-bar { display: block; height: 100%; background: var(--el-color-primary); border-radius: 2px; }
.trend-calls { flex: none; width: 56px; text-align: right; }
@media (max-width: 900px) {
  .usage-grid { grid-template-columns: 1fr; }
}
</style>
