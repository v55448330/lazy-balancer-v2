<template>
  <div v-if="info" class="log-storage-bar">
    <el-tooltip :content="tooltipContent" placement="top">
      <div class="bar-body">
        <span class="name">{{ info.name }}</span>
        <span class="sizes">{{ sizeText }}</span>
        <el-progress
          v-if="info.limit_bytes"
          :percentage="percentage"
          :stroke-width="6"
          :show-text="false"
          :color="progressColor"
          class="bar"
        />
        <span class="note">{{ noteText }}</span>
      </div>
    </el-tooltip>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { request } from '@/utils/api'

interface LogStorageInfo {
  key: string
  name: string
  size_bytes: number
  rotated_bytes: number
  limit_bytes?: number | null
  keep_count: number
  rows?: number | null
  retention_note?: string
  config_source: string
}

const props = defineProps<{ logKey: string; caddyId?: string }>()

const info = ref<LogStorageInfo | null>(null)

const humanSize = (bytes: number): string => {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

const percentage = computed(() => {
  if (!info.value?.limit_bytes) return 0
  return Math.min(100, Math.round((info.value.size_bytes / info.value.limit_bytes) * 100))
})

const progressColor = computed(() => (percentage.value >= 90 ? '#f56c6c' : percentage.value >= 70 ? '#e6a23c' : '#409eff'))

const sizeText = computed(() => {
  const i = info.value
  if (!i) return ''
  if (i.limit_bytes) return `${humanSize(i.size_bytes)} / ${humanSize(i.limit_bytes)}`
  if (i.rows !== null && i.rows !== undefined) return `${i.rows.toLocaleString()} 条 · ${humanSize(i.size_bytes)}`
  return humanSize(i.size_bytes)
})

const noteText = computed(() => {
  const i = info.value
  if (!i) return ''
  if (i.limit_bytes) return `满 ${humanSize(i.limit_bytes)} 轮转，保留 ${i.keep_count} 份${i.rotated_bytes > 0 ? `（副本 ${humanSize(i.rotated_bytes)}）` : ''}`
  return i.retention_note || ''
})

const tooltipContent = computed(() => `${info.value?.config_source || ''}${info.value?.retention_note ? ' · ' + info.value.retention_note : ''}`)

onMounted(async () => {
  try {
    const params = props.caddyId ? { caddy_id: props.caddyId } : {}
    const res = await request.get<{ data?: { logs?: LogStorageInfo[] } }>('/logs/stats', { params })
    info.value = res.data?.logs?.find((l) => l.key === props.logKey) || null
  } catch (e) {
    console.error('Failed to load log stats:', e)
  }
})
</script>

<style scoped>
.log-storage-bar { font-size: 12px; color: #6b7280; }
.bar-body { display: flex; align-items: center; gap: 8px; min-width: 0; }
.name { white-space: nowrap; }
.sizes { white-space: nowrap; color: #374151; }
.bar { width: 90px; flex-shrink: 0; }
.note { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
</style>
