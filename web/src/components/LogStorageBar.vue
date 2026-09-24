<template>
  <div v-if="info" class="log-storage-bar">
    <el-tooltip :content="tooltipContent" placement="top">
      <div class="bar-body">
        <span class="name">{{ info.name }}</span>
        <span v-if="isEmpty" class="note">暂无日志</span>
        <template v-else>
          <span class="sizes">{{ sizeText }}</span>
          <el-progress
            v-if="info.limit_bytes || info.limit_rows"
            :percentage="percentage"
            :stroke-width="6"
            :show-text="false"
            :color="progressColor"
            class="bar"
          />
          <span class="note">{{ noteText }}</span>
        </template>
      </div>
    </el-tooltip>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { request, formatBytes } from '@/utils/api'

interface LogStorageInfo {
  key: string
  name: string
  size_bytes: number
  rotated_bytes: number
  limit_bytes?: number | null
  limit_rows?: number | null
  db_bytes?: number | null
  keep_count: number
  rows?: number | null
  retention_note: string
  config_source: string
}

const props = defineProps<{ logKey: string; caddyId?: string }>()

const info = ref<LogStorageInfo | null>(null)

// F49-P5-10：复用 api.ts 的 formatBytes（站内字节格式化单一事实源，原私有
// humanSize 与 Dashboard 精度不一致）
const humanSize = formatBytes

const isEmpty = computed(() => {
  const i = info.value
  if (!i) return false
  return !!i.limit_bytes && i.size_bytes === 0 && i.rotated_bytes === 0
})

const percentage = computed(() => {
  const i = info.value
  if (!i) return 0
  // 条数上限(安全事件:进度=条数/上限,2026-09-14 用户裁定)
  if (i.limit_rows && i.rows != null) return Math.min(100, Math.round((i.rows / i.limit_rows) * 100))
  if (i.limit_bytes) return Math.min(100, Math.round((i.size_bytes / i.limit_bytes) * 100))
  return 0
})

const progressColor = computed(() => (percentage.value >= 90 ? '#f56c6c' : percentage.value >= 70 ? '#e6a23c' : '#409eff'))

const sizeText = computed(() => {
  const i = info.value
  if (!i) return ''
  if (i.limit_rows && i.rows != null) {
    const base = `${i.rows.toLocaleString()} / ${i.limit_rows.toLocaleString()} 条`
    const parts = [base]
    if (i.size_bytes > 0) parts.push(`日志 ${humanSize(i.size_bytes)}`)
    if (i.db_bytes) parts.push(`库 ${humanSize(i.db_bytes)}`)
    return parts.join(' · ')
  }
  if (i.limit_bytes) return `${humanSize(i.size_bytes)} / ${humanSize(i.limit_bytes)}`
  if (i.rows !== null && i.rows !== undefined) return `${i.rows.toLocaleString()} 条 · ${humanSize(i.size_bytes)}`
  return humanSize(i.size_bytes)
})

const noteText = computed(() => {
  const i = info.value
  if (!i) return ''
  if (i.limit_bytes && i.keep_count > 0) return `满 ${humanSize(i.limit_bytes)} 轮转，保留 ${i.keep_count} 份${i.rotated_bytes > 0 ? `（副本 ${humanSize(i.rotated_bytes)}）` : ''}`
  if (i.limit_bytes) return `满 ${humanSize(i.limit_bytes)} 轮转${i.retention_note ? `，${i.retention_note}` : ''}${i.rotated_bytes > 0 ? `（副本 ${humanSize(i.rotated_bytes)}）` : ''}`
  // 上限数字已在 sizes（rows/limit_rows）中展示,行内不重复——精简文案
  if (i.limit_rows) return `满额自动裁最旧${i.retention_note ? '，' + i.retention_note : ''}`
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
/* min-width:0——作为 flex 项必须可缩到内容宽度以下,内层 .note 的
   省略号(text-overflow)才会生效;否则长保留文案把右侧分页/按钮挤出容器
   (第 37 轮用户实证:事件日志页点第 5 页后分页器溢出卡片右缘 ~30-195px)。
   全部五处父级(事件日志/操作日志/规则日志弹窗/规则集更新弹窗/证书任务弹窗)
   共用同一 flex+margin-right:auto 模式,组件级一处修复全覆盖。 */
.log-storage-bar { font-size: 12px; color: #6b7280; min-width: 0; }
.bar-body { display: flex; align-items: center; gap: 8px; min-width: 0; }
.name { white-space: nowrap; }
.sizes { white-space: nowrap; color: #374151; }
.bar { width: 90px; flex-shrink: 0; }
.note { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
</style>
