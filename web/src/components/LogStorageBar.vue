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
        <!-- 取数失败保留上一次统计（不整条消失），并显式标注数值可能陈旧 -->
        <span v-if="error" class="note note--error">统计暂不可用</span>
      </div>
    </el-tooltip>
  </div>
  <!-- 从未取到统计时不留空白：先说明取数失败，再说明「请求成功但该日志无统计」
       ——三者（有值/失败/无统计）都必须有可见归宿，否则整条统计会静默消失 -->
  <div v-else-if="error" class="form-tip-line">日志统计暂不可用</div>
  <div v-else-if="unavailable" class="form-tip-line">该日志暂无统计数据</div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { formatBytes } from '@/utils/formatBytes'
import { formatInt } from '@/utils/formatInt'
import { useLogStorageStats } from '@/composables/useLogStorageStats'

const props = defineProps<{ logKey: string; caddyId?: string; refreshKey?: number }>()

// 取数（含换行清空 / 换行重取 / 刷新号重取）在组合子内自洽：logKey 或 caddyId
// 变化即重新取数并先清空旧行，调用方不必再靠 :key 重挂组件。
const { info, error, unavailable } = useLogStorageStats({
  target: () => ({ logKey: props.logKey, caddyId: props.caddyId }),
  refreshKey: () => props.refreshKey,
})

// 复用 utils/formatBytes（站内字节格式化单一事实源，原私有 humanSize 与
// Dashboard 精度不一致；该模块零 UI 依赖，不得改回 api.ts 上的旧位置）
const humanSize = formatBytes

const isEmpty = computed(() => {
  const i = info.value
  if (!i) return false
  return !!i.limit_bytes && i.size_bytes === 0 && i.rotated_bytes === 0
})

// 条数口径形态（安全事件：进度=条数/上限，2026-09-14 用户裁定）——即使行数
// 读取失败也保持该形态（进度置 0 且文案标注不可用），不得滑到字节口径。
// rows_unavailable 是后端的显式披露（行数读取失败）：即使响应里仍带着上一次
// 的行数（后端改为「保留旧值 + flag」时），也必须按不可用呈现，不能把陈旧
// 计数当有效值展示。
const rowsMode = computed(() => !!info.value?.limit_rows)
const rowsUnavailable = computed(() => rowsMode.value && (info.value?.rows_unavailable === true || info.value?.rows == null))

// 待补采缓存（安全事件行）：IPC 主路径写入，失败才落 spool，正常应为 0。
// 三态必须分开——有计数（含 0）/ 计数失败（cache_unavailable）/ 字段缺席
// （旧后端或非安全事件行）。缺席时整段不渲染：把缺席渲染成「0 条」会把
// 「不知道」说成「一切正常」，是这个指标最危险的误读。
const cacheKnown = computed(() => {
  const i = info.value
  if (!i) return false
  return i.cache_entries != null || i.cache_unavailable === true
})
const cacheCountText = computed(() => {
  const i = info.value
  if (!i || !cacheKnown.value) return ''
  if (i.cache_unavailable === true || i.cache_entries == null) return '缓存计数暂不可用'
  // 0 条也要显示（正常态）；不设 >0 门槛，否则「0 条」与「没这项统计」无法区分。
  return `缓存 ${formatInt(i.cache_entries)} 条`
})

const percentage = computed(() => {
  const i = info.value
  if (!i) return 0
  // 条数上限(安全事件:进度=条数/上限,2026-09-14 用户裁定)
  if (i.limit_rows) {
    if (rowsUnavailable.value) return 0
    return Math.min(100, Math.round(((i.rows ?? 0) / i.limit_rows) * 100))
  }
  if (i.limit_bytes) return Math.min(100, Math.round((i.size_bytes / i.limit_bytes) * 100))
  return 0
})

const progressColor = computed(() => (percentage.value >= 90 ? '#f56c6c' : percentage.value >= 70 ? '#e6a23c' : '#409eff'))

const sizeText = computed(() => {
  const i = info.value
  if (!i) return ''
  if (i.limit_rows) {
    const base = rowsUnavailable.value
      ? `计数暂不可用 / ${formatInt(i.limit_rows)} 条`
      : `${formatInt(i.rows ?? 0)} / ${formatInt(i.limit_rows)} 条`
    // 安全事件主容量 = 事件行数/行帽：真实容量在库里，audit.log 的 size_bytes
    // 只是写入侧同文件的体量（随轮转/缓存补采漂移），不再当该行容量展示。
    const parts = [base]
    if (cacheCountText.value) parts.push(cacheCountText.value)
    if (i.db_bytes) parts.push(`库 ${humanSize(i.db_bytes)}`)
    return parts.join(' · ')
  }
  if (i.limit_bytes) return `${humanSize(i.size_bytes)} / ${humanSize(i.limit_bytes)}`
  if (i.rows !== null && i.rows !== undefined) return `${formatInt(i.rows)} 条 · ${humanSize(i.size_bytes)}`
  return humanSize(i.size_bytes)
})

const noteText = computed(() => {
  const i = info.value
  if (!i) return ''
  // 条数上限形态(安全事件)：行内只保留清理策略，保留期/行宽/理论体积等
  // 细节放在 hover tooltip（retention_note），避免长文案挤压分页。
  if (i.limit_rows) {
    return rowsUnavailable.value ? '行数暂不可用；超限按最旧优先清理' : '超限按最旧优先清理'
  }
  const parts: string[] = []
  if (i.limit_bytes) parts.push(`满 ${humanSize(i.limit_bytes)} 轮转`)
  if (i.db_backed) {
    // 纯库内行(操作日志=audit_log 表按保留期清理):没有轮转归档概念,
    // keep_count=0 渲染「暂无归档」会被读成归档失败——只披露清理口径。
    if (i.retention_note) parts.push(i.retention_note)
    return parts.join('，')
  }
  if (i.keep_count > 0) {
    // 固定份数上限(Caddy/certjob 等):已归档时 N/M,未归档时「暂无归档，保留 M 份」
    parts.push(i.rotated_count > 0 ? `已归档 ${i.rotated_count}/${i.keep_count} 份` : `暂无归档（满额保留 ${i.keep_count} 份）`)
  } else {
    // 时间戳轮转族(运行日志):无固定份数上限——归档数恒显示(含 0)
    parts.push(i.rotated_count > 0 ? `已归档 ${i.rotated_count} 份` : '暂无归档')
  }
  if (i.rotated_bytes > 0) parts.push(`副本 ${humanSize(i.rotated_bytes)}`)
  if (i.keep_count === 0 && i.retention_note) parts.push(i.retention_note)
  return parts.join('，')
})

// 缓存段的口径说明（hover 展开）：条目/字节/上限，以及它到底是什么——
// 「IPC 失败后的待补采条目，正常应为 0」。行内只放条数，解释留给 tooltip，
// 避免长文案把右侧分页挤出容器。
const cacheDetail = computed(() => {
  const i = info.value
  if (!i || !cacheKnown.value) return ''
  const parts: string[] = []
  if (i.cache_unavailable === true || i.cache_entries == null) {
    parts.push('缓存计数暂不可用（计数读取失败）')
  } else {
    let head = `缓存 ${formatInt(i.cache_entries)} 条`
    if (i.cache_bytes != null) head += ` · ${humanSize(i.cache_bytes)}`
    if (i.cache_limit_entries != null && i.cache_limit_entries > 0) head += ` / 上限 ${formatInt(i.cache_limit_entries)} 条`
    if (i.cache_limit_bytes != null && i.cache_limit_bytes > 0) head += `（${humanSize(i.cache_limit_bytes)}）`
    parts.push(head)
  }
  parts.push('缓存为 IPC 失败后的待补采条目，正常应为 0')
  return parts.join(' · ')
})

const tooltipContent = computed(() => {
  const i = info.value
  const parts: string[] = []
  if (i?.config_source) parts.push(i.config_source)
  if (i?.retention_note) parts.push(i.retention_note)
  if (i?.limit_rows) parts.push('超出上限时按最旧优先清理')
  if (cacheDetail.value) parts.push(cacheDetail.value)
  return parts.join(' · ')
})
</script>

<style scoped>
/* min-width:0——作为 flex 项必须可缩到内容宽度以下,内层 .note 的
   省略号(text-overflow)才会生效;否则长保留文案把右侧分页/按钮挤出容器
   (用户实证:事件日志页点第 5 页后分页器溢出卡片右缘 ~30-195px)。
   全部五处父级(事件日志/操作日志/规则日志弹窗/规则集更新弹窗/证书任务弹窗)
   共用同一 flex+margin-right:auto 模式,组件级一处修复全覆盖。 */
.log-storage-bar { font-size: 12px; color: #6b7280; min-width: 0; }
.bar-body { display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1 1 auto; }
.name { white-space: nowrap; }
.sizes { white-space: nowrap; color: #374151; }
.bar { width: 90px; flex-shrink: 0; }
.note { flex: 1 1 auto; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.note--error { flex: none; color: #e6a23c; }
</style>
