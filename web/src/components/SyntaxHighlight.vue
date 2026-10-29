<template>
  <pre class="prism-code" :class="`language-${language}`" :style="height ? { height, maxHeight: 'none' } : undefined" v-html="highlighted"></pre>
</template>

<script setup lang="ts">
import { useDebouncedHighlight } from '@/composables/useDebouncedHighlight'

const props = defineProps<{
  readonly content: string
  readonly language: string
  readonly height?: string
}>()

// 首帧只渲染「转义后的纯文本」，Prism 全文高亮推迟到停顿后补水：被消费于整份
// Caddy 配置 JSON 与整份 CRS 规则文件（百 KB 级），同步 computed 会在弹框打开
// 瞬间阻塞主线程数十~百毫秒（页面卡白）。与 CodeEditor 同一条管线
// （composables/useDebouncedHighlight：转义首帧 + 160ms 防抖 / 500ms 最大等待），
// 首帧/尾换行口径不再由两个组件各自解释。
const { highlighted } = useDebouncedHighlight(() => props.content, () => props.language)
</script>

<style scoped>
.prism-code {
  margin: 0;
  padding: 16px;
  border-radius: 6px;
  background: #1e293b;
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.6;
  overflow: auto;
  max-height: 70vh;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
