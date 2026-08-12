<template>
  <pre class="prism-code" :class="`language-${language}`" :style="height ? { height, maxHeight: 'none' } : undefined" v-html="highlighted"></pre>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { highlightCode } from '@/utils/highlight'

const props = defineProps<{
  readonly content: string
  readonly language: string
  readonly height?: string
}>()

const highlighted = computed(() => highlightCode(props.content, props.language))
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
