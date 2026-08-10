<template>
  <pre class="prism-code" :class="`language-${language}`" v-html="highlighted"></pre>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import Prism from 'prismjs'
import 'prismjs/themes/prism-okaidia.css'
import 'prismjs/components/prism-markup'
import 'prismjs/components/prism-css'
import 'prismjs/components/prism-clike'
import 'prismjs/components/prism-apacheconf'
import 'prismjs/components/prism-nginx'
import 'prismjs/components/prism-http'
import 'prismjs/components/prism-ini'

const props = defineProps<{
  readonly content: string
  readonly language: string
}>()

const highlighted = computed(() => {
  if (!props.content) return ''
  const lang = props.language || 'markup'
  const grammar = Prism.languages[lang] || Prism.languages.markup
  try {
    return Prism.highlight(props.content, grammar, lang)
  } catch {
    return props.content
  }
})
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
