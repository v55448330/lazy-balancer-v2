<template>
  <div class="code-editor" :style="{ height }">
    <pre ref="preRef" class="code-editor-highlight" :class="`language-${language}`" aria-hidden="true"><code v-html="highlighted"></code></pre>
    <textarea
      class="code-editor-input"
      :value="modelValue"
      :placeholder="placeholder"
      spellcheck="false"
      @input="onInput"
      @scroll="onScroll"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { highlightCode } from '@/utils/highlight'

const props = withDefaults(defineProps<{
  readonly modelValue: string
  readonly language: string
  readonly placeholder?: string
  readonly height?: string
}>(), { placeholder: '', height: '520px' })

const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const preRef = ref<HTMLElement | null>(null)

const highlighted = computed(() => {
  const html = highlightCode(props.modelValue, props.language)
  // Keep the highlight layer in sync height-wise when content ends with a newline.
  return props.modelValue.endsWith('\n') ? html + '<br>' : html
})

const onInput = (e: Event) => {
  emit('update:modelValue', (e.target as HTMLTextAreaElement).value)
}

const onScroll = (e: Event) => {
  const t = e.target as HTMLTextAreaElement
  if (preRef.value) {
    preRef.value.scrollTop = t.scrollTop
    preRef.value.scrollLeft = t.scrollLeft
  }
}
</script>

<style scoped>
.code-editor {
  position: relative;
  width: 100%;
  border-radius: 6px;
  background: #1e293b;
  overflow: hidden;
}
.code-editor-highlight,
.code-editor-input {
  margin: 0;
  padding: 16px;
  border: none;
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.6;
  letter-spacing: normal;
  tab-size: 4;
  white-space: pre;
  overflow: auto;
  width: 100%;
  height: 100%;
}
.code-editor-highlight {
  pointer-events: none;
  background: #1e293b;
}
.code-editor-input {
  position: absolute;
  inset: 0;
  resize: none;
  outline: none;
  background: transparent;
  color: transparent;
  caret-color: #e4e4e7;
}
.code-editor-input::placeholder {
  color: #64748b;
}
</style>
