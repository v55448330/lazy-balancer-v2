<template>
  <div class="code-editor" :style="{ height }">
    <pre ref="preRef" class="code-editor-highlight" :class="`language-${language}`" aria-hidden="true"><code v-html="highlighted"></code></pre>
    <textarea
      class="code-editor-input"
      :value="modelValue"
      :placeholder="placeholder"
      :aria-label="ariaLabel || undefined"
      :readonly="readonly || undefined"
      spellcheck="false"
      @input="onInput"
      @scroll="onScroll"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, shallowRef } from 'vue'
import { watchDebounced } from '@vueuse/core'
import { highlightCode } from '@/utils/highlight'
import { escapeHtml, withCodeTrailingBreak } from '@/utils/escape'

const props = withDefaults(defineProps<{
  readonly modelValue: string
  readonly language: string
  readonly placeholder?: string
  readonly height?: string
  /** 可访问名：placeholder 不是合法替代（读屏不读占位符为名称），
   *  每个消费方必须提供业务语义名。 */
  readonly ariaLabel?: string
  /** 只读：请求在途等场景冻结内容编辑（textarea 只读，不再产生 update 事件）。 */
  readonly readonly?: boolean
}>(), { placeholder: '', height: '520px', ariaLabel: '', readonly: false })

const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const preRef = ref<HTMLElement | null>(null)

// textarea 的文字是透明的（color: transparent），屏幕上可见文本全部来自高亮层。
// 因此高亮层必须同时承担「即时回显」：键入/首帧先写入转义纯文本，Prism 全文
// 高亮再按防抖结果覆盖（与 SyntaxHighlight 首帧同形）——否则字符要等到
// 下一轮防抖（最长 500ms）才出现。
const highlighted = shallowRef(withCodeTrailingBreak(escapeHtml(props.modelValue), props.modelValue))
const updateHighlight = (): void => {
  highlighted.value = withCodeTrailingBreak(highlightCode(props.modelValue, props.language), props.modelValue)
}
// Prism 全文高亮在停顿后执行，连续输入最长每 500ms 补一次，避免每个键击都
// 阻塞主线程。组件卸载时 watchDebounced 自动清理定时器。
watchDebounced(
  () => [props.modelValue, props.language] as const,
  updateHighlight,
  { debounce: 160, maxWait: 500, immediate: true },
)

const onInput = (e: Event) => {
  const value = (e.target as HTMLTextAreaElement).value
  // 同步纯文本兜底：防抖高亮尚未落地时，键入字符也必须立刻可见。
  highlighted.value = withCodeTrailingBreak(escapeHtml(value), value)
  emit('update:modelValue', value)
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
