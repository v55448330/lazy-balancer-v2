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
import { ref } from 'vue'
import { useDebouncedHighlight } from '@/composables/useDebouncedHighlight'

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
// 高亮再按防抖结果覆盖——否则字符要等到下一轮防抖（最长 500ms）才出现。
// 管线（转义首帧 + 160/500ms 防抖 + 尾换行补齐）与 SyntaxHighlight 同一单源；
// trailingBreak 让高亮层与相邻 textarea 逐行对齐。
const { highlighted, setSyncedRaw } = useDebouncedHighlight(() => props.modelValue, () => props.language, { trailingBreak: true })

const onInput = (e: Event) => {
  const value = (e.target as HTMLTextAreaElement).value
  // 同步纯文本兜底：防抖高亮尚未落地时，键入字符也必须立刻可见。
  setSyncedRaw(value)
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
/* 直角：由 main.css `#app :is(.code-editor)` 单源声明（DESIGN_SPEC §26-10），
   组件内不再重复圆角值。 */
.code-editor {
  position: relative;
  width: 100%;
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
  /* 全局 border-box 只覆盖 input/textarea（main.css），pre 默认 content-box：
     height:100%+padding 会让高亮层视口比 textarea 高 32px、最大 scrollTop 小
     32px——textarea 滚到底时 scrollTop 同步被钳位，高亮层少滚 32px，文字相对
     光标下移（只在滚动区间末端触发=「滚到底才错位」根因）。对齐 textarea 的
     border-box 盒模型，两侧滚动几何一致。 */
  box-sizing: border-box;
  /* 不自绘滚动条（overflow:hidden 仍可程序滚动）：杜绝 pre/textarea 滚动条
     宽度分叉；右侧/底部各加 16px 冗余，覆盖 textarea 经典滚动条（≤17px）
     占据的滚动范围，保证 pre 的最大 scrollTop/scrollLeft 恒 ≥ textarea，
     scrollTop 同步永不钳位。 */
  overflow: hidden;
  padding-right: 32px;
  padding-bottom: 32px;
}
/* prism-okaidia 主题对 code[class*=language-] 强设 font-family: Consolas 与
   line-height: 1.5（组件层是 SF Mono/Menlo 与 1.6）——高亮层与透明 textarea
   度量分叉，光标/选择/点击位置随行数纵向漂移。强制内层 code 全量继承编辑器
   度量（同源对齐的唯一保证）。 */
.code-editor-highlight :deep(code) {
  font-family: inherit;
  font-size: inherit;
  line-height: inherit;
  white-space: inherit;
  tab-size: inherit;
  /* prism-okaidia 的 text-shadow:0 1px 让高亮字形整体下移 1px——与透明
     textarea 的 caret/选择矩形恒差 1px（用户实测残余错位感的来源）。 */
  text-shadow: none;
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
