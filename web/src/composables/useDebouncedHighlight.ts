// 代码高亮渲染管线单源：CodeEditor（拦截页编辑器）与 SyntaxHighlight（配置预览/
// CRS 源码折叠/规则内容预览）原各写一份「转义首帧 + 160/500ms 防抖全文高亮」，
// 首帧口径已分叉（编辑器补尾换行 `<br>`，代码块不补，两处各自解释）。本 composable
// 统一：
//   - 首帧只输出**转义纯文本**（v-html 注入面：原文直出即注入）
//   - Prism 全文高亮推迟到键入/切换停顿后（debounce 160ms / maxWait 500ms）：
//     被消费于百 KB 级整份配置与 CRS 规则文件，同步 computed 会在弹框打开瞬间
//     阻塞主线程数十~百毫秒
//   - 尾换行补 `<br>` 作为**选项**（编辑器与相邻 textarea 需逐行对齐；纯代码块
//     不需要），不再由两个组件各自决定
//   - setSyncedRaw：键入/父级更新时同步回显转义纯文本（高亮层是屏幕上唯一的
//     可见文本，等防抖落地会出现最长 500ms 的字符缺失）
// 转义与尾换行复用 utils/escape 单源；不注册 onUnmounted——watchDebounced 随
// 组件作用域自动清理。
import { shallowRef, type ShallowRef } from 'vue'
import { watchDebounced } from '@vueuse/core'
import { highlightCode } from '@/utils/highlight'
import { escapeHtml, withCodeTrailingBreak } from '@/utils/escape'

interface DebouncedHighlightOptions {
  /** 源码以换行结尾时补 `<br>`（与相邻 textarea 逐行对齐用；纯代码块不需要）。 */
  readonly trailingBreak?: boolean
  /** 停顿多久后做全文高亮（毫秒）。 */
  readonly debounce?: number
  /** 连续输入时最长多久补一次高亮（毫秒）。 */
  readonly maxWait?: number
}

interface DebouncedHighlight {
  /** v-html 渲染源：首帧/键入回显为转义纯文本，停顿后为 Prism 高亮 HTML。 */
  readonly highlighted: ShallowRef<string>
  /** 同步回显：把原文字符串按转义口径立即写入（防抖结果随后覆盖）。 */
  readonly setSyncedRaw: (raw: string) => void
}

export function useDebouncedHighlight(
  source: () => string,
  language: () => string,
  options: DebouncedHighlightOptions = {},
): DebouncedHighlight {
  const trailingBreak = options.trailingBreak ?? false
  // 高亮层 HTML 的收尾口径：转义首帧/键入回显/Prism 产出三处共用，尾换行按选项补齐
  const finish = (html: string, raw: string): string => (trailingBreak ? withCodeTrailingBreak(html, raw) : html)
  const highlighted = shallowRef(finish(escapeHtml(source()), source()))
  watchDebounced(
    () => [source(), language()] as const,
    ([raw, lang]) => {
      highlighted.value = finish(highlightCode(raw, lang), raw)
    },
    { debounce: options.debounce ?? 160, maxWait: options.maxWait ?? 500, immediate: true },
  )
  return {
    highlighted,
    setSyncedRaw: (raw: string): void => {
      highlighted.value = finish(escapeHtml(raw), raw)
    },
  }
}
