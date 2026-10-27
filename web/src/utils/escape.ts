// escapeHtml 共享实现——收敛原 ansi/branding/highlight 三份独立实现。
// HTML 属性上下文必须含引号转义(与原 ansi/branding 版一致;highlight 版在
// Prism 上下文无属性注入面,统一到含引号版无行为回归)。
// 查表为模块级常量——replace 回调每个匹配字符触发一次，逐字符构造字面量在
// 大日志（上限 256KB）渲染路径上是可消除的分配。
const escapeHtmlTable: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

export const escapeHtml = (raw: string): string =>
  raw.replace(/[&<>"']/g, (ch) => escapeHtmlTable[ch] ?? ch)

/**
 * 代码块 HTML 的尾部换行补齐：源码以换行结尾时补一个 `<br>`——`pre` 区域末尾的
 * 换行在部分浏览器下不占行高，高亮层与相邻 textarea 的最后一行会错位。
 * 高亮层（Prism 产出）与纯文本兜底（escapeHtml 产出）共用本函数。
 */
export const withCodeTrailingBreak = (html: string, source: string): string =>
  source.endsWith('\n') ? `${html}<br>` : html
