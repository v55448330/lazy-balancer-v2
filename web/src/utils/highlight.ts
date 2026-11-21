import '@/utils/prism-manual'
import Prism from 'prismjs'
import 'prismjs/themes/prism-okaidia.css'
// 仅保留有消费方的语法：markup（拦截页 HTML/邮件模板）/css/apacheconf（CRS 规则预览）/
// json（Caddy 配置/拦截页 JSON/webhook 模板）/markdown（QQ 机器人模板）。
// clike/nginx/http/ini 全仓零消费（Prism 1.30.0 核实已注册语法互不依赖），删除以收敛包体。
import 'prismjs/components/prism-markup'
import 'prismjs/components/prism-css'
import 'prismjs/components/prism-apacheconf'
import 'prismjs/components/prism-json'
import 'prismjs/components/prism-markdown'
import { escapeHtml } from '@/utils/escape'
import { hasOwn } from '@/utils/hasOwn'

export const highlightCode = (content: string, language: string): string => {
  if (!content) return ''
  const lang = language || 'markup'
  // Prism.languages 是普通对象且 lang 来自文件扩展名/调用方：直接下标会把
  // 原型键（constructor/toString 等）当成 grammar 传入 → 高亮抛错并静默退化为
  // 纯转义。无自有 grammar 时回退 markup。
  const grammar = hasOwn(Prism.languages, lang) ? Prism.languages[lang] : Prism.languages.markup
  try {
    return Prism.highlight(content, grammar, lang)
  } catch {
    // 兜底转义收敛到 utils/escape 的 escapeHtml（含引号转义，与 ansi/
    // branding 版同口径），HTML 属性上下文复用该输出不再有引号注入面
    return escapeHtml(content)
  }
}
