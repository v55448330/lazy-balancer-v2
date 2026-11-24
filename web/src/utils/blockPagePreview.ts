// 拦截页预览的内容组装（纯函数，无 Vue/i18n 依赖；行为测试见
// tests/securityPagesRefsAndPreview.spec.ts）。列表行预览与编辑弹框内「预览」
// （未保存草稿）共用同一组装——预览看到的就是保存后客户端收到的内容。

import { escapeHtml } from './escape.ts'

/**
 * 预览「API · JSON」页签的内容：页面配置了 JSON 时原样展示；未配置时展示引擎
 * 将生成的最小 JSON——消息从页面 HTML 的 <title> 派生（与后端
 * defaultBlockPageJSONMessage 同一来源），无标题回落 "Request blocked"，且不含
 * code（状态码由 HTTP status 表达）。不解析入参：非法 JSON 原样返回（交给高亮
 * 层展示，由保存前校验拦截），不抛错。
 */
export const resolveBlockPageJson = (json: string, html: string): string => {
  const trimmed = (json || '').trim()
  if (trimmed) return trimmed
  const match = (html || '').match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  const title = (match?.[1] || '').replace(/<[^>]*>/g, '').trim()
  return JSON.stringify({ message: title || 'Request blocked' }, null, 2)
}

/**
 * 预览「浏览器 · HTML」页签的 srcdoc：HTML 类型原样渲染；非 HTML 类型（旧版单档
 * JSON/XML/纯文本）按源码展示——srcdoc 恒按 text/html 解析，直接塞入会被吞标签/
 * 压成无格式文本流，与真实响应不一致。空内容（含纯空白草稿）展示 emptyMessage
 * 占位。
 */
export const blockPagePreviewHtml = (content: string, contentType: string | undefined, emptyMessage: string): string => {
  const text = content || ''
  if (!text.trim()) {
    return `<p style="color: #999; padding: 20px; text-align: center">${escapeHtml(emptyMessage)}</p>`
  }
  const isHtml = !contentType || contentType.startsWith('text/html')
  return isHtml
    ? text
    : `<pre style="white-space: pre-wrap; word-break: break-all; margin: 0; padding: 12px; font: 13px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace">${escapeHtml(text)}</pre>`
}
