// 模板预览 Markdown 渲染（QQ 子集）行为契约。2026-11-22 用户实测预览区
// 未渲染定稿模板：`* ` 星号列表、`---` 分隔线按字面显示、{{event_title}}
// 样例值缺失——本文件钉住三者与既有子集（标题/加粗/`- ` 列表/引用/表格）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mdToHtml } from '../src/utils/mdPreview.ts'

test('星号列表渲染为 ul/li（与 QQ 客户端一致，定稿模板用 * 前缀）', () => {
  const html = mdToHtml('* **级别**： critical\n* **事件名称**：证书续签失败')
  assert.match(html, /<ul><li><strong>级别<\/strong>： critical<\/li>/)
  assert.match(html, /<li><strong>事件名称<\/strong>：证书续签失败<\/li><\/ul>/)
  assert.ok(!html.includes('* '), '列表标记不得按字面保留')
})

test('--- 分隔线渲染为 hr（定稿模板的分节形态）', () => {
  const html = mdToHtml('## 🔔 标题\n---\n**正文**\n---\n> 品牌通知中心')
  assert.equal((html.match(/<hr>/g) || []).length, 2)
  assert.match(html, /<h3>🔔 标题<\/h3>/)
  assert.ok(!html.includes('---'), '分隔线不得按字面保留')
})

test('回归：既有子集不变（标题/加粗/- 列表/引用/表格/代码span）', () => {
  const html = mdToHtml([
    '# 一级', '## 二级', '### 三级',
    '- 短横列表', '**加粗**与`code`',
    '> 引用行',
    '| 列A | 列B |', '| --- | --- |', '| 1 | 2 |',
  ].join('\n'))
  assert.match(html, /<h2>一级<\/h2>/)
  assert.match(html, /<h3>二级<\/h3>/)
  assert.match(html, /<h4>三级<\/h4>/)
  assert.match(html, /<li>短横列表<\/li>/)
  assert.match(html, /<strong>加粗<\/strong>/)
  assert.match(html, /<code>code<\/code>/)
  assert.match(html, /<blockquote>引用行<\/blockquote>/)
  assert.match(html, /<table><thead><tr><th>列A<\/th><th>列B<\/th><\/tr>/)
})

test('XSS 面：先转义再渲染（标签与属性注入按字面显示）', () => {
  const html = mdToHtml('* <img src=x onerror=alert(1)>\n---')
  assert.ok(!/<img/.test(html.replace(/&lt;img/, '')), '注入标签必须被转义')
  assert.match(html, /&lt;img src=x/)
})
