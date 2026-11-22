// 模板预览 Markdown 渲染行为契约（2026-11-22 用户裁定方案 B：引入 marked +
// DOMPurify 三方渲染，替代手写子集渲染器）。钉住定稿模板/日报预置在 marked
// (GFM+breaks) 下的结构输出与 DOMPurify 消毒。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { JSDOM } from 'jsdom'

// DOMPurify 在 Node 下绑定 globalThis.window——渲染模块初始化即取 window，
// 静态导入会拿到 undefined，必须先立 jsdom 窗口再动态载入（顺序约束）。
const dom = new JSDOM('')
const domWindow = dom.window as unknown as Record<string, unknown>
for (const k of ['document', 'Node', 'Element', 'DOMParser', 'window'] as const) {
  if (!(k in globalThis)) Object.defineProperty(globalThis, k, { value: k === 'window' ? dom.window : domWindow[k], configurable: true })
}
const { mdToHtml } = await import('../src/utils/mdPreview.ts')

test('定稿事件模板：星号列表/加粗标签/分隔线/引用（marked GFM+breaks）', () => {
  const html = mdToHtml('## 🔔 证书续签失败\n---\n**证书 3 天后过期**\n---\n* **级别**： critical\n* **事件名称**：证书续签失败\n---\n> Lazy Balancer 通知中心')
  assert.match(html, /<h2[^>]*>🔔 证书续签失败<\/h2>/, '## 渲染为 h2')
  assert.equal((html.match(/<hr\s*\/?>/g) || []).length, 3, '三条分隔线')
  assert.match(html, /<li><strong>级别<\/strong>： critical<\/li>/, '星号列表+行内加粗')
  assert.match(html, /<blockquote>\s*<p>Lazy Balancer 通知中心<\/p>/, '引用块')
  assert.match(html, /<p><strong>证书 3 天后过期<\/strong><\/p>/, '正文行不得被 --- 提升为 setext 标题（QQ 按分隔线渲染）')
})

test('fenced code 内的 --- 不得被当作分隔线/setext 下划线（代码块原样保留）', () => {
  const html = mdToHtml('说明\n\n```text\nalpha\n---\nbeta\n```\n\n---\n结尾')
  assert.match(html, /<pre><code[^>]*>alpha\n---\nbeta/, '代码块内 --- 必须原样保留')
  assert.equal((html.match(/<hr\s*\/?>/g) || []).length, 1, '仅代码块外的 --- 渲染为分隔线')
  assert.ok(!/<h2[^>]*>alpha/.test(html), '代码块内不得触发 setext 标题')
  // 围栏字符/长度不匹配的行不得误闭合代码块（``` 内出现 ~~~ 仍是代码正文）
  const mixed = mdToHtml('```\nalpha\n~~~\n---\nbeta\n```\n\n---\n结尾')
  assert.match(mixed, /<pre><code[^>]*>alpha\n~~~\n---\nbeta/, '``` 内 ~~~ 不闭合围栏')
  assert.equal((mixed.match(/<hr\s*\/?>/g) || []).length, 1, '仅围栏外的 --- 为分隔线')
})

test('日报预置：GFM 表格（表头/数据行）', () => {
  const html = mdToHtml('| 指标 | 数值 |\n| :--- | ---: |\n| 集群状态 | 3/3 |\n| 运行时长 | 32 天 |')
  assert.match(html, /<table>/, '表格元素')
  assert.match(html, /<th[^>]*>指标<\/th>/, '表头单元格')
  assert.match(html, /<td[^>]*>集群状态<\/td>/, '数据单元格')
})

test('breaks：单换行保留为行结构（模板按行排版不并段）', () => {
  const html = mdToHtml('**各节点摘要**\nslave-a：请求 22014 · 拦截 156')
  assert.match(html, /<br\s*\/?>/, '单换行转 <br>')
})

test('XSS 面：事件属性与危险协议被 DOMPurify 消毒', () => {
  const html = mdToHtml('* <img src=x onerror=alert(1)>\n\n[link](javascript:alert(1))')
  assert.ok(!/onerror/.test(html), '事件属性必须被剥离')
  assert.ok(!/javascript:/.test(html), 'javascript: 协议必须被剥离')
})

test('消毒收紧：style 属性与 img 标签被剥离（UI 欺骗/追踪面）', () => {
  const styled = mdToHtml('<div style="color:red;font-weight:700">伪造成功</div>')
  assert.ok(!/style=/i.test(styled), '内联 style 必须剥离（可伪造状态配色）')
  assert.ok(styled.includes('伪造成功'), '文本内容保留')
  const img = mdToHtml('<img src="https://track.example/pixel.png" alt="x">\n\n![t](https://track.example/2.png)')
  assert.ok(!/<img/i.test(img), 'img 标签必须剥离（远程图片=追踪面）')
})

test('回归：标题层级与代码 span', () => {
  const html = mdToHtml('# 一级\n## 二级\n### 三级\n\n行内 `code` 标记')
  assert.match(html, /<h1[^>]*>一级<\/h1>/)
  assert.match(html, /<h2[^>]*>二级<\/h2>/)
  assert.match(html, /<h3[^>]*>三级<\/h3>/)
  assert.match(html, /<code>code<\/code>/)
})

test('日报多值变量表格化（与后端 mdMultiValueTable 同口径）', async () => {
  const { dailyMultiValueMd } = await import('../src/utils/mdPreview.ts')
  const ips = dailyMultiValueMd('top_ips', '45.33.32.9 ×321\n1.2.3.4 ×120')
  assert.match(ips ?? '', /\| 攻击源 IP \| 次数 \|\n\| --- \| ---: \|\n\| 45\.33\.32\.9 \| 321 \|/)
  const certs = dailyMultiValueMd('cert_expiring', 'a.com · 2026-11-25')
  assert.match(certs ?? '', /\| 域名 \| 到期日 \|\n\| --- \| ---: \|\n\| a\.com \| 2026-11-25 \|/)
  const nodes = dailyMultiValueMd('nodes_summary', 'slave-a：请求 22014 · 拦截 156 · 独立IP 402\nslave-b：请求 9821 · 拦截 12 · 独立IP 210 · TOP 规则 SQLi')
  assert.match(nodes ?? '', /\| 节点 \| 请求 \| 拦截 \| 独立IP \| 备注 \|/)
  assert.match(nodes ?? '', /\| slave-b \| 9821 \| 12 \| 210 \| TOP 规则 SQLi \|/)
  assert.match(nodes ?? '', /\| slave-a \| 22014 \| 156 \| 402 \| — \|/)
  // 样例空格形态（× 前带空格）同样解析；坏行返回 null（预览回退原值）
  assert.match(dailyMultiValueMd('top_ips', '45.33.32.9 × 321') ?? '', /\| 45\.33\.32\.9 \| 321 \|/)
  // 备注列同样转义管道符（不转义会把该行拆成错位单元格/破表）
  const piped = dailyMultiValueMd('nodes_summary', 'slave-c：请求 10 · 拦截 1 · 独立IP 5 · 规则 a|b')
  assert.match(piped ?? '', /\| 规则 a｜b \|/, '备注列管道符必须转义为全角')
  assert.equal(dailyMultiValueMd('nodes_summary', 'bad：数据损坏'), null)
  assert.equal(dailyMultiValueMd('requests', '1200'), null)
})

test('多值表格块空行分隔（粘连会把下一表表头吞成数据行）', async () => {
  const { dailyMultiValueMd } = await import('../src/utils/mdPreview.ts')
  const block = (label: string, md: string): string => `**${label}**\n\n${md}\n`
  const ips = dailyMultiValueMd('top_ips', '45.33.32.9 ×321\n1.2.3.4 ×120') ?? ''
  const paths = dailyMultiValueMd('top_paths', '/login ×200\n/api ×150') ?? ''
  const spaced = block('TOP 攻击源 IP', ips) + '\n' + block('TOP 攻击路径', paths)
  const html = mdToHtml(spaced)
  assert.equal((html.match(/<table>/g) || []).length, 2, '两表各自成表')
  assert.ok(!/<td[^>]*>-{3,}<\/td>/.test(html), '分隔行不得被吞成数据行')
  // 粘连形态的反例钉测（生成端禁止产出）
  const glued = `**A**\n${ips}\n**B**\n${paths}`
  const gluedHtml = mdToHtml(glued)
  assert.ok(/<td[^>]*>-{3,}<\/td>/.test(gluedHtml) || (gluedHtml.match(/<table>/g) || []).length < 2, '粘连形态必然破表（生成端必须空行分隔）')
})

// 跨栈共享夹具（web/tests/fixtures/daily-multivalue-md.json，同一文件被
// internal/notify 的 Go 用例读取）：两侧各写一份 regex 断言曾让备注列转义、
// 空格形态、坏行回退的判定分叉而双绿。夹具要求**逐字相等**（含全角转义与
// 「—」缺省），单侧改格式立即红。
test('多值表格跨栈等价：共享夹具逐字一致', async () => {
  const { dailyMultiValueMd } = await import('../src/utils/mdPreview.ts')
  const fixture = JSON.parse(
    readFileSync(new URL('./fixtures/daily-multivalue-md.json', import.meta.url), 'utf8'),
  ) as Array<{ key: string; value: string; expected: string | null }>
  assert.ok(fixture.length >= 8, `夹具规模异常（${fixture.length}）`)
  for (const [index, tc] of fixture.entries()) {
    assert.equal(
      dailyMultiValueMd(tc.key, tc.value),
      tc.expected,
      `夹具第 ${index + 1} 行（${tc.key} ${JSON.stringify(tc.value)}）与后端 mdMultiValueTable 口径不一致`,
    )
  }
})
