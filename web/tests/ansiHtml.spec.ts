// 任务日志 ANSI SGR → HTML 的行为测试：颜色/样式栈、256 色与真彩、边界码位、
// 转义与未闭合样式的收尾。CSV/log 输出直接进 v-html，转义缺失即注入面。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks, code, section, webFiles } from './_helpers.ts'

// ansi.ts 经 `@/utils/escape` 别名取共享转义实现，node 不认别名——先注册解析钩子。
// 静态 import 会先于钩子注册执行，故此处必须动态 import。
registerModuleHooks()
const { ansiToHtml } = await import('../src/utils/ansi.ts')

const ESC = '\u001b'
const color = (hex: string): string => `<span style="color:${hex}">`
const background = (hex: string): string => `<span style="background-color:${hex}">`

test('无转义序列原样返回，HTML 特殊字符全部转义', () => {
  assert.equal(ansiToHtml('hello'), 'hello')
  assert.equal(ansiToHtml('<b>&"x"\'</b>'), '&lt;b&gt;&amp;&quot;x&quot;&#39;&lt;/b&gt;')
})

test('基本前景色开合：着色段独立成 span，0 复位后不再包裹', () => {
  assert.equal(ansiToHtml(`${ESC}[31mred${ESC}[0m`), `${color('#ef4444')}red</span>`)
  assert.equal(ansiToHtml(`${ESC}[31ma${ESC}[0mb`), `${color('#ef4444')}a</span>b`)
})

test('组合码按顺序生效，样式串按 粗/斜/下划线/前景/背景 排列', () => {
  assert.equal(ansiToHtml(`${ESC}[1;31mx${ESC}[0m`), '<span style="font-weight:bold;color:#ef4444">x</span>')
  assert.equal(ansiToHtml(`${ESC}[3;4mx${ESC}[0m`), '<span style="font-style:italic;text-decoration:underline">x</span>')
  assert.equal(
    ansiToHtml(`${ESC}[31;41mx${ESC}[0m`),
    '<span style="color:#ef4444;background-color:#ef4444">x</span>',
  )
})

test('换色时先闭合上一段（不嵌套 span），未闭合样式在尾部自动收尾', () => {
  assert.equal(
    ansiToHtml(`${ESC}[31ma${ESC}[32mb${ESC}[0m`),
    `${color('#ef4444')}a</span>${color('#22c55e')}b</span>`,
  )
  assert.equal(ansiToHtml(`${ESC}[1mbold`), '<span style="font-weight:bold">bold</span>')
})

test('39/49 只清各自通道，另一通道保持', () => {
  assert.equal(ansiToHtml(`${ESC}[31ma${ESC}[39mb${ESC}[0m`), `${color('#ef4444')}a</span>b`)
  assert.equal(ansiToHtml(`${ESC}[41ma${ESC}[49mb${ESC}[0m`), `${background('#ef4444')}a</span>b`)
})

test('22/23/24 逐个关闭对应样式，其余样式保留', () => {
  assert.equal(
    ansiToHtml(`${ESC}[1;3mx${ESC}[22my${ESC}[0m`),
    '<span style="font-weight:bold;font-style:italic">x</span><span style="font-style:italic">y</span>',
  )
})

test('256 色：16-231 走 6×6×6 立方，232-255 走灰阶', () => {
  assert.equal(ansiToHtml(`${ESC}[38;5;196mx${ESC}[0m`), `${color('rgb(255,0,0)')}x</span>`)
  // 196 = 16 + 180 → r=levels[5]=255, g=levels[0]=0, b=levels[0]=0
  assert.equal(ansiToHtml(`${ESC}[48;5;232mx${ESC}[0m`), `${background('rgb(8,8,8)')}x</span>`)
  // 232 起灰阶：8 + (232-232)*10 = 8
  assert.equal(ansiToHtml(`${ESC}[38;5;300mx${ESC}[0m`), 'x', '越界索引不得产出颜色')
})

test('真彩 38;2 取值区间钳到 0-255', () => {
  assert.equal(ansiToHtml(`${ESC}[38;2;10;20;30mx${ESC}[0m`), `${color('rgb(10,20,30)')}x</span>`)
  assert.equal(ansiToHtml(`${ESC}[38;2;300;20;30mx${ESC}[0m`), `${color('rgb(255,20,30)')}x</span>`)
})

test('未知码位丢弃序列本身但不吞正文', () => {
  assert.equal(ansiToHtml(`${ESC}[99mx${ESC}[0m`), 'x')
  assert.equal(ansiToHtml(`before${ESC}[99mafter`), 'beforeafter')
})

test('空参数等价 0（复位）', () => {
  assert.equal(ansiToHtml(`${ESC}[31ma${ESC}[mb`), `${color('#ef4444')}a</span>b`)
})

// 转义即安全边界：日志内容含请求路径/UA 等外部输入，v-html 只能接「先转义原始
// 日志、后做着色」的产出；回退成原始日志直出会从「不着色」升级为注入面。
//
// 消费面按目录扫描枚举（`webFiles('src', ['.vue'])`），不再手写文件名清单：新增
// 日志视图、或改写既有管线（去掉转义 / 把转义挪到着色之后）都必须在这里变红。
// 非日志 v-html 面（SyntaxHighlight/CodeEditor 高亮层、品牌 footerHtml）不在
// 本条范围内，其首帧转义由 infraWiring 与 utilsSingleSource 承担。
test('日志消费面（目录扫描）：每个 v-html 日志面都必须先转义再着色', () => {
  const files = webFiles('src', ['.vue'])
  assert.ok(files.length >= 40, `扫描面过小（${files.length} 个 .vue）——目录枚举失效`)
  const faces: Array<{ file: string; name: string }> = []
  for (const file of files) {
    const text = code(file)
    // 任何 v-html 都不得直接接原始日志 ref（含 `.value` 的下标形态）
    assert.doesNotMatch(text, /v-html="[^"]*[Cc]ontent\.value[^"]*"/, `${file}：原始日志不得直出（转义缺失即注入面）`)
    for (const match of text.matchAll(/v-html="([^"]+)"/g)) {
      const expr = match[1]!.trim()
      if (!/log/i.test(expr)) continue
      // 内联表达式无法静态取源，按日志面处理并强制改走 computed
      assert.match(expr, /^[A-Za-z_$][\w$]*$/, `${file}：v-html 日志绑定必须是单个标识符（${expr}）`)
      faces.push({ file, name: expr })
    }
  }
  // 扫描面下限 + 正向名册：现有三个日志面（Caddy 全局日志 / 规则日志 / 证书任务
  // 日志）。少一个说明同一份管线被拆走而扫描没跟上；多一个必须同步登记。
  assert.ok(faces.length >= 3, `日志 v-html 面少于 3（${JSON.stringify(faces)}）——目录扫描失效`)
  assert.deepEqual(
    faces.map((face) => `${face.file}#${face.name}`).sort(),
    [
      'src/views/Rules.vue#ruleLogHtml',
      'src/views/settings/CaddyGlobalSettings.vue#logHtml',
      'src/views/settings/CertJobs.vue#logHtml',
    ],
  )
  for (const face of faces) {
    const text = code(face.file)
    // 定义体切到下一个顶层声明：转义必须包住原始日志 ref，且早于任何着色 replace
    const decl = section(text, `const ${face.name} = `, '\nconst ')
    assert.match(
      decl,
      /(?:ansiToHtml|escapeHtml)\(\s*\w*[Ll]og\w*\.value/,
      `${face.file}#${face.name}：必须先转义原始日志（escapeHtml/ansiToHtml 包住 log ref）`,
    )
    const escaped = decl.search(/(?:ansiToHtml|escapeHtml)\(/)
    const colored = decl.search(/\.replace\(/)
    if (colored >= 0) {
      assert.ok(escaped < colored, `${face.file}#${face.name}：着色不得早于转义（先拼 HTML 再转义=注入面）`)
    }
  }
})

test('真彩缺参形态：真彩段被忽略，剩余参数按普通 SGR 解释（正文不丢）', () => {
  // 现状语义（钉住，避免未来改动被当成回归或反之）：`38;2;<缺参>` 不构成真彩
  // 三元组，解析器跳过颜色部分，后续参数仍按独立 SGR 码处理（1=加粗）。
  assert.equal(ansiToHtml(`${ESC}[38;2;1;2mx${ESC}[0m`), '<span style="font-weight:bold">x</span>')
  assert.equal(ansiToHtml(`before${ESC}[38;2;1;2mafter`), 'before<span style="font-weight:bold">after</span>')
})
