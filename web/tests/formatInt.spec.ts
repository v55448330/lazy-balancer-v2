// 整数千分位单源验收（formatInt）+ 裸 toLocaleString 清零守卫。
//
// 背景：面板 15 处统计数字此前各自裸调 toLocaleString()（默认 locale 随宿主
// LC_ALL/LANG 漂移：de → `1.234`、fr → `1 234`，同一份代码在不同开发机/CI
// 上给出不同文案，de/fr 用户还会把千分位读成小数点），与
// crsRuleCountLabel 的手工分组形成三套口径。收敛为单源 formatInt
// （手工分组、',' 分隔、locale 无关），crsRuleCountLabel 共用同一内核。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { formatInt } from '../src/utils/formatInt.ts'
import { crsRuleCountLabel } from '../src/utils/securityLibraries.ts'
import { code, webFiles } from './_helpers.ts'

test('formatInt：千分位逐级分组，负号不参与分组', () => {
  assert.equal(formatInt(0), '0')
  assert.equal(formatInt(7), '7')
  assert.equal(formatInt(832), '832')
  assert.equal(formatInt(999), '999')
  assert.equal(formatInt(1000), '1,000')
  assert.equal(formatInt(1234), '1,234')
  assert.equal(formatInt(1234567), '1,234,567')
  assert.equal(formatInt(123456789), '123,456,789')
  assert.equal(formatInt(-1234), '-1,234')
})

test('crsRuleCountLabel 与 formatInt 共用内核（分组正则不得第二份内联）', () => {
  assert.equal(crsRuleCountLabel(832), '832 条规则')
  assert.equal(crsRuleCountLabel(1234), '1,234 条规则')
  assert.equal(crsRuleCountLabel(1234567), '1,234,567 条规则')
  const lib = code('src/utils/securityLibraries.ts')
  assert.match(lib, /formatInt\(/, 'crsRuleCountLabel 必须消费 formatInt 内核')
  assert.doesNotMatch(lib, /\\B\(\?=\(\\d\{3\}\)/, '手工分组正则不得在 securityLibraries 第二份内联')
})

test('守卫：站内不再有裸 .toLocaleString( 调用（白名单：SecurityOverview 的 fmtStatNum）', () => {
  // 断言口径：`.toLocaleString(`（带点调用形态）。注释里不带点的
  // 「`toLocaleString()`」字样不误伤；显式 locale 的调用只剩
  // SecurityOverview.vue 的 fmtStatNum（'en-US' 实参，归并行代理维护，
  // 按任务书白名单豁免）。
  const whitelisted: Record<string, true> = { 'src/views/security/SecurityOverview.vue': true }
  // 剥注释视图（code）：守卫断言对象是真实调用，注释里的形态字样不误伤
  // （如 Rules.vue 头部「不再用浏览器本地时区的 toLocaleString」文档注释）。
  const offenders: string[] = []
  for (const file of webFiles('src', ['.ts', '.vue'])) {
    if (whitelisted[file]) continue
    const body = code(file)
    if (/\.toLocaleString\(/.test(body)) offenders.push(file)
  }
  assert.deepEqual(offenders, [], '统计数字千分位必须走单源 formatInt，不得再裸调 toLocaleString')
})
