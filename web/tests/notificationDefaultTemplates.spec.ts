// 事件缺省模板跨栈等价钉：本次修复前前后端各持一份字符串，微信预置实际已与
// 后端投递形态分叉（多一行事件/节点、缺「通知中心」后缀、标题行多带级别），
// 而两侧测试都不覆盖该字符串——用户点「恢复默认」得到的模板与真正投递的
// 默认形态不一致且无人发现。
//
// 判据：
//   1. zh 模板与共享夹具逐字相等（夹具同时被 internal/notify 的 Go 用例读取，
//      后端 defaultEventTemplate 亦对同一夹具断言）；
//   2. en 模板与 zh 行数/占位符序列一致（本地化只换标签词与冒号，不改结构）；
//   3. 无缺省模板通道返回空串。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { defaultEventTpl } from '../src/utils/eventDefaultTemplates.ts'

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/event-default-templates.json', import.meta.url), 'utf8'),
) as Record<string, string>

const placeholders = (text: string): string[] => text.match(/\{\{[a-z_]+\}\}/g) ?? []

test('zh 事件缺省模板与后端共享夹具逐字等价', () => {
  assert.ok(Object.keys(fixture).length >= 2, '跨栈夹具规模异常')
  for (const [typ, want] of Object.entries(fixture)) {
    assert.equal(defaultEventTpl(typ, 'zh'), want, `${typ} zh 缺省模板必须与后端投递形态逐字一致`)
  }
})

test('en 模板结构等价：行数与占位符序列一致（仅标签词/冒号本地化）', () => {
  for (const typ of Object.keys(fixture)) {
    const zh = defaultEventTpl(typ, 'zh').split('\n')
    const en = defaultEventTpl(typ, 'en').split('\n')
    assert.equal(en.length, zh.length, `${typ} en 行数与 zh 必须一致`)
    assert.deepEqual(placeholders(en.join('\n')), placeholders(zh.join('\n')), `${typ} en 占位符序列必须与 zh 一致`)
  }
  // 标签确实本地化（不是照抄中文）
  assert.doesNotMatch(defaultEventTpl('qq', 'en'), /级别|事件名称|所属节点|发生时间/, 'en 模板不得残留中文标签')
  assert.doesNotMatch(defaultEventTpl('wx_clawbot', 'en'), /级别|事件名称|所属节点|发生时间/, 'en 模板不得残留中文标签')
})

test('无缺省模板通道返回空串', () => {
  for (const typ of ['webhook', 'email', 'unknown']) {
    assert.equal(defaultEventTpl(typ, 'zh'), '', `${typ} 无事件缺省模板（各自版式承载）`)
  }
})
