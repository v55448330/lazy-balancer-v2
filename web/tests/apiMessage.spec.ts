// 响应消息按键渲染的边界（web/DESIGN_SPEC.md §25-8）。
//
// 渲染必须逐字复现后端 apimsg.Tf 的输出：切换文案来源时用户看到的文字不变。
// 两侧对等靠一份共享夹具（tests/fixtures/apiMessage_format.json）：后端侧由
// internal/apimsg/envelope_test.go 的 renderSlots 镜像求值，这里由 formatApiMessage
// 求值；同一模板 + 参数必须得出同一结果。
//
// apiMessageText 是响应拦截器两条失败路径取「要显示的文字」的唯一入口：有键、
// 词条里有、参数齐 → 按当前语言渲染；其余一律返回 null，由调用方回落后端 message。
// 回落路径是安全网——拿不准的输入必须放弃，而不是拼出一句错话。
//
// 用例取后端目录里的真实词条：词条形态一变（新的占位符、新的参数个数），测试随之
// 变化，不会与现实脱节。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { loadBackendCatalog, loadFrontendEnglish } from '../scripts/gen-api-messages.ts'
import { apiMessageText, formatApiMessage, templateVerbs } from '../src/utils/apiMessage.ts'

// 中文母本来自后端目录（只有键 + 中文）；英文来自唯一维护源
// src/locales/apiMessages.en.json（2026-11-25 收尾：后端不再有英文译文）。
const english = loadFrontendEnglish()
const entries = loadBackendCatalog().map((entry) => ({ ...entry, en: english[entry.key] ?? '' }))
const zhOf = (key: string): string => entries.find((entry) => entry.key === key)?.zh ?? ''
const enOf = (key: string): string => entries.find((entry) => entry.key === key)?.en ?? ''
const noArg = entries.find((entry) => templateVerbs(entry.zh).length === 0)
const oneArg = entries.find((entry) => templateVerbs(entry.zh).join() === 's')
const twoArgs = entries.find((entry) => templateVerbs(entry.zh).join() === 's,d')

test('与后端共享夹具逐字相同：同一模板 + 参数两侧渲染一致', () => {
  const cases = JSON.parse(readFileSync(new URL('./fixtures/apiMessage_format.json', import.meta.url), 'utf8')) as Array<{
    template: string
    params: string[]
    expected: string
  }>
  assert.ok(cases.length >= 10, `夹具只有 ${cases.length} 条——对等守卫会空过`)
  for (const item of cases) {
    assert.equal(formatApiMessage(item.template, item.params), item.expected, item.template)
  }
})

test('有键、词条里有、无参数 → 按当前语言渲染', () => {
  assert.ok(noArg, '后端目录里必须有不含占位符的词条（否则本用例空转）')
  assert.equal(apiMessageText({ message: '后端原文', message_key: noArg.key }, 'zh-CN'), zhOf(noArg.key))
  assert.equal(apiMessageText({ message: '后端原文', message_key: noArg.key }, 'en'), enOf(noArg.key))
})

test('有键、参数齐 → 参数按槽回填，与后端 message 逐字相同', () => {
  assert.ok(oneArg, '后端目录里必须有 %s 词条（否则本用例空转）')
  assert.equal(
    apiMessageText({ message_key: oneArg.key, message_params: ['no_such_item'] }, 'zh-CN'),
    zhOf(oneArg.key).replace('%s', 'no_such_item'),
  )
  if (twoArgs) {
    const params = ['a', 'b']
    assert.equal(apiMessageText({ message_key: twoArgs.key, message_params: params }, 'zh-CN'), formatApiMessage(zhOf(twoArgs.key), params))
  }
})

test('回落：拿不准的输入返回 null，交由调用方回落后端原文', () => {
  const key = oneArg?.key ?? 'x.y'
  const cases: ReadonlyArray<readonly [string, unknown]> = [
    ['信封不是对象', 'x'],
    ['信封为空', null],
    ['没有键', { message: '后端原文' }],
    ['键不是字符串', { message_key: 42 }],
    ['键为空串', { message_key: '' }],
    ['词条里没有这个键', { message_key: 'no.suchKey' }],
    ['键是对象原型上的属性名', { message_key: 'constructor' }],
    ['带占位符却没有参数', { message_key: key }],
    ['参数不是数组', { message_key: key, message_params: { 0: 'a' } }],
    ['参数为 null', { message_key: key, message_params: null }],
    ['参数里混入非字符串', { message_key: key, message_params: [1] }],
  ]
  for (const [name, envelope] of cases) {
    assert.equal(apiMessageText(envelope, 'zh-CN'), null, name)
  }
})

test('渲染规则与后端同口径：参数多少与槽数不一致、槽外写法都照 Tf 的行为', () => {
  // 参数用完：占位符原样留下；参数多出：多余的忽略。
  assert.equal(formatApiMessage('%s 条', []), '%s 条')
  assert.equal(formatApiMessage('%s 条', ['a', 'b']), 'a 条')
  // 槽以外的写法原样保留、不消费参数。
  assert.equal(formatApiMessage('%f %s', ['x']), '%f x')
  assert.equal(formatApiMessage('%5d', []), '%5d')
  assert.equal(formatApiMessage('尾部 %', []), '尾部 %')
  // %% 是字面百分号，不占参数。
  assert.equal(formatApiMessage('100%% %s', ['完成']), '100% 完成')
  assert.deepEqual(templateVerbs('100%% %s 完成 %d 条'), ['s', 'd'])
})

test('语言：en 用英文译文，其余取中文母本', () => {
  assert.ok(noArg)
  assert.equal(apiMessageText({ message_key: noArg.key }, 'en'), enOf(noArg.key))
  assert.equal(apiMessageText({ message_key: noArg.key }, 'zh-CN'), zhOf(noArg.key))
  assert.equal(apiMessageText({ message_key: noArg.key }, 'fr' as 'zh-CN'), zhOf(noArg.key))
})

test('覆盖面：后端目录里的每一条词条，中英文都能用匹配的参数渲染出来', () => {
  // 渲染器只实现 %s/%d/%v/%q；目录里一旦出现别的动词，这条就红——那时要么实现它，
  // 要么确认该词条可以永远回落原文，并在这里登记例外。
  const unrenderable: string[] = []
  for (const entry of entries) {
    for (const [lang, template] of [['zh', entry.zh], ['en', entry.en]] as const) {
      const params = templateVerbs(template).map(() => 'x')
      const rendered = formatApiMessage(template, params)
      if (/%[sdvq]/.test(rendered)) unrenderable.push(`${entry.key} (${lang}): ${template}`)
    }
  }
  assert.deepEqual(unrenderable, [])
})
