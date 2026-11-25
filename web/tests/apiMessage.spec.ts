// 响应消息按键渲染的边界（web/DESIGN_SPEC.md §25-8）。
//
// apiMessageText 是响应拦截器两条失败路径取「要显示的文字」的唯一入口：有键、词条
// 里有、参数齐 → 按当前语言渲染；其余一律返回 null，由调用方回落后端 message。
// 回落路径是安全网——渲染器遇到任何没把握的输入都必须放弃，而不是拼出一句错话。
//
// 用例取后端目录里的真实词条：词条形态一变（出现新的占位符、新的参数个数），测试
// 随之变化，不会与现实脱节。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { loadBackendCatalog } from '../scripts/gen-api-messages.ts'
import { apiMessageText, formatApiMessage, templateVerbs } from '../src/utils/apiMessage.ts'

const entries = loadBackendCatalog()
const zhOf = (key: string): string => entries.find((entry) => entry.key === key)?.zh ?? ''
const enOf = (key: string): string => entries.find((entry) => entry.key === key)?.en ?? ''
const noArg = entries.find((entry) => templateVerbs(entry.zh).length === 0)
const oneArg = entries.find((entry) => templateVerbs(entry.zh).join() === 's')
const countArg = entries.find((entry) => templateVerbs(entry.zh).join() === 'd')

test('有键、词条里有、无参数 → 按当前语言渲染', () => {
  assert.ok(noArg, '后端目录里必须有不含占位符的词条（否则本用例空转）')
  assert.equal(apiMessageText({ message: '后端原文', message_key: noArg.key }, 'zh-CN'), zhOf(noArg.key))
  assert.equal(apiMessageText({ message: '后端原文', message_key: noArg.key }, 'en'), enOf(noArg.key))
})

test('有键、参数齐 → 占位符按顺序插值，与后端 fmt 的结果一致', () => {
  assert.ok(oneArg && countArg, '后端目录里必须有 %s 与 %d 词条（否则本用例空转）')
  assert.equal(
    apiMessageText({ message_key: oneArg.key, message_params: ['no_such_item'] }, 'zh-CN'),
    zhOf(oneArg.key).replace('%s', 'no_such_item'),
  )
  assert.equal(
    apiMessageText({ message_key: countArg.key, message_params: [3] }, 'en'),
    enOf(countArg.key).replace('%d', '3'),
  )
})

test('回落：拿不准的输入一律返回 null，交由调用方回落后端原文', () => {
  const key = oneArg?.key ?? 'x.y'
  // 目标：以下每种形态都渲染不出可靠结果。
  const cases: ReadonlyArray<readonly [string, unknown]> = [
    ['信封不是对象', 'x'],
    ['信封为空', null],
    ['没有键', { message: '后端原文' }],
    ['键不是字符串', { message_key: 42 }],
    ['键为空串', { message_key: '' }],
    ['词条里没有这个键', { message_key: 'no.suchKey' }],
    ['键是对象原型上的属性名', { message_key: 'constructor' }],
    ['带占位符却没有参数', { message_key: key }],
    ['参数个数不符', { message_key: key, message_params: ['a', 'b'] }],
    ['参数不是数组', { message_key: key, message_params: { 0: 'a' } }],
    ['参数为 null', { message_key: key, message_params: null }],
    ['无占位符的模板却带了参数', { message_key: noArg?.key ?? 'x.y', message_params: ['多余'] }],
  ]
  for (const [name, envelope] of cases) {
    assert.equal(apiMessageText(envelope as Record<string, unknown>, 'zh-CN'), null, name)
  }
})

test('畸形模板与参数：渲染器放弃而不是拼出错话', () => {
  // 占位符集之外的动词、孤立百分号——后端 fmt 的动词远不止这四种，没实现的必须回落。
  // 零参数与一个参数都要试：只试一个参数的话，「参数个数不符」这道防线会掩盖住
  // 「没实现的动词」这道防线（变异验证实录）。
  for (const template of ['%f', '%.2f', '%5d', '%x', '进度 50%', '%']) {
    assert.equal(formatApiMessage(template, []), null, `${template}，零参数`)
    assert.equal(formatApiMessage(template, [1]), null, `${template}，一个参数`)
  }
  // %d 只接受整数；%s 接受任意值。
  assert.equal(formatApiMessage('%d 条', [1.5]), null)
  assert.equal(formatApiMessage('%d 条', ['3']), null)
  assert.equal(formatApiMessage('%s 条', [3]), '3 条')
  assert.equal(formatApiMessage('%s', [true]), 'true')
  assert.equal(formatApiMessage('%s', [null]), '<nil>')
  assert.equal(formatApiMessage('%s 条', []), null)
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
  // 渲染器只实现了 %s/%d/%v/%q；目录里一旦出现别的动词，这条就红——那时要么实现它，
  // 要么确认该词条可以永远回落原文，并在这里登记例外。
  const unrenderable: string[] = []
  for (const entry of entries) {
    for (const [lang, template] of [['zh', entry.zh], ['en', entry.en]] as const) {
      const verbs = templateVerbs(template)
      const params = verbs.map((verb) => (verb === 'd' ? 1 : 'x'))
      if (formatApiMessage(template, params) === null) unrenderable.push(`${entry.key} (${lang}): ${template}`)
    }
  }
  assert.deepEqual(unrenderable, [])
})
