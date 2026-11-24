// 通知中心草稿合并回归：模块部分选中保留、停用通道模板保留、body 不钉 per-channel；
// 事件模板「等于预置」只有中文机器人预置等价于后端默认链，其余预置必须落库
// （否则保存后实际投递走默认链 ≠ 编辑器里看到的预置）。
// 运行：cd web && node --test tests/notificationDrafts.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  channelTemplateByteLimit,
  mergeChannelTemplateDrafts,
  ruleTemplateIsHtml,
  toggleDailyModules,
  utf8ByteLength,
} from '../src/utils/notificationDrafts.ts'

test('大模块勾选只影响状态变化的模块：部分选中模块不被删除', () => {
  const modules = [
    { id: 'm1', items: ['a', 'b'] },
    { id: 'm2', items: ['c', 'd'] },
    { id: 'm3', items: ['e', 'f'] },
  ]
  // m1 全选；m2 部分选中（c）；m3 全选。
  const items = ['a', 'b', 'c', 'e', 'f']
  const next = toggleDailyModules(items, modules, ['m1', 'm3'])
  assert.deepEqual(new Set(next), new Set(['a', 'b', 'c', 'e', 'f']), '未变化的 m2 必须保留 c')
})

test('大模块勾选：取消全选模块会整组删除，重新勾选会整组加入', () => {
  const modules = [{ id: 'm1', items: ['a', 'b'] }]
  assert.deepEqual(toggleDailyModules(['a', 'b', 'c'], modules, []), ['c'])
  assert.deepEqual(new Set(toggleDailyModules(['c'], modules, ['m1'])), new Set(['c', 'a', 'b']))
})

test('模板长度按 UTF-8 字节计数（与后端 len 同口径）', () => {
  assert.equal(utf8ByteLength('abc'), 3)
  assert.equal(utf8ByteLength('中文'), 6)
  assert.equal(utf8ByteLength('a中'), 4)
})

test('事件模板保存保留停用通道的既有模板', () => {
  const existing = { '1': '渠道1模板', '9': '停用渠道模板' }
  const out = mergeChannelTemplateDrafts(existing, [{
    channelId: '1', text: '渠道1模板', defaultZh: '默认', defaultEn: 'default', bodyTemplate: '',
  }])
  assert.equal(out['9'], '停用渠道模板', '未展示的停用通道模板不得被整体覆盖删除')
  assert.equal(out['1'], '渠道1模板')
})

test('事件模板保存：等于事件级 body 时删除 per-channel 键', () => {
  const existing = { '2': '旧模板2' }
  const out = mergeChannelTemplateDrafts(existing, [
    { channelId: '2', text: '事件正文', defaultZh: '默认', defaultEn: 'default', bodyTemplate: '事件正文' },
  ])
  assert.deepEqual(out, {}, 'body 副本不得钉成 per-channel 模板')
})

test('只有中文机器人预置等价于默认链（等于它才删键）', () => {
  const bot = mergeChannelTemplateDrafts(undefined, [
    { channelId: '1', text: '中文预置', defaultZh: '中文预置', defaultEn: 'en-preset', bodyTemplate: '', presetIsDefaultChain: true },
  ])
  assert.deepEqual(bot, {}, '中文机器人预置=后端默认模板（跨栈逐字等价）→ 不钉副本')
})

test('英文预置与 webhook/email 预置必须落库（后端默认链不均等）', () => {
  const en = mergeChannelTemplateDrafts(undefined, [
    { channelId: '2', text: 'en-preset', defaultZh: '中文预置', defaultEn: 'en-preset', bodyTemplate: '', presetIsDefaultChain: true },
  ])
  assert.equal(en['2'], 'en-preset', '后端缺省模板只有中文——英文预置保存后必须按英文发')
  const hook = mergeChannelTemplateDrafts(undefined, [
    { channelId: '3', text: '{"level": {{level}}}', defaultZh: '{"level": {{level}}}', defaultEn: 'en', bodyTemplate: '', presetIsDefaultChain: false },
  ])
  assert.equal(hook['3'], '{"level": {{level}}}', 'webhook 默认信封≠预置 JSON——必须落库')
})

test('规则级邮件模板的格式由内容决定：含 HTML 标签=HTML，否则纯文本', () => {
  assert.equal(ruleTemplateIsHtml('<div style="color:red">{{title}}<br>{{body}}</div>'), true)
  assert.equal(ruleTemplateIsHtml('<!DOCTYPE html><p>{{title}}</p>'), true)
  assert.equal(ruleTemplateIsHtml('{{title}}\n{{body}}'), false)
  assert.equal(ruleTemplateIsHtml('阈值 a < b 且 c > d'), false, '比较运算里的尖括号不是标签')
})

test('通道模板字节上限与后端保存门同口径', () => {
  assert.equal(channelTemplateByteLimit('qq'), 2000)
  assert.equal(channelTemplateByteLimit('wx_clawbot'), 2000)
  assert.equal(channelTemplateByteLimit('email'), 4000)
  assert.equal(channelTemplateByteLimit('webhook'), 0)
})
