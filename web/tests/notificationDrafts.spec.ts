// 通知中心草稿合并回归：模块部分选中保留、停用通道模板保留、body 不钉 per-channel。
// 运行：cd web && node --test tests/notificationDrafts.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  mergeChannelTemplateDrafts,
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

test('事件模板保存：草稿等于默认或事件级 body 时删除 per-channel 键', () => {
  const existing = { '1': '旧模板', '2': '旧模板2' }
  const out = mergeChannelTemplateDrafts(existing, [
    { channelId: '1', text: '默认', defaultZh: '默认', defaultEn: 'default', bodyTemplate: '事件正文' },
    { channelId: '2', text: '事件正文', defaultZh: '默认', defaultEn: 'default', bodyTemplate: '事件正文' },
  ])
  assert.deepEqual(out, {}, '默认/body 副本不得钉成 per-channel 模板')
})
