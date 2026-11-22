// 投递流水分通道结果收敛：一次投递重试会向
// notification_delivery_channels 追加同 channel_id 的新结果行（daemon 每次
// 投递尝试插一行），列表 JOIN 会带出全部历史行——展开列表重复、成功/失败计数
// 被放大。前端按 channel_id 只保留最新结果行（有 id 取最大 id；接口按 id 升序
// 返回时，后出现者即最新）。
//
// 运行：cd web && node --test tests/deliveryLog.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { latestChannelResults } from '../src/utils/deliveryLog.ts'
import { code } from './_helpers.ts'

test('同一通道多次尝试只保留最大 id 的结果行', () => {
  const rows = [
    { channel_id: 1, id: 11, status: 'failed' },
    { channel_id: 2, id: 12, status: 'sent' },
    { channel_id: 1, id: 13, status: 'sent' },
  ]
  const got = latestChannelResults(rows)
  assert.equal(got.length, 2, '同通道历史行必须收敛为一行')
  assert.equal(got.find(r => r.channel_id === 1)?.id, 13, '保留最大 id')
  assert.equal(got.find(r => r.channel_id === 2)?.id, 12)
})

test('缺 id 字段时按接口升序（后出现=最新）收敛', () => {
  const rows = [
    { channel_id: 7, status: 'failed' },
    { channel_id: 7, status: 'sent' },
  ]
  const got = latestChannelResults(rows)
  assert.deepEqual(got, [{ channel_id: 7, status: 'sent' }])
})

test('乱序 id 仍取最大（不依赖出现顺序）', () => {
  const got = latestChannelResults([
    { channel_id: 3, id: 20, status: 'sent' },
    { channel_id: 3, id: 9, status: 'failed' },
  ])
  assert.equal(got.length, 1)
  assert.equal(got[0]!.id, 20)
})

test('DeliveryLog 接线：列表装载即收敛每通道结果', () => {
  const text = code('src/views/notifications/DeliveryLog.vue')
  assert.match(text, /latestChannelResults\(/, '展开行/计数必须消费收敛后的通道结果')
})
