// 通道编辑目标脱敏契约：通道列表 DTO 带 target_masked，管理员编辑
// 非属主通道时目标已被后端脱敏（脱敏后不再是合法 target JSON）。编辑必须：
//   1. 目标输入框置空 + 占位提示「已脱敏，重新输入完整目标」；
//   2. 未输入新目标 → PUT 体只含 name/style_config，禁止把脱敏串回写覆盖真实目标；
//   3. 输入了新目标 → 按通道类型的 target JSON 键正常提交。
//
// 运行：cd web && node --test tests/channelEdit.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { channelEditPayload, channelTargetKey } from '../src/utils/channelEdit.ts'
import { code } from './_helpers.ts'

test('脱敏态未输入新目标：编辑体只含 name（target 键缺省）', () => {
  const payload = channelEditPayload({ name: '  ops  ', targetValue: '', type: 'webhook', targetMasked: true })
  assert.deepEqual(payload, { name: 'ops' })
  assert.ok(!('target' in payload), '脱敏目标不得回写（后端保留原 target）')
  const blank = channelEditPayload({ name: 'ops', targetValue: '   ', type: 'email', targetMasked: true })
  assert.ok(!('target' in blank), '仅空白字符=未输入新目标')
})

test('脱敏态输入新目标：按通道类型键正常提交 target JSON', () => {
  const webhook = channelEditPayload({ name: 'ops', targetValue: ' https://example.com/hook ', type: 'webhook', targetMasked: true })
  assert.equal(webhook.target, JSON.stringify({ url: 'https://example.com/hook' }))
  const bot = channelEditPayload({ name: 'bot', targetValue: 'openid-1', type: 'qq', targetMasked: true })
  assert.equal(bot.target, JSON.stringify({ openid: 'openid-1' }))
})

test('未脱敏态保持原行为：目标为空同样提交（与后端校验同口径）', () => {
  const payload = channelEditPayload({ name: 'mine', targetValue: '', type: 'email', targetMasked: false })
  assert.equal(payload.target, JSON.stringify({ email: '' }))
})

test('类型→target 键映射与通道 target JSON 契约一致', () => {
  assert.equal(channelTargetKey('webhook'), 'url')
  assert.equal(channelTargetKey('email'), 'email')
  assert.equal(channelTargetKey('qq'), 'openid')
  assert.equal(channelTargetKey('wx_clawbot'), 'receiver')
  assert.equal(channelTargetKey('unknown'), 'target', '未知类型回落 target 键')
})

test('ChannelCards 接线：target_masked 置空目标 + 占位提示 + 保存经 channelEditPayload', () => {
  const text = code('src/views/notifications/ChannelCards.vue')
  assert.match(text, /target_masked/, '必须消费后端脱敏标记')
  assert.match(text, /channelEditPayload\(/, '编辑保存体必须经纯函数（脱敏态省略 target）')
  assert.match(text, /targetMaskedPlaceholder/, '脱敏目标输入框必须有占位提示')
  assert.match(text, /style_config: buildStyleConfig\(\)/, '样式仍按全量覆盖提交')
})
