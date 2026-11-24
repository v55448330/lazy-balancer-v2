import test from 'node:test'
import assert from 'node:assert/strict'
import {
  dailyBodyTplKey,
  effectiveDailyMode,
  planDailyChannelStyle,
} from '../src/utils/channelStyle.ts'
import { overviewDeliveryStats } from '../src/utils/notificationOverview.ts'

test('日报模板键与事件模板键分离', () => {
  assert.equal(dailyBodyTplKey('webhook'), 'daily_payload_template')
  assert.equal(dailyBodyTplKey('email'), 'daily_body_template')
  assert.equal(dailyBodyTplKey('qq'), 'daily_content_template')
})

test('日报模式推断只看日报模板键', () => {
  assert.equal(effectiveDailyMode(undefined, 'qq'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_content_template: 'tpl' }), 'qq'), 'template')
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: '静态版式' }), 'qq'), 'modules', '无日报变量的事件模板不推断日报模式')
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: '{{requests}}' }), 'qq'), 'modules', '事件模板键不参与日报模式推断')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'modules', daily_content_template: 'tpl' }), 'qq'), 'modules', '显式值优先')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'template' }), 'qq'), 'template')
})

test('自定义模板模式：草稿等于预置也落库（所见即所得）', () => {
  const preset = '{"requests": {{requests}}}'
  const plan = planDailyChannelStyle({ raw: '{}', type: 'webhook', draft: preset, presets: [preset, 'en'], mode: 'template' })
  assert.equal(plan.style.daily_payload_template, preset)
  assert.equal(plan.style.daily_mode, 'template')
  assert.equal(plan.changed, true)
})

test('内置模板模式：预置草稿不落库；自定义草稿保留', () => {
  const preset = 'x'
  const p1 = planDailyChannelStyle({ raw: '{}', type: 'email', draft: preset, presets: [preset], mode: 'modules' })
  assert.equal(p1.style.daily_body_template, undefined)
  const p2 = planDailyChannelStyle({ raw: '{}', type: 'email', draft: 'mine', presets: [preset], mode: 'modules' })
  assert.equal(p2.style.daily_body_template, 'mine')
})

test('清空草稿删除日报模板键；事件模板键原样保留', () => {
  const cleared = planDailyChannelStyle({
    raw: JSON.stringify({ daily_mode: 'template', daily_body_template: 'old' }), type: 'email', draft: '  ', presets: [], mode: 'template',
  })
  assert.equal(cleared.style.daily_body_template, undefined)
  // 列表接口输出的已是新布局：事件模板与日报模板在同一通道上并存时，日报卡
  // 只动日报键——不得把事件键当作存量日报模板迁走或覆盖。
  const coexist = planDailyChannelStyle({
    raw: JSON.stringify({ daily_mode: 'template', daily_content_template: 'old', content_template: '{{title}}' }), type: 'qq', draft: '{{requests}}', presets: [], mode: 'template',
  })
  assert.equal(coexist.style.daily_content_template, '{{requests}}')
  assert.equal(coexist.style.content_template, '{{title}}', '事件模板键不属于日报卡')
  assert.equal(coexist.changed, true)
})

test('概览投递卡统一 7 天口径：合计与成功率', () => {
  assert.deepEqual(overviewDeliveryStats([]), { deliveries: 0, successRate: 0 })
  assert.deepEqual(overviewDeliveryStats([
    { date: '2026-11-22', total: 10, sent: 9, rate: 0.9 },
    { date: '2026-11-23', total: 30, sent: 21, rate: 0.7 },
  ]), { deliveries: 40, successRate: 0.75 })
})
