// CC 防护交互重组行为验收（何时介入 × 怎么处置 两个正交问题）。
//
// 后端契约（不可破坏）：
//   · human_verify_mode: off/auto/force；force 恒挑战（lbhuman/handler.go:153），
//     queue/reject 仅在 auto + CC 检测触发时生效（serveCCTriggerAction）。
//   · cc_detect_enabled：auto 模式下阈值触发开关。
//   · cc_trigger_action: challenge/queue/reject。
//
// UI 重组映射（纯前端，数据模型零破坏）：
//   何时介入：none→off / always→force / anomaly→auto+cc_detect_enabled=true
//   怎么处置：challenge/queue/reject → cc_trigger_action（force 时恒 challenge）
//   拦截页过滤：stage2 按动作要求占位符；mixed 不过滤（单 block_page_id 兼 WAF）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ccInterventionFromForm,
  ccFormFromIntervention,
  ccEffectiveAction,
  ccPageCompatible,
  ccStage2PageOptions,
} from '../src/utils/policyPayload.ts'

// ── 何时介入：form → 三档 ──
test('何时介入：off→none，force→always，auto+检测开→anomaly', () => {
  assert.equal(ccInterventionFromForm({ humanVerifyMode: 'off', ccDetectEnabled: false }), 'none')
  assert.equal(ccInterventionFromForm({ humanVerifyMode: 'off', ccDetectEnabled: true }), 'none')
  assert.equal(ccInterventionFromForm({ humanVerifyMode: 'force', ccDetectEnabled: false }), 'always')
  assert.equal(ccInterventionFromForm({ humanVerifyMode: 'force', ccDetectEnabled: true }), 'always')
  assert.equal(ccInterventionFromForm({ humanVerifyMode: 'auto', ccDetectEnabled: true }), 'anomaly')
})

test('何时介入：auto+检测关（历史装饰态）归一 anomaly（保存即启用检测，消除永不触发）', () => {
  assert.equal(ccInterventionFromForm({ humanVerifyMode: 'auto', ccDetectEnabled: false }), 'anomaly')
})

// ── 何时介入：三档 → form 字段 ──
test('何时介入映射：none→off+检测关；always→force+检测关；anomaly→auto+检测开', () => {
  assert.deepEqual(ccFormFromIntervention('none'), { human_verify_mode: 'off', cc_detect_enabled: false })
  assert.deepEqual(ccFormFromIntervention('always'), { human_verify_mode: 'force', cc_detect_enabled: false })
  assert.deepEqual(ccFormFromIntervention('anomaly'), { human_verify_mode: 'auto', cc_detect_enabled: true })
})

test('何时介入往返：三档 → form → 三档 恒等', () => {
  for (const v of ['none', 'always', 'anomaly'] as const) {
    const f = ccFormFromIntervention(v)
    assert.equal(ccInterventionFromForm({ humanVerifyMode: f.human_verify_mode, ccDetectEnabled: f.cc_detect_enabled }), v)
  }
})

// ── 有效处置动作（force 恒挑战） ──
test('有效处置：force 恒 challenge（后端 force 不经动作分流）；auto/off 透传', () => {
  assert.equal(ccEffectiveAction('force', 'queue'), 'challenge')
  assert.equal(ccEffectiveAction('force', 'reject'), 'challenge')
  assert.equal(ccEffectiveAction('force', 'challenge'), 'challenge')
  assert.equal(ccEffectiveAction('auto', 'queue'), 'queue')
  assert.equal(ccEffectiveAction('auto', 'reject'), 'reject')
  assert.equal(ccEffectiveAction('auto', 'challenge'), 'challenge')
  assert.equal(ccEffectiveAction('off', 'reject'), 'reject')
})

// ── 页面兼容性（占位符） ──
const page = (id: number, content: string) => ({ id, content })
test('页面兼容：challenge 按验证方式要 human_verify/human_js 组件', () => {
  assert.equal(ccPageCompatible(page(1, '<div>{{human_verify_widget}}</div>'), 'challenge', 'slider'), true)
  assert.equal(ccPageCompatible(page(1, '<div>{{human_js_widget}}</div>'), 'challenge', 'js'), true)
  assert.equal(ccPageCompatible(page(1, '<div>{{human_verify_widget}}</div>'), 'challenge', 'js'), false)
  assert.equal(ccPageCompatible(page(1, '<p>plain</p>'), 'challenge', 'slider'), false)
})

test('页面兼容：queue 要 queue_widget；reject 任何页均可', () => {
  assert.equal(ccPageCompatible(page(1, '{{queue_widget}}'), 'queue', 'slider'), true)
  assert.equal(ccPageCompatible(page(1, '{{human_verify_widget}}'), 'queue', 'slider'), false)
  assert.equal(ccPageCompatible(page(1, '<p>plain</p>'), 'reject', 'slider'), true)
  assert.equal(ccPageCompatible(page(1, ''), 'reject', 'js'), true)
})

// ── stage2 页面下拉过滤；mixed 不过滤 ──
const pages = [
  page(9005, '{{human_verify_widget}}'),
  page(9006, '{{human_js_widget}}'),
  page(9007, '{{queue_widget}}'),
  page(9001, '<p>429</p>'),
  page(50, '<p>custom waf</p>'),
]
test('stage2 页面过滤：challenge/slider 只列含滑块组件页', () => {
  const ids = ccStage2PageOptions(pages, 'stage2', 'challenge', 'slider').map((p) => p.id)
  assert.deepEqual(ids, [9005])
})
test('stage2 页面过滤：queue 只列含排队组件页；reject 列全部', () => {
  assert.deepEqual(ccStage2PageOptions(pages, 'stage2', 'queue', 'slider').map((p) => p.id), [9007])
  assert.deepEqual(ccStage2PageOptions(pages, 'stage2', 'reject', 'slider').map((p) => p.id), [9005, 9006, 9007, 9001, 50])
})
test('mixed 不过滤：单 block_page_id 兼 WAF 页，硬过滤会破坏阶段3拦截页', () => {
  assert.deepEqual(ccStage2PageOptions(pages, 'mixed', 'challenge', 'slider').map((p) => p.id), [9005, 9006, 9007, 9001, 50])
  assert.deepEqual(ccStage2PageOptions(pages, 'stage3', 'challenge', 'slider').map((p) => p.id), [9005, 9006, 9007, 9001, 50])
})