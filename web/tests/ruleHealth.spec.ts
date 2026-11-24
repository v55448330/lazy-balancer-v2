// 规则健康结论单源（行为测试）：规则页列表、仪表盘规则卡、处理流程弹框三面
// 必须给出同一级别与同色阶。判定口径以规则页既有口径为准：
//   全部上游不健康/降级 → 不健康（danger）
//   部分上游不健康/降级 → 降级（warning）
//   全部上游状态未知     → 未知（info）
//   部分上游状态未知     → 降级（warning）
//   全部上游不可观测     → 不适用（info）
//   其余                 → 健康（success）
//
// 运行：cd web && npm test
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'

import {
  RULE_HEALTH_LABEL_KEY,
  RULE_HEALTH_TAG_TYPE,
  ruleHealthLevel,
  ruleHealthLevelOfUpstreams,
  type RuleHealthSummary,
  type UpstreamHealthSnapshot,
} from '../src/utils/ruleHealth.ts'

const summary = (healthy = 0, unhealthy = 0, degraded = 0, unknown = 0, na = 0): RuleHealthSummary => ({
  healthy,
  unhealthy,
  degraded,
  unknown,
  na,
  total: healthy + unhealthy + degraded + unknown + na,
})

test('规则健康级别：按规则页口径判定', () => {
  const cases: Array<[string, RuleHealthSummary, string]> = [
    ['全部不健康', summary(0, 3), 'unhealthy'],
    ['全部降级', summary(0, 0, 2), 'unhealthy'],
    ['不健康 + 降级合计占满', summary(0, 1, 1), 'unhealthy'],
    ['部分不健康', summary(2, 1), 'degraded'],
    ['部分降级', summary(2, 0, 1), 'degraded'],
    ['不健康优先于降级', summary(1, 1, 1), 'degraded'],
    ['全部未知', summary(0, 0, 0, 2), 'unknown'],
    ['部分未知', summary(2, 0, 0, 1), 'degraded'],
    ['全部不可观测', summary(0, 0, 0, 0, 2), 'not_applicable'],
    ['部分不可观测不影响健康结论', summary(2, 0, 0, 0, 1), 'healthy'],
    ['全部健康', summary(3), 'healthy'],
  ]
  for (const [name, status, want] of cases) {
    assert.equal(ruleHealthLevel(status), want, name)
  }
})

test('规则健康级别：零上游沿用既有口径（不改变语义）', () => {
  // 既有规则页实现里 0 === 0 落到「不健康」分支；单源后保持不变，
  // 由调用方保证零上游规则不进入健康展示。
  assert.equal(ruleHealthLevel(summary()), 'unhealthy')
})

test('规则健康色阶与文案键覆盖每个级别', () => {
  const levels: Array<'unhealthy' | 'degraded' | 'unknown' | 'not_applicable' | 'healthy'> = ['unhealthy', 'degraded', 'unknown', 'not_applicable', 'healthy']
  for (const level of levels) {
    assert.ok(level in RULE_HEALTH_TAG_TYPE, `缺色阶: ${level}`)
    assert.ok(level in RULE_HEALTH_LABEL_KEY, `缺文案键: ${level}`)
  }
  assert.deepEqual(
    levels.map((level) => RULE_HEALTH_TAG_TYPE[level]),
    ['danger', 'warning', 'info', 'info', 'success'],
  )
})

test('规则健康级别不受额外字段影响', () => {
  const withExtra: RuleHealthSummary & { extra: string } = { ...summary(1, 1), extra: 'ignored' }
  assert.equal(ruleHealthLevel(withExtra), 'degraded')
})

test('接线：规则页与处理流程弹框都经单源取级别与色阶', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /RULE_HEALTH_TAG_TYPE\[ruleHealthLevel\(status\)\]/, '规则页色阶必须取自单源')
  assert.match(rules, /RULE_HEALTH_LABEL_KEY\[ruleHealthLevel\(status\)\]/, '规则页文案必须取自单源')
  assert.doesNotMatch(rules, /status\.unhealthy \+ status\.degraded === status\.total/, '规则页不得再自写健康判定')
  const flow = code('src/components/RuleFlowDialog.vue')
  assert.match(flow, /RULE_HEALTH_TAG_TYPE\[ruleHealthLevel\(target\.health\)\]/, '流程弹框色阶必须取自单源')
  assert.doesNotMatch(flow, /unhealthy \+ target\.health\.degraded > 0 \? 'warning'/, '流程弹框不得再自写「任一不健康 = 警示」')
})

const snap = (state: 'healthy' | 'unhealthy' | 'degraded' | 'unknown'): UpstreamHealthSnapshot =>
  state === 'healthy' ? { healthy: true, unknown: false }
    : state === 'unhealthy' ? { healthy: false, unknown: false }
      : state === 'degraded' ? { healthy: true, unknown: false, degraded: true }
        : { healthy: false, unknown: true }

test('由上游快照求级别：与规则页同口径（部分不健康 = 降级）', () => {
  assert.equal(ruleHealthLevelOfUpstreams([snap('healthy'), snap('unhealthy'), snap('healthy')]), 'degraded', '仪表盘此前把「任一不健康」判成不健康（危险）')
  assert.equal(ruleHealthLevelOfUpstreams([snap('unhealthy'), snap('unhealthy')]), 'unhealthy')
  assert.equal(ruleHealthLevelOfUpstreams([snap('healthy'), undefined]), 'degraded', '缺快照计为未知 → 部分未知 = 降级')
  assert.equal(ruleHealthLevelOfUpstreams([undefined, snap('unknown')]), 'unknown')
  assert.equal(ruleHealthLevelOfUpstreams([snap('healthy'), snap('healthy')]), 'healthy')
  assert.equal(ruleHealthLevelOfUpstreams([snap('healthy'), snap('degraded')]), 'degraded')
})

test('接线：仪表盘规则卡的健康级别经单源', () => {
  const dashboard = code('src/views/Dashboard.vue')
  assert.match(dashboard, /ruleHealthLevelOfUpstreams\(/, '仪表盘不得再自写健康级别判定')
  assert.doesNotMatch(dashboard, /if \(hasUnhealthy\) status = 'unhealthy'/, '仪表盘不得再用「任一不健康 = 不健康」')
})
