// 证书有效期结论单源（行为测试）：规则向导预览行、TLS 步骤提示框、规则列表 TLS 列
// 的证书提示、处理流程弹框的剩余天数行必须给出同一结论与同一色阶。此前列表提示
// 显示「N 天」且色阶跟后端 status（16 天 = 绿色），向导显示「16 天后」警示色，
// 同一张证书在两个面口径不一。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'
import { certExpiryConclusion } from '../src/utils/certExpiry.ts'

test('证书有效期结论：过期 / 当天 / 临期 / 正常 四形状', () => {
  const expired = certExpiryConclusion(-569)
  assert.equal(expired.tone, 'is-danger')
  assert.match(expired.text, /569/)
  assert.ok(!expired.text.includes('-'), '带符号的天数不得上屏')

  const today = certExpiryConclusion(0)
  assert.equal(today.tone, 'is-warning')

  const soon = certExpiryConclusion(16)
  assert.equal(soon.tone, 'is-warning', '≤30 天为警示')
  const boundary = certExpiryConclusion(30)
  assert.equal(boundary.tone, 'is-warning', '30 天仍为警示')

  const normal = certExpiryConclusion(31)
  assert.equal(normal.tone, 'is-success')
  assert.equal(certExpiryConclusion(66).tone, 'is-success')
})

test('证书有效期结论：同一天数多次调用结果稳定（纯函数）', () => {
  assert.deepEqual(certExpiryConclusion(16), certExpiryConclusion(16))
  assert.notDeepEqual(certExpiryConclusion(16), certExpiryConclusion(31))
})

test('接线：四个面都经单源取结论', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /certExpiryConclusion\(certInfo\.daysUntilExpiry\)/, '向导预览行与 TLS 步提示框必须经单源')
  assert.match(rules, /certDaysConclusion\(certInfoMap\[row\.caddy_id\]\)/, '规则列表 TLS 列证书提示必须经单源')
  assert.match(rules, /\? certExpiryConclusion\(cert\?\.days_remaining \?\? 0\) : null/, '列表提示的结论必须来自单源（天数不可得时为空）')
  assert.doesNotMatch(rules, /if \(days < 0\) return t\('common\.app\.rules\.wizard\.expiredDaysAgo'/, 'Rules.vue 不得再自写有效期判定')
  assert.doesNotMatch(rules, /wizard\.tableCertDays/, '列表提示不得再用「N 天」另一套文案')
  const flow = code('src/components/RuleFlowDialog.vue')
  assert.match(flow, /certExpiryConclusion\(certInfo\.days_remaining/, '处理流程弹框剩余天数行必须经单源')
})
