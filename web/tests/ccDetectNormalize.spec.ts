// P2-01 修复钉测：新建 stage2 智能触发（auto+cc_detect_enabled=false）保存载荷
// 必须归一 cc_detect_enabled=true（界面显示智能触发⇒落库检测启用，消除静默失效）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildPolicyPayload, type PolicyPayloadInput } from '../src/utils/policyPayload.ts'

const base = (over: Partial<PolicyPayloadInput> = {}): PolicyPayloadInput => ({
  name: 'CC', description: '', enabled: true, mode: 'blocking', anomalyThreshold: 5,
  ipAclEnabled: false, ipAclMode: 'deny', ipAclList: [], ipAclListRefs: [], ipWhitelist: [], ipWhitelistRefs: [], ipWhitelistEnabled: false,
  crsRuleGroups: [], crsExcludedRules: [], customRuleIds: [], blockPageId: 0, blockResponseMode: 'auto', blockStatusCode: 403,
  geoipEnabled: false, geoipMode: 'deny', geoipCountries: '', geoipCrawlerExempt: false, geoipCrawlerEngines: '',
  wafCheckResponse: false, logRequestBody: false, trustDetection: false, policyType: 'stage2',
  humanVerifyMode: 'auto', humanVerifyType: 'slider', humanVerifyTtl: 30, humanExemptPaths: [],
  ccDetectEnabled: false, ccRpsLimit: 40, ccRpsWindow: 10, cc4xxRatio: 70, ccSessionAnomaly: false, ccSessionUaThreshold: 5,
  ccTriggerAction: 'challenge', ccQueueWaitSec: 0, ...over,
})

test('stage2 智能触发（auto+检测关）保存归一 cc_detect_enabled=true', () => {
  const p = buildPolicyPayload(base())
  assert.equal(p.cc_detect_enabled, true, '界面智能触发⇒落库检测必须启用')
  assert.equal(p.human_verify_mode, 'auto')
})

test('stage2 始终验证（force）保存 cc_detect_enabled=false（force 恒挑战不需检测）', () => {
  const p = buildPolicyPayload(base({ humanVerifyMode: 'force' }))
  assert.equal(p.human_verify_mode, 'force')
  assert.equal(p.cc_detect_enabled, false)
})

test('stage2 关闭（off）保存 cc_detect_enabled=false', () => {
  const p = buildPolicyPayload(base({ humanVerifyMode: 'off', ccDetectEnabled: true }))
  assert.equal(p.human_verify_mode, 'off')
  assert.equal(p.cc_detect_enabled, false)
})

test('stage2 智能触发已启用检测保持 true', () => {
  const p = buildPolicyPayload(base({ ccDetectEnabled: true }))
  assert.equal(p.cc_detect_enabled, true)
})