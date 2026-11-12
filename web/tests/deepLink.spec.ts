// 深链 URL 构造单源验收：页面键受 PageId 约束、参数键常量导出，视图不得
// 再写 `/?page=` 字面量（改名时静默回落 dashboard）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code } from './_helpers.ts'
import { DEEP_LINK_PARAMS, pageUrl } from '../src/utils/deepLink.ts'

test('pageUrl：基础形态与参数编码', () => {
  assert.equal(pageUrl('security-events'), '/?page=security-events')
  assert.equal(
    pageUrl('rules', { [DEEP_LINK_PARAMS.ruleSearch]: 'lb_a b' }),
    '/?page=rules&rs=lb_a+b',
  )
  assert.equal(
    pageUrl('security-policies', { [DEEP_LINK_PARAMS.policyId]: 7 }),
    '/?page=security-policies&sp=7',
  )
})

test('参数键常量与消费侧解析一致', () => {
  assert.equal(DEEP_LINK_PARAMS.ruleSearch, 'rs')
  assert.equal(DEEP_LINK_PARAMS.policyId, 'sp')
  assert.equal(DEEP_LINK_PARAMS.policySearch, 'sp-search')
  assert.equal(DEEP_LINK_PARAMS.securityRulesTab, 'tab')
})

test('深链交接入口：8 个 window.open 调用点全部走 pageUrl，视图内无 /?page= 字面量', () => {
  // 调用点名册（逐个正向断言）：仅断言「无字面量」时，整行 window.open 被删
  // （入口消失）仍全绿。pageUrl 生产调用点共 8 处（总览新增自动封禁配置入口）。
  const callSites: Array<{ path: string; expected: number }> = [
    { path: 'src/views/security/SecurityEvents.vue', expected: 3 },
    { path: 'src/views/security/SecurityOverview.vue', expected: 2 },
    { path: 'src/views/security/SecurityPolicies.vue', expected: 3 },
  ]
  for (const { path, expected } of callSites) {
    const text = code(path)
    assert.match(text, /from '@\/utils\/deepLink'/, `${path} 未接入深链单源`)
    assert.doesNotMatch(text, /window\.open\('\/\?page=/, `${path} 仍有字面量深链`)
    assert.doesNotMatch(text, /window\.open\(`\/\?page=/, `${path} 仍有字面量深链`)
    const calls = text.match(/window\.open\(pageUrl\(/g) ?? []
    assert.equal(calls.length, expected, `${path} 的 pageUrl 交接入口数量变化（少=入口消失，多=新增入口需同步名册）`)
  }
  // 目标页键逐项正向钉（入口指向错误页面同样算回归）
  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /window\.open\(pageUrl\('rules', \{ \[DEEP_LINK_PARAMS\.ruleSearch\]: row\.rule_caddy_id \}\)/)
  assert.match(events, /window\.open\(pageUrl\('security-policies', \{ \[DEEP_LINK_PARAMS\.policyId\]: row\.policy_id \}\)/)
  assert.match(events, /window\.open\(pageUrl\('security-policies', \{ \[DEEP_LINK_PARAMS\.policySearch\]: row\.policy_name \}\)/)
  assert.match(code('src/views/security/SecurityOverview.vue'), /window\.open\(pageUrl\('security-events'\)/)
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /window\.open\(pageUrl\('security-rules', \{ \[DEEP_LINK_PARAMS\.securityRulesTab\]: 'custom' \}\)/)
  assert.match(policies, /window\.open\(pageUrl\('security-block-pages'\)/)
  assert.match(policies, /window\.open\(pageUrl\('rules', \{ \[DEEP_LINK_PARAMS\.ruleSearch\]: caddyId \}\)/)
  // 消费侧参数名同样走常量
  assert.match(code('src/views/Rules.vue'), /get\(DEEP_LINK_PARAMS\.ruleSearch\)/)
  assert.match(code('src/views/security/SecurityRules.vue'), /get\(DEEP_LINK_PARAMS\.securityRulesTab\)/)
  assert.match(code('src/views/security/SecurityPolicies.vue'), /get\(DEEP_LINK_PARAMS\.policySearch\)/)
})
