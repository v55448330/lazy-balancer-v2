// 深链 URL 构造单源验收：页面键受 PageId 约束、参数键常量导出，视图不得
// 再写 `/?page=` 字面量（改名时静默回落 dashboard）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code } from './_helpers.ts'
import { DEEP_LINK_PARAMS, EVENTS_AUTOBAN_CONFIG, parseSecurityEventsDeepLink, pageUrl } from '../src/utils/deepLink.ts'

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
  assert.equal(
    pageUrl('security-events', { [DEEP_LINK_PARAMS.eventsAction]: 'blocked' }),
    '/?page=security-events&action=blocked',
  )
})

test('事件页深链解析：动作筛选只接受「动作」下拉四值，非法值不透传成筛选条件', () => {
  assert.deepEqual(parseSecurityEventsDeepLink('?page=security-events&action=blocked'), { action: 'blocked', openAutobanConfig: false })
  assert.deepEqual(parseSecurityEventsDeepLink(''), { action: '', openAutobanConfig: false })
  for (const value of ['logged', 'trust', 'challenged']) {
    assert.equal(parseSecurityEventsDeepLink(`?action=${value}`).action, value)
  }
  // 任意字符串不得成为 action 筛选（下钻页带着未知条件查后端，空列表会被读成「无事件」）
  for (const bad of ['BLOCKED', 'all', '', 'blocked%20']) {
    assert.equal(parseSecurityEventsDeepLink(`?action=${bad}`).action, '', `action=${bad} 必须被丢弃`)
  }
})

test('事件页深链解析：自动封禁配置意图只认 config，可与动作筛选并存', () => {
  assert.equal(parseSecurityEventsDeepLink(`?${DEEP_LINK_PARAMS.eventsAutoban}=${EVENTS_AUTOBAN_CONFIG}`).openAutobanConfig, true)
  for (const bad of ['1', '', 'CONFIG', 'view']) {
    assert.equal(parseSecurityEventsDeepLink(`?${DEEP_LINK_PARAMS.eventsAutoban}=${bad}`).openAutobanConfig, false, `autoban=${bad} 必须被丢弃`)
  }
  assert.deepEqual(
    parseSecurityEventsDeepLink(`?${DEEP_LINK_PARAMS.eventsAction}=blocked&${DEEP_LINK_PARAMS.eventsAutoban}=${EVENTS_AUTOBAN_CONFIG}`),
    { action: 'blocked', openAutobanConfig: true },
  )
})

test('参数键常量与消费侧解析一致', () => {
  assert.equal(DEEP_LINK_PARAMS.ruleSearch, 'rs')
  assert.equal(DEEP_LINK_PARAMS.policyId, 'sp')
  assert.equal(DEEP_LINK_PARAMS.policySearch, 'sp-search')
  assert.equal(DEEP_LINK_PARAMS.securityRulesTab, 'tab')
  assert.equal(DEEP_LINK_PARAMS.eventsAction, 'action')
  assert.equal(DEEP_LINK_PARAMS.eventsAutoban, 'autoban')
  assert.equal(EVENTS_AUTOBAN_CONFIG, 'config')
})

test('深链交接入口：10 个 window.open 调用点全部走 pageUrl，视图内无 /?page= 字面量', () => {
  // 调用点名册（逐个正向断言）：仅断言「无字面量」时，整行 window.open 被删
  // （入口消失）仍全绿。pageUrl 生产调用点共 10 处（总览自动封禁配置入口已随
  // NAT 移除批退役；事件页一键启用拦截深链随 2026-11-21 裁定退役——默认策略
  // 流程取代；默认策略弹框的「返回策略列表」改为关闭弹框、不再新开标签；
  // 事件 4 + 总览 1 + 策略 5（含默认策略弹框完成指引 1 处））。
  const callSites: Array<{ path: string; expected: number }> = [
    { path: 'src/views/security/SecurityEvents.vue', expected: 4 },
    { path: 'src/views/security/SecurityOverview.vue', expected: 1 },
    { path: 'src/views/security/SecurityPolicies.vue', expected: 5 },
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
  // 未生效黄条「前往绑定规则」：定位到 binding 环节那条就绪未绑定的策略
  assert.match(events, /window\.open\(pageUrl\('security-policies', \{ \[DEEP_LINK_PARAMS\.policyId\]: autobanBindingPolicyId\.value \}\)/)
  // 总览「查看全部」=「最近拦截事件」卡的下钻，必须带拦截筛选
  assert.match(code('src/views/security/SecurityOverview.vue'), /window\.open\(pageUrl\('security-events', \{ \[DEEP_LINK_PARAMS\.eventsAction\]: 'blocked' \}\)/)
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /window\.open\(pageUrl\('security-rules', \{ \[DEEP_LINK_PARAMS\.securityRulesTab\]: 'custom' \}\)/)
  assert.match(policies, /window\.open\(pageUrl\('security-block-pages'\)/)
  assert.match(policies, /window\.open\(pageUrl\('rules', \{ \[DEEP_LINK_PARAMS\.ruleSearch\]: caddyId \}\)/)
  // 「查看自动封禁配置」必须带配置意图（事件页进页后自动打开配置弹框）
  assert.match(policies, /window\.open\(pageUrl\('security-events', \{ \[DEEP_LINK_PARAMS\.eventsAutoban\]: EVENTS_AUTOBAN_CONFIG \}\)/)
  // 默认策略弹框完成指引：IP 名单 tab 深链保留；「返回策略列表」不再新开标签
  assert.match(policies, /window\.open\(pageUrl\('security-rules', \{ \[DEEP_LINK_PARAMS\.securityRulesTab\]: 'ip-lists' \}\)/)
  assert.doesNotMatch(policies, /window\.open\(pageUrl\('security-policies'\)/, '「返回策略列表」必须关闭弹框回到当前列表，不得新开同页标签')
  // 消费侧参数名同样走常量
  assert.match(code('src/views/Rules.vue'), /get\(DEEP_LINK_PARAMS\.ruleSearch\)/)
  assert.match(code('src/views/security/SecurityRules.vue'), /get\(DEEP_LINK_PARAMS\.securityRulesTab\)/)
  assert.match(code('src/views/security/SecurityPolicies.vue'), /get\(DEEP_LINK_PARAMS\.policySearch\)/)
  assert.match(code('src/views/security/SecurityPolicies.vue'), /get\(DEEP_LINK_PARAMS\.policyId\)/, 'sp（策略 ID 聚焦）消费侧必须走常量')
  // 事件页消费侧走解析单源（非法值不透传成筛选条件）
  assert.match(events, /parseSecurityEventsDeepLink\(window\.location\.search\)/)
})
