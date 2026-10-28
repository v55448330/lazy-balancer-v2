// 「取消信任」处置计划验收：可移除条目与残余 CIDR 信任必须一次算清。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { planTrustRemoval, classifyTrustRemovalVerification } from '../src/utils/trustRemoval.ts'
import { isTrustExemptionCandidate } from '../src/utils/securityStages.ts'

const ip = '203.0.113.7'

test('内联精确 + 引用 CIDR：可移除但必须报告残余信任（原实现谎报已取消）', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify([ip]),
    whitelistRefs: '[1]',
    lists: [{ id: 1, name: '办公网段' }],
    removableListIds: [1],
    listEntries: () => ['203.0.113.0/24'],
  })
  assert.equal(plan.inlineExact, true)
  assert.equal(plan.hasRemovable, true)
  assert.deepEqual(plan.exactRefListIds, [])
  assert.deepEqual(plan.residualSources, ['引用列表「办公网段」的 CIDR 条目'])
})

test('仅内联精确条目：移除后信任真正解除（无残余）', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify([ip, '198.51.100.0/24']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(plan.hasRemovable, true)
  assert.deepEqual(plan.residualSources, [])
})

test('引用列表精确条目可移除 + 内联 CIDR 仍残余', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify(['203.0.113.0/24']),
    whitelistRefs: '[2]',
    lists: [{ id: 2, name: '可信 IP' }],
    removableListIds: [2],
    listEntries: () => [ip],
  })
  assert.deepEqual(plan.exactRefListIds, [2])
  assert.deepEqual(plan.residualSources, ['策略内联 CIDR 条目'])
})

test('仅 CIDR 提供信任：本弹窗无可执行动作', () => {
  const inlineCidr = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify(['203.0.113.0/24']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(inlineCidr.hasRemovable, false)
  assert.deepEqual(inlineCidr.residualSources, ['策略内联 CIDR 条目'])

  const refCidr = planTrustRemoval({
    ip,
    inlineWhitelist: '[]',
    whitelistRefs: '[3]',
    lists: [{ id: 3, name: '数据中心' }],
    removableListIds: [3],
    listEntries: () => ['203.0.113.0/24'],
  })
  assert.equal(refCidr.hasRemovable, false)
  assert.deepEqual(refCidr.residualSources, ['引用列表「数据中心」的 CIDR 条目'])
})

test('引用列表精确条目但不在可移除集合：不得纳入删除计划，且必须报告残余信任', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: '[]',
    whitelistRefs: '[4]',
    lists: [{ id: 4, name: '系统名单' }],
    removableListIds: [],
    listEntries: () => [ip],
  })
  assert.equal(plan.hasRemovable, false)
  assert.deepEqual(plan.exactRefListIds, [])
  // 不可移除的精确条目同样提供信任：漏计会让「取消信任」在无可执行动作时
  // 指引用户去编辑一个本弹窗无法移除的来源，或谎报已解除。
  assert.deepEqual(plan.residualSources, ['引用列表「系统名单」的精确条目（不可在本弹窗移除）'])
})

test('可移除列表的精确条目移除后不再是残余来源', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: '[]',
    whitelistRefs: '[5,6]',
    lists: [{ id: 5, name: '可移除' }, { id: 6, name: '系统名单' }],
    removableListIds: [5],
    listEntries: (id) => (id === 5 ? [ip] : ['203.0.113.0/24']),
  })
  assert.deepEqual(plan.exactRefListIds, [5])
  assert.deepEqual(plan.residualSources, ['引用列表「系统名单」的 CIDR 条目'])
})

test('空白归一：带空格的精确条目仍视为可移除', () => {
  const plan = planTrustRemoval({
    ip: ` ${ip} `,
    inlineWhitelist: JSON.stringify([` ${ip} `]),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(plan.inlineExact, true)
  assert.deepEqual(plan.residualSources, [])
})

test('IPv6 残余信任：精确条目移除后覆盖它的 IPv6 CIDR 必须报告（不得谎报已取消）', () => {
  const v6 = '2001:db8:abcd::7'
  const plan = planTrustRemoval({
    ip: v6,
    inlineWhitelist: JSON.stringify([v6, '2001:db8::/32']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(plan.inlineExact, true)
  assert.deepEqual(plan.residualSources, ['策略内联 CIDR 条目'])
  // 不在 CIDR 覆盖范围内 → 无残余（不得把「同族但不同前缀」也算残余）
  const clear = planTrustRemoval({
    ip: v6,
    inlineWhitelist: JSON.stringify([v6, '2001:db9::/32']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.deepEqual(clear.residualSources, [])
})

test('取消信任写后核对：详情或名单失败是状态未知，不得回退写前快照报成功', () => {
  assert.equal(classifyTrustRemovalVerification({ detailLoaded: false, missingListIds: [], residualSources: [] }), 'unknown')
  assert.equal(classifyTrustRemovalVerification({ detailLoaded: true, missingListIds: [7], residualSources: [] }), 'unknown')
  assert.equal(classifyTrustRemovalVerification({ detailLoaded: false, missingListIds: [], residualSources: ['写入前快照'] }), 'unknown')
  assert.equal(classifyTrustRemovalVerification({ detailLoaded: true, missingListIds: [], residualSources: [] }), 'cleared')
  assert.equal(classifyTrustRemovalVerification({ detailLoaded: true, missingListIds: [], residualSources: ['引用列表 CIDR'] }), 'residual')

})

// 跨策略信任豁免的候选策略判定：事件详情端点不过滤 enabled——属主
// 策略可能事后被禁用，禁用策略不渲染、不可能放行，不得参与「由某策略信任名单
// 放行」的归因。语义按 trustHitMode：非阶段 0 存量信任引擎恒 DetectionOnly，
// 即使 trust_detection=false 也可解释 logged 事件。
// 谓词归属 securityStages.ts，基础语义（stage0 直通不参与 / 非阶段 0 存量恒参与
// / 禁用策略不参与）由 securityStagesModel.spec.ts 完整覆盖；本文件只保留本模块
// 独有的增量形状：ip_whitelist_enabled=false、stage1 存量、类型缺省。
test('豁免候选的增量形状：信任开关关闭、stage1 存量、类型缺省', () => {
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: false, policy_type: 'stage0', trust_detection: true }), false)
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true, policy_type: 'stage1', trust_detection: false }), true)
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true }), false)
})
