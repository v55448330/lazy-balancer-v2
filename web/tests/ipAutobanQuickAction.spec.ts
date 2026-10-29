import { test } from 'node:test'
import assert from 'node:assert/strict'

import { autobanEntryExpired, autobanEntryRemaining } from '../src/utils/autobanEntry.ts'
import { buildIpQuickModel, type IpQuickList, type IpQuickPolicy } from '../src/utils/ipQuickLists.ts'

const wallClock = (msFromNow: number): string =>
  new Date(Date.now() + msFromNow).toISOString().slice(0, 19).replace('T', ' ')

const policy = (patch: Partial<IpQuickPolicy>): IpQuickPolicy => ({
  id: 1,
  name: '策略',
  policy_type: 'stage1',
  ip_acl_mode: 'deny',
  ip_acl_list: '[]',
  ip_acl_list_refs: '[]',
  ip_whitelist: '[]',
  ip_whitelist_refs: '[]',
  ...patch,
})
const list = (patch: Partial<IpQuickList>): IpQuickList => ({
  id: 10,
  name: '名单',
  entry_count: 1,
  ref_policies: [],
  ...patch,
})

test('自动封禁到期与剩余时间使用真实到期语义', () => {
  assert.equal(autobanEntryExpired(wallClock(3 * 3600_000)), false)
  assert.equal(autobanEntryExpired(wallClock(-60_000)), true)
  assert.equal(autobanEntryExpired(''), false)
  assert.equal(autobanEntryExpired('not-a-timestamp'), false)
  assert.match(autobanEntryRemaining(wallClock(3 * 3600_000 + 60_000)), /^\d+ 小时 \d+ 分$/)
  assert.equal(autobanEntryRemaining(wallClock(-5 * 60_000)), '0 分钟')
})

test('同一 IP 的黑、白、信任成员关系相互独立', () => {
  const policies = [
    policy({ id: 1, name: '黑名单策略', ip_acl_mode: 'deny', ip_acl_list_refs: '[10]' }),
    policy({ id: 2, name: '白名单策略', ip_acl_mode: 'allow', ip_acl_list_refs: '[11]' }),
    policy({ id: 3, name: '信任策略', policy_type: 'stage0', ip_whitelist_refs: '[12]' }),
  ]
  const lists = [list({ id: 10, name: '黑名单 A' }), list({ id: 11, name: '白名单 A' }), list({ id: 12, name: '信任 A' })]
  const model = buildIpQuickModel('203.0.113.7', policies, lists, {
    10: ['203.0.113.7'], 11: ['203.0.113.7'], 12: ['203.0.113.7'],
  })
  assert.equal(model.deny.sources[0].name, '黑名单 A')
  assert.equal(model.allow.sources[0].name, '白名单 A')
  assert.equal(model.trust.sources[0].name, '信任 A')
  assert.equal(model.deny.targets.length, 0)
  assert.equal(model.allow.targets.length, 0)
  assert.equal(model.trust.targets.length, 0)
})

test('名单成员事实不依赖策略开关或规则上下文', () => {
  const model = buildIpQuickModel('::1', [policy({ ip_acl_list: '["::1"]' })], [], {})
  assert.equal(model.deny.sources.length, 1)
  assert.equal(model.deny.sources[0].kind, 'inline')
  assert.equal(model.deny.sources[0].exact, true)
})

test('CIDR 命中只产生编辑源，不产生精确移除或重复添加目标', () => {
  const policies = [policy({ ip_acl_list_refs: '[10]' })]
  const model = buildIpQuickModel('10.1.2.3', policies, [list({ id: 10 })], { 10: ['10.0.0.0/8'] })
  assert.equal(model.deny.sources[0].exact, false)
  assert.equal(model.deny.sources[0].matchedEntry, '10.0.0.0/8')
  assert.equal(model.deny.targets.length, 0)
})

test('同一共享名单被多个策略引用时来源与目标均按名单去重', () => {
  const policies = [
    policy({ id: 1, name: '策略 A', ip_acl_list_refs: '[10]' }),
    policy({ id: 2, name: '策略 B', ip_acl_list_refs: '[10]' }),
  ]
  const lists = [list({ id: 10, ref_policies: [{ id: 1, name: '策略 A' }, { id: 2, name: '策略 B' }] })]
  const missing = buildIpQuickModel('203.0.113.7', policies, lists, { 10: [] })
  assert.equal(missing.deny.targets.length, 1)
  assert.equal(missing.deny.targets[0].policies.length, 2)
  const hit = buildIpQuickModel('203.0.113.7', policies, lists, { 10: ['203.0.113.7'] })
  assert.equal(hit.deny.sources.length, 1)
  assert.equal(hit.deny.sources[0].policies.length, 2)
})

test('系统名单不成为快捷写入目标；无引用名单时保留新建并关联出口', () => {
  const policies = [
    policy({ id: 1, ip_acl_list_refs: '[10]' }),
    policy({ id: 2, name: '空策略', ip_acl_list_refs: '[]' }),
  ]
  const model = buildIpQuickModel('203.0.113.7', policies, [list({ id: 10, system: true })], {})
  assert.equal(model.deny.targets.length, 2)
  assert.ok(model.deny.targets.every((target) => target.kind === 'policy'))
})

test('多个候选目标全部保留，由组件要求用户显式选择', () => {
  const policies = [policy({ ip_acl_list_refs: '[10,11]' })]
  const model = buildIpQuickModel('203.0.113.7', policies, [list({ id: 10, name: 'A' }), list({ id: 11, name: 'B' })], { 10: [], 11: [] })
  assert.deepEqual(model.deny.targets.map((target) => target.name), ['A', 'B'])
})

// 混合策略（兼容旧版的存量组）与「摘要缺 policy_type」是既有库里的真实形态：
// 两侧判定一旦丢掉 mixed/缺省分支，这些策略在弹框里既不显示已存在来源、也不给
// 任何可点目标——用户会以为该 IP 不在任何 ACL 里。
test('混合策略：ACL 两侧与信任侧都参与来源与目标', () => {
  const policies = [policy({
    name: '混合策略',
    policy_type: 'mixed',
    ip_acl_mode: 'deny',
    ip_acl_list: '["203.0.113.7"]',
    ip_acl_list_refs: '[10]',
    ip_whitelist: '[]',
    ip_whitelist_refs: '[12]',
  })]
  const lists = [list({ id: 10, name: '黑名单 A' }), list({ id: 12, name: '信任 A', entry_count: 3 })]
  const model = buildIpQuickModel('203.0.113.7', policies, lists, { 10: [], 12: [] })
  assert.deepEqual(model.deny.sources.map((source) => source.kind), ['inline'], '混合策略的 ACL 内联精确条目必须显示为来源')
  assert.deepEqual(model.deny.targets.map((target) => target.name), ['黑名单 A'], '未命中的引用名单必须是可加入目标')
  assert.deepEqual(model.trust.targets.map((target) => target.name), ['信任 A'], '混合策略的信任侧同理由信任名单承接')
  // allow 侧不参与：ip_acl_mode=deny 的单侧语义对混合策略同样成立
  assert.deepEqual(model.allow.sources, [])
  assert.deepEqual(model.allow.targets, [])
})

test('策略类型缺省（精简载荷）：按混合口径同时支持 ACL 与信任侧', () => {
  const policies = [
    policy({ id: 7, name: '缺省类型（ACL）', policy_type: undefined, ip_acl_mode: 'deny', ip_acl_list_refs: '[10]' }),
    policy({ id: 8, name: '缺省类型（信任）', policy_type: undefined, ip_whitelist_refs: '[12]' }),
  ]
  const model = buildIpQuickModel('203.0.113.7', policies, [list({ id: 10, name: '黑名单 A' }), list({ id: 12, name: '信任 A' })], { 10: [], 12: [] })
  // 两侧都要出现「加入既有名单」入口（只剩「新建名单」出口说明该侧被判为不支持）
  assert.ok(
    model.deny.targets.some((target) => target.kind === 'list' && target.name === '黑名单 A'),
    '缺省类型不得把 ACL 侧判为「不支持」',
  )
  assert.ok(
    model.trust.targets.some((target) => target.kind === 'list' && target.name === '信任 A'),
    '缺省类型不得把信任侧判为「不支持」',
  )
})

test('目标排序：名单入口在前、策略出口在后（同类按名称）', () => {
  // 一个可写名单 + 一条无可写引用的策略（出「新建名单」出口）：list 必须排在前，
  // 否则用户在高亮处看到的是「新建名单」而不是已有的同名名单。
  // 顺序刻意让「新建名单」出口先入表：不排序时它会排在名单前面。
  const policies = [
    policy({ id: 2, name: '乙', ip_acl_list_refs: '[]' }),
    policy({ id: 1, name: '甲', ip_acl_list_refs: '[10]' }),
  ]
  const model = buildIpQuickModel('203.0.113.7', policies, [list({ id: 10, name: 'Z 名单' })], { 10: [] })
  assert.deepEqual(model.deny.targets.map((target) => target.kind), ['list', 'policy'])
  assert.equal(model.deny.targets[0].name, 'Z 名单')
})
