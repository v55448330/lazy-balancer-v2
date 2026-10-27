// 阶段投影与 CIDR 匹配行为验收
//   阶段 2 拦截页失效必须显性（回落默认 429），不得静默省略
//   ACL 内容门口径（与后端摘要 has_ip_control 分层，禁止统一）
//   IPv6 CIDR 命中（命中定位 / 残余信任判定）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  aclAssociateSides,
  attachStageDetails,
  blockPageStageCanIntercept,
  addressAllowDenyConflictText,
  buildStageModel,
  customRuleCanBlockInMode,
  entryMatchesIp,
  ensureSharedEntries,
  eventDetailRefIds,
  extractCrsRuleSnippet,
  formatAclModeDetail,
  hasIPACLControl,
  hasTrustDetectionBinding,
  inferPolicyType,
  invalidateSharedEntriesCache,
  isTrustExemptionCandidate,
  isWafDurationFamily,
  missingSharedEntryIds,
  pickDefaultPolicyTab,
  triggerStageFamily,
  trustHitMode,
  type SecurityStageBinding,
  type SecurityStageBlockPage,
  type SecurityStageIPList,
  type SecurityStagePolicy,
  type StageDetailSources,
} from '../src/utils/securityStages.ts'
import { trustEnabledForPolicyType } from '../src/utils/policyPayload.ts'
import { code, section } from './_helpers.ts'

const policyOf = (overrides: Partial<SecurityStagePolicy> = {}): SecurityStagePolicy => ({
  id: 1,
  name: '策略 A',
  mode: 'off',
  enabled: true,
  has_ip_control: false,
  has_rate_limit: false,
  has_geoip: false,
  has_custom_rules: false,
  geoip_countries: '[]',
  custom_rules_count: 0,
  ip_acl_mode: 'deny',
  ip_acl_list: '[]',
  ip_whitelist: '[]',
  rate_limit_rps: 10,
  rate_limit_burst: 20,
  ...overrides,
})

const bindingOf = (overrides: Partial<SecurityStageBinding> = {}): SecurityStageBinding => ({
  policy_id: 1,
  name: '策略 A',
  mode: 'off',
  enabled: true,
  rate_limit_enabled: true,
  ...overrides,
})

const stageRows = (
  binding: SecurityStageBinding,
  policy: SecurityStagePolicy,
  blockPages: readonly SecurityStageBlockPage[],
  stageIndex: 0 | 1 | 2 | 3,
): Array<{ label: string; detail: string }> => buildStageModel([binding], [policy], [], blockPages).stages[stageIndex].groups[0]?.rows ?? []

test('阶段 2：拦截页已删/内容空时显性给出失效回落（不再静默省略该行）', () => {
  const policy = policyOf({ has_rate_limit: true, block_page_id: 0 })
  // 页已删：binding/策略仍指向 #9，但页面列表里没有它
  const deleted = stageRows(bindingOf({ block_page_id: 9 }), policy, [], 2)
  assert.deepEqual(deleted.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '已失效（回落绑定链首个有效页，无则默认 429）',
  })
  // 内容为空：同样视为失效
  const empty = stageRows(bindingOf({ block_page_id: 9 }), policy, [{ id: 9, name: '限流页', content: '' }], 2)
  assert.deepEqual(empty.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '已失效（回落绑定链首个有效页，无则默认 429）',
  })
  // 有效页：保留页名 + 429 语义
  const valid = stageRows(bindingOf({ block_page_id: 9 }), policy, [{ id: 9, name: '限流页', content: '<p>x</p>' }], 2)
  assert.deepEqual(valid.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '限流页（429 时渲染）',
  })
  // 未配置（0）：不虚增行（与阶段 1/3 的「未配置」口径一致——阶段 2 只呈现已配置）
  const unset = stageRows(bindingOf({ block_page_id: 0 }), policy, [], 2)
  assert.equal(unset.some((row) => row.label === '拦截页（策略页）'), false)
})

test('ACL 内容门：启用但名单空不记账为阶段 1 能力（摘要展示另走 has_ip_control）', () => {
  // 启用 ∧ 空名单：内容门 false（无 ACL 渲染产物）；摘要标志虽为 true 也不得用于阶段出组
  const enabledEmpty = policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '[]', ip_acl_list_refs: '[]', ip_blacklist: '[]' })
  assert.equal(hasIPACLControl(enabledEmpty), false)
  assert.equal(inferPolicyType(enabledEmpty), 'stage3')
  assert.equal(buildStageModel([bindingOf()], [enabledEmpty], [], []).stages[1].groups.length, 0, '阶段 1 不虚增空组')

  // 启用 ∧ 内联非空 → true
  assert.equal(hasIPACLControl(policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '["10.0.0.0/8"]' })), true)
  // 启用 ∧ 仅引用非空 → true
  assert.equal(hasIPACLControl(policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '[]', ip_acl_list_refs: '[3]' })), true)
  // 遗留黑名单非空（未启用 ACL 开关）→ true
  assert.equal(hasIPACLControl(policyOf({ has_ip_control: true, ip_acl_enabled: false, ip_blacklist: '["1.2.3.4"]' })), true)
  // 原始字段缺失（精简绑定载荷）→ 回退摘要标志
  assert.equal(hasIPACLControl({ has_ip_control: true }), true)
  assert.equal(hasIPACLControl({ has_ip_control: false }), false)
})

test('IPv6 CIDR：前缀位匹配生效且只作用于同族', () => {
  // v6 /32
  assert.equal(entryMatchesIp('2001:db8::/32', '2001:db8:1234::1'), true)
  assert.equal(entryMatchesIp('2001:db8::/32', '2001:db9::1'), false)
  // /128 精确前缀
  assert.equal(entryMatchesIp('2001:db8::1/128', '2001:db8::1'), true)
  assert.equal(entryMatchesIp('2001:db8::1/128', '2001:db8::2'), false)
  // /0 全匹配（v6 条目对 v6 地址）
  assert.equal(entryMatchesIp('::/0', '2001:db8::1'), true)
  // '::' 压缩尾与嵌入 IPv4 尾
  assert.equal(entryMatchesIp('fe80::/10', 'fe80::abc'), true)
  assert.equal(entryMatchesIp('::ffff:192.168.0.0/112', '::ffff:192.168.3.4'), true)
  assert.equal(entryMatchesIp('::ffff:192.168.0.0/112', '::ffff:192.169.3.4'), false)
  // 族隔离：v4 地址不得命中 v6 CIDR，反之亦然
  assert.equal(entryMatchesIp('::/0', '192.168.1.1'), false)
  assert.equal(entryMatchesIp('0.0.0.0/0', '2001:db8::1'), false)
  // 非法形态不误判
  assert.equal(entryMatchesIp('2001:db8::/129', '2001:db8::1'), false)
  assert.equal(entryMatchesIp('1::2::3/64', '1::2'), false)
  assert.equal(entryMatchesIp('gggg::/16', 'gggg::1'), false)
  // 既有 IPv4 语义不回归
  assert.equal(entryMatchesIp('203.0.113.0/24', '203.0.113.7'), true)
  assert.equal(entryMatchesIp('203.0.113.0/24', '203.0.114.7'), false)
  // 精确条目（无 /）仍按串相等
  assert.equal(entryMatchesIp('2001:db8::1', '2001:db8::1'), true)
})

// IP 快捷处置动作的模式门控——
// ip_acl_list_refs 是黑/白共用字段：名单本身无黑白属性，语义由 ip_acl_mode
// 决定（渲染只对 allow/deny 发射拒绝规则；绕过=免检测、空模式不发射）。
// 同一字段上同时给「拦截」「放行」两个动作会在模式生效后反转用户意图。
test('ACL 加入动作：deny 只给拦截、allow 只给放行，绕过/空/未知不给动作', () => {
  assert.deepEqual(aclAssociateSides('deny'), { deny: true, allow: false })
  assert.deepEqual(aclAssociateSides('allow'), { deny: false, allow: true })
  assert.deepEqual(aclAssociateSides('绕过'), { deny: false, allow: false })
  assert.deepEqual(aclAssociateSides(''), { deny: false, allow: false })
  assert.deepEqual(aclAssociateSides(undefined), { deny: false, allow: false })
})

test('ACL 加入动作：任何模式都不得同时提供拦截与放行', () => {
  for (const mode of ['deny', 'allow', '绕过', '', 'weird', undefined]) {
    const sides = aclAssociateSides(mode)
    assert.ok(!(sides.deny && sides.allow), `模式 ${String(mode)} 同时提供了拦截与放行`)
  }
})

// 事件详情预取名单集合——
// 详情弹框只消费「属主策略 ACL refs（命中列表/内联判定）+ 全部信任 refs
// （跨策略信任豁免）」；他策略 ACL 名单零消费，并入会在他策略引用大名单
// （内置威胁名单可达上万条）时全量下载。
test('事件详情预取：属主 ACL ∪ 全部信任，不含他策略 ACL', () => {
  const own = { ip_acl_list_refs: '[1,2]', ip_whitelist_refs: '[3]' }
  const others = [
    { ip_acl_list_refs: '[9,10]', ip_whitelist_refs: '[3,4]' },
    { ip_acl_list_refs: '[11]', ip_whitelist_refs: '[5]' },
  ]
  assert.deepEqual(eventDetailRefIds(own, others), [1, 2, 3, 4, 5])
  assert.ok(!eventDetailRefIds(own, others).includes(9))
})

test('事件详情预取：无属主策略时仅取信任 refs；去重保序并丢弃非法 id', () => {
  assert.deepEqual(eventDetailRefIds(null, [{ ip_whitelist_refs: '[7]' }, { ip_whitelist_refs: '[7,8]' }]), [7, 8])
  assert.deepEqual(eventDetailRefIds({ ip_acl_list_refs: '[0,6,6,2]', ip_whitelist_refs: '[]' }, []), [6, 2])
  assert.deepEqual(eventDetailRefIds(null, []), [])
})

test('拦截页回落文案：失效策略页不得断言「回落默认 403」（真实回落取绑定链首个有效页）', () => {
  const stage1 = stageRows(bindingOf(), policyOf({ block_page_id: 9 }), [], 1)
  assert.deepEqual(stage1.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '已失效（回落绑定链首个有效页）',
  })
  // 阶段 3 同口径：逐策略合成码，页失效时回落同为绑定链首个有效页
  // （无规则级覆盖时行标签为「拦截页」）
  const stage3 = stageRows(bindingOf({ block_page_id: 9 }), policyOf({ mode: 'blocking' }), [], 3)
  assert.equal(stage3.find((row) => row.label === '拦截页')?.detail, '已失效（回落绑定链首个有效页）')
  // 未配置：跟随绑定链首个有效页，无则默认 403
  const unset = stageRows(bindingOf({ block_page_id: 0 }), policyOf({ mode: 'blocking' }), [], 3)
  assert.equal(unset.find((row) => row.label === '拦截页')?.detail, '未配置（跟随绑定链首个有效页，无则默认 403）')
})

test('ACL 摘要：有名单但模式为空/未知时显示「未配置模式」而非「黑名单模式」', () => {
  const two = { ip_acl_list: '["1.1.1.1","2.2.2.2"]', ip_blacklist: '[]' }
  // 目标形状：空模式/未知模式——名单存在但 ACL 不发射拒绝规则
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: '' }), '未配置模式 · 2 条')
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: 'unknown-x' }), '未配置模式 · 2 条')
  // 畸形形状：空模式 + 独立黑名单——独立黑名单无模式门，仍须追告生效
  assert.equal(
    formatAclModeDetail([], { ip_acl_mode: '', ip_acl_list: '["1.1.1.1"]', ip_blacklist: '["3.3.3.3"]' }),
    '未配置模式 · 1 条；独立黑名单 1 条仍生效',
  )
  // 回归形状：allow/绕过/deny 既有分支不动
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: 'allow' }), '白名单模式 · 2 条')
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: '绕过' }), '免检测模式 · 2 条')
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: 'deny' }), '黑名单模式 · 2 条')
  // 回归形状：deny 含独立黑名单的合并文案
  assert.equal(
    formatAclModeDetail([], { ip_acl_mode: 'deny', ip_acl_list: '["1.1.1.1"]', ip_blacklist: '["3.3.3.3"]' }),
    '黑名单模式 · 2 条（名单 1 + 独立 1）',
  )
})

test('白名单空生效集必须显性警示「将拒绝所有请求」', () => {
  // 引擎 allow 空集发射否定算子＝恒拒（带外直写/旧快照可达）
  assert.equal(formatAclModeDetail([], { ip_acl_mode: 'allow', ip_acl_list: '[]', ip_blacklist: '[]' }), '白名单模式 · 0 条（将拒绝所有请求）')
  // 有条目/其他模式不追加警示（回归形状）
  assert.equal(formatAclModeDetail([], { ip_acl_mode: 'allow', ip_acl_list: '["1.1.1.1"]' }), '白名单模式 · 1 条')
  assert.equal(formatAclModeDetail([], { ip_acl_mode: 'deny', ip_acl_list: '[]' }), '黑名单模式 · 0 条')
})

test('白名单零生效集：ACL 关闭时不得误报「将拒绝所有请求」，独立黑名单追告不得丢失', () => {
  // ACL 关闭（保留名单）：渲染侧不进入 ACL 发射块（security.go 的
  // IPACLEnabled 门）——「空 allow 集恒拒」不成立，告警在此形态是误报。
  assert.equal(
    formatAclModeDetail([], { ip_acl_enabled: false, ip_acl_mode: 'allow', ip_acl_list: '["1.1.1.1"]', ip_blacklist: '[]' }),
    '白名单模式 · 未启用 ACL',
  )
  // 零生效集告警必须与「独立黑名单仍生效」并存：两条结论缺一都会误导
  assert.equal(
    formatAclModeDetail([], { ip_acl_mode: 'allow', ip_acl_list: '[]', ip_blacklist: '["1.1.1.1"]' }),
    '白名单模式 · 0 条（将拒绝所有请求）；独立黑名单 1 条仍生效',
  )
  // ACL 关闭 + 独立黑名单：无恒拒告警，黑名单仍须追告
  assert.equal(
    formatAclModeDetail([], { ip_acl_enabled: false, ip_acl_mode: 'allow', ip_acl_list: '["1.1.1.1"]', ip_blacklist: '["2.2.2.2"]' }),
    '白名单模式 · 未启用 ACL；独立黑名单 1 条仍生效',
  )
  // 回归：显式开启的空集仍须告警
  assert.equal(formatAclModeDetail([], { ip_acl_enabled: true, ip_acl_mode: 'allow', ip_acl_list: '[]' }), '白名单模式 · 0 条（将拒绝所有请求）')
})

test('缺失名单条目判定单源：只报未缓存的正 id（静默失败的唯一可见信号）', async () => {
  // 经生产写入口落地（writeSharedEntries 记录加载时刻）——直接写 sharedEntriesCache
  // 没有加载时刻，按 TTL 契约本就该被判为陈旧，自写自断言会失去鉴别力。
  invalidateSharedEntriesCache()
  try {
    await ensureSharedEntries([7], async () => ['1.1.1.1'])
    assert.deepEqual(missingSharedEntryIds([7, 8, 8, 0, -3]), [8], '已缓存/非正 id 不得计入缺失')
    assert.deepEqual(missingSharedEntryIds([]), [])
  } finally {
    invalidateSharedEntriesCache()
  }
})

test('阶段可拦截能力门：stage3 关模式/检测无 block 规则、stage1 无能力均不得宣称生效', () => {
  // 阶段 2 恒可（429 归因另由绑定链限流门控）
  assert.equal(blockPageStageCanIntercept({ stage: 2 }), true)
  // 阶段 3：off 恒 false；blocking 恒 true；detection/custom_only 仅 block 自定义规则
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'off', hasBlockingCustomRule: true }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'blocking' }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'detection' }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'detection', hasBlockingCustomRule: true }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'custom_only' }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'custom_only', hasBlockingCustomRule: true }), true)
  // 阶段 1：ACL/独立黑名单/地域任一成立
  assert.equal(blockPageStageCanIntercept({ stage: 1 }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 1, hasAclEntries: true }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 1, hasBlacklistEntries: true }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 1, hasGeoip: true }), true)
})

test('检测模式拦截页能力：body 规则只记录，URI 规则仍可拦截，其他模式不受相位限制', () => {
  const body = { id: 1, name: 'body', action: 'block', enabled: true, conditions: [{ target: 'body' }] }
  const uri = { id: 2, name: 'uri', action: 'block', enabled: true, conditions: [{ target: 'uri' }] }
  const mixed = { id: 3, name: 'mixed', action: 'block', enabled: true, conditions: [{ target: 'uri' }, { target: 'body' }] }
  assert.equal(customRuleCanBlockInMode('detection', body), false)
  assert.equal(customRuleCanBlockInMode('detection', uri), true)
  assert.equal(customRuleCanBlockInMode('detection', mixed), false, '任一 body 条件会把整条规则归入 phase 2')
  assert.equal(customRuleCanBlockInMode('detection', { ...uri, conditions: undefined }), true, '缺省条件按无 body 条件处理')
  assert.equal(customRuleCanBlockInMode('custom_only', body), true)
  assert.equal(customRuleCanBlockInMode('blocking', body), true)
  assert.equal(customRuleCanBlockInMode('detection', { ...uri, enabled: false }), false)
  assert.equal(customRuleCanBlockInMode('detection', { ...uri, action: 'pass' }), false)

  const notes = section(code('src/views/security/SecurityPolicies.vue'), 'const blockPageNotes = ', 'const boundRuleRows = computed')
  assert.match(notes, /customRuleCanBlockInMode\(form\.value\.mode, rule\)/, '视图能力门必须消费相位感知谓词')
})

test('地址冲突语义：阶段 0 信任跨策略优先，ACL 与存量信任仍只豁免所属策略', () => {
  assert.equal(addressAllowDenyConflictText({ kind: 'acl', denyPolicyName: '拒绝策略' }), '允许不跨策略生效，该地址仍会被「拒绝策略」拦截')
  assert.equal(addressAllowDenyConflictText({ kind: 'trust', policyType: 'mixed', denyPolicyName: '拒绝策略' }), '信任不跨策略生效，该地址仍会被「拒绝策略」拦截')
  const passthrough = addressAllowDenyConflictText({ kind: 'trust', policyType: 'stage0', trustDetection: false, denyPolicyName: '拒绝策略' })
  assert.equal(passthrough, '阶段 0 信任跨策略优先生效：直通模式跳过全部安全检测')
  const detection = addressAllowDenyConflictText({ kind: 'trust', policyType: 'stage0', trustDetection: true, denyPolicyName: '拒绝策略' })
  assert.equal(detection, '阶段 0 信任跨策略优先生效：保留检测模式仅记录、不拦截')
  assert.doesNotMatch(passthrough + detection, /仍会被|信任不跨策略/)

  const page = code('src/views/security/SecurityPolicies.vue')
  const conflicts = section(page, 'const computeBindingConflicts = ', 'const peerPolicyViews = computed')
  const realtime = section(page, 'const aclSectionAlert = computed', 'const whitelistSectionAlert = computed')
  const trust = section(page, 'const whitelistSectionAlert = computed', 'const blockPageBroken = ')
  for (const body of [conflicts, realtime, trust]) {
    assert.match(body, /addressAllowDenyConflictText\(/, '冲突告警必须按 ACL/信任及阶段类型选择真实语义')
  }
  assert.match(conflicts, /ipAclAllowEntries/)
  assert.match(conflicts, /ipTrustEntries/)
  assert.match(realtime, /peer\.trustSet/)
})

test('信任命中语义：非阶段 0 策略恒保留检测（与 trust_detection 无关）', () => {
  assert.equal(trustHitMode('stage0', false), 'passthrough')
  assert.equal(trustHitMode('stage0', true), 'detection')
  assert.equal(trustHitMode('mixed', false), 'detection')
  assert.equal(trustHitMode('stage1', false), 'detection')
  // 类型缺省（精简载荷/旧摘要）回落旧口径
  assert.equal(trustHitMode(undefined, false), 'passthrough')
  assert.equal(trustHitMode(undefined, true), 'detection')
})

test('阶段 0 投影：非阶段 0 策略的存量信任显示保留检测', () => {
  const mixed = policyOf({ policy_type: 'mixed', ip_whitelist: '["1.1.1.1"]', trust_detection: false })
  const rows = stageRows(bindingOf(), mixed, [], 0)
  assert.equal(rows.find((row) => row.label === '模式')?.detail, '保留检测记录（事件动作=检测）')
  const stage0 = policyOf({ policy_type: 'stage0', ip_whitelist: '["1.1.1.1"]', trust_detection: false })
  const stage0Rows = stageRows(bindingOf(), stage0, [], 0)
  assert.equal(stage0Rows.find((row) => row.label === '模式')?.detail, '直通上游（不产生安全事件）')
})

test('豁免候选：非阶段 0 存量信任（trust_detection=false）参与归因，阶段 0 直通不参与', () => {
  const base = { enabled: true, ip_whitelist_enabled: true }
  assert.equal(isTrustExemptionCandidate({ ...base, policy_type: 'mixed', trust_detection: false }), true)
  assert.equal(isTrustExemptionCandidate({ ...base, policy_type: 'stage0', trust_detection: false }), false)
  assert.equal(isTrustExemptionCandidate({ ...base, policy_type: 'stage0', trust_detection: true }), true)
  assert.equal(isTrustExemptionCandidate({ ...base, enabled: false, policy_type: 'mixed' }), false)
})

test('事件详情预取按类别/动作收窄：WAF 已拦截事件不取 ACL/信任引用', () => {
  const own = { ip_acl_list_refs: '[1,2]', ip_whitelist_refs: '[3]' }
  const others = [{ ip_whitelist_refs: '[4]' }]
  // 省略 scope = 全集（既有调用口径不变）
  assert.deepEqual(eventDetailRefIds(own, others), [1, 2, 3, 4])
  // WAF 拦截事件：三类全关（只保留名单名称查询，不下载条目）
  assert.deepEqual(eventDetailRefIds(own, others, { ownerAcl: false, ownerTrust: false, otherTrust: false }), [])
  // IP 类拦截事件：仍需属主 ACL 条目，无需信任/跨策略豁免
  assert.deepEqual(eventDetailRefIds(own, others, { ownerAcl: true, ownerTrust: false, otherTrust: false }), [1, 2])
  // 未拦截事件的豁免归因：属主 + 他策略信任，不含属主 ACL
  assert.deepEqual(eventDetailRefIds(own, others, { ownerAcl: false, ownerTrust: true, otherTrust: true }), [3, 4])
})

// 阶段 1 明细 vs 摘要对账：摘要对非 deny 模式提示「独立黑名单 N 条仍生效」，
// 明细模型必须同时给出这些条目，否则排障时摘要报数、明细无据可查。
test('阶段 1 明细：独立黑名单逐条可对账，且不受 ACL 开关门控', () => {
  // non-deny 模式：摘要强调「独立黑名单 N 条仍生效」，明细必须给出同一批条目
  const policy = policyOf({
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: true,
    ip_acl_mode: 'allow',
    ip_acl_list: '["10.0.0.0/8"]',
    ip_blacklist: '["1.2.3.4"," 5.6.7.8 "]',
  })
  assert.match(formatAclModeDetail([], policy), /；独立黑名单 2 条仍生效/)
  const details = attachStageDetails(
    buildStageModel([bindingOf()], [policy], [], []),
    { policies: [policy], ipLists: [] },
  ).stages[1].groups[0]?.details
  assert.deepEqual(details?.blacklistEntries, ['1.2.3.4', '5.6.7.8'], '独立黑名单必须去重去空后逐条进入明细')
  assert.equal(details?.aclInlineCount, 1)

  // ACL 关闭（保留名单）：内联 ACL 明细按开关门省略，独立黑名单不受该门控
  const disabled = policyOf({
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: false,
    ip_acl_mode: '绕过',
    ip_acl_list: '["10.0.0.0/8"]',
    ip_blacklist: '["1.2.3.4","5.6.7.8"]',
  })
  assert.match(formatAclModeDetail([], disabled), /；独立黑名单 2 条仍生效/)
  const disabledDetails = attachStageDetails(
    buildStageModel([bindingOf()], [disabled], [], []),
    { policies: [disabled], ipLists: [] },
  ).stages[1].groups[0]?.details
  assert.deepEqual(disabledDetails?.blacklistEntries, ['1.2.3.4', '5.6.7.8'])
  assert.equal(disabledDetails?.aclInlineCount, undefined)

  // deny 模式：黑名单计入生效集，明细同样逐条（不因模式变化而丢失）
  const deny = policyOf({
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: true,
    ip_acl_mode: 'deny',
    ip_acl_list: '["10.0.0.0/8"]',
    ip_blacklist: '["1.2.3.4"]',
  })
  const denyDetails = attachStageDetails(
    buildStageModel([bindingOf()], [deny], [], []),
    { policies: [deny], ipLists: [] },
  ).stages[1].groups[0]?.details
  assert.deepEqual(denyDetails?.blacklistEntries, ['1.2.3.4'])
  assert.equal(denyDetails?.aclInlineCount, 1)
})

// WAF 耗时族：加和式（duration_us + precheck_us）只对 WAF 段独立计时的族成立；
// 预检族 duration_us 恒等于 precheck_us，加和会翻倍。全仓单源谓词。
test('WAF 耗时族谓词：wafCrs/wafCustom/body 加和，预检族与未知不入族', () => {
  for (const id of ['942100', '959999', '100123', '1500000', '11']) {
    assert.equal(isWafDurationFamily(triggerStageFamily(id)), true, `id ${id} 应属 WAF 耗时族`)
  }
  for (const id of ['2', '3', '4', '7', '12', '14', '800123', '850123', '810123', '', 'not-a-rule']) {
    assert.equal(isWafDurationFamily(triggerStageFamily(id)), false, `id ${id} 不应属 WAF 耗时族`)
  }
  // 与检测模式归因族的集合差异：body 加和但不由检测模式解释
  assert.equal(isWafDurationFamily('body'), true)
})

// CRS 源码片段定位：`id:942100` 是 `id:9421000` 的子串，纯 includes 会把片段
// 中心落到更长的 ID 行。边界匹配后片段必须落在精确 ID 行。
test('CRS 源码片段按 ID 边界定位（短 ID 不命中更长的 ID 行）', () => {
  const content = [
    'SecRule ARGS "@rx a" "id:9421000,phase:2,deny"',
    'SecRule ARGS "@rx b" "id:942100,phase:2,deny"', // 目标行（idx 1）
    'SecRule ARGS "@rx c" "id:942101,phase:2,deny"',
  ].join('\n')
  assert.equal(
    extractCrsRuleSnippet(content, '942100', 0),
    'SecRule ARGS "@rx b" "id:942100,phase:2,deny"',
  )
  // 上下文窗口 ±1 行
  assert.equal(extractCrsRuleSnippet(content, '942100', 1).split('\n').length, 3)
  // 引号/空格形态同样命中
  assert.equal(extractCrsRuleSnippet(`id:'942102'`, '942102', 0), `id:'942102'`)
  assert.equal(extractCrsRuleSnippet('id:"942103"', '942103', 0), 'id:"942103"')
  assert.equal(extractCrsRuleSnippet('id: 942104', '942104', 0), 'id: 942104')
  // 孤儿前缀（仅更长的 ID 存在）不得误命中
  assert.equal(extractCrsRuleSnippet('id:9421000', '942100', 0), '')
  // 非法/空输入
  assert.equal(extractCrsRuleSnippet(content, '', 0), '')
  assert.equal(extractCrsRuleSnippet('', '942100', 0), '')
})


// 禁用规则的锁摘要/流程必须显式降级：enabled=0 时控制面不渲染任何路由，
// 安全链不进入运行配置——阶段模型必须携带 ruleDisabled，消费方据此灰锁 +
// 顶部禁用横幅（否则巡检得到「四阶段在位」的高估结论）。
test('禁用规则：阶段模型携带 ruleDisabled 且不影响阶段内容', () => {
  const policy = policyOf({ policy_type: 'stage1', has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '["10.0.0.0/8"]' })
  const binding = bindingOf()
  const enabledModel = buildStageModel([binding], [policy], [], [], null, true)
  assert.equal(enabledModel.ruleDisabled, false)
  const disabledModel = buildStageModel([binding], [policy], [], [], null, false)
  assert.equal(disabledModel.ruleDisabled, true)
  // 绑定与阶段页保留：阶段内容不因禁用而消失（启用后生效的「保留配置」口径）
  assert.equal(disabledModel.hasAnyPolicy, true)
  assert.deepEqual(
    disabledModel.stages.map((stage) => stage.groups.length),
    enabledModel.stages.map((stage) => stage.groups.length),
  )
  // 缺省（未知态）不得宣称已禁用
  assert.equal(buildStageModel([binding], [policy], [], []).ruleDisabled, false)
})

test('阶段 0：绑定链存在阶段 0 策略即启用，名单空出灰态行（内容门不得冒充未启用）', () => {
  // 只能经 API/带外导入形成「阶段 0 策略 + 空信任名单」：原实现按内容门过滤，
  // 流程弹框/锁摘要会显示「阶段 0 未启用」，与绑定链事实相反。
  const emptyTrust = policyOf({ policy_type: 'stage0', ip_whitelist: '[]', ip_whitelist_refs: '[]' })
  const model = buildStageModel([bindingOf()], [emptyTrust], [], [])
  assert.equal(model.stages[0].enabled, true)
  assert.deepEqual(model.stages[0].groups[0]?.rows.map((row) => [row.label, row.detail]), [
    ['信任名单', '未配置'],
    ['模式', '直通上游（不产生安全事件）'],
  ])
  // 无阶段 0 策略绑定时不得虚增阶段 0 组（默认策略推断为 stage3）
  assert.equal(buildStageModel([bindingOf()], [policyOf()], [], []).stages[0].groups.length, 0)
})

// 规则级阶段拦截页覆盖与多策略绑定链的多组排布：生产主路径
// （Rules.vue 传 stagePages + ruleEnabled）此前只有纯函数级钉，集成层零覆盖，
// 且既有助手固定取 groups[0]——第二组起的标签/顺序缺陷永远隐身。
test('规则级阶段 1 拦截页覆盖：命中/失效/未配三种措辞', () => {
  const pages = [{ id: 5, name: '自定义 403 页', content: '<p>x</p>' }]
  const policy = policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '["10.0.0.0/8"]' })

  const configured = buildStageModel([bindingOf()], [policy], [], pages, {
    block_page_stage1_id: 5,
    block_page_stage1_status: 404,
  })
  assert.deepEqual(configured.stages[1].override, { pageId: 5, pageName: '自定义 403 页', status: 404, broken: false })
  assert.deepEqual(configured.stages[1].groups[0].rows.find((row) => row.label === '拦截页'), {
    label: '拦截页',
    detail: '规则覆盖：自定义 403 页（状态码 404）',
  })

  // 页已删/内容空：override.broken + 失效文案（回落跟随策略）
  const broken = buildStageModel([bindingOf()], [policy], [], pages, { block_page_stage1_id: 99 })
  assert.equal(broken.stages[1].override?.broken, true)
  assert.equal(broken.stages[1].override?.pageName, '页面 #99')
  assert.deepEqual(broken.stages[1].groups[0].rows.find((row) => row.label === '拦截页'), {
    label: '拦截页',
    detail: '已失效（回落跟随策略）',
  })

  // 未配：默认状态码 403 的「未配置」口径
  const unset = buildStageModel([bindingOf()], [policy], [], pages, null)
  assert.equal(unset.stages[1].override, null)
  assert.deepEqual(unset.stages[1].groups[0].rows.find((row) => row.label === '拦截页'), {
    label: '拦截页',
    detail: '未配置（跟随绑定链首个有效页，无则默认 403）',
  })
})

test('规则级阶段 3 覆盖与策略级页并存：规则覆盖行在前、策略页行在后', () => {
  const pages = [
    { id: 7, name: '规则覆盖页', content: '<p>rule</p>' },
    { id: 8, name: '策略页', content: '<p>policy</p>' },
  ]
  const policy = policyOf({ mode: 'blocking' })
  const model = buildStageModel([bindingOf({ block_page_id: 8 })], [policy], [], pages, {
    block_page_stage3_id: 7,
  })
  const rows = model.stages[3].groups[0].rows
  const overrideRow = rows.find((row) => row.label === '拦截页（规则覆盖）')
  const policyRow = rows.find((row) => row.label === '拦截页（策略页）')
  assert.deepEqual(overrideRow, { label: '拦截页（规则覆盖）', detail: '规则覆盖页（状态码 403）' })
  assert.deepEqual(policyRow, { label: '拦截页（策略页）', detail: '策略页（状态码 403）' })
  assert.ok(rows.indexOf(overrideRow!) < rows.indexOf(policyRow!), '规则覆盖行必须在策略页行之前（覆盖优先语义）')
})

test('多策略绑定链：同阶段两条策略出两组且按绑定顺序编号', () => {
  const acl = (id: number, name: string): SecurityStagePolicy =>
    policyOf({ id, name, has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '["10.0.0.0/8"]' })
  const bindings = [bindingOf({ policy_id: 1, name: '策略 A' }), bindingOf({ policy_id: 2, name: '策略 B' })]
  const model = buildStageModel(bindings, [acl(1, '策略 A'), acl(2, '策略 B')], [], [])

  assert.equal(model.stages[1].groups.length, 2, '同阶段两条策略必须各出一组')
  assert.deepEqual(
    model.stages[1].groups.map((group) => ({ key: group.key, order: group.order, name: group.name })),
    [
      { key: 1, order: 1, name: '策略 A' },
      { key: 2, order: 2, name: '策略 B' },
    ],
    '组顺序=绑定链顺序（policy_id ASC），且序号为 1-based',
  )
  // 阶段 0 不在评估链内：无 override 概念，且无阶段 0 策略时为空组集合
  assert.equal(model.stages[0].override, null)
  assert.equal(model.stages[0].enabled, false)
})

test('fs96-01 阶段 1 脚注降级判定：混合策略存量信任同样降级，不得按 policy_type 等值漏判', () => {
  const bound = new Set([1])
  const mixed = policyOf({
    id: 1,
    policy_type: 'mixed',
    ip_whitelist_enabled: true,
    ip_whitelist: '["203.0.113.7"]',
    trust_detection: false,
  })
  // 引擎口径：mixed 存量信任进 id:3 并集（DetectionOnly），与 trust_detection 无关
  assert.equal(hasTrustDetectionBinding(bound, [mixed]), true)
  // 阶段 0 仍按 trust_detection
  assert.equal(hasTrustDetectionBinding(bound, [policyOf({
    id: 1, policy_type: 'stage0', ip_whitelist_enabled: true, ip_whitelist: '["1.1.1.1"]', trust_detection: true,
  })]), true)
  assert.equal(hasTrustDetectionBinding(bound, [policyOf({
    id: 1, policy_type: 'stage0', ip_whitelist_enabled: true, ip_whitelist: '["1.1.1.1"]', trust_detection: false,
  })]), false)
  // 回归形状：未绑定 / 禁用 / 信任关闭 / 空名单 → 不得声称存在降级路径
  assert.equal(hasTrustDetectionBinding(new Set([9]), [mixed]), false)
  assert.equal(hasTrustDetectionBinding(bound, [{ ...mixed, enabled: false }]), false)
  assert.equal(hasTrustDetectionBinding(bound, [{ ...mixed, ip_whitelist_enabled: false }]), false)
  assert.equal(hasTrustDetectionBinding(bound, [{ ...mixed, ip_whitelist: '[]', ip_whitelist_refs: '[]' }]), false)
})

test('fs96-02 信任生效谓词：阶段 0 恒启用（新建态 ipWhitelistEnabled=false 也不得判零生效）', () => {
  assert.equal(trustEnabledForPolicyType('stage0', false), true)
  assert.equal(trustEnabledForPolicyType('stage0', true), true)
  // 其余类型按三态开关
  assert.equal(trustEnabledForPolicyType('stage1', true), true)
  assert.equal(trustEnabledForPolicyType('stage1', false), false)
  assert.equal(trustEnabledForPolicyType('mixed', false), false)
})

test('fs96-05 策略列表默认 tab 选择：第一个非空类型，全空回落阶段 1', () => {
  const counts = (overrides: Partial<Record<'stage0' | 'stage1' | 'stage2' | 'stage3' | 'mixed', number>> = {}) => ({
    stage0: 0, stage1: 0, stage2: 0, stage3: 0, mixed: 0, ...overrides,
  })
  // 只部署阶段 3：不得停在阶段 1 空表
  assert.equal(pickDefaultPolicyTab(counts({ stage3: 2 })), 'stage3')
  // 阶段顺序优先（阶段 0 有条目即优先于阶段 3）
  assert.equal(pickDefaultPolicyTab(counts({ stage0: 1, stage3: 2 })), 'stage0')
  assert.equal(pickDefaultPolicyTab(counts({ stage1: 1, stage2: 3 })), 'stage1')
  // 混合兼容组按阶段顺序排最后
  assert.equal(pickDefaultPolicyTab(counts({ mixed: 4 })), 'mixed')
  // 全空回落到阶段 1（列表初始态）
  assert.equal(pickDefaultPolicyTab(counts()), 'stage1')
})

// ── 阶段抽屉的明细面 ──
// 此前覆盖只到「出组/不出的结构」，用户实际读到的
// 明细行（地域措辞、限流口径、自定义规则 join、CRS 组标签、引用名单名/计数、
// 条目合并去重）与阶段 2/3 的 buildGroupDetails 整块零执行。

const detailsAt = (stageIndex: 0 | 1 | 2 | 3, policy: SecurityStagePolicy, ipLists: SecurityStageIPList[] = [], sources?: StageDetailSources) => {
  const binding = bindingOf({ policy_id: policy.id, mode: policy.mode })
  const model = buildStageModel([binding], [policy], ipLists, [])
  return attachStageDetails(model, { policies: [policy], ipLists, sources }).stages[stageIndex].groups[0]?.details
}

test('明细 · 阶段 1 地域行：启用按模式措辞，关闭但保留区域显性披露', () => {
  const deny = policyOf({ id: 21, has_geoip: true, geoip_mode: 'deny', geoip_countries: '["US","CN"]' })
  assert.deepEqual(
    stageRows(bindingOf({ policy_id: 21 }), deny, [], 1).find((row) => row.label === '地域拦截'),
    { label: '地域拦截', detail: '拦截所选区域 · 2 区域' },
  )
  const allow = policyOf({ id: 21, has_geoip: true, geoip_mode: 'allow', geoip_countries: '["US"]' })
  assert.equal(
    stageRows(bindingOf({ policy_id: 21 }), allow, [], 1).find((row) => row.label === '地域拦截')?.detail,
    '仅允许所选区域 · 1 区域',
  )
  // 关闭但保留区域：不得显示成「0 区域」或干脆不出行（用户看不出保留了什么）
  const retained = policyOf({ id: 21, has_geoip: false, geoip_countries: '["US","JP","KR"]' })
  assert.equal(
    stageRows(bindingOf({ policy_id: 21 }), retained, [], 1).find((row) => row.label === '地域拦截')?.detail,
    '已关闭（保留 3 区域）',
  )
  // 无地域能力且无保留区域 → 阶段 1 不出组
  const none = policyOf({ id: 21, has_geoip: false, geoip_countries: '[]' })
  assert.equal(buildStageModel([bindingOf({ policy_id: 21 })], [none], [], []).stages[1].groups[0], undefined)
})

test('明细 · 阶段 2 限流口径：限流双 zone 口径随 burst 切换', () => {
  const burst = policyOf({ id: 31, has_rate_limit: true, rate_limit_rps: 10, rate_limit_burst: 20 })
  assert.deepEqual(detailsAt(2, burst)?.rateLimit, {
    rps: 10,
    burst: 20,
    caption: '1s 窗口上限 30 次（含突发）· 60s 窗口上限 600 次（持续 10 次/秒）',
  })
  // burst=0：后端只发射单 1s 窗口，文案不得再承诺 60s 窗口
  const noBurst = policyOf({ id: 31, has_rate_limit: true, rate_limit_rps: 10, rate_limit_burst: 0 })
  assert.deepEqual(detailsAt(2, noBurst)?.rateLimit, { rps: 10, burst: 0, caption: '1s 窗口上限 10 次' })
})

test('明细 · 阶段 3 自定义规则与 CRS 组：自定义规则按 id join 规则库、CRS 组标签可回退裸码', () => {
  const policy = policyOf({ id: 41, mode: 'blocking', has_custom_rules: true, custom_rules_count: 3 })
  const sources: StageDetailSources = {
    fullPolicies: new Map([[41, { id: 41, custom_rules: [7, 8, 999], crs_rule_groups: ['42', '55', '99'] }]]),
    customRules: [
      { id: 7, name: 'SQL 注入', action: 'block', conditions: [{ target: 'ARGS' }, { target: 'BODY' }] },
      { id: 8, name: 'XSS', action: 'log', score: 5, enabled: false },
    ],
    crsFiles: [
      { filename: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf', category: 'SQL 注入' },
      { filename: 'RESPONSE-955-WEB-SHELLS.conf', category: 'Web Shells' },
    ],
  }
  const details = detailsAt(3, policy, [], sources)
  // 命中库的行带名称/动作/目标串/启用态；已删除的行（999）显性标注「规则 #id」
  assert.deepEqual(details?.customRules, [
    { id: 7, name: 'SQL 注入', action: 'block', targets: 'ARGS / BODY', score: 0, enabled: true },
    { id: 8, name: 'XSS', action: 'log', targets: '', score: 5, enabled: false },
    { id: 999, name: '规则 #999', action: '-', targets: '', score: 0, enabled: true },
  ])
  assert.deepEqual(details?.crsGroups, ['请求 · 942 · SQL 注入', '响应 · 955 · Web Shells', '99'])
  // 规则文件列表未加载 / 组已消失 → 回退裸组码，不阻断明细区
  const bare = detailsAt(3, policy, [], { fullPolicies: sources.fullPolicies })
  assert.deepEqual(bare?.crsGroups, ['42', '55', '99'])
  // 绑定详情未拉取（无 fullPolicies）→ 明细对象为空，不虚增 customRules/crsGroups 键
  assert.deepEqual(detailsAt(3, policy), {})
})

test('明细 · 阶段 3 模式行：检测 / 仅自定义措辞与 CRS 行裁剪', () => {
  const detection = policyOf({ id: 51, mode: 'detection', crs_rule_groups: '["42","55"]' })
  const detectionRows = stageRows(bindingOf({ policy_id: 51, mode: 'detection' }), detection, [], 3)
  assert.deepEqual(detectionRows[0], { label: 'WAF（检测）', detail: '仅记录不阻断' })
  assert.deepEqual(detectionRows.find((row) => row.label === 'CRS 规则组'), { label: 'CRS 规则组', detail: '2 组' })

  const customOnly = policyOf({ id: 51, mode: 'custom_only', has_custom_rules: true, custom_rules_count: 4, crs_rule_groups: '["42"]' })
  const customRows = stageRows(bindingOf({ policy_id: 51, mode: 'custom_only' }), customOnly, [], 3)
  assert.deepEqual(customRows[0], { label: 'WAF（仅自定义）', detail: '自定义规则按动作执行' })
  assert.equal(customRows.some((row) => row.label === 'CRS 规则组'), false, '仅自定义模式 CRS 不参与评估，不得出 CRS 行')
  assert.deepEqual(customRows.find((row) => row.label === '自定义规则'), { label: '自定义规则', detail: '4 条' })
})

test('明细 · 条目合并与 ACL 名单计数：内联优先去重、引用条目带来源/备注、缺失名单跳过；ACL 名单名与计数', () => {
  const ipLists: SecurityStageIPList[] = [
    {
      id: 10,
      name: '名单甲',
      entry_count: 2,
      entries: [
        { value: '2.2.2.2', remark: '重复项，不得覆盖内联' },
        { value: '3.3.3.3', remark: '备注' },
        { value: '   ' },
      ],
    },
    { id: 11, entries: [{ value: '4.4.4.4' }] },
  ]
  const trust = policyOf({
    id: 61,
    policy_type: 'stage0',
    ip_whitelist: '["1.1.1.1"," 2.2.2.2 ","1.1.1.1",""]',
    ip_whitelist_refs: '[10,11,12]',
  })
  assert.deepEqual(detailsAt(0, trust, ipLists)?.trustEntries, [
    { value: '1.1.1.1', source: '内联' },
    { value: '2.2.2.2', source: '内联' },
    { value: '3.3.3.3', remark: '备注', source: '列表：名单甲' },
    // 引用条目无备注时键存在但为 undefined（消费方按 ?? 展示，不得改写为默认文案）
    { value: '4.4.4.4', remark: undefined, source: '列表：#11' },
  ])

  const acl = policyOf({
    id: 62,
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: true,
    ip_acl_list: '["9.9.9.9","9.9.9.9","8.8.8.8"]',
    ip_acl_list_refs: '[10,13]',
  })
  const aclDetails = detailsAt(1, acl, ipLists)
  assert.equal(aclDetails?.aclInlineCount, 2, '内联按去重值计数')
  assert.deepEqual(aclDetails?.aclLists, [
    { name: '名单甲', count: 2 },
    { name: '列表 #13', count: 0 },
  ], '未加载的引用名单显性显示为「列表 #id」，不得静默丢弃')

  // ACL 关闭但保留名单：明细与摘要同门——不出 aclLists/aclInlineCount，
  // 遗留独立黑名单仍照常列出（它不受 ACL 开关门控）。
  const closed = policyOf({
    id: 63,
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: false,
    ip_acl_list: '["9.9.9.9"]',
    ip_acl_list_refs: '[10]',
    ip_blacklist: '["7.7.7.7","7.7.7.7"]',
  })
  const closedDetails = detailsAt(1, closed, ipLists)
  assert.equal(closedDetails?.aclLists, undefined)
  assert.equal(closedDetails?.aclInlineCount, undefined)
  assert.deepEqual(closedDetails?.blacklistEntries, ['7.7.7.7'])
})
