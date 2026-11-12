// 安全策略保存载荷行为验收
// 载荷原先内联在 SecurityPolicies.handleSave，字段语义（阶段外裁剪、引用释放、
// stage0 信任恒启用、geoip 三态归一、mixed 不显式提交）无求值测试。
//
// 后端契约：internal/models/security.go UpdateSecurityPolicyRequest。
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildPolicyPayload, crawlerExemptionNeedsEngines, type PolicyPayloadInput } from '../src/utils/policyPayload.ts'
import { repoCode, section } from './_helpers.ts'

// 后端请求结构的 json 标签是字段名的唯一权威（UpdateSecurityPolicyRequest）。
// 载荷键集必须与其中逐项对齐：前端新增/改名而 Go 未收 → 静默丢弃；Go 改名而
// 前端未跟 → 字段永不生效。唯一有意缺口 = 遗留 ip_blacklist（编辑面只读，
// 由导入/历史数据维护，不在保存载荷内）。
const goRequest = section(
  repoCode('internal/models/security.go'),
  'type UpdateSecurityPolicyRequest struct',
  '\n}\n',
)
const GO_FIELD_TAGS = [...goRequest.matchAll(/json:"([a-z0-9_]+)(?:,[^"]*)?"/g)].map((match) => match[1])
assert.equal(GO_FIELD_TAGS.length, (goRequest.match(/json:"/g) ?? []).length, '每个 json 标签都必须被解析')

const base = (over: Partial<PolicyPayloadInput> = {}): PolicyPayloadInput => ({
  name: '策略 A',
  description: '',
  enabled: true,
  mode: 'blocking',
  anomalyThreshold: 5,
  ipAclEnabled: false,
  ipAclMode: 'deny',
  ipAclList: [],
  ipAclListRefs: [],
  ipWhitelist: [],
  ipWhitelistRefs: [],
  ipWhitelistEnabled: false,
  crsRuleGroups: [],
  crsExcludedRules: [],
  customRuleIds: [],
  blockPageId: 0,
  blockResponseMode: 'auto',
  blockStatusCode: 403,
  geoipCountries: [],
  geoipEnabled: false,
  geoipMode: 'deny',
  geoipCrawlerExempt: false,
  geoipCrawlerEngines: ['googlebot'],
  wafCheckResponse: false,
  logRequestBody: false,
  trustDetection: false,
  policyType: 'stage3',
  humanVerifyMode: 'auto',
  humanVerifyType: 'slider',
  humanVerifyTtl: 30,
  humanExemptPaths: ['/static/'],
  ccDetectEnabled: true,
  ccRpsLimit: 40,
  ccRpsWindow: 10,
  cc4xxRatio: 70,
  ccSessionAnomaly: false,
  ccSessionUaThreshold: 5,
  ccResponse: 'verify',
  ...over,
})

test('Create 与 Update 请求结构字段集一致（同一载荷双路径消费）', () => {
  // 前端 buildPolicyPayload 同时服务创建与编辑；后端两份结构字段集漂移
  // （如只在 Update 增字段）时，创建路径会静默丢弃该字段。
  const go = repoCode('internal/models/security.go')
  const createRequest = section(go, 'type CreateSecurityPolicyRequest struct', '\n}\n')
  const createTags = [...createRequest.matchAll(/json:"([a-z0-9_]+)(?:,[^"]*)?"/g)].map((match) => match[1])
  assert.ok(createTags.length >= 28, `Create 字段解析不足: ${createTags.length}`)
  assert.deepEqual([...createTags].sort(), [...GO_FIELD_TAGS].sort(), 'Create 与 Update 字段集漂移')
})

test('载荷字段集与后端 UpdateSecurityPolicyRequest 逐项对表', () => {
  assert.ok(GO_FIELD_TAGS.length >= 28, `后端字段解析不足: ${GO_FIELD_TAGS.length}`)
  const payloadKeys = Object.keys(buildPolicyPayload(base()))
  const unknownToGo = payloadKeys.filter((key) => !GO_FIELD_TAGS.includes(key))
  assert.deepEqual(unknownToGo, [], '前端提交的字段后端必须接收（否则静默丢弃）')
  const notSubmitted = GO_FIELD_TAGS.filter((tag) => !payloadKeys.includes(tag))
  assert.deepEqual(notSubmitted, ['ip_blacklist'], '唯一有意缺口=遗留 ip_blacklist（编辑面只读）')
  assert.equal(payloadKeys.length, GO_FIELD_TAGS.length - 1, '字段数必须与后端声明一致（减去遗留字段）')
})

test('数组字段按 JSON 文本下发（名单/引用/组/排除/自定义/区域/引擎）', () => {
  const payload = buildPolicyPayload(base({
    ipAclEnabled: true,
    ipAclList: ['1.2.3.4'],
    ipAclListRefs: [3, 7],
    crsRuleGroups: ['942'],
    crsExcludedRules: [{ target: '942100', scope: 'all', ips: [], listRefs: [] }],
    customRuleIds: [12],
    geoipEnabled: true,
    geoipCountries: ['CN'],
  }))
  assert.equal(payload.ip_acl_list, '["1.2.3.4"]')
  assert.equal(payload.ip_acl_list_refs, '[3,7]')
  assert.equal(payload.crs_rule_groups, '["942"]')
  assert.equal(payload.crs_excluded_rules, '[{"target":"942100","scope":"all","ips":[],"listRefs":[]}]')
  assert.equal(payload.custom_rules, '[12]')
  assert.equal(payload.geoip_countries, '["CN"]')
  assert.equal(payload.geoip_crawler_engines, '["googlebot"]')
})

test('ACL 关闭保留引用与内联名单（关闭再打开不丢数据）', () => {
  const payload = buildPolicyPayload(base({ ipAclEnabled: false, ipAclList: ['1.2.3.4'], ipAclListRefs: [3] }))
  assert.equal(payload.ip_acl_list, '["1.2.3.4"]')
  assert.equal(payload.ip_acl_list_refs, '[3]', '关闭开关不得静默释放引用')
})

test('ACL 引用仅在用户显式清空后释放', () => {
  const cleared = buildPolicyPayload(base({ ipAclEnabled: false, ipAclListRefs: [] }))
  assert.equal(cleared.ip_acl_list_refs, '[]')
})

test('信任开关三态：关闭不生效但保留引用；开启保留引用', () => {
  const off = buildPolicyPayload(base({ ipWhitelistEnabled: false, ipWhitelist: ['9.9.9.9'], ipWhitelistRefs: [2] }))
  assert.equal(off.ip_whitelist_enabled, false)
  assert.equal(off.ip_whitelist, '["9.9.9.9"]')
  assert.equal(off.ip_whitelist_refs, '[2]', '关闭开关不得静默释放引用')
  const on = buildPolicyPayload(base({ ipWhitelistEnabled: true, ipWhitelistRefs: [2] }))
  assert.equal(on.ip_whitelist_enabled, true)
  assert.equal(on.ip_whitelist_refs, '[2]')
})

test('阶段 0 信任名单策略恒启用（开关位不参与）', () => {
  const payload = buildPolicyPayload(base({ policyType: 'stage0', ipWhitelistEnabled: false, ipWhitelistRefs: [5] }))
  assert.equal(payload.ip_whitelist_enabled, true)
  assert.equal(payload.ip_whitelist_refs, '[5]')
  assert.equal(payload.policy_type, 'stage0')
})

test('geoip 三态归一：关闭 → off；开启但模式 off → deny；爬虫豁免随地域开关', () => {
  assert.equal(buildPolicyPayload(base({ geoipEnabled: false, geoipMode: 'allow', geoipCrawlerExempt: true })).geoip_mode, 'off')
  assert.equal(buildPolicyPayload(base({ geoipEnabled: false, geoipCrawlerExempt: true })).geoip_crawler_exempt, false)
  assert.equal(buildPolicyPayload(base({ geoipEnabled: true, geoipMode: 'off' })).geoip_mode, 'deny')
  assert.equal(buildPolicyPayload(base({ geoipEnabled: true, geoipMode: 'allow' })).geoip_mode, 'allow')
  assert.equal(buildPolicyPayload(base({ geoipEnabled: true, geoipCrawlerExempt: true })).geoip_crawler_exempt, true)
})

test('阶段 2/3 人机验证载荷：stage2/stage3 承载全字段；其余类型归零（与后端阶段能力矩阵同口径）', () => {
  const s2 = buildPolicyPayload(base({ policyType: 'stage2' }))
  assert.equal(s2.human_verify_mode, 'auto')
  assert.equal(s2.human_verify_type, 'slider')
  assert.equal(s2.cc_detect_enabled, true)
  const s3 = buildPolicyPayload(base({ policyType: 'stage3' }))
  assert.equal(s3.human_verify_mode, 'auto')
  assert.equal(s3.human_verify_type, 'slider')
  assert.equal(s3.human_verify_ttl, 30)
  assert.equal(s3.human_exempt_paths, '["/static/"]')
  // IP 级放行与挑战页已退役（2026-11-12 用户裁定）：载荷不得再出现该两键
  assert.equal('human_exempt_ips' in s3, false, '豁免 IP 已退役（阶段 0 信任名单为唯一入口）')
  assert.equal('human_challenge_page_id' in s3, false, '自定义挑战页已退役（拦截页覆盖）')
  assert.equal(s3.cc_detect_enabled, true)
  assert.equal(s3.cc_rps_limit, 40)
  assert.equal(s3.cc_rps_window, 10)
  assert.equal(s3.cc_4xx_ratio, 70)
  assert.equal(s3.cc_session_anomaly, false)
  assert.equal(s3.cc_session_ua_threshold, 5)
  // 非阶段 3：能力域归零（后端 applyStageZeros 同口径），但数值字段保留（后端按需归一）
  const waf = buildPolicyPayload(base({ policyType: 'stage4', humanVerifyMode: 'force', humanExemptPaths: ['/x/'], ccDetectEnabled: true }))
  assert.equal(waf.human_verify_mode, 'off', '非人机验证阶段不得提交非 off 模式')
  assert.equal(waf.human_exempt_paths, '[]')
  assert.equal(waf.cc_detect_enabled, false)
  // mixed 不提交 policy_type，人机验证同样归零（混合策略不含阶段 3 能力）
  const mixed = buildPolicyPayload(base({ policyType: 'mixed' }))
  assert.equal(mixed.policy_type, undefined)
  assert.equal(mixed.human_verify_mode, 'off')
})

test('mixed 不显式提交类型（省略=后端按内容推断）', () => {
  const payload = buildPolicyPayload(base({ policyType: 'mixed' }))
  assert.equal('policy_type' in payload, true)
  assert.equal(payload.policy_type, undefined)
  assert.equal(buildPolicyPayload(base({ policyType: 'stage1' })).policy_type, 'stage1')
})

test('配额限流字段已下线：载荷不得再提交 rate_limit_*', () => {
  const payload = buildPolicyPayload(base({ anomalyThreshold: 9, blockStatusCode: 503, blockPageId: 4 }))
  assert.equal('rate_limit_enabled' in payload, false)
  assert.equal('rate_limit_rps' in payload, false)
  assert.equal('rate_limit_burst' in payload, false)
  assert.equal(payload.anomaly_threshold, 9)
  assert.equal(payload.block_status_code, 503)
  assert.equal(payload.block_page_id, 4)
})

test('豁免开启 + 空引擎 = 不可保存（后端空集=全部引擎）', () => {
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: true, crawlerExempt: true, engines: [] }), true)
  // 勾选任一引擎即合法
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: true, crawlerExempt: true, engines: ['googlebot'] }), false)
  // 地域关闭或豁免关闭 = 引擎选择不参与（不阻断保存）
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: false, crawlerExempt: true, engines: [] }), false)
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: true, crawlerExempt: false, engines: [] }), false)
})
