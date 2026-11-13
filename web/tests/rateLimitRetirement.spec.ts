// 阶段 2 配额限流退役后的命名与分区一致性（2026-11-13 用户裁定：已下线的
// 阶段 2 限流安全策略升级为 CC 防护，系统不应再以其旧名/旧编号示人）。
//
// 判定边界（用户明确界定，不可扩大）：
//   在范围＝阶段 2 配额限流安全策略的残留：旧编号 stage4 分区、恒 429 文案、
//          借 RateLimit 命名的 CC 防护词条键、零消费的死词条 → 本文件钉住
//   不在范围＝其它位置的限流，一律保留原命名与语义，不得改名：
//          · 请求频次保护：登录/MFA/集群机器接口/MCP/OIDC（middleware 桶机制）
//          · CA 的 ACME 429 退避：isACMERRateLimit / CAProviderRateLimitError
//          · 对外契约：HTTP 429 / Retry-After / apidocs 的 rate_limited 描述
//          · 历史标识：rate_limit_* 列名（迁移与备份裁剪依据）、任务 ID
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, repoCode, section } from './_helpers.ts'
import { inferPolicyType, normalizePolicyType } from '../src/utils/securityStages.ts'

const binding = code('src/components/SecurityBindingEditor.vue')
const policies = code('src/views/security/SecurityPolicies.vue')
const zhViews = code('src/locales/zh/views.ts')
const enViews = code('src/locales/en/views.ts')
const zhSecurity = code('src/locales/zh/security.ts')
const enSecurity = code('src/locales/en/security.ts')

// ── A1. 分区数与 canonical 四阶段一致（功能误标，非纯文案） ──

test('inferPolicyType 永不产出 stage4：绑定编辑器不得保留第 5 个恒空分区', () => {
  // 归一契约：旧编号 stage4 读入即并入 stage3
  assert.equal(normalizePolicyType('stage4'), 'stage3')
  // 全形状枚举：WAF 三态 / 自定义规则 / 人机 / CC / 信任 / ACL / 零能力
  const shapes: Array<[string, Record<string, unknown>]> = [
    ['WAF blocking', { policy_type: 'stage3', mode: 'blocking' }],
    ['WAF detection', { mode: 'detection' }],
    ['WAF custom_only', { mode: 'custom_only' }],
    ['仅自定义规则', { mode: 'off', custom_rules_count: 2 }],
    ['旧编号 stage4', { policy_type: 'stage4', mode: 'blocking' }],
    ['人机验证', { human_verify_mode: 'force' }],
    ['CC 检测', { cc_detect_enabled: true }],
    ['零能力', { mode: 'off' }],
  ]
  for (const [name, p] of shapes) {
    assert.notEqual(inferPolicyType(p as never), 'stage4', `${name} 不得归入 stage4`)
  }
})

test('绑定编辑器分区严格四阶段：stage3=内容防护，无 stage4 分区与 bindStage4 桶', () => {
  const sections = section(binding, 'const stageSections = computed<StageSection[]>(', '\n])')
  const types = [...sections.matchAll(/type: '(stage\d)'/g)].map((m) => m[1])
  assert.deepEqual(types, ['stage0', 'stage1', 'stage2', 'stage3'], '分区必须恰好四阶段且按序')
  assert.doesNotMatch(binding, /bindStage4/, '恒空的第 5 桶必须删除')
  assert.doesNotMatch(binding, /'stage4'/, '不得再引用旧编号分区')
  // stage3 分区必须挂内容防护标题，不得再挂「人机验证」
  assert.match(sections, /type: 'stage3' as const, title: t\('common\.app\.views\.secBinding\.stage3Title'\)/)
  assert.doesNotMatch(sections, /humanTitle/, 'stage3 不得挂人机验证标题（挑战属阶段 2 动作）')
})

test('绑定回填分桶与四阶段分区同构（WAF 策略落 stage3 可写桶）', () => {
  const buckets = section(binding, 'const buckets:', '\n    for (const policy of props.policies)')
  assert.doesNotMatch(buckets, /stage4/, '回填桶不得含旧编号')
  assert.match(buckets, /stage3: bindStage3/, 'WAF 策略必须回填 stage3 桶（原落 bindHuman）')
  assert.doesNotMatch(binding, /bindHuman/, '旧 bindHuman 桶必须收敛为 bindStage3')
})

// ── A2. 已退役能力的词条键与文案不得残留 ──

test('secBinding 三键改名：CC 防护语义不再借用 RateLimit 命名', () => {
  for (const [oldKey, newKey] of [
    ['multiRateLimitBadge', 'multiCcPolicyBadge'],
    ['singleRateLimitTip', 'singleCcPolicyTip'],
    ['otherRateLimitBlock', 'otherCcPolicyBlock'],
  ] as const) {
    assert.doesNotMatch(zhViews, new RegExp(`'${oldKey}'`), `zh 旧键 ${oldKey} 必须移除`)
    assert.doesNotMatch(enViews, new RegExp(`'${oldKey}'`), `en 旧键 ${oldKey} 必须移除`)
    assert.match(zhViews, new RegExp(`'${newKey}'`), `zh 新键 ${newKey} 必须在场`)
    assert.match(enViews, new RegExp(`'${newKey}'`), `en 新键 ${newKey} 必须在场`)
    assert.doesNotMatch(binding, new RegExp(oldKey), `组件不得再引用 ${oldKey}`)
    assert.match(binding, new RegExp(newKey), `组件必须引用 ${newKey}`)
  }
})

test('策略页迁移风险键改名：rateLimitRisk → ccPolicyRisk', () => {
  assert.doesNotMatch(zhSecurity, /"rateLimitRisk"/)
  assert.doesNotMatch(enSecurity, /"rateLimitRisk"/)
  assert.match(zhSecurity, /"ccPolicyRisk"/)
  assert.match(enSecurity, /"ccPolicyRisk"/)
  assert.doesNotMatch(policies, /rateLimitRisk/)
  assert.match(policies, /ccPolicyRisk/)
})

test('阶段 2/3 词条按 canonical 命名：无「限流」「速率限制」「阶段 4」', () => {
  const secBinding = section(zhViews, "'secBinding'", '\n  },')
  assert.match(secBinding, /'stage2Title': '阶段 2 · CC 防护/)
  assert.match(secBinding, /'stage3Title': '阶段 3 · 内容防护/)
  assert.doesNotMatch(secBinding, /限流|速率限制|恒 429/, 'secBinding 不得残留退役口径')
  assert.doesNotMatch(secBinding, /'stage4Title'|'humanTitle'/, '旧编号/人机独立阶段标题必须删除')

  const enBinding = section(enViews, "'secBinding'", '\n  },')
  assert.match(enBinding, /'stage2Title': 'Stage 2 · CC protection/)
  assert.match(enBinding, /'stage3Title': 'Stage 3 · Content protection/)
  assert.doesNotMatch(enBinding, /Rate limit|Rate limiting|always return 429/i)
  assert.doesNotMatch(enBinding, /'stage4Title'|'humanTitle'/)
})

test('策略页阶段 2 副标题与拦截页提示不得再宣称恒 429', () => {
  assert.match(zhSecurity, /"subStage2": "配置人机验证挑战与 CC 异常检测/)
  assert.doesNotMatch(zhSecurity, /"statusTipStage2"/, '死键（零消费）必须删除')
  const noPage = zhSecurity.match(/"stage2NoPage": "([^"]*)"/)
  assert.ok(noPage, 'stage2NoPage 必须在场')
  assert.doesNotMatch(noPage![1], /限流|429/, '未配拦截页提示不得再提限流 429')
})

test('已退役能力的死词条整族清除（零消费方，保留即歧义源）', () => {
  const deadViews = ['rateLimitCaptionDual', 'rateLimitCaptionSingle', 'rateLimitRowLabel', 'rateLimitSummary', 'chip429', 'chip429Caption', 'summary429']
  for (const k of deadViews) {
    assert.doesNotMatch(zhViews, new RegExp(`'${k}'`), `zh 死键 ${k} 必须删除`)
    assert.doesNotMatch(enViews, new RegExp(`'${k}'`), `en 死键 ${k} 必须删除`)
  }
  assert.doesNotMatch(code('src/locales/zh/rules.ts'), /rateLimitWindowBasis/, '死键 rateLimitWindowBasis 必须删除')
  assert.doesNotMatch(code('src/locales/en/rules.ts'), /rateLimitWindowBasis/)
})

// ── A3. 在役限流不在本次范围：必须保持原命名与语义（防越界改名复发） ──

test('请求频次保护（登录/集群/MCP）保持原命名——不属阶段 2 退役范围', () => {
  const mw = repoCode('internal/middleware/middleware.go')
  for (const name of ['loginRateLimit', 'clusterRateLimit', 'clusterRegisterRateLimit', 'clusterMachineRateLimit', 'mcpSourceRateLimit', 'mcpAPIKeyRateLimit', 'SweepRateLimitBuckets']) {
    assert.match(mw, new RegExp(`func ${name}\\(`), `在役限流 ${name} 必须保持原名（用户界定：其它位置的限流不受影响）`)
  }
  assert.doesNotMatch(mw, /func (loginThrottle|clusterThrottle|SweepThrottleBuckets)\(/, '不得把在役限流改名为 throttle')
  // 桶清扫任务 ID 是 task_loop_prefs 主键，改名会丢用户调度设置
  assert.match(repoCode('internal/services/taskengine_wire_runtime.go'), /ID:\s+"ratelimit-bucket-sweep"/, '在役任务 ID 不得改名（落库主键，无迁移）')
})

test('CA 的 ACME 429 退避保持原命名——CA 侧真实 rate limit', () => {
  assert.match(repoCode('internal/acme/issuer.go'), /func isACMERRateLimit\(/, 'CA 429 判定必须保持原名')
  assert.match(repoCode('internal/services/certissuer.go'), /type CAProviderRateLimitError struct/, 'CA 限流错误类型必须保持原名')
  assert.match(code('src/locales/zh/common.ts'), /issueRateLimited/, 'CA 签发限流词条不得删除')
  assert.match(code('src/locales/zh/misc.ts'), /rateLimitSweep: '限流桶清扫'/, '桶清扫任务显示名保持原样')
})

test('历史标识不动：rate_limit_* 列名是迁移与备份裁剪依据', () => {
  assert.match(repoCode('internal/db/db.go'), /"rate_limit_enabled", "rate_limit_rps", "rate_limit_burst"/, '退役列名清单不得改名（否则存量库删不掉列）')
  const backup = repoCode('internal/handlers/config_backup.go')
  for (const col of ['rate_limit_enabled', 'rate_limit_rps', 'rate_limit_burst']) {
    assert.match(backup, new RegExp(`delete\\(policy, "${col}"\\)`), `旧备份裁剪键 ${col} 不得改名`)
  }
})
