// CC 防护面板文案与保存门契约验收（阶段 2 = CC 防护：人机挑战 + CC 异常检测）。
//
// 覆盖：
//   · 4xx 比例输入上界 [0,100]（0=关闭，后端契约）；
//   · CC 检测开启但人机验证关闭 → 非阻断保存警告（与 ccEnabledTip「仅人机开启时生效」同口径）；
//   · 阶段 2 未配挑战页（block_page_id=0）= 内置挑战页一等路径，保存放行、提示不得宣称 403/绑定链兜底；
//   · 阶段 2 副标题/脚注/失效回落/未配页提示按真实渲染语义（挑战发放/失败计入自动封禁观测，无直接封禁）；
//   · 退役死词条整族清除（events.cc* / overview.status.human* / cc.passFail / challengePageLabel*）；
//   · 自动封禁配置弹框注释与后端喂入门同口径；
//   · zh/en 双语键集齐备（无裸键、无单侧残留）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildStageModel, stageSubLabel, type SecurityStageBinding, type SecurityStagePolicy } from '../src/utils/securityStages.ts'
import { tSafe } from '../src/i18n/tSafe.ts'
import { code, section, source } from './_helpers.ts'
import zhSecurity from '../src/locales/zh/security.ts'
import enSecurity from '../src/locales/en/security.ts'
import zhViews from '../src/locales/zh/views.ts'
import enViews from '../src/locales/en/views.ts'

const policies = code('src/views/security/SecurityPolicies.vue')
const events = code('src/views/security/SecurityEvents.vue')
const zhSec = code('src/locales/zh/security.ts')
const enSec = code('src/locales/en/security.ts')
const zhView = code('src/locales/zh/views.ts')
const enView = code('src/locales/en/views.ts')

const bindingOf = (overrides: Partial<SecurityStageBinding> = {}): SecurityStageBinding => ({
  policy_id: 1, name: '策略 A', mode: 'off', enabled: true, ...overrides,
})
const policyOf = (overrides: Partial<SecurityStagePolicy> = {}): SecurityStagePolicy => ({
  id: 1, name: '策略 A', mode: 'off', enabled: true,
  has_ip_control: false, has_geoip: false, has_custom_rules: false,
  geoip_countries: '[]', custom_rules_count: 0, ip_acl_mode: 'deny', ip_acl_list: '[]', ip_whitelist: '[]',
  ...overrides,
})

// ── 1. 4xx 比例输入上界（后端契约 [0,100]，0=关闭） ──
test('CC 4xx 比例输入：min=0（0=关闭）且 max=100（后端合法域上界）', () => {
  const input = policies.match(/<el-input-number v-model="form\.cc_4xx_ratio"[^>]*>/)
  assert.ok(input, 'cc_4xx_ratio 输入控件必须在场')
  assert.match(input![0], /:min="0"/, '0=关闭是合法值，下界不得抬高')
  assert.match(input![0], /:max="100"/, '上界必须钉死后端契约 100，不得放任 >100 提交')
  // 突刺窗口上界 3600 秒（既有契约，保持）
  const windowInput = policies.match(/<el-input-number v-model="form\.cc_rps_window"[^>]*>/)
  assert.ok(windowInput && /:max="3600"/.test(windowInput[0]), 'cc_rps_window 上界 3600 保持')
})

// ── 2. CC-only 保存警告（非阻断；复用 autoNeedsCc 警告形态） ──
test('CC 检测开启但人机验证关闭：保存警告接线（非阻断）+ 文案与 ccEnabledTip 同口径', () => {
  const save = section(policies, 'const handleSave = async', 'const payload = buildPolicyPayload(')
  assert.match(save, /ccDetectWithoutHumanWarning\(/, '保存流必须消费 CC-only 警告谓词')
  assert.match(save, /ElMessage\.warning\(t\('app\.security\.policies\.human\.ccNeedsHuman'\)\)/, '警告走 ElMessage.warning（非阻断）')
  // 非阻断：警告之后不得 return（继续保存流程）
  const warnAt = save.indexOf("ElMessage.warning(t('app.security.policies.human.ccNeedsHuman')")
  const afterWarn = save.slice(warnAt, warnAt + 200)
  assert.doesNotMatch(afterWarn, /\breturn\b/, '警告不得阻断保存（无 return）')
  // 就地警告线（autoNeedsCc 同形态：el-text type=warning）
  assert.match(policies, /v-if="form\.cc_detect_enabled && form\.human_verify_mode === 'off'"[\s\S]{0,160}?ccNeedsHuman/, 'CC 步骤内就地警告线（与 autoNeedsCc 同形态）')
  // 文案口径：仅人机开启时生效（与 ccEnabledTip 一致），不得宣称直接封禁
  const zhTip = zhSec.match(/"ccNeedsHuman": "([^"]*)"/)
  assert.ok(zhTip, 'ccNeedsHuman zh 词条必须在场')
  assert.match(zhTip![1], /仅在人机验证开启时生效|人机验证关闭/, '警告口径必须与 ccEnabledTip「仅人机开启时生效」一致')
  assert.ok(enSec.includes('"ccNeedsHuman"'), 'ccNeedsHuman en 词条必须成对在场')
})

// ── 阶段 2 无页（0）= 内置挑战页一等路径：保存放行 + 提示如实 ──
test('阶段 2 未配挑战页（0）：保存校验放行（内置挑战页一等路径，不判缺占位符）', () => {
  // 占位符校验单源：仅对 >0 的真实页生效；0=内置挑战页放行
  const computed = section(policies, 'const challengePageMissingWidget = computed', '\nconst handleSave')
  assert.match(computed, /challengePageNeedsWidgetCheck\(\{/, '组件必须消费单源谓词（不内联第二份判定）')
  assert.doesNotMatch(computed, /block_page_id <= 0\) return true/, '0=内置挑战页不得判缺占位符（死路必须删除）')
  // 保存门消费同一谓词（缺占位符仍阻断真实页）
  const save = section(policies, 'const handleSave = async', 'const payload = buildPolicyPayload(')
  assert.match(save, /challengePageMissingWidget\.value/, '保存门必须消费占位符校验谓词')
})

test('阶段 2 未配挑战页（0）：下拉选项与提示走挑战语境（内置挑战页，不宣称 403/绑定链兜底）', () => {
  // 下拉 0 选项与提示线按 stage 分流（stage2 → 挑战语境键）
  assert.match(policies, /:label="t\(editorPolicyType === 'stage2' \? 'app\.security\.policies\.bp\.stage2NoPageDefault' : 'app\.security\.policies\.bp\.noPageDefault'\)"/, '0 选项 label 按 stage 分流')
  assert.match(policies, /t\(editorPolicyType === 'stage2' \? 'app\.security\.policies\.bp\.stage2NoPageTip' : 'app\.security\.policies\.bp\.noPageTipDefault'\)/, '未配页提示按 stage 分流')
  // 只读查看投影同样分流
  assert.match(policies, /d\.human_verify_mode[\s\S]{0,80}stage2NoPageDefault/, '只读查看投影 0 页按 stage2 分流')
  // zh 文案：内置挑战页语义，无 403/绑定链兜底
  const opt = zhSec.match(/"stage2NoPageDefault": "([^"]*)"/)
  const tip = zhSec.match(/"stage2NoPageTip": "([^"]*)"/)
  assert.ok(opt && tip, 'stage2 专用 0 页选项/提示词条必须成对在场')
  for (const text of [opt![1], tip![1]]) {
    assert.match(text, /内置挑战页/, '必须如实呈现内置挑战页回退')
    assert.doesNotMatch(text, /403|绑定链|兜底/, 'stage2 挑战语境不得宣称 403/绑定链兜底')
  }
  assert.ok(enSec.includes('"stage2NoPageDefault"') && enSec.includes('"stage2NoPageTip"'), 'en 必须成对在场')
  // stage3 的 403 口径保持不变（noPageTipDefault 仍服务 WAF 拦截兜底）
  assert.match(zhSec, /"noPageTipDefault": "[^"]*Caddy 默认 403/, 'stage3 拦截兜底口径不得被误改')
})

// ── 4. 阶段 2 副标题（退役「速率限制」→ CC 防护/人机验证口径） ──
test('阶段 2 副标题：CC 防护/人机验证口径（速率限制已退役），zh/en 同步', () => {
  assert.equal(stageSubLabel(2), '人机挑战 · CC 异常检测')
  assert.doesNotMatch(stageSubLabel(2), /速率限制|限流/, '副标题不得残留退役限流口径')
  assert.match(zhView, /'sub2': '人机挑战 · CC 异常检测'/)
  assert.match(enView, /'sub2': 'Human challenge · CC anomaly detection'/)
})

// ── 5. 封禁文案残留三处（CC 直接封禁已退役 → 自动封禁观测口径） ──
test('CC 投影/未配页/策略页行文案：无直接封禁宣称，封禁走自动封禁观测口径', () => {
  const projection = zhSec.match(/"projection": "([^"]*)"/g) ?? []
  const ccProjection = projection.find((line) => line.includes('CC 防护'))
  assert.ok(ccProjection, 'CC 投影词条必须在场')
  assert.doesNotMatch(ccProjection!, /或直接封禁/, 'CC 直接封禁已退役，不得宣称')
  assert.match(ccProjection!, /自动封禁/, '封禁口径必须指向自动封禁观测')
  // stage2NoPage：挑战按内置挑战页返回（封禁由自动封禁承载，不宣称挑战页直接封禁）
  const noPage = zhSec.match(/"stage2NoPage": "([^"]*)"/)
  assert.ok(noPage && /挑战按内置挑战页返回/.test(noPage![1]), 'stage2NoPage 必须为内置挑战页口径')
  assert.doesNotMatch(noPage![1], /封禁/, 'stage2NoPage 不得宣称挑战页承载封禁')
  // pageOnStage2：发起挑战时渲染（无封禁语义）
  assert.match(zhView, /'pageOnStage2': '\{name\}（发起挑战时渲染）'/)
  assert.match(enView, /'pageOnStage2': '\{name\} \(rendered when a challenge is issued\)'/)
  // en 同步无直接封禁
  const enProjection = enSec.match(/"projection": "([^"]*)"/g) ?? []
  const enCc = enProjection.find((line) => line.includes('CC protection'))
  assert.ok(enCc && /auto-ban observation/.test(enCc) && !/or an immediate ban/.test(enCc), 'en CC 投影必须指向自动封禁观测，不得宣称「或直接封禁」')
})

// ── 6. stage2Footnote：挑战发放/失败产生事件行，不计拦截/检测/攻击面 ──
test('阶段 2 脚注：挑战/通过不计拦截、检测与攻击面统计（不宣称「不产生安全事件」）', () => {
  const model = buildStageModel([bindingOf()], [policyOf({ human_verify_mode: 'force' })], [], [])
  const footnote = model.stages[2].footnote ?? ''
  assert.doesNotMatch(footnote, /不产生安全事件/, '挑战发放/失败实际产生事件行，不得宣称零事件')
  assert.match(footnote, /不计入拦截、检测与攻击面统计/, '必须如实呈现统计口径')
  assert.match(footnote, /安全总览「CC 防护」卡片/, '统计入口指引保留')
  assert.match(zhView, /'stage2Footnote': 'CC 防护的挑战\/通过不计入拦截、检测与攻击面统计；挑战\/封禁统计见安全总览「CC 防护」卡片'/)
  assert.match(enView, /'stage2Footnote': 'CC protection challenges\/passes are not counted in block, detection or attack-surface stats; challenge\/ban stats are in the Security overview CC card'/)
})

// ── 7. blockPageBrokenStage2：回退内置挑战页（非绑定链/403） ──
test('阶段 2 拦截页失效：回退内置挑战页（插件占位符回退），非绑定链首个有效页/403', () => {
  const policy = policyOf({ human_verify_mode: 'force', block_page_id: 0 })
  const rows = buildStageModel([bindingOf({ block_page_id: 9 })], [policy], [], []).stages[2].groups[0]?.rows ?? []
  const pageRow = rows.find((row) => row.label === '拦截页（策略页）')
  assert.deepEqual(pageRow, { label: '拦截页（策略页）', detail: '已失效（回退内置挑战页）' })
  assert.match(zhView, /'blockPageBrokenStage2': '已失效（回退内置挑战页）'/)
  assert.match(enView, /'blockPageBrokenStage2': 'Broken \(falls back to the built-in challenge page\)'/)
  // stage1/3 的绑定链回落口径不受影响
  assert.match(zhView, /'blockPageBroken403': '已失效（回落绑定链首个有效页）'/)
})

// ── 8. 死键群清理（zh/en 成对删除；活键保留） ──
test('退役死词条整族清除：events.cc* / overview.status.human* / cc.passFail / challengePageLabel*（zh/en 成对）', () => {
  // events.cc* 死键只在 events 命名空间内判定——policies.human.ccSection/ccEnabledLabel
  // 是同名活键（不同命名空间），全文件裸键名匹配会误命中（死键判定限定 events 块）。
  const eventsBlockZh = section(zhSec, '"events": {', '\n   },')
  const eventsBlockEn = section(enSec, '"events": {', '\n   },')
  const deadEvents = ['ccSectionDesc', 'ccSection', 'ccEnabledLabel', 'ccEnabledHint', 'ccRpsLabel', 'ccRpsPer', 'ccRpsSec', 'ccRpsHint', 'cc4xxLabel', 'cc4xxHint', 'ccSessionLabel', 'ccSessionUaSuffix', 'ccSessionHint']
  for (const key of deadEvents) {
    assert.doesNotMatch(eventsBlockZh, new RegExp(`"${key}"`), `zh events.${key} 死键必须删除`)
    assert.doesNotMatch(eventsBlockEn, new RegExp(`"${key}"`), `en events.${key} 死键必须删除`)
  }
  // ccProtectionHint 是 events 命名空间活键，必须保留在 events 块内
  assert.match(eventsBlockZh, /"ccProtectionHint"/, 'zh events.ccProtectionHint 活键不得误删')
  assert.match(eventsBlockEn, /"ccProtectionHint"/, 'en events.ccProtectionHint 活键不得误删')
  // overview.status.human* 五键
  const statusBlockZh = section(zhSec, '"status": {', '\n    },')
  const statusBlockEn = section(enSec, '"status": {', '\n    },')
  for (const key of ['human', 'challenged', 'challengedTip', 'humanTip', 'humanPassRate']) {
    assert.doesNotMatch(statusBlockZh, new RegExp(`"${key}"`), `zh overview.status.${key} 死键必须删除`)
    assert.doesNotMatch(statusBlockEn, new RegExp(`"${key}"`), `en overview.status.${key} 死键必须删除`)
  }
  // cc.passFail 与 challengePageLabel* 三键
  assert.doesNotMatch(zhSec, /"passFail"/, 'zh cc.passFail 死键必须删除')
  assert.doesNotMatch(enSec, /"passFail"/, 'en cc.passFail 死键必须删除')
  for (const key of ['challengePageLabel', 'challengePageLabelBuiltin', 'challengePageBuiltin']) {
    assert.doesNotMatch(zhSec, new RegExp(`"${key}"`), `zh human.${key} 死键必须删除`)
    assert.doesNotMatch(enSec, new RegExp(`"${key}"`), `en human.${key} 死键必须删除`)
  }
  // 活键保留：ccProtectionHint（事件筛选 option title）、stageHuman、policies.human.cc* 同名活键
  assert.match(zhSec, /"ccProtectionHint"/, 'ccProtectionHint 是活键，不得误删')
  assert.match(events, /t\('app\.security\.events\.ccProtectionHint'\)/, 'ccProtectionHint 消费点必须在场')
  assert.match(policies, /t\('app\.security\.policies\.human\.ccSection'\)/, 'policies.human.ccSection 活键不得误删')
  assert.match(policies, /t\('app\.security\.policies\.human\.ccEnabledLabel'\)/, 'policies.human.ccEnabledLabel 活键不得误删')
  assert.match(zhSec, /"ccEnabledTip"/, 'ccEnabledTip 活键保留')
})

test('自动封禁状态接口：不声明后端不返回的 cc_* 字段（AutobanStatus 死字段清除）', () => {
  const iface = section(events, 'interface AutobanStatus {', '\n}')
  for (const field of ['cc_detect_enabled', 'cc_rps_limit', 'cc_rps_window', 'cc_4xx_ratio', 'cc_session_anomaly', 'cc_session_ua_threshold']) {
    assert.doesNotMatch(iface, new RegExp(field), `AutobanStatus.${field} 死字段必须删除（后端 status 响应不返回）`)
  }
})

// ── 9. 自动封禁配置弹框注释与实现同口径（挑战发放/失败按维度计数） ──
test('自动封禁配置弹框注释：四维口径（WAF 两族 + 挑战发放/失败），不宣称「只吃阶段 3 命中」', () => {
  // section() 只在注释外匹配 marker，无法切注释体；注释口径钉直接对原始源切片。
  const raw = source('src/views/security/SecurityEvents.vue')
  const start = raw.indexOf('<!-- 喂入门')
  assert.ok(start >= 0, '喂入门注释必须在场')
  const end = raw.indexOf('-->', start)
  assert.ok(end > start, '喂入门注释必须闭合')
  const comment = raw.slice(start, end)
  assert.doesNotMatch(comment, /只吃阶段 3 命中/, '旧注释「只吃阶段 3 命中」与四维口径不符，必须改写')
  assert.match(comment, /挑战发放\/失败|challenge_issued|challenge_failed/, '注释必须涵盖挑战发放/失败维度')
  assert.match(comment, /autobanStage3Eligible/, '注释必须指向后端阶段门谓词单源')
})

// ── 10. 双语 parity：改动域 zh/en 键集齐备（无裸键、无单侧残留） ──
// 词条树为编译期常量对象；递归遍历需按记录收窄（Object.entries 入参约束）。
type LocaleTree = { [key: string]: unknown }
const leafPaths = (node: unknown, prefix = ''): string[] => {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return prefix ? [prefix] : []
  const record = node as LocaleTree
  return Object.entries(record).flatMap(([key, value]) => leafPaths(value, prefix ? `${prefix}.${key}` : key))
}

test('双语 parity：CC 改动域 zh/en 键集完全一致（无单侧裸键）', () => {
  // geo.provinces 为有意不对称映射（zh 市名即源文，消费方仅 en 侧映射且带裸键
  // 回退守卫），不在本次 CC 改动域；parity 守卫覆盖本次触及的 security 与
  // views.stages 两棵子树（新增/删除/改键都在此）。
  // 词条模块默认导出为编译期常量树；按记录收窄后逐层取子树（命名常量，非内联断言成员访问）。
  const zhSecRoot = zhSecurity as LocaleTree
  const enSecRoot = enSecurity as LocaleTree
  const zhViewRoot = zhViews as LocaleTree
  const enViewRoot = enViews as LocaleTree
  const zhSecTree = zhSecRoot.app
  const enSecTree = enSecRoot.app
  const zhViewsApp = zhViewRoot.app as LocaleTree
  const enViewsApp = enViewRoot.app as LocaleTree
  const zhViewsTree = zhViewsApp.views as LocaleTree
  const enViewsTree = enViewsApp.views as LocaleTree
  const pairs: Array<[string, unknown, unknown]> = [
    ['security', zhSecTree, enSecTree],
    ['views.stages', zhViewsTree.stages, enViewsTree.stages],
  ]
  // geo.provinces 为有意不对称映射（zh 市名即源文，消费方仅 en 侧映射且带裸键回退
  // 守卫，见 SecurityPolicies.vue / BasicSettings.vue 的 mapped.includes 判定），
  // 不属本次 CC 改动域，parity 比对显式豁免该子树。
  const PARITY_EXEMPT_PREFIX = 'security.policies.geo.provinces.'
  for (const [name, zh, en] of pairs) {
    const zhKeys = new Set(leafPaths(zh).filter((key) => !key.startsWith(PARITY_EXEMPT_PREFIX)))
    const enKeys = new Set(leafPaths(en).filter((key) => !key.startsWith(PARITY_EXEMPT_PREFIX)))
    const zhOnly = [...zhKeys].filter((key) => !enKeys.has(key))
    const enOnly = [...enKeys].filter((key) => !zhKeys.has(key))
    assert.deepEqual(zhOnly, [], `${name}: zh 独有键（en 缺译 → 英文界面裸键）必须为空`)
    assert.deepEqual(enOnly, [], `${name}: en 独有键（zh 缺失）必须为空`)
  }
})

test('新增/改动词条 zh 侧可解析（无裸键回退）', () => {
  const keys: Array<[string, string]> = [
    ['app.security.policies.human.ccNeedsHuman', 'CC'],
    ['app.security.policies.bp.stage2NoPageDefault', '内置挑战页'],
    ['app.security.policies.bp.stage2NoPageTip', '内置挑战页'],
    ['common.app.views.stages.sub2', 'CC'],
    ['common.app.views.stages.stage2Footnote', 'CC'],
    ['common.app.views.stages.blockPageBrokenStage2', '内置挑战页'],
    ['common.app.views.stages.pageOnStage2', '挑战'],
  ]
  for (const [key, token] of keys) {
    const zh = tSafe(key, { name: '页' })
    assert.notEqual(zh, key, `zh 词条 ${key} 不得裸键回退`)
    assert.ok(zh.includes(token), `zh 词条 ${key} 口径必须含「${token}」`)
  }
})