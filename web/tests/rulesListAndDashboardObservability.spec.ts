// 规则列表与概览的可观测性契约：访问日志入口、健康结论单源、观测面深链连通、
// 概览口径披露、证书有效期结论单源。
//
// 行为类断言落在纯函数（node 直跑）；接线类断言读 code() 剥注释视图，判据写成
// 「返回违例清单的检查函数」并自带判据自检——把源码文本改坏后判据必须报出违例
// （只断言「存在」的钉子，在条件被删、分支写反时仍全绿）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, openTags } from './_helpers.ts'

const rulesCode: string = code('src/views/Rules.vue')

/** 限段读取；marker 缺失时返回空串（让判据报「缺接线」而不是抛错——自检样本可删 marker）。 */
const between = (source: string, startMarker: string, endMarker: string): string => {
  const start = source.indexOf(startMarker)
  if (start < 0) return ''
  const end = source.indexOf(endMarker, start + startMarker.length)
  return end < 0 ? source.slice(start) : source.slice(start, end)
}

/** 源码文本被改坏后判据必须报出预期违例；样本未命中源码（变异失效）同样判红。 */
const assertMutationCaught = (source: string, check: (text: string) => string[], breaks: Array<[string, (text: string) => string, RegExp]>): void => {
  for (const [what, mutate, expected] of breaks) {
    const mutated = mutate(source)
    assert.notEqual(mutated, source, `自检样本未命中源码：${what}（变异已失效，需同步样本）`)
    const violations = check(mutated)
    assert.ok(violations.some((v) => expected.test(v)), `${what}：判据未报出违例（实际：${violations.join('；') || '无'}）`)
  }
}

// ── 规则行：访问日志入口两态与「未发布」提示 ─────────────────────────────────

const ruleLogEntryViolations = (source: string): string[] => {
  const out: string[] = []
  const actions = between(source, `<el-table-column :label="t('common.app.rules.common.actions')"`, '</el-table-column>')
  const buttons = openTags(actions, 'el-button')
  const viewButton = buttons.find((tag) => /^<el-button v-if="row\.log_enabled"/.test(tag))
  if (!viewButton) out.push('缺「已开启→查看日志」入口（v-if="row.log_enabled"）')
  else {
    if (!viewButton.includes('@click="openRuleLogDialog(row as Rule)"')) out.push('查看日志入口必须打开访问日志弹框')
    if (viewButton.includes('isReadOnly')) out.push('查看日志入口不得按只读禁用（只读=可看，后端对全部登录用户开放读）')
  }
  const blockedTip = openTags(actions, 'el-tooltip').find((tag) => tag.includes("t('common.app.rules.list.logDisabledTooltip')"))
  if (!blockedTip) out.push('缺「未开启→禁用日志 + 原因」分支')
  else {
    if (blockedTip.includes('isReadOnly')) out.push('禁用态 tooltip 不得再按只读给原因')
    if (!/v-else(?!-if)/.test(blockedTip)) out.push('禁用态分支必须是兜底 v-else')
  }
  const blockedButton = buttons.find((tag) => /^<el-button type="primary" link size="small" disabled>/.test(tag))
  if (!blockedButton) out.push('兜底分支的「日志」按钮必须恒禁用')
  const health = between(source, "<el-table-column :label=\"t('common.app.rules.common.health')\"", "<el-table-column :label=\"t('common.app.rules.list.updatedBy')\"")
  const unpublished = between(health, '<el-tooltip', '</el-tooltip>')
  if (!unpublished.includes("t('common.app.rules.list.unpublishedHint')")) out.push('「未发布」提示必须保留原因')
  return out
}

test('规则行：访问日志入口两态与「未发布」提示接线（接线判据）', () => {
  assert.deepEqual(ruleLogEntryViolations(rulesCode), [])
})

test('判据自检：访问日志入口被改坏时判据必须报出违例', () => {
  assertMutationCaught(rulesCode, ruleLogEntryViolations, [
    ['查看入口按只读禁用', (s) => s.replace(/(<el-button v-if="row\.log_enabled")/, '$1 :disabled="isReadOnly"'), /不得按只读禁用/],
    ['禁用态 tooltip 仍按只读给原因', (s) => s.replace(`<el-tooltip v-else :content="t('common.app.rules.list.logDisabledTooltip')">`, `<el-tooltip v-else :content="isReadOnly ? readOnlyMessage : t('common.app.rules.list.logDisabledTooltip')">`), /不得再按只读给原因/],
    ['禁用态不再恒禁用', (s) => s.replace('<el-button type="primary" link size="small" disabled>', '<el-button type="primary" link size="small">'), /必须恒禁用/],
  ])
})

test('词条：访问日志禁用原因 zh/en 成对', () => {
  const zh = code('src/locales/zh/rules.ts')
  const en = code('src/locales/en/rules.ts')
  assert.match(zh, /logDisabledTooltip: '该规则未开启访问日志'/)
  assert.match(en, /logDisabledTooltip: 'Access log is not enabled for this rule\.'/)
})

// ── 规则列表：列名与词条、处理流程入口与阶段 2 策略计数 ─────────────────────

const flowCode: string = code('src/components/RuleFlowDialog.vue')

const upstreamColumnViolations = (source: string): string[] => {
  const out: string[] = []
  if (!source.includes(`<el-table-column :label="t('common.app.rules.common.upstreamType')"`)) out.push('「上游」列显示的是静态/动态，列头必须是「上游类型」')
  if (/N\/A/.test(source)) out.push('N/A 字面量未走词条（notApplicable）')
  return out
}

const flowEntryViolations = (source: string, flow: string): string[] => {
  const out: string[] = []
  const lock = openTags(source, 'el-icon').find((tag) => tag.includes('class="acl-lock-icon"'))
  if (!lock) out.push('缺处理流程入口（锁图标）')
  else {
    if (!lock.includes('@click="openFlowFromLock(row as Rule)"')) out.push('处理流程入口声明了按钮语义，必须响应点击（指针/读屏激活走 click）')
    if (!lock.includes('role="button"')) out.push('处理流程入口必须是按钮语义')
    if (!lock.includes('tabindex="0"')) out.push('处理流程入口必须可键盘聚焦')
    if (!lock.includes(`:aria-label="t('common.app.rules.list.viewFlowAria', { ruleName: row.name })"`)) out.push('处理流程入口必须有「查看安全处理流程」aria-label')
  }
  if (!/\.acl-lock-icon:focus-visible \{ outline:/.test(source)) out.push('处理流程入口必须有可见焦点环')
  if (!flow.includes('stagePolicyCountText(typedStageByKey(node.key)!.stage, typedStageByKey(node.key)!.groups.length)')) out.push('流程弹框阶段 2 区必须给出本规则的策略计数与说明')
  return out
}

test('规则列表：列头「上游类型」与 N/A 词条化（接线判据）', () => {
  assert.deepEqual(upstreamColumnViolations(rulesCode), [])
  const zh = code('src/locales/zh/rules.ts')
  const en = code('src/locales/en/rules.ts')
  assert.match(zh, /upstreamType: '上游类型'/)
  assert.match(zh, /notApplicable: '不适用'/)
  assert.match(en, /upstreamType: 'Upstream type'/)
  assert.match(en, /notApplicable: 'N\/A'/)
})

test('判据自检：列头/词条被改坏时判据必须报出违例', () => {
  assertMutationCaught(rulesCode, upstreamColumnViolations, [
    ['列头改回「上游」', (s) => s.replace(`:label="t('common.app.rules.common.upstreamType')"`, `:label="t('common.app.rules.common.upstream')"`), /列头必须是「上游类型」/],
    ['N/A 字面量回潮', (s) => s.replace('<span class="upstream-na">', '<span class="upstream-na">N/A '), /N\/A 字面量未走词条/],
  ])
})

test('处理流程入口：按钮语义/点击/键盘可达；阶段 2 策略计数（接线判据）', () => {
  assert.deepEqual(flowEntryViolations(rulesCode, flowCode), [])
  assert.match(code('src/locales/zh/rules.ts'), /stage2PolicyCount: '[^']*CC 防护策略[^']*'/)
  assert.match(code('src/locales/en/rules.ts'), /stage2PolicyCount: '[^']+'/)
})

test('判据自检：处理流程入口/阶段 2 计数被改坏时判据必须报出违例', () => {
  assertMutationCaught(rulesCode, (s) => flowEntryViolations(s, flowCode), [
    ['入口不响应点击', (s) => s.replace(' @click="openFlowFromLock(row as Rule)"', ''), /必须响应点击/],
    ['入口不可聚焦', (s) => s.replace('tabindex="0"\n                    :aria-label', ':aria-label'), /必须可键盘聚焦/],
    ['入口无按钮语义', (s) => s.replace('role="button"\n', ''), /必须是按钮语义/],
  ])
  assertMutationCaught(flowCode, (f) => flowEntryViolations(rulesCode, f), [
    ['阶段 2 不给策略计数', (s) => s.replace(/<div v-else-if="typedStageByKey\(node\.key\)!\.stage === 2" class="flow-panel-stats">[^\n]*\n/, ''), /阶段 2 区必须给出本规则的策略计数/],
  ])
})
