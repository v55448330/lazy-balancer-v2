// 规则列表与概览的可观测性契约：列表刷新与轮询、访问日志入口、健康结论单源、
// 观测面深链连通、概览口径披露、证书有效期结论单源。
//
// 行为类断言落在纯函数（node 直跑）；接线类断言读 code() 剥注释视图，判据写成
// 「返回违例清单的检查函数」并自带判据自检——把源码文本改坏后判据必须报出违例
// （只断言「存在」的钉子，在条件被删、分支写反时仍全绿）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, openTags } from './_helpers.ts'
import { RULE_LIST_POLL_MS, ruleListPollPaused } from '../src/utils/ruleListRefresh.ts'
import { ruleLogEntryState } from '../src/utils/ruleAccessLog.ts'

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

// ── 规则列表：页头刷新与可见性轮询 ─────────────────────────────────────────

/** 接线判据：返回违例清单（空=通过）。入参是源码文本，便于用改坏的源码自检。 */
const ruleListRefreshViolations = (source: string): string[] => {
  const out: string[] = []
  const refreshButton = openTags(source, 'el-button').find((tag) => tag.includes('@click="refreshRuleList"'))
  if (!refreshButton) out.push('页头缺「刷新」按钮（@click="refreshRuleList"）')
  else {
    if (!refreshButton.includes(':icon="Refresh"')) out.push('刷新按钮必须带 Refresh 图标（与事件页同款）')
    if (refreshButton.includes(':loading')) out.push('刷新按钮不得带 loading')
    if (!source.includes(`${refreshButton}{{ t('common.app.rules.common.refresh') }}</el-button>`)) out.push('刷新按钮文案必须走 refresh 词条')
  }
  const fetchRules = between(source, 'const fetchRules = async', 'const fetchCertInfo')
  if (!/if \(!options\.background\) loading\.value = true/.test(fetchRules)) out.push('后台轮询轮次不得置表格 loading 遮罩')
  if (!/silent: options\.background === true/.test(fetchRules)) out.push('后台轮询轮次必须静默请求（失败只置横幅，不每轮弹 toast）')
  if (!/if \(options\.background && rulesRequestInFlight\) return/.test(fetchRules)) out.push('后台轮询轮次必须让位在途请求（单飞门）')
  if (!/catch \(error: unknown\)[\s\S]*?rulesLoadError\.value = true/.test(fetchRules)) out.push('后台轮询失败仍必须置 rulesLoadError 横幅')
  const polling = between(source, 'const ruleListRefresh = createVisibilityIntervals({', 'const retryCertPolling')
  if (!polling) out.push('缺列表可见性轮询（createVisibilityIntervals）')
  if (!/tick: \(\) => \{ if \(!ruleListPollPaused\(ruleListEditActivity\(\)\)\) void fetchRules\(false, \{ background: true \}\) \}/.test(polling)) {
    out.push('轮询 tick 必须先过编辑面让位判定，再走 fetchRules 的后台轮次')
  }
  if (!/ms: RULE_LIST_POLL_MS/.test(polling)) out.push('轮询周期必须取 RULE_LIST_POLL_MS 单源')
  if (!/immediate: true/.test(polling)) out.push('恢复可见/挂载时必须立即补一轮（回到标签页即见他端变更）')
  if (!/onMounted\(\(\) => \{[\s\S]*?ruleListRefresh\.start\(\)/.test(source)) out.push('挂载必须启动轮询')
  if (!/onUnmounted\(\(\) => \{[\s\S]*?ruleListRefresh\.stop\(\)/.test(source)) out.push('卸载必须停表')
  return out
}

test('规则列表轮询周期为 30 秒', () => {
  assert.equal(RULE_LIST_POLL_MS, 30_000)
})

test('轮询让位判定：任一编辑面打开或写操作在途即跳过本轮，全部空闲才刷新', () => {
  const idle = { wizardOpen: false, flowOpen: false, bindOpen: false, toggling: false, deleting: false }
  assert.equal(ruleListPollPaused(idle), false, '全部空闲必须刷新')
  const surfaces = ['wizardOpen', 'flowOpen', 'bindOpen', 'toggling', 'deleting'] as const
  for (const surface of surfaces) {
    assert.equal(ruleListPollPaused({ ...idle, [surface]: true }), true, `${surface} 单独成立时必须让位`)
  }
  assert.equal(ruleListPollPaused({ ...idle, wizardOpen: true, deleting: true }), true)
})

test('规则页：页头刷新按钮与可见性轮询接线（接线判据）', () => {
  assert.deepEqual(ruleListRefreshViolations(rulesCode), [])
})

test('判据自检：轮询接线被改坏时判据必须报出违例', () => {
  assertMutationCaught(rulesCode, ruleListRefreshViolations, [
    ['删掉让位判定', (s) => s.replace('if (!ruleListPollPaused(ruleListEditActivity())) ', ''), /先过编辑面让位判定/],
    ['周期写死', (s) => s.replace('ms: RULE_LIST_POLL_MS', 'ms: 15_000'), /RULE_LIST_POLL_MS 单源/],
    ['卸载不停表', (s) => s.replace('ruleListRefresh.stop()', ''), /卸载必须停表/],
    ['挂载不启动', (s) => s.replace('ruleListRefresh.start()', ''), /挂载必须启动轮询/],
    ['后台轮次置 loading', (s) => s.replace('if (!options.background) loading.value = true', 'loading.value = true'), /不得置表格 loading/],
    ['后台轮次不静默', (s) => s.replace('silent: options.background === true', 'silent: false'), /必须静默请求/],
    ['后台轮次不让位在途请求', (s) => s.replace('if (options.background && rulesRequestInFlight) return', ''), /单飞门/],
    ['刷新按钮加 loading', (s) => s.replace('@click="refreshRuleList">', ':loading="loading" @click="refreshRuleList">'), /不得带 loading/],
    ['刷新按钮缺图标', (s) => s.replace(':icon="Refresh" @click="refreshRuleList"', '@click="refreshRuleList"'), /必须带 Refresh 图标/],
    ['删掉整个轮询', (s) => s.replace(/const ruleListRefresh = createVisibilityIntervals\(\{[\s\S]*?\n\}\)\n/, ''), /缺列表可见性轮询/],
  ])
})

// ── 规则行：访问日志入口三态与「未发布」恢复指引 ─────────────────────────────

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
  const tooltips = openTags(actions, 'el-tooltip')
  const enableTip = tooltips.find((tag) => tag.includes("ruleLogEntryState(row as Rule, canEditRule(row as Rule)) === 'enable'"))
  if (!enableTip) out.push('缺「未开启且可编辑→去开启」入口')
  else {
    if (!enableTip.includes("t('common.app.rules.list.logEnableEntryTip')")) out.push('「去开启」必须带原因 tooltip（该规则未开启访问日志）')
    const enableButton = buttons.find((tag) => tag.includes('@click="openWizardForAccessLog(row as Rule)"'))
    if (!enableButton) out.push('「去开启」必须打开编辑向导')
    else if (!/^\s*\{\{ t\('common\.app\.rules\.list\.logEnableEntry'\) \}\}\s*<\/el-button>/.test(source.slice(source.indexOf(enableButton) + enableButton.length))) out.push('「去开启」文案必须走 logEnableEntry 词条')
  }
  const blockedTip = tooltips.find((tag) => tag.includes("t('common.app.rules.list.logUnsupportedTcp')"))
  if (!blockedTip) out.push('缺「未开启且不可编辑→禁用日志 + 原因」分支（含 TCP 不支持提示）')
  else {
    if (!blockedTip.includes("t('common.app.rules.list.logDisabledTooltip')")) out.push('禁用态 tooltip 文案必须是「该规则未开启访问日志」')
    if (blockedTip.includes('isReadOnly')) out.push('禁用态 tooltip 不得再按只读给原因')
    if (!/v-else(?!-if)/.test(blockedTip)) out.push('禁用态分支必须是兜底 v-else')
  }
  const blockedButton = buttons.find((tag) => /^<el-button type="primary" link size="small" disabled>/.test(tag))
  if (!blockedButton) out.push('兜底分支的「日志」按钮必须恒禁用')
  const openForLog = between(source, 'const openWizardForAccessLog =', '\n// ── ')
  if (!openForLog) out.push('缺 openWizardForAccessLog（去开启的落点：编辑向导 + 定位访问日志开关）')
  else {
    if (!/await openWizard\(rule\)/.test(openForLog)) out.push('「去开启」必须走既有 openWizard（只读/保存在途守卫同源）')
    // el-dialog 的焦点陷阱在打开后的下一拍把焦点落到对话框容器（晚于 nextTick）——
    // 同步/nextTick 里 focus 会被夺回（浏览器实测），必须排在其后的宏任务里；
    // 滚动取居中：打开动画期间对话框带位移，贴边滚动会把开关裁掉一截（浏览器实测）。
    if (!/setTimeout\(\(\) => \{[\s\S]*?accessLogSwitchRef\.value\?\.focus\(\)[\s\S]*?\}, 0\)/.test(openForLog)) out.push('「去开启」必须把焦点落到访问日志开关，且晚于对话框焦点陷阱（宏任务）')
    if (!/scrollIntoView\?\.\(\{ block: 'center' \}\)/.test(openForLog)) out.push('「去开启」定位必须把开关滚到可视区居中')
  }
  if (!source.includes('<el-switch v-model="wizardForm.log_enabled" ref="accessLogSwitchRef" />')) out.push('访问日志开关必须挂 ref（定位目标）')
  const health = between(source, "<el-table-column :label=\"t('common.app.rules.common.health')\"", "<el-table-column :label=\"t('common.app.rules.list.updatedBy')\"")
  const unpublished = between(health, '<el-tooltip', '</el-tooltip>')
  if (!unpublished.includes("<template #content>")) out.push('「未发布」提示必须用内容插槽承载两行（原因 + 恢复指引）')
  if (!unpublished.includes("t('common.app.rules.list.unpublishedHint')")) out.push('「未发布」提示必须保留原因')
  if (!unpublished.includes("t('common.app.rules.list.unpublishedRecoverHint')")) out.push('「未发布」提示必须补恢复指引')
  return out
}

test('访问日志入口三态：开启=查看；未开启且可编辑=去开启；未开启且只读=禁用；TCP 恒不支持', () => {
  assert.equal(ruleLogEntryState({ log_enabled: true, protocol: 'http' }, false), 'view', '只读用户可看已开启的访问日志')
  assert.equal(ruleLogEntryState({ log_enabled: true, protocol: 'tcp' }, false), 'view')
  assert.equal(ruleLogEntryState({ log_enabled: false, protocol: 'http' }, true), 'enable', '可编辑的 HTTP 规则给「去开启」')
  assert.equal(ruleLogEntryState({ log_enabled: false, protocol: 'http' }, false), 'logOff', '只读/从节点/证书任务锁定：禁用并说明未开启')
  assert.equal(ruleLogEntryState({ log_enabled: false, protocol: 'tcp' }, true), 'tcpUnsupported', 'TCP 没有访问日志开关，不得给「去开启」')
  assert.equal(ruleLogEntryState({ log_enabled: false, protocol: 'tcp' }, false), 'tcpUnsupported')
})

test('规则行：访问日志入口三态与「未发布」恢复指引接线（接线判据）', () => {
  assert.deepEqual(ruleLogEntryViolations(rulesCode), [])
})

test('判据自检：访问日志入口/未发布指引被改坏时判据必须报出违例', () => {
  assertMutationCaught(rulesCode, ruleLogEntryViolations, [
    ['查看入口按只读禁用', (s) => s.replace(/(<el-button v-if="row\.log_enabled")/, '$1 :disabled="isReadOnly"'), /不得按只读禁用/],
    ['去开启不设可编辑门', (s) => s.replace(`v-else-if="ruleLogEntryState(row as Rule, canEditRule(row as Rule)) === 'enable'"`, 'v-else-if="!row.log_enabled"'), /缺「未开启且可编辑→去开启」/],
    ['去开启不给原因', (s) => s.replace(`:content="t('common.app.rules.list.logEnableEntryTip')"`, ':content="\'\'"'), /必须带原因 tooltip/],
    ['去开启不定位开关', (s) => s.replace('accessLogSwitchRef.value?.focus()', ''), /焦点落到访问日志开关/],
    ['定位早于焦点陷阱（焦点被对话框容器夺回）', (s) => s.replace(/setTimeout\(\(\) => \{[\s\S]*?\}, 0\)/, 'accessLogSwitchRef.value?.focus()'), /焦点落到访问日志开关/],
    ['贴边滚动（开关被裁掉一截）', (s) => s.replace("scrollIntoView?.({ block: 'center' })", "scrollIntoView?.({ block: 'nearest' })"), /滚到可视区居中/],
    ['开关不挂 ref', (s) => s.replace(' ref="accessLogSwitchRef" />', ' />'), /必须挂 ref/],
    ['禁用态 tooltip 仍按只读给原因', (s) => s.replace(`:content="row.protocol === 'tcp'`, `:content="isReadOnly ? readOnlyMessage : row.protocol === 'tcp'`), /不得再按只读给原因/],
    ['未发布不补恢复指引', (s) => s.replace(/<br \/>\{\{ t\('common\.app\.rules\.list\.unpublishedRecoverHint'\) \}\}/, ''), /必须补恢复指引/],
  ])
})

test('词条：访问日志入口与未发布恢复指引 zh/en 成对', () => {
  const zh = code('src/locales/zh/rules.ts')
  const en = code('src/locales/en/rules.ts')
  for (const key of ['logEnableEntry', 'logEnableEntryTip', 'logUnsupportedTcp', 'unpublishedRecoverHint']) {
    assert.match(zh, new RegExp(`${key}: '[^']+'`), `zh 缺 ${key}`)
    assert.match(en, new RegExp(`${key}: '[^']+'`), `en 缺 ${key}`)
  }
  assert.match(zh, /logDisabledTooltip: '该规则未开启访问日志'/)
  assert.match(zh, /logEnableEntry: '去开启'/)
  assert.match(zh, /unpublishedRecoverHint: '[^']*启用至少一个上游[^']*'/, '恢复指引必须点明「启用至少一个上游」')
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
