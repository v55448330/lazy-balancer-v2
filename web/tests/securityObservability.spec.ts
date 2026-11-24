// 安全防护观测面的口径契约：
//   · 策略列表「状态」：启用/禁用二态标签（关联规则数在独立列，不进状态列）；
//   · 删除策略确认：只写明将解除的绑定数量（不列规则名）；列表行内启停只提交 {enabled}；
//   · 策略页两处跳转与事件页深链消费（「查看全部」带动作筛选 / 「查看自动封禁配置」
//     进页开弹框 / 「返回策略列表」关闭弹框不新开标签）；
//   · 安全总览：只在进入页面时取数（无页头刷新、无定时刷新），「最近拦截事件」下钻带筛选；
//   · 文案口径：威胁名单误报提示、拦截页 0 选项、封禁弹框副标题与详情 IP 入口、
//     累犯升级档列、CC 累计标签。
// 判定逻辑走 utils 真实代码（行为求值）；渲染点与双语词条以「源码钉 + 运行期词表
// 解析」双钉——只钉源码抓不到键缺失，只钉词表抓不到渲染点丢失。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { i18n } from '../src/i18n/index.ts'
import { code, elementSlice, member, section } from './_helpers.ts'
import { policyDeleteScope } from '../src/utils/securityPolicyList.ts'

type LocaleTree = { [key: string]: unknown }
const messages = i18n.global.messages.value as Record<string, LocaleTree>

/** 运行期挂载树取叶子（缺键/非字符串叶子即失败——裸键不得靠 includes 假绿）。 */
const term = (locale: 'zh-CN' | 'en') => (path: string): string => {
  const value = path.split('.').reduce<unknown>((node, key) => (node as LocaleTree | undefined)?.[key], messages[locale])
  assert.equal(typeof value, 'string', `${locale} 词条 ${path} 必须是字符串叶子（缺键=界面裸键）`)
  return value as string
}
const zh = term('zh-CN')
const en = term('en')

const policies = code('src/views/security/SecurityPolicies.vue')
const events = code('src/views/security/SecurityEvents.vue')
const overview = code('src/views/security/SecurityOverview.vue')

// ── 策略列表「状态」列：启用/禁用二态标签 ──

test('策略列表状态｜状态单元格只看启用态，不按关联规则数改判', () => {
  const labelAt = policies.indexOf(`:label="t('app.security.policies.table.status')"`)
  assert.ok(labelAt > 0, '状态列必须在场')
  const column = elementSlice(policies, policies.lastIndexOf('<el-table-column', labelAt), 'el-table-column')
  assert.match(column, /:type="row\.enabled \? 'success' : 'info'"/, '标签色只看启用态')
  assert.match(column, /\{\{ row\.enabled \? t\('app\.security\.policies\.status\.enabled'\) : t\('app\.security\.policies\.status\.disabled'\) \}\}/, '标签文案只看启用态')
  assert.doesNotMatch(column, /rule_count/, '状态列不得按关联规则数改判（关联规则数在独立列）')
})

test('策略列表状态｜回归：复合状态判定与其词条键一并移除', () => {
  assert.doesNotMatch(policies, /policyListStatus|POLICY_LIST_STATUS_TAG|enabledUnbound/, '页面不得残留复合状态判定')
  for (const locale of ['zh-CN', 'en'] as const) {
    const policiesNode = (((messages[locale] as LocaleTree).app as LocaleTree).security as LocaleTree).policies as LocaleTree
    assert.ok(!('enabledUnbound' in (policiesNode.status as LocaleTree)), `${locale} 不得残留 enabledUnbound 词条键`)
  }
})

// ── 删除策略确认：只披露将解除的绑定数量 ──

test('删除披露｜数量取列表行 rule_count 与页内绑定快照的较大值', () => {
  assert.equal(policyDeleteScope(3, 3), 3)
  assert.equal(policyDeleteScope(3, 5), 5, '绑定快照新于列表时以快照为准（数量不得小于实际将解除的绑定数）')
})

test('删除披露｜回归：绑定快照拿不到（传 0）时仍按行计数披露；零绑定不披露', () => {
  assert.equal(policyDeleteScope(4, 0), 4, '不得因为读不到绑定就不披露')
  assert.equal(policyDeleteScope(0, 0), 0)
})

test('删除披露｜渲染点：零绑定只有首行确认文案；有绑定追加一句数量，不列规则名', () => {
  const message = section(policies, 'const policyDeleteMessage = ', '\nfunction handleDelete')
  assert.match(
    message,
    /policyDeleteScope\(row\.rule_count, securityBindingsFailed\.value \? 0 : policyBoundRules\(row\.id\)\.length\)/,
    '绑定数取列表行 rule_count；页内绑定快照解析出的条数兜底，绑定加载失败传 0',
  )
  assert.match(
    message,
    /count === 0 \? confirm : h\('div', \[h\('div', confirm\), h\('p', \{ class: 'confirm-scope-lead' \}, t\('app\.security\.policies\.msg\.deleteScopeLead', \{ n: count \}\)\)\]\)/,
    '只追加一句带数量的引导行',
  )
  assert.doesNotMatch(message, /confirm-scope-list|h\('li'|rule\.name|unnamed/, '不得列出规则名')
  assert.match(section(policies, 'function handleDelete(', '\nconst goToCustomRulesPage'), /ElMessageBox\.confirm\(policyDeleteMessage\(row\), /, '删除确认必须消费级联披露')
})

test('删除披露｜词条：zh/en 成对、带数量占位符、以句号收尾', () => {
  assert.match(zh('app.security.policies.msg.deleteScopeLead'), /^同时解除与 \{n\} 条规则的绑定（规则本身保留）。$/)
  assert.match(en('app.security.policies.msg.deleteScopeLead'), /\{n\}/)
  for (const gone of ['deleteScopeCountOnly', 'deleteScopeMore']) {
    const policiesNode = (((messages['zh-CN'] as LocaleTree).app as LocaleTree).security as LocaleTree).policies as LocaleTree
    assert.ok(!(gone in (policiesNode.msg as LocaleTree)), `不得残留只服务规则名清单的词条键 ${gone}`)
  }
})

// ── 策略列表行内启停 ──

test('策略启停｜操作列开关：一行确认 → 只提交 {enabled} → 成功回读；取消/失败回滚', () => {
  const actionsAt = policies.indexOf(`:label="t('app.security.policies.table.actions')"`)
  assert.ok(actionsAt > 0, '操作列必须在场')
  const actions = elementSlice(policies, policies.lastIndexOf('<el-table-column', actionsAt), 'el-table-column')
  const switchAt = actions.indexOf('<el-switch')
  assert.ok(switchAt > 0, '操作列必须有启停开关')
  const toggleSwitch = elementSlice(actions, switchAt, 'el-switch')
  assert.match(toggleSwitch, /v-model="row\.enabled"/)
  assert.match(toggleSwitch, /:disabled="isReadOnly \|\| policyTogglingId !== null"/, '只读（从节点/非管理员）与在途时禁用')
  assert.match(toggleSwitch, /@change="togglePolicy\(row as PolicySummary\)"/)
  const fn = member(policies, 'const togglePolicy = async (row: PolicySummary)')
  const confirmAt = fn.indexOf('await ElMessageBox.confirm(')
  const putAt = fn.indexOf('await request.put(`/security/policies/${row.id}`, { enabled: nextEnabled })')
  assert.ok(confirmAt > 0 && putAt > confirmAt, '确认必须早于请求，且只提交 {enabled}')
  assert.match(fn, /t\('app\.security\.policies\.msg\.toggleConfirm', \{ action, name: row\.name \}\)/, '确认文案一行')
  assert.match(fn, /if \(isCaddyApplyDegraded\(res\)\) showSaveResult\(res, ''\)/, 'DB 已提交但 Caddy 应用失败必须可见')
  assert.match(fn, /await fetchData\(\)/, '成功后刷新列表')
  const catchBlock = fn.slice(fn.indexOf('} catch'))
  const rollback = catchBlock.indexOf('row.enabled = !nextEnabled')
  const cancel = catchBlock.indexOf("if (error === 'cancel' || error === 'close') return")
  const reread = catchBlock.indexOf('void fetchData()')
  assert.ok(rollback > 0 && cancel > rollback && reread > cancel, '失败先回滚；取消早退不回读，真实失败再回读')
  assert.match(fn, /policyTogglingId\.value = null/, 'finally 释放在途占位')
})

test('策略启停｜词条：zh/en 成对，确认文案一句话', () => {
  assert.equal(zh('app.security.policies.msg.toggleConfirm'), '确定{action}策略「{name}」？')
  // 与状态列标签「启用 / 禁用」同词：同一页面不给同一动作两个名字
  assert.equal(zh('app.security.policies.action.disable'), zh('app.security.policies.status.disabled'))
  assert.equal(zh('app.security.policies.action.enable'), '启用')
  for (const key of [
    'app.security.policies.msg.toggleConfirm',
    'app.security.policies.msg.toggleConfirmTitle',
    'app.security.policies.action.toggleAria',
  ]) {
    assert.match(en(key), /\{(action|name)\}/, `${key} 的 en 词条必须带插值`)
    assert.doesNotMatch(`${zh(key)}${en(key)}`.replaceAll('{action}', '').replaceAll('{name}', ''), /[{}]/, `${key} 不得出现 {action}/{name} 之外的花括号`)
  }
})

// ── 跳转与深链 ──

test('策略页跳转｜「查看自动封禁配置」带配置意图深链；「返回策略列表」只关闭弹框', () => {
  const goToAutoban = section(policies, 'const goToAutobanConfig = ', '\n')
  assert.match(goToAutoban, /pageUrl\('security-events', \{ \[DEEP_LINK_PARAMS\.eventsAutoban\]: EVENTS_AUTOBAN_CONFIG \}\)/)
  // 「返回策略列表」：用户就在策略列表页，关闭弹框即回到列表（与弹框 footer 的
  // 「关闭」同一写法），不新开同页标签。
  const doneTip = section(policies, 'class="info-note-bar defaults-done-tip"', '</div>')
  assert.match(doneTip, /<AccessibleLink type="primary" size="small" @click="defaultsVisible = false">\{\{ t\('app\.security\.policies\.defaults\.goRules'\) \}\}<\/AccessibleLink>/)
  assert.doesNotMatch(policies, /window\.open\(pageUrl\('security-policies'\)/, '返回列表不得新开同页标签')
})

test('事件页深链消费｜挂载时应用动作筛选并按意图打开自动封禁配置弹框，消费后清除 query', () => {
  const mounted = section(events, 'onMounted(() => {', '\n})')
  assert.match(mounted, /parseSecurityEventsDeepLink\(window\.location\.search\)/, '消费侧必须走解析单源（非法值不透传成筛选条件）')
  assert.match(mounted, /filters\.value\.action = link\.action/, '动作筛选必须落到筛选态再拉列表')
  assert.match(mounted, /window\.history\.replaceState\(null, '', window\.location\.pathname\)/, '消费后必须清除参数（否则每次回到本页都被重新应用）')
  assert.match(mounted, /const autobanReady = Promise\.all\(\[fetchAutobanStatus\(\), fetchAutobanConfig\(\)\]\)/, '状态与配置缓存必须先就绪')
  assert.match(mounted, /if \(link\.openAutobanConfig\) void autobanReady\.then\(openAutobanConfigFromLink\)/, '必须等状态与配置就绪后再开弹框')
  const land = section(events, 'const openAutobanConfigFromLink = ', '\nconst ')
  assert.match(land, /if \(autobanWritable\.value\) openAutobanConfig\(\)/)
  assert.match(land, /else ElMessage\.warning\(autobanConfigTooltip\.value\)/, '开不了弹框时必须说明原因（只读/从节点/加载失败），不得静默')
})

test('安全总览｜只在进入页面时取数：无页头刷新按钮、无定时刷新；失败态保留「立即重试」', () => {
  const header = elementSlice(overview, overview.indexOf('<div class="page-header">'), 'div')
  assert.doesNotMatch(header, /@click="reloadAll"/, '页头不得有刷新按钮')
  assert.doesNotMatch(overview, /createVisibilityIntervals|reloadInBackground|overview\.page\.refresh/, '不得有定时刷新与页头刷新词条键')
  assert.match(overview, /onMounted\(\(\) => \{ void reloadAll\(\) \}\)/, '进入页面取数必须保留')
  assert.equal(overview.split(`@click="reloadAll">{{ t('app.security.overview.page.retryNow') }}</el-button>`).length - 1, 2, '失败态的「立即重试」保留')
})

test('安全总览下钻｜「查看全部」带拦截筛选', () => {
  assert.match(
    section(overview, 'const goToEvents = ', '\n'),
    /window\.open\(pageUrl\('security-events', \{ \[DEEP_LINK_PARAMS\.eventsAction\]: 'blocked' \}\), '_blank', 'noopener'\)/,
    '「最近拦截事件」卡的下钻必须带 action=blocked',
  )
})

test('总览黄条「前往绑定规则」｜与事件页同写法：定位判据单源 + 深链复用已登记参数', () => {
  assert.match(overview, /policy_id\?: number \| null/)
  assert.match(overview, /const autobanBindingPolicyId = computed\(\(\) => autobanStatus\.value === null \? null : autobanMissingPolicyId\(autobanStatus\.value\)\)/)
  const barAt = overview.indexOf('<el-alert v-if="autobanIneffective"')
  assert.ok(barAt > 0, '前置：未生效黄条必须存在（否则本断言空转）')
  const bar = elementSlice(overview, barAt, 'el-alert')
  assert.match(
    bar,
    /\{\{ autobanIneffectiveText \}\} <AccessibleLink v-if="autobanBindingPolicyId !== null" type="primary" @click="goToBindingPolicy">\{\{ t\('app\.security\.events\.goToBindingRules'\) \}\}<\/AccessibleLink>/,
    '黄条内必须有「前往绑定规则」入口（文案复用事件页词条）',
  )
  assert.match(
    overview,
    /const goToBindingPolicy = \(\) => \{\s*if \(autobanBindingPolicyId\.value === null\) return\s*window\.open\(pageUrl\('security-policies', \{ \[DEEP_LINK_PARAMS\.policyId\]: autobanBindingPolicyId\.value \}\), '_blank', 'noopener'\)\s*\}/,
    '导航必须复用 pageUrl + DEEP_LINK_PARAMS.policyId 新标签打开',
  )
})

// ── 文案口径 ──

test('封禁弹框｜副标题如实描述列表来源；详情弹框 IP 走快捷处置入口', () => {
  const subtitle = zh('app.security.events.banConsoleSubtitle')
  assert.match(subtitle, /自动封禁名单」中的全部条目/)
  assert.match(subtitle, /含手动添加到该名单的/)
  assert.doesNotMatch(subtitle, /正在生效的封禁条目（含手动封禁）/, '列表数据源只有自动封禁名单：经 IP 快捷弹框加入「手动黑名单」的封禁不在其中')
  assert.match(en('app.security.events.banConsoleSubtitle'), /every entry in the "Auto-ban list"/)
  const ctx = elementSlice(events, events.lastIndexOf('<el-dialog', events.indexOf('class="ctx-event-dialog')), 'el-dialog')
  assert.match(ctx, /<IPLocationAction v-if="ctxEvent\.client_ip" :ip="ctxEvent\.client_ip" :location="''" \/>/, '详情弹框 IP 必须是快捷处置入口（归属地由独立行承载，不重复内联）')
  assert.doesNotMatch(ctx, /\{\{ ctxEvent\.client_ip \|\| '—' \}\}/, '纯文本 IP 不得残留')
})

test('威胁名单误报提示｜必须同时披露信任名单的豁免范围', () => {
  const tipZh = zh('common.app.views.trigDetail.memberSystemTip')
  assert.match(tipZh, /误报可将该 IP 加入信任名单豁免/)
  assert.match(tipZh, /信任名单会跳过 IP 访问控制 \/ CC 防护 \/ WAF 的全部检测/)
  const tipEn = en('common.app.views.trigDetail.memberSystemTip')
  assert.match(tipEn, /add this IP to the trust list/)
  assert.match(tipEn, /skip all IP access control \/ CC protection \/ WAF checks/)
})

test('拦截页 0 选项｜选项名与「兜底页 / 全链无页 403」两条提示同口径', () => {
  const option = zh('app.security.policies.bp.noPageDefault')
  assert.match(option, /^不使用拦截页（兜底显示绑定链首个有页策略的页面；全链无页时返回 Caddy 默认 403）$/
    , '选项名不得再宣称「直接返回状态码」——无页时状态码不生效')
  const optionEn = en('app.security.policies.bp.noPageDefault')
  assert.match(optionEn, /^No block page \(falls back to the first page-enabled policy in the binding chain; Caddy's default 403 if none has a page\)$/)
})

test('总览列与标签｜累犯升级档列标明全局口径；CC 两个累计标签标明进程累计', () => {
  assert.equal(zh('app.security.overview.autoban.colEscalation'), '累犯升级档（全局）')
  assert.equal(en('app.security.overview.autoban.colEscalation'), 'Escalation (global)')
  assert.equal(zh('app.security.overview.cc.passedTotal'), '进程累计通过')
  assert.equal(zh('app.security.overview.cc.failedTotal'), '进程累计失败')
  assert.equal(en('app.security.overview.cc.passedTotal'), 'Passed (process total)')
  assert.equal(en('app.security.overview.cc.failedTotal'), 'Failed (process total)')
  // 列宽随列名加宽（88px 容不下「累犯升级档（全局）」）
  const column = elementSlice(overview, overview.lastIndexOf('<el-table-column', overview.indexOf(`:label="t('app.security.overview.autoban.colEscalation')"`)), 'el-table-column')
  assert.match(column, /width="1[3-9]\d"/)
})

test('提示文案｜zh 母本词条值不再出现内部词（策略类型代码、评估规则 ID、规则 id 段、模式代码）', () => {
  // 只扫词条值，不扫键名：subStage0 / stage0Title 这类键名是代码标识，不上屏。
  const values = (text: string, quote: '"' | "'"): string[] =>
    [...text.matchAll(new RegExp(`:\\s*${quote}((?:[^${quote}\\\\]|\\\\.)*)${quote}`, 'g'))].map((m) => m[1])
  const internalWords: ReadonlyArray<readonly [RegExp, string]> = [
    [/\bstage[0-9]\b/, '策略类型代码（stageN）'],
    [/\bmixed\b/, '策略类型代码（mixed）'],
    [/\b(901|949|959|999)\b/, '评估 / 豁免规则 ID'],
    [/\bid [0-9]/i, '规则 id 段'],
    [/旧 id/, '「旧 id」'],
    [/（deny）/, '模式代码（deny）'],
  ]
  for (const [file, quote] of [['src/locales/zh/security.ts', '"'], ['src/locales/zh/views.ts', "'"]] as const) {
    for (const value of values(code(file), quote)) {
      for (const [re, label] of internalWords) {
        assert.doesNotMatch(value, re, `${file} 词条值出现内部词「${label}」：${value}`)
      }
    }
  }
})

test('IP 快捷处置｜加入黑名单的动词统一为「封禁」：两条写入路径同一动词，与永久封禁披露句同名', () => {
  assert.equal(zh('app.security.ipLocation.verbs.block'), '封禁')
  assert.equal(zh('common.app.views.trustAssoc.verbDeny'), '封禁')
  assert.equal(en('app.security.ipLocation.verbs.block'), 'Ban')
  assert.equal(en('common.app.views.trustAssoc.verbDeny'), 'Ban')
  // 渲染点：既有名单直加走 verbs.block；无名单先建再关联走 SIDE_CONFIG.deny.verb
  assert.match(code('src/views/security/IPLocationAction.vue'), /const verb = side === 'deny' \? t\('app\.security\.ipLocation\.verbs\.block'\)/)
  assert.match(
    code('src/composables/useTrustAssociation.ts'),
    /deny: \{ refField: 'ip_acl_list_refs', suffix: t\('common\.app\.views\.trustAssoc\.suffixDeny'\), verb: t\('common\.app\.views\.trustAssoc\.verbDeny'\) \}/,
  )
})
