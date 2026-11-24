// 安全防护观测面的口径契约：
//   · 策略列表「状态」：启用 ≠ 生效（启用但零绑定 = 未关联规则，warning）；
//   · 删除策略确认：列出将被解除绑定的规则，规则名不可得时降级为只报数量；
//   · 策略页两处跳转与事件页深链消费（「查看全部」带动作筛选 / 「查看自动封禁配置」
//     进页开弹框 / 「返回策略列表」关闭弹框不新开标签）；
//   · 安全总览的可见性感知刷新与页头刷新按钮；
//   · 文案口径：威胁名单误报提示、拦截页 0 选项、封禁弹框副标题与详情 IP 入口、
//     累犯升级档列、CC 累计标签。
// 判定逻辑走 utils 真实代码（行为求值）；渲染点与双语词条以「源码钉 + 运行期词表
// 解析」双钉——只钉源码抓不到键缺失，只钉词表抓不到渲染点丢失。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { i18n } from '../src/i18n/index.ts'
import { code, elementSlice, section } from './_helpers.ts'
import { POLICY_DELETE_SCOPE_MAX_NAMES, POLICY_LIST_STATUS_TAG, policyDeleteScope, policyListStatus } from '../src/utils/securityPolicyList.ts'

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

// ── 策略列表「状态」列：启用 ≠ 生效 ──

test('策略列表状态｜目标：启用但零绑定判为「启用未关联规则」，其余两态不变', () => {
  assert.equal(policyListStatus(true, 0), 'enabledUnbound')
  assert.equal(policyListStatus(true, 3), 'enabled')
  assert.equal(policyListStatus(false, 0), 'disabled')
  assert.equal(policyListStatus(false, 3), 'disabled')
})

test('策略列表状态｜边界：1 条绑定即算已关联；禁用态不因零绑定改判', () => {
  assert.equal(policyListStatus(true, 1), 'enabled')
  assert.equal(policyListStatus(false, 1), 'disabled')
})

test('策略列表状态｜回归：未关联态必须是 warning 且词条写明「未关联规则」（不得再只显示「启用」）', () => {
  assert.equal(POLICY_LIST_STATUS_TAG.enabledUnbound.type, 'warning')
  assert.equal(POLICY_LIST_STATUS_TAG.enabled.type, 'success')
  assert.equal(POLICY_LIST_STATUS_TAG.disabled.type, 'info')
  assert.equal(zh(POLICY_LIST_STATUS_TAG.enabledUnbound.labelKey), '启用 · 未关联规则')
  assert.match(en(POLICY_LIST_STATUS_TAG.enabledUnbound.labelKey), /^Enabled · /)
  for (const tag of Object.values(POLICY_LIST_STATUS_TAG)) {
    assert.notEqual(zh(tag.labelKey), tag.labelKey, `zh 词条 ${tag.labelKey} 不得裸键回退`)
  }
})

test('策略列表状态｜渲染点：状态单元格的色与词条都经 policyListStatus 单源给出', () => {
  const labelAt = policies.indexOf(`:label="t('app.security.policies.table.status')"`)
  assert.ok(labelAt > 0, '状态列必须在场')
  const column = elementSlice(policies, policies.lastIndexOf('<el-table-column', labelAt), 'el-table-column')
  const statusOfRow = 'POLICY_LIST_STATUS_TAG\\[policyListStatus\\(row\\.enabled, row\\.rule_count\\)\\]'
  assert.equal([...column.matchAll(new RegExp(statusOfRow, 'g'))].length, 2, '标签色与标签文案必须各取一次单源判定（enabled 与 rule_count 同时参与）')
  assert.match(column, new RegExp(`:type="${statusOfRow}\\.type"`), '标签色必须取单源判定（不得再写 row.enabled ? success : info）')
  assert.match(column, new RegExp(`\\{\\{ t\\(${statusOfRow}\\.labelKey\\) \\}\\}`), '标签文案必须取单源词条键')
  assert.doesNotMatch(column, /row\.enabled \? 'success' : 'info'/, '二值标签形态不得残留')
})

// ── 删除策略确认：级联披露与降级 ──

test('删除披露｜目标：规则名可得时逐条具名，余量为零', () => {
  assert.deepEqual(policyDeleteScope(3, ['A', 'B', 'C']), { count: 3, names: ['A', 'B', 'C'], unnamed: 0 })
})

test('删除披露｜回归：规则名不可得时仍披露绑定数量（不得静默成「无关联」），也不用名字数冒充绑定数', () => {
  assert.deepEqual(policyDeleteScope(3, []), { count: 3, names: [], unnamed: 3 })
  assert.deepEqual(policyDeleteScope(5, ['A']), { count: 5, names: ['A'], unnamed: 4 })
})

test('删除披露｜边界：零绑定无级联；具名有上限且余量如实', () => {
  assert.deepEqual(policyDeleteScope(0, []), { count: 0, names: [], unnamed: 0 })
  const names = Array.from({ length: 30 }, (_, i) => `R${i + 1}`)
  const capped = policyDeleteScope(30, names)
  assert.equal(capped.names.length, POLICY_DELETE_SCOPE_MAX_NAMES)
  assert.equal(capped.unnamed, 30 - POLICY_DELETE_SCOPE_MAX_NAMES)
  assert.deepEqual(
    policyDeleteScope(POLICY_DELETE_SCOPE_MAX_NAMES, names.slice(0, POLICY_DELETE_SCOPE_MAX_NAMES)),
    { count: POLICY_DELETE_SCOPE_MAX_NAMES, names: names.slice(0, POLICY_DELETE_SCOPE_MAX_NAMES), unnamed: 0 },
    '恰好到上限不多报余量',
  )
})

test('删除披露｜渲染点：确认框以标准清单类列出规则名，名称取页内绑定快照、加载失败时降级', () => {
  const message = section(policies, 'const policyDeleteMessage = ', '\nfunction handleDelete')
  assert.match(
    message,
    /policyDeleteScope\(row\.rule_count, securityBindingsFailed\.value \? \[\] : policyBoundRules\(row\.id\)\.map\(\(rule\) => rule\.name\)\)/,
    '绑定数取列表行 rule_count；规则名取页内绑定快照，绑定加载失败传空（降级为只报数量）',
  )
  assert.match(message, /h\('p', \{ class: 'confirm-scope-lead' \}, t\('app\.security\.policies\.msg\.deleteScopeCountOnly', \{ n: scope\.count \}\)\)/, '无名可列时只报数量')
  assert.match(message, /h\('p', \{ class: 'confirm-scope-lead' \}, t\('app\.security\.policies\.msg\.deleteScopeLead', \{ n: scope\.count \}\)\)/, '引导行必须写明绑定数量')
  assert.match(message, /h\('ul', \{ class: 'confirm-scope-list' \}, \[/, '规则名清单必须走全局单源类')
  assert.match(message, /\.\.\.scope\.names\.map\(\(name\) => h\('li', name\)\)/, '逐条列出规则名')
  assert.match(message, /scope\.unnamed > 0 \? \[h\('li', t\('app\.security\.policies\.msg\.deleteScopeMore', \{ n: scope\.unnamed \}\)\)\] : \[\]/, '未具名余量必须显性标注')
  assert.match(section(policies, 'function handleDelete(', '\nconst goToCustomRulesPage'), /ElMessageBox\.confirm\(policyDeleteMessage\(row\), /, '删除确认必须消费级联披露')
})

test('删除披露｜词条：zh/en 成对且都带数量占位符', () => {
  for (const key of ['deleteScopeLead', 'deleteScopeCountOnly', 'deleteScopeMore']) {
    assert.match(zh(`app.security.policies.msg.${key}`), /\{n\}/, `zh ${key} 必须带 {n}`)
    assert.match(en(`app.security.policies.msg.${key}`), /\{n\}/, `en ${key} 必须带 {n}`)
  }
  assert.match(zh('app.security.policies.msg.deleteScopeLead'), /同时解除与 \{n\} 条规则的绑定/)
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

test('安全总览刷新｜30s 可见性感知刷新走单源，卸载停表；后台刷新不翻转重试按钮 loading', () => {
  assert.match(overview, /import \{ createVisibilityIntervals \} from '@\/composables\/useVisibilityIntervals'/)
  assert.match(overview, /createVisibilityIntervals\(\{ intervals: \[\{ tick: \(\) => \{ void reloadInBackground\(\) \}, ms: 30_000 \}\] \}\)/, '刷新必须交给可见性单源（隐藏页停表、恢复可见立即补一轮）')
  assert.match(overview, /onMounted\(overviewRefresh\.start\)/)
  assert.match(overview, /onBeforeUnmount\(overviewRefresh\.stop\)/, '离开页面必须停表')
  const background = section(overview, 'const reloadInBackground = async', '\nconst ')
  assert.doesNotMatch(background, /reloading\.value = true/, '后台刷新不得让重试按钮每 30s 闪一次 loading')
  assert.match(background, /if \(reloadInFlight\) return/, '手动刷新/上一轮后台刷新在途时让路')
  // 手动与后台共用同一组请求（六路不分叉）
  for (const fn of ['fetchData', 'fetchBlockedEvents', 'fetchAutobanStatus', 'fetchIP2RegionInfo', 'fetchThreatLib', 'fetchCrawlerLib']) {
    assert.equal(overview.split(`\n  ${fn}(),`).length, 2, `${fn} 必须只在请求组清单里出现一次（手动/后台共用）`)
  }
})

test('安全总览刷新｜页头刷新按钮（事件页同款）；「查看全部」带拦截筛选下钻', () => {
  const header = elementSlice(overview, overview.indexOf('<div class="page-header">'), 'div')
  assert.match(header, /<el-button :icon="Refresh" @click="reloadAll">\{\{ t\('app\.security\.overview\.page\.refresh'\) \}\}<\/el-button>/)
  assert.equal(zh('app.security.overview.page.refresh'), '刷新')
  assert.equal(en('app.security.overview.page.refresh'), 'Refresh')
  assert.match(
    section(overview, 'const goToEvents = ', '\n'),
    /window\.open\(pageUrl\('security-events', \{ \[DEEP_LINK_PARAMS\.eventsAction\]: 'blocked' \}\), '_blank', 'noopener'\)/,
    '「最近拦截事件」卡的下钻必须带 action=blocked',
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
