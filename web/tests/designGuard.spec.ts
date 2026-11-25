// 全仓前端设计守卫（DESIGN_SPEC.md 的机器化落地，用户裁定 2026-11-19 第四轮）：
// 后续任何前端新增/修改违反设计标准即红、无法交付。规则与豁免同口径：
// 豁免必须登记理由（legacy 内嵌面板/百分号输入），条目失效（文件改合规）即红。
//
// 运行：cd web && npm test（node --test 自动纳入）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, webFiles } from './_helpers.ts'

// shadow="never" 豁免：对话框内嵌面板（dialog-panel--flush），非页面级卡片。
// 页面级 list-card/图表卡一律默认 always（DESIGN_SPEC §2）。
const SHADOW_NEVER_EXEMPT = [
  'src/components/rules/PathRulesEditor.vue', // 规则编辑弹框内嵌路径面板
]
// v-model.number 豁免：权重百分号输入（el-input-number 无 % suffix 形态）。
// 其余数字输入一律 el-input-number（DESIGN_SPEC §8）。
const VMODEL_NUMBER_EXEMPT = [
  'src/components/rules/PathRulesEditor.vue', // upstream.weight 带 % suffix
]

test('设计守卫：禁止 window.confirm/window.alert（确认一律 ElMessageBox）', () => {
  for (const f of webFiles('src', ['.vue', '.ts'])) {
    const src = code(f)
    assert.ok(!/window\.(confirm|alert)\(/.test(src), `${f} 使用 window.confirm/alert，违反 DESIGN_SPEC §7`)
  }
})

test('设计守卫：v-chart 必须经 chartBase/统一 echarts 注册（禁手搓图表）', () => {
  for (const f of webFiles('src', ['.vue'])) {
    const src = code(f)
    if (!src.includes('<v-chart')) continue
    assert.ok(
      src.includes('chartBase') || src.includes('utils/echarts'),
      `${f} 使用 v-chart 但未导入 chartBase/utils/echarts，违反 DESIGN_SPEC §4`,
    )
  }
})

test('设计守卫：shadow="never" 仅限登记的内嵌面板（页面卡默认 always）', () => {
  const hits: string[] = []
  for (const f of webFiles('src', ['.vue'])) {
    if (code(f).includes('shadow="never"')) hits.push(f)
  }
  for (const f of hits) {
    assert.ok(SHADOW_NEVER_EXEMPT.includes(f), `${f} shadow="never" 未登记豁免，违反 DESIGN_SPEC §2`)
  }
  // 豁免条目必须仍在违规（改合规后应删除条目，防豁免漂移）
  for (const f of SHADOW_NEVER_EXEMPT) {
    assert.ok(hits.includes(f), `豁免 ${f} 已无 shadow="never"，请从 SHADOW_NEVER_EXEMPT 删除`)
  }
})

test('设计守卫：v-model.number 仅限登记的百分号输入（其余 el-input-number）', () => {
  const hits: string[] = []
  for (const f of webFiles('src', ['.vue'])) {
    if (code(f).includes('v-model.number')) hits.push(f)
  }
  for (const f of hits) {
    assert.ok(VMODEL_NUMBER_EXEMPT.includes(f), `${f} v-model.number 未登记豁免，违反 DESIGN_SPEC §8`)
  }
  for (const f of VMODEL_NUMBER_EXEMPT) {
    assert.ok(hits.includes(f), `豁免 ${f} 已无 v-model.number，请从 VMODEL_NUMBER_EXEMPT 删除`)
  }
})

test('设计守卫：通知/密钥面表头左对齐（设计标准 bearer，禁 center/right）', () => {
  const bearers = [
    'src/views/notifications/NotificationCenter.vue',
    'src/views/notifications/DeliveryLog.vue',
    'src/views/notifications/ChannelCards.vue',
    'src/views/Keys.vue',
  ]
  for (const f of bearers) {
    const src = code(f)
    assert.ok(!/align="(center|right)"/.test(src), `${f} 表头/列 align=center/right，违反表头左对齐标准`)
  }
})

test('设计守卫：通知面标准（描述类/分区竖条/弹框体高度/预览固定/多选去对号）', () => {
  const nc = code('src/views/notifications/NotificationCenter.vue')
  // 描述必须用标准类，禁自写 hint 覆写
  assert.ok(!/tpl-lang-hint/.test(nc), '描述禁用自写 tpl-lang-hint（应 form-tip-inline）')
  assert.match(nc, /class="form-tip-inline"/, '同行描述必须用 form-tip-inline')
  assert.match(nc, /class="form-tip-line"/, '块级描述必须用 form-tip-line')
  // 分区标题彩色竖条：DialogSectionHeader
  assert.match(nc, /import DialogSectionHeader from '@\/components\/DialogSectionHeader\.vue'/, '分区标题必须用 DialogSectionHeader')
  assert.match(nc, /<DialogSectionHeader :title="tplEditorLabel" \/>/, '内容模板分区标题带竖条')
  // 弹框体限高与内部滚动走全局单源（DESIGN_SPEC §26-2）：组件自写的 max-height 公式
  // （曾有 100dvh − 180px / 100vh − 300px 两份，后者静默覆盖前者）一律废止。
  assert.ok(!/\.rule-edit-dialog[^}]*max-height/.test(nc), '模板弹框体限高必须走全局（禁自写公式）')
  assert.match(nc, /\.rule-edit-dialog \.el-dialog__body \{ overflow-x: hidden; \}/, '预览弹框体禁横向滚动（§16）')
  // 预览固定高度（2026-11-22 裁定：独立日报预览弹框下线，预览统一收敛到编辑消息模板弹框）
  assert.match(nc, /height: 360px; max-height: 46vh/, '预览区必须固定高度')
  assert.ok(!/daily-preview-dialog/.test(nc), '独立日报预览弹框已下线（不得残留弹框类）')
  // bordered 多选隐藏勾选对号
  assert.match(nc, /\.notif-pick-group \.el-checkbox\.is-bordered \.el-checkbox__inner \{ display: none; \}/, 'bordered 多选必须隐藏勾选对号')
  // 卡头保存为实体按钮（非 link）
  assert.ok(!/link type="primary" :loading="savingDaily"/.test(nc), '每日摘要保存必须为实体按钮（与规则卡头一致）')
})

test('设计守卫：保存/删除确认的后果清单（DESIGN_SPEC §20）', () => {
  const rules = code('src/views/Rules.vue')
  // 规则删除确认必须列出后端真实级联对象（不得只有一句「确定删除吗」）
  assert.match(rules, /ruleDeleteScopeLead/, '删除确认必须引导查看级联清单')
  assert.match(rules, /h\('ul', \{ class: 'confirm-scope-list' \}, deleteScopeItems\.map/, '删除确认必须以 .confirm-scope-list 列出级联对象')
  // 保存响应 warnings 同形逐条披露（创建与更新同口径）
  assert.match(rules, /h\('ul', \{ class: 'confirm-scope-list' \}, submitWarnings\.map/, '保存披露必须以同一清单形态逐条展示')
  // 钉三元形态本身：只要求键出现过的话，把创建/更新的标题写反也绿。
  assert.match(rules, /t\(wasEditing \? '[^']*ruleUpdatedNotice' : '[^']*ruleCreatedNotice'\)/, '披露标题：更新走 ruleUpdatedNotice、创建走 ruleCreatedNotice（三元不得写反）')
  // 删除清单必须覆盖后端同删的证书文件与日志文件（removeRuleCertFiles / RemoveRuleLogFiles）
  assert.match(rules, /ruleDeleteScopeCertFiles/, '删除清单必须列出证书文件')
  assert.match(rules, /ruleDeleteScopeLogFiles/, '删除清单必须列出日志文件')
  // 禁用同样披露影响面（流量中断 + 防护失效），同样用标准清单类
  assert.match(rules, /ruleDisableScopeLead/, '禁用确认必须披露影响面')
  assert.match(rules, /h\('ul', \{ class: 'confirm-scope-list' \}, \[/, '禁用影响面必须以 .confirm-scope-list 列出')
  // 披露条件必须按「目标状态」判断：开关 v-model 先行翻转，进入处理函数时
  // rule.enabled 已是目标态。写成当前态会把条件写反（浏览器实测抓到过）。
  assert.match(rules, /const nextEnabled = rule\.enabled[\s\S]{0,600}?const toggleBody = !nextEnabled/, '禁用披露必须以目标状态为准（!nextEnabled）')
  // 单源：该类只允许定义在 main.css
  const css = code('src/styles/main.css')
  assert.match(css, /\.confirm-scope-list \{/, '.confirm-scope-list 必须定义在 main.css')
  assert.match(css, /\.confirm-scope-lead \{/, '.confirm-scope-lead 必须定义在 main.css')
  for (const f of webFiles('src', ['.vue'])) {
    assert.ok(!/^\.confirm-scope-(list|lead) \{/m.test(code(f)), `${f} 重复定义 .confirm-scope-* 全局类（DESIGN_SPEC §20 单源）`)
  }
})

test('设计守卫：不可逆封禁必须披露永久生效与累犯清零', () => {
  const add = code('src/composables/useIpListAdd.ts')
  assert.match(add, /options\.ban \? t\('common\.app\.views\.ipAdd\.banNote'\)/, 'useIpListAdd 必须支持 ban 披露')
  const assoc = code('src/composables/useTrustAssociation.ts')
  // 逐调用点钉（两处各有独立参数对象；只钉「出现过一次」会让单点变异假绿）
  assert.match(assoc, /addIpToList\(ip, list, \{ verb, ban: side === 'deny', successText:/, 'joinSpecificList 的 deny 侧必须传 ban 披露')
  assert.match(assoc, /addIpToList\(ip, opt, \{ verb: cfg\.verb, ban: side === 'deny', successText:/, 'ensureListAndJoin 的 deny 侧必须传 ban 披露')
  assert.equal((assoc.match(/ban: side === 'deny'/g) ?? []).length, 2, 'deny 侧 ban 披露必须恰好覆盖两个调用点')
  assert.match(assoc, /const banNote = side === 'deny' \? t\('common\.app\.views\.ipAdd\.banNote'\)/, '自动建单确认同样披露封禁后果')
  // deny 侧共四条写路径：复用既有名单的确认绕过 addIpListAdd 直发 POST，同样必须带披露
  assert.match(assoc, /confirmJoinExisting', \{ ip, name: reuseTarget\.name, tip, note: banNote/, '复用既有名单的确认必须带封禁披露')
  const viewsZh = code('src/locales/zh/views.ts')
  assert.match(viewsZh, /'confirmJoinExisting': '[^']*\{tip\}\{note\}/, '复用既有名单的词条必须有 note 槽位')
  // 关闭接入的确认名词必须是卡片标题而非开关文案（否则成「确定关闭启用 API 接入吗」）
  const keysNaming = code('src/views/Keys.vue')
  assert.match(keysNaming, /accessName = t\(kind === 'api' \? 'app\.notification\.keysAccess\.apiCardTitle' : 'app\.notification\.keysAccess\.mcpCardTitle'\)/, '接入关闭确认的名词必须取卡片标题')
  // SMTP 凭据页写的是同一端点，从节点必须同样禁写（与 Keys.vue 两个开关同门）
  const creds = code('src/views/notifications/SystemCredentials.vue')
  assert.match(creds, /:disabled="!canSave \|\| nodeWriteBlocked"/, 'SMTP 凭据页保存在从节点必须禁用')
  assert.match(creds, /:disabled="!form\.smtpHost \|\| nodeWriteBlocked"/, 'SMTP 凭据页测试在从节点必须禁用')
  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /ban: true/, '候选行封禁必须传 ban 披露')
  assert.match(events, /disableScopePermanent/, '禁用自动封禁必须披露永久条目不会解除')
  const zh = code('src/locales/zh/views.ts')
  assert.match(zh, /'banNote': '封禁立即生效且默认永久/, '封禁披露文案必须写明永久')
})

test('设计守卫：全局 API / MCP 接入开关关闭必须披露后果且从节点不可拨', () => {
  const keys = code('src/views/Keys.vue')
  assert.match(keys, /const confirmAccessOff = async/, '关闭全局接入必须走确认')
  assert.match(keys, /h\('ul', \{ class: 'confirm-scope-list' \}, scope\.map/, '接入关闭确认必须用标准清单类披露后果')
  assert.match(keys, /if \(!on && !\(await confirmAccessOff\('api'\)\)\)/, '关闭 API 接入必须确认')
  assert.match(keys, /if \(!on && !\(await confirmAccessOff\('mcp'\)\)\)/, '关闭 MCP 接入必须确认')
  // 从节点：后端 requireNotifyMaster 已拒写，开关必须同步禁用并给出原因
  const switches = keys.match(/<el-switch v-if="isAdmin" v-model="(apiEnabled|mcpEnabled)"[^>]*>/g) ?? []
  assert.equal(switches.length, 2, '应有两个全局接入开关')
  for (const sw of switches) {
    assert.match(sw, /:disabled="switchSaving \|\| nodeWriteBlocked"/, '接入开关在从节点必须禁用')
  }
  assert.equal((keys.match(/<el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">\s*<div>\s*<el-switch v-if="isAdmin"/g) ?? []).length, 2, '两个开关都必须带禁用原因提示')
})

test('设计守卫：空白名单策略绑定入口必须警示并确认', () => {
  const editor = code('src/components/SecurityBindingEditor.vue')
  assert.match(editor, /acl_empty_allow\?: boolean/, '策略行必须承接后端摘要的空白名单判定')
  assert.match(editor, /v-if="policy.acl_empty_allow"[^>]*type="warning"/, '空白名单策略在选项行必须有警示标记')
  assert.match(editor, /v-if="currentPolicyEmptyAllow" class="info-note-bar"/, '策略侧绑定弹框必须有整页警示条')
  const submit = editor.slice(editor.indexOf('const submit = async'))
  // 规则侧：提交前确认（取消即不提交）
  assert.match(submit, /if \(emptyAllowSelected\.value\.length > 0\) \{[\s\S]*?if \(!\(await confirmEmptyAllow\(/, '规则侧提交前必须确认空白名单策略')
  // 策略侧：只对「本次新绑定」的规则确认
  assert.match(submit, /if \(currentPolicyEmptyAllow\.value && toBind\.length > 0\) \{[\s\S]*?if \(!\(await confirmEmptyAllow\(/, '策略侧提交前必须确认空白名单策略')
  assert.match(editor, /h\('ul', \{ class: 'confirm-scope-list' \}, names\.map/, '确认清单必须用标准清单类')
})

test('设计守卫：说明块内的行内链接随正文字号（DESIGN_SPEC §21-1）', () => {
  const css = code('src/styles/main.css')
  assert.match(css, /\.form-tip-line \.el-link,\n\.form-tip-inline \.el-link,\n\.info-note-bar \.el-link \{\s*font-size: inherit;\s*vertical-align: baseline;\s*\}/, '三个说明块内的 el-link 必须 font-size: inherit')
})

test('设计守卫：证书有效期文案单源，负数天数不上屏（DESIGN_SPEC §21-2）', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(code('src/utils/certExpiry.ts'), /daysUntilExpiry < 0[\s\S]*?expiredDaysAgo[\s\S]*?expiresToday[\s\S]*?expiresInDays/, '有效期结论必须由 utils/certExpiry 的 certExpiryConclusion 单源给出')
  assert.match(rules, /certExpiryConclusion\(certInfo\.daysUntilExpiry\)\.text/, '向导预览行与 TLS 步提示框必须消费单源')
  assert.match(code('src/components/RuleFlowDialog.vue'), /certExpiryConclusion\(certInfo\.days_remaining, certInfo\.status === 'expired'\)\.text/, '处理流程弹框的剩余天数行必须消费单源并带过期状态')
  // 模板与计算属性之外不得再把带符号的剩余天数直接喂给词条
  assert.doesNotMatch(rules, /\{ n: certInfo\.daysUntilExpiry \}/, '不得直接渲染 certInfo.daysUntilExpiry')
  assert.match(rules, /class="cert-preview-row"/, '预览行必须同一行对齐')
  assert.match(rules, /<dl class="cert-facts">[\s\S]*?<ul v-if="certWarnings\.length > 0" class="cert-warn-list">/, '提示框必须分证书事实与警告列表两段')
  assert.match(code('src/locales/zh/rules.ts'), /expiredDaysAgo: '已过期 \{n\} 天'/, '过期文案必须是「已过期 N 天」')
})

test('设计守卫：从节点 / 只读页面的写表单整体禁用（DESIGN_SPEC §21-3）', () => {
  const creds = code('src/views/notifications/SystemCredentials.vue')
  assert.match(creds, /<el-form [^>]*:disabled="saving \|\| nodeWriteBlocked"/, 'SMTP 凭据表单必须在从节点整体禁用')
  // 表单级禁用会被控件上的显式 :disabled="false" 压过（用户实测：「跳过证书校验」开关在从节点仍可拨）
  assert.match(creds, /:disabled="nodeWriteBlocked \|\| !form\.smtpTls"/, 'SMTP 页带显式禁用的开关必须同时带只读判据')
  const keys = code('src/views/Keys.vue')
  assert.match(keys, /:disabled="creating \|\| nodeWriteBlocked"/, '新建密钥表单必须在从节点整体禁用')
  assert.match(keys, /:disabled="featureSaving \|\| nodeWriteBlocked"/, '功能配置表单必须在从节点整体禁用')
  assert.equal((keys.match(/:disabled="!isAdmin \|\| nodeWriteBlocked" \/>/g) ?? []).length, 4, '四个只读开关的显式禁用必须同时带只读判据')
  assert.doesNotMatch(keys + creds, /:disabled="!(isAdmin|form\.smtpTls)" \/>/, '显式 :disabled 不得压过表单级只读')
})

test('设计守卫：规则选择器次行提示对齐与间距（DESIGN_SPEC §21-4）', () => {
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /\.rule-binding-preview \{[^}]*margin: 2px 0 4px 22px; \}/, '预览行左边缘必须等于协议标签左边缘（22px）')
  assert.match(policies, /\.rule-binding-preview\.is-empty \{ margin-top: 8px; \}/, '无已绑策略时必须留出间距')
  assert.match(policies, /class="rule-binding-preview" :class="\{ 'is-empty': pickerMeta\(rule\)\.blockReason === '' && pickerMeta\(rule\)\.chain\.length === 0 \}"/, '空态必须落 is-empty')
  const editor = code('src/components/SecurityBindingEditor.vue')
  assert.match(editor, /\.picker-rule-detail \{[^}]*margin: 2px 0 2px 22px; \}/, '绑定规则弹框明细行左边缘必须等于协议标签左边缘（22px）')
  assert.match(editor, /\.picker-rule-detail\.is-empty \{ margin-top: 8px; \}/, '绑定规则弹框空态必须留出间距')
  assert.match(editor, /class="picker-rule-detail" :class="\{ 'is-empty': \(bindings\[rule\.caddy_id\] \|\| \[\]\)\.length === 0 \}"/, '绑定规则弹框空态必须落 is-empty')
})

test('设计守卫：策略状态列即开关 / 删除策略只报绑定数量 / 深链过值域（DESIGN_SPEC §22、§24-1）', () => {
  const policies = code('src/views/security/SecurityPolicies.vue')
  const statusColumn = /<el-table-column :label="t\('app\.security\.policies\.table\.status'\)"[\s\S]*?<\/el-table-column>/.exec(policies)?.[0] ?? ''
  assert.match(statusColumn, /<el-switch\s+v-model="row\.enabled"/, '状态列直接放启停开关（用户裁定：开关替代状态标签，不另设列）')
  assert.doesNotMatch(statusColumn, /<el-tag/, '状态列不再并列「启用/禁用」标签')
  assert.equal([...policies.matchAll(/<el-switch\s+v-model="row\.enabled"/g)].length, 1, '行内启停开关全页只此一个（操作列不得再有）')
  assert.doesNotMatch(policies, /policyListStatus|POLICY_LIST_STATUS_TAG|enabledUnbound/, '「启用 · 未关联规则」复合状态已按用户裁定回退，不得重做（列表已有关联规则数量列）')
  assert.match(policies, /policyDeleteScope\(/, '删除策略的绑定解除数量必须经单源计算')
  const deleteMessage = /const policyDeleteMessage = \(row: PolicySummary\) => \{[\s\S]*?\n\}/.exec(policies)?.[0] ?? ''
  assert.match(deleteMessage, /policies\.msg\.deleteScopeLead', \{ n: count \}\)/, '删除策略确认必须写明将解除绑定的规则数量')
  assert.doesNotMatch(deleteMessage, /confirm-scope-list|h\('li'|names/, '只报数量，不列规则名（用户裁定）')
  const overview = code('src/views/security/SecurityOverview.vue')
  assert.doesNotMatch(overview, /createVisibilityIntervals\(|overviewRefresh|page\.refresh/, '安全总览的刷新按钮与自动刷新已按用户裁定回退，不得重做（数据量大时正在看会被刷新）')
  assert.match(code('src/views/security/SecurityEvents.vue'), /parseSecurityEventsDeepLink\(window\.location\.search\)/, '事件页必须消费深链解析单源')
})

test('设计守卫：规则列表的刷新轮询与日志直达入口已按用户裁定回退，不得重做', () => {
  const rules = code('src/views/Rules.vue')
  assert.doesNotMatch(rules, /refreshRuleList|ruleListRefresh|ruleListPollPaused|RULE_LIST_POLL_MS/, '规则列表不加刷新按钮、不做轮询（用户裁定过度设计）')
  assert.doesNotMatch(rules, /logEnableEntry|openWizardForAccessLog|unpublishedRecoverHint/, '日志未开启时不给「去开启」入口、「未发布」不给恢复指引（用户裁定过度设计）')
  assert.doesNotMatch(rules, /protocolSwitchImpact|ElMessageBox\.confirm\(\s*h\('div', \[\s*h\('p', \{ class: 'confirm-scope-lead' \}, t\('common\.app\.rules\.msgs\.switchTcpClearsLead/, '向导切协议前不弹确认框（用户裁定过度设计）')
})

test('设计守卫：全站直角——登录卡片 / SSO 按钮 / 侧栏菜单项 / 节点标签 / 导入面板标签与分组框（DESIGN_SPEC §1）', () => {
  // 基线钉测：这些选择器已按用户裁定归零（此前登录卡片 12px、SSO 按钮 10px、
  // 侧栏菜单项 6px、节点标签 8px、导入面板标签胶囊形），守卫防止回潮。
  const ruleBody = (file: string, selector: RegExp): string => {
    const match = new RegExp(`${selector.source}\\s*\\{([^}]*)\\}`).exec(code(file))
    assert.ok(match, `${file} 必须有 ${selector.source} 规则`)
    return match[1]
  }
  assert.match(ruleBody('src/views/Login.vue', /\.login-card/), /border-radius:\s*0;/, '登录卡片必须直角')
  assert.match(ruleBody('src/views/Login.vue', /\.oidc-sso-btn/), /border-radius:\s*0;/, 'SSO 登录按钮必须直角')
  assert.match(ruleBody('src/components/layout/AppLayout.vue', /\.layout-menu :deep\(\.el-menu-item\),\s*\.layout-menu :deep\(\.el-sub-menu__title\)/), /border-radius:\s*0;/, '侧栏菜单项必须直角')
  assert.match(ruleBody('src/components/layout/AppLayout.vue', /\.layout-menu :deep\(\.el-sub-menu \.el-menu-item\)/), /border-radius:\s*0;/, '侧栏子菜单项必须直角')
  assert.match(ruleBody('src/components/layout/AppLayout.vue', /\.node-tag/), /border-radius:\s*0;/, '节点标签必须直角')
  assert.match(ruleBody('src/views/settings/BasicSettings.vue', /\.section-chip/), /border-radius:\s*0;/, '备份分类标签必须直角')
  assert.match(ruleBody('src/views/settings/BasicSettings.vue', /\.import-summary-chip/), /border-radius:\s*0;/, '导入摘要标签必须直角')
  assert.match(ruleBody('src/views/settings/BasicSettings.vue', /\.import-sections/), /border-radius:\s*0;/, '导入分组框必须直角')
  assert.match(ruleBody('src/views/Dashboard.vue', /\.status-code/), /border-radius:\s*0;/, '仪表盘状态码标签必须直角')
})
