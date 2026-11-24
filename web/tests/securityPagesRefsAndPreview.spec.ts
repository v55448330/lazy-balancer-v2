// 安全规则页「引用策略」与拦截页预览的口径契约：
//   · 自定义规则列表的「引用策略」列与同页 IP 名单引用列同形：计数含禁用策略、
//     悬浮逐条标注启用态、零引用显示数字 0；
//   · 删除自定义规则的确认框必须披露引用面，只写条数、不列策略名（2026-11-24 用户
//     裁定：把数量写成一串名称属过度设计）：被启用策略引用 = 服务端拒绝删除
//     （409）；仅禁用策略引用 = 不阻止删除，但留下失效引用；
//   · 拦截页预览：编辑弹框内「预览」预览未保存草稿，与列表行预览走同一内容组装；
//     JSON 回退从页面 HTML 派生、空内容占位、非法 JSON 不抛错；
//   · 拦截页删除确认文案与删除门一致（被引用 = 不可删除，而非「策略将失去该页面」）。
// 判定逻辑走 utils 真实代码（行为求值）；渲染点与双语词条以「源码钉 + 运行期词表
// 解析」双钉——只钉源码抓不到键缺失，只钉词表抓不到渲染点丢失。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { i18n } from '../src/i18n/index.ts'
import { code, elementSlice, member, openTags, repoCode, section, webFiles } from './_helpers.ts'
import { refDeleteDisclosure } from '../src/utils/securityRefs.ts'
import { blockPagePreviewHtml, resolveBlockPageJson } from '../src/utils/blockPagePreview.ts'

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

// ── 引用披露判定（utils/securityRefs） ──

type RefRow = Parameters<typeof refDeleteDisclosure>[0]
const refRow = (over: Partial<RefRow> = {}): RefRow => ({ ref_count: 0, ref_count_enabled: 0, ref_policies: [], ...over })
const policy = (id: number, name: string, enabled = true) => ({ id, name, enabled })

test('引用披露｜零引用：无阻止、无失效引用', () => {
  assert.deepEqual(refDeleteDisclosure(refRow()), { state: 'none', enabledCount: 0, disabledCount: 0 })
})

test('引用披露｜被启用策略引用：阻止删除，启用/禁用分开计数', () => {
  const scope = refDeleteDisclosure(refRow({
    ref_count: 3,
    ref_count_enabled: 2,
    ref_policies: [policy(1, '后台保护'), policy(2, '灰度策略', false), policy(3, '默认策略')],
  }))
  assert.deepEqual(scope, { state: 'blocked', enabledCount: 2, disabledCount: 1 })
})

test('引用披露｜仅禁用策略引用：不阻止删除，失效引用条数如实给出', () => {
  const scope = refDeleteDisclosure(refRow({
    ref_count: 2,
    ref_count_enabled: 0,
    ref_policies: [policy(4, '停用A', false), policy(5, '停用B', false)],
  }))
  assert.deepEqual(scope, { state: 'disabledOnly', enabledCount: 0, disabledCount: 2 })
})

test('引用披露｜回归：缺 ref_count_enabled 时按 ref_policies 启用态推导，不得当成「无引用」', () => {
  const scope = refDeleteDisclosure(refRow({
    ref_count: 2,
    ref_count_enabled: undefined,
    ref_policies: [policy(1, 'A'), policy(2, 'B', false)],
  }))
  assert.deepEqual(scope, { state: 'blocked', enabledCount: 1, disabledCount: 1 }, '启用策略在引用就必须按阻止删除披露')
})

test('引用披露｜回归：ref_policies 拿不到时仍按计数披露（不得因缺明细而静默）', () => {
  assert.deepEqual(refDeleteDisclosure(refRow({ ref_count: 3, ref_count_enabled: 3 })), { state: 'blocked', enabledCount: 3, disabledCount: 0 })
  assert.deepEqual(refDeleteDisclosure(refRow({ ref_count: 3, ref_policies: null })), { state: 'disabledOnly', enabledCount: 0, disabledCount: 3 })
})

test('引用披露｜边界：结果只含状态与两个条数，不携带策略名（确认框不逐条具名）', () => {
  const names = Array.from({ length: 30 }, (_, i) => `策略${i + 1}`)
  const scope = refDeleteDisclosure(refRow({
    ref_count: 30,
    ref_count_enabled: 30,
    ref_policies: names.map((name, i) => policy(i + 1, name)),
  }))
  assert.deepEqual(scope, { state: 'blocked', enabledCount: 30, disabledCount: 0 })
  assert.deepEqual(Object.keys(scope).sort(), ['disabledCount', 'enabledCount', 'state'])
})

// ── 自定义规则「引用策略」列与删除确认（SecurityRules 渲染点） ──

const RULES = 'src/views/security/SecurityRules.vue'

test('引用策略列｜行类型承接列表接口的引用面（与 IP 名单行同形）', () => {
  const customRule = /interface CustomRule \{[^\n]*\}/.exec(code(RULES))?.[0]
  assert.ok(customRule, 'CustomRule 行类型必须存在')
  for (const field of ['ref_count: number', 'ref_count_enabled: number', 'ref_policies: SecurityRefPolicy[]']) {
    assert.ok(customRule.includes(field), `CustomRule 必须承接 ${field}`)
  }
})

test('引用策略列｜跨栈对表：字段名与后端列表行一致，删除门只数启用策略', () => {
  const handler = repoCode('internal/handlers/security.go')
  const row = /type customRuleListRow struct \{[\s\S]*?\n\}/.exec(handler)?.[0]
  assert.ok(row, '后端自定义规则列表行类型必须存在')
  for (const tag of ['json:"ref_count"', 'json:"ref_count_enabled"', 'json:"ref_policies"']) {
    assert.ok(row.includes(tag), `后端列表行必须输出 ${tag}`)
  }
  const del = section(handler, 'func (h *Handlers) DeleteSecurityCustomRule(', '\nfunc ')
  assert.match(del, /FROM security_policies WHERE enabled=1/, '删除门只数启用策略的引用——披露口径「启用」由此而来')
  assert.match(del, /http\.StatusConflict/)
})

test('引用策略列｜渲染点：计数 + 悬浮逐条具名 + 零引用占位，与 IP 名单引用列同形', () => {
  const text = code(RULES)
  const customTab = section(text, 'name="custom"', 'name="ip-lists"')
  const columnTag = openTags(customTab, 'el-table-column').find((tag) => tag.includes("t('common.app.views.secRules.customTab.colPolicyRefs')"))
  assert.ok(columnTag, '自定义规则表必须有「引用策略」列')
  const column = elementSlice(customTab, customTab.indexOf(columnTag), 'el-table-column')
  assert.match(column, /<el-tooltip v-if="row\.ref_policies\.length > 0" placement="top" popper-class="ip-list-refs-popper"/, '有引用时计数可悬浮展开')
  assert.match(
    column,
    /v-for="p in row\.ref_policies" :key="p\.id">\{\{ p\.name \}\}<template v-if="!p\.enabled">\{\{ t\('common\.app\.views\.secRules\.ipTab\.refDisabledNote'\) \}\}<\/template>/,
    '逐条列出策略名，禁用策略带标注',
  )
  assert.match(column, /<span>\{\{ row\.ref_count \}\}<\/span>/, '单元格显示引用总数（含禁用策略）')
  assert.match(column, /<template v-else>\{\{ row\.ref_count \}\}<\/template>/, '零引用显示数字 0（不再显示「未被引用」）')
  const ipTab = section(text, 'name="ip-lists"', '</el-tab-pane>')
  assert.match(ipTab, /<template v-else>\{\{ row\.ref_count \}\}<\/template>/, '同页 IP 名单引用列零值同口径')
})

test('删除自定义规则｜渲染点：确认框消费引用披露，只写条数、不列策略名，首行保留既有确认文案', () => {
  const text = code(RULES)
  const message = section(text, 'const customRuleDeleteMessage = ', '\nconst deletingCustomRuleId')
  assert.match(message, /const scope = refDeleteDisclosure\(row\)/, '披露判定必须走单源纯函数')
  assert.match(message, /h\('div', t\('common\.app\.views\.secRules\.msgs\.ruleDeleteConfirm', \{ name: row\.name \}\)\)/, '首行保留既有确认文案')
  assert.match(
    message,
    /scope\.state === 'blocked'[\s\S]*?t\('common\.app\.views\.secRules\.msgs\.ruleDeleteRefBlockedLead', \{ n: scope\.enabledCount \}\)/,
    '被启用策略引用必须写明条数',
  )
  assert.match(
    message,
    /scope\.disabledCount > 0[\s\S]*?t\('common\.app\.views\.secRules\.msgs\.ruleDeleteRefDisabledLead', \{ n: scope\.disabledCount \}\)/,
    '仅禁用策略引用同样必须披露',
  )
  assert.equal([...message.matchAll(/class: 'confirm-scope-lead'/g)].length, 2, '两段披露各一条引导行')
  assert.doesNotMatch(message, /confirm-scope-list|h\('li'|names|unnamed/, '只写条数，不得列出策略名')
  const del = member(text, 'const deleteCustomRule = (row: CustomRule)')
  assert.match(del, /ElMessageBox\.confirm\(customRuleDeleteMessage\(row\), t\('common\.app\.views\.secRules\.common\.confirm'\), \{ type: 'warning' \}\)/, '删除确认必须消费引用披露')
  assert.match(del, /request\.delete\(`\/security\/custom-rules\/\$\{row\.id\}`\)/, '确认后仍发 DELETE（列表可能过期，以服务端裁决为准）')
})

test('删除 IP 地址列表｜渲染点：被启用策略引用时确认框只追加一句数量（不列策略名），条数只数启用中的策略', () => {
  const text = code(RULES)
  const message = section(text, 'const ipListDeleteMessage = ', '\nconst deletingIpListId')
  assert.match(message, /const enabledCount = row\.ref_policies\.filter\(\(p\) => p\.enabled\)\.length/, '条数取行内引用面里启用中的策略')
  assert.match(
    message,
    /enabledCount === 0 \? confirm : h\('div', \[h\('div', confirm\), h\('p', \{ class: 'confirm-scope-lead' \}, t\('common\.app\.views\.secRules\.msgs\.ipListDeleteRefLead', \{ n: enabledCount \}\)\)\]\)/,
    '零启用引用只有首行确认文案；有引用追加一句带数量的引导行',
  )
  assert.doesNotMatch(message, /confirm-scope-list|h\('li'|p\.name/, '不得列出策略名')
  const del = member(text, 'const deleteIpList = (row: IPListRow)')
  assert.match(del, /ElMessageBox\.confirm\(ipListDeleteMessage\(row\), /, '删除确认必须消费引用披露')
  assert.match(del, /request\.delete\(`\/security\/ip-lists\/\$\{row\.id\}`\)/, '确认后仍发 DELETE（以服务端 409 裁决为准）')
  // 跨栈对表：列表行必须带逐策略启用态，删除门只数启用策略——披露的条数由此而来
  const handler = repoCode('internal/handlers/securityiplists.go')
  assert.match(handler, /Enabled\s+bool\s+`json:"enabled"`/, '列表行 ref_policies 必须带启用态')
  assert.match(section(handler, 'func (h *Handlers) DeleteIPList(', '\nfunc '), /FROM security_policies WHERE enabled=1/, '删除门只数启用策略的引用')
})

test('引用策略｜词条：列头 / 披露引导行 zh/en 双侧在位且可插值；「未被引用」词条键已移除', () => {
  assert.equal(zh('common.app.views.secRules.customTab.colPolicyRefs'), '引用策略')
  assert.ok(en('common.app.views.secRules.customTab.colPolicyRefs').length > 0)
  assert.equal(i18n.global.te('common.app.views.secRules.common.refNone', 'zh-CN'), false, 'zh 不得残留 refNone 词条键')
  assert.equal(i18n.global.te('common.app.views.secRules.common.refNone', 'en'), false, 'en 不得残留 refNone 词条键')
  assert.match(i18n.global.t('common.app.views.secRules.msgs.ipListDeleteRefLead', { n: 2 }, { locale: 'zh-CN' }), /^该名单正被 2 条启用中的安全策略引用/, 'IP 名单删除披露必须带条数并点明「启用」')
  assert.match(en('common.app.views.secRules.msgs.ipListDeleteRefLead'), /\{n\}/, 'IP 名单删除披露 en 词条必须带 {n}')
  const blockedLead = i18n.global.t('common.app.views.secRules.msgs.ruleDeleteRefBlockedLead', { n: 2 }, { locale: 'zh-CN' })
  assert.match(blockedLead, /^该规则正被 2 条启用中的安全策略引用/, '引导行必须带条数并点明「启用」')
  assert.match(zh('common.app.views.secRules.msgs.ruleDeleteRefDisabledLead'), /^引用该规则的 \{n\} 条策略均已禁用，不阻止删除/)
  for (const key of [
    'common.app.views.secRules.msgs.ruleDeleteRefBlockedLead',
    'common.app.views.secRules.msgs.ruleDeleteRefDisabledLead',
  ]) {
    assert.match(en(key), /\{n\}/, `${key} 的 en 词条必须带 {n} 插值`)
    assert.doesNotMatch(`${zh(key)}${en(key)}`.replaceAll('{n}', ''), /[{}]/, `${key} 不得出现 {n} 之外的花括号（vue-i18n 会当成插值）`)
    assert.doesNotMatch(zh(key), /[:：]$/, `${key} 是独立句子，不得以冒号结尾引出名称清单`)
  }
  assert.equal(i18n.global.te('common.app.views.secRules.msgs.ruleDeleteRefMore', 'zh-CN'), false, 'zh 不得残留「其余 N 条」词条键（不再逐条具名）')
  assert.equal(i18n.global.te('common.app.views.secRules.msgs.ruleDeleteRefMore', 'en'), false, 'en 不得残留 ruleDeleteRefMore 词条键')
})

// ── 拦截页预览内容组装（utils/blockPagePreview） ──

const EMPTY = '(空内容)'
const emptyHtml = `<p style="color: #999; padding: 20px; text-align: center">${EMPTY}</p>`

test('拦截页预览｜HTML 原样进沙箱（已保存页与未保存草稿同一组装）', () => {
  assert.equal(blockPagePreviewHtml('<h1>Denied</h1>', 'text/html; charset=utf-8', EMPTY), '<h1>Denied</h1>')
  assert.equal(blockPagePreviewHtml('<h1>Denied</h1>', undefined, EMPTY), '<h1>Denied</h1>', '缺内容类型按 HTML')
})

test('拦截页预览｜非 HTML 类型按源码展示并转义（srcdoc 恒按 HTML 解析）', () => {
  const out = blockPagePreviewHtml('<b>x&y</b>', 'application/json', EMPTY)
  assert.match(out, /^<pre style="[^"]*">/)
  assert.ok(out.includes('&lt;b&gt;x&amp;y&lt;/b&gt;'), '源码必须整体转义')
  assert.doesNotMatch(out, /<b>/, '不得把源码标签当 HTML 渲染')
})

test('拦截页预览｜空内容回落占位，占位文案转义', () => {
  assert.equal(blockPagePreviewHtml('', 'text/html', EMPTY), emptyHtml)
  assert.equal(blockPagePreviewHtml('   \n', 'text/html', EMPTY), emptyHtml, '纯空白草稿同样回落占位')
  assert.equal(
    blockPagePreviewHtml('', 'text/html', '<x>&'),
    '<p style="color: #999; padding: 20px; text-align: center">&lt;x&gt;&amp;</p>',
  )
})

test('拦截页预览｜JSON 回退从页面 HTML 的 <title> 派生，无标题回落默认消息', () => {
  assert.deepEqual(JSON.parse(resolveBlockPageJson('', '<html><head><title>访问被拒绝</title></head></html>')), { message: '访问被拒绝' })
  assert.deepEqual(JSON.parse(resolveBlockPageJson('   ', '<title>Access <b>Denied</b></title>')), { message: 'Access Denied' }, '标题内标签剥离')
  assert.deepEqual(JSON.parse(resolveBlockPageJson('', '<p>no title</p>')), { message: 'Request blocked' })
  assert.deepEqual(JSON.parse(resolveBlockPageJson('', '')), { message: 'Request blocked' })
})

test('拦截页预览｜已配置 JSON 原样展示；非法 JSON 不抛错（由保存前校验拦截）', () => {
  assert.equal(resolveBlockPageJson('  {"message":"custom"}  ', '<title>t</title>'), '{"message":"custom"}')
  assert.doesNotThrow(() => resolveBlockPageJson('{not json', '<title>t</title>'))
  assert.equal(resolveBlockPageJson('{not json', '<title>t</title>'), '{not json', '非法 JSON 原样交给高亮层')
})

// ── 拦截页预览渲染点（SecurityBlockPages） ──

const PAGES = 'src/views/security/SecurityBlockPages.vue'

test('拦截页预览｜渲染点：编辑弹框 footer 有「预览」按钮，预览未保存草稿且排在保存之前', () => {
  const text = code(PAGES)
  const dialog = elementSlice(text, text.indexOf('<el-dialog v-model="dialogVisible"'), 'el-dialog')
  const footerAt = dialog.indexOf('<template #footer>')
  assert.ok(footerAt > 0, '编辑弹框必须有 footer')
  const footer = dialog.slice(footerAt)
  const previewAt = footer.indexOf(`@click="previewDraft">{{ t('app.security.blockPages.dialog.preview') }}</el-button>`)
  const saveAt = footer.indexOf(`@click="handleSave">{{ t('app.security.blockPages.dialog.save') }}</el-button>`)
  assert.ok(previewAt > 0, '编辑弹框 footer 必须有「预览」按钮')
  assert.ok(saveAt > previewAt, '「预览」排在「保存」之前（取消 / 预览 / 保存）')
  const buttons = openTags(footer, 'el-button')
  const previewButton = buttons.find((tag) => tag.includes('@click="previewDraft"'))
  const saveButton = buttons.find((tag) => tag.includes('@click="handleSave"'))
  assert.ok(previewButton !== undefined && saveButton !== undefined)
  assert.ok(previewButton.includes(':disabled="saving"'), '保存中不得打开预览')
  const saveVisibility = /v-if="[^"]*"/.exec(saveButton)?.[0]
  assert.ok(saveVisibility !== undefined, '保存按钮必须带可见性条件')
  assert.ok(previewButton.includes(saveVisibility), '「预览」与「保存」同一可见性条件（只读/内置页只留「取消」）')
})

test('拦截页预览｜列表行与草稿共用同一内容组装（同一预览弹框、同一 iframe 沙箱）', () => {
  const text = code(PAGES)
  const assemble = member(text, 'const previewFromContent = (')
  assert.match(
    assemble,
    /previewContent\.value = blockPagePreviewHtml\(content, contentType, t\('app\.security\.blockPages\.preview\.emptyContent'\)\)/,
    'HTML 页签内容必须走 utils 单源组装',
  )
  assert.match(assemble, /previewJson\.value = resolveBlockPageJson\(jsonContent, content\)/, 'JSON 页签回退必须由同一份 HTML 派生')
  assert.match(assemble, /previewTab\.value = 'html'\s+previewKey\.value\+\+\s+previewVisible\.value = true/, '每次预览回到 HTML 页签并重建 iframe')
  assert.match(
    member(text, 'const previewPage = (row: BlockPage)'),
    /previewFromContent\(row\.content \|\| '', row\.json_content \|\| '', row\.content_type\)/,
    '列表行预览必须委托同一组装',
  )
  assert.match(
    member(text, 'const previewDraft = ('),
    /previewFromContent\(form\.value\.content, form\.value\.json_content, form\.value\.content_type\)/,
    '草稿预览必须读未保存的表单内容',
  )
  assert.equal(openTags(text, 'el-dialog').length, 2, '只有编辑弹框与预览弹框（草稿预览复用既有预览弹框）')
  assert.equal([...text.matchAll(/<iframe /g)].length, 1, '只有一个沙箱 iframe')
  assert.doesNotMatch(text, /resolvedJson\b/, 'SFC 内的旧 JSON 回退实现必须收敛到 utils 单源')
})

test('拦截页预览｜草稿预览显式标注「未保存、保存后生效」，已保存页预览不带该标注', () => {
  const text = code(PAGES)
  assert.match(member(text, 'const previewDraft = ('), /previewIsDraft\.value = true/)
  assert.match(member(text, 'const previewPage = (row: BlockPage)'), /previewIsDraft\.value = false/)
  const previewDialog = elementSlice(text, text.indexOf('<el-dialog v-model="previewVisible"'), 'el-dialog')
  assert.match(
    previewDialog,
    /<div v-if="previewIsDraft" class="info-note-bar"><span class="info-note-desc">\{\{ t\('app\.security\.blockPages\.preview\.draftNote'\) \}\}<\/span><\/div>/,
  )
  assert.equal(zh('app.security.blockPages.dialog.preview'), '预览')
  assert.equal(zh('app.security.blockPages.preview.draftNote'), '预览的是当前编辑内容（尚未保存），保存后才会生效')
  assert.match(en('app.security.blockPages.preview.draftNote'), /unsaved/i)
})

// ── 拦截页删除确认文案（与删除门一致） ──

test('拦截页删除确认｜文案与删除门一致：被引用=不可删除，不再声称「策略将失去该页面」', () => {
  const zhText = zh('app.security.blockPages.deleteConfirm.text')
  const enText = en('app.security.blockPages.deleteConfirm.text')
  assert.ok(zhText.includes('{name}') && enText.includes('{name}'), '确认文案必须点名页面')
  assert.doesNotMatch(zhText, /将失去/, 'zh 不得再声称引用策略会失去该页面（实际是不可删除）')
  assert.doesNotMatch(enText, /will lose/i, 'en 不得再声称引用策略会失去该页面')
  assert.match(zhText, /被启用中的安全策略引用时不可删除/, '文案陈述的删除门 = 启用策略引用（与后端 409 门同口径）')
  assert.match(enText, /can't be deleted while an enabled security policy references it/, 'en 与 zh 同口径')
  assert.match(
    member(code(PAGES), 'const handleDelete = (row: BlockPage)'),
    /ElMessageBox\.confirm\(t\('app\.security\.blockPages\.deleteConfirm\.text', \{ name: row\.name \}\)/,
    '删除确认必须消费该词条',
  )
  // 跨栈：文案陈述的那道删除门（启用策略引用）必须仍在——门口径一变，文案必须随之复核。
  const del = section(repoCode('internal/handlers/security.go'), 'func (h *Handlers) DeleteSecurityBlockPage(', '\nfunc ')
  assert.match(del, /FROM security_policies WHERE block_page_id=\? AND enabled=1/)
  // 规则级阶段拦截页已停用（前端无入口、写侧不再提交），后端为其保留的残留引用门
  // 不进用户文案——确认框只陈述用户在界面上解除得了的那道门。该功能一旦恢复入口，
  // 本断言转红：届时文案必须补上规则级引用。
  for (const dir of ['src/views', 'src/components', 'src/utils', 'src/composables']) {
    for (const file of webFiles(dir, ['.vue', '.ts'])) {
      assert.doesNotMatch(code(file), /block_page_stage[13]_id/, `${file} 出现规则级阶段拦截页字段：功能恢复入口后，删除确认文案必须补上规则级引用`)
    }
  }
})
