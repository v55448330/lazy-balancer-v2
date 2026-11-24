// API 接入页（Keys.vue）概览口径钉：
// ① 接入统计卡与 MCP 会话卡只对管理员渲染——两者消费的端点在后端挂在 admin 路由组，
//    非管理员不渲染（不发注定 403 的请求、不显示 0 值与失败横幅），改读说明条；
// ② 「API 最近调用」列头自明（时间/密钥/方法/路径/来源 IP/状态码），来源 IP 列消费
//    后端 recent_calls 的 ip 字段；同页 MCP 会话卡的来源列头与之同键同文案；
// ③ 密钥管理页签的空态只有表格内一份。
//
// 运行：cd web && node --test tests/keysAccessOverview.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import zhViews from '../src/locales/zh/views.ts'
import enViews from '../src/locales/en/views.ts'
import { code, openTags, repoCode } from './_helpers.ts'

const KEYS_PAGE = 'src/views/Keys.vue'
const STATS_CARDS = 'src/views/settings/AccessStatsCards.vue'
const SESSIONS_CARD = 'src/views/settings/McpSessionsCard.vue'

const NOTE_KEY = 'common.app.views.keys.statsAdminOnly'
const SOURCE_IP_KEY = 'common.app.views.keys.colSourceIp'

type Dict = Record<string, unknown>

/** 点路径取词条；取不到返回 undefined（由断言报缺失，不在此处抛错）。 */
const word = (tree: unknown, path: string): unknown =>
  path.split('.').reduce<unknown>((node, key) => (node !== null && typeof node === 'object' ? (node as Dict)[key] : undefined), tree)

/** `<template>` 段（已剥注释）——结构断言只落在标签上。 */
const templateOf = (file: string): string => {
  const text = code(file)
  const scriptAt = text.indexOf('<script')
  assert.ok(scriptAt > 0, `${file} 缺 <script>`)
  return text.slice(0, scriptAt)
}

/** 开标签的静态属性值（逐属性读取，不绑定属性书写顺序）；缺失返回 undefined。 */
const attr = (openTag: string, name: string): string | undefined =>
  openTag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1]

/** 开标签是否带某个指令（`v-if="…"` 取值形态与 `v-else` 布尔形态都算）。 */
const hasDir = (openTag: string, name: string): boolean =>
  new RegExp(`\\s${name}(?=[\\s/>=])`).test(openTag)

/**
 * `<el-tab-pane … name="…">` 页签段（到它的 `</el-tab-pane>`；页签互不嵌套）。
 */
const tabPane = (tpl: string, name: string): string => {
  const openTag = openTags(tpl, 'el-tab-pane').find((tag) => attr(tag, 'name') === name)
  assert.ok(openTag, `缺 ${name} 页签`)
  const start = tpl.indexOf(openTag)
  const end = tpl.indexOf('</el-tab-pane>', start)
  assert.ok(end > start, `页签 ${name} 缺闭合标签`)
  return tpl.slice(start, end)
}

/** 文本里首个 `<el-table` 开标签起到其 `</el-table>` 的整表段。 */
const tableAt = (tpl: string, marker: string): string => {
  const markerAt = tpl.indexOf(marker)
  assert.ok(markerAt > 0, `缺 ${marker}`)
  const start = tpl.lastIndexOf('<el-table', markerAt)
  assert.ok(start >= 0 && tpl.slice(start, markerAt).indexOf('>') === -1, `${marker} 必须落在 <el-table> 开标签内`)
  const end = tpl.indexOf('</el-table>', markerAt)
  assert.ok(end > start, '<el-table> 缺闭合标签')
  return tpl.slice(start, end)
}

test('概览页签：接入统计卡仅管理员渲染，非管理员读说明条', () => {
  const overview = tabPane(templateOf(KEYS_PAGE), 'overview')
  const statsTags = openTags(overview, 'AccessStatsCards')
  assert.equal(statsTags.length, 1, '接入统计卡只渲染一处')
  const statsTag = statsTags[0]!
  assert.equal(attr(statsTag, 'v-if'), 'isAdmin', '接入统计卡必须按管理员角色渲染')

  // 说明条是统计卡的 v-else 分支：v-else 只认紧邻的前一个兄弟节点
  const afterStats = overview.slice(overview.indexOf(statsTag) + statsTag.length)
  const nextTag = afterStats.match(/^\s*<[A-Za-z][\w-]*(?:[^>"']|"[^"]*"|'[^']*')*>/)?.[0]
  assert.ok(nextTag, '统计卡之后必须有说明条')
  assert.ok(hasDir(nextTag, 'v-else'), '说明条必须是统计卡的 v-else 分支（管理员不显示）')
  assert.equal(attr(nextTag, 'class'), 'info-note-bar', '说明条必须用标准 info-note-bar')
  const noteBody = afterStats.slice(nextTag.length, afterStats.indexOf('</div>', nextTag.length))
  assert.ok(noteBody.includes(`t('${NOTE_KEY}')`), '说明条必须引用 statsAdminOnly 词条')

  const sessionTags = openTags(overview, 'McpSessionsCard')
  assert.equal(sessionTags.length, 1, 'MCP 会话卡只渲染一处')
  assert.equal(attr(sessionTags[0]!, 'v-if'), 'isAdmin', 'MCP 会话卡必须按管理员角色渲染')

  // 接入方式卡（端点/鉴权/用途）不受管理员门影响：页签内不得出现整段门控的 <template v-if>
  const gatedTemplates = openTags(overview, 'template').filter((tag) => hasDir(tag, 'v-if'))
  assert.deepEqual(gatedTemplates, [], '概览页签不得用 <template v-if> 整段门控（会把接入方式卡一并藏掉）')
  const accessRow = openTags(overview, 'el-row').find((tag) => attr(tag, 'class') === 'keys-mcp-block')
  assert.ok(accessRow, '接入方式卡必须在位')
  assert.ok(!hasDir(accessRow, 'v-if') && !hasDir(accessRow, 'v-else'), '接入方式卡不得挂角色门')
})

test('非管理员不请求 admin 专属统计端点（不渲染即不发请求 + 统计拉取函数首句守卫）', () => {
  const script = code(KEYS_PAGE).slice(code(KEYS_PAGE).indexOf('<script'))
  const fetchAt = script.indexOf('const fetchMcpStats = async')
  assert.ok(fetchAt > 0, 'fetchMcpStats 必须在位')
  assert.match(
    script.slice(fetchAt),
    /^const fetchMcpStats = async \(\): Promise<void> => \{\s*if \(!isAdmin\.value\) return/,
    'fetchMcpStats 首句必须按管理员角色短路',
  )
})

test('对表后端：统计/会话端点挂在 admin 路由组（概览仅管理员渲染的依据）', () => {
  const routes = repoCode('internal/middleware/middleware.go')
  for (const route of ['admin.GET("/api-keys/access-overview"', 'admin.GET("/security/mcp-sessions"', 'admin.GET("/notification/mcp/stats"']) {
    assert.ok(routes.includes(route), `后端路由必须保持 admin 组（放开给普通用户时需同步放开概览渲染）：${route}`)
  }
})

test('API 最近调用列表头自明：时间/密钥/方法/路径/来源 IP/状态码', () => {
  const table = tableAt(templateOf(STATS_CARDS), ':data="restStats.recent_calls"')
  const columns = openTags(table, 'el-table-column').map((tag) => ({ prop: attr(tag, 'prop') ?? null, label: attr(tag, ':label') ?? attr(tag, 'label') ?? null }))
  assert.deepEqual(columns, [
    { prop: 'time', label: "t('app.notification.deliveries.colTime')" },
    { prop: 'key_name', label: "t('app.notification.keysSessions.colKey')" },
    { prop: 'method', label: "t('common.app.views.keys.colMethod')" },
    { prop: 'path', label: "t('common.app.views.keys.colPath')" },
    { prop: 'ip', label: `t('${SOURCE_IP_KEY}')` },
    { prop: null, label: "t('common.app.views.keys.colStatusCode')" },
  ])
  // 状态码单元格仍按 <400 成功/其余失败着色
  assert.match(table, /scope\.row\.status < 400 \? 'success' : 'danger'/, '状态码标签语义不得漂移')
})

test('MCP 侧列头：TOP 工具表「工具」列保留，会话卡来源列头与 REST 最近调用同键', () => {
  const topTools = tableAt(templateOf(STATS_CARDS), ':data="mcpStats.top_tools"')
  assert.ok(
    openTags(topTools, 'el-table-column').some((tag) => attr(tag, 'prop') === 'tool' && attr(tag, ':label') === "t('app.notification.keysUsage.colTool')"),
    'TOP 工具表的「工具」列头必须保留（该列确实是工具名）',
  )

  const sessionColumns = openTags(templateOf(SESSIONS_CARD), 'el-table-column')
  const sourceColumns = sessionColumns.filter((tag) => attr(tag, 'prop') === 'ip')
  assert.equal(sourceColumns.length, 1, 'MCP 会话卡必须有且只有一列来源地址')
  assert.equal(attr(sourceColumns[0]!, ':label'), `t('${SOURCE_IP_KEY}')`, 'MCP 会话卡来源列头必须与 REST 最近调用同键')
})

test('来源 IP 列的数据依据：后端 recent_calls 返回 ip 字段', () => {
  const go = repoCode('internal/services/api_call_stats.go')
  const structAt = go.indexOf('type RecentAPICall struct {')
  assert.ok(structAt > 0, 'RecentAPICall 必须在位')
  assert.match(go.slice(structAt, go.indexOf('}', structAt)), /IP\s+string\s+`json:"ip"`/, 'recent_calls 条目必须带 ip')
})

test('密钥管理页签空态单份：表格 :empty-text 直出，卡外不再叠 el-empty', () => {
  const pane = tabPane(templateOf(KEYS_PAGE), 'keys')
  assert.equal((pane.match(/common\.app\.views\.keys\.emptyText/g) ?? []).length, 1, '空态文案只出现一处')
  assert.ok(pane.includes(`:empty-text="t('common.app.views.keys.emptyText')"`), '空态必须由表格 :empty-text 直出')
  assert.equal((pane.match(/<el-empty\b/g) ?? []).length, 0, '卡外不得再叠第二份 el-empty')
  // 删的是重复空态，不是错误态：加载失败仍是显性横幅
  assert.ok(code(KEYS_PAGE).includes("t('common.app.views.keys.loadErrorBanner')"), '加载失败横幅必须在位')
})

test('词条：说明条与四个列头 zh/en 成对', () => {
  const zh = zhViews as unknown
  const en = enViews as unknown
  const expected: ReadonlyArray<readonly [string, string, string]> = [
    ['statsAdminOnly', '接入统计与 MCP 会话仅管理员可查看', 'Access statistics and MCP sessions are visible to administrators only'],
    ['colMethod', '方法', 'Method'],
    ['colPath', '路径', 'Path'],
    ['colSourceIp', '来源 IP', 'Source IP'],
    ['colStatusCode', '状态码', 'Status'],
  ]
  for (const [key, zhText, enText] of expected) {
    assert.equal(word(zh, `app.views.keys.${key}`), zhText, `zh keys.${key} 漂移`)
    assert.equal(word(en, `app.views.keys.${key}`), enText, `en keys.${key} 漂移`)
  }
})
