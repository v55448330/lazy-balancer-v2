// API 接入更名钉：设置页签/页头/描述三处词条更名且调用点仍走单源；
// Keys.vue 三新区块（MCP 接入卡/会话表/调用统计）接线与端点消费。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'
import { SETTINGS_TAB_IDS } from '../src/utils/settingsPages.ts'

test('更名词典：apikeys 页签/描述/页头 zh=API 接入 en=API access（zh/en 同位）', () => {
  const zh = code('src/locales/zh/views.ts')
  const en = code('src/locales/en/views.ts')
  // settingsTab.apikeys（侧栏+面包屑+Settings 页头单源 settingsPages 取词）
  assert.match(zh, /apikeys: 'API 接入'/, 'settingsTab.apikeys 必须为「API 接入」')
  assert.match(en, /apikeys: 'API access'/)
  // settingsDesc.apikeys
  assert.match(zh, /apikeys: '管理 API 密钥、MCP 接入与会话'/)
  assert.match(en, /apikeys: 'Manage API keys, MCP access and sessions'/)
  // keys.pageTitle / keys.pageDesc（Keys.vue 页头）
  assert.match(zh, /'pageTitle': 'API 接入'/)
  assert.match(zh, /'pageDesc': '管理 API 密钥、MCP 接入与会话'/)
  assert.match(en, /'pageTitle': 'API access'/)
  // 旧文案不得残留（改名残留=侧栏/页头漂移）
  assert.doesNotMatch(zh, /apikeys: 'API 密钥'/)
  assert.doesNotMatch(zh, /'pageTitle': 'API 密钥'/)
  assert.doesNotMatch(en, /apikeys: 'API keys'/)
})

test('页签清单不变：apikeys 仍是 SETTINGS_TAB_IDS 成员（更名不改键）', () => {
  assert.deepEqual([...SETTINGS_TAB_IDS], ['basic', 'cluster', 'certificates', 'apikeys', 'tasks'])
})

test('Keys.vue 页头与侧栏文案仍走词条单源（不改字面量）', () => {
  const text = code('src/views/Keys.vue')
  assert.match(text, /\{\{ t\('common\.app\.views\.keys\.pageTitle'\) \}\}/)
  assert.match(text, /\{\{ t\('common\.app\.views\.keys\.pageDesc'\) \}\}/)
  // 导航文案单源：AppLayout 侧栏 apikeys 项必须仍消费 NAV_LABELS
  const layout = code('src/components/layout/AppLayout.vue')
  assert.match(layout, /NAV_LABELS\['settings-apikeys'\]/)
})

test('Keys.vue 三 tab 投影：概览/密钥/MCP', () => {
  const text = code('src/views/Keys.vue')
  assert.match(text, /el-tabs/, '必须使用 tabs')
  assert.match(text, /apiActiveTab/, 'tab 状态必须在位')
  assert.match(text, /AccessStatsCards/, '统计卡必须在位')
  assert.match(text, /McpSessionsCard/, 'MCP 会话必须在位')
  assert.match(text, /keys-table/, '密钥表格必须在位')
})


test('API 密钥统计：api_keys 现成字段现算，不虚报调用计数', () => {
  const text = code('src/views/Keys.vue')
  const statsBlock = text.slice(text.indexOf('const ACTIVE_WINDOW_MS'), text.indexOf('const creating'))
  assert.match(statsBlock, /key\.is_enabled/, '启用数必须来自 is_enabled 现成字段')
  assert.match(statsBlock, /key\.last_used/, '近 7 天活跃必须来自 last_used 现成字段')
  assert.match(statsBlock, /7 \* 24 \* 60 \* 60 \* 1000/, '活跃窗口=7 天')
  assert.doesNotMatch(statsBlock, /today_calls|calls/, 'API 侧不得虚报调用计数（该数据不存在）')
})

test('接入仪表盘：REST/MCP 指标对称（今日调用/活跃维度/错误率）+趋势图+明细并排', () => {
  const text = code('src/views/settings/AccessStatsCards.vue')
  assert.match(text, /defineProps<\{\s*apiKeyStats: \{ total: number; enabled: number; active7d: number \}/)
  assert.match(text, /mcpStats: McpStats \| null/)
  // REST overview 端点数据（对称化的调用/错误率数据源）
  assert.match(text, /restStats:/, 'REST 列必须有 overview 数据 prop')
  // REST 侧指标（今日调用=overview、活跃密钥=api_keys、错误率=overview）
  for (const key of ['statTodayCalls', 'statActive7d', 'statErrorRate']) {
    assert.match(text, new RegExp(`t\\('app\\.notification\\.(keysUsage|keysAccess)\\.${key}'\\)`))
  }
  // MCP 侧同形态 tiles + TOP 工具 + 趋势
  for (const key of ['statTodayCalls', 'statActiveSessions', 'statErrorRate']) {
    assert.match(text, new RegExp(`t\\('app\\.notification\\.keysUsage\\.${key}'\\)`))
  }
  assert.match(text, /mcpStats\.top_tools/)
  assert.match(text, /props\.mcpStats\?\.trend \?\? \[\]/, '趋势缺数据必须空态而非抛错')
  assert.match(text, /recent_calls/, 'REST 最近调用明细必须在位')
  assert.match(text, /:label="t\('app\.notification\.keysUsage\.colTool'\)"/)
  // 仪表盘形态：ECharts 趋势（共享基线）+ Dashboard stat-item 网格，非 div bar
  assert.match(text, /v-chart/, '趋势必须用 ECharts（全站图表规范）')
  assert.match(text, /axisChartBase/, '图表必须经共享基线构建')
  assert.match(text, /class="stat-item"/, '统计必须 Dashboard stat-item 同构')
  assert.doesNotMatch(text, /trend-bar-track/, '旧 div 横条形态禁止回潮')
})

test('MCP 会话表消费会话契约：mine=1 / 管理员全平台 / 强制断开 / 全局开关', () => {
  const text = code('src/views/settings/McpSessionsCard.vue')
  assert.match(text, /request\.get<McpSessionsResponse>\(`\/security\/mcp-sessions\$\{query\}`\)/)
  assert.match(text, /isAdmin\.value \? '' : '\?mine=1'/, '管理员无参数=全平台；非管理员 mine=1')
  assert.match(text, /request\.post\(`\/security\/mcp-sessions\/\$\{encodeURIComponent\(row\.session_id\)\}\/disconnect`\)/)
  // 断开按钮管理员限定（非管理员列不渲染）
  assert.match(text, /v-if="isAdmin" :label="t\('app\.notification\.deliveries\.colAction'\)"/)
  const dialogBlock = text.slice(text.indexOf('const disconnect ='), text.indexOf('defineExpose'))
  assert.match(dialogBlock, /ElMessageBox\.confirm/, '强制断开必须先确认')
  // 全局开关（原接入卡唯一新有价值项）：管理员限定 + 最小 PUT + 停用提示
  assert.match(text, /v-model="mcpEnabled"/)
  const toggleBlock = text.slice(text.indexOf('const toggleMcp'), text.indexOf('const disconnect ='))
  assert.match(toggleBlock, /request\.put\('\/notification\/settings', \{ mcp_enabled: on \}\)/, '开关写入必须最小 PUT')
  assert.match(text, /v-if="!mcpEnabled"[^>]*class="mcp-disabled-note"/, '全局停用必须带提示语')
  assert.match(text, /t\('app\.notification\.keysSessions\.mcpDisabledNote'\)/)
})
