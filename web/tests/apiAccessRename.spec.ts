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

test('Keys.vue 三新区块接线：接入卡/会话表/调用统计', () => {
  const text = code('src/views/Keys.vue')
  for (const comp of ['McpAccessCard', 'McpSessionsCard', 'McpUsageCard']) {
    assert.match(text, new RegExp(`import ${comp} from './settings/${comp}\\.vue'`), `${comp} 必须落位 settings 域`)
  }
  const blocksStart = text.indexOf("<el-divider content-position=\"left\" class=\"section-divider\">{{ t('app.notification.keysAccess.title') }}")
  assert.ok(blocksStart > 0, 'MCP 区块分隔标题缺失')
  const blocks = text.slice(blocksStart, text.indexOf('<el-dialog', blocksStart))
  assert.match(blocks, /<McpAccessCard :stats="mcpStats"/)
  assert.match(blocks, /<McpSessionsCard/)
  // 调用统计是管理员数据（/notification/mcp/stats 契约管理员限定）
  assert.match(blocks, /<McpUsageCard v-if="isAdmin" :stats="mcpStats"/)
  // 统计单次拉取：管理员门 + 端点
  assert.match(text, /if \(!isAdmin\.value\) return/, 'stats 拉取必须管理员限定')
  assert.match(text, /request\.get<McpStatsResponse>\('\/notification\/mcp\/stats'\)/)
})

test('MCP 会话表消费会话契约：mine=1 / 管理员全平台 / 强制断开', () => {
  const text = code('src/views/settings/McpSessionsCard.vue')
  assert.match(text, /request\.get<McpSessionsResponse>\(`\/security\/mcp-sessions\$\{query\}`\)/)
  assert.match(text, /isAdmin\.value \? '' : '\?mine=1'/, '管理员无参数=全平台；非管理员 mine=1')
  assert.match(text, /request\.post\(`\/security\/mcp-sessions\/\$\{encodeURIComponent\(row\.session_id\)\}\/disconnect`\)/)
  // 断开按钮管理员限定（非管理员列不渲染）
  assert.match(text, /v-if="isAdmin" :label="t\('app\.notification\.deliveries\.colAction'\)"/)
  const dialogBlock = text.slice(text.indexOf('const disconnect ='), text.indexOf('defineExpose'))
  assert.match(dialogBlock, /ElMessageBox\.confirm/, '强制断开必须先确认')
})

test('MCP 接入卡：端点/认证示例/playbook/管理员全局开关', () => {
  const text = code('src/views/settings/McpAccessCard.vue')
  assert.match(text, /new URL\('\/api\/v1\/mcp', window\.location\.origin\)/)
  assert.match(text, /X-API-Key: <YOUR_API_KEY>/, '认证示例必须携带 X-API-Key 头')
  assert.match(text, /request\.get<Blob>\('\/mcp\/ops-playbook', \{ responseType: 'blob' \}\)/)
  // 全局开关：管理员限定 + 最小 PUT（只动 mcp_enabled）
  assert.match(text, /v-if="isAdmin"/, '全局开关必须管理员限定')
  const toggleBlock = text.slice(text.indexOf('const toggleMcp'), text.indexOf('const playbookDownloading'))
  assert.match(toggleBlock, /request\.put\('\/notification\/settings', \{ mcp_enabled: on \}\)/, '开关写入必须最小 PUT')
  // 统计卡三指标
  for (const key of ['statTodayCalls', 'statActiveSessions', 'statErrorRate']) {
    assert.match(text, new RegExp(`t\\('app\\.notification\\.keysAccess\\.${key}'\\)`))
  }
})

test('调用统计卡：TOP 工具表+趋势投影（无数据空态）', () => {
  const text = code('src/views/settings/McpUsageCard.vue')
  assert.match(text, /defineProps<\{ stats: McpStats \| null \}>\(\)/)
  assert.match(text, /stats\.top_tools/)
  assert.match(text, /props\.stats\?\.trend \?\? \[\]/, '趋势缺数据必须空态而非抛错')
  assert.match(text, /:label="t\('app\.notification\.keysUsage\.colTool'\)"/)
  assert.match(text, /:label="t\('app\.notification\.keysUsage\.colCalls'\)"/)
})
