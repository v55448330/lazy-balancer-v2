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

test('Keys.vue 区块接线：统计并列卡+会话卡（原 MCP 文档对话框不动）', () => {
  const text = code('src/views/Keys.vue')
  assert.match(text, /import AccessStatsCards from '\.\/settings\/AccessStatsCards\.vue'/)
  assert.match(text, /import McpSessionsCard from '\.\/settings\/McpSessionsCard\.vue'/)
  assert.doesNotMatch(text, /McpAccessCard|McpUsageCard/, '接入卡已按裁定删除，不得残留引用')
  const blocksStart = text.indexOf("<el-divider content-position=\"left\" class=\"section-divider\">{{ t('app.notification.keysAccess.title') }}")
  assert.ok(blocksStart > 0, 'MCP 区块分隔标题缺失')
  const blocks = text.slice(blocksStart, text.indexOf('<el-dialog', blocksStart))
  // 结构：统计并列卡（API+MCP）→ 会话卡；playbook/认证示例只在原对话框内
  assert.match(blocks, /<AccessStatsCards :api-key-stats="apiKeyStats" :mcp-stats="mcpStats"/)
  assert.match(blocks, /<McpSessionsCard/)
  assert.doesNotMatch(blocks, /ops-playbook|X-API-Key/, '端点/认证示例/playbook 不得在页面区块重复（原对话框已承载）')
  // 原有 MCP 文档入口保持：页头按钮 + 对话框内 playbook 下载
  assert.match(text, /@click="mcpDocsVisible = true"/)
  assert.match(text, /request\.get<Blob>\('\/mcp\/ops-playbook', \{ responseType: 'blob' \}\)/)
  // 统计单次拉取：管理员门 + 端点
  assert.match(text, /if \(!isAdmin\.value\) return/, 'stats 拉取必须管理员限定')
  assert.match(text, /request\.get<McpStatsResponse>\('\/notification\/mcp\/stats'\)/)
})

test('API 密钥统计：api_keys 现成字段现算，不虚报调用计数', () => {
  const text = code('src/views/Keys.vue')
  const statsBlock = text.slice(text.indexOf('const ACTIVE_WINDOW_MS'), text.indexOf('const creating'))
  assert.match(statsBlock, /key\.is_enabled/, '启用数必须来自 is_enabled 现成字段')
  assert.match(statsBlock, /key\.last_used/, '近 7 天活跃必须来自 last_used 现成字段')
  assert.match(statsBlock, /7 \* 24 \* 60 \* 60 \* 1000/, '活跃窗口=7 天')
  assert.doesNotMatch(statsBlock, /today_calls|calls/, 'API 侧不得虚报调用计数（该数据不存在）')
})

test('统计并列卡：API 三指标 tiles + MCP tiles/TOP 工具/趋势同形态', () => {
  const text = code('src/views/settings/AccessStatsCards.vue')
  assert.match(text, /defineProps<\{\s*apiKeyStats: \{ total: number; enabled: number; active7d: number \}/)
  assert.match(text, /mcpStats: McpStats \| null/)
  // API 侧三指标（词条）
  for (const key of ['statTotal', 'statEnabled', 'statActive7d']) {
    assert.match(text, new RegExp(`t\\('app\\.notification\\.keysAccess\\.${key}'\\)`))
  }
  // MCP 侧同形态 tiles + TOP 工具 + 趋势
  for (const key of ['statTodayCalls', 'statActiveSessions', 'statErrorRate']) {
    assert.match(text, new RegExp(`t\\('app\\.notification\\.keysUsage\\.${key}'\\)`))
  }
  assert.match(text, /mcpStats\.top_tools/)
  assert.match(text, /props\.mcpStats\?\.trend \?\? \[\]/, '趋势缺数据必须空态而非抛错')
  assert.match(text, /:label="t\('app\.notification\.keysUsage\.colTool'\)"/)
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
