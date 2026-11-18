// 通知中心接线钉：页面键注册、App/侧栏接线、四页签组件投影、REST 端点契约
// 消费点、zh/en 词条同位。每条断言对应本功能的一个可观察接线点；关键边界用
// section()/带边界的断言，避免全文空转假绿。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'
import { PAGE_IDS } from '../src/utils/pageIds.ts'

const leafKeys = (node: unknown, prefix = ''): string[] => {
  if (typeof node !== 'object' || node === null) return [prefix]
  const out: string[] = []
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    out.push(...leafKeys(v, prefix ? `${prefix}.${k}` : k))
  }
  return out
}

test('页面键注册：notifications 进入 PAGE_IDS 并通过 App.vue 机械对表', () => {
  assert.ok((PAGE_IDS as readonly string[]).includes('notifications'), 'notifications 页面键必须注册（否则深链/OIDC return_to 拒绝）')
  // infraWiring 的机械对表会逐键核对 App.vue 分支；此处钉本页异步组件导入存在
  const app = code('src/App.vue')
  assert.match(app, /const NotificationCenter = createAsyncPage\(\(\) => import\('@\/views\/notifications\/NotificationCenter\.vue'\)\)/)
  assert.match(app, /<NotificationCenter v-else-if="currentPage === 'notifications'" \/>/)
})

test('侧栏接线：通知中心菜单项紧跟 API 密钥之后（铃铛图标）', () => {
  const text = code('src/components/layout/AppLayout.vue')
  const apikeysAt = text.indexOf('index="settings-apikeys"')
  const notificationsAt = text.indexOf('index="notifications"')
  assert.ok(apikeysAt > 0, 'API 密钥菜单项存在')
  assert.ok(notificationsAt > apikeysAt, '通知中心菜单项必须排在 API 密钥之后')
  const item = text.slice(notificationsAt, text.indexOf('</el-menu-item>', notificationsAt))
  assert.match(item, /<Bell \/>/, '通知中心必须用铃铛图标')
  assert.match(item, /NAV_LABELS\.notifications/)
  // 面包屑与侧栏文案单源：NAV_ITEMS 必须登记（漏登记=面包屑回退仪表盘）
  const navItems = text.slice(text.indexOf('const NAV_ITEMS'), text.indexOf('const navLabels'))
  assert.match(navItems, /id: 'notifications'/)
  assert.match(navItems, /navNotifications/, '侧栏文案必须走 navNotifications 词条')
})

test('通知页配置面板投影：触发条件+通道+SMTP+投递', () => {
  const text = code('src/views/notifications/NotificationCenter.vue')
  assert.match(text, /request\.get<[^>]*>\('\/notification\/rules'\)/, '必须消费规则端点')
  assert.match(text, /trigger-grid/, '触发条件网格必须在位')
  assert.match(text, /channel-grid/, '通道网格必须在位')
  assert.match(text, /DialogHeader/, '模板编辑弹窗必须用 DialogHeader')
  assert.match(text, /DeliveryLog/, '投递记录必须在位')
  assert.match(text, /SystemCredentials/, 'SMTP 设置必须在位')
  assert.match(text, /ChannelCards/, '通道管理必须在位')
})



test('通道卡 REST 契约：卡片网格+测试/启停/删除', () => {
  const text = code('src/views/notifications/ChannelCards.vue')
  assert.match(text, /request\.get<NotificationChannelsResponse>\('\/notification\/channels'\)/)
  assert.match(text, /request\.post\(`\/notification\/channels\/\$\{ch\.id\}\/test`\)/)
  assert.match(text, /request\.put\(`\/notification\/channels\/\$\{ch\.id\}`/, '启停/编辑')
  assert.match(text, /request\.delete\(`\/notification\/channels\/\$\{ch\.id\}`\)/)
  // 卡片网格形态（非表格）
  assert.match(text, /class="ch-card"/, '通道必须为卡片网格形态')
  assert.match(text, /class="ch-icon/, '卡片必须有类型彩色图标')
})


test('订阅矩阵消费 catalog+subscriptions 契约，保存走 items 语义', () => {
  const text = code('src/views/notifications/SubscriptionMatrix.vue')
  assert.match(text, /request\.get<NotificationCatalogResponse>\('\/notification\/catalog'\)/)
  assert.match(text, /request\.get<NotificationSubsResponse>\('\/notification\/subscriptions'\)/)
  const saveBlock = text.slice(text.indexOf('const saveSubs'), text.indexOf('onMounted(()'))
  assert.match(saveBlock, /items: events\.value\.map/, '保存必须按 PUT {items:[…]} 契约提交')
  assert.match(saveBlock, /min_level: state\?\.subscribed \? \(state\.min_level \|\| evt\.level\) : ''/, '未订阅事件必须以空 min_level 显式删行（契约语义）')
  // 日报已拆独立页签：订阅矩阵禁止残留日报卡片/手动触发/事件行注入
  assert.doesNotMatch(text, /daily-report\/trigger/, '旧日报触发端点引用禁止回潮（统一 /notification/daily/trigger）')
  assert.doesNotMatch(text, /DAILY_EVENT|dailyTitle|triggerDaily/, '订阅矩阵日报卡片已删（独立页签承载），禁止回潮')
})

test('投递记录消费 deliveries 契约：过滤/全平台/失败重发', () => {
  const text = code('src/views/notifications/DeliveryLog.vue')
  assert.match(text, /params\.set\('limit', String\(DELIVERY_LIMIT\)\)/)
  assert.match(text, /params\.set\('status', statusFilter\.value\)/)
  assert.match(text, /params\.set\('all', '1'\)/, '管理员全平台参数 all=1')
  assert.match(text, /request\.get<NotificationDeliveriesResponse>\(`\/notification\/deliveries\?/)
  assert.match(text, /request\.post\(`\/notification\/deliveries\/\$\{row\.id\}\/resend`\)/)
  const resendable = text.slice(text.indexOf('const RESENDABLE'), text.indexOf('const deliveries ='))
  assert.match(resendable, /\['failed', 'dead'\]/, '重发入口仅失败态（failed/dead）')
})

test('系统凭据消费 settings 契约：GET 嵌套形状+secret 留空不提交', () => {
  const text = code('src/views/notifications/SystemCredentials.vue')
  assert.match(text, /request\.get<NotificationSettingsResponse>\('\/notification\/settings'\)/)
  assert.match(text, /request\.put\('\/notification\/settings', payload\)/)
  assert.match(text, /data\?\.smtp\?\.pass_configured === true/)
  const saveBlock = text.slice(text.indexOf('const payload: NotificationSettingsPayload'), text.indexOf('await request.put'))
  // 空 secret 必须以条件展开省略键（不能提交空串覆盖既有凭据）
  assert.match(saveBlock, /\.\.\.\(form\.value\.smtpPass \? \{ pass: form\.value\.smtpPass \} : \{\}\)/)
  // 页面收敛裁定：系统凭据页只剩 SMTP——QQ/微信凭据单源=扫码绑定自动落库
  // （通道向导承载展示与编辑），MCP 全局开关归 MCP 会话卡；手工形态禁止回潮
  assert.doesNotMatch(text, /qqSecret|qqAppId|wxCred|mcpEnabled|WxQRLogin|bind-state/, 'QQ/微信凭据与 MCP 开关不得在系统凭据页回潮')
  assert.match(text, /creds\.smtpSection/, '页面收敛为邮件凭据单一卡')
})

test('zh/en 通知词条同位：叶子键集一致且 app.notification 前缀', async () => {
  const [{ default: zh }, { default: en }] = await Promise.all([
    import('../src/locales/zh/notifications.ts'),
    import('../src/locales/en/notifications.ts'),
  ]) as Array<{ default: Record<string, unknown> }>
  const app = (tree: Record<string, unknown>): Record<string, unknown> => {
    assert.ok(tree.app && typeof tree.app === 'object', '词条必须挂在 app 下')
    const inner = (tree.app as Record<string, unknown>).notification
    assert.ok(inner && typeof inner === 'object', '必须存在 app.notification 子树（键前缀契约）')
    return inner as Record<string, unknown>
  }
  const zhKeys = leafKeys(app(zh)).sort()
  const enKeys = leafKeys(app(en)).sort()
  assert.deepEqual(enKeys, zhKeys, 'en/zh 叶子键集必须完全同位')
  assert.ok(zhKeys.length >= 80, `通知词条规模异常（${zhKeys.length}）——疑似解析事故`)
  // 关键文案双语言抽查（漂移即红）
  const zhApp = app(zh) as Record<string, Record<string, string>>
  const enApp = app(en) as Record<string, Record<string, string>>
  assert.equal(zhApp.tabs.credentials, '邮件凭据')
  assert.equal(enApp.tabs.credentials, 'Email credentials')
})
