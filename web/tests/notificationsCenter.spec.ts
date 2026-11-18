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

test('通知页四页签投影：channels/subs/deliveries 恒在，credentials 仅管理员', () => {
  const text = code('src/views/notifications/NotificationCenter.vue')
  assert.match(text, /:label="t\('app\.notification\.tabs\.channels'\)" name="channels"/)
  assert.match(text, /:label="t\('app\.notification\.tabs\.subs'\)" name="subs"/)
  assert.match(text, /:label="t\('app\.notification\.tabs\.deliveries'\)" name="deliveries"/)
  assert.match(text, /:label="t\('app\.notification\.tabs\.credentials'\)" name="credentials"/)
  assert.match(text, /<el-tab-pane v-if="isAdmin"[^>]*name="credentials">/, '系统凭据页签必须管理员限定')
  for (const comp of ['ChannelCards', 'SubscriptionMatrix', 'DeliveryLog', 'SystemCredentials']) {
    assert.match(text, new RegExp(`import ${comp} from './${comp}\\.vue'`), `${comp} 必须落位 notifications 域内`)
  }
})

test('通道卡消费通道 REST 契约：CRUD+test+按类型目标 JSON', () => {
  const text = code('src/views/notifications/ChannelCards.vue')
  assert.match(text, /request\.get<NotificationChannelsResponse>\('\/notification\/channels'\)/)
  assert.match(text, /request\.post<NotificationCreateChannelResponse & \{ data\?: \{ id: number; reused\?: boolean \} \}>\('\/notification\/channels'/)
  assert.match(text, /request\.put\(`\/notification\/channels\/\$\{editTarget\.value\.id\}`/)
  assert.match(text, /request\.delete\(`\/notification\/channels\/\$\{ch\.id\}`\)/)
  assert.match(text, /request\.post\(`\/notification\/channels\/\$\{ch\.id\}\/test`\)/)
  // 目标 JSON 按后端 validateChannelTarget 的键约束（url/email/openid/receiver）
  const targetField = text.slice(text.indexOf('const targetField'), text.indexOf('const parseTargetValue'))
  assert.match(targetField, /case 'webhook': return 'url'/)
  assert.match(targetField, /case 'email': return 'email'/)
  assert.match(targetField, /case 'qq': return 'openid'/)
  assert.match(targetField, /case 'wx_clawbot': return 'receiver'/)
  // 向导三步（类型→目标→确认）与状态点/测试-编辑-删除动作在模板投影
  const templateSrc = code('src/views/notifications/ChannelCards.vue')
  const template = templateSrc.slice(0, templateSrc.indexOf('<script'))
  assert.match(template, /<el-steps/, '添加向导必须分步')
  assert.match(template, /class="status-dot"/, '通道卡必须有启停状态点')
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
  assert.match(text, /data\?\.qq\?\.secret_configured === true/)
  assert.match(text, /data\?\.wx_bot_cred_configured === true/)
  assert.match(text, /mcp_enabled: form\.value\.mcpEnabled/)
  const saveBlock = text.slice(text.indexOf('const payload: NotificationSettingsPayload'), text.indexOf('await request.put'))
  // 空 secret 必须以条件展开省略键（不能提交空串覆盖既有凭据）
  assert.match(saveBlock, /\.\.\.\(form\.value\.smtpPass \? \{ pass: form\.value\.smtpPass \} : \{\}\)/)
  // QQ 凭据不走 settings PUT（单源=扫码绑定自动落库），手工形态禁止回潮
  assert.doesNotMatch(text, /qqSecret/)
  // 微信凭据走 iLink 扫码登录卡（REST start/status；confirmed 即服务端已落
  // 凭据）——手工粘贴 wx.cred 形态已删除，禁止回潮
  assert.match(text, /request\.post<\{ code: number; data\?: \{ qr_content: string \} \}>\('\/notification\/wx\/qr\/start', \{\}\)/)
  assert.match(text, /request\.get<\{ code: number; data\?: \{ status: string; confirmed: boolean \} \}>\('\/notification\/wx\/qr\/status'\)/)
  assert.doesNotMatch(text, /wx:\s*\{\s*cred:/)
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
  assert.equal(zhApp.tabs.credentials, '系统凭据')
  assert.equal(enApp.tabs.credentials, 'System credentials')
})
