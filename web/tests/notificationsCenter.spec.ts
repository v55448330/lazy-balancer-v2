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

test('通知页五 tab 投影：概览/规则/通道/投递/邮件服务', () => {
  const text = code('src/views/notifications/NotificationCenter.vue')
  assert.match(text, /el-tabs/, '必须使用 tabs')
  assert.match(text, /request\.get<[^>]*>\(rulesUrl\)/, '必须消费规则端点')
  // 概览=仪表盘（stat 卡+ECharts 趋势+通道分布），非简易 div bar
  assert.match(text, /v-chart/, '概览趋势必须用 ECharts（全站图表规范）')
  assert.match(text, /axisChartBase|pieChartBase/, '图表必须经共享基线构建')
  assert.match(text, /class="stat-item"/, '概览统计卡必须 Dashboard 同构')
  assert.match(text, /DialogHeader/, '模板编辑弹窗必须用 DialogHeader')
  for (const comp of ['DeliveryLog', 'ChannelCards', 'SystemCredentials']) {
    assert.match(text, new RegExp(`import ${comp} from './${comp}\\.vue'`), `${comp} 必须在位`)
  }
})




test('通道卡 REST 契约：卡片网格+测试/启停/删除+样式编辑', () => {
  const text = code('src/views/notifications/ChannelCards.vue')
  assert.match(text, /request\.get<NotificationChannelsResponse>\(url\)/)
  assert.match(text, /request\.post\(`\/notification\/channels\/\$\{ch\.id\}\/test`/)
  assert.match(text, /request\.put\(`\/notification\/channels\/\$\{ch\.id\}`/, '启停/编辑')
  assert.match(text, /request\.delete\(`\/notification\/channels\/\$\{ch\.id\}`\)/)
  // 卡片网格形态（非表格）
  assert.match(text, /class="ch-card"/, '通道必须为卡片网格形态')
  assert.match(text, /class="ch-icon/, '卡片必须有类型彩色图标')
  // 消息样式编辑（style_config 全量覆盖；键白名单与后端一致）
  assert.match(text, /style_config: buildStyleConfig\(\)/, '编辑保存必须提交样式')
  assert.match(text, /ElMessageBox\.confirm/, '删除必须走站内确认框（非 window.confirm）')
})


test('规则编辑契约：行内草稿保存+每通道模板部分更新，不改启用态；事件可读标题', () => {
  const text = code('src/views/notifications/NotificationCenter.vue')
  const tplBlock = text.slice(text.indexOf('const saveTemplate'), text.indexOf('const testRule'))
  assert.doesNotMatch(tplBlock, /channel_ids/, '模板保存不再写通道选择（已前移到事件规则表格内联）')
  assert.match(tplBlock, /channel_templates: tpls/, '保存必须提交每通道模板')
  assert.doesNotMatch(tplBlock, /enabled: true/, '模板保存不得强制启用规则')
  assert.doesNotMatch(tplBlock, /body_template:/, '每通道模板取代单一 body_template 直写')
  assert.match(tplBlock, /ElMessageBox\.confirm/, '模板保存需确认（取消不写）')
  // 行草稿保存：事件/通道/级别三键部分更新 + 确认 + MFA 感知成功提示
  const rowBlock = text.slice(text.indexOf('const saveRuleDraft'), text.indexOf('const cancelRuleDraft'))
  assert.match(rowBlock, /events: d\.events, channel_ids: d\.channel_ids, min_level: d\.min_level/, '行保存只提交事件/通道/级别三键')
  assert.match(rowBlock, /ElMessageBox\.confirm/, '行保存需确认（取消不写）')
  assert.match(rowBlock, /mfaAwareSuccess/, '行保存成功经 MFA 感知提示')
  // 摘要卡保存：项目/通道/时间三键部分更新 + 确认
  const dailyBlock = text.slice(text.indexOf('const saveDailyDraft'), text.indexOf('const cancelDailyDraft'))
  assert.match(dailyBlock, /items: d\.items, channel_ids: d\.channel_ids, send_time: d\.send_time/, '卡保存只提交项目/通道/时间三键')
  assert.match(dailyBlock, /ElMessageBox\.confirm/, '卡保存需确认（取消不写）')
  assert.match(dailyBlock, /mfaAwareSuccess/, '卡保存成功经 MFA 感知提示')
  // 级别列=下拉选择（radio-button 三按钮在窄列竖排堆叠的缺陷形态禁止回潮）；
  // 选项文案走 subs.levels 多语言词条（信息/警告/严重）
  assert.match(text, /el-select v-model="ruleDraftOf\(asRule\(row\)\)\.min_level"/, '级别列必须为紧凑下拉（绑定行草稿）')
  assert.match(text, /t\('app\.notification\.subs\.levels\.info'\)/, '级别选项必须多语言')
  // 事件/发送至列=点击浮层内的 bordered 多选（绑定行草稿；未测试通道禁选+提示）
  assert.match(text, /<el-popover[^>]*trigger="click"/, '事件/发送至列必须为点击浮层多选')
  assert.match(text, /el-checkbox-group v-model="ruleDraftOf\(asRule\(row\)\)\.events"/, '事件列必须为浮层多选（绑定行草稿）')
  assert.match(text, /el-checkbox-group v-model="ruleDraftOf\(asRule\(row\)\)\.channel_ids"/, '发送至列必须为浮层多选（绑定行草稿）')
  assert.match(text, /<el-checkbox[^>]*border size="small"/, '多选组必须为 bordered 复选组')
  assert.match(text, /:disabled="ch\.last_test_ok !== true"/, '未测试通道禁选')
  // 每日摘要独立卡片（不混事件规则表格）+ 三字段卡内联编辑
  assert.match(text, /daily-card/, '每日摘要必须独立卡片')
  assert.match(text, /el-time-select v-model="dailyDraft\.send_time"/, '投递时间必须卡内联编辑')
  assert.match(text, /el-checkbox-group v-model="dailyDraft\.items"/, '包含项目必须卡内联编辑')
  assert.match(text, /el-checkbox-group v-model="dailyDraft\.channel_ids"/, '目标通道必须卡内联编辑')
  assert.match(text, /eventRules/, '事件规则独立表格数据源')
  // 规则测试走 /test 端点（按选定通道+模板渲染）
  assert.match(text, /\/test/, '规则测试必须走规则级 test 端点')
  // 事件展示=可读标题（event_titles 单源），禁止裸事件键
  assert.match(text, /eventTitle\(asRule\(row\), ev\)/, '事件选项必须经可读标题映射')
  // 模板弹框不再承载接收通道选择（tplSelectedChannels 残留清零）
  assert.doesNotMatch(text, /tplSelectedChannels/, '接收通道选择已前移到表格，弹框残留必须清零')
  // 邮件 HTML 预览=sandbox iframe；webhook/邮件编辑=CodeEditor 高亮
  assert.match(text, /sandbox="" :srcdoc="previewText"/, '邮件渲染预览必须 sandbox iframe')
  assert.match(text, /CodeEditor v-if="tplEditorLang !== 'text'"/, 'JSON/HTML 必须高亮编辑')
  // 概览=全平台（无用户筛选）；三维分布图在位
  assert.match(text, /delivery-stats/, '分布统计端点必须消费')
  assert.match(text, /distByChannelTitle/, '通道投递分布图必须在位')
  assert.match(text, /distByEventTitle/, '事件分布图必须在位')
})

test('投递记录消费 deliveries 契约：恒全量+用户/通道维度+失败重发', () => {
  const text = code('src/views/notifications/DeliveryLog.vue')
  assert.match(text, /params\.set\('page_size', String\(pageSize\.value\)\)/, '分页契约：page_size（默认 50 上限 200）')
  assert.match(text, /params\.set\('page', String\(page\.value\)\)/, '分页契约：page')
  assert.match(text, /total\.value = res\.data\?\.total/, '底部统计 total 必须消费')
  assert.match(text, /params\.set\('status', statusFilter\.value\)/)
  assert.doesNotMatch(text, /allScope/, '全平台开关已删（投递记录恒全量，用户裁定）')
  assert.match(text, /request\.get<NotificationDeliveriesResponse>\(`\/notification\/deliveries\?/)
  assert.match(text, /request\.post\(`\/notification\/deliveries\/\$\{row\.id\}\/resend`\)/)
  // 用户/通道维度列在位；裸事件键列禁止回潮
  assert.match(text, /colChannels/, '投递通道列必须在位')
  assert.match(text, /scope\.row\.username/, '用户列必须显示用户名')
  assert.doesNotMatch(text, /colEventType/, '裸事件键列禁止回潮（可读标题单源）')
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
