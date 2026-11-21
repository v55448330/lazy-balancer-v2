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
  // 卡头统一保存：事件/通道/级别三键部分更新 + 确认 + MFA 感知成功提示
  const rowBlock = text.slice(text.indexOf('const anyRuleDirty'), text.indexOf('const cancelAllRuleDrafts'))
  assert.match(rowBlock, /events: d\.events, channel_ids: d\.channel_ids, min_level: d\.min_level/, '卡头保存提交事件/通道/级别三键')
  assert.match(rowBlock, /ElMessageBox\.confirm/, '卡头保存需确认（取消不写）')
  assert.match(rowBlock, /mfaAwareSuccess/, '卡头保存成功经 MFA 感知提示')
  // 摘要卡保存：项目/通道/时间三键部分更新 + 确认
  const dailyBlock = text.slice(text.indexOf('const saveDailyDraft'), text.indexOf('const cancelDailyDraft'))
  assert.match(dailyBlock, /items: d\.items, channel_ids: d\.channel_ids, send_time: d\.send_time/, '卡保存只提交项目/通道/时间三键')
  assert.match(dailyBlock, /ElMessageBox\.confirm/, '卡保存需确认（取消不写）')
  assert.match(dailyBlock, /mfaAwareSuccess/, '卡保存成功经 MFA 感知提示')
  // 最低级别列已下线（事件可选后不再需要）；行草稿仍保留 min_level（默认 info 随保存）
  assert.doesNotMatch(text, /app\.notification\.rules\.minLevel/, '最低级别列已下线')
  assert.match(text, /min_level/, '行草稿仍保留 min_level（默认 info 随保存）')
  // 事件/发送至列=点击浮层内的 bordered 多选（绑定行草稿；未测试通道禁选+提示）
  assert.match(text, /<el-popover[^>]*trigger="click"/, '事件/发送至列必须为点击浮层多选')
  assert.match(text, /el-checkbox-group v-model="ruleDraftOf\(asRule\(row\)\)\.events"/, '事件列必须为浮层多选（绑定行草稿）')
  assert.match(text, /el-checkbox-group v-model="ruleDraftOf\(asRule\(row\)\)\.channel_ids"/, '发送至列必须为浮层多选（绑定行草稿）')
  assert.match(text, /<el-checkbox[^>]*border size="small"/, '多选组必须为 bordered 复选组')
  assert.match(text, /:disabled="ch\.enabled === false \|\| ch\.last_test_ok !== true"/, '未测试/停用通道禁选')
  // 每日摘要独立卡片（不混事件规则表格）+ 三字段卡内联编辑
  assert.match(text, /daily-card/, '每日摘要必须独立卡片')
  assert.match(text, /el-time-select v-model="dailyDraft\.send_time"/, '投递时间必须卡内联编辑')
  assert.match(text, /:model-value="dailyModuleChecked"/, '包含模块勾选必须绑定模块选中集（2026-11-21 裁定：按模块选择）')
  assert.match(text, /@update:model-value="toggleDailyModule"/, '模块勾选切换必须走 toggleDailyModule（整组项目入/出 items）')
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

test('统一模板弹框+停用通道联动+事件级别分区+正文语言切换', () => {
  const text = code('src/views/notifications/NotificationCenter.vue')

  // 1) 日报配置弹框整体并入统一模板弹框（旧弹框/入口零残留；日报卡只剩「编辑模板」）
  assert.doesNotMatch(text, /dailyConfigVisible|dailyConfigLoading|openDailyConfig/, '日报配置弹框状态/入口必须清零')
  assert.doesNotMatch(text, /daily-config-dialog|daily-config-row/, '日报配置弹框版式残留必须清零')
  assert.doesNotMatch(text, /配置日报/, '「配置日报」按钮语义必须改为「编辑模板」')
  assert.match(text, /@click="openDailyTpl"[\s\S]{0,80}daily\.editTemplate/, '日报卡入口=编辑模板（打开统一弹框）')
  assert.match(text, /const openDailyTpl = async \(\): Promise<void> => \{[\s\S]{0,300}tplMode\.value = 'daily'/, '日报入口进入 daily 模式（同一弹框）')
  assert.match(text, /const tplMode = ref<'rule' \| 'daily'>/, 'rule/daily 共用同一模板弹框')

  // 2) 停用通道联动：全量通道 DTO + 禁选 + 已选自动移出草稿 + 提示
  assert.match(text, /const allChannels = ref<RuleChannel\[\]>\(\[\]\)/, '停用通道态必须经全量通道 DTO 补齐')
  assert.match(text, /const channelOptions = computed<RuleChannel\[\]>/, '发送至选项=启用+停用通道合并集')
  assert.match(text, /request\.get<NotificationChannelsResponse>\(url, \{ silent: true \}\)/, '全量通道经 /notification/channels')
  assert.match(text, /const pruneChannelIds = \(ids: number\[\]\): number\[\] =>/, '停用通道必须从草稿中移出')
  const seedBlock = text.slice(text.indexOf('const seedDrafts'), text.indexOf('const ruleDraftOf'))
  assert.match(seedBlock, /pruneChannelIds/, '草稿播种时停用通道同样移出（不产生伪脏态）')
  assert.match(text, /const baselineChannelIds = \(ids\?: number\[\]\): number\[\] =>/, '脏判定基线同口径裁剪')
  assert.match(text, /channelDisabledHint/, '停用通道必须有提示（info-note-bar/form-hint）')
  assert.match(text, /class="info-note-bar"><span class="info-note-desc">\{\{ t\('app\.notification\.rules\.channelDisabledHint'\) \}\}/, '发送至浮层提示用 info-note-bar')
  assert.match(text, /:title="channelPickTitle\(ch\)"/, '停用/未测试通道 title 提示单源')

  // 3) 浮层宽度=触发器实测 offsetWidth（点击测量绑定）；底部不足翻上、不横向位移
  assert.match(text, /:width="pickWidth\.events"/, '事件浮层宽度绑定触发器实测值')
  assert.match(text, /:width="pickWidth\.channels"/, '发送至浮层宽度绑定触发器实测值')
  assert.match(text, /const measurePickWidth = \(e: MouseEvent, kind: 'events' \| 'channels'\)/, '点击时测量触发器宽度')
  assert.match(text, /offsetWidth/, '宽度来源=触发器 offsetWidth')
  assert.match(text, /@click="measurePickWidth\(\$event, 'events'\)"/, '事件触发器点击即测量')
  assert.match(text, /@click="measurePickWidth\(\$event, 'channels'\)"/, '发送至触发器点击即测量')
  assert.match(text, /pick-trigger--events \{ min-width: 340px; \}/, '事件触发器保留 min-width（下限）')
  assert.match(text, /pick-trigger--channels \{ min-width: 300px; \}/, '发送至触发器保留 min-width（下限）')
  assert.match(text, /placement="bottom-start"/, '定位底部优先')
  const popperBlock = text.slice(text.indexOf('const pickPopperOptions'), text.indexOf('const pickPopperOptions') + 400)
  assert.match(popperBlock, /fallbackPlacements: \['top-start', 'top'\]/, '底部空间不足翻到触发器上方')
  assert.doesNotMatch(popperBlock, /'right'|'left'/, '不得向右/左横向回退')
  assert.match(popperBlock, /altAxis: false/, 'preventOverflow 禁止横向位移')
  assert.doesNotMatch(text, /popperViewportSafe/, '横向回退工具不用于表格多选浮层')
  assert.match(text, /const pickWidth = ref<\{ events: number; channels: number \}>/, '宽度态按触发器类型分存')

  // 4) 事件浮层按级别分区（严重/警告/信息三段），中性样式：无着色、无图例
  assert.match(text, /const eventLevel = \(row: Rule, ev: string\): EventLevel =>/, '事件级别必须解析自目录')
  assert.match(text, /const eventLevelSections = \(rule: Rule\)/, '事件按级别分段')
  assert.match(text, /EVENT_SECTION_ORDER: readonly EventLevel\[\] = \['critical', 'warn', 'info'\]/, '分段顺序=严重→警告→信息')
  assert.match(text, /v-for="sec in eventLevelSections\(asRule\(row\)\)"/, '浮层按分区渲染')
  assert.match(text, /class="notif-level-head">\{\{ t\(`app\.notification\.subs\.levels\.\$\{sec\.level\}`\) \}\}/, '段标题=级别词条')
  assert.doesNotMatch(text, /class="notif-pick-title">/, '组标题已删（级别段标题即标题）')
  assert.doesNotMatch(text, /ev-level-|ev-level-legend|ev-legend-dot|ev-dot-/, '级别着色与图例必须清零')
  assert.doesNotMatch(text, /--ev-critical/, '级别色变量必须清零')

  // 5) 模板弹框语言切换：zh/en 默认预设（保存即正文语言）
  assert.match(text, /const tplLang = ref<TplLang>/, '弹框语言态')
  assert.match(text, /<el-radio-button value="zh">中文<\/el-radio-button>/, '中文切换项')
  assert.match(text, /<el-radio-button value="en">English<\/el-radio-button>/, 'English 切换项')
  assert.match(text, /const onTplLangChange = \(v: string \| number \| boolean \| undefined\): void =>/, '切换即载入该语言预设')
  assert.match(text, /const defaultTplFor = \(typ: string, lang: TplLang\): string =>/, '事件预置 zh/en 双版本')
  assert.match(text, /const defaultDailyTplFor = \(typ: string, lang: TplLang\): string =>/, '日报预置 zh/en 双版本')
  assert.match(text, /draft !== defaultTplFor\(ch\.type, 'zh'\) && draft !== defaultTplFor\(ch\.type, 'en'\)/, '任一语言预置均视为默认（不冗余落库）')
  assert.match(text, /tplChannelLabel/, '通道切换必须带「通道」标签词条')
  assert.match(text, /class="tpl-channel-row">\s*<span class="tpl-format-label">\{\{ t\('app\.notification\.rules\.tplChannelLabel'\) \}\}/, '通道切换行带 label')

  // 6) 消息模板列删除；编辑模板/测试在操作列；保存/取消统一到卡头（任一行脏时）
  assert.doesNotMatch(text, /rules\.bodyTemplate/, '消息模板列必须删除')
  const actionsAt = text.indexOf("t('app.notification.rules.actions')")
  const actionsBlock = text.slice(actionsAt, text.indexOf('</el-table-column>', actionsAt))
  assert.match(actionsBlock, /editTemplate\(asRule\(row\)\)/, '操作列必须有编辑模板按钮')
  assert.match(actionsBlock, /testRule\(asRule\(row\)\)/, '测试在操作列')
  assert.doesNotMatch(actionsBlock, /saveRuleDraft|cancelRuleDraft/, '保存/取消已移出操作列')
  assert.match(text, /anyRuleDirty/, '卡头保存显隐依赖任一行脏')
  assert.match(text, /saveAllRuleDrafts/, '卡头统一保存')
  assert.match(text, /cancelAllRuleDrafts/, '卡头统一取消')
  assert.doesNotMatch(text, /privacy-hint|privacyHint/, '脱敏描述已删')
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
  // 用户维度列在位；投递通道列改为「成功/失败」计数（细节在展开行）；裸事件键列禁止回潮
  assert.match(text, /colResult/, '成功/失败计数列必须在位')
  assert.doesNotMatch(text, /colChannels/, '投递通道列已移除（细节在展开行）')
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

// 2026-11-22 日报渲染模式显式开关（用户裁定）：弹窗 radio + daily_mode 落库 +
// 模块拼装只读/预览提示；Markdown 预览=消息卡 CSS 方案（主题变量，禁 hex）。
test('日报渲染模式显式开关与消息卡预览样式', () => {
  const nc = code('src/views/notifications/NotificationCenter.vue')
  assert.match(nc, /t\('app\.notification\.daily\.renderMode'\)/, '渲染模式行必须在弹窗')
  assert.match(nc, /value="modules"/, '模块拼装选项必须在位')
  assert.match(nc, /value="template"/, '自定义模板选项必须在位')
  assert.match(nc, /style\.daily_mode = dailyModes\.value\[String\(ch\.id\)\] \?\? 'modules'/, '保存必须落 daily_mode（缺省 modules）')
  assert.match(nc, /:readonly="tplMode === 'daily' && tplDailyMode === 'modules'"/, '模块拼装模式编辑器必须只读')
  assert.match(nc, /modeModulesPreviewHint/, '模块拼装预览提示必须在位')
  assert.match(nc, /seedDailyModes/, '弹窗打开必须按存量/显式值播种渲染模式')
  // 消息卡：主题变量 + designGuard 高度 token 保持
  assert.match(nc, /\.tpl-md-preview \{ background: var\(--el-fill-color-light\)/, '预览画布必须用主题变量')
  assert.ok(!/\.tpl-md-preview[^\n]*#f9fafb/.test(nc), '预览样式禁硬编码 hex')
  assert.match(nc, /\.tpl-md-preview hr \{ border: none; border-top: 1px solid var\(--el-border-color-lighter\)/, '分节 hr 须主题变量')
  // 设计规范：直角对齐，预览样式禁 border-radius（2026-11-22 用户纠偏）
  const mdPreviewCss = nc.split('\n').filter(l => l.includes('.tpl-md-preview')).join('\n')
  assert.ok(!/border-radius/.test(mdPreviewCss), '预览样式禁用圆角（直角对齐设计规范）')
  // 表格网格必须可见（lighter 边框实测近不可见）+ 标题层级可辨（18/15/14）
  assert.match(nc, /\.tpl-md-preview th, \.tpl-md-preview td \{ border: 1px solid var\(--el-border-color\); padding: 6px 12px;/, '表格边框须用可见档位（非 lighter）')
  assert.match(nc, /\.tpl-md-preview h2 \{ font-size: 18px/, 'h2 层级 18px')
  assert.match(nc, /\.tpl-md-preview h3 \{ font-size: 15px/, 'h3 层级 15px（与 h2 拉开可辨差距）')
})
