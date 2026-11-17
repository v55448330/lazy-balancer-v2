// 视图层展示一致性回归钉：弹框正文留白标记类、事件详情 CC 新动作投影与
// WAF 摘要归一、封禁控制台分页范式、口径标签单源、大屏动作徽标配色、
// 总览累犯下钻加载门。
//
// 运行：cd web && npm test -- --test-name-pattern=<子串>（全量 npm test）

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, cssDeclarations, section, source } from './_helpers.ts'
import { i18n } from '../src/i18n/index.ts'
import { buildStageModel, type SecurityStagePolicy, type SecurityStageBinding } from '../src/utils/securityStages.ts'
import { autobanScopeLabel } from '../src/utils/autobanStatus.ts'
import { tSafe } from '../src/i18n/tSafe.ts'

const dialogFile = 'src/components/events/TriggerDetailDialog.vue'
const eventsFile = 'src/views/security/SecurityEvents.vue'
const overviewFile = 'src/views/security/SecurityOverview.vue'

// ── 弹框正文留白标记类（dialog-body-inset）─────────────────────
// 消费方遍布全系统（含 append-to-body teleport 弹框，scoped :deep 不可靠），
// 正文留白必须由全局 main.css 的显式规则承载；「零 padding」的旧注释描述
// 不得与真实声明并存。
test('dialog-body-inset：全局显式规则与三段式正文留白同值（20px）', () => {
  const css = code('src/styles/main.css')
  const inset = cssDeclarations(css, '.dialog-body-inset .el-dialog__body')
  assert.equal(inset.get('padding'), '20px', '标记类必须有全局定义（消费方 13 文件，零定义=死类）')
  const globalBody = cssDeclarations(css, '.el-dialog .el-dialog__body')
  assert.equal(globalBody.get('padding'), '20px', '全局三段式正文留白保持 20px')
  assert.equal(inset.get('padding'), globalBody.get('padding'), '两处留白必须同值（单一视觉语言）')
  // 旧注释宣称「dialog-body-inset 的零 padding」——与显式 20px 定义矛盾即红。
  assert.doesNotMatch(source('src/styles/main.css'), /dialog-body-inset 的零 padding/, '零 padding 旧描述必须与定义同步')
})

// ── 事件详情 human 分支：CC 新动作四行投影 ─────────────────────
// queue/reject 策略在规则流程抽屉可见（buildStageModel s2 行），事件详情
// 弹框此前只有模式/方式/TTL/突刺——同一策略两处投影口径分叉。
test('事件详情 human 分支复用阶段 2 投影：触发后动作/等待秒数/4xx/会话行', () => {
  const dialog = code(dialogFile)
  assert.match(dialog, /buildStageModel\(\[binding\], \[projected\], \[\], \[\]\)\.stages\[2\]/, '必须复用 buildStageModel 阶段 2 行构造（不得第二份实现）')
  assert.match(dialog, /v-for="r in ccDetailRows"/, 'human 明细必须渲染投影行')
  // 策略详情载荷接口必须携带新动作字段（后端 GET /security/policies/:id 返回）
  const iface = section(dialog, 'interface PolicyRow {', '\n}')
  for (const field of ['cc_trigger_action', 'cc_4xx_ratio', 'cc_session_anomaly', 'cc_queue_wait_sec']) {
    assert.match(iface, new RegExp(`${field}\\?`), `PolicyRow 缺字段 ${field}`)
  }
  // 四行词条由投影单源消费（securityStages），母本齐备由 ccProtectionContracts 钉
  const stages = code('src/utils/securityStages.ts')
  for (const key of ['ccActionRowLabel', 'cc4xxRowLabel', 'ccSessionRowLabel', 'ccQueueWaitRowLabel']) {
    assert.ok(stages.includes(key), `投影单源缺行键 ${key}`)
  }
})

test('事件详情 CC 投影与流程抽屉同口径：force 恒挑战、queue 等待 0 披露自动窗口', () => {
  const base: SecurityStagePolicy = {
    id: 7, name: 'CC 策略', mode: 'off', enabled: true,
    has_ip_control: false, has_geoip: false, has_custom_rules: false,
    geoip_countries: '', custom_rules_count: 0, ip_acl_mode: 'deny',
    ip_acl_list: '', ip_whitelist: '', policy_type: 'stage2',
  }
  const binding: SecurityStageBinding = { policy_id: 7, name: 'CC 策略', mode: 'off', enabled: true }
  const rowsOf = (overrides: Partial<SecurityStagePolicy>) =>
    buildStageModel([binding], [{ ...base, ...overrides }], [], []).stages[2].groups[0]?.rows ?? []

  // force 恒挑战（后端契约）：cc_trigger_action=queue 不得改变处置动作
  const force = rowsOf({ human_verify_mode: 'force', cc_trigger_action: 'queue', cc_queue_wait_sec: 9 })
  const forceAction = force.find((r) => r.label === tSafe('common.app.views.stages.ccActionRowLabel'))
  assert.deepEqual(forceAction, { label: tSafe('common.app.views.stages.ccActionRowLabel'), detail: tSafe('common.app.views.stages.ccAction_challenge') })
  assert.equal(force.some((r) => r.label === tSafe('common.app.views.stages.ccQueueWaitRowLabel')), false, 'force 不产生等待行')

  // auto+queue：等待 0=自动取 CC 窗口（最常见配置不得隐行）
  const queue = rowsOf({ human_verify_mode: 'auto', cc_trigger_action: 'queue', cc_queue_wait_sec: 0, cc_rps_window: 10 })
  const waitRow = queue.find((r) => r.label === tSafe('common.app.views.stages.ccQueueWaitRowLabel'))
  assert.deepEqual(waitRow, { label: tSafe('common.app.views.stages.ccQueueWaitRowLabel'), detail: tSafe('common.app.views.stages.ccQueueWaitAutoValue', { sec: 10 }) })

  // auto+queue+显式等待：按配置秒数
  const queueExplicit = rowsOf({ human_verify_mode: 'auto', cc_trigger_action: 'queue', cc_queue_wait_sec: 25 })
  assert.equal(queueExplicit.find((r) => r.label === tSafe('common.app.views.stages.ccQueueWaitRowLabel'))?.detail, tSafe('common.app.views.stages.ccQueueWaitRowValue', { sec: 25 }))

  // 检测三条件：4xx=0（关闭）/会话未启用不虚增行；启用时逐行呈现
  const detect = rowsOf({ human_verify_mode: 'auto', cc_detect_enabled: true, cc_rps_limit: 40, cc_rps_window: 10, cc_4xx_ratio: 70, cc_session_anomaly: true, cc_session_ua_threshold: 5 })
  assert.ok(detect.some((r) => r.label === tSafe('common.app.views.stages.cc4xxRowLabel')), '4xx>0 必须有行')
  assert.ok(detect.some((r) => r.label === tSafe('common.app.views.stages.ccSessionRowLabel')), '会话启用必须有行')
  const detectOff = rowsOf({ human_verify_mode: 'auto', cc_detect_enabled: true, cc_4xx_ratio: 0, cc_session_anomaly: false })
  assert.equal(detectOff.some((r) => r.label === tSafe('common.app.views.stages.cc4xxRowLabel')), false, '4xx=0 关闭不得虚增行')
  assert.equal(detectOff.some((r) => r.label === tSafe('common.app.views.stages.ccSessionRowLabel')), false, '会话未启用不得虚增行')
})

// ── 事件详情 wafSummary：CRS 组数归一 + detection 自定义计数 ────
test('事件详情 WAF 摘要：组数经 normalizeCrsGroups，detection 模式计自定义规则', () => {
  const dialog = code(dialogFile)
  const waf = section(dialog, 'const wafSummary = computed', '\n})')
  assert.match(waf, /normalizeCrsGroups\(/, 'CRS 组数必须归一（历史文件名前缀/重复/系统基础组不得把组数说大）')
  assert.match(dialog, /import \{ normalizeCrsGroups \} from '@\/utils\/crsGroups'/)
  // detection 与 blocking/custom_only 同门（buildStage3Rows 的 CRS 评估面）
  assert.match(waf, /p\.mode === 'custom_only' \|\| p\.mode === 'blocking' \|\| p\.mode === 'detection'/, '自定义计数门必须含 detection')
})

// ── 封禁控制台分页：useClampedPagination 单一范式 ──────────────
test('封禁控制台分页走 useClampedPagination（computed 内不得写页码）', () => {
  const events = code(eventsFile)
  assert.match(events, /import \{ useClampedPagination \} from '@\/composables\/useClampedPagination'/)
  assert.match(events, /useClampedPagination\(autobanBansFiltered, banPage, banPageSize\)/, '分页切片必须走夹紧组合子')
  assert.doesNotMatch(events, /const autobanBansPaged = computed\(\(\) => \{[\s\S]*?banPage\.value = /, 'computed 内副作用写页码必须退役')
  assert.match(events, /:data="autobanBansPaged"/, '表体仍消费分页切片')
})

// ── autoban 口径标签：总览/事件页单源 ──────────────────────────
test('autoban 口径标签单源：两视图都消费 utils/autobanStatus 的标签函数', () => {
  // 行为：四合法成员走词条，未知值原样回显（fail-visible）
  assert.equal(autobanScopeLabel('blocked'), tSafe('app.security.events.scopeBlocked'))
  assert.equal(autobanScopeLabel('logged'), tSafe('app.security.events.scopeLogged'))
  assert.equal(autobanScopeLabel('challenge_issued'), tSafe('app.security.events.scopeChallengeIssued'))
  assert.equal(autobanScopeLabel('challenge_failed'), tSafe('app.security.events.scopeChallengeFailed'))
  assert.equal(autobanScopeLabel('constructor'), 'constructor', '原型键不得渲染成函数源码')
  for (const file of [eventsFile, overviewFile]) {
    const page = code(file)
    assert.match(page, /autobanScopeLabel/, `${file} 必须消费单源标签函数`)
    assert.doesNotMatch(page, /const autobanScopeLabel = /, `${file} 本地标签副本必须退役`)
    assert.doesNotMatch(page, /app\.security\.overview\.autoban\.scopeBlocked/, `${file} 不得再读总览域口径标签词条（双源）`)
  }
})

// ── 大屏事件流：trust/challenged 死样式不得回潮 ─────────────────
// feed 的 AttackEventSQLPredicate 整类排除 trust/challenged（事件流不可达），
// 两条徽标配色规则已已删除——类名/样式任一回潮都是死代码回归。
test('大屏事件流：trust/challenged 徽标类不存在（feed 整类排除，死样式删除回归钉）', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  for (const cls of ['.act-trust', '.act-challenged']) {
    assert.ok(!screen.includes(cls), `${cls} 死样式不得回潮（feed 排除 trust/challenged，不可达）`)
  }
})

// ── 总览累犯下钻：加载门（与事件页入口同口径）──────────────────
test('总览累犯下钻：状态未就绪禁用，写门提示区分加载中/加载失败', () => {
  const overview = code(overviewFile)
  assert.match(overview, /class="autoban-stat-link" :disabled="autobanStatus === null \|\| autobanError" @click="recidivismDialogVisible = true"/, '加载中（status=null）不得下钻')
  const reason = section(overview, 'const recidivismWriteBlockedReason = computed', '\n})')
  assert.match(reason, /autobanStatus\.value === null/, '写门提示必须有加载中分支')
  assert.match(reason, /t\('app\.security\.events\.blockedReasonLoading'\)/, '加载中文案与事件页同键')
  assert.match(reason, /autobanError\.value/, '加载失败分支不得被加载中分支吞掉')
})

// ── 触发详情 ACL 模式词：空/未知模式与阶段投影同口径（未配置模式） ──
// formatAclModeDetail 裁定：空/未知 ip_acl_mode 名单存在但渲染侧零发射——
// 显「未配置模式」而非「黑名单模式」。弹框摘要/hero 内联/命中位置三处同族。
test('ACL 模式词：空/未知模式显「未配置模式」，deny/allow/绕过 回归不动（zh/en 成对）', () => {
  const dialog = code(dialogFile)
  // 摘要：deny 显式分支 + 空/未知兜底走 modeUnset（不得回落 modeDeny）
  const acl = section(dialog, 'const aclSummary = computed', '\n})')
  assert.match(acl, /p\.ip_acl_mode === 'deny'/, 'deny 必须显式分支')
  assert.match(acl, /trigDetail\.modeUnset/, '空/未知模式兜底必须走 modeUnset 词条')
  assert.doesNotMatch(acl, /: t\('common\.app\.views\.trigDetail\.modeDeny'\)/, '不得以黑名单模式兜底空/未知')
  // hero 内联命中源与命中位置行：模式词单源 helper（三处不得各写一份三元）
  assert.match(dialog, /const aclModeWord = /, '模式词必须单源 helper')
  const hero = section(dialog, 'const heroHitSource = computed', '\n})')
  assert.match(hero, /aclModeWord/, 'hero 内联命中源必须消费单源模式词')
  assert.match(dialog, /inlineAclList', \{ mode: aclModeWord/, '命中位置行必须消费单源模式词')
  // 词条双钉：zh 母本原文 + en 成对（与 stages.unsetMode 同语义）
  assert.equal(tSafe('common.app.views.trigDetail.modeUnset'), '未配置模式')
  assert.match(code('src/locales/en/views.ts'), /'modeUnset': 'Mode not configured'/)
  assert.equal(tSafe('common.app.views.trigDetail.sideUnset'), '未配置模式')
  assert.match(code('src/locales/en/views.ts'), /'sideUnset': 'unset-mode '/)
})

// ── 词条陈旧面：autoban 四维口径 / CC 突刺（配额已退役）/ 白名单占位换行 ──
test('taskDesc.autoban 四维口径（拦截/检测/挑战发放/挑战失败），不再宣称「全部」', () => {
  const zh = tSafe('common.app.taskDesc.autoban')
  assert.match(zh, /拦截\/检测\/挑战发放\/挑战失败/, '口径必须四维（与 AUTOBAN_SCOPES 同集）')
  assert.doesNotMatch(zh, /拦截\/检测\/全部/, '「全部」不是合法口径成员')
  const en = code('src/locales/en/common.ts')
  assert.match(en, /block\/detect\/challenge issued\/challenge failed/, 'en 四维口径成对')
  assert.doesNotMatch(en, /block\/detect\/all/, 'en 不得残留「all」口径')
})

test('ccModeAuto 突刺口径（配额已退役）：zh/en 与策略表单 ccSection 同词', () => {
  assert.equal(tSafe('common.app.views.trigDetail.ccModeAuto'), '智能触发（突刺 / 4xx 激增 / 多 UA）')
  assert.match(code('src/locales/en/views.ts'), /'ccModeAuto': 'Smart trigger \(spike \/ 4xx burst \/ multi-UA\)'/)
  assert.doesNotMatch(code('src/locales/zh/views.ts'), /配额突刺/, '配额已退役，不得残留')
})

test('keys.whitelistPlaceholder 真实换行（字面 \\n 不得渲染成可见文本，zh/en 双语）', () => {
  for (const loc of ['zh-CN', 'en'] as const) {
    i18n.global.locale.value = loc
    const text = tSafe('common.app.views.keys.whitelistPlaceholder')
    assert.ok(text.includes('\n'), `${loc}: 占位文案必须含真实换行`)
    assert.doesNotMatch(text, /\\n/, `${loc}: 字面 backslash-n 会渲染成可见文本`)
  }
  i18n.global.locale.value = 'zh-CN'
  // zh/en 源文件成对：真实转义 \n（单反斜杠），不得双反斜杠字面量
  assert.doesNotMatch(code('src/locales/zh/views.ts'), /'whitelistPlaceholder':[^\\]*\\\\n/, 'zh 不得双反斜杠字面量')
  assert.doesNotMatch(code('src/locales/en/views.ts'), /'whitelistPlaceholder':[^\\]*\\\\n/, 'en 不得双反斜杠字面量')
})

// ── en 术语单源：basic.map 大屏=threat screen；观察级=provisional ──
test('en basic.map 术语与 overview.page.threatScreen 同词（不得 Dashboard 分叉）', () => {
  const en = code('src/locales/en/settings.ts')
  const mapBlock = section(en, '"map": {', '\n        },')
  assert.doesNotMatch(mapBlock, /[Dd]ashboard/, 'basic.map 域 zh 母本=威胁大屏，en 不得译 Dashboard')
  assert.match(mapBlock, /"siteLocation": "Threat screen site location"/)
  assert.match(mapBlock, /"visualMode": "Threat screen visual mode"/)
  // 与总览入口键同词根（threat screen）
  assert.match(code('src/locales/en/security.ts'), /"threatScreen": "Threat screen"/)
})

test('en 观察级单源 provisional：crawlerVerifyNote 不得 observe-level 分叉', () => {
  const enViews = code('src/locales/en/views.ts')
  assert.match(enViews, /'crawlerVerifyNote': '[^']*provisional[^']*'/, '观察级 en 统一 provisional（与引擎标签/crawlerTip 同词）')
  assert.doesNotMatch(enViews, /observe-level/, 'observe-level 双词分叉必须退役')
})
