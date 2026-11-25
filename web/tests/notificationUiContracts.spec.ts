// 通知中心 / 安全策略 / 威胁大屏的交互与可访问性契约：
//   - 默认策略折叠行键盘可达（role/tabindex/aria-expanded/Enter+Space 去重）
//   - 秒级刷新的大屏主时钟不得是 live region（读屏每秒播报）
//   - 混合策略查看弹框体限高 + 内部滚动（§16，与同文件另两个弹框同口径）
//   - 通知面表单描述必须用 §16 标准类（form-tip-inline/form-tip-line）
//   - tab 重入刷新：三子组件的 defineExpose 由父组件真实消费
//   - 投递展开行失败无错误不得显示「无错误」；未知通道状态不得伪装成失败
//   - 通道卡轮询随页面可见性暂停（createVisibilityIntervals 单源）
//   - webhook 日报载荷预览同样替换日报变量（JSON 编码，与后端同口径）
//
// 运行：cd web && node --test tests/notificationUiContracts.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { channelErrorKind, channelStatusMessageKey, channelStatusTagType } from '../src/utils/deliveryLog.ts'
import { renderDailySamples } from '../src/utils/dailySamples.ts'
import { code, openTags, section } from './_helpers.ts'

const NOTIFICATIONS = 'src/views/notifications'
const POLICIES = 'src/views/security/SecurityPolicies.vue'
const THREAT = 'src/views/security/ThreatScreen.vue'

const openTagWith = (text: string, tag: string, marker: RegExp): string => {
  const hit = openTags(text, tag).find((candidate) => marker.test(candidate))
  assert.ok(hit, `未找到匹配 ${marker} 的 <${tag}> 开标签`)
  return hit
}

// ── 默认策略折叠行的键盘可达性 ──
test('默认策略折叠行：role=button + tabindex + aria-expanded + Enter/Space 去重激活', () => {
  const policies = code(POLICIES)
  const row = openTagWith(policies, 'div', /class="defaults-row"/)
  assert.match(row, /role="button"/, '可点击行必须声明按钮语义')
  assert.match(row, /:tabindex="0"/, '行必须进入 Tab 序（纯键盘用户可达）')
  assert.match(row, /:aria-expanded="defaultsExpanded\.has\(section\.key \+ row\.name\)"/, '展开态必须暴露给读屏')
  assert.match(row, /@keydown\.enter\.prevent="activateOnce\(\$event,/, 'Enter 激活且长按去重')
  assert.match(row, /@keydown\.space\.prevent="activateOnce\(\$event,/, 'Space 激活且阻止页面滚动')
  assert.match(row, /@click="toggleDefaultsRow\(section\.key \+ row\.name\)"/, '鼠标路径保持原有行为')
  // 同文件既有 a11y 范式（rule-picker-trigger）必须在位，两处同形
  assert.match(openTagWith(policies, 'div', /class="rule-picker-trigger"/), /role="button" tabindex="0"/)
})

// ── 大屏主时钟不是 live region ──
test('秒级刷新主时钟不得标 role=status（读屏每秒播报）', () => {
  const threat = code(THREAT)
  const clock = openTagWith(threat, 'div', /class="main-clock"/)
  assert.doesNotMatch(clock, /role="status"/, '主时钟是装饰性 HUD，不得作为 live region')
  assert.doesNotMatch(clock, /aria-live="(?:polite|assertive)"/, '主时钟不得声明 live 区域')
  // 真正的 live region 必须保留：攻击弹框与错误栈
  assert.match(threat, /class="toasts" role="status" aria-live="polite"/, '攻击弹框仍须播报')
  assert.match(threat, /class="error-stack" role="status" aria-live="polite"/, '错误栈仍须播报')
})

// ── 弹框体高度门（§26-2：全局单源限高）──
test('安全策略三个弹框：正文不再自写限高公式，统一走全局单源', () => {
  const policies = code(POLICIES)
  const dialog = openTagWith(policies, 'el-dialog', /v-model="viewPolicyVisible"/)
  assert.match(dialog, /class="[^"]*\bdialog-body-inset\b/, '弹框必须显式标记 dialog-body-inset（正文留白单源）')
  // 2026-11-25 §26-2 裁定：弹框体限高只允许全局 .el-dialog .el-dialog__body 一处，
  // 组件自写的 100vh − 300px 一类公式一律删除——否则同一弹框出现两条滚动区。
  for (const selector of ['.view-policy-body', '.wizard-content', '.defaults-dialog-body']) {
    assert.doesNotMatch(
      policies,
      new RegExp(`\\${selector}\\s*\\{[^}]*max-height`),
      `${selector} 不得自写限高公式（§26-2）`,
    )
  }
})

// ── 描述类标准（§16）──
test('通知三组件：form-hint/bind-hint 清零，标准描述类在位且不再组件内重定义', () => {
  for (const file of ['NotificationCenter.vue', 'ChannelCards.vue', 'SystemCredentials.vue']) {
    const src = code(`${NOTIFICATIONS}/${file}`)
    assert.doesNotMatch(src, /class="[^"]*\bform-hint\b/, `${file}: form-hint 为 §16 遗留类，禁止再用`)
    assert.doesNotMatch(src, /class="[^"]*\bbind-hint\b/, `${file}: 自写 bind-hint 与 §16 冲突`)
    assert.doesNotMatch(src, /^\.form-hint \{/m, `${file}: 不得在 scoped CSS 重定义 form-hint`)
    assert.doesNotMatch(src, /^\.bind-hint \{/m, `${file}: 不得在 scoped CSS 重定义 bind-hint`)
    assert.doesNotMatch(src, /creds-inline-hint/, `${file}: 自写行内 hint 覆写必须删除`)
  }
  const center = code(`${NOTIFICATIONS}/NotificationCenter.vue`)
  assert.match(center, /class="form-tip-inline"/, '同行描述走 form-tip-inline')
  const cards = code(`${NOTIFICATIONS}/ChannelCards.vue`)
  assert.match(cards, /class="form-tip-line"/, '块级描述走 form-tip-line')
  const creds = code(`${NOTIFICATIONS}/SystemCredentials.vue`)
  // SMTP 两条开关说明（端口口径 51 字符 / 跳过校验 21 字）超 §26-5 同行阈值 → 块级。
  assert.doesNotMatch(creds, /class="form-tip-inline"/, 'SMTP 开关说明超阈值一律块级（§26-5）')
  assert.match(creds, /class="form-tip-line"/, 'SMTP 块级描述走 form-tip-line')
})

// ── tab 重入刷新：defineExpose 真实消费 ──
test('tab 重入刷新：三子组件挂 ref，activeTab 切换调用其实例方法', () => {
  const center = code(`${NOTIFICATIONS}/NotificationCenter.vue`)
  assert.match(center, /<ChannelCards ref="channelCardsRef" \/>/, '通道卡必须挂 ref（否则重入陈旧）')
  assert.match(center, /<DeliveryLog ref="deliveryLogRef" \/>/, '投递记录必须挂 ref')
  assert.match(center, /<SystemCredentials ref="systemCredentialsRef" \/>/, '邮件服务必须挂 ref')
  const watchTab = section(center, 'watch(activeTab,', '\n})')
  assert.match(watchTab, /channelCardsRef\.value\?\.fetchChannels\(/, '切回通道 tab 必须静默重取')
  assert.match(watchTab, /deliveryLogRef\.value\?\.fetchDeliveries\(\)/, '切回投递 tab 必须重取')
  assert.match(watchTab, /systemCredentialsRef\.value\?\.fetchSettings\(\)/, '切回邮件服务 tab 必须重取')
  assert.match(watchTab, /fetchRules\(false\)/, '规则 tab 行为保持不变')
  // 被消费的三个 expose 必须仍在子组件里（脚本侧契约）
  assert.match(code(`${NOTIFICATIONS}/ChannelCards.vue`), /defineExpose\(\{ fetchChannels \}\)/)
  assert.match(code(`${NOTIFICATIONS}/DeliveryLog.vue`), /defineExpose\(\{ fetchDeliveries \}\)/)
  assert.match(code(`${NOTIFICATIONS}/SystemCredentials.vue`), /defineExpose\(\{ fetchSettings \}\)/)
})

// ── 失败无错误 / 未知状态 ──
test('分通道状态：未知状态中性回显原文，已知状态走词条', () => {
  assert.equal(channelStatusMessageKey('sent'), 'statusSent')
  assert.equal(channelStatusMessageKey('failed'), 'statusFailed')
  assert.equal(channelStatusMessageKey('dead'), 'statusDead')
  assert.equal(channelStatusMessageKey('pending'), 'statusPending')
  assert.equal(channelStatusMessageKey('throttled'), null, '未知状态不得映射成任何既有词条')
  assert.equal(channelStatusTagType('sent'), 'success')
  assert.equal(channelStatusTagType('failed'), 'danger')
  assert.equal(channelStatusTagType('throttled'), 'info', '未知状态必须中性着色（不得伪装成失败）')
})

test('展开行错误文案形态：失败无错误=未记录原因，成功/等待=无错误', () => {
  assert.equal(channelErrorKind({ status: 'sent' }), 'none')
  assert.equal(channelErrorKind({ status: 'pending' }), 'none')
  assert.equal(channelErrorKind({ status: 'failed', error: '  ' }), 'missing', '空白错误等同未记录')
  assert.equal(channelErrorKind({ status: 'dead', error: null }), 'missing')
  assert.equal(channelErrorKind({ status: 'failed', error: 'connection refused' }), 'error')
})

test('投递展开行接线：错误文案/状态标签单源化，两条死 CSS 清零', () => {
  const log = code(`${NOTIFICATIONS}/DeliveryLog.vue`)
  assert.match(log, /\{\{ channelErrorText\(ch\) \}\}/, '错误列必须走单源文案（区分未记录原因）')
  assert.match(log, /:type="channelStatusTagType\(ch\.status\)"/, '通道状态标签类型必须走单源判据')
  assert.match(log, /expandErrorMissing/, '失败无错误必须有专门文案（不得显示「无错误」）')
  assert.doesNotMatch(log, /ch\.error \|\| t\('app\.notification\.deliveries\.expandNoError'\)/, '「失败但无错误」不得落成「无错误」')
  assert.doesNotMatch(log, /^\.delivery-filters \{/m, '死类 .delivery-filters 必须清零')
  assert.doesNotMatch(log, /^\.scope-hint \{/m, '死类 .scope-hint 必须清零')
})

// ── 可见性感知轮询 + 死 CSS ──
test('通道卡 15s 轮询随可见性暂停（仓库单源），不达标致轮询清零', () => {
  const cards = code(`${NOTIFICATIONS}/ChannelCards.vue`)
  assert.match(cards, /createVisibilityIntervals\(\{ intervals: \[\{ tick: \(\) => \{ void fetchChannels\(true\) \}, ms: 15000 \}\] \}\)/, '轮询必须走可见性单源')
  assert.match(cards, /linkPoll\.start\(\)/, '挂载即启动')
  assert.match(cards, /linkPoll\?\.stop\(\)/, '卸载必须摘监听并清定时器')
  assert.doesNotMatch(cards, /setInterval\(\(\) => \{ void fetchChannels\(true\) \}, 15000\)/, '裸 setInterval 常驻轮询必须清零')
})

// ── webhook 日报预览变量替换 ──
test('日报样例替换：json=后端同口径（值一律 JSON 编码），文本/markdown 原样', () => {
  const json = renderDailySamples('{\n  "date": {{date}},\n  "requests": {{requests}}\n}', { format: 'json' })
  assert.equal(json, '{\n  "date": "2026-11-18",\n  "requests": "128340"\n}', 'JSON 载荷模板的占位值必须加引号（后端 renderStyleTemplateJSON 同口径）')
  const text = renderDailySamples('日期 {{date}} / 请求 {{requests}}', { format: 'text' })
  assert.equal(text, '日期 2026-11-18 / 请求 128340', '文本格式原样嵌入')
  const md = renderDailySamples('{{top_ips}}', {
    format: 'markdown',
    mdMultiValue: (key, value) => (key === 'top_ips' ? `| IP | 次数 |\n| --- | --- |\n| ${value.split('\n')[0]} |` : null),
  })
  assert.match(md, /^\n\| IP \| 次数 \|/, 'markdown 多值变量按语义表格展开（前后留空行）')
  assert.match(md, /\n$/)
  const untouched = renderDailySamples('无变量模板', { format: 'json' })
  assert.equal(untouched, '无变量模板', '无占位符时原样返回')
})

test('预览接线：webhook 不再被排除，过期注释与实现同口径', () => {
  const center = code(`${NOTIFICATIONS}/NotificationCenter.vue`)
  assert.doesNotMatch(center, /tplActiveChannel\.value\?\.type !== 'webhook'/, 'webhook 不得跳过日报变量样例替换')
  assert.match(center, /renderDailySamples\(text, \{/, '预览替换必须委托单源纯函数')
  assert.match(center, /const format = isWebhookPayload \? 'json' :/, 'webhook 载荷模板按 JSON 值语义替换')
  const ph = section(center, 'const tplActivePh = computed', '\n})')
  assert.doesNotMatch(ph, /webhook 载荷模板仅事件变量/, '过期注释（后端日报派发对 webhook 同样替换日报变量）必须修正')
  assert.match(ph, /\[\.\.\.dailyPh, \.\.\.tplPh\]/, '日报模式两类变量都可用（含 webhook）')
})
