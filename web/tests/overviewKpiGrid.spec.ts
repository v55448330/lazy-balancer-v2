import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, cssDeclarations, member, openTags, section } from './_helpers.ts'

// 安全总览状态条重设计（用户裁定）：活跃策略退役，四 KPI（拦截/检测/正常请求/
// 人机验证）等分栅格 + 每列同构（标签/今日/昨日/协议拆分），契约字段防御式消费，
// 趋势与攻击类型分布同行等高。源码钉 spec：断言落在剥注释视图上。

/** 状态条防护区（status-guard）按竖分隔线切成四列切片。 */
const guardCols = (): [string, string, string] => {
  const guard = section(code('src/views/security/SecurityOverview.vue'), '<div class="status-guard">', '<div class="status-lib">')
  const cols = guard.split('<div class="strip-divider"></div>')
  assert.equal(cols.length, 3, `前置：防护区必须恰好三列（两条竖分隔线），实际 ${cols.length}`)
  return cols as [string, string, string]
}

test('三 KPI 等分栅格：拦截/检测/正常请求 同构三列，挑战移入 CC 卡片', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  const guard = section(page, '<div class="status-guard">', '<div class="status-lib">')
  assert.equal(
    openTags(guard, 'div').filter((t) => t.includes('class="guard-item"')).length,
    3,
    '必须恰好三个 guard-item 列（挑战统计移至 CC 卡片）',
  )
  assert.equal(guard.split('<div class="strip-divider"></div>').length - 1, 2, '列间必须两条竖分隔线')
  assert.doesNotMatch(page, /活跃策略/, '活跃策略指标必须退役')
  assert.doesNotMatch(guard, /active_policies/, '防护区不得再渲染 active_policies')
  // 等分与分隔形态（flex 等宽栅格，不引新组件）
  const item = cssDeclarations(page, '.guard-item')
  assert.equal(item.get('flex'), '1 1 0', '三列必须 flex:1 1 0 等宽')
  assert.equal(item.get('flex-direction'), 'column', '列内四行纵向排布')
  const divider = cssDeclarations(page, '.strip-divider')
  assert.equal(divider.get('width'), '1px', '竖分隔线宽 1px')
})

test('每列同构：标签 / 今日主数值 / 昨日对比 / 协议拆分 / 通过率', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  const [blocked, detected, normal] = guardCols()
  const card = section(page, '<el-card shadow="always" class="overview-card status-strip-card">', '<div class="status-strip">')
  assert.match(card, /<template #header>/, '状态条卡必须有卡头（与其他卡片一致）')
  assert.match(card, /class="title-icon"><Stopwatch \/><\/el-icon>/, '卡头图标 Stopwatch')
  // 卡头（与其他卡片同构）：card-title + 语义图标 + 「防护运行状态」。
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(card, /<span>\{\{ t\('app\.security\.overview\.status\.cardTitle'\) \}\}<\/span>/, '卡头标题「防护运行状态」')
  assert.ok(code('src/locales/zh/security.ts').includes('防护运行状态'), '卡头标题原文必须在 zh 母本词条中')
  // 列 1 拦截：红主题 + 今日合计 + 昨日门 + 双胶囊拆分（HTTP=合计−TCP）
  assert.match(blocked, /class="strip-label">\s*\{\{ t\('app\.security\.overview\.status\.blocked'\) \}\}/, '标签无色点（用户裁定撤回），13px/600')
  assert.match(blocked, /<el-tooltip :content="todayCountTip"/, '拦截列保留既有口径 tooltip')
  assert.match(blocked, /class="strip-value is-danger">\{\{ fmtStatNum\(overview\.today_blocked\) \}\}/)
  assert.match(blocked, /v-if="yesterdayBlocked !== null" class="strip-sub"><span class="strip-sub-label">\{\{ t\('app\.security\.overview\.status\.yesterday'\) \}\}<\/span>/)
  assert.match(blocked, /v-if="todayBlockedSplit" class="strip-sub">/)
  assert.match(blocked, /proto-split-label">HTTP<\/span><span class="strip-sub-num">\{\{ fmtStatNum\(todayBlockedSplit\.http\) \}\}/)
  assert.match(blocked, /proto-split-label">TCP<\/span><span class="strip-sub-num">\{\{ fmtStatNum\(todayBlockedSplit\.tcp\) \}\}/)
  // 列 2 检测：橙主题 + 昨日门 + HTTP/TCP 双胶囊拆分（TCP 检测来自信任检测
  // logged——可能产生数据就如实显示；HTTP=合计−TCP）
  assert.match(detected, /class="strip-label">\{\{ t\('app\.security\.overview\.status\.detected'\) \}\}/)
  assert.doesNotMatch(detected, /el-tooltip/, '重设计后仅拦截列带 tooltip')
  assert.doesNotMatch(detected, /strip-label-dot/, '标签色点已按用户裁定撤回')
  assert.match(detected, /class="strip-value is-warning">\{\{ fmtStatNum\(overview\.today_detected\) \}\}/)
  assert.match(detected, /v-if="yesterdayDetected !== null" class="strip-sub"><span class="strip-sub-label">\{\{ t\('app\.security\.overview\.status\.yesterday'\) \}\}<\/span>/)
  assert.match(detected, /v-if="todayDetectedSplit" class="strip-sub">/)
  assert.match(detected, /proto-split-label">HTTP<\/span><span class="strip-sub-num">\{\{ fmtStatNum\(todayDetectedSplit\.http\) \}\}/)
  assert.match(detected, /proto-split-label">TCP<\/span><span class="strip-sub-num">\{\{ fmtStatNum\(todayDetectedSplit\.tcp\) \}\}/)
  // 列 3 正常请求：默认深色 + 昨日门 + HTTP/TCP 双点（字段缺失整行隐藏）
  assert.match(normal, /class="strip-label">\{\{ t\('app\.security\.overview\.status\.normal'\) \}\}/)
  // 三列标签/「昨日」原文钉 zh 母本(键改名后负断言不空转)
  assert.ok(code('src/locales/zh/security.ts').includes('拦截'), '拦截标签原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('检测'), '检测标签原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('"正常请求"'), '正常请求标签原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('"昨日"'), '「昨日」标签原文必须在 zh 母本词条中')
  assert.match(normal, /class="strip-value">\{\{ fmtStatNum\(overview\.normal_today\) \}\}/)
  assert.match(normal, /v-if="normalYesterday !== null" class="strip-sub"><span class="strip-sub-label">\{\{ t\('app\.security\.overview\.status\.yesterday'\) \}\}<\/span>/)
  assert.match(normal, /v-if="normalTodaySplit" class="strip-sub">/)
  assert.match(normal, /proto-dot--http[\s\S]{0,200}proto-split-label">HTTP<\/span><span class="strip-sub-num">\{\{ fmtStatNum\(normalTodaySplit\.http\) \}\}/)
  assert.match(normal, /proto-dot--tcp[\s\S]{0,200}proto-split-label">TCP<\/span><span class="strip-sub-num">\{\{ fmtStatNum\(normalTodaySplit\.tcp\) \}\}/)
  // 主数值排版钉测：24px/800；三列主题色（拦截红/检测橙/正常 #303133）；
  // 标签 13px/600（用户裁定：稍大并加粗）；「昨日」标签词 700 加粗
  const value = cssDeclarations(page, '.strip-value')
  assert.equal(value.get('font-size'), '24px')
  assert.equal(value.get('font-weight'), '800')
  assert.equal(value.get('color'), '#303133')
  assert.equal(cssDeclarations(page, '.strip-value.is-danger').get('color'), '#f56c6c')
  assert.equal(cssDeclarations(page, '.strip-value.is-warning').get('color'), '#e6a23c')
  const label = cssDeclarations(page, '.strip-label')
  assert.equal(label.get('font-size'), '13px')
  assert.equal(label.get('font-weight'), '600')
  assert.doesNotMatch(page, /strip-label-dot/, '色点样式已整体移除')
  assert.equal(cssDeclarations(page, '.strip-sub-label').get('font-weight'), '700')
  // CC 卡片：原限流卡片替换为 CC 防护统计（今日挑战/通过率/通过失败/封禁）
  assert.match(page, /t\('app\.security\.overview\.cc\.title'\)/)
  assert.match(page, /t\('app\.security\.overview\.cc\.challengedToday'\)/)
  assert.match(page, /t\('app\.security\.overview\.cc\.passRate'\)/)
  assert.match(page, /t\('app\.security\.overview\.cc\.passFail'\)/)
  assert.match(page, /t\('app\.security\.overview\.cc\.bans'\)/)
  assert.doesNotMatch(page, /rateLimitBlocks|fetchRateLimitBlocks|rate-limit-blocks/, '限流卡片与取数必须整体移除')
  assert.equal(cssDeclarations(page, '.strip-value.is-info').get('color'), '#409eff')
})

test('防御式消费：契约字段缺失（旧后端）对应行隐藏', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  // /security/overview 新契约字段：全部可选 number（旧后端缺省 → 行隐藏）
  const iface = section(page, 'interface Overview', '}')
  for (const field of [
    'yesterday_blocked', 'yesterday_blocked_tcp', 'yesterday_detected', 'yesterday_detected_tcp',
    'today_blocked_tcp', 'today_detected_tcp',
    'normal_today', 'normal_today_http', 'normal_today_tcp',
    'normal_yesterday', 'normal_yesterday_http', 'normal_yesterday_tcp',
  ]) {
    assert.match(iface, new RegExp(`\\b${field}\\??: number\\b`), `契约字段 ${field} 必须声明为可选 number`)
  }
  // 昨日行共用单源门：非有限数 → null（行隐藏）
  const gate = section(page, 'const statOrNull =', 'const yesterdayBlocked')
  assert.match(gate, /Number\.isFinite/)
  for (const c of ['yesterdayBlocked', 'yesterdayDetected', 'normalYesterday']) {
    assert.match(page, new RegExp(`const ${c} = computed\\(\\(\\) => statOrNull\\(overview\\.value\\.${c === 'normalYesterday' ? 'normal_yesterday' : c === 'yesterdayBlocked' ? 'yesterday_blocked' : 'yesterday_detected'}\\)\\)`))
  }
  // 拦截拆分：today_blocked_tcp 缺失（旧后端）→ null 整行隐藏
  const tbSplit = member(page, 'const todayBlockedSplit =')
  assert.match(tbSplit, /today_blocked_tcp/)
  assert.match(tbSplit, /return null/)
  // 正常请求拆分：HTTP/TCP 两字段齐备才显示，缺失 → null
  const ntSplit = member(page, 'const normalTodaySplit =')
  assert.match(ntSplit, /normal_today_http/)
  assert.match(ntSplit, /normal_today_tcp/)
  assert.match(ntSplit, /return null/)
  // 检测列拆分行：today_detected_tcp 缺失（旧后端）→ null 整行隐藏
  const tdSplit = member(page, 'const todayDetectedSplit =')
  assert.match(tdSplit, /today_detected_tcp/)
  assert.match(tdSplit, /return null/)
  // 检测列两行均带 v-if（昨日门 + 拆分门）
  const [, detected] = guardCols()
  assert.equal([...detected.matchAll(/<div v-if[^>]*class="strip-sub">/g)].length, 2, '检测列昨日行+拆分行各带 v-if')
})

test('同行等高：趋势与攻击类型分布拉伸同高，「按阶段展示」不撑高卡头', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /<el-row :gutter="20" class="mb-5 charts-row">/, '图表行挂 charts-row 类')
  assert.equal(cssDeclarations(page, '.charts-row .el-card').get('height'), '100%', '同行两卡必须 height:100% 拉伸等高')
  // checkbox 脱离内联样式，高度钉到卡头标题行（行内紧凑，不撑高卡头）。
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(page, /<el-checkbox v-model="attackByStage" size="small" class="header-checkbox">\{\{ t\('app\.security\.overview\.trend\.byStage'\) \}\}<\/el-checkbox>/)
  assert.ok(code('src/locales/zh/security.ts').includes('按阶段展示'), '「按阶段展示」原文必须在 zh 母本词条中')
  const cb = cssDeclarations(page, '.header-checkbox')
  assert.equal(cb.get('height'), '20px', 'checkbox 高度钉到卡头标题行')
  assert.equal(cb.get('margin-left'), '12px')
  assert.doesNotMatch(page, /style="margin-left: 12px"/, '内联样式必须退役')
})
