import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, cssDeclarations, member, openTags, section } from './_helpers.ts'

// 安全总览状态条重设计（用户裁定）：活跃策略退役，三 KPI（拦截/检测/正常请求）
// 等分栅格 + 每列四行同构（标签/今日/昨日/协议拆分），契约字段防御式消费，
// 趋势与攻击类型分布同行等高。源码钉 spec：断言落在剥注释视图上。

/** 状态条防护区（status-guard）按竖分隔线切成三列切片。 */
const guardCols = (): [string, string, string] => {
  const guard = section(code('src/views/security/SecurityOverview.vue'), '<div class="status-guard">', '<div class="status-lib">')
  const cols = guard.split('<div class="strip-divider"></div>')
  assert.equal(cols.length, 3, `前置：防护区必须恰好三列（两条竖分隔线），实际 ${cols.length}`)
  return cols as [string, string, string]
}

test('三 KPI 等分栅格：拦截/检测/正常请求 同构三列，活跃策略退役', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  const guard = section(page, '<div class="status-guard">', '<div class="status-lib">')
  assert.equal(
    openTags(guard, 'div').filter((t) => t.includes('class="guard-item"')).length,
    3,
    '必须恰好三个 guard-item 列',
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

test('每列四行同构：标签 / 今日主数值 / 昨日对比 / 协议拆分', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  const [blocked, detected, normal] = guardCols()
  // 卡头（与其他卡片同构）：card-title + 语义图标 + 「防护运行状态」
  const card = section(page, '<el-card shadow="always" class="overview-card status-strip-card">', '<div class="status-strip">')
  assert.match(card, /<template #header>/, '状态条卡必须有卡头（与其他卡片一致）')
  assert.match(card, /class="title-icon"><Stopwatch \/><\/el-icon>/, '卡头图标 Stopwatch')
  assert.match(card, /<span>防护运行状态<\/span>/, '卡头标题「防护运行状态」')
  // 列 1 拦截：红主题 + 今日合计 + 昨日门 + 双胶囊拆分（HTTP=合计−TCP）
  assert.match(blocked, /class="strip-label">\s*拦截/, '标签无色点（用户裁定撤回），13px/600')
  assert.match(blocked, /<el-tooltip :content="todayCountTip"/, '拦截列保留既有口径 tooltip')
  assert.match(blocked, /class="strip-value is-danger">\{\{ fmtStatNum\(overview\.today_blocked\) \}\}/)
  assert.match(blocked, /v-if="yesterdayBlocked !== null" class="strip-sub"><span class="strip-sub-label">昨日<\/span>/)
  assert.match(blocked, /v-if="todayBlockedSplit" class="strip-sub">/)
  assert.match(blocked, /proto-dot--http[\s\S]{0,120}HTTP \{\{ fmtStatNum\(todayBlockedSplit\.http\) \}\}/)
  assert.match(blocked, /proto-dot--tcp[\s\S]{0,120}TCP \{\{ fmtStatNum\(todayBlockedSplit\.tcp\) \}\}/)
  // 列 2 检测：橙主题 + 昨日门 + 单 HTTP 点（TCP 恒 0 不显示 TCP）
  assert.match(detected, /class="strip-label">检测/)
  assert.doesNotMatch(detected, /el-tooltip/, '重设计后仅拦截列带 tooltip')
  assert.doesNotMatch(detected, /strip-label-dot/, '标签色点已按用户裁定撤回')
  assert.match(detected, /class="strip-value is-warning">\{\{ fmtStatNum\(overview\.today_detected\) \}\}/)
  assert.match(detected, /v-if="yesterdayDetected !== null" class="strip-sub"><span class="strip-sub-label">昨日<\/span>/)
  assert.match(detected, /<div class="strip-sub">\s*<span class="proto-split-item"><i class="proto-dot proto-dot--http/)
  assert.doesNotMatch(detected, /proto-dot--tcp/, '检测列不得出现 TCP 点')
  // 列 3 正常请求：默认深色 + 昨日门 + HTTP/TCP 双点（字段缺失整行隐藏）
  assert.match(normal, /class="strip-label">正常请求/)
  assert.match(normal, /class="strip-value">\{\{ fmtStatNum\(overview\.normal_today\) \}\}/)
  assert.match(normal, /v-if="normalYesterday !== null" class="strip-sub"><span class="strip-sub-label">昨日<\/span>/)
  assert.match(normal, /v-if="normalTodaySplit" class="strip-sub">/)
  assert.match(normal, /proto-dot--http[\s\S]{0,120}HTTP \{\{ fmtStatNum\(normalTodaySplit\.http\) \}\}/)
  assert.match(normal, /proto-dot--tcp[\s\S]{0,120}TCP \{\{ fmtStatNum\(normalTodaySplit\.tcp\) \}\}/)
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
})

test('防御式消费：契约字段缺失（旧后端）对应行隐藏', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  // /security/overview 新契约字段：全部可选 number（旧后端缺省 → 行隐藏）
  const iface = section(page, 'interface Overview', '}')
  for (const field of [
    'yesterday_blocked', 'yesterday_blocked_tcp', 'yesterday_detected', 'yesterday_detected_tcp',
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
  // 检测列拆分行恒显（today_detected 非可选）：只有昨日行带 v-if，拆分行无门
  const [, detected] = guardCols()
  assert.equal([...detected.matchAll(/<div v-if[^>]*class="strip-sub">/g)].length, 1, '检测列只有昨日行带 v-if')
})

test('同行等高：趋势与攻击类型分布拉伸同高，「按阶段展示」不撑高卡头', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /<el-row :gutter="20" class="mb-5 charts-row">/, '图表行挂 charts-row 类')
  assert.equal(cssDeclarations(page, '.charts-row .el-card').get('height'), '100%', '同行两卡必须 height:100% 拉伸等高')
  // checkbox 脱离内联样式，高度钉到卡头标题行（行内紧凑，不撑高卡头）
  assert.match(page, /<el-checkbox v-model="attackByStage" size="small" class="header-checkbox">按阶段展示<\/el-checkbox>/)
  const cb = cssDeclarations(page, '.header-checkbox')
  assert.equal(cb.get('height'), '20px', 'checkbox 高度钉到卡头标题行')
  assert.equal(cb.get('margin-left'), '12px')
  assert.doesNotMatch(page, /style="margin-left: 12px"/, '内联样式必须退役')
})
