// 首页/任务监控的三处视图缺陷：
//   - 状态码列注释承诺「超高换行兜底」，样式却是 nowrap + overflow:hidden，
//     百万级流量时末尾 Block badge 被静默裁掉（安全拦截看起来为 0）；
//   - 「24h 失败」KPI 在只读态挂 Lock 图标，被读成「失败数被锁定」；
//   - 规则健康查询用布尔门直接丢弃在途期间的新版本需求，旧响应又被版本守卫
//     丢弃 → 新规则集整轮健康列陈旧且无提示。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { cssDeclarations, cssRule, elementSlice, openTags, section, code } from './_helpers.ts'

test('状态码列超高时换行，不裁掉 Block badge', () => {
  const page = code('src/views/Dashboard.vue')
  // 声明表判定：`section(page, '.status-codes {', '}')` 的终止标记是第一个 `}`，
  // 规则一旦多一条嵌套块（`&:hover { … }`）切片就在那里截断，随后两条负断言
  // 恒真；按属性/值判定与排版、属性顺序无关。
  const decls = cssDeclarations(page, '.status-codes')
  assert.equal(decls.get('flex-wrap'), 'wrap', '必须与列注释承诺的换行兜底一致')
  assert.equal(decls.has('overflow'), false, 'overflow:hidden 静默裁掉末尾 badge（含 title 不可达）')
  // 嵌套块里的声明不进顶层声明表，负断言必须覆盖整块文本：
  // `&:hover { flex-wrap: nowrap }` 与现代槽内 min-width 同样会裁掉 badge。
  const block = cssRule(page, '.status-codes')
  assert.doesNotMatch(block, /nowrap/, 'nowrap 会让 flex-shrink:0 的 badge 溢出（含嵌套块）')
  assert.doesNotMatch(block, /overflow:\s*hidden/, 'overflow:hidden 静默裁掉末尾 badge（含嵌套块）')
  // 「badge 在列内」按元素配对取段：全页存在性断言在 badge 挪出状态码列
  // （如挪到流量列）时仍假绿。
  const codesTag = openTags(page, 'div').find((tag) => tag.includes('status-codes'))
  assert.ok(codesTag !== undefined, '状态码列 div.status-codes 缺失')
  const codesEl = elementSlice(page, page.indexOf(codesTag), 'div')
  assert.match(codesEl, /class="status-code status-blocked"/, 'Block badge 必须仍在状态码列内')
})

test('24h 失败 KPI 不再挂只读锁图标', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  // 整串字面属性作切片起点（`<div class="tm-kpi-num" :class="{ … }">`）在加/删
  // 一个属性时就假红。按属性集定位 24h 失败数字块，再取其所在 KPI 卡整段
  // （原缺陷的 Lock 挂在卡内 label div 上，只切数字 div 会漏掉回归点）。
  const numTag = openTags(page, 'div').find((tag) => tag.includes('tm-kpi-num') && tag.includes('fail24h'))
  assert.ok(numTag !== undefined, '24h 失败 KPI 数字块缺失')
  // 四张 KPI 卡共用同一开标签字面串，不能按串回搜位置——取数字块之前最近
  // 的 <el-card 开标签（elementAt 同款「offset 之前最近开启者」语义）。
  const numAt = page.indexOf(numTag)
  let cardAt = -1
  for (const match of page.slice(0, numAt).matchAll(/<el-card\b/g)) cardAt = match.index
  assert.ok(cardAt >= 0, '24h 失败 KPI 必须在 el-card 内')
  const card = elementSlice(page, cardAt, 'el-card')
  assert.match(card, /fail24h/, '切错 KPI 卡（必须含 24h 失败数字）')
  assert.doesNotMatch(card, /Lock/, '只读语义由操作列禁用与错误横幅承载，不在单个 KPI 上暗示数据受限')
  assert.doesNotMatch(page, /tm-kpi-lock/, '配套样式属死样式')
  // Lock 仍被证书队列横幅与详情图标消费——不得连带删除 import
  assert.match(page, /<el-icon class="title-icon"><Lock \/><\/el-icon>/)
  assert.match(page, /category === '证书' \? Lock/)
})

test('规则健康查询在途时记录新版本需求并在收尾补跑', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /let ruleHealthInFlight = false/)
  assert.doesNotMatch(page, /isFetchingRuleHealth/, '布尔门已退役')
  const fetchHealth = section(page, 'const fetchRuleHealth = async', 'const controlCaddy')
  // 全页负断言（上方 doesNotMatch(page, /isFetchingRuleHealth/)）已蕴含「入口
  // 不再以在途标记丢弃需求」；此处按行号取第二行的写法脆弱且零增量，已删除。
  assert.match(fetchHealth, /if \(ruleHealthInFlight\) \{/, '在途分支必须显式处理新需求')
  assert.match(fetchHealth, /pendingRuleHealth = \{ rules: currentRules, version \}/, '只保留最新需求')
  assert.match(fetchHealth, /pendingRuleHealth\.version < version/, '更旧的需求不得覆盖更新版本')
  const replay = section(fetchHealth, '} finally {', '\n  }\n}')
  assert.match(replay, /await fetchRuleHealth\(pending\.rules, pending\.version\)/, '收尾补跑被丢弃的版本')
  assert.match(replay, /pending\.version !== version/, '同一版本无需重跑（在途那轮已覆盖）')
  // 补跑不得沿用旧轮次 signal（上一轮可能已 abort）
  assert.doesNotMatch(replay, /roundSignal/, '补跑必须回落页级永久 signal')
})
