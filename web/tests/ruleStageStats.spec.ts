// 单规则阶段计数展示口径：取数失败、空载荷、零计数、未归因桶必须互相可区分。
// 旧实现把「失败」与「成功但载荷为空」都压成 '—'（面板行压成空串），读者无法
// 判断是请求失败还是确实零拦截；未归因桶整键丢弃，让「未归因」显示成 0。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { stageAvgDurationUs, stageCountChip, stageCountSummary, stageTimingChip, unattributedCountText, type RuleStageCounts } from '../src/utils/ruleStageStats.ts'
import { code, repoCode } from './_helpers.ts'

const counts = (patch: Partial<RuleStageCounts> = {}): RuleStageCounts => ({
  stage1_blocked_24h: 0,
  stage3_blocked_24h: 0,
  stage_unattributed_24h: 0,
  ...patch,
})

test('计数 chip：请求在途不出 chip（加载态不外泄）', () => {
  assert.deepEqual(stageCountChip(1, null, { settled: false, failed: false }), {})
  assert.deepEqual(stageCountChip(1, counts(), { settled: false, failed: false }), {})
})

test('计数 chip：失败=「计数不可用」，不再与空载荷共用一个 —', () => {
  assert.deepEqual(stageCountChip(1, null, { settled: true, failed: true }), { chip: '计数不可用' })
  // 即便旧载荷仍在内存（失败前已有值），失败态优先——不得把陈旧计数当结论
  assert.deepEqual(stageCountChip(1, counts({ stage1_blocked_24h: 9 }), { settled: true, failed: true }), { chip: '计数不可用' })
})

test('计数 chip：成功但载荷为空仍为 —（契约违约，不得冒充 0）', () => {
  assert.deepEqual(stageCountChip(3, null, { settled: true, failed: false }), { chip: '—' })
})

test('计数 chip：成功且有计数时各阶段取自己的桶（阶段 2 CC 防护无规则级分桶）', () => {
  const data = counts({ stage1_blocked_24h: 4, stage3_blocked_24h: 7 })
  assert.deepEqual(stageCountChip(1, data, { settled: true, failed: false }), { chip: '24h 拦截 4' })
  // 阶段 2 = CC 防护：挑战/通过计数由 /security/human/stats 承担，规则级节点不出 chip
  assert.deepEqual(stageCountChip(2, data, { settled: true, failed: false }), {})
  // 阶段 3 = 内容防护（WAF）：后端字段 stage3_blocked_24h 与阶段号同值
  assert.deepEqual(stageCountChip(3, data, { settled: true, failed: false }), { chip: '24h 拦截 7' })
})

test('面板统计行：成功且为零要说出「0 次」，失败与在途都不占行', () => {
  assert.match(stageCountSummary(1, counts(), { settled: true, failed: false }), /本阶段拦截 0 次/)
  assert.equal(stageCountSummary(1, counts(), { settled: true, failed: true }), '', '失败由面板失败行承载，不得压成空行冒充成功')
  assert.equal(stageCountSummary(1, null, { settled: false, failed: false }), '')
  assert.equal(stageCountSummary(0, counts(), { settled: true, failed: false }), '', '阶段 0 无计数概念')
  // 阶段 2 CC 防护：不得回落 WAF 桶（stage3_blocked_24h）冒充本阶段统计
  assert.equal(stageCountSummary(2, counts({ stage3_blocked_24h: 5 }), { settled: true, failed: false }), '', '阶段 2 CC 防护无规则级统计行')
  assert.match(stageCountSummary(3, counts({ stage3_blocked_24h: 5 }), { settled: true, failed: false }), /本阶段拦截 5 次/, '阶段 3 WAF 取 stage3_blocked_24h')
})

test('未归因桶：有值时披露，无值时不打扰', () => {
  assert.equal(unattributedCountText(counts()), '')
  assert.equal(unattributedCountText(null), '')
  assert.match(unattributedCountText(counts({ stage_unattributed_24h: 3 })), /另有 3 次未能归因阶段/)
  const summary = stageCountSummary(3, counts({ stage3_blocked_24h: 0, stage_unattributed_24h: 12 }), { settled: true, failed: false })
  assert.match(summary, /本阶段拦截 0 次/)
  assert.match(summary, /另有 12 次未能归因阶段/, '未归因拦截不得被读成「零拦截」')
})

test('耗时：无采样不出角标，有采样按格式给出', () => {
  assert.equal(stageTimingChip(1, counts()), '')
  assert.equal(stageTimingChip(1, null), '')
  assert.equal(stageTimingChip(1, counts({ precheck_avg_us: 2500, precheck_samples: 8 })), '平均耗时 2.5ms')
  assert.equal(stageTimingChip(3, counts({ waf_avg_us: 400 })), '平均耗时 0.400ms')
  assert.equal(stageAvgDurationUs(1, null), 0)
  assert.equal(stageAvgDurationUs(3, counts({ waf_avg_us: 400 })), 400)
  assert.match(stageCountSummary(1, counts({ precheck_avg_us: 2500, precheck_samples: 8 }), { settled: true, failed: false }), /近 24 小时 8 次采样/)
})

// ── 阶段 2 配额限流退役后的阶段号回归（2026-11-13）──
// buildStageModel 只产 stage 0/1/2/3（stage3=内容防护 WAF），旧实现把 stage3
// 当人机验证返回空、WAF 计数留在永不传入的 stage4 兜底 → 流程弹框 WAF 24h
// 拦截数与统计行恒不显示。阶段号域必须收敛到 1|2|3，不得再留 stage4。
test('阶段号域：WAF 计数走 stage3（stage4 旧编号已退役，不得吞掉拦截数）', () => {
  const data = counts({ stage1_blocked_24h: 4, stage3_blocked_24h: 7 })
  const settled = { settled: true, failed: false }
  assert.deepEqual(stageCountChip(3, data, settled), { chip: '24h 拦截 7' }, 'stage3=内容防护 WAF，必须显示本阶段拦截数')
  assert.match(stageCountSummary(3, data, settled), /本阶段拦截 7 次/, 'stage3 统计行不得为空')
  // 阶段 2（CC 防护）仍无规则级分桶：挑战统计在 /security/human/stats
  assert.deepEqual(stageCountChip(2, data, settled), {})
  assert.equal(stageCountSummary(2, data, settled), '')
  // 耗时函数同域：WAF 段耗时按 stage3 取，调用方不再做 3→4 映射
  assert.equal(stageTimingChip(3, counts({ waf_avg_us: 400 })), '平均耗时 0.400ms')
  assert.equal(stageAvgDurationUs(3, counts({ waf_avg_us: 400 })), 400)
})

test('阶段号域：流程弹框与统计单源都不再出现 stage4 旧编号', () => {
  const stats = code('src/utils/ruleStageStats.ts')
  assert.doesNotMatch(stats, /1 \| 4|stage === 4|stage: 1 \| 2 \| 3 \| 4|0 \| 1 \| 2 \| 3 \| 4/, 'ruleStageStats 不得保留 stage4 阶段号域')
  const dialog = code('src/components/RuleFlowDialog.vue')
  assert.doesNotMatch(dialog, /stageTimingLabel\(4\)|1 \| 4|0 \| 1 \| 2 \| 3 \| 4/, 'RuleFlowDialog 不得再做 3→4 阶段号映射')
})

// 跨栈机械钉：前端类型键集必须与后端 stage-stats 响应体键集完全一致。后端新增/
// 改名桶而前端未同步（如 stage_unattributed_24h 长期缺席）、或前端凭空造键，都会
// 在此变红——这是「后端有钉、前端无对表」缺口的封堵。
test('stage-stats 键集：前端类型与后端响应体逐键一致', () => {
  const go = repoCode('internal/handlers/security_overview.go')
  const start = go.indexOf('"stage1_blocked_24h"')
  assert.ok(start >= 0, '后端响应体必须含 stage1_blocked_24h')
  const block = go.slice(start, go.indexOf('}})', start))
  const backendKeys = [...block.matchAll(/"([a-z0-9_]+)":/g)].map((m) => m[1]!)
  assert.ok(backendKeys.length >= 7, `后端键集解析异常（${backendKeys.length} 个）`)

  const front = code('src/utils/ruleStageStats.ts')
  const ifaceStart = front.indexOf('export interface RuleStageCounts {')
  assert.ok(ifaceStart >= 0, '前端类型必须存在')
  const iface = front.slice(ifaceStart, front.indexOf('\n}', ifaceStart))
  const frontendKeys = [...iface.matchAll(/^\s{2}([a-z0-9_]+)(?:\?)?:/gm)].map((m) => m[1]!)
  assert.ok(frontendKeys.length >= 7, `前端键集解析异常（${frontendKeys.length} 个）`)

  assert.deepEqual([...frontendKeys].sort(), [...backendKeys].sort(), '前端 type 键集与后端 stage-stats 响应键集不一致')
  assert.ok(frontendKeys.includes('stage_unattributed_24h'), '未归因桶必须在前端类型中')
})
