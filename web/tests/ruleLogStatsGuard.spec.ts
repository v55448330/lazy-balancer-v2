// 日志统计守卫契约（回归钉）：统计 tab 的「本轮判定」收敛为 seq 单源——
// maps 恒等比较曾与 seq 双重判定互相误判，导致 offset 滞留 0 → 下一 tick
// 全量重灌历史（统计慢/卡在正在统计）；两请求带 8s 超时兜底防无限骨架。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { codeSection } from './_helpers.ts'

const STATS_SECTION_START = 'const fetchLogStream = async () => {'
const STATS_SECTION_END = 'const onRuleLogDialogOpened = () => {'

const statsCode = () => codeSection('src/views/Rules.vue', STATS_SECTION_START, STATS_SECTION_END)

test('统计守卫不得再比较 logStatsMaps 恒等（seq 单源）', () => {
  const code = statsCode()
  assert.ok(code.includes('const fetchLogStream'), '锚点缺失：fetchLogStream 不在切片内（守卫空转）')
  assert.ok(!code.includes('logStatsMaps.value !=='), 'stats 守卫不得比较 logStatsMaps 恒等——与 seq 双重判定会误判丢 offset')
})

test('/logs 与 log-stream 请求必须带 8s 超时兜底（防无限「正在统计」）', () => {
  const code = statsCode()
  const timeoutCount = (code.match(/timeout: 8000/g) || []).length
  assert.ok(timeoutCount >= 2, `统计两请求（/logs、log-stream）应各带 timeout: 8000，实见 ${timeoutCount} 处`)
})

test('startLogStats 激活去重：加载中的重复激活直接合并', () => {
  const code = statsCode()
  assert.ok(code.includes('if (ruleLogStatsLoading.value) return'), 'startLogStats 缺少加载期去重早退')
  // 去重必须先于 maps/offset 重置（否则第二次激活仍会把 offset 打回 0）
  const dedupeAt = code.indexOf('if (ruleLogStatsLoading.value) return')
  const offsetResetAt = code.indexOf('logStatsOffset.value = 0')
  assert.ok(dedupeAt > 0 && offsetResetAt > dedupeAt, '激活去重早退必须位于 offset 重置之前')
})
