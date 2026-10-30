// 规则编辑的乐观并发前置条件 + 规则日志「实时统计」窗口口径。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { member, code, stripComments } from './_helpers.ts'

const page = code('src/views/Rules.vue')
const types = code('src/types/rules.ts')

test('编辑向导记录打开时的 updated_at 并随保存回传 expected_updated_at', () => {
  assert.match(page, /const editingRuleVersion = ref\(''\)/)
  assert.match(page, /editingRuleVersion\.value = fullRule\.updated_at \|\| ''/)
  assert.match(page, /expected_updated_at: editingRuleVersion\.value/)
  assert.match(types, /expected_updated_at\?: string/)
})

test('版本冲突（409）刷新列表并提示重新打开，不静默覆盖', () => {
  assert.match(page, /error instanceof ApiRequestError && error\.status === 409/)
  assert.match(page, /规则已被他人修改/)
  // 边界硬失败：marker 缺失时 indexOf 返回 -1，slice(-1) 会退化成文件末字符、
  // 断言自动变宽仍绿（本用例要守的「409 刷新列表」失守也不会红）。
  const catchMarker = "console.error('submit wizard failed'"
  const catchIdx = page.indexOf(catchMarker)
  assert.ok(catchIdx > 0, `catch 起点 marker 缺失: ${catchMarker}`)
  const conflictIdx = page.indexOf('error instanceof ApiRequestError && error.status === 409')
  assert.ok(conflictIdx > 0 && conflictIdx < catchIdx, '409 分支必须位于提交失败 catch 之前')
  const conflict = page.slice(conflictIdx, catchIdx)
  assert.match(conflict, /fetchRules\(/)
})

test('实时统计先灌最近 ≤1000 行历史，再从 EOF 增量叠加（2026-10-30 用户裁定）', () => {
  // 结构边界：花括号配对取函数体（下一条函数声明作终点会让后插的语句落进
  // 切片，断言可能被相邻函数满足）。
  const body = stripComments(member(page, 'const startLogStats = async'))
  // 起始路径必须消费 tail 历史（含 ≤1000 行）并推进到 EOF；增量流从 EOF 接续零重叠。
  assert.match(body, /consumeLogLinesChunked\(/)
  assert.match(body, /logStatsOffset\.value = res\.data\?\.offset \?\? 0/)
  // 历史行时间戳解析（started_at 取首行 ts）
  assert.match(body, /parseLogLineTimestamp\(/)
})
