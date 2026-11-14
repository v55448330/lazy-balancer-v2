// 阶段 3 摘要的 CRS 组数必须按归一后长度计数：历史文件名前缀、重复值、
// 系统基础组（01/49/59）不得 inflate 组数——否则同一策略在编辑器与详情里
// 的组数口径分叉。JSON 字符串与数组两种库值形态同口径。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildStageModel, type SecurityStageBinding, type SecurityStagePolicy } from '../src/utils/securityStages.ts'
import { tSafe } from '../src/i18n/tSafe.ts'
const binding = (id = 1) => ({ policy_id: id, name: 'p', enabled: true, rank: 1, mode: 'blocking' } as unknown as SecurityStageBinding)
const policy = (groups: string | string[]) => ({ id: 1, name: 'p', mode: 'blocking', policy_type: 'stage3', crs_rule_groups: groups } as unknown as SecurityStagePolicy)
test('阶段 3 CRS 组数按归一后长度计数（历史文件名/重复/基础组不 inflate）', () => {
  const raw = JSON.stringify(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf', '42', '42', '01', '93'])
  const rows = buildStageModel([binding()], [policy(raw)], [], []).stages[3].groups[0]?.rows ?? []
  const crsRow = rows.find((r) => r.label === tSafe('common.app.views.stages.crsGroupsRowLabel'))
  assert.ok(crsRow)
  assert.equal(crsRow!.detail, tSafe('common.app.views.stages.crsGroupsCount', { count: 2 }))
})
test('数组形态同样归一（含基础设施组剥离）', () => {
  const rows = buildStageModel([binding()], [policy(['49', '59', '942100'])], [], []).stages[3].groups[0]?.rows ?? []
  const crsRow = rows.find((r) => r.label === tSafe('common.app.views.stages.crsGroupsRowLabel'))
  assert.equal(crsRow!.detail, tSafe('common.app.views.stages.crsGroupsCount', { count: 1 }))
})
