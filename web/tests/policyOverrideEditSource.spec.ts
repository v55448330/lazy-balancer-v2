// 「拦截页」步骤的归因必须读**本会话暂存编辑**，而不是库值。
//
// 同一次向导会话里，规则级阶段拦截页覆盖被改选后处于「待保存」：关联规则步骤
// 显示「待保存」、保存载荷按暂存值提交。若拦截页步骤的归因仍读 allRules 的库值，
// 同一次会话里两步会给出相反结论（关联规则说待保存，本步仍说「规则已配置阶段页
// 覆盖」），用户据此会改错策略页。归因算法本身的正确性由 blockPageAttribution
// 的行为用例承担；本条只钉它的输入来源与三步同源。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），该读取
// 路径在组件 computed 内——用「限段 + 单源」文本钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

const POLICIES = 'src/views/security/SecurityPolicies.vue'

test('归因输入取 overrideEditOf（seed=库值 + 本会话编辑），不读库值直查', () => {
  const text = code(POLICIES)
  const notes = member(text, 'const blockPageNotes = (caddyId: string, chain: ChainEntry[]): BlockPageNote[] =>')
  const overrideFor = section(notes, 'const overrideFor = (stage: 1 | 3)', '\n  }')
  assert.match(overrideFor, /const edit = overrideEditOf\(caddyId\)/, '覆盖值必须走暂存视图')
  assert.match(overrideFor, /stage === 1 \? edit\.stage1_id : edit\.stage3_id/, '两阶段分别取暂存字段')
  assert.doesNotMatch(overrideFor, /allRules\.value\.find/, '不得在归因里直查库值（会让同会话两步结论相反）')
  assert.doesNotMatch(overrideFor, /block_page_stage[13]_id/, '不得直接读库字段（绕开暂存）')
})

test('overrideEditOf 是唯一读路径：库值回退在它内部完成', () => {
  const text = code(POLICIES)
  const reader = section(text, 'const overrideEditOf = (caddyId: string): StageOverrideEdit =>', '\nconst ')
  assert.match(reader, /stageOverrideEdits\.value\[caddyId\] \?\? stageOverrideSeed\(caddyId\)/, '读路径=暂存值 ?? 库值 seed')
  // 消费面同源三处：关联规则步骤（模板）、保存载荷、拦截页归因
  assert.match(text, /:model-value="overrideEditOf\(row\.caddyId\)\[stage === 1 \? 'stage1_id' : 'stage3_id'\]"/, '关联规则步骤读同一函数')
  const payload = section(text, 'const pendingOverrideRules = computed', 'const originalBoundRules')
  assert.match(payload, /edit: overrideEditOf\(caddyId\), seed: stageOverrideSeed\(caddyId\)/, '保存载荷读同一函数')
})
