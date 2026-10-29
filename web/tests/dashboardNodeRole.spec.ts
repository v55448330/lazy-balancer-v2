// 系统概览页的一致性 tag 在「节点角色未知」窗口必须 fail-closed：nodeMode 为
// null（/config 首拉失败或 15s 重试期内）时 configConsistent 不构成证据，展示层
// 不得宣告「配置正常」。分支顺序（从节点 → 角色未知 → 配置正常/异常）由源码钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, code } from './_helpers.ts'

const dashboard = code('src/views/Dashboard.vue')

test('角色未知分支位于配置正常/异常之前，且文案与 tag 形态复用既有样式', () => {
  const chain = section(dashboard, 'v-if="authStore.isSlaveNode"', 'configConsistent === \'false\'')
  const unknownAt = chain.indexOf("nodeModeRole === 'unknown'")
  const consistentAt = chain.indexOf("configConsistent === 'true'")
  assert.ok(unknownAt > 0, '缺少 nodeModeRole === \'unknown\' 分支')
  assert.ok(consistentAt > unknownAt, '角色未知分支必须在「配置正常」之前（否则未知窗口仍显示配置正常）')
  const unknownBranch = chain.slice(unknownAt, consistentAt)
  assert.match(unknownBranch, /角色未知/)
  assert.match(unknownBranch, /<el-tag type="info" size="small" effect="plain">/)
})

test('三态节点角色派生单源：判据在 utils/nodeRole，视图只消费', () => {
  // 判据本身由 nodeRole.spec.ts 的四态行为用例钉住（方向+文案+tag 色）。
  // 此前这里钉「=== 'master' / === 'slave' 出现过」——两支互换仍绿。
  assert.match(dashboard, /const nodeRoleView = computed\(\(\) => resolveNodeRole\(authStore\.nodeMode\)\)/, '视图必须消费单源派生')
  assert.match(dashboard, /const nodeModeRole = computed\(\(\) => nodeRoleView\.value\.role\)/)
  assert.match(dashboard, /const nodeModeLabel = computed\(\(\) => nodeRoleView\.value\.label\)/)
  assert.match(dashboard, /const nodeModeTagType = computed\(\(\) => nodeRoleView\.value\.tagType\)/)
  assert.doesNotMatch(dashboard, /nodeMode === 'master'/, '判据不得回流到视图（第二份口径）')
  assert.match(dashboard, /:type="nodeModeTagType"/, '模板必须消费派生 tag 类型')
  // 文案/tag 方向由 nodeRole.spec.ts 的四态期望钉住；视图里不得再出现第二份
  // '主节点'/'从节点' 文案映射（写在这里就会与单源分叉）。
  assert.doesNotMatch(dashboard, /nodeModeRole\.value === 'master'/, '视图不得按角色值再派生一次')
  assert.doesNotMatch(dashboard, /isSlave \? 'warning' : 'success'/, '二态表达式必须退役')
})
