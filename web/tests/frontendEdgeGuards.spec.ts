// 前端边界守卫：
//   - 展示层普通对象查表必须先 hasOwn（原型链键不得渲染为函数/绕过兜底）；
//   - IP 名单查询是只读操作，成功提示不得走 MFA 宽限提示；
//   - 过滤态删除映射缺失时下标为 -1，splice(-1) 会误删末条。
//
// 运行：cd web && node --test tests/frontendEdgeGuards.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

test('TaskMonitor 标签查表前 hasOwn 守卫（constructor/toString 等原型键不得命中）', () => {
  const tm = code('src/views/settings/TaskMonitor.vue')
  assert.match(member(tm, 'const taskDesc ='), /hasOwn\(TASK_NAME_KEYS,/, 'taskDesc 必须先 hasOwn')
  assert.match(member(tm, 'const taskDisplayName ='), /hasOwn\(TASK_NAME_KEYS,/, 'taskDisplayName 必须先 hasOwn')
  assert.match(member(tm, 'const categoryLabel ='), /hasOwn\(keys,/, 'categoryLabel 必须先 hasOwn')
})

test('IP 名单查询成功提示走 ElMessage.success（只读查询不走 MFA 宽限提示）', () => {
  const sec = code('src/views/security/SecurityRules.vue')
  const fn = member(sec, 'const applyIpListQuery =')
  assert.match(fn, /ElMessage\.success\(/, '查询成功提示必须为普通成功提示')
  assert.doesNotMatch(fn, /mfaAwareSuccess/, '只读查询不得消费 MFA 宽限提示')
})

test('removeIpListEntry 收到 -1 越界下标直接返回（不得 splice 末条）', () => {
  const sec = code('src/views/security/SecurityRules.vue')
  const fn = member(sec, 'const removeIpListEntry =')
  assert.match(fn, /if \(index < 0\) return/, '负下标必须早退')
})
