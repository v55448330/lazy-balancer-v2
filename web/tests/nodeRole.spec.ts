// 节点角色三态派生的行为验收（穷举 master / slave / null / undefined）。
//
// 判据此前写在 Dashboard.vue 的 computed 里，用例只能钉「=== 'master' 与
// === 'slave' 出现过」——两支互换、标签互换、tag 色互换都仍然全绿：
// 存在性断言没有方向。抽成 resolveNodeRole 后按四态逐项钉住输出。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { resolveNodeRole } from '../src/utils/nodeRole.ts'

test('主节点：success 色 + 主节点文案', () => {
  assert.deepEqual(resolveNodeRole('master'), { role: 'master', label: '主节点', tagType: 'success' })
})

test('从节点：warning 色 + 从节点文案（不得与主节点同形）', () => {
  assert.deepEqual(resolveNodeRole('slave'), { role: 'slave', label: '从节点', tagType: 'warning' })
})

test('null（/config 首拉失败或重试期）与 undefined（未取到）都归 unknown，且 fail-closed 用 info', () => {
  for (const mode of [null, undefined]) {
    assert.deepEqual(
      resolveNodeRole(mode),
      { role: 'unknown', label: '节点角色未知', tagType: 'info' },
      `${String(mode)} 必须归 unknown`,
    )
  }
})

test('未知态不得被误判为主/从节点（反向覆盖：标签与 tag 色逐一不同）', () => {
  const master = resolveNodeRole('master')
  const slave = resolveNodeRole('slave')
  const unknown = resolveNodeRole('unknown')
  for (const [name, view] of [['主节点', master], ['从节点', slave]] as const) {
    assert.notEqual(unknown.label, view.label, `未知态标签不得与${name}相同`)
    assert.notEqual(unknown.tagType, view.tagType, `未知态 tag 不得与${name}同色`)
  }
  assert.notEqual(master.tagType, slave.tagType, '主/从 tag 色必须可区分')
})
