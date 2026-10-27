// 展示词表的原型链安全：`Record<string, …>` 字面量 + 外部字符串键（库值/后端枚举）
// 的裸下标会把 Object.prototype 上的 constructor / toString / __proto__ 当成命中，
// 返回原生函数——`??`/`||` 兜底被绕过：标签列渲染出函数源码，或把「无值」判成
// 「有值」。这类键只能由带外改库产生（UI 表单不给这些值），但展示层不该因此崩形态。
//
// 本文件两件事：
//   1) 行为：hasOwn 与裸下标的差异（含多行三元形态）；
//   2) 扫描：安全三张视图里所有 `const NAME: Record<…> = {…}` 展示词表的读取点
//      必须过 hasOwn——新增词表自动纳入，词表读点被改回裸下标即变红。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { hasOwn } from '../src/utils/hasOwn.ts'
import { code } from './_helpers.ts'

const SECURITY_FILES = [
  'src/views/security/SecurityPolicies.vue',
  'src/views/security/SecurityRules.vue',
  'src/components/events/TriggerDetailDialog.vue',
]

// 违规读点 = 出现 `NAME[` 且「前两行 + 本行」内没有 `hasOwn(NAME,` 的行下标。
// 涵盖单行三元与换行三元（`hasOwn(T, k)` 在条件行、`T[k]` 在结果行）两种写法。
const unguardedReads = (lines: readonly string[], name: string): number[] =>
  lines.flatMap((line, index) => {
    if (!line.includes(`${name}[`) || line.includes(`const ${name}:`)) return []
    const context = [lines[index - 2] ?? '', lines[index - 1] ?? '', line].join('\n')
    return context.includes(`hasOwn(${name}`) ? [] : [index]
  })

test('原型键：裸下标返回函数，hasOwn 判定为无值', () => {
  const labels: Record<string, string> = { deny: '拒绝' }
  // 裸下标：命中原型链 → 返回函数（真值），`?? '默认'` 兜底失效
  assert.equal(typeof labels['constructor'], 'function', '裸下标命中原型链（这就是要防的形态）')
  assert.equal(hasOwn(labels, 'constructor'), false, 'hasOwn 不把原型键当自有键')
  assert.equal(hasOwn(labels, '__proto__'), false)
  assert.equal(hasOwn(labels, 'toString'), false)
  assert.equal(hasOwn(labels, 'deny'), true, '自有键仍命中')
})

test('判据自检：裸下标被抓、单行/换行三元放行', () => {
  assert.deepEqual(unguardedReads(['const x = T[key] ?? fallback'], 'T'), [0], '裸下标必须被抓')
  assert.deepEqual(unguardedReads(['const x = hasOwn(T, key) ? T[key] : fallback'], 'T'), [], '单行三元放行')
  assert.deepEqual(
    unguardedReads(['const x = (hasOwn(T, key)', '  ? T[key]', "  : '—')"], 'T'),
    [],
    '换行三元（条件行在上一行）放行',
  )
  assert.deepEqual(unguardedReads(['const T: Record<string, string> = {}'], 'T'), [], '词表声明本身不算读点')
})

test('安全三张视图的展示词表读取全部过 hasOwn', () => {
  const tables: Array<{ file: string; name: string }> = []
  for (const file of SECURITY_FILES) {
    for (const match of code(file).matchAll(/^const ([A-Z][A-Z0-9_]*): Record<string, /gm)) {
      tables.push({ file, name: match[1]! })
    }
  }
  // 扫描面下限：ACL 标签/ACL 提示/地域模式词表 + 动作视图/条件占位 + 触发详情动作
  assert.ok(tables.length >= 6, `发现的展示词表少于 6（${tables.length}）——发现规则失效`)

  const offenders: string[] = []
  for (const { file, name } of tables) {
    const lines = code(file).split('\n')
    for (const index of unguardedReads(lines, name)) offenders.push(`${file}:${index + 1} ${name}`)
    const reads = lines.filter((line) => line.includes(`${name}[`) && !line.includes(`const ${name}:`)).length
    assert.ok(reads > 0, `${file}：${name} 无读取点——死词表要么删掉，要么接上消费面`)
  }
  assert.deepEqual(offenders, [], '展示词表读取未过 hasOwn：原型键命中原生函数，兜底与标签展示同时失真')
})
