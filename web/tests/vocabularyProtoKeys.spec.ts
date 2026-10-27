// 展示词表的原型链安全：`Record<string, …>` 字面量 + 外部字符串键（库值/后端枚举）
// 的裸下标会把 Object.prototype 上的 constructor / toString / __proto__ 当成命中，
// 返回原生函数——`??`/`||` 兜底被绕过：标签列渲染出函数源码，或把「无值」判成
// 「有值」。这类键只能由带外改库产生（UI 表单不给这些值），但展示层不该因此崩形态。
//
// 本文件三件事：
//   1) 行为：hasOwn 与裸下标的差异（含多行三元形态）；
//   2) 判据自检（裸下标被抓、单行/换行三元与 hasOwnProperty.call 放行）；
//   3) 扫描：**全仓**（`webFiles('src', …)`）`const NAME: Record<string, …>` 表的
//      读取点必须过 hasOwn——新增词表自动纳入，词表读点被改回裸下标即变红。
//      原实现只硬编码安全三张视图，第四张视图里的词表不会被检查。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { hasOwn } from '../src/utils/hasOwn.ts'
import { code, webFiles } from './_helpers.ts'

// 非展示词表（登记即裁定，附键来源）：键来自内部字面量或归一化数据结构，不是
// 库值/后端枚举，读取点无需 hasOwn。新增条目必须写清键来源；条目失效（表被
// 改名/删除）由登记存在性断言报错。
const NON_VOCABULARY_RECORD_TABLES = [
  // 导航标题：只以字面量页面键读取（页面键集合由 utils/pageIds 单源）
  'src/components/layout/AppLayout.vue#NAV_LABELS',
  // 省界数据表：键为归一化省名，写入循环的别名来自 Object.entries(COUNTRY_ALIAS)
  'src/utils/admin1Provinces.ts#ADMIN1_PROVINCES',
  // 国别名表：只经 Object.entries 消费（自有可枚举键）
  'src/utils/admin1Provinces.ts#COUNTRY_ALIAS',
  // 国家质心数据表：数据读取，主要读取点已过 hasOwn（另有字面量常量键 '中国'）
  'src/utils/countryCentroids.ts#COUNTRY_CENTROIDS',
  // 策略图标：键为后端策略枚举，读取点自带 ?? 兜底
  'src/views/Rules.vue#STRATEGY_ICONS',
] as const

// 违规读点 = 出现 `NAME[` 且「前两行 + 本行」内没有自有属性判定。
// 涵盖单行三元、换行三元（判定在条件行、`T[k]` 在结果行）与
// `Object.prototype.hasOwnProperty.call(T, k)` 三种写法。
const hasOwnGuard = (context: string, name: string): boolean =>
  context.includes(`hasOwn(${name}`) || context.includes(`hasOwnProperty.call(${name}`)

const unguardedReads = (lines: readonly string[], name: string): number[] =>
  lines.flatMap((line, index) => {
    if (!line.includes(`${name}[`) || line.includes(`const ${name}:`)) return []
    const context = [lines[index - 2] ?? '', lines[index - 1] ?? '', line].join('\n')
    return hasOwnGuard(context, name) ? [] : [index]
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
  // 词表用 Object.prototype.hasOwnProperty.call 判定同样合法（oidcCallback 即此形态）
  assert.deepEqual(
    unguardedReads(["  return Object.prototype.hasOwnProperty.call(T, k) ? T[k] : '—'"], 'T'),
    [],
    'hasOwnProperty.call 判定放行',
  )
  // 判的是**本表**：别的表过了 hasOwn 不算
  assert.deepEqual(unguardedReads(['const a = hasOwn(U, k) ? U[k] : 0', 'const b = T[k]'], 'T'), [1], '他表守卫不得串用')
  assert.deepEqual(unguardedReads(['const T: Record<string, string> = {}'], 'T'), [], '词表声明本身不算读点')
})

test('全仓 Record<string, …> 表：展示词表读取全部过 hasOwn（目录扫描）', () => {
  const files = webFiles('src', ['.ts', '.vue'])
  assert.ok(files.length >= 150, `扫描面过小（${files.length} 个文件）——目录枚举失效`)
  const tables: Array<{ key: string; file: string; name: string }> = []
  for (const file of files) {
    for (const match of code(file).matchAll(/^(?:export )?const ([A-Z][A-Z0-9_]*): Record<string, /gm)) {
      tables.push({ key: `${file}#${match[1]}`, file, name: match[1]! })
    }
  }
  // 扫描面下限：本仓现有 15 张（6 张安全展示词表 + 导航/数据/图标表）
  assert.ok(tables.length >= 14, `发现的 Record 表少于 14（${tables.length}）——发现规则失效`)
  // 登记存在性：非词表登记不得悬空（表改名/删除后同步更新登记表）
  for (const registered of NON_VOCABULARY_RECORD_TABLES) {
    assert.ok(tables.some((table) => table.key === registered), `登记的非词表已不存在：${registered}`)
  }

  const offenders: string[] = []
  for (const { key, file, name } of tables) {
    if ((NON_VOCABULARY_RECORD_TABLES as readonly string[]).includes(key)) continue
    const lines = code(file).split('\n')
    for (const index of unguardedReads(lines, name)) offenders.push(`${file}:${index + 1} ${name}`)
    const reads = lines.filter((line) => line.includes(`${name}[`) && !line.includes(`const ${name}:`)).length
    assert.ok(reads > 0, `${key} 无读取点——死词表要么删掉，要么接上消费面`)
  }
  assert.deepEqual(offenders, [], '展示词表读取未过 hasOwn：原型键命中原生函数，兜底与标签展示同时失真')
})
