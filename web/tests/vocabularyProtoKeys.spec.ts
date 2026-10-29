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
  // 设置页标题投影：仅展开进 pageTitle，不直接以下标消费
  'src/components/layout/AppLayout.vue#settingsPageTitles',
  // HTML 转义表：固定正则字符集键，不是库值/后端枚举
  'src/utils/escape.ts#escapeHtmlTable',
  // 表格锁弹框登记表：键为规则 caddy_id，值是组件实例，不用于标签展示
  'src/views/Rules.vue#lockPopovers',
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

// 无显式 Record 注解、但键来自外部状态的展示词表：显式登记纳入同一扫描。
const UNANNOTATED_VOCABULARY_TABLES = [
  'src/utils/certJobStatus.ts#CERT_JOB_STATUS_LABELS',
] as const

// 词表读点计数（`NAME[` 出现在非声明行）。
// `owner` 非空时只统计该文件：同名 Record 表分布在多个模块时，按名全仓计数会把
// B 文件的读取算给 A 文件的死表（`reads > 0` 恒真）；不传 owner = 全仓口径（
// 词表被别的模块合法消费，如 chartTheme.statusColor 只在消费方读取）。
const tableReads = (textByFile: ReadonlyMap<string, string>, name: string, owner?: string): number => {
  let reads = 0
  for (const [file, text] of textByFile) {
    if (owner !== undefined && file !== owner) continue
    for (const line of text.split('\n')) {
      if (line.includes(`${name}[`) && !line.includes(`const ${name}:`)) reads += 1
    }
  }
  return reads
}

// 仅换行三元的 `? NAME[k]` 可向上一行借守卫；相邻独立语句不得互相借守卫。
const unguardedReads = (lines: readonly string[], name: string): number[] =>
  lines.flatMap((line, index) => {
    if (!new RegExp(`(?<![\\w$])${name}\\[`).test(line) || line.includes(`const ${name}:`)) return []
    const context = line.trimStart().startsWith('?') ? `${lines[index - 1] ?? ''}\n${line}` : line
    return new RegExp(`hasOwn\\(\\s*${name}\\s*,|hasOwnProperty\\.call\\(\\s*${name}\\s*,`).test(context) ? [] : [index]
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
  assert.deepEqual(
    unguardedReads(['const a = hasOwn(T, k) ? T[k] : 0', 'const b = T[m]'], 'T'),
    [1],
    '前一条语句的守卫不得遮蔽下一条裸读',
  )
})

test('判据自检：同名词表的读取不得跨文件互相救活（死表必红）', () => {
  const sources = new Map([
    ['src/utils/a.ts', "const statusLabels: Record<string, string> = { deny: '拒绝' }"],
    ['src/views/B.vue', "const statusLabels: Record<string, string> = { allow: '放行' }\nconst label = statusLabels[key] ?? '—'"],
  ])
  assert.equal(tableReads(sources, 'statusLabels'), 1, '全仓计数会把 B 的读取算给 A 的死表（这就是要防的假绿）')
  assert.equal(tableReads(sources, 'statusLabels', 'src/utils/a.ts'), 0, '重名时只看所属文件：A 的死表必须报 0')
  assert.equal(tableReads(sources, 'statusLabels', 'src/views/B.vue'), 1, '真有读点的表仍计 1')
  // 声明行本身不算读点（否则任何词表都恒 live）
  assert.equal(tableReads(new Map([['a.ts', 'const T: Record<string, string> = {}']]), 'T'), 0)
})

test('全仓 Record<string, …> 表：展示词表读取全部过 hasOwn（目录扫描）', () => {
  const files = webFiles('src', ['.ts', '.vue'])
  assert.ok(files.length >= 150, `扫描面过小（${files.length} 个文件）——目录枚举失效`)
  const tables: Array<{ key: string; file: string; name: string }> = []
  for (const file of files) {
    for (const match of code(file).matchAll(/^(?:export )?const ([A-Za-z_$][\w$]*): Record<string, /gm)) {
      tables.push({ key: `${file}#${match[1]}`, file, name: match[1]! })
    }
  }
  for (const registered of UNANNOTATED_VOCABULARY_TABLES) {
    if (tables.some((table) => table.key === registered)) continue
    const [file, name] = registered.split('#')
    tables.push({ key: registered, file: file!, name: name! })
  }
  // 扫描面下限：显式 Record 注解表全集 + 登记的无注解词表。
  assert.ok(tables.length >= 20, `发现的 Record 表少于 20（${tables.length}）——发现规则失效`)
  for (const registered of NON_VOCABULARY_RECORD_TABLES) {
    assert.ok(tables.some((table) => table.key === registered), `登记的非词表已不存在：${registered}`)
  }

  const strippedByFile = new Map(files.map((file) => [file, code(file)]))
  // 重名表（同名 Record 表出现在多个文件）的读点只能算进各自的文件。
  const filesDeclaringName = new Map<string, Set<string>>()
  for (const table of tables) {
    const owners = filesDeclaringName.get(table.name) ?? new Set<string>()
    owners.add(table.file)
    filesDeclaringName.set(table.name, owners)
  }
  const offenders: string[] = []
  for (const { key, name, file } of tables) {
    if ((NON_VOCABULARY_RECORD_TABLES as readonly string[]).includes(key)) continue
    const shared = (filesDeclaringName.get(name)?.size ?? 0) > 1
    assert.ok(tableReads(strippedByFile, name, shared ? file : undefined) > 0, `${key} 无读取点——死词表要么删掉，要么接上消费面`)
    for (const [owner, stripped] of strippedByFile) {
      for (const index of unguardedReads(stripped.split('\n'), name)) offenders.push(`${owner}:${index + 1} ${name}`)
    }
  }
  assert.deepEqual(offenders, [], '展示词表读取未过 hasOwn：原型键命中原生函数，兜底与标签展示同时失真')
})
