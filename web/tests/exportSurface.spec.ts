// 导出面 ≤ 消费面门禁：定义目录里的具名导出必须存在「定义文件之外」的消费方，
// 否则它就是模块内私有物（export 会让读者误以为它是跨模块稳定契约，进而绕开
// 单源直接构造内部形状）。
//
// 为什么落成门禁：这类残留反复出现——人工 grep 收口每次都能收敛一部分却从未
// 归零，而且新增文件（如本单元的动作映射单源）本身就会又一次带出同族导出。
// 判据机械化后，新增残留会在测试门禁上直接失败。
//
// 口径（与全仓 grep 的消费面扫描一致）：
// - 定义面 = src/utils、src/composables、src/stores、src/types 下的 .ts/.vue；
// - 消费面 = src/**.ts/.vue + tests/**.ts（含用例对符号的按名引用）；
// - 定义面走注释剥离视图：注释掉的 export 不算符号；消费面走「标识符扫描」
//   视图：注释与字符串/模板/正则字面量里的符号名都不算消费——测试用源码切片
//   marker（`section(code('x'), 'const foo = ' …)`）或正则断言提到某个名字，
//   并不会让它变成跨模块契约（否则死导出永远留在门槛内）。模板 `${…}` 插值
//   里的标识符仍是代码，照常计入；
// - 同名符号跨模块冲突时，任一文件的消费都会算作命中——本门禁是下限，不做
//   逐模块消歧。
//
// 无需白名单：`Pick<>`/`Omit<>`/`typeof` 等跨文件引用本身就带符号名，自然计入
// 消费面；真正零消费的导出只应改为模块私有（确需跨模块时先有消费方）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, webFiles } from './_helpers.ts'

const DEFINITION_DIRS = ['src/utils', 'src/composables', 'src/stores', 'src/types'] as const
const SOURCE_EXTENSIONS = ['.ts', '.vue'] as const

// `export const X` / `export async function X` / `export declare const X` …；
// `export default` 与 `export * from` 不是具名导出，不参与判定。
const DECLARATION = /^export\s+(?:(?:declare|abstract)\s+)*(?:(?:async)\s+)?(?:const|let|var|function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/
// `export { a, b as c }` / `export type { A }`：导出名取 `as` 右侧。块可跨多行
// （Prettier 会把长列表换行）——`g` 全扫 + `[\s\S]` 跨行，单行形态是其特例。
const NAMED_EXPORT = /^export\s+(?:type\s+)?\{([\s\S]*?)\}/gm

/** 源文件里的具名导出名（声明行 + `export { … }` 块，含多行形态与 `as` 别名）。 */
const exportedNames = (text: string): string[] => {
  const names: string[] = []
  for (const line of text.split('\n')) {
    const declaration = DECLARATION.exec(line)
    if (declaration) names.push(declaration[1])
  }
  for (const named of text.matchAll(NAMED_EXPORT)) {
    for (const part of named[1].split(',')) {
      const exported = part.trim().split(/\s+as\s+/).pop()?.trim()
      if (exported) names.push(exported)
    }
  }
  return names
}

/** 正则字面量可能出现的上一个有效字符（表达式位置的运算符/开括号/逗号等）。
 * 刻意不含 `<`/`>`：Vue 模板的闭合标签（`</el-option>`）会让 `<` 后的正斜杠被
 * 误判成正则起点，一路吞到下一个 `/` —— 整段模板与脚本的标识符消失（假绿）。 */
const REGEX_PRECEDER_CHARS = '([{,;:=!&|?+-*%^'
/** 关键字之后的正斜杠是正则字面量起点而不是除号。 */
const REGEX_KEYWORDS: Record<string, true> = {
  return: true,
  typeof: true,
  instanceof: true,
  in: true,
  of: true,
  new: true,
  delete: true,
  void: true,
  case: true,
  do: true,
  else: true,
  yield: true,
  await: true,
  throw: true,
}

/**
 * 扫过一段代码，收集「不在字符串/模板/正则字面量里」的标识符。
 * `stopAtBrace` 供模板 `${ … }` 插值递归使用（返回时 next 指向 `}` 之后）。
 *
 * 为什么需要它：`code()` 只剥注释，测试里用源码切片 marker（`section(code('x'), 'const foo = ' …)`）
 * 与正则断言（`assert.match(src, /rules: Entry\[\]/)`）中的符号名会被当成「消费方」，
 * 死导出因此永远留在门槛内。字符串里的名字不是消费——消费是代码里的标识符引用。
 */
const scanIdentifiers = (text: string, from: number, stopAtBrace: boolean): { tokens: string[]; next: number } => {
  const tokens: string[] = []
  let i = from
  let lastSignificant = ''
  let lastWord = ''
  while (i < text.length) {
    const ch = text[i]
    if (stopAtBrace && ch === '}') return { tokens, next: i + 1 }
    if (/[A-Za-z_$]/.test(ch)) {
      const start = i
      while (i < text.length && /[\w$]/.test(text[i])) i++
      lastWord = text.slice(start, i)
      tokens.push(lastWord)
      lastSignificant = 'a' // 标识符/数字收尾：后续 `/` 是除号
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const literal = skipLiteral(text, i)
      tokens.push(...literal.interpolated)
      i = literal.next
      lastSignificant = 'v'
      lastWord = ''
      continue
    }
    if (ch === '/' && (lastSignificant === '' || REGEX_PRECEDER_CHARS.includes(lastSignificant) || REGEX_KEYWORDS[lastWord] === true)) {
      i = skipRegex(text, i)
      lastSignificant = 'v'
      lastWord = ''
      continue
    }
    if (!/\s/.test(ch)) {
      lastSignificant = ch
      lastWord = ''
    }
    i++
  }
  return { tokens, next: i }
}

/** 跳过 `'…'`/`"…"`/`` `…` ``；模板插值 `${ … }` 内部的标识符仍是代码。 */
const skipLiteral = (text: string, start: number): { next: number; interpolated: string[] } => {
  const quote = text[start]
  const interpolated: string[] = []
  let i = start + 1
  while (i < text.length) {
    const ch = text[i]
    if (ch === '\\') {
      i += 2
      continue
    }
    if (ch === quote) return { next: i + 1, interpolated }
    if (quote === '`' && ch === '$' && text[i + 1] === '{') {
      const inner = scanIdentifiers(text, i + 2, true)
      interpolated.push(...inner.tokens)
      i = inner.next
      continue
    }
    i++
  }
  return { next: i, interpolated }
}

/** 跳过 `/…/flags`（字符类内的 `/` 不结束字面量）。 */
const skipRegex = (text: string, start: number): number => {
  let i = start + 1
  let inClass = false
  while (i < text.length) {
    const ch = text[i]
    if (ch === '\\') {
      i += 2
      continue
    }
    if (ch === '[') inClass = true
    else if (ch === ']') inClass = false
    else if (ch === '/' && !inClass) return i + 1
    i++
  }
  return i
}

/** 源文本表（文件名 → 注释剥离后的视图）→ 消费面 token 索引。 */
const indexSources = (sources: ReadonlyMap<string, string>): Map<string, Set<string>> => {
  const index = new Map<string, Set<string>>()
  for (const [file, text] of sources) {
    for (const token of scanIdentifiers(text, 0, false).tokens) {
      const holders = index.get(token)
      if (holders) holders.add(file)
      else index.set(token, new Set([file]))
    }
  }
  return index
}

/**
 * 零外部消费的导出清单。`definitions` = 文件名 → 注释剥离视图（便于用合成源码
 * 直接验证判据）；`tokenIndex` = 消费面的 token 索引。
 */
const findUnusedExports = (
  definitions: ReadonlyMap<string, string>,
  tokenIndex: ReadonlyMap<string, ReadonlySet<string>>,
): { checked: number; unused: string[] } => {
  const unused: string[] = []
  let checked = 0
  for (const [file, text] of definitions) {
    for (const name of exportedNames(text)) {
      checked++
      const holders = tokenIndex.get(name)
      const consumedOutside = holders !== undefined
        && [...holders].some((holder) => holder !== file)
      if (!consumedOutside) unused.push(`${file} → ${name}`)
    }
  }
  return { checked, unused }
}

const definitionFiles = DEFINITION_DIRS.flatMap((dir) => webFiles(dir, SOURCE_EXTENSIONS))
const definitionSources = new Map(definitionFiles.map((file) => [file, code(file)] as const))
const consumerFiles = [...webFiles('src', SOURCE_EXTENSIONS), ...webFiles('tests', ['.ts'])]

// 测试基建（`tests/_helpers.ts` / `_stubs.ts`）的导出口径与 src 相同：具名导出必须
// 有本文件之外的消费方。src 侧残留（如 ADAPTIVE_SAMPLE_TIERS）由上面的门禁自动
// 拦下，tests 侧此前零门禁——helper 失去消费方后只会无声膨胀。
const TEST_INFRA_FILES = ['tests/_helpers.ts', 'tests/_stubs.ts'] as const
const testInfraSources = new Map(TEST_INFRA_FILES.map((file) => [file, code(file)] as const))

/** 消费面 token 索引（src + tests 全量扫描，两次调用共用同一份结果）。 */
let consumerTokenIndex: Map<string, Set<string>> | null = null
const indexConsumers = (): Map<string, Set<string>> => {
  consumerTokenIndex ??= indexSources(new Map(consumerFiles.map((file) => [file, code(file)] as const)))
  return consumerTokenIndex
}

test('定义目录的每个具名导出都有定义文件之外的消费方', () => {
  const { checked, unused } = findUnusedExports(definitionSources, indexConsumers())
  // 扫描面自检：解析器失效（正则不再匹配）会让清单恒空——那是最容易发生的假绿。
  assert.ok(definitionFiles.length >= 100, `定义面文件数异常偏少（${definitionFiles.length}），扫描目录配置已失效`)
  assert.ok(checked >= 400, `解析到的具名导出异常偏少（${checked}），导出声明正则已失效`)
  assert.deepEqual(
    unused,
    [],
    '零外部消费的导出必须改为模块私有（确需跨模块导出时先落消费方）：\n' + unused.join('\n'),
  )
})

test('测试基建（_helpers/_stubs）的具名导出同样必须有本文件之外的消费方', () => {
  const { checked, unused } = findUnusedExports(testInfraSources, indexConsumers())
  assert.ok(checked >= 25, `测试基建解析到的导出异常偏少（${checked}），导出声明正则已失效`)
  assert.deepEqual(
    unused,
    [],
    '零消费的测试基建导出必须删掉（helper 失去消费方后只会无声膨胀）：\n' + unused.join('\n'),
  )
})

test('判据不是空转：外部消费 / 仅本文件自用 / 无任何引用 三种形态区分得开', () => {
  const definitions = new Map([
    ['src/utils/a.ts', 'export const consumed = 1\nexport const selfOnly = 2\nexport const orphan = 3'],
  ])
  const tokenIndex = new Map([
    ['consumed', new Set(['src/utils/a.ts', 'src/views/Use.vue'])],
    ['selfOnly', new Set(['src/utils/a.ts'])],
  ])
  assert.deepEqual(findUnusedExports(definitions, tokenIndex), {
    checked: 3,
    unused: ['src/utils/a.ts → selfOnly', 'src/utils/a.ts → orphan'],
  })
})

test('测试内字符串/正则 marker 不算消费方（按名切片不得给死导出续命）', () => {
  const consumerSources = new Map([
    // 源码存在性钉的两种常见形态：切片 marker 字符串 + 正则断言。
    ['tests/viewsWiringGuards.spec.ts', [
      "const body = section(code('src/utils/restart.ts'), 'const reloadAfterRestart = async', 'export interface RestartServiceOptions')",
      'assert.match(src, /rules: CrsRuleIndexEntry\\[\\]/)',
    ].join('\n')],
    // 真实消费：import 绑定与模板插值里的标识符仍是代码。
    ['tests/realConsumer.spec.ts', [
      "import { realSymbol } from '../src/utils/real.ts'",
      'const label = `${realSymbol}`',
      'const ratio = realSymbol / 2',
    ].join('\n')],
  ])
  const definitions = new Map([
    ['src/utils/restart.ts', [
      'export const reloadAfterRestart = async () => {}',
      'export interface RestartServiceOptions {}',
      'export const realSymbol = 1',
    ].join('\n')],
  ])
  assert.deepEqual(findUnusedExports(definitions, indexSources(consumerSources)), {
    checked: 3,
    unused: ['src/utils/restart.ts → reloadAfterRestart', 'src/utils/restart.ts → RestartServiceOptions'],
  })
})

test('导出名解析覆盖声明形态与 as 别名（正则退化会静默漏检）', () => {
  assert.deepEqual(
    exportedNames([
      'export const a = 1',
      'export async function b() {}',
      'export interface C {}',
      'export type D = string',
      'export declare const e: number',
      'export { f, g as h }',
      'export type { I }',
      '// export const commented = 1',
      'export {',
      '  multilineOne,',
      '  multilineTwo as multilineAlias,',
      '} from "./x"',
      'export type {',
      '  MultilineType,',
      '}',
      'export * from "./y"',
      'export default {}',
    ].join('\n')),
    ['a', 'b', 'C', 'D', 'e', 'f', 'h', 'I', 'multilineOne', 'multilineAlias', 'MultilineType'],
  )
})

test('多行具名导出块同样参与判定（解析不到即静默假绿）', () => {
  const definitions = new Map([
    ['src/utils/multi.ts', [
      'export {',
      '  listedUnused,',
      '} from "./x"',
      'export type {',
      '  typeUnused as typeAliased,',
      '}',
      'export { consumedMulti } from "./y"',
    ].join('\n')],
  ])
  const tokenIndex = new Map([
    ['consumedMulti', new Set(['src/utils/multi.ts', 'src/views/Use.vue'])],
  ])
  assert.deepEqual(findUnusedExports(definitions, tokenIndex), {
    checked: 3,
    unused: ['src/utils/multi.ts → listedUnused', 'src/utils/multi.ts → typeAliased'],
  })
})
