// 测试侧 helper 单源：源码读取/限段/成员切片 + 假 DOM 宿主 + 模块解析钩子。
// SFC 源码钉 spec 共用 source()/section()/member()，不复刻各自的切片实现——缺
// marker 时 indexOf 返回 -1，切片会变空或倒置、断言空转（假绿）。此处所有边界
// 检查都是硬失败。
//
// 非 spec 文件（不以 .spec.ts 结尾），node --test tests/*.spec.ts 不会把它当用例。
//
// 导入风格约束（隐性 → 显式）：被 node --test 直接 import 的 src 模块链必须
// 使用相对路径 + .ts 扩展名（如 './x.ts'）——node 直跑 TS 无打包器别名/扩展名
// 解析（tsconfig allowImportingTsExtensions 仅为类型层面放行）；仅经打包器
// 消费的模块保持无扩展名风格。

import { readdirSync, readFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { createRenderer } from 'vue'

const webRoot = new URL('../', import.meta.url)

// 源码读取缓存：同一文件（SecurityPolicies.vue / Rules.vue 等）被跨 spec 反复
// 读取数十次；测试只读源文件、无「读取前/后对比」用法，缓存安全。若未来出现
// 「写文件后重读」的用例，须绕开本 helper。
const sourceCache = new Map<string, string>()
const readCached = (url: URL): string => {
  const key = url.href
  const hit = sourceCache.get(key)
  if (hit !== undefined) return hit
  const text = readFileSync(url, 'utf8')
  sourceCache.set(key, text)
  return text
}

/** 读取相对 `web/` 的源文件（如 `'src/views/Rules.vue'`）。 */
export const source = (relative: string): string => readCached(new URL(relative, webRoot))

/** 读取相对仓库根的源文件（跨栈对表读 Go 声明用，如 `'internal/db/db.go'`）。 */
export const repoSource = (relative: string): string => readCached(new URL(`../${relative}`, webRoot))

/**
 * 剥注释视图的源文件读取。**代码存在性**正断言（`assert.match`/`includes` 找
 * 符号、调用、分支）应默认走本函数：注释掉实现是常见的临时手段，raw 视图下
 * 断言仍绿（假绿）。文案/模板文字断言（用户可见字符串）保留 raw。
 *
 * 例外只允许「文档钉」——断言的对象本就是注释文字时，用例名必须显式标注
 * 「文档钉」，避免被误认为行为覆盖。
 */
export const code = (relative: string): string => stripComments(source(relative))

/** 同 code，但读取相对仓库根的路径（跨栈 Go 源码存在性断言用）。 */
export const repoCode = (relative: string): string => stripComments(repoSource(relative))

/**
 * code() 视图的限段读取：先在 raw 文本上按 marker 切片（marker 常是注释分隔
 * 行，剥注释后就找不到），再剥注释。断言落在代码上、边界仍用原始 marker。
 */
export const codeSection = (relative: string, startMarker: string, endMarker: string): string =>
  stripComments(section(source(relative), startMarker, endMarker))

/**
 * 递归列出 `web/` 下某个目录的源文件（返回相对 `web/` 的正斜杠路径）。
 * 「唯一消费方/全仓不得出现」类扫描必须遍历目录而非单文件：单文件判据在
 * 新增消费方时静默失效（扫描面缺口）。
 */
export const webFiles = (relativeDir: string, extensions: readonly string[]): string[] => {
  const base = new URL(relativeDir.endsWith('/') ? relativeDir : `${relativeDir}/`, webRoot)
  const entries = readdirSync(base, { recursive: true, withFileTypes: true }) as Array<{
    name: string
    parentPath: string
    isFile(): boolean
  }>
  const prefix = relativeDir.replace(/\/$/, '')
  return entries
    .filter((entry) => entry.isFile() && extensions.some((ext) => entry.name.endsWith(ext)))
    .map((entry) => {
      const rel = `${entry.parentPath}/${entry.name}`.replace(/\\/g, '/').replace(/\/{2,}/g, '/')
      const at = rel.indexOf(prefix)
      return at >= 0 ? rel.slice(at) : rel
    })
    .sort()
}

/** 注释内出现代码形态仍算「源码里存在」——切片误命中注释会让断言空转。 */
const REGEX_PRECEDING_KEYWORDS: Record<string, true> = {
  return: true, typeof: true, case: true, in: true, of: true, new: true,
  delete: true, void: true, instanceof: true, yield: true, await: true, else: true, do: true,
}

/**
 * 正则字面量只可能出现在这些记号之后（表达式起点的运算符、开括号、分隔符）。
 * 收尾记号（`)`/`]`/`>`/引号）一律不进入正则态——原判据是「前一非空白字符
 * 不是 `)`/`]` 就算正则」，于是 `</div><!-- x -->`、`<br /> <!-- x -->` 里闭合
 * 标签的 `/` 会把该行余下文本吞成「正则」，同行模板注释永不被剥离：注释里
 * 复述代码即假绿（`section()` 从注释中段起切），注释被当代码即误红。
 */
const REGEX_PRECEDING_CHARS: Record<string, true> = {
  '(': true, ',': true, ';': true, ':': true, '=': true, '!': true, '&': true,
  '|': true, '?': true, '+': true, '-': true, '*': true, '%': true, '^': true,
  '~': true, '[': true, '{': true,
}

/**
 * 注释区间（`//`、`/* *\/`、Vue 模板 `<!-- -->`）。
 *
 * 词法判定与 stripComments 同源：跳过字符串与正则字面量，避免把 `'http://…'`
 * 或 `/\/\//` 里的注释记号当真注释。区间用于「只在代码里找 marker」。
 */
const commentSpans = (text: string): Array<readonly [number, number]> => {
  const spans: Array<readonly [number, number]> = []
  let prevSignificant = ''
  let prevWord = ''
  // 箭头函数体（`=> /re/`）：`>` 本身不是正则起点，但紧跟 `=` 的 `>` 是。
  let prevIsArrow = false
  const regexAllowedAfter = (): boolean => {
    if (prevSignificant === '') return true
    if (prevIsArrow) return true
    if (/[\w]/.test(prevSignificant)) return REGEX_PRECEDING_KEYWORDS[prevWord] === true
    return REGEX_PRECEDING_CHARS[prevSignificant] === true
  }
  let i = 0
  while (i < text.length) {
    const ch = text[i]
    const next = text[i + 1]
    if (ch === '/' && next === '/' && text[i - 1] !== ':') {
      // `scheme://host`（模板文案/资源地址里的 URL）不是行注释：JS/TS 里 `:`
      // 后紧跟 `//` 不构成注释起点，却是 URL 的唯一形态。漏了这条守卫，
      // 模板里 `<code>lazy-balancer://docs/…</code>` 会把该行余下文本当注释剥掉。
      const start = i
      while (i < text.length && text[i] !== '\n') i++
      spans.push([start, i])
      continue
    }
    if (ch === '/' && next === '*') {
      const start = i
      i += 2
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++
      i = Math.min(text.length, i + 2)
      spans.push([start, i])
      continue
    }
    if (ch === '<' && text.startsWith('<!--', i)) {
      const start = i
      const end = text.indexOf('-->', i + 4)
      i = end < 0 ? text.length : end + 3
      spans.push([start, i])
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch
      i++
      while (i < text.length) {
        const c = text[i]
        if (c === '\\' && i + 1 < text.length) {
          i += 2
          continue
        }
        i++
        if (c === quote) break
      }
      prevSignificant = quote
      prevWord = ''
      prevIsArrow = false
      continue
    }
    if (ch === '/' && regexAllowedAfter()) {
      i++
      let inClass = false
      while (i < text.length) {
        const c = text[i]
        i++
        if (c === '\\' && i < text.length) {
          i++
          continue
        }
        if (c === '[') inClass = true
        else if (c === ']') inClass = false
        else if (c === '/' && !inClass) break
        else if (c === '\n') break
      }
      prevSignificant = '/'
      prevWord = ''
      prevIsArrow = false
      continue
    }
    if (/\s/.test(ch)) {
      // 空白不改词/字符状态
    } else if (/[\w]/.test(ch)) {
      prevWord = /[\w]/.test(prevSignificant) ? prevWord + ch : ch
      prevSignificant = ch
      prevIsArrow = false
    } else {
      prevIsArrow = ch === '>' && prevSignificant === '='
      prevSignificant = ch
      prevWord = ''
    }
    i++
  }
  return spans
}

/**
 * marker 首个**不在注释内**的命中位置（-1 = 代码里没有）。
 *
 * 以注释文字为断言对象的「文档钉」标记本身是注释（`//`/`/*`/`<!--`）——此时按
 * 字面命中处理，否则文档钉永远找不到起点。
 */
const indexOfOutsideComments = (text: string, marker: string, from = 0): number => {
  if (/^\s*(?:\/\/|\/\*|<!--)/.test(marker)) return text.indexOf(marker, from)
  const spans = commentSpans(text)
  let at = from
  for (;;) {
    const hit = text.indexOf(marker, at)
    if (hit < 0) return -1
    const span = spans.find(([start, end]) => hit >= start && hit < end)
    if (!span) return hit
    at = span[1]
  }
}

/**
 * 从 startMarker 切到其后的 endMarker（endMarker 必须在 startMarker 之后）。
 * 缺任一 marker 或顺序倒置 → 抛错（而非返回空/倒置切片）；这是「限段钉」的统一边界。
 *
 * 两端都只在注释外匹配：注释里复述的代码形态（本仓注释密度高）会让切片落进
 * 注释中段——`match` 被注释满足（假绿）、`doesNotMatch` 恒真。
 */
export const section = (text: string, startMarker: string, endMarker: string): string => {
  const start = indexOfOutsideComments(text, startMarker)
  if (start < 0) throw new Error(`missing start marker: ${startMarker}`)
  const end = indexOfOutsideComments(text, endMarker, start + startMarker.length)
  if (end <= start) throw new Error(`missing end marker: ${endMarker} after ${startMarker}`)
  return text.slice(start, end)
}

/**
 * 提取文本中某个标签的全部**开标签**（`<name …>`，引号内的 `>` 不截断）。
 *
 * 结构断言必须按「开标签属性集」逐属性判定：把两个属性写进同一条正则的字面
 * 顺序（`…type="error"[^>]*title="…"`）在模板调整属性书写顺序时即假红，而界面
 * 完全没变。`[^>]*` 只把范围限制在标签内，不消除先后约束。
 */
export const openTags = (text: string, tag: string): string[] =>
  [...text.matchAll(new RegExp(`<${tag}\\b(?:[^>"']|"[^"]*"|'[^']*')*>`, 'g'))].map((m) => m[0])

/**
 * 去掉注释（`//`、`/* *\/`、Vue 模板 `<!-- -->`），保留字符串字面量与正则字面量。
 * 死代码扫描必须先剥注释：注释里提到退役符号不构成生产消费，否则维护者被迫
 * 改写历史说明或放宽正则。
 *
 * 正则字面量（`/…/`）必须识别——否则 `/\/\//` 之后的真实引用会被当行注释吞掉
 * （假绿），正则里的 `/*` 会吞掉大段代码（假红）。判定规则（词法启发）：
 * 仅当 `/` 前一有效记号是表达式起点（运算符 / 开括号 / `,` `;` `:`、`return`
 * 等关键字、箭头 `=>`）时才进入正则态，其余一律按除法处理——模板标签的
 * `</div>`、`<br />` 里的 `/` 因此不再吞掉同行 `<!-- -->`；
 * 正则态内遇未转义 `/` 或换行退出（字符类 `[...]` 内的 `/` 不退出）。
 */
export const stripComments = (text: string): string => {
  const spans = commentSpans(text)
  if (spans.length === 0) return text
  let out = ''
  let at = 0
  for (const [start, end] of spans) {
    out += text.slice(at, start)
    at = end
  }
  return out + text.slice(at)
}

/**
 * 推进 promise 作业队列 turns 次（纯微任务，不碰真实时钟）。用于「实现已发出
 * 的异步链还会跑几跳」这类不可观测长度的收尾：固定次数的 `setTimeout` 是
 * 猜作业队列长度且依赖真实时钟，单次 `await Promise.resolve()` 又常常不够。
 */
export const drainMicrotasks = async (turns = 64): Promise<void> => {
  for (let i = 0; i < turns; i++) await Promise.resolve()
}

/**
 * 有界条件等待（纯微任务）：直到 predicate 成立，或耗尽 turns 跳后以带原因的
 * 断言失败收场。把「等异步实现收敛」从猜次数改成等状态——未收敛时给出可读
 * 原因，而不是把中间态当结果断言（假绿）或挂到测试超时（挂起）。
 */
export const waitForMicrotasks = async (
  predicate: () => boolean,
  what: string,
  turns = 64,
): Promise<void> => {
  for (let i = 0; i < turns; i++) {
    if (predicate()) return
    await Promise.resolve()
  }
  throw new Error(`微任务预算 ${turns} 跳内未满足：${what}`)
}

/** 续行运算符：命中则说明上一行的 `)`/`}` 只是表达式内部收尾，声明还没结束。 */
const CONTINUATION_CHAR = /^[.?,:=&|{[(+)+\-*/]$/

/**
 * 声明头在行尾之后是否仍延续：`computed<…>(() =>\n  …\n    .filter(…)\n
 *    .map((p) => {` 这类链式表达式，行尾 `)` 只是内层调用收尾。
 *
 * 判据 = 下一个**代码**字符（跳过空白与注释）是续行运算符。注释里的续行不算
 * ——`const h = () => ({ a: 1 })\n// 说明\nconst k = …` 仍须硬失败，否则切片
 * 会顺延到下一个成员（doesNotMatch 恒真空转）。
 */
const nextCodeChar = (text: string, from: number): string => {
  const spans = commentSpans(text)
  let i = from
  while (i < text.length) {
    if (/\s/.test(text[i])) { i++; continue }
    const span = spans.find(([start, end]) => i >= start && i < end)
    if (span) { i = span[1]; continue }
    return text[i]
  }
  return ''
}

/**
 * 候选块是类型注解而非函数体：
 *   - 收尾后声明头仍通向 `=>` 或函数体 `{`（多行返回类型）；
 *   - 候选 `{` 前的最后一个代码字符是 `:`（`opts: {\n … }` 参数/属性类型）。
 *
 * 后者比「候选落在括号组内」精确：箭头回调体本身也在 `computed(… )`/`watch(… )`
 * 的括号里（链式 `.map((p) => {`），按 paren>0 判定会把真实函数体全部误杀。
 */
const isTypeAnnotationBlock = (text: string, open: number, close: number): boolean => {
  if (close >= 0 && headerContinuesAfterBlock(text, close)) return true
  let i = open - 1
  while (i >= 0 && /\s/.test(text[i])) i--
  return i >= 0 && text[i] === ':'
}

/**
 * 候选块收尾后声明头是否仍未结束：多行返回类型（`): {\n … } => {` /
 * `): {\n … } {`）——是则该块是类型注解，不是函数体。
 *
 * 只认「收尾后经 `)`/`:`/`|`/`&`/空白可达 `=>` 或 `{`」：对象字面量成员的尾部
 * `,`（合法的下一属性分隔）不在此列，避免把真函数体误判成类型块。
 */
const headerContinuesAfterBlock = (text: string, close: number): boolean => {
  let i = close + 1
  while (i < text.length) {
    const ch = text[i]
    if (/\s/.test(ch)) { i++; continue }
    if (ch === ')' || ch === ':' || ch === '|' || ch === '&') { i++; continue }
    if (ch === '=' && text[i + 1] === '>') return true
    return ch === '{'
  }
  return false
}

/**
 * 扫过 start→open 的声明头，返回**候选 `{` 处的括号深度**；声明在候选之前已
 * 结束则硬失败。
 *
 * 单表达式成员（`const h = () => ({ a: 1 })`）没有块体，`{\n` 会顺延到**下一个
 * 成员**的块体，切片因此越界（match 可被邻接代码满足=假绿，doesNotMatch 假红）。
 * 声明在候选 `{` 之前已结束——顶层 `;`，或行尾（顶层）`)`/`}`——一律硬失败：
 * 说明该 marker 指向的不是块体成员，唯一正确的修法是换一个可切片的成员。
 */
const scanDeclarationHeader = (
  text: string,
  start: number,
  open: number,
  marker: string,
): { paren: number; bracket: number } => {
  type Mode = 'code' | 'line' | 'block' | 'single' | 'double' | 'template'
  let mode: Mode = 'code'
  let paren = 0
  let bracket = 0
  // 声明头里的顶层 `{...}` 只可能是类型/对象字面量（真正的函数体从 `{\n` 起算，
  // 不在扫描范围内）——其内的 `;`（返回类型对象的属性分隔）不构成声明结束。
  let typeBraces = 0
  let closedTypeBrace = false
  let lastSignificant = ''
  for (let i = start; i < open; i++) {
    const ch = text[i]
    const next = text[i + 1]
    if (mode === 'line') {
      if (ch === '\n') mode = 'code'
      continue
    }
    if (mode === 'block') {
      if (ch === '*' && next === '/') { mode = 'code'; i++ }
      continue
    }
    if (mode === 'single' || mode === 'double') {
      const quote = mode === 'single' ? "'" : '"'
      if (ch === '\\') i++
      else if (ch === quote) mode = 'code'
      continue
    }
    if (mode === 'template') {
      if (ch === '\\') i++
      else if (ch === '`') mode = 'code'
      continue
    }
    if (ch === '/' && next === '/') { mode = 'line'; i++; continue }
    if (ch === '/' && next === '*') { mode = 'block'; i++; continue }
    if (ch === '"') { mode = 'double'; lastSignificant = ch; continue }
    if (ch === "'") { mode = 'single'; lastSignificant = ch; continue }
    if (ch === '`') { mode = 'template'; lastSignificant = ch; continue }
    if (ch === '(') { paren++; lastSignificant = ch; continue }
    if (ch === ')') { paren--; lastSignificant = ch; continue }
    if (ch === '[') { bracket++; lastSignificant = ch; continue }
    if (ch === ']') { bracket--; lastSignificant = ch; continue }
    if (ch === '{') {
      if (paren <= 0 && bracket <= 0) typeBraces++
      lastSignificant = ch
      continue
    }
    if (ch === '}') {
      if (paren <= 0 && bracket <= 0 && typeBraces > 0) {
        typeBraces--
        // 刚收尾一个类型块：紧随其后的行尾可能是「返回类型块 + 下一行函数体」
        // 形态（`}\n{`），不构成「声明已结束」。
        closedTypeBrace = typeBraces === 0
      }
      lastSignificant = ch
      continue
    }
    if (ch === '\n') {
      if (closedTypeBrace) {
        closedTypeBrace = false
        lastSignificant = '\n'
        continue
      }
      // 顶层行尾落在 `)`/`}` = 声明已结束（单表达式箭头体 / 对象字面量成员）；
      // 缩进内的续行（参数表/类型注解/链式调用）不在此列——下一代码字符是
      // 续行运算符时只是内层表达式收尾。
      if (
        paren <= 0 && bracket <= 0 && typeBraces === 0
        && (lastSignificant === ')' || lastSignificant === '}')
        && !CONTINUATION_CHAR.test(nextCodeChar(text, i + 1))
      ) {
        throw new Error(`member has no block body: ${marker}`)
      }
      continue
    }
    if (ch === ';' && paren <= 0 && bracket <= 0 && typeBraces === 0) {
      throw new Error(`member has no block body: ${marker}`)
    }
    if (!/\s/.test(ch)) lastSignificant = ch
  }
  return { paren, bracket }
}

/**
 * 成员体起点：marker 之后首个 `{` + 换行的候选块，跳过类型注解候选。
 *
 * 多行返回类型（`): {\n … } => {`）与参数对象类型（`opts: {\n … }`）都是「类型
 * 注解」，判据见 isTypeAnnotationBlock。排除后从该块收尾继续找下一个候选。
 */
const memberBlockOpen = (text: string, start: number, marker: string): number => {
  let searchFrom = start
  for (;;) {
    const open = indexOfOutsideComments(text, '{\n', searchFrom)
    if (open < 0) throw new Error(`member has no body: ${marker}`)
    scanDeclarationHeader(text, start, open, marker)
    const close = matchBrace(text, open)
    if (close < 0 || !isTypeAnnotationBlock(text, open, close)) return open
    searchFrom = close + 1
  }
}

/**
 * 花括号配对（open 指向 `{`）：返回匹配的 `}` 下标，未闭合返回 -1。
 *
 * 必须跳过字符串/模板量/注释里的括号：`const s = '}'` 或注释里的孤立 `}`
 * 会让切片提前收尾（后续 doesNotMatch 假绿）；孤立 `{` 则越界吞下相邻函数
 * （match 假绿）。模板量里的 `${...}` 是表达式，其内部括号按代码计。
 */
const matchBrace = (text: string, open: number): number => {
  type Mode = 'code' | 'line' | 'block' | 'single' | 'double' | 'template'
  let mode: Mode = 'code'
  let depth = 0
  // 进入模板量 `${` 时记录当前 depth；同 depth 的 `}` 返回模板量文本。
  const templateExprDepths: number[] = []
  for (let i = open; i < text.length; i++) {
    const ch = text[i]
    const next = text[i + 1]
    if (mode === 'line') {
      if (ch === '\n') mode = 'code'
      continue
    }
    if (mode === 'block') {
      if (ch === '*' && next === '/') { mode = 'code'; i++ }
      continue
    }
    if (mode === 'single' || mode === 'double') {
      const quote = mode === 'single' ? "'" : '"'
      if (ch === '\\') i++
      else if (ch === quote) mode = 'code'
      continue
    }
    if (mode === 'template') {
      if (ch === '\\') i++
      else if (ch === '`') mode = 'code'
      else if (ch === '$' && next === '{') { templateExprDepths.push(depth); mode = 'code'; i++ }
      continue
    }
    if (ch === '/' && next === '/') { mode = 'line'; i++; continue }
    if (ch === '/' && next === '*') { mode = 'block'; i++; continue }
    if (ch === '"') { mode = 'double'; continue }
    if (ch === "'") { mode = 'single'; continue }
    if (ch === '`') { mode = 'template'; continue }
    if (ch === '{') { depth++; continue }
    if (ch === '}') {
      if (templateExprDepths.length > 0 && templateExprDepths[templateExprDepths.length - 1] === depth) {
        templateExprDepths.pop()
        mode = 'template'
        continue
      }
      depth--
      if (depth === 0) return i
    }
  }
  return -1
}

/**
 * 截取成员体：从 marker 处的函数/方法声明花括号配对到收尾。
 *
 * 起点只在注释外命中：注释里复述的成员形态（本仓注释密度高）会切到错误位置，
 * 后续 `doesNotMatch` 恒真。收尾按花括号配对（见 matchBrace）。
 */
export const member = (text: string, marker: string): string => {
  const start = indexOfOutsideComments(text, marker)
  if (start < 0) throw new Error(`missing member: ${marker}`)
  const open = memberBlockOpen(text, start, marker)
  const close = matchBrace(text, open)
  if (close < 0) throw new Error(`unbalanced braces in member: ${marker}`)
  return text.slice(start, close + 1)
}

/** 最小 document 宿主：只提供 hidden + visibilitychange 监听（composable 消费面）。 */
export class FakeDocument {
  hidden = false
  private readonly listeners = new Set<() => void>()
  addEventListener(_type: 'visibilitychange', listener: () => void): void { this.listeners.add(listener) }
  removeEventListener(_type: 'visibilitychange', listener: () => void): void { this.listeners.delete(listener) }
  dispatch(): void { for (const listener of [...this.listeners]) listener() }
  get listenerCount(): number { return this.listeners.size }
}

/** 最小 window 宿主：只提供 setInterval/clearInterval 与手动点火。 */
export class FakeWindow {
  private nextId = 1
  private readonly timers = new Map<number, () => void>()
  setInterval(callback: () => void): number {
    const id = this.nextId++
    this.timers.set(id, callback)
    return id
  }
  clearInterval(id: number): void { this.timers.delete(id) }
  fire(): void { for (const callback of [...this.timers.values()]) callback() }
  get size(): number { return this.timers.size }
}

/**
 * 无 DOM 的组件宿主：`setup()` 在真实组件实例内执行，`unmount()` 触发
 * `onUnmounted`。SSR 渲染（renderToString）不执行卸载钩子——卸载清理（停定时器/
 * 取消帧/摘监听）只能用真实 mount + unmount 覆盖，否则钩子被删也全绿。
 */
export const mountForLifecycle = (setup: () => void): { unmount: () => void } => {
  const app = createRenderer<object, object>({
    createElement: (): object => ({}),
    createText: (): object => ({}),
    createComment: (): object => ({}),
    setText: (): void => {},
    setElementText: (): void => {},
    insert: (): void => {},
    remove: (): void => {},
    parentNode: (): null => null,
    nextSibling: (): null => null,
    patchProp: (): void => {},
  }).createApp({ setup, render: () => null })
  app.mount({})
  return { unmount: () => app.unmount() }
}

const srcRoot = new URL('../src/', import.meta.url)

/**
 * 让 `node --test` 直接加载 src 模块：解析 `@/…` 别名，并把 replacements 里的
 * 规格符替换为给定模块（测试替身 / 失败模块）。字节级依赖（element-plus 的
 * CSS 导入、1.9MB 省界表）不进测试进程。
 *
 * 必须在 `await import(...)` 之前调用——静态 import 先于本模块代码执行。
 * replacement 为函数时按次求值（可表达「首次失败、重试成功」）。
 */
// 模块解析钩子：`@/x` → src/x.ts。仅当 specifier 没有扩展名时补 `.ts`——
// 无条件拼接会把 `@/views/X.vue` 解析成 `X.vue.ts` 而失败。钩子是进程级、
// 只能累积（registerHooks 无注销面）：单个 spec 文件只注册一次、不支持 .vue
// 装载（模板级行为测试需另行方案，见 viewsCore 的静态 import 自检守卫）。
export const registerModuleHooks = (replacements: Record<string, string | (() => string)> = {}): void => {
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const replacement = replacements[specifier]
      if (replacement) return { url: typeof replacement === 'function' ? replacement() : replacement, shortCircuit: true }
      if (specifier.startsWith('@/')) {
        const target = specifier.slice(2)
        const withExtension = /\.[a-z0-9]+$/i.test(target) ? target : `${target}.ts`
        return nextResolve(new URL(withExtension, srcRoot).href, context)
      }
      return nextResolve(specifier, context)
    },
  })
}
