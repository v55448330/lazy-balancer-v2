// 后端消息键 + 前端接口消息词条 → 前端渲染表的生成器（web/DESIGN_SPEC.md §25-8）。
//
// 职责边界（2026-11-25 项目所有者裁定：后端只下发稳定键与参数，文案只归前端）：
//   - 后端目录（internal/i18n/catalog_*.go）只有「键 + 中文母本」，是接口契约与
//     message 兜底原文的来源，不含任何英文译文；
//   - 前端词条 src/locales/apiMessages.en.json 是英文的唯一维护源（手写）；
//   - 本脚本把两者拼成 src/i18n/apiMessages.ts（前端的 zh/en 渲染表），并校验
//     键集合双向对等：后端多一个键前端缺词条、前端多一个后端没有的键，都红。
//
// 用法（在 web/ 下）：
//   npm run gen:api-messages           重新导出 src/i18n/apiMessages.ts
//   npm run gen:api-messages -- --check 只校验，不一致时退出码 1
//
// 解析与渲染是纯函数并导出：对等守卫直接复用，不另写一份解析逻辑。
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** 一条后端消息词条：只有键与中文母本，英文译文归前端（src/locales/apiMessages.en.json）。 */
export interface ApiMessage {
  readonly key: string
  readonly zh: string
}

/** 后端目录文件（相对仓库根），按此顺序拼接——与后端 init 的登记顺序一致。 */
export const BACKEND_CATALOG_FILES: readonly string[] = [
  'internal/i18n/catalog_gen.go',
  'internal/i18n/catalog_manual.go',
  'internal/i18n/catalog_unkeyed.go',
  'internal/i18n/catalog_audit_detail.go',
]

/** 生成文件（相对 web/）。 */
export const OUTPUT_FILE = 'src/i18n/apiMessages.ts'

// Register("key", "zh")：两个双引号字面量，各自允许 \" 与 \\ 转义。
// 只认两参形态：后端目录不得携带英文译文（英文唯一来源是
// src/locales/apiMessages.en.json），出现第三参直接解析失败。
const REGISTER_LINE = /^\s*Register\("((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)"\),?\s*$/

/**
 * Go 双引号字符串字面量的内容 → 解码后的文本（按 Go 的转义规则，见 go/spec 的
 * "String literals"）。不认识的转义返回 null——宁可让守卫报错，也不悄悄解错。
 */
export const goUnquote = (body: string): string | null => {
  let out = ''
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]
    if (ch !== '\\') {
      out += ch
      continue
    }
    const esc = body[i + 1]
    if (esc === undefined) return null
    i++
    switch (esc) {
      case 'a': out += '\u0007'; break
      case 'b': out += '\b'; break
      case 'f': out += '\f'; break
      case 'n': out += '\n'; break
      case 'r': out += '\r'; break
      case 't': out += '\t'; break
      case 'v': out += '\v'; break
      case '\\': out += '\\'; break
      case "'": out += "'"; break
      case '"': out += '"'; break
      case 'x': {
        const hex = body.slice(i + 1, i + 3)
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null
        out += String.fromCharCode(Number.parseInt(hex, 16))
        i += 2
        break
      }
      case 'u': case 'U': {
        const width = esc === 'u' ? 4 : 8
        const hex = body.slice(i + 1, i + 1 + width)
        if (!new RegExp(`^[0-9a-fA-F]{${width}}$`).test(hex)) return null
        const code = Number.parseInt(hex, 16)
        if (code > 0x10ffff) return null
        out += String.fromCodePoint(code)
        i += width
        break
      }
      default: {
        // 八进制 \OOO：Go 要求恰好三位。
        const oct = body.slice(i, i + 3)
        if (!/^[0-7]{3}$/.test(oct)) return null
        out += String.fromCharCode(Number.parseInt(oct, 8))
        i += 2
      }
    }
  }
  return out
}

/**
 * 解析后端目录源码里的全部 Register(key, zh)。
 * 遇到 Register( 却不是单行形态的行直接抛错：静默跳过会让词条悄悄缺失。
 */
export const parseBackendCatalog = (goSource: string, fileName = '<catalog>'): ApiMessage[] => {
  const entries: ApiMessage[] = []
  goSource.split('\n').forEach((line, index) => {
    // 注释行（// 与 /* */ 块内的 * 续行）不读：注释里举例的 Register 不是词条。
    if (/^\s*(\/\/|\/\*|\*)/.test(line) || !line.includes('Register(')) return
    const match = REGISTER_LINE.exec(line)
    if (!match) throw new Error(`${fileName}:${index + 1}: Register 不是单行 (key, zh) 形态: ${line.trim()}`)
    const values = match.slice(1).map((body) => {
      const decoded = goUnquote(body)
      if (decoded === null) throw new Error(`${fileName}:${index + 1}: 字符串字面量含不认识的转义: ${body}`)
      return decoded
    })
    entries.push({ key: values[0] as string, zh: values[1] as string })
  })
  return entries
}

/** 键 → 文本的 TS 对象字面量（JSON 转义，与 Go 源码里的写法无关）。 */
const renderMap = (pairs: ReadonlyArray<readonly [string, string]>): string => {
  const lines = pairs.map(([key, text]) => `  ${JSON.stringify(key)}: ${JSON.stringify(text)},`)
  return `{\n${lines.join('\n')}\n}`
}

/** 前端自带的英文词条（2026-11-25 裁定：后端不再翻译，英文译文归前端）。 */
export const FRONTEND_EN_FILE = 'src/locales/apiMessages.en.json'

/**
 * 合并中英词条：
 *   - 中文母本一律取后端目录（后端 message 的兜底原文同源）；
 *   - 英文只取前端词条（src/locales/apiMessages.en.json）——后端不再提供英文，
 *     缺译由守卫要求补齐（`missing`）；
 *   - 前端词条里出现后端目录没有的键 = 死条目（`errors`）——目录改名后必须同步删。
 */
export const mergeTranslations = (
  entries: readonly ApiMessage[],
  frontendEnglish: Readonly<Record<string, string>>,
): { zh: Array<[string, string]>; en: Array<[string, string]>; errors: string[]; missing: string[] } => {
  const known = new Set(entries.map((entry) => entry.key))
  const errors = Object.keys(frontendEnglish)
    .filter((key) => !known.has(key))
    .map((key) => `前端英文词条含后端目录没有的键（死条目）：${key}`)
  const zh: Array<[string, string]> = []
  const en: Array<[string, string]> = []
  const missing: string[] = []
  for (const entry of entries) {
    zh.push([entry.key, entry.zh])
    const translated = frontendEnglish[entry.key]
    if (translated) en.push([entry.key, translated])
    else missing.push(entry.key)
  }
  return { zh, en, errors, missing }
}

/** 生成 src/i18n/apiMessages.ts 的全文。键按后端登记顺序（重新导出时 diff 只动变化的行）。 */
export const renderApiMessagesModule = (entries: readonly ApiMessage[], frontendEnglish: Readonly<Record<string, string>> = {}): string => {
  const keys = new Set<string>()
  for (const entry of entries) {
    if (keys.has(entry.key)) throw new Error(`后端目录里键重复：${entry.key}`)
    keys.add(entry.key)
  }
  const { zh, en } = mergeTranslations(entries, frontendEnglish)
  return [
    '// 由 scripts/gen-api-messages.ts 拼装——不要手改。',
    '// 中文母本来自后端目录（internal/i18n/catalog_*.go，只有键 + 中文）；',
    '// 英文译文来自前端词条 src/locales/apiMessages.en.json（唯一维护源，手写）。',
    '// 改了任一侧后在 web/ 下运行 npm run gen:api-messages；',
    '// tests/apiMessagesParity.spec.ts 钉住键集合双向对等与本文件逐字相等。',
    '// 键是后端响应的 message_key（域名.驼峰名）；渲染入口见 utils/apiMessage.ts。',
    '',
    `/** 中文母本（后端 message 的兜底原文同源）。 */`,
    `export const API_MESSAGE_ZH: Readonly<Record<string, string>> = ${renderMap(zh)}`,
    '',
    '/** 英文译文（前端词条优先，后端遗留英文次选；只有中文兜底的键不在此表）。 */',
    `export const API_MESSAGE_EN: Readonly<Record<string, string>> = ${renderMap(en)}`,
    '',
  ].join('\n')
}

const webRoot = new URL('../', import.meta.url)

/** 读后端目录并解析（相对仓库根定位 catalog 文件）。 */
export const loadBackendCatalog = (): ApiMessage[] =>
  BACKEND_CATALOG_FILES.flatMap((file) => parseBackendCatalog(readFileSync(new URL(`../${file}`, webRoot), 'utf8'), file))

/** 已提交的生成文件全文；文件不存在返回 null。 */
export const readGeneratedModule = (): string | null => {
  try {
    return readFileSync(new URL(OUTPUT_FILE, webRoot), 'utf8')
  } catch {
    return null
  }
}

/** 前端自带的英文词条；文件不存在按空表处理。 */
export const loadFrontendEnglish = (): Record<string, string> => {
  try {
    const parsed: unknown = JSON.parse(readFileSync(new URL(FRONTEND_EN_FILE, webRoot), 'utf8'))
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${FRONTEND_EN_FILE} 必须是 JSON 对象`)
    const table: Record<string, string> = {}
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value !== 'string') throw new Error(`${FRONTEND_EN_FILE}: ${key} 的值必须是字符串`)
      table[key] = value
    }
    return table
  } catch (error) {
    if (error !== null && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return {}
    throw error
  }
}

// 入口判断：被 node 直接执行时才跑。不用 import.meta.main——它要 Node 24.2+，而 engines
// 声明的最低版本是 22.18，在 22 上它是 undefined，生成器会静默什么都不做。
const invokedDirectly = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (invokedDirectly) {
  const check = process.argv.includes('--check')
  const entries = loadBackendCatalog()
  const frontendEnglish = loadFrontendEnglish()
  const { errors, missing } = mergeTranslations(entries, frontendEnglish)
  if (errors.length > 0) {
    console.error(`前端英文词条有 ${errors.length} 处问题：\n${errors.join('\n')}`)
    process.exit(1)
  }
  if (missing.length > 0) {
    console.warn(`以下 ${missing.length} 个键只有中文兜底、前端尚未提供英文译文（守卫会拦）：\n  ${missing.join('\n  ')}`)
  }
  const expected = renderApiMessagesModule(entries, frontendEnglish)
  if (check) {
    if (readGeneratedModule() === expected) {
      console.log(`${OUTPUT_FILE} 与两侧来源一致（${entries.length} 条）`)
    } else {
      console.error(`${OUTPUT_FILE} 与来源不一致——在 web/ 下运行 npm run gen:api-messages 重新导出`)
      process.exit(1)
    }
  } else {
    writeFileSync(fileURLToPath(new URL(OUTPUT_FILE, webRoot)), expected)
    console.log(`已导出 ${OUTPUT_FILE}（${entries.length} 条，英文 ${mergeTranslations(entries, frontendEnglish).en.length} 条）`)
  }
}
