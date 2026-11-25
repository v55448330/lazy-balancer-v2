// 后端消息词条 → 前端接口消息词条的生成器（web/DESIGN_SPEC.md §25-8）。
//
// 后端目录（internal/i18n/catalog_gen.go、catalog_manual.go）是后端响应消息的
// 中英文母本。前端按 message_key 自己渲染提示文字，需要同一份词条；手抄两份必然
// 分叉，所以由本脚本导出，tests/apiMessagesParity.spec.ts 钉住「与后端目录逐字相等」。
//
// 用法（在 web/ 下）：
//   npm run gen:api-messages           重新导出 src/i18n/apiMessages.ts
//   npm run gen:api-messages -- --check 只校验，不一致时退出码 1
//
// 解析与渲染是纯函数并导出：对等守卫直接复用，不另写一份解析逻辑。
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** 一条后端消息词条。 */
export interface ApiMessage {
  readonly key: string
  readonly zh: string
  readonly en: string
}

/** 后端目录文件（相对仓库根），按此顺序拼接——与后端 init 的登记顺序一致。 */
export const BACKEND_CATALOG_FILES: readonly string[] = [
  'internal/i18n/catalog_gen.go',
  'internal/i18n/catalog_manual.go',
]

/** 生成文件（相对 web/）。 */
export const OUTPUT_FILE = 'src/i18n/apiMessages.ts'

// Register("key", "zh", "en")：三个双引号字面量，各自允许 \" 与 \\ 转义。
const REGISTER_LINE = /^\s*Register\("((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)"\),?\s*$/

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
 * 解析后端目录源码里的全部 Register(key, zh, en)。
 * 遇到 Register( 却不是单行三参数形态的行直接抛错：静默跳过会让词条悄悄缺失。
 */
export const parseBackendCatalog = (goSource: string, fileName = '<catalog>'): ApiMessage[] => {
  const entries: ApiMessage[] = []
  goSource.split('\n').forEach((line, index) => {
    // 注释行（// 与 /* */ 块内的 * 续行）不读：注释里举例的 Register 不是词条。
    if (/^\s*(\/\/|\/\*|\*)/.test(line) || !line.includes('Register(')) return
    const match = REGISTER_LINE.exec(line)
    if (!match) throw new Error(`${fileName}:${index + 1}: Register 不是单行三参数形态: ${line.trim()}`)
    const values = match.slice(1).map((body) => {
      const decoded = goUnquote(body)
      if (decoded === null) throw new Error(`${fileName}:${index + 1}: 字符串字面量含不认识的转义: ${body}`)
      return decoded
    })
    entries.push({ key: values[0] as string, zh: values[1] as string, en: values[2] as string })
  })
  return entries
}

/** 键 → 文本的 TS 对象字面量（JSON 转义，与 Go 源码里的写法无关）。 */
const renderMap = (entries: readonly ApiMessage[], pick: (entry: ApiMessage) => string): string => {
  const lines = entries.map((entry) => `  ${JSON.stringify(entry.key)}: ${JSON.stringify(pick(entry))},`)
  return `{\n${lines.join('\n')}\n}`
}

/** 生成 src/i18n/apiMessages.ts 的全文。键按后端登记顺序（重新导出时 diff 只动变化的行）。 */
export const renderApiMessagesModule = (entries: readonly ApiMessage[]): string => {
  const keys = new Set<string>()
  for (const entry of entries) {
    if (keys.has(entry.key)) throw new Error(`后端目录里键重复：${entry.key}`)
    keys.add(entry.key)
  }
  return [
    '// 由 scripts/gen-api-messages.ts 从后端目录导出——不要手改。',
    '// 后端改了词条后，在 web/ 下运行 npm run gen:api-messages 重新导出；',
    '// tests/apiMessagesParity.spec.ts 钉住本文件与后端目录逐字相等。',
    '// 键是后端响应的 message_key（域名.驼峰名）；渲染入口见 utils/apiMessage.ts。',
    '',
    `/** 中文母本（后端 message 的兜底原文同源）。 */`,
    `export const API_MESSAGE_ZH: Readonly<Record<string, string>> = ${renderMap(entries, (entry) => entry.zh)}`,
    '',
    '/** 英文译文。 */',
    `export const API_MESSAGE_EN: Readonly<Record<string, string>> = ${renderMap(entries, (entry) => entry.en)}`,
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

// 入口判断：被 node 直接执行时才跑。不用 import.meta.main——它要 Node 24.2+，而 engines
// 声明的最低版本是 22.18，在 22 上它是 undefined，生成器会静默什么都不做。
const invokedDirectly = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (invokedDirectly) {
  const check = process.argv.includes('--check')
  const entries = loadBackendCatalog()
  const expected = renderApiMessagesModule(entries)
  if (check) {
    if (readGeneratedModule() === expected) {
      console.log(`${OUTPUT_FILE} 与后端目录一致（${entries.length} 条）`)
    } else {
      console.error(`${OUTPUT_FILE} 与后端目录不一致——在 web/ 下运行 npm run gen:api-messages 重新导出`)
      process.exit(1)
    }
  } else {
    writeFileSync(fileURLToPath(new URL(OUTPUT_FILE, webRoot)), expected)
    console.log(`已导出 ${OUTPUT_FILE}（${entries.length} 条）`)
  }
}
