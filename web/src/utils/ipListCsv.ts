// IP 名单 CSV 往返：导出对含逗号/引号的备注加双引号并
// 双写内部引号，而原解析器只按 `^([^,\s]+)(?:[,\s]+(.*))?$` 切分、不做 CSV
// 反转义——自产文件导回后备注被截断/保留外层引号，二次往返累积漂移。
// 此模块是导出/导入共用的字段级单源。

/**
 * 表格软件按公式求值的形态：可选的前导 `\t`/`\r`（部分工具先剥空白再识别公式）
 * 之后紧跟 `= + - @`。纯空白开头（如制表符缩进）不是公式入口，不得中和——
 * 否则「首尾空白加引号保真」的往返契约会被无故改写。
 */
const CSV_FORMULA_LEADING = /^[\t\r]*[=+\-@]/

/**
 * 备注字段导出：换行归一为空格（导入端按行切分，多行备注无法回读），
 * 含逗号、双引号或首尾空白时按 RFC4180 包裹并双写内部引号。
 * 首尾空白必须加引号：导入侧对未加引号的字段做 trim 归一，不加引号会让
 * 「导出→导入」丢失备注的两端空格（模块声明的是逐字往返）。
 *
 * 公式中和：以 `= + - @`（或其前带 `\t`/`\r`）开头的备注在表格软件里是公式/DDE
 * 入口，纯文本导出即静默求值。中和=在**引号串之前**再前置一个单引号；导入侧
 * readUnneutralized 按同一判据剥一个，往返逐字相等，且字面单引号不会被吞
 * （`'=x` 导出为 `''=x`，回读仍是 `'=x`）。
 */
function formatCsvRemark(remark: string): string {
  const singleLine = remark.replace(/[\r\n]+/g, ' ')
  const neutralized = neutralizeCsvFormula(singleLine)
  return /[",]|^\s|\s$/.test(singleLine) ? `"${neutralized.replace(/"/g, '""')}"` : neutralized
}

/** 前导单引号串之后紧跟公式形态 → 前置一个单引号（表格软件视整串为文本）。 */
function neutralizeCsvFormula(value: string): string {
  const quotes = /^'*/.exec(value)?.[0] ?? ''
  return CSV_FORMULA_LEADING.test(value.slice(quotes.length)) ? `'${value}` : value
}

/** 导入侧对称剥离：前导引号串非空且其后紧跟公式形态时剥掉一个引号。 */
function readUnneutralized(value: string): string {
  const quotes = /^'*/.exec(value)?.[0] ?? ''
  if (quotes === '') return value
  return CSV_FORMULA_LEADING.test(value.slice(quotes.length)) ? value.slice(1) : value
}

/** 导出一行（第一列 IP/CIDR，第二列备注；备注为空保留尾随逗号）。 */
export function formatIpListEntryLine(value: string, remark: string): string {
  return `${value},${formatCsvRemark(remark)}`
}

/** 解析行尾/字段内的双引号包裹值（`""` 反转义）；未闭合返回 null。 */
function readQuotedField(raw: string, start: number): { text: string; next: number } | null {
  let i = start + 1
  let text = ''
  while (i < raw.length) {
    const ch = raw[i]
    if (ch === '"') {
      if (raw[i + 1] === '"') {
        text += '"'
        i += 2
        continue
      }
      return { text, next: i + 1 }
    }
    text += ch
    i++
  }
  return null
}

/** 备注长度上限（Unicode code point 计）：超长行拒绝导入，不再静默截断。 */
export const ipListRemarkMaxLength = 100

/**
 * 引号字段闭合后的剩余部分：三形态——「空白 + 单个逗号 + 备注」「纯空白」
 * 「空白 + 备注（无逗号，与非引号分支的空白分隔对齐）」；其余残留返回 null
 * （整行按非法拒绝——闭合引号后直接粘连的残片不得并入备注）。旧实现把首
 * 字段残留整体并入备注、把备注字段残留静默丢弃——导入结果与源文件不一致
 * 却无提示。
 */
function readFieldRest(raw: string, from: number): string | null {
  const rest = raw.slice(from)
  if (/^\s*$/.test(rest)) return ''
  const withComma = rest.match(/^\s*,([\s\S]*)$/)
  if (withComma) return withComma[1] ?? ''
  const blankSeparated = rest.match(/^\s+([\s\S]*)$/)
  return blankSeparated ? blankSeparated[1] : null
}

/**
 * 解析导入行：第一列可为双引号包裹的 CSV 字段（`""` 反转义）；引号字段之后
 * 只认「空白 + 逗号 + 空白」，闭合引号后的任何残留都按非法行拒绝。纯文本行
 * 不带引号时按原正则切分，逗号/空白分隔均兼容。
 * validate 由调用方注入（isValidCidr）——本模块不依赖校验实现。
 *
 * 返回：合法行 { value, remark }；备注超过 ipListRemarkMaxLength 返回
 * { error: 'remark_too_long' }（调用方须带行号拒绝，与非法 CIDR 同策略点名）；
 * 其余不可解析形态（空行/非法值/未闭合引号/引号闭合后的残留）返回 null。
 * 残留按非法行拒绝而非并入备注或丢弃：导入结果必须与源文件一致，且由导入
 * 流程按行号点名，用户才知道该行没被采用。
 */
export function parseIpListEntryLine(
  line: string,
  validate: (value: string) => boolean,
): { value: string; remark: string } | { error: 'remark_too_long' } | null {
  const text = line.trim()
  if (text === '') return null
  let value: string
  let rest: string
  if (text.startsWith('"')) {
    const field = readQuotedField(text, 0)
    if (!field) return null
    value = field.text
    const afterField = readFieldRest(text, field.next)
    if (afterField === null) return null
    rest = afterField
  } else {
    const match = text.match(/^([^,\s]+)(?:[,\s]+([\s\S]*))?$/)
    if (!match) return null
    value = match[1] ?? ''
    rest = match[2] ?? ''
  }
  const normalized = value.trim()
  if (!normalized || !validate(normalized)) return null
  let remark = rest.trim()
  if (remark.startsWith('"')) {
    const field = readQuotedField(remark, 0)
    if (!field) return null
    // 备注是最后一列：闭合引号后只允许空白；即使第三列为空也属畸形行
    if (!/^\s*$/.test(remark.slice(field.next))) return null
    remark = field.text
  }
  // 导出侧为防表格软件求值而前置的单引号在此对称剥离（未悬挂公式字符的字面
  // 单引号原样保留）——往返逐字相等。
  remark = readUnneutralized(remark)
  if (Array.from(remark).length > ipListRemarkMaxLength) {
    return { error: 'remark_too_long' }
  }
  return { value: normalized, remark }
}
