/**
 * IP 名单导入判定纯函数单源（2026-11-02 交互重设计）：
 * 选择文件只暂存原文，保存时才解析判定——重复条目弹窗点名（以 IP 为准，
 * 同 IP 不同备注按首条为准），其余新条目合并进列表。
 */
import { entryKey } from './ipListSaveGuard.ts'

interface ImportSourceLine {
  no: number
  text: string
}

interface ImportDuplicate {
  lineNo: number
  value: string
  remark: string
}

interface ImportOutcome {
  /** 可直接并入列表的新条目（已按文件序去重，lineNo 供弹窗预览展示） */
  newEntries: Array<{ lineNo: number; value: string; remark: string }>
  /** 与现有列表或文件内其他行重复的行（含重复行号与该行原文） */
  duplicates: ImportDuplicate[]
  /** 非法行号（解析失败或备注超长——由注入的 parse 结果判定） */
  invalidLines: number[]
}

type ImportLineParseResult =
  | { value: string; remark: string }
  | { error: 'remark_too_long' }
  | null

/**
 * existingValues：当前列表已有条目值（trim 后）；lines：文件非空行（no=1 起）。
 * parse 由调用方注入（SecurityRules 与测试同一实现，保持行语法单源）。
 */
export function computeImportOutcome(
  existingValues: ReadonlySet<string>,
  lines: readonly ImportSourceLine[],
  parse: (text: string) => ImportLineParseResult,
): ImportOutcome {
  // 判重键与保存守卫单源同口径（entryKey：trim+小写）——IPv6 大小写变体是同一
  // 地址，按原文判重会漏判（2001:DB8::1 与 2001:db8::1 重复入表，后端写侧判重 400）。
  const seen = new Set([...existingValues].map(entryKey))
  const newEntries: ImportOutcome['newEntries'] = []
  const duplicates: ImportDuplicate[] = []
  const invalidLines: number[] = []
  for (const line of lines) {
    const parsed = parse(line.text)
    if (!parsed) {
      invalidLines.push(line.no)
      continue
    }
    if ('error' in parsed) {
      invalidLines.push(line.no)
      continue
    }
    const key = entryKey(parsed.value)
    if (seen.has(key)) {
      duplicates.push({ lineNo: line.no, value: parsed.value, remark: parsed.remark })
      continue
    }
    seen.add(key)
    newEntries.push({ lineNo: line.no, value: parsed.value, remark: parsed.remark })
  }
  return { newEntries, duplicates, invalidLines }
}
