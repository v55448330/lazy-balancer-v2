// 正则预览编译（前端语法预校验 + 高亮着色共用单源）。
//
// 合法以后端 RE2(coraza) 为准；RE2 支持组合内联 flag(?im)/中置 flag(a(?i)b)/
// flag 组((?i:...))/命名组((?P<name>))/flag 取反((?-i))，不支持 lookaround/
// 反向引用（这些先挡掉，避免把 RE2 不支持形态当合法）。
//
// 中置 flag 在 JS 不识别，剥离后试编译。剥离正则**不得要求 flag 后紧跟非 ')'**
// ——RE2 允许 flag 紧邻分组闭括号（`(a(?i)b)`、`(?:abc(?i))`），旧 lookahead
// `(?=[^)]|$)` 会漏剥离并把合法规则误判语法错误。
//
// 试编译顺序：原文 → 剥离中置 flag → flag 组转普通分组；真语法错误（未闭合
// 括号等）在三段全失败后判 invalid，不被兜底掩盖。

interface RegexPreviewCompile {
  re: RegExp | null
  valid: boolean
}

export function compileJSRegex(pattern: string): RegexPreviewCompile {
  // 合法性以后端 RE2(coraza)为准。
  if (/\(\?<?[=!]/.test(pattern) || /\\[1-9]/.test(pattern) || /\\k</.test(pattern)) {
    return { re: null, valid: false }
  }
  // lead 捕获含取反 '-'——白名单 {i,m,s,U,-} 真正生效（此前捕获组不含 '-'，
  // 取反形态连 lead 都匹配不上）。
  const lead = pattern.match(/^\(\?([-a-zA-Z]+)\)/)
  if (lead && !/^(?:[imsU]+(?:-[imsU]+)?|-[imsU]+)$/.test(lead[1])) {
    return { re: null, valid: false }
  }
  let src = pattern
  let flags = ''
  if (lead) {
    // RE2 取反语义：'-' 后的 flag 关闭、前缀开启；JS 无原生取反，预览近似：
    // '-' 前的正向 flag 照收（!negated 守卫），'-' 后的跳过（不重置累积——
    // (?i-s) 保留 i、丢弃 s，比全清更接近 RE2）；纯取反((?-i))不加任何 flag。
    let negated = false
    for (const f of lead[1].toLowerCase()) {
      if (f === '-') { negated = true; continue }
      if (!negated && (f === 'i' || f === 'm' || f === 's') && !flags.includes(f)) flags += f
    }
    src = src.slice(lead[0].length)
  }
  src = src.replace(/\(\?P</g, '(?<')
  // 中置内联 flag((?i)a(?m)b)——JS 不识别，剥离后重试（RE2 合法）。
  const midFlagStripped = src.replace(/\(\?(?:[imsU]+(?:-[imsU]+)?|-[imsU]+)\)/g, '')
  // flag 组((?i:...))——JS 不识别，替换为普通分组后再试。
  const flagGroupsOpened = src.replace(/\(\?[-imsU]+:/g, '(')
  // 两种 RE2 形态可同时出现（a(?i)b(?m:c)）：单形态候选都失败，需链式
  // 先剥中置 flag 再展开 flag 组，否则前端比后端更严、合法规则保存被拦。
  const combined = midFlagStripped.replace(/\(\?[-imsU]+:/g, '(')
  const candidates = [src, midFlagStripped, flagGroupsOpened, combined]
  for (const candidate of candidates) {
    try {
      return { re: new RegExp(candidate, flags), valid: true }
    } catch {
      continue
    }
  }
  return { re: null, valid: false }
}
