type PathUpstreamInput = {
  readonly protocol: 'http' | 'https'
  readonly address: string
  readonly port: number
  readonly weight: number
}

type PathRuleInput = {
  readonly match_type: 'prefix' | 'exact'
  readonly path: string
  readonly sort_order: number
  readonly upstreams: readonly PathUpstreamInput[] | null
}

const isValidIpv4 = (value: string): boolean => {
  const segments = value.split('.')
  if (segments.length !== 4) return false
  return segments.every((segment) => {
    if (!/^\d{1,3}$/.test(segment)) return false
    const octet = Number(segment)
    return octet >= 0 && octet <= 255 && String(octet) === segment
  })
}

const isValidIpv6 = (value: string): boolean => {
  if (!value.includes(':') || value.includes('%')) return false
  try {
    return new URL(`http://[${value}]/`).hostname.length > 0
  } catch {
    return false
  }
}

export const isValidCidr = (rawValue: string): boolean => {
  const value = rawValue.trim()
  if (!value) return false
  const parts = value.split('/')
  if (parts.length > 2) return false

  const address = parts[0] ?? ''
  const isIpv4 = isValidIpv4(address)
  const isIpv6 = !isIpv4 && isValidIpv6(address)
  if (!isIpv4 && !isIpv6) return false
  if (parts.length === 1) return true

  const prefixText = parts[1] ?? ''
  if (!/^\d+$/.test(prefixText)) return false
  const prefix = Number(prefixText)
  return prefix >= 0 && prefix <= (isIpv4 ? 32 : 128)
}

// M32：与后端 internal/handlers/rule_features.go:323-350 同源的路径归一键——
// prefix 渲染为 [路径, 路径/*] 双 matcher 故尾部的 / 与 * 一并剥离（Go
// TrimRight cutset 语义），exact 仅剥尾 /；剥空回退 "/"。
export const canonicalPathKey = (matchType: 'prefix' | 'exact', raw: string): string => {
  const trimmed = raw.trim()
  const canonical = matchType === 'prefix' ? trimmed.replace(/[*\/]+$/, '') : trimmed.replace(/\/+$/, '')
  return canonical === '' ? '/' : canonical
}

export const validatePathRules = (rules: readonly PathRuleInput[]): string | null => {
  const seen = new Map<string, number>()
  // C-F3 同后端：prefix 与 exact 在同一路径上并存时，路由按 SortOrder 首条终结
  // 匹配，靠后的一条必被遮蔽成死规则——保存前整组拒绝（跨类型互查）。
  const seenPrefixRoots = new Map<string, number>()
  const seenExactNorms = new Map<string, number>()
  for (const [index, rule] of rules.entries()) {
    const rowNumber = index + 1
    // 与后端同口径：前缀校验用原始串（后端 HasPrefix 在 TrimSpace 之前）
    if (!rule.path.startsWith('/')) return `第 ${rowNumber} 条路径必须以 / 开头`
    if (/[*?{}]/.test(rule.path)) return `第 ${rowNumber} 条路径不能包含 * ? { } 通配字符`
    const canonical = canonicalPathKey(rule.match_type, rule.path)
    const duplicateKey = `${rule.match_type}:${canonical}`
    const seenAt = seen.get(duplicateKey)
    if (seenAt !== undefined) return `第 ${rowNumber} 条路径与第 ${seenAt} 条重复（${rule.path.trim()}）`
    seen.set(duplicateKey, rowNumber)
    if (rule.match_type === 'prefix') {
      const shadowAt = seenExactNorms.get(canonical)
      if (shadowAt !== undefined) return `第 ${rowNumber} 条路径与第 ${shadowAt} 条：同一路径同时存在前缀与精确匹配规则会造成遮蔽，请调整`
      seenPrefixRoots.set(canonical, rowNumber)
    } else {
      const shadowAt = seenPrefixRoots.get(canonical)
      if (shadowAt !== undefined) return `第 ${rowNumber} 条路径与第 ${shadowAt} 条：同一路径同时存在前缀与精确匹配规则会造成遮蔽，请调整`
      seenExactNorms.set(canonical, rowNumber)
    }
    if (rule.upstreams === null) continue
    if (rule.upstreams.length === 0) return `第 ${rowNumber} 条路径至少需要一个自定义上游`

    for (const upstream of rule.upstreams) {
      if (!upstream.address.trim()) return `第 ${rowNumber} 条路径的自定义上游地址不能为空`
      if (upstream.port < 1 || upstream.port > 65535) return `第 ${rowNumber} 条路径的自定义上游端口无效`
      if (upstream.weight < 1) return `第 ${rowNumber} 条路径的自定义上游权重必须大于 0`
    }
  }
  return null
}
