type PathUpstreamInput = {
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

export const validatePathRules = (rules: readonly PathRuleInput[]): string | null => {
  const seen = new Map<string, number>()
  for (const [index, rule] of rules.entries()) {
    const rowNumber = index + 1
    const path = rule.path.trim()
    if (!path.startsWith('/')) return `第 ${rowNumber} 条路径必须以 / 开头`
    if (/[*?{}]/.test(path)) return `第 ${rowNumber} 条路径不能包含 * ? { } 通配字符`
    const duplicateKey = `${rule.match_type}:${path}`
    const seenAt = seen.get(duplicateKey)
    if (seenAt !== undefined) return `第 ${rowNumber} 条路径与第 ${seenAt} 条重复（${path}）`
    seen.set(duplicateKey, rowNumber)
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
