// IP / CIDR 解析单源：v4 八位组、v6 十六进制组、CIDR 判据与长整/大整折算。
//
// 此前四个消费点各写一份（ruleValidation 的写侧判据、trustedProxyRanges 的
// 网段并集键、securityStages 的事件匹配、upstreamKeys 的上游归一键），边界
// 判据已经分叉：前导零、%zone、`::` 展开各按各的宽容度。口径统一在此实现，
// 差异一律由显式参数表达——写侧预校验不得因为共享实现而放松，事件匹配侧也
// 不应因为「统一」而被收紧到丢匹配。
//
// - allowLeadingZeros=false：拒 `01` 这类前导零（后端 netip / WHATWG 同口径），
//   写侧判据必须用这个；true 保留历史宽容（事件匹配侧按十进制数值收）。
// - allowZone=false：拒 `fe80::1%eth0`（写侧 SNI/网段非法）；true 时丢弃 zone
//   再解析（引擎上报的链路本地地址带 zone，匹配侧必须能收）。

/** IPv4 八位组解析选项。 */
interface IPv4OctetOptions {
  readonly allowLeadingZeros: boolean
}

/** IPv6 组解析选项。 */
interface IPv6GroupOptions {
  readonly allowZone: boolean
}

const OCTET_PATTERN = /^\d{1,3}$/
const GROUP_PATTERN = /^[0-9a-fA-F]{1,4}$/

/**
 * IPv4 点分十进制 → 4 个八位组；无法解析返回 null。
 * 只接受纯数字段（不收空格与指数写法——那类字符串在后端必然是非法地址）。
 */
export const parseIPv4Octets = (
  address: string,
  options: IPv4OctetOptions,
): readonly number[] | null => {
  const parts = address.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const part of parts) {
    if (!OCTET_PATTERN.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    // 往返比对：`String(octet) === part` 只在无前导零时成立。
    if (!options.allowLeadingZeros && String(octet) !== part) return null
    octets.push(octet)
  }
  return octets
}

/**
 * IPv6 地址 → 8 个十六进制组；无法解析返回 null。
 *
 * 支持 `::` 压缩（必须代表至少一个被压缩的组）与嵌入 IPv4 尾
 * （`::ffff:1.2.3.4` 按 32 位折算成两组，使同一地址的不同书写形态落到同一
 * 结果上）。不做 trim：带首尾空格的形态是非法地址，写侧判据必须拒（调用方
 * 需要宽容时自己先 trim）。
 */
export const parseIPv6Groups = (
  address: string,
  options: IPv6GroupOptions,
): readonly number[] | null => {
  let text = address
  const zone = text.indexOf('%')
  if (zone >= 0) {
    if (!options.allowZone) return null
    text = text.slice(0, zone)
  }
  const body = text
  if (!body.includes(':') || body.includes('[') || body.includes(']')) return null

  const parseGroups = (segment: string, allowEmbeddedV4: boolean): readonly number[] | null => {
    const parts = segment.split(':')
    const out: number[] = []
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]
      if (part === '') return null
      if (part.includes('.')) {
        // 嵌入 IPv4 只允许出现在整条地址的最后 32 位（`::` 左侧的段不算末尾）
        if (!allowEmbeddedV4 || i !== parts.length - 1) return null
        const octets = parseIPv4Octets(part, { allowLeadingZeros: true })
        if (!octets) return null
        out.push((octets[0] << 8) | octets[1])
        out.push((octets[2] << 8) | octets[3])
        continue
      }
      if (!GROUP_PATTERN.test(part)) return null
      out.push(Number.parseInt(part, 16))
    }
    return out
  }

  const halves = body.split('::')
  if (halves.length > 2) return null
  if (halves.length === 2) {
    const headText = halves[0]
    const tailText = halves[1]
    const head = headText === '' ? [] : parseGroups(headText, false)
    const tail = tailText === '' ? [] : parseGroups(tailText, true)
    if (head === null || tail === null) return null
    const missing = 8 - head.length - tail.length
    if (missing < 1) return null
    return [...head, ...Array.from({ length: missing }, () => 0), ...tail]
  }
  const groups = parseGroups(body, true)
  return groups !== null && groups.length === 8 ? groups : null
}

/**
 * RFC 5952 压缩写法：最长零组折叠、同长取最前、单零组不折叠、小写。
 * 与 WHATWG / netip 的 IPv6 序列化同形（`::` 折叠形态逐例一致），故不必借道
 * 平台解析器——避免「能过判据却归一失败」的不可达防御分支。
 */
const compressV6Groups = (groups: readonly number[]): string => {
  let bestStart = -1
  let bestLength = 0
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] !== 0) continue
    let end = i
    while (end < groups.length && groups[end] === 0) end++
    if (end - i > bestLength) {
      bestStart = i
      bestLength = end - i
    }
    i = end - 1
  }
  const hex = groups.map((group) => group.toString(16))
  if (bestLength < 2) return hex.join(':')
  const head = hex.slice(0, bestStart).join(':')
  const tail = hex.slice(bestStart + bestLength).join(':')
  return `${head}::${tail}`
}

/**
 * IPv6 字面量的压缩规范形态（小写、去方括号）；非 IPv6 / 非法返回 null。
 * 判据与归一形态同源（同一地址的任何等价写法落到同一串）。
 */
export const canonicalV6Text = (value: string): string | null => {
  const groups = parseIPv6Groups(value, { allowZone: false })
  return groups === null ? null : compressV6Groups(groups)
}

/** 事件侧宽容 IPv4 解析单源（toV4Long 的实现基座）。
 *  既定口径（与 toV6BigInt 同族，事件匹配侧不收紧——securityStages 事件匹配
 *  消费引擎上报形态）：首尾空白容忍、`%zone` 丢弃、前导零按十进制数值收。
 *  与 split+Number 的历史写法的本质差异：空段/空白段/非十进制形态（`0x1`、
 *  `1e2`、`+1`）一律拒绝——Number('')===0 会把 `1.2.3.`、`1. .2.3` 放行为
 *  0 段，制造从未存在于引擎上报中的地址。写侧预校验不得用本函数（用
 *  parseIPv4Octets({allowLeadingZeros:false})）。模块私有——唯一消费方是
 *  同文件的 toV4Long（exportSurface 守卫禁止零外部消费的导出）。 */
const parseIPv4Lenient = (address: string): readonly number[] | null => {
  const text = address.trim()
  const zone = text.indexOf('%')
  const body = zone >= 0 ? text.slice(0, zone) : text
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(body)) return null
  const octets = body.split('.').map((part) => Number(part))
  if (octets.some((octet) => octet > 255)) return null
  return octets
}

/** IPv4 → 32 位无符号整数；无法解析返回 -1（调用方以此为非法哨兵）。
 *  走事件侧宽容单源 parseIPv4Lenient（zone 宽容 + 前导零按数值 + 空段拒绝）。 */
export const toV4Long = (address: string): number => {
  const octets = parseIPv4Lenient(address)
  if (!octets) return -1
  return (((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0)
}

/** IPv6 → 128 位无符号整数；无法解析返回 null。`%zone` 丢弃（引擎上报的
 *  链路本地地址带 zone，匹配侧必须能收；首尾空白同属历史宽容口径）。 */
export const toV6BigInt = (address: string): bigint | null => {
  const groups = parseIPv6Groups(address.trim(), { allowZone: true })
  if (!groups) return null
  let out = 0n
  for (const group of groups) out = (out << 16n) | BigInt(group)
  return out
}

/** 严格 IPv4 判据（写侧预校验：拒前导零）。 */
export const isValidV4 = (value: string): boolean => parseIPv4Octets(value, { allowLeadingZeros: false }) !== null

/** 严格 IPv6 判据（写侧预校验：拒 %zone，不做 trim）。 */
export const isValidV6 = (value: string): boolean => parseIPv6Groups(value, { allowZone: false }) !== null

/**
 * IP 或 CIDR 判据（写侧预校验）：裸 IP 与 `地址/前缀长度` 两种形态。
 * 与后端 parseTrustedProxyPrefix / 规则 IP 条件的写侧门同口径——前端只在
 * 后端**必然拒绝**的形态上拦，故这里严格按地址语法判定。
 */
export const isValidCidr = (rawValue: string): boolean => {
  const value = rawValue.trim()
  if (!value) return false
  const parts = value.split('/')
  if (parts.length > 2) return false

  const address = parts[0] ?? ''
  const isV4 = isValidV4(address)
  const isV6 = !isV4 && isValidV6(address)
  if (!isV4 && !isV6) return false
  if (parts.length === 1) return true

  const prefixText = parts[1] ?? ''
  if (!/^\d+$/.test(prefixText)) return false
  const prefix = Number(prefixText)
  return prefix >= 0 && prefix <= (isV4 ? 32 : 128)
}
