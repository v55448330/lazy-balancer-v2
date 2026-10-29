/**
 * 受信代理（CDN 回源）配置的行内校验，与后端判据单源：
 *
 * - `internal/services/caddy.go` 的 `trustedProxyMinPrefixBits`（IPv4 /8、
 *   IPv6 /29）/ `TrustedProxyPrefixAllSpace`（全空间形态）/
 *   `TrustedProxyPrefixCanonical`（Masked 剥主机位 + v4-mapped 折等价 v4）；
 * - `internal/handlers/config_trustedproxy.go` 的 `normalizeTrustedProxyRanges`
 *   （内联网段上限 64 条，裸 IP 由后端补 /32 或 /128）、
 *   `normalizeTrustedProxyHeaders`（请求头条数 ≤8（小写去重后）、字符集
 *   `^[A-Za-z0-9-]{1,64}$`）与 `trustedProxyMaxTotalCIDRs`
 *   （内联 + 引用展开 ≤2000）。
 *
 * 后端在 /config/preview 与 PUT /config 才拒绝非法形态，用户拿到的只是
 * 一次全局 toast 且无法定位是哪一条；同仓路径规则编辑器已把「清空即标红、
 * 不等到点保存才被整组拒绝」写成契约，本模块承担同一角色。
 *
 * 方向性约束：前端只在后端**必然拒绝**的形态上报错；不确定的形态一律放行，
 * 由后端兜底（前端误拒比晚失败更糟——会挡住合法配置）。
 */

import { isValidCidr, parseIPv4Octets, parseIPv6Groups } from './ipAddress.ts'

/** 允许的最小前缀长度（/29 覆盖 Cloudflare 官方最宽回源段）。
 *  导出供跨栈对表测试与后端 trustedProxyMinPrefixBits 直接同值比对。 */
export const TRUSTED_PROXY_MIN_PREFIX_BITS = { ipv4: 8, ipv6: 29 } as const

/** 内联网段条数上限（引用名单条目另计，后端总量门为 2000）。
 *  导出供跨栈对表测试与后端 normalizeTrustedProxyRanges 同值比对。 */
export const TRUSTED_PROXY_MAX_INLINE_ENTRIES = 64

/** 请求头条数上限（按小写去重后的条数计——后端 normalizeTrustedProxyHeaders
 *  先 strings.ToLower 去重、再判 len(normalized) > 8）。
 *  导出供跨栈对表测试与后端 normalizeTrustedProxyHeaders 同值比对。 */
export const TRUSTED_PROXY_MAX_HEADERS = 8

/** 请求头名允许的字符集（与后端 trustedProxyHeaderPattern 逐字对齐）。 */
const TRUSTED_PROXY_HEADER_PATTERN = /^[A-Za-z0-9-]{1,64}$/

/** 受信网段总量上限：内联 ∪ 引用展开（与后端 trustedProxyMaxTotalCIDRs 同值）。 */
export const TRUSTED_PROXY_MAX_TOTAL_ENTRIES = 2000

/** 覆盖全部地址空间的**规范**形态（等同信任任意来源），逐条对齐后端
 *  `TrustedProxyPrefixAllSpace` 的 case 列表——v4-mapped 变体不在此列，
 *  由 `mappedV4Prefix` 折成等价 v4 后落回这组（与后端
 *  `TrustedProxyPrefixCanonical` 同口径）。 */
const ALL_SPACE_PREFIXES: readonly string[] = ['0.0.0.0/8', '0.0.0.0/0', '::/0']

/** 最小前缀长度的统一文案（全空间判据优先，故两处共用）。 */
const MIN_PREFIX_BITS_MESSAGE = `最小允许 /${TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4}（IPv4）与 /${TRUSTED_PROXY_MIN_PREFIX_BITS.ipv6}（IPv6）`

/**
 * 单条目校验：返回空串=通过，否则为可直接展示的原因。
 * 裸 IP 视为 /32 或 /128，宽度恒合法。
 * 模块内实现细节：对外只暴露整列入口（trustedProxyRangesError /
 * trustedProxyReferencedRangesError）——绕过条数门直连单条校验的面不该存在。
 */
const trustedProxyRangeError = (rawValue: string): string => {
  const value = rawValue.trim()
  if (!value) return '不能为空'
  if (!isValidCidr(value)) return '不是合法的 IP 或 CIDR'
  const [address = '', bitsText] = value.split('/')
  const isIpv6 = address.includes(':')
  const bits = bitsText === undefined ? (isIpv6 ? 128 : 32) : Number(bitsText)
  // v4-mapped（::ffff:a.b.c.d）按等价 v4 判宽：mapped /96 折算即 0.0.0.0/0，
  // 位数 <96 覆盖整个 v4-mapped 空间——后端同判据必然拒绝（主机位变体曾
  // 绕过全空间门，前端不得静默放行）。
  const mapped = isIpv6 ? mappedV4Prefix(address, bits) : null
  if (mapped) {
    if (mapped.network === '0.0.0.0' && (mapped.bits === 0 || mapped.bits === 8)) return '覆盖全部地址空间，等同信任任意来源'
    if (mapped.bits < TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4) return MIN_PREFIX_BITS_MESSAGE
    return ''
  }
  const canonical = trustedProxyPrefixKey(value)
  if (canonical !== null && ALL_SPACE_PREFIXES.some((prefix) => trustedProxyPrefixKey(prefix) === canonical)) {
    return '覆盖全部地址空间，等同信任任意来源'
  }
  if (bitsText === undefined) return ''
  const minBits = isIpv6 ? TRUSTED_PROXY_MIN_PREFIX_BITS.ipv6 : TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4
  if (bits < minBits) return MIN_PREFIX_BITS_MESSAGE
  return ''
}

/**
 * 整列表校验：返回空串=全部通过，否则为一条「逐项点名」的汇总文案
 * （保存门与行内提示共用，避免两处文案漂移）。
 */
export const trustedProxyRangesError = (values: readonly string[]): string => {
  const problems = values
    .map((value) => ({ value: value.trim(), error: trustedProxyRangeError(value) }))
    .filter((item) => item.error !== '')
  const parts = problems.map((item) => `${item.value || '(空)'}（${item.error}）`)
  if (values.length > TRUSTED_PROXY_MAX_INLINE_ENTRIES) {
    parts.push(`内联网段最多 ${TRUSTED_PROXY_MAX_INLINE_ENTRIES} 条（当前 ${values.length} 条），超出部分请存为地址列表后引用`)
  }
  return parts.length === 0 ? '' : `受信网段不可用：${parts.join('；')}`
}

/**
 * 单个请求头校验：返回空串=通过。后端按原始值匹配字符集（不去空格），
 * 故这里同样不做 trim——带尾随空格的输入在后端必然 400。
 * 模块内实现细节：对外只暴露整组入口 trustedProxyHeadersError。
 */
const trustedProxyHeaderError = (rawValue: string): string =>
  TRUSTED_PROXY_HEADER_PATTERN.test(rawValue) ? '' : '非法请求头名（仅允许字母/数字/连字符，1-64 字符）'

/**
 * 整组请求头校验：空串=通过，否则为「逐项点名」的汇总文案。
 * 条数按**小写去重后**的条数判定（后端 normalizeTrustedProxyHeaders 先
 * strings.ToLower 去重、再判 len(normalized) > 8）；按原始条数判会把后端
 * 必然接受的配置硬拦（9 条含 1 条大小写重复 → 归一为 8 条）。
 * 字符集仍逐条点名：后端在去重前对每一条做字符集校验。
 */
export const trustedProxyHeadersError = (values: readonly string[]): string => {
  const parts = values
    .map((value) => ({ value, error: trustedProxyHeaderError(value) }))
    .filter((item) => item.error !== '')
    .map((item) => `${item.value || '(空)'}（${item.error}）`)
  const uniqueCount = new Set(values.map((value) => value.toLowerCase())).size
  if (uniqueCount > TRUSTED_PROXY_MAX_HEADERS) {
    const merged = uniqueCount < values.length ? '，重复项已合并' : ''
    parts.push(`最多 ${TRUSTED_PROXY_MAX_HEADERS} 条（去重后 ${uniqueCount} 条${merged}）`)
  }
  return parts.length === 0 ? '' : `受信代理请求头不可用：${parts.join('；')}`
}

/**
 * 总量门：内联 ∪ 引用展开 ≤ 2000（与后端 `trustedProxyTotalGate` 同口径）。
 *
 * 后端按「规范化前缀集合大小」判定——同一网段既内联又出现在引用名单时只计
 * 一次；按条目数累加会把实际展开集合远小于上限的合法载荷拒掉。引用面的条目
 * 原文来自 `GET /security/ip-lists/:id`（`values`）；尚未拉取或拉取失败时
 * （`null`）只能按 `entryCount` 估算，且**无法参与去重**——多份互相重叠的
 * 名单会被逐份累加，估算值可能远大于真实并集。
 *
 * 因此硬门只拦「可证超限」两种形态：①已解析并集已超上限；②某份未加载名单
 * 自身条数已超上限（任何并集都至少包含它）。其余含估算项的形态一律降级为
 * 非阻断提示（`trustedProxyTotalWarning`），由后端去重判定兜底——前端不得以
 * 估算数字否掉后端会接受的配置。
 */
export interface TrustedProxyReferencedEntries {
  /** 名单条目原文；null = 尚未拉取或拉取失败（按 entryCount 计入且无法去重）。 */
  readonly values: readonly string[] | null
  /** 列表条数缓存（/security/ip-lists 的 entry_count）；values 已知时忽略。 */
  readonly entryCount: number
}

/**
 * 引用名单条目的行内校验：与内联网段复用同一 `trustedProxyRangeError`
 * （最小 /8、/29 与全空间形态，含 v4-mapped 归一），并按名单名逐项点名。
 * 未加载/加载失败的名单不参与（保存由后端兜底），避免把未知当非法。
 */
export const trustedProxyReferencedRangesError = (
  referenced: readonly (TrustedProxyReferencedEntries & { readonly name: string })[],
): string => {
  const problems: string[] = []
  for (const ref of referenced) {
    if (ref.values === null) continue
    for (const value of ref.values) {
      const error = trustedProxyRangeError(value)
      if (error) problems.push(`引用名单「${ref.name}」：${value.trim() || '(空)'}（${error}）`)
    }
  }
  return problems.length === 0 ? '' : `受信网段不可用：${problems.join('；')}`
}

/** 展开规模（并集口径）。referenced 含与内联重叠的键，与后端错误文案同构。 */
interface TrustedProxyExpansion {
  /** 已解析网段的并集大小（可证事实；硬门只用这个与单份上限判定）。 */
  readonly resolvedUnion: number
  /** 估算合计 = resolvedUnion + unresolved（含无法去重的按条数累加项，仅供提示）。 */
  readonly union: number
  readonly inline: number
  readonly referenced: number
  /** 未能去重、按 entryCount 计入的条数（>0 时文案须声明为估算）。 */
  readonly unresolved: number
  /** 未加载引用中单份最大 entryCount（单份自身超上限即可证整体超限）。 */
  readonly maxUnresolvedEntryCount: number
}

/** IPv4 字节按前缀长度掩码成网络地址串（主机位归零）。 */
const maskV4Octets = (octets: readonly number[], bits: number): string =>
  octets
    .map((octet, index) => {
      const keep = bits - index * 8
      if (keep <= 0) return 0
      if (keep >= 8) return octet
      return octet & (0xff << (8 - keep)) & 0xff
    })
    .join('.')

/** IPv6 十六进制组按前缀长度掩码（主机位归零）。 */
const maskV6Groups = (groups: readonly number[], bits: number): readonly number[] =>
  groups.map((group, index) => {
    const keep = bits - index * 16
    if (keep <= 0) return 0
    if (keep >= 16) return group
    return group & (0xffff << (16 - keep)) & 0xffff
  })

/**
 * v4-mapped 前缀归一（与后端 `TrustedProxyPrefixCanonical` 同口径）：返回等价
 * v4 网络与位数——`::ffff:203.0.113.7/120` → `203.0.113.0/24`，
 * `::ffff:0.0.0.1/96` → `0.0.0.0/0`；位数 <96 的映射写法覆盖整个
 * v4-mapped 空间（=全部 IPv4），同样归一为 `0.0.0.0/0`。
 * 非映射形态返回 null（主机位不影响全空间/最小前缀判定，调用方自行掩码）。
 */
const mappedV4Prefix = (address: string, bits: number): { readonly network: string; readonly bits: number } | null => {
  const groups = parseIPv6Groups(address.trim(), { allowZone: false })
  if (!groups) return null
  const isMapped =
    groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff
  if (!isMapped) return null
  if (bits < 96) return { network: '0.0.0.0', bits: 0 }
  const octets = [(groups[6] ?? 0) >> 8, (groups[6] ?? 0) & 0xff, (groups[7] ?? 0) >> 8, (groups[7] ?? 0) & 0xff]
  const v4Bits = bits - 96
  return { network: maskV4Octets(octets, v4Bits), bits: v4Bits }
}

/**
 * 规范化前缀键（裸 IP 补 /32 或 /128；主机位掩码归零；v4-mapped 折成等价
 * v4）：只用于前端并集判定，故不必逐字等于 Go 的 `netip.Prefix.String()`
 * ——只需让**同一网段的任何书写形态**（含 mapped 与主机位变体）落到同一键上，
 * 与后端 `trustedProxyPrefixKeys` 的去重口径一致（否则前端并集会虚高，
 * 把后端判为合法的 2000 条配置硬拦）。
 * 无法解析返回 null（非法形态由网段判据逐条点名，这里不计入并集）。
 * 模块内实现细节：键形态不对外承诺，经 trustedProxyExpansion 间接断言。
 */
const trustedProxyPrefixKey = (rawValue: string): string | null => {
  const value = rawValue.trim()
  if (!value) return null
  const slash = value.indexOf('/')
  const address = slash < 0 ? value : value.slice(0, slash)
  const bitsText = slash < 0 ? '' : value.slice(slash + 1)
  const v4 = parseIPv4Octets(address, { allowLeadingZeros: true })
  if (v4) {
    const bits = bitsText === '' ? 32 : Number(bitsText)
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null
    return `v4:${maskV4Octets(v4, bits)}/${bits}`
  }
  const v6 = parseIPv6Groups(address.trim(), { allowZone: false })
  if (!v6) return null
  const bits = bitsText === '' ? 128 : Number(bitsText)
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null
  const mapped = mappedV4Prefix(address, bits)
  if (mapped) return `v4:${mapped.network}/${mapped.bits}`
  return `v6:${maskV6Groups(v6, bits).join(':')}/${bits}`
}

/** 受信网段展开规模：内联 ∪ 引用展开（规范化前缀去重），与后端判定同口径。 */
export const trustedProxyExpansion = (
  inlineValues: readonly string[],
  referenced: readonly TrustedProxyReferencedEntries[],
): TrustedProxyExpansion => {
  const union = new Set<string>()
  for (const value of inlineValues) {
    const key = trustedProxyPrefixKey(value)
    if (key) union.add(key)
  }
  const inline = union.size
  let referencedKeys = 0
  let unresolved = 0
  let maxUnresolvedEntryCount = 0
  for (const ref of referenced) {
    if (ref.values === null) {
      const count = Math.max(0, ref.entryCount)
      unresolved += count
      if (count > maxUnresolvedEntryCount) maxUnresolvedEntryCount = count
      continue
    }
    const keys = new Set<string>()
    for (const value of ref.values) {
      const key = trustedProxyPrefixKey(value)
      if (key) keys.add(key)
    }
    referencedKeys += keys.size
    for (const key of keys) union.add(key)
  }
  const resolvedUnion = union.size
  return {
    resolvedUnion,
    union: resolvedUnion + unresolved,
    inline,
    referenced: referencedKeys + unresolved,
    unresolved,
    maxUnresolvedEntryCount,
  }
}

/** 硬门文案（可证超限形态共用）：与后端错误文案同结构。 */
const totalExceededMessage = (union: number, inline: number, referencedCount: number, unresolved: number): string => {
  const estimate = unresolved > 0
    ? `；其中 ${unresolved} 条按条数估算（引用名单条目未加载，重叠网段未参与去重）`
    : ''
  return `受信网段总数超过 ${TRUSTED_PROXY_MAX_TOTAL_ENTRIES} 上限（去重后合计 ${union}：内联 ${inline} + 引用展开 ${referencedCount}；重叠网段只计一次${estimate}），请收窄内联网段或减少引用列表`
}

/** 总量门：返回空串=通过，否则为可直接展示的汇总文案（与后端文案同结构）。 */
export const trustedProxyTotalError = (
  inlineValues: readonly string[],
  referenced: readonly TrustedProxyReferencedEntries[],
): string => {
  const { resolvedUnion, union, inline, referenced: referencedCount, unresolved, maxUnresolvedEntryCount } =
    trustedProxyExpansion(inlineValues, referenced)
  // 只拦可证超限：已解析并集超限，或某份未加载名单自身已超上限。多份未加载
  // 名单互相重叠时按条数累加的值只是上界估计，不能据此否掉合法配置。
  if (resolvedUnion <= TRUSTED_PROXY_MAX_TOTAL_ENTRIES && maxUnresolvedEntryCount <= TRUSTED_PROXY_MAX_TOTAL_ENTRIES) {
    return ''
  }
  return totalExceededMessage(union, inline, referencedCount, unresolved)
}

/**
 * 总量提示（非阻断）：估算合计越过上限、但无法证明真实并集超限时返回文案，
 * 否则空串。消费方据此提示后**继续保存**，最终以后端去重判定为准。
 */
export const trustedProxyTotalWarning = (
  inlineValues: readonly string[],
  referenced: readonly TrustedProxyReferencedEntries[],
): string => {
  const { resolvedUnion, union, inline, referenced: referencedCount, unresolved, maxUnresolvedEntryCount } =
    trustedProxyExpansion(inlineValues, referenced)
  if (unresolved === 0 || union <= TRUSTED_PROXY_MAX_TOTAL_ENTRIES) return ''
  // 可证超限由硬门报错，不重复提示
  if (resolvedUnion > TRUSTED_PROXY_MAX_TOTAL_ENTRIES || maxUnresolvedEntryCount > TRUSTED_PROXY_MAX_TOTAL_ENTRIES) return ''
  return `受信网段合计约 ${union} 条，可能超过 ${TRUSTED_PROXY_MAX_TOTAL_ENTRIES} 上限（内联 ${inline} + 引用展开 ${referencedCount}；其中 ${unresolved} 条来自条目未加载的引用列表，按条数估算且未参与去重）。仍可保存，最终以服务端按去重后的网段集合判定为准`
}
