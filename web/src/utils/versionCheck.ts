/**
 * 面板「检查更新」的版本目录消费层：官网 versions.json 的形状、版本比较纯函数、
 * 远端拉取（5s 超时、失败一律 null 静默——装饰性检查零打扰，console 零噪音）。
 * 数据源由官网 GitHub Pages 提供（Access-Control-Allow-Origin: *），按数组序排列
 * （新在前）；channel 取值 stable / beta / retired， retired 条目不参与更新判定。
 */

/** 官网版本目录地址（与 lazy-balancer-site 发版链路同源）。 */
export const VERSIONS_URL = 'https://www.lazybalancer.org/versions.json'

/** versions.json 的单条版本目录像（仅声明消费面字段，其余原样忽略）。 */
export interface RemoteVersionEntry {
  version: string
  channel: string
  channel_label?: string
  theme?: string
  notes?: string[]
  hints?: string[]
}

interface RemoteVersionsPayload {
  updated_at?: string
  versions?: unknown
}

/** 解析后的版本：数值三元组 + 预发布段（`-` 后缀，如 `beta`、`beta.2`；正式版为 null）。 */
interface ParsedVersion {
  major: number
  minor: number
  patch: number
  prerelease: string | null
}

// 预发布段必须以字母/数字开头（`v2.4.0-` 这类悬挂连字符视为畸形）。
const VERSION_PATTERN = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?$/

/** 解析 `vX.Y.Z` / `vX.Y.Z-beta[.n]`；畸形输入（含非字符串）返回 null。 */
export function parseVersion(input: string): ParsedVersion | null {
  if (typeof input !== 'string') return null
  const match = VERSION_PATTERN.exec(input.trim())
  if (match === null) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null,
  }
}

/** semver 预发布段先后：逐标识符比较，数字段按数值且小于字母段，缺段的一方更低。 */
const comparePrerelease = (a: string, b: string): number => {
  const left = a.split('.')
  const right = b.split('.')
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i]
    const y = right[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    const nx = /^\d+$/.test(x) ? Number(x) : null
    const ny = /^\d+$/.test(y) ? Number(y) : null
    if (nx !== null && ny !== null) {
      if (nx !== ny) return nx < ny ? -1 : 1
    } else if (nx !== null) {
      return -1
    } else if (ny !== null) {
      return 1
    } else if (x !== y) {
      return x < y ? -1 : 1
    }
  }
  return 0
}

/**
 * candidate 是否比 current 新。语义：
 * - 忽略 `v` 前缀与首尾空白；
 * - 同版本号下带预发布段视为预发布（v2.4.0-beta 相对 v2.4.0 不是新版本，
 *   v2.4.0 相对 v2.4.0-beta 是新版本——beta 用户能收到转正提示）；
 * - 任一侧畸形输入返回 false。
 */
export function isNewer(candidate: string, current: string): boolean {
  const cand = parseVersion(candidate)
  const cur = parseVersion(current)
  if (cand === null || cur === null) return false
  if (cand.major !== cur.major) return cand.major > cur.major
  if (cand.minor !== cur.minor) return cand.minor > cur.minor
  if (cand.patch !== cur.patch) return cand.patch > cur.patch
  if (cand.prerelease === null && cur.prerelease === null) return false
  if (cand.prerelease === null) return true
  if (cur.prerelease === null) return false
  return comparePrerelease(cand.prerelease, cur.prerelease) > 0
}

/** 目录内该渠道的最新条目（数组序=新到旧，取首个匹配；缺失返回 null）。 */
export function pickLatestChannel(versions: RemoteVersionEntry[], channel: 'stable' | 'beta'): RemoteVersionEntry | null {
  return versions.find((entry) => entry.channel === channel) ?? null
}

/**
 * 拉取官网版本目录。超时（AbortSignal.timeout）、网络失败、HTTP 非 2xx、
 * JSON 损坏、形状不符一律返回 null（静默跳过），不产生任何 console 输出。
 */
export async function fetchRemoteVersions(timeoutMs = 5000): Promise<RemoteVersionEntry[] | null> {
  try {
    const res = await fetch(VERSIONS_URL, { signal: AbortSignal.timeout(timeoutMs) })
    if (!res.ok) return null
    const payload = (await res.json()) as RemoteVersionsPayload
    if (!Array.isArray(payload?.versions)) return null
    return payload.versions.filter(
      (entry): entry is RemoteVersionEntry =>
        typeof entry === 'object' && entry !== null &&
        typeof (entry as RemoteVersionEntry).version === 'string' &&
        typeof (entry as RemoteVersionEntry).channel === 'string',
    )
  } catch {
    return null
  }
}
