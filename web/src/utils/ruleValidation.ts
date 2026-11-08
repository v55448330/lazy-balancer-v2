import { upstreamDedupeKey } from './upstreamKeys.ts'
import { isValidV4, isValidV6 } from './ipAddress.ts'
import { tSafe as t } from '../i18n/tSafe.ts'

type PathUpstreamInput = {
  readonly protocol: 'http' | 'https'
  readonly address: string
  readonly port: number
  readonly weight: number
}

type PathRuleInput = {
  readonly match_type: 'prefix' | 'exact'
  readonly path: string
  readonly upstream_path?: string
  readonly sort_order: number
  readonly upstreams: readonly PathUpstreamInput[] | null
  // 直接返回/301 跳转（2026-10-10）：''=转发（现状）/static/redirect
  readonly response_mode?: '' | 'static' | 'redirect' | 'forward'
  readonly response_status?: number
  readonly response_body?: string
  readonly response_content_type?: string
  readonly redirect_to?: string
}
// isValidHostName 与后端 isValidHost（internal/handlers/helpers.go）逐条对齐的
// 主机名校验：标签字符 [A-Za-z0-9_-]、标签首尾须字母或数字、
// 单标签 ≤63、总长 ≤253。前端方向不放宽到 IP 字面量（SNI 语义不需要）。
export const isValidHostName = (value: string): boolean => {
  if (value === '' || value.length > 253) return false
  // 全数字点分串（999.1.1.1、1.2.3.4.5）并非合法 IP，却满足标签字符表：
  // 与后端同口径拒绝，避免前端放行、保存时才被 400 拦下。
  if (value.includes('.') && value.split('.').every((part) => /^\d+$/.test(part))) return false
  return value.split('.').every((part) => {
    if (part === '' || part.length > 63) return false
    if (!/^[A-Za-z0-9_-]+$/.test(part)) return false
    return /^[A-Za-z0-9]/.test(part) && /[A-Za-z0-9]$/.test(part)
  })
}


// 地址/CIDR 解析单源在 utils/ipAddress（写侧严格口径，拒前导零与 %zone）。
// M32：与后端 internal/handlers/rule_features.go:323-350 同源的路径归一键——
// prefix 渲染为 [路径, 路径/*] 双 matcher 故尾部的 / 与 * 一并剥离（Go
// TrimRight cutset 语义），exact 仅剥尾 /；剥空回退 "/"。
export const canonicalPathKey = (matchType: 'prefix' | 'exact', raw: string): string => {
  const trimmed = raw.trim()
  const canonical = matchType === 'prefix' ? trimmed.replace(/[*\/]+$/, '') : trimmed.replace(/\/+$/, '')
  return canonical === '' ? '/' : canonical
}

/**
 * 同类型路径查重键：与后端 rule_features.go 同口径——prefix 用归一键
 * （剥尾 / 与 *），exact 用 trim 后**原串**（不剥尾 /：`/a` 与 `/a/` 是两条独立
 * exact matcher，后端接受并渲染）。跨类型遮蔽互查仍用 canonicalPathKey。
 */
export const pathDuplicateKey = (matchType: 'prefix' | 'exact', raw: string): string =>
  `${matchType}:${matchType === 'prefix' ? canonicalPathKey('prefix', raw) : raw.trim()}`


// 直接返回的常用状态码白名单（与后端 validStaticResponseStatuses 同源）。
// 数组形态 + 标准全称单源自此导出——编辑器下拉（PathRulesEditor）只 import，
// 禁止在组件侧再抄一份（曾双源：下拉可选但保存被拒）。
export const STATIC_RESPONSE_STATUSES: readonly number[] = [200, 201, 204, 400, 401, 403, 404, 410, 500, 502, 503]

export const STATIC_RESPONSE_STATUS_REASONS: Readonly<Record<number, string>> = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 410: 'Gone',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
}

const STATIC_RESPONSE_STATUS_SET: Readonly<Record<number, true>> = Object.fromEntries(
  STATIC_RESPONSE_STATUSES.map((code) => [code, true]),
)
/**
 * 上游路径改写单条判定（与后端 validateRuleFeatures 同口径）：空串=原样转发；
 * 非空须以 / 开头且不含空格 ? #（query/fragment 不允许）。路径编辑器与整组
 * 校验共用，避免两处口径漂移。
 */
export const upstreamPathRuleError = (upstreamPath: string): string | null => {
  if (!upstreamPath) return null
  if (!upstreamPath.startsWith('/')) return t('common.app.ruleValidation.pathLeadingSlash')
  if (/[\s?#]/.test(upstreamPath)) return t('common.app.ruleValidation.upstreamPathSpaceChars')
  return null
}

/**
 * 单条路径规则的**字段级**错误（不含行号，也不含整组判定——重复/遮蔽由
 * validatePathRules 负责）。组级校验与行内红框共用此函数：两套实现曾漂移到
 * 「组级拒空串、行级放行空串」，用户清空路径后行内无红框、点保存才整组被拒。
 * 文案不带行号，调用方按需加「第 N 条路径：」前缀（组级）或原样展示（行内）。
 */
export const pathRuleError = (rule: PathRuleInput): string | null => {
  // 与后端同口径：前缀校验用原始串（后端 HasPrefix 在 TrimSpace 之前）
  if (!rule.path.startsWith('/')) return t('common.app.ruleValidation.pathLeadingSlash')
  if (/[*?{}]/.test(rule.path)) return t('common.app.ruleValidation.pathWildcardChars')
  const upstreamError = upstreamPathRuleError(rule.upstream_path ?? '')
  if (upstreamError) return t('common.app.ruleValidation.upstreamPathWrapped', { error: upstreamError })
  return null
}

export const validatePathRules = (rules: readonly PathRuleInput[]): string | null => {
  const seen = new Map<string, number>()
  // 同后端：prefix 与 exact 在同一路径上并存时，路由按 SortOrder 首条终结
  // 匹配，靠后的一条必被遮蔽成死规则——保存前整组拒绝（跨类型互查）。
  const seenPrefixRoots = new Map<string, number>()
  const seenExactNorms = new Map<string, number>()
  for (const [index, rule] of rules.entries()) {
    const rowNumber = index + 1
    // 字段级错误优先于组级（重复/遮蔽）——与行内红框同一判据、同一文案。
    const fieldError = pathRuleError(rule)
    if (fieldError) return t('common.app.ruleValidation.rowPathError', { row: rowNumber, error: fieldError })
    const canonical = canonicalPathKey(rule.match_type, rule.path)
    const duplicateKey = pathDuplicateKey(rule.match_type, rule.path)
    const seenAt = seen.get(duplicateKey)
    if (seenAt !== undefined) return t('common.app.ruleValidation.rowDuplicate', { row: rowNumber, other: seenAt, path: rule.path.trim() })
    seen.set(duplicateKey, rowNumber)
    if (rule.match_type === 'prefix') {
      const shadowAt = seenExactNorms.get(canonical)
      if (shadowAt !== undefined) return t('common.app.ruleValidation.rowShadow', { row: rowNumber, other: shadowAt })
      seenPrefixRoots.set(canonical, rowNumber)
    } else {
      const shadowAt = seenPrefixRoots.get(canonical)
      if (shadowAt !== undefined) return t('common.app.ruleValidation.rowShadow', { row: rowNumber, other: shadowAt })
      seenExactNorms.set(canonical, rowNumber)
    }
    // 直接返回/301 跳转（2026-10-10 用户裁定）：与后端 validateRuleFeatures 同口径
    // 'forward' 为 UI 选择器哨兵（el-select 空串选项不显示标签），与 '' 同义
    const responseMode = rule.response_mode === 'forward' ? '' : (rule.response_mode ?? '')
    if (responseMode === 'static') {
      const status = rule.response_status || 200
      if (!STATIC_RESPONSE_STATUS_SET[status]) return t('common.app.ruleValidation.staticStatusNotCommon', { row: rowNumber, status })
      if ([...rule.response_body ?? ''].length > 64) return t('common.app.ruleValidation.responseBodyTooLong', { row: rowNumber })
      const ct = rule.response_content_type ?? ''
      if (ct !== '' && ct !== 'text/plain' && ct !== 'application/json' && ct !== 'text/html') return t('common.app.ruleValidation.responseFormatLimited', { row: rowNumber })
      if (rule.redirect_to) return t('common.app.ruleValidation.staticRedirectConflict', { row: rowNumber })
      if (rule.upstreams !== null || rule.upstream_path) return t('common.app.ruleValidation.staticUpstreamConflict', { row: rowNumber })
      continue
    }
    if (responseMode === 'redirect') {
      const target = rule.redirect_to ?? ''
      if (!target.trim()) return t('common.app.ruleValidation.redirectAddressRequired', { row: rowNumber })
      // 形状校验查原串（与后端 rule_features.go 同位）——
      // 此前 trim 后判定，" http://x" 前端放行、后端按原串 400，口径分叉。
      // eslint-disable-next-line no-control-regex
      if (/[\x00-\x1f\x7f]/.test(target)) return t('common.app.ruleValidation.redirectInvalidChars', { row: rowNumber })
      if (!target.startsWith('/') && !target.startsWith('http://') && !target.startsWith('https://')) return t('common.app.ruleValidation.redirectAbsoluteRequired', { row: rowNumber })
      // 与后端 rule_features.go:464 同句——301 跳转与响应内容互斥
      //（UI 正常切换模式会清空内容，此处防回读载荷/残留表单态双携，后端恒 400）。
      if (rule.response_body || rule.response_content_type) return t('common.app.ruleValidation.redirectResponseConflict', { row: rowNumber })
      if (rule.upstreams !== null || rule.upstream_path) return t('common.app.ruleValidation.redirectUpstreamConflict', { row: rowNumber })
      continue
    }
    if (responseMode) return t('common.app.ruleValidation.responseModeInvalid', { row: rowNumber })
    if (rule.upstreams === null) continue
    if (rule.upstreams.length === 0) return t('common.app.ruleValidation.upstreamRequired', { row: rowNumber })

    // 自定义上游池：与后端 rule_features.go 同口径的三项池级
    // 校验——http/https 混布（同池 reverse_proxy 池级 TLS 传输下 http 上游静默
    // 全灭）、主机形态（后端 isValidHost：IP 字面量或主机名）、host:port 去重
    // （重复条使权重翻倍、均衡语义静默漂移）。此前只校验空/端口/权重，非法行
    // 行内无错、点保存才被全局 toast 拒绝且不定位到行。
    const poolProtocols = new Set(rule.upstreams.map((upstream) => (upstream.protocol || 'http')))
    if (poolProtocols.has('http') && poolProtocols.has('https')) {
      return t('common.app.ruleValidation.upstreamMixedProtocol', { row: rowNumber })
    }
    const seenHostPorts = new Set<string>()
    for (const upstream of rule.upstreams) {
      const address = upstream.address.trim()
      if (!address) return t('common.app.ruleValidation.upstreamAddressRequired', { row: rowNumber })
      // 上游地址接受 IP 字面量与主机名（isValidHostName 有意排除 IP 字面量——
      // SNI 语义不需要，上游地址需要），与后端 isValidHost 同形。
      if (!(isValidV4(address) || isValidV6(address) || isValidHostName(address))) {
        return t('common.app.ruleValidation.upstreamHostInvalid', { row: rowNumber, address })
      }
      if (upstream.port < 1 || upstream.port > 65535) return t('common.app.ruleValidation.upstreamPortInvalid', { row: rowNumber })
      const protocol = (upstream.protocol ?? '') as string
      if (protocol !== '' && protocol !== 'http' && protocol !== 'https') {
        return t('common.app.ruleValidation.upstreamProtocolLimited', { row: rowNumber })
      }
      if (upstream.weight < 1) return t('common.app.ruleValidation.upstreamWeightPositive', { row: rowNumber })
      // 与后端 upstreamDedupeHost 同口径：IP 按地址语义归一（IPv6 等价写法
      // 是同一后端），主机名 lower+trim；后端写侧是权威门。
      const hostPort = upstreamDedupeKey(address, upstream.port)
      if (seenHostPorts.has(hostPort)) return t('common.app.ruleValidation.upstreamDuplicate', { row: rowNumber, hostPort })
      seenHostPorts.add(hostPort)
    }
  }
  return null
}

// ── 数值边界单源（表单控件 ↔ 后端写侧门）──
// 控件边界此前各自写死且与写侧门漂移（间隔 min 5 vs 后端 ≥1、超时 max 30 vs
// 后端无上限、重试间隔 max 10000 vs 后端 60000、最大连接 max 100000 vs 后端
// 无上限）——API/MCP/导入写入的合法值在向导中被 spinner 静默夹回 UI 边界。
// 后端口径：internal/handlers/handlers.go（间隔/超时 ≥1，无上限）、
// rule_features.go（重试窗口/间隔 [-1|0, 60000]）、max_connections ≥0 无上限。
// el-input-number 只在交互（spinner/输入失焦）时夹紧，库值超界回显不被改写。
export const RULE_NUMERIC_LIMITS = {
  healthCheckIntervalMin: 1,
  healthCheckTimeoutMin: 1,
  tcpTryIntervalMax: 60000,
  maxConnectionsMin: 0,
} as const
