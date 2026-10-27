/**
 * OIDC 回跳 fragment 的接收契约（App.vue / Login.vue 共用单源）。
 *
 * 后端回调成功以 `#/oidc/callback?token=…&expires_at=…&return_to=…` 302 回前端，
 * 令牌不发给服务器。这条 fragment 通道本身**没有任何来源证明**：任意链接都能
 * 携带一条别人的有效 JWT，让受害者浏览器把会话切成攻击者的账号（登录 CSRF /
 * 会话替换）。本模块给出前台能做到的三道门：
 *
 * 1. **来源绑定（nonce 往返）**：发起登录时本标签页生成 nonce 写入
 *    sessionStorage，并把 nonce 塞进 `return_to`（页面键 + `app_nonce` 查询项），
 *    后端原样回显到回调 fragment 的 `return_to`。回调侧只有命中同值才接受令牌
 *    ——构造链接不可能知道受害者浏览器里的 nonce。
 * 2. **载荷过滤**：只接受 `auth_method === 'oidc'` 的令牌，且 fragment 的
 *    `expires_at` 必须与令牌 `exp` 一致（本地账号令牌、改期令牌一律拒绝）。
 *    载荷未验签，仅作形状过滤——令牌真伪仍由服务端 /users/me 决定。
 * 3. **失败文案白名单**：fragment 的 `error` 原文不可信（任意链接可在面板内
 *    投放提示文案），只透出后端固定文案集合与 RFC 6749 标准错误码，其余归一
 *    为通用文案。
 */

/** 本标签页发起 OIDC 登录的 nonce 键（sessionStorage）。 */
export const OIDC_APP_NONCE_KEY = 'oidc_app_nonce'
/** `return_to` 里承载 nonce 的查询项名。 */
const OIDC_APP_NONCE_PARAM = 'app_nonce'
/** 未命中白名单时统一呈现的失败文案。 */
const OIDC_GENERIC_ERROR = '登录失败，请重新登录'

/** 生成 32 位十六进制 nonce（crypto 不可用时退化为时间+随机，仅作一次性标记）。 */
export const createOidcAppNonce = (): string => {
  const bytes = new Uint8Array(16)
  const cryptoApi = globalThis.crypto
  if (cryptoApi && typeof cryptoApi.getRandomValues === 'function') {
    cryptoApi.getRandomValues(bytes)
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256)
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** 把 nonce 并入站内回跳路径（`/rules` → `/rules?app_nonce=<nonce>`）。 */
export const withOidcAppNonce = (returnTo: string, nonce: string): string => {
  if (!nonce) return returnTo
  const separator = returnTo.includes('?') ? '&' : '?'
  return `${returnTo}${separator}${OIDC_APP_NONCE_PARAM}=${encodeURIComponent(nonce)}`
}

/**
 * 从回跳路径拆出「页面键 + nonce」。后端只放行站内相对路径，此处再按
 * 查询串剥掉 nonce——页面导航不得带上本轮登录的内部参数。
 */
export const splitOidcReturnTo = (returnTo: string): { path: string; nonce: string } => {
  const at = returnTo.indexOf('?')
  if (at < 0) return { path: returnTo, nonce: '' }
  const path = returnTo.slice(0, at)
  const params = new URLSearchParams(returnTo.slice(at + 1))
  const nonce = params.get(OIDC_APP_NONCE_PARAM) ?? ''
  params.delete(OIDC_APP_NONCE_PARAM)
  const rest = params.toString()
  return { path: rest ? `${path}?${rest}` : path, nonce }
}

const decodeSegment = (segment: string): string => {
  const normalized = segment.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

/** 解出 JWT 载荷（不验签）。非三段/非 JSON 载荷返回 null。 */
const decodeJwtPayload = (token: string): Record<string, unknown> | null => {
  const segments = token.split('.')
  if (segments.length !== 3) return null
  try {
    const parsed: unknown = JSON.parse(decodeSegment(segments[1]))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    return null
  }
}

type OidcTokenRejection =
  | 'malformed'        // 不是三段式 JWT / 载荷不可解析
  | 'not-oidc'         // 载荷未标记 auth_method=oidc（例如他人本地账号令牌）
  | 'expiry-mismatch'  // fragment expires_at 与令牌 exp 不一致
  | 'expired'          // 令牌已过期
  | 'nonce-missing'    // 本浏览器没有发起过登录（或已消费）
  | 'nonce-mismatch'   // 回调 nonce 与本次发起不一致（构造链接）

type OidcTokenVerdict = { ok: true; username: string } | { ok: false; reason: OidcTokenRejection }

/** 各拒绝原因的固定用户文案。 */
export const OIDC_REJECTION_TEXT: Record<OidcTokenRejection, string> = {
  malformed: '登录链接无效，请重新登录',
  'not-oidc': '登录链接不是本次单点登录签发的令牌，已拒绝',
  'expiry-mismatch': '登录链接已损坏，请重新登录',
  expired: '登录链接已过期，请重新登录',
  'nonce-missing': '登录链接已失效，请重新登录',
  'nonce-mismatch': '登录链接与本次登录不匹配，已拒绝',
}

/**
 * 判定 fragment 携带的令牌能否被本浏览器接受。
 *
 * 调用方在判定为 ok 时方可写会话；拒绝时不得触碰现有会话（localStorage/token）。
 * `expectedNonce` 来自 sessionStorage，消费后必须删除（一次性）。
 */
export const verifyOidcCallbackToken = (input: {
  readonly token: string
  readonly expiresAt: string
  readonly nonce: string
  readonly expectedNonce: string
  readonly now?: number
}): OidcTokenVerdict => {
  const payload = decodeJwtPayload(input.token)
  if (!payload) return { ok: false, reason: 'malformed' }
  if (payload.auth_method !== 'oidc') return { ok: false, reason: 'not-oidc' }
  const tokenExp = payload.exp
  const fragmentExp = Number(input.expiresAt)
  if (typeof tokenExp !== 'number' || !Number.isFinite(tokenExp) || !Number.isFinite(fragmentExp) || tokenExp !== fragmentExp) {
    return { ok: false, reason: 'expiry-mismatch' }
  }
  const now = input.now ?? Math.floor(Date.now() / 1000)
  if (tokenExp <= now) return { ok: false, reason: 'expired' }
  if (!input.expectedNonce) return { ok: false, reason: 'nonce-missing' }
  if (input.nonce !== input.expectedNonce) return { ok: false, reason: 'nonce-mismatch' }
  return { ok: true, username: typeof payload.username === 'string' ? payload.username : '' }
}

/** 后端 fail() 会发出的固定文案集合（与 auth_oidc.go 的 fail 调用逐条对表，
 *  web/tests/oidcCallback.spec.ts 有跨栈钉测防漂移）。 */
const OIDC_BACKEND_MESSAGES: readonly string[] = [
  'OIDC 配置读取失败',
  'OIDC 未启用',
  '登录请求过于频繁，请稍后再试',
  'OIDC 服务不可达，请检查配置',
  '生成状态失败',
  '生成 nonce 失败',
  '登录状态无效或已过期,请重新登录',
  '登录状态已过期,请重新登录',
  '登录状态与当前浏览器不匹配,请重新登录',
  'OIDC 令牌交换失败，请稍后重试',
  '提供商未返回 id_token',
  'ID Token 校验失败，请稍后重试',
  '解析用户信息失败',
  'nonce 不匹配(疑似重放)',
  '提供商未返回用户标识(sub)',
  '账号不在允许登录的范围，请联系管理员',
  '账号已被禁用',
  '查询用户失败',
  '创建 OIDC 用户失败',
  '签发登录令牌失败',
]

/** RFC 6749 / OIDC Core 标准错误码 → 固定中文文案。 */
const OIDC_STANDARD_ERRORS: Record<string, string> = {
  invalid_request: '请求无效',
  unauthorized_client: '客户端无权使用该方式登录',
  access_denied: '授权被拒绝',
  unsupported_response_type: '认证服务不支持该登录方式',
  invalid_scope: '授权范围无效',
  server_error: '认证服务内部错误',
  temporarily_unavailable: '认证服务暂时不可用',
  interaction_required: '需要交互式登录',
  login_required: '需要重新登录',
  account_selection_required: '需要选择账号',
  consent_required: '需要授权确认',
  invalid_grant: '授权已失效，请重新登录',
}

/**
 * fragment/query 里的 `error` 原文 → 可展示文案。
 *
 * 只透出后端固定文案与标准错误码；未知文案（任意链接可投放）归一为通用文案。
 * 不做原文截断回显——截断后的陌生文案仍属不可信内容。
 */
export const oidcErrorMessage = (raw: string): string => {
  const text = raw.trim()
  if (!text) return OIDC_GENERIC_ERROR
  // 提供商标注形态「提供商拒绝授权: <标准码>」（后端 fallback 只放行标准码）——
  // 后缀仍按标准码表翻译，表外的后缀不原文透出。
  const providerPrefix = '提供商拒绝授权'
  if (text === providerPrefix) return OIDC_STANDARD_ERRORS.access_denied
  if (text.startsWith(`${providerPrefix}: `)) {
    const code = text.slice(providerPrefix.length + 2).trim().toLowerCase()
    return Object.prototype.hasOwnProperty.call(OIDC_STANDARD_ERRORS, code) ? OIDC_STANDARD_ERRORS[code] : OIDC_STANDARD_ERRORS.access_denied
  }
  const code = text.toLowerCase()
  // 词表是普通对象：`constructor`/`toString` 等原型键必须先过 hasOwn，
  // 否则返回 Object.prototype 上的函数（模板渲染函数源码）。
  if (Object.prototype.hasOwnProperty.call(OIDC_STANDARD_ERRORS, code)) return OIDC_STANDARD_ERRORS[code]
  if (OIDC_BACKEND_MESSAGES.includes(text)) return text
  return OIDC_GENERIC_ERROR
}
