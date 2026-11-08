/**
 * MFA 自助/管理端点 401 的判定单源。
 *
 * 语义：这些端点持有效 JWT 输错密码/验证码时返回 401，属「凭证错误」而非会话
 * 失效——不得弹「会话失效」并强制登出，只传播后端文案供重试。但同一路径先经
 * jwtAuth 鉴权，它发出的会话 401（`登录状态已过期，请重新登录`、`登录状态已
 * 失效，请重新登录`、`密码已修改，请重新登录`、`缺少认证信息`、`登录凭证无效`、
 * `用户不存在或已禁用`）仍是会话失效，必须继续走全局重新登录流程。
 *
 * 因此按**后端文案白名单**豁免，而不是按路径前缀豁免（原实现仅匹配路径，
 * 把 428→verify-step 窗口内的会话过期 401 误当验码错误）。
 * 文案源（internal/handlers/mfa.go）：
 * - `验证码错误`（verify-step / setup 重绑 / disable / 管理员 reset）
 * - `验证码错误次数过多，绑定已作废，请重新开始绑定`（activate 失败上限）
 * - `MFA 挑战无效或已过期，请重新登录` / `MFA 挑战已被使用，请重新登录`（登录第二步）
 *
 * 429 无需入白名单：登录后验码限流（60 秒 5 次失败 → `验证码尝试过于频繁，请稍后再试`）
 * 走全局默认分支直接透传后端文案 toast，不触发会话失效流程，也不重试原请求。
 */
export const MFA_CREDENTIAL_REJECTION_MESSAGES: readonly string[] = [
  '验证码错误',
  '验证码错误次数过多，绑定已作废，请重新开始绑定',
  'MFA 挑战无效或已过期，请重新登录',
  'MFA 挑战已被使用，请重新登录',
]

// i18n 后判定首选 message_key(稳定,与文案语言解耦);字面量仅作无键旧响应兜底。
// 键与文案母本钉测见 tests/mfaErrors.spec.ts ↔ internal/i18n/catalog_gen.go。
const MFA_CREDENTIAL_REJECTION_KEYS: readonly string[] = [
  'k_345a8c4a',
  'k_df527f47',
  'k_5c5030a7',
  'k_201b3428',
]

/**
 * 401 是否为 MFA 端点的「凭证/挑战错误」（自助 /auth/mfa/* 与管理员
 * /users/:id/mfa/reset）：是 → 调用方只传播文案；否（含会话过期文案、
 * 非 MFA 端点）→ 继续走会话失效流程。
 */
export const isMfaCredentialRejection = (
  url: string | undefined,
  status: number | undefined,
  message: string,
  messageKey?: string,
): boolean => status === 401
  && ((url ?? '').includes('/auth/mfa/') || (url ?? '').includes('/mfa/reset'))
  && (messageKey !== undefined
    ? MFA_CREDENTIAL_REJECTION_KEYS.includes(messageKey)
    : MFA_CREDENTIAL_REJECTION_MESSAGES.includes(message))
