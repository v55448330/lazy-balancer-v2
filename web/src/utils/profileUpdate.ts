/**
 * PATCH /users/me 的唯一业务 401：当前密码校验失败。
 * 同一路径的其它 401 仍是会话失效，必须继续走全局重新登录流程。
 */
// i18n:判定首选 message_key(k_9561dfdb,钉测见 tests/profileUpdate.spec.ts),
// 字面量仅作无键旧响应兜底。
export const isCurrentPasswordRejection = (
  method: string | undefined,
  url: string | undefined,
  status: number | undefined,
  message: string,
  messageKey?: string,
): boolean => status === 401
  && (messageKey !== undefined ? messageKey === 'k_9561dfdb' : message === '当前密码错误')
  && (method ?? '').toLowerCase() === 'patch'
  && /\/users\/me(\?|$)/.test(url ?? '')
