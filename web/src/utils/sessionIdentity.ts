// 请求级会话身份：登录、登出、OIDC 与换账号推进代际；同账号 MFA step-up
// 只刷新令牌，不推进代际。请求发起时记录代际，迟到的 428 据此拒绝处置新会话。
import { decodeJwtPayload } from './jwt.ts'

let sessionGeneration = 0

export const currentSessionGeneration = (): number => sessionGeneration

export const advanceSessionGeneration = (): void => {
  sessionGeneration++
}

const tokenUserId = (token: string): string | null => {
  // 解码走单源 decodeJwtPayload（TextDecoder，非 ASCII 正确）；本谓词只管 user_id。
  const payload = decodeJwtPayload(token)
  if (!payload || !('user_id' in payload)) return null
  const userId = payload.user_id
  return typeof userId === 'number' || typeof userId === 'string' ? String(userId) : null
}

/** 跨标签页令牌变化是否为同一账号的 MFA 刷新；不可解析令牌保守按换身份处理。 */
export const isSameTokenIdentity = (previous: string | null, next: string | null): boolean => {
  if (!previous || !next) return false
  const previousUserId = tokenUserId(previous)
  return previousUserId !== null && previousUserId === tokenUserId(next)
}
