// JWT 载荷解码单源（不验签）。站内消费方：
//   - oidcCallback：回跳令牌校验（auth_method/exp 门）；
//   - api.isTokenExpired：会话过期谓词（exp 门）；
//   - sessionIdentity.tokenUserId：跨标签页身份比对（user_id 门）。
//
// 解码口径取 oidcCallback 原 TextDecoder 版：base64url → 字节 → UTF-8 解码。
// 此前 api/sessionIdentity 两份用 atob 直出 Latin-1 字符串，非 ASCII 载荷
// （中文 username）产出 mojibake——JSON.parse 虽不报错，解出的身份串已不可信
// （tests/jwtDecode.spec.ts 钉非 ASCII 回归）。本模块零依赖：api.ts 可安全
// 导入；反向禁止本模块从 utils/api.ts 导入（api.ts 顶层引 axios/element-plus，
// 会把整条 UI 依赖链带进纯数据 chunk——同 formatBytes 约定）。

const decodeSegment = (segment: string): string => {
  const normalized = segment.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

/** 解出 JWT 载荷（不验签）。非三段/非 JSON/非对象载荷返回 null。 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
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
