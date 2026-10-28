// 用户名/密码前端策略单源：与后端 validateUsernamePolicy /
// validatePasswordPolicy（internal/handlers/auth.go）同口径——用户管理、
// 首次设置管理员、个人资料三处入口不得各写字符串与正则。
//
// 用户名：3-50 位，小写英文开头，字符只允许小写字母 + 数字
// （后端 ^[a-z][a-z0-9]*$；长度由 binding min=3,max=50 覆盖）。
// 密码：8-24 位可打印 ASCII（数字/大小写字母/特殊字符），不允许汉字或
// 其他非 ASCII；空值=不修改（由调用方按入口语义决定是否必填）。

export const USERNAME_MIN_LENGTH = 3
export const USERNAME_MAX_LENGTH = 50
export const USERNAME_POLICY_RE = /^[a-z][a-z0-9]*$/

export const PASSWORD_MIN_LENGTH = 8
export const PASSWORD_MAX_LENGTH = 24

export const USERNAME_LENGTH_MESSAGE = `用户名长度需为 ${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} 位`
export const USERNAME_POLICY_MESSAGE = '用户名仅允许小写英文开头，字符只允许小写字母和数字'
export const PASSWORD_LENGTH_MESSAGE = `密码长度需为 ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 位`
export const PASSWORD_CHARSET_MESSAGE = '密码仅支持数字、大小写字母和特殊字符，不允许汉字或其他非 ASCII 字符'

/** 用户名校验；空值返回 null（必填由调用方按入口语义拦截）。 */
export function validateUsername(value: string): string | null {
  if (!value) return null
  if (value.length < USERNAME_MIN_LENGTH || value.length > USERNAME_MAX_LENGTH) return USERNAME_LENGTH_MESSAGE
  if (!USERNAME_POLICY_RE.test(value)) return USERNAME_POLICY_MESSAGE
  return null
}

/** 密码校验；空值返回 null（「留空=不修改」入口语义）。 */
export function validatePassword(value: string): string | null {
  if (!value) return null
  if (value.length < PASSWORD_MIN_LENGTH || value.length > PASSWORD_MAX_LENGTH) return PASSWORD_LENGTH_MESSAGE
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0
    if (code < 32 || code > 126) return PASSWORD_CHARSET_MESSAGE
  }
  return null
}

/**
 * 「确认框有值但新密码留空」的拦截文案；无此形态返回 null。
 *
 * 「留空=不修改」只对新密码字段成立：用户只填确认框时，载荷会省略 password
 * （后端保留原密码）却回报成功——界面上的假成功。调用方须在「两次不一致」
 * 判定之前消费本函数。
 */
export function missingNewPasswordMessage(password: string, passwordConfirm: string): string | null {
  if (password || !passwordConfirm) return null
  return '请填写新密码（新密码留空表示不修改密码）'
}
