/**
 * SMTP 连通性测试的放行闸门 + 端口校验。
 *
 * 测试结果只证明「发出测试那一刻」的投递配置：请求在途期间改了投递相关字段，
 * 旧结果不得放行保存。调用方发请求前 begin(当前表单)，成功回调里仅当
 * appliesTo(当前表单) 才置通过位。
 */
export interface SmtpDeliveryConfig {
  smtpHost: string
  smtpPort: number
  smtpUser: string
  smtpPass: string
  smtpFrom: string
  smtpTls: boolean
  smtpInsecure: boolean
}

/** 端口数值归一：数字串与数值等价；空串/布尔/非数值串 → NaN。 */
const portNumber = (port: unknown): number => {
  if (typeof port === 'string') return port.trim() === '' ? NaN : Number(port)
  return typeof port === 'number' ? port : NaN
}

/** 投递配置快照键：host 去首尾空白、端口数值归一（未配置/非数值同归 0）。 */
const deliveryKey = (config: SmtpDeliveryConfig): string => JSON.stringify([
  config.smtpHost.trim(),
  portNumber(config.smtpPort) || 0,
  config.smtpUser,
  config.smtpPass,
  config.smtpFrom,
  config.smtpTls,
  config.smtpInsecure,
])

export const createSmtpTestGate = (): {
  begin(config: SmtpDeliveryConfig): void
  appliesTo(config: SmtpDeliveryConfig): boolean
} => {
  let snapshot: string | null = null
  return {
    begin(config) { snapshot = deliveryKey(config) },
    appliesTo(config) { return snapshot !== null && deliveryKey(config) === snapshot },
  }
}

/** 端口校验文案：未配置(0)与合法 1-65535 整数/数字串返回空串，其余返回 invalidText。 */
export const smtpPortError = (port: unknown, invalidText: string): string => {
  const value = portNumber(port)
  if (value === 0) return ''
  return Number.isInteger(value) && value >= 1 && value <= 65535 ? '' : invalidText
}
