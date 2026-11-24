/**
 * 「请求已出站但没拿到响应」判定——供导入/还原这类分钟级同步写请求使用。
 *
 * axios 拦截器把无响应的失败（断连/DNS/CORS/超时）统一转成
 * `ApiRequestError(message, undefined, …)`；带 status 的失败说明后端已经裁决
 * （400 校验失败/5xx 回滚），不能读成「可能仍在后台执行」。会话止损拒绝与主动
 * 取消既没有出站也不属于断连，同样不在此列。
 *
 * 不 import utils/api：该模块在导入期构造 i18n 实例并依赖 `@/` 别名，node 侧
 * 行为测试无法解析——本判定只依赖错误对象的可观察形态（name/status/code）。
 */
export const isConnectionInterruption = (error: unknown): boolean => {
  if (typeof error !== 'object' || error === null) return false
  const candidate = error as {
    name?: unknown
    status?: unknown
    code?: unknown
    sessionExpiredHalted?: unknown
  }
  if (candidate.sessionExpiredHalted === true) return false
  if (candidate.code === 'ERR_CANCELED') return false
  return candidate.name === 'ApiRequestError' && candidate.status === undefined
}
