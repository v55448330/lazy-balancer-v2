// 操作日志分页的深翻页上限契约（单源）：后端 GET /audit-logs 对 page>500 显式
// 400（深 OFFSET 会退化为全表扫描，见 internal/handlers/auditlog.go
// auditLogDeepPageLimit），并把上限写进稳定 message_key。前端分页器若按真实
// total 渲染页码，用户能点到上限之后的页——点击只得到一条 toast、表格保留上一
// 页旧行，空态文案却写着「日志加载失败」（把「已到上限」误报成故障）。
//
// 口径：分页器总数按「上限 × 每页条数」截断，页码不越界；总数仍超上限时在分页
// 器旁常显提示（有更多结果，请缩小筛选）；400 错误按该 key 归为独立状态而非
// 通用加载失败。
export const AUDIT_LOG_DEEP_PAGE_LIMIT = 500
export const AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY = 'audit.deepPageLimitExceeded'

const normalizedPageSize = (pageSize: number): number => {
  const rows = Math.floor(pageSize)
  return Number.isFinite(rows) && rows > 0 ? rows : 1
}

/** 分页器可用总数：超上限时钳到「上限 × 每页条数」（页码因此不会越界）。 */
export const auditLogPaginationTotal = (total: number, pageSize: number, limit = AUDIT_LOG_DEEP_PAGE_LIMIT): number => {
  if (!Number.isFinite(total) || total <= 0) return 0
  return Math.min(Math.floor(total), limit * normalizedPageSize(pageSize))
}

/** 结果数超过深翻页上限（分页器被截断，需常显「缩小筛选范围」提示）。 */
export const auditLogDeepPageExceeded = (total: number, pageSize: number, limit = AUDIT_LOG_DEEP_PAGE_LIMIT): boolean =>
  Number.isFinite(total) && total > limit * normalizedPageSize(pageSize)

/**
 * 该错误是否为深翻页上限 400（而不是通用加载失败）。
 * 优先按稳定 message_key 判别；旧后端/中间层剥掉 key 时按语义文案兜底
 * （zh 母本「结果过多（超过 N 页）…缩小范围」）。
 */
export const isAuditLogDeepPageError = (error: unknown): boolean => {
  const candidate = error as { status?: number; messageKey?: string; message?: string } | null | undefined
  if (!candidate || candidate.status !== 400) return false
  if (candidate.messageKey !== undefined) return candidate.messageKey === AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY
  const message = candidate.message ?? ''
  return message.includes('超过') && message.includes('页')
}
