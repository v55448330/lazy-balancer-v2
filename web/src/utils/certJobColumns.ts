// 证书任务表列宽与「按容器宽收敛」单源。
//
// 两条约束同时成立：
// ① 容器更宽时表格必须占满整宽——弹性列声明 min-width，Element Plus 把多余宽度
//    均分给这些列（固定宽的只有状态/重试/操作）；
// ② 容器更窄时按优先级隐藏低价值列——min-width 之和超过容器仍会撑出滚动条。
// 收敛下限：不可让位列（domain/status/validity/attempts/actions）最小合计
// CERT_JOB_COLUMNS_MIN_WIDTH = 619px。容器 ≥619px 时由 .cert-jobs-wrap 的
// overflow:hidden 兜底（卡片/页面级不出现横向滚动）；容器 <619px、让位耗尽后
// 仍未装下时切 .cert-jobs-wrap--scroll 的 overflow-x:auto 横向滚动——可滚动
// 优先于裁切：裁断会让右侧「操作」列不可达，滚动保住全部可达列。
//
// 下方 WIDTHS 即「每列最小宽度」，既用于 ② 的让位判据，也是 ① 的弹性基线。
// 纯函数便于单测：给定容器宽度返回应显示的列集合。

export type CertJobColumnId =
  | 'rule_id'
  | 'domain'
  | 'status'
  | 'issuer'
  | 'validity'
  | 'renewal'
  | 'updated'
  | 'attempts'
  | 'cooling'
  | 'actions'

/** 各列固定宽度（px）；合计须与 CertJobs.vue 的 width 声明一致。 */
export const CERT_JOB_COLUMN_WIDTHS: Record<CertJobColumnId, number> = {
  rule_id: 116,
  domain: 210,
  status: 84,
  issuer: 84,
  validity: 155,
  renewal: 150,
  updated: 150,
  attempts: 80,
  cooling: 90,
  actions: 130,
}

export const CERT_JOB_COLUMNS: readonly CertJobColumnId[] = [
  'rule_id',
  'domain',
  'status',
  'issuer',
  'validity',
  'renewal',
  'updated',
  'attempts',
  'cooling',
  'actions',
]

/**
 * 隐藏优先级：容器不足时依次让位。规则 ID 与域名是排查主键，**最后**让位；
 * 先让位低价值列：冷却时间（并入重试单元格 tooltip）、颁发者、自动重签时间、
 * 更新时间。域名/状态/有效期/重试/操作恒保留——没有它们表格失去意义。
 */
const CERT_JOB_COLUMN_HIDE_ORDER: readonly CertJobColumnId[] = [
  'cooling',
  'issuer',
  'renewal',
  'updated',
  'rule_id',
]

export const certJobColumnsWidth = (columns: Iterable<CertJobColumnId>): number => {
  let total = 0
  for (const id of columns) total += CERT_JOB_COLUMN_WIDTHS[id]
  return total
}

export const CERT_JOB_COLUMNS_TOTAL_WIDTH = certJobColumnsWidth(CERT_JOB_COLUMNS)

/** 不可让位列的最小合计宽（px）——让位耗尽后的下限；低于此宽表格内部被裁切。 */
export const CERT_JOB_COLUMNS_MIN_WIDTH = certJobColumnsWidth(
  CERT_JOB_COLUMNS.filter((id) => !CERT_JOB_COLUMN_HIDE_ORDER.includes(id)),
)

/**
 * 贪心选择：从全列出发，按隐藏优先级逐列让位，直到合计宽度不超过容器宽，
 * 或已无列可让。返回应显示的列集合（恒包含不可让位列）。
 */
export const pickVisibleCertJobColumns = (
  containerWidth: number,
): ReadonlySet<CertJobColumnId> => {
  const visible = new Set<CertJobColumnId>(CERT_JOB_COLUMNS)
  let total = CERT_JOB_COLUMNS_TOTAL_WIDTH
  // 容器宽未知/未测量（0 或非有限）时按最简集处理会闪列；调用侧初始为
  // Infinity，仅在 ResizeObserver 给出真实宽度后才会进入隐藏分支。
  if (!Number.isFinite(containerWidth) || containerWidth <= 0) return visible
  for (const id of CERT_JOB_COLUMN_HIDE_ORDER) {
    if (total <= containerWidth) break
    if (!visible.has(id)) continue
    visible.delete(id)
    total -= CERT_JOB_COLUMN_WIDTHS[id]
  }
  return visible
}
