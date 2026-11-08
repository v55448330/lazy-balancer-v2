// 系统指标分项降级展示单源：后端 getSystemMetrics 对失败分项返回零值并在
// `degraded` 中披露（全失败才 500）。展示层必须据此把「没采到」呈现为
// 「采集失败」而非 0——否则 CPU 单点故障时用户看到「内存 0 B / 磁盘 0%」，
// 排障窗口反而误判。

/** 已知分项（顺序即文案顺序）；仅模块内使用，导出面只留消费函数。 */
const SYSTEM_METRIC_PARTS = ['cpu', 'memory', 'disk', 'pids'] as const
type SystemMetricPart = (typeof SYSTEM_METRIC_PARTS)[number]

// 展示文案走 i18n（批次 D metrics 域）：键形与 zh 母本原文由 systemMetricsDegraded
// 行为钉（跨域）+ metrics 域双钉承载；label 在调用时刻解析。
import { tSafe as t } from '../i18n/tSafe.ts'

const SYSTEM_METRIC_LABEL_KEYS: Record<SystemMetricPart, string> = {
  cpu: 'common.app.views.metrics.partCpu',
  memory: 'common.app.views.metrics.partMemory',
  disk: 'common.app.views.metrics.partDisk',
  pids: 'common.app.views.metrics.partPids',
}

/** 只收已知分项（未知值忽略，向前兼容后端新增分项）。 */
export const degradedMetricParts = (degraded: readonly string[] | undefined): Set<SystemMetricPart> => {
  const parts = new Set<SystemMetricPart>()
  for (const value of degraded ?? []) {
    if ((SYSTEM_METRIC_PARTS as readonly string[]).includes(value)) parts.add(value as SystemMetricPart)
  }
  return parts
}

/** 降级提示文案用的分项名（保持稳定顺序 cpu→memory→disk）。 */
export const degradedMetricLabels = (degraded: readonly string[] | undefined): string[] => {
  const parts = degradedMetricParts(degraded)
  return SYSTEM_METRIC_PARTS.filter((part) => parts.has(part)).map((part) => t(SYSTEM_METRIC_LABEL_KEYS[part]))
}

/** 文本百分比保留后端原始值：超过配额仍显示 122% 等真实超限程度。 */
export const pidsPercentLabel = (percent: number): string => percent.toFixed(0)

/** 通用资源进度条：降级时不绘制（null），正常/超限值统一只封视觉上限。 */
export const metricProgressPercent = (percent: number, degraded: boolean): number | null =>
  degraded ? null : Math.min(percent, 100)

/** 进程配额还多一个「不限额不画进度」形态；文本百分比不受影响。 */
export const pidsProgressPercent = (percent: number, max: number, degraded: boolean): number | null =>
  degraded || max <= 0 ? null : Math.min(percent, 100)

/** 「已用 / 上限」文案：上限 0 视为不限额（cgroup pids.max = max）。 */
export const pidsUsageLabel = (current: number, max: number): string =>
  `${Math.max(current, 0)} / ${max > 0 ? max : t('common.app.views.metrics.unlimited')}`

/**
 * 接近配额的比例分级：≥95% 危险、≥80% 警告。
 * 配额打满时容器内无法 fork（连 cat 都会失败），故阈值比常规资源更保守。
 */
export const pidsTone = (percent: number): 'normal' | 'warning' | 'critical' => {
  if (percent >= 95) return 'critical'
  if (percent >= 80) return 'warning'
  return 'normal'
}

/** 采集失败不代表配额正常或耗尽：值容器使用中性色。 */
export const pidsValueTone = (percent: number, degraded: boolean): 'normal' | 'warning' | 'critical' | null =>
  degraded ? null : pidsTone(percent)

/** 后端 0 同时覆盖未采集/读取失败与真正不限额，不能断言为「不限」。 */
export const nprocLimitLabel = (limit: number): string => limit > 0 ? String(limit) : t('common.app.views.metrics.nprocUnknown')

/** 进程配额帮助文案单源：ulimit 的零值歧义由 nprocLimitLabel 保留。 */
export const pidsTooltipText = (limit: number): string =>
  t('common.app.views.metrics.pidsTooltip', { limit: nprocLimitLabel(limit) })
