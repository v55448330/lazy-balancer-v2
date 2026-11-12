// 单规则阶段计数（GET /security/rules/:caddy_id/stage-stats）的展示口径单源：
// 流程弹框的阶段 chip 与阶段面板统计行都从这里取文案，不再各写一份。
//
// 四种形态必须互相可区分（旧实现在面板行/ chip 上把它们压平了）：
//   · 未到数（请求在途）      → 不出 chip、不出统计行
//   · 取数失败（5xx/网络）    → 「计数不可用」+ 面板失败行（可重试）
//   · 成功但载荷为空          → 「—」（后端契约违约，非零计数也不存在）
//   · 成功且有计数            → 具体数字（含未归因桶披露）
//
// 未归因桶 stage_unattributed_24h 是后端恒定下发的键：rule_triggered 为空/非数值
// （旧版本文件名形态、集群回插）的拦截无法归到阶段 1/3。丢弃该键会把「未归因」
// 读成「零拦截」，故两个阶段的面板行都要披露它。

import { formatDurationUs } from './securityStages.ts'
import { tSafe as t } from '../i18n/tSafe.ts'


/** 后端 stage-stats 响应载荷（键集与 internal/handlers/security_overview.go 对表） */
export interface RuleStageCounts {
  stage1_blocked_24h: number
  stage3_blocked_24h: number
  stage_unattributed_24h: number
  // 分段平均处理耗时（µs）：预检段=信任+IP ACL+GeoIP（同一 coraza handler
  // 不可分）；WAF 段=隔离预检后的评估成本（含限流，纳秒级可忽略）。
  precheck_avg_us?: number
  precheck_samples?: number
  waf_avg_us?: number
  waf_samples?: number
}

/** 计数取数的会话态：`settled`=请求已结束，`failed`=以失败结束 */
interface RuleStageCountsView {
  settled: boolean
  failed: boolean
}

/** 阶段平均耗时（µs）；无数据返回 0（不渲染耗时块） */
export const stageAvgDurationUs = (stage: 1 | 4, counts: RuleStageCounts | null): number => {
  if (!counts) return 0
  return stage === 1 ? (counts.precheck_avg_us ?? 0) : (counts.waf_avg_us ?? 0)
}

/** 时间线卡片上的「平均耗时」角标；无采样返回空串（不占位） */
export const stageTimingChip = (stage: 1 | 4, counts: RuleStageCounts | null): string => {
  const us = stageAvgDurationUs(stage, counts)
  return us > 0 ? t('common.app.views.stageStats.avgDurationChip', { duration: formatDurationUs(us) }) : ''
}

const timingDetailText = (stage: 1 | 4, counts: RuleStageCounts): string => {
  const us = stageAvgDurationUs(stage, counts)
  if (us <= 0) return ''
  const samples = stage === 1 ? (counts.precheck_samples ?? 0) : (counts.waf_samples ?? 0)
  return t('common.app.views.stageStats.timingDetail', { duration: formatDurationUs(us), samples })
}

/** 未归因桶披露；无未归因记录返回空串（默认不打扰） */
export const unattributedCountText = (counts: RuleStageCounts | null): string => {
  const count = counts?.stage_unattributed_24h ?? 0
  return count > 0 ? t('common.app.views.stageStats.unattributedNote', { count }) : ''
}

/** 阶段节点 chip：未到数不出 chip；失败=「计数不可用」；空载荷='—' */
export const stageCountChip = (
  stage: 1 | 2 | 3 | 4,
  counts: RuleStageCounts | null,
  view: RuleStageCountsView,
): { chip?: string; caption?: string } => {
  if (!view.settled) return {}
  if (view.failed) return { chip: t('common.app.views.stageStats.countUnavailable') }
  if (!counts) return { chip: '—' }
  if (stage === 1) return { chip: t('common.app.views.stageStats.chipStage24h', { count: counts.stage1_blocked_24h }) }
  if (stage === 2) return {} // CC 挑战统计为全局端点，规则级无分桶
  if (stage === 3) return {} // 阶段 3 人机验证：挑战计数由 lb_human 统计端点（总览卡）承担，规则级无分桶
  return { chip: t('common.app.views.stageStats.chipStage24h', { count: counts.stage3_blocked_24h }) } // 阶段 4 WAF
}

/**
 * 阶段面板统计行：失败与空载荷都不占行（失败由面板内的失败行承载，不在这里
 * 压成空串让读者以为没有内容）。阶段 0 无计数概念，恒空串。
 */
export const stageCountSummary = (
  stage: 0 | 1 | 2 | 3 | 4,
  counts: RuleStageCounts | null,
  view: RuleStageCountsView,
): string => {
  if (stage === 0 || !view.settled || view.failed || !counts) return ''
  if (stage === 1) return t('common.app.views.stageStats.summaryStage24h', { count: counts.stage1_blocked_24h }) + timingDetailText(1, counts) + unattributedCountText(counts)
  if (stage === 2) return '' // CC 挑战统计为全局端点，规则级无分桶
  // 阶段 3 人机验证：规则级无分桶（挑战计数在 /security/human/stats），不得回落 WAF 桶冒充本阶段统计
  if (stage === 3) return ''
  return t('common.app.views.stageStats.summaryStage24h', { count: counts.stage3_blocked_24h }) + timingDetailText(4, counts) + unattributedCountText(counts)
}
