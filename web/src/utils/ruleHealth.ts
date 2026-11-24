// 规则健康结论单源：规则页列表、仪表盘规则卡、处理流程弹框三面共用同一判定与
// 同一色阶。此前三面各写一份——规则页「部分不健康 = 降级（警示）」、仪表盘
// 「任一不健康 = 不健康（危险）」、部分未知一边算降级一边算未知——同一规则在
// 不同页面给出不同级别。判定口径以规则页既有口径为准，这里只收敛实现、不改语义。

/** 规则健康汇总：各状态的上游条数；total = 各项之和。 */
export interface RuleHealthSummary {
  healthy: number
  unhealthy: number
  degraded: number
  unknown: number
  na: number
  total: number
}

export type RuleHealthLevel = 'unhealthy' | 'degraded' | 'unknown' | 'not_applicable' | 'healthy'

export type RuleHealthTagType = 'danger' | 'warning' | 'info' | 'success'

/** ruleHealthLevel 把健康汇总收敛成一个级别（规则页既有口径）。 */
export const ruleHealthLevel = (status: RuleHealthSummary): RuleHealthLevel => {
  if (status.unhealthy + status.degraded === status.total) return 'unhealthy'
  if (status.unhealthy + status.degraded > 0) return 'degraded'
  if (status.unknown === status.total) return 'unknown'
  if (status.unknown > 0) return 'degraded'
  // 动态 DNS 上游结构性 N/A（引擎按解析 IP 跟踪，域名级不可观测）
  if (status.na === status.total) return 'not_applicable'
  return 'healthy'
}

/** RULE_HEALTH_TAG_TYPE 是级别到 el-tag type 的唯一映射。 */
export const RULE_HEALTH_TAG_TYPE: Record<RuleHealthLevel, RuleHealthTagType> = {
  unhealthy: 'danger',
  degraded: 'warning',
  unknown: 'info',
  not_applicable: 'info',
  healthy: 'success',
}

/** RULE_HEALTH_LABEL_KEY 是级别到文案键的唯一映射（规则页词条，三面共用）。 */
export const RULE_HEALTH_LABEL_KEY: Record<RuleHealthLevel, string> = {
  unhealthy: 'common.app.rules.common.unhealthy',
  degraded: 'common.app.rules.common.degraded',
  unknown: 'common.app.rules.common.unknown',
  not_applicable: 'common.app.rules.common.notApplicable',
  healthy: 'common.app.rules.list.healthNormal',
}

/** 上游健康快照（/config/health 的单项形态）；缺快照的上游计为未知。 */
export interface UpstreamHealthSnapshot {
  healthy?: boolean
  unknown?: boolean
  degraded?: boolean
}

/** ruleHealthLevelOfUpstreams 由逐上游快照计数后判定——与规则页同一口径
 * （部分上游不健康 = 降级，而不是「任一不健康 = 不健康」）。 */
export const ruleHealthLevelOfUpstreams = (snapshots: Array<UpstreamHealthSnapshot | undefined>): RuleHealthLevel =>
  ruleHealthLevel(
    snapshots.reduce<RuleHealthSummary>(
      (counts, snapshot) => {
        if (!snapshot || snapshot.unknown) counts.unknown += 1
        else if (!snapshot.healthy) counts.unhealthy += 1
        else if (snapshot.degraded) counts.degraded += 1
        else counts.healthy += 1
        return counts
      },
      { healthy: 0, unhealthy: 0, degraded: 0, unknown: 0, na: 0, total: snapshots.length },
    ),
  )