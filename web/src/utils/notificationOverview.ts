// 通知中心概览卡的派生口径（纯函数，便于单测）。

interface DailyTrendPoint {
  date: string
  total: number
  sent: number
  rate: number
}

interface OverviewDeliveryStats {
  deliveries: number
  successRate: number
}

/**
 * 概览「投递量/成功率」卡的统一口径：近 7 天投递趋势的合计（管理员=全平台、
 * 普通用户=本人，由 delivery-trend 端点按角色收窄）。此前管理员读全平台全时
 * 统计、普通用户读近 7 天本人——同一张卡两种时间口径。
 */
export const overviewDeliveryStats = (trend: readonly DailyTrendPoint[]): OverviewDeliveryStats => {
  let deliveries = 0
  let sent = 0
  for (const point of trend) {
    deliveries += point.total
    sent += point.sent
  }
  return { deliveries, successRate: deliveries > 0 ? sent / deliveries : 0 }
}
