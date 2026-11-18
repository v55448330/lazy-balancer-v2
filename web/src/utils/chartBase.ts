// 全站图表基线（2026-11-19 从 Dashboard/SecurityOverview/TaskMonitor 提取）：
// 三参考页的 tooltip/grid/轴/legend/序列视觉参数单一来源。新页面图表 MUST
// 经此构建，禁止再手搓 div bar 或各持一套轴色值。
// 既有三页的 option 为历史形态（零视觉变更原则不动）；本模块是新增消费面的规范入口。
import type { EChartsOption, LineSeriesOption, BarSeriesOption, PieSeriesOption } from 'echarts'

/** Dashboard 流量图同款 tooltip（白底/灰边/12px 深灰字）。 */
const chartTooltip = {
  trigger: 'axis' as const,
  backgroundColor: 'rgba(255,255,255,0.95)',
  borderColor: '#e5e7eb',
  textStyle: { color: '#374151', fontSize: 12 },
}

/** Dashboard 同款类目轴（灰轴线/10px 浅灰标签）。 */
const categoryAxis = (data: string[]): EChartsOption['xAxis'] => ({
  type: 'category',
  data,
  axisLine: { lineStyle: { color: '#e5e7eb' } },
  axisLabel: { fontSize: 10, color: '#9ca3af' },
})

/** Dashboard 同款数值轴（无轴线/浅灰分隔线/10px 标签）。 */
const valueAxis = (extra?: Record<string, unknown>): EChartsOption['yAxis'] => ({
  type: 'value',
  axisLine: { show: false },
  axisLabel: { fontSize: 10, color: '#9ca3af' },
  splitLine: { lineStyle: { color: '#f3f4f6' } },
  ...extra,
})

/** Dashboard 折线序列基线：smooth/2px 线/10% 面积/无符号点。 */
export const lineSeries = (name: string, color: string, data: (number | null)[], extra?: Partial<LineSeriesOption>): LineSeriesOption => ({
  name,
  type: 'line',
  color,
  data,
  smooth: true,
  showSymbol: false,
  lineStyle: { color, width: 2 },
  areaStyle: { color: `${color}1a` },
  ...extra,
})

/** SecurityOverview 趋势图同款柱序列（可 stack）。 */
export const barSeries = (name: string, color: string, data: number[], extra?: Partial<BarSeriesOption>): BarSeriesOption => ({
  name,
  type: 'bar',
  data,
  itemStyle: { color },
  ...extra,
})

/** TaskMonitor/SecurityOverview 同款环形饼序列（白描边/4px 圆角）。 */
const donutSeries = (data: { name: string; value: number; itemStyle?: { color: string } }[], extra?: Partial<PieSeriesOption>): PieSeriesOption => ({
  type: 'pie',
  radius: ['45%', '68%'],
  center: ['50%', '44%'],
  itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
  label: { show: false },
  data,
  ...extra,
})

/** 轴触发图表基线（Dashboard grid/legend 口径）：legend 底部 11px 灰字。 */
export const axisChartBase = (legend: string[], xData: string[], series: EChartsOption['series'], opts?: { yExtra?: Record<string, unknown>; legendTop?: boolean }): EChartsOption => ({
  tooltip: chartTooltip,
  legend: opts?.legendTop
    ? { data: legend, top: 0, itemGap: 24, textStyle: { fontSize: 11, color: '#6b7280' } }
    : { data: legend, bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: opts?.legendTop
    ? { left: 8, right: 16, top: 36, bottom: 8, containLabel: true }
    : { left: 8, right: 16, top: 15, bottom: 32, containLabel: true },
  xAxis: categoryAxis(xData),
  yAxis: valueAxis(opts?.yExtra),
  series,
})

/** 饼图基线（TaskMonitor 口径）：item tooltip + 底部滚动 legend。 */
export const pieChartBase = (data: { name: string; value: number; itemStyle?: { color: string } }[]): EChartsOption => ({
  tooltip: { ...chartTooltip, trigger: 'item' as const },
  legend: { bottom: 0, type: 'scroll', textStyle: { fontSize: 11, color: '#6b7280' } },
  series: [donutSeries(data)],
})

/** 语义色（与 chartTheme/Dashboard stat 色族同源）。 */
export const chartColors = {
  blue: '#3b82f6',
  green: '#10b981',
  purple: '#8b5cf6',
  orange: '#f59e0b',
  red: '#ef4444',
  cyan: '#06b6d4',
} as const