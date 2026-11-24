// 仪表盘披露口径的纯计算（无 DOM / i18n 依赖，node --test 可直接断言）。

// 规则卡只展示「按请求数/流量排名的前 10 条 + 指标采集失败行」，零流量规则
// 不进入排行——表格行数可能少于规则总数。只要有规则未展示就必须披露（已展示
// 条数与总数），否则「只看到 3 行」会被读成「只有 3 条规则」。
// 返回 null = 规则已全部展示，无需披露；非整数/负数同样不披露（不呈现可疑数字）。
export const ruleCardOverflowHint = (
  total: number,
  shown: number,
): { readonly total: number; readonly shown: number; readonly hidden: number } | null => {
  if (!Number.isInteger(total) || !Number.isInteger(shown) || total < 0 || shown < 0 || total <= shown) return null
  return { total, shown, hidden: total - shown }
}
