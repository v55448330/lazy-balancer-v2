// FE40-D1-2：负载策略→文案映射（Rules/Dashboard 共用）。
// 键集与后端 httpStrategies 全集对齐（weighted_round_robin/least_conn/
// ip_hash/random/first/cookie）；Dashboard 原死键 round_robin 与 Rules 原
// 死键 header 已删除（后端不接受该两形态）。
export const strategyLabels: Record<string, string> = {
  weighted_round_robin: '轮询',
  least_conn: '最少连接',
  ip_hash: 'IP 哈希',
  cookie: 'Cookie 粘滞',
  first: '首个可用',
  random: '随机',
}

export const getStrategyLabel = (strategy: string): string => strategyLabels[strategy] || strategy
