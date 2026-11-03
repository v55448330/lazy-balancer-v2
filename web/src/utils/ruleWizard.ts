/** 水合期间保留库值；只有用户主动关闭 DNS 服务器才清空。 */
export const dnsServerAfterToggle = (current: string, enabled: boolean, hydrating: boolean): string => {
  if (hydrating || enabled) return current
  return ''
}

/**
 * 被动健康检查下隐藏的超时字段（只把 timeout 输入放进主动探测模板）
 * 后端 validateRuleFeatures（rule_features.go）**不区分主动/被动**地
 * 要求 `0 < timeout < interval`，提交载荷也恒带该值。存量/带外数据（历史
 * 之前、迁移只回填 ≤0）在关闭主动检查后会被保存校验拦下，而输入框不可见 →
 * 「请让超时小于间隔」无处修改的死锁提示。
 * 保存前在被动模式下把越界值钳到 `interval-1` 并显性提示：保留后端不变式，
 * 不降级校验、不静默改动可见字段（interval>1 才有合法解，否则原样返回）。
 */
export const clampPassiveHealthCheckTimeout = (
  interval: number,
  timeout: number,
): { timeout: number; clamped: boolean } => {
  if (!(interval > 1) || !(timeout >= interval)) return { timeout, clamped: false }
  return { timeout: Math.max(1, Math.floor(interval) - 1), clamped: true }
}

/**
 * 复制向导载荷的规则级回源 Host：向导「复制」走 POST /rules 重建，
 * CreateRule 无 Update 的 nil=保留语义——省略 host_header 会落空串，副本丢失
 * 源规则的 Host 覆盖。复制路径必须显式携带源值（空串=源规则本就未覆盖）。
 */
export const copyRuleHostHeader = (source: { host_header?: string | null }): string => source.host_header ?? ''
