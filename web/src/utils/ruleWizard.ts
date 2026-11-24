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

/** NTLM 接管字段面：关闭 NTLM 与切 TCP 共用同一份「恢复默认」。 */
interface NtlmTakeoverForm {
  strategy: string
  proxy_flush_interval: number
  upstream_keepalive_timeout: number
  upstream_force_http1: number
  tcp_try_duration: number
  enable_active_health_check: boolean
}

/** NTLM 关闭 / 切 TCP 时接管字段的恢复目标（主动检查保持关闭，用户可再自行开启）。 */
const NTLM_RESET: NtlmTakeoverForm = {
  strategy: 'weighted_round_robin',
  proxy_flush_interval: 0,
  upstream_keepalive_timeout: 0,
  upstream_force_http1: 0,
  tcp_try_duration: 0,
  enable_active_health_check: false,
}

export const resetNtlmTakeover = (form: NtlmTakeoverForm): void => {
  form.strategy = NTLM_RESET.strategy
  form.proxy_flush_interval = NTLM_RESET.proxy_flush_interval
  form.upstream_keepalive_timeout = NTLM_RESET.upstream_keepalive_timeout
  form.upstream_force_http1 = NTLM_RESET.upstream_force_http1
  form.tcp_try_duration = NTLM_RESET.tcp_try_duration
  form.enable_active_health_check = NTLM_RESET.enable_active_health_check
}

// ── 关闭向导前的未保存检查 ──

const canonicalize = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map((item) => canonicalize(item))
  if (value === null || typeof value !== 'object') return value
  const entries = Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
  return Object.fromEntries(entries.map(([key, item]) => [key, canonicalize(item)]))
}

/** 向导草稿指纹：键序无关（表单就地改写时同一份数据的键序会变），嵌套内容全量纳入。 */
export const wizardDraftFingerprint = (form: unknown): string => JSON.stringify(canonicalize(form))

/**
 * 向导草稿跟踪（关闭前的未保存检查）。
 *
 * 基线不能在打开的同一拍取：el-input-number 在 modelValue watch 里把越界值钳写回
 * 表单（禁用行权重 0 → 1），而上游表格的单元格要到 el-table 挂载后的下一拍才
 * 渲染——那一拍取的基线会把这类控件自动归一误判成「用户改过」。所以：
 *   open()   弹框开始入场时先留一份早鸟基线；
 *   touch()  用户在向导内容区有过输入（capture 阶段的 pointerdown / keydown）；
 *   settle() 入场动画结束（归一已落定）时定稿——期间用户已操作过则保留早鸟基线，
 *            不吞掉入场这几百毫秒里的真实修改；
 *   isDirty() 用户碰过表单且当前草稿与基线不同。没碰过就不算脏：那时的差异
 *            只可能来自控件归一。
 */
export const createWizardDraftTracker = (readForm: () => unknown) => {
  let baseline = ''
  let touched = false
  return {
    open: (): void => {
      baseline = wizardDraftFingerprint(readForm())
      touched = false
    },
    touch: (): void => {
      touched = true
    },
    settle: (): void => {
      if (baseline !== '' && !touched) baseline = wizardDraftFingerprint(readForm())
    },
    clear: (): void => {
      baseline = ''
      touched = false
    },
    isDirty: (): boolean => touched && baseline !== '' && wizardDraftFingerprint(readForm()) !== baseline,
  }
}

// ── 动态上游：仅保留首个启用上游 ──

interface DynamicUpstreamRow {
  host: string
  port: number
  weight: number
  enabled?: boolean
}

/** 开启动态上游后会被禁用的行：首个启用上游之后的启用行（禁用行不参与）。 */
export const dynamicUpstreamSurplus = (upstreams: readonly DynamicUpstreamRow[]): DynamicUpstreamRow[] =>
  upstreams.filter((upstream) => upstream.enabled !== false).slice(1)

/** 就地应用「仅一个启用上游」：多余启用行禁用清零，首个启用上游权重 100。 */
export const applyDynamicUpstreamLimit = (upstreams: DynamicUpstreamRow[]): void => {
  dynamicUpstreamSurplus(upstreams).forEach((upstream) => {
    upstream.enabled = false
    upstream.weight = 0
  })
  const retained = upstreams.find((upstream) => upstream.enabled !== false)
  if (retained) retained.weight = 100
}

/**
 * 复制向导的域名初值：HTTP 副本不继承源域名——同域名同端口的副本一启用就撞
 * 「端口 / 域名冲突」，而冲突要到用户启用时才报。留空迫使其在向导里换成新域名；
 * TCP 规则没有域名概念，原样返回。
 */
export const copyRuleDomain = (source: { readonly protocol: string; readonly domain?: string | null }): string =>
  source.protocol === 'http' ? '' : (source.domain ?? '')
