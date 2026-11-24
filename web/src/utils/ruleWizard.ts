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

// ── 协议切换：HTTP 态快照 → 切 TCP 清理 → 点回 HTTP 回填 ──
//
// 向导里把协议点到 TCP 必须清掉一批 HTTP 专属配置（后端 TCP 写侧门硬拒、载荷
// 无条件上送、TCP 下又没有可见控件可关）。误点再点回 HTTP 时这些配置要原样
// 回来。回填只还原「被切换清掉、且用户在 TCP 下没再改动」的字段：有 TCP 控件
// 的共享字段（监听端口 / 负载策略 / NTLM 接管组 / 上游协议）被显式改过就保留，
// 没有 TCP 控件的 HTTP 专属字段必然还是清理后的值，必然回填。

type WizardUpstreamProtocol = 'http' | 'https' | 'tcp' | 'tls'

interface SwitchUpstream {
  id?: number
  host: string
  port: number
  protocol: WizardUpstreamProtocol
  origin_domain?: string
}

interface NtlmTakeoverForm {
  strategy: string
  proxy_flush_interval: number
  upstream_keepalive_timeout: number
  upstream_force_http1: number
  tcp_try_duration: number
  enable_active_health_check: boolean
}

/** 协议切换会改写的向导表单字段面（两协议通用、切换不碰的字段不在其中）。 */
interface ProtocolSwitchForm extends NtlmTakeoverForm {
  listen_port: number
  enable_tls: boolean
  ntlm_compatible: number
  forward_auth_enabled: number
  forward_auth_upstream: string
  custom_routes_enabled: boolean
  health_check_host?: string
  path_rules: unknown[]
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  upstreams: SwitchUpstream[]
}

export interface HttpStateSnapshot {
  listen_port: number
  enable_tls: boolean
  strategy: string
  forward_auth_enabled: number
  forward_auth_upstream: string
  upstream_force_http1: number
  custom_routes_enabled: boolean
  health_check_host: string
  path_rules: unknown[]
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  /** 切换前 NTLM 开启时才有：接管组原值。 */
  ntlmTakeover: Pick<NtlmTakeoverForm, 'proxy_flush_interval' | 'upstream_keepalive_timeout' | 'tcp_try_duration' | 'enable_active_health_check'> | null
  upstreams: SwitchUpstream[]
}

const cloneValue = <Value>(value: Value): Value => {
  if (Array.isArray(value)) return value.map((item) => cloneValue(item)) as Value
  if (value === null || typeof value !== 'object') return value
  const copy: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) copy[key] = cloneValue(item)
  return copy as Value
}

const toTcpProtocol = (protocol: WizardUpstreamProtocol): WizardUpstreamProtocol =>
  protocol === 'http' ? 'tcp' : protocol === 'https' ? 'tls' : protocol

const toHttpProtocol = (protocol: WizardUpstreamProtocol): WizardUpstreamProtocol =>
  protocol === 'tcp' ? 'http' : protocol === 'tls' ? 'https' : protocol

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

/** 拍下切换前的 HTTP 态（深拷贝：之后表单怎么改都污染不到快照）。 */
export const snapshotHttpState = (form: ProtocolSwitchForm): HttpStateSnapshot => ({
  listen_port: form.listen_port,
  enable_tls: form.enable_tls,
  strategy: form.strategy,
  forward_auth_enabled: form.forward_auth_enabled,
  forward_auth_upstream: form.forward_auth_upstream,
  upstream_force_http1: form.upstream_force_http1,
  custom_routes_enabled: form.custom_routes_enabled,
  health_check_host: form.health_check_host ?? '',
  path_rules: cloneValue(form.path_rules),
  dynamic_dns: form.dynamic_dns,
  enable_dns_server: form.enable_dns_server,
  dns_server: form.dns_server,
  ntlmTakeover: form.ntlm_compatible === 1
    ? {
        proxy_flush_interval: form.proxy_flush_interval,
        upstream_keepalive_timeout: form.upstream_keepalive_timeout,
        tcp_try_duration: form.tcp_try_duration,
        enable_active_health_check: form.enable_active_health_check,
      }
    : null,
  upstreams: form.upstreams.map((upstream) => ({
    id: upstream.id,
    host: upstream.host,
    port: upstream.port,
    protocol: upstream.protocol,
    origin_domain: upstream.origin_domain ?? '',
  })),
})

// 回填按字段逐一比对的平面键。enable_tls 排在 listen_port 之前、enable_dns_server
// 排在 dns_server 之前：即便联动 watcher 在回填途中写了端口 / DNS 地址，后写的
// 快照值仍然生效。
const PLAIN_KEYS = [
  'enable_tls',
  'listen_port',
  'forward_auth_enabled',
  'forward_auth_upstream',
  'upstream_force_http1',
  'custom_routes_enabled',
  'health_check_host',
  'dynamic_dns',
  'enable_dns_server',
  'dns_server',
] as const

type TcpProjection = Pick<HttpStateSnapshot, (typeof PLAIN_KEYS)[number] | 'strategy'>

type PlainKey = (typeof PLAIN_KEYS)[number]
type PlainRecord = Record<PlainKey, unknown>

/**
 * 一份 HTTP 态快照「切到 TCP 之后」的样子。applyTcpState 照它写入、
 * restoreHttpState 照它比对——清理与回填共用同一张投影，才不会出现
 * 「清了却没回填」或「回填判据与清理判据各写一份」的漏项。
 */
const tcpProjection = (snapshot: HttpStateSnapshot): TcpProjection => ({
  listen_port: snapshot.listen_port === 80 || snapshot.listen_port === 443 ? 8080 : snapshot.listen_port,
  enable_tls: false,
  // NTLM 接管与 cookie 会话保持都是 HTTP 语义，TCP 下回落轮询
  strategy: snapshot.ntlmTakeover !== null || snapshot.strategy === 'cookie' ? NTLM_RESET.strategy : snapshot.strategy,
  forward_auth_enabled: 0,
  // 网关地址只在开关开启时清空：关闭态保留地址是「重新开启即可恢复」的既有约定
  forward_auth_upstream: snapshot.forward_auth_enabled === 1 ? '' : snapshot.forward_auth_upstream,
  upstream_force_http1: 0,
  custom_routes_enabled: false,
  health_check_host: '',
  dynamic_dns: false,
  enable_dns_server: false,
  dns_server: '',
})

/**
 * 把表单切到 TCP 态：HTTP 专属配置整面清空。DB 中不存在 TCP:80/443 存量规则
 * （后端无条件拒绝），80/443 迁到 8080，其余端口原样保留。
 */
export const applyTcpState = (form: ProtocolSwitchForm): { portRelocated: boolean } => {
  const snapshot = snapshotHttpState(form)
  const tcp = tcpProjection(snapshot)
  if (snapshot.ntlmTakeover) {
    form.ntlm_compatible = 0
    resetNtlmTakeover(form)
  }
  // PLAIN_KEYS 是联合键集，逐键直写会退化成 never；经 Record 视图写入保持写入面封闭
  const target = form as unknown as PlainRecord
  const tcpView = tcp as unknown as PlainRecord
  for (const key of PLAIN_KEYS) target[key] = tcpView[key]
  form.strategy = tcp.strategy
  form.path_rules = []
  form.upstreams.forEach((upstream) => {
    upstream.origin_domain = ''
    upstream.protocol = toTcpProtocol(upstream.protocol)
  })
  return { portRelocated: tcp.listen_port !== snapshot.listen_port }
}

/**
 * 切到 `nextProtocol` 时会被清空、且不是开关（而是用户填过的内容）的项：
 * 路径规则 / 逐上游回源域名 / 认证网关地址。视图据此列清单确认，取消保持原协议。
 * 切向 HTTP 不清理任何内容（TCP 侧没有这些字段可丢）。
 */
export const protocolSwitchImpact = (form: ProtocolSwitchForm, nextProtocol: string) => {
  if (nextProtocol !== 'tcp') return { pathRules: 0, originDomains: [] as string[], forwardAuthUpstream: '' }
  return {
    pathRules: form.path_rules.length,
    originDomains: form.upstreams
      .map((upstream) => (upstream.origin_domain ?? '').trim())
      .filter((domain) => domain !== ''),
    forwardAuthUpstream: form.forward_auth_enabled === 1 ? form.forward_auth_upstream.trim() : '',
  }
}


/**
 * 上游行身份：库内行按 id（TCP 下改了地址仍是同一后端），未入库的行按
 * host:port。有无 id 不一致的行视为不同行——未入库的新行不得认领库内行的回源域名。
 */
const sameBackend = (left: SwitchUpstream, right: SwitchUpstream): boolean => {
  if (left.id !== undefined || right.id !== undefined) return left.id !== undefined && left.id === right.id
  return left.host === right.host && left.port === right.port
}

/**
 * 点回 HTTP 时按快照回填，返回是否有字段被回填（视图据此提示「已恢复」）。
 * 某字段当前值已不等于 TCP 清理后的值 = 用户在 TCP 下显式改过，保留不覆盖。
 */
export const restoreHttpState = (form: ProtocolSwitchForm, snapshot: HttpStateSnapshot): boolean => {
  const tcp = tcpProjection(snapshot)
  let restored = false
  const formView = form as unknown as PlainRecord
  const tcpView = tcp as unknown as PlainRecord
  const snapView = snapshot as unknown as PlainRecord
  for (const key of PLAIN_KEYS) {
    if (formView[key] !== tcpView[key] || formView[key] === snapView[key]) continue
    formView[key] = snapView[key]
    restored = true
  }
  if (snapshot.ntlmTakeover) {
    // NTLM 拉回会连带接管策略 / 刷新 / Keepalive / 重试 / 主动检查：
    // 整组都没在 TCP 下动过才还原，否则不拉回（避免与用户刚改的字段互相矛盾）
    const untouched = form.strategy === tcp.strategy
      && form.ntlm_compatible === 0
      && form.proxy_flush_interval === NTLM_RESET.proxy_flush_interval
      && form.upstream_keepalive_timeout === NTLM_RESET.upstream_keepalive_timeout
      && form.tcp_try_duration === NTLM_RESET.tcp_try_duration
      && form.enable_active_health_check === NTLM_RESET.enable_active_health_check
    if (untouched) {
      form.ntlm_compatible = 1
      form.strategy = snapshot.strategy
      form.proxy_flush_interval = snapshot.ntlmTakeover.proxy_flush_interval
      form.upstream_keepalive_timeout = snapshot.ntlmTakeover.upstream_keepalive_timeout
      form.tcp_try_duration = snapshot.ntlmTakeover.tcp_try_duration
      form.enable_active_health_check = snapshot.ntlmTakeover.enable_active_health_check
      restored = true
    }
  } else if (form.strategy === tcp.strategy && form.strategy !== snapshot.strategy) {
    form.strategy = snapshot.strategy
    restored = true
  }
  if (form.path_rules.length === 0 && snapshot.path_rules.length > 0) {
    form.path_rules = cloneValue(snapshot.path_rules)
    restored = true
  }
  const unmatched = [...snapshot.upstreams]
  form.upstreams.forEach((upstream) => {
    const at = unmatched.findIndex((source) => sameBackend(source, upstream))
    if (at === -1) {
      // TCP 下新增 / 改过地址的行：不认领任何快照值，只把协议回落到 HTTP 族
      upstream.protocol = toHttpProtocol(upstream.protocol)
      return
    }
    const [source] = unmatched.splice(at, 1)
    if (upstream.origin_domain === '' && source.origin_domain !== '') {
      upstream.origin_domain = source.origin_domain
      restored = true
    }
    if (upstream.protocol !== toTcpProtocol(source.protocol)) {
      // TCP 下改过该行协议（tcp ↔ tls）：保留用户选择，只把协议族回落到 HTTP
      upstream.protocol = toHttpProtocol(upstream.protocol)
    } else if (upstream.protocol !== source.protocol) {
      upstream.protocol = source.protocol
      restored = true
    }
  })
  return restored
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
