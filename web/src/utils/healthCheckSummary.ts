/**
 * 健康检查摘要单源：规则向导「配置预览」与单规则配置查看器共用同一份口径。
 *
 * 两处曾各自拼字符串，主动分支只打印 path/interval/timeout（HTTP）或探测端口
 * （TCP），失败阈值与恢复阈值只在被动分支出现——预览自称配置核对面，改过的
 * 阈值在核对面看不到，只能保存后从单规则 JSON 查看器发现。字段语义取自后端
 * rule_features.go（active/passive 共用 unhealthy 阈值，active 独占 healthy 阈值）。
 *
 * 渲染层不写死兜底：调用方传入的表单/配置值原样呈现，缺项按 0 显性暴露，
 * 不用「|| 默认值」把未配置掩盖成建议值。
 */

// 摘要文案走 i18n（批次 D ingest 域）：键形与 zh 母本原文由 healthCheckSummary.spec
// 双钉承载；数值口径（区间窗/阈值次数）以参数注入，zh 输出与抽词前逐字一致。
import { tSafe as t } from '../i18n/tSafe.ts'

interface HealthCheckSummaryInput {
  readonly protocol: string
  readonly enable_active_health_check: boolean
  readonly health_check_path: string
  readonly health_check_interval: number
  readonly health_check_timeout: number
  readonly health_check_host?: string
  readonly tcp_health_check_port: number
  readonly health_check_healthy_threshold: number
  readonly health_check_unhealthy_threshold: number
}

/**
 * 主动探测摘要：HTTP 走路径 + Host（留空=跟随后端域名/上游地址），
 * TCP 走探测端口（0=各上游自身端口）；两者都点名失败阈值与恢复阈值
 * （主动探测两阈值都参与，被动只用失败阈值）。
 */
export function activeHealthCheckSummary(value: HealthCheckSummaryInput): string {
  const window = `(${value.health_check_interval}s/${value.health_check_timeout}s)`
  const thresholds = t('common.app.views.ingest.activeThresholds', {
    unhealthy: value.health_check_unhealthy_threshold,
    healthy: value.health_check_healthy_threshold,
  })
  if (value.protocol === 'tcp') {
    const port = value.tcp_health_check_port || t('common.app.views.ingest.probePortDefault')
    return t('common.app.views.ingest.activeTcp', { port, window, thresholds })
  }
  const host = value.health_check_host ? t('common.app.views.ingest.activeHostSuffix', { host: value.health_check_host }) : ''
  return t('common.app.views.ingest.activeHttp', { path: value.health_check_path || '/', window, host, thresholds })
}

/** 被动熔断摘要：恢复窗口 = 检查间隔的 3 倍（后端被动失效记忆窗口）。 */
export function passiveHealthCheckSummary(value: HealthCheckSummaryInput): string {
  return t('common.app.views.ingest.passive', {
    unhealthy: value.health_check_unhealthy_threshold,
    window: value.health_check_interval * 3,
  })
}

/** 预览/查看器的健康检查行：主动开启时给主动摘要，否则给被动摘要。 */
export function healthCheckSummary(value: HealthCheckSummaryInput): string {
  return value.enable_active_health_check
    ? activeHealthCheckSummary(value)
    : passiveHealthCheckSummary(value)
}
