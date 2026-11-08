// 代理超时字段定义与预览摘要单源。
//
// 表单控件（components/rules/ProxyTimeoutFields.vue）与规则向导的「配置预览」
// 必须给出同一组字段标签与继承语义——预览曾漏掉整组 7 项，用户只能保存后从
// 单规则配置查看器发现改错。字段描述/建议值只在此维护，控件与预览都读它。
//
// 上限口径：后端 rule_features.go 仅校验「不能为负」与 flush_interval >= -1，
// 无上限——长连接/流式（SSE/LLM 长响应、WebSocket 代理）合法需要 >24h。
// 前端不设 max，避免把带外/导入的更大值静默夹回。
import type { ProxyTimeoutConfig } from '@/types/rules.ts'
import { tSafe as t } from '../i18n/tSafe.ts'

interface ProxyTimeoutField {
  readonly key: keyof ProxyTimeoutConfig
  readonly label: string
  readonly min: number
  readonly desc: string
  readonly suggest?: number
}

export const PROXY_TIMEOUT_FIELDS: readonly ProxyTimeoutField[] = [
  { key: 'proxy_dial_timeout', label: t('common.app.views.proxyTimeout.dialTimeout'), min: 0, desc: t('common.app.views.proxyTimeout.dialDesc'), suggest: 10 },
  { key: 'proxy_response_header_timeout', label: t('common.app.views.proxyTimeout.responseHeaderTimeout'), min: 0, desc: t('common.app.views.proxyTimeout.responseHeaderDesc'), suggest: 30 },
  { key: 'proxy_read_timeout', label: t('common.app.views.proxyTimeout.readTimeout'), min: 0, desc: t('common.app.views.proxyTimeout.readDesc'), suggest: 60 },
  { key: 'proxy_write_timeout', label: t('common.app.views.proxyTimeout.writeTimeout'), min: 0, desc: t('common.app.views.proxyTimeout.writeDesc'), suggest: 60 },
  { key: 'proxy_stream_timeout', label: t('common.app.views.proxyTimeout.streamTimeout'), min: 0, desc: t('common.app.views.proxyTimeout.streamDesc') },
  { key: 'proxy_flush_interval', label: t('common.app.views.proxyTimeout.flushInterval'), min: -1, desc: t('common.app.views.proxyTimeout.flushDesc') },
  { key: 'proxy_stream_close_delay', label: t('common.app.views.proxyTimeout.streamCloseDelay'), min: 0, desc: t('common.app.views.proxyTimeout.closeDelayDesc') },
]

/** 单个超时值的人读形态：0=继承全局；-1=立即透传（仅刷新间隔）。 */
const timeoutValueLabel = (field: keyof ProxyTimeoutConfig, value: number | undefined): string => {
  const seconds = value ?? 0
  if (field === 'proxy_flush_interval') {
    if (seconds === -1) return t('common.app.views.proxyTimeout.passthrough')
    return seconds > 0 ? `${seconds}s` : t('common.app.views.proxyTimeout.inheritGlobal')
  }
  return seconds > 0 ? `${seconds}s` : t('common.app.views.proxyTimeout.inheritGlobal')
}

/** 预览用一行摘要：七项全列，避免任何一项在核对面缺席。 */
export const proxyTimeoutSummary = (value: ProxyTimeoutConfig): string =>
  PROXY_TIMEOUT_FIELDS
    .map((field) => `${field.label} ${timeoutValueLabel(field.key, value[field.key])}`)
    .join(' / ')
