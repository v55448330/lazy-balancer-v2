// 通知中心 / MCP 会话 REST 契约类型（单一事实源，按平台接线定案契约定稿）。
// 前端消费方：views/notifications/*、views/settings/Mcp*.vue、views/Keys.vue。
// 通道行契约另见 internal/handlers/notification_channels.go（notificationChannelDTO）。

import type { APIResponse } from './index.ts'

/** 事件级别（与 internal/notify Level 同串）。 */
export type NotificationLevel = 'info' | 'warn' | 'critical'

/** 投递状态（internal/notify/deliveries.go 状态机：pending → sent / failed / dead）。 */
export type DeliveryStatus = 'pending' | 'sent' | 'failed' | 'dead'

/** 通道类型（internal/handlers/notification_channels.go 白名单）。 */
export type NotificationChannelType = 'webhook' | 'email' | 'qq' | 'wx_clawbot'

/** GET /notification/channels 行（管理员视角非属主 target 脱敏）。 */
export interface NotificationChannel {
  id: number
  user_id: number
  type: NotificationChannelType
  name: string
  target: string
  enabled: boolean
  last_test_at: string
  last_test_ok: boolean
  style_config?: string
}

export type NotificationChannelsResponse = APIResponse<{ channels: NotificationChannel[] }>
export type NotificationCreateChannelResponse = APIResponse<{ id: number }>

/** GET /notification/catalog 行。group 为服务端下发的分组显示串（认证/安全/…）。 */
export interface CatalogEvent {
  id: string
  group: string
  level: NotificationLevel
  default_subscribed: boolean
}

export type NotificationCatalogResponse = APIResponse<{ events: CatalogEvent[] }>

/** GET /notification/subscriptions 行（订阅态合并视图）。 */
interface NotificationSubscriptionRow {
  event_type: string
  level: NotificationLevel
  default_subscribed: boolean
  subscribed: boolean
  min_level: NotificationLevel | ''
}

export type NotificationSubsResponse = APIResponse<{ subscriptions: NotificationSubscriptionRow[] }>

/** PUT /notification/subscriptions 请求体：min_level 空=删行回默认（契约显式语义）。 */
export interface NotificationSubsPayload {
  items: Array<{ event_type: string; min_level: NotificationLevel | '' }>
}

/** GET /notification/deliveries 行（limit 默认 50 上限 200；?status= 过滤；管理员 ?all=1）。 */
export interface NotificationDelivery {
  id: number
  user_id: number
  event_type: string
  level: NotificationLevel
  title: string
  body: string
  status: DeliveryStatus
  attempts: number
  error: string
  created_at: string
  sent_at: string
}

export type NotificationDeliveriesResponse = APIResponse<{ deliveries: NotificationDelivery[] }>

/** GET /notification/settings（管理员）：secret 只回配置布尔，不回明文。 */
interface NotificationSettings {
  smtp: {
    host: string
    port: number
    user: string
    from: string
    pass_configured: boolean
  }
  qq: {
    appid: string
    secret_configured: boolean
  }
  wx_bot_cred_configured: boolean
  mcp_enabled: boolean
  attack_warn_at: string
  attack_critical_at: string
}

export type NotificationSettingsResponse = APIResponse<NotificationSettings>

/**
 * PUT /notification/settings 请求体。secret 值留空=不修改（提交时省略键）。
 * TODO(协议-校准): 契约仅定义 GET 形状；PUT 的 secret 键名（pass/secret/wx
 * 凭据键）与 attack_warn_at/attack_critical_at 的写路径语义未定，按 GET 嵌套
 * 同形提交，联调时与 N4 对齐后修正。
 */
export interface NotificationSettingsPayload {
  smtp?: {
    host?: string
    port?: number
    user?: string
    from?: string
    pass?: string
  }
  qq?: {
    appid?: string
    secret?: string
  }
  mcp_enabled?: boolean
}

/** GET /notification/mcp/stats（管理员）。 */
interface McpTopTool {
  tool: string
  calls: number
}

interface McpTrendPoint {
  date: string
  calls: number
}

export interface McpStats {
  today_calls: number
  active_sessions: number
  error_rate: number
  top_tools: McpTopTool[]
  trend: McpTrendPoint[]
}

export type McpStatsResponse = APIResponse<McpStats>

/** GET /security/mcp-sessions 行。 */
export interface McpSession {
  session_id: string
  user_id: number
  username: string
  key_id: number
  key_name: string
  ip: string
  user_agent: string
  first_seen: string
  last_seen: string
  online: boolean
}

export type McpSessionsResponse = APIResponse<{ sessions: McpSession[] }>
