// 通知中心 / MCP 会话 REST 契约类型（单一事实源，按平台接线定案契约定稿）。
// 前端消费方：views/notifications/*、views/settings/Mcp*.vue、views/Keys.vue。
// 通道行契约另见 internal/handlers/notification_channels.go（notificationChannelDTO）。

import type { APIResponse } from './index.ts'

/** 事件级别（与 internal/notify Level 同串）。 */
type NotificationLevel = 'info' | 'warn' | 'critical'

/** 投递状态（internal/notify/deliveries.go 状态机：pending → sent / partial / failed / dead）。 */
export type DeliveryStatus = 'pending' | 'sent' | 'partial' | 'failed' | 'dead'

/** 通道类型（internal/handlers/notification_channels.go 白名单）。 */
export type NotificationChannelType = 'webhook' | 'email' | 'qq' | 'wx_clawbot'

/** GET /notification/channels 行（管理员视角非属主 target 脱敏）。 */
export interface NotificationChannel {
  id: number
  user_id: number
  type: NotificationChannelType
  name: string
  target: string
  /** true=target 已被后端脱敏（非属主视角）：编辑时不得回写 target。 */
  target_masked: boolean
  enabled: boolean
  last_test_at: string
  last_test_ok: boolean
  style_config?: string
  /** qq/wx 实时入站连接态（常驻会话 per-bot）；webhook/email=none。 */
  link_connected?: boolean
  link_state?: 'online' | 'offline' | 'none'
  /** wx 接收者会话上下文就绪=可主动发送（连接在线≠会话就绪）。 */
  session_ready?: boolean
}

export type NotificationChannelsResponse = APIResponse<{ channels: NotificationChannel[] }>


/** GET /notification/deliveries 行（page_size 默认 50 上限 200；?status= 过滤；恒全量）。 */
export interface NotificationDelivery {
  id: number
  user_id: number
  username: string
  event_type: string
  event_title: string
  level: NotificationLevel
  title: string
  body: string
  status: DeliveryStatus
  /** 测试发送标记（通道测试/规则测试/日报测试落库行；备注列展示）。 */
  is_test: boolean
  attempts: number
  error: string
  created_at: string
  sent_at: string
  channels: { channel_id: number; channel_name: string; channel_type: string; status: string; error: string; duration_ms?: number }[]
}

export type NotificationDeliveriesResponse = APIResponse<{ deliveries: NotificationDelivery[]; total: number }>

/** GET /notification/settings（管理员）：secret 只回配置布尔，不回明文。
 * 形状对齐 internal/handlers/notification_settings.go：QQ/微信凭据不回显
 * （单源=扫码绑定自动落库），阈值是 int（JSON number）。 */
interface NotificationSettings {
  smtp: {
    host: string
    port: string
    user: string
    from: string
    pass_configured: boolean
    tls: boolean
    insecure: boolean
  }
  mcp_enabled: boolean
  api_enabled: boolean
  attack_warn_at: number
  attack_critical_at: number
}

export type NotificationSettingsResponse = APIResponse<NotificationSettings>

/**
 * PUT /notification/settings 请求体（部分更新：仅出现的键生效）。
 * secret 值留空=不修改（提交时省略键）。QQ 凭据不走本端点（扫码绑定自动
 * 落库）；阈值整体校验 0<warn<critical。
 */
export interface NotificationSettingsPayload {
  smtp?: {
    host?: string
    port?: string
    user?: string
    from?: string
    pass?: string
    tls?: boolean
    insecure?: boolean
  }
  mcp_enabled?: boolean
  api_enabled?: boolean
  attack_warn_at?: number
  attack_critical_at?: number
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
