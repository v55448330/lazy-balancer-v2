export interface CurrentUser {
  id: number
  username: string
  role: 'admin' | 'user'
  is_enabled: boolean
  display_name: string | null
  mfa_enabled?: boolean
}

export interface UserListItem extends Omit<CurrentUser, 'is_enabled'> {
  is_enabled: boolean
  mfa_enabled?: boolean
  created_at?: string | null
  last_login?: string | null
}

// M5：PATCH /users/me 请求体——提交新密码（password 非空）必须携带
// current_password 过后端密码确认门，仅改显示名时不需要。
export interface UpdateCurrentUserInput {
  readonly display_name?: string
  readonly password?: string
  readonly current_password?: string
}

export interface APIKey {
  readonly id: number
  readonly name: string
  readonly key_prefix: string
  readonly created_by: number
  readonly username: string
  readonly is_enabled: boolean
  readonly mcp_enabled: boolean
  readonly read_only: boolean
  readonly mcp_ip_whitelist: string[]
  readonly last_used?: string | null
  readonly expires_at?: string | null
  readonly created_at: string
}

export interface CreateAPIKeyInput {
  readonly name: string
  readonly mcp_enabled: boolean
  readonly read_only: boolean
  readonly mcp_ip_whitelist: string[]
  readonly expires_at?: string
}

export interface UpdateAPIKeyInput {
  readonly is_enabled?: boolean
  readonly mcp_enabled?: boolean
  readonly read_only?: boolean
  readonly mcp_ip_whitelist?: string[]
}

export interface MCPToolSpec {
  readonly name: string
  readonly description: string
  readonly method: string
  readonly path: string
  readonly read_only: boolean
  readonly input_schema?: Record<string, unknown>
  readonly usage?: string
}


export interface SystemInfo {
  hostname: string
  os_info: string
  kernel: string
  architecture: string
  node_mode: string
  caddy_version: string
  uptime?: number
  network_ips: Record<string, string>
  version?: string
}

export interface MetricsOverview {
  total_requests: number
  requests_per_sec: number
  bytes_in: number
  bytes_out: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  latency_p50: number
  latency_p95: number
  latency_p99: number
  active_rules: number
  total_rules: number
  online_nodes: number
}

export interface SystemMetrics {
  cpu_percent: number
  memory_used: number
  memory_total: number
  memory_percent: number
  disk_used: number
  disk_total: number
  disk_percent: number
}

export interface CaddyMetrics {
  requests_total: number
  requests_in_flight: number
}

export interface RealtimeTraffic {
  bytes_in: number
  bytes_out: number
}

export interface ConnectionStats {
  established: number
  time_wait: number
  total: number
}

export * from './rules'

export interface RuleMetrics {
  requests_total?: number
  requests_in_flight?: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  bytes_in: number
  bytes_out: number
}

export interface HostMetrics {
  host: string
  requests_total: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  bytes_in: number
  bytes_out: number
}

export interface APIResponse<T = never> {
  code: number
  message?: string
  data?: T
}

export interface CertJobsPage<TJob> {
  readonly list: readonly TJob[]
  readonly total: number
  readonly page: number
  readonly page_size: number
}

export type ClusterNodeMode = 'master' | 'slave'

export type ClusterNodeStatus = 'pending' | 'online' | 'offline'

export interface ClusterHealth {
  readonly caddy_ok: boolean
  readonly rules_count: number
  readonly certs_expiring_30d: number
  readonly last_sync_at: string
  readonly last_sync_error: string
  readonly sync_error_code?: string
  readonly uptime_sec: number
}

export interface ClusterSectionSync {
  readonly section: string
  readonly label: string
  readonly hash: string
  readonly master_hash: string
  readonly synced: boolean
}

export interface ClusterNode {
  readonly id: number
  readonly name: string
  readonly ip_address: string
  readonly port: number
  readonly protocol: string
  readonly access_url: string
  readonly status: ClusterNodeStatus
  readonly is_approved: boolean
  readonly reported_version: number
  readonly current_version: number
  readonly health: ClusterHealth | null
  readonly last_seen: string
  readonly created_at: string
  readonly section_sync?: readonly ClusterSectionSync[] | null
}

export interface ClusterStatus {
  readonly node_mode: ClusterNodeMode
  readonly cluster_version: number
  readonly master_url: string
  readonly sync_interval: number
  readonly sync_global_config: boolean
  readonly sync_users: boolean
  readonly sync_rules: boolean
  readonly sync_waf_files: boolean
  readonly sync_security: boolean
  readonly cluster_active: boolean
  readonly applied_version: number
  readonly last_sync_at: string
  readonly last_sync_error: string
  /** 后端 models.ClusterStatus 随状态下发（apply_failed/pin_mismatch 等），驱动从节点面板补救按钮与错误文案翻译 */
  readonly sync_error_code?: string
  readonly pending_count: number
  readonly approved_count: number
}

export interface ClusterRegistrationInput {
  readonly master_url: string
  readonly register_token: string
  readonly node_name?: string
}

export interface ClusterRegisterToken {
  readonly token: string
  readonly expires_at: string
}

export interface ClusterModeResult {
  readonly status: string
}

export interface ClusterSyncResult {
  readonly applied_version: number
  readonly changed: boolean
}

/**
 * GET /config 响应（前端消费字段子集，FI-05 单一事实源）：
 * 与后端 models.GlobalConfig 的 json 契约逐字段对齐；集群专属字段
 * （is_master/master_url/sync_interval 等）与敏感字段（dns_credentials）不在此面。
 */
export interface GlobalConfigData {
  log_level: string
  caddy_log_level: string
  caddy_log_size_mb: number
  request_body_max_size_mb: number
  http_read_timeout: number
  http_write_timeout: number
  http_idle_timeout: number
  upstream_keepalive_timeout: number
  proxy_dial_timeout: number
  proxy_response_header_timeout: number
  proxy_read_timeout: number
  proxy_write_timeout: number
  proxy_stream_timeout: number
  proxy_flush_interval: number
  proxy_stream_close_delay: number
  server_tokens_hidden: boolean
  cert_job_log_size_mb: number
  audit_log_size_mb: number
  runtime_log_size_mb: number
  access_log_json: boolean
  access_log_format: string
  audit_retention_months: number
  jwt_expire_minutes: number
  timezone: string
  mfa_write_guard: boolean
  mfa_lockout_enabled: boolean
  acme_email: string
  cert_expiry_days: number
  cert_renewal_days: number
  cert_renewal_attempts: number
  default_ca_provider_id: number
  dns_provider: string
}
