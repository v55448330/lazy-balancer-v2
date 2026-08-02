export interface CurrentUser {
  id: number
  username: string
  role: 'admin' | 'user'
  is_enabled: boolean
  display_name: string | null
}

export interface UserListItem extends Omit<CurrentUser, 'is_enabled'> {
  is_enabled: boolean
  created_at?: string | null
  last_login?: string | null
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
  ip_addresses?: string
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
  total_requests?: number
  healthy?: boolean
  degraded?: boolean
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

export interface ApiResponse<T = never> extends Omit<APIResponse<T>, 'data'> {
  data: T
}

export type ClusterNodeMode = 'master' | 'slave'

export type ClusterNodeStatus = 'pending' | 'online' | 'offline'

export interface ClusterHealth {
  readonly caddy_ok: boolean
  readonly rules_count: number
  readonly certs_expiring_30d: number
  readonly last_sync_at: string
  readonly last_sync_error: string
  readonly uptime_sec: number
}

export interface ClusterNode {
  readonly id: number
  readonly name: string
  readonly ip_address: string
  readonly port: number
  readonly access_url: string
  readonly status: ClusterNodeStatus
  readonly is_approved: boolean
  readonly reported_version: number
  readonly current_version: number
  readonly health: ClusterHealth | null
  readonly last_seen: string
  readonly created_at: string
}

export interface ClusterStatus {
  readonly node_mode: ClusterNodeMode
  readonly cluster_version: number
  readonly master_url: string
  readonly sync_interval: number
  readonly sync_caddy_config: boolean
  readonly cluster_active: boolean
  readonly applied_version: number
  readonly last_sync_at: string
  readonly last_sync_error: string
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
