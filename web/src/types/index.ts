export interface NullableString {
  String: string
  Valid: boolean
}

export interface User {
  id: number
  username: string
  role: string
  display_name?: string | NullableString | null
  created_at?: string | null
  last_login?: string | null
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

export interface Rule {
  id?: number
  caddy_id: string
  name: string
  protocol: string
  listen_port: number
  strategy: string
  enabled: boolean
  upstreams: any[]
  enable_tls: boolean
  tls_auto_https: boolean
}

export interface RuleMetrics {
  requests_total?: number
  requests_in_flight?: number
  total_requests?: number
  healthy?: boolean
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

export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

export interface ChartDataPoint {
  time: number
  [key: string]: number
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
