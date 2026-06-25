export interface User {
  id: number
  username: string
  role: string
  display_name?: string
  created_at?: string | null
  last_login?: string | null
}

export interface AuthState {
  user: User | null
  token: string | null
  nodeMode: string
}

export interface SystemInfo {
  hostname: string
  os_info: string
  kernel: string
  architecture: string
  node_mode: string
  caddy_version: string
  network_ips: Record<string, string>
  ip_addresses?: string
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