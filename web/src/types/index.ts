export interface CurrentUser {
  id: number
  username: string
  role: 'admin' | 'user'
  is_enabled: boolean
  display_name: string | null
  mfa_enabled?: boolean
  auth_provider?: string
  // 初始化创建的首个管理员（break-glass 入口）。后端三条强保护：不可删除、
  // 不可禁用、不可降级（role 恒为 admin）；保护判定读库失败时 fail-closed 500
  // （无法判定保护目标则不放行），前端操作会被 400/500 拒绝。
  // 响应面：所有用户响应路径（密码登录 / MFA 登录与 step-up / GET·PATCH
  // /users/me / PUT /users/:id / 从节点票据登录）均由 db.UserRowColumns 单源
  // 列清单真实下发（非仅 GET /users 列表）——不要按端点分叉解读。字段无
  // omitempty，类型保留可选只为容忍历史形态响应（缺省按 false 归一化，
  // 即非保护目标；后端仍二次拦截）。
  is_setup_admin?: boolean
}

export interface UserListItem extends CurrentUser {
  // 原 Omit<CurrentUser,'is_enabled'> + 立即重加 is_enabled 是
  // 无操作变换——直接 extends 消除冗余（is_enabled/mfa_enabled
  // 两条 extends 已继承的无操作重声明一并删除）
  created_at?: string | null
  last_login?: string | null
}

// PATCH /users/me 请求体——提交新密码（password 非空）必须携带
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
  /** 进程/线程配额：cgroup pids.current / pids.max（按线程计数、含僵尸）。 */
  pids_current: number
  /** 0 = 不限额（cgroup pids.max 为 "max"）。 */
  pids_max: number
  /** PID 1 的 RLIMIT_NPROC 软限（ulimit -u）；0 = 未采集/无限，仅作二级提示。 */
  nproc_limit: number
  pids_percent: number
  /**
   * 分项降级披露：本次采集失败的分项（memory/disk/cpu/pids）。
   * 存在项在卡片内显示「采集失败」而非 0——后端对失败项返回零值，展示层不得
   * 把「没采到」呈现成「用量为 0」。全部失败时后端返回 500（无本字段）。
   */
  degraded?: string[]
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
  blocked?: number
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

// ── 证书任务视图类型唯一事实源 ──
// 后端 certJobListItem 投影（internal/handlers/certjobs.go，列表/详情同源）。
// 此前 CertJobs（全字段）/Rules（精简）/TaskMonitor（横幅行）三处各持一份
// 局部声明，后端增/改字段时漏改处 TS 不报错、运行期静默降级。
// 视图按需 Pick 子集（Rules 侧即 Pick<CertJobListItem, ...>）。

/** 证书任务状态机（后端 db.certJobStatuses 全集）；
 *  utils/certJobStatus 的标签/色调表按 Record<CertJobStatus, …> 编译期穷尽消费。 */
export type CertJobStatus =
  | 'queued'
  | 'pending'
  | 'processing'
  | 'creating_account'
  | 'creating_order'
  | 'order_created'
  | 'waiting_order_ready'
  | 'order_ready'
  | 'cleanup_dns'
  | 'cleanup_warning'
  | 'presenting_dns'
  | 'waiting_propagation'
  | 'dns_propagated'
  | 'accepting_challenge'
  | 'waiting_order_valid'
  | 'order_valid'
  | 'validating'
  | 'validated'
  | 'finalizing'
  | 'finalized'
  | 'downloading'
  | 'downloaded'
  | 'issued'
  | 'failed'
  | 'waiting_ca'
  | 'disabled'

type CertJobCertificateStatus = 'expired' | 'expiring' | 'unknown' | 'valid'

export interface CertJobListItem {
  id: number
  rule_id: string
  domain: string
  ca_provider_id?: number
  ca_provider_name?: string
  status: CertJobStatus
  message: string
  issuer?: string
  days_remaining: number
  certificate_status: CertJobCertificateStatus
  renewal_attempts?: number
  ca_available_after?: string | null
  last_error_code?: string
  expires_at?: string | null
  // 后端派生的真实到期时刻（expires_at 缺失时按 PEM 解析），UI 的有效期/
  // 重签时间以它为门——只判 expires_at 会让导入/集群回插的行显示「-」。
  not_after?: string | null
  created_at?: string
  updated_at?: string | null
  // 此刻剩余重试冷却（秒，向上取整）：0=现在即可重试，null=该状态永久不可重试。
  // 后端已按 updated_at 起算扣减，前端只判 ≤0，不得再按 updated_at 二次扣减。
  retry_cooldown_seconds: number | null
}

export type ClusterNodeMode = 'master' | 'slave' | 'unknown'

export type ClusterNodeStatus = 'pending' | 'online' | 'offline'

export interface ClusterHealth {
  readonly caddy_ok: boolean
  readonly rules_count: number
  readonly certs_expiring_30d: number
  readonly last_sync_at: string
  readonly last_sync_error: string
  readonly sync_error_code?: string
  readonly uptime_sec: number
  readonly crs_version?: string
  readonly ip2region_version?: string
  readonly threat_version?: string
  readonly crawler_version?: string
}

interface ClusterSectionSync {
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
  readonly server_map_lat: number
  readonly server_map_lon: number
  readonly site_inherited: boolean
  readonly section_sync?: readonly ClusterSectionSync[] | null
}

/** 集群同步错误码（后端下发 health.sync_error_code 的已知值域，驱动错误文案翻译） */
type ClusterSyncErrorCode = 'schema_too_new' | 'schema_too_old' | 'signature_invalid' | 'pin_mismatch' | 'validation_failed' | 'apply_failed' | 'transport_error'

type ClusterHealthWithSyncError = ClusterHealth & { readonly sync_error_code?: ClusterSyncErrorCode }

/** 节点视图模型（收敛：ClusterSettings/ClusterMasterPanel 原两处重复
 *  声明）——health.sync_error_code 收窄为已知错误码联合 */
export type ClusterNodeWithSyncError = Omit<ClusterNode, 'health'> & { readonly health: ClusterHealthWithSyncError | null }

export interface ClusterStatus {
  readonly node_mode: ClusterNodeMode
  readonly cluster_version: number
  readonly master_url: string
  readonly sync_interval: number
  readonly sync_users: boolean
  readonly sync_rules: boolean
  readonly sync_security: boolean
  readonly cluster_active: boolean
  readonly applied_version: number
  readonly last_sync_at: string
  readonly last_sync_error: string
  /** 后端 models.ClusterStatus 随状态下发（apply_failed/pin_mismatch 等），驱动从节点面板补救按钮与错误文案翻译 */
  readonly sync_error_code?: string
  readonly pending_count: number
  readonly approved_count: number
  /** 从节点→主节点链路为明文 HTTP 时常驻 true（后端 models.ClusterStatus）。*/
  readonly transport_insecure: boolean
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
 * GET /config 响应（前端消费字段子集，单一事实源）
 * 与后端 models.GlobalConfig 的 json 契约逐字段对齐；集群专属字段
 * （is_master/master_url/sync_interval 等）与敏感字段（dns_credentials）不在此面——
 * is_master 的 /config 消费投影见 stores/auth.ts 的 ConfigProjection。
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
  task_log_size_mb: number
  audit_log_size_mb: number
  runtime_log_size_mb: number
  access_log_json: boolean
  access_log_format: string
  audit_retention_months: number
  // 威胁大屏本站坐标（v3）：0,0=未设置（大屏回退地图视觉中心）
  server_map_lat: number
  server_map_lon: number
  threat_screen_mode: string
  threat_traffic_sample_n: number
  security_events_retention_days: number
  security_events_row_cap: number
  jwt_expire_minutes: number
  timezone: string
  mfa_write_guard: boolean
  mfa_lockout_enabled: boolean
  // v2.3.x 受信代理（CDN 真实 IP）：ranges/headers 为 JSON 数组文本（有序）；
  // range_refs 为引用的 IP 地址列表 id（JSON 整数数组文本，与 ranges 合并生效）。
  trusted_proxy_enabled: boolean
  trusted_proxy_ranges: string
  trusted_proxy_range_refs: string
  trusted_proxy_headers: string
  trusted_proxy_strict: boolean
  acme_email: string
  cert_expiry_days: number
  cert_renewal_days: number
  cert_renewal_attempts: number
  default_ca_provider_id: number
  github_proxy_url?: string
  // GitHub 访问令牌是否已配置（后端只回传布尔，不回传令牌本体）：隐显占位用
  has_github_token?: boolean
}
