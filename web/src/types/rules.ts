export type RuleProtocol = 'http' | 'tcp'
export type UpstreamProtocol = 'http' | 'https' | 'tcp' | 'tls'

export interface Upstream {
  id: number
  rule_id: string
  host: string
  port: number
  weight: number
  // 废弃列（写侧恒 0，渲染只读规则级 dynamic_dns）；响应面已 omitempty 收敛，键可能缺席
  dynamic_dns?: boolean
  enabled: boolean
  protocol: UpstreamProtocol
  max_connections: number
  // 逐上游回源域名（2026-10-10）：驱动该上游回源 Host 头与 HTTPS SNI；空=跟随后端域名
  origin_domain?: string
}

export type UpstreamInput = Omit<Upstream, 'id' | 'rule_id'> & {
  id?: number
  rule_id?: string
}

export interface PathRuleUpstream {
  protocol: 'http' | 'https'
  address: string
  port: number
  weight: number
}

// 流程弹框「路由分发」行（RuleFlowTarget.pathRules 元素，渲染投影形状）：上游仅
// 携带主机/端口/启用位，健康态由弹框按 upstreamHealth 快照同逻辑映射。
// response_mode 非空 = 静态返回/301 跳转（不转发上游）。
export interface RuleFlowPathRule {
  path: string
  match_type: string
  upstreams: Array<{ host: string; port: number; enabled: boolean }> | null
  response_mode?: '' | 'static' | 'redirect'
  response_status?: number
  redirect_to?: string
}

export interface PathRule {
  id?: number
  match_type: 'prefix' | 'exact'
  path: string
  // 上游 path 改写：空串=原样转发；非空前缀剥匹配前缀后前置、精确整体替换（query 保留）
  upstream_path: string
  sort_order: number
  upstreams: PathRuleUpstream[] | null
  // 直接返回/301 跳转（2026-10-10 用户裁定）：''=转发上游（现状）/static=静态响应/redirect=301 跳转
  // 'forward' 为 UI 选择器哨兵（el-select 空串选项不显示标签，显示为「请选择」）——提交时归一为 ''
  response_mode?: '' | 'static' | 'redirect' | 'forward'
  response_status?: number
  response_body?: string
  response_content_type?: '' | 'text/plain' | 'application/json' | 'text/html'
  redirect_to?: string
}

export interface ProxyTimeoutConfig {
  proxy_dial_timeout: number
  proxy_response_header_timeout: number
  proxy_read_timeout: number
  proxy_write_timeout: number
  proxy_stream_timeout: number
  proxy_flush_interval: number
  proxy_stream_close_delay: number
}

export interface Rule extends ProxyTimeoutConfig {
  id: number
  caddy_id: string
  name: string
  description: string
  protocol: RuleProtocol
  domain: string
  listen_port: number
  strategy: string
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  dns_family: string
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_unhealthy_threshold: number
  health_check_healthy_threshold: number
  enable_active_health_check: boolean
  tcp_health_check_port: number
  tcp_proxy_protocol: boolean
  tcp_try_duration: number
  tcp_try_interval: number
  request_body_max_size_mb: number
  upstream_keepalive_timeout: number
  server_tokens_hidden: number
  // NTLM 兼容开关：1=开启（要求 strategy=cookie；仅 HTTP 规则）
  ntlm_compatible: number
  // 通用列：1=上游强制 HTTP/1.1（https 上游禁 ALPN h2）；NTLM 接管时恒 1
  upstream_force_http1: number
  // 认证网关（forward_auth）：1=全部请求先经网关校验（仅 HTTP 规则）
  forward_auth_enabled: number
  // 网关地址 http(s)://host:port
  forward_auth_upstream: string
  // 网关校验路径（默认 /api/authz/forward-auth）
  forward_auth_uri: string
  // 认证通过后拷入原请求的身份头清单（逗号分隔）
  forward_auth_copy_headers: string
  host_header: string
  // 健康检查域名：主动健康检查 probe 的 Host 头；空=跟随 host_header
  health_check_host?: string
  upstreams: Upstream[] | null
  enable_tls: boolean
  tls_source: string
  acme_config_id: number
  ca_provider_id: number
  tls_cert?: string
  tls_key?: string
  // GetRule 对只读 Key/非管理员掩码 tls_key 时的「已有隐藏私钥」标记
  tls_key_set?: boolean
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string
  enabled: boolean
  log_enabled: boolean
  custom_routes_enabled: boolean
  path_rules: PathRule[]
  // 规则级阶段拦截页覆盖 4 字段已退役（触发归因裁定）：后端保留列停用，
  // 响应仍可能携带——类型保留仅为读取容忍，前端不再消费/提交。
  block_page_stage1_id: number
  block_page_stage1_status: number
  block_page_stage3_id: number
  block_page_stage3_status: number
  created_by: number
  updated_by: number
  created_at: string
  updated_at: string | null
}

export interface CreateRuleRequest extends ProxyTimeoutConfig {
  name: string
  description: string
  protocol: RuleProtocol
  domain: string
  listen_port: number
  strategy: string
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  dns_family: string
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_unhealthy_threshold: number
  health_check_healthy_threshold: number
  enable_active_health_check: boolean
  tcp_health_check_port: number
  tcp_proxy_protocol: boolean
  tcp_try_duration: number
  tcp_try_interval: number
  request_body_max_size_mb: number
  upstream_keepalive_timeout: number
  server_tokens_hidden: number
  ntlm_compatible: number
  upstream_force_http1: number
  // 认证网关四件套（仅 HTTP；enabled=1 时 upstream 必填）
  forward_auth_enabled: number
  forward_auth_upstream: string
  forward_auth_uri: string
  forward_auth_copy_headers: string
  custom_routes_enabled: boolean
  path_rules: PathRule[]
  host_header: string
  health_check_host?: string
  upstreams: UpstreamInput[]
  enable_tls: boolean
  tls_source: string
  acme_config_id: number
  ca_provider_id: number
  tls_cert: string
  tls_key: string
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string
  log_enabled: boolean
}

export interface UpdateRuleRequest extends Omit<CreateRuleRequest,
  | 'request_body_max_size_mb'
  | 'upstream_keepalive_timeout'
  | 'server_tokens_hidden'
  | 'ntlm_compatible'
  | 'upstream_force_http1'
  | 'forward_auth_enabled'
  | 'forward_auth_upstream'
  | 'forward_auth_uri'
  | 'forward_auth_copy_headers'
  | 'custom_routes_enabled'
  | 'tcp_proxy_protocol'
  | keyof ProxyTimeoutConfig
  | 'path_rules'
  | 'ca_provider_id'
  | 'host_header'> {
  // host_header 可选（2026-10-10 向导退役后端域名配置项）：省略=保留原值（后端 *string 合并语义）
  host_header?: string
  request_body_max_size_mb?: number
  upstream_keepalive_timeout?: number
  server_tokens_hidden?: number
  ntlm_compatible?: number
  upstream_force_http1?: number
  // 认证网关四件套：省略=保留原值（后端指针合并语义）；显式空串=清空
  forward_auth_enabled?: number
  forward_auth_upstream?: string
  forward_auth_uri?: string
  forward_auth_copy_headers?: string
  custom_routes_enabled?: boolean
  tcp_proxy_protocol: boolean
  proxy_dial_timeout?: number
  proxy_response_header_timeout?: number
  proxy_read_timeout?: number
  proxy_write_timeout?: number
  proxy_stream_timeout?: number
  proxy_flush_interval?: number
  proxy_stream_close_delay?: number
  path_rules?: PathRule[]
  ca_provider_id?: number
  enabled: boolean
  // 乐观并发前置条件：编辑向导回传打开时的 updated_at；省略=不校验。
  expected_updated_at?: string
}
