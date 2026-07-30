export type IpAclMode = '' | 'allow' | 'deny'

export interface Upstream {
  id: number
  rule_id: string
  host: string
  port: number
  weight: number
  domain: string
  dynamic_dns: boolean
  enabled: boolean
  protocol: string
  dns_server: string
  max_connections: number
}

export type UpstreamInput = Omit<Upstream, 'id' | 'rule_id' | 'dns_server'> & {
  id?: number
  rule_id?: string
  dns_server?: string
}

export interface PathRuleUpstream {
  protocol: 'http' | 'https'
  address: string
  port: number
  weight: number
}

export interface PathRule {
  id?: number
  match_type: 'prefix' | 'exact'
  path: string
  sort_order: number
  upstreams: PathRuleUpstream[] | null
}

export interface ProxyTimeoutConfig {
  proxy_dial_timeout: number
  proxy_response_header_timeout: number
  proxy_read_timeout: number
  proxy_write_timeout: number
  proxy_stream_timeout: number
}

export interface Rule extends ProxyTimeoutConfig {
  id: number
  caddy_id: string
  name: string
  description: string
  protocol: string
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
  host_header: string
  upstreams: Upstream[] | null
  enable_tls: boolean
  tls_source: string
  acme_config_id: number
  ca_provider_id: number
  tls_cert?: string
  tls_key?: string
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string
  enabled: boolean
  log_enabled: boolean
  ip_acl_mode: IpAclMode
  ip_acl_list: string[]
  custom_routes_enabled: boolean
  path_rules: PathRule[]
  created_by: number
  updated_by: number
  created_at: string
  updated_at: string | null
}

export interface CreateRuleRequest extends ProxyTimeoutConfig {
  name: string
  description: string
  protocol: string
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
  ip_acl_mode: IpAclMode
  ip_acl_list: string[]
  custom_routes_enabled: boolean
  path_rules: PathRule[]
  host_header: string
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
  | 'ip_acl_mode'
  | 'ip_acl_list'
  | 'custom_routes_enabled'
  | 'tcp_proxy_protocol'
  | keyof ProxyTimeoutConfig
  | 'path_rules'
  | 'ca_provider_id'> {
  request_body_max_size_mb?: number
  upstream_keepalive_timeout?: number
  server_tokens_hidden?: number
  ip_acl_mode?: IpAclMode
  ip_acl_list?: string[]
  custom_routes_enabled?: boolean
  tcp_proxy_protocol: boolean
  proxy_dial_timeout?: number
  proxy_response_header_timeout?: number
  proxy_read_timeout?: number
  proxy_write_timeout?: number
  proxy_stream_timeout?: number
  path_rules?: PathRule[]
  ca_provider_id?: number
  enabled: boolean
}

export interface RuleAclRequest {
  ip_acl_mode: IpAclMode
  ip_acl_list: string[]
}
