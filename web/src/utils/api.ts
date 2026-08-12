import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig } from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import type {
  ApiResponse,
  CaddyMetrics,
  ConnectionStats,
  HostMetrics,
  MetricsOverview,
  RealtimeTraffic,
  Rule,
  SystemInfo,
  SystemMetrics,
} from '@/types'

declare module 'axios' {
  interface AxiosRequestConfig {
    /** Skip the global error toast for this request (used by background pollers). */
    silent?: boolean
  }
}

interface GlobalConfigData {
  log_level: string
  caddy_log_path: string
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
  runtime_log_size_mb: number
  access_log_json: boolean
  access_log_format: string
  audit_retention_months: number
  security_events_retention_days: number
  security_events_retention_max: number
  jwt_expire_minutes: number
  timezone: string
  acme_email: string
  cert_expiry_days: number
  cert_renewal_days: number
  cert_renewal_attempts: number
  default_ca_provider_id: number
  dns_provider: string
}

interface RequestClient {
  get(url: '/system/info', config?: AxiosRequestConfig): Promise<ApiResponse<SystemInfo>>
  get(url: '/system/metrics', config?: AxiosRequestConfig): Promise<ApiResponse<SystemMetrics>>
  get(url: '/metrics/realtime', config?: AxiosRequestConfig): Promise<ApiResponse<RealtimeTraffic>>
  get(url: '/caddy/metrics', config?: AxiosRequestConfig): Promise<ApiResponse<CaddyMetrics>>
  get(url: '/caddy/host-metrics', config?: AxiosRequestConfig): Promise<ApiResponse<HostMetrics[]>>
  get(url: '/rules', config?: AxiosRequestConfig): Promise<ApiResponse<Rule[]>>
  get(url: '/metrics/overview', config?: AxiosRequestConfig): Promise<ApiResponse<MetricsOverview>>
  get(url: '/metrics/connections', config?: AxiosRequestConfig): Promise<ApiResponse<ConnectionStats>>
  get(url: '/caddy/status', config?: AxiosRequestConfig): Promise<ApiResponse<{ status: string }>>
  get(url: '/config', config?: AxiosRequestConfig): Promise<ApiResponse<GlobalConfigData>>
  get(url: '/admin-tls', config?: AxiosRequestConfig): Promise<ApiResponse<{ enabled: boolean; mode: string; cert_info?: { domain: string; issuer: string; not_after: string; days_left: number } | null }>>
  get<T = ApiResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T>
  post<T = ApiResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  put<T = ApiResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  patch<T = ApiResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  delete<T = ApiResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T>
}

let sessionExpiredDialogOpen = false

export class ApiRequestError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
    this.name = 'ApiRequestError'
  }
}

const service: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

service.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token && token !== 'null' && token !== 'undefined') {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

service.interceptors.response.use(
  (response) => {
    const res = response.data
    if (res.code !== undefined && res.code !== 0 && res.code !== 200) {
      if (!response.config.silent) {
        ElMessage.error(res.message || '请求失败')
      }
      return Promise.reject(new Error(res.message || '请求失败'))
    }
    return res
  },
  async (error) => {
    if (axios.isCancel(error)) return Promise.reject(error)
    const status = error.response?.status
    const backendMsg = error.response?.data?.message
    const message = backendMsg || error.message || '网络错误'
    const isLoginRequest = error.config?.url?.includes('/auth/login') || error.config?.url?.includes('/auth/ticket-login')
    if (status === 401) {
      if (!isLoginRequest) {
        const { useAuthStore } = await import('@/stores/auth')
        const authStore = useAuthStore()
        if (authStore.intentionalLogout || !authStore.token || !localStorage.getItem('token')) {
          return Promise.reject(new Error(message))
        }
        if (!sessionExpiredDialogOpen) {
          sessionExpiredDialogOpen = true
          ElMessageBox.confirm(backendMsg || '登录已过期，请重新登录', '会话失效', {
            confirmButtonText: '确定',
            cancelButtonText: '取消',
            type: 'warning',
          }).then(() => {
            localStorage.removeItem('token')
            window.location.reload()
          }).catch(() => {
            localStorage.removeItem('token')
            window.location.reload()
          })
        }
      }
    } else if (!isLoginRequest) {
      if (!error.config?.silent) {
        ElMessage.error(message)
      }
    }
    return Promise.reject(new ApiRequestError(message, status))
  }
)

export const request: RequestClient = {
  get<T = ApiResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.get(url, config)
  },
  post<T = ApiResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return service.post(url, data, config)
  },
  put<T = ApiResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return service.put(url, data, config)
  },
  patch<T = ApiResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return service.patch(url, data, config)
  },
  delete<T = ApiResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.delete(url, config)
  },
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.max(Math.floor(Math.log(bytes) / Math.log(k)), 0), sizes.length - 1)
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export function isTokenExpired(token: string): boolean {
  if (!token || token === 'null' || token === 'undefined') return true
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return true
    const encodedPayload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const paddedPayload = encodedPayload.padEnd(encodedPayload.length + (4 - encodedPayload.length % 4) % 4, '=')
    const payload: unknown = JSON.parse(atob(paddedPayload))
    if (!payload || typeof payload !== 'object' || !('exp' in payload) || typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return true
    const exp = payload.exp * 1000
    if (!Number.isFinite(exp)) return true
    return Date.now() >= exp
  } catch {
    return true
  }
}

export default service
