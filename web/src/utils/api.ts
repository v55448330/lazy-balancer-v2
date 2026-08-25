import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig } from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import type {
  APIResponse,
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
  acme_email: string
  cert_expiry_days: number
  cert_renewal_days: number
  cert_renewal_attempts: number
  default_ca_provider_id: number
  dns_provider: string
  mfa_write_guard: boolean
  mfa_lockout_enabled: boolean
}

interface RequestClient {
  get(url: '/system/info', config?: AxiosRequestConfig): Promise<APIResponse<SystemInfo>>
  get(url: '/system/metrics', config?: AxiosRequestConfig): Promise<APIResponse<SystemMetrics>>
  get(url: '/metrics/realtime', config?: AxiosRequestConfig): Promise<APIResponse<RealtimeTraffic>>
  get(url: '/caddy/metrics', config?: AxiosRequestConfig): Promise<APIResponse<CaddyMetrics>>
  get(url: '/caddy/host-metrics', config?: AxiosRequestConfig): Promise<APIResponse<HostMetrics[]>>
  get(url: '/rules', config?: AxiosRequestConfig): Promise<APIResponse<Rule[]>>
  get(url: '/metrics/overview', config?: AxiosRequestConfig): Promise<APIResponse<MetricsOverview>>
  get(url: '/metrics/connections', config?: AxiosRequestConfig): Promise<APIResponse<ConnectionStats>>
  get(url: '/caddy/status', config?: AxiosRequestConfig): Promise<APIResponse<{ status: string; apply_error?: string; config_consistent?: string; config_drift?: string }>>
  get(url: '/config', config?: AxiosRequestConfig): Promise<APIResponse<GlobalConfigData>>
  get(url: '/admin-tls', config?: AxiosRequestConfig): Promise<APIResponse<{ enabled: boolean; mode: string; cert_info?: { domain: string; issuer: string; not_after: string; days_left: number } | null }>>
  get<T = APIResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T>
  post<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  put<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  patch<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  delete<T = APIResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T>
}

// v2.1.8 MFA step-up 弹码：返回验证码或 null（取消）。
let mfaPromptOpen = false
// R72 八次：MFA 宽限窗提示节流（60 秒一次）
let lastMfaGraceNoticeAt = 0

// R72 十三次：最近一次宽限窗放行时间戳——showSaveResult 读取（导出 getter），
// 距今 <3s 视为「本次保存刚经过宽限窗」，业务 toast 追加（MFA 已验证）。
// R72 十五次：区分两种来源——grace（用户不知情，业务提示需说明）与 justNow
//（弹码后重试，用户刚验证过，业务提示不加缀）。
let mfaGraceLastAt = 0
let mfaVerifiedJustNowAt = 0
export const wasRecentMfaGrace = (): boolean =>
  Date.now() - mfaGraceLastAt < 3_000 && Date.now() - mfaVerifiedJustNowAt > 3_000

// R72 十八次（用户裁决）：写操作成功提示的统一 MFA 装饰——宽限窗内（用户不知情）
// 前缀「MFA 在验证窗口期，本次操作免验证，」；弹码后重试（用户刚验证）不加缀。
// 所有写事件的成功提示都应经此助手发出。
export const mfaAwareSuccess = (message: string): void => {
  if (wasRecentMfaGrace()) {
    ElMessage.success(`MFA 在验证窗口期，本次操作免验证，${message}`)
    return
  }
  ElMessage.success(message)
}
const promptMfaCode = (): Promise<string | null> =>
  new Promise((resolve) => {
    if (mfaPromptOpen) { resolve(null); return }
    mfaPromptOpen = true
    ElMessageBox.prompt('请输入 6 位验证码（或恢复代码）', 'MFA 验证', {
      confirmButtonText: '验证',
      cancelButtonText: '取消',
      inputPattern: /^.{6,16}$/,
      inputErrorMessage: '请输入验证码或恢复代码',
      type: 'warning',
    })
      .then(({ value }) => resolve(value.trim()))
      .catch(() => resolve(null))
      .finally(() => { mfaPromptOpen = false })
  })

let sessionExpiredDialogOpen = false

// Blob 下载（配置导出、MCP 手册）失败时，错误响应体是 Blob 而非 JSON，
// 需读出文本后解析后端 message，否则只能展示 axios 的英文兜底文案。
async function blobErrorMessage(responseData: unknown): Promise<string | undefined> {
  if (!(responseData instanceof Blob) || responseData.size === 0) return undefined
  try {
    const parsed: unknown = JSON.parse(await responseData.text())
    if (typeof parsed === 'object' && parsed !== null && 'message' in parsed && typeof (parsed as { message: unknown }).message === 'string') {
      return (parsed as { message: string }).message
    }
  } catch {
    return undefined
  }
  return undefined
}

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
    // R72 八次→十三次（用户裁决）：宽限窗放行时记录时间戳（mfaGraceLastAt）——
    // showSaveResult 等页面级反馈读取它，在「保存成功」等 toast 文案后追加
    // 「（MFA 已验证）」；silent 请求（无页面级反馈）弹独立 info 兜底（60s 节流）。
    const mfaVerifiedAgo = response.headers?.['x-mfa-verified-seconds-ago']
    if (mfaVerifiedAgo !== undefined) {
      mfaGraceLastAt = Date.now()
      if (response.config?.silent) {
        const now = Date.now()
        if (now - lastMfaGraceNoticeAt > 60_000) {
          lastMfaGraceNoticeAt = now
          ElMessage.info('MFA 在验证窗口期，本次操作免验证')
        }
      }
    }
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
    const backendMsg = error.response?.data?.message ?? (await blobErrorMessage(error.response?.data))
    // 网络层失败（断网/DNS/CORS）没有任何响应体，502/504 网关错误返回的是 HTML
    // 而非后端 JSON，两者都会把 axios 英文原文（"Network Error" /
    // "Request failed with status code 502"）直接抛给用户，这里统一映射为
    // 中文提示；后端 message 与 Blob 导出错误路径保持最高优先级。
    let fallback = ''
    if (!error.response) {
      fallback = /timeout/i.test(String(error.message)) ? '请求超时，请稍后重试' : '网络连接失败，请检查网络连接'
    } else if (!backendMsg) {
      if (status === 502 || status === 503 || status === 504) {
        fallback = '服务暂时不可用，请稍后重试'
      } else if (status === 500) {
        fallback = '服务器内部错误'
      } else {
        fallback = error.message
      }
    }
    const message = backendMsg || fallback || '网络错误'
    const isLoginRequest = error.config?.url?.includes('/auth/login') || error.config?.url?.includes('/auth/ticket-login')
    if (status === 401) {
      // R72 D-新2：MFA 自助端点的 401 是「凭证错误」（持有效 JWT 输错密码/验证码），
      // 不是会话失效——直接传播后端文案，不得弹「会话失效」并强制登出。
      if (error.config?.url?.includes('/auth/mfa/')) {
        return Promise.reject(new ApiRequestError(message, status))
      }
      if (!isLoginRequest) {
        const { useAuthStore } = await import('@/stores/auth')
        const authStore = useAuthStore()
        if (authStore.intentionalLogout || !authStore.token || !localStorage.getItem('token')) {
          return Promise.reject(new Error(message))
        }
        if (!sessionExpiredDialogOpen) {
          sessionExpiredDialogOpen = true
          // R71 D-新1：confirm 的取消分支与确定行为完全相同，「取消」形同虚设且误导
          // ——改单按钮 alert（会话已死，任何请求都会 401，刷新是唯一合理结局）。
          ElMessageBox.alert(backendMsg || '登录已过期，请重新登录', '会话失效', {
            confirmButtonText: '重新登录',
            type: 'warning',
          }).finally(() => {
            localStorage.removeItem('token')
            window.location.reload()
          })
        }
      }
    } else if (status === 428 && error.response?.data?.code === 428 && error.config && !error.config._mfaRetried) {
      // v2.1.8 MFA step-up：写操作（或票据签发）需 10 分钟内的 MFA 验证——
      // 全局弹码验证 → 新 JWT → 原请求自动重试一次。全站生效，页面零改动。
      try {
        const { useAuthStore } = await import('@/stores/auth')
        const authStore = useAuthStore()
        const code = await promptMfaCode()
        if (code) {
          await authStore.refreshMfaStep(code)
          // R72 十五次（用户裁决）：验证成功不再独立 toast——用户刚输完码知道
          // 验证成功，反馈并入重试后的业务提示（宽限头会照常发出，但
          // wasRecentMfaGrace 因 justNow 标记而不加缀）。
          mfaVerifiedJustNowAt = Date.now()
          error.config._mfaRetried = true
          return service.request(error.config)
        }
        // 取消弹码：温和提示，不暴露 428 英文常量。
        if (!error.config?.silent) {
          ElMessage.warning('已取消 MFA 验证，操作未执行')
        }
      } catch (stepError: unknown) {
        // R72 D-新2/D-新4：verify-step 失败（如输错码，401 文案已由 /auth/mfa/
        // 豁免分支携带）——给出可见反馈，不再静默吞掉。
        ElMessage.error(stepError instanceof Error ? stepError.message : 'MFA 验证未完成')
        return Promise.reject(stepError)
      }
    } else if (!isLoginRequest) {
      if (!error.config?.silent) {
        ElMessage.error(message)
      }
    }
    return Promise.reject(new ApiRequestError(message, status))
  }
)

// 响应拦截器已将 AxiosResponse 解包为 response.data，因此这里的运行时
// 返回值即 T；axios 1.19 的泛型收紧后需在封装边界做一次窄断言对齐契约。
export const request: RequestClient = {
  get<T = APIResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.get(url, config) as Promise<T>
  },
  post<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return service.post(url, data, config) as Promise<T>
  },
  put<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return service.put(url, data, config) as Promise<T>
  },
  patch<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return service.patch(url, data, config) as Promise<T>
  },
  delete<T = APIResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.delete(url, config) as Promise<T>
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
