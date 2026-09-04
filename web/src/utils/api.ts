import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig } from 'axios'
import { h, nextTick, ref } from 'vue'
import { ElInputOtp, ElMessage, ElMessageBox } from 'element-plus'
import type { InputOtpInstance } from 'element-plus'
import 'element-plus/es/components/input-otp/style/css'
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
  get(url: '/caddy/status', config?: AxiosRequestConfig): Promise<APIResponse<{ status: string; pid?: string; apply_error?: string; config_consistent?: string; config_drift?: string }>>
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
// R73：兜底 toast 的句柄——页面级反馈（mfaAwareSuccess）渲染同文案时关闭它，
// 否则用户会同时看到「免验证」兜底条与「免验证+保存成功」业务条两条重复提示。
let lastMfaGraceNotice: { close: () => void } | null = null

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
    // 同文案的兜底条已存在时关闭——最终只留这一条（兜底条的职责是覆盖无页面
    // 反馈的静默请求；有页面反馈时它即冗余）。
    lastMfaGraceNotice?.close()
    lastMfaGraceNotice = null
    ElMessage.success(`MFA 在验证窗口期，本次操作免验证，${message}`)
    return
  }
  ElMessage.success(message)
}
// 用户裁决（N+10）：除登录（Login.vue）与重置 MFA（Users.vue resetMfa，均走
// 归一化 + 6-16 位恢复码契约）外，step-up 写守卫链（含配置导入等全部 428 重试
// 流）仅接受 6 位动态验证码——后端 MFAVerifyTOTPCode 同口径拒绝恢复码，此处
// 前端同步收口：文案不再提及恢复代码，校验为 6 位数字。
export const normalizeMfaCodeInput = (raw: string): string => raw.trim().split(/\s+/)[0] ?? ''

export const validateMfaCodeInput = (raw: string): boolean => {
  const code = normalizeMfaCodeInput(raw)
  return code.length >= 6 && code.length <= 16
}

const validateTotpCodeInput = (raw: string): boolean => /^\d{6}$/.test(normalizeMfaCodeInput(raw))

const promptMfaCode = (): Promise<string | null> =>
  new Promise((resolve) => {
    if (mfaPromptOpen) { resolve(null); return }
    mfaPromptOpen = true
    // el-input-otp 自定义内容（替换原生 prompt 的普通 input）：值在 confirm 时从
    // otpCode 读取；填满 6 位自动触发 confirm（finish → handlers.confirm）。
    // message 函数在 MessageBox 渲染上下文中执行，otpCode 变更会驱动重渲染。
    const otpCode = ref('')
    const otpRef = ref<InputOtpInstance>()
    ElMessageBox({
      title: 'MFA 验证',
      type: 'warning',
      // 自定义类：OTP 内容块加高正文区，全局 CSS 把 warning 图标从垂直居中改为
      // 与首行文本顶对齐（EP 2.14 容器 align-items:center 会让图标悬在空中部）
      customClass: 'mfa-stepup-message-box',
      showCancelButton: true,
      confirmButtonText: '验证',
      cancelButtonText: '取消',
      message: ({ confirm }) =>
        h('div', { style: 'display: flex; flex-direction: column; gap: 14px; padding-top: 2px;' }, [
          h('div', null, '请输入 6 位动态验证码（此操作不支持恢复代码）'),
          h(ElInputOtp, {
            ref: otpRef,
            modelValue: otpCode.value,
            'onUpdate:modelValue': (v: string) => { otpCode.value = v },
            length: 6,
            inputmode: 'numeric',
            validator: (char: string) => /^\d$/.test(char),
            onFinish: () => { if (validateTotpCodeInput(otpCode.value)) confirm() },
            style: 'align-self: center;',
          }),
        ]),
      beforeClose: (action, _instance, done) => {
        if (action === 'confirm' && !validateTotpCodeInput(otpCode.value)) {
          ElMessage.error('请输入 6 位数字验证码')
          return
        }
        done()
      },
    })
      .then(() => resolve(normalizeMfaCodeInput(otpCode.value)))
      .catch(() => resolve(null))
      .finally(() => { mfaPromptOpen = false })
    // OTP 自动聚焦：MessageBox 的 autofocus 默认落在确认按钮，nextTick 后夺回给 OTP
    void nextTick(() => otpRef.value?.focus())
  })

let sessionExpiredDialogOpen = false
// 用户指令（会话过期全站止损）：首个 401 的「会话失效」弹窗出现后、用户点击
// 「重新登录」前，页面轮询器（usePollingTask / 裸 setInterval / blob 下载）仍按
// 各自周期出站请求，每个再吃一个 401，后端认证拒绝审计被刷屏。置位后下方请求
// 拦截器直接拒绝、不再出站任何请求；标志随确认后的 location.reload() 一并消亡。
let sessionExpiredDetected = false

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

// 会话过期止损的请求拦截拒绝（未出站、无响应体）：打标供响应拦截器识别并
// 原样透传——否则会被下方兜底逻辑映射成「网络连接失败」toast。
const sessionHaltedRequestError = (): ApiRequestError => {
  const error = new ApiRequestError('登录已过期', 401)
  ;(error as ApiRequestError & { sessionExpiredHalted?: boolean }).sessionExpiredHalted = true
  return error
}

const service: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

service.interceptors.request.use(
  (config) => {
    // 会话过期全站止损（用户指令，见 sessionExpiredDetected 注释）：弹窗等待
    // 确认期间不再出站任何请求。
    if (sessionExpiredDetected) throw sessionHaltedRequestError()
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
      // R73：弹码验证后的自动重试不再发「免验证」兜底——用户刚输完码（与 R72 十五次
      // 页面级反馈同口径）；且新 toast 发出前关闭上一条，避免连发重复。
      if (response.config?.silent && Date.now() - mfaVerifiedJustNowAt > 3_000) {
        const now = Date.now()
        if (now - lastMfaGraceNoticeAt > 60_000) {
          lastMfaGraceNoticeAt = now
          lastMfaGraceNotice?.close()
          lastMfaGraceNotice = ElMessage.info('MFA 在验证窗口期，本次操作免验证')
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
    // 止损拦截的拒绝：请求未出站，不 toast、不走 401 会话失效弹窗（弹窗已在
    // 展示中），原样透传给调用方。
    if ((error as { sessionExpiredHalted?: boolean }).sessionExpiredHalted) {
      return Promise.reject(error)
    }
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
      // C-1 补正：管理员重置端点 /users/:id/mfa/reset 同样以 401 返回「验证码错误」，
      // 需同口径放行（Users.vue 的 catch 展示后端文案供重试），否则误杀会话并在
      // 锁定开关默认关闭时计入失败锁定计数。仅匹配 /mfa/reset 路径段，不泛化放行。
      if (error.config?.url?.includes('/auth/mfa/') || error.config?.url?.includes('/mfa/reset')) {
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
          // 用户指令（会话过期全站止损）：置位后请求拦截器拒绝后续所有出站请求，
          // 阻断弹窗等待期间轮询器的 401 刷屏；随确认后的 reload 一并消亡。
          sessionExpiredDetected = true
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
        // D5 IMP-2：静默取消同样以中文文案 reject，避免下方透出 428 英文常量。
        return Promise.reject(new ApiRequestError('已取消 MFA 验证，操作未执行', status))
      } catch (stepError: unknown) {
        // R72 D-新2/D-新4：verify-step 失败（如输错码，401 文案已由 /auth/mfa/
        // 豁免分支携带）——给出可见反馈，不再静默吞掉。
        ElMessage.error(stepError instanceof Error ? stepError.message : 'MFA 验证未完成')
        // D5 IMP-1：已 toast 的错误打标，下游 catch（Users.vue resetMfa）跳过二次弹窗。
        if (stepError instanceof Error) {
          ;(stepError as Error & { mfaSurfaced?: boolean }).mfaSurfaced = true
        }
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
