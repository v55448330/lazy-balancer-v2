import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig } from 'axios'
import { h, nextTick, ref } from 'vue'
import { ElInputOtp, ElMessage, ElMessageBox } from 'element-plus'
import type { InputOtpInstance } from 'element-plus'
import 'element-plus/es/components/input-otp/style/css'
import type {
  APIResponse,
  ConnectionStats,
  GlobalConfigData,
  RealtimeTraffic,
  Rule,
  SystemInfo,
  SystemMetrics,
  UpdateCurrentUserInput,
} from '@/types'
import { classifyAuthFailure, createMfaGraceTracker, createMfaStepUp, createSessionStepUpGate, isRequestAuthTokenCurrent, runMfaStepUpRequest } from '@/utils/apiFailure'
import { currentSessionGeneration } from '@/utils/sessionIdentity'

declare module 'axios' {
  interface AxiosRequestConfig {
    /** Skip the global error toast for this request (used by background pollers). */
    silent?: boolean
    /** 发起请求时的本地会话令牌；响应 401 用它识别迟到的旧会话请求。 */
    _authToken?: string
    /** 发起请求时的身份代际；428 在弹码、刷新与重放前复核。 */
    _sessionGeneration?: number
  }
}


interface RequestClient {
  get(url: '/system/info', config?: AxiosRequestConfig): Promise<APIResponse<SystemInfo>>
  get(url: '/system/metrics', config?: AxiosRequestConfig): Promise<APIResponse<SystemMetrics>>
  get(url: '/metrics/realtime', config?: AxiosRequestConfig): Promise<APIResponse<RealtimeTraffic>>
  get(url: '/rules', config?: AxiosRequestConfig): Promise<APIResponse<Rule[]>>
  get(url: '/metrics/connections', config?: AxiosRequestConfig): Promise<APIResponse<ConnectionStats>>
  get(url: '/caddy/status', config?: AxiosRequestConfig): Promise<APIResponse<{ status: string; pid?: string; apply_error?: string; background_apply_error?: string; config_consistent?: string; config_drift?: string; config_drift_since?: string }>>
  get(url: '/config', config?: AxiosRequestConfig): Promise<APIResponse<GlobalConfigData>>
  get(url: '/admin-tls', config?: AxiosRequestConfig): Promise<APIResponse<{ enabled: boolean; mode: string; config_unavailable?: boolean; cert_info?: { domain: string; issuer: string; not_after: string; days_left: number } | null; cert_info_error?: string }>>
  get<T = APIResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T>
  post<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  put<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  // 本人资料自助更新——提交新密码必须带 current_password（后端密码确认门）。
  patch(url: '/users/me', data: UpdateCurrentUserInput, config?: AxiosRequestConfig): Promise<APIResponse>
  patch<T = APIResponse<unknown>>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T>
  delete<T = APIResponse<unknown>>(url: string, config?: AxiosRequestConfig): Promise<T>
}

// MFA step-up 与宽限窗提示的编排状态机抽到 utils/apiFailure（可在 node 下行为
// 测试）：mfaStepUp = 弹码 + verify-step 刷新单飞；mfaGrace = 60s 节流、兜底条
// 去重与「刚弹码验证」抑制。
const mfaGrace = createMfaGraceTracker()

// （用户裁决）：写操作成功提示的统一 MFA 装饰——宽限窗内（用户不知情）
// 前缀「MFA 在验证窗口期，本次操作免验证，」；弹码后重试（用户刚验证）不加缀。
// 所有写事件（含任务触发/开关、配置保存、名单增删、导入）的成功提示都应经此
// 助手发出；复制/查看类非写事件（复制密钥、读取文件内容、重新加载详情）不走
// MFA step-up，直接 ElMessage.success 即可——该豁免是契约的一部分。
export const mfaAwareSuccess = (message: string): void => {
  if (mfaGrace.consumeGraceForSuccess(Date.now())) {
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

// 428 step-up 的弹窗实现。单飞/清空时序由 utils/apiFailure.createMfaStepUp 承担
// （并发 428 共享同一 Promise；验证码消费后立刻作废，杜绝同码重放）。
const showMfaPrompt = (): Promise<string | null> =>
  new Promise<string | null>((resolve) => {
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
    // OTP 自动聚焦：MessageBox 的 autofocus 默认落在确认按钮，nextTick 后夺回给 OTP
    void nextTick(() => otpRef.value?.focus())
  })

const mfaStepUp = createMfaStepUp(showMfaPrompt)

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
  // data = 后端错误响应体（信封 { code, message, data }）。失败分支的事实披露
  // （如导入/还原的 data.warnings：规则库文件面判决、软跳过/归一化）只在这里
  // ——不回传的话调用方拿到的是被拦截器替换后的错误，除 message 外全部丢失。
  constructor(message: string, readonly status?: number, readonly data?: unknown) {
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
    const authToken = token && token !== 'null' && token !== 'undefined' ? token : undefined
    config._authToken = authToken
    config._sessionGeneration = currentSessionGeneration()
    if (authToken) {
      config.headers.Authorization = `Bearer ${authToken}`
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
    // →十三次（用户裁决）：宽限窗放行时记录时间戳（mfaGraceLastAt）——
    // showSaveResult 等页面级反馈读取它，在「保存成功」等 toast 文案后追加
    // 「（MFA 已验证）」；silent 请求（无页面级反馈）弹独立 info 兜底（60s 节流）。
    const mfaVerifiedAgo = response.headers?.['x-mfa-verified-seconds-ago']
    if (mfaVerifiedAgo !== undefined) {
      // 宽限窗放行记账：silent 请求（无页面级反馈）发一条 60s 节流的 info 兜底；
      // 弹码后的自动重试不发（用户刚输完码），同文案兜底条去重由跟踪器负责。
      mfaGrace.onGraceResponse(
        !!response.config?.silent,
        Date.now(),
        () => ElMessage.info('MFA 在验证窗口期，本次操作免验证'),
      )
    }
    if (res.code !== undefined && res.code !== 0 && res.code !== 200) {
      if (!response.config.silent) {
        ElMessage.error(res.message || '请求失败')
      }
      // 业务码失败与 HTTP 失败统一错误类型：调用方按
      // instanceof ApiRequestError 判别（如 409/业务码分支）时不再漏判。
      //
      // 契约（跨栈，前端据此分类）：业务码失败分支携带的是 **HTTP status**，
      // 因此后端必须保证「code≠0 时 HTTP 状态与业务码同值」（当前 apikeys/
      // cluster_ticket/错误分支均如此）。未来若新增「HTTP 200 + code≠0」端点，
      // 按 status===409 分类的调用方（如 useLibUpdateDialog）将静默绕过分类与
      // 重试逻辑——此契约由 tests/apiErrorContract.spec.ts 钉住现状。
      //
      // 第三参数与 HTTP 失败分支同形（error.response.data = 完整信封）：失败
      // 分支的事实披露（导入/还原的 data.warnings 等）只经 ApiRequestError.data
      // 传递，两类失败的错误对象形状必须一致，否则改走业务码信封的端点会让
      // 消费方（importFailureReport 读 data.data）静默丢失 warnings。
      // 此处 `res` 本身就是 response.data（拦截器已解包），故必须传 res 而不是
      // res.data——后者是载荷，比 HTTP 分支少一层信封。
      return Promise.reject(new ApiRequestError(res.message || '请求失败', response.status, res))
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
    const kind = classifyAuthFailure({
      status,
      dataCode: error.response?.data?.code,
      method: error.config?.method,
      url: error.config?.url,
      message,
      isLoginRequest,
      hasConfig: !!error.config,
      mfaRetried: !!error.config?._mfaRetried,
    })
    // D-新2：MFA 自助端点的 401 是「凭证错误」（持有效 JWT 输错密码/验证码），
    // 不是会话失效——直接传播后端文案，不得弹「会话失效」并强制登出。
    // 补正：管理员重置端点 /users/:id/mfa/reset 同样以 401 返回「验证码错误」，
    // 需同口径放行（Users.vue 的 catch 展示后端文案供重试），否则误杀会话。
    // 只有后端明确的「当前密码错误」才豁免会话失效；同端点的 token 过期/未登录
    // 401 仍必须进入下方重新登录流程（分类判据见 utils/apiFailure）。
    if (kind === 'credential-rejection') {
      return Promise.reject(new ApiRequestError(message, status))
    }
    if (kind === 'session-expired') {
      // 登出 A、登录 B 后，A 的在途请求才返回 401：它只属于 A，不得弹框或止损 B。
      if (error.config && !isRequestAuthTokenCurrent(error.config._authToken, localStorage.getItem('token'))) {
        return Promise.reject(new ApiRequestError(message, status, error.response?.data))
      }
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
        // D-新1：confirm 的取消分支与确定行为完全相同，「取消」形同虚设且误导
        // ——改单按钮 alert（会话已死，任何请求都会 401，刷新是唯一合理结局）。
        ElMessageBox.alert(backendMsg || '登录已过期，请重新登录', '会话失效', {
          confirmButtonText: '重新登录',
          type: 'warning',
        }).finally(() => {
          localStorage.removeItem('token')
          window.location.reload()
        })
      }
    } else if (kind === 'step-up') {
      // 428 也只能处置发起请求时的身份。MFA 刷新只换令牌、不推进代际；
      // 登录/登出/OIDC/换账号推进后，旧请求不得借用新会话验码或重放。
      // 身份比较单源在 createSessionStepUpGate（行为可被 node:test 直接钉住）。
      const isCurrent = createSessionStepUpGate(error.config?._sessionGeneration, currentSessionGeneration)
      if (!isCurrent()) {
        return Promise.reject(new ApiRequestError(message, status, error.response?.data))
      }
      try {
        // 保持动态加载以断开 api ↔ auth store 的静态循环依赖。
        const { useAuthStore } = await import('@/stores/auth')
        const authStore = useAuthStore()
        const outcome = await runMfaStepUpRequest({
          isCurrent,
          prompt: mfaStepUp.prompt,
          refresh: (code) => mfaStepUp.ensureRefresh(code, (confirmationCode) => authStore.refreshMfaStep(confirmationCode)),
          replay: () => {
            error.config._mfaRetried = true
            return service.request(error.config)
          },
          onVerified: () => { mfaGrace.markVerifiedJustNow(Date.now()) },
        })
        if (outcome.kind === 'replayed') return outcome.value
        if (outcome.kind === 'stale') {
          return Promise.reject(new ApiRequestError(message, status, error.response?.data))
        }
        // 取消弹码（共享 Promise resolve null 即用户真取消）：温和提示，不暴露 428 英文常量。
        if (!error.config?.silent) {
          ElMessage.warning('已取消 MFA 验证，操作未执行')
        }
        return Promise.reject(new ApiRequestError('已取消 MFA 验证，操作未执行', status))
      } catch (stepError: unknown) {
        // verify-step 失败给出可见反馈；下游 catch 可据标记跳过二次弹窗。
        ElMessage.error(stepError instanceof Error ? stepError.message : 'MFA 验证未完成')
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
    return Promise.reject(new ApiRequestError(message, status, error.response?.data))
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

