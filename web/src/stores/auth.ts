import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { APIResponse, ClusterNodeMode, CurrentUser } from '@/types'
import { isTokenExpired, request, ApiRequestError } from '@/utils/api'
import { ElMessage } from 'element-plus'

const pages = [
  'dashboard',
  'rules',
  'security-policies',
  'security-rules',
  'security-block-pages',
  'security-overview',
  'security-events',
  'caddy',
  'users',
  'audit-log',
  'settings-basic',
  'settings-cluster',
  'settings-certificates',
  'settings-apikeys',
] as const
export type PageId = (typeof pages)[number]
const validPages: ReadonlySet<string> = new Set(pages)
// 页面键唯一事实源——App.vue OIDC return_to 校验等处复用,禁止另起字面量清单(双源漂移)。
export const isPageId = (page: string): page is PageId => validPages.has(page)
const queryPage = new URLSearchParams(location.search).get('page')
const queryPageValid: PageId | null = queryPage && isPageId(queryPage) ? queryPage : null
// URL hash 优先（刷新/多标签页可靠；导航用 replaceState 不产生历史条目，浏览器返回键会离开面板）；localStorage 作为后备。
const hashMatch = window.location.hash.match(/^#\/(.+)$/)
const hashPage = hashMatch ? hashMatch[1] : null
const storedCurrentPage = localStorage.getItem('currentPage')
const initialCurrentPage: PageId =
  queryPageValid ??
  (hashPage && isPageId(hashPage) ? hashPage :
   storedCurrentPage && isPageId(storedCurrentPage) ? storedCurrentPage : 'dashboard')
// 审计 B4-I1：深链 ?page= 仅作首屏入口——消费后立即剥离并同步 localStorage，
// 否则参数永久留在 URL 上遮蔽 hash 导航（深链标签页导航后刷新被拉回原页）。
if (storedCurrentPage !== initialCurrentPage) localStorage.setItem('currentPage', initialCurrentPage)
if (queryPageValid) {
  const url = new URL(window.location.href)
  url.searchParams.delete('page')
  window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
}

interface AuthResponse {
  readonly token: string
  readonly node_mode: ClusterNodeMode
  readonly user?: CurrentUser
}

export const useAuthStore = defineStore('auth', () => {
  const user = ref<CurrentUser | null>(null)
  const token = ref<string | null>(localStorage.getItem('token'))
  // F49-10（第 49 轮审计）：节点模式三态化——null=未知（/config 未成功拉取），
  // 不再默认 'master'：从节点刷新+瞬时失败窗口曾按主节点 fail-open 渲染写控件。
  const nodeMode = ref<ClusterNodeMode | null>(null)
  const timezone = ref<string>('Asia/Shanghai')
  const loading = ref(false)
  const intentionalLogout = ref(false)
  const currentPage = ref<PageId>(initialCurrentPage)

  const isLoggedIn = computed(() => !!token.value && !isTokenExpired(token.value))
  const readOnlyReason = computed<'slave' | 'non-admin' | 'unknown' | null>(() => {
    if (nodeMode.value === 'slave') return 'slave'
    if (user.value) {
      if (user.value.role !== 'admin') return 'non-admin'
      // F49-10：admin 用户但节点模式未知（/config 未成功拉取）同样按只读呈现
      // （fail-closed），与下方用户信息未知窗口同口径。
      if (nodeMode.value === null) return isLoggedIn.value ? 'unknown' : null
      return null
    }
    // token 有效但用户信息尚未成功拉取（如 /users/me 瞬时失败）：权限未知按只读
    // 呈现（fail-closed），避免该窗口期按 admin 视图放行（fail-open）
    return isLoggedIn.value ? 'unknown' : null
  })
  const readOnlyMessage = computed(() => {
    if (readOnlyReason.value === 'slave') return '从节点只读，请在主节点操作'
    if (readOnlyReason.value === 'non-admin') return '非管理员用户只读'
    if (readOnlyReason.value === 'unknown') return '信息加载中，暂以只读模式呈现'
    return ''
  })

  let userRetryTimer: number | null = null

  const clearUserRetryTimer = (): void => {
    if (userRetryTimer !== null) {
      window.clearTimeout(userRetryTimer)
      userRetryTimer = null
    }
  }

  const scheduleUserRetry = (): void => {
    if (userRetryTimer !== null || !token.value) return
    userRetryTimer = window.setTimeout(() => {
      userRetryTimer = null
      void fetchUser()
    }, 15_000)
  }

  async function fetchUser() {
    if (!token.value) return
    try {
      // A6-S1：静默拉取——失败态已由 15s 重试循环与 readOnlyMessage 横幅（AppLayout
      // 只读标签）持续反馈，与其余轮询体系的 silent 口径一致，不再叠加 toast 噪音。
      const res = await request.get<APIResponse<CurrentUser>>('/users/me', { silent: true })
      if (res.data) {
        user.value = {
          id: res.data.id,
          username: res.data.username,
          role: res.data.role,
          is_enabled: res.data.is_enabled,
          display_name: res.data.display_name,
          mfa_enabled: res.data.mfa_enabled ?? false,
          auth_provider: res.data.auth_provider ?? 'local',
        }
      } else {
        // A6-S2：200 但 data 为空——user 仍为 null（unknown 只读窗口）且原先此处
        // 不安排重试（静默死亡，永不恢复）。与瞬时失败同口径：定时重试拉取。
        scheduleUserRetry()
      }
    } catch (error: unknown) {
      // 瞬时失败（非 401）保留最近一次已知的用户与权限，不清空；显式 401 由全局
      // 拦截器「会话失效」流统一处理（清 token 重载），logout 才主动清除。
      // 用户信息尚无已知值时定时重试拉取，使 fail-closed 的只读窗口自动恢复。
      if (!(error instanceof ApiRequestError && error.status === 401)) scheduleUserRetry()
      console.error(error)
    }
  }

  let configRetryTimer: number | null = null

  const clearConfigRetryTimer = (): void => {
    if (configRetryTimer !== null) {
      window.clearTimeout(configRetryTimer)
      configRetryTimer = null
    }
  }

  // F49-10：节点模式拉取失败与用户身份同口径——定时重试使未知窗口自动恢复
  const scheduleConfigRetry = (): void => {
    if (configRetryTimer !== null || !token.value) return
    configRetryTimer = window.setTimeout(() => {
      configRetryTimer = null
      void fetchConfig(true)
    }, 15_000)
  }

  async function fetchConfig(silent = false) {
    if (!token.value) return
    try {
      const res = await request.get<APIResponse<{ readonly is_master: boolean; readonly timezone?: string }>>('/config', { silent })
      if (res.data) {
        nodeMode.value = res.data.is_master ? 'master' : 'slave'
        if (res.data.timezone) timezone.value = res.data.timezone
      } else {
        scheduleConfigRetry()
      }
    } catch (e) {
      // 瞬时失败保留最近一次已知模式，未知态由重试循环收敛（401 走全局拦截器）
      if (!(e instanceof ApiRequestError && e.status === 401)) scheduleConfigRetry()
      console.error(e)
    }
  }

// FI-18：重入护栏显式化——loading 期间的重复调用不再伪装成「登录成功」
//（原 login 重入返回 { mfaRequired:false } 与成功形态无法区分），
// skipped:true 表示本次请求未发出，调用方应提示并中止。
interface LoginResult {
  skipped: boolean
  mfaRequired: boolean
  mfaToken?: string
}

  async function login(username: string, password: string): Promise<LoginResult> {
    if (loading.value) return { skipped: true, mfaRequired: false }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/login', { username, password }, { silent: true })
      // v2.1.8 MFA 两步登录：后端返回 mfa_required 时无 token——调用方（Login.vue）
      // 切换到验证码步骤；silent 抑制拦截器把 200 的 mfa_required 形态当错误 toast。
      if ((res as unknown as { mfa_required?: boolean }).mfa_required) {
        return { skipped: false, mfaRequired: true, mfaToken: (res as unknown as { mfa_token: string }).mfa_token }
      }
      applyAuthResponse(res)
      await fetchConfig()
      return { skipped: false, mfaRequired: false }
    } finally {
      loading.value = false
    }
  }

  // v2.1.8 MFA step-up：验证码刷新 mfa_ts（新 JWT 替换当前 token，身份不变）。
  async function refreshMfaStep(code: string) {
    const res = await request.post<AuthResponse>('/auth/mfa/verify-step', { code }, { silent: true })
    applyAuthResponse(res)
  }

  // v2.1.8 MFA 第二步：验证码换 JWT。重入护栏与 login 同口径（skipped 显式判别）。
  async function verifyMfaLogin(mfaToken: string, code: string): Promise<{ skipped: boolean }> {
    if (loading.value) return { skipped: true }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/mfa/verify', { mfa_token: mfaToken, code }, { silent: true })
      applyAuthResponse(res)
      await fetchConfig()
      return { skipped: false }
    } finally {
      loading.value = false
    }
  }

  function applyAuthResponse(res: AuthResponse) {
    intentionalLogout.value = false
    clearUserRetryTimer()
    clearConfigRetryTimer()
    token.value = res.token
    nodeMode.value = res.node_mode
    localStorage.setItem('token', res.token)
    if (res.user) {
      user.value = {
        id: res.user.id,
        username: res.user.username,
        role: res.user.role,
        is_enabled: res.user.is_enabled,
        display_name: res.user.display_name,
        mfa_enabled: res.user.mfa_enabled ?? false,
        // OIDC-4:票据登录响应携带的来源标记——缺失按本地,避免从节点 UI 误判
        auth_provider: res.user.auth_provider ?? 'local',
      }
    }
  }

  // v2.3.0 OIDC:后端回调跳转携带的令牌直接建会话(用户信息由 init 拉取)。
  function applyOIDCToken(rawToken: string) {
    intentionalLogout.value = false
    clearUserRetryTimer()
    clearConfigRetryTimer()
    token.value = rawToken
    localStorage.setItem('token', rawToken)
  }

  async function loginWithTicket(ticket: string): Promise<{ skipped: boolean }> {
    if (loading.value) return { skipped: true }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/ticket-login', { ticket })
      applyAuthResponse(res)
      await fetchConfig()
      return { skipped: false }
    } finally {
      loading.value = false
    }
  }

  async function logout() {
    intentionalLogout.value = true
    try {
      if (token.value) await request.post('/auth/logout')
    } catch (caught: unknown) {
      console.warn('服务端注销失败，已执行本地退出', caught)
    } finally {
      clearUserRetryTimer()
      clearConfigRetryTimer()
      user.value = null
      token.value = null
      nodeMode.value = null
      localStorage.removeItem('token')
    }
  }

  // FI-07：token 已在客户端判定过期（或本就不存在）时，服务端吊销毫无意义——
  // 撤销表只对仍有效的 jti 有价值，过期令牌必吃 401 并在后端认证拒绝审计记
  // 一条 jwt_expired 噪音。此路径仅做本地清理；手动登出（logout）仍走服务端吊销。
  // intentionalLogout 语义与 logout() 一致：抑制后续在途请求 401 的全局弹窗。
  function localLogout(): void {
    intentionalLogout.value = true
    clearUserRetryTimer()
    clearConfigRetryTimer()
    user.value = null
    token.value = null
    nodeMode.value = null
    localStorage.removeItem('token')
  }

  function showToast(type: 'success' | 'error' | 'info' | 'warning', message: string) {
    ElMessage({
      message,
      type,
      duration: 3000,
    })
  }

  function setCurrentPage(page: PageId) {
    if (!validPages.has(page)) return
    currentPage.value = page
    localStorage.setItem('currentPage', page)
    if (window.location.hash !== `#/${page}`) {
      window.history.replaceState(null, '', `#/${page}`)
    }
  }

  function setNodeMode(mode: ClusterNodeMode) {
    nodeMode.value = mode
  }

  async function init() {
    if (!token.value || isTokenExpired(token.value)) {
      localLogout()
      return
    }
    await fetchUser()
    await fetchConfig()
  }

  return {
    user,
    token,
    nodeMode,
    timezone,
    loading,
    intentionalLogout,
    currentPage,
    isLoggedIn,
    readOnlyReason,
    readOnlyMessage,
    login,
    verifyMfaLogin,
    refreshMfaStep,
    loginWithTicket,
    applyOIDCToken,
    logout,
    fetchUser,
    fetchConfig,
    setNodeMode,
    init,
    setCurrentPage,
    showToast,
  }
})
