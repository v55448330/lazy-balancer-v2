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
const isPageId = (page: string): page is PageId => validPages.has(page)
const queryPage = new URLSearchParams(location.search).get('page')
const queryPageValid: PageId | null = queryPage && isPageId(queryPage) ? queryPage : null
// URL hash 优先（刷新/多标签页/前进后退可靠）；localStorage 作为后备。
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
  const nodeMode = ref<ClusterNodeMode>('master')
  const timezone = ref<string>('Asia/Shanghai')
  const loading = ref(false)
  const intentionalLogout = ref(false)
  const currentPage = ref<PageId>(initialCurrentPage)

  const isLoggedIn = computed(() => !!token.value && !isTokenExpired(token.value))
  const readOnlyReason = computed<'slave' | 'non-admin' | 'unknown' | null>(() => {
    if (nodeMode.value === 'slave') return 'slave'
    if (user.value) return user.value.role !== 'admin' ? 'non-admin' : null
    // token 有效但用户信息尚未成功拉取（如 /users/me 瞬时失败）：权限未知按只读
    // 呈现（fail-closed），避免该窗口期按 admin 视图放行（fail-open）
    return isLoggedIn.value ? 'unknown' : null
  })
  const readOnlyMessage = computed(() => {
    if (readOnlyReason.value === 'slave') return '从节点只读，请在主节点操作'
    if (readOnlyReason.value === 'non-admin') return '非管理员用户只读'
    if (readOnlyReason.value === 'unknown') return '用户信息加载中，暂以只读模式呈现'
    return ''
  })

  let userRetryTimer: ReturnType<typeof setTimeout> | null = null

  const clearUserRetryTimer = (): void => {
    if (userRetryTimer !== null) {
      clearTimeout(userRetryTimer)
      userRetryTimer = null
    }
  }

  const scheduleUserRetry = (): void => {
    if (userRetryTimer !== null || !token.value) return
    userRetryTimer = setTimeout(() => {
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

  async function fetchConfig(silent = false) {
    if (!token.value) return
    try {
      const res = await request.get<APIResponse<{ readonly is_master: boolean; readonly timezone?: string }>>('/config', { silent })
      if (res.data) {
        nodeMode.value = res.data.is_master ? 'master' : 'slave'
        if (res.data.timezone) timezone.value = res.data.timezone
      }
    } catch (e) {
      console.error(e)
    }
  }

  async function login(username: string, password: string): Promise<{ mfaRequired: boolean; mfaToken?: string }> {
    if (loading.value) return { mfaRequired: false }
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/login', { username, password }, { silent: true })
      // v2.1.8 MFA 两步登录：后端返回 mfa_required 时无 token——调用方（Login.vue）
      // 切换到验证码步骤；silent 抑制拦截器把 200 的 mfa_required 形态当错误 toast。
      if ((res as unknown as { mfa_required?: boolean }).mfa_required) {
        return { mfaRequired: true, mfaToken: (res as unknown as { mfa_token: string }).mfa_token }
      }
      applyAuthResponse(res)
      await fetchConfig()
      return { mfaRequired: false }
    } finally {
      loading.value = false
    }
  }

  // v2.1.8 MFA step-up：验证码刷新 mfa_ts（新 JWT 替换当前 token，身份不变）。
  async function refreshMfaStep(code: string) {
    const res = await request.post<AuthResponse>('/auth/mfa/verify-step', { code }, { silent: true })
    applyAuthResponse(res)
  }

  // v2.1.8 MFA 第二步：验证码换 JWT。
  async function verifyMfaLogin(mfaToken: string, code: string) {
    if (loading.value) return
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/mfa/verify', { mfa_token: mfaToken, code }, { silent: true })
      applyAuthResponse(res)
      await fetchConfig()
    } finally {
      loading.value = false
    }
  }

  function applyAuthResponse(res: AuthResponse) {
    intentionalLogout.value = false
    clearUserRetryTimer()
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
      }
    }
  }

  async function loginWithTicket(ticket: string) {
    if (loading.value) return
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/ticket-login', { ticket })
      applyAuthResponse(res)
      await fetchConfig()
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
      user.value = null
      token.value = null
      nodeMode.value = 'master'
      localStorage.removeItem('token')
    }
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
      await logout()
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
    logout,
    fetchUser,
    fetchConfig,
    setNodeMode,
    init,
    setCurrentPage,
    showToast,
  }
})
