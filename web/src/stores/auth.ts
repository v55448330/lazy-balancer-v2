import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { APIResponse, ClusterNodeMode, CurrentUser } from '@/types'
import { isTokenExpired, request } from '@/utils/api'
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
const storedCurrentPage = localStorage.getItem('currentPage')
const initialCurrentPage: PageId =
  queryPageValid ??
  (storedCurrentPage && isPageId(storedCurrentPage) ? storedCurrentPage : 'dashboard')
if (!queryPageValid && storedCurrentPage !== initialCurrentPage) localStorage.setItem('currentPage', initialCurrentPage)

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
  const readOnlyReason = computed<'slave' | 'non-admin' | null>(() => {
    if (nodeMode.value === 'slave') return 'slave'
    if (user.value && user.value.role !== 'admin') return 'non-admin'
    return null
  })
  const readOnlyMessage = computed(() => {
    if (readOnlyReason.value === 'slave') return '从节点只读，请在主节点操作'
    if (readOnlyReason.value === 'non-admin') return '非管理员用户只读'
    return ''
  })

  async function fetchUser() {
    if (!token.value) return
    try {
      const res = await request.get<APIResponse<CurrentUser>>('/users/me')
      if (res.data) {
        user.value = {
          id: res.data.id,
          username: res.data.username,
          role: res.data.role,
          is_enabled: res.data.is_enabled,
          display_name: res.data.display_name,
          mfa_enabled: res.data.mfa_enabled ?? false,
        }
      }
    } catch (e) {
      console.error(e)
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
