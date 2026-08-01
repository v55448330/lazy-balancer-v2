import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { ApiResponse, ClusterNodeMode, CurrentUser } from '@/types'
import { isTokenExpired, request } from '@/utils/api'
import { ElMessage } from 'element-plus'

const pages = [
  'dashboard',
  'rules',
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
const storedCurrentPage = localStorage.getItem('currentPage')
const initialCurrentPage: PageId = storedCurrentPage && isPageId(storedCurrentPage) ? storedCurrentPage : 'dashboard'
if (storedCurrentPage !== initialCurrentPage) localStorage.setItem('currentPage', initialCurrentPage)

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
      const res = await request.get<ApiResponse<CurrentUser>>('/users/me')
      if (res.data) {
        user.value = {
          id: res.data.id,
          username: res.data.username,
          role: res.data.role,
          is_enabled: res.data.is_enabled,
          display_name: res.data.display_name,
        }
      }
    } catch (e) {
      console.error(e)
    }
  }

  async function fetchConfig() {
    if (!token.value) return
    try {
      const res = await request.get<ApiResponse<{ readonly is_master: boolean; readonly timezone?: string }>>('/config')
      if (res.data) {
        nodeMode.value = res.data.is_master ? 'master' : 'slave'
        if (res.data.timezone) timezone.value = res.data.timezone
      }
    } catch (e) {
      console.error(e)
    }
  }

  async function login(username: string, password: string) {
    if (loading.value) return
    loading.value = true
    try {
      const res = await request.post<AuthResponse>('/auth/login', { username, password })
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
