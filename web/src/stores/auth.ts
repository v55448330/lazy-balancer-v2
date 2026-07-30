import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { ApiResponse, ClusterNodeMode, CurrentUser } from '@/types'
import { isTokenExpired, request } from '@/utils/api'
import { ElMessage } from 'element-plus'

const validPages = new Set([
  'dashboard',
  'rules',
  'caddy',
  'users',
  'audit-log',
  'settings-basic',
  'settings-cluster',
  'settings-certificates',
  'settings-apikeys',
])
const storedCurrentPage = localStorage.getItem('currentPage')
const initialCurrentPage = storedCurrentPage && validPages.has(storedCurrentPage) ? storedCurrentPage : 'dashboard'
if (storedCurrentPage !== initialCurrentPage) localStorage.setItem('currentPage', initialCurrentPage)

export const useAuthStore = defineStore('auth', () => {
  const user = ref<CurrentUser | null>(null)
  const token = ref<string | null>(localStorage.getItem('token'))
  const nodeMode = ref<ClusterNodeMode>('master')
  const timezone = ref<string>('Asia/Shanghai')
  const loading = ref(false)
  const currentPage = ref<string>(initialCurrentPage)

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

  const normalizeDisplayName = (value: CurrentUser['display_name'], username?: string) => {
    return value || username || ''
  }

  const displayName = computed(() => {
    if (!user.value) return ''
    return normalizeDisplayName(user.value.display_name, user.value.username)
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
          display_name: normalizeDisplayName(res.data.display_name, res.data.username),
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
    loading.value = true
    try {
      const res = await request.post<{
        readonly token: string
        readonly node_mode: ClusterNodeMode
        readonly user?: CurrentUser
      }>('/auth/login', { username, password })
      token.value = res.token
      nodeMode.value = res.node_mode
      localStorage.setItem('token', res.token)
      if (res.user) {
        user.value = {
          id: res.user.id,
          username: res.user.username,
          role: res.user.role,
          is_enabled: res.user.is_enabled,
          display_name: normalizeDisplayName(res.user.display_name, res.user.username),
        }
      }
      await fetchConfig()
    } finally {
      loading.value = false
    }
  }

  function logout() {
    user.value = null
    token.value = null
    nodeMode.value = 'master'
    localStorage.removeItem('token')
  }

  function showToast(type: 'success' | 'error' | 'info' | 'warning', title: string, message?: string) {
    ElMessage({
      message: message || title,
      type,
      duration: 3000,
    })
  }

  function setCurrentPage(page: string) {
    currentPage.value = page
    localStorage.setItem('currentPage', page)
  }

  function setNodeMode(mode: ClusterNodeMode) {
    nodeMode.value = mode
  }

  async function init() {
    if (!token.value || isTokenExpired(token.value)) {
      logout()
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
    currentPage,
    isLoggedIn,
    readOnlyReason,
    readOnlyMessage,
    normalizeDisplayName,
    displayName,
    login,
    logout,
    fetchUser,
    fetchConfig,
    setNodeMode,
    init,
    setCurrentPage,
    showToast,
  }
})
