import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { ApiResponse, ClusterNodeMode, User } from '@/types'
import { isTokenExpired, request } from '@/utils/api'
import { ElMessageBox, ElMessage } from 'element-plus'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const token = ref<string | null>(localStorage.getItem('token'))
  const nodeMode = ref<ClusterNodeMode>('master')
  const timezone = ref<string>('Asia/Shanghai')
  const loading = ref(false)
  const currentPage = ref<string>(localStorage.getItem('currentPage') || 'dashboard')

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

  const normalizeDisplayName = (value: User['display_name'], username?: string) => {
    if (typeof value === 'string') return value || username || ''
    if (value && typeof value === 'object' && 'String' in value) return value.String || username || ''
    return username || ''
  }

  const displayName = computed(() => {
    if (!user.value) return ''
    return normalizeDisplayName(user.value.display_name, user.value.username)
  })

  const userRole = computed(() => {
    if (!user.value) return '用户'
    return user.value.role === 'admin' ? '管理员' : '用户'
  })

  async function fetchUser() {
    if (!token.value) return
    try {
      const res = await request.get<ApiResponse<User>>('/users/me')
      if (res.data) {
        user.value = {
          id: res.data.id,
          username: res.data.username,
          role: res.data.role,
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
        readonly user?: User
      }>('/auth/login', { username, password })
      token.value = res.token
      nodeMode.value = res.node_mode
      localStorage.setItem('token', res.token)
      if (res.user) {
        user.value = {
          id: res.user.id,
          username: res.user.username,
          role: res.user.role,
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

  function showToast(type: 'success' | 'error' | 'info', title: string, message?: string) {
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

  function showConfirm(title: string, message: string, onConfirm: () => void) {
    ElMessageBox.confirm(message, title, {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning',
    })
      .then(() => {
        onConfirm()
      })
      .catch(() => {})
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
    userRole,
    login,
    logout,
    fetchUser,
    fetchConfig,
    setNodeMode,
    init,
    setCurrentPage,
    showToast,
    showConfirm,
  }
})
