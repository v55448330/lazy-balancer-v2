import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { User } from '@/types'
import { isTokenExpired, request } from '@/utils/api'
import { ElMessageBox, ElMessage } from 'element-plus'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const token = ref<string | null>(localStorage.getItem('token'))
  const nodeMode = ref<string>('master')
  const loading = ref(false)
  const currentPage = ref<string>(localStorage.getItem('currentPage') || 'dashboard')

  const isLoggedIn = computed(() => !!token.value && !isTokenExpired(token.value))

  const displayName = computed(() => {
    if (!user.value) return ''
    const name = user.value.display_name as any
    if (typeof name === 'string') return name || user.value.username || ''
    if (name && typeof name === 'object' && 'String' in name) return name.String || user.value.username || ''
    return user.value.username || ''
  })

  const userRole = computed(() => {
    if (!user.value) return '用户'
    return user.value.role === 'admin' ? '管理员' : '用户'
  })

  async function fetchUser() {
    if (!token.value) return
    try {
      const res = await request.get<any>('/users/me')
      if (res.data) {
        user.value = {
          id: res.data.id,
          username: res.data.username,
          role: res.data.role,
          display_name: res.data.display_name?.String || res.data.display_name,
        }
      }
    } catch (e) {
      console.error(e)
    }
  }

  async function fetchConfig() {
    if (!token.value) return
    try {
      const res = await request.get<any>('/config')
      if (res.data) {
        nodeMode.value = res.data.is_master ? 'master' : 'slave'
      }
    } catch (e) {
      console.error(e)
    }
  }

  async function login(username: string, password: string) {
    loading.value = true
    try {
      const res = await request.post<any>('/auth/login', { username, password })
      token.value = res.token
      nodeMode.value = res.node_mode
      localStorage.setItem('token', res.token)
      if (res.user) {
        user.value = {
          id: res.user.id,
          username: res.user.username,
          role: res.user.role,
          display_name: res.user.display_name?.String || res.user.display_name,
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
    loading,
    currentPage,
    isLoggedIn,
    displayName,
    userRole,
    login,
    logout,
    fetchUser,
    fetchConfig,
    init,
    setCurrentPage,
    showToast,
    showConfirm,
  }
})