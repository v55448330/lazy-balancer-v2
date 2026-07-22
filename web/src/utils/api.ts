import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig } from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'

let sessionExpiredDialogOpen = false

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
    if (res.code !== undefined && res.code !== 0 && res.code !== 200) {
      ElMessage.error(res.message || '请求失败')
      return Promise.reject(new Error(res.message || '请求失败'))
    }
    return res
  },
  (error) => {
    const status = error.response?.status
    const backendMsg = error.response?.data?.message
    const message = backendMsg || error.message || '网络错误'
      if (status === 401) {
        const isLoginRequest = error.config?.url?.includes('/auth/login')
        if (!isLoginRequest) {
          if (!sessionExpiredDialogOpen) {
            sessionExpiredDialogOpen = true
            ElMessageBox.confirm(backendMsg || '登录已过期，请重新登录', '会话失效', {
              confirmButtonText: '确定',
              cancelButtonText: '取消',
              type: 'warning',
            }).then(() => {
              localStorage.removeItem('token')
              window.location.reload()
            }).catch(() => {
              localStorage.removeItem('token')
              window.location.reload()
            })
          }
      }
      } else if (!error.config?.url?.includes('/auth/login')) {
        ElMessage.error(message)
      }
    return Promise.reject(new Error(message))
  }
)

export const request = {
  get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.get(url, config)
  },
  post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return service.post(url, data, config)
  },
  put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return service.put(url, data, config)
  },
  delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return service.delete(url, config)
  },
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export function isTokenExpired(token: string): boolean {
  if (!token || token === 'null' || token === 'undefined') return false
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return false
    const payload = JSON.parse(atob(parts[1]))
    if (!payload.exp) return false
    const exp = payload.exp * 1000
    return Date.now() >= exp
  } catch {
    return false
  }
}

export default service