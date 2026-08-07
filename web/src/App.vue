<template>
  <el-config-provider :locale="zhCn">
    <div v-if="loading" class="min-h-screen flex items-center justify-center bg-slate-900">
      <div class="flex flex-col items-center gap-4">
        <div class="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
        <div class="text-slate-400">加载中...</div>
      </div>
    </div>

    <Login v-else-if="!authStore.token || isTokenExpired(authStore.token || '')" />
    <AppLayout v-else>
      <Dashboard v-if="currentPage === 'dashboard'" />
      <Rules v-else-if="currentPage === 'rules'" />
      <SecurityPolicies v-else-if="currentPage === 'security-policies'" />
      <SecurityRules v-else-if="currentPage === 'security-rules'" />
      <SecurityEvents v-else-if="currentPage === 'security-events'" />
      <Settings v-else-if="currentPage === 'settings-basic' || currentPage === 'settings-cluster' || currentPage === 'settings-certificates' || currentPage === 'settings-apikeys'" />
      <CaddyConfig v-else-if="currentPage === 'caddy'" />
      <Users v-else-if="currentPage === 'users'" />
      <AuditLog v-else-if="currentPage === 'audit-log'" />
    </AppLayout>
  </el-config-provider>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, defineAsyncComponent } from 'vue'
import type { AsyncComponentLoader } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { ApiRequestError, isTokenExpired } from '@/utils/api'
import { ElMessage } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import AppLayout from '@/components/layout/AppLayout.vue'
import Login from '@/views/Login.vue'
import AsyncPageError from '@/views/AsyncPageError.vue'

const createAsyncPage = (loader: AsyncComponentLoader) => defineAsyncComponent({
  loader,
  errorComponent: AsyncPageError,
  onError: (_error, retry, fail, attempts) => {
    if (attempts <= 1) {
      retry()
      return
    }
    fail()
  },
})

const Dashboard = createAsyncPage(() => import('@/views/Dashboard.vue'))
const Rules = createAsyncPage(() => import('@/views/Rules.vue'))
const SecurityPolicies = createAsyncPage(() => import('@/views/security/SecurityPolicies.vue'))
const SecurityRules = createAsyncPage(() => import('@/views/security/SecurityRules.vue'))
const SecurityEvents = createAsyncPage(() => import('@/views/security/SecurityEvents.vue'))
const Settings = createAsyncPage(() => import('@/views/Settings.vue'))
const CaddyConfig = createAsyncPage(() => import('@/views/CaddyConfig.vue'))
const Users = createAsyncPage(() => import('@/views/Users.vue'))
const AuditLog = createAsyncPage(() => import('@/views/AuditLog.vue'))

const authStore = useAuthStore()
const loading = ref(true)

const currentPage = computed(() => authStore.currentPage)

onMounted(async () => {
  const url = new URL(window.location.href)
  const fragment = new URLSearchParams(url.hash.slice(1))
  const hasLoginTicket = fragment.has('login_ticket')
  const loginTicket = fragment.get('login_ticket') ?? ''
  if (hasLoginTicket) {
    fragment.delete('login_ticket')
    const remainingHash = fragment.toString()
    window.history.replaceState({}, '', `${url.pathname}${url.search}${remainingHash ? `#${remainingHash}` : ''}`)
  }

  try {
    if (hasLoginTicket) {
      const hadValidSession = authStore.isLoggedIn
      try {
        await authStore.loginWithTicket(loginTicket)
        authStore.setCurrentPage('dashboard')
      } catch (error: unknown) {
        if (hadValidSession) await authStore.init()
        ElMessage.error(error instanceof ApiRequestError && (error.status === 400 || error.status === 401) ? '票据无效或已过期' : '登录服务异常')
      }
    } else {
      await authStore.init()
    }
  } finally {
    loading.value = false
  }
})
</script>
