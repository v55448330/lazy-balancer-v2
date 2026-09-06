<template>
  <el-config-provider :locale="zhCn">
    <div v-if="loading" class="app-loading">
      <div class="app-loading__inner">
        <div class="app-loading__spinner"></div>
        <div class="app-loading__text">加载中...</div>
      </div>
    </div>

    <Login v-else-if="!authStore.token || isTokenExpired(authStore.token || '')" />
    <AppLayout v-else>
      <Dashboard v-if="currentPage === 'dashboard'" />
      <Rules v-else-if="currentPage === 'rules'" />
      <SecurityPolicies v-else-if="currentPage === 'security-policies'" />
      <SecurityRules v-else-if="currentPage === 'security-rules'" />
      <SecurityBlockPages v-else-if="currentPage === 'security-block-pages'" />
      <SecurityOverview v-else-if="currentPage === 'security-overview'" />
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
const SecurityBlockPages = createAsyncPage(() => import('@/views/security/SecurityBlockPages.vue'))
const SecurityOverview = createAsyncPage(() => import('@/views/security/SecurityOverview.vue'))
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
        const result = await authStore.loginWithTicket(loginTicket)
        // FI-18：重入护栏命中（挂载期为单次调用，防御性判断）——未建立会话时不导航。
        if (!result.skipped) authStore.setCurrentPage('dashboard')
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

<style scoped>
.app-loading {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #0f172a;
}
.app-loading__inner {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
}
.app-loading__spinner {
  width: 48px;
  height: 48px;
  border: 4px solid #3b82f6;
  border-top-color: transparent;
  border-radius: 50%;
  animation: app-loading-spin 0.8s linear infinite;
}
.app-loading__text {
  color: #94a3b8;
  font-size: 14px;
}
@keyframes app-loading-spin {
  to { transform: rotate(360deg); }
}
</style>
