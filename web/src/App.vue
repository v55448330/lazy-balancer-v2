<template>
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
    <Settings v-else-if="currentPage === 'settings-basic' || currentPage === 'settings-cluster' || currentPage === 'settings-certificates' || currentPage === 'settings-apikeys'" />
    <CaddyConfig v-else-if="currentPage === 'caddy'" />
    <Users v-else-if="currentPage === 'users'" />
    <AuditLog v-else-if="currentPage === 'audit-log'" />
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { isTokenExpired } from '@/utils/api'
import { ElMessage } from 'element-plus'
import Login from '@/views/Login.vue'
import AppLayout from '@/components/layout/AppLayout.vue'
import Dashboard from '@/views/Dashboard.vue'
import Rules from '@/views/Rules.vue'
import Settings from '@/views/Settings.vue'
import CaddyConfig from '@/views/CaddyConfig.vue'
import Users from '@/views/Users.vue'
import AuditLog from '@/views/AuditLog.vue'

const authStore = useAuthStore()
const loading = ref(true)

const currentPage = computed(() => authStore.currentPage)

onMounted(async () => {
  const url = new URL(window.location.href)
  const hasLoginTicket = url.searchParams.has('login_ticket')
  const loginTicket = url.searchParams.get('login_ticket') ?? ''
  if (hasLoginTicket) {
    url.searchParams.delete('login_ticket')
    window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`)
  }

  try {
    if (hasLoginTicket) {
      try {
        await authStore.loginWithTicket(loginTicket)
        authStore.setCurrentPage('dashboard')
      } catch {
        authStore.logout()
        ElMessage.error('登录票据无效或已过期，请重新登录')
      }
    } else {
      await authStore.init()
    }
  } finally {
    loading.value = false
  }
})
</script>
