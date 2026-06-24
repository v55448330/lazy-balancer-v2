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
    <Settings v-else-if="currentPage === 'settings'" />
    <CaddyConfig v-else-if="currentPage === 'caddy'" />
    <Users v-else-if="currentPage === 'users'" />
  </AppLayout>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { isTokenExpired } from '@/utils/api'
import Login from '@/views/Login.vue'
import AppLayout from '@/components/layout/AppLayout.vue'
import Dashboard from '@/views/Dashboard.vue'
import Rules from '@/views/Rules.vue'
import Settings from '@/views/Settings.vue'
import CaddyConfig from '@/views/CaddyConfig.vue'
import Users from '@/views/Users.vue'

const authStore = useAuthStore()
const loading = ref(true)

const currentPage = computed(() => authStore.currentPage)

onMounted(async () => {
  await authStore.init()
  loading.value = false
})

defineExpose({ currentPage })
</script>