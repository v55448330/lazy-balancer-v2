<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Bell /></el-icon>
          {{ t('app.notification.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('app.notification.pageDesc') }}</p>
      </div>
    </div>

    <el-tabs v-model="activeTab" class="notification-tabs">
      <el-tab-pane :label="t('app.notification.tabs.channels')" name="channels">
        <ChannelCards />
      </el-tab-pane>
      <el-tab-pane :label="t('app.notification.tabs.subs')" name="subs">
        <SubscriptionMatrix />
      </el-tab-pane>
      <el-tab-pane :label="t('app.notification.tabs.deliveries')" name="deliveries">
        <DeliveryLog />
      </el-tab-pane>
      <el-tab-pane v-if="isAdmin" :label="t('app.notification.tabs.credentials')" name="credentials">
        <SystemCredentials />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import ChannelCards from './ChannelCards.vue'
import SubscriptionMatrix from './SubscriptionMatrix.vue'
import DeliveryLog from './DeliveryLog.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t } = useI18n()
const authStore = useAuthStore()

// 系统凭据是管理员分页：非管理员整页隐藏（fail-closed，与 API 密钥只读模式
// 同一角色单源）
const isAdmin = computed(() => authStore.user?.role === 'admin')

const activeTab = ref('channels')
</script>

<style scoped>
.notification-tabs :deep(.el-tabs__content) { padding-top: 4px; }
</style>
