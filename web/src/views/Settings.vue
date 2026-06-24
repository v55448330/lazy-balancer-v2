<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Setting /></el-icon>
          系统设置
        </h2>
        <p class="page-desc">配置系统参数、证书提供者和行为选项</p>
      </div>
    </div>

    <div class="settings-layout">
      <div class="settings-sidebar">
        <div
          class="menu-item"
          :class="{ active: activeTab === 'basic' }"
          @click="activeTab = 'basic'"
        >
          <el-icon><Setting /></el-icon>
          <span>基础设置</span>
        </div>
        <div
          class="menu-item"
          :class="{ active: activeTab === 'cluster' }"
          @click="activeTab = 'cluster'"
        >
          <el-icon><Connection /></el-icon>
          <span>集群管理</span>
        </div>
        <div
          class="menu-item"
          :class="{ active: activeTab === 'certificates' }"
          @click="activeTab = 'certificates'"
        >
          <el-icon><Lock /></el-icon>
          <span>免费证书</span>
        </div>
        <div
          v-if="isAdmin"
          class="menu-item"
          :class="{ active: activeTab === 'apikeys' }"
          @click="activeTab = 'apikeys'"
        >
          <el-icon><Key /></el-icon>
          <span>API 密钥</span>
        </div>
      </div>

      <div class="settings-content">
        <BasicSettings v-if="activeTab === 'basic'" v-model:settings="settings" />
        <ClusterSettings v-if="activeTab === 'cluster'" v-model:settings="settings" />
        <FreeCertificates v-if="activeTab === 'certificates'" v-model:global="global" />
        <APIKeys v-if="activeTab === 'apikeys' && isAdmin" />
      </div>
    </div>

    <div class="save-bar">
      <el-button type="primary" size="large" @click="handleSave" :loading="saving">
        <el-icon><Check /></el-icon>保存设置
      </el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage } from 'element-plus'
import { Setting, Connection, Lock, Key, Check } from '@element-plus/icons-vue'
import BasicSettings from './settings/BasicSettings.vue'
import ClusterSettings from './settings/ClusterSettings.vue'
import FreeCertificates from './settings/FreeCertificates.vue'
import APIKeys from './settings/APIKeys.vue'

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const activeTab = ref('basic')
const saving = ref(false)

const settings = ref<any>({
  dns_provider: 'dnspod',
  dns_credentials: '',
  letsencrypt_email: '',
  log_level: 'info',
  access_log_enabled: true,
  is_master: true,
  master_url: '',
  sync_interval: 60,
})

const global = ref<any>({
  acme_email: '',
  cert_expiry_days: 30,
})

const fetchSettings = async () => {
  try {
    const res = await request.get('/config')
    if (res.data) {
      settings.value = {
        dns_provider: res.data.dns_provider || 'dnspod',
        dns_credentials: res.data.dns_credentials || '',
        letsencrypt_email: res.data.letsencrypt_email || '',
        log_level: res.data.log_level || 'info',
        access_log_enabled: res.data.access_log_enabled ?? true,
        is_master: res.data.is_master ?? true,
        master_url: res.data.master_url || '',
        sync_interval: res.data.sync_interval || 60,
      }
      global.value = {
        acme_email: res.data.acme_email || '',
        cert_expiry_days: res.data.cert_expiry_days ?? 30,
      }
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
  }
}

const handleSave = async () => {
  saving.value = true
  try {
    await request.put('/config', {
      ...settings.value,
      acme_email: global.value.acme_email,
      cert_expiry_days: global.value.cert_expiry_days,
    })
    ElMessage.success('保存成功')
  } catch (error) {
    console.error('Failed to save settings:', error)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  fetchSettings()
})
</script>

<style scoped>
.page { max-width: 1200px; margin: 0 auto; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header-left { flex: 1; }

.page-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.title-icon { color: #3b82f6; font-size: 20px; }

.page-desc {
  font-size: 13px;
  color: #6b7280;
  margin: 4px 0 0 28px;
}

.settings-layout {
  display: flex;
  gap: 20px;
}

.settings-sidebar {
  width: 200px;
  flex-shrink: 0;
  background: #ffffff;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
  padding: 8px;
}

.menu-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-radius: 6px;
  cursor: pointer;
  color: #6b7280;
  font-size: 14px;
  transition: all 0.2s;
}

.menu-item:hover {
  background: #f9fafb;
  color: #111827;
}

.menu-item.active {
  background: #eff6ff;
  color: #3b82f6;
  font-weight: 500;
}

.settings-content {
  flex: 1;
  min-width: 0;
}

.save-bar {
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  justify-content: flex-end;
}
</style>
