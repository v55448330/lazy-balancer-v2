<template>
  <div class="page" v-if="activeTab === 'apikeys' && isAdmin">
    <APIKeys />
  </div>

  <div class="page" v-else>
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Setting /></el-icon>
          {{ pageTitle }}
        </h2>
        <p class="page-desc">{{ pageDesc }}</p>
      </div>
    </div>

    <BasicSettings
      v-if="activeTab === 'basic'"
      v-model:settings="settings"
      @save="handleSaveBasic"
    />
    <ClusterSettings
      v-else-if="activeTab === 'cluster'"
      v-model:settings="settings"
      @save="handleSaveCluster"
    />
    <FreeCertificates
      v-else-if="activeTab === 'certificates'"
      v-model:global="global"
      @save="handleSaveCertificates"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage } from 'element-plus'
import { Setting } from '@element-plus/icons-vue'
import BasicSettings from './settings/BasicSettings.vue'
import ClusterSettings from './settings/ClusterSettings.vue'
import FreeCertificates from './settings/FreeCertificates.vue'
import APIKeys from './settings/APIKeys.vue'

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const activeTab = ref('basic')

const settings = ref<any>({
  log_level: 'info',
  access_log_enabled: true,
  caddy_log_path: '/app/logs/caddy.log',
  caddy_log_level: 'info',
  caddy_log_size_mb: 100,
  is_master: true,
  master_url: '',
  sync_interval: 60,
})

const global = ref<any>({
  acme_email: '',
  cert_expiry_days: 30,
  cert_renewal_days: 30,
  default_ca_provider_id: 0,
})

const titles: Record<string, string> = {
  basic: '基础设置',
  cluster: '集群管理',
  certificates: '免费证书',
  apikeys: 'API 密钥',
}

const descs: Record<string, string> = {
  basic: '配置系统日志、访问日志和基础行为',
  cluster: '配置主从节点模式和同步策略',
  certificates: '配置 ACME 邮箱、DNS 提供商和证书签发任务',
  apikeys: '管理 API 访问密钥',
}

const pageTitle = computed(() => titles[activeTab.value] || '系统设置')
const pageDesc = computed(() => descs[activeTab.value] || '')

const fetchSettings = async () => {
  try {
    const res = await request.get('/config')
    if (res.data) {
      settings.value = {
        log_level: res.data.log_level || 'info',
        access_log_enabled: res.data.access_log_enabled ?? true,
        caddy_log_path: res.data.caddy_log_path || '/app/logs/caddy.log',
        caddy_log_level: res.data.caddy_log_level || 'info',
        caddy_log_size_mb: res.data.caddy_log_size_mb ?? 100,
        is_master: res.data.is_master ?? true,
        master_url: res.data.master_url || '',
        sync_interval: res.data.sync_interval || 60,
      }
      global.value = {
        acme_email: res.data.acme_email || '',
        cert_expiry_days: res.data.cert_expiry_days ?? 30,
        cert_renewal_days: res.data.cert_renewal_days ?? 30,
        default_ca_provider_id: res.data.default_ca_provider_id ?? 0,
      }
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
  }
}

const saveConfig = async (payload: any) => {
  try {
    await request.put('/config', payload)
    ElMessage.success('保存成功')
  } catch (error) {
    console.error('Failed to save settings:', error)
  }
}

const handleSaveBasic = async () => {
  await fetchSettings()
}

const handleSaveCluster = async () => {
  await saveConfig({
    is_master: settings.value.is_master,
    master_url: settings.value.master_url,
    sync_interval: settings.value.sync_interval,
  })
}

const handleSaveCertificates = async (payload: any) => {
  await saveConfig(payload)
}

const syncActiveTabFromPage = () => {
  const map: Record<string, string> = {
    'settings-basic': 'basic',
    'settings-cluster': 'cluster',
    'settings-certificates': 'certificates',
    'settings-apikeys': 'apikeys',
  }
  activeTab.value = map[authStore.currentPage] || 'basic'
}

watch(() => authStore.currentPage, syncActiveTabFromPage)

onMounted(() => {
  syncActiveTabFromPage()
  fetchSettings()
})
</script>

<style scoped>
.page { max-width: 1500px; margin: 0 auto; }

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
</style>
