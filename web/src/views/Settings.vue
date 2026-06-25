<template>
  <div v-if="activeTab === 'apikeys' && isAdmin" class="page">
    <APIKeys />
  </div>

  <div v-else class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Setting /></el-icon>
          {{ pageTitle }}
        </h2>
        <p class="page-desc">{{ pageDesc }}</p>
      </div>
    </div>

    <BasicSettings v-if="activeTab === 'basic'" v-model:settings="settings" />
    <ClusterSettings v-else-if="activeTab === 'cluster'" v-model:settings="settings" />
    <FreeCertificates v-else-if="activeTab === 'certificates'" v-model:global="global" />

    <div class="save-bar">
      <el-button type="primary" size="large" @click="handleSave" :loading="saving">
        <el-icon><Check /></el-icon>保存设置
      </el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage } from 'element-plus'
import { Setting, Check } from '@element-plus/icons-vue'
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

.save-bar {
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  justify-content: flex-end;
}
</style>
