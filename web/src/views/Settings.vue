<template>
  <div class="page" v-if="activeTab === 'apikeys'">
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

    <div v-if="activeTab === 'basic'" class="basic-settings-grid">
      <BasicSettings
        v-model:settings="settings"
        @save="handleSaveBasic"
      />
      <CaddyGlobalSettings
        v-model:settings="settings"
        @save="handleSaveBasic"
      />
    </div>
    <ClusterSettings
      v-else-if="activeTab === 'cluster'"
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
import { Setting } from '@element-plus/icons-vue'
import BasicSettings from './settings/BasicSettings.vue'
import CaddyGlobalSettings from './settings/CaddyGlobalSettings.vue'
import ClusterSettings from './settings/ClusterSettings.vue'
import FreeCertificates from './settings/FreeCertificates.vue'
import APIKeys from '@/views/Keys.vue'

const authStore = useAuthStore()

const activeTab = ref('basic')

interface SettingsConfig {
  log_level: string
  caddy_log_path: string
  caddy_log_level: string
  caddy_log_size_mb: number
  request_body_max_size_mb: number
  http_read_timeout: number
  http_write_timeout: number
  http_idle_timeout: number
  upstream_keepalive_timeout: number
  proxy_dial_timeout: number
  proxy_response_header_timeout: number
  proxy_read_timeout: number
  proxy_write_timeout: number
  proxy_stream_timeout: number
  server_tokens_hidden: boolean
  cert_job_log_size_mb: number
  runtime_log_size_mb: number
  access_log_json: boolean
  access_log_format: string
  audit_retention_months: number
  jwt_expire_minutes: number
  timezone: string
}

interface CertificateConfig {
  acme_email: string
  cert_expiry_days: number
  cert_renewal_days: number
  cert_renewal_attempts: number
  default_ca_provider_id: number
  dns_provider: string
}

const settings = ref<SettingsConfig>({
  log_level: 'info',
  caddy_log_path: '/app/logs/caddy.log',
  caddy_log_level: 'info',
  caddy_log_size_mb: 100,
  request_body_max_size_mb: 0,
  http_read_timeout: 60,
  http_write_timeout: 60,
  http_idle_timeout: 120,
  upstream_keepalive_timeout: 60,
  proxy_dial_timeout: 0,
  proxy_response_header_timeout: 0,
  proxy_read_timeout: 0,
  proxy_write_timeout: 0,
  proxy_stream_timeout: 0,
  server_tokens_hidden: false,
  cert_job_log_size_mb: 10,
  runtime_log_size_mb: 100,
  access_log_json: true,
  access_log_format: 'resp_headers -> delete\nrequest>tls -> delete\nrequest>remote_port -> delete\nlevel -> delete\nlogger -> delete\nmsg -> delete\nrequest>remote_ip -> src\nrequest>client_ip -> src_ip\nrequest>method -> http_method\nrequest>host -> server\nrequest>uri -> uri_path\nrequest>proto -> protocol\nuser_id -> user\nts -> time_local\nsize -> bytes_out\nbytes_read -> bytes_in\nduration -> request_time',
  audit_retention_months: 3,
  jwt_expire_minutes: 20,
  timezone: 'Asia/Shanghai',
})

const global = ref<CertificateConfig>({
  acme_email: '',
  cert_expiry_days: 30,
  cert_renewal_days: 30,
  cert_renewal_attempts: 5,
  default_ca_provider_id: 0,
  dns_provider: 'dnspod',
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
        caddy_log_path: res.data.caddy_log_path || '/app/logs/caddy.log',
        caddy_log_level: res.data.caddy_log_level || 'info',
        caddy_log_size_mb: res.data.caddy_log_size_mb ?? 100,
        request_body_max_size_mb: res.data.request_body_max_size_mb ?? 0,
        http_read_timeout: res.data.http_read_timeout ?? 60,
        http_write_timeout: res.data.http_write_timeout ?? 60,
        http_idle_timeout: res.data.http_idle_timeout ?? 120,
        upstream_keepalive_timeout: res.data.upstream_keepalive_timeout ?? 60,
        proxy_dial_timeout: res.data.proxy_dial_timeout ?? 0,
        proxy_response_header_timeout: res.data.proxy_response_header_timeout ?? 0,
        proxy_read_timeout: res.data.proxy_read_timeout ?? 0,
        proxy_write_timeout: res.data.proxy_write_timeout ?? 0,
        proxy_stream_timeout: res.data.proxy_stream_timeout ?? 0,
        server_tokens_hidden: res.data.server_tokens_hidden ?? false,
        cert_job_log_size_mb: res.data.cert_job_log_size_mb ?? 10,
        runtime_log_size_mb: res.data.runtime_log_size_mb ?? 100,
        access_log_json: res.data.access_log_json ?? true,
        access_log_format: res.data.access_log_format || settings.value.access_log_format,
        audit_retention_months: res.data.audit_retention_months ?? 3,
        jwt_expire_minutes: res.data.jwt_expire_minutes ?? 20,
        timezone: res.data.timezone || 'Asia/Shanghai',
      }
      global.value = {
        acme_email: res.data.acme_email || '',
        cert_expiry_days: res.data.cert_expiry_days ?? 30,
        cert_renewal_days: res.data.cert_renewal_days ?? 30,
        cert_renewal_attempts: res.data.cert_renewal_attempts ?? 5,
        default_ca_provider_id: res.data.default_ca_provider_id ?? 0,
        dns_provider: res.data.dns_provider || 'dnspod',
      }
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
  }
}

const handleSaveBasic = async () => {
  await fetchSettings()
}

const handleSaveCertificates = async () => {
  await fetchSettings()
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
.basic-settings-grid { display: grid; grid-template-columns: 5fr 7fr; gap: 20px; align-items: start; }
@media (max-width: 1100px) { .basic-settings-grid { grid-template-columns: 1fr; } }

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
