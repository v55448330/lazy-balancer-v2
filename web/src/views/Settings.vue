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
        @save="handleSaveCaddy"
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
  proxy_flush_interval: number
  proxy_stream_close_delay: number
  server_tokens_hidden: boolean
  cert_job_log_size_mb: number
  audit_log_size_mb: number
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
  proxy_flush_interval: 0,
  proxy_stream_close_delay: 0,
  server_tokens_hidden: false,
  cert_job_log_size_mb: 10,
  audit_log_size_mb: 10,
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
let settingsRequestSeq = 0

// Each card owns a subset of the shared `settings`/`global` objects. Apply
// helpers merge only the saved card's keys back from the server so sibling
// cards keep whatever the user typed that has not been saved yet.
type ConfigPayload = SettingsConfig & CertificateConfig

const applyBasicKeys = (data: ConfigPayload) => {
  settings.value.log_level = data.log_level || 'info'
  settings.value.cert_job_log_size_mb = data.cert_job_log_size_mb ?? 10
  settings.value.audit_log_size_mb = data.audit_log_size_mb ?? 10
  settings.value.runtime_log_size_mb = data.runtime_log_size_mb ?? 100
  settings.value.audit_retention_months = data.audit_retention_months ?? 3
  settings.value.jwt_expire_minutes = data.jwt_expire_minutes ?? 20
  settings.value.timezone = data.timezone || 'Asia/Shanghai'
}

const applyCaddyKeys = (data: ConfigPayload) => {
  settings.value.caddy_log_path = data.caddy_log_path || '/app/logs/caddy.log'
  settings.value.caddy_log_level = data.caddy_log_level || 'info'
  settings.value.caddy_log_size_mb = data.caddy_log_size_mb ?? 100
  settings.value.request_body_max_size_mb = data.request_body_max_size_mb ?? 0
  settings.value.http_read_timeout = data.http_read_timeout ?? 60
  settings.value.http_write_timeout = data.http_write_timeout ?? 60
  settings.value.http_idle_timeout = data.http_idle_timeout ?? 120
  settings.value.upstream_keepalive_timeout = data.upstream_keepalive_timeout ?? 60
  settings.value.proxy_dial_timeout = data.proxy_dial_timeout ?? 0
  settings.value.proxy_response_header_timeout = data.proxy_response_header_timeout ?? 0
  settings.value.proxy_read_timeout = data.proxy_read_timeout ?? 0
  settings.value.proxy_write_timeout = data.proxy_write_timeout ?? 0
  settings.value.proxy_stream_timeout = data.proxy_stream_timeout ?? 0
  settings.value.proxy_flush_interval = data.proxy_flush_interval ?? 0
  settings.value.proxy_stream_close_delay = data.proxy_stream_close_delay ?? 0
  settings.value.server_tokens_hidden = data.server_tokens_hidden ?? false
  settings.value.access_log_json = data.access_log_json ?? true
  settings.value.access_log_format = data.access_log_format || settings.value.access_log_format
}

const applyCertKeys = (data: ConfigPayload) => {
  global.value.acme_email = data.acme_email || ''
  global.value.cert_expiry_days = data.cert_expiry_days ?? 30
  global.value.cert_renewal_days = data.cert_renewal_days ?? 30
  global.value.cert_renewal_attempts = data.cert_renewal_attempts ?? 5
  global.value.default_ca_provider_id = data.default_ca_provider_id ?? 0
  global.value.dns_provider = data.dns_provider || 'dnspod'
}

const fetchSettings = async () => {
  const requestSeq = ++settingsRequestSeq
  try {
    const res = await request.get('/config')
    if (requestSeq === settingsRequestSeq && res.data) {
      applyBasicKeys(res.data)
      applyCaddyKeys(res.data)
      applyCertKeys(res.data)
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
  }
}

const refreshConfigSection = async (apply: (data: ConfigPayload) => void) => {
  const requestSeq = ++settingsRequestSeq
  try {
    const res = await request.get('/config')
    if (requestSeq === settingsRequestSeq && res.data) {
      apply(res.data)
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
  }
}

const handleSaveBasic = async () => {
  await refreshConfigSection(applyBasicKeys)
}

const handleSaveCaddy = async () => {
  await refreshConfigSection(applyCaddyKeys)
}

const handleSaveCertificates = async () => {
  await refreshConfigSection(applyCertKeys)
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
