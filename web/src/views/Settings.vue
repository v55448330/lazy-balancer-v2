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

    <!-- 首屏 /config 失败显性化 + 重试——原仅 console，保存门永久禁用
         只能整页刷新 -->
    <el-alert v-if="configBannerVisible" type="error" :closable="false" show-icon class="error-banner" style="margin-bottom: 16px">
      <template #title>
        基础配置加载失败，保存已暂停以避免默认值覆盖真实配置。<el-button link type="danger" @click="fetchSettings">重试</el-button>
      </template>
    </el-alert>

    <div v-if="activeTab === 'tasks'" class="task-monitor-wrap">
      <TaskMonitor />
    </div>

    <div v-if="activeTab === 'basic'" class="basic-settings-grid">
      <BasicSettings
        v-model:settings="settings"
        :config-loaded="configLoaded"
        :on-save="handleSaveBasic"
        :saved-threat-screen-mode="savedThreatScreenMode"
        :saved-threat-traffic-sample-n="savedThreatTrafficSampleN"
      />
      <CaddyGlobalSettings
        v-model:settings="settings"
        :config-loaded="configLoaded"
        @save="handleSaveCaddy"
      />
    </div>
    <ClusterSettings
      v-else-if="activeTab === 'cluster'"
    />
    <FreeCertificates
      v-else-if="activeTab === 'certificates'"
      v-model:global="global"
      :config-loaded="configLoaded"
      @save="handleSaveCertificates"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { resetSettingsDraft, syncSettingsDraftIdentity } from '@/composables/useSettingsDraft'
import { request } from '@/utils/api'
import { DEFAULT_ACCESS_LOG_FORMAT } from '@/utils/caddyDefaults'
import { normalizeTrafficSampleN } from '@/utils/threatFlowRules'
import { displaySecurityEventsRetentionDays, displaySecurityEventsRowCap, displayThreatScreenMode } from '@/utils/configValues'
import { SETTINGS_TAB_DESCS, SETTINGS_TAB_TITLES, settingsTabConsumesConfig, settingsTabOfPage, type SettingsTabId } from '@/utils/settingsPages'
import { useAuthStore } from '@/stores/auth'
import { Setting } from '@element-plus/icons-vue'
import BasicSettings from './settings/BasicSettings.vue'
import CaddyGlobalSettings from './settings/CaddyGlobalSettings.vue'
import ClusterSettings from './settings/ClusterSettings.vue'
import FreeCertificates from './settings/FreeCertificates.vue'
import APIKeys from '@/views/Keys.vue'
import TaskMonitor from './settings/TaskMonitor.vue'

const authStore = useAuthStore()

// 初值即按当前页键派生（setup 期 authStore 已就绪）——原恒 'basic' 等
// onMounted 才纠正，从侧栏进 cluster/certificates/tasks/apikeys 时首帧错挂
// BasicSettings+CaddyGlobalSettings（闪烁 + 发出 /system/info、/config、
// /admin-tls、/security/ip-lists 等请求后随即卸载）。
const activeTab = ref<SettingsTabId>(settingsTabOfPage(authStore.currentPage) ?? 'basic')

// /config 契约单一事实源迁至 types/index.ts（GlobalConfigData）——
// 两块设置卡各持互斥子集，这里按卡片分组做派生别名，不再复制字段清单。
import type { GlobalConfigData } from '@/types'

type CertificateConfig = Pick<GlobalConfigData,
  | 'acme_email'
  | 'cert_expiry_days'
  | 'cert_renewal_days'
  | 'cert_renewal_attempts'
  | 'default_ca_provider_id'
  | 'dns_provider'
>
type SettingsConfig = Omit<GlobalConfigData, keyof CertificateConfig>

const settings = ref<SettingsConfig>({
  log_level: 'info',
  caddy_log_level: 'info',
  caddy_log_size_mb: 100,
  request_body_max_size_mb: 0,
  http_read_timeout: 60,
  http_write_timeout: 60,
  http_idle_timeout: 120,
  upstream_keepalive_timeout: 0,
  proxy_dial_timeout: 0,
  proxy_response_header_timeout: 0,
  proxy_read_timeout: 0,
  proxy_write_timeout: 0,
  proxy_stream_timeout: 0,
  proxy_flush_interval: 0,
  proxy_stream_close_delay: 0,
  server_tokens_hidden: false,
  task_log_size_mb: 10,
  audit_log_size_mb: 10,
  runtime_log_size_mb: 100,
  access_log_json: true,
  access_log_format: DEFAULT_ACCESS_LOG_FORMAT,
  server_map_lat: 0,
  server_map_lon: 0,
  threat_screen_mode: 'map',
  security_events_retention_days: 90,
  threat_traffic_sample_n: -1,
  security_events_row_cap: 1_000_000,
  trusted_proxy_enabled: false,
  trusted_proxy_ranges: '[]',
  trusted_proxy_range_refs: '[]',
  trusted_proxy_headers: '[]',
  trusted_proxy_strict: true,
  audit_retention_months: 3,
  jwt_expire_minutes: 20,
  timezone: 'Asia/Shanghai',
  mfa_write_guard: false,
  mfa_lockout_enabled: false,
})

const global = ref<CertificateConfig>({
  acme_email: '',
  cert_expiry_days: 30,
  cert_renewal_days: 30,
  cert_renewal_attempts: 5,
  default_ca_provider_id: 0,
  dns_provider: 'dnspod',
})

// 标题/描述/页键映射单源见 utils/settingsPages（AppLayout 面包屑共用同一份）
const pageTitle = computed(() => SETTINGS_TAB_TITLES[activeTab.value])
const pageDesc = computed(() => SETTINGS_TAB_DESCS[activeTab.value])
// 服务端最近一次确认的大屏展示字段：基础卡据此判断用户是否真的编辑过，
// 并在切页重挂后仍能识别未保存编辑（本地 ref 会随卸载丢失）。
const savedThreatScreenMode = ref<'map' | 'globe'>('map')
const savedThreatTrafficSampleN = ref(-1)
let settingsRequestSeq = 0

// Each card owns a subset of the shared `settings`/`global` objects. Apply
// helpers merge only the saved card's keys back from the server so sibling
// cards keep whatever the user typed that has not been saved yet.
type ConfigPayload = SettingsConfig & CertificateConfig

const applyBasicKeys = (data: ConfigPayload) => {
  settings.value.log_level = data.log_level || 'info'
  settings.value.task_log_size_mb = data.task_log_size_mb ?? 10
  settings.value.audit_log_size_mb = data.audit_log_size_mb ?? 10
  settings.value.runtime_log_size_mb = data.runtime_log_size_mb ?? 100
  settings.value.audit_retention_months = data.audit_retention_months ?? 3
  settings.value.jwt_expire_minutes = data.jwt_expire_minutes ?? 20
  settings.value.timezone = data.timezone || 'Asia/Shanghai'
  settings.value.mfa_write_guard = data.mfa_write_guard ?? false
  settings.value.mfa_lockout_enabled = data.mfa_lockout_enabled ?? false
  // 基础卡自有字段：此前只在 Caddy 卡的合并函数里回写，基础卡保存后
  // 父模型停留旧值——切页重挂后用旧值覆盖本地 ref，再次保存即把旧值写回库。
  // 大屏本站坐标/视觉模式/安全事件保留/行数上限/流量采样均归基础卡所有。
  settings.value.server_map_lat = data.server_map_lat ?? 0
  settings.value.server_map_lon = data.server_map_lon ?? 0
  const threatMode = displayThreatScreenMode(data.threat_screen_mode)
  settings.value.threat_screen_mode = threatMode
  savedThreatScreenMode.value = threatMode
  settings.value.security_events_retention_days = displaySecurityEventsRetentionDays(data.security_events_retention_days)
  const sampleN = normalizeTrafficSampleN(data.threat_traffic_sample_n)
  settings.value.threat_traffic_sample_n = sampleN
  savedThreatTrafficSampleN.value = sampleN
  settings.value.security_events_row_cap = displaySecurityEventsRowCap(data.security_events_row_cap)
  // GitHub 下载代理与令牌状态随整包回填（基础设置卡不再自拉第二份 /config）：
  // 空值留给卡片的展示兜底（未配置→默认代理），令牌状态按未配置展示。
  settings.value.github_proxy_url = data.github_proxy_url ?? ''
  settings.value.has_github_token = data.has_github_token ?? false
}

const applyCaddyKeys = (data: ConfigPayload) => {
  settings.value.caddy_log_level = data.caddy_log_level || 'info'
  settings.value.caddy_log_size_mb = data.caddy_log_size_mb ?? 100
  settings.value.request_body_max_size_mb = data.request_body_max_size_mb ?? 0
  settings.value.http_read_timeout = data.http_read_timeout ?? 60
  settings.value.http_write_timeout = data.http_write_timeout ?? 60
  settings.value.http_idle_timeout = data.http_idle_timeout ?? 120
  settings.value.upstream_keepalive_timeout = data.upstream_keepalive_timeout ?? 0
  settings.value.proxy_dial_timeout = data.proxy_dial_timeout ?? 0
  settings.value.proxy_response_header_timeout = data.proxy_response_header_timeout ?? 0
  settings.value.proxy_read_timeout = data.proxy_read_timeout ?? 0
  settings.value.proxy_write_timeout = data.proxy_write_timeout ?? 0
  settings.value.proxy_stream_timeout = data.proxy_stream_timeout ?? 0
  settings.value.proxy_flush_interval = data.proxy_flush_interval ?? 0
  settings.value.proxy_stream_close_delay = data.proxy_stream_close_delay ?? 0
  settings.value.server_tokens_hidden = data.server_tokens_hidden ?? false
  settings.value.access_log_json = data.access_log_json ?? true
  // 空格式需双向一致：DB 为空时 UI 同步清空，避免旧模板被下次保存写回 DB
  settings.value.access_log_format = data.access_log_format ?? ''
  // v2.3.x 受信代理（CDN 真实 IP）
  settings.value.trusted_proxy_enabled = data.trusted_proxy_enabled ?? false
  settings.value.trusted_proxy_ranges = data.trusted_proxy_ranges ?? '[]'
  settings.value.trusted_proxy_range_refs = data.trusted_proxy_range_refs ?? '[]'
  settings.value.trusted_proxy_headers = data.trusted_proxy_headers ?? '[]'
  settings.value.trusted_proxy_strict = data.trusted_proxy_strict ?? true
  // 大屏本站坐标/视觉模式/安全事件保留/流量采样归基础卡（见 applyBasicKeys）——
  // Caddy 卡保存不得回写这些字段，否则覆盖基础卡未保存的编辑。
}

const applyCertKeys = (data: ConfigPayload) => {
  // M31：回显侧同 trim——存量配置中已带入的空白不再随表单回写扩散
  global.value.acme_email = (data.acme_email || '').trim()
  global.value.cert_expiry_days = data.cert_expiry_days ?? 30
  global.value.cert_renewal_days = data.cert_renewal_days ?? 30
  global.value.cert_renewal_attempts = data.cert_renewal_attempts ?? 5
  global.value.default_ca_provider_id = data.default_ca_provider_id ?? 0
  global.value.dns_provider = data.dns_provider || 'dnspod'
}

const configLoaded = ref(false)
// 首屏失败显性化（模板重试入口）；任一成功 /config 读取都恢复保存门
const configLoadFailed = ref(false)
// 横幅只在消费 /config 的分页成立（集群/任务监控不读它，文案会误导）
const configBannerVisible = computed(() => configLoadFailed.value && settingsTabConsumesConfig(activeTab.value))
const fetchSettings = async () => {
  const requestSeq = ++settingsRequestSeq
  configLoaded.value = false
  try {
    const res = await request.get('/config')
    if (requestSeq === settingsRequestSeq && res.data) {
      applyBasicKeys(res.data)
      applyCaddyKeys(res.data)
      applyCertKeys(res.data)
      configLoaded.value = true
      configLoadFailed.value = false
    }
  } catch (error) {
    console.error('Failed to fetch settings:', error)
    if (requestSeq === settingsRequestSeq) configLoadFailed.value = true
  }
}

const refreshConfigSection = async (apply: (data: ConfigPayload) => void) => {
  const requestSeq = ++settingsRequestSeq
  try {
    const res = await request.get('/config')
    if (requestSeq === settingsRequestSeq && res.data) {
      apply(res.data)
      // 任一成功读取即恢复保存门——首屏瞬时失败后经卡片保存后刷新
      // 成功的路径不再让 Basic/Caddy 保存永久禁用（原只有 fetchSettings 置 true）。
      configLoaded.value = true
      configLoadFailed.value = false
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
  activeTab.value = settingsTabOfPage(authStore.currentPage) ?? 'basic'
}

// 仅消费 settings/global 的分页才拉整包 /config（apikeys/tasks/cluster 不接
// props，白拉 60+ 字段整包后丢弃）；切回 basic/certificates 且未加载时补拉。
// 判据单源在 utils/settingsPages（横幅与拉取门必须同源：各自枚举会在调整
// 「消费 /config」分页时静默分叉）。

watch(() => authStore.currentPage, () => {
  syncActiveTabFromPage()
  if (settingsTabConsumesConfig(activeTab.value) && !configLoaded.value) void fetchSettings()
})

// 同一标签页通过登录票据换号不会卸载设置页：身份变化必须清空上一位用户的
// 一次性令牌、证书暂存与 dirty 标记，避免跨账号残留。
watch(() => authStore.user?.id, (userId) => {
  syncSettingsDraftIdentity(userId ?? null)
})

onMounted(() => {
  syncSettingsDraftIdentity(authStore.user?.id ?? null)
  if (settingsTabConsumesConfig(activeTab.value)) void fetchSettings()
})

// 设置草稿（令牌输入/安全事件 dirty/管理面板证书暂存）随「设置」逻辑页面
// 存活：页内切换分页不重置（否则基础设置卡的暂存内容静默丢失），离开系统
// 设置（本组件卸载）才复位。
onUnmounted(() => {
  resetSettingsDraft()
})
</script>

<style scoped>
.basic-settings-grid { display: grid; grid-template-columns: 5.2fr 6.8fr; gap: 20px; align-items: start; }
@media (max-width: 1100px) { .basic-settings-grid { grid-template-columns: 1fr; } }
</style>
