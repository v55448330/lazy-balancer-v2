<template>
  <div class="basic-stack">
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Setting /></el-icon>
            <span>基础设置</span>
          </div>
        </div>
      </template>
        <el-form :model="settings" label-width="120px" class="settings-form" :disabled="isReadOnly">
          <el-form-item label="日志级别">
            <el-select v-model="settings.log_level" class="compact-select">
              <el-option label="Debug" value="debug" />
              <el-option label="Info" value="info" />
              <el-option label="Warning" value="warn" />
              <el-option label="Error" value="error" />
            </el-select>
            <el-text type="info" size="small" class="tip-inline">控制 Lazy Balancer 自身日志详细程度</el-text>
          </el-form-item>
          <el-form-item label="证书日志大小">
            <el-input-number v-model="settings.cert_job_log_size_mb" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">MB，滚动阈值，保留 5 份（建议 10-50）</el-text>
          </el-form-item>
          <el-form-item label="运行日志大小">
            <el-input-number v-model="settings.runtime_log_size_mb" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">MB，轮转阈值（建议 50-200）</el-text>
          </el-form-item>
          <el-form-item label="日志保留">
            <el-input-number v-model="settings.audit_retention_months" :min="1" :max="12" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">个月，操作与运行日志超期清理（建议 3-6）</el-text>
          </el-form-item>
          <el-form-item label="登录过期">
            <el-input-number v-model="settings.jwt_expire_minutes" :min="5" :max="1440" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">分钟，登录令牌有效期（默认 20）</el-text>
          </el-form-item>
          <el-form-item label="时区">
            <el-select v-model="settings.timezone" filterable class="compact-select">
              <el-option label="Asia/Shanghai (UTC+8)" value="Asia/Shanghai" />
              <el-option label="Asia/Hong_Kong (UTC+8)" value="Asia/Hong_Kong" />
              <el-option label="Asia/Tokyo (UTC+9)" value="Asia/Tokyo" />
              <el-option label="Asia/Singapore (UTC+8)" value="Asia/Singapore" />
              <el-option label="Asia/Seoul (UTC+9)" value="Asia/Seoul" />
              <el-option label="Asia/Bangkok (UTC+7)" value="Asia/Bangkok" />
              <el-option label="Asia/Kolkata (UTC+5:30)" value="Asia/Kolkata" />
              <el-option label="Asia/Dubai (UTC+4)" value="Asia/Dubai" />
              <el-option label="Europe/London (UTC+0)" value="Europe/London" />
              <el-option label="Europe/Paris (UTC+1)" value="Europe/Paris" />
              <el-option label="Europe/Berlin (UTC+1)" value="Europe/Berlin" />
              <el-option label="Europe/Moscow (UTC+3)" value="Europe/Moscow" />
              <el-option label="America/New_York (UTC-5)" value="America/New_York" />
              <el-option label="America/Chicago (UTC-6)" value="America/Chicago" />
              <el-option label="America/Denver (UTC-7)" value="America/Denver" />
              <el-option label="America/Los_Angeles (UTC-8)" value="America/Los_Angeles" />
              <el-option label="America/Sao_Paulo (UTC-3)" value="America/Sao_Paulo" />
              <el-option label="Australia/Sydney (UTC+10)" value="Australia/Sydney" />
              <el-option label="UTC" value="UTC" />
            </el-select>
            <el-text type="info" size="small" class="tip-inline">影响日志时间戳与证书时间；仅 Caddy 日志需重启服务生效</el-text>
          </el-form-item>
          <el-form-item label="强制 HTTPS">
            <el-switch v-model="adminTls.enabled" @change="onAdminTlsToggle" />
            <el-button v-if="adminTls.enabled" size="small" style="margin-left: 8px;" @click="openAdminTlsDialog">配置证书</el-button>
            <el-text type="info" size="small" class="tip-inline">启用后 :8000 仅经 HTTPS 访问（HTTP 不再生效），需重启服务生效</el-text>
          </el-form-item>
          <el-form-item label="运行日志">
            <el-button size="small" :icon="View" @click="openAppLogDialog">查看日志</el-button>
            <el-text type="info" size="small" class="tip-inline">查看 Lazy Balancer 自身运行日志</el-text>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="handleSave">
              <el-icon><Check /></el-icon>
              <span class="btn-text">保存</span>
            </el-button>
          </el-form-item>
        </el-form>
    </el-card>

    <el-card class="info-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><InfoFilled /></el-icon>
            <span>系统信息</span>
          </div>
        </div>
      </template>
      <div class="info-list">
        <div class="info-item">
          <span class="info-label">版本</span>
          <el-tag type="info" size="small">{{ appVersion }}</el-tag>
        </div>
        <div class="info-item">
          <span class="info-label">运行模式</span>
          <el-tag :type="authStore.nodeMode === 'master' ? 'success' : 'warning'" size="small">
            {{ authStore.nodeMode === 'master' ? '主节点' : '从节点' }}
          </el-tag>
        </div>
        <div class="info-item">
          <span class="info-label">配置备份</span>
          <div class="backup-actions">
            <el-button size="small" :disabled="backupDisabled" :loading="exporting" @click="exportBackup">导出</el-button>
            <el-button size="small" type="warning" plain :disabled="backupDisabled" @click="triggerImport">导入</el-button>
          </div>
        </div>
        <div class="info-item">
          <span class="info-label">重启服务</span>
          <el-button size="small" type="danger" plain :disabled="isReadOnly" :loading="restarting" @click="handleRestart">重启</el-button>
        </div>
        <el-text type="info" size="small" class="backup-tip">备份包含全部配置、规则、用户、密钥与证书任务；导入将覆盖当前配置，仅主节点可用</el-text>
      </div>
    </el-card>

    <el-dialog v-model="adminTlsDialogVisible" title="HTTPS 证书配置" width="min(520px, 92vw)" destroy-on-close @closed="onAdminTlsDialogClose">
      <el-form label-width="110px">
        <el-form-item label="证书来源">
          <el-radio-group v-model="adminTlsForm.mode">
            <el-radio value="selfsigned">本地自签名证书</el-radio>
            <el-radio value="upload">上传证书</el-radio>
          </el-radio-group>
        </el-form-item>
        <template v-if="adminTlsForm.mode === 'upload'">
          <el-form-item label="证书文件">
            <input type="file" accept=".crt,.pem,.cer" @change="(e) => onTlsFile(e, 'cert')" />
          </el-form-item>
          <el-form-item label="私钥文件">
            <input type="file" accept=".key,.pem" @change="(e) => onTlsFile(e, 'key')" />
          </el-form-item>
          <el-form-item v-if="adminTlsForm.inspecting" label=" ">
            <el-text type="info" size="small">解析中…</el-text>
          </el-form-item>
          <template v-if="adminTlsForm.certInfo">
            <el-form-item label="证书信息">
              <div class="tls-cert-info">
                <div>域名：{{ adminTlsForm.certInfo.domain }}</div>
                <div>签发者：{{ adminTlsForm.certInfo.issuer }}</div>
                <div>过期时间：{{ adminTlsForm.certInfo.not_after }}（剩余 {{ adminTlsForm.certInfo.days_left }} 天）</div>
              </div>
            </el-form-item>
          </template>
        </template>
        <el-form-item v-if="adminTlsForm.mode === 'selfsigned'" label="说明">
          <el-text type="info" size="small">自动生成自签名证书，浏览器会提示不受信任；集群同步会自动跳过自签验证</el-text>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="adminTlsDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="adminTlsSaving" :disabled="adminTlsForm.mode === 'upload' && !adminTlsForm.certInfo" @click="saveAdminTls">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="appLogVisible" title="Lazy Balancer 运行日志" width="min(1100px, 94vw)" destroy-on-close @opened="onAppLogOpened" @closed="onAppLogClosed">
      <div class="log-toolbar">
        <el-switch v-model="appLogAutoRefresh" active-text="自动刷新" />
        <el-button size="small" :loading="appLogLoading" @click="fetchAppLogs">刷新</el-button>
      </div>
      <div ref="appLogContainer" class="log-viewer"><pre>{{ appLogContent || '暂无日志' }}</pre></div>
      <template #footer><el-button @click="appLogVisible = false">关闭</el-button></template>
    </el-dialog>

    <el-dialog v-model="importDialogVisible" title="导入配置备份" width="min(560px, 92vw)" :close-on-click-modal="false" @close="onImportDialogClosed">
      <div class="import-picker">
        <el-button :icon="Upload" @click="chooseImportFile">选择备份文件</el-button>
        <span v-if="importFileName" class="import-filename">{{ importFileName }}</span>
        <span v-else class="import-hint">支持 V2 完整备份与 V1（nginx 版）备份</span>
      </div>
      <input ref="importInput" type="file" accept="application/json,.json,.bak" class="import-input" @change="handleImportFile" />

      <div v-if="importValidating" v-loading="true" class="import-validating">正在校验备份文件...</div>

      <template v-if="importValidation && !importValidating">
        <el-alert v-if="!importValidation.valid" :title="importValidation.error || '备份文件校验失败'" type="error" :closable="false" show-icon class="import-alert" />
        <template v-else>
          <div class="import-result">
            <el-tag :type="importValidation.type === 'v1' ? 'warning' : 'success'" size="small">
              {{ importValidation.type === 'v1' ? 'V1 兼容导入' : 'V2 完整备份' }}
            </el-tag>
            <div class="import-summary">
              <span v-for="(count, key) in importValidation.summary" :key="key" class="import-summary-item">
                {{ summaryLabels[key] || key }} {{ count }}
              </span>
            </div>
            <ul v-if="importValidation.warnings?.length" class="import-warnings">
              <li v-for="(warning, index) in importValidation.warnings" :key="index">{{ warning }}</li>
            </ul>
            <el-alert
              v-if="importValidation.type !== 'v1'"
              title="导入将覆盖当前全部配置（规则、用户、密钥、证书任务）"
              type="warning"
              :closable="false"
              show-icon
              class="import-alert"
            />
            <el-alert
              v-else
              title="仅导入负载均衡规则，其他数据不受影响"
              type="info"
              :closable="false"
              show-icon
              class="import-alert"
            />
          </div>
        </template>
      </template>

      <template #footer>
        <el-button @click="importDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="!importValidation?.valid" :loading="importing" @click="confirmImport">确认导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { Setting, InfoFilled, Check, View, Upload } from '@element-plus/icons-vue'
import type { SystemInfo } from '@/types'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const backupDisabled = computed(() => isReadOnly.value || authStore.nodeMode !== 'master')
const exporting = ref(false)
const importing = ref(false)
const appVersion = ref('-')

onMounted(async () => {
  try {
    const res = await request.get<{ data: SystemInfo }>('/system/info')
    appVersion.value = res.data.version || '-'
  } catch {
    appVersion.value = '-'
  }
})

const appLogVisible = ref(false)
const appLogContent = ref('')
const appLogLoading = ref(false)
const appLogAutoRefresh = ref(true)
const appLogContainer = ref<HTMLElement | null>(null)
let appLogTimer: ReturnType<typeof setInterval> | null = null
let appLogRequestSeq = 0

const fetchAppLogs = async (): Promise<void> => {
  if (appLogLoading.value) return
  const requestSeq = ++appLogRequestSeq
  appLogLoading.value = true
  try {
    const res = await request.get<{ data?: { content?: string } }>('/system/logs')
    if (requestSeq !== appLogRequestSeq || !appLogVisible.value) return
    appLogContent.value = res.data?.content || ''
    await nextTick()
    if (appLogContainer.value) appLogContainer.value.scrollTop = appLogContainer.value.scrollHeight
  } finally {
    if (requestSeq === appLogRequestSeq) appLogLoading.value = false
  }
}

const stopAppLogTimer = (): void => {
  if (appLogTimer) {
    clearInterval(appLogTimer)
    appLogTimer = null
  }
}

const openAppLogDialog = (): void => {
  appLogVisible.value = true
}

const onAppLogOpened = (): void => {
  void fetchAppLogs()
  stopAppLogTimer()
  if (appLogAutoRefresh.value) appLogTimer = setInterval(() => void fetchAppLogs(), 3000)
}

const onAppLogClosed = (): void => {
  stopAppLogTimer()
  appLogRequestSeq++
  appLogLoading.value = false
  appLogContent.value = ''
}

watch(appLogAutoRefresh, (enabled) => {
  if (!appLogVisible.value) return
  stopAppLogTimer()
  if (enabled) appLogTimer = setInterval(() => void fetchAppLogs(), 3000)
})

onUnmounted(() => {
  disposed = true
  stopAppLogTimer()
  if (tlsProtocolRedirectTimer) clearTimeout(tlsProtocolRedirectTimer)
  if (tlsProtocolFallbackTimer) clearTimeout(tlsProtocolFallbackTimer)
  tlsProtocolRedirectTimer = null
  tlsProtocolFallbackTimer = null
})

const exportBackup = async (): Promise<void> => {
  if (backupDisabled.value || exporting.value) return
  exporting.value = true
  try {
    const blob = await request.get<Blob>('/config/export', { responseType: 'blob' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `lazy-balancer-backup-${new Date().toISOString().slice(0, 10)}.json`
    link.click()
    URL.revokeObjectURL(url)
    ElMessage.success('配置备份已导出')
  } finally {
    exporting.value = false
  }
}

interface ImportValidation {
  valid: boolean
  type?: string
  error?: string
  summary?: Record<string, number>
  warnings?: string[]
}

const importDialogVisible = ref(false)
const importFileName = ref('')
const importFileContent = ref('')
const importValidation = ref<ImportValidation | null>(null)
const importValidating = ref(false)
const importInput = ref<HTMLInputElement | null>(null)
let importValidationSeq = 0

const summaryLabels: Record<string, string> = {
  lb_rules: '规则',
  upstreams: '上游',
  users: '用户',
  api_keys: 'API 密钥',
  ca_providers: 'CA 提供商',
  certificate_configs: 'DNS 提供商',
  cert_jobs: '证书任务',
  rules: '规则',
  tls_rules: '其中 TLS 规则',
}

const triggerImport = (): void => {
  if (backupDisabled.value) return
  importValidationSeq++
  importValidating.value = false
  importFileName.value = ''
  importFileContent.value = ''
  importValidation.value = null
  importDialogVisible.value = true
}

const onImportDialogClosed = (): void => {
  importValidationSeq++
  importValidating.value = false
}

const chooseImportFile = (): void => {
  importInput.value?.click()
}

const handleImportFile = async (event: Event): Promise<void> => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  const validationSeq = ++importValidationSeq
  importFileName.value = file.name
  importValidation.value = null
  importValidating.value = true
  try {
    const fileContent = await file.text()
    const res = await request.post<{ data: ImportValidation }>('/config/import/validate', fileContent, {
      headers: { 'Content-Type': 'application/json' },
    })
    if (validationSeq !== importValidationSeq) return
    importFileContent.value = fileContent
    importValidation.value = res.data
  } catch {
    if (validationSeq === importValidationSeq) {
      importValidation.value = { valid: false, error: '校验请求失败，请重试' }
    }
  } finally {
    if (validationSeq === importValidationSeq) {
      importValidating.value = false
    }
  }
}

const confirmImport = async (): Promise<void> => {
  const validation = importValidation.value
  if (!validation?.valid || importing.value) return
  importing.value = true
  try {
    const endpoint = validation.type === 'v1' ? '/config/import/v1' : '/config/import'
    const res = await request.post<{ message?: string }>(endpoint, importFileContent.value, {
      headers: { 'Content-Type': 'application/json' },
    })
    importDialogVisible.value = false
    ElMessage.success({ message: `${res.message || '配置导入成功'}，正在刷新…`, duration: 800 })
    setTimeout(() => window.location.reload(), 800)
  } finally {
    importing.value = false
  }
}

interface BasicSettingsConfig {
  log_level: string
  cert_job_log_size_mb: number
  runtime_log_size_mb: number
  audit_retention_months: number
  jwt_expire_minutes: number
  timezone: string
}

interface ConfigPreviewResponse {
  data?: {
    changed: boolean
    section: string
    changes: string[]
  }
}

interface AdminTlsCertInfo {
  domain: string
  issuer: string
  not_after: string
  days_left: number
}

interface AdminTlsForm {
  mode: string
  certFile: File | null
  keyFile: File | null
  certInfo: AdminTlsCertInfo | null
  inspecting: boolean
}

const settings = defineModel<BasicSettingsConfig>('settings', { required: true })
const emit = defineEmits<{
  (e: 'save'): void
}>()

const saving = ref(false)

const adminTls = ref({ enabled: false, mode: 'selfsigned' })
const adminTlsForm = ref<AdminTlsForm>({ mode: 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false })
const adminTlsDialogVisible = ref(false)
const adminTlsSaving = ref(false)

const loadAdminTls = async () => {
  try {
    const res = await request.get('/admin-tls')
    if (res.data) {
      adminTls.value = { enabled: res.data.enabled, mode: res.data.mode || 'selfsigned' }
    }
  } catch { /* ignore */ }
}

const openAdminTlsDialog = () => {
  adminTlsForm.value = { mode: adminTls.value.mode === 'upload' ? 'upload' : 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false }
  adminTlsDialogVisible.value = true
}

const onAdminTlsDialogClose = () => {
  tlsInspectSeq++
  adminTlsForm.value = { mode: 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false }
  loadAdminTls()
}

const onAdminTlsToggle = async (val: string | number | boolean) => {
  if (!val) {
    try {
      await request.put('/admin-tls', formDataOf({ enabled: 'false' }))
      notifyTlsRestarting(false)
    } catch {
      adminTls.value.enabled = true
    }
    return
  }
  openAdminTlsDialog()
}

const formDataOf = (fields: Record<string, string>): FormData => {
  const fd = new FormData()
  for (const [k, v] of Object.entries(fields)) fd.append(k, v)
  return fd
}

let tlsInspectSeq = 0
let tlsProtocolRedirectTimer: ReturnType<typeof setTimeout> | null = null
let tlsProtocolFallbackTimer: ReturnType<typeof setTimeout> | null = null
let disposed = false

const onTlsFile = async (e: Event, kind: 'cert' | 'key') => {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (kind === 'cert') adminTlsForm.value.certFile = file
  else adminTlsForm.value.keyFile = file
  adminTlsForm.value.certInfo = null
  if (adminTlsForm.value.certFile && adminTlsForm.value.keyFile) {
    const seq = ++tlsInspectSeq
    adminTlsForm.value.inspecting = true
    try {
      const fd = new FormData()
      fd.append('cert_file', adminTlsForm.value.certFile)
      fd.append('key_file', adminTlsForm.value.keyFile)
      const res = await request.post<{ data?: AdminTlsCertInfo }>('/admin-tls/inspect', fd)
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.certInfo = res.data ?? null
      }
    } catch {
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.certInfo = null
      }
    } finally {
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.inspecting = false
      }
    }
  }
}

const notifyTlsRestarting = (toHttps: boolean) => {
  ElMessageBox.alert(`已保存，服务正在自动重启，即将跳转到 ${toHttps ? 'HTTPS' : 'HTTP'} 地址（从节点同步后将自动重启生效）。`, '正在重启', {
    confirmButtonText: '知道了',
    type: 'success',
    showClose: false,
    closeOnClickModal: false,
    closeOnPressEscape: false,
  }).catch(() => {})
  const target = `${toHttps ? 'https' : 'http'}://${location.host}/`
  if (tlsProtocolRedirectTimer) clearTimeout(tlsProtocolRedirectTimer)
  if (tlsProtocolFallbackTimer) clearTimeout(tlsProtocolFallbackTimer)
  tlsProtocolRedirectTimer = setTimeout(() => {
    if (!disposed) window.location.replace(target)
  }, 1500)
  tlsProtocolFallbackTimer = setTimeout(() => {
    if (!disposed) ElMessage.warning(`若未自动跳转请手动访问新地址：${target}`)
  }, 15000)
}

const saveAdminTls = async () => {
  adminTlsSaving.value = true
  try {
    const fd = formDataOf({ enabled: 'true', mode: adminTlsForm.value.mode })
    if (adminTlsForm.value.mode === 'upload') {
      const { certFile, keyFile } = adminTlsForm.value
      if (!certFile || !keyFile) return
      fd.append('cert_file', certFile)
      fd.append('key_file', keyFile)
    }
    await request.put('/admin-tls', fd)
    adminTlsDialogVisible.value = false
    notifyTlsRestarting(true)
  } finally {
    adminTlsSaving.value = false
  }
}

loadAdminTls()
const restarting = ref(false)

const handleRestart = async () => {
  if (isReadOnly.value || restarting.value) return
  await ElMessageBox.confirm('重启期间服务短暂不可用（约 10 秒），容器将自动拉起。确认重启？', '重启服务', {
    confirmButtonText: '重启',
    cancelButtonText: '取消',
    type: 'warning',
  })
  restarting.value = true
  try {
    await request.post('/system/restart')
    ElMessage.success('服务正在重启，稍后自动刷新页面')
    setTimeout(() => window.location.reload(), 10000)
  } finally {
    restarting.value = false
  }
}

const handleSave = async () => {
  if (isReadOnly.value) return
  if (saving.value) return
  saving.value = true
  try {
    const payload = {
      log_level: settings.value.log_level,
      cert_job_log_size_mb: settings.value.cert_job_log_size_mb,
      runtime_log_size_mb: settings.value.runtime_log_size_mb,
      audit_retention_months: settings.value.audit_retention_months,
      jwt_expire_minutes: settings.value.jwt_expire_minutes,
      timezone: settings.value.timezone,
      source: 'basic',
    }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    if (preview.data?.changed) {
      const changes = preview.data.changes.length > 0 ? preview.data.changes.join('；') : '检测到配置变更'
      await ElMessageBox.confirm(changes, `确认保存${preview.data.section || '基础设置'}？`, {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
      })
    }
    await request.put('/config', payload)
    ElMessage.success('保存成功')
    emit('save')
  } catch (error) {
    console.error('Failed to save basic settings:', error)
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.basic-stack { display: flex; flex-direction: column; gap: 20px; }
.card-header { display: flex; align-items: center; }
.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}
.settings-form { padding: 4px 0; }
.compact-select { width: 240px; max-width: 100%; }
.tip-inline { margin-left: 8px; line-height: 1.5; }
.info-list { padding: 4px 0; }
.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid var(--border-lighter);
}
.info-item:last-child { border-bottom: none; }
.info-label { color: var(--text-secondary); font-size: 13px; }
.btn-text { margin-left: 4px; }
.backup-actions { display: flex; align-items: center; gap: 8px; }
.import-input { display: none; }
.backup-tip { display: block; margin-top: 8px; line-height: 1.5; }
.log-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.log-viewer { height: 60vh; min-height: 320px; overflow: auto; padding: 12px 16px; background: #0f172a; border-radius: var(--radius-sm, 6px); }
.log-viewer pre { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.7; color: #e2e8f0; white-space: pre-wrap; word-break: break-all; }
.import-picker { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.import-filename { font-size: 13px; color: var(--el-text-color-primary); }
.import-hint { font-size: 12px; color: var(--el-text-color-secondary); }
.import-validating { padding: 24px 0; text-align: center; color: var(--el-text-color-secondary); font-size: 13px; }
.import-result { display: flex; flex-direction: column; gap: 12px; }
.import-summary { display: flex; flex-wrap: wrap; gap: 8px 16px; font-size: 13px; color: var(--el-text-color-primary); }
.import-warnings { margin: 0; padding-left: 18px; font-size: 12px; color: var(--el-text-color-secondary); line-height: 1.8; }
.import-alert { margin-top: 4px; }
</style>
