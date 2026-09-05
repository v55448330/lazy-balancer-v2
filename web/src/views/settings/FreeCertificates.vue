<template>
  <div>
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Setting /></el-icon>
            <span>ACME 全局设置</span>
          </div>
        </div>
      </template>
      <el-form :model="global" label-width="140px" :disabled="isReadOnly">
        <el-form-item label="ACME 邮箱" required>
          <el-input v-model="global.acme_email" placeholder="your@email.com" style="width: 240px;" />
          <el-text type="info" size="small" class="tip-inline">用于 CA 账户注册，使用 ACME 签发时必须填写</el-text>
        </el-form-item>
        <el-form-item label="过期提醒天数">
          <el-input-number v-model="global.cert_expiry_days" :min="1" :max="90" />
        </el-form-item>
        <el-form-item label="自动续签时间">
          <el-input-number v-model="global.cert_renewal_days" :min="1" :max="90" />
          <el-text type="info" size="small" class="tip-inline">证书到期前多少天自动尝试重签</el-text>
        </el-form-item>
        <el-form-item label="续签重试次数">
          <el-input-number v-model="global.cert_renewal_attempts" :min="1" :max="10" />
          <el-text type="info" size="small" class="tip-inline">证书续签失败（包括 CA 频率限制）后的最大自动重试次数</el-text>
        </el-form-item>
        <el-form-item label="CA 提供商" required>
          <el-select v-model="global.default_ca_provider_id" style="width: 240px;" placeholder="请选择 CA 提供商">
            <el-option v-for="p in enabledCAProviders" :key="p.id" :label="p.name" :value="p.id" />
          </el-select>
          <el-text type="info" size="small" class="tip-inline">系统默认使用的证书签发机构</el-text>
        </el-form-item>
        <el-form-item label="DNS 提供商">
          <el-select v-model="global.dns_provider" style="width: 240px;" placeholder="请选择 DNS 提供商">
            <el-option label="DNSPod" value="dnspod" />
          </el-select>
          <el-text type="info" size="small" class="tip-inline">全局默认 DNS 提供商，创建规则时默认使用</el-text>
        </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="handleSave">
              <el-icon><Check /></el-icon>
              <span class="btn-text">保存</span>
            </el-button>
          </el-form-item>
      </el-form>
    </el-card>

    <el-card class="settings-card" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><OfficeBuilding /></el-icon>
            <span>CA 提供商</span>
          </div>
        </div>
      </template>
      <el-table v-if="caProviders.length > 0" :data="caProviders" size="small" v-loading="loadingCAProviders">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="provider" label="类型" />
        <el-table-column prop="directory_url" label="Directory URL" show-overflow-tooltip />
        <el-table-column prop="max_concurrent" label="最大并发" width="90" />
        <el-table-column prop="min_interval_ms" label="最小间隔(ms)" width="120" />
        <el-table-column prop="enabled" label="状态" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="140" align="center">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :loading="testingCAId === row.id" :disabled="isReadOnly || isTesting" @click="testCAProvider(row)">测试</el-button>
            <el-button link type="primary" size="small" :disabled="isReadOnly || savingCA" @click="openCAProviderDialog(row)">编辑</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-else description="暂无 CA 提供商" :image-size="60" />
    </el-card>

    <el-card class="settings-card" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Connection /></el-icon>
            <span>DNS 提供商配置</span>
          </div>
          <el-button type="primary" size="small" :disabled="isReadOnly || saving" @click="openConfigDialog()">
            <el-icon><Plus /></el-icon>
            <span class="btn-text">添加</span>
          </el-button>
        </div>
      </template>
      <el-table v-if="configs.length > 0" :data="configs" size="small">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="dns_provider" label="提供商" />
        <el-table-column prop="enabled" label="状态" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" align="center">
          <template #default="{ row }">
            <el-button link type="primary" size="small" :loading="testingId === row.id" :disabled="isReadOnly || isTesting" @click="testConfig(row)">测试</el-button>
            <el-button link type="primary" size="small" :disabled="isReadOnly || saving" @click="openConfigDialog(row)">编辑</el-button>
            <el-button link type="danger" size="small" :loading="deletingId === row.id" :disabled="isReadOnly || deletingId !== null" @click="deleteConfig(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-else description="暂无 DNS 提供商配置" :image-size="60" />
    </el-card>

    <el-card class="settings-card" style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Document /></el-icon>
            <span>签发任务</span>
          </div>
        </div>
      </template>
      <CertJobs />
    </el-card>

    <el-dialog
      v-model="dialogVisible"
      :title="editingId ? '编辑 DNS 提供商配置' : '添加 DNS 提供商配置'"
      width="min(520px, 92vw)"
      :close-on-click-modal="false"
      :before-close="beforeConfigDialogClose"
    >
      <el-form :model="form" label-width="120px">
        <el-form-item label="配置名称" required>
          <el-input v-model="form.name" placeholder="例如：我的证书配置" />
        </el-form-item>
        <el-form-item label="DNS 提供商" required>
          <el-select v-model="form.dns_provider" style="width: 100%" @change="onProviderChange">
            <el-option v-for="p in providers" :key="p.code" :label="p.name" :value="p.code" />
          </el-select>
        </el-form-item>
        <template v-if="selectedProvider">
          <template v-for="field in selectedProvider.credential_fields" :key="field.name">
            <el-form-item :label="field.label" v-if="shouldShowField(field)">
              <el-select
                v-if="field.type === 'select'"
                v-model="form.dns_credentials[field.name]"
                style="width: 100%"
                @change="onAuthModeChange"
              >
                <el-option
                  v-for="opt in field.options"
                  :key="opt"
                  :label="opt === 'dnspod' ? 'DNSPod API' : '腾讯云 API'"
                  :value="opt"
                />
              </el-select>
              <el-input
                v-else
                v-model="form.dns_credentials[field.name]"
                :type="field.type === 'password' ? 'password' : 'text'"
                :placeholder="field.placeholder || ''"
                show-password
              />
            </el-form-item>
          </template>
        </template>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="saving" @click="closeConfigDialog">取消</el-button>
        <el-button type="primary" :loading="saving" :disabled="saving" @click="saveConfig">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="caDialogVisible" title="编辑 CA 提供商" width="min(520px, 92vw)" :before-close="beforeCADialogClose">
      <el-form :model="caForm" label-width="140px" :disabled="savingCA">
        <el-form-item label="名称">
          <el-input v-model="caForm.name" disabled />
        </el-form-item>
        <el-form-item label="类型">
          <el-input v-model="caForm.provider" disabled />
        </el-form-item>
        <el-form-item label="Directory URL">
          <el-input v-model="caForm.directory_url" disabled />
          <el-text type="info" size="small" class="tip-block">Directory URL 为官方固定地址，不可修改</el-text>
        </el-form-item>
        <el-form-item label="最大并发">
          <el-input-number v-model="caForm.max_concurrent" :min="1" :max="100" />
        </el-form-item>
        <el-form-item label="最小间隔(ms)">
          <el-input-number v-model="caForm.min_interval_ms" :min="1000" :max="60000" :step="1000" />
        </el-form-item>
        <template v-if="caForm.provider === 'zerossl'">
          <el-form-item label="EAB KID">
            <el-input v-model="caCreds.eab_kid" placeholder="留空则自动获取" />
            <el-text type="info" size="small" class="tip-block">
              可选，留空时会在测试或签发时自动从 ZeroSSL API 获取；也可手动填写（见
              <a href="https://app.zerossl.com/developer" target="_blank" rel="noopener noreferrer" class="link">ZeroSSL Developer</a>
              ）
            </el-text>
          </el-form-item>
          <el-form-item label="EAB HMAC Key">
            <el-input v-model="caCreds.eab_hmac_key" type="password" placeholder="留空则自动获取" show-password />
          </el-form-item>
        </template>
        <el-form-item label="启用">
          <el-switch v-model="caForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="savingCA" @click="closeCADialog">取消</el-button>
        <el-button type="primary" :loading="savingCA" :disabled="savingCA" @click="saveCAProvider">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, reactive } from 'vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Check, Connection, Document, OfficeBuilding, Plus, Setting } from '@element-plus/icons-vue'
import CertJobs from './CertJobs.vue'
import type { APIResponse } from '@/types'

interface CredentialField {
  name: string
  label: string
  type: string
  required: boolean
  placeholder?: string
  options?: string[]
}

interface DNSProvider {
  code: string
  name: string
  credential_fields: CredentialField[]
}

interface CertConfig {
  id?: number
  name: string
  dns_provider: string
  dns_credentials?: Record<string, string> | string
  enabled: boolean
}

interface CAProvider {
  id: number
  name: string
  provider: string
  directory_url: string
  credentials: string
  max_concurrent: number
  min_interval_ms: number
  enabled: boolean
}

interface CAProviderCredentials {
  eab_kid: string
  eab_hmac_key: string
}

interface GlobalCertificateConfig {
  acme_email: string
  cert_expiry_days: number
  cert_renewal_days: number
  cert_renewal_attempts: number
  default_ca_provider_id: number
  dns_provider: string
}

interface ConfigPreviewResponse {
  data?: {
    changed: boolean
    section: string
    changes: string[]
  }
}

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const global = defineModel<GlobalCertificateConfig>('global', { required: true })
const emit = defineEmits<{
  (e: 'save'): void
}>()

const saving = ref(false)
const configs = ref<CertConfig[]>([])
const providers = ref<DNSProvider[]>([])
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const testingId = ref<number | null>(null)
const deletingId = ref<number | null>(null)
const form = ref<{
  name: string
  dns_provider: string
  dns_credentials: Record<string, string>
  enabled: boolean
}>({
  name: '',
  dns_provider: 'dnspod',
  dns_credentials: {},
  enabled: true,
})

const caProviders = ref<CAProvider[]>([])
const loadingCAProviders = ref(false)
const testingCAId = ref<number | null>(null)
const isTesting = computed(() => testingId.value !== null || testingCAId.value !== null)
const caDialogVisible = ref(false)
const savingCA = ref(false)
const editingCAProvider = ref<CAProvider | null>(null)
const caForm = reactive<CAProvider>({
  id: 0,
  name: '',
  provider: 'zerossl',
  directory_url: '',
  credentials: '{}',
  max_concurrent: 1,
  min_interval_ms: 10000,
  enabled: true,
})
const caCreds = reactive<CAProviderCredentials>({
  eab_kid: '',
  eab_hmac_key: '',
})

const enabledCAProviders = computed(() => caProviders.value.filter(p => p.enabled))

const selectedProvider = computed(() => providers.value.find(p => p.code === form.value.dns_provider))
const authMode = computed(() => form.value.dns_credentials['auth_mode'] || 'dnspod')

const shouldShowField = (field: CredentialField) => {
  if (field.name === 'auth_mode') return true
  if (authMode.value === 'tencent_cloud') {
    return field.name === 'secret_id' || field.name === 'secret_key'
  }
  return field.name === 'app_id' || field.name === 'app_token'
}

const onProviderChange = () => {
  form.value.dns_credentials = { auth_mode: 'dnspod' }
}

const onAuthModeChange = () => {
  const mode = authMode.value
  form.value.dns_credentials = { auth_mode: mode }
}

const fetchConfigs = async () => {
  try {
    const res = await request.get<APIResponse<CertConfig[]>>('/certificate-configs')
    configs.value = res.data || []
  } catch (error) {
    console.error('Failed to fetch cert configs:', error)
  }
}

const fetchProviders = async () => {
  try {
    const res = await request.get<APIResponse<DNSProvider[]>>('/dns-providers')
    providers.value = res.data || []
  } catch (error) {
    console.error('Failed to fetch DNS providers:', error)
  }
}

const parseCACredentials = (raw: string): CAProviderCredentials => {
  if (!raw) return { eab_kid: '', eab_hmac_key: '' }
  try {
    const parsed = JSON.parse(raw)
    return {
      eab_kid: parsed.eab_kid || '',
      eab_hmac_key: parsed.eab_hmac_key || '',
    }
  } catch {
    return { eab_kid: '', eab_hmac_key: '' }
  }
}

const stringifyCACredentials = (creds: CAProviderCredentials): string => {
  return JSON.stringify({
    eab_kid: creds.eab_kid,
    eab_hmac_key: creds.eab_hmac_key,
  })
}

const fetchCAProviders = async () => {
  loadingCAProviders.value = true
  try {
    const res = await request.get<APIResponse<CAProvider[]>>('/ca-providers')
    caProviders.value = res.data || []
  } catch (caught: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to fetch CA providers:', caught)
  } finally {
    loadingCAProviders.value = false
  }
}

const openCAProviderDialog = (p: CAProvider) => {
  if (savingCA.value) return
  editingCAProvider.value = p
  Object.assign(caForm, {
    name: p.name,
    provider: p.provider,
    directory_url: p.directory_url,
    enabled: p.enabled,
    max_concurrent: p.max_concurrent,
    min_interval_ms: p.min_interval_ms,
  })
  const parsed = parseCACredentials(typeof p.credentials === 'string' ? p.credentials : JSON.stringify(p.credentials || {}))
  caCreds.eab_kid = parsed.eab_kid
  caCreds.eab_hmac_key = parsed.eab_hmac_key
  caDialogVisible.value = true
}

const beforeCADialogClose = (done: () => void): void => {
  if (!savingCA.value) done()
}

const closeCADialog = (): void => {
  if (!savingCA.value) caDialogVisible.value = false
}

const saveCAProvider = async () => {
  if (savingCA.value) return

  savingCA.value = true
  try {
    const payload: Partial<CAProvider> & { credentials: string } = {
      name: caForm.name,
      provider: caForm.provider,
      directory_url: caForm.directory_url.trim(),
      enabled: caForm.enabled,
      max_concurrent: caForm.max_concurrent,
      min_interval_ms: caForm.min_interval_ms,
      credentials: caForm.provider === 'zerossl'
        ? stringifyCACredentials(caCreds)
        : '{}',
    }
    const provider = editingCAProvider.value
    if (!provider) return
    await request.put(`/ca-providers/${provider.id}`, payload)
    mfaAwareSuccess('CA 提供商配置已更新')
    caDialogVisible.value = false
    fetchCAProviders()
  } catch (caught: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to save CA provider:', caught)
  } finally {
    savingCA.value = false
  }
}

const testCAProvider = async (p: CAProvider) => {
  if (isTesting.value) return
  testingCAId.value = p.id
  try {
    const res = await request.post<APIResponse>(`/ca-providers/${p.id}/test`)
    mfaAwareSuccess(res.message || 'CA 提供商测试通过')
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to test CA provider:', error)
  } finally {
    testingCAId.value = null
  }
}

const openConfigDialog = (config?: CertConfig) => {
  if (saving.value) return
  if (config) {
    editingId.value = config.id || null
    const rawCreds = config.dns_credentials || {}
    let parsedCreds: Record<string, string> = {}
    if (typeof rawCreds === 'string') {
      try {
        parsedCreds = JSON.parse(rawCreds) || {}
      } catch {
        parsedCreds = {}
      }
    } else {
      parsedCreds = rawCreds
    }
    if (!parsedCreds.auth_mode) {
      if (parsedCreds.secret_id && parsedCreds.secret_key) {
        parsedCreds.auth_mode = 'tencent_cloud'
      } else {
        parsedCreds.auth_mode = 'dnspod'
      }
    }
    form.value = {
      name: config.name,
      dns_provider: config.dns_provider,
      dns_credentials: parsedCreds,
      enabled: config.enabled,
    }
  } else {
    editingId.value = null
    form.value = {
      name: '',
      dns_provider: providers.value[0]?.code || 'dnspod',
      dns_credentials: { auth_mode: 'dnspod' },
      enabled: true,
    }
  }
  dialogVisible.value = true
}

const beforeConfigDialogClose = (done: () => void): void => {
  if (!saving.value) done()
}

const closeConfigDialog = (): void => {
  if (!saving.value) dialogVisible.value = false
}

const saveConfig = async () => {
  if (saving.value) return
  const targetId = editingId.value
  const payload = {
    name: form.value.name,
    dns_provider: form.value.dns_provider,
    dns_credentials: { ...form.value.dns_credentials },
    enabled: form.value.enabled,
  }
  if (!payload.name || !payload.dns_provider) {
    ElMessage.warning('请填写配置名称和 DNS 提供商')
    return
  }
  saving.value = true

  const domain = await promptTestDomain(true)
  if (!domain) {
    saving.value = false
    return
  }

  try {
    const url = targetId
      ? `/certificate-configs/${targetId}/test`
      : '/certificate-configs/test'
    await request.post(url, { ...payload, domain })
  } catch (caught: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to verify DNS credentials:', caught)
    saving.value = false
    return
  }

  try {
    if (targetId) {
      await request.put(`/certificate-configs/${targetId}`, payload)
      mfaAwareSuccess('配置已更新')
    } else {
      await request.post('/certificate-configs', payload)
      mfaAwareSuccess('配置已创建')
    }
    dialogVisible.value = false
    fetchConfigs()
  } catch (caught: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to save cert config:', caught)
  } finally {
    saving.value = false
  }
}

const deleteConfig = async (config: CertConfig) => {
  if (isReadOnly.value || deletingId.value !== null) return
  const configId = config.id
  if (configId === undefined) return
  try {
    await ElMessageBox.confirm(`确定要删除配置 "${config.name}" 吗？`, '删除确认', { type: 'warning' })
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('Failed to confirm cert config deletion:', error)
    return
  }
  if (deletingId.value !== null) return
  deletingId.value = configId
  try {
    await request.delete(`/certificate-configs/${configId}`)
    mfaAwareSuccess('配置已删除')
    fetchConfigs()
  } catch (error: unknown) {
    console.error('Failed to delete cert config:', error)
  } finally {
    if (deletingId.value === configId) deletingId.value = null
  }
}

const promptTestDomain = async (isSave = false): Promise<string | null> => {
  try {
    const { value } = await ElMessageBox.prompt(
      isSave
        ? '保存前需要验证 DNS 凭证。请输入一个该 DNS 账户下可管理的域名（例如 example.com），系统将临时写入并删除 _acme-challenge.lb-test 记录来验证权限'
        : '请输入一个该 DNS 账户下可管理的域名（例如 example.com），系统将临时写入并删除 _acme-challenge.lb-test 记录来验证权限',
      '验证 DNS 凭证',
      {
        confirmButtonText: isSave ? '验证并保存' : '验证',
        cancelButtonText: '取消',
        inputPlaceholder: 'example.com',
        inputValidator: (value) => {
          if (!value) return '请输入域名'
          if (!/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(value.trim())) return '域名格式不正确'
          return true
        },
      }
    )
    return value.trim()
  } catch {
    return null
  }
}

const testConfig = async (config: CertConfig) => {
  if (isTesting.value || !config.id) return
  testingId.value = config.id
  try {
    const domain = await promptTestDomain(false)
    if (!domain) return
    const res = await request.post(`/certificate-configs/${config.id}/test`, { domain })
    mfaAwareSuccess(res.message || '凭证有效')
  } catch (caught: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to test cert config:', caught)
  } finally {
    testingId.value = null
  }
}

const handleSave = async () => {
  if (isReadOnly.value) return
  if (saving.value) return
  if (!global.value.acme_email || !global.value.acme_email.trim()) {
    ElMessage.warning('请填写 ACME 邮箱')
    return
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(global.value.acme_email.trim())) {
    ElMessage.warning('ACME 邮箱格式不正确')
    return
  }
  if (!global.value.default_ca_provider_id) {
    ElMessage.warning('请选择 CA 提供商')
    return
  }
  saving.value = true
  try {
    const payload = {
      // M31：提交侧 trim——避免粘贴带入的首尾空白被原样写入配置并回显扩散
      acme_email: global.value.acme_email.trim(),
      cert_expiry_days: global.value.cert_expiry_days,
      cert_renewal_days: global.value.cert_renewal_days,
      cert_renewal_attempts: global.value.cert_renewal_attempts,
      default_ca_provider_id: global.value.default_ca_provider_id,
      dns_provider: global.value.dns_provider || 'dnspod',
      source: 'acme',
    }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    if (preview.data?.changed) {
      const changes = preview.data.changes.length > 0 ? preview.data.changes.join('；') : '检测到配置变更'
      await ElMessageBox.confirm(changes, `确认保存${preview.data.section || 'ACME 设置'}？`, {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
      })
    }
    await request.put('/config', payload)
    mfaAwareSuccess('保存成功')
    emit('save')
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') {
      console.error('Failed to save certificate settings:', error)
    }
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  fetchConfigs()
  fetchProviders()
  fetchCAProviders()
})
</script>

<style scoped>
.tip-block a.link { color: #3b82f6; text-decoration: none; }
.tip-block a.link:hover { text-decoration: underline; }
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}
.btn-text { margin-left: 4px; }
.tip-inline { margin-left: 8px; line-height: 1.5; }
.tip-block { display: block; margin-top: 4px; line-height: 1.5; }
</style>
