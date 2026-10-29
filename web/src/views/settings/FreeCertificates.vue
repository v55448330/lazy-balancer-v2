<template>
  <div>
    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>证书配置数据加载失败：证书配置/DNS 提供商/CA 提供商列表可能为空（非真实状态）</span>
          <el-button link type="danger" @click="retryLoad">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Setting /></el-icon>
            <span>ACME 全局设置</span>
          </div>
        </div>
      </template>
      <el-form :model="global" label-width="140px" :disabled="isReadOnly || savingGlobal">
        <el-form-item label="ACME 邮箱" required>
          <el-input v-model="global.acme_email" placeholder="your@email.com" style="width: 240px;" />
          <span class="form-tip-inline">用于 CA 账户注册，使用 ACME 签发时必须填写</span>
        </el-form-item>
        <el-form-item label="过期提醒天数">
          <el-input-number v-model="global.cert_expiry_days" :min="1" :max="365" />
          <span class="form-tip-inline">证书剩余天数少于该值时标记为「即将过期」，并在证书列表与告警中提醒。</span>
        </el-form-item>
        <el-form-item label="自动续签时间">
          <el-input-number v-model="global.cert_renewal_days" :min="1" :max="CERT_RENEWAL_DAYS_MAX" />
          <span
            class="form-tip-inline"
            title="选择 84–88 天（超过证书寿命 − 7 天）时，系统按证书实际寿命把窗口收敛为到期前 7 天再续签，并对该规则每小时留一条告警（库值保持原样）。0 = 默认 30 天，仅 API 直写/备份导入可达，本控件下限为 1。"
          >到期前多少天开始自动续签，建议不超过 60 天（上限 {{ CERT_RENEWAL_DAYS_MAX }} 天）；到期前 7 天内必定续签。</span>
        </el-form-item>
        <el-form-item label="续签重试次数">
          <el-input-number v-model="global.cert_renewal_attempts" :min="1" :max="10" />
          <span class="form-tip-inline">证书续签失败（包括 CA 频率限制）后的最大自动重试次数</span>
        </el-form-item>
        <el-form-item label="CA 提供商" required>
          <el-select v-model="global.default_ca_provider_id" style="width: 240px;" placeholder="请选择 CA 提供商">
            <!-- 选项=启用 ∪ 当前值（已禁用项仅回显、置 disabled 不可新选——
                 原口径下存量指向已禁用 CA 时显示裸数字 id 但校验照过，自相矛盾） -->
            <el-option v-for="p in defaultCAProviderOptions" :key="p.id" :label="referencedOptionLabel(p)" :value="p.id" :disabled="!p.enabled" />
          </el-select>
          <span class="form-tip-inline">系统默认使用的证书签发机构</span>
        </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingGlobal" :disabled="isReadOnly || !props.configLoaded" @click="handleSave">
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
            <el-button link type="primary" size="small" :loading="testingCAId === row.id" :disabled="isReadOnly || isTesting" @click="testCAProvider(row as CAProvider)">测试</el-button>
            <el-button link type="primary" size="small" :disabled="isReadOnly || savingCA" @click="openCAProviderDialog(row as CAProvider)">编辑</el-button>
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
          <el-button type="primary" size="small" :disabled="isReadOnly || savingConfig" @click="openConfigDialog()">
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
            <el-button link type="primary" size="small" :loading="testingId === row.id" :disabled="isReadOnly || isTesting" @click="testConfig(row as CertConfig)">测试</el-button>
            <el-button link type="primary" size="small" :disabled="isReadOnly || savingConfig" @click="openConfigDialog(row as CertConfig)">编辑</el-button>
            <el-button link type="danger" size="small" :loading="deletingId === row.id" :disabled="isReadOnly || deletingId !== null" @click="deleteConfig(row as CertConfig)">删除</el-button>
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
      width="min(560px, 92vw)"
      :close-on-click-modal="false"
      :before-close="beforeConfigDialogClose"
      class="dns-config-dialog"
      top="6vh"
    >
      <template #header>
        <DialogHeader :icon="Connection" :title="editingId ? '编辑 DNS 提供商配置' : '添加 DNS 提供商配置'" tone="success"
          subtitle="ACME DNS-01 验证使用的解析商凭证，保存后可测试连通性" />
      </template>
      <el-form :model="form" label-width="120px" class="lb-form" :disabled="savingConfig">
        <el-form-item label="配置名称" required>
          <el-input v-model="form.name" placeholder="例如：我的证书配置" maxlength="100" />
        </el-form-item>
        <el-form-item label="DNS 提供商" required>
          <el-select v-model="form.dns_provider" style="width: 100%" @change="onProviderChange">
            <el-option v-for="p in providers" :key="p.code" :label="p.name" :value="p.code" />
          </el-select>
          <div class="form-tip-line">DNS-01 验证时向该提供商写入/清理 TXT 记录</div>
        </el-form-item>
        <template v-if="selectedProvider">
          <el-divider content-position="left" class="section-divider">认证凭证</el-divider>
          <template v-for="field in selectedProvider.credential_fields" :key="field.name">
            <el-form-item :label="field.label" v-if="shouldShowField(field)">
              <el-select
                v-if="field.type === 'select'"
                v-model="form.dns_credentials[field.name]"
                style="width: 100%"
                @change="onCredentialFieldChange"
              >
                <el-option
                  v-for="opt in field.options"
                  :key="opt"
                  :label="credentialOptionLabel(field, opt)"
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
          <div class="form-tip-line">切换认证方式会清除另一认证方式的已保存凭证，需重新填写</div>
        </template>
        <el-divider content-position="left" class="section-divider">状态</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
          <span class="form-tip-inline">停用后签发/续签不再使用该配置</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="savingConfig" @click="closeConfigDialog">取消</el-button>
        <el-button type="primary" :loading="savingConfig" :disabled="savingConfig" @click="saveConfig">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="caDialogVisible" width="min(560px, 92vw)" :close-on-click-modal="false" :before-close="beforeCADialogClose" class="ca-config-dialog" top="6vh">
      <template #header>
        <DialogHeader :icon="Postcard" title="编辑 CA 提供商" subtitle="证书签发机构对接参数：并发 / 间隔与 EAB 凭证（ZeroSSL）" tone="warning" />
      </template>
      <el-form :model="caForm" label-width="120px" :disabled="savingCA" class="lb-form">
        <el-form-item label="名称">
          <el-input v-model="caForm.name" disabled />
        </el-form-item>
        <el-form-item label="类型">
          <el-input v-model="caForm.provider" disabled />
        </el-form-item>
        <el-form-item label="Directory URL">
          <el-input v-model="caForm.directory_url" disabled />
          <div class="form-tip-line">官方固定地址，不可修改</div>
        </el-form-item>
        <el-divider content-position="left" class="section-divider">签发速率</el-divider>
        <el-form-item label="最大并发">
          <el-input-number v-model="caForm.max_concurrent" :min="1" :max="100" />
          <span class="form-tip-inline">同时进行的签发任务数</span>
        </el-form-item>
        <el-form-item label="最小间隔">
          <el-input-number v-model="caForm.min_interval_ms" :min="1" :max="60000" :step="1000" />
          <span class="form-tip-inline">两次新签发之间的最小间隔（毫秒）</span>
        </el-form-item>
        <template v-if="caForm.provider === 'zerossl'">
          <el-divider content-position="left" class="section-divider">EAB 凭证（ZeroSSL）</el-divider>
          <el-form-item label="EAB KID">
            <el-input v-model="caCreds.eab_kid" placeholder="留空则自动获取" />
            <div class="form-tip-line">
              可选，留空时会在测试或签发时自动从 ZeroSSL API 获取；也可手动填写（见
              <el-link type="primary" href="https://app.zerossl.com/developer" target="_blank" rel="noopener noreferrer">ZeroSSL Developer</el-link>
              ）
            </div>
          </el-form-item>
          <el-form-item label="EAB HMAC Key">
            <el-input v-model="caCreds.eab_hmac_key" type="password" placeholder="留空则自动获取" show-password />
          </el-form-item>
        </template>
        <el-divider content-position="left" class="section-divider">状态</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="caForm.enabled" />
          <span class="form-tip-inline">停用后新签发任务不再使用该 CA</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="savingCA" @click="closeCADialog">取消</el-button>
        <el-button type="primary" :loading="savingCA" :disabled="savingCA" @click="saveCAProvider">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="dnsVerifyVisible" width="min(560px, 92vw)" class="dialog-body-inset" :close-on-click-modal="false" @closed="onDnsVerifyClosed">
      <template #header>
        <DialogHeader :icon="Connection" title="验证 DNS 凭证" :subtitle="dnsVerifySubtitle" tone="warning" />
      </template>
      <el-form label-width="90px" @submit.prevent="confirmDnsVerify">
        <el-form-item label="管理域名" :error="dnsVerifyError">
          <el-input v-model="dnsVerifyDomain" placeholder="example.com" autofocus clearable @keyup.enter="confirmDnsVerify" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dnsVerifyVisible = false">取消</el-button>
        <el-button type="primary" @click="confirmDnsVerify">{{ dnsVerifyIsSave ? '验证并保存' : '验证' }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, reactive } from 'vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Check, Connection, Document, OfficeBuilding, Plus, Postcard, Setting } from '@element-plus/icons-vue'
import CertJobs from './CertJobs.vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { applyCredentialFieldChange, credentialFieldVisible, credentialOptionLabel, defaultCredentialsFor, type CredentialFieldMeta } from '@/utils/dnsProviderFields'
import { dnsConfigNeedsChallenge, type DnsConfigBaseline } from '@/utils/dnsConfigChallenge'
import { selectableReferencedOptions, referencedOptionLabel } from '@/utils/caProviderOptions'
import { acmeGlobalWritePayload, CERT_RENEWAL_DAYS_MAX } from '@/utils/configValues'
import type { APIResponse } from '@/types'

// 字段可见性/选项文案由后端元数据驱动（visible_when/option_labels），
// 不再按 dnspod 的两种认证模式在前端硬编码字段名。
type CredentialField = CredentialFieldMeta

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
// 父级 /config 加载完成前禁止保存——表单此刻仍是默认值，补填
// 邮箱后保存会把 30/30/5/dnspod 等默认续签参数静默覆盖已定制值。
// 与 BasicSettings/CaddyGlobalSettings 同一 configLoaded 契约。
const props = defineProps<{
  configLoaded: boolean
  /** 父级在保存成功后回填 /config；必须 await 完成再解冻表单。 */
  onSave?: () => void | Promise<void>
}>()
const emit = defineEmits<{
  (e: 'save'): void
}>()

// 两个独立表单的保存态：原共用一个 saving——任一保存
// 期间另一表单的按钮/弹框被连带禁用。CA 提供商历来独立（savingCA）。
const savingGlobal = ref(false)
const savingConfig = ref(false)
const configs = ref<CertConfig[]>([])
const providers = ref<DNSProvider[]>([])
// 证书配置/DNS 提供商/CA 提供商加载失败显性化（原仅 console，
// 空列表与真实无数据不可区分）——聚合为单条横幅 + 重试。
const configsError = ref(false)
const providersError = ref(false)
const caProvidersError = ref(false)
const loadError = computed(() => configsError.value || providersError.value || caProvidersError.value)
const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
// 存量遗留配置的凭据列为空（NULL/''，导入保留的「尚未配置」形态）。
// 这类配置在用户未编辑任何凭证字段时，保存载荷省略 dns_credentials——否则
// 后端会把表单形态的空对象当作新提交的凭证校验，改名/禁用被旧空值阻断。
const legacyEmptyCredentials = ref(false)
// 打开弹框时的库内快照：保存前的真实 DNS 挑战只对「需要重新验证」的变更执行
// （新建/提供商变更/凭证变更/禁用→启用）。仅改名或仅禁用不得再向 DNS 账户写
// 临时记录——凭证已失效时那一步会变成永远保存不了的死路。
const configBaseline = ref<DnsConfigBaseline | null>(null)
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
// 表单副本不再携带 credentials——凭证经 caCreds（EAB 键对）单独编辑，
// 保存载荷按 provider 计算；原 `credentials: '{}'` 全文件零读取，误导读者以为
// 表单凭证来源。（CAProvider.credentials 仍用于列表行解析，保留。）
// id 同属死字段（Object.assign 不含、保存走 editingCAProvider.id）——一并剔除。
const caForm = reactive<Omit<CAProvider, 'credentials' | 'id'>>({
  name: '',
  provider: 'zerossl',
  directory_url: '',
  max_concurrent: 1,
  min_interval_ms: 10000,
  enabled: true,
})
const caCreds = reactive<CAProviderCredentials>({
  eab_kid: '',
  eab_hmac_key: '',
})

const defaultCAProviderOptions = computed(() => selectableReferencedOptions(caProviders.value, global.value.default_ca_provider_id))

const selectedProvider = computed(() => providers.value.find(p => p.code === form.value.dns_provider))

// 可见性完全由后端元数据（visible_when）决定——新增 provider 的字段
// 不会被隐藏，也不再依赖 dnspod 的字段名。
const shouldShowField = (field: CredentialField) => credentialFieldVisible(field, form.value.dns_credentials)

const onProviderChange = () => {
  form.value.dns_credentials = defaultCredentialsFor(selectedProvider.value?.credential_fields ?? [])
}

// 选择类字段变更后只清理被 visible_when 隐藏的键（不同模式的字段集互斥，隐藏值
// 保留会以不可见字段的形式随保存载荷提交），其它 select 与文本字段的值保留。
const onCredentialFieldChange = () => {
  form.value.dns_credentials = applyCredentialFieldChange(
    selectedProvider.value?.credential_fields ?? [],
    form.value.dns_credentials,
  )
}

const fetchConfigs = async () => {
  try {
    const res = await request.get<APIResponse<CertConfig[]>>('/certificate-configs')
    configs.value = res.data || []
    configsError.value = false
  } catch (error) {
    console.error('Failed to fetch cert configs:', error)
    configsError.value = true
  }
}

const fetchProviders = async () => {
  try {
    const res = await request.get<APIResponse<DNSProvider[]>>('/dns-providers')
    providers.value = res.data || []
    providersError.value = false
  } catch (error) {
    console.error('Failed to fetch DNS providers:', error)
    providersError.value = true
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
    caProvidersError.value = false
  } catch (caught: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to fetch CA providers:', caught)
    caProvidersError.value = true
  } finally {
    loadingCAProviders.value = false
  }
}

// 重试所有失败来源（成功来源重复拉取无副作用）
const retryLoad = (): void => {
  if (configsError.value) void fetchConfigs()
  if (providersError.value) void fetchProviders()
  if (caProvidersError.value) void fetchCAProviders()
}

const openCAProviderDialog = (p: CAProvider) => {
  if (isReadOnly.value || savingCA.value) return
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

// CA 提供商凭证能力（后端 caproviders.go 的两种 provider）：letsencrypt
// 不接受凭证（非空即 400）、zerossl 用 EAB。新增/导入出未知 provider 时
// 返回 null 由保存侧报错，绝不静默写 '{}' 清空凭证。
const caProviderCredentialsPayload = (provider: string): string | null => {
  if (provider === 'zerossl') return stringifyCACredentials(caCreds)
  if (provider === 'letsencrypt') return '{}'
  return null
}

const saveCAProvider = async () => {
  // 写动作函数级守卫（弹框打开期间角色/节点模式可能变化）
  if (isReadOnly.value || savingCA.value) return
  const credentials = caProviderCredentialsPayload(caForm.provider)
  if (credentials === null) {
    ElMessage.error(`未知的 CA 提供商「${caForm.provider}」——无法生成凭证载荷，请刷新页面后重试`)
    return
  }

  try {
    await ElMessageBox.confirm(`将保存 CA 提供商「${caForm.name}」的配置修改，是否继续？`, '确认保存', {
      type: 'warning', confirmButtonText: '确认保存', cancelButtonText: '取消',
    })
  } catch { return }
  savingCA.value = true
  try {
    const payload: Partial<CAProvider> & { credentials: string } = {
      name: caForm.name,
      provider: caForm.provider,
      directory_url: caForm.directory_url.trim(),
      enabled: caForm.enabled,
      max_concurrent: caForm.max_concurrent,
      min_interval_ms: caForm.min_interval_ms,
      credentials,
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
  // 测试会真实申请 EAB（写 ca_providers.credentials），属写操作；先明确确认再发起。
  if (isReadOnly.value || isTesting.value) return
  const eabNote = p.provider === 'zerossl' ? '，ZeroSSL 可能自动申请并保存 EAB 凭证' : ''
  try {
    await ElMessageBox.confirm(`将对 CA 提供商「${p.name}」发起真实连通性测试${eabNote}。是否继续？`, '测试 CA 提供商', {
      type: 'warning', confirmButtonText: '开始测试', cancelButtonText: '取消',
    })
  } catch { return }
  testingCAId.value = p.id
  try {
    const res = await request.post<APIResponse>(`/ca-providers/${p.id}/test`)
    mfaAwareSuccess(res.message || 'CA 提供商测试通过')
    // 测试可能写入测试前不存在的 ZeroSSL EAB：列表必须刷新，否则随后用陈旧
    // 表单保存会把刚申请到的 EAB 覆盖回空值（后端凭证列虽已按语义比较跳过
    // 未变更的写入，这里仍以最新凭证为编辑基线）。
    await fetchCAProviders()
  } catch (error: unknown) {
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to test CA provider:', error)
  } finally {
    testingCAId.value = null
  }
}

const openConfigDialog = (config?: CertConfig) => {
  if (isReadOnly.value || savingConfig.value) return
  // 依赖未就绪不得进表单：/dns-providers 失败或为空时凭证字段无法派生，
  // 用户填完点保存只会拿到 400（等同让用户白填一屏）。
  if (providersError.value || providers.value.length === 0) {
    ElMessage.warning(providersError.value
      ? 'DNS 提供商列表加载失败，请刷新页面或稍后重试'
      : '暂无可用的 DNS 提供商，无法新建配置')
    return
  }
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
      parsedCreds = { ...rawCreds }
    }
    // 库值原样回填，不按 provider 名或凭证形态推断认证方式：「原始凭证 → 规范
    // 凭证」的唯一实现是后端 dnsprovider.CanonicalCredentials（保存前验证与签发
    // 链共用），缺失 auth_mode 的存量形态由它归一；前端复刻该推断会给新增
    // provider 注入无关键并随保存原样落库。
    // 遗留空凭据（NULL/''）：保存时省略凭证，交由后端按「未提交」处理。
    legacyEmptyCredentials.value = Object.keys(parsedCreds).length === 0
    // 回填后与写路径同跑一次隐藏键清理：历史切换过认证方式的配置可能同时留有
    // 两套互斥凭证，隐藏的一半否则会以不可见字段随保存原样落库并随备份传播。
    // 仅当全部 select 字段都有值时清理——缺 auth_mode 的存量凭证由后端
    // CanonicalCredentials 归一，前端无法判断归属，按空值清理会误删另一套凭证。
    const providerFields = providers.value.find((p) => p.code === config.dns_provider)?.credential_fields ?? []
    const selects = providerFields.filter((f) => f.type === 'select' && (f.options?.length ?? 0) > 0)
    const canPruneHidden = selects.length > 0 && selects.every((f) => (parsedCreds[f.name] ?? '') !== '')
    // 表单初值与挑战基线必须同源：基线用未裁剪的库值、表单用裁剪后的凭证时，
    // 只要库里存在被当前元数据判为隐藏的键（导入/带外写/旧版本遗留，或后端
    // 未来调整 visible_when），键集必然不同 → 仅改名/仅停用也被判「凭证变更」
    // 而强制真实 DNS 挑战。
    const initialCredentials = canPruneHidden ? applyCredentialFieldChange(providerFields, parsedCreds) : { ...parsedCreds }
    form.value = {
      name: config.name,
      dns_provider: config.dns_provider,
      dns_credentials: initialCredentials,
      enabled: config.enabled,
    }
    // 挑战判定基线＝打开弹框时的库值（凭证快照按与表单同一份归一结果取拷贝，
    // 未填过即 null）——与保存时的表单自比会恒等，改名/禁用就再也判不出
    // 「无需验证」；直接快照原样库值则会把不可见的隐藏键算进差异。
    configBaseline.value = {
      dnsProvider: config.dns_provider,
      dnsCredentials: legacyEmptyCredentials.value ? null : { ...initialCredentials },
      enabled: config.enabled,
    }
  } else {
    editingId.value = null
    legacyEmptyCredentials.value = false
    configBaseline.value = null
    form.value = {
      name: '',
      dns_provider: providers.value[0]?.code || 'dnspod',
      // 默认凭证由 provider 的 select 字段首个选项派生（不再写死 auth_mode）
      dns_credentials: defaultCredentialsFor(providers.value[0]?.credential_fields ?? []),
      enabled: true,
    }
  }
  dialogVisible.value = true
}

const beforeConfigDialogClose = (done: () => void): void => {
  if (!savingConfig.value) done()
}

const closeConfigDialog = (): void => {
  if (!savingConfig.value) dialogVisible.value = false
}

const saveConfig = async () => {
  // 写动作函数级守卫
  if (isReadOnly.value || savingConfig.value) return
  const targetId = editingId.value
  // 遗留空凭据且用户未填任何凭证值 → 视为「未提交凭证」：载荷省略该字段，
  // 保存前测试也无需执行（没有凭证可测）。后端对省略形态按非凭证更新放行。
  const credentialsUnsubmitted = legacyEmptyCredentials.value
    && !Object.values(form.value.dns_credentials).some(value => String(value ?? '').trim() !== '')
  const payload: {
    name: string
    dns_provider: string
    enabled: boolean
    dns_credentials?: Record<string, string>
  } = {
    name: form.value.name,
    dns_provider: form.value.dns_provider,
    enabled: form.value.enabled,
  }
  if (!credentialsUnsubmitted) {
    payload.dns_credentials = { ...form.value.dns_credentials }
  }
  if (!payload.name || !payload.dns_provider) {
    ElMessage.warning('请填写配置名称和 DNS 提供商')
    return
  }
  try {
    await ElMessageBox.confirm(`将${targetId ? '更新' : '创建'} DNS 提供商配置「${payload.name}」，是否继续？`, '确认保存', {
      type: 'warning', confirmButtonText: '确认保存', cancelButtonText: '取消',
    })
  } catch { return }
  savingConfig.value = true

  // 真实 DNS 挑战只在凭证需要重新验证时执行：新建、提供商变更、凭证变更、
  // 禁用→启用。仅改名/仅禁用/未触碰敏感项直接保存——编辑既有配置的降级操作
  // 不该要求用户再提供一个可管理的域名。
  const needsChallenge = dnsConfigNeedsChallenge(configBaseline.value, {
    dnsProvider: form.value.dns_provider,
    dnsCredentials: form.value.dns_credentials,
    enabled: form.value.enabled,
  })
  if (needsChallenge) {
    const domain = await promptTestDomain(true)
    if (!domain) {
      savingConfig.value = false
      return
    }

    try {
      // 编辑保存前测试：表单凭证含全掩码 ***（非 admin GET 回显、用户未改）时仍测
      // DB 存量（:id/test）；用户实际改过凭证（无 ***）则内联新凭证走无 id 的 /test
      // 当前面板恒 admin JWT（GET 回显明文）且只读用户打不开本弹框，
      // 掩码回传分支在 UI 内不可达——保留作为非 UI 客户端（API Key/只读通道拿到
      // 掩码值直接回传）的防御路径；该分支只验证库中原值，不验证表单改动。
      const hasMaskedCred = Object.values(payload.dns_credentials ?? {}).some(v => v === '***')
      const url = targetId && hasMaskedCred
        ? `/certificate-configs/${targetId}/test`
        : '/certificate-configs/test'
      await request.post(url, { ...payload, domain })
    } catch (caught: unknown) {
      // Error toast is already shown by the global axios interceptor.
      console.error('Failed to verify DNS credentials:', caught)
      savingConfig.value = false
      return
    }
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
    savingConfig.value = false
  }
}

const deleteConfig = async (config: CertConfig) => {
  // savingConfig 在途时不得删除（保存 = test → PUT 两步，删除会让第二步
  // 打向已不存在的 id）；deletingId 防重入照旧。
  if (isReadOnly.value || savingConfig.value || deletingId.value !== null) return
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

const dnsVerifyVisible = ref(false)
const dnsVerifyDomain = ref('')
const dnsVerifyError = ref('')
const dnsVerifyIsSave = ref(false)
let dnsVerifyResolver: ((domain: string | null) => void) | null = null

const dnsVerifySubtitle = computed(() => dnsVerifyIsSave.value
  ? '保存前需验证 DNS 权限。系统将临时写入并删除 _acme-challenge.lb-test TXT 记录'
  : '请输入该 DNS 账户下可管理的域名。系统将临时写入并删除 _acme-challenge.lb-test TXT 记录')

const resolveDnsVerify = (domain: string | null): void => {
  const resolve = dnsVerifyResolver
  dnsVerifyResolver = null
  resolve?.(domain)
}

const onDnsVerifyClosed = (): void => resolveDnsVerify(null)

const confirmDnsVerify = (): void => {
  const domain = dnsVerifyDomain.value.trim()
  if (!domain) {
    dnsVerifyError.value = '请输入域名'
    return
  }
  if (!/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(domain)) {
    dnsVerifyError.value = '域名格式不正确'
    return
  }
  dnsVerifyError.value = ''
  dnsVerifyVisible.value = false
  resolveDnsVerify(domain)
}

const promptTestDomain = (isSave = false): Promise<string | null> => new Promise((resolve) => {
  resolveDnsVerify(null)
  dnsVerifyIsSave.value = isSave
  dnsVerifyDomain.value = ''
  dnsVerifyError.value = ''
  dnsVerifyResolver = resolve
  dnsVerifyVisible.value = true
})

const testConfig = async (config: CertConfig) => {
  // 测试会真实 Present+CleanUp DNS TXT（后端已移出只读豁免），属写操作
  if (isReadOnly.value || isTesting.value || !config.id) return
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
  if (!props.configLoaded) {
    ElMessage.warning('配置尚未加载完成，暂不能保存')
    return
  }
  if (isReadOnly.value) return
  if (savingGlobal.value) return
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
  // CA 提供商列表未就绪时不能把「加载失败/加载中」误报成「不存在」：前者
  // 下拉本就没有选项，用户「重新选择」无从下手，且整卡保存被无故阻断。
  // 前置门按「加载态 → 失败态 → 真不存在」排序。
  if (loadingCAProviders.value) {
    ElMessage.warning('CA 提供商列表加载中，请稍后再保存')
    return
  }
  if (caProvidersError.value) {
    ElMessage.warning('CA 提供商列表加载失败，请点顶部「立即重试」后再保存')
    return
  }
  // 默认 CA 被禁用/删除后，整卡任何保存都会被写侧门拒绝（英文 400）——
  // 前置为可定位的中文提示，避免只改其它字段也无法保存。
  const defaultCA = caProviders.value.find((p) => p.id === global.value.default_ca_provider_id)
  if (!defaultCA) {
    ElMessage.warning('默认 CA 提供商不存在，请重新选择')
    return
  }
  if (!defaultCA.enabled) {
    ElMessage.warning('默认 CA 提供商已被禁用：请先在 CA 提供商列表中启用它，或改选其他 CA')
    return
  }
  savingGlobal.value = true
  try {
    const payload = acmeGlobalWritePayload({
      email: global.value.acme_email,
      expiryDays: global.value.cert_expiry_days,
      renewalDays: global.value.cert_renewal_days,
      renewalAttempts: global.value.cert_renewal_attempts,
      defaultCAProviderId: global.value.default_ca_provider_id,
    })
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    if (preview.data?.changed) {
      const changes = preview.data.changes.length > 0 ? preview.data.changes.join('；') : '检测到配置变更'
      await ElMessageBox.confirm(changes, `确认保存${preview.data.section || 'ACME 设置'}？`, {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
      })
    }
    const saveResp = await request.put('/config', payload)
    const saveMessage = (saveResp as unknown as { message?: string }).message ?? ''
    mfaAwareSuccess(saveMessage.includes('配置无变化') ? saveMessage : '保存成功')
    // 等待父级回填后再由 finally 解冻，避免迟到的 /config 覆盖在途编辑；
    // 未传回调的旧调用方保留事件兜底。
    const parentRefresh = props.onSave
    if (parentRefresh) await parentRefresh()
    if (!parentRefresh) emit('save')
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') {
      console.error('Failed to save certificate settings:', error)
    }
  } finally {
    savingGlobal.value = false
  }
}

onMounted(() => {
  fetchConfigs()
  fetchProviders()
  fetchCAProviders()
})
</script>

<style scoped>
/* .cred-divider 并入.section-divider*/
.section-divider { margin: 24px 0 20px; }
.section-divider :deep(.el-divider__text) { font-size: 14px; color: var(--text-secondary, #6b7280); font-weight: 600; }
.lb-form :deep(.el-form-item) { margin-bottom: 18px; }
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
</style>
