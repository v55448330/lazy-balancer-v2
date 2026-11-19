<template>
  <el-card class="list-card" v-loading="loading">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon class="title-icon"><Message /></el-icon>
          <span>{{ t('app.notification.creds.smtpSection') }}</span>
        </div>
      </div>
    </template>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.notification.creds.loadFailed') }}</span>
          <el-button link type="danger" @click="fetchSettings">{{ t('common.app.views.audit.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-form v-if="!loadError" :label-width="$flw('130px')" :disabled="saving" class="creds-form">
      <el-form-item :label="t('app.notification.creds.smtpHost')">
        <el-input v-model="form.smtpHost" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpPort')" :error="portError || undefined">
        <el-input-number v-model="form.smtpPort" :min="0" :max="65535" :controls="false" class="creds-port" :placeholder="t('app.notification.creds.portPlaceholder')" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpUser')">
        <el-input v-model="form.smtpUser" class="creds-input" autocomplete="off" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpFrom')">
        <el-input v-model="form.smtpFrom" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpPass')">
        <div class="creds-pass-row">
          <el-input
            v-model="form.smtpPass"
            type="password"
            show-password
            :placeholder="t('app.notification.creds.secretPlaceholder')"
            class="creds-input"
            autocomplete="new-password"
          />
          <el-tag :type="smtpPassConfigured ? 'success' : 'info'" size="small" effect="plain">
            {{ smtpPassConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
          </el-tag>
        </div>
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpTls')">
        <el-switch v-model="form.smtpTls" />
        <span class="form-hint creds-inline-hint">{{ t('app.notification.creds.smtpTlsHint') }}</span>
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpInsecure')">
        <el-switch v-model="form.smtpInsecure" :disabled="!form.smtpTls" />
        <span class="form-hint creds-inline-hint">{{ t('app.notification.creds.smtpInsecureHint') }}</span>
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpTestTo')">
        <div class="smtp-test-row">
          <el-input v-model="form.smtpTestTo" class="creds-input" :placeholder="t('app.notification.creds.smtpTestToHint')" />
          <el-button size="small" :loading="smtpTesting" :disabled="!form.smtpHost" @click="testSMTP">{{ t('app.notification.creds.smtpTest') }}</el-button>
        </div>
        <div class="form-hint">{{ t('app.notification.creds.smtpTestHint') }}</div>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveSettings">
          {{ t('app.notification.creds.save') }}
        </el-button>
      </el-form-item>

      <el-divider content-position="left">{{ t('app.notification.creds.oauthSection') }}</el-divider>
      <template v-if="oauthConfigured">
        <el-form-item :label="t('app.notification.creds.oauthStatus')">
          <div class="oauth-row">
            <el-tag type="success" size="small">{{ t('app.notification.creds.oauthAuthorized') }}</el-tag>
            <el-button size="small" type="danger" plain :loading="oauthUnbinding" @click="unbindOAuth">{{ t('app.notification.creds.oauthUnbind') }}</el-button>
          </div>
          <div class="form-hint">{{ t('app.notification.creds.oauthAuthorizedHint') }}</div>
        </el-form-item>
      </template>
      <template v-else-if="!deviceFlow.active">
        <el-form-item :label="t('app.notification.creds.oauthTenant')">
          <div class="oauth-row">
            <el-select v-model="oauthForm.tenant" class="creds-port">
              <el-option label="common" value="common" />
              <el-option label="organizations" value="organizations" />
              <el-option label="consumers" value="consumers" />
              <el-option :label="t('app.notification.creds.oauthTenantCustom')" value="__custom__" />
            </el-select>
            <el-input v-if="oauthForm.tenant === '__custom__'" v-model="oauthCustomTenant" class="creds-input oauth-custom" :placeholder="t('app.notification.creds.oauthTenantPlaceholder')" />
          </div>
        </el-form-item>
        <el-form-item :label="t('app.notification.creds.oauthClientId')">
          <el-input v-model="oauthForm.clientId" class="creds-input" :placeholder="t('app.notification.creds.oauthClientIdPlaceholder')" />
          <div class="form-hint">{{ t('app.notification.creds.oauthClientIdHint') }}</div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="oauthStarting" :disabled="!oauthForm.clientId.trim()" @click="startOAuthDevice">{{ t('app.notification.creds.oauthStart') }}</el-button>
          <span class="form-hint creds-inline-hint">{{ t('app.notification.creds.oauthStartHint') }}</span>
        </el-form-item>
      </template>
      <template v-else>
        <el-form-item :label="t('app.notification.creds.oauthUserCode')">
          <div class="oauth-row">
            <span class="oauth-code">{{ deviceFlow.userCode }}</span>
            <el-button size="small" @click="copyUserCode">{{ t('app.notification.creds.oauthCopy') }}</el-button>
          </div>
        </el-form-item>
        <el-form-item :label="t('app.notification.creds.oauthVerify')">
          <a :href="deviceFlow.verificationUri" target="_blank" rel="noopener" class="oauth-link">{{ deviceFlow.verificationUri }}</a>
        </el-form-item>
        <el-form-item :label="t('app.notification.creds.oauthStatus')">
          <div class="oauth-row">
            <span class="form-hint">{{ oauthStatusText }}</span>
            <el-button size="small" @click="cancelOAuthDevice">{{ t('app.notification.creds.oauthCancel') }}</el-button>
          </div>
        </el-form-item>
      </template>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
// 邮件凭据（SMTP）：通知中心唯一保留的手工凭据面。QQ/微信凭据单源=
// 扫码绑定自动落库（通道向导承载，本页不再展示）；MCP 全局开关归
// MCP 会话卡（API 接入页）。
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Message } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import type {
  NotificationSettingsPayload,
  NotificationSettingsResponse,
} from '@/types/notifications.ts'

const { t } = useI18n()

const loading = ref(false)
const loadError = ref(false)
const saving = ref(false)
const portError = ref('')

const form = ref({
  smtpHost: '',
  smtpPort: 0,
  smtpUser: '',
  smtpFrom: '',
  smtpPass: '',
  smtpTestTo: '',
  smtpTls: true,
  smtpInsecure: false,
})
// 服务端已配置布尔（GET 只回布尔不回明文），保存成功后重查刷新
const smtpPassConfigured = ref(false)
const smtpTesting = ref(false)
let settingsRequestSeq = 0

// ── SMTP OAuth2（XOAUTH2，Outlook/Office365 设备码流）──
const oauthConfigured = ref(false)
const oauthForm = ref({ tenant: 'common', clientId: '' })
const oauthCustomTenant = ref('')
const oauthStarting = ref(false)
const oauthUnbinding = ref(false)
const deviceFlow = ref({ active: false, userCode: '', verificationUri: '', status: 'pending', interval: 5, error: '' })
let oauthPollTimer: ReturnType<typeof setTimeout> | null = null

const oauthStatusText = computed(() => {
  const s = deviceFlow.value.status
  if (s === 'error') return deviceFlow.value.error || t('app.notification.creds.oauthError')
  if (s === 'expired') return t('app.notification.creds.oauthExpired')
  if (s === 'completed') return t('app.notification.creds.oauthCompleted')
  return t('app.notification.creds.oauthPending')
})

const effectiveTenant = (): string =>
  oauthForm.value.tenant === '__custom__' ? oauthCustomTenant.value.trim() : oauthForm.value.tenant

const stopOAuthPoll = (): void => {
  if (oauthPollTimer) { clearTimeout(oauthPollTimer); oauthPollTimer = null }
}

const pollOAuthDevice = async (): Promise<void> => {
  try {
    const res = await request.get<{ code: number; data?: { status?: string; interval?: number; error?: string } }>(
      '/notification/settings/smtp-oauth', { silent: true })
    const d = res.data
    const status = d?.status ?? 'error'
    deviceFlow.value.status = status
    deviceFlow.value.error = d?.error ?? ''
    if (status === 'completed') {
      stopOAuthPoll()
      deviceFlow.value.active = false
      oauthConfigured.value = true
      mfaAwareSuccess(t('app.notification.creds.oauthCompleted'))
      await fetchSettings()
      return
    }
    if (status === 'expired' || status === 'error' || status === 'idle') {
      stopOAuthPoll()
      if (status !== 'idle') ElMessage.error(deviceFlow.value.error || t('app.notification.creds.oauthError'))
      deviceFlow.value.active = false
      return
    }
    const interval = (d?.interval ?? deviceFlow.value.interval) + (status === 'slow_down' ? 5 : 0)
    deviceFlow.value.interval = interval
    stopOAuthPoll()
    oauthPollTimer = setTimeout(() => { void pollOAuthDevice() }, interval * 1000)
  } catch {
    stopOAuthPoll()
    deviceFlow.value.active = false
    ElMessage.error(t('app.notification.creds.oauthError'))
  }
}

const startOAuthDevice = async (): Promise<void> => {
  if (oauthStarting.value) return
  oauthStarting.value = true
  try {
    const res = await request.post<{ code: number; message?: string; data?: { user_code?: string; verification_uri?: string; interval?: number } }>(
      '/notification/settings/smtp-oauth',
      { tenant: effectiveTenant(), client_id: oauthForm.value.clientId.trim() }, { silent: true })
    if (res.code !== 0 && res.code !== 200) {
      ElMessage.error(res.message || t('app.notification.creds.oauthError'))
      return
    }
    deviceFlow.value = {
      active: true, userCode: res.data?.user_code ?? '', verificationUri: res.data?.verification_uri ?? '',
      status: 'pending', interval: res.data?.interval ?? 5, error: '',
    }
    stopOAuthPoll()
    oauthPollTimer = setTimeout(() => { void pollOAuthDevice() }, deviceFlow.value.interval * 1000)
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : t('app.notification.creds.oauthError'))
  } finally {
    oauthStarting.value = false
  }
}

const cancelOAuthDevice = (): void => {
  stopOAuthPoll()
  deviceFlow.value.active = false
}

const copyUserCode = async (): Promise<void> => {
  try {
    await navigator.clipboard.writeText(deviceFlow.value.userCode)
    ElMessage.success(t('app.notification.creds.oauthCopied'))
  } catch {
    ElMessage.error(t('app.notification.creds.oauthError'))
  }
}

const unbindOAuth = async (): Promise<void> => {
  if (oauthUnbinding.value) return
  oauthUnbinding.value = true
  try {
    await request.delete('/notification/settings/smtp-oauth')
    mfaAwareSuccess(t('app.notification.creds.oauthUnbound'))
    oauthConfigured.value = false
    await fetchSettings()
  } catch (error: unknown) {
    console.error('Failed to unbind SMTP OAuth:', error)
  } finally {
    oauthUnbinding.value = false
  }
}

// SMTP 连通性测试：发送当前表单草稿（host/port/user/pass/from/tls/insecure），
// 无需先保存即可验证；pass 留空沿用已保存密码。test_to 空=发给自己。
const testSMTP = async (): Promise<void> => {
  if (smtpTesting.value) return
  smtpTesting.value = true
  try {
    const res = await request.post<{ code: number; message?: string }>('/notification/settings/smtp-test',
      {
        test_to: form.value.smtpTestTo.trim(),
        host: form.value.smtpHost.trim(),
        port: form.value.smtpPort ? String(form.value.smtpPort) : '',
        user: form.value.smtpUser,
        pass: form.value.smtpPass,
        from: form.value.smtpFrom,
        tls: form.value.smtpTls,
        insecure: form.value.smtpInsecure,
      }, { silent: true })
    if (res.code === 0 || res.code === 200) {
      mfaAwareSuccess(t('app.notification.creds.smtpTestOk'))
    } else {
      ElMessage.error(res.message || t('app.notification.creds.smtpTestFailed'))
    }
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : t('app.notification.creds.smtpTestFailed'))
  } finally {
    smtpTesting.value = false
  }
}

const portValid = computed(() => {
  const port = form.value.smtpPort
  // 0 = 未配置（占位），1-65535 = 合法
  return port === 0 || (Number.isInteger(port) && port >= 1 && port <= 65535)
})

const canSave = computed(() => portValid.value)

const fetchSettings = async (): Promise<void> => {
  const seq = ++settingsRequestSeq
  loading.value = true
  try {
    const res = await request.get<NotificationSettingsResponse>('/notification/settings')
    if (seq !== settingsRequestSeq) return
    const data = res.data
    form.value = {
      smtpHost: data?.smtp?.host ?? '',
      smtpPort: Number(data?.smtp?.port) || 0,
      smtpUser: data?.smtp?.user ?? '',
      smtpFrom: data?.smtp?.from ?? '',
      smtpPass: '',
      smtpTestTo: form.value.smtpTestTo,
      smtpTls: data?.smtp?.tls !== false,
      smtpInsecure: data?.smtp?.insecure === true,
    }
    smtpPassConfigured.value = data?.smtp?.pass_configured === true
    const oa = data?.smtp_oauth
    oauthConfigured.value = oa?.configured === true
    if (oa?.client_id) oauthForm.value.clientId = oa.client_id
    if (oa?.tenant) {
      if (['common', 'organizations', 'consumers'].includes(oa.tenant)) oauthForm.value.tenant = oa.tenant
      else { oauthForm.value.tenant = '__custom__'; oauthCustomTenant.value = oa.tenant }
    }
    loadError.value = false
  } catch (error: unknown) {
    console.error('Failed to fetch notification settings:', error)
    if (seq === settingsRequestSeq) loadError.value = true
  } finally {
    if (seq === settingsRequestSeq) loading.value = false
  }
}

const saveSettings = async (): Promise<void> => {
  if (saving.value) return
  if (!portValid.value) {
    portError.value = t('app.notification.creds.portInvalid')
    return
  }
  saving.value = true
  try {
    // secret 留空即省略键（不覆盖既有凭据）
    const payload: NotificationSettingsPayload = {
      smtp: {
        host: form.value.smtpHost,
        port: form.value.smtpPort ? String(form.value.smtpPort) : '',
        user: form.value.smtpUser,
        from: form.value.smtpFrom,
        tls: form.value.smtpTls,
        insecure: form.value.smtpInsecure,
        ...(form.value.smtpPass ? { pass: form.value.smtpPass } : {}),
      },
    }
    await request.put('/notification/settings', payload)
    mfaAwareSuccess(t('app.notification.creds.saved'))
    form.value = { ...form.value, smtpPass: '', smtpTestTo: form.value.smtpTestTo }
    await fetchSettings()
  } catch (error: unknown) {
    console.error('Failed to save notification settings:', error)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  void fetchSettings()
})

onUnmounted(() => { stopOAuthPoll() })

defineExpose({ fetchSettings })
</script>

<style scoped>
.el-card { --el-card-border-color: #ebeef5; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.creds-form { max-width: 640px; }
.creds-input { width: 100%; max-width: 420px; }
.creds-port { width: 160px; }
.creds-pass-row { display: flex; align-items: center; gap: 10px; width: 100%; }
.smtp-test-row { display: flex; gap: 8px; width: 100%; align-items: center; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; line-height: 1.5; }
.creds-inline-hint { margin-top: 0; margin-left: 12px; }
.oauth-row { display: flex; align-items: center; gap: 10px; width: 100%; flex-wrap: wrap; }
.oauth-custom { max-width: 240px; }
.oauth-code { font-family: monospace; font-size: 18px; font-weight: 600; letter-spacing: 2px; color: #111827; }
.oauth-link { color: #3b82f6; font-size: 13px; word-break: break-all; }
</style>
