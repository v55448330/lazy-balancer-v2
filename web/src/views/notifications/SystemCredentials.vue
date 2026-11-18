<template>
  <el-card shadow="never" v-loading="loading">
    <template #header>
      <div class="card-header-row">
        <span>{{ t('app.notification.tabs.credentials') }}</span>
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveSettings">
          {{ t('app.notification.creds.save') }}
        </el-button>
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

    <el-form v-if="!loadError" :label-width="$flw('130px')" :disabled="saving">
      <el-divider content-position="left" class="creds-divider">{{ t('app.notification.creds.smtpSection') }}</el-divider>
      <el-form-item :label="t('app.notification.creds.smtpHost')">
        <el-input v-model="form.smtpHost" :placeholder="'smtp.example.com'" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpPort')" :error="portError">
        <el-input v-model.number="form.smtpPort" class="creds-input creds-port" @input="portError = ''" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpUser')">
        <el-input v-model="form.smtpUser" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpFrom')">
        <el-input v-model="form.smtpFrom" :placeholder="'alert@example.com'" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpPassword')">
        <el-input
          v-model="form.smtpPass"
          type="password"
          show-password
          :placeholder="t('app.notification.creds.secretPlaceholder')"
          class="creds-input"
          autocomplete="new-password"
        />
        <el-tag :type="smtpPassConfigured ? 'success' : 'info'" size="small" effect="plain" class="cred-state-tag">
          {{ smtpPassConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
        </el-tag>
      </el-form-item>

      <el-divider content-position="left" class="creds-divider">{{ t('app.notification.creds.qqSection') }}</el-divider>
      <!-- QQ 凭据单源=扫码绑定自动落库（通道向导）；无手工输入入口 -->
      <el-form-item :label="t('app.notification.creds.qqCred')">
        <div class="wx-login-card">
          <div class="wx-login-state-row">
            <el-tag :type="qqCredConfigured ? 'success' : 'info'" size="small" effect="plain">
              {{ qqCredConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
            </el-tag>
            <code v-if="form.qqAppId" class="channel-target">{{ form.qqAppId }}</code>
          </div>
          <div class="wx-login-hint">{{ t('app.notification.creds.qqCredHint') }}</div>
        </div>
      </el-form-item>

      <el-divider content-position="left" class="creds-divider">{{ t('app.notification.creds.wxSection') }}</el-divider>
      <el-form-item :label="t('app.notification.creds.wxCred')">
        <div class="wx-login-card">
          <div class="wx-login-state-row">
            <el-tag :type="wxCredConfigured ? 'success' : 'info'" size="small" effect="plain">
              {{ wxCredConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
            </el-tag>
            <el-button size="small" type="primary" :loading="wxQr.loading" @click="startWxQRLogin">
              {{ wxCredConfigured ? t('app.notification.creds.wxRelogin') : t('app.notification.creds.wxScanLogin') }}
            </el-button>
          </div>
          <div v-if="wxQr.qrImg" class="wx-login-qr-panel">
            <img class="wx-login-qr" :src="wxQr.qrImg" :alt="t('app.notification.creds.wxQrAlt')" />
            <div class="wx-login-hint">{{ wxQrStatusText }}</div>
            <el-button v-if="wxQr.expired" size="small" @click="startWxQRLogin">{{ t('app.notification.creds.wxQrRefresh') }}</el-button>
          </div>
        </div>
      </el-form-item>

      <el-divider content-position="left" class="creds-divider">{{ t('app.notification.creds.mcpSection') }}</el-divider>
      <el-form-item :label="t('app.notification.creds.mcpEnabled')">
        <el-switch v-model="form.mcpEnabled" />
        <span class="switch-hint">{{ t('app.notification.creds.mcpEnabledHint') }}</span>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import QRCode from 'qrcode'
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
  qqAppId: '',
  mcpEnabled: false,
})
// 服务端已配置布尔（GET 只回布尔不回明文），保存成功后重查刷新
const smtpPassConfigured = ref(false)
const qqCredConfigured = ref(false)
const wxCredConfigured = ref(false)
let settingsRequestSeq = 0

// 微信 iLink 扫码登录卡：start 拿二维码 URL（本地 QRCode 渲染）→
// status 长轮询（服务端挂起至状态变化）；confirmed 即凭据已落库、收发启用。
const wxQr = ref<{ qrImg: string; loading: boolean; status: string; expired: boolean; timer: number | null }>({
  qrImg: '', loading: false, status: '', expired: false, timer: null,
})

const wxQrStatusText = computed(() => {
  if (wxQr.value.expired) return t('app.notification.creds.wxQrExpired')
  switch (wxQr.value.status) {
    case 'scaned': return t('app.notification.creds.wxQrScaned')
    case 'confirmed': return t('app.notification.creds.wxQrConfirmed')
    default: return t('app.notification.creds.wxQrWaiting')
  }
})

const startWxQRLogin = async (): Promise<void> => {
  if (wxQr.value.loading) return
  wxQr.value.loading = true
  wxQr.value.expired = false
  wxQr.value.status = ''
  try {
    const res = await request.post<{ code: number; data?: { qr_content: string } }>('/notification/wx/qr/start', {})
    const qrUrl = res.data?.qr_content ?? ''
    wxQr.value.qrImg = qrUrl ? await QRCode.toDataURL(qrUrl, { width: 180, margin: 1 }) : ''
    startWxQRPolling()
  } catch (error: unknown) {
    console.error('Failed to start wx QR login:', error)
  } finally {
    wxQr.value.loading = false
  }
}

const startWxQRPolling = (): void => {
  if (wxQr.value.timer !== null) window.clearInterval(wxQr.value.timer)
  const timer = window.setInterval(async () => {
    try {
      const res = await request.get<{ code: number; data?: { status: string; confirmed: boolean } }>('/notification/wx/qr/status')
      const data = res.data
      wxQr.value.status = data?.status ?? ''
      if (data?.confirmed) {
        wxQr.value.qrImg = ''
        if (wxQr.value.timer !== null) {
          window.clearInterval(wxQr.value.timer)
          wxQr.value.timer = null
        }
        mfaAwareSuccess(t('app.notification.creds.wxQrConfirmed'))
        await fetchSettings()
      } else if (data?.status === 'expired') {
        wxQr.value.expired = true
        if (wxQr.value.timer !== null) {
          window.clearInterval(wxQr.value.timer)
          wxQr.value.timer = null
        }
      }
    } catch {
      // 轮询失败保持等待
    }
  }, 3000)
  wxQr.value.timer = timer
  window.setTimeout(() => {
    if (wxQr.value.timer === timer && wxQr.value.status !== 'confirmed') {
      wxQr.value.expired = true
      window.clearInterval(timer)
      wxQr.value.timer = null
    }
  }, 5 * 60 * 1000)
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
      smtpPort: data?.smtp?.port ?? 0,
      smtpUser: data?.smtp?.user ?? '',
      smtpFrom: data?.smtp?.from ?? '',
      smtpPass: '',
      qqAppId: data?.qq?.appid ?? '',
      mcpEnabled: data?.mcp_enabled === true,
    }
    smtpPassConfigured.value = data?.smtp?.pass_configured === true
    qqCredConfigured.value = data?.qq?.secret_configured === true
    wxCredConfigured.value = data?.wx_bot_cred_configured === true
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
    // TODO(协议-校准): PUT body 契约未定稿（GET 只给了形状）。按 GET 嵌套同形
    // 提交，secret 键名 pass/secret/cred 为拟定值，留空即省略键（不覆盖既有
    // 凭据）；联调与 N4 对齐后修正键名。
    const payload: NotificationSettingsPayload = {
      smtp: {
        host: form.value.smtpHost,
        port: form.value.smtpPort,
        user: form.value.smtpUser,
        from: form.value.smtpFrom,
        ...(form.value.smtpPass ? { pass: form.value.smtpPass } : {}),
      },
      mcp_enabled: form.value.mcpEnabled,
    }
    await request.put('/notification/settings', payload)
    mfaAwareSuccess(t('app.notification.creds.saved'))
    form.value = { ...form.value, smtpPass: '' }
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

defineExpose({ fetchSettings })
</script>

<style scoped>
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
/* 微信扫码登录卡 */
.wx-login-card { display: flex; flex-direction: column; gap: 12px; }
.wx-login-state-row { display: flex; align-items: center; gap: 10px; }
.wx-login-qr-panel { display: flex; flex-direction: column; align-items: center; gap: 8px; }
.wx-login-qr { width: 180px; height: 180px; border-radius: 8px; border: 1px solid var(--el-border-color); }
.wx-login-hint { color: var(--text-secondary, #6b7280); font-size: 13px; }
.creds-divider { margin-top: 8px; }
.creds-input { max-width: 420px; }
.creds-port { max-width: 160px; }
.cred-state-tag { margin-left: 10px; }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
</style>
