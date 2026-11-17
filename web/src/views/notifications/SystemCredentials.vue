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
      <el-form-item :label="t('app.notification.creds.qqAppId')">
        <el-input v-model="form.qqAppId" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.qqSecret')">
        <el-input
          v-model="form.qqSecret"
          type="password"
          show-password
          :placeholder="t('app.notification.creds.secretPlaceholder')"
          class="creds-input"
          autocomplete="new-password"
        />
        <el-tag :type="qqSecretConfigured ? 'success' : 'info'" size="small" effect="plain" class="cred-state-tag">
          {{ qqSecretConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
        </el-tag>
      </el-form-item>

      <el-divider content-position="left" class="creds-divider">{{ t('app.notification.creds.wxSection') }}</el-divider>
      <el-form-item :label="t('app.notification.creds.wxCred')">
        <el-input v-model="form.wxCred" type="password" show-password :placeholder="t('app.notification.creds.secretPlaceholder')" class="creds-input" autocomplete="new-password" />
        <el-tag :type="wxCredConfigured ? 'success' : 'info'" size="small" effect="plain" class="cred-state-tag">
          {{ wxCredConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
        </el-tag>
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
  qqSecret: '',
  wxCred: '',
  mcpEnabled: false,
})
// 服务端已配置布尔（GET 只回布尔不回明文），保存成功后重查刷新
const smtpPassConfigured = ref(false)
const qqSecretConfigured = ref(false)
const wxCredConfigured = ref(false)
let settingsRequestSeq = 0

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
      qqSecret: '',
      wxCred: '',
      mcpEnabled: data?.mcp_enabled === true,
    }
    smtpPassConfigured.value = data?.smtp?.pass_configured === true
    qqSecretConfigured.value = data?.qq?.secret_configured === true
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
      qq: {
        appid: form.value.qqAppId,
        ...(form.value.qqSecret ? { secret: form.value.qqSecret } : {}),
      },
      ...(form.value.wxCred ? { wx: { cred: form.value.wxCred } } : {}),
      mcp_enabled: form.value.mcpEnabled,
    }
    await request.put('/notification/settings', payload)
    mfaAwareSuccess(t('app.notification.creds.saved'))
    form.value = { ...form.value, smtpPass: '', qqSecret: '', wxCred: '' }
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
.creds-divider { margin-top: 8px; }
.creds-input { max-width: 420px; }
.creds-port { max-width: 160px; }
.cred-state-tag { margin-left: 10px; }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
</style>
