<template>
  <el-card shadow="never" v-loading="loading">
    <template #header>
      <span class="card-title">{{ t('app.notification.creds.smtpSection') }}</span>
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
      <el-form-item :label="t('app.notification.creds.smtpHost')">
        <el-input v-model="form.smtpHost" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpPort')">
        <el-input v-model.number="form.smtpPort" class="creds-port" :placeholder="t('app.notification.creds.portPlaceholder')" />
        <div v-if="portError" class="el-form-item__error">{{ portError }}</div>
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpUser')">
        <el-input v-model="form.smtpUser" class="creds-input" autocomplete="off" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpFrom')">
        <el-input v-model="form.smtpFrom" class="creds-input" />
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpPass')">
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
      <el-form-item>
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveSettings">
          {{ t('app.notification.creds.save') }}
        </el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
// 邮件凭据（SMTP）：通知中心唯一保留的手工凭据面。QQ/微信凭据单源=
// 扫码绑定自动落库（通道向导承载，本页不再展示）；MCP 全局开关归
// MCP 会话卡（API 接入页）。
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
})
// 服务端已配置布尔（GET 只回布尔不回明文），保存成功后重查刷新
const smtpPassConfigured = ref(false)
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
    }
    smtpPassConfigured.value = data?.smtp?.pass_configured === true
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
        port: form.value.smtpPort,
        user: form.value.smtpUser,
        from: form.value.smtpFrom,
        ...(form.value.smtpPass ? { pass: form.value.smtpPass } : {}),
      },
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
.card-title { font-weight: 600; }
.creds-input { max-width: 420px; }
.creds-port { max-width: 160px; }
.cred-state-tag { margin-left: 10px; }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
</style>
