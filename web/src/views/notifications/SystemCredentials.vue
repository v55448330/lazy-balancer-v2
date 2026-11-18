<template>
  <el-card class="list-card" v-loading="loading">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon class="title-icon"><Message /></el-icon>
          <span>{{ t('app.notification.creds.smtpSection') }}</span>
        </div>
        <el-tag :type="smtpPassConfigured ? 'success' : 'info'" size="small">
          {{ smtpPassConfigured ? t('app.notification.creds.configured') : t('app.notification.creds.notConfigured') }}
        </el-tag>
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
      <el-form-item :label="t('app.notification.creds.smtpTestTo')">
        <div class="smtp-test-row">
          <el-input v-model="form.smtpTestTo" class="creds-input" :placeholder="t('app.notification.creds.smtpTestToHint')" />
          <el-button :loading="smtpTesting" :disabled="!form.smtpHost" @click="testSMTP">{{ t('app.notification.creds.smtpTest') }}</el-button>
        </div>
        <div class="form-hint">{{ t('app.notification.creds.smtpTestHint') }}</div>
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
})
// 服务端已配置布尔（GET 只回布尔不回明文），保存成功后重查刷新
const smtpPassConfigured = ref(false)
const smtpTesting = ref(false)
let settingsRequestSeq = 0

// SMTP 连通性测试：test_to 非空=发标记邮件；空=仅握手+AUTH（保存后测试
// 用已落库配置；未保存的草稿 host 不参与——按钮 disabled 条件已拦）
const testSMTP = async (): Promise<void> => {
  if (smtpTesting.value) return
  smtpTesting.value = true
  try {
    const res = await request.post<{ code: number; message?: string }>('/notification/settings/smtp-test',
      { test_to: form.value.smtpTestTo.trim() }, { silent: true })
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
      smtpPort: data?.smtp?.port ?? 0,
      smtpUser: data?.smtp?.user ?? '',
      smtpFrom: data?.smtp?.from ?? '',
      smtpPass: '',
      smtpTestTo: form.value.smtpTestTo,
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
</style>
