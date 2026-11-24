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

    <el-form v-if="!loadError" :label-width="$flw('130px')" :disabled="saving || nodeWriteBlocked" class="creds-form">
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
        <span class="form-tip-inline">{{ t('app.notification.creds.smtpTlsHint') }}</span>
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpInsecure')">
        <el-switch v-model="form.smtpInsecure" :disabled="nodeWriteBlocked || !form.smtpTls" />
        <span class="form-tip-inline">{{ t('app.notification.creds.smtpInsecureHint') }}</span>
      </el-form-item>
      <el-form-item :label="t('app.notification.creds.smtpTestTo')">
        <div class="smtp-test-row">
          <el-input v-model="form.smtpTestTo" class="creds-input" :placeholder="t('app.notification.creds.smtpTestToHint')" />
          <el-button size="small" :loading="smtpTesting" :disabled="!form.smtpHost || nodeWriteBlocked" @click="testSMTP">{{ t('app.notification.creds.smtpTest') }}</el-button>
        </div>
        <div class="form-tip-line">{{ t('app.notification.creds.smtpTestHint') }}</div>
      </el-form-item>
      <el-form-item>
        <el-tooltip :disabled="!nodeWriteBlocked" :content="nodeWriteBlockedReason">
          <div>
            <el-button type="primary" :loading="saving" :disabled="!canSave || nodeWriteBlocked" @click="saveSettings">
              {{ t('app.notification.creds.save') }}
            </el-button>
          </div>
        </el-tooltip>
        <div v-if="smtpDirty && !smtpTestOk" class="form-tip-line">{{ t('app.notification.creds.smtpSaveGateHint') }}</div>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
// 邮件凭据（SMTP）：通知中心唯一保留的手工凭据面。QQ/微信凭据单源=
// 扫码绑定自动落库（通道向导承载，本页不再展示）；MCP 全局开关归
// MCP 会话卡（API 接入页）。
import { computed, ref, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Message } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { createSmtpTestGate, smtpPortError } from '@/utils/smtpTestGate'
import type {
  NotificationSettingsPayload,
  NotificationSettingsResponse,
} from '@/types/notifications.ts'

const { t } = useI18n()

const authStore = useAuthStore()
const loading = ref(false)
const loadError = ref(false)
const saving = ref(false)
// 该页写的是通知设置（PUT /notification/settings），后端只允许主节点写：从节点/
// 节点未知时页面必须先自证不可写，否则用户填满表单、测试通过、保存才 403。
const nodeWriteBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const nodeWriteBlockedReason = computed(() => authStore.isSlaveNode
  ? t('common.app.views.keys.slaveReadOnly')
  : t('common.app.views.keys.nodeUnknownReadOnly'))

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
const smtpTestOk = ref(false) // 当前表单配置已测试通过
const smtpSavedSnapshot = ref('') // 已保存配置快照（不含 pass，GET 不回明文）
const smtpSnapshot = (f: typeof form.value): string => JSON.stringify({
  host: f.smtpHost.trim(), port: f.smtpPort, user: f.smtpUser, from: f.smtpFrom, tls: f.smtpTls, insecure: f.smtpInsecure,
})
// 变动=与已保存配置不同或输入新密码；变动后须重新测试通过才允许保存。
const smtpDirty = computed(() => smtpSnapshot(form.value) !== smtpSavedSnapshot.value || form.value.smtpPass !== '')
watch(form, () => { smtpTestOk.value = false }, { deep: true })
const testGate = createSmtpTestGate() // 最近一次测试发出时的投递配置快照
let settingsRequestSeq = 0

// SMTP 连通性测试：发送当前表单草稿（host/port/user/pass/from/tls/insecure），
// 无需先保存即可验证；pass 留空沿用已保存密码。test_to 空=发给自己。
const testSMTP = async (): Promise<void> => {
  if (smtpTesting.value) return
  smtpTesting.value = true
  try {
    testGate.begin(form.value)
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
      // 在途期间投递配置已变动：结果只证明发出测试时的配置，不得放行保存。
      if (testGate.appliesTo(form.value)) {
        mfaAwareSuccess(t('app.notification.creds.smtpTestOk'))
        smtpTestOk.value = true
      } else {
        ElMessage.warning(t('app.notification.creds.smtpSaveGateHint'))
      }
    } else {
      ElMessage.error(res.message || t('app.notification.creds.smtpTestFailed'))
    }
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : t('app.notification.creds.smtpTestFailed'))
  } finally {
    smtpTesting.value = false
  }
}

const portError = computed(() => smtpPortError(form.value.smtpPort, t('app.notification.creds.portInvalid')))
const portValid = computed(() => portError.value === '')

const canSave = computed(() => portValid.value && (!smtpDirty.value || smtpTestOk.value))

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
    smtpSavedSnapshot.value = smtpSnapshot(form.value)
    smtpTestOk.value = false
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
  saving.value = true
  try {
    // secret 留空即省略键（不覆盖既有凭据）
    const payload: NotificationSettingsPayload = {
      smtp: {
        host: form.value.smtpHost.trim(),
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
</style>
