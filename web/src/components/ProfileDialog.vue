<template>
  <el-dialog
    :model-value="modelValue"
    width="min(520px, 92vw)"
    :close-on-click-modal="false"
    :before-close="beforeClose"
    class="profile-dialog"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
    @opened="handleOpen"
  >
    <template #header>
      <DialogHeader :icon="User" :title="t('common.app.views.profile.title')" :subtitle="isOIDCUser ? t('common.app.views.profile.oidcSubtitle') : t('common.app.views.profile.localSubtitle')" />
    </template>
    <div v-if="isReadOnly" class="info-note-bar profile-readonly-note"><span class="info-note-desc">{{ authStore.readOnlyMessage }}</span></div>
    <el-form :model="profileForm" :label-width="$flw('96px')" class="profile-form" :disabled="saving">
      <el-form-item :label="t('common.app.views.profile.usernameLabel')">
        <el-input v-model="profileForm.username" disabled />
      </el-form-item>
      <template v-if="isOIDCUser">
        <el-form-item :label="t('common.app.views.profile.displayNameLabel')">
          <el-input :model-value="profileForm.display_name" disabled />
        </el-form-item>
        <el-form-item :label="t('common.app.views.profile.authMethodLabel')" for="policy-auth-mode-static">
          <input type="text" id="policy-auth-mode-static" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
          <el-tag type="primary" effect="plain" size="small">{{ t('common.app.views.profile.oidcTag') }}</el-tag>
        </el-form-item>
      </template>
      <template v-else>
        <el-form-item :label="t('common.app.views.profile.displayNameLabel')">
          <el-input v-model="profileForm.display_name" :disabled="isReadOnly" :placeholder="t('common.app.views.profile.optionalPlaceholder')" maxlength="50" />
        </el-form-item>
        <el-form-item :label="t('common.app.views.profile.newPasswordLabel')">
          <el-input v-model="profileForm.password" :disabled="isReadOnly" type="password" minlength="8" maxlength="24" :placeholder="t('common.app.views.profile.newPasswordPlaceholder')" show-password />
        </el-form-item>
        <el-form-item :label="t('common.app.views.profile.confirmPasswordLabel')">
          <el-input v-model="profileForm.passwordConfirm" :disabled="isReadOnly" type="password" minlength="8" maxlength="24" :placeholder="t('common.app.views.profile.confirmPasswordPlaceholder')" show-password />
        </el-form-item>
        <el-form-item :label="t('common.app.views.profile.currentPasswordLabel')">
          <el-input v-model="profileForm.currentPassword" :disabled="isReadOnly" type="password" maxlength="72" :placeholder="profileForm.password ? t('common.app.views.profile.currentPasswordRequired') : t('common.app.views.profile.currentPasswordHint')" show-password />
        </el-form-item>
        <el-form-item :label="t('common.app.views.profile.twoFactorLabel')" for="profile-mfa-static">
          <input type="text" id="profile-mfa-static" aria-hidden="true" tabindex="-1" autocomplete="off" style="display:none">
          <div class="mfa-row">
            <el-tag :type="mfaEnabled ? 'success' : 'info'" size="small" effect="plain">{{ mfaEnabled ? t('common.app.views.profile.mfaOn') : t('common.app.views.profile.mfaOff') }}</el-tag>
            <el-button v-if="!mfaEnabled" size="small" type="primary" plain :disabled="isReadOnly" @click="startEnable">{{ t('common.app.views.profile.enableMfa') }}</el-button>
            <template v-else>
              <el-button size="small" :disabled="isReadOnly" @click="startMfaAction('disable')">{{ t('common.app.views.profile.disableMfa') }}</el-button>
              <el-button size="small" type="warning" plain :disabled="isReadOnly" @click="startMfaAction('reset')">{{ t('common.app.views.profile.resetMfa') }}</el-button>
            </template>
          </div>
          <div class="form-tip-line">{{ t('common.app.views.profile.mfaRowTip') }}</div>
        </el-form-item>
      </template>
    </el-form>
    <div v-if="isOIDCUser" class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.profile.oidcManagedNote') }}</span></div>
    <template #footer>
      <el-button :disabled="saving" @click="closeProfile">{{ t('common.app.views.profile.cancel') }}</el-button>
      <el-button v-if="!isOIDCUser" type="primary" :loading="saving" :disabled="isReadOnly || saving" @click="saveProfile">{{ t('common.app.views.profile.save') }}</el-button>
    </template>
    <!-- 关闭/重置 MFA 前的动态码确认：与全站 MFA 写操作同一验证语义 -->
    <el-dialog
      v-model="mfaCodeDialog"
      append-to-body
      width="min(420px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!mfaSubmitting"
      :show-close="!mfaSubmitting"
    >
      <template #header>
        <DialogHeader :icon="Lock" :title="mfaAction === 'reset' ? t('common.app.views.profile.resetMfa') : t('common.app.views.profile.disableMfa')" />
      </template>
      <div class="form-tip-line">{{ mfaAction === 'reset' ? t('common.app.views.profile.resetConfirmTip') : t('common.app.views.profile.disableConfirmTip') }}</div>
      <el-input
        v-if="!mfaWriteGuard"
        v-model="mfaCode"
        class="mfa-code-field"
        :placeholder="t('common.app.views.profile.currentCodePlaceholder')"
        maxlength="6"
        :aria-label="t('common.app.views.profile.currentCodePlaceholder')"
        @input="mfaCode = sanitizeTotpDigits(mfaCode)"
      />
      <template #footer>
        <el-button :disabled="mfaSubmitting" @click="mfaCodeDialog = false">{{ t('common.app.views.profile.cancel') }}</el-button>
        <el-button type="primary" :loading="mfaSubmitting" :disabled="!mfaWriteGuard && mfaCode.length !== 6" @click="confirmMfaAction">
          {{ mfaAction === 'reset' ? (mfaWriteGuard ? t('common.app.views.profile.confirmReset') : t('common.app.views.profile.verifyAndReset')) : (mfaWriteGuard ? t('common.app.views.profile.confirmDisable') : t('common.app.views.profile.verifyAndDisable')) }}
        </el-button>
      </template>
    </el-dialog>
    <MfaBindingWizard
      :model-value="wizardVisible"
      :secret="pendingSecret"
      :uri="pendingUri"
      :username="authStore.user?.username || ''"
      @activated="onMfaActivated"
      @update:model-value="(v: boolean) => { wizardVisible = v; if (!v) clearPendingSecret() }"
    />
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Lock, User } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import MfaBindingWizard from '@/components/MfaBindingWizard.vue'
import { request, mfaAwareSuccess, ApiRequestError, sanitizeTotpDigits } from '@/utils/api'
import { requireData } from '@/utils/requireData'
import { isCurrentPasswordRejection } from '@/utils/profileUpdate'
import { missingNewPasswordMessage, validatePassword } from '@/utils/credentials'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse } from '@/types'

const { t } = useI18n()
const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const authStore = useAuthStore()
const isOIDCUser = computed(() => authStore.user?.auth_provider === 'oidc')
const isReadOnly = computed(() => authStore.readOnlyReason === 'slave' || authStore.readOnlyReason === 'unknown')
const mfaEnabled = computed(() => authStore.user?.mfa_enabled === true)
const mfaWriteGuard = computed(() => authStore.mfaWriteGuard)
const saving = ref(false)
const profileForm = ref({ username: '', display_name: '', password: '', passwordConfirm: '', currentPassword: '' })
const syncProfileForm = () => {
  profileForm.value = {
    username: authStore.user?.username || '',
    display_name: authStore.user?.display_name || '',
    password: '',
    passwordConfirm: '',
    currentPassword: '',
  }
}
const handleOpen = (): void => {
  syncProfileForm()
}
watch(() => props.modelValue, (visible) => { if (visible) syncProfileForm() })
const beforeClose = (done: () => void): void => {
  // 关闭/重置 MFA 与绑定向导在途期间不得关闭个人资料弹框（向导为嵌套弹框）
  if (!saving.value && !mfaSubmitting.value && !wizardVisible.value) done()
}
const closeProfile = (): void => {
  emit('update:modelValue', false)
}
const saveProfile = async () => {
  if (isReadOnly.value || saving.value) return
  const passwordError = validatePassword(profileForm.value.password)
  if (passwordError) { authStore.showToast('warning', passwordError); return }
  // 「只填确认框、新密码留空」：validatePassword('') = null（留空=不修改），载荷会
  // 省略 password（后端保留原密码）却回报「保存成功」——界面上的假成功。拦截必须
  // 先于「两次不一致」判定，否则该形态被当成不一致话术。
  const missingNewPassword = missingNewPasswordMessage(profileForm.value.password, profileForm.value.passwordConfirm)
  if (missingNewPassword) { authStore.showToast('warning', missingNewPassword); return }
  if (profileForm.value.password && !profileForm.value.currentPassword) { authStore.showToast('warning', t('common.app.views.profile.currentPasswordMissing')); return }
  if (profileForm.value.password && profileForm.value.password !== profileForm.value.passwordConfirm) { authStore.showToast('warning', t('common.app.views.profile.newPasswordMismatch')); return }
  const passwordChanged = Boolean(profileForm.value.password)
  // 占位先于确认：确认框悬挂期按钮已进入在途态，第二击不会再叠一个确认框。
  saving.value = true
  try {
    if (passwordChanged) {
      try {
        await ElMessageBox.confirm(
          t('common.app.views.profile.passwordChangeConfirmMsg'),
          t('common.app.views.profile.passwordChangeConfirmTitle'),
          { type: 'warning', confirmButtonText: t('common.app.views.profile.confirmSave'), cancelButtonText: t('common.app.views.profile.cancel') },
        )
      } catch { return }
    }
    await request.patch('/users/me', {
      display_name: profileForm.value.display_name,
      ...(profileForm.value.password && { password: profileForm.value.password, current_password: profileForm.value.currentPassword }),
    })
    emit('update:modelValue', false)
    if (passwordChanged) {
      authStore.showToast('success', t('common.app.views.profile.passwordChangedRelogin'))
      await authStore.logout()
    } else {
      mfaAwareSuccess(t('common.app.views.profile.saved'))
      await authStore.fetchUser()
    }
  } catch (error: unknown) {
    if (error instanceof ApiRequestError && isCurrentPasswordRejection('patch', '/users/me', error.status, error.message)) {
      authStore.showToast('error', error.message)
    } else {
      console.error('Failed to save profile:', error)
    }
  } finally {
    saving.value = false
  }
}

// ── 两步验证自助（启用 / 关闭 / 重置）──
// 已启用时后端 setup 需当前动态码确认（换绑定验码门），故「重置」= 验码 →
// setup 取新 secret → 绑定向导 → activate（等价换密钥 + 恢复码）。
const wizardVisible = ref(false)
const pendingSecret = ref('')
const pendingUri = ref('')
const mfaCodeDialog = ref(false)
const mfaCode = ref('')
const mfaAction = ref<'disable' | 'reset'>('disable')
const mfaSubmitting = ref(false)

const clearPendingSecret = (): void => {
  pendingSecret.value = ''
  pendingUri.value = ''
}

const startEnable = async (): Promise<void> => {
  if (isReadOnly.value || mfaSubmitting.value) return
  mfaSubmitting.value = true
  try {
    const res = await request.post<APIResponse<{ secret: string; uri: string }>>('/auth/mfa/setup', {}, { silent: true })
    // 200 但无 data = 后端契约违约（弱网截断/网关改包）：requireData 抛错落到
    // 下方 catch 显性报错，静默 return 会让按钮复位、弹框不动，与「没点上」
    // 不可区分
    const data = requireData(res.data, t('common.app.views.profile.responseAbnormal'))
    pendingSecret.value = data.secret
    pendingUri.value = data.uri
    wizardVisible.value = true
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : t('common.app.views.profile.mfaSetupFailed'))
  } finally {
    mfaSubmitting.value = false
  }
}

const startMfaAction = (action: 'disable' | 'reset'): void => {
  if (isReadOnly.value || mfaSubmitting.value) return
  mfaAction.value = action
  mfaCode.value = ''
  mfaCodeDialog.value = true
}

const confirmMfaAction = async (): Promise<void> => {
  if ((!mfaWriteGuard.value && mfaCode.value.length !== 6) || mfaSubmitting.value) return
  const code = mfaWriteGuard.value ? '' : mfaCode.value
  mfaSubmitting.value = true
  try {
    if (mfaAction.value === 'disable') {
      await request.post('/auth/mfa/disable', { code }, { silent: true })
      mfaCodeDialog.value = false
      mfaAwareSuccess(t('common.app.views.profile.mfaDisabledToast'))
      await authStore.fetchUser()
      return
    }
    const res = await request.post<APIResponse<{ secret: string; uri: string }>>('/auth/mfa/setup', { code }, { silent: true })
    // 同 startEnable：200 无 data 经 requireData 抛错显性报错（验码弹框保持
    // 打开，凭据不复位）
    const data = requireData(res.data, t('common.app.views.profile.responseAbnormal'))
    mfaCodeDialog.value = false
    pendingSecret.value = data.secret
    pendingUri.value = data.uri
    wizardVisible.value = true
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : t('common.app.views.profile.actionFailed'))
  } finally {
    mfaSubmitting.value = false
  }
}

const onMfaActivated = async (): Promise<void> => {
  await authStore.fetchUser()
}
</script>

<style scoped>
.profile-form { padding: 4px 28px 0; }
.profile-form :deep(.el-form-item) { margin-bottom: 20px; }
.profile-form :deep(.el-form-item__label) { color: var(--el-text-color-regular); }
.profile-readonly-note { margin: 0 28px 12px; }
.mfa-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-height: 32px; }
.mfa-code-field { margin-top: 4px; }
</style>
