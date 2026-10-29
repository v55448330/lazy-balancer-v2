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
      <DialogHeader :icon="User" title="个人资料" :subtitle="isOIDCUser ? 'OIDC 企业认证账户' : '本地账户'" />
    </template>
    <div v-if="isReadOnly" class="info-note-bar profile-readonly-note"><span class="info-note-desc">{{ authStore.readOnlyMessage }}</span></div>
    <el-form :model="profileForm" label-width="96px" class="profile-form" :disabled="saving">
      <el-form-item label="用户名">
        <el-input v-model="profileForm.username" disabled />
      </el-form-item>
      <template v-if="isOIDCUser">
        <el-form-item label="显示名">
          <el-input :model-value="profileForm.display_name" disabled />
        </el-form-item>
        <el-form-item label="认证方式">
          <el-tag type="primary" effect="plain" size="small">OIDC 企业认证</el-tag>
        </el-form-item>
        <el-form-item label-width="0">
          <div class="oidc-hint-block">显示名与密码由认证服务管理，如需修改请前往 OIDC 服务</div>
        </el-form-item>
      </template>
      <template v-else>
        <el-form-item label="显示名">
          <el-input v-model="profileForm.display_name" :disabled="isReadOnly" placeholder="选填" maxlength="50" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="profileForm.password" :disabled="isReadOnly" type="password" minlength="8" maxlength="24" placeholder="如不修改请留空（8-24位）" show-password />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="profileForm.passwordConfirm" :disabled="isReadOnly" type="password" minlength="8" maxlength="24" placeholder="再次输入新密码" show-password />
        </el-form-item>
        <el-form-item label="当前密码">
          <el-input v-model="profileForm.currentPassword" :disabled="isReadOnly" type="password" maxlength="72" :placeholder="profileForm.password ? '修改密码时必填' : '填写新密码后需确认'" show-password />
        </el-form-item>
        <el-form-item label="两步验证">
          <div class="mfa-row">
            <el-tag :type="mfaEnabled ? 'success' : 'info'" size="small" effect="plain">{{ mfaEnabled ? '已启用' : '未启用' }}</el-tag>
            <el-button v-if="!mfaEnabled" size="small" type="primary" plain :disabled="isReadOnly" @click="startEnable">启用 MFA</el-button>
            <template v-else>
              <el-button size="small" :disabled="isReadOnly" @click="startMfaAction('disable')">关闭 MFA</el-button>
              <el-button size="small" type="warning" plain :disabled="isReadOnly" @click="startMfaAction('reset')">重置 MFA</el-button>
            </template>
          </div>
          <div class="form-tip-line">关闭或重置需输入当前动态验证码；重置会立即换绑新的验证器并重新生成恢复代码。</div>
        </el-form-item>
      </template>
    </el-form>
    <template #footer>
      <el-button :disabled="saving" @click="closeProfile">取消</el-button>
      <el-button v-if="!isOIDCUser" type="primary" :loading="saving" :disabled="isReadOnly || saving" @click="saveProfile">保存</el-button>
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
        <DialogHeader :icon="Lock" :title="mfaAction === 'reset' ? '重置 MFA' : '关闭 MFA'" />
      </template>
      <div class="form-tip-line">{{ mfaAction === 'reset' ? '重置会立即换绑验证器，旧验证器与旧恢复代码全部失效。' : '关闭后登录不再需要动态验证码。' }}</div>
      <el-input
        v-if="!mfaWriteGuard"
        v-model="mfaCode"
        class="mfa-code-field"
        placeholder="当前 6 位动态验证码"
        maxlength="6"
        aria-label="当前 6 位动态验证码"
        @input="mfaCode = mfaCode.replace(/\D/g, '')"
      />
      <template #footer>
        <el-button :disabled="mfaSubmitting" @click="mfaCodeDialog = false">取消</el-button>
        <el-button type="primary" :loading="mfaSubmitting" :disabled="!mfaWriteGuard && mfaCode.length !== 6" @click="confirmMfaAction">
          {{ mfaAction === 'reset' ? (mfaWriteGuard ? '确认重置' : '验证并重置') : (mfaWriteGuard ? '确认关闭' : '验证并关闭') }}
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
import { ElMessage, ElMessageBox } from 'element-plus'
import { Lock, User } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import MfaBindingWizard from '@/components/MfaBindingWizard.vue'
import { request, mfaAwareSuccess, ApiRequestError } from '@/utils/api'
import { isCurrentPasswordRejection } from '@/utils/profileUpdate'
import { validatePassword } from '@/utils/credentials'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse } from '@/types'

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
const closeProfile = (): void => { if (!saving.value && !mfaSubmitting.value && !wizardVisible.value) emit('update:modelValue', false) }
const saveProfile = async () => {
  if (isReadOnly.value || saving.value) return
  const passwordError = validatePassword(profileForm.value.password)
  if (passwordError) { authStore.showToast('warning', passwordError); return }
  if (profileForm.value.password && !profileForm.value.currentPassword) { authStore.showToast('warning', '请输入当前密码'); return }
  if (profileForm.value.password && profileForm.value.password !== profileForm.value.passwordConfirm) { authStore.showToast('warning', '两次输入的新密码不一致'); return }
  const passwordChanged = Boolean(profileForm.value.password)
  // 占位先于确认：确认框悬挂期按钮已进入在途态，第二击不会再叠一个确认框。
  saving.value = true
  try {
    if (passwordChanged) {
      try {
        await ElMessageBox.confirm(
          '将保存个人资料并修改密码，保存后需要重新登录。确认继续？',
          '保存个人资料',
          { type: 'warning', confirmButtonText: '确认保存', cancelButtonText: '取消' },
        )
      } catch { return }
    }
    await request.patch('/users/me', {
      display_name: profileForm.value.display_name,
      ...(profileForm.value.password && { password: profileForm.value.password, current_password: profileForm.value.currentPassword }),
    })
    emit('update:modelValue', false)
    if (passwordChanged) {
      authStore.showToast('success', '密码已修改，请重新登录')
      await authStore.logout()
    } else {
      mfaAwareSuccess('保存成功')
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
    // 200 但无 data = 后端契约违约（弱网截断/网关改包）：必须显性报错，
    // 静默 return 会让按钮复位、弹框不动，与「没点上」不可区分
    if (!res.data) {
      ElMessage.error('响应异常，请重试')
      return
    }
    pendingSecret.value = res.data.secret
    pendingUri.value = res.data.uri
    wizardVisible.value = true
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : '生成 MFA 密钥失败')
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
      mfaAwareSuccess('MFA 已关闭')
      await authStore.fetchUser()
      return
    }
    const res = await request.post<APIResponse<{ secret: string; uri: string }>>('/auth/mfa/setup', { code }, { silent: true })
    // 同 startEnable：200 无 data 必须显性报错（验码弹框保持打开，凭据不复位）
    if (!res.data) {
      ElMessage.error('响应异常，请重试')
      return
    }
    mfaCodeDialog.value = false
    pendingSecret.value = res.data.secret
    pendingUri.value = res.data.uri
    wizardVisible.value = true
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : '操作失败')
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
.oidc-hint-block {
  width: 100%;
  padding: 8px 12px;
  background: var(--el-fill-color-light);
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.7;
}
</style>
