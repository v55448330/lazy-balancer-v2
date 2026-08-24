<template>
  <el-card class="settings-card mfa-card">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <el-icon><Key /></el-icon>
          <span>MFA 多因素认证</span>
        </div>
        <el-tag v-if="mfaStatus.enabled" type="success" size="small">已启用</el-tag>
        <el-tag v-else type="info" size="small">未启用</el-tag>
      </div>
    </template>

    <div v-if="!mfaStatus.enabled && !binding.active" class="mfa-intro">
      <el-text type="info">为账号绑定 TOTP 验证器（Google/Microsoft Authenticator 等），登录时需额外输入动态验证码。</el-text>
      <el-button type="primary" @click="startBinding">启用 MFA</el-button>
    </div>

    <div v-else-if="binding.active" class="mfa-binding">
      <el-steps :active="binding.step" simple class="binding-steps">
        <el-step title="扫描二维码" />
        <el-step title="输入验证码" />
        <el-step title="保存恢复代码" />
      </el-steps>

      <div v-if="binding.step === 0" class="binding-body">
        <div class="qr-wrap">
          <canvas ref="qrCanvas" class="qr-canvas" />
        </div>
        <el-text type="info" size="small">无法扫码时手动输入密钥：</el-text>
        <el-text class="secret-text" size="small" selectable>{{ binding.secret }}</el-text>
        <div class="binding-actions">
          <el-button @click="cancelBinding">取消</el-button>
          <el-button type="primary" @click="binding.step = 1">下一步</el-button>
        </div>
      </div>

      <div v-else-if="binding.step === 1" class="binding-body">
        <el-input
          v-model="binding.code"
          placeholder="请输入验证器显示的 6 位验证码"
          size="large"
          maxlength="6"
          class="code-input"
          @input="binding.code = binding.code.replace(/\D/g, '')"
        />
        <div class="binding-actions">
          <el-button @click="binding.step = 0">上一步</el-button>
          <el-button type="primary" :loading="binding.loading" @click="activate">验证并启用</el-button>
        </div>
      </div>

      <div v-else class="binding-body">
        <el-alert type="warning" :closable="false" show-icon title="恢复代码仅此一次显示"
          description="每个恢复代码只能使用一次。请在安全的地方保存（如密码管理器），丢失设备时用于登录。" />
        <div class="recovery-grid">
          <div v-for="code in binding.recoveryCodes" :key="code" class="recovery-item">{{ code }}</div>
        </div>
        <div class="binding-actions">
          <el-button @click="copyRecoveryCodes">复制全部</el-button>
          <el-button @click="downloadRecoveryCodes">下载 .txt</el-button>
          <el-button type="primary" @click="finishBinding">我已保存</el-button>
        </div>
      </div>
    </div>

    <div v-else class="mfa-manage">
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="状态">
          <el-tag type="success" size="small">已启用</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="剩余恢复代码">
          {{ mfaStatus.recovery_codes_remaining }} 个
          <el-text v-if="mfaStatus.recovery_codes_remaining < 3" type="danger" size="small">（偏少，建议重新生成）</el-text>
        </el-descriptions-item>
      </el-descriptions>
      <div class="manage-actions">
        <el-button @click="regenerateDialog = true">重新生成恢复代码</el-button>
        <el-button type="danger" @click="disableDialog = true">禁用 MFA</el-button>
      </div>
    </div>

    <el-dialog v-model="regenerateDialog" title="重新生成恢复代码" width="420px" @closed="regenerateForm.password = ''">
      <el-form @submit.prevent="regenerate">
        <el-form-item label="当前密码">
          <el-input v-model="regenerateForm.password" type="password" show-password @keyup.enter="regenerate" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="regenerateDialog = false">取消</el-button>
        <el-button type="primary" :loading="regenerateForm.loading" @click="regenerate">确认重新生成</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="disableDialog" title="禁用 MFA（双重确认）" width="440px" @closed="disableForm.password = ''; disableForm.code = ''">
      <el-alert type="warning" :closable="false" show-icon class="disable-alert"
        description="禁用后登录将不再需要验证码。此操作需要当前密码和有效验证码，防止会话被劫持后 MFA 被一键关闭。" />
      <el-form @submit.prevent="disable">
        <el-form-item label="当前密码">
          <el-input v-model="disableForm.password" type="password" show-password />
        </el-form-item>
        <el-form-item label="验证码">
          <el-input v-model="disableForm.code" placeholder="6 位验证码或恢复代码" @keyup.enter="disable" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="disableDialog = false">取消</el-button>
        <el-button type="danger" :loading="disableForm.loading" @click="disable">确认禁用</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { nextTick, onMounted, reactive, ref } from 'vue'
import QRCode from 'qrcode'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Key } from '@element-plus/icons-vue'
import { request } from '@/utils/api'

interface APIResponse<T = unknown> { code: number; message?: string; data?: T }
interface MfaStatusResponse { enabled: boolean; recovery_codes_remaining: number }

const mfaStatus = reactive<MfaStatusResponse>({ enabled: false, recovery_codes_remaining: 0 })
const qrCanvas = ref<HTMLCanvasElement | null>(null)

const binding = reactive({
  active: false,
  step: 0,
  secret: '',
  uri: '',
  code: '',
  recoveryCodes: [] as string[],
  loading: false,
})

const regenerateDialog = ref(false)
const regenerateForm = reactive({ password: '', loading: false })

const disableDialog = ref(false)
const disableForm = reactive({ password: '', code: '', loading: false })

const fetchStatus = async () => {
  try {
    const res = await request.get<APIResponse<MfaStatusResponse>>('/auth/mfa/status', { silent: true })
    if (res.data) {
      mfaStatus.enabled = res.data.enabled
      mfaStatus.recovery_codes_remaining = res.data.recovery_codes_remaining
    }
  } catch { /* 静默：卡片初始化失败不弹错 */ }
}

const startBinding = async () => {
  try {
    const res = await request.post<APIResponse<{ secret: string; uri: string }>>('/auth/mfa/setup', {}, { silent: true })
    if (!res.data) return
    binding.secret = res.data.secret
    binding.uri = res.data.uri
    binding.code = ''
    binding.recoveryCodes = []
    binding.step = 0
    binding.active = true
    await nextTick()
    if (qrCanvas.value) {
      await QRCode.toCanvas(qrCanvas.value, binding.uri, { width: 220, margin: 1 })
    }
  } catch (error) {
    console.error('Failed to start MFA binding:', error)
  }
}

const cancelBinding = () => { binding.active = false }

const activate = async () => {
  if (binding.code.length !== 6 || binding.loading) return
  binding.loading = true
  try {
    const res = await request.post<APIResponse<{ recovery_codes: string[] }>>('/auth/mfa/activate', { code: binding.code }, { silent: true })
    if (!res.data) return
    binding.recoveryCodes = res.data.recovery_codes
    binding.step = 2
    await fetchStatus()
    ElMessage.success('MFA 已启用')
  } catch (error) {
    console.error('Failed to activate MFA:', error)
  } finally {
    binding.loading = false
  }
}

const finishBinding = () => {
  binding.active = false
  ElMessage.success('MFA 绑定完成')
}

const copyRecoveryCodes = async () => {
  try {
    await navigator.clipboard.writeText(binding.recoveryCodes.join('\n'))
    ElMessage.success('恢复代码已复制')
  } catch {
    ElMessage.warning('复制失败，请手动选择复制')
  }
}

const downloadRecoveryCodes = () => {
  const blob = new Blob([`Lazy Balancer MFA 恢复代码\n\n${binding.recoveryCodes.join('\n')}\n\n每个代码只能使用一次。`], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'lazy-balancer-mfa-recovery-codes.txt'
  anchor.click()
  URL.revokeObjectURL(url)
}

const regenerate = async () => {
  if (!regenerateForm.password || regenerateForm.loading) return
  regenerateForm.loading = true
  try {
    const res = await request.post<APIResponse<{ recovery_codes: string[] }>>('/auth/mfa/recovery-codes', { password: regenerateForm.password }, { silent: true })
    if (!res.data) return
    binding.recoveryCodes = res.data.recovery_codes
    binding.step = 2
    binding.active = true
    regenerateDialog.value = false
    await fetchStatus()
  } catch (error) {
    console.error('Failed to regenerate recovery codes:', error)
  } finally {
    regenerateForm.loading = false
  }
}

const disable = async () => {
  if (!disableForm.password || !disableForm.code || disableForm.loading) return
  disableForm.loading = true
  try {
    await ElMessageBox.confirm('确认禁用 MFA？禁用后登录将不再需要验证码。', '最终确认', { type: 'warning', confirmButtonText: '确认禁用' })
  } catch {
    disableForm.loading = false
    return
  }
  try {
    await request.post('/auth/mfa/disable', { password: disableForm.password, code: disableForm.code }, { silent: true })
    disableDialog.value = false
    await fetchStatus()
    ElMessage.success('MFA 已禁用')
  } catch (error) {
    console.error('Failed to disable MFA:', error)
  } finally {
    disableForm.loading = false
  }
}

onMounted(fetchStatus)
</script>

<style scoped>
.mfa-intro {
  display: flex;
  flex-direction: column;
  gap: 16px;
  align-items: flex-start;
}
.binding-steps {
  margin-bottom: 20px;
}
.binding-body {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}
.qr-wrap {
  background: #fff;
  padding: 8px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 4px;
}
.secret-text {
  font-family: monospace;
  background: var(--el-fill-color-light);
  padding: 4px 10px;
  border-radius: 3px;
  letter-spacing: 1px;
}
.binding-actions {
  display: flex;
  gap: 10px;
  margin-top: 6px;
}
.code-input {
  width: 240px;
  text-align: center;
  font-size: 18px;
  letter-spacing: 6px;
}
.recovery-grid {
  display: grid;
  grid-template-columns: repeat(2, 200px);
  gap: 8px 24px;
  margin-top: 8px;
}
.recovery-item {
  font-family: monospace;
  font-size: 14px;
  background: var(--el-fill-color-light);
  padding: 6px 10px;
  border-radius: 3px;
  text-align: center;
  user-select: all;
}
.manage-actions {
  display: flex;
  gap: 10px;
  margin-top: 14px;
}
.disable-alert {
  margin-bottom: 14px;
}
</style>
