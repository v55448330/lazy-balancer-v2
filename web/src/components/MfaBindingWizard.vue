<template>
  <el-dialog
    :model-value="modelValue"
    width="min(520px, 92vw)"
    class="dialog-body-inset"
    append-to-body
    :close-on-click-modal="false"
    :show-close="step !== 2"
    :before-close="beforeClose"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
    @closed="handleClosed"
  >
    <template #header>
      <DialogHeader :icon="Lock" title="启用 MFA（两步验证）" subtitle="扫码绑定验证器 → 输码验证 → 保存恢复码" tone="primary" />
    </template>
    <el-steps :active="step" simple style="margin-bottom: 18px">
      <el-step title="扫码" />
      <el-step title="验证" />
      <el-step title="恢复码" />
    </el-steps>
    <div v-if="step === 0" class="mfa-step-column">
      <div v-if="!qrError" class="mfa-qr-frame">
        <canvas ref="qrCanvas" width="220" height="220" />
      </div>
      <div v-else class="info-note-bar" role="status">
        <span class="info-note-desc">二维码生成失败，无法扫码</span>
        <span class="info-note-sub">请使用下方密钥在 Google/Microsoft Authenticator 等验证器中手动添加</span>
      </div>
      <el-text type="info" size="small">无法扫码时手动输入密钥：</el-text>
      <el-text size="small" class="mfa-secret">{{ secret }}</el-text>
      <el-text type="info" size="small">使用 Google/Microsoft Authenticator 等扫码</el-text>
    </div>
    <div v-else-if="step === 1" class="mfa-step-column mfa-step-column--verify">
      <el-input
        v-model="code"
        placeholder="请输入 6 位验证码"
        size="large"
        maxlength="6"
        aria-label="6 位动态验证码"
        class="mfa-code-input"
        @input="code = code.replace(/\D/g, '')"
      />
      <el-text type="info" size="small">为「{{ username }}」绑定</el-text>
    </div>
    <div v-else class="mfa-recovery-column">
      <div class="info-note-bar"><span class="info-note-desc">恢复代码仅此一次显示</span><span class="info-note-sub">每个恢复代码只能使用一次，请妥善保存。丢失验证器时用于登录。</span></div>
      <div class="mfa-recovery-grid">
        <div v-for="item in recoveryCodes" :key="item" class="mfa-recovery-code">{{ item }}</div>
      </div>
    </div>
    <template #footer>
      <el-button v-if="step === 0" :disabled="loading" @click="emit('update:modelValue', false)">取消</el-button>
      <el-button v-if="step === 0" type="primary" @click="step = 1">下一步</el-button>
      <el-button v-if="step === 1" :disabled="loading" @click="step = 0">上一步</el-button>
      <el-button v-if="step === 1" type="primary" :loading="loading" :disabled="code.length !== 6" @click="activate">验证并启用</el-button>
      <el-button v-if="step === 2" @click="copyRecovery">复制全部</el-button>
      <el-button v-if="step === 2" type="primary" @click="confirmRecoverySaved">我已保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Lock } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { copyText } from '@/utils/copy'
import { createOneTimeSecretCloseGuard } from '@/utils/oneTimeSecretGuard'
import type { APIResponse } from '@/types'

// MFA 绑定/换绑向导（个人自助）：父组件负责在打开前取到 pending secret/uri
// （换绑需先验当前动态码），本组件只承担「扫码 → 验证 → 恢复码」三步与
// 一次性凭据的生命周期——关闭即清 secret/恢复码，恢复码步禁止静默关闭。
const props = defineProps<{
  modelValue: boolean
  secret: string
  uri: string
  username: string
}>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  activated: []
}>()

const qrCanvas = ref<HTMLCanvasElement | null>(null)
// 二维码渲染失败态：画布上下文不可用/受限 WebView/uri 异常时，空白画布既不提示
// 也不降级，用户只会以为页面卡住（no unhandled rejection 也不够——必须说清下一步）。
const qrError = ref(false)
const step = ref(0)
const code = ref('')
const recoveryCodes = ref<string[]>([])
const loading = ref(false)

/** 恢复码是仅此一次下发的登录凭证：关闭前必须明确确认已保存；提交中不得关闭，
 *  未走到恢复码步（无秘密可丢）直接关闭（一次性凭据守卫单源）。 */
const beforeClose = createOneTimeSecretCloseGuard({
  message: '恢复代码仅此一次显示，关闭后将无法再次查看。确认已保存？',
  title: '保存恢复代码',
  blocked: () => loading.value,
  skip: () => step.value !== 2,
})

const handleClosed = (): void => {
  step.value = 0
  code.value = ''
  recoveryCodes.value = []
  qrError.value = false
}

// 渲染失败不抛出（原实现 async 无 catch，调用点 void 丢弃 → unhandled rejection
// 且画布留白）：置失败位，模板改说「二维码生成失败，请用下方密钥手动添加」。
const renderQr = async (): Promise<void> => {
  if (!props.uri) return
  qrError.value = false
  await nextTick()
  if (!qrCanvas.value) return
  try {
    await QRCode.toCanvas(qrCanvas.value, props.uri, { width: 220, margin: 1 })
  } catch (error: unknown) {
    qrError.value = true
    console.warn('MFA 二维码渲染失败，已降级为手动输入密钥', error)
  }
}

watch(() => props.modelValue, (visible) => {
  if (!visible) return
  step.value = 0
  code.value = ''
  recoveryCodes.value = []
})

// 扫码步的画布随 v-if 卸载，返回上一步时是全新空画布；可见且回到扫码步即重绘。
// 合并两项来源，避免打开向导时先复位步骤再直接渲染造成两次渲染。
watch([() => props.modelValue, step], ([visible, current]) => {
  if (visible && current === 0) void renderQr()
}, { immediate: true })

const activate = async (): Promise<void> => {
  // 按钮已按 6 位禁用；函数内保留短路作为纵深兜底（脚本/键盘直触路径）。
  if (code.value.length !== 6 || loading.value) return
  loading.value = true
  try {
    const res = await request.post<APIResponse<{ recovery_codes: string[] }>>('/auth/mfa/activate', { code: code.value }, { silent: true })
    if (!res.data) {
      // 契约违约（200 无 data）：不得静默停在验证步——按钮已从 loading 复位，
      // 无提示会让用户以为没点上而重复提交。
      ElMessage.error('响应异常，请重试')
      return
    }
    recoveryCodes.value = res.data.recovery_codes
    step.value = 2
    mfaAwareSuccess('MFA 已启用')
    emit('activated')
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : '验证失败')
  } finally {
    loading.value = false
  }
}

const copyRecovery = async (): Promise<void> => {
  const ok = await copyText(recoveryCodes.value.join('\n'))
  if (ok) ElMessage.success('恢复代码已复制')
  else ElMessage.warning('复制失败，请手动选择复制')
}

const confirmRecoverySaved = async (): Promise<void> => {
  try {
    await ElMessageBox.confirm('恢复代码仅此一次显示。请确认已复制并妥善保存恢复代码；未保存将无法在丢失验证器时恢复登录。', '确认已保存', {
      type: 'warning', confirmButtonText: '我已保存', cancelButtonText: '返回检查',
    })
    emit('update:modelValue', false)
  } catch { /* 返回检查，不关闭 */ }
}
</script>

<style scoped>
.mfa-step-column {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}
.mfa-step-column--verify { gap: 14px; }
.mfa-qr-frame {
  background: #fff;
  padding: 8px;
  border: 1px solid var(--el-border-color-lighter);
}
.mfa-secret {
  font-family: monospace;
  background: var(--el-fill-color-light);
  padding: 4px 10px;
}
.mfa-code-input {
  width: 240px;
  text-align: center;
  font-size: 18px;
  letter-spacing: 6px;
}
.mfa-recovery-column {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.mfa-recovery-grid {
  display: grid;
  grid-template-columns: repeat(2, 200px);
  gap: 8px 24px;
  margin-top: 6px;
}
.mfa-recovery-code {
  font-family: monospace;
  font-size: 14px;
  background: var(--el-fill-color-light);
  padding: 6px 10px;
  text-align: center;
  user-select: all;
}
</style>
