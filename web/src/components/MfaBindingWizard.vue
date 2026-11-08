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
      <DialogHeader :icon="Lock" :title="t('common.app.views.mfa.wizardTitle')" :subtitle="t('common.app.views.mfa.wizardSubtitle')" tone="primary" />
    </template>
    <el-steps :active="step" simple style="margin-bottom: 18px">
      <el-step :title="t('common.app.views.mfa.stepScan')" />
      <el-step :title="t('common.app.views.mfa.stepVerify')" />
      <el-step :title="t('common.app.views.mfa.stepRecovery')" />
    </el-steps>
    <div v-if="step === 0" class="mfa-step-column">
      <div v-if="!qrError" class="mfa-qr-frame">
        <canvas ref="qrCanvas" width="220" height="220" />
      </div>
      <div v-else class="info-note-bar" role="status">
        <span class="info-note-desc">{{ t('common.app.views.mfa.qrFailedTitle') }}</span>
        <span class="info-note-sub">{{ t('common.app.views.mfa.qrFailedHint') }}</span>
      </div>
      <el-text type="info" size="small">{{ t('common.app.views.mfa.manualKeyHint') }}</el-text>
      <el-text size="small" class="mfa-secret">{{ secret }}</el-text>
      <el-text type="info" size="small">{{ t('common.app.views.mfa.scanWithApp') }}</el-text>
    </div>
    <div v-else-if="step === 1" class="mfa-step-column mfa-step-column--verify">
      <el-input
        v-model="code"
        :placeholder="t('common.app.views.mfa.codePlaceholder')"
        size="large"
        maxlength="6"
        :aria-label="t('common.app.views.mfa.codeAria')"
        class="mfa-code-input"
        @input="code = sanitizeTotpDigits(code)"
      />
      <el-text type="info" size="small">{{ t('common.app.views.mfa.bindingFor', { username }) }}</el-text>
    </div>
    <div v-else class="mfa-recovery-column">
      <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.mfa.recoveryOnceBadge') }}</span><span class="info-note-sub">{{ t('common.app.views.mfa.recoveryOnceHint') }}</span></div>
      <div class="mfa-recovery-grid">
        <div v-for="item in recoveryCodes" :key="item" class="mfa-recovery-code">{{ item }}</div>
      </div>
    </div>
    <template #footer>
      <el-button v-if="step === 0" :disabled="loading" @click="emit('update:modelValue', false)">{{ t('common.app.views.mfa.cancel') }}</el-button>
      <el-button v-if="step === 0" type="primary" @click="step = 1">{{ t('common.app.views.mfa.next') }}</el-button>
      <el-button v-if="step === 1" :disabled="loading" @click="step = 0">{{ t('common.app.views.mfa.prev') }}</el-button>
      <el-button v-if="step === 1" type="primary" :loading="loading" :disabled="code.length !== 6" @click="activate">{{ t('common.app.views.mfa.verifyActivate') }}</el-button>
      <el-button v-if="step === 2" @click="copyRecovery">{{ t('common.app.views.mfa.copyAll') }}</el-button>
      <el-button v-if="step === 2" type="primary" @click="confirmRecoverySaved">{{ t('common.app.views.mfa.savedButton') }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Lock } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess, sanitizeTotpDigits } from '@/utils/api'
import { copyText } from '@/utils/copy'
import { createOneTimeSecretCloseGuard } from '@/utils/oneTimeSecretGuard'
import { requireData } from '@/utils/requireData'
import type { APIResponse } from '@/types'

// MFA 绑定/换绑向导（个人自助）：父组件负责在打开前取到 pending secret/uri
// （换绑需先验当前动态码），本组件只承担「扫码 → 验证 → 恢复码」三步与
// 一次性凭据的生命周期——关闭即清 secret/恢复码，恢复码步禁止静默关闭。
const { t } = useI18n()
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
  message: t('common.app.views.mfa.closeGuardMessage'),
  title: t('common.app.views.mfa.closeGuardTitle'),
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
    // 契约违约（200 无 data）经 requireData 抛错落到下方 catch——不得静默停在
    // 验证步：按钮已从 loading 复位，无提示会让用户以为没点上而重复提交。
    const data = requireData(res.data, t('common.app.views.mfa.responseAbnormal'))
    recoveryCodes.value = data.recovery_codes
    step.value = 2
    mfaAwareSuccess(t('common.app.views.mfa.enabledToast'))
    emit('activated')
  } catch (error: unknown) {
    ElMessage.error(error instanceof Error ? error.message : t('common.app.views.mfa.verifyFailed'))
  } finally {
    loading.value = false
  }
}

const copyRecovery = async (): Promise<void> => {
  const ok = await copyText(recoveryCodes.value.join('\n'))
  if (ok) ElMessage.success(t('common.app.views.mfa.copiedToast'))
  else ElMessage.warning(t('common.app.views.mfa.copyFailedToast'))
}

const confirmRecoverySaved = async (): Promise<void> => {
  try {
    await ElMessageBox.confirm(t('common.app.views.mfa.confirmSavedMessage'), t('common.app.views.mfa.confirmSavedTitle'), {
      type: 'warning', confirmButtonText: t('common.app.views.mfa.savedButton'), cancelButtonText: t('common.app.views.mfa.backToCheck'),
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
