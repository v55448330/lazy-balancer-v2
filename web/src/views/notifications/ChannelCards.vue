<template>
  <el-card shadow="never" class="channel-card-wrap">
    <template #header>
      <div class="card-header-row">
        <span>{{ t('app.notification.tabs.channels') }}</span>
        <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason" placement="top">
          <div>
            <el-button type="primary" :disabled="writeBlocked || wizardVisible" @click="openWizard">
              <el-icon><Plus /></el-icon>
              {{ t('app.notification.channels.add') }}
            </el-button>
          </div>
        </el-tooltip>
      </div>
    </template>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.notification.channels.loadFailed') }}</span>
          <el-button link type="danger" @click="fetchChannels">{{ t('common.app.views.audit.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <el-row v-loading="loading" :gutter="16">
      <el-col v-for="ch in channels" :key="ch.id" :xs="24" :sm="12" :lg="8" class="channel-col">
        <el-card shadow="hover" :class="{ 'channel-disabled': !ch.enabled }">
          <template #header>
            <div class="channel-title-row">
              <span class="channel-name">
                <el-icon class="channel-type-icon"><component :is="typeIcon(ch.type)" /></el-icon>
                {{ ch.name }}
              </span>
              <span class="channel-title-side">
                <el-tag v-if="!isMine(ch)" size="small" type="info" effect="plain">
                  {{ t('app.notification.channels.ownerTag', { id: ch.user_id }) }}
                </el-tag>
                <el-tooltip :content="testStateText(ch)" placement="top">
                  <span class="status-dot" :class="ch.enabled ? 'is-on' : 'is-off'" aria-hidden="true" />
                </el-tooltip>
                <el-tag :type="ch.enabled ? 'success' : 'info'" size="small">
                  {{ ch.enabled ? t('app.notification.channels.enabledTag') : t('app.notification.channels.disabledTag') }}
                </el-tag>
              </span>
            </div>
          </template>
          <el-descriptions :column="1" size="small" border>
            <el-descriptions-item :label="t('app.notification.channels.name')">
              <span class="channel-type-label">{{ typeLabel(ch.type) }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="Target">
              <code class="channel-target">{{ displayTarget(ch) }}</code>
              <div v-if="!isMine(ch)" class="info-note-bar channel-masked-note">
                <span class="info-note-desc">{{ t('app.notification.channels.maskedHint') }}</span>
              </div>
            </el-descriptions-item>
            <el-descriptions-item :label="t('app.notification.channels.test')">
              <span :class="testStateClass(ch)">{{ testStateText(ch) }}</span>
            </el-descriptions-item>
          </el-descriptions>
          <div class="channel-actions">
            <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
              <div>
                <el-button size="small" :loading="testingId === ch.id" :disabled="writeBlocked" @click="testChannel(ch)">
                  {{ t('app.notification.channels.test') }}
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
              <div>
                <el-button size="small" type="primary" plain :disabled="writeBlocked" @click="openEdit(ch)">
                  {{ t('app.notification.channels.edit') }}
                </el-button>
              </div>
            </el-tooltip>
            <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
              <div>
                <el-button size="small" type="danger" plain :loading="deletingIds.has(ch.id)" :disabled="writeBlocked" @click="deleteChannel(ch)">
                  {{ t('app.notification.channels.delete') }}
                </el-button>
              </div>
            </el-tooltip>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-empty v-if="!loading && !loadError && channels.length === 0" :description="t('app.notification.channels.emptyText')" :image-size="80" />

    <!-- 添加向导：类型 → 目标 → 确认，按所选类型渲染对应目标表单 -->
    <el-dialog
      v-model="wizardVisible"
      class="dialog-body-inset"
      width="min(560px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!submitting"
      :show-close="!submitting"
      top="6vh"
      @closed="resetWizard"
    >
      <template #header>
        <DialogHeader :icon="Plus" :title="t('app.notification.channels.add')" :subtitle="t('app.notification.pageDesc')" />
      </template>
      <el-steps :active="wizardStep" align-center finish-status="success" class="wizard-steps">
        <el-step :title="t('app.notification.channels.wizardStepType')" />
        <el-step :title="t('app.notification.channels.wizardStepTarget')" />
        <el-step :title="t('app.notification.channels.wizardStepConfirm')" />
      </el-steps>

      <div v-if="wizardStep === 0" class="wizard-type-grid">
        <el-button
          v-for="typ in CHANNEL_TYPES"
          :key="typ"
          class="wizard-type-btn"
          :type="wizardForm.type === typ ? 'primary' : 'default'"
          :plain="wizardForm.type !== typ"
          @click="wizardForm.type = typ"
        >
          <el-icon><component :is="typeIcon(typ)" /></el-icon>
          {{ typeLabel(typ) }}
        </el-button>
      </div>

      <el-form v-else-if="wizardStep === 1" :label-width="$flw('110px')" :disabled="submitting">
        <el-form-item :label="t('app.notification.channels.name')">
          <el-input v-model="wizardForm.name" maxlength="100" :placeholder="t('app.notification.channels.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="targetLabel(wizardForm.type)">
          <el-input
            v-if="wizardForm.type === 'webhook'"
            v-model="wizardForm.targetValue"
            :placeholder="t('app.notification.channels.targetWebhookPlaceholder')"
          />
          <el-input
            v-else-if="wizardForm.type === 'email'"
            v-model="wizardForm.targetValue"
            :placeholder="t('app.notification.channels.targetEmailPlaceholder')"
          />
          <el-input
            v-else-if="wizardForm.type === 'wx_clawbot'"
            v-model="wizardForm.targetValue"
            :placeholder="t('app.notification.channels.targetWxPlaceholder')"
          />
        </el-form-item>
        <!-- QQ 扫码绑定闭环：生成绑定码 → 扫码加好友 → 发「绑定 码」→ 轮询回填 openid -->
        <template v-if="wizardForm.type === 'qq'">
          <div class="info-note-bar"><span class="info-note-desc">{{ targetHint('qq') }}</span></div>
          <div v-if="!qqBind.code && !qqBind.bound" class="qq-bind-actions">
            <el-button type="primary" :loading="qqBind.loading" @click="generateQQBindCode">
              {{ t('app.notification.channels.qqBindGenerate') }}
            </el-button>
          </div>
          <div v-else-if="qqBind.code && !qqBind.bound" class="qq-bind-panel">
            <div class="qq-bind-code"><code>{{ qqBind.code }}</code></div>
            <div class="qq-bind-steps">
              <div>1. {{ t('app.notification.channels.qqBindStepScan') }}</div>
              <div>2. {{ t('app.notification.channels.qqBindStepSend', { code: qqBind.code }) }}</div>
              <div>3. {{ t('app.notification.channels.qqBindStepWait') }}</div>
            </div>
            <el-button size="small" @click="generateQQBindCode">{{ t('app.notification.channels.qqBindRegenerate') }}</el-button>
          </div>
          <div v-else class="qq-bind-bound">
            <el-tag type="success">{{ t('app.notification.channels.qqBoundTag') }}</el-tag>
            <code class="qq-bind-openid">{{ qqBind.openid }}</code>
          </div>
        </template>
        <div v-else class="info-note-bar"><span class="info-note-desc">{{ targetHint(wizardForm.type) }}</span></div>
      </el-form>

      <el-descriptions v-else :column="1" size="small" border :title="t('app.notification.channels.confirmSummary')">
        <el-descriptions-item :label="t('app.notification.channels.name')">{{ wizardForm.name }}</el-descriptions-item>
        <el-descriptions-item :label="t('app.notification.tabs.channels')">{{ typeLabel(wizardForm.type) }}</el-descriptions-item>
        <el-descriptions-item label="Target"><code>{{ wizardForm.targetValue }}</code></el-descriptions-item>
      </el-descriptions>

      <template #footer>
        <el-button :disabled="submitting" @click="wizardStep === 0 ? closeWizard() : wizardStep--">
          {{ wizardStep === 0 ? t('common.app.views.keys.cancel') : t('app.notification.channels.prev') }}
        </el-button>
        <el-button v-if="wizardStep < 2" type="primary" :disabled="!canAdvance" @click="wizardStep++">
          {{ t('app.notification.channels.next') }}
        </el-button>
        <el-button v-else type="primary" :loading="submitting" :disabled="!canAdvance" @click="submitWizard">
          {{ t('app.notification.channels.submit') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 编辑：名称 / 启停 / 目标（类型不可改——后端 UNIQUE(user_id,type,target) 按类型约束目标形状） -->
    <el-dialog
      v-model="editVisible"
      class="dialog-body-inset"
      width="min(560px, 92vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!saving"
      :show-close="!saving"
      top="6vh"
      @closed="resetEdit"
    >
      <template #header>
        <DialogHeader :icon="Setting" :title="t('app.notification.channels.edit')" :subtitle="editTarget?.name || ''" />
      </template>
      <el-form :label-width="$flw('110px')" :disabled="saving">
        <el-form-item :label="t('app.notification.channels.name')">
          <el-input v-model="editForm.name" maxlength="100" :placeholder="t('app.notification.channels.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="targetLabel(editTarget?.type)">
          <el-input v-model="editForm.targetValue" />
        </el-form-item>
        <el-form-item :label="t('app.notification.tabs.channels')">
          <el-switch v-model="editForm.enabled" />
          <span class="switch-hint">{{ editForm.enabled ? t('app.notification.channels.enabledTag') : t('app.notification.channels.disabledTag') }}</span>
        </el-form-item>
        <div class="info-note-bar"><span class="info-note-desc">{{ targetHint(editTarget?.type) }}</span></div>
      </el-form>
      <template #footer>
        <el-button :disabled="saving" @click="editVisible = false">{{ t('common.app.views.keys.cancel') }}</el-button>
        <el-button type="primary" :loading="saving" :disabled="!canSaveEdit" @click="saveEdit">
          {{ t('common.app.views.keys.save') }}
        </el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ChatDotRound, ChatLineRound, Link, Message, Plus, Setting } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import type {
  NotificationChannel,
  NotificationChannelType,
  NotificationChannelsResponse,
  NotificationCreateChannelResponse,
} from '@/types/notifications.ts'

const { t } = useI18n()
const authStore = useAuthStore()

// 通知通道是登录用户的自助资源（非管理员专属），写门与 API 密钥页同口径：
// 仅从节点/角色未知时 fail-closed；非管理员可正常管理本人通道。
const writeBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const writeBlockedReason = computed(() =>
  authStore.isSlaveNode
    ? t('common.app.views.keys.slaveReadOnly')
    : t('common.app.views.keys.nodeUnknownReadOnly'),
)

const CHANNEL_TYPES: readonly NotificationChannelType[] = ['webhook', 'email', 'qq', 'wx_clawbot']

const channels = ref<NotificationChannel[]>([])
const loading = ref(false)
const loadError = ref(false)
const testingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
let channelsRequestSeq = 0

const isMine = (ch: NotificationChannel): boolean => ch.user_id === (authStore.user?.id ?? -1)

const typeIcon = (typ: NotificationChannelType) => {
  switch (typ) {
    case 'webhook': return Link
    case 'email': return Message
    case 'qq': return ChatDotRound
    case 'wx_clawbot': return ChatLineRound
  }
}

const typeLabel = (typ: NotificationChannelType | undefined): string => {
  switch (typ) {
    case 'webhook': return t('app.notification.channels.typeWebhook')
    case 'email': return t('app.notification.channels.typeEmail')
    case 'qq': return t('app.notification.channels.typeQQ')
    case 'wx_clawbot': return t('app.notification.channels.typeWx')
    default: return '-'
  }
}

/** target 为按类型约束的 JSON（{url|email|openid|receiver}）；展示取主字段，畸形回退原文。 */
const targetField = (typ: NotificationChannelType): string => {
  switch (typ) {
    case 'webhook': return 'url'
    case 'email': return 'email'
    case 'qq': return 'openid'
    case 'wx_clawbot': return 'receiver'
  }
}

const parseTargetValue = (ch: NotificationChannel): string => {
  try {
    const parsed = JSON.parse(ch.target) as Record<string, unknown>
    const value = parsed[targetField(ch.type)]
    return typeof value === 'string' ? value : ch.target
  } catch {
    return ch.target
  }
}

const displayTarget = (ch: NotificationChannel): string => parseTargetValue(ch) || '-'

const testStateText = (ch: NotificationChannel): string => {
  if (!ch.last_test_at) return t('app.notification.channels.neverTested')
  return ch.last_test_ok ? t('app.notification.channels.lastTestOk') : t('app.notification.channels.lastTestFail')
}

const testStateClass = (ch: NotificationChannel): string =>
  ch.last_test_at ? (ch.last_test_ok ? 'test-ok' : 'test-fail') : 'test-unknown'

const targetLabel = (typ: NotificationChannelType | undefined): string => {
  switch (typ) {
    case 'webhook': return t('app.notification.channels.targetWebhookUrl')
    case 'email': return t('app.notification.channels.targetEmail')
    case 'qq': return t('app.notification.channels.targetQQ')
    case 'wx_clawbot': return t('app.notification.channels.targetWx')
    default: return 'Target'
  }
}

const targetHint = (typ: NotificationChannelType | undefined): string => {
  switch (typ) {
    case 'webhook': return t('app.notification.channels.targetWebhookHint')
    case 'qq': return t('app.notification.channels.targetQQHint')
    case 'wx_clawbot': return t('app.notification.channels.targetWxHint')
    default: return ''
  }
}

const fetchChannels = async (): Promise<void> => {
  const seq = ++channelsRequestSeq
  loading.value = true
  try {
    const res = await request.get<NotificationChannelsResponse>('/notification/channels')
    if (seq === channelsRequestSeq) {
      channels.value = res.data?.channels ?? []
      loadError.value = false
    }
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，此处只置显性错误态（空列表≠无故障）
    console.error('Failed to fetch notification channels:', error)
    if (seq === channelsRequestSeq) loadError.value = true
  } finally {
    if (seq === channelsRequestSeq) loading.value = false
  }
}

// --- 添加向导 ---
const wizardVisible = ref(false)
const wizardStep = ref(0)
const submitting = ref(false)
const wizardForm = ref({ type: 'webhook' as NotificationChannelType, name: '', targetValue: '' })

const openWizard = (): void => {
  if (writeBlocked.value || submitting.value) return
  resetWizard()
  wizardVisible.value = true
}

const resetWizard = (): void => {
  wizardStep.value = 0
  wizardForm.value = { type: 'webhook', name: '', targetValue: '' }
  if (qqBind.value.timer !== null) {
    window.clearInterval(qqBind.value.timer)
    qqBind.value.timer = null
  }
  qqBind.value = { code: '', openid: '', bound: false, loading: false, timer: null }
}

const closeWizard = (): void => { wizardVisible.value = false }

// QQ 扫码绑定状态（向导内闭环：生成码→扫码发指令→轮询回填 openid）
const qqBind = ref<{ code: string; openid: string; bound: boolean; loading: boolean; timer: number | null }>({
  code: '', openid: '', bound: false, loading: false, timer: null,
})

const generateQQBindCode = async (): Promise<void> => {
  if (qqBind.value.loading) return
  qqBind.value.loading = true
  try {
    const res = await request.post<NotificationCreateChannelResponse & { data: { code: string } }>('/notification/qq/bind-code', {})
    qqBind.value.code = res.data?.code ?? ''
    startQQBindPolling()
  } finally {
    qqBind.value.loading = false
  }
}

const startQQBindPolling = (): void => {
  if (qqBind.value.timer !== null) return
  const timer = window.setInterval(async () => {
    try {
      const res = await request.get<NotificationCreateChannelResponse & { data: { bound: boolean; openid: string; has_code: boolean } }>('/notification/qq/bind-code')
      const data = res.data
      if (data?.bound) {
        qqBind.value.bound = true
        qqBind.value.openid = data.openid
        wizardForm.value.targetValue = data.openid
        if (qqBind.value.timer !== null) {
          window.clearInterval(qqBind.value.timer)
          qqBind.value.timer = null
        }
      }
    } catch {
      // 轮询失败保持等待；超时（10 分钟）由 expires_at 提示重新生成
    }
  }, 3000)
  qqBind.value.timer = timer
  window.setTimeout(() => {
    if (qqBind.value.timer === timer && !qqBind.value.bound) {
      window.clearInterval(timer)
      qqBind.value.timer = null
    }
  }, 10 * 60 * 1000)
}

const canAdvance = computed(() => {
  if (wizardStep.value === 0) return true
  if (wizardForm.value.type === 'qq') {
    // QQ：openid 由扫码绑定自动回填，手填通道已退役
    return wizardForm.value.name.trim() !== '' && qqBind.value.bound && wizardForm.value.targetValue.trim() !== ''
  }
  // 目标步：名称与目标值都必填（后端对目标按类型做最小契约校验）
  return wizardForm.value.name.trim() !== '' && wizardForm.value.targetValue.trim() !== ''
})

const buildTarget = (typ: NotificationChannelType, value: string): string =>
  JSON.stringify({ [targetField(typ)]: value.trim() })

const submitWizard = async (): Promise<void> => {
  if (writeBlocked.value || submitting.value || !canAdvance.value) return
  submitting.value = true
  try {
    await request.post<NotificationCreateChannelResponse>('/notification/channels', {
      type: wizardForm.value.type,
      name: wizardForm.value.name.trim(),
      target: buildTarget(wizardForm.value.type, wizardForm.value.targetValue),
    })
    mfaAwareSuccess(t('app.notification.channels.createSuccess'))
    wizardVisible.value = false
    await fetchChannels()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast；保持向导打开让用户修正目标（后端 400 带类型契约原因）
    console.error('Failed to create notification channel:', error)
  } finally {
    submitting.value = false
  }
}

// --- 编辑 ---
const editVisible = ref(false)
const saving = ref(false)
const editTarget = ref<NotificationChannel | null>(null)
const editForm = ref({ name: '', targetValue: '', enabled: true })

const openEdit = (ch: NotificationChannel): void => {
  if (writeBlocked.value || saving.value) return
  editTarget.value = ch
  editForm.value = { name: ch.name, targetValue: parseTargetValue(ch), enabled: ch.enabled }
  editVisible.value = true
}

const resetEdit = (): void => {
  editTarget.value = null
  editForm.value = { name: '', targetValue: '', enabled: true }
}

const canSaveEdit = computed(() => editForm.value.name.trim() !== '' && editForm.value.targetValue.trim() !== '')

const saveEdit = async (): Promise<void> => {
  if (writeBlocked.value || saving.value || !editTarget.value || !canSaveEdit.value) return
  saving.value = true
  try {
    await request.put(`/notification/channels/${editTarget.value.id}`, {
      name: editForm.value.name.trim(),
      target: buildTarget(editTarget.value.type, editForm.value.targetValue),
      enabled: editForm.value.enabled,
    })
    mfaAwareSuccess(t('app.notification.channels.updateSuccess'))
    editVisible.value = false
    await fetchChannels()
  } catch (error: unknown) {
    console.error('Failed to update notification channel:', error)
  } finally {
    saving.value = false
  }
}

// --- 测试 / 删除 ---
const testChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || testingId.value !== null) return
  testingId.value = ch.id
  try {
    await request.post(`/notification/channels/${ch.id}/test`)
    ElMessage.success(t('app.notification.channels.testSuccess'))
    await fetchChannels()
  } catch (error: unknown) {
    // 失败分支：拦截器已弹后端 message（含发送失败原因）；再补一条定位提示
    ElMessage.error(t('app.notification.channels.testFailed'))
    console.error('Failed to test notification channel:', error)
    await fetchChannels()
  } finally {
    testingId.value = null
  }
}

const deleteChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || deletingIds.value.has(ch.id)) return
  deletingIds.value.add(ch.id)
  try {
    try {
      await ElMessageBox.confirm(t('app.notification.channels.deleteConfirm'), t('app.notification.channels.delete'), {
        type: 'warning',
        confirmButtonText: t('common.app.views.keys.confirmDelete'),
        cancelButtonText: t('common.app.views.keys.cancel'),
      })
    } catch { return }
    await request.delete(`/notification/channels/${ch.id}`)
    mfaAwareSuccess(t('app.notification.channels.deleteSuccess'))
    await fetchChannels()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('Failed to delete notification channel:', error)
  } finally {
    deletingIds.value.delete(ch.id)
  }
}

onMounted(() => {
  void fetchChannels()
})

defineExpose({ fetchChannels })
</script>

<style scoped>
.card-header-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.channel-col { margin-bottom: 16px; }
.channel-disabled { opacity: 0.72; }
.channel-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.channel-name { min-width: 0; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px; }
.channel-type-icon { flex: none; }
.channel-title-side { display: inline-flex; align-items: center; gap: 8px; flex: none; }
.channel-type-label { color: var(--text-secondary, #6b7280); }
.channel-target { word-break: break-all; }
.channel-masked-note { margin-top: 6px; }
.channel-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.status-dot.is-on { background: var(--el-color-success); }
.status-dot.is-off { background: var(--el-text-color-disabled); }
.test-ok { color: var(--el-color-success); }
.test-fail { color: var(--el-color-danger); }
.test-unknown { color: var(--el-text-color-secondary); }
.wizard-steps { margin-bottom: 20px; }
.wizard-type-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.wizard-type-btn { height: 64px; font-size: 14px; }
.switch-hint { margin-left: 10px; font-size: 12px; color: var(--text-secondary, #6b7280); }
</style>
