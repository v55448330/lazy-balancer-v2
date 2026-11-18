<template>
  <div>
    <!-- 工具栏 -->
    <div class="ch-toolbar">
      <el-radio-group v-model="filterType" size="small">
        <el-radio-button value="">{{ t('app.notification.channels.filterAll') }}</el-radio-button>
        <el-radio-button v-for="typ in CHANNEL_TYPES" :key="typ" :value="typ">{{ typeLabel(typ) }}</el-radio-button>
      </el-radio-group>
      <span class="toolbar-spacer" />
      <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
        <div>
          <el-button type="primary" :disabled="writeBlocked || drawerVisible" @click="openCreate">
            <el-icon><Plus /></el-icon>
            {{ t('app.notification.channels.add') }}
          </el-button>
        </div>
      </el-tooltip>
    </div>

    <!-- 通道卡片网格（Dashboard 同构：彩色图标+状态+内联操作） -->
    <el-row v-loading="loading" :gutter="16">
      <el-col v-for="ch in filteredChannels" :key="ch.id" :xs="24" :sm="12" :lg="8" class="ch-col">
        <el-card class="ch-card" :class="[`ch-${ch.type}`, { 'ch-disabled': !ch.enabled }]">
          <div class="ch-card-head">
            <div class="ch-icon" :class="`ch-icon-${ch.type}`">
              <el-icon :size="20"><component :is="typeIcon(ch.type)" /></el-icon>
            </div>
            <div class="ch-head-info">
              <div class="ch-name">{{ ch.name }}</div>
              <div class="ch-type-text">{{ typeLabel(ch.type) }}<el-tag v-if="!isMine(ch)" size="small" effect="plain" class="ch-owner">{{ t('app.notification.channels.ownerTag', { id: ch.user_id }) }}</el-tag></div>
            </div>
            <el-switch v-model="ch.enabled" size="small" :disabled="writeBlocked" @change="toggleEnabled(ch)" />
          </div>
          <div class="ch-target">
            <span class="ch-target-label">{{ targetLabelShort(ch.type) }}</span>
            <code class="ch-target-value">{{ displayTarget(ch) }}</code>
          </div>
          <div class="ch-meta">
            <span class="ch-test" :class="testStateClass(ch)">
              <i class="ch-test-dot" :class="ch.last_test_ok ? 'is-ok' : 'is-fail'" />
              {{ testStateText(ch) }}
            </span>
          </div>
          <div class="ch-actions">
            <el-button size="small" text type="primary" :loading="testingId === ch.id" :disabled="writeBlocked" @click="testChannel(ch)">
              {{ t('app.notification.channels.test') }}
            </el-button>
            <el-button size="small" text type="primary" :disabled="writeBlocked" @click="openEdit(ch)">
              {{ t('app.notification.channels.edit') }}
            </el-button>
            <el-button size="small" text type="danger" :loading="deletingIds.has(ch.id)" :disabled="writeBlocked" @click="deleteChannel(ch)">
              {{ t('app.notification.channels.delete') }}
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>
    <el-empty v-if="!loading && filteredChannels.length === 0 && !loadError"
      :description="t('app.notification.channels.emptyText')" :image-size="80" />

    <!-- 编辑抽屉 -->
    <el-dialog v-model="drawerVisible" class="dialog-body-inset" width="min(560px, 94vw)" top="6vh"
      :title="editTarget ? t('app.notification.channels.edit') : t('app.notification.channels.add')"
      :close-on-click-modal="false" @close="resetDrawer">
      <el-form :label-width="$flw('90px')" :disabled="saving">
        <el-form-item :label="t('app.notification.channels.name')">
          <el-input v-model="drawerForm.name" maxlength="100" :placeholder="t('app.notification.channels.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('app.notification.channels.colType')">
          <el-radio-group v-if="!editTarget" v-model="drawerForm.type">
            <el-radio-button v-for="typ in CHANNEL_TYPES" :key="typ" :value="typ">{{ typeLabel(typ) }}</el-radio-button>
          </el-radio-group>
          <span v-else>{{ typeLabel(drawerForm.type) }}</span>
        </el-form-item>
        <el-form-item :label="targetLabel(drawerForm.type)">
          <el-input v-model="drawerForm.targetValue" :placeholder="targetPlaceholder(drawerForm.type)" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="drawerVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveDrawer">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChatDotRound, ChatLineRound, Link, Message, Plus } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import type { NotificationChannel, NotificationChannelType, NotificationChannelsResponse } from '@/types/notifications.ts'

const { t } = useI18n()
const authStore = useAuthStore()

const CHANNEL_TYPES: readonly NotificationChannelType[] = ['webhook', 'email', 'qq', 'wx_clawbot']

const loading = ref(false)
const loadError = ref(false)
const channels = ref<NotificationChannel[]>([])
const filterType = ref<NotificationChannelType | ''>('')
const testingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
const drawerVisible = ref(false)
const editTarget = ref<NotificationChannel | null>(null)
let fetchSeq = 0

const writeBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const writeBlockedReason = computed(() =>
  authStore.isSlaveNode ? t('common.app.views.keys.slaveReadOnly') : t('common.app.views.keys.nodeUnknownReadOnly'))

const filteredChannels = computed(() =>
  filterType.value ? channels.value.filter((ch) => ch.type === filterType.value) : channels.value)
const isMine = (ch: NotificationChannel): boolean => ch.user_id === (authStore.user?.id ?? -1)

const typeIcon = (typ: NotificationChannelType) => {
  switch (typ) {
    case 'webhook': return Link
    case 'email': return Message
    case 'qq': return ChatDotRound
    default: return ChatLineRound
  }
}
const typeLabel = (typ: NotificationChannelType | undefined): string => {
  switch (typ) {
    case 'webhook': return t('app.notification.channels.typeWebhook')
    case 'email': return t('app.notification.channels.typeEmail')
    case 'qq': return t('app.notification.channels.typeQQ')
    default: return t('app.notification.channels.typeWx')
  }
}
const targetLabelShort = (typ: NotificationChannelType): string => {
  switch (typ) {
    case 'webhook': return 'URL'
    case 'email': return '@'
    case 'qq': return 'OpenID'
    default: return 'wxid'
  }
}
const targetField = (typ: NotificationChannelType): string => {
  switch (typ) {
    case 'webhook': return 'url'
    case 'email': return 'email'
    case 'qq': return 'openid'
    default: return 'receiver'
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
const displayTarget = (ch: NotificationChannel): string => {
  const v = parseTargetValue(ch)
  if (!isMine(ch) && v.length > 8) return v.slice(0, 4) + '••••' + v.slice(-4)
  return v || '-'
}

const testStateText = (ch: NotificationChannel): string => {
  if (!ch.last_test_at) return t('app.notification.channels.neverTested')
  return ch.last_test_ok ? t('app.notification.channels.lastTestOk') : t('app.notification.channels.lastTestFail')
}
const testStateClass = (ch: NotificationChannel): string =>
  !ch.last_test_at ? 'test-none' : ch.last_test_ok ? 'test-ok' : 'test-fail'

const fetchChannels = async (): Promise<void> => {
  const seq = ++fetchSeq
  loading.value = true
  try {
    const res = await request.get<NotificationChannelsResponse>('/notification/channels')
    if (seq !== fetchSeq) return
    channels.value = res.data?.channels ?? []
    loadError.value = false
  } catch {
    if (seq === fetchSeq) loadError.value = true
  } finally {
    if (seq === fetchSeq) loading.value = false
  }
}

const drawerForm = ref({ type: 'webhook' as NotificationChannelType, name: '', targetValue: '' })
const saving = ref(false)
const canSave = computed(() => drawerForm.value.name.trim() !== '' && drawerForm.value.targetValue.trim() !== '')

const targetLabel = (typ: NotificationChannelType): string => {
  const map: Record<string, string> = { webhook: t('app.notification.channels.targetWebhookUrl'), email: t('app.notification.channels.targetEmail'), qq: t('app.notification.channels.targetQQ'), wx_clawbot: t('app.notification.channels.targetWx') }
  return map[typ] ?? 'Target'
}
const targetPlaceholder = (typ: NotificationChannelType): string => {
  const map: Record<string, string> = { webhook: t('app.notification.channels.targetWebhookPlaceholder'), email: t('app.notification.channels.targetEmailPlaceholder'), qq: t('app.notification.channels.targetQQHint'), wx_clawbot: t('app.notification.channels.targetWxPlaceholder') }
  return map[typ] ?? ''
}

const saveDrawer = async (): Promise<void> => {
  if (saving.value || !canSave.value) return
  saving.value = true
  try {
    const key = { webhook: 'url', email: 'email', qq: 'openid', wx_clawbot: 'receiver' }[drawerForm.value.type] ?? 'target'
    const body = { type: drawerForm.value.type, name: drawerForm.value.name.trim(), target: JSON.stringify({ [key]: drawerForm.value.targetValue.trim() }) }
    if (editTarget.value) {
      await request.put(`/notification/channels/${editTarget.value.id}`, body)
    } else {
      await request.post('/notification/channels', body)
    }
    drawerVisible.value = false
    await fetchChannels()
  } catch (e) { console.error(e) } finally { saving.value = false }
}

const resetDrawer = (): void => {
  drawerForm.value = { type: 'webhook', name: '', targetValue: '' }
  editTarget.value = null
}

const openCreate = (): void => {
  editTarget.value = null
  drawerVisible.value = true
}

const openEdit = (ch: NotificationChannel): void => {
  editTarget.value = ch
  drawerVisible.value = true
}

const toggleEnabled = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value) return
  try {
    await request.put(`/notification/channels/${ch.id}`, { enabled: ch.enabled })
  } catch {
    ch.enabled = !ch.enabled
  }
}

const testChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || testingId.value !== null) return
  testingId.value = ch.id
  try {
    await request.post(`/notification/channels/${ch.id}/test`)
  } catch { /* handled by refresh */ }
  finally {
    testingId.value = null
    await fetchChannels()
  }
}

const deleteChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || deletingIds.value.has(ch.id)) return
  if (!window.confirm(t('app.notification.channels.deleteConfirm'))) return
  deletingIds.value.add(ch.id)
  try {
    await request.delete(`/notification/channels/${ch.id}`)
    await fetchChannels()
  } catch { /* handled */ }
  finally {
    deletingIds.value.delete(ch.id)
  }
}

onMounted(() => {
  void fetchChannels()
})

defineExpose({ fetchChannels })
</script>

<style scoped>
.ch-toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.toolbar-spacer { flex: 1; }
.ch-col { margin-bottom: 16px; }

/* 通道卡片（Dashboard 同构视觉） */
.ch-card { margin-bottom: 0; }
.ch-card :deep(.el-card__body) { padding: 16px; }
.ch-disabled { opacity: 0.6; }

.ch-card-head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.ch-icon {
  width: 44px; height: 44px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  flex: none;
}
.ch-icon-webhook { background: #eff6ff; color: #3b82f6; }
.ch-icon-email { background: #ecfdf5; color: #10b981; }
.ch-icon-qq { background: #eff6ff; color: #3b82f6; }
.ch-icon-wx_clawbot { background: #f0fdf4; color: #22c55e; }

.ch-head-info { flex: 1; min-width: 0; }
.ch-name { font-size: 15px; font-weight: 600; color: #111827; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ch-type-text { font-size: 12px; color: #6b7280; margin-top: 2px; display: flex; align-items: center; gap: 4px; }
.ch-owner { margin-left: 2px; }

.ch-target {
  display: flex; align-items: baseline; gap: 8px;
  padding: 8px 10px;
  background: var(--el-fill-color-extra-light);
  border-radius: 6px;
  margin-bottom: 10px;
}
.ch-target-label { flex: none; font-size: 11px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; }
.ch-target-value { font-size: 12px; color: #374151; word-break: break-all; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.ch-meta { margin-bottom: 8px; }
.ch-test { font-size: 12px; display: inline-flex; align-items: center; gap: 5px; }
.ch-test-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.ch-test-dot.is-ok { background: #10b981; }
.ch-test-dot.is-fail { background: #ef4444; }
.test-ok { color: #10b981; }
.test-fail { color: #ef4444; }
.test-none { color: #9ca3af; }

.ch-actions { display: flex; gap: 4px; justify-content: flex-end; border-top: 1px solid var(--el-border-color-extra-light); padding-top: 8px; }
</style>
