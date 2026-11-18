<template>
  <div>
    <!-- 工具栏：类型筛选 + 添加（页面级标题由 NotificationCenter 承载） -->
    <div class="ch-toolbar">
      <el-check-tag v-for="f in typeFilters" :key="f.key" :checked="filterType === f.key"
        @change="filterType = f.key">{{ f.label }}</el-check-tag>
      <span class="toolbar-spacer" />
      <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
        <div>
          <el-button type="primary" :disabled="writeBlocked || drawerVisible" @click="openCreate">
            {{ t('app.notification.channels.add') }}
          </el-button>
        </div>
      </el-tooltip>
    </div>

    <el-table v-loading="loading" :data="filteredChannels" stripe class="ch-table"
      :empty-text="loadError ? t('app.notification.channels.loadFailed') : t('app.notification.channels.emptyText')">
      <el-table-column :label="t('app.notification.channels.name')" min-width="160">
        <template #default="scope">
          <div class="ch-name-cell">
            <el-icon class="ch-type-icon"><component :is="typeIcon(scope.row.type)" /></el-icon>
            <span class="ch-name">{{ scope.row.name }}</span>
            <el-tag v-if="!isMine(asCh(scope.row))" size="small" type="info" effect="plain">
              {{ t('app.notification.channels.ownerTag', { id: scope.row.user_id }) }}
            </el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.channels.colType')" width="110">
        <template #default="scope">
          <span class="ch-muted">{{ typeLabel(scope.row.type) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.channels.colTarget')" min-width="200">
        <template #default="scope">
          <code class="ch-target">{{ displayTarget(asCh(scope.row)) }}</code>
          <div v-if="!isMine(asCh(scope.row))" class="ch-masked">{{ t('app.notification.channels.maskedHint') }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.channels.colStatus')" width="130" align="center">
        <template #default="scope">
          <el-tooltip :content="testStateText(asCh(scope.row))" placement="top">
            <span class="status-dot" :class="statusDotClass(asCh(scope.row))" aria-hidden="true" />
          </el-tooltip>
          <el-tag :type="scope.row.enabled ? 'success' : 'info'" size="small" class="ml4">
            {{ scope.row.enabled ? t('app.notification.channels.enabledTag') : t('app.notification.channels.disabledTag') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.channels.lastTested')" width="150">
        <template #default="scope">
          <span :class="testStateClass(asCh(scope.row))">{{ testStateText(asCh(scope.row)) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('app.notification.deliveries.colAction')" width="230" align="right" fixed="right">
        <template #default="scope">
          <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
            <div class="row-actions">
              <el-button size="small" :loading="testingId === scope.row.id" :disabled="writeBlocked" @click="testChannel(asCh(scope.row))">
                {{ t('app.notification.channels.test') }}
              </el-button>
              <el-button size="small" type="primary" plain :disabled="writeBlocked" @click="openEdit(asCh(scope.row))">
                {{ t('app.notification.channels.edit') }}
              </el-button>
              <el-button size="small" type="danger" plain :loading="deletingIds.has(scope.row.id)" :disabled="writeBlocked" @click="deleteChannel(asCh(scope.row))">
                {{ t('app.notification.channels.delete') }}
              </el-button>
            </div>
          </el-tooltip>
        </template>
      </el-table-column>
    </el-table>

    <!-- 创建/编辑抽屉：名称→类型→目标→消息样式，一步式全可见 -->
    <el-drawer v-model="drawerVisible" size="540px" :close-on-click-modal="false"
      :title="drawerMode === 'create' ? t('app.notification.channels.add') : t('app.notification.channels.edit')"
      @closed="resetDrawer">
      <el-form :label-width="$flw('96px')" :disabled="submitting">
        <el-form-item :label="t('app.notification.channels.name')">
          <el-input v-model="drawerForm.name" maxlength="100" :placeholder="t('app.notification.channels.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('app.notification.channels.colType')">
          <el-radio-group v-if="drawerMode === 'create'" v-model="drawerForm.type">
            <el-radio-button v-for="typ in CHANNEL_TYPES" :key="typ" :value="typ">{{ typeLabel(typ) }}</el-radio-button>
          </el-radio-group>
          <span v-else class="ch-muted">{{ typeLabel(drawerForm.type) }}</span>
        </el-form-item>

        <!-- 目标（按类型） -->
        <el-form-item v-if="drawerForm.type === 'webhook'" :label="t('app.notification.channels.targetWebhookUrl')">
          <el-input v-model="drawerForm.targetValue" :placeholder="t('app.notification.channels.targetWebhookPlaceholder')" />
          <div class="ch-hint">{{ t('app.notification.channels.targetWebhookHint') }}</div>
        </el-form-item>
        <el-form-item v-else-if="drawerForm.type === 'email'" :label="t('app.notification.channels.targetEmail')">
          <el-input v-model="drawerForm.targetValue" :placeholder="t('app.notification.channels.targetEmailPlaceholder')" />
          <div class="ch-hint">{{ t('app.notification.channels.targetEmailHint') }}</div>
        </el-form-item>
        <el-form-item v-else-if="drawerForm.type === 'qq'" :label="t('app.notification.channels.targetQQ')">
          <div class="bind-stage">
            <template v-if="!qqBind.qrUrl && !qqBind.bound">
              <p class="bind-hint">{{ t('app.notification.channels.targetQQHint') }}</p>
              <el-button type="primary" :loading="qqBind.loading" @click="generateQQBindCode">
                {{ t('app.notification.channels.qqBindGenerate') }}
              </el-button>
            </template>
            <template v-else-if="qqBind.qrUrl && !qqBind.bound">
              <img v-if="qqBind.qrImg" class="bind-qr" :src="qqBind.qrImg" :alt="t('app.notification.channels.qqBindQrAlt')" />
              <div class="bind-steps">
                <div>1. {{ t('app.notification.channels.qqBindStepScan') }}</div>
                <div>2. {{ t('app.notification.channels.qqBindStepConfirm') }}</div>
                <div>3. {{ t('app.notification.channels.qqBindStepWait') }}</div>
              </div>
              <el-button size="small" @click="generateQQBindCode">{{ t('app.notification.channels.qqBindRegenerate') }}</el-button>
            </template>
            <template v-else>
              <el-tag type="success" effect="light">{{ t('app.notification.channels.qqBoundTag') }}</el-tag>
              <code class="bind-openid">{{ qqBind.openid }}</code>
              <span class="bind-sub">{{ t('app.notification.channels.qqBoundNext') }}</span>
            </template>
          </div>
        </el-form-item>
        <el-form-item v-else :label="t('app.notification.channels.targetWx')">
          <div class="bind-stage">
            <template v-if="!wxBind.botReady">
              <p class="bind-hint">{{ t('app.notification.channels.wxBindHintLogin') }}</p>
              <template v-if="isAdminUser">
                <img v-if="wxLogin.qrImg" class="bind-qr" :src="wxLogin.qrImg" :alt="t('app.notification.creds.wxQrAlt')" />
                <div class="bind-steps">
                  <div>1. {{ t('app.notification.channels.wxBindScanLogin') }}</div>
                  <div>2. {{ t('app.notification.channels.wxBindConfirm') }}</div>
                </div>
                <el-button v-if="wxLogin.expired" size="small" @click="startWxLogin">{{ t('app.notification.creds.wxQrRefresh') }}</el-button>
                <el-button v-else type="primary" :loading="wxLogin.loading" @click="startWxLogin">
                  {{ t('app.notification.creds.wxScanLogin') }}
                </el-button>
              </template>
              <p v-else class="bind-sub">{{ t('app.notification.channels.wxBindNeedAdmin') }}</p>
            </template>
            <template v-else>
              <el-tag v-if="!drawerForm.targetValue" type="warning" effect="light">
                {{ t('app.notification.channels.wxBindSendMessage') }}
              </el-tag>
              <template v-else>
                <el-tag type="success" effect="light">{{ t('app.notification.channels.wxBindCapturedTag') }}</el-tag>
                <code class="bind-openid">{{ drawerForm.targetValue }}</code>
              </template>
              <el-input v-model="drawerForm.targetValue" class="bind-manual"
                :placeholder="t('app.notification.channels.targetWxPlaceholder')">
                <template #prefix><el-icon><ChatLineRound /></el-icon></template>
              </el-input>
              <span class="bind-sub">{{ t('app.notification.channels.wxBindManualHint') }}</span>
              <el-button size="small" link type="primary" @click="startWxLogin">
                {{ t('app.notification.channels.wxReloginBot') }}
              </el-button>
              <template v-if="wxLogin.qrImg">
                <img class="bind-qr" :src="wxLogin.qrImg" :alt="t('app.notification.creds.wxQrAlt')" />
                <span class="bind-sub">{{ t('app.notification.channels.wxBindConfirm') }}</span>
                <el-button v-if="wxLogin.expired" size="small" @click="startWxLogin">{{ t('app.notification.creds.wxQrRefresh') }}</el-button>
              </template>
            </template>
          </div>
        </el-form-item>

        <!-- 消息样式（QQ/微信=内容模板；webhook=载荷模板；邮件=标题+正文模板） -->
        <el-divider class="style-divider" content-position="left">
          {{ t('app.notification.channels.styleSection') }}
        </el-divider>
        <template v-if="drawerForm.type === 'webhook'">
          <el-form-item :label="t('app.notification.channels.stylePayloadTpl')">
            <el-input v-model="drawerForm.style.payload_template" type="textarea" :rows="6" class="mono-input"
              :placeholder="t('app.notification.channels.stylePayloadPlaceholder')" />
            <div class="ph-chips">
              <el-tag v-for="ph in PLACEHOLDERS" :key="ph" size="small" effect="plain" class="ph-chip"
                @click="appendPh('payload_template', ph)">{{ ph }}</el-tag>
            </div>
            <div class="ch-hint">{{ t('app.notification.channels.styleTplHint') }}</div>
          </el-form-item>
        </template>
        <template v-else-if="drawerForm.type === 'email'">
          <el-form-item :label="t('app.notification.channels.styleSubjectTpl')">
            <el-input v-model="drawerForm.style.subject_template"
              :placeholder="t('app.notification.channels.styleSubjectPlaceholder')" />
          </el-form-item>
          <el-form-item :label="t('app.notification.channels.styleBodyTpl')">
            <el-input v-model="drawerForm.style.body_template" type="textarea" :rows="6" class="mono-input"
              :placeholder="t('app.notification.channels.styleBodyPlaceholder')" />
          </el-form-item>
          <el-form-item :label="t('app.notification.channels.styleBodyFormat')">
            <el-radio-group v-model="drawerForm.style.body_format">
              <el-radio value="text">Text</el-radio>
              <el-radio value="html">HTML</el-radio>
            </el-radio-group>
          </el-form-item>
        </template>
        <template v-else-if="drawerForm.type === 'qq'">
          <el-form-item :label="t('app.notification.channels.styleMsgType')">
            <el-radio-group v-model="drawerForm.style.msg_type">
              <el-radio value="text">{{ t('app.notification.channels.styleMsgText') }}</el-radio>
              <el-radio value="markdown">Markdown</el-radio>
            </el-radio-group>
            <div class="ch-hint">{{ t('app.notification.channels.styleMsgMdHint') }}</div>
          </el-form-item>
          <el-form-item :label="t('app.notification.channels.styleContentTpl')">
            <el-input v-model="drawerForm.style.content_template" type="textarea" :rows="4" class="mono-input"
              :placeholder="t('app.notification.channels.styleContentPlaceholder')" />
            <div class="ch-hint">{{ t('app.notification.channels.styleContentHint') }}</div>
          </el-form-item>
        </template>
        <template v-else>
          <el-form-item :label="t('app.notification.channels.styleContentTpl')">
            <el-input v-model="drawerForm.style.content_template" type="textarea" :rows="4" class="mono-input"
              :placeholder="t('app.notification.channels.styleContentPlaceholder')" />
            <div class="ch-hint">{{ t('app.notification.channels.styleContentHint') }}</div>
          </el-form-item>
        </template>
        <el-form-item :label="t('app.notification.channels.styleDailyFormat')">
          <el-select v-model="drawerForm.style.daily_format" class="style-select" clearable placeholder="Auto">
            <el-option value="text" label="Text" />
            <el-option value="markdown" label="Markdown" />
            <el-option value="html" label="HTML" />
            <el-option value="json" label="JSON" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="drawer-footer">
          <el-button v-if="drawerMode === 'edit' && drawerTarget" :loading="testingId === drawerTarget.id" @click="testChannel(drawerTarget)">
            {{ t('app.notification.channels.test') }}
          </el-button>
          <span class="toolbar-spacer" />
          <el-button @click="drawerVisible = false">{{ t('common.app.views.keys.cancel') }}</el-button>
          <el-button type="primary" :loading="submitting" :disabled="!canSave" @click="saveDrawer">
            {{ drawerMode === 'create' ? t('app.notification.channels.submit') : t('common.app.views.keys.save') }}
          </el-button>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ChatDotRound, ChatLineRound, Link, Message } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
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

const CHANNEL_TYPES: readonly NotificationChannelType[] = ['webhook', 'email', 'qq', 'wx_clawbot']
const PLACEHOLDERS = ['{{title}}', '{{body}}', '{{level}}', '{{event}}', '{{time}}', '{{node}}'] as const

const loading = ref(false)
const loadError = ref(false)
const channels = ref<NotificationChannel[]>([])
const filterType = ref<NotificationChannelType | ''>('')
const testingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
let channelsSeq = 0

const writeBlocked = computed(() => authStore.isSlaveNode || authStore.readOnlyReason === 'unknown')
const writeBlockedReason = computed(() =>
  authStore.isSlaveNode ? t('common.app.views.keys.slaveReadOnly') : t('common.app.views.keys.nodeUnknownReadOnly'))
const isAdminUser = computed(() => authStore.user?.role === 'admin')

const typeFilters = computed(() => [
  { key: '' as NotificationChannelType | '', label: t('app.notification.channels.filterAll') },
  ...CHANNEL_TYPES.map((typ) => ({ key: typ as NotificationChannelType | '', label: typeLabel(typ) })),
])
const filteredChannels = computed(() =>
  filterType.value ? channels.value.filter((ch) => ch.type === filterType.value) : channels.value)
const asCh = (row: unknown): NotificationChannel => row as NotificationChannel
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
const displayTarget = (ch: NotificationChannel): string => parseTargetValue(ch) || '-'

const statusDotClass = (ch: NotificationChannel): string =>
  ch.enabled && ch.last_test_ok === true ? 'is-on' : 'is-off'
const testStateText = (ch: NotificationChannel): string => {
  if (!ch.last_test_at) return t('app.notification.channels.neverTested')
  const label = ch.last_test_ok ? t('app.notification.channels.lastTestOk') : t('app.notification.channels.lastTestFail')
  return `${label} · ${fmtTime(ch.last_test_at)}`
}
const testStateClass = (ch: NotificationChannel): string =>
  ch.last_test_ok ? 'test-ok' : 'test-fail'
const fmtTime = (v: string): string => {
  if (!v) return ''
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? v : d.toLocaleString('zh-CN', { hour12: false })
}

const buildTarget = (typ: NotificationChannelType, value: string): string =>
  JSON.stringify({ [targetField(typ)]: value.trim() })

const fetchChannels = async (): Promise<void> => {
  const seq = ++channelsSeq
  loading.value = true
  try {
    const res = await request.get<NotificationChannelsResponse>('/notification/channels')
    if (seq !== channelsSeq) return
    channels.value = res.data?.channels ?? []
    loadError.value = false
  } catch (error: unknown) {
    console.error('Failed to fetch channels:', error)
    if (seq === channelsSeq) loadError.value = true
  } finally {
    if (seq === channelsSeq) loading.value = false
  }
}

// --- 抽屉 ---
const drawerVisible = ref(false)
const drawerMode = ref<'create' | 'edit'>('create')
const drawerTarget = ref<NotificationChannel | null>(null)
const submitting = ref(false)
const emptyStyle = (): Record<string, string> => ({
  payload_template: '', subject_template: '', body_template: '', content_template: '',
  body_format: 'text', msg_type: 'text', daily_format: '',
})
const drawerForm = ref<{ type: NotificationChannelType; name: string; targetValue: string; enabled: boolean; style: Record<string, string> }>({
  type: 'webhook', name: '', targetValue: '', enabled: true, style: emptyStyle(),
})

const appendPh = (field: string, ph: string): void => {
  const cur = drawerForm.value.style[field] ?? ''
  drawerForm.value.style[field] = cur === '' || cur.endsWith(' ') ? cur + ph : `${cur} ${ph}`
}

const canSave = computed(() => {
  if (drawerForm.value.name.trim() === '') return false
  if (drawerForm.value.type === 'qq') {
    return qqBind.value.bound && drawerForm.value.targetValue.trim() !== ''
  }
  return drawerForm.value.targetValue.trim() !== ''
})

const openCreate = (): void => {
  if (writeBlocked.value) return
  drawerMode.value = 'create'
  drawerTarget.value = null
  drawerForm.value = { type: 'webhook', name: '', targetValue: '', enabled: true, style: emptyStyle() }
  drawerVisible.value = true
}

const openEdit = (ch: NotificationChannel): void => {
  if (writeBlocked.value) return
  drawerMode.value = 'edit'
  drawerTarget.value = ch
  let style: Record<string, string> = emptyStyle()
  try {
    style = { ...style, ...(JSON.parse(ch.style_config || '{}') as Record<string, string>) }
  } catch { /* 坏配置=默认 */ }
  drawerForm.value = { type: ch.type, name: ch.name, targetValue: parseTargetValue(ch), enabled: ch.enabled, style }
  drawerVisible.value = true
}

const resetDrawer = (): void => {
  drawerMode.value = 'create'
  drawerTarget.value = null
  drawerForm.value = { type: 'webhook', name: '', targetValue: '', enabled: true, style: emptyStyle() }
  stopWxTimers()
}

const saveDrawer = async (): Promise<void> => {
  if (writeBlocked.value || submitting.value || !canSave.value) return
  submitting.value = true
  try {
    const styleOut: Record<string, string> = {}
    for (const [k, v] of Object.entries(drawerForm.value.style)) {
      if (v !== '' && !(k === 'body_format' && v === 'text') && !(k === 'msg_type' && v === 'text')) styleOut[k] = v
    }
    if (drawerMode.value === 'create') {
      const res = await request.post<NotificationCreateChannelResponse & { data?: { reused?: boolean } }>('/notification/channels', {
        type: drawerForm.value.type,
        name: drawerForm.value.name.trim(),
        target: buildTarget(drawerForm.value.type, drawerForm.value.targetValue),
        style_config: styleOut,
      })
      if (res.data?.reused) {
        ElMessage.info(t('app.notification.channels.reusedHint'))
      } else {
        mfaAwareSuccess(t('app.notification.channels.createSuccess'))
      }
    } else if (drawerTarget.value) {
      await request.put(`/notification/channels/${drawerTarget.value.id}`, {
        name: drawerForm.value.name.trim(),
        target: buildTarget(drawerForm.value.type, drawerForm.value.targetValue),
        enabled: drawerForm.value.enabled,
        style_config: styleOut,
      })
      mfaAwareSuccess(t('app.notification.channels.updateSuccess'))
    }
    drawerVisible.value = false
    await fetchChannels()
  } catch (error: unknown) {
    console.error('Failed to save channel:', error)
  } finally {
    submitting.value = false
  }
}

const testChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || testingId.value !== null) return
  testingId.value = ch.id
  try {
    await request.post(`/notification/channels/${ch.id}/test`)
    mfaAwareSuccess(t('app.notification.channels.testSuccess'))
  } catch (error: unknown) {
    console.error('Failed to test channel:', error)
  } finally {
    testingId.value = null
    await fetchChannels()
  }
}

const deleteChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || deletingIds.value.has(ch.id)) return
  try {
    await ElMessageBox.confirm(t('app.notification.channels.deleteConfirm'), { type: 'warning' })
  } catch {
    return
  }
  deletingIds.value.add(ch.id)
  try {
    await request.delete(`/notification/channels/${ch.id}`)
    mfaAwareSuccess(t('app.notification.channels.deleteSuccess'))
    await fetchChannels()
  } catch (error: unknown) {
    console.error('Failed to delete channel:', error)
  } finally {
    deletingIds.value.delete(ch.id)
  }
}

// --- QQ 扫码 ---
const qqBind = ref<{ qrUrl: string; qrImg: string; openid: string; bound: boolean; loading: boolean; timer: number | null }>({
  qrUrl: '', qrImg: '', openid: '', bound: false, loading: false, timer: null,
})

const generateQQBindCode = async (): Promise<void> => {
  if (qqBind.value.loading) return
  qqBind.value.loading = true
  try {
    const res = await request.post<NotificationCreateChannelResponse & { data: { qr_content: string } }>('/notification/qq/bind-code', {})
    const qrUrl = res.data?.qr_content ?? ''
    qqBind.value.qrUrl = qrUrl
    qqBind.value.qrImg = qrUrl ? await QRCode.toDataURL(qrUrl, { width: 220, margin: 1 }) : ''
    startQQPolling()
  } finally {
    qqBind.value.loading = false
  }
}

const startQQPolling = (): void => {
  if (qqBind.value.timer !== null) return
  let busy = false
  const pollOnce = async (): Promise<void> => {
    if (busy) return
    busy = true
    try {
      const res = await request.get<NotificationCreateChannelResponse & { data: { bound: boolean; openid: string } }>('/notification/qq/bind-code', { silent: true })
      if (res.data?.bound) {
        qqBind.value.bound = true
        qqBind.value.openid = res.data.openid
        drawerForm.value.targetValue = res.data.openid
        if (qqBind.value.timer !== null) {
          window.clearInterval(qqBind.value.timer)
          qqBind.value.timer = null
        }
      }
    } catch {
      // 保持等待；过期由用户重新生成
    } finally {
      busy = false
    }
  }
  void pollOnce()
  const timer = window.setInterval(pollOnce, 3000)
  qqBind.value.timer = timer
  window.setTimeout(() => {
    if (qqBind.value.timer === timer && !qqBind.value.bound) {
      window.clearInterval(timer)
      qqBind.value.timer = null
    }
  }, 10 * 60 * 1000)
}

// --- 微信绑定 ---
const wxBind = ref<{ botReady: boolean; timer: number | null }>({ botReady: false, timer: null })
const wxLogin = ref<{ qrImg: string; loading: boolean; expired: boolean; timer: number | null }>({
  qrImg: '', loading: false, expired: false, timer: null,
})

const refreshWxState = async (): Promise<void> => {
  try {
    const res = await request.get<NotificationCreateChannelResponse & { data: { bot_ready: boolean; receiver: string } }>('/notification/wx/bind-state', { silent: true })
    wxBind.value.botReady = res.data?.bot_ready === true
    if (res.data?.receiver && !drawerForm.value.targetValue) {
      drawerForm.value.targetValue = res.data.receiver
    }
  } catch {
    wxBind.value.botReady = false
  }
}

const startWxPolling = (): void => {
  if (wxBind.value.timer !== null) return
  let busy = false
  const pollOnce = async (): Promise<void> => {
    if (busy) return
    busy = true
    try {
      await refreshWxState()
      if (drawerForm.value.targetValue && wxBind.value.timer !== null) {
        window.clearInterval(wxBind.value.timer)
        wxBind.value.timer = null
      }
    } finally {
      busy = false
    }
  }
  void pollOnce()
  wxBind.value.timer = window.setInterval(pollOnce, 3000)
}

const stopWxTimers = (): void => {
  if (wxBind.value.timer !== null) {
    window.clearInterval(wxBind.value.timer)
    wxBind.value.timer = null
  }
  if (wxLogin.value.timer !== null) {
    window.clearInterval(wxLogin.value.timer)
    wxLogin.value.timer = null
  }
}

const startWxLogin = async (): Promise<void> => {
  if (wxLogin.value.loading) return
  wxLogin.value.loading = true
  wxLogin.value.expired = false
  try {
    const res = await request.post<{ code: number; data?: { qr_content: string } }>('/notification/wx/qr/start', {})
    const qrUrl = res.data?.qr_content ?? ''
    wxLogin.value.qrImg = qrUrl ? await QRCode.toDataURL(qrUrl, { width: 220, margin: 1 }) : ''
    if (wxLogin.value.timer !== null) window.clearInterval(wxLogin.value.timer)
    const timer = window.setInterval(async () => {
      try {
        const st = await request.get<{ code: number; data?: { status: string; confirmed: boolean } }>('/notification/wx/qr/status', { silent: true })
        if (st.data?.confirmed) {
          wxLogin.value.qrImg = ''
          wxLogin.value.expired = false
          window.clearInterval(timer)
          wxLogin.value.timer = null
          wxBind.value.botReady = true
          if (!drawerForm.value.targetValue) startWxPolling()
        } else if (st.data?.status === 'expired') {
          wxLogin.value.expired = true
          window.clearInterval(timer)
          wxLogin.value.timer = null
        }
      } catch {
        // 保持等待
      }
    }, 3000)
    wxLogin.value.timer = timer
  } catch (error: unknown) {
    console.error('Failed to start wx login:', error)
  } finally {
    wxLogin.value.loading = false
  }
}

watch(
  () => [drawerVisible.value, drawerForm.value.type] as const,
  ([visible, typ]) => {
    if (visible && typ === 'wx_clawbot') {
      void refreshWxState().then(() => {
        if (wxBind.value.botReady && !drawerForm.value.targetValue) startWxPolling()
      })
    } else if (!visible) {
      stopWxTimers()
    }
  }
)

onMounted(() => {
  void fetchChannels()
})

defineExpose({ fetchChannels })
</script>

<style scoped>
.ch-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.toolbar-spacer { flex: 1; }
.ch-table { width: 100%; }
.ch-name-cell { display: flex; align-items: center; gap: 6px; min-width: 0; }
.ch-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ch-type-icon { color: var(--el-color-primary); flex: none; }
.ch-muted { color: var(--text-secondary, #6b7280); }
.ch-target { word-break: break-all; }
.ch-masked { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 2px; }
.ch-hint { font-size: 12px; color: var(--text-secondary, #6b7280); margin-top: 4px; line-height: 1.6; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; vertical-align: middle; }
.status-dot.is-on { background: var(--el-color-success); }
.status-dot.is-off { background: var(--el-text-color-disabled); }
.ml4 { margin-left: 4px; }
.row-actions { display: inline-flex; gap: 6px; }
.test-ok { color: var(--el-color-success); font-size: 12px; }
.test-fail { color: var(--el-color-danger); font-size: 12px; }

/* 绑定舞台（抽屉内居中面板） */
.bind-stage {
  display: flex; flex-direction: column; align-items: center; gap: 12px;
  padding: 20px 16px; width: 100%;
  border: 1px dashed var(--el-border-color); border-radius: 8px;
  background: var(--el-fill-color-extra-light); text-align: center;
}
.bind-hint { margin: 0; font-size: 13px; color: var(--text-secondary, #6b7280); line-height: 1.7; }
.bind-sub { font-size: 12px; color: var(--text-secondary, #6b7280); }
.bind-qr { width: 220px; height: 220px; border-radius: 8px; border: 1px solid var(--el-border-color); }
.bind-steps { color: var(--text-secondary, #6b7280); font-size: 13px; line-height: 1.9; text-align: left; }
.bind-openid { word-break: break-all; font-size: 13px; }
.bind-manual { max-width: 320px; }

.style-divider { margin: 10px 0 12px; }
.mono-input :deep(textarea) { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.style-select { width: 220px; }
.ph-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-chip { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.drawer-footer { display: flex; align-items: center; gap: 8px; }
</style>
