<template>
  <div>
    <!-- 通道管理：工具栏入卡头（全站 list-card 规范），类型筛选置卡头 -->
    <el-card class="list-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><ChatDotRound /></el-icon>
            <span>{{ t('app.notification.rules.channelsTab') }}</span>
          </div>
          <div class="card-header-actions">
            <el-radio-group v-model="filterType" size="small">
              <el-radio-button value="">{{ t('app.notification.channels.filterAll') }}</el-radio-button>
              <el-radio-button v-for="typ in CHANNEL_TYPES" :key="typ" :value="typ">{{ typeLabel(typ) }}</el-radio-button>
            </el-radio-group>
            <el-select v-if="isAdminUser" v-model="filterUserId" size="small" clearable :placeholder="t('app.notification.channels.allUsers')" style="width:140px" @change="fetchChannels">
              <el-option v-for="u in userList" :key="u.id" :value="u.id" :label="u.username" />
            </el-select>
            <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
              <div>
                <el-button type="primary" size="small" :disabled="writeBlocked || drawerVisible" @click="openCreate">
                  <el-icon><Plus /></el-icon>
                  {{ t('app.notification.channels.add') }}
                </el-button>
              </div>
            </el-tooltip>
          </div>
        </div>
      </template>

      <!-- 通道卡片网格：统一尺寸/间距/层级（名称+类型 tag / 接收者+传输摘要 / 底栏=测试态+文字操作） -->
      <el-row v-loading="loading" :gutter="16">
        <el-col v-for="ch in filteredChannels" :key="ch.id" :xs="24" :sm="12" :lg="8" class="ch-col">
          <el-card class="ch-card" :class="[`ch-${ch.type}`, { 'ch-disabled': !ch.enabled }]">
            <div class="ch-card-head">
              <div class="ch-icon" :class="`ch-icon-${ch.type}`">
                <el-icon :size="20"><component :is="typeIcon(ch.type)" /></el-icon>
              </div>
              <div class="ch-head-info">
                <div class="ch-name" :title="ch.name">{{ ch.name }}</div>
                <div class="ch-tags">
                  <el-tag size="small" effect="plain" type="info">{{ typeLabel(ch.type) }}</el-tag>
                  <el-tag v-if="!isMine(ch)" size="small" effect="plain">{{ t('app.notification.channels.ownerTag', { id: ch.user_id }) }}</el-tag>
                  <el-tag v-if="rebindIncompleteIds.has(ch.id)" size="small" effect="plain" type="danger">{{ t('app.notification.channels.rebindIncompleteTag') }}</el-tag>
                  <el-tag v-if="!ch.enabled" size="small" effect="plain" type="warning">{{ t('app.notification.channels.disabledTag') }}</el-tag>
                </div>
              </div>
              <el-switch v-model="ch.enabled" size="small" :disabled="writeBlocked" @change="toggleEnabled(ch)" />
            </div>
            <div class="ch-info">
              <div class="ch-target">
                <span class="ch-target-label">{{ targetLabelShort(ch.type) }}</span>
                <code class="ch-target-value" :title="displayTarget(ch)">{{ displayTarget(ch) }}</code>
              </div>
              <div class="ch-transport">
                <span class="ch-transport-label">{{ t('app.notification.channels.transportSection') }}</span>
                <span class="ch-transport-value">{{ transportSummary(ch) }}</span>
              </div>
            </div>
            <div v-if="ch.type === 'wx_clawbot' && !wxSessionOk(ch)" class="info-note-bar rebind-note">
              <span class="info-note-desc">{{ t('app.notification.channels.wxSessionStaleHint') }}</span>
              <el-button size="small" link type="primary" :disabled="writeBlocked" @click="openEdit(ch)">{{ t('app.notification.channels.rebindRetry') }}</el-button>
            </div>
            <div v-if="rebindIncompleteIds.has(ch.id)" class="info-note-bar rebind-note">
              <span class="info-note-desc">{{ t('app.notification.channels.rebindIncompleteHint') }}</span>
              <el-button size="small" link type="primary" :disabled="writeBlocked" @click="openEdit(ch)">{{ t('app.notification.channels.rebindRetry') }}</el-button>
            </div>
            <div class="ch-foot">
              <el-tooltip :content="channelHealthTip(ch)" placement="top">
                <el-tag size="small" effect="plain" :type="channelHealth(ch).type">{{ channelHealth(ch).label }}</el-tag>
              </el-tooltip>
              <span class="ch-verified">{{ ch.last_test_at ? formatDate(ch.last_test_at) : t('app.notification.channels.healthNeverVerified') }}</span>
              <div class="ch-actions">
                <el-button size="small" link type="primary" :loading="testingId === ch.id" :disabled="writeBlocked" @click="testChannel(ch)">
                  {{ t('app.notification.channels.test') }}
                </el-button>
                <el-button size="small" link type="primary" :disabled="writeBlocked" @click="openEdit(ch)">
                  {{ t('app.notification.channels.edit') }}
                </el-button>
                <el-button size="small" link type="danger" :loading="deletingIds.has(ch.id)" :disabled="writeBlocked" @click="deleteChannel(ch)">
                  {{ t('app.notification.channels.delete') }}
                </el-button>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>
      <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
        <template #title>
          <div class="polling-error-title">
            <span>{{ t('app.notification.channels.loadFailed') }}</span>
            <el-button link type="danger" @click="fetchChannels()">{{ t('common.app.views.audit.retryNow') }}</el-button>
          </div>
        </template>
      </el-alert>
      <el-empty v-if="!loading && filteredChannels.length === 0 && !loadError"
        :description="t('app.notification.channels.emptyText')" :image-size="80" />
    </el-card>

    <!-- 编辑弹窗（DialogHeader 规范）：基本信息 + 传输配置分组。
         机器人协议固定（QQ=Markdown/微信=纯文本），无传输配置区；
         webhook 保留 method/headers，email 保留 subject/body_format。 -->
    <el-dialog v-model="drawerVisible" class="dialog-body-inset" width="min(720px, 94vw)" top="6vh"
      :close-on-click-modal="false" @close="resetDrawer">
      <template #header>
        <DialogHeader :icon="editTarget ? Edit : Plus" :title="editTarget ? t('app.notification.channels.edit') : t('app.notification.channels.add')" :subtitle="typeLabel(drawerForm.type)" tone="primary" />
      </template>
      <DialogSectionHeader :title="t('app.notification.channels.configSection')" />
      <el-form :label-width="$flw('110px')" :disabled="saving">
        <el-form-item :label="t('app.notification.channels.name')">
          <el-input v-model="drawerForm.name" maxlength="100" :placeholder="t('app.notification.channels.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('app.notification.channels.colType')">
          <el-radio-group v-if="!editTarget" v-model="drawerForm.type">
            <el-radio-button v-for="typ in CHANNEL_TYPES" :key="typ" :value="typ">{{ typeLabel(typ) }}</el-radio-button>
          </el-radio-group>
          <span v-else>{{ typeLabel(drawerForm.type) }}</span>
        </el-form-item>
        <el-form-item v-if="drawerForm.type === 'webhook' || drawerForm.type === 'email'" :label="targetLabel(drawerForm.type)">
          <el-input v-model="drawerForm.targetValue" :placeholder="targetPlaceholder(drawerForm.type)" />
        </el-form-item>
        <template v-else>
          <el-divider />
          <div class="bind-area bind-center">
            <div class="bind-helper">
              <el-button v-if="bindPhase === 'idle' && !editTarget" size="small" :loading="bindLoading" @click="startBind">{{ t('app.notification.channels.bindGenerate') }}</el-button>
              <el-button v-if="bindPhase === 'idle' && editTarget" size="small" type="primary" plain :loading="rebindStarting" :disabled="writeBlocked" @click="startRebind">{{ t('app.notification.channels.rebindAction') }}</el-button>
              <div v-if="bindPhase === 'idle' && editTarget" class="bind-hint">{{ t('app.notification.channels.rebindIdleHint') }}</div>
              <!-- 重绑暂停提示：连接成功前只说暂停+扫码，不提前要求发送「绑定测试」
                   （指令延迟到 awaiting_message 阶段——用户裁定 2026-11-21）。 -->
              <el-alert v-if="rebindActive && bindPhase !== 'awaiting_message' && bindPhase !== 'confirmed'" type="warning" :closable="false" show-icon class="bind-success-alert">
                <template #title><span v-for="(p, i) in bindParts(t('app.notification.channels.rebindPausedHint'))" :key="i"><b v-if="p.bold">{{ p.text }}</b><template v-else>{{ p.text }}</template></span></template>
              </el-alert>
              <img v-if="bindQrImg" :src="bindQrImg" class="bind-qr-img" />
              <div v-if="bindPhase === 'scanning'" class="bind-hint">{{ t('app.notification.channels.bindScanHint') }}</div>
              <div v-if="bindPhase === 'scanning' && bindQrExpiresAt" class="bind-hint">{{ t('app.notification.channels.bindQrCountdown', { time: bindCountdownText }) }}</div>
              <div v-if="bindPhase === 'scanning' && !bindQrExpiresAt" class="bind-hint">{{ t('app.notification.channels.bindQrWxHint') }}</div>
              <el-alert v-if="bindPhase === 'expired'" type="error" :closable="false" show-icon class="bind-success-alert">
                <template #title>{{ t('app.notification.channels.bindExpiredHint') }}</template>
              </el-alert>
              <el-button v-if="bindPhase === 'expired'" size="small" type="primary" :loading="bindLoading" @click="startBind">{{ t('app.notification.channels.bindRefresh') }}</el-button>
              <el-alert v-if="bindPhase === 'connecting'" type="info" :closable="false" show-icon class="bind-success-alert">
                <template #title>{{ t('app.notification.channels.bindConnecting') }}</template>
              </el-alert>
              <el-alert v-if="bindPhase === 'awaiting_message'" type="warning" :closable="false" show-icon class="bind-success-alert">
                <template #title><span v-for="(p, i) in bindParts(t(rebindActive ? 'app.notification.channels.rebindAwaitMsg' : 'app.notification.channels.bindAwaitMsg'))" :key="i"><b v-if="p.bold">{{ p.text }}</b><template v-else>{{ p.text }}</template></span></template>
              </el-alert>
              <el-alert v-if="bindPhase === 'confirmed'" type="success" :closable="false" show-icon class="bind-success-alert">
                <template #title>{{ t('app.notification.channels.bindConfirmed') }}</template>
              </el-alert>
              <div v-if="bindPhase === 'idle' && drawerForm.type === 'wx_clawbot' && wxAlreadyLoggedIn" class="bind-hint"><span v-for="(p, i) in bindParts(t('app.notification.channels.wxAlreadyLoggedInHint'))" :key="i"><b v-if="p.bold">{{ p.text }}</b><template v-else>{{ p.text }}</template></span></div>
              <div class="bind-hint"><span v-for="(p, i) in bindParts(drawerForm.type === 'qq' ? t('app.notification.channels.qqBindHint') : t('app.notification.channels.wxSendMsgHint'))" :key="i"><b v-if="p.bold">{{ p.text }}</b><template v-else>{{ p.text }}</template></span></div>
            </div>
            <div v-if="drawerForm.targetValue" class="bind-hint bind-receiver">{{ t('app.notification.channels.bindReceiverCaptured', { id: drawerForm.targetValue }) }}</div>
          </div>
        </template>
      </el-form>

      <!-- 传输配置（编辑既有 webhook/email 通道）：请求方式/请求头/标题/正文格式。
           消息正文模板已归通知规则（每通道模板），此处不再编辑模板。 -->
      <template v-if="editTarget && (drawerForm.type === 'webhook' || drawerForm.type === 'email')">
        <DialogSectionHeader :title="t('app.notification.channels.transportSection')" class="ch-form-section" />
        <el-form :label-width="$flw('110px')" :disabled="saving">
          <template v-if="drawerForm.type === 'webhook'">
            <el-form-item :label="t('app.notification.channels.styleMethod')">
              <div class="field-col">
                <el-radio-group v-model="styleForm.method" size="small">
                  <el-radio-button value="POST">POST</el-radio-button>
                  <el-radio-button value="GET">GET</el-radio-button>
                </el-radio-group>
                <div class="form-hint">{{ t('app.notification.channels.styleMethodHint') }}</div>
              </div>
            </el-form-item>
            <el-form-item :label="t('app.notification.channels.styleHeaders')" class="headers-form-item">
              <div class="header-rows">
                <div v-for="(row, i) in headerRows" :key="i" class="header-row">
                  <el-select v-model="row.name" size="small" filterable allow-create default-first-option :placeholder="t('app.notification.channels.styleHeaderName')" class="header-name">
                    <el-option v-for="h in WEBHOOK_HEADER_PRESETS" :key="h" :value="h" :label="h" />
                  </el-select>
                  <el-input v-model="row.value" size="small" :placeholder="t('app.notification.channels.styleHeaderValue')" class="header-value" />
                  <el-button size="small" link type="danger" class="header-del" @click="removeHeaderRow(i)">{{ t('app.notification.channels.delete') }}</el-button>
                </div>
                <div class="header-foot">
                  <el-button size="small" link type="primary" :disabled="headerRows.length >= 8" @click="addHeaderRow">+ {{ t('app.notification.channels.styleHeaderAdd') }}</el-button>
                  <span class="form-hint">{{ t('app.notification.channels.styleHeadersHint') }}</span>
                </div>
              </div>
            </el-form-item>
          </template>
          <template v-else>
            <el-form-item :label="t('app.notification.channels.styleSubjectTpl')">
              <el-input v-model="styleForm.subject_template" :placeholder="t('app.notification.channels.styleSubjectPlaceholder')" />
            </el-form-item>
            <el-form-item :label="t('app.notification.channels.styleBodyFormat')">
              <el-radio-group v-model="styleForm.body_format" size="small">
                <el-radio-button value="text">{{ t('app.notification.channels.styleFormatText') }}</el-radio-button>
                <el-radio-button value="html">{{ t('app.notification.channels.styleFormatHtml') }}</el-radio-button>
              </el-radio-group>
            </el-form-item>
          </template>
          <div class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.channels.transportMovedHint') }}</span></div>
        </el-form>
      </template>
      <div v-else-if="editTarget" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.channels.botProtocolHint') }}</span></div>
      <template #footer>
        <el-button @click="drawerVisible = false">{{ t('app.notification.channels.cancel') }}</el-button>
        <el-button type="primary" :loading="saving" :disabled="!canSave || rebindActive" @click="saveDrawer">{{ t('app.notification.channels.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChatDotRound, ChatLineRound, Edit, Link, Message, Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { formatDate } from '@/utils/date'
import { request, mfaAwareSuccess } from '@/utils/api'
import { safeLocalStorageGet, safeLocalStorageSet } from '@/utils/safeWebStorage'
import { useAuthStore } from '@/stores/auth'
import {
  buildChannelStyleConfig, channelStyleExtras, channelStyleFormFrom, emptyChannelStyleForm, parseStyleConfig,
} from '@/utils/channelStyle'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import type { NotificationChannel, NotificationChannelType, NotificationChannelsResponse } from '@/types/notifications.ts'

const { t } = useI18n()
const authStore = useAuthStore()

const CHANNEL_TYPES: readonly NotificationChannelType[] = ['webhook', 'email', 'qq', 'wx_clawbot']

const loading = ref(false)
const loadError = ref(false)
const channels = ref<NotificationChannel[]>([])
const filterType = ref<NotificationChannelType | ''>('')
const filterUserId = ref<number | ''>('')
const userList = ref<{ id: number; username: string }[]>([])
const isAdminUser = computed(() => authStore.user?.role === 'admin')
const testingId = ref<number | null>(null)
const deletingIds = ref(new Set<number>())
const drawerVisible = ref(false)
const editTarget = ref<NotificationChannel | null>(null)
let fetchSeq = 0

// 重新扫码绑定（编辑态机器人通道）：记旧 target 供失败回滚；未完成标记按
// 通道 id 持久化（旧 bot 不可用→保持停用，不静默丢，卡片提示重试）。
const REBIND_INCOMPLETE_KEY = 'lb.notification.rebind_incomplete'
interface RebindState {
  channelId: number
  channelType: NotificationChannelType
  oldTarget: string
}
const rebind = ref<RebindState | null>(null)
const rebindActive = computed(() => rebind.value !== null)
const rebindStarting = ref(false)
const rebindIncompleteIds = ref(new Set<number>())
let rebindTimer: ReturnType<typeof setTimeout> | null = null
let rebindFinalizing = false
const loadRebindIncomplete = (): void => {
  const raw = safeLocalStorageGet(REBIND_INCOMPLETE_KEY)
  if (!raw) return
  try {
    const parsed = JSON.parse(raw) as unknown
    if (Array.isArray(parsed)) {
      rebindIncompleteIds.value = new Set(parsed.filter((v): v is number => typeof v === 'number'))
    }
  } catch { /* 坏值按空集 */ }
}
const markRebindIncomplete = (id: number, on: boolean): void => {
  const next = new Set(rebindIncompleteIds.value)
  if (on) next.add(id)
  else next.delete(id)
  rebindIncompleteIds.value = next
  safeLocalStorageSet(REBIND_INCOMPLETE_KEY, JSON.stringify([...next]))
}

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

// 卡片传输摘要（机器人协议固定：QQ=Markdown、微信=纯文本；webhook=请求方式、email=正文格式）
const transportSummary = (ch: NotificationChannel): string => {
  let sc: Record<string, string> = {}
  try { sc = JSON.parse(ch.style_config || '{}') as Record<string, string> } catch { sc = {} }
  if (ch.type === 'webhook') return (sc.method || 'POST').toUpperCase()
  if (ch.type === 'email') return sc.body_format === 'html' ? 'HTML' : t('app.notification.channels.styleFormatText')
  if (ch.type === 'qq') return 'Markdown'
  return t('app.notification.channels.styleFormatText') // 微信 iLink 仅文本
}

// 「绑定测试」关键词加粗（提示更醒目，降低困惑）。
const bindParts = (s: string): { text: string; bold: boolean }[] => {
  const parts: { text: string; bold: boolean }[] = []
  const kw = '绑定测试'
  let rest = s
  let idx = rest.indexOf(kw)
  while (idx >= 0) {
    if (idx > 0) parts.push({ text: rest.slice(0, idx), bold: false })
    parts.push({ text: kw, bold: true })
    rest = rest.slice(idx + kw.length)
    idx = rest.indexOf(kw)
  }
  if (rest) parts.push({ text: rest, bold: false })
  return parts
}
// 复合健康态（单一事实呈现，避免「在线+就绪+测试失败」自相矛盾）：
// disabled > link_down > session_stale(wx) > test_failed > unverified > ready
type HealthState = 'disabled' | 'link_down' | 'session_stale' | 'test_failed' | 'unverified' | 'ready'
const channelHealth = (ch: NotificationChannel): { state: HealthState; label: string; type: 'info' | 'success' | 'warning' | 'danger' } => {
  if (!ch.enabled) return { state: 'disabled', label: t('app.notification.channels.healthDisabled'), type: 'info' }
  if ((ch.type === 'qq' || ch.type === 'wx_clawbot') && ch.link_connected === false) {
    return { state: 'link_down', label: t('app.notification.channels.healthLinkDown'), type: 'danger' }
  }
  if (ch.type === 'wx_clawbot' && !wxSessionOk(ch)) {
    return { state: 'session_stale', label: t('app.notification.channels.healthSessionStale'), type: 'warning' }
  }
  if (ch.last_test_ok === false) return { state: 'test_failed', label: t('app.notification.channels.healthTestFailed'), type: 'danger' }
  if (!ch.last_test_at) return { state: 'unverified', label: t('app.notification.channels.healthUnverified'), type: 'info' }
  return { state: 'ready', label: t('app.notification.channels.healthReady'), type: 'success' }
}
const channelHealthTip = (ch: NotificationChannel): string => {
  const verified = ch.last_test_at ? formatDate(ch.last_test_at) : t('app.notification.channels.healthNeverVerified')
  return t('app.notification.channels.healthTooltip', { state: channelHealth(ch).label, time: verified })
}
const wxSessionOk = (ch: NotificationChannel): boolean => ch.session_ready === true && ch.last_test_ok !== false

const fetchChannels = async (silent = false): Promise<void> => {
  const seq = ++fetchSeq
  if (!silent) loading.value = true
  try {
    const url = filterUserId.value ? `/notification/channels?user_id=${filterUserId.value}` : '/notification/channels'
    const res = await request.get<NotificationChannelsResponse>(url)
    if (seq !== fetchSeq) return
    channels.value = res.data?.channels ?? []
    // 已恢复投递且测试通过=重绑闭环，清理陈旧未完成标记。
    if (rebindIncompleteIds.value.size) {
      for (const c of channels.value) {
        if (c.enabled && c.last_test_ok && rebindIncompleteIds.value.has(c.id)) markRebindIncomplete(c.id, false)
      }
    }
    loadError.value = false
  } catch {
    if (seq === fetchSeq) loadError.value = true
  } finally {
    if (seq === fetchSeq) loading.value = false
  }
}

const drawerForm = ref({ type: 'webhook' as NotificationChannelType, name: '', targetValue: '' })
const saving = ref(false)
const canSave = computed(() => {
  if (drawerForm.value.name.trim() === '') return false
  const typ = drawerForm.value.type
  // 机器人通道新建：须绑定会话 confirmed（收到「绑定测试」）才允许保存。
  if ((typ === 'qq' || typ === 'wx_clawbot') && !editTarget.value) {
    return bindPhase.value === 'confirmed' && drawerForm.value.targetValue.trim() !== ''
  }
  return drawerForm.value.targetValue.trim() !== ''
})

// 传输配置表单（键白名单=后端 validateChannelStyle；模板键保留回填不编辑——
// 正文模板已归通知规则，保存时原样透传既有模板键避免覆盖丢失。
// 机器人协议固定：QQ 恒 msg_type=markdown，微信纯文本，无表单控件）
interface HeaderRow { name: string; value: string }
// webhook 请求头预设（后端白名单同口径）：下拉选择+可创建 X-* 自定义头。
const WEBHOOK_HEADER_PRESETS = ['Authorization', 'X-API-Key', 'Content-Type', 'Accept', 'User-Agent']
const styleForm = ref(emptyChannelStyleForm())
// 表单不认识的既有 style_config 键（daily_mode 等）——全量覆盖保存必须原样带回，
// 否则保存一次就抹掉日报渲染模式（见 utils/channelStyle.ts 契约说明）。
const styleExtras = ref<Record<string, unknown>>({})
const headerRows = ref<HeaderRow[]>([])
const addHeaderRow = (): void => { if (headerRows.value.length < 8) headerRows.value.push({ name: '', value: '' }) }
const removeHeaderRow = (i: number): void => { headerRows.value.splice(i, 1) }
const buildStyleConfig = (): Record<string, unknown> => {
  const headers: Record<string, string> = {}
  for (const row of headerRows.value) {
    if (row.name.trim() && row.value.trim()) headers[row.name.trim()] = row.value.trim()
  }
  return buildChannelStyleConfig(drawerForm.value.type, styleForm.value, headers, styleExtras.value)
}

const targetLabel = (typ: NotificationChannelType): string => {
  const map: Record<string, string> = { webhook: t('app.notification.channels.targetWebhookUrl'), email: t('app.notification.channels.targetEmail'), qq: t('app.notification.channels.targetQQ'), wx_clawbot: t('app.notification.channels.targetWx') }
  return map[typ] ?? 'Target'
}
const targetPlaceholder = (typ: NotificationChannelType): string => {
  const map: Record<string, string> = { webhook: t('app.notification.channels.targetWebhookPlaceholder'), email: t('app.notification.channels.targetEmailPlaceholder') }
  return map[typ] ?? ''
}

const saveDrawer = async (): Promise<void> => {
  if (saving.value || !canSave.value) return
  // 操作确认标准：保存写库需弹框确认。
  try {
    await ElMessageBox.confirm(t('app.notification.channels.saveConfirm'), t('app.notification.channels.confirmTitle'), { type: 'warning' })
  } catch { return }
  saving.value = true
  try {
    // 编辑目标必须在任何 await 之前捕获：抽屉关闭（drawerVisible=false →
    // resetDrawer）会把 editTarget 清空，保存后才判 `editTarget.value` 恒为
    // null，机器人通道的「保存即自动测试」整段被跳过（静默不回测）。
    const editing = editTarget.value
    const key = { webhook: 'url', email: 'email', qq: 'openid', wx_clawbot: 'receiver' }[drawerForm.value.type] ?? 'target'
    const target = JSON.stringify({ [key]: drawerForm.value.targetValue.trim() })
    if (editing) {
      // 编辑：名称/目标/样式一次提交（样式全量覆盖=所见即所存）
      await request.put(`/notification/channels/${editing.id}`, {
        name: drawerForm.value.name.trim(),
        target,
        style_config: buildStyleConfig(),
      })
      mfaAwareSuccess(t('app.notification.channels.updateSuccess'))
    } else {
      const res = await request.post<{ data?: { id?: number; reused?: boolean } }>('/notification/channels', { type: drawerForm.value.type, name: drawerForm.value.name.trim(), target })
      mfaAwareSuccess(res.data?.reused ? t('app.notification.channels.reusedHint') : t('app.notification.channels.createSuccess'))
      const newId = res.data?.id
      const reused = res.data?.reused === true
      drawerVisible.value = false
      await fetchChannels()
      // 新建保存即自动测试：立即验证可达性并刷新测试态（复用既有通道不重复测试）
      if (newId && !reused) {
        const created = channels.value.find(c => c.id === newId)
        if (created) await doTestChannel(created)
      }
      return
    }
    drawerVisible.value = false
    await fetchChannels()
    // 机器人通道保存后自动测试：按捕获的编辑目标类型判定（关闭抽屉已清
    // editTarget，用 target 判型才能稳定触发），绑定「绑定测试」确认后立即
    // 验证可达性，无需手动点测试。
    if (editing.type === 'qq' || editing.type === 'wx_clawbot') {
      const cur = channels.value.find(c => c.id === editing.id)
      if (cur) await doTestChannel(cur)
    }
  } catch (e) { console.error(e) } finally { saving.value = false }
}

const bindLoading = ref(false)
const bindQrImg = ref('')
// 绑定会话状态机：idle→scanning（扫码）→connecting（连接测试）→awaiting_message
// （待发送「绑定测试」）→confirmed（入站确认+品牌回复，允许保存）。
const bindPhase = ref<'idle' | 'scanning' | 'connecting' | 'awaiting_message' | 'confirmed' | 'expired'>('idle')
const bindScannerID = ref('')
const bindBotKey = ref('')
const bindQrExpiresAt = ref<number | null>(null) // QQ 已知 TTL（expires_in）；wx 服务端驱动=null
const bindQrLeft = ref(0)
let bindCountTimer: ReturnType<typeof setInterval> | null = null
const bindCountdownText = computed(() => {
  const s = Math.max(0, bindQrLeft.value)
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`
})
// QQ 产码带 expires_in→倒计时，归零置 expired；wx 无客户端 TTL→不倒计时（提示尽快扫码）。
const startQrCountdown = (expiresIn: number | undefined): void => {
  if (bindCountTimer) { clearInterval(bindCountTimer); bindCountTimer = null }
  if (!expiresIn) { bindQrExpiresAt.value = null; return }
  bindQrExpiresAt.value = Date.now() + expiresIn * 1000
  bindQrLeft.value = expiresIn
  bindCountTimer = setInterval(() => {
    bindQrLeft.value = Math.max(0, Math.round(((bindQrExpiresAt.value ?? 0) - Date.now()) / 1000))
    if (bindQrLeft.value <= 0) {
      if (bindCountTimer) { clearInterval(bindCountTimer); bindCountTimer = null }
      if (bindPhase.value === 'scanning') { bindPhase.value = 'expired'; bindQrImg.value = ''; stopBindPolling() }
    }
  }, 1000)
}
const wxAlreadyLoggedIn = ref(false) // 全局已有微信登录态→提示无需重复扫码
const checkWxLoggedIn = async (): Promise<void> => {
  try {
    const res = await request.get<{ data?: { bot_ready?: boolean } }>('/notification/wx/bind-state', { silent: true })
    wxAlreadyLoggedIn.value = res.data?.bot_ready === true
  } catch { wxAlreadyLoggedIn.value = false }
}
// 切换通道类型：重置绑定态；切到微信探测全局登录态（提示无需重复扫码）。
watch(() => drawerForm.value.type, (typ) => {
  bindPhase.value = 'idle'
  bindRegistered = false
  bindScannerID.value = ''
  bindBotKey.value = ''
  bindQrImg.value = ''
  bindQrExpiresAt.value = null
  stopBindPolling()
  if (typ === 'wx_clawbot') void checkWxLoggedIn()
  else wxAlreadyLoggedIn.value = false
})
const startBind = async (): Promise<boolean> => {
  bindLoading.value = true
  bindPhase.value = 'scanning'
  bindRegistered = false
  try {
    const endpoint = drawerForm.value.type === 'qq' ? '/notification/qq/bind-code' : '/notification/wx/qr/start'
    const res = await request.post<{ data?: { qr_content?: string; expires_in?: number } }>(endpoint, {})
    const qrUrl = res.data?.qr_content ?? ''
    if (!qrUrl) {
      bindPhase.value = 'idle'
      return false
    }
    const QRCode = (await import('qrcode')).default
    bindQrImg.value = await QRCode.toDataURL(qrUrl, { width: 200, margin: 1 })
    pollScan()
    startQrCountdown(Math.min(res.data?.expires_in ?? 300, 300)) // 统一 5min；wx 服务端更早 expired 优先
    return true
  } catch (e) {
    console.error(e)
    bindPhase.value = 'idle'
    return false
  } finally { bindLoading.value = false }
}
let bindTimer: ReturnType<typeof setInterval> | null = null
let bindTimeout: ReturnType<typeof setTimeout> | null = null
const stopBindPolling = (): void => {
  if (bindTimer !== null) { clearInterval(bindTimer); bindTimer = null }
  if (bindTimeout !== null) { clearTimeout(bindTimeout); bindTimeout = null }
  if (bindCountTimer !== null) { clearInterval(bindCountTimer); bindCountTimer = null }
}
// 扫码轮询（顺序 setTimeout 链：wx qr/status 为长轮询 ≤40s，setInterval 会并发
// 堆积且 confirmed 时多回调重复注册；顺序轮询避免）。confirmed/bound/expired 即停。
const pollScan = (): void => {
  stopBindPolling()
  const isQQ = drawerForm.value.type === 'qq'
  const tick = async (): Promise<void> => {
    try {
      if (isQQ) {
        const res = await request.get<{ data?: { bound?: boolean; openid?: string; appid?: string; expired?: boolean; status?: number } }>('/notification/qq/bind-code', { silent: true })
        if (res.data?.bound && res.data?.openid) {
          bindScannerID.value = res.data.openid
          bindBotKey.value = res.data.appid ?? ''
          drawerForm.value.targetValue = res.data.openid
          bindQrImg.value = ''
          stopBindPolling()
          void registerBindSession()
          return
        } else if (res.data?.expired || res.data?.status === 3) {
          bindPhase.value = 'expired'; bindQrImg.value = ''; stopBindPolling(); return
        }
      } else {
        const qs = await request.get<{ data?: { confirmed?: boolean; scanner_id?: string; bot_key?: string; status?: string } }>('/notification/wx/qr/status', { silent: true })
        if (qs.data?.confirmed) {
          bindScannerID.value = qs.data.scanner_id ?? ''
          bindBotKey.value = qs.data.bot_key ?? ''
          drawerForm.value.targetValue = qs.data.scanner_id ?? ''
          bindQrImg.value = ''
          stopBindPolling()
          void registerBindSession()
          return
        } else if (qs.data?.status === 'expired') {
          bindPhase.value = 'expired'; bindQrImg.value = ''; stopBindPolling(); return
        }
      }
    } catch { /* keep polling */ }
    bindTimer = setTimeout(() => { void tick() }, 3000)
  }
  bindTimer = setTimeout(() => { void tick() }, 1000)
  bindTimeout = setTimeout(() => { stopBindPolling(); if (bindPhase.value === 'scanning') bindPhase.value = 'expired' }, 300000)
}
// 注册绑定会话→连接测试→轮询入站「绑定测试」确认（bindRegistered 防重复注册）。
let bindRegistered = false
const registerBindSession = async (): Promise<void> => {
  if (bindRegistered) return
  bindRegistered = true
  bindPhase.value = 'connecting'
  try {
    await request.post('/notification/bind-session', { type: drawerForm.value.type, scanner_id: bindScannerID.value, bot_key: bindBotKey.value }, { silent: true })
  } catch { /* 仍轮询 */ }
  pollBindSession()
}
const pollBindSession = (): void => {
  stopBindPolling()
  const q = `/notification/bind-session?type=${encodeURIComponent(drawerForm.value.type)}&scanner_id=${encodeURIComponent(bindScannerID.value)}&bot_key=${encodeURIComponent(bindBotKey.value)}`
  const tick = async (): Promise<void> => {
    try {
      const res = await request.get<{ data?: { phase?: string; receiver?: string; connected?: boolean } }>(q, { silent: true })
      const d = res.data
      if (d?.phase === 'confirmed') {
        bindPhase.value = 'confirmed'
        if (d.receiver) drawerForm.value.targetValue = d.receiver
        stopBindPolling()
        return
      }
      bindPhase.value = d?.connected ? 'awaiting_message' : 'connecting'
    } catch { /* keep polling */ }
    bindTimer = setTimeout(() => { void tick() }, 2500)
  }
  bindTimer = setTimeout(() => { void tick() }, 500)
  bindTimeout = setTimeout(stopBindPolling, 600000)
}
onUnmounted(() => {
  stopBindPolling()
  clearRebindTimer()
})

const cleanupBindSession = async (): Promise<void> => {
  // 清理后端绑定会话+待绑定凭据，防幽灵入站连接（未保存通道的 bot）。
  // 先同步捕获并复位本地态，再等 DELETE 完成（回滚/落库前的顺序保证）。
  const scannerID = bindScannerID.value
  if (!bindRegistered || !scannerID) return
  const type = drawerForm.value.type
  const botKey = bindBotKey.value
  bindRegistered = false
  bindScannerID.value = ''
  bindBotKey.value = ''
  try {
    await request.delete(`/notification/bind-session?type=${encodeURIComponent(type)}&scanner_id=${encodeURIComponent(scannerID)}&bot_key=${encodeURIComponent(botKey)}`, { silent: true })
  } catch { /* 会话可能已过期：忽略 */ }
}

const clearRebindTimer = (): void => {
  if (rebindTimer !== null) { clearTimeout(rebindTimer); rebindTimer = null }
}
// 旧 bot 可用性探测：通道 target 未改动，link/session/test 字段即旧 bot 现状。
const botChannelAvailable = (ch: NotificationChannel | undefined): boolean => {
  if (!ch) return false
  if (ch.link_connected === true) return true
  if (ch.type === 'wx_clawbot' && ch.session_ready === true) return true
  return ch.last_test_ok === true
}
// 重绑未完成（弹框关闭/扫码超时/未 confirmed/中途失败）：按旧 bot 可用性回滚，
// 旧 bot 不可用则保持停用并标记未完成（不静默丢旧 target），提示重试。
const revertRebind = async (rb: RebindState): Promise<void> => {
  await fetchChannels(true)
  const ch = channels.value.find(c => c.id === rb.channelId)
  if (!ch) { markRebindIncomplete(rb.channelId, false); return }
  if (botChannelAvailable(ch)) {
    try {
      await request.put(`/notification/channels/${rb.channelId}`, { target: rb.oldTarget, enabled: true })
      markRebindIncomplete(rb.channelId, false)
      mfaAwareSuccess(t('app.notification.channels.rebindRollbackOk'))
    } catch (e) {
      console.error(e)
      markRebindIncomplete(rb.channelId, true)
      ElMessage.error(t('app.notification.channels.rebindRollbackFailed'))
    }
  } else {
    try {
      await request.put(`/notification/channels/${rb.channelId}`, { enabled: false })
    } catch (e) { console.error(e) }
    markRebindIncomplete(rb.channelId, true)
    ElMessage.warning(t('app.notification.channels.rebindIncompleteWarn'))
  }
  await fetchChannels(true)
}
const abortRebind = async (): Promise<void> => {
  const rb = rebind.value
  if (!rb) return
  rebind.value = null
  clearRebindTimer()
  stopBindPolling()
  // 先清绑定会话/待钉凭据，再回滚 target：防 wx 回滚 PUT 误钉本轮新扫凭据。
  await cleanupBindSession()
  bindQrImg.value = ''
  bindQrExpiresAt.value = null
  bindPhase.value = 'idle'
  await revertRebind(rb)
}
// confirmed（收到「绑定测试」入站）→ 落新 target 并恢复投递。
const finalizeRebind = async (): Promise<void> => {
  const rb = rebind.value
  if (!rb || rebindFinalizing) return
  const newTarget = drawerForm.value.targetValue.trim()
  if (!newTarget) { await abortRebind(); return }
  rebindFinalizing = true
  clearRebindTimer()
  try {
    const target = JSON.stringify({ [targetField(rb.channelType)]: newTarget })
    await request.put(`/notification/channels/${rb.channelId}`, { target, enabled: true })
    // 新 target 已落库（凭据已钉住），再清绑定会话/待钉凭据。
    await cleanupBindSession()
    markRebindIncomplete(rb.channelId, false)
    rebind.value = null
    mfaAwareSuccess(t('app.notification.channels.rebindSuccess'))
    drawerVisible.value = false
    await fetchChannels()
  } catch (e) {
    console.error(e)
    ElMessage.error(t('app.notification.channels.rebindSaveFailed'))
    await abortRebind()
  } finally { rebindFinalizing = false }
}
const startRebind = async (): Promise<void> => {
  const ch = editTarget.value
  if (!ch || (ch.type !== 'qq' && ch.type !== 'wx_clawbot')) return
  if (rebind.value || rebindStarting.value || writeBlocked.value) return
  // 旧 target 必须可解析且带接收者键（非属主脱敏/损坏值无法回滚，拒绝进入流程）。
  let readable = false
  try {
    const parsed = JSON.parse(ch.target) as Record<string, unknown>
    readable = typeof parsed[targetField(ch.type)] === 'string'
  } catch { readable = false }
  if (!readable) {
    ElMessage.error(t('app.notification.channels.rebindTargetUnreadable'))
    return
  }
  try {
    await ElMessageBox.confirm(t('app.notification.channels.rebindConfirm'), t('app.notification.channels.confirmTitle'), { type: 'warning' })
  } catch { return }
  rebindStarting.value = true
  rebind.value = { channelId: ch.id, channelType: ch.type, oldTarget: ch.target }
  try {
    // 先暂停投递（target 保持旧值，任何失败都可原样回滚）。
    await request.put(`/notification/channels/${ch.id}`, { enabled: false })
    ch.enabled = false
    rebindTimer = setTimeout(() => { void abortRebind() }, 600000)
    const started = await startBind()
    if (!started) {
      ElMessage.error(t('app.notification.channels.rebindQrFailed'))
      await abortRebind()
    }
  } catch (e) {
    console.error(e)
    ElMessage.error(t('app.notification.channels.rebindPauseFailed'))
    // 请求结果不确定（可能已在服务端生效）：按旧 bot 可用性对账回滚/标记。
    await abortRebind()
  } finally { rebindStarting.value = false }
}
watch(bindPhase, (phase) => {
  if (!rebind.value) return
  if (phase === 'confirmed') void finalizeRebind()
  else if (phase === 'expired') void abortRebind()
})

const resetDrawer = (): void => {
  if (rebind.value && !rebindFinalizing) {
    // 弹框关闭=重绑未完成：先按旧机器人可用性回滚/标记，再复位表单。
    void abortRebind()
  } else if (!rebind.value) {
    stopBindPolling()
    void cleanupBindSession()
  }
  // 重绑落库中（rebindFinalizing）：绑定清理由 finalizeRebind 收口，避免抢跑清 pin。
  bindQrImg.value = ''
  bindQrExpiresAt.value = null
  bindPhase.value = 'idle'
  bindRegistered = false
  bindScannerID.value = ''
  bindBotKey.value = ''
  wxAlreadyLoggedIn.value = false
  drawerForm.value = { type: 'webhook', name: '', targetValue: '' }
  styleForm.value = emptyChannelStyleForm()
  styleExtras.value = {}
  headerRows.value = []
  editTarget.value = null
}

const openCreate = (): void => {
  editTarget.value = null
  drawerVisible.value = true
}

const openEdit = (ch: NotificationChannel): void => {
  editTarget.value = ch
  drawerForm.value = { type: ch.type, name: ch.name, targetValue: parseTargetValue(ch) }
  if (ch.type === 'wx_clawbot') void checkWxLoggedIn()
  // 回填既有样式（style_config JSON → 表单；缺省键=默认形态；未知键进
  // styleExtras 原样带回，保存不得抹掉）
  const s = channelStyleFormFrom(ch.style_config)
  const rows: HeaderRow[] = []
  const parsedHeaders = parseStyleConfig(ch.style_config).headers
  if (parsedHeaders && typeof parsedHeaders === 'object') {
    for (const [hk, hv] of Object.entries(parsedHeaders as Record<string, unknown>)) {
      if (typeof hv === 'string') rows.push({ name: hk, value: hv })
    }
  }
  styleForm.value = s
  styleExtras.value = channelStyleExtras(ch.style_config)
  headerRows.value = rows
  drawerVisible.value = true
}

const toggleEnabled = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value) return
  const target = ch.enabled
  // 操作确认标准：启用/禁用属状态变更，需弹框确认；取消回滚开关。
  try {
    await ElMessageBox.confirm(
      target ? t('app.notification.channels.enableConfirm', { name: ch.name }) : t('app.notification.channels.disableConfirm', { name: ch.name }),
      t('app.notification.channels.confirmTitle'), { type: 'warning' })
  } catch { ch.enabled = !target; return }
  try {
    await request.put(`/notification/channels/${ch.id}`, { enabled: target })
    if (target) markRebindIncomplete(ch.id, false)
    await fetchChannels() // 刷新连接/会话/测试态，状态准确
    // 启用即复验：主动测一次使状态从「未验证」变为真实结果（失败给出引导）
    if (target && (ch.type === 'qq' || ch.type === 'wx_clawbot')) {
      const cur = channels.value.find(c => c.id === ch.id)
      if (cur) await doTestChannel(cur)
    }
  } catch {
    ch.enabled = !target
  }
}

const doTestChannel = async (ch: NotificationChannel): Promise<void> => {
  testingId.value = ch.id
  try {
    await request.post(`/notification/channels/${ch.id}/test`, {}, { silent: true })
    mfaAwareSuccess(t('app.notification.channels.testSuccess'))
  } catch {
    ElMessage.error(t('app.notification.channels.testFailed'))
  } finally {
    testingId.value = null
    await fetchChannels()
  }
}
const testChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || testingId.value !== null) return
  // 操作确认标准：测试会真实外发消息，需弹框确认。
  try {
    const msg = (ch.type === 'wx_clawbot' && !ch.session_ready)
      ? t('app.notification.channels.testConfirmWxNoSession', { name: ch.name })
      : t('app.notification.channels.testConfirm', { name: ch.name })
    await ElMessageBox.confirm(msg, t('app.notification.channels.confirmTitle'), { type: 'warning' })
  } catch { return }
  await doTestChannel(ch)
}

const deleteChannel = async (ch: NotificationChannel): Promise<void> => {
  if (writeBlocked.value || deletingIds.value.has(ch.id)) return
  try {
    await ElMessageBox.confirm(t('app.notification.channels.deleteConfirm'), t('app.notification.channels.delete'), { type: 'warning' })
  } catch { return }
  deletingIds.value.add(ch.id)
  try {
    await request.delete(`/notification/channels/${ch.id}`)
    markRebindIncomplete(ch.id, false)
    mfaAwareSuccess(t('app.notification.channels.deleteSuccess'))
    await fetchChannels()
  } catch { /* handled */ }
  finally {
    deletingIds.value.delete(ch.id)
  }
}

let linkPoll: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  loadRebindIncomplete()
  void fetchChannels()
  // 实时连接态：常驻入站会话在线态周期刷新（静默，不闪 loading）。
  linkPoll = setInterval(() => { void fetchChannels(true) }, 15000)
  if (isAdminUser.value) {
    request.get<{ data?: { users: { id: number; username: string }[] } }>('/notification/admin/overview', { silent: true })
      .then(r => { userList.value = r.data?.users ?? [] }).catch(() => {})
  }
})
onUnmounted(() => { if (linkPoll) clearInterval(linkPoll) })

defineExpose({ fetchChannels })
</script>

<style scoped>
.el-card { --el-card-border-color: #ebeef5; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }

/* 通道卡片：等高网格（flex 列齐高），统一间距/层级，全站直角 */
.ch-col { margin-bottom: 16px; display: flex; }
.ch-card { width: 100%; margin-bottom: 0; display: flex; flex-direction: column; }
.ch-card :deep(.el-card__body) { padding: 16px; flex: 1; display: flex; flex-direction: column; }
.ch-disabled { opacity: 0.6; }

.ch-card-head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.ch-icon {
  width: 40px; height: 40px; border-radius: 0;
  display: flex; align-items: center; justify-content: center;
  flex: none;
}
.ch-icon-webhook { background: #eff6ff; color: #3b82f6; }
.ch-icon-email { background: #ecfdf5; color: #10b981; }
.ch-icon-qq { background: #eff6ff; color: #3b82f6; }
.ch-icon-wx_clawbot { background: #f0fdf4; color: #22c55e; }

.ch-head-info { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }
.ch-name { font-size: 14px; font-weight: 600; color: #111827; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ch-tags { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }

/* 信息区：接收者+传输摘要两行紧凑排布，间距统一 */
.ch-info { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }

.ch-target {
  display: flex; align-items: baseline; gap: 8px;
  padding: 7px 10px;
  background: var(--el-fill-color-extra-light);
  border-radius: 0;
}
.ch-target-label { flex: none; font-size: 11px; font-weight: 600; color: var(--text-secondary); }
.ch-target-value { font-size: 12px; color: #374151; word-break: break-all; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ch-transport { display: flex; align-items: baseline; gap: 8px; }
.ch-transport-label { flex: none; font-size: 11px; font-weight: 600; color: var(--text-secondary); }
.ch-transport-value { font-size: 12px; color: #374151; }

/* 底栏：测试态（左）+文字操作（右），分隔线收口，margin-top:auto 齐高 */
.ch-foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; border-top: 1px solid var(--el-border-color-extra-light); padding-top: 8px; margin-top: auto; }
.ch-verified { font-size: 12px; color: #6b7280; margin-right: auto; }
.test-ok { color: #059669; }
.test-fail { color: #f56c6c; }
.test-none { color: #9ca3af; }

.ch-actions { display: flex; align-items: center; gap: 4px; }

/* 重绑未完成提示条（卡片内）：文本左、重试右，直角细边框 */
.rebind-note { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin: 0 0 12px; }
.rebind-note .info-note-desc { flex: 1; min-width: 0; }

/* 编辑弹窗：绑定辅助区 + 传输配置分组 */
.ch-form-section { margin-top: 4px; }
.bind-area { display: flex; flex-direction: column; align-items: stretch; gap: 10px; padding: 16px; border: 1px dashed var(--el-border-color); width: 100%; box-sizing: border-box; }
.bind-helper { display: flex; flex-direction: column; align-items: center; gap: 8px; }
.bind-qr-img { width: 200px; height: 200px; }
.bind-hint { font-size: 12px; color: #6b7280; text-align: center; }
.bind-center { align-items: center; text-align: center; }
.bind-receiver { word-break: break-all; color: #059669; }
.bind-success-alert { margin-bottom: 8px; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; line-height: 1.5; }
.field-col { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; }
/* 自定义请求头：label 与右侧第一行输入框（无行时与添加按钮）垂直对齐 */
.headers-form-item { align-items: flex-start; }
.headers-form-item :deep(.el-form-item__label) { line-height: 24px; }
.header-rows { width: 100%; display: flex; flex-direction: column; gap: 8px; }
.header-row { display: grid; grid-template-columns: 180px 1fr auto; gap: 8px; align-items: center; }
.header-name { width: 100%; }
.header-value { width: 100%; }
.header-del { flex: none; }
.header-foot { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.header-foot .form-hint { margin: 0; }
</style>
