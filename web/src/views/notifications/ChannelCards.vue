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
            <div class="ch-foot">
              <span v-if="ch.type === 'qq' || ch.type === 'wx_clawbot'" class="ch-link" :class="ch.link_connected ? 'is-online' : 'is-offline'">
                <i class="ch-link-dot" />{{ ch.link_connected ? t('app.notification.channels.linkOnline') : t('app.notification.channels.linkOffline') }}
              </span>
              <span v-if="ch.type === 'wx_clawbot'" class="ch-session" :class="ch.session_ready ? 'is-ready' : 'is-pending'" :title="t('app.notification.channels.sessionHint')">
                {{ ch.session_ready ? t('app.notification.channels.sessionReady') : t('app.notification.channels.sessionPending') }}
              </span>
              <span class="ch-test" :class="testStateClass(ch)">
                <i class="ch-test-dot" :class="!ch.last_test_at ? 'is-none' : ch.last_test_ok ? 'is-ok' : 'is-fail'" />
                {{ testStateText(ch) }}
              </span>
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
    <el-dialog v-model="drawerVisible" class="dialog-body-inset" width="min(600px, 94vw)" top="6vh"
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
        <el-form-item v-else :label="targetLabel(drawerForm.type)">
          <div class="bind-area">
            <!-- 接收者手动输入为主：一个用户可绑定多个机器人通道（不同接收者），
                 保存不依赖入站捕获；扫码/自动回填仅作辅助。 -->
            <el-input v-model="drawerForm.targetValue" :placeholder="drawerForm.type === 'qq' ? t('app.notification.channels.botOpenidPlaceholder') : t('app.notification.channels.botReceiverPlaceholder')" />
            <div class="bind-helper">
              <el-button v-if="bindPhase === 'idle'" size="small" :loading="bindLoading" @click="startBind">{{ t('app.notification.channels.bindGenerate') }}</el-button>
              <img v-if="bindQrImg" :src="bindQrImg" class="bind-qr-img" />
              <div v-if="bindPhase === 'scanning'" class="bind-hint">{{ t('app.notification.channels.bindScanHint') }}</div>
              <el-alert v-if="bindPhase === 'connecting'" type="info" :closable="false" show-icon class="bind-success-alert">
                <template #title>{{ t('app.notification.channels.bindConnecting') }}</template>
              </el-alert>
              <el-alert v-if="bindPhase === 'awaiting_message'" type="warning" :closable="false" show-icon class="bind-success-alert">
                <template #title>{{ t('app.notification.channels.bindAwaitMsg') }}</template>
              </el-alert>
              <el-alert v-if="bindPhase === 'confirmed'" type="success" :closable="false" show-icon class="bind-success-alert">
                <template #title>{{ t('app.notification.channels.bindConfirmed') }}</template>
              </el-alert>
              <div v-if="bindPhase === 'idle' && drawerForm.type === 'wx_clawbot' && wxAlreadyLoggedIn" class="bind-hint">{{ t('app.notification.channels.wxAlreadyLoggedInHint') }}</div>
              <div class="bind-hint">{{ drawerForm.type === 'qq' ? t('app.notification.channels.qqBindHint') : t('app.notification.channels.wxSendMsgHint') }}</div>
            </div>
          </div>
        </el-form-item>
      </el-form>

      <!-- 传输配置（编辑既有 webhook/email 通道）：请求方式/请求头/标题/正文格式。
           消息正文模板已归通知规则（每通道模板），此处不再编辑模板。 -->
      <template v-if="editTarget && (drawerForm.type === 'webhook' || drawerForm.type === 'email')">
        <DialogSectionHeader :title="t('app.notification.channels.transportSection')" class="ch-form-section" />
        <el-form :label-width="$flw('110px')" :disabled="saving">
          <template v-if="drawerForm.type === 'webhook'">
            <el-form-item :label="t('app.notification.channels.styleMethod')">
              <el-radio-group v-model="styleForm.method" size="small">
                <el-radio-button value="POST">POST</el-radio-button>
                <el-radio-button value="GET">GET</el-radio-button>
              </el-radio-group>
              <div class="form-hint">{{ t('app.notification.channels.styleMethodHint') }}</div>
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
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveDrawer">{{ t('app.notification.channels.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChatDotRound, ChatLineRound, Edit, Link, Message, Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
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

const testStateText = (ch: NotificationChannel): string => {
  if (!ch.last_test_at) return t('app.notification.channels.neverTested')
  return ch.last_test_ok ? t('app.notification.channels.testStateOk') : t('app.notification.channels.testStateFail')
}
const testStateClass = (ch: NotificationChannel): string =>
  !ch.last_test_at ? 'test-none' : ch.last_test_ok ? 'test-ok' : 'test-fail'

const fetchChannels = async (silent = false): Promise<void> => {
  const seq = ++fetchSeq
  if (!silent) loading.value = true
  try {
    const url = filterUserId.value ? `/notification/channels?user_id=${filterUserId.value}` : '/notification/channels'
    const res = await request.get<NotificationChannelsResponse>(url)
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
const emptyStyle = () => ({ payload_template: '', subject_template: '', body_template: '', content_template: '', body_format: 'text', daily_format: '', method: 'POST' })
const styleForm = ref(emptyStyle())
const headerRows = ref<HeaderRow[]>([])
const addHeaderRow = (): void => { if (headerRows.value.length < 8) headerRows.value.push({ name: '', value: '' }) }
const removeHeaderRow = (i: number): void => { headerRows.value.splice(i, 1) }
const buildStyleConfig = (): Record<string, unknown> => {
  const s = styleForm.value
  const out: Record<string, unknown> = {}
  const typ = drawerForm.value.type
  if (typ === 'webhook') {
    if (s.payload_template.trim()) out.payload_template = s.payload_template
    if (s.method === 'GET') out.method = 'GET'
    const headers: Record<string, string> = {}
    for (const row of headerRows.value) {
      if (row.name.trim() && row.value.trim()) headers[row.name.trim()] = row.value.trim()
    }
    if (Object.keys(headers).length) out.headers = headers
  }
  if (typ === 'email') {
    if (s.subject_template.trim()) out.subject_template = s.subject_template
    if (s.body_template.trim()) out.body_template = s.body_template
    if (s.body_format === 'html') out.body_format = 'html'
  }
  if (typ === 'qq' || typ === 'wx_clawbot') {
    if (s.content_template.trim()) out.content_template = s.content_template
    if (typ === 'qq') out.msg_type = 'markdown'
  }
  if (s.daily_format) out.daily_format = s.daily_format
  return out
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
    const key = { webhook: 'url', email: 'email', qq: 'openid', wx_clawbot: 'receiver' }[drawerForm.value.type] ?? 'target'
    const target = JSON.stringify({ [key]: drawerForm.value.targetValue.trim() })
    if (editTarget.value) {
      // 编辑：名称/目标/样式一次提交（样式全量覆盖=所见即所存）
      await request.put(`/notification/channels/${editTarget.value.id}`, {
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
  } catch (e) { console.error(e) } finally { saving.value = false }
}

const bindLoading = ref(false)
const bindQrImg = ref('')
// 绑定会话状态机：idle→scanning（扫码）→connecting（连接测试）→awaiting_message
// （待发送「绑定测试」）→confirmed（入站确认+品牌回复，允许保存）。
const bindPhase = ref<'idle' | 'scanning' | 'connecting' | 'awaiting_message' | 'confirmed'>('idle')
const bindScannerID = ref('')
const bindBotKey = ref('')
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
  bindScannerID.value = ''
  bindBotKey.value = ''
  bindQrImg.value = ''
  stopBindPolling()
  if (typ === 'wx_clawbot') void checkWxLoggedIn()
  else wxAlreadyLoggedIn.value = false
})
const startBind = async (): Promise<void> => {
  bindLoading.value = true
  bindPhase.value = 'scanning'
  try {
    const endpoint = drawerForm.value.type === 'qq' ? '/notification/qq/bind-code' : '/notification/wx/qr/start'
    const res = await request.post<{ data?: { qr_content?: string } }>(endpoint, {})
    const qrUrl = res.data?.qr_content ?? ''
    if (qrUrl) {
      const QRCode = (await import('qrcode')).default
      bindQrImg.value = await QRCode.toDataURL(qrUrl, { width: 200, margin: 1 })
      pollScan()
    }
  } catch (e) { console.error(e) } finally { bindLoading.value = false }
}
let bindTimer: ReturnType<typeof setInterval> | null = null
let bindTimeout: ReturnType<typeof setTimeout> | null = null
const stopBindPolling = (): void => {
  if (bindTimer !== null) { clearInterval(bindTimer); bindTimer = null }
  if (bindTimeout !== null) { clearTimeout(bindTimeout); bindTimeout = null }
}
// 扫码轮询：confirmed 后取 scanner_id/bot_key（QQ=openid/appid）注册绑定会话。
const pollScan = (): void => {
  stopBindPolling()
  const isQQ = drawerForm.value.type === 'qq'
  bindTimer = setInterval(async () => {
    try {
      if (isQQ) {
        const res = await request.get<{ data?: { bound?: boolean; openid?: string; appid?: string } }>('/notification/qq/bind-code', { silent: true })
        if (res.data?.bound && res.data?.openid) {
          bindScannerID.value = res.data.openid
          bindBotKey.value = res.data.appid ?? ''
          drawerForm.value.targetValue = res.data.openid
          bindQrImg.value = ''
          stopBindPolling()
          void registerBindSession()
        }
      } else {
        const qs = await request.get<{ data?: { confirmed?: boolean; scanner_id?: string; bot_key?: string } }>('/notification/wx/qr/status', { silent: true })
        if (qs.data?.confirmed) {
          bindScannerID.value = qs.data.scanner_id ?? ''
          bindBotKey.value = qs.data.bot_key ?? ''
          bindQrImg.value = ''
          stopBindPolling()
          void registerBindSession()
        }
      }
    } catch { /* keep polling */ }
  }, 3000)
  bindTimeout = setTimeout(stopBindPolling, 300000)
}
// 注册绑定会话→连接测试→轮询入站「绑定测试」确认。
const registerBindSession = async (): Promise<void> => {
  bindPhase.value = 'connecting'
  try {
    await request.post('/notification/bind-session', { type: drawerForm.value.type, scanner_id: bindScannerID.value, bot_key: bindBotKey.value }, { silent: true })
  } catch { /* 仍轮询 */ }
  pollBindSession()
}
const pollBindSession = (): void => {
  stopBindPolling()
  const q = `/notification/bind-session?type=${encodeURIComponent(drawerForm.value.type)}&scanner_id=${encodeURIComponent(bindScannerID.value)}&bot_key=${encodeURIComponent(bindBotKey.value)}`
  bindTimer = setInterval(async () => {
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
  }, 2500)
  bindTimeout = setTimeout(stopBindPolling, 600000)
}
onUnmounted(stopBindPolling)

const resetDrawer = (): void => {
  stopBindPolling()
  bindQrImg.value = ''
  bindPhase.value = 'idle'
  bindScannerID.value = ''
  bindBotKey.value = ''
  wxAlreadyLoggedIn.value = false
  drawerForm.value = { type: 'webhook', name: '', targetValue: '' }
  styleForm.value = emptyStyle()
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
  // 回填既有样式（style_config JSON → 表单；缺省键=默认形态）
  const s = emptyStyle()
  const rows: HeaderRow[] = []
  try {
    const parsed = JSON.parse(ch.style_config || '{}') as Record<string, unknown>
    for (const k of Object.keys(s) as (keyof typeof s)[]) {
      if (typeof parsed[k] === 'string') s[k] = parsed[k] as string
    }
    if (parsed.headers && typeof parsed.headers === 'object') {
      for (const [hk, hv] of Object.entries(parsed.headers as Record<string, unknown>)) {
        if (typeof hv === 'string') rows.push({ name: hk, value: hv })
      }
    }
  } catch { /* 坏 JSON 按默认形态 */ }
  styleForm.value = s
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
    mfaAwareSuccess(t('app.notification.channels.deleteSuccess'))
    await fetchChannels()
  } catch { /* handled */ }
  finally {
    deletingIds.value.delete(ch.id)
  }
}

let linkPoll: ReturnType<typeof setInterval> | null = null
onMounted(() => {
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
.ch-test { font-size: 12px; display: inline-flex; align-items: center; gap: 5px; }
.ch-test-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.ch-test-dot.is-ok { background: #059669; }
.ch-test-dot.is-fail { background: #f56c6c; }
.ch-test-dot.is-none { background: #9ca3af; }
.ch-link { font-size: 12px; display: inline-flex; align-items: center; gap: 5px; }
.ch-link-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.ch-link.is-online { color: #059669; }
.ch-link.is-online .ch-link-dot { background: #059669; }
.ch-link.is-offline { color: #f56c6c; }
.ch-link.is-offline .ch-link-dot { background: #f56c6c; }
.ch-session { font-size: 12px; padding: 1px 6px; border-radius: 3px; }
.ch-session.is-ready { color: #059669; background: #ecfdf5; }
.ch-session.is-pending { color: #d97706; background: #fffbeb; }
.ch-test { margin-right: auto; }
.test-ok { color: #059669; }
.test-fail { color: #f56c6c; }
.test-none { color: #9ca3af; }

.ch-actions { display: flex; align-items: center; gap: 4px; }

/* 编辑弹窗：绑定辅助区 + 传输配置分组 */
.ch-form-section { margin-top: 4px; }
.bind-area { display: flex; flex-direction: column; align-items: stretch; gap: 10px; padding: 16px; border: 1px dashed var(--el-border-color); width: 100%; }
.bind-helper { display: flex; flex-direction: column; align-items: center; gap: 8px; }
.bind-qr-img { width: 200px; height: 200px; }
.bind-hint { font-size: 12px; color: #6b7280; text-align: center; }
.bind-success-alert { margin-bottom: 8px; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; line-height: 1.5; }
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
