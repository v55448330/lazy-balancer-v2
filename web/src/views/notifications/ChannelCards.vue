<template>
  <div>
    <!-- 通道管理：工具栏入卡头（全站 list-card 规范），类型筛选置卡体首行 -->
    <el-card class="list-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><ChatDotRound /></el-icon>
            <span>{{ t('app.notification.rules.channelsTab') }}</span>
          </div>
          <div class="card-header-actions">
            <el-select v-if="isAdminUser" v-model="filterUserId" size="small" clearable :placeholder="t('app.notification.channels.allUsers')" style="width:140px" @change="fetchChannels">
              <el-option v-for="u in userList" :key="u.id" :value="u.id" :label="u.username" />
            </el-select>
            <el-tooltip :disabled="!writeBlocked" :content="writeBlockedReason">
              <div>
                <el-button type="primary" :disabled="writeBlocked || drawerVisible" @click="openCreate">
                  <el-icon><Plus /></el-icon>
                  {{ t('app.notification.channels.add') }}
                </el-button>
              </div>
            </el-tooltip>
          </div>
        </div>
      </template>
      <div class="ch-filter-row">
        <el-radio-group v-model="filterType" size="small">
          <el-radio-button value="">{{ t('app.notification.channels.filterAll') }}</el-radio-button>
          <el-radio-button v-for="typ in CHANNEL_TYPES" :key="typ" :value="typ">{{ typeLabel(typ) }}</el-radio-button>
        </el-radio-group>
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
    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.notification.channels.loadFailed') }}</span>
          <el-button link type="danger" @click="fetchChannels">{{ t('common.app.views.audit.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>
    <el-empty v-if="!loading && filteredChannels.length === 0 && !loadError"
      :description="t('app.notification.channels.emptyText')" :image-size="80" />
    </el-card>

    <!-- 编辑弹窗（DialogHeader 规范 + 消息样式编辑） -->
    <el-dialog v-model="drawerVisible" class="dialog-body-inset" width="min(600px, 94vw)" top="6vh"
      :close-on-click-modal="false" @close="resetDrawer">
      <template #header>
        <DialogHeader :icon="editTarget ? Edit : Plus" :title="editTarget ? t('app.notification.channels.edit') : t('app.notification.channels.add')" :subtitle="typeLabel(drawerForm.type)" tone="primary" />
      </template>
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
            <template v-if="drawerForm.targetValue">
              <el-tag type="success" effect="plain">{{ t('app.notification.channels.bindBound') }} · {{ drawerForm.targetValue }}</el-tag>
              <el-button size="small" text type="primary" @click="drawerForm.targetValue = ''">{{ t('app.notification.channels.bindRebind') }}</el-button>
            </template>
            <template v-else>
              <el-button type="primary" :loading="bindLoading" @click="startBind">{{ t('app.notification.channels.bindGenerate') }}</el-button>
              <img v-if="bindQrImg" :src="bindQrImg" class="bind-qr-img" />
              <div v-if="bindQrImg" class="bind-hint">{{ t('app.notification.channels.bindScanHint', { app: drawerForm.type === 'qq' ? 'QQ' : t('app.notification.channels.typeWx') }) }}</div>
            </template>
          </div>
        </el-form-item>
      </el-form>

      <!-- 传输配置（编辑既有通道时）：请求方式/请求头/消息类型/日报格式。
           消息正文模板已归通知规则（每通道模板），此处不再编辑模板。 -->
      <template v-if="editTarget">
        <el-collapse v-model="transportExpanded" class="transport-collapse">
          <el-collapse-item :title="t('app.notification.channels.transportSection')" name="transport">
        <el-form :label-width="$flw('110px')" :disabled="saving">
          <template v-if="drawerForm.type === 'webhook'">
            <el-form-item :label="t('app.notification.channels.styleMethod')">
              <el-radio-group v-model="styleForm.method" size="small">
                <el-radio-button value="POST">POST</el-radio-button>
                <el-radio-button value="GET">GET</el-radio-button>
              </el-radio-group>
              <div class="form-hint">{{ t('app.notification.channels.styleMethodHint') }}</div>
            </el-form-item>
            <el-form-item :label="t('app.notification.channels.styleHeaders')">
              <div class="header-rows">
                <div v-for="(row, i) in headerRows" :key="i" class="header-row">
                  <el-input v-model="row.name" size="small" :placeholder="t('app.notification.channels.styleHeaderName')" class="header-name" />
                  <el-input v-model="row.value" size="small" :placeholder="t('app.notification.channels.styleHeaderValue')" class="header-value" />
                  <el-button size="small" link type="danger" @click="removeHeaderRow(i)">{{ t('app.notification.channels.delete') }}</el-button>
                </div>
                <el-button size="small" link type="primary" :disabled="headerRows.length >= 8" @click="addHeaderRow">+ {{ t('app.notification.channels.styleHeaderAdd') }}</el-button>
                <div class="form-hint">{{ t('app.notification.channels.styleHeadersHint') }}</div>
              </div>
            </el-form-item>
          </template>
          <template v-else-if="drawerForm.type === 'email'">
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
          <template v-else>
            <el-form-item v-if="drawerForm.type === 'qq'" :label="t('app.notification.channels.styleMsgType')">
              <el-radio-group v-model="styleForm.msg_type" size="small">
                <el-radio-button value="text">{{ t('app.notification.channels.styleMsgText') }}</el-radio-button>
                <el-radio-button value="markdown">{{ t('app.notification.channels.styleMsgMd') }}</el-radio-button>
              </el-radio-group>
              <div v-if="styleForm.msg_type === 'markdown'" class="form-hint">{{ t('app.notification.channels.styleMsgMdHint') }}</div>
            </el-form-item>
          </template>
          <el-form-item :label="t('app.notification.channels.styleDailyFormat')">
            <el-select v-model="styleForm.daily_format" size="small" style="width:160px">
              <el-option value="" :label="t('app.notification.channels.styleFormatAuto')" />
              <el-option value="text" :label="t('app.notification.channels.styleFormatText')" />
              <el-option value="markdown" :label="t('app.notification.channels.styleFormatMarkdown')" />
              <el-option value="html" :label="t('app.notification.channels.styleFormatHtml')" />
              <el-option value="json" :label="t('app.notification.channels.styleFormatJson')" />
            </el-select>
          </el-form-item>
          <div class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.channels.tplMovedHint') }}</span></div>
        </el-form>
          </el-collapse-item>
        </el-collapse>
      </template>
      <template #footer>
        <el-button @click="drawerVisible = false">{{ t('app.notification.channels.cancel') }}</el-button>
        <el-button type="primary" :loading="saving" :disabled="!canSave" @click="saveDrawer">{{ t('app.notification.channels.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChatDotRound, ChatLineRound, Edit, Link, Message, Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import DialogHeader from '@/components/DialogHeader.vue'
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
const transportExpanded = ref<string[]>([]) // 传输配置高级区默认折叠
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
const canSave = computed(() => drawerForm.value.name.trim() !== '' && drawerForm.value.targetValue.trim() !== '')

// 传输配置表单（键白名单=后端 validateChannelStyle；模板键保留回填不编辑——
// 正文模板已归通知规则，保存时原样透传既有模板键避免覆盖丢失）
interface HeaderRow { name: string; value: string }
const emptyStyle = () => ({ payload_template: '', subject_template: '', body_template: '', content_template: '', msg_type: 'text', body_format: 'text', daily_format: '', method: 'POST' })
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
    if (typ === 'qq' && s.msg_type === 'markdown') out.msg_type = 'markdown'
  }
  if (s.daily_format) out.daily_format = s.daily_format
  return out
}

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
        if (created) await testChannel(created)
      }
      return
    }
    drawerVisible.value = false
    await fetchChannels()
  } catch (e) { console.error(e) } finally { saving.value = false }
}

const bindLoading = ref(false)
const bindQrImg = ref('')
const startBind = async (): Promise<void> => {
  bindLoading.value = true
  try {
    const endpoint = drawerForm.value.type === 'qq' ? '/notification/qq/bind-code' : '/notification/wx/qr/start'
    const res = await request.post<{ data?: { qr_content?: string } }>(endpoint, {})
    const qrUrl = res.data?.qr_content ?? ''
    if (qrUrl) {
      const QRCode = (await import('qrcode')).default
      bindQrImg.value = await QRCode.toDataURL(qrUrl, { width: 200, margin: 1 })
      // 轮询绑定结果
      pollBind()
    }
  } catch (e) { console.error(e) } finally { bindLoading.value = false }
}
let bindTimer: ReturnType<typeof setInterval> | null = null
let bindTimeout: ReturnType<typeof setTimeout> | null = null
const stopBindPolling = (): void => {
  if (bindTimer !== null) { clearInterval(bindTimer); bindTimer = null }
  if (bindTimeout !== null) { clearTimeout(bindTimeout); bindTimeout = null }
}
const pollBind = (): void => {
  stopBindPolling()
  const endpoint = drawerForm.value.type === 'qq' ? '/notification/qq/bind-code' : '/notification/wx/bind-state'
  bindTimer = setInterval(async () => {
    try {
      const res = await request.get<{ data?: { bound?: boolean; openid?: string; receiver?: string; bot_ready?: boolean } }>(endpoint, { silent: true })
      const val = res.data?.openid ?? res.data?.receiver ?? ''
      if (val) { drawerForm.value.targetValue = val; bindQrImg.value = ''; stopBindPolling() }
    } catch { /* keep polling */ }
  }, 3000)
  bindTimeout = setTimeout(stopBindPolling, 300000)
}
onUnmounted(stopBindPolling)

const resetDrawer = (): void => {
  stopBindPolling()
  bindQrImg.value = ''
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
    await request.post(`/notification/channels/${ch.id}/test`, {}, { silent: true })
    mfaAwareSuccess(t('app.notification.channels.testSuccess'))
  } catch {
    ElMessage.error(t('app.notification.channels.testFailed'))
  } finally {
    testingId.value = null
    await fetchChannels()
  }
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

onMounted(() => {
  void fetchChannels()
  if (isAdminUser.value) {
    request.get<{ data?: { users: { id: number; username: string }[] } }>('/notification/admin/overview', { silent: true })
      .then(r => { userList.value = r.data?.users ?? [] }).catch(() => {})
  }
})

defineExpose({ fetchChannels })
</script>

<style scoped>
.el-card { --el-card-border-color: #ebeef5; }
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.ch-filter-row { margin-bottom: 16px; }
.transport-collapse { margin-top: 8px; border-top: none; }
.transport-collapse :deep(.el-collapse-item__header) { font-size: 13px; font-weight: 600; color: #374151; }
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
.bind-area { display: flex; flex-direction: column; align-items: center; gap: 10px; padding: 16px; border: 1px dashed var(--el-border-color); width: 100%; }
.bind-qr-img { width: 200px; height: 200px; }
.bind-hint { font-size: 12px; color: #6b7280; }
.style-section-title { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 12px; }
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin: 4px 0 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; line-height: 1.5; }
.header-rows { width: 100%; display: flex; flex-direction: column; gap: 6px; }
.header-row { display: flex; gap: 8px; align-items: center; }
.header-name { width: 200px; flex: none; }
.header-value { flex: 1; }
</style>
