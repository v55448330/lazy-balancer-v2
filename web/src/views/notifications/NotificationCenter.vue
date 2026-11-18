<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Bell /></el-icon>
          {{ t('app.notification.rules.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('app.notification.rules.pageDesc') }}</p>
      </div>
    </div>

    <!-- ═══ 区块一：触发条件（什么事件通知我）═══ -->
    <el-card shadow="never">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Bell /></el-icon>
            <span>{{ t('app.notification.rules.triggersSection') }}</span>
          </div>
        </div>
      </template>
      <div v-loading="loading" class="trigger-grid">
        <div v-for="rule in rules" :key="rule.id" class="trigger-item" :class="{ active: rule.enabled }">
          <div class="trigger-head">
            <el-switch v-model="rule.enabled" size="small" @change="toggleRule(rule)" />
            <span class="trigger-name">{{ rule.title }}</span>
          </div>
          <div class="trigger-detail">
            <template v-if="rule.trigger === 'daily'">
              <el-time-select v-model="rule.send_time" start="00:00" step="00:30" end="23:30" size="small" class="trigger-time" @change="saveRuleField(rule)" />
            </template>
            <template v-else>
              <el-radio-group v-model="rule.min_level" size="small" @change="saveRuleField(rule)">
                <el-radio-button value="info">Info</el-radio-button>
                <el-radio-button value="warn">Warn</el-radio-button>
                <el-radio-button value="critical">Critical</el-radio-button>
              </el-radio-group>
              <span class="trigger-count">{{ rule.events?.length || 0 }} {{ t('app.notification.rules.events') }}</span>
            </template>
          </div>
          <el-button v-if="rule.trigger === 'daily'" size="small" text type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
          <el-button v-else size="small" text type="primary" @click="editTemplate(rule)">{{ t('app.notification.rules.bodyTemplate') }}</el-button>
        </div>
      </div>
    </el-card>

    <!-- ═══ 区块二：接收通道（通知发到哪里）═══ -->
    <el-card shadow="never" class="mt-4">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><ChatDotRound /></el-icon>
            <span>{{ t('app.notification.rules.channelsSection') }}</span>
          </div>
          <el-button size="small" type="primary" @click="showChannelManage = true">{{ t('app.notification.rules.manageChannels') }}</el-button>
        </div>
      </template>
      <div class="channel-grid">
        <div v-for="ch in availableChannels" :key="ch.id" class="channel-item">
          <el-icon :size="20" :style="{ color: channelColor(ch.type) }">
            <component :is="channelIcon(ch.type)" />
          </el-icon>
          <div class="channel-info">
            <div class="channel-name">{{ ch.name }}</div>
            <div class="channel-type">{{ ch.type }}</div>
          </div>
          <el-tag size="small" type="success" effect="plain">{{ t('app.notification.rules.channelActive') }}</el-tag>
        </div>
        <div v-if="availableChannels.length === 0" class="channel-empty">
          <p>{{ t('app.notification.rules.noChannels') }}</p>
          <el-button type="primary" @click="showChannelManage = true">{{ t('app.notification.rules.addChannel') }}</el-button>
        </div>
      </div>
    </el-card>

    <!-- ═══ 区块三：SMTP 设置（管理员）═══ -->
    <template v-if="isAdmin">
      <el-card shadow="never" class="mt-4">
        <template #header>
          <div class="card-header">
            <div class="card-title">
              <el-icon class="title-icon"><Message /></el-icon>
              <span>{{ t('app.notification.rules.smtpSettings') }}</span>
            </div>
          </div>
        </template>
        <SystemCredentials />
      </el-card>
    </template>

    <!-- ═══ 区块四：最近投递 ═══ -->
    <el-card shadow="never" class="mt-4">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><List /></el-icon>
            <span>{{ t('app.notification.rules.recentDeliveries') }}</span>
          </div>
        </div>
      </template>
      <DeliveryLog />
    </el-card>

    <!-- 模板编辑弹窗（SecurityPolicies 同构：DialogHeader+直角） -->
    <el-dialog v-model="tplDialogVisible" class="dialog-body-inset" width="min(560px, 94vw)" top="8vh">
      <template #header>
        <DialogHeader :icon="Bell" :title="tplEditingRule?.title || ''" :subtitle="t('app.notification.rules.bodyTemplate')" tone="primary" />
      </template>
      <el-form :label-width="$flw('80px')">
        <el-form-item :label="t('app.notification.rules.bodyTemplate')">
          <el-input v-model="tplText" type="textarea" :rows="5"
            :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row">
            <el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag>
          </div>
          <div class="form-hint">{{ t('app.notification.rules.templateHint') }}</div>
        </el-form-item>
        <el-form-item :label="t('app.notification.rules.preview')">
          <pre class="tpl-preview">{{ previewText }}</pre>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="tplDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="savingTpl" @click="saveTemplate">保存</el-button>
      </template>
    </el-dialog>

    <!-- 通道管理抽屉 -->
    <el-drawer v-model="showChannelManage" size="680px" :title="t('app.notification.rules.manageChannels')">
      <ChannelCards />
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell, ChatDotRound, ChatLineRound, Link, List, Message } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import DialogHeader from '@/components/DialogHeader.vue'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

interface RuleChannel { id: number; type: string; name: string }
interface Rule { id: string; trigger: string; title: string; events?: string[]; min_level?: string; send_time?: string; items?: string[]; channels: RuleChannel[]; body_template: string; enabled: boolean }

const loading = ref(false)
const rules = ref<Rule[]>([])
const availableChannels = ref<RuleChannel[]>([])
const showChannelManage = ref(false)

// 模板编辑
const tplDialogVisible = ref(false)
const tplEditingRule = ref<Rule | null>(null)
const tplText = ref('')
const savingTpl = ref(false)
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}']
const previewText = computed(() => tplText.value.replace(/\{\{title\}\}/g, '证书续签失败').replace(/\{\{body\}\}/g, '证书 3 天后过期').replace(/\{\{level\}\}/g, 'critical').replace(/\{\{time\}\}/g, '2026-11-18 09:00'))

const channelIcon = (type: string) => ({ webhook: Link, email: Message, qq: ChatDotRound, wx_clawbot: ChatLineRound }[type] ?? Link)
const channelColor = (type: string) => ({ webhook: '#3b82f6', email: '#10b981', qq: '#3b82f6', wx_clawbot: '#22c55e' }[type] ?? '#6b7280')

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels: RuleChannel[] } }>('/notification/rules')
    rules.value = res.data?.rules ?? []
    availableChannels.value = res.data?.channels ?? []
  } catch (e) { console.error(e) } finally { loading.value = false }
}

const toggleRule = async (rule: Rule): Promise<void> => {
  try { await request.post(`/notification/rules/${rule.id}`, { enabled: rule.enabled, min_level: rule.min_level, body_template: rule.body_template, send_time: rule.send_time }) }
  catch { rule.enabled = !rule.enabled }
}

const saveRuleField = async (rule: Rule): Promise<void> => {
  try { await request.post(`/notification/rules/${rule.id}`, { enabled: rule.enabled, min_level: rule.min_level, body_template: rule.body_template, send_time: rule.send_time }) }
  catch { /* revert on error */ }
}

const editTemplate = (rule: Rule): void => {
  tplEditingRule.value = rule
  tplText.value = rule.body_template
  tplDialogVisible.value = true
}

const saveTemplate = async (): Promise<void> => {
  if (!tplEditingRule.value || savingTpl.value) return
  savingTpl.value = true
  try {
    await request.post(`/notification/rules/${tplEditingRule.value.id}`, { enabled: true, body_template: tplText.value, min_level: tplEditingRule.value.min_level })
    tplEditingRule.value.body_template = tplText.value
    mfaAwareSuccess(t('app.notification.rules.saved'))
    tplDialogVisible.value = false
  } catch (e) { console.error(e) } finally { savingTpl.value = false }
}

const previewDaily = async (): Promise<void> => {
  try { const res = await request.post<{ data?: { content: string } }>('/notification/daily/preview', { format: 'markdown' }); if (res.data?.content) window.open('', '_blank')?.document.write(`<pre>${res.data.content}</pre>`) } catch { /* */ }
}

onMounted(() => { void fetchRules() })
</script>

<style scoped>
/* Dashboard 同构卡片头部 */
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.mt-4 { margin-top: 16px; }

/* 触发条件网格：内联编辑（开关+级别选择+时间选择直接在卡内） */
.trigger-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
.trigger-item { padding: 12px; border: 1px solid var(--el-border-color-lighter); }
.trigger-item.active { border-left: 3px solid var(--el-color-primary); }
.trigger-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.trigger-name { font-size: 14px; font-weight: 600; color: #111827; }
.trigger-detail { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.trigger-time { width: 100px; }
.trigger-count { font-size: 12px; color: #6b7280; }

/* 通道网格 */
.channel-grid { display: flex; flex-direction: column; gap: 10px; }
.channel-item { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border: 1px solid var(--el-border-color-extra-light); }
.channel-info { flex: 1; min-width: 0; }
.channel-name { font-size: 14px; font-weight: 600; color: #111827; }
.channel-type { font-size: 12px; color: #6b7280; }
.channel-empty { text-align: center; padding: 20px; }

/* 模板编辑 */
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; }
.tpl-preview { background: #f9fafb; padding: 10px; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
</style>
