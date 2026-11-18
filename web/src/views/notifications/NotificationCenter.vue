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
      <div class="header-actions">
        <el-button type="primary" @click="showAddWizard = true">
          <el-icon><Plus /></el-icon>
          {{ t('app.notification.rules.addRule') }}
        </el-button>
      </div>
    </div>

    <!-- 规则卡片列表 -->
    <div v-loading="loading" class="rules-list">
      <div v-for="rule in rules" :key="rule.id" class="rule-card" :class="{ 'rule-paused': !rule.enabled }">
        <div class="rule-card-head">
          <div class="rule-icon" :class="rule.trigger === 'daily' ? 'rule-icon-daily' : 'rule-icon-event'">
            <el-icon :size="18"><component :is="rule.trigger === 'daily' ? Calendar : Bell" /></el-icon>
          </div>
          <div class="rule-title-area">
            <div class="rule-title">{{ rule.title }}</div>
            <div class="rule-trigger-desc">
              <template v-if="rule.trigger === 'daily'">
                {{ t('app.notification.rules.everyDay') }} {{ rule.send_time }}
                <span v-if="rule.items?.length" class="rule-items">· {{ rule.items.map(i => itemLabel(i)).join(' / ') }}</span>
              </template>
              <template v-else>
                {{ rule.events?.length || 0 }} {{ t('app.notification.rules.events') }}
                <span v-if="rule.min_level" class="rule-level">≥ {{ rule.min_level }}</span>
              </template>
            </div>
          </div>
          <el-switch v-model="rule.enabled" size="small" @change="toggleRule(rule)" />
        </div>

        <div class="rule-channels">
          <span class="rule-channels-label">{{ t('app.notification.rules.sendTo') }}</span>
          <el-tag v-for="ch in rule.channels" :key="ch.id" size="small" effect="plain" class="rule-channel-tag">
            {{ ch.name }}（{{ ch.type }}）
          </el-tag>
          <span v-if="!rule.channels?.length" class="rule-no-channels">{{ t('app.notification.rules.noChannels') }}</span>
        </div>

        <div v-if="rule.body_template" class="rule-template">
          <span class="rule-template-label">{{ t('app.notification.rules.customTemplate') }}</span>
          <code class="rule-template-preview">{{ rule.body_template.slice(0, 80) }}{{ rule.body_template.length > 80 ? '…' : '' }}</code>
        </div>

        <div class="rule-actions">
          <el-button size="small" text type="primary" @click="editRule(rule)">{{ t('app.notification.rules.edit') }}</el-button>
          <el-button v-if="rule.trigger === 'event'" size="small" text type="primary" @click="testRule(rule)">{{ t('app.notification.rules.test') }}</el-button>
          <el-button v-if="rule.trigger === 'daily'" size="small" text type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
        </div>
      </div>
      <el-empty v-if="!loading && rules.length === 0" :description="t('app.notification.rules.emptyText')" :image-size="80" />
    </div>

    <!-- 最近投递摘要 -->
    <el-divider content-position="left">{{ t('app.notification.rules.recentDeliveries') }}</el-divider>
    <DeliveryLog />

    <!-- 编辑抽屉 -->
    <el-drawer v-model="showEditDrawer" size="500px" :title="t('app.notification.rules.editRule')">
      <el-form v-if="editingRule" :label-width="$flw('90px')" :disabled="savingRule">
        <el-form-item :label="t('app.notification.rules.trigger')">
          <span class="form-muted">{{ editingRule.title }}</span>
        </el-form-item>
        <el-form-item v-if="editingRule.trigger === 'event'" :label="t('app.notification.rules.minLevel')">
          <el-radio-group v-model="editingRule.min_level">
            <el-radio value="info">Info</el-radio>
            <el-radio value="warn">Warn</el-radio>
            <el-radio value="critical">Critical</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="editingRule.trigger === 'daily'" :label="t('app.notification.rules.sendTime')">
          <el-time-select v-model="editingRule.send_time" start="00:00" step="00:30" end="23:30" />
        </el-form-item>
        <el-form-item v-if="editingRule.trigger === 'daily'" :label="t('app.notification.rules.items')">
          <el-checkbox-group v-model="editingRule.items">
            <el-checkbox v-for="it in dailyItems" :key="it.id" :value="it.id" :label="it.id">{{ it.label }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item :label="t('app.notification.rules.bodyTemplate')">
          <el-input v-model="editingRule.body_template" type="textarea" :rows="4" class="mono"
            :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row">
            <el-tag v-for="ph in templatePlaceholders" :key="ph" size="small" effect="plain" class="ph-tag"
              @click="editingRule.body_template += ph">{{ ph }}</el-tag>
          </div>
          <div class="form-hint">{{ t('app.notification.rules.templateHint') }}</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEditDrawer = false">取消</el-button>
        <el-button type="primary" :loading="savingRule" @click="saveRule">保存</el-button>
      </template>
    </el-drawer>

    <!-- 添加规则向导 -->
    <el-dialog v-model="showAddWizard" :title="t('app.notification.rules.addRule')" width="560px" :close-on-click-modal="false">
      <el-steps :active="wizardStep" align-center finish-status="success" class="wizard-steps">
        <el-step :title="t('app.notification.rules.stepTrigger')" />
        <el-step :title="t('app.notification.rules.stepChannel')" />
        <el-step :title="t('app.notification.rules.stepTemplate')" />
      </el-steps>

      <!-- Step 1: 触发条件 -->
      <div v-if="wizardStep === 0" class="wizard-body">
        <div class="wizard-option" :class="{ selected: wizardForm.trigger === 'event' }" @click="wizardForm.trigger = 'event'">
          <el-icon :size="22"><Bell /></el-icon>
          <div>
            <div class="wizard-option-title">{{ t('app.notification.rules.eventTrigger') }}</div>
            <div class="wizard-option-desc">{{ t('app.notification.rules.eventTriggerDesc') }}</div>
          </div>
        </div>
        <div class="wizard-option" :class="{ selected: wizardForm.trigger === 'daily' }" @click="wizardForm.trigger = 'daily'">
          <el-icon :size="22"><Calendar /></el-icon>
          <div>
            <div class="wizard-option-title">{{ t('app.notification.rules.dailyTrigger') }}</div>
            <div class="wizard-option-desc">{{ t('app.notification.rules.dailyTriggerDesc') }}</div>
          </div>
        </div>
        <template v-if="wizardForm.trigger === 'event'">
          <el-divider />
          <div class="wizard-event-groups">
            <div v-for="group in eventGroups" :key="group.name"
              class="wizard-event-group" :class="{ selected: wizardForm.group === group.name }"
              @click="wizardForm.group = group.name">
              <el-icon><component :is="group.icon" /></el-icon>
              <span>{{ group.name }}</span>
              <span class="wizard-event-count">{{ group.events.length }}</span>
            </div>
          </div>
        </template>
      </div>

      <!-- Step 2: 接收通道 -->
      <div v-if="wizardStep === 1" class="wizard-body">
        <div v-if="availableChannels.length === 0" class="wizard-no-channels">
          <p>{{ t('app.notification.rules.needChannelFirst') }}</p>
          <el-button type="primary" @click="$emit('add-channel')">{{ t('app.notification.rules.addChannel') }}</el-button>
        </div>
        <div v-else class="wizard-channel-list">
          <div v-for="ch in availableChannels" :key="ch.id"
            class="wizard-channel-item" :class="{ selected: wizardForm.channelIds.includes(ch.id) }"
            @click="toggleChannel(ch.id)">
            <el-icon :size="18"><component :is="channelIcon(ch.type)" /></el-icon>
            <div>
              <div>{{ ch.name }}</div>
              <div class="wizard-channel-type">{{ ch.type }}</div>
            </div>
            <el-icon v-if="wizardForm.channelIds.includes(ch.id)" class="wizard-check"><CircleCheckFilled /></el-icon>
          </div>
        </div>
      </div>

      <!-- Step 3: 消息模板 -->
      <div v-if="wizardStep === 2" class="wizard-body">
        <el-form :label-width="$flw('90px')">
          <el-form-item :label="t('app.notification.rules.bodyTemplate')">
            <el-input v-model="wizardForm.body_template" type="textarea" :rows="4" class="mono"
              :placeholder="t('app.notification.rules.templatePlaceholder')" />
            <div class="ph-row">
              <el-tag v-for="ph in templatePlaceholders" :key="ph" size="small" effect="plain" class="ph-tag"
                @click="wizardForm.body_template += ph">{{ ph }}</el-tag>
            </div>
          </el-form-item>
          <el-form-item :label="t('app.notification.rules.preview')">
            <pre class="wizard-preview">{{ renderPreview() }}</pre>
          </el-form-item>
        </el-form>
      </div>

      <template #footer>
        <el-button v-if="wizardStep > 0" @click="wizardStep--">{{ t('app.notification.rules.prev') }}</el-button>
        <el-button v-if="wizardStep < 2" type="primary" :disabled="!canAdvanceWizard" @click="wizardStep++">
          {{ t('app.notification.rules.next') }}
        </el-button>
        <el-button v-if="wizardStep === 2" type="primary" :loading="savingRule" @click="saveWizardRule">
          {{ t('app.notification.rules.save') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 通道管理（内嵌，从规则页直接可达） -->
    <el-drawer v-model="showChannelManage" size="620px" :title="t('app.notification.rules.manageChannels')">
      <ChannelCards />
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell, Calendar, CircleCheckFilled, Plus } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'

const { t } = useI18n()
const emit = defineEmits<{ 'add-channel': [] }>()

interface RuleChannel { id: number; type: string; name: string }
interface Rule {
  id: string; trigger: string; title: string; events?: string[]; min_level?: string
  send_time?: string; items?: string[]; formats?: Record<string, string>
  channels: RuleChannel[]; body_template: string; enabled: boolean; subscribed?: boolean
}

const loading = ref(false)
const rules = ref<Rule[]>([])
const availableChannels = ref<RuleChannel[]>([])
const dailyItems = ref<{ id: string; label: string }[]>([])
type EventGroup = { name: string; events: { id: string; title: string }[]; icon: string }
const eventGroups = ref<EventGroup[]>([])

const showEditDrawer = ref(false)
const showAddWizard = ref(false)
const showChannelManage = ref(false)
const editingRule = ref<Rule | null>(null)
const savingRule = ref(false)
const wizardStep = ref(0)
const wizardForm = ref({
  trigger: 'event', group: '', channelIds: [] as number[], body_template: '',
})
const templatePlaceholders = ['{{title}}', '{{body}}', '{{level}}', '{{time}}']

const canAdvanceWizard = computed(() => {
  if (wizardStep.value === 0) {
    return wizardForm.value.trigger === 'daily' || wizardForm.value.group !== ''
  }
  if (wizardStep.value === 1) {
    return wizardForm.value.channelIds.length > 0
  }
  return true
})

const channelIcon = (type: string) => {
  const map: Record<string, unknown> = { webhook: 'Link', email: 'Message', qq: 'ChatDotRound', wx_clawbot: 'ChatLineRound' }
  return map[type] ?? 'Link'
}

const itemLabel = (id: string): string => {
  const found = dailyItems.value.find(d => d.id === id)
  return found?.label ?? id
}

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<{ code: number; data?: {
      rules: Rule[]; channels: RuleChannel[];
      catalog: { id: string; title: string; group: string; level: string }[];
      daily_items?: { id: string; label: string }[]
    } }>('/notification/rules')
    rules.value = res.data?.rules ?? []
    availableChannels.value = res.data?.channels ?? []
    dailyItems.value = res.data?.daily_items ?? []
    // 构建事件分组
    const groups: Record<string, Array<{ id: string; title: string }>> = {}
    for (const e of res.data?.catalog ?? []) {
      if (!groups[e.group]) groups[e.group] = []
      groups[e.group].push({ id: e.id, title: e.title })
    }
    eventGroups.value = Object.entries(groups).map(([name, events]) => ({
      name, events, icon: 'Bell',
    }))
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

const toggleRule = async (rule: Rule): Promise<void> => {
  savingRule.value = true
  try {
    await request.put(`/notification/rules/${rule.id}`, {
      enabled: rule.enabled,
      min_level: rule.min_level,
      body_template: rule.body_template,
      send_time: rule.send_time,
      items: rule.items,
      formats: rule.formats,
    })
  } catch {
    rule.enabled = !rule.enabled
  } finally {
    savingRule.value = false
  }
}

const editRule = (rule: Rule): void => {
  editingRule.value = { ...rule }
  showEditDrawer.value = true
}

const saveRule = async (): Promise<void> => {
  if (!editingRule.value || savingRule.value) return
  savingRule.value = true
  try {
    await request.put(`/notification/rules/${editingRule.value.id}`, {
      enabled: editingRule.value.enabled,
      min_level: editingRule.value.min_level,
      body_template: editingRule.value.body_template,
      send_time: editingRule.value.send_time,
      items: editingRule.value.items,
      formats: editingRule.value.formats,
    })
    mfaAwareSuccess(t('app.notification.rules.saved'))
    showEditDrawer.value = false
    await fetchRules()
  } catch (e) {
    console.error(e)
  } finally {
    savingRule.value = false
  }
}

const testRule = async (rule: Rule): Promise<void> => {
  // 发送测试通知到该规则的通道
  for (const ch of rule.channels) {
    try {
      await request.post(`/notification/channels/${ch.id}/test`)
    } catch { /* */ }
  }
  mfaAwareSuccess(t('app.notification.rules.testSent'))
}

const previewDaily = async (): Promise<void> => {
  try {
    const res = await request.post<{ code: number; data?: { content: string } }>('/notification/daily/preview', { format: 'markdown' })
    if (res.data?.content) {
      // 显示预览弹窗（简化：用 alert 格式）
      window.open('', '_blank')?.document.write(`<pre>${res.data.content}</pre>`)
    }
  } catch { /* */ }
}

const toggleChannel = (id: number): void => {
  const idx = wizardForm.value.channelIds.indexOf(id)
  if (idx >= 0) {
    wizardForm.value.channelIds.splice(idx, 1)
  } else {
    wizardForm.value.channelIds.push(id)
  }
}

const renderPreview = (): string => {
  const tpl = wizardForm.value.body_template || '{{title}}\n{{body}}'
  return tpl
    .replace(/\{\{title\}\}/g, '证书续签失败')
    .replace(/\{\{body\}\}/g, '规则 example.com 的证书将在 3 天后过期')
    .replace(/\{\{level\}\}/g, 'critical')
    .replace(/\{\{time\}\}/g, '2026-11-18 09:00')
    .replace(/\{\{event\}\}/g, 'cert.failed')
}

const saveWizardRule = async (): Promise<void> => {
  savingRule.value = true
  try {
    const ruleId = wizardForm.value.trigger === 'daily' ? 'daily' : `group:${wizardForm.value.group}`
    await request.put(`/notification/rules/${ruleId}`, {
      enabled: true,
      min_level: 'warn',
      body_template: wizardForm.value.body_template,
      send_time: wizardForm.value.trigger === 'daily' ? '09:00' : '',
      items: wizardForm.value.trigger === 'daily' ? ['requests', 'blocked', 'attack_top'] : [],
    })
    mfaAwareSuccess(t('app.notification.rules.saved'))
    showAddWizard.value = false
    wizardStep.value = 0
    wizardForm.value = { trigger: 'event', group: '', channelIds: [], body_template: '' }
    await fetchRules()
  } catch (e) {
    console.error(e)
  } finally {
    savingRule.value = false
  }
}

onMounted(() => {
  void fetchRules()
})
</script>

<style scoped>
/* 页头 */
.page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
.page-title { display: flex; align-items: center; gap: 8px; font-size: 20px; font-weight: 600; margin: 0; }
.title-icon { color: var(--el-color-primary); }
.page-desc { font-size: 13px; color: var(--text-secondary); margin: 4px 0 0; }

/* 规则卡片 */
.rules-list { display: flex; flex-direction: column; gap: 12px; }
.rule-card {
  border: 1px solid var(--el-border-color-lighter); border-radius: 10px; padding: 16px;
  background: var(--el-bg-color); transition: box-shadow 0.15s ease;
}
.rule-card:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.04); }
.rule-paused { opacity: 0.6; }

.rule-card-head { display: flex; align-items: center; gap: 12px; }
.rule-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; flex: none; }
.rule-icon-event { background: #eff6ff; color: #3b82f6; }
.rule-icon-daily { background: #f5f3ff; color: #8b5cf6; }
.rule-title-area { flex: 1; min-width: 0; }
.rule-title { font-size: 15px; font-weight: 600; color: #111827; }
.rule-trigger-desc { font-size: 12px; color: #6b7280; margin-top: 2px; }
.rule-level { margin-left: 6px; font-weight: 600; color: var(--el-color-warning); }
.rule-items { color: #6b7280; }

.rule-channels { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin: 10px 0 6px; padding-left: 52px; }
.rule-channels-label { font-size: 12px; color: #6b7280; flex: none; }
.rule-channel-tag { }
.rule-no-channels { font-size: 12px; color: var(--el-color-warning); font-style: italic; }

.rule-template { display: flex; align-items: baseline; gap: 8px; margin: 4px 0; padding-left: 52px; }
.rule-template-label { font-size: 12px; color: #6b7280; flex: none; }
.rule-template-preview { font-size: 11px; color: #374151; background: var(--el-fill-color-extra-light); padding: 2px 6px; border-radius: 4px; }

.rule-actions { display: flex; gap: 4px; justify-content: flex-end; margin-top: 6px; border-top: 1px solid var(--el-border-color-extra-light); padding-top: 8px; }

/* 向导 */
.wizard-steps { margin-bottom: 20px; }
.wizard-body { min-height: 200px; }
.wizard-option {
  display: flex; align-items: center; gap: 14px; padding: 14px 16px;
  border: 2px solid var(--el-border-color-lighter); border-radius: 10px;
  cursor: pointer; margin-bottom: 10px; transition: all 0.15s ease;
  color: #6b7280;
}
.wizard-option:hover { border-color: var(--el-color-primary-light-5); }
.wizard-option.selected { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.wizard-option-title { font-size: 15px; font-weight: 600; color: #111827; }
.wizard-option-desc { font-size: 12px; color: #6b7280; margin-top: 2px; }

.wizard-event-groups { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
.wizard-event-group {
  display: flex; align-items: center; gap: 8px; padding: 10px 12px;
  border: 1px solid var(--el-border-color-lighter); border-radius: 8px; cursor: pointer;
  transition: all 0.15s ease;
}
.wizard-event-group:hover { border-color: var(--el-color-primary-light-5); }
.wizard-event-group.selected { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.wizard-event-count { margin-left: auto; font-size: 11px; color: #6b7280; background: var(--el-fill-color); border-radius: 4px; padding: 1px 6px; }

.wizard-channel-list { display: flex; flex-direction: column; gap: 8px; }
.wizard-channel-item {
  display: flex; align-items: center; gap: 12px; padding: 12px 14px;
  border: 2px solid var(--el-border-color-lighter); border-radius: 10px; cursor: pointer;
  transition: all 0.15s ease;
}
.wizard-channel-item:hover { border-color: var(--el-color-primary-light-5); }
.wizard-channel-item.selected { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.wizard-channel-type { font-size: 11px; color: #6b7280; }
.wizard-check { margin-left: auto; color: var(--el-color-primary); }
.wizard-no-channels { text-align: center; padding: 30px; }
.wizard-preview {
  background: var(--el-fill-color-extra-light); border-radius: 6px; padding: 10px;
  font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: pre-wrap; word-break: break-all; margin: 0;
}

/* 共用 */
.form-muted { color: var(--text-secondary); }
.form-hint { font-size: 12px; color: var(--text-secondary); margin-top: 4px; }
.mono :deep(textarea) { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
