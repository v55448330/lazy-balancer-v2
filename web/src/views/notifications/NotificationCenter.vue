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
        <el-button @click="showChannelManage = true">{{ t('app.notification.rules.manageChannels') }}</el-button>
        <el-button v-if="isAdmin" @click="showSmtp = !showSmtp">{{ t('app.notification.rules.smtpSettings') }}</el-button>
        <el-button type="primary" @click="showAddWizard = true">{{ t('app.notification.rules.addRule') }}</el-button>
      </div>
    </div>

    <!-- 规则列表：el-card 网格（系统统一直角+shadow=never） -->
    <el-row v-loading="loading" :gutter="16">
      <el-col v-for="rule in rules" :key="rule.id" :xs="24" :md="12" :xl="8">
        <el-card shadow="never" class="rule-el-card" :class="{ 'is-paused': !rule.enabled }">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon">
                  <component :is="rule.trigger === 'daily' ? Calendar : Bell" />
                </el-icon>
                <span>{{ rule.title }}</span>
              </div>
              <el-switch v-model="rule.enabled" size="small" @change="toggleRule(rule)" />
            </div>
          </template>
          <div class="rule-desc">
            <template v-if="rule.trigger === 'daily'">
              {{ t('app.notification.rules.everyDay') }} {{ rule.send_time }}
            </template>
            <template v-else>
              {{ rule.events?.length || 0 }} {{ t('app.notification.rules.events') }}
              <span v-if="rule.min_level" class="rule-level">≥{{ rule.min_level }}</span>
            </template>
          </div>
          <div v-if="rule.trigger === 'daily' && rule.items?.length" class="rule-items">
            {{ rule.items.map(i => itemLabel(i)).join(' / ') }}
          </div>
          <div class="rule-channels">
            <el-tag v-for="ch in rule.channels" :key="ch.id" size="small" effect="plain" class="rule-ch-tag">
              {{ ch.name }}
            </el-tag>
            <span v-if="!rule.channels?.length" class="rule-no-ch">{{ t('app.notification.rules.noChannels') }}</span>
          </div>
          <div v-if="rule.body_template" class="rule-tpl">
            <code>{{ rule.body_template.slice(0, 60) }}{{ rule.body_template.length > 60 ? '…' : '' }}</code>
          </div>
          <div class="rule-ops">
            <el-button size="small" text type="primary" @click="editRule(rule)">{{ t('app.notification.rules.edit') }}</el-button>
            <el-button v-if="rule.trigger === 'event'" size="small" text type="primary" @click="testRule(rule)">{{ t('app.notification.rules.test') }}</el-button>
            <el-button v-if="rule.trigger === 'daily'" size="small" text type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>
    <el-empty v-if="!loading && rules.length === 0" :description="t('app.notification.rules.emptyText')" :image-size="80" />

    <!-- SMTP 设置 -->
    <template v-if="isAdmin && showSmtp">
      <el-divider content-position="left">{{ t('app.notification.rules.smtpSettings') }}</el-divider>
      <SystemCredentials />
    </template>

    <!-- 投递记录 -->
    <el-divider content-position="left">{{ t('app.notification.rules.recentDeliveries') }}</el-divider>
    <DeliveryLog />

    <!-- 编辑抽屉（系统统一直角） -->
    <el-drawer v-model="showEditDrawer" size="500px" :title="t('app.notification.rules.editRule')">
      <el-form v-if="editingRule" :label-width="$flw('90px')" :disabled="savingRule">
        <el-form-item :label="t('app.notification.rules.trigger')">
          <span>{{ editingRule.title }}</span>
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
          <el-input v-model="editingRule.body_template" type="textarea" :rows="4"
            :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row">
            <el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag"
              @click="editingRule.body_template += ph">{{ ph }}</el-tag>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEditDrawer = false">取消</el-button>
        <el-button type="primary" :loading="savingRule" @click="saveRule">保存</el-button>
      </template>
    </el-drawer>

    <!-- 通道管理（完整 ChannelCards 含 QR 绑定） -->
    <el-drawer v-model="showChannelManage" size="680px" :title="t('app.notification.rules.manageChannels')">
      <ChannelCards />
    </el-drawer>

    <!-- 添加规则向导 -->
    <el-dialog v-model="showAddWizard" :title="t('app.notification.rules.addRule')" width="560px" :close-on-click-modal="false">
      <el-steps :active="wizardStep" align-center finish-status="success">
        <el-step :title="t('app.notification.rules.stepTrigger')" />
        <el-step :title="t('app.notification.rules.stepChannel')" />
        <el-step :title="t('app.notification.rules.stepTemplate')" />
      </el-steps>
      <div v-if="wizardStep === 0" class="wiz-body">
        <div class="wiz-opt" :class="{ sel: wf.trigger === 'event' }" @click="wf.trigger = 'event'">
          <el-icon :size="22"><Bell /></el-icon>
          <div><div class="wiz-t">{{ t('app.notification.rules.eventTrigger') }}</div><div class="wiz-d">{{ t('app.notification.rules.eventTriggerDesc') }}</div></div>
        </div>
        <div class="wiz-opt" :class="{ sel: wf.trigger === 'daily' }" @click="wf.trigger = 'daily'">
          <el-icon :size="22"><Calendar /></el-icon>
          <div><div class="wiz-t">{{ t('app.notification.rules.dailyTrigger') }}</div><div class="wiz-d">{{ t('app.notification.rules.dailyTriggerDesc') }}</div></div>
        </div>
        <template v-if="wf.trigger === 'event'">
          <el-divider />
          <div class="wiz-groups">
            <div v-for="g in eventGroups" :key="g.name" class="wiz-grp" :class="{ sel: wf.group === g.name }" @click="wf.group = g.name">
              <span>{{ g.name }}</span><span class="wiz-cnt">{{ g.events.length }}</span>
            </div>
          </div>
        </template>
      </div>
      <div v-if="wizardStep === 1" class="wiz-body">
        <div v-if="availableChannels.length === 0" class="wiz-empty">
          <p>{{ t('app.notification.rules.needChannelFirst') }}</p>
          <el-button type="primary" @click="showChannelManage = true">{{ t('app.notification.rules.addChannel') }}</el-button>
        </div>
        <div v-else class="wiz-chs">
          <div v-for="ch in availableChannels" :key="ch.id" class="wiz-ch" :class="{ sel: wf.channelIds.includes(ch.id) }" @click="togCh(ch.id)">
            <div><div>{{ ch.name }}</div><div class="wiz-ct">{{ ch.type }}</div></div>
            <el-icon v-if="wf.channelIds.includes(ch.id)" class="wiz-ck"><CircleCheckFilled /></el-icon>
          </div>
        </div>
      </div>
      <div v-if="wizardStep === 2" class="wiz-body">
        <el-form :label-width="$flw('90px')">
          <el-form-item :label="t('app.notification.rules.bodyTemplate')">
            <el-input v-model="wf.body_template" type="textarea" :rows="4"
              :placeholder="t('app.notification.rules.templatePlaceholder')" />
            <div class="ph-row">
              <el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag"
                @click="wf.body_template += ph">{{ ph }}</el-tag>
            </div>
          </el-form-item>
          <el-form-item :label="t('app.notification.rules.preview')">
            <pre class="wiz-prev">{{ renderPreview() }}</pre>
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <el-button v-if="wizardStep > 0" @click="wizardStep--">{{ t('app.notification.rules.prev') }}</el-button>
        <el-button v-if="wizardStep < 2" type="primary" :disabled="!canAdv" @click="wizardStep++">{{ t('app.notification.rules.next') }}</el-button>
        <el-button v-if="wizardStep === 2" type="primary" :loading="savingRule" @click="saveWiz">{{ t('app.notification.rules.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell, Calendar, CircleCheckFilled } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

interface RuleChannel { id: number; type: string; name: string }
interface Rule { id: string; trigger: string; title: string; events?: string[]; min_level?: string; send_time?: string; items?: string[]; formats?: Record<string,string>; channels: RuleChannel[]; body_template: string; enabled: boolean }

const loading = ref(false)
const rules = ref<Rule[]>([])
const availableChannels = ref<RuleChannel[]>([])
const dailyItems = ref<{ id: string; label: string }[]>([])
const eventGroups = ref<{ name: string; events: { id: string }[] }[]>([])
const showSmtp = ref(false)
const showEditDrawer = ref(false)
const showAddWizard = ref(false)
const showChannelManage = ref(false)
const editingRule = ref<Rule | null>(null)
const savingRule = ref(false)
const wizardStep = ref(0)
const wf = ref({ trigger: 'event', group: '', channelIds: [] as number[], body_template: '' })
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}']

const canAdv = computed(() => {
  if (wizardStep.value === 0) return wf.value.trigger === 'daily' || wf.value.group !== ''
  if (wizardStep.value === 1) return wf.value.channelIds.length > 0
  return true
})
const itemLabel = (id: string): string => dailyItems.value.find(d => d.id === id)?.label ?? id

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels: RuleChannel[]; catalog: { id: string; group: string }[]; daily_items?: { id: string; label: string }[] } }>('/notification/rules')
    rules.value = res.data?.rules ?? []
    availableChannels.value = res.data?.channels ?? []
    dailyItems.value = res.data?.daily_items ?? []
    const gr: Record<string, Array<{ id: string }>> = {}
    for (const e of res.data?.catalog ?? []) { if (!gr[e.group]) gr[e.group] = []; gr[e.group].push({ id: e.id }) }
    eventGroups.value = Object.entries(gr).map(([name, events]) => ({ name, events }))
  } catch (e) { console.error(e) } finally { loading.value = false }
}

const toggleRule = async (rule: Rule): Promise<void> => {
  savingRule.value = true
  try { await request.post(`/notification/rules/${rule.id}`, { enabled: rule.enabled, min_level: rule.min_level, body_template: rule.body_template }) }
  catch { rule.enabled = !rule.enabled }
  finally { savingRule.value = false }
}

const editRule = (r: Rule): void => { editingRule.value = { ...r }; showEditDrawer.value = true }

const saveRule = async (): Promise<void> => {
  if (!editingRule.value || savingRule.value) return
  savingRule.value = true
  try {
    await request.post(`/notification/rules/${editingRule.value.id}`, { enabled: editingRule.value.enabled, min_level: editingRule.value.min_level, body_template: editingRule.value.body_template, send_time: editingRule.value.send_time, items: editingRule.value.items })
    mfaAwareSuccess(t('app.notification.rules.saved'))
    showEditDrawer.value = false; await fetchRules()
  } catch (e) { console.error(e) } finally { savingRule.value = false }
}

const testRule = async (rule: Rule): Promise<void> => {
  for (const ch of rule.channels) { try { await request.post(`/notification/channels/${ch.id}/test`) } catch { /* */ } }
  mfaAwareSuccess(t('app.notification.rules.testSent'))
}

const previewDaily = async (): Promise<void> => {
  try { const res = await request.post<{ data?: { content: string } }>('/notification/daily/preview', { format: 'markdown' }); if (res.data?.content) window.open('', '_blank')?.document.write(`<pre>${res.data.content}</pre>`) } catch { /* */ }
}

const togCh = (id: number): void => { const i = wf.value.channelIds.indexOf(id); if (i >= 0) wf.value.channelIds.splice(i, 1); else wf.value.channelIds.push(id) }
const renderPreview = (): string => (wf.value.body_template || '{{title}}\n{{body}}').replace(/\{\{title\}\}/g, '证书续签失败').replace(/\{\{body\}\}/g, '证书 3 天后过期').replace(/\{\{level\}\}/g, 'critical').replace(/\{\{time\}\}/g, '2026-11-18 09:00')

const saveWiz = async (): Promise<void> => {
  savingRule.value = true
  try {
    const rid = wf.value.trigger === 'daily' ? 'daily' : `group:${wf.value.group}`
    await request.post(`/notification/rules/${rid}`, { enabled: true, min_level: 'warn', body_template: wf.value.body_template, send_time: wf.value.trigger === 'daily' ? '09:00' : '', items: wf.value.trigger === 'daily' ? ['requests', 'blocked', 'attack_top'] : [] })
    mfaAwareSuccess(t('app.notification.rules.saved'))
    showAddWizard.value = false; wizardStep.value = 0
    wf.value = { trigger: 'event', group: '', channelIds: [], body_template: '' }
    await fetchRules()
  } catch (e) { console.error(e) } finally { savingRule.value = false }
}

onMounted(() => { void fetchRules() })
</script>

<style scoped>
/* 系统 Dashboard 同构：card-header/card-title/title-icon 全局类复用 */
.rule-el-card { margin-bottom: 16px; }
.is-paused { opacity: 0.6; }
.rule-desc { font-size: 13px; color: #6b7280; margin-bottom: 8px; }
.rule-items { font-size: 12px; color: #6b7280; margin-bottom: 6px; }
.rule-level { margin-left: 4px; font-weight: 600; color: #e67e22; }
.rule-channels { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 6px; }
.rule-ch-tag { }
.rule-no-ch { font-size: 12px; color: #e67e22; }
.rule-tpl code { font-size: 11px; color: #374151; background: var(--el-fill-color-extra-light); padding: 2px 6px; }
.rule-ops { display: flex; gap: 4px; justify-content: flex-end; border-top: 1px solid var(--el-border-color-extra-light); padding-top: 6px; margin-top: 4px; }

.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

.wiz-body { min-height: 200px; }
.wiz-opt { display: flex; align-items: center; gap: 14px; padding: 14px 16px; border: 1px solid var(--el-border-color); cursor: pointer; margin-bottom: 10px; color: #6b7280; }
.wiz-opt:hover { border-color: var(--el-color-primary); }
.wiz-opt.sel { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.wiz-t { font-size: 15px; font-weight: 600; color: #111827; }
.wiz-d { font-size: 12px; color: #6b7280; margin-top: 2px; }
.wiz-groups { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
.wiz-grp { display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; border: 1px solid var(--el-border-color); cursor: pointer; }
.wiz-grp:hover { border-color: var(--el-color-primary); }
.wiz-grp.sel { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.wiz-cnt { font-size: 11px; color: #6b7280; background: var(--el-fill-color); padding: 1px 6px; }
.wiz-chs { display: flex; flex-direction: column; gap: 8px; }
.wiz-ch { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border: 1px solid var(--el-border-color); cursor: pointer; }
.wiz-ch:hover { border-color: var(--el-color-primary); }
.wiz-ch.sel { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.wiz-ct { font-size: 11px; color: #6b7280; }
.wiz-ck { margin-left: auto; color: var(--el-color-primary); }
.wiz-empty { text-align: center; padding: 30px; }
.wiz-prev { background: var(--el-fill-color-extra-light); padding: 10px; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
</style>
