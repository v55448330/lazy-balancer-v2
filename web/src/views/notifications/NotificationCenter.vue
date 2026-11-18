<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Bell /></el-icon>
          {{ t('app.notification.pageTitle') }}
        </h2>
        <p class="page-desc">{{ t('app.notification.pageDesc') }}</p>
      </div>
    </div>

    <el-tabs v-model="activeTab">
      <!-- Tab 0: 概览 -->
      <el-tab-pane :label="t('app.notification.rules.overviewTab')" name="overview">
        <el-row :gutter="16">
          <el-col :span="6"><div class="stat-item"><div class="stat-icon stat-blue"><el-icon><ChatDotRound /></el-icon></div><div class="stat-content"><div class="stat-value">{{ overviewStats.channels }}</div><div class="stat-label">{{ t('app.notification.rules.statChannels') }}</div></div></div></el-col>
          <el-col :span="6"><div class="stat-item"><div class="stat-icon stat-purple"><el-icon><Bell /></el-icon></div><div class="stat-content"><div class="stat-value">{{ overviewStats.rules }}</div><div class="stat-label">{{ t('app.notification.rules.statRules') }}</div></div></div></el-col>
          <el-col :span="6"><div class="stat-item"><div class="stat-icon stat-green"><el-icon><CircleCheckFilled /></el-icon></div><div class="stat-content"><div class="stat-value">{{ overviewStats.deliveries }}</div><div class="stat-label">{{ t('app.notification.rules.statDeliveries') }}</div></div></div></el-col>
          <el-col :span="6"><div class="stat-item"><div class="stat-icon" :class="overviewStats.successRate > 0.9 ? 'stat-green' : 'stat-orange'"><el-icon><DataAnalysis /></el-icon></div><div class="stat-content"><div class="stat-value">{{ (overviewStats.successRate * 100).toFixed(1) }}%</div><div class="stat-label">{{ t('app.notification.rules.statSuccessRate') }}</div></div></div></el-col>
        </el-row>
        <el-divider content-position="left">{{ t('app.notification.rules.recentDeliveries') }}</el-divider>
        <DeliveryLog />
      </el-tab-pane>

      <!-- Tab 1: 通道管理 -->
      <el-tab-pane :label="t('app.notification.rules.channelsTab')" name="channels">
        <ChannelCards />
      </el-tab-pane>

      <!-- Tab 2: 通知规则 -->
      <el-tab-pane :label="t('app.notification.rules.rulesTab')" name="rules">
        <div v-loading="loading" class="trigger-grid">
          <el-card v-for="rule in rules" :key="rule.id" class="trigger-item" :class="{ active: rule.enabled }">
            <div class="trigger-head">
              <el-switch v-model="rule.enabled" size="small" @change="toggleRule(rule)" />
              <span class="trigger-name">{{ rule.title }}</span>
              <el-button size="small" text type="primary" class="trigger-tpl-btn" @click="editTemplate(rule)">
                {{ rule.body_template ? t('app.notification.rules.customTemplate') : t('app.notification.rules.bodyTemplate') }}
              </el-button>
            </div>
            <div class="trigger-detail">
              <template v-if="rule.trigger === 'daily'">
                <el-time-select v-model="rule.send_time" start="00:00" step="00:30" end="23:30" size="small" class="trigger-time" @change="saveRuleField(rule)" />
                <el-button size="small" text type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
              </template>
              <template v-else>
                <el-radio-group v-model="rule.min_level" size="small" @change="saveRuleField(rule)">
                  <el-radio-button value="info">Info</el-radio-button>
                  <el-radio-button value="warn">Warn</el-radio-button>
                  <el-radio-button value="critical">Critical</el-radio-button>
                </el-radio-group>
                <div class="trigger-events">
                  <el-tag v-for="ev in (rule.events || []).slice(0, 4)" :key="ev" size="small" effect="plain" class="ev-tag">{{ ev }}</el-tag>
                  <span v-if="(rule.events?.length || 0) > 4" class="ev-more">+{{ rule.events!.length - 4 }}</span>
                </div>
                <el-button size="small" text type="primary" @click="testRule(rule)">{{ t('app.notification.rules.test') }}</el-button>
              </template>
            </div>
          </el-card>
        </div>
        <el-empty v-if="!loading && rules.length === 0" :description="t('app.notification.rules.emptyText')" :image-size="80" />
      </el-tab-pane>

      <!-- Tab 3: 投递记录 -->
      <el-tab-pane :label="t('app.notification.rules.deliveriesTab')" name="deliveries">
        <DeliveryLog />
      </el-tab-pane>

      <!-- Tab 4: 邮件服务（管理员） -->
      <el-tab-pane v-if="isAdmin" :label="t('app.notification.rules.smtpTab')" name="smtp">
        <SystemCredentials />
      </el-tab-pane>
    </el-tabs>

    <!-- 模板编辑弹窗 -->
    <el-dialog v-model="tplDialogVisible" class="dialog-body-inset" width="min(560px, 94vw)" top="8vh">
      <template #header>
        <DialogHeader :icon="Bell" :title="tplEditingRule?.title || ''" :subtitle="t('app.notification.rules.bodyTemplate')" tone="primary" />
      </template>
      <el-form :label-width="$flw('80px')">
        <el-form-item :label="t('app.notification.rules.bodyTemplate')">
          <el-input v-model="tplText" type="textarea" :rows="5" :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row">
            <el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag>
          </div>
          <div class="form-hint">{{ t('app.notification.rules.templateHint') }}</div>
        </el-form-item>
        <el-form-item :label="t('app.notification.rules.preview')">
          <pre class="tpl-preview">{{ previewText }}</pre>
        </el-form-item>
        <el-form-item :label="t('app.notification.rules.channelFormats')">
          <div class="fmt-hints">
            <div class="fmt-hint"><el-tag size="small">QQ</el-tag> 文本或 Markdown（需权限）</div>
            <div class="fmt-hint"><el-tag size="small">微信</el-tag> 纯文本</div>
            <div class="fmt-hint"><el-tag size="small">Webhook</el-tag> JSON（payload_template）</div>
            <div class="fmt-hint"><el-tag size="small">邮件</el-tag> HTML 或纯文本（subject_template + body_template）</div>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="tplDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="savingTpl" @click="saveTemplate">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Bell, ChatDotRound, CircleCheckFilled, DataAnalysis } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import DialogHeader from '@/components/DialogHeader.vue'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const activeTab = ref('overview')

interface RuleChannel { id: number; type: string; name: string }
interface Rule { id: string; trigger: string; title: string; events?: string[]; min_level?: string; send_time?: string; channels: RuleChannel[]; body_template: string; enabled: boolean }

const overviewStats = ref({ channels: 0, rules: 0, deliveries: 0, successRate: 0 })
const loading = ref(false)
const rules = ref<Rule[]>([])
const tplDialogVisible = ref(false)
const tplEditingRule = ref<Rule | null>(null)
const tplText = ref('')
const savingTpl = ref(false)
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}']
const previewText = computed(() => tplText.value.replace(/\{\{title\}\}/g, '证书续签失败').replace(/\{\{body\}\}/g, '证书 3 天后过期').replace(/\{\{level\}\}/g, 'critical').replace(/\{\{time\}\}/g, '2026-11-18 09:00'))

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels?: { id: number }[] } }>('/notification/rules')
    rules.value = res.data?.rules ?? []
    overviewStats.value = { channels: res.data?.channels?.length ?? 0, rules: rules.value.filter(r => r.enabled).length, deliveries: 0, successRate: 0 }
  } catch (e) { console.error(e) } finally { loading.value = false }
}

const toggleRule = async (rule: Rule): Promise<void> => {
  try { await request.post(`/notification/rules/${rule.id}`, { enabled: rule.enabled, min_level: rule.min_level, body_template: rule.body_template, send_time: rule.send_time }) }
  catch { rule.enabled = !rule.enabled }
}

const saveRuleField = async (rule: Rule): Promise<void> => {
  try { await request.post(`/notification/rules/${rule.id}`, { enabled: rule.enabled, min_level: rule.min_level, body_template: rule.body_template, send_time: rule.send_time }) } catch { /* */ }
}

const editTemplate = (rule: Rule): void => { tplEditingRule.value = rule; tplText.value = rule.body_template; tplDialogVisible.value = true }

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

const testRule = async (rule: Rule): Promise<void> => {
  for (const ch of rule.channels) { try { await request.post(`/notification/channels/${ch.id}/test`) } catch { /* */ } }
  mfaAwareSuccess(t('app.notification.rules.testSent'))
}

const previewDaily = async (): Promise<void> => {
  try { const res = await request.post<{ data?: { content: string } }>('/notification/daily/preview', { format: 'markdown' }); if (res.data?.content) window.open('', '_blank')?.document.write(`<pre>${res.data.content}</pre>`) } catch { /* */ }
}

onMounted(() => { void fetchRules() })
</script>

<style scoped>
.trigger-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
.trigger-item { margin-bottom: 0; }
.trigger-item.active { border-left: 3px solid var(--el-color-primary); }
.trigger-item :deep(.el-card__body) { padding: 14px; }
.trigger-head { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.trigger-name { font-size: 14px; font-weight: 600; color: #111827; flex: 1; }
.trigger-tpl-btn { margin-left: auto; }
.trigger-detail { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.trigger-time { width: 100px; }
.trigger-count { font-size: 12px; color: #6b7280; }
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; }
.tpl-preview { background: #f9fafb; padding: 10px; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
.trigger-events { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.ev-tag { font-size: 11px; }
.ev-more { font-size: 11px; color: #6b7280; }
.fmt-hints { display: flex; flex-direction: column; gap: 6px; }
.fmt-hint { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #6b7280; }
/* Dashboard stat-item 同构 */
.stat-item { display: flex; align-items: center; gap: 14px; padding: 16px; background: #f9fafb; border-radius: 8px; }
.stat-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
.stat-blue { background: #eff6ff; color: #3b82f6; }
.stat-purple { background: #f5f3ff; color: #8b5cf6; }
.stat-green { background: #ecfdf5; color: #10b981; }
.stat-orange { background: #fff7ed; color: #f59e0b; }
.stat-value { font-size: 20px; font-weight: 600; color: #111827; line-height: 1.2; }
.stat-label { font-size: 12px; color: #6b7280; margin-top: 2px; }
</style>
