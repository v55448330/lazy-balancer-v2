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
        <!-- 管理员：用户筛选器 -->
        <div v-if="isAdmin" class="overview-filter">
          <el-select v-model="adminUserId" size="small" clearable placeholder="全平台" style="width:160px" @change="fetchAdminOverview">
            <el-option v-for="u in adminUsers" :key="u.id" :value="u.id" :label="u.username" />
          </el-select>
        </div>
        <el-row :gutter="16" class="overview-stats">
          <el-col :span="6"><div class="stat-item"><div class="stat-icon stat-blue"><el-icon><ChatDotRound /></el-icon></div><div class="stat-content"><div class="stat-value">{{ overviewStats.channels }}</div><div class="stat-label">{{ t('app.notification.rules.statChannels') }}</div></div></div></el-col>
          <el-col :span="6"><div class="stat-item"><div class="stat-icon stat-purple"><el-icon><Bell /></el-icon></div><div class="stat-content"><div class="stat-value">{{ overviewStats.rules }}</div><div class="stat-label">{{ t('app.notification.rules.statRules') }}</div></div></div></el-col>
          <el-col :span="6"><div class="stat-item"><div class="stat-icon stat-green"><el-icon><CircleCheckFilled /></el-icon></div><div class="stat-content"><div class="stat-value">{{ overviewStats.deliveries }}</div><div class="stat-label">{{ t('app.notification.rules.statDeliveries') }}</div></div></div></el-col>
          <el-col :span="6"><div class="stat-item"><div class="stat-icon" :class="overviewStats.successRate > 0.9 ? 'stat-green' : 'stat-orange'"><el-icon><DataAnalysis /></el-icon></div><div class="stat-content"><div class="stat-value">{{ (overviewStats.successRate * 100).toFixed(1) }}%</div><div class="stat-label">{{ t('app.notification.rules.statSuccessRate') }}</div></div></div></el-col>
        </el-row>
        <!-- 7天投递趋势（简易bar） -->
        <el-card class="trend-card">
          <template #header><div class="card-header"><div class="card-title"><el-icon class="title-icon"><DataAnalysis /></el-icon><span>{{ t('app.notification.rules.trendTitle') }}</span></div></div></template>
          <div class="trend-bars">
            <div v-for="d in trendData" :key="d.date" class="trend-bar-item">
              <div class="trend-bar-fill" :style="{ height: d.pct + '%' }"></div>
              <div class="trend-bar-label">{{ d.date.slice(5) }}</div>
              <div class="trend-bar-value">{{ d.count }}</div>
            </div>
          </div>
        </el-card>
      </el-tab-pane>

      <!-- Tab 1: 通道管理 -->
      <el-tab-pane :label="t('app.notification.rules.channelsTab')" name="channels">
        <ChannelCards />
      </el-tab-pane>

      <!-- Tab 2: 通知规则 -->
      <el-tab-pane :label="t('app.notification.rules.rulesTab')" name="rules">
        <el-table :data="rules" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }">
          <el-table-column :label="t('app.notification.rules.trigger')" min-width="130">
            <template #default="{ row }">
              <div class="rule-name-cell">
                <el-icon :size="16" :style="{ color: row.trigger === 'daily' ? '#8b5cf6' : '#3b82f6' }"><component :is="row.trigger === 'daily' ? Calendar : Bell" /></el-icon>
                <span class="rule-name-text">{{ row.title }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.notification.rules.events')" min-width="200">
            <template #default="{ row }">
              <template v-if="row.trigger === 'daily'">
                <el-time-select v-model="row.send_time" start="00:00" step="00:30" end="23:30" size="small" style="width:100px" @change="saveRuleField(asRule(row))" />
              </template>
              <template v-else>
                <el-tag v-for="ev in (row.events || []).slice(0, 3)" :key="ev" size="small" effect="plain" class="mr4">{{ ev }}</el-tag>
                <span v-if="(row.events?.length || 0) > 3" class="ev-more">+{{ row.events!.length - 3 }}</span>
              </template>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.notification.rules.minLevel')" width="150" align="center">
            <template #default="{ row }">
              <el-radio-group v-if="row.trigger === 'event'" v-model="row.min_level" size="small" @change="saveRuleField(asRule(row))">
                <el-radio-button value="info">Info</el-radio-button>
                <el-radio-button value="warn">Warn</el-radio-button>
                <el-radio-button value="critical">Crit</el-radio-button>
              </el-radio-group>
              <el-button v-else size="small" text type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.notification.rules.sendTo')" min-width="130">
            <template #default="{ row }">
              <el-tag v-for="ch in (row.channels || []).slice(0, 2)" :key="ch.id" size="small" effect="plain" class="mr4">{{ ch.name }}</el-tag>
              <span v-if="(row.channels?.length || 0) > 2" class="ev-more">+{{ row.channels!.length - 2 }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.notification.rules.bodyTemplate')" width="90" align="center">
            <template #default="{ row }">
              <el-button size="small" link type="primary" @click="editTemplate(asRule(row))">{{ row.body_template ? t('app.notification.rules.customTemplate') : t('app.notification.rules.edit') }}</el-button>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.notification.rules.enabled')" width="65" align="center">
            <template #default="{ row }"><el-switch v-model="row.enabled" size="small" @change="toggleRule(asRule(row))" /></template>
          </el-table-column>
          <el-table-column :label="t('app.notification.rules.actions')" width="80" fixed="right">
            <template #default="{ row }">
              <el-button v-if="row.trigger === 'event'" size="small" link type="primary" @click="testRule(asRule(row))">{{ t('app.notification.rules.test') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
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
      <el-tabs v-model="tplChannelTab">
        <el-tab-pane label="QQ" name="qq">
          <el-input v-model="tplText" type="textarea" :rows="5" :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row"><el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag></div>
        </el-tab-pane>
        <el-tab-pane label="微信" name="wx">
          <el-input v-model="tplText" type="textarea" :rows="5" :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row"><el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag></div>
        </el-tab-pane>
        <el-tab-pane label="Webhook" name="webhook">
          <el-input v-model="tplText" type="textarea" :rows="6" placeholder='{"title":"{{title}}","body":"{{body}}","level":"{{level}}"}' />
          <div class="ph-row"><el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag></div>
        </el-tab-pane>
        <el-tab-pane label="邮件" name="email">
          <div class="tpl-section-label">标题模板</div>
          <el-input v-model="tplSubject" placeholder="{{title}}" style="margin-bottom:8px" />
          <div class="tpl-section-label">正文模板</div>
          <el-input v-model="tplText" type="textarea" :rows="4" :placeholder="t('app.notification.rules.templatePlaceholder')" />
          <div class="ph-row"><el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag></div>
        </el-tab-pane>
      </el-tabs>
      <el-divider />
      <div class="tpl-section-label">{{ t('app.notification.rules.preview') }}</div>
      <pre class="tpl-preview">{{ previewText }}</pre>
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
import { Calendar, Bell, ChatDotRound, CircleCheckFilled, DataAnalysis } from '@element-plus/icons-vue'
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
const adminUserId = ref<number | ''>('')
const adminUsers = ref<{ id: number; username: string }[]>([])
const trendData = ref<{ date: string; count: number; pct: number }[]>([])

const fetchAdminOverview = async (): Promise<void> => {
  if (!isAdmin.value) return
  try {
    const res = await request.get<{ data?: { stats: { channels: number; rules: number; deliveries: number; success_rate: number }; users: { id: number; username: string }[] } }>('/notification/admin/overview', { silent: true })
    if (res.data?.stats) {
      overviewStats.value = { channels: res.data.stats.channels, rules: res.data.stats.rules, deliveries: res.data.stats.deliveries, successRate: res.data.stats.success_rate }
    }
    adminUsers.value = res.data?.users ?? []
  } catch { /* */ }
}
const asRule = (row: unknown): Rule => row as Rule
const loading = ref(false)
const rules = ref<Rule[]>([])
const tplDialogVisible = ref(false)
const tplEditingRule = ref<Rule | null>(null)
const tplText = ref('')
const tplChannelTab = ref('qq')
const tplSubject = ref('')
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

onMounted(() => {
  void fetchRules()
  void fetchAdminOverview()
  // 7天趋势（从投递记录统计——简化为静态演示数据，实际应从后端获取）
  const days: { date: string; count: number; pct: number }[] = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000)
    days.push({ date: d.toISOString().slice(0, 10), count: 0, pct: 0 })
  }
  trendData.value = days
})
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
.rule-name-cell { display: flex; align-items: center; gap: 8px; }
.rule-name-text { font-weight: 600; }
.mr4 { margin-right: 4px; }
.tpl-section-label { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 8px; }
.tpl-textarea { margin-bottom: 8px; }
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
/* 概览 */
.overview-filter { margin-bottom: 12px; }
.overview-stats { margin-bottom: 16px; }
.trend-card { margin-top: 16px; }
.trend-bars { display: flex; align-items: flex-end; gap: 12px; height: 120px; padding: 0 8px; }
.trend-bar-item { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; }
.trend-bar-fill { width: 100%; background: var(--el-color-primary); opacity: 0.7; min-height: 2px; transition: height 0.3s; }
.trend-bar-label { font-size: 11px; color: #6b7280; margin-top: 4px; }
.trend-bar-value { font-size: 11px; color: #374151; font-weight: 600; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
</style>
