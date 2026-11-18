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
      <!-- Tab 0: 概览（仪表盘：统计卡+趋势图+通道分布，Dashboard 同构） -->
      <el-tab-pane :label="t('app.notification.rules.overviewTab')" name="overview">
        <el-card class="overview-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><DataAnalysis /></el-icon>
                <span>{{ t('app.notification.rules.statsTitle') }}</span>
              </div>
              <el-select v-if="isAdmin" v-model="adminUserId" size="small" clearable :placeholder="t('app.notification.rules.allPlatform')" style="width:160px" @change="onOverviewFilter">
                <el-option v-for="u in adminUsers" :key="u.id" :value="u.id" :label="u.username" />
              </el-select>
            </div>
          </template>
          <el-row :gutter="16">
            <el-col :xs="12" :sm="6">
              <div class="stat-item">
                <div class="stat-icon stat-blue"><el-icon><ChatDotRound /></el-icon></div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewStats.channels }}</div>
                  <div class="stat-label">{{ t('app.notification.rules.statChannels') }}</div>
                </div>
              </div>
            </el-col>
            <el-col :xs="12" :sm="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple"><el-icon><Bell /></el-icon></div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewStats.rules }}</div>
                  <div class="stat-label">{{ t('app.notification.rules.statRules') }}</div>
                </div>
              </div>
            </el-col>
            <el-col :xs="12" :sm="6">
              <div class="stat-item">
                <div class="stat-icon stat-green"><el-icon><CircleCheckFilled /></el-icon></div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewStats.deliveries }}</div>
                  <div class="stat-label">{{ t('app.notification.rules.statDeliveries') }}</div>
                </div>
              </div>
            </el-col>
            <el-col :xs="12" :sm="6">
              <div class="stat-item">
                <div class="stat-icon" :class="overviewStats.successRate >= 0.9 ? 'stat-green' : 'stat-orange'"><el-icon><Odometer /></el-icon></div>
                <div class="stat-content">
                  <div class="stat-value">{{ (overviewStats.successRate * 100).toFixed(1) }}%</div>
                  <div class="stat-label">{{ t('app.notification.rules.statSuccessRate') }}</div>
                </div>
              </div>
            </el-col>
          </el-row>
        </el-card>

        <el-row :gutter="16" class="overview-charts">
          <el-col :xs="24" :md="14">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon chart-icon"><TrendCharts /></el-icon>
                    <span>{{ t('app.notification.rules.trendTitle') }}</span>
                  </div>
                </div>
              </template>
              <div class="chart-container">
                <v-chart v-if="trendData.length" :option="trendChartOption" autoresize />
                <el-empty v-else :description="t('app.notification.rules.trendEmpty')" :image-size="60" />
              </div>
            </el-card>
          </el-col>
          <el-col :xs="24" :md="10">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon pie-icon"><ChatDotRound /></el-icon>
                    <span>{{ t('app.notification.rules.channelDistTitle') }}</span>
                  </div>
                </div>
              </template>
              <div class="chart-container">
                <v-chart v-if="channelDist.length" :option="channelDistOption" autoresize />
                <el-empty v-else :description="t('app.notification.rules.channelDistEmpty')" :image-size="60" />
              </div>
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- Tab 1: 通道管理 -->
      <el-tab-pane :label="t('app.notification.rules.channelsTab')" name="channels">
        <ChannelCards />
      </el-tab-pane>

      <!-- Tab 2: 通知规则 -->
      <el-tab-pane :label="t('app.notification.rules.rulesTab')" name="rules">
        <el-card class="list-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Bell /></el-icon>
                <span>{{ t('app.notification.rules.rulesTab') }}</span>
              </div>
              <div v-if="isAdmin" class="card-header-actions">
                <el-select v-model="rulesUserId" size="small" clearable :placeholder="t('app.notification.rules.myRules')" style="width:150px" @change="fetchRules">
                  <el-option v-for="u in adminUsers" :key="u.id" :value="u.id" :label="u.username" />
                </el-select>
                <span class="privacy-hint">{{ t('app.notification.rules.privacyHint') }}</span>
              </div>
            </div>
          </template>
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
            <el-table-column :label="t('app.notification.rules.minLevel')" width="120" align="center">
              <template #default="{ row }">
                <el-select v-if="row.trigger === 'event'" v-model="row.min_level" size="small" style="width:96px" @change="saveRuleField(asRule(row))">
                  <el-option value="info" :label="t('app.notification.rules.levelInfo')" />
                  <el-option value="warn" :label="t('app.notification.rules.levelWarn')" />
                  <el-option value="critical" :label="t('app.notification.rules.levelCritical')" />
                </el-select>
                <el-button v-else size="small" link type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.sendTo')" min-width="130">
              <template #default="{ row }">
                <el-tag v-for="ch in (row.channels || []).slice(0, 2)" :key="ch.id" size="small" effect="plain" class="mr4">{{ ch.name }}</el-tag>
                <span v-if="(row.channels?.length || 0) > 2" class="ev-more">+{{ row.channels!.length - 2 }}</span>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.bodyTemplate')" width="110" align="center">
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
        </el-card>
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

    <!-- 模板编辑弹窗（四通道预置模板；邮件标题在通道样式配置，此处正文） -->
    <el-dialog v-model="tplDialogVisible" class="dialog-body-inset" width="min(560px, 94vw)" top="8vh">
      <template #header>
        <DialogHeader :icon="Bell" :title="tplEditingRule?.title || ''" :subtitle="t('app.notification.rules.bodyTemplate')" tone="primary" />
      </template>
      <el-radio-group v-model="tplChannelTab" size="small" class="tpl-channel-switch">
        <el-radio-button value="qq">QQ</el-radio-button>
        <el-radio-button value="wx">{{ t('app.notification.channels.typeWx') }}</el-radio-button>
        <el-radio-button value="webhook">Webhook</el-radio-button>
        <el-radio-button value="email">{{ t('app.notification.channels.typeEmail') }}</el-radio-button>
      </el-radio-group>

      <div class="tpl-field">
        <div class="tpl-section-head">
          <div class="tpl-section-label">{{ tplChannelTab === 'webhook' ? t('app.notification.rules.tplJson') : tplChannelTab === 'email' ? t('app.notification.rules.tplBody') : t('app.notification.rules.tplText') }}</div>
          <el-button size="small" link type="primary" @click="tplText = defaultTplFor(tplChannelTab)">{{ t('app.notification.rules.tplDefault') }}</el-button>
        </div>
        <el-input v-model="tplText" type="textarea" :rows="6" :placeholder="defaultTplFor(tplChannelTab)" />
        <div class="ph-row">
          <el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag>
        </div>
        <div class="form-hint">{{ t('app.notification.rules.tplPhHint') }}</div>
        <div v-if="tplChannelTab === 'email'" class="form-hint">{{ t('app.notification.rules.tplSubjectHint') }}</div>
        <div class="form-hint">{{ t('app.notification.rules.templateHint') }}</div>
      </div>

      <el-divider />
      <div class="tpl-section-label">{{ t('app.notification.rules.preview') }}</div>
      <pre class="tpl-preview">{{ previewText }}</pre>
      <template #footer>
        <el-button @click="tplDialogVisible = false">{{ t('app.notification.rules.cancel') }}</el-button>
        <el-button type="primary" :loading="savingTpl" @click="saveTemplate">{{ t('app.notification.rules.save') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Calendar, Bell, ChatDotRound, CircleCheckFilled, DataAnalysis, Odometer, TrendCharts } from '@element-plus/icons-vue'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import { axisChartBase, barSeries, lineSeries, pieChartBase, chartColors } from '@/utils/chartBase'
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
const rulesUserId = ref<number | ''>('')
const adminUsers = ref<{ id: number; username: string }[]>([])
const channelDist = ref<{ type: string; count: number }[]>([])

// 7 天投递趋势（ECharts：成功/失败堆叠柱 + 成功率折线，SecurityOverview/Dashboard 同构）
const trendData = ref<{ date: string; total: number; sent: number; rate: number }[]>([])
const trendChartOption = computed<EChartsOption>(() => {
  const rows = trendData.value
  const labels = rows.map(d => d.date.slice(5))
  const sentName = t('app.notification.rules.trendSent')
  const failedName = t('app.notification.rules.trendFailed')
  const rateName = t('app.notification.rules.trendRate')
  const opt = axisChartBase(
    [sentName, failedName, rateName],
    labels,
    [
      barSeries(sentName, chartColors.green, rows.map(d => d.sent), { stack: 'total', barMaxWidth: 28 }),
      barSeries(failedName, chartColors.red, rows.map(d => d.total - d.sent), { stack: 'total', barMaxWidth: 28 }),
      lineSeries(rateName, chartColors.blue, rows.map(d => Math.round(d.rate * 100)), { yAxisIndex: 1, areaStyle: undefined, showSymbol: true }),
    ],
    { legendTop: true, yExtra: { minInterval: 1 } },
  )
  // 成功率右轴（0-100%）：单轴基线上追加第二数值轴
  const base = (Array.isArray(opt.yAxis) ? opt.yAxis : [opt.yAxis]).filter((a): a is NonNullable<typeof a> => a != null)
  return { ...opt, yAxis: [...base, { type: 'value' as const, min: 0, max: 100, axisLine: { show: false }, axisLabel: { fontSize: 10, color: '#9ca3af', formatter: '{value}%' }, splitLine: { show: false } }] }
})

const channelTypeLabel = (typ: string): string => {
  switch (typ) {
    case 'webhook': return t('app.notification.channels.typeWebhook')
    case 'email': return t('app.notification.channels.typeEmail')
    case 'qq': return t('app.notification.channels.typeQQ')
    default: return t('app.notification.channels.typeWx')
  }
}
const channelDistOption = computed<EChartsOption>(() => pieChartBase(
  channelDist.value.map(d => ({ name: channelTypeLabel(d.type), value: d.count })),
))

const fetchTrend = async (): Promise<void> => {
  try {
    const uid = adminUserId.value
    const url = uid ? `/notification/delivery-trend?user_id=${uid}` : '/notification/delivery-trend'
    const res = await request.get<{ data?: { trend: { date: string; total: number; sent: number; rate: number }[] } }>(url, { silent: true })
    trendData.value = res.data?.trend ?? []
    // 非管理员无 admin/overview：投递量/成功率由本人 7 天趋势汇总（同口径）
    if (!isAdmin.value) {
      const total = trendData.value.reduce((s, d) => s + d.total, 0)
      const sent = trendData.value.reduce((s, d) => s + d.sent, 0)
      overviewStats.value = { ...overviewStats.value, deliveries: total, successRate: total > 0 ? sent / total : 0 }
    }
  } catch { /* keep empty */ }
}

const fetchAdminOverview = async (): Promise<void> => {
  if (!isAdmin.value) return
  try {
    const url = adminUserId.value ? `/notification/admin/overview?user_id=${adminUserId.value}` : '/notification/admin/overview'
    const res = await request.get<{ data?: { stats: { channels: number; rules: number; deliveries: number; success_rate: number }; channel_by_type?: { type: string; count: number }[]; users: { id: number; username: string }[] } }>(url, { silent: true })
    if (res.data?.stats) {
      overviewStats.value = { channels: res.data.stats.channels, rules: res.data.stats.rules, deliveries: res.data.stats.deliveries, successRate: res.data.stats.success_rate }
    }
    channelDist.value = res.data?.channel_by_type ?? []
    adminUsers.value = res.data?.users ?? []
  } catch { /* */ }
}
const onOverviewFilter = (): void => {
  void fetchAdminOverview()
  void fetchTrend()
}
const asRule = (row: unknown): Rule => row as Rule
const loading = ref(false)
const rules = ref<Rule[]>([])
const tplDialogVisible = ref(false)
const tplEditingRule = ref<Rule | null>(null)
const tplText = ref('')
const tplChannelTab = ref('qq')
// 预置默认模板（实体预填，非仅 placeholder）：四通道形态各异
const defaultTplFor = (ch: string): string => {
  if (ch === 'webhook') return '{"title":"{{title}}","body":"{{body}}","level":"{{level}}","time":"{{time}}"}'
  if (ch === 'email') return '{{title}}\n\n{{body}}\n\n{{level}} · {{time}}'
  return '{{title}}\n{{body}}\n—— {{level}} · {{time}}'
}
const savingTpl = ref(false)
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}']
const previewText = computed(() => tplText.value
  .replace(/\{\{title\}\}/g, t('app.notification.rules.previewSampleTitle'))
  .replace(/\{\{body\}\}/g, t('app.notification.rules.previewSampleBody'))
  .replace(/\{\{level\}\}/g, 'critical')
  .replace(/\{\{time\}\}/g, '2026-11-18 09:00'))

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    const rulesUrl = rulesUserId.value ? `/notification/rules?user_id=${rulesUserId.value}` : '/notification/rules'
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels?: { id: number; type: string }[] } }>(rulesUrl)
    rules.value = res.data?.rules ?? []
    // 非管理员：概览统计来自本人规则/通道（管理员走 admin/overview）
    if (!isAdmin.value) {
      const chs = res.data?.channels ?? []
      overviewStats.value = { channels: chs.length, rules: rules.value.filter(r => r.enabled).length, deliveries: overviewStats.value.deliveries, successRate: overviewStats.value.successRate }
      const counts = new Map<string, number>()
      for (const ch of chs) counts.set(ch.type, (counts.get(ch.type) ?? 0) + 1)
      channelDist.value = [...counts.entries()].map(([type, count]) => ({ type, count }))
    }
  } catch (e) { console.error(e) } finally { loading.value = false }
}

const toggleRule = async (rule: Rule): Promise<void> => {
  try { await request.post(`/notification/rules/${rule.id}`, { enabled: rule.enabled }) }
  catch { rule.enabled = !rule.enabled }
}

const saveRuleField = async (rule: Rule): Promise<void> => {
  // 部分更新：只提交变更字段（后端缺省键不动既有值）
  const body = rule.trigger === 'daily' ? { send_time: rule.send_time } : { min_level: rule.min_level }
  try { await request.post(`/notification/rules/${rule.id}`, body) } catch { /* */ }
}

const editTemplate = (rule: Rule): void => {
  tplEditingRule.value = rule
  tplChannelTab.value = 'qq'
  tplText.value = rule.body_template || defaultTplFor('qq')
  tplDialogVisible.value = true
}
// 通道切换：预置模板随通道形态切换（QQ/微信文本、Webhook JSON、邮件正文）；
// 事件模板为单一 body_template，切换即换预置形态，保存以当前文本为准。
watch(tplChannelTab, (ch) => {
  if (tplDialogVisible.value) tplText.value = defaultTplFor(ch)
})

const saveTemplate = async (): Promise<void> => {
  if (!tplEditingRule.value || savingTpl.value) return
  savingTpl.value = true
  try {
    // 只写模板：不得改动启用状态/级别/时间（部分更新语义）
    await request.post(`/notification/rules/${tplEditingRule.value.id}`, { body_template: tplText.value })
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
  void fetchTrend()
})
</script>

<style scoped>
/* Dashboard 卡片规范同构（card-header/card-title/title-icon/stat-item） */
.card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; row-gap: 8px; }
.card-header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }
.chart-icon { color: #f59e0b; }
.pie-icon { color: #8b5cf6; }
.stat-item { display: flex; align-items: center; gap: 14px; padding: 16px; background: #f9fafb; border-radius: 8px; }
.stat-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
.stat-blue { background: #eff6ff; color: #3b82f6; }
.stat-purple { background: #f5f3ff; color: #8b5cf6; }
.stat-green { background: #ecfdf5; color: #10b981; }
.stat-orange { background: #fff7ed; color: #f59e0b; }
.stat-value { font-size: 20px; font-weight: 600; color: #111827; line-height: 1.2; }
.stat-label { font-size: 12px; color: #6b7280; margin-top: 2px; }
.overview-card { margin-bottom: 16px; }
.overview-charts { margin-bottom: 16px; }
.chart-card :deep(.el-card__body) { height: 280px; padding: 16px; box-sizing: border-box; }
.chart-container { height: 248px; }
.chart-container .echarts { height: 100%; }
.privacy-hint { font-size: 12px; color: #9ca3af; }
.rule-name-cell { display: flex; align-items: center; gap: 8px; }
.rule-name-text { font-weight: 600; }
.mr4 { margin-right: 4px; }
.ev-more { font-size: 11px; color: #6b7280; }
.tpl-channel-switch { margin-bottom: 16px; }
.tpl-field { margin-bottom: 12px; }
.tpl-section-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.tpl-section-head .tpl-section-label { margin-bottom: 0; }
.tpl-section-label { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 8px; }
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; }
.tpl-preview { background: #f9fafb; padding: 10px; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
</style>