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
      <!-- Tab 0: 概览（全平台仪表盘：统计+趋势+三维分布；不区分用户） -->
      <el-tab-pane :label="t('app.notification.rules.overviewTab')" name="overview">
        <el-card class="overview-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><DataAnalysis /></el-icon>
                <span>{{ t('app.notification.rules.statsTitle') }}</span>
              </div>
              <span v-if="isAdmin" class="scope-hint">{{ t('app.notification.rules.allPlatformHint') }}</span>
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

        <!-- 投递分布三维（每通道结果口径，7 天） -->
        <el-row :gutter="16" class="overview-charts">
          <el-col :xs="24" :md="8">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon pie-icon"><ChatDotRound /></el-icon>
                    <span>{{ t('app.notification.rules.distByChannelTitle') }}</span>
                  </div>
                </div>
              </template>
              <div class="chart-container">
                <v-chart v-if="deliveryStats.by_channel.length" :option="byChannelOption" autoresize />
                <el-empty v-else :description="t('app.notification.rules.distEmpty')" :image-size="60" />
              </div>
            </el-card>
          </el-col>
          <el-col :xs="24" :md="8">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon chart-icon"><Odometer /></el-icon>
                    <span>{{ t('app.notification.rules.distRateTitle') }}</span>
                  </div>
                </div>
              </template>
              <div class="chart-container">
                <v-chart v-if="deliveryStats.by_type.length" :option="rateByTypeOption" autoresize />
                <el-empty v-else :description="t('app.notification.rules.distEmpty')" :image-size="60" />
              </div>
            </el-card>
          </el-col>
          <el-col :xs="24" :md="8">
            <el-card class="chart-card">
              <template #header>
                <div class="card-header">
                  <div class="card-title">
                    <el-icon class="title-icon"><Bell /></el-icon>
                    <span>{{ t('app.notification.rules.distByEventTitle') }}</span>
                  </div>
                </div>
              </template>
              <div class="chart-container">
                <v-chart v-if="deliveryStats.by_event.length" :option="byEventOption" autoresize />
                <el-empty v-else :description="t('app.notification.rules.distEmpty')" :image-size="60" />
              </div>
            </el-card>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- Tab 1: 通道管理 -->
      <el-tab-pane :label="t('app.notification.rules.channelsTab')" name="channels">
        <ChannelCards />
      </el-tab-pane>

      <!-- Tab 2: 通知规则（每日摘要独立卡片 + 事件规则表格） -->
      <el-tab-pane :label="t('app.notification.rules.rulesTab')" name="rules">
        <!-- 每日摘要：独立交互卡片（定时摘要与事件规则形态不同，不混表格） -->
        <el-card v-if="dailyRule" class="daily-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon daily-icon"><Calendar /></el-icon>
                <span>{{ t('app.notification.rules.dailyTitle') }}</span>
              </div>
              <div class="card-header-actions">
                <el-button size="small" link type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
                <el-switch v-model="dailyRule.enabled" size="small" @change="toggleRule(dailyRule)" />
              </div>
            </div>
          </template>
          <div class="daily-body">
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.dailySendTime') }}</span>
              <el-time-select v-model="dailyRule.send_time" start="00:00" step="00:30" end="23:30" size="small" style="width:110px" @change="saveRuleField(dailyRule)" />
              <span class="form-hint">{{ t('app.notification.rules.dailyTimeHint') }}</span>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.sendTo') }}</span>
              <div class="daily-channels">
                <el-tag v-for="ch in (dailyRule.channels || [])" :key="ch.id" size="small" effect="plain">{{ ch.name }}</el-tag>
                <span v-if="!(dailyRule.channels || []).length" class="ev-more">{{ t('app.notification.rules.noChannelsHint') }}</span>
              </div>
            </div>
          </div>
        </el-card>

        <el-card class="list-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Bell /></el-icon>
                <span>{{ t('app.notification.rules.eventRulesTitle') }}</span>
              </div>
              <div v-if="isAdmin" class="card-header-actions">
                <el-select v-model="rulesUserId" size="small" style="width:160px" @change="fetchRules">
                  <el-option v-for="u in adminUsers" :key="u.id" :value="u.id" :label="u.username" />
                </el-select>
                <span class="privacy-hint">{{ t('app.notification.rules.privacyHint') }}</span>
              </div>
            </div>
          </template>
          <el-table :data="eventRules" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }">
            <el-table-column :label="t('app.notification.rules.trigger')" min-width="110">
              <template #default="{ row }">
                <div class="rule-name-cell">
                  <el-icon :size="16" color="#3b82f6"><Bell /></el-icon>
                  <span class="rule-name-text">{{ row.title }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.events')" min-width="200">
              <template #default="{ row }">
                <el-tag v-for="ev in (row.events || []).slice(0, 3)" :key="ev" size="small" effect="plain" class="mr4">{{ eventTitle(asRule(row), ev) }}</el-tag>
                <el-tooltip v-if="(row.events?.length || 0) > 3" :content="remainingEventTitles(asRule(row))" placement="top">
                  <span class="ev-more">+{{ row.events!.length - 3 }}</span>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.minLevel')" width="120" align="center">
              <template #default="{ row }">
                <el-select v-model="row.min_level" size="small" style="width:96px" @change="saveRuleField(asRule(row))">
                  <el-option value="info" :label="t('app.notification.subs.levels.info')" />
                  <el-option value="warn" :label="t('app.notification.subs.levels.warn')" />
                  <el-option value="critical" :label="t('app.notification.subs.levels.critical')" />
                </el-select>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.sendTo')" min-width="130">
              <template #default="{ row }">
                <template v-if="row.channel_ids && row.channel_ids.length === 0">
                  <span class="ev-more">{{ t('app.notification.rules.noDelivery') }}</span>
                </template>
                <template v-else>
                  <el-tag v-for="ch in (row.channels || []).slice(0, 2)" :key="ch.id" size="small" effect="plain" class="mr4">{{ ch.name }}</el-tag>
                  <span v-if="(row.channels?.length || 0) > 2" class="ev-more">+{{ row.channels!.length - 2 }}</span>
                </template>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.bodyTemplate')" width="90" align="center">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="editTemplate(asRule(row))">{{ t('app.notification.rules.edit') }}</el-button>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.enabled')" width="65" align="center">
              <template #default="{ row }"><el-switch v-model="row.enabled" size="small" @change="toggleRule(asRule(row))" /></template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.actions')" width="80" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" :loading="testingRuleId === row.id" @click="testRule(asRule(row))">{{ t('app.notification.rules.test') }}</el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!loading && eventRules.length === 0" :description="t('app.notification.rules.emptyText')" :image-size="80" />
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

    <!-- 规则编辑弹窗：接收通道选择 + 每通道消息模板（通道 tab 随实际通道动态生成） -->
    <el-dialog v-model="tplDialogVisible" class="dialog-body-inset rule-edit-dialog" width="min(860px, 94vw)" top="5vh">
      <template #header>
        <DialogHeader :icon="Bell" :title="t('app.notification.rules.editTemplateTitle')" :subtitle="tplEditingRule?.title || ''" tone="primary" />
      </template>

      <!-- 接收通道：勾选=仅发选定通道；全不选=不投递（保存即生效） -->
      <div class="tpl-section-label">{{ t('app.notification.rules.sendTo') }}</div>
      <div class="rule-ch-select">
        <el-checkbox-group v-model="tplSelectedChannels">
          <el-checkbox v-for="ch in userChannels" :key="ch.id" :value="ch.id" border size="small">
            {{ ch.name }}（{{ channelTypeLabel(ch.type) }}）
          </el-checkbox>
        </el-checkbox-group>
        <div class="form-hint">{{ t('app.notification.rules.channelSelectHint') }}</div>
        <div v-if="tplSelectedChannels.length === 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.rules.noDeliveryWarn') }}</span></div>
      </div>

      <el-divider />

      <!-- 每通道模板：tab=选定通道；未选通道时仍可编辑全部通道模板（保存后不投递） -->
      <template v-if="userChannels.length">
        <el-radio-group v-model="tplChannelTab" size="small" class="tpl-channel-switch">
          <el-radio-button v-for="ch in tplTabChannels" :key="ch.id" :value="String(ch.id)">{{ ch.name }}</el-radio-button>
        </el-radio-group>

        <div class="tpl-field">
          <div class="tpl-section-head">
            <div class="tpl-section-label">{{ tplEditorLabel }}</div>
            <el-button size="small" link type="primary" @click="resetTplToDefault">{{ t('app.notification.rules.tplDefault') }}</el-button>
          </div>
          <!-- JSON/HTML/Markdown 高亮编辑（CodeEditor 全站单源）；微信纯文本用 textarea -->
          <CodeEditor v-if="tplEditorLang !== 'text'" v-model="tplText" :language="tplEditorLang" height="220px" :aria-label="tplEditorLabel" />
          <el-input v-else v-model="tplText" type="textarea" :rows="7" :placeholder="defaultTplFor(tplActiveChannel?.type || 'wx_clawbot')" />
          <div class="ph-row">
            <el-tag v-for="ph in tplPh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag>
          </div>
          <div class="form-hint">{{ t('app.notification.rules.tplPhHint') }}</div>
          <div v-if="tplActiveChannel?.type === 'email'" class="form-hint">{{ t('app.notification.rules.tplSubjectHint') }}</div>
          <div v-if="tplActiveChannel?.type === 'qq'" class="form-hint">{{ t('app.notification.rules.tplQqMdHint') }}</div>
          <div class="form-hint">{{ t('app.notification.rules.templateHint') }}</div>
        </div>

        <el-divider />
        <div class="tpl-section-head">
          <div class="tpl-section-label">{{ t('app.notification.rules.preview') }}</div>
          <el-radio-group v-if="tplActiveChannel?.type === 'email'" v-model="emailPreviewMode" size="small">
            <el-radio-button value="render">{{ t('app.notification.rules.previewRender') }}</el-radio-button>
            <el-radio-button value="source">{{ t('app.notification.rules.previewSource') }}</el-radio-button>
          </el-radio-group>
        </div>
        <!-- 邮件 HTML：sandbox iframe 渲染预览（无脚本/无同源）；其余纯文本 pre -->
        <iframe v-if="tplActiveChannel?.type === 'email' && emailPreviewMode === 'render'" class="tpl-html-preview" sandbox="" :srcdoc="previewText" :title="t('app.notification.rules.preview')" />
        <pre v-else class="tpl-preview">{{ previewText }}</pre>
      </template>
      <el-empty v-else :description="t('app.notification.rules.noChannelsHint')" :image-size="60" />

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
import { ElMessage } from 'element-plus'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import { axisChartBase, barSeries, lineSeries, pieChartBase, chartColors } from '@/utils/chartBase'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import DialogHeader from '@/components/DialogHeader.vue'
import CodeEditor from '@/components/CodeEditor.vue'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const activeTab = ref('overview')

interface RuleChannel { id: number; type: string; name: string }
interface Rule {
  id: string; trigger: string; title: string; events?: string[]
  event_titles?: Record<string, string>; min_level?: string; send_time?: string
  channels: RuleChannel[]; channel_ids?: number[]; channel_templates?: Record<string, string>
  body_template: string; enabled: boolean
}

// 事件可读标题（catalog title 单源；禁止裸事件键展示）
const eventTitle = (row: Rule, ev: string): string => row.event_titles?.[ev] || ev
const remainingEventTitles = (row: Rule): string =>
  (row.events || []).slice(3).map(ev => eventTitle(row, ev)).join('、')

const overviewStats = ref({ channels: 0, rules: 0, deliveries: 0, successRate: 0 })
const rulesUserId = ref<number>(0) // 管理员视角用户（0=未初始化，adminUsers 到达后默认本人）；非管理员恒本人
const adminUsers = ref<{ id: number; username: string }[]>([])
const channelDist = ref<{ type: string; count: number }[]>([])
const userChannels = ref<RuleChannel[]>([])

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

// 投递分布三维（delivery-stats：每通道结果口径，7 天）
interface DeliveryStats {
  by_channel: { channel_id: number; name: string; type: string; total: number; sent: number; rate: number }[]
  by_type: { type: string; total: number; sent: number; rate: number }[]
  by_event: { event_type: string; title: string; total: number }[]
}
const deliveryStats = ref<DeliveryStats>({ by_channel: [], by_type: [], by_event: [] })
const byChannelOption = computed<EChartsOption>(() => pieChartBase(
  deliveryStats.value.by_channel.map(d => ({ name: d.name, value: d.total })),
))
const rateByTypeOption = computed<EChartsOption>(() => {
  const rows = deliveryStats.value.by_type
  const name = t('app.notification.rules.trendRate')
  return axisChartBase([name], rows.map(d => channelTypeLabel(d.type)), [
    barSeries(name, chartColors.blue, rows.map(d => Math.round(d.rate * 100)), { barMaxWidth: 36 }),
  ], { yExtra: { min: 0, max: 100, axisLabel: { fontSize: 10, color: '#9ca3af', formatter: '{value}%' } } })
})
const byEventOption = computed<EChartsOption>(() => {
  const rows = deliveryStats.value.by_event
  const name = t('app.notification.rules.statDeliveries')
  const opt = axisChartBase([name], rows.map(d => d.title), [
    barSeries(name, chartColors.purple, rows.map(d => d.total), { barMaxWidth: 18 }),
  ], { yExtra: { minInterval: 1 } })
  // 横向条形（事件标题长，类目轴换 y）：grid 左侧留白给标题
  return { ...opt, grid: { left: 8, right: 24, top: 15, bottom: 32, containLabel: true }, xAxis: { type: 'value', minInterval: 1, axisLine: { show: false }, axisLabel: { fontSize: 10, color: '#9ca3af' }, splitLine: { lineStyle: { color: '#f3f4f6' } } }, yAxis: { type: 'category', data: rows.map(d => d.title), axisLine: { lineStyle: { color: '#e5e7eb' } }, axisLabel: { fontSize: 10, color: '#6b7280', width: 90, overflow: 'truncate' } } }
})
const fetchDeliveryStats = async (): Promise<void> => {
  try {
    const res = await request.get<{ data?: DeliveryStats }>('/notification/delivery-stats', { silent: true })
    if (res.data) deliveryStats.value = { by_channel: res.data.by_channel ?? [], by_type: res.data.by_type ?? [], by_event: res.data.by_event ?? [] }
  } catch { /* keep empty */ }
}

const fetchTrend = async (): Promise<void> => {
  try {
    // 概览=全平台口径（管理员）；普通用户端点自动收窄本人
    const res = await request.get<{ data?: { trend: { date: string; total: number; sent: number; rate: number }[] } }>('/notification/delivery-trend', { silent: true })
    trendData.value = res.data?.trend ?? []
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
    const res = await request.get<{ data?: { stats: { channels: number; rules: number; deliveries: number; success_rate: number }; channel_by_type?: { type: string; count: number }[]; users: { id: number; username: string }[] } }>('/notification/admin/overview', { silent: true })
    if (res.data?.stats) {
      overviewStats.value = { channels: res.data.stats.channels, rules: res.data.stats.rules, deliveries: res.data.stats.deliveries, successRate: res.data.stats.success_rate }
    }
    channelDist.value = res.data?.channel_by_type ?? []
    adminUsers.value = res.data?.users ?? []
    // 规则视角默认本人（首次到达时初始化；不覆盖用户已选）
    if (rulesUserId.value === 0 && authStore.user?.id) rulesUserId.value = authStore.user.id
  } catch { /* */ }
}
const asRule = (row: unknown): Rule => row as Rule
const loading = ref(false)
const rules = ref<Rule[]>([])
const eventRules = computed(() => rules.value.filter(r => r.trigger === 'event'))
const dailyRule = computed(() => rules.value.find(r => r.trigger === 'daily') ?? null)
const testingRuleId = ref<string | null>(null)

// ===== 规则编辑弹窗（通道选择 + 每通道模板） =====
const tplDialogVisible = ref(false)
const tplEditingRule = ref<Rule | null>(null)
const tplSelectedChannels = ref<number[]>([])
const tplChannelTab = ref('') // 通道 ID 字符串
const tplTexts = ref<Record<string, string>>({}) // 通道 ID → 草稿模板
const emailPreviewMode = ref<'render' | 'source'>('render')
const savingTpl = ref(false)
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}', '{{event}}', '{{node}}']

// 模板 tab 通道集：有选定=选定通道；未选=全部通道（仍可编辑模板，保存后不投递）
const tplTabChannels = computed<RuleChannel[]>(() => {
  if (tplSelectedChannels.value.length === 0) return userChannels.value
  return userChannels.value.filter(ch => tplSelectedChannels.value.includes(ch.id))
})
const tplActiveChannel = computed(() => tplTabChannels.value.find(ch => String(ch.id) === tplChannelTab.value) ?? tplTabChannels.value[0])
const tplText = computed({
  get: () => tplTexts.value[tplChannelTab.value] ?? '',
  set: (v: string) => { tplTexts.value = { ...tplTexts.value, [tplChannelTab.value]: v } },
})
const tplEditorLang = computed(() => {
  const typ = tplActiveChannel.value?.type
  if (typ === 'webhook') return 'json'
  if (typ === 'email') return 'markup'
  if (typ === 'qq') return 'markdown'
  return 'text'
})
const tplEditorLabel = computed(() => {
  const typ = tplActiveChannel.value?.type
  if (typ === 'webhook') return t('app.notification.rules.tplJson')
  if (typ === 'email') return t('app.notification.rules.tplBody')
  return t('app.notification.rules.tplText')
})

// 精美预置模板（各通道最佳实践形态）：
// - QQ：markdown 富文本（官方 msg_type=2；标题+引用正文+元信息行）
// - 微信：iLink 纯文本协议，清晰分隔线形态（无 markdown 能力）
// - webhook：完整六键 JSON（与默认载荷同构）
// - email：内联样式 HTML 卡片（邮件客户端兼容：table 布局+内联 CSS）
const defaultTplFor = (typ: string): string => {
  if (typ === 'webhook') return JSON.stringify({ level: '{{level}}', time: '{{time}}', node: '{{node}}', title: '{{title}}', body: '{{body}}', event: '{{event}}' }, null, 2)
  if (typ === 'email') return [
    '<div style="max-width:560px;margin:0 auto;font-family:\'Helvetica Neue\',Arial,\'PingFang SC\',\'Microsoft YaHei\',sans-serif;">',
    '  <div style="background:#1e293b;padding:18px 24px;">',
    '    <span style="color:#f8fafc;font-size:16px;font-weight:600;">Lazy Balancer</span>',
    '    <span style="float:right;background:#ef4444;color:#fff;font-size:11px;padding:2px 10px;border-radius:10px;">{{level}}</span>',
    '  </div>',
    '  <div style="border:1px solid #e2e8f0;border-top:none;padding:24px;">',
    '    <h2 style="margin:0 0 12px;font-size:18px;color:#0f172a;">{{title}}</h2>',
    '    <p style="margin:0 0 16px;font-size:14px;line-height:1.7;color:#334155;">{{body}}</p>',
    '    <table style="width:100%;font-size:12px;color:#64748b;border-top:1px solid #f1f5f9;padding-top:12px;">',
    '      <tr><td style="padding:4px 0;">事件</td><td style="text-align:right;">{{event}}</td></tr>',
    '      <tr><td style="padding:4px 0;">节点</td><td style="text-align:right;">{{node}}</td></tr>',
    '      <tr><td style="padding:4px 0;">时间</td><td style="text-align:right;">{{time}}</td></tr>',
    '    </table>',
    '  </div>',
    '  <p style="text-align:center;font-size:11px;color:#94a3b8;margin:16px 0;">此邮件由 Lazy Balancer 通知中心自动发送</p>',
    '</div>',
  ].join('\n')
  if (typ === 'qq') return '# {{title}}\n\n> {{body}}\n\n**级别**：{{level}}　**事件**：{{event}}\n**节点**：{{node}}　**时间**：{{time}}'
  return '【{{title}}】\n────────────\n{{body}}\n────────────\n级别：{{level}} | 事件：{{event}}\n节点：{{node}} | 时间：{{time}}'
}
const resetTplToDefault = (): void => {
  if (tplActiveChannel.value) tplText.value = defaultTplFor(tplActiveChannel.value.type)
}
const previewText = computed(() => tplText.value
  .replace(/\{\{title\}\}/g, t('app.notification.rules.previewSampleTitle'))
  .replace(/\{\{body\}\}/g, t('app.notification.rules.previewSampleBody'))
  .replace(/\{\{level\}\}/g, 'critical')
  .replace(/\{\{event\}\}/g, 'cert.failed')
  .replace(/\{\{node\}\}/g, 'node-a')
  .replace(/\{\{time\}\}/g, '2026-11-18 09:00'))

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    // 默认当前用户；管理员可选其他用户（规则/通道按用户区分，概览才全平台）
    const rulesUrl = isAdmin.value && rulesUserId.value > 0 ? `/notification/rules?user_id=${rulesUserId.value}` : '/notification/rules'
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels?: RuleChannel[] } }>(rulesUrl)
    rules.value = res.data?.rules ?? []
    userChannels.value = res.data?.channels ?? []
    if (!isAdmin.value) {
      const chs = userChannels.value
      overviewStats.value = { channels: chs.length, rules: rules.value.filter(r => r.enabled).length, deliveries: overviewStats.value.deliveries, successRate: overviewStats.value.successRate }
      const counts = new Map<string, number>()
      for (const ch of chs) counts.set(ch.type, (counts.get(ch.type) ?? 0) + 1)
      channelDist.value = [...counts.entries()].map(([type, count]) => ({ type, count }))
    }
  } catch (e) { console.error(e) } finally { loading.value = false }
}

// 写请求归属：管理员在他人视角时代管该用户（?user_id 与 GET 视角同口径）
const ruleWriteUrl = (ruleId: string): string =>
  isAdmin.value && rulesUserId.value > 0 && rulesUserId.value !== authStore.user?.id
    ? `/notification/rules/${ruleId}?user_id=${rulesUserId.value}`
    : `/notification/rules/${ruleId}`

const toggleRule = async (rule: Rule): Promise<void> => {
  try { await request.post(ruleWriteUrl(rule.id), { enabled: rule.enabled }) }
  catch { rule.enabled = !rule.enabled }
}

const saveRuleField = async (rule: Rule): Promise<void> => {
  // 部分更新：只提交变更字段（后端缺省键不动既有值）
  const body = rule.trigger === 'daily' ? { send_time: rule.send_time } : { min_level: rule.min_level }
  try { await request.post(ruleWriteUrl(rule.id), body) } catch { /* */ }
}

const editTemplate = (rule: Rule): void => {
  tplEditingRule.value = rule
  // channel_ids 三态：undefined=缺省（全部通道，UI 呈现为全选）；[]=显式不投递
  tplSelectedChannels.value = rule.channel_ids === undefined || rule.channel_ids === null
    ? userChannels.value.map(ch => ch.id)
    : [...rule.channel_ids]
  // 草稿初始化：既有每通道模板 > 事件级模板 > 通道形态预置
  const drafts: Record<string, string> = {}
  for (const ch of userChannels.value) {
    drafts[String(ch.id)] = rule.channel_templates?.[String(ch.id)] || rule.body_template || defaultTplFor(ch.type)
  }
  tplTexts.value = drafts
  const targets = tplSelectedChannels.value.length ? userChannels.value.filter(ch => tplSelectedChannels.value.includes(ch.id)) : userChannels.value
  tplChannelTab.value = targets.length ? String(targets[0].id) : ''
  emailPreviewMode.value = 'render'
  tplDialogVisible.value = true
}
// 通道选择变化：tab 不在当前 tab 集内时回落到首个
watch(tplSelectedChannels, () => {
  if (!tplTabChannels.value.some(ch => String(ch.id) === tplChannelTab.value)) {
    tplChannelTab.value = tplTabChannels.value.length ? String(tplTabChannels.value[0].id) : ''
  }
}, { deep: true })

const saveTemplate = async (): Promise<void> => {
  if (!tplEditingRule.value || savingTpl.value) return
  savingTpl.value = true
  try {
    // 通道选择 + 每通道模板（部分更新：不动启用态/级别/时间）。
    // 仅提交与预置/事件级模板不同的草稿（空差异=沿用默认链）。
    const tpls: Record<string, string> = {}
    for (const ch of userChannels.value) {
      const draft = tplTexts.value[String(ch.id)] ?? ''
      if (draft && draft !== defaultTplFor(ch.type)) tpls[String(ch.id)] = draft
    }
    await request.post(ruleWriteUrl(tplEditingRule.value.id), {
      channel_ids: tplSelectedChannels.value,
      channel_templates: tpls,
    })
    tplEditingRule.value.channel_ids = [...tplSelectedChannels.value]
    tplEditingRule.value.channel_templates = tpls
    mfaAwareSuccess(t('app.notification.rules.saved'))
    tplDialogVisible.value = false
    await fetchRules()
  } catch (e) { console.error(e) } finally { savingTpl.value = false }
}

const testRule = async (rule: Rule): Promise<void> => {
  // 按规则选定通道+每通道模板渲染发送（后端 TestRuleDelivery；不落投递行）
  if (testingRuleId.value !== null) return
  testingRuleId.value = rule.id
  try {
    const base = ruleWriteUrl(rule.id)
    const url = base.includes('?') ? base.replace('?', '/test?') : base + '/test'
    const res = await request.post<{ code: number; message?: string }>(url, {}, { silent: true })
    if (res.code === 0) mfaAwareSuccess(res.message || t('app.notification.rules.testSent'))
    else ElMessage.error(res.message || t('app.notification.rules.testFailed'))
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : t('app.notification.rules.testFailed'))
  } finally { testingRuleId.value = null }
}

const previewDaily = async (): Promise<void> => {
  try { const res = await request.post<{ data?: { content: string } }>('/notification/daily/preview', { format: 'markdown' }); if (res.data?.content) window.open('', '_blank')?.document.write(`<pre>${res.data.content}</pre>`) } catch { /* */ }
}

onMounted(() => {
  void fetchRules()
  void fetchAdminOverview()
  void fetchTrend()
  void fetchDeliveryStats()
})
</script>

<style scoped>
/* Dashboard 卡片规范同构（DESIGN_SPEC.md §2：边框 #ebeef5）。
 * tab 内容区 overflow:hidden 会裁剪卡片四周阴影——padding 留出阴影空间。 */
:deep(.el-tabs__content) { overflow: visible; }
.el-tab-pane { padding: 6px; margin: -6px; }
.el-card { --el-card-border-color: #ebeef5; }
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
.scope-hint { font-size: 12px; color: #9ca3af; }
.rule-ch-select { margin-bottom: 4px; }
.rule-ch-select :deep(.el-checkbox) { margin-right: 12px; margin-bottom: 6px; }
.tpl-html-preview { width: 100%; height: 300px; border: 1px solid #e5e7eb; background: #fff; }
.rule-edit-dialog :deep(.el-dialog__body) { max-height: calc(100dvh - 180px); overflow-y: auto; }
.daily-card { margin-bottom: 16px; }
.daily-icon { color: #8b5cf6; }
.daily-body { display: flex; flex-direction: column; gap: 12px; }
.daily-field { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.daily-label { font-size: 13px; color: #4b5563; flex: none; width: 70px; }
.daily-channels { display: flex; gap: 6px; flex-wrap: wrap; }
</style>