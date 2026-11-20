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
                <template v-if="dailyDraftDirty">
                  <el-button size="small" type="primary" :loading="savingDaily" @click="saveDailyDraft">{{ t('app.notification.rules.save') }}</el-button>
                  <el-button size="small" @click="cancelDailyDraft">{{ t('app.notification.rules.cancel') }}</el-button>
                </template>
                <el-button size="small" link type="primary" @click="openDailyTpl">{{ t('app.notification.daily.editTemplate') }}</el-button>
                <el-button size="small" link type="primary" :loading="testingDaily" @click="testDaily">{{ t('app.notification.daily.testSend') }}</el-button>
                <el-button size="small" link type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
                <el-switch v-model="dailyRule.enabled" size="small" @change="toggleRule(dailyRule)" />
              </div>
            </div>
          </template>
          <div v-if="dailyDraft" class="daily-body">
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.dailySendTime') }}</span>
              <el-time-select v-model="dailyDraft.send_time" start="00:00" end="23:30" step="00:30" size="small" style="width: 120px" />
              <span class="form-hint">{{ t('app.notification.rules.dailyTimeHint') }}</span>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.daily.itemsLabel') }}</span>
              <el-checkbox-group v-model="dailyDraft.items" size="small" class="notif-pick-group daily-items">
                <el-checkbox v-for="opt in dailyItemOptions" :key="opt.id" :value="opt.id" border size="small">{{ dailyItemLabel(opt.id) }}</el-checkbox>
              </el-checkbox-group>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.sendTo') }}</span>
              <div class="daily-ch-select">
                <el-checkbox-group v-model="dailyDraft.channel_ids" size="small" class="notif-pick-group">
                  <el-checkbox v-for="ch in channelOptions" :key="ch.id" :value="ch.id" border size="small" :disabled="ch.enabled === false || ch.last_test_ok !== true" :title="channelPickTitle(ch)">
                    {{ ch.name }}（{{ channelTypeLabel(ch.type) }}）
                  </el-checkbox>
                </el-checkbox-group>
                <div class="form-hint">{{ t('app.notification.rules.channelSelectHint') }}</div>
                <div v-if="hasDisabledChannels" class="form-hint">{{ t('app.notification.rules.channelDisabledHint') }}</div>
                <span v-if="!userChannels.length" class="ev-more">{{ t('app.notification.rules.noChannelsHint') }}</span>
                <div class="daily-warn-slot">
                  <div v-if="dailyDraft.channel_ids.length === 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.rules.noDeliveryWarn') }}</span></div>
                </div>
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
              <div class="card-header-actions">
                <template v-if="anyRuleDirty">
                  <el-button size="small" type="primary" :loading="savingAllRules" @click="saveAllRuleDrafts">{{ t('app.notification.rules.save') }}</el-button>
                  <el-button size="small" @click="cancelAllRuleDrafts">{{ t('app.notification.rules.cancel') }}</el-button>
                </template>
                <div v-if="isAdmin" class="user-pick">
                  <span class="user-pick-label">{{ t('app.notification.rules.userLabel') }}</span>
                  <el-select v-model="rulesUserId" size="small" style="width:160px" @change="() => fetchRules(true)">
                    <el-option v-for="u in adminUsers" :key="u.id" :value="u.id" :label="u.username" />
                  </el-select>
                </div>
              </div>
            </div>
          </template>
          <el-table :data="eventRules" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb', color: '#374151', fontWeight: 600 }">
            <el-table-column :label="t('app.notification.rules.trigger')" width="90">
              <template #default="{ row }">
                <span class="rule-name-text">{{ eventGroup(row.title) }}</span>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.events')" min-width="360">
              <template #default="{ row }">
                <el-popover placement="bottom-start" trigger="click" :width="pickWidth.events" :popper-options="pickPopperOptions" popper-class="nd-pick-popper">
                  <template #reference>
                    <button type="button" class="pick-trigger pick-trigger--events" :title="ruleEventSummary(asRule(row))" @click="measurePickWidth($event, 'events')">
                      <span class="pick-summary" :class="{ 'is-empty': ruleDraftOf(asRule(row)).events.length === 0 }">{{ ruleEventSummary(asRule(row)) }}</span>
                      <el-icon class="pick-caret"><ArrowDown /></el-icon>
                    </button>
                  </template>
                  <div class="notif-pick-panel">
                    <el-checkbox-group v-model="ruleDraftOf(asRule(row)).events" size="small" class="notif-pick-group notif-pick-sections">
                      <div v-for="sec in eventLevelSections(asRule(row))" :key="sec.level" class="notif-level-section" :class="`is-${sec.level}`">
                        <div class="notif-level-head">{{ t(`app.notification.subs.levels.${sec.level}`) }}</div>
                        <div class="notif-level-items">
                          <el-checkbox v-for="ev in sec.events" :key="ev" :value="ev" border size="small">{{ eventTitle(asRule(row), ev) }}</el-checkbox>
                        </div>
                      </div>
                    </el-checkbox-group>
                    <div class="notif-pick-hint">{{ t('app.notification.rules.eventSelectHint') }}</div>
                  </div>
                </el-popover>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.sendTo')" min-width="320">
              <template #default="{ row }">
                <el-popover placement="bottom-start" trigger="click" :width="pickWidth.channels" :popper-options="pickPopperOptions" popper-class="nd-pick-popper">
                  <template #reference>
                    <button type="button" class="pick-trigger pick-trigger--channels" :title="ruleChannelSummary(asRule(row))" @click="measurePickWidth($event, 'channels')">
                      <span class="pick-summary" :class="{ 'is-empty': ruleDraftOf(asRule(row)).channel_ids.length === 0 }">{{ ruleChannelSummary(asRule(row)) }}</span>
                      <el-icon class="pick-caret"><ArrowDown /></el-icon>
                    </button>
                  </template>
                  <div class="notif-pick-panel">
                    <el-checkbox-group v-model="ruleDraftOf(asRule(row)).channel_ids" size="small" class="notif-pick-group">
                      <el-checkbox v-for="ch in channelOptions" :key="ch.id" :value="ch.id" border size="small" :disabled="ch.enabled === false || ch.last_test_ok !== true" :title="channelPickTitle(ch)">
                        {{ ch.name }}（{{ channelTypeLabel(ch.type) }}）
                      </el-checkbox>
                    </el-checkbox-group>
                    <div v-if="!userChannels.length" class="notif-pick-hint">{{ t('app.notification.rules.noChannelsHint') }}</div>
                    <div v-else class="notif-pick-hint">{{ t('app.notification.rules.channelSelectHint') }}</div>
                    <div v-if="hasDisabledChannels" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.rules.channelDisabledHint') }}</span></div>
                    <div v-if="userChannels.length && ruleDraftOf(asRule(row)).channel_ids.length === 0" class="notif-pick-hint">{{ t('app.notification.rules.noDeliveryWarn') }}</div>
                  </div>
                </el-popover>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.enabled')" width="65">
              <template #default="{ row }"><el-switch v-model="row.enabled" size="small" @change="toggleRule(asRule(row))" /></template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.actions')" width="150" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="editTemplate(asRule(row))">{{ t('app.notification.daily.editTemplate') }}</el-button>
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

    <!-- 模板弹框（事件规则与日报每通道共享）：rule 模式=每通道规则模板（接收通道已前移到
         事件规则表格的多选浮层草稿）；daily 模式=通道正文模板（style_config：机器人 content_template/webhook payload_template/email body_template）。
         两模式同一版式：通道切换 radio + 格式行 + 编辑器 + 变量芯片 + 提示 + 折叠预览 + 取消/保存，
         仅数据源不同。机器人格式协议固定（仅高亮/预览样式）；webhook/email 格式可选。 -->
    <el-dialog v-model="tplDialogVisible" append-to-body class="dialog-body-inset rule-edit-dialog" width="min(860px, 94vw)" top="5vh">
      <template #header>
        <DialogHeader :icon="Bell" :title="t('app.notification.rules.editTemplateTitle')" :subtitle="tplMode === 'rule' ? (tplEditingRule?.title || '') : (tplActiveChannel?.name || '')" tone="primary" />
      </template>

      <!-- 每通道模板：tab=目标通道（rule 模式=规则已保存的选定通道，未选=全部；daily 模式=全部通道） -->
      <template v-if="tplTabChannels.length">
        <!-- 正文语言：切换即载入该语言默认预设（中文/English），保存即消息正文语言 -->
        <div class="tpl-lang-row">
          <span class="tpl-format-label">{{ t('app.notification.rules.tplLangLabel') }}</span>
          <el-radio-group :model-value="tplLang" size="small" @change="onTplLangChange">
            <el-radio-button value="zh">中文</el-radio-button>
            <el-radio-button value="en">English</el-radio-button>
          </el-radio-group>
          <span class="form-hint tpl-lang-hint">{{ t('app.notification.rules.tplLangHint') }}</span>
        </div>
        <div class="tpl-channel-row">
          <span class="tpl-format-label">{{ t('app.notification.rules.tplChannelLabel') }}</span>
          <el-radio-group v-model="tplChannelTab" size="small">
            <el-radio-button v-for="ch in tplTabChannels" :key="ch.id" :value="String(ch.id)">{{ ch.name }}</el-radio-button>
          </el-radio-group>
        </div>

          <div class="tpl-field">
            <div class="tpl-section-head">
              <DialogSectionHeader :title="tplEditorLabel" />
              <el-button size="small" link type="primary" @click="resetTplToDefault">{{ t('app.notification.rules.tplDefault') }}</el-button>
            </div>
          <div class="tpl-format-row">
            <span class="tpl-format-label">{{ t('app.notification.rules.tplFormatLabel') }}</span>
            <el-tag v-if="isBotChannel(tplActiveChannel?.type || '')" size="small" effect="plain">{{ dailyFormatLabel(tplFixedFormat) }}</el-tag>
            <el-select v-else :model-value="tplFormatSelectValue" size="small" style="width: 170px" @change="onTplFormatChange">
              <el-option v-for="f in tplFormatSelectOptions" :key="f.value" :value="f.value" :label="f.label" />
            </el-select>
          </div>
          <!-- JSON/HTML/Markdown 高亮编辑（CodeEditor 全站单源）；纯文本用 textarea -->
          <CodeEditor v-if="tplEditorLang !== 'text'" v-model="tplText" :language="tplEditorLang" height="220px" :aria-label="tplEditorLabel" />
          <el-input v-else v-model="tplText" type="textarea" :rows="7" :placeholder="tplPlaceholder" />
          <div v-if="tplLengthLimit > 0" class="tpl-length-row">
            <span class="form-hint" :class="{ 'tpl-length-over': tplText.length > tplLengthLimit }">{{ tplText.length }} / {{ tplLengthLimit }}</span>
          </div>
          <div class="ph-row">
            <el-tag v-for="ph in tplActivePh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag>
          </div>
          <div class="tpl-hints">
            <div v-for="hint in tplHints" :key="hint" class="form-hint">{{ hint }}</div>
          </div>
          <div v-if="tplLengthLimit > 0 && tplText.length > tplLengthLimit" class="info-note-bar"><span class="info-note-desc">{{ tplActiveChannel?.type === 'email' ? t('app.notification.daily.bodyTemplateTooLong') : t('app.notification.daily.templateTooLong') }}</span></div>
        </div>

        <el-divider />
        <!-- 预览区默认折叠（防弹框超屏）：展开后渲染/源码切换与预览正文 -->
        <el-collapse v-model="tplPreviewOpen" class="tpl-preview-collapse">
          <el-collapse-item name="preview">
            <template #title><DialogSectionHeader :title="t('app.notification.rules.preview')" /></template>
            <!-- 上半部分即正文源码，预览区直接渲染：HTML iframe / Markdown 渲染；不再提供源码切换 -->
            <iframe v-if="tplEditorLang === 'markup'" class="tpl-html-preview" sandbox="" :srcdoc="previewText" :title="t('app.notification.rules.preview')" />
            <div v-else-if="tplEditorLang === 'markdown'" class="tpl-md-preview" v-html="tplPreviewHtml"></div>
            <pre v-else class="tpl-preview">{{ previewText }}</pre>
          </el-collapse-item>
        </el-collapse>
      </template>
      <el-empty v-else :description="t('app.notification.rules.noChannelsHint')" :image-size="60" />

      <template #footer>
        <el-button @click="tplDialogVisible = false">{{ t('app.notification.rules.cancel') }}</el-button>
        <el-button type="primary" :loading="tplSaving" @click="saveTplDialog">{{ t('app.notification.rules.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- 日报预览弹窗（卡片预览与通道格式预览共用；html=sandbox iframe，其余纯文本 pre） -->
    <el-dialog v-model="dailyPreviewVisible" append-to-body class="dialog-body-inset daily-preview-dialog" width="min(680px, 92vw)" top="6vh">
      <template #header>
        <DialogHeader :icon="Calendar" :title="t('app.notification.daily.previewTitle')" :subtitle="dailyPreviewSource" tone="primary" />
      </template>
      <div v-if="!dailyPreviewFmtLocked" class="daily-preview-toolbar">
        <el-radio-group v-model="dailyPreviewFmt" size="small" @change="renderDailyPreview">
          <el-radio-button v-for="f in dailyPreviewFormatOptions" :key="f.value" :value="f.value">{{ f.label }}</el-radio-button>
        </el-radio-group>
      </div>
      <div class="daily-preview-body">
        <iframe v-if="dailyPreviewFmt === 'html'" class="daily-html-preview" sandbox="" :srcdoc="dailyPreviewText" :title="t('app.notification.daily.previewTitle')" />
        <div v-else-if="dailyPreviewFmt === 'markdown'" v-loading="dailyPreviewLoading" class="tpl-md-preview" v-html="dailyPreviewHtml"></div>
        <pre v-else v-loading="dailyPreviewLoading" class="tpl-preview">{{ dailyPreviewText || t('app.notification.daily.previewEmpty') }}</pre>
      </div>
      <template #footer>
        <el-button @click="dailyPreviewVisible = false">{{ t('app.notification.rules.cancel') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ArrowDown, Calendar, Bell, ChatDotRound, CircleCheckFilled, DataAnalysis, Odometer, TrendCharts } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import { axisChartBase, barSeries, lineSeries, pieChartBase } from '@/utils/chartBase'
import { securityActionColors } from '@/utils/chartTheme'
import { request, mfaAwareSuccess, ApiRequestError } from '@/utils/api'
import { hasOwn } from '@/utils/hasOwn'
import type { NotificationChannel, NotificationChannelsResponse } from '@/types/notifications.ts'
import { useAuthStore } from '@/stores/auth'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import CodeEditor from '@/components/CodeEditor.vue'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t, tm, locale } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const activeTab = ref('overview')

interface RuleChannel { id: number; type: string; name: string; last_test_ok?: boolean; enabled?: boolean }
interface Rule {
  id: string; trigger: string; title: string; events?: string[]
  event_titles?: Record<string, string>; event_levels?: Record<string, string>; min_level?: string; send_time?: string
  channels: RuleChannel[]; channel_ids?: number[]; channel_templates?: Record<string, string>
  body_template: string; enabled: boolean
  items?: string[]; formats?: Record<string, string>
}
// 事件目录行（rules 端点返回；内联事件选项数据源，按 group 分组）
interface CatalogEvent { id: string; title: string; level: string; group: string }

// 事件可读标题多语言：优先当前语言 eventTitles 映射（tm 原始对象索引，键含点号
// 不走 t 路径解析），回退后端 catalog title，再回退事件键。禁止裸键展示。
const eventTitle = (row: Rule, ev: string): string => {
  const m = (tm('app.notification.eventTitles') || {}) as Record<string, string>
  if (hasOwn(m, ev)) return m[ev]
  const titles = row.event_titles
  return (titles && hasOwn(titles, ev) ? titles[ev] : '') || ev
}
const eventGroup = (group: string): string => {
  const m = (tm('app.notification.eventGroups') || {}) as Record<string, string>
  return hasOwn(m, group) ? m[group] : group
}
// 事件级别（目录 level 单源，回退规则携带的 event_levels，再回退 info）：
// 浮层多选按级别分区（严重/警告/信息），中性样式不着色。
const EVENT_LEVELS = ['info', 'warn', 'critical'] as const
type EventLevel = typeof EVENT_LEVELS[number]
const eventLevel = (row: Rule, ev: string): EventLevel => {
  const lv = eventCatalog.value.find(e => e.id === ev)?.level ?? row.event_levels?.[ev] ?? 'info'
  return lv === 'critical' || lv === 'warn' ? lv : 'info'
}

const overviewStats = ref({ channels: 0, rules: 0, deliveries: 0, successRate: 0 })
const rulesUserId = ref<number>(0) // 管理员视角用户（0=未初始化，adminUsers 到达后默认本人）；非管理员恒本人
const adminUsers = ref<{ id: number; username: string }[]>([])
const channelDist = ref<{ type: string; count: number }[]>([])
const userChannels = ref<RuleChannel[]>([])
// 全量通道（含停用）：rules 端点只回启用通道（投递语义），停用态经
// /notification/channels 补齐——发送至选项需展示停用通道并禁选，已选项自动移出草稿。
const allChannels = ref<RuleChannel[]>([])
const channelOptions = computed<RuleChannel[]>(() => {
  if (!allChannels.value.length) return userChannels.value
  const live = new Map(userChannels.value.map(c => [c.id, c]))
  return allChannels.value.map(c => ({ ...c, last_test_ok: live.get(c.id)?.last_test_ok ?? c.last_test_ok }))
})
const hasDisabledChannels = computed(() => channelOptions.value.some(c => c.enabled === false))
const channelPickTitle = (ch: RuleChannel): string | undefined =>
  ch.enabled === false ? t('app.notification.rules.channelDisabledHint')
    : ch.last_test_ok !== true ? t('app.notification.rules.channelUntestedHint') : undefined
// 可选通道集=启用通道（channel_ids 缺省=全部启用通道）；停用通道从草稿移除，
// 避免保存时把停用通道写回。基线同口径裁剪，禁用联动不产生伪脏草稿。
const enabledChannelIds = (): number[] => channelOptions.value.filter(c => c.enabled !== false).map(c => c.id)
const pruneChannelIds = (ids: number[]): number[] => ids.filter(id => channelOptions.value.find(c => c.id === id)?.enabled !== false)
const baselineChannelIds = (ids?: number[]): number[] => pruneChannelIds(ids ?? enabledChannelIds())
const eventCatalog = ref<CatalogEvent[]>([])
// 行事件选项=该行所属 catalog 分组的事件（group: 端点按组写订阅）；
// catalog 未到达时回退规则自带 events。
const rowEventOptions = (rule: Rule): string[] => {
  const ids = eventCatalog.value.filter(e => e.group === rule.title).map(e => e.id)
  return ids.length ? ids : (rule.events ?? [])
}
// 浮层事件分区：按级别分三段（严重→警告→信息），仅列非空段；级别取 catalog level。
const EVENT_SECTION_ORDER: readonly EventLevel[] = ['critical', 'warn', 'info']
const eventLevelSections = (rule: Rule): { level: EventLevel; events: string[] }[] =>
  EVENT_SECTION_ORDER
    .map(level => ({ level, events: rowEventOptions(rule).filter(ev => eventLevel(rule, ev) === level) }))
    .filter(sec => sec.events.length > 0)

// 表格多选浮层（事件/发送至）：宽度=触发器实测 offsetWidth（点击时测量），
// 与触发器/下拉框同宽。定位底部优先，底部空间不足翻到触发器上方——回退候选
// 仅垂直（通用视口安全工具含左右回退，会把面板横向挤出表格列）。
const pickWidth = ref<{ events: number; channels: number }>({ events: 340, channels: 300 })
const measurePickWidth = (e: MouseEvent, kind: 'events' | 'channels'): void => {
  const w = (e.currentTarget as HTMLElement | null)?.offsetWidth ?? 0
  if (w > 0) pickWidth.value = { ...pickWidth.value, [kind]: w }
}
const pickPopperOptions = {
  modifiers: [
    { name: 'flip', options: { fallbackPlacements: ['top-start', 'top'] } },
    // 仅纵向兜底；altAxis=false 禁止横向位移（面板不得向右挤）
    { name: 'preventOverflow', options: { padding: 8, altAxis: false } },
  ],
}

// 7 天投递趋势（ECharts：成功/失败堆叠柱 + 成功率折线，SecurityOverview/Dashboard 同构）
const trendData = ref<{ date: string; total: number; sent: number; rate: number }[]>([])
// 概览图表直角规范：柱/饼 borderRadius 0 + 图例 icon rect（chartBase 基线上的局部
// 覆盖，对齐全站图表页直角形态；饼保留白描边仅作分块间隔）。
const squareChartCorners = (opt: EChartsOption): EChartsOption => {
  if (opt.legend && !Array.isArray(opt.legend)) opt.legend.icon = 'rect'
  if (Array.isArray(opt.series)) {
    for (const s of opt.series) {
      if (s.type === 'bar') s.itemStyle = { ...s.itemStyle, borderRadius: 0 }
      else if (s.type === 'pie') s.itemStyle = { ...s.itemStyle, borderRadius: 0 }
    }
  }
  return opt
}

// 概览图表柔和色板（对齐全站降饱和裁定：Element 柔和色族 + SecurityOverview
// 语义色单源，替换 vivid tailwind chartColors；红=拦截色、橙=检出色）。
const softChartColors = {
  blue: '#409eff',
  green: '#059669',
  teal: '#0e7490',
  orange: securityActionColors.detected,
  red: securityActionColors.blocked,
} as const
const softPiePalette = [softChartColors.blue, softChartColors.green, softChartColors.orange, softChartColors.teal, softChartColors.red]

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
      barSeries(sentName, softChartColors.green, rows.map(d => d.sent), { stack: 'total', barMaxWidth: 28 }),
      barSeries(failedName, softChartColors.red, rows.map(d => d.total - d.sent), { stack: 'total', barMaxWidth: 28 }),
      lineSeries(rateName, softChartColors.blue, rows.map(d => Math.round(d.rate * 100)), { yAxisIndex: 1, areaStyle: undefined, showSymbol: true }),
    ],
    { legendTop: true, yExtra: { minInterval: 1 } },
  )
  // 成功率右轴（0-100%）：单轴基线上追加第二数值轴
  const base = (Array.isArray(opt.yAxis) ? opt.yAxis : [opt.yAxis]).filter((a): a is NonNullable<typeof a> => a != null)
  return squareChartCorners({ ...opt, yAxis: [...base, { type: 'value' as const, min: 0, max: 100, axisLine: { show: false }, axisLabel: { fontSize: 10, color: '#9ca3af', formatter: '{value}%' }, splitLine: { show: false } }] })
})

const channelTypeLabel = (typ: string): string => {
  switch (typ) {
    case 'webhook': return t('app.notification.channels.typeWebhook')
    case 'email': return t('app.notification.channels.typeEmail')
    case 'qq': return t('app.notification.channels.typeQQ')
    default: return t('app.notification.channels.typeWx')
  }
}
const channelDistOption = computed<EChartsOption>(() => squareChartCorners(pieChartBase(
  channelDist.value.map((d, i) => ({ name: channelTypeLabel(d.type), value: d.count, itemStyle: { color: softPiePalette[i % softPiePalette.length] } })),
)))

// 投递分布三维（delivery-stats：每通道结果口径，7 天）
interface DeliveryStats {
  by_channel: { channel_id: number; name: string; type: string; total: number; sent: number; rate: number }[]
  by_type: { type: string; total: number; sent: number; rate: number }[]
  by_event: { event_type: string; title: string; total: number }[]
}
const deliveryStats = ref<DeliveryStats>({ by_channel: [], by_type: [], by_event: [] })
const byChannelOption = computed<EChartsOption>(() => squareChartCorners(pieChartBase(
  deliveryStats.value.by_channel.map((d, i) => ({ name: d.name, value: d.total, itemStyle: { color: softPiePalette[i % softPiePalette.length] } })),
)))
const rateByTypeOption = computed<EChartsOption>(() => {
  const rows = deliveryStats.value.by_type
  const name = t('app.notification.rules.trendRate')
  return squareChartCorners(axisChartBase([name], rows.map(d => channelTypeLabel(d.type)), [
    barSeries(name, softChartColors.blue, rows.map(d => Math.round(d.rate * 100)), { barMaxWidth: 36 }),
  ], { yExtra: { min: 0, max: 100, axisLabel: { fontSize: 10, color: '#9ca3af', formatter: '{value}%' } } }))
})
const byEventOption = computed<EChartsOption>(() => {
  const rows = deliveryStats.value.by_event
  const name = t('app.notification.rules.statDeliveries')
  const opt = axisChartBase([name], rows.map(d => d.title), [
    barSeries(name, softChartColors.teal, rows.map(d => d.total), { barMaxWidth: 18 }),
  ], { yExtra: { minInterval: 1 } })
  // 横向条形（事件标题长，类目轴换 y）：grid 左侧留白给标题
  return squareChartCorners({ ...opt, grid: { left: 8, right: 24, top: 15, bottom: 32, containLabel: true }, xAxis: { type: 'value', minInterval: 1, axisLine: { show: false }, axisLabel: { fontSize: 10, color: '#9ca3af' }, splitLine: { lineStyle: { color: '#f3f4f6' } } }, yAxis: { type: 'category', data: rows.map(d => d.title), axisLine: { lineStyle: { color: '#e5e7eb' } }, axisLabel: { fontSize: 10, color: '#6b7280', width: 90, overflow: 'truncate' } } })
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
const dailyItemOptions = ref<{ id: string; label: string }[]>([])
const testingDaily = ref(false)
// 日报项目/格式多语言标签（tm 原始对象索引）
const dailyItemLabel = (id: string): string => {
  const m = (tm('app.notification.dailyItems') || {}) as Record<string, string>
  return hasOwn(m, id) ? m[id] : id
}
const dailyFormatLabel = (v: string): string => {
  const m = (tm('app.notification.dailyFormats') || {}) as Record<string, string>
  return hasOwn(m, v) ? m[v] : v
}
const dailyFormatOptions = computed(() => ['auto', 'markdown', 'text', 'html', 'json'].map(v => ({ value: v, label: dailyFormatLabel(v) })))

// ===== 模板弹框（事件规则 + 日报每通道共享） =====
// rule 模式=每通道规则模板（接收通道已前移到事件规则表格内联编辑）；daily 模式=通道正文模板（style_config）。
const tplDialogVisible = ref(false)
const tplMode = ref<'rule' | 'daily'>('rule')
const tplEditingRule = ref<Rule | null>(null)
const tplChannelTab = ref('') // 通道 ID 字符串
const tplTexts = ref<Record<string, string>>({}) // 通道 ID → 草稿模板
const tplFormats = ref<Record<string, string>>({}) // rule 模式：通道 ID → 正文格式（编辑高亮/预览状态）
const tplPreviewOpen = ref<string[]>([]) // 预览区默认折叠（防弹框超屏），开弹框时复位
const savingTpl = ref(false)
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}', '{{event}}', '{{event_title}}', '{{node}}', '{{brand}}']
const tplFormatOptions = ['text', 'markdown', 'html', 'json'].map(v => ({ value: v, label: dailyFormatLabel(v) }))

// 模板 tab 通道集：rule 模式=规则已保存的选定通道∩userChannels（未选/缺省=全部，
// 仍可编辑模板）；daily 模式=全部通道（含停用——模板可先配好，启用即生效）。
// 通道选择不再在弹框内编辑。
const tplTabChannels = computed<RuleChannel[]>(() => {
  if (tplMode.value === 'daily') return channelOptions.value
  const ids = tplEditingRule.value?.channel_ids
  if (ids === undefined || ids === null || ids.length === 0) return userChannels.value
  return userChannels.value.filter(ch => ids.includes(ch.id))
})
const tplActiveChannel = computed(() => tplTabChannels.value.find(ch => String(ch.id) === tplChannelTab.value) ?? tplTabChannels.value[0])
const tplText = computed({
  get: () => tplTexts.value[tplChannelTab.value] ?? '',
  set: (v: string) => { tplTexts.value = { ...tplTexts.value, [tplChannelTab.value]: v } },
})
// 正文格式：机器人协议固定（QQ=markdown、微信=纯文本，仅决定高亮/预览样式）；
// daily 模式 webhook/email 随日报生效格式（日报覆盖 > 类型自动映射，持久化）；
// rule 模式 webhook/email=编辑状态（缺省 json/html，后端无规则级格式字段）。
const tplActiveFormat = computed<string>(() => {
  const ch = tplActiveChannel.value
  if (!ch) return 'text'
  if (isBotChannel(ch.type)) return fixedDailyFormat(ch.type)
  if (tplMode.value === 'daily') {
    const f = dailyRule.value ? dailyFormatOf(dailyRule.value, ch.type) : 'auto'
    return f === 'auto' ? autoDailyFormat(ch.type) : f
  }
  return tplFormats.value[tplChannelTab.value] || (ch.type === 'webhook' ? 'json' : 'html')
})
const setTplFormat = (v: string): void => { tplFormats.value = { ...tplFormats.value, [tplChannelTab.value]: v } }
// 版式统一：rule/daily 共用同一格式行（机器人协议固定 tag；webhook/email 同款下拉），
// 仅数据源不同——rule=编辑高亮状态，daily=持久化格式（auto=回退类型映射）。
const tplFixedFormat = computed(() => fixedDailyFormat(tplActiveChannel.value?.type || ''))
const tplFormatSelectValue = computed<string>(() => {
  const ch = tplActiveChannel.value
  if (!ch) return 'text'
  if (tplMode.value === 'daily') return dailyFormatOf(dailyRule.value, ch.type)
  return tplFormats.value[tplChannelTab.value] || (ch.type === 'webhook' ? 'json' : 'html')
})
const tplFormatSelectOptions = computed(() => tplMode.value === 'daily' ? dailyFormatOptions.value : tplFormatOptions)
const onTplFormatChange = (v: string): void => {
  if (tplMode.value === 'daily') void saveDailyFormat(dailyRule.value, tplActiveChannel.value?.type || '', v)
  else setTplFormat(v)
}
// 提示行统一结构：占位符说明恒在；类型提示 + 模式提示次序一致
const tplHints = computed<string[]>(() => {
  const typ = tplActiveChannel.value?.type || ''
  const hints = [t('app.notification.rules.tplPhHint')]
  if (typ === 'email') hints.push(t('app.notification.rules.tplSubjectHint'))
  if (typ === 'qq') hints.push(t('app.notification.rules.tplQqMdHint'))
  if (tplMode.value === 'rule') hints.push(t('app.notification.rules.templateHint'))
  else if (isBotChannel(typ)) hints.push(t('app.notification.daily.contentTemplateHint'))
  else if (typ === 'webhook') hints.push(t('app.notification.daily.webhookTplHint'))
  else hints.push(t('app.notification.daily.emailTplHint'))
  return hints
})
const tplEditorLang = computed(() => {
  const fmt = tplActiveFormat.value
  if (fmt === 'json') return 'json'
  if (fmt === 'html') return 'markup'
  if (fmt === 'markdown') return 'markdown'
  return 'text'
})
const tplEditorLabel = computed(() => {
  if (tplMode.value === 'daily') return t('app.notification.daily.contentTemplate')
  const typ = tplActiveChannel.value?.type
  if (typ === 'webhook') return t('app.notification.rules.tplJson')
  if (typ === 'email') return t('app.notification.rules.tplBody')
  return t('app.notification.rules.tplText')
})
// 占位符集：rule 模式=事件变量；daily 模式机器人/邮件=日报+事件变量（后端日报
// 派发对 content_template/renderStyleTemplate 两类同时替换）；webhook 载荷模板仅事件变量。
const tplActivePh = computed<string[]>(() => {
  if (tplMode.value === 'daily' && tplActiveChannel.value?.type !== 'webhook') return [...dailyPh, ...tplPh]
  return tplPh
})
const tplPlaceholder = computed(() => {
  const typ = tplActiveChannel.value?.type || 'wx_clawbot'
  return tplMode.value === 'daily' ? defaultChannelTplFor(typ, tplLang.value) : defaultTplFor(typ, tplLang.value)
})

// ===== 模板语言预设（正文语言在弹框内切换；不做 per-user locale） =====
// 语言切换只重载该语言默认预设（zh/en 两套同构版式）；保存入库的是正文本身，
// 即消息语言。默认取当前界面语言。
type TplLang = 'zh' | 'en'
const tplLang = ref<TplLang>(String(locale.value).toLowerCase().startsWith('en') ? 'en' : 'zh')
const TPL_LABELS: Record<TplLang, Record<string, string>> = {
  zh: {
    emailDailyTitle: '{{title}}（{{date}}）',
    signature: '此邮件由 {{brand}} 通知中心自动发送 · {{time}}',
    eventDetail: '📋 事件详情',
    fieldHeader: '项目', valueHeader: '内容',
    level: '级别', event: '事件', node: '节点', time: '时间', date: '日期',
    dailyHeader: '📊 {{brand}} 日报', generatedAt: '生成于',
    secOverview: '🌐 全局概览', secSecurity: '🛡 安全风险', secCert: '🔒 证书状态',
    secCluster: '🖥 集群与运行', secIntegrations: '🔌 接入与任务', secAuth: '👤 用户认证',
    wxCluster: '🖥 集群与系统', secRun: '⚙️ 运行状态', metricHeader: '指标',
    requests: '请求数', allowed: '放行次数', logged: '观察次数', distinctIps: '独立 IP 数',
    bandwidth: '总带宽', peakQps: '峰值请求/窗', blocked: '拦截次数', attackTop: '攻击 TOP 规则',
    topIps: 'TOP 攻击源 IP', topPaths: 'TOP 攻击路径', cc: 'CC 触发次数', autoban: '自动封禁次数',
    certStatus: '证书状态', certExpiring: '临期证书明细', clusterStatus: '集群状态',
    uptime: '运行时长', threatDb: '威胁库版本', appVersion: '应用版本',
    apiCalls: 'API 调用(今日)', mcpCalls: 'MCP 调用', taskStatus: '定时任务', backup: '自动备份',
    loginStatus: '登录认证',
    wxBandwidth: '带宽', wxPeakQps: '峰值 QPS', wxThreatDb: '规则库', wxAppVersion: '版本', wxBackup: '备份', wxLogin: '登录',
    colon: '：',
  },
  en: {
    emailDailyTitle: '{{title}} ({{date}})',
    signature: 'Sent automatically by {{brand}} Notification Center · {{time}}',
    eventDetail: '📋 Event details',
    fieldHeader: 'Field', valueHeader: 'Value',
    level: 'Level', event: 'Event', node: 'Node', time: 'Time', date: 'Date',
    dailyHeader: '📊 {{brand}} Daily Report', generatedAt: 'Generated at',
    secOverview: '🌐 Overview', secSecurity: '🛡 Security', secCert: '🔒 Certificates',
    secCluster: '🖥 Cluster & Runtime', secIntegrations: '🔌 Integrations & Tasks', secAuth: '👤 User Authentication',
    wxCluster: '🖥 Cluster & System', secRun: '⚙️ Runtime Status', metricHeader: 'Metric',
    requests: 'Requests', allowed: 'Allowed', logged: 'Logged', distinctIps: 'Distinct IPs',
    bandwidth: 'Bandwidth', peakQps: 'Peak QPS', blocked: 'Blocked', attackTop: 'Top attack rule',
    topIps: 'Top source IPs', topPaths: 'Top attack paths', cc: 'CC triggers', autoban: 'Auto bans',
    certStatus: 'Certificate status', certExpiring: 'Expiring certificates', clusterStatus: 'Cluster status',
    uptime: 'Uptime', threatDb: 'Threat DB', appVersion: 'App version',
    apiCalls: 'API calls (today)', mcpCalls: 'MCP calls', taskStatus: 'Scheduled tasks', backup: 'Backup',
    loginStatus: 'Login',
    wxBandwidth: 'Bandwidth', wxPeakQps: 'Peak QPS', wxThreatDb: 'Rule DB', wxAppVersion: 'Version', wxBackup: 'Backup', wxLogin: 'Login',
    colon: ': ',
  },
}
const tplLabelsFor = (lang: TplLang): Record<string, string> => TPL_LABELS[lang]

// 精美预置模板（各通道最佳实践形态，事件与日报同族版式）：
// - QQ：markdown 富文本（官方 msg_type=2；## 标题+emoji 分节+指标表+引用正文+品牌时间署名）
// - 微信：iLink 纯文本协议（【标题】+分隔线+键值对齐+署名，无 markdown 标记）
// - webhook：完整六键 JSON（与默认载荷同构）
// - email：统一内联样式 HTML 卡片（emailCardTpl 单源：品牌头+级别徽章+标题+元信息表+正文+署名）
// 邮件卡片统一版式（事件/日报同族）：max-width 640、深色品牌头+级别徽章、标题、
// 元信息 table、正文、品牌时间署名。内联样式+table 布局（邮件客户端兼容），直角对齐全站设计语言。
const emailCardTpl = (titleTpl: string, bodyHtml: string, metaRows: [string, string][], footer: string): string => {
  const meta = metaRows.map(([k, v]) => `      <tr><td style="padding:6px 0;color:#64748b;">${k}</td><td style="padding:6px 0;text-align:right;color:#334155;">${v}</td></tr>`).join('\n')
  return [
    '<div style="max-width:640px;margin:0 auto;font-family:\'Helvetica Neue\',Arial,\'PingFang SC\',\'Microsoft YaHei\',sans-serif;">',
    '  <div style="background:#1e293b;padding:16px 24px;">',
    '    <table style="width:100%;border-collapse:collapse;"><tr>',
    '      <td style="color:#f8fafc;font-size:16px;font-weight:600;">{{brand}}</td>',
    '      <td style="text-align:right;"><span style="background:#3b82f6;color:#fff;font-size:11px;padding:2px 10px;">{{level}}</span></td>',
    '    </tr></table>',
    '  </div>',
    '  <div style="border:1px solid #e2e8f0;border-top:none;padding:24px;">',
    `    <h2 style="margin:0 0 16px;font-size:18px;color:#0f172a;">${titleTpl}</h2>`,
    bodyHtml,
    '    <table style="width:100%;font-size:12px;border-top:1px solid #f1f5f9;margin-top:16px;border-collapse:collapse;">',
    meta,
    '    </table>',
    '  </div>',
    `  <p style="text-align:center;font-size:11px;color:#94a3b8;margin:16px 0;">${footer}</p>`,
    '</div>',
  ].join('\n')
}
const defaultTplFor = (typ: string, lang: TplLang): string => {
  const L = tplLabelsFor(lang)
  if (typ === 'webhook') return JSON.stringify({ level: '{{level}}', time: '{{time}}', node: '{{node}}', title: '{{title}}', body: '{{body}}', event: '{{event}}' }, null, 2)
  if (typ === 'email') return emailCardTpl('{{title}}',
    '    <div style="font-size:14px;line-height:1.7;color:#334155;white-space:pre-wrap;">{{body}}</div>',
    [[L.event, '{{event_title}}'], [L.node, '{{node}}'], [L.time, '{{time}}']],
    L.signature)
  if (typ === 'qq') return [
    '# 🔔 {{title}}',
    '',
    '> {{body}}',
    '',
    `## ${L.eventDetail}`,
    '',
    `| ${L.fieldHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    `| ${L.level} | {{level}} |`,
    `| ${L.event} | {{event_title}} |`,
    `| ${L.node} | {{node}} |`,
    `| ${L.time} | {{time}} |`,
    '',
    '> {{brand}} · {{time}}',
  ].join('\n')
  return [
    '【{{title}}】',
    '────────────',
    '{{body}}',
    '────────────',
    `${L.level}${L.colon}{{level}}`,
    `${L.event}${L.colon}{{event_title}}`,
    `${L.node}${L.colon}{{node}}`,
    `${L.time}${L.colon}{{time}}`,
    '—— {{brand}} · {{time}}',
  ].join('\n')
}
const resetTplToDefault = (): void => {
  const ch = tplActiveChannel.value
  if (!ch) return
  tplText.value = tplMode.value === 'daily' ? defaultChannelTplFor(ch.type, tplLang.value) : defaultTplFor(ch.type, tplLang.value)
}
// 日报预览样例值（daily 模式预览；键集=契约日报 ID 全集+date，
// top_ips/top_paths/cert_expiring 为多行文本列表样例）
const dailySampleValues = {
  date: '2026-11-18',
  requests: '128340', allowed: '120111', logged: '7026', distinct_ips: '3204',
  bandwidth: '1.2 GB', peak_qps: '340',
  blocked: '1203', attack_top: 'SQLi × 321',
  top_ips: '45.33.32.9 × 321\n1.2.3.4 × 120',
  top_paths: '/login × 200\n/api × 150',
  cc_triggered: '3', autoban: '17',
  cert_status: 'OK', cert_expiring: 'a.com · 2026-11-25\nb.com · 2026-11-28',
  cluster_status: '3/3', uptime: '32 天',
  threat_db: 'CRS 4.0 · IP库 2026-11', app_version: 'v2.4.4',
  api_calls: '1200', mcp_calls: '300',
  task_status: '成功 12 / 失败 1', backup_status: '成功 7 / 失败 0',
  login_status: '成功 40 / 失败 3 / MFA失败 1',
}
// 轻量 Markdown→HTML（预览用，覆盖 QQ 模板子集：#/##/### 标题、**加粗**、- 列表、
// > 引用、| 表格、段落；先转义再渲染，禁脚本）。
const mdToHtml = (md: string): string => {
  const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const inline = (s: string): string => esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+?)`/g, '<code>$1</code>')
  const lines = md.split('\n')
  const out: string[] = []
  let i = 0
  while (i < lines.length) {
    const ln = lines[i]
    if (/^\s*\|/.test(ln) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|?\s*$/.test(lines[i + 1])) {
      const header = ln.trim().replace(/^\||\|$/g, '').split('|').map(c => `<th>${inline(c.trim())}</th>`).join('')
      i += 2
      const rows: string[] = []
      while (i < lines.length && /^\s*\|/.test(lines[i])) {
        rows.push(lines[i].trim().replace(/^\||\|$/g, '').split('|').map(c => `<td>${inline(c.trim())}</td>`).join(''))
        i++
      }
      out.push(`<table><thead><tr>${header}</tr></thead><tbody>${rows.map(r => `<tr>${r}</tr>`).join('')}</tbody></table>`)
      continue
    }
    if (/^###\s+/.test(ln)) { out.push(`<h4>${inline(ln.replace(/^###\s+/, ''))}</h4>`); i++; continue }
    if (/^##\s+/.test(ln)) { out.push(`<h3>${inline(ln.replace(/^##\s+/, ''))}</h3>`); i++; continue }
    if (/^#\s+/.test(ln)) { out.push(`<h2>${inline(ln.replace(/^#\s+/, ''))}</h2>`); i++; continue }
    if (/^\s*-\s+/.test(ln)) {
      const items: string[] = []
      while (i < lines.length && /^\s*-\s+/.test(lines[i])) { items.push(`<li>${inline(lines[i].replace(/^\s*-\s+/, ''))}</li>`); i++ }
      out.push(`<ul>${items.join('')}</ul>`); continue
    }
    if (/^\s*>\s?/.test(ln)) {
      const items: string[] = []
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) { items.push(inline(lines[i].replace(/^\s*>\s?/, ''))); i++ }
      out.push(`<blockquote>${items.join('<br>')}</blockquote>`); continue
    }
    if (ln.trim() === '') { i++; continue }
    out.push(`<p>${inline(ln)}</p>`); i++
  }
  return out.join('\n')
}
const previewText = computed(() => {
  let text = tplText.value
    .replace(/\{\{title\}\}/g, t('app.notification.rules.previewSampleTitle'))
    .replace(/\{\{body\}\}/g, t('app.notification.rules.previewSampleBody'))
    .replace(/\{\{level\}\}/g, 'critical')
    .replace(/\{\{event\}\}/g, 'cert.failed')
    .replace(/\{\{node\}\}/g, 'node-a')
    .replace(/\{\{time\}\}/g, '2026-11-18 09:00')
    .replace(/\{\{brand\}\}/g, 'Lazy Balancer')
  if (tplMode.value === 'daily' && tplActiveChannel.value?.type !== 'webhook') {
    for (const [k, v] of Object.entries(dailySampleValues)) text = text.split(`{{${k}}}`).join(v)
  }
  return text
})
// 长度校验提示（后端 validateChannelStyle 同口径）：daily 模式机器人 content_template
// ≤2000、email body_template ≤4000；rule 模式与 webhook 无长度限制（webhook 保存校验 JSON 可解析）。
const tplLengthLimit = computed<number>(() => {
  if (tplMode.value !== 'daily') return 0
  const typ = tplActiveChannel.value?.type || ''
  if (isBotChannel(typ)) return 2000
  if (typ === 'email') return 4000
  return 0
})

// 全量通道 DTO（enabled/last_test_ok/style_config 单源）：rules 端点只回启用通道
// （投递语义），停用通道经此补齐发送至选项的禁用态，同时作为日报模板草稿来源。
const fetchChannels = async (): Promise<void> => {
  try {
    // 管理员视角：rulesUserId 未初始化时按本人（与规则 GET 的 uid 口径一致），
    // 避免无 user_id 时管理员的「全部用户通道」串入发送至选项。
    let url = '/notification/channels'
    if (isAdmin.value) {
      const uid = rulesUserId.value > 0 ? rulesUserId.value : authStore.user?.id
      if (!uid) return
      url = `/notification/channels?user_id=${uid}`
    }
    const res = await request.get<NotificationChannelsResponse>(url, { silent: true })
    const list = res.data?.channels ?? []
    dailyFullChannels.value = list
    allChannels.value = list.map(c => ({ id: c.id, type: c.type, name: c.name, enabled: c.enabled, last_test_ok: c.last_test_ok }))
  } catch { /* 通道 DTO 不可用时退化为 rules 端点的启用通道集 */ }
}

const fetchRules = async (reseedDrafts: boolean): Promise<void> => {
  loading.value = true
  try {
    // 默认当前用户；管理员可选其他用户（规则/通道按用户区分，概览才全平台）
    const rulesUrl = isAdmin.value && rulesUserId.value > 0 ? `/notification/rules?user_id=${rulesUserId.value}` : '/notification/rules'
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels?: RuleChannel[]; catalog?: CatalogEvent[]; daily_items?: { id: string; label: string }[] } }>(rulesUrl)
    rules.value = res.data?.rules ?? []
    // 最低级别预选：空值回退目录默认级别 info（目录各组最低级别，亦为后端
    // 新建订阅行的起始级别）——下拉不再呈现空「请选择」态；仅显示兜底，不写库。
    for (const r of rules.value) {
      if (r.trigger === 'event' && !r.min_level) r.min_level = 'info'
    }
    userChannels.value = res.data?.channels ?? []
    eventCatalog.value = res.data?.catalog ?? []
    dailyItemOptions.value = res.data?.daily_items ?? []
    await fetchChannels()
    seedDailyTplDrafts()
    seedDrafts(reseedDrafts)
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
  // 启停写操作需确认；取消/失败时回拨开关（switch 的 @change 已先行改值）
  const confirmText = rule.enabled ? t('app.notification.rules.enableConfirm') : t('app.notification.rules.disableConfirm')
  try { await ElMessageBox.confirm(confirmText, t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { rule.enabled = !rule.enabled; return }
  try { await request.post(ruleWriteUrl(rule.id), { enabled: rule.enabled }) }
  catch (e) {
    rule.enabled = !rule.enabled
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
  }
}

// ===== 内联编辑草稿（事件规则行 + 每日摘要卡） =====
// 选择类字段在表格/卡片内联编辑：草稿 dirty 时行内（卡头）呈现保存/取消；
// 保存=确认后部分更新 POST，取消=回滚草稿。通道三态同口径：undefined=全部
// （草稿呈现全选）、[]=不投递、非空=选定。
interface RuleDraft { events: string[]; channel_ids: number[]; min_level: string }
interface DailyDraft { items: string[]; channel_ids: number[]; send_time: string }
const ruleDrafts = ref<Record<string, RuleDraft>>({})
const dailyDraft = ref<DailyDraft | null>(null)
const savingAllRules = ref(false)
const savingDaily = ref(false)
const newRuleDraft = (rule: Rule): RuleDraft => ({
  events: [...(rule.events ?? [])],
  channel_ids: baselineChannelIds(rule.channel_ids),
  min_level: rule.min_level || 'info',
})
const newDailyDraft = (rule: Rule): DailyDraft => ({
  items: [...(rule.items ?? [])],
  channel_ids: baselineChannelIds(rule.channel_ids),
  send_time: rule.send_time || '09:00',
})
// 草稿播种：force=全量重建（首次加载/管理员切换视角）；否则保留已有脏草稿
// （弹框打开/模板保存后的刷新不得抹掉未保存的内联编辑）。停用通道联动：
// 已选通道中已被停用的自动移出草稿（不产生伪脏态）。
const seedDrafts = (force: boolean): void => {
  const drafts: Record<string, RuleDraft> = {}
  for (const r of rules.value) {
    if (r.trigger !== 'event') continue
    const existing = ruleDrafts.value[r.id]
    drafts[r.id] = !force && existing ? { ...existing, channel_ids: pruneChannelIds(existing.channel_ids) } : newRuleDraft(r)
  }
  ruleDrafts.value = drafts
  const daily = dailyRule.value
  if (daily) dailyDraft.value = !force && dailyDraft.value ? { ...dailyDraft.value, channel_ids: pruneChannelIds(dailyDraft.value.channel_ids) } : newDailyDraft(daily)
}
const ruleDraftOf = (rule: Rule): RuleDraft => {
  const existing = ruleDrafts.value[rule.id]
  if (existing) return existing
  const fresh = newRuleDraft(rule)
  ruleDrafts.value = { ...ruleDrafts.value, [rule.id]: fresh }
  return fresh
}
// 表格多选触发器摘要：前 2 项名称 + 余量（事件=可读标题，通道=通道名）；
// 空选=不投递（'[]' 落库语义），与保存侧同口径。
const summarizePick = (names: string[]): string =>
  names.length > 2 ? `${names.slice(0, 2).join('、')} +${names.length - 2}` : names.join('、')
const ruleEventSummary = (rule: Rule): string => {
  const evs = ruleDraftOf(rule).events
  if (!evs.length) return t('app.notification.rules.noDelivery')
  return summarizePick(evs.map(ev => eventTitle(rule, ev)))
}
const ruleChannelSummary = (rule: Rule): string => {
  const ids = ruleDraftOf(rule).channel_ids
  if (!ids.length) return t('app.notification.rules.noDelivery')
  const names = channelOptions.value.filter(ch => ids.includes(ch.id)).map(ch => ch.name)
  return names.length ? summarizePick(names) : t('app.notification.rules.noDelivery')
}
// 选择类字段按集合比较（多选顺序不影响 dirty 判定）
const sameSet = <T>(a: readonly T[], b: readonly T[]): boolean => {
  if (a.length !== b.length) return false
  const s = new Set(b)
  return a.every(x => s.has(x))
}
const ruleDraftDirty = (rule: Rule): boolean => {
  const d = ruleDrafts.value[rule.id]
  if (!d) return false
  return !sameSet(d.events, rule.events ?? [])
    || !sameSet(d.channel_ids, baselineChannelIds(rule.channel_ids))
    || d.min_level !== (rule.min_level || 'info')
}
const dailyDraftDirty = computed<boolean>(() => {
  const r = dailyRule.value
  const d = dailyDraft.value
  if (!r || !d) return false
  return !sameSet(d.items, r.items ?? [])
    || !sameSet(d.channel_ids, baselineChannelIds(r.channel_ids))
    || d.send_time !== (r.send_time || '09:00')
})

// 事件规则卡头统一保存/取消：存在任一行草稿脏时显示，保存所有脏行。
const anyRuleDirty = computed<boolean>(() => eventRules.value.some(r => ruleDraftDirty(asRule(r))))
const saveAllRuleDrafts = async (): Promise<void> => {
  const dirty = eventRules.value.map(asRule).filter(r => ruleDraftDirty(r))
  if (!dirty.length || savingAllRules.value) return
  try { await ElMessageBox.confirm(t('app.notification.rules.saveRuleConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
  savingAllRules.value = true
  try {
    for (const rule of dirty) {
      const d = ruleDrafts.value[rule.id]
      if (!d) continue
      await request.post(ruleWriteUrl(rule.id), { events: d.events, channel_ids: d.channel_ids, min_level: d.min_level })
      rule.events = [...d.events]
      rule.channel_ids = [...d.channel_ids]
      rule.min_level = d.min_level
    }
    mfaAwareSuccess(t('app.notification.rules.saved'))
  } catch (e) {
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
  } finally { savingAllRules.value = false }
}
const cancelAllRuleDrafts = (): void => {
  const m = { ...ruleDrafts.value }
  for (const r of eventRules.value) m[r.id] = newRuleDraft(asRule(r))
  ruleDrafts.value = m
}

// 每日摘要卡保存：确认后部分更新 items/channel_ids/send_time；空项目拦截同口径。
const saveDailyDraft = async (): Promise<void> => {
  const r = dailyRule.value
  const d = dailyDraft.value
  if (!r || !d || savingDaily.value) return
  if (d.items.length === 0) { ElMessage.warning(t('app.notification.daily.itemsRequired')); return }
  try { await ElMessageBox.confirm(t('app.notification.daily.saveDailyConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
  savingDaily.value = true
  try {
    await request.post(ruleWriteUrl(r.id), { items: d.items, channel_ids: d.channel_ids, send_time: d.send_time })
    r.items = [...d.items]
    r.channel_ids = [...d.channel_ids]
    r.send_time = d.send_time
    mfaAwareSuccess(t('app.notification.rules.saved'))
  } catch (e) {
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
  } finally { savingDaily.value = false }
}
const cancelDailyDraft = (): void => {
  const r = dailyRule.value
  if (r) dailyDraft.value = newDailyDraft(r)
}
// 日报 per-channel 格式保存：formats 键=通道族；auto=删除该键（回退自动映射）；
// 写操作需确认，失败回滚本地格式（select 经 :model-value 单向绑定随回滚复位）
const saveDailyFormat = async (rule: Rule | null, channelType: string, format: string): Promise<void> => {
  if (!rule) return
  try { await ElMessageBox.confirm(t('app.notification.daily.formatSaveConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
  const formats: Record<string, string> = { ...(rule.formats || {}) }
  if (format === 'auto') delete formats[channelType]
  else formats[channelType] = format
  const prev = rule.formats
  rule.formats = formats
  try {
    await request.post(ruleWriteUrl(rule.id), { formats })
    mfaAwareSuccess(t('app.notification.rules.saved'))
  } catch (e) {
    rule.formats = prev
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
  }
}
const dailyFormatOf = (rule: Rule | null, channelType: string): string => rule?.formats?.[channelType] || 'auto'
// 通道自动映射（webhook=json/email=html；机器人协议固定：QQ=markdown、微信=纯文本）
const autoDailyFormat = (typ: string): string => {
  switch (typ) {
    case 'webhook': return 'json'
    case 'email': return 'html'
    case 'qq': return 'markdown'
    default: return 'text'
  }
}
// 日报测试发送：与定时日报同管线，落投递行（结果见投递记录）；写操作需确认
const testDaily = async (): Promise<void> => {
  if (testingDaily.value) return
  try { await ElMessageBox.confirm(t('app.notification.daily.testConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
  testingDaily.value = true
  try {
    await request.post('/notification/daily/test', {})
    mfaAwareSuccess(t('app.notification.daily.testSent'))
  } catch (e) {
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
  } finally { testingDaily.value = false }
}

// ===== 日报模板（每通道格式/内容模板；基本配置已前移到摘要卡内联） =====
const dailyFullChannels = ref<NotificationChannel[]>([])
const dailyTplDrafts = ref<Record<number, string>>({})
const savingTplChannelId = ref<number | null>(null)

// 机器人协议固定：QQ=Markdown、微信=纯文本（格式不可选，仅决定编辑高亮与预览样式）
const isBotChannel = (typ: string): boolean => typ === 'qq' || typ === 'wx_clawbot'
const fixedDailyFormat = (typ: string): string => (typ === 'qq' ? 'markdown' : 'text')
// 日报变量（后端派发时从日报载荷 values 替换；键集=DailyItemIDs 全集+date）
const dailyPh = ['{{date}}', '{{requests}}', '{{allowed}}', '{{logged}}', '{{blocked}}', '{{distinct_ips}}', '{{bandwidth}}', '{{peak_qps}}', '{{attack_top}}', '{{top_ips}}', '{{top_paths}}', '{{cc_triggered}}', '{{autoban}}', '{{cert_status}}', '{{cert_expiring}}', '{{cluster_status}}', '{{uptime}}', '{{threat_db}}', '{{app_version}}', '{{api_calls}}', '{{mcp_calls}}', '{{task_status}}', '{{backup_status}}', '{{login_status}}']
// 精美预置日报模板（事件与日报同族版式；分节=全局概览/安全风险/证书/集群与系统/运行状态）：
// QQ=Markdown 分节表格（含 top_ips/top_paths/cert_expiring 多行变量），
// 微信=纯文本分节行（iLink 协议无 markdown 能力），email=统一 HTML 卡片（日报版式）。
const defaultDailyTplFor = (typ: string, lang: TplLang): string => {
  const L = tplLabelsFor(lang)
  const c = L.colon
  const row = (label: string, key: string): string => `| ${label} | {{${key}}} |`
  if (typ === 'email') return emailCardTpl(L.emailDailyTitle,
    '    <div style="font-size:14px;line-height:1.7;color:#334155;">{{body}}</div>',
    [[L.date, '{{date}}'], [L.time, '{{time}}']],
    L.signature)
  if (typ === 'qq') return [
    `# ${L.dailyHeader}`,
    `> {{date}} · ${L.generatedAt} {{time}}`,
    '',
    `## ${L.secOverview}`,
    '',
    `| ${L.metricHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    row(L.requests, 'requests'),
    row(L.allowed, 'allowed'),
    row(L.logged, 'logged'),
    row(L.distinctIps, 'distinct_ips'),
    row(L.bandwidth, 'bandwidth'),
    row(L.peakQps, 'peak_qps'),
    '',
    `## ${L.secSecurity}`,
    '',
    `| ${L.metricHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    row(L.blocked, 'blocked'),
    row(L.attackTop, 'attack_top'),
    row(L.cc, 'cc_triggered'),
    row(L.autoban, 'autoban'),
    '',
    `**${L.topIps}**`,
    '{{top_ips}}',
    `**${L.topPaths}**`,
    '{{top_paths}}',
    '',
    `## ${L.secCert}`,
    '',
    `| ${L.metricHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    row(L.certStatus, 'cert_status'),
    '',
    `**${L.certExpiring}**`,
    '{{cert_expiring}}',
    '',
    `## ${L.secCluster}`,
    '',
    `| ${L.metricHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    row(L.clusterStatus, 'cluster_status'),
    row(L.uptime, 'uptime'),
    row(L.threatDb, 'threat_db'),
    row(L.appVersion, 'app_version'),
    '',
    `## ${L.secIntegrations}`,
    '',
    `| ${L.metricHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    row(L.apiCalls, 'api_calls'),
    row(L.mcpCalls, 'mcp_calls'),
    row(L.taskStatus, 'task_status'),
    row(L.backup, 'backup_status'),
    '',
    `## ${L.secAuth}`,
    '',
    `| ${L.metricHeader} | ${L.valueHeader} |`,
    '| --- | --- |',
    row(L.loginStatus, 'login_status'),
    '',
    '> {{brand}} · {{time}}',
  ].join('\n')
  const line = (label: string, key: string): string => `${label}${c}{{${key}}}`
  return [
    `${L.dailyHeader}${lang === 'en' ? ' ({{date}})' : '（{{date}}）'}`,
    '────────────',
    '',
    L.secOverview,
    line(L.requests, 'requests'),
    line(L.allowed, 'allowed'),
    line(L.logged, 'logged'),
    line(L.distinctIps, 'distinct_ips'),
    line(L.wxBandwidth, 'bandwidth'),
    line(L.wxPeakQps, 'peak_qps'),
    '',
    L.secSecurity,
    line(L.blocked, 'blocked'),
    line(L.attackTop, 'attack_top'),
    `${L.topIps}${c}`,
    '{{top_ips}}',
    `${L.topPaths}${c}`,
    '{{top_paths}}',
    line(L.cc, 'cc_triggered'),
    line(L.autoban, 'autoban'),
    '',
    L.secCert,
    line(L.certStatus, 'cert_status'),
    `${L.certExpiring}${c}`,
    '{{cert_expiring}}',
    '',
    L.wxCluster,
    line(L.clusterStatus, 'cluster_status'),
    line(L.uptime, 'uptime'),
    line(L.wxThreatDb, 'threat_db'),
    line(L.wxAppVersion, 'app_version'),
    line(L.apiCalls, 'api_calls'),
    line(L.mcpCalls, 'mcp_calls'),
    '',
    L.secRun,
    line(L.taskStatus, 'task_status'),
    line(L.wxBackup, 'backup_status'),
    line(L.wxLogin, 'login_status'),
    '',
    '—— {{brand}} · {{time}}',
  ].join('\n')
}
// 通道模式预置（日报）：机器人=分节日报模板；email=统一 HTML 卡片（日报版式）；
// webhook=JSON 载荷模板（占位符不裹引号，与保存侧 probe 校验同口径）。
const defaultChannelTplFor = (typ: string, lang: TplLang): string => {
  if (typ === 'webhook') return [
    '{',
    '  "level": {{level}},',
    '  "time": {{time}},',
    '  "node": {{node}},',
    '  "title": {{title}},',
    '  "body": {{body}},',
    '  "event": {{event}}',
    '}',
  ].join('\n')
  return defaultDailyTplFor(typ, lang)
}

// 弹框打开即时刷新（不依赖页面刷新）：rules=规则数据+通道摘要测试态（不重建内联
// 脏草稿）；fetchRules 内已含全量通道 DTO（enabled/style_config——规则端点摘要不含样式键）。
// 管理员代管 user_id 与规则视角同口径。
const refreshDialogState = async (): Promise<void> => {
  await fetchRules(false)
}

// 日报草稿库：既有正文模板 > 通道形态预置（逐通道；未保存过=预置形态）
const seedDailyTplDrafts = (): void => {
  const drafts: Record<number, string> = {}
  for (const ch of channelOptions.value) {
    const full = dailyFullChannels.value.find(c => c.id === ch.id)
    let style: Record<string, unknown> = {}
    try { style = JSON.parse(full?.style_config || '{}') as Record<string, unknown> } catch { style = {} }
    const tpl = style[channelBodyTplKey(ch.type)]
    const saved = typeof tpl === 'string' ? tpl : ''
    drafts[ch.id] = saved || defaultChannelTplFor(ch.type, tplLang.value)
  }
  dailyTplDrafts.value = drafts
}

// 日报模式入口（每日摘要卡「编辑模板」）：与事件规则共享同一模板弹框——
// 仅数据源不同：daily 模式通道范围=全部通道，默认模板=日报版式。
const openDailyTpl = async (): Promise<void> => {
  if (!dailyRule.value) return
  tplMode.value = 'daily'
  tplEditingRule.value = null
  try { await refreshDialogState() } catch (e) { console.error(e) }
  const drafts: Record<string, string> = {}
  for (const c of tplTabChannels.value) drafts[String(c.id)] = dailyTplDrafts.value[c.id] ?? defaultChannelTplFor(c.type, tplLang.value)
  tplTexts.value = drafts
  tplChannelTab.value = tplTabChannels.value.length ? String(tplTabChannels.value[0].id) : ''
  tplPreviewOpen.value = []
  tplDialogVisible.value = true
}

// 通道正文模板键位：机器人=content_template（事件+日报变量）、webhook=payload_template
// （JSON 载荷）、email=body_template（正文；标题在通道传输配置）。
const channelBodyTplKey = (typ: string): string => typ === 'webhook' ? 'payload_template' : typ === 'email' ? 'body_template' : 'content_template'

// 正文模板保存：PUT 通道 style_config 为全量覆盖语义——回读既有键仅替换
// 正文模板键（空模板=移除该键回退默认形态）；保存写库需确认。返回是否成功。
const saveChannelBodyTemplate = async (ch: RuleChannel): Promise<boolean> => {
  const full = dailyFullChannels.value.find(c => c.id === ch.id)
  if (!full || savingTplChannelId.value !== null) return false
  const draft = (dailyTplDrafts.value[ch.id] ?? '').trim()
  if (isBotChannel(ch.type) && draft.length > 2000) { ElMessage.error(t('app.notification.daily.templateTooLong')); return false }
  if (ch.type === 'email' && draft.length > 4000) { ElMessage.error(t('app.notification.daily.bodyTemplateTooLong')); return false }
  try {
    await ElMessageBox.confirm(t('app.notification.daily.saveTplConfirm', { name: ch.name }), t('app.notification.rules.confirmTitle'), { type: 'warning' })
  } catch { return false }
  savingTplChannelId.value = ch.id
  try {
    let style: Record<string, unknown> = {}
    try { style = JSON.parse(full.style_config || '{}') as Record<string, unknown> } catch { style = {} }
    const key = channelBodyTplKey(ch.type)
    if (draft) style[key] = draft
    else delete style[key]
    await request.put(`/notification/channels/${ch.id}`, { style_config: style })
    full.style_config = JSON.stringify(style)
    mfaAwareSuccess(t('app.notification.daily.templateSaved'))
    return true
  } catch (e) {
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
    return false
  } finally { savingTplChannelId.value = null }
}

// 语言切换：载入该语言默认预设进全部通道编辑器（未保存编辑随之重置；保存即正文语言）
const onTplLangChange = (v: string | number | boolean | undefined): void => {
  tplLang.value = v === 'en' ? 'en' : 'zh'
  const drafts: Record<string, string> = {}
  for (const ch of tplTabChannels.value) {
    drafts[String(ch.id)] = tplMode.value === 'daily'
      ? defaultChannelTplFor(ch.type, tplLang.value)
      : defaultTplFor(ch.type, tplLang.value)
  }
  tplTexts.value = drafts
  if (!tplTabChannels.value.some(ch => String(ch.id) === tplChannelTab.value)) {
    tplChannelTab.value = tplTabChannels.value.length ? String(tplTabChannels.value[0].id) : ''
  }
}
// 通道模式保存：草稿回写日报草稿库后落通道配置；成功关闭弹框
const saveChannelTplFromDialog = async (): Promise<void> => {
  const ch = tplActiveChannel.value
  if (!ch) return
  dailyTplDrafts.value = { ...dailyTplDrafts.value, [ch.id]: tplTexts.value[String(ch.id)] ?? '' }
  if (await saveChannelBodyTemplate(ch)) tplDialogVisible.value = false
}

// 弹框底部保存入口（版式统一：两模式同按钮/同确认；仅写库数据源不同）
const tplSaving = computed(() => tplMode.value === 'rule' ? savingTpl.value : savingTplChannelId.value !== null)
const saveTplDialog = (): void => {
  if (tplMode.value === 'rule') void saveTemplate()
  else void saveChannelTplFromDialog()
}

const editTemplate = async (rule: Rule): Promise<void> => {
  // 打开即重拉 rules+channels：测试态/既有模板以最新为准（不依赖页面刷新）
  try { await refreshDialogState() } catch (e) { console.error(e) }
  const fresh = rules.value.find(r => r.id === rule.id) ?? rule
  tplMode.value = 'rule'
  tplEditingRule.value = fresh
  // 草稿初始化：既有每通道模板 > 事件级模板 > 通道形态预置；格式=类型缺省
  const drafts: Record<string, string> = {}
  const formats: Record<string, string> = {}
  for (const ch of userChannels.value) {
    drafts[String(ch.id)] = fresh.channel_templates?.[String(ch.id)] || fresh.body_template || defaultTplFor(ch.type, tplLang.value)
    formats[String(ch.id)] = ch.type === 'webhook' ? 'json' : ch.type === 'email' ? 'html' : fixedDailyFormat(ch.type)
  }
  tplTexts.value = drafts
  tplFormats.value = formats
  // tab 集=规则已保存的选定通道（未选=全部）；通道选择已前移到表格内联
  const targets = tplTabChannels.value
  tplChannelTab.value = targets.length ? String(targets[0].id) : ''
  tplPreviewOpen.value = []
  tplDialogVisible.value = true
}

const saveTemplate = async (): Promise<void> => {
  if (!tplEditingRule.value || savingTpl.value) return
  // 保存写库需确认（取消不执行）
  try { await ElMessageBox.confirm(t('app.notification.rules.saveTplConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
  savingTpl.value = true
  try {
    // 每通道模板部分更新（不动启用态/级别/时间/通道选择——通道选择已前移到表格内联）。
    // 仅提交与预置（任一语言）/事件级模板不同的草稿（空差异=沿用默认链）。
    const tpls: Record<string, string> = {}
    for (const ch of userChannels.value) {
      const draft = tplTexts.value[String(ch.id)] ?? ''
      if (draft && draft !== defaultTplFor(ch.type, 'zh') && draft !== defaultTplFor(ch.type, 'en')) tpls[String(ch.id)] = draft
    }
    await request.post(ruleWriteUrl(tplEditingRule.value.id), { channel_templates: tpls })
    tplEditingRule.value.channel_templates = tpls
    mfaAwareSuccess(t('app.notification.rules.saved'))
    tplDialogVisible.value = false
    await fetchRules(false)
  } catch (e) {
    if (!(e instanceof ApiRequestError)) ElMessage.error(e instanceof Error ? e.message : t('common.app.api.requestFailed'))
  } finally { savingTpl.value = false }
}

const testRule = async (rule: Rule): Promise<void> => {
  // 按规则选定通道+每通道模板渲染发送（后端 TestRuleDelivery；不落投递行）；真实发送需确认
  if (testingRuleId.value !== null) return
  try { await ElMessageBox.confirm(t('app.notification.rules.testConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
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

// ===== 日报预览弹窗（卡片预览与通道格式预览共用；html=sandbox iframe 渲染） =====
const dailyPreviewVisible = ref(false)
const dailyPreviewText = ref('')
const dailyPreviewFmt = ref('markdown')
const tplPreviewHtml = computed(() => mdToHtml(previewText.value))
const dailyPreviewHtml = computed(() => mdToHtml(dailyPreviewText.value))
const dailyPreviewSource = ref('')
const dailyPreviewLoading = ref(false)
const dailyPreviewFmtLocked = ref(false) // 机器人预览格式随协议固定（隐藏切换器）
const dailyPreviewFormatOptions = ['markdown', 'text', 'html', 'json'].map(v => ({ value: v, label: dailyFormatLabel(v) }))

const fetchDailyPreview = async (format: string): Promise<void> => {
  dailyPreviewLoading.value = true
  try {
    const res = await request.post<{ data?: { content: string; format: string } }>('/notification/daily/preview', {
      items: dailyRule.value?.items,
      format,
    })
    dailyPreviewText.value = res.data?.content ?? ''
    dailyPreviewFmt.value = res.data?.format || format
  } catch (e) { console.error(e) } finally { dailyPreviewLoading.value = false }
}

// 弹框内切换格式即时重渲
const renderDailyPreview = (): void => { void fetchDailyPreview(dailyPreviewFmt.value) }

// 卡片预览：昨日真实数据（默认 markdown）
const previewDaily = (): void => {
  if (dailyPreviewLoading.value) return
  dailyPreviewSource.value = ''
  dailyPreviewFmt.value = 'markdown'
  dailyPreviewFmtLocked.value = false
  dailyPreviewText.value = ''
  dailyPreviewVisible.value = true
  void fetchDailyPreview('markdown')
}

onMounted(() => {
  void fetchRules(true)
  void fetchAdminOverview()
  void fetchTrend()
  void fetchDeliveryStats()
})
// 回到规则页即时刷新：通道管理里刚停用的通道必须立刻反映为禁选（已选自动移出草稿）
watch(activeTab, v => { if (v === 'rules') void fetchRules(false) })
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
.user-pick { display: inline-flex; align-items: center; gap: 8px; }
.user-pick-label { font-size: 13px; color: #4b5563; }
.rule-name-text { font-weight: 600; }
.ev-more { font-size: 11px; color: #6b7280; }
/* 表格多选触发器（事件/发送至）：摘要 + 展开箭头，点击弹 bordered 复选组 */
.pick-trigger {
  display: flex; align-items: center; gap: 6px; width: 100%; max-width: 100%;
  height: 24px; padding: 0 8px; background: #fff;
  border: 1px solid #dcdfe6; border-radius: 0; color: #303133;
  font-family: inherit; font-size: 12px; line-height: 1; cursor: pointer; text-align: left;
}
.pick-trigger:hover { border-color: #409eff; }
.pick-trigger:focus-visible { border-color: #409eff; outline: 2px solid #c6e2ff; outline-offset: 0; }
/* 触发器 min-width 与浮层面板同宽（事件=340、发送至=300）：摘要与面板对齐不截断 */
.pick-trigger--events { min-width: 340px; }
.pick-trigger--channels { min-width: 300px; }
.pick-summary { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pick-summary.is-empty { color: #9ca3af; }
.pick-caret { flex: none; font-size: 12px; color: #909399; }
.tpl-lang-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.tpl-lang-hint { margin-top: 0; }
.tpl-channel-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.tpl-field { margin-bottom: 12px; }
.tpl-section-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.tpl-section-head .tpl-section-label { margin-bottom: 0; }
.tpl-section-label { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 8px; }
.tpl-format-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.tpl-format-label { flex: none; font-size: 12px; color: #6b7280; }
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; }
.tpl-hints { display: flex; flex-direction: column; gap: 2px; margin-top: 6px; }
.tpl-hints .form-hint { margin-top: 0; }
.tpl-preview { background: #f9fafb; padding: 10px; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; margin: 0; height: 360px; max-height: 46vh; overflow: auto; }
.tpl-md-preview { background: #f9fafb; padding: 10px 12px; font-size: 13px; line-height: 1.7; color: #111827; border: 1px solid #eef2f7; height: 360px; max-height: 46vh; overflow: auto; }
.tpl-md-preview h2 { font-size: 16px; margin: 6px 0; }
.tpl-md-preview h3 { font-size: 14px; margin: 8px 0 6px; }
.tpl-md-preview h4 { font-size: 13px; margin: 8px 0 4px; }
.tpl-md-preview table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 6px 0; }
.tpl-md-preview th, .tpl-md-preview td { border: 1px solid #e5e7eb; padding: 4px 8px; text-align: left; }
.tpl-md-preview th { background: #f3f4f6; }
.tpl-md-preview blockquote { border-left: 3px solid #d1d5db; margin: 6px 0; padding: 2px 10px; color: #6b7280; }
.tpl-md-preview ul { margin: 4px 0; padding-left: 18px; }
.tpl-md-preview code { background: #eef2f7; padding: 1px 4px; font-family: ui-monospace, monospace; }
.tpl-html-preview, .daily-html-preview { height: 360px; max-height: 46vh; width: 100%; border: 0; }
.rule-edit-dialog :deep(.el-dialog__body) { max-height: calc(100vh - 240px); overflow-y: auto; }
.daily-preview-dialog :deep(.el-dialog__body) { max-height: calc(100vh - 240px); overflow-y: auto; }
/* 预览折叠区：默认折叠防超屏；头仿节标题形态，去默认边框 */
.tpl-preview-collapse { border: none; --el-collapse-header-height: 36px; }
.tpl-preview-collapse :deep(.el-collapse-item__header) { font-size: 13px; font-weight: 600; color: #374151; border-bottom: none; }
.tpl-preview-collapse :deep(.el-collapse-item__wrap) { border-bottom: none; }
.tpl-preview-collapse :deep(.el-collapse-item__content) { padding-bottom: 0; }
.tpl-preview-mode { margin-bottom: 8px; }
.scope-hint { font-size: 12px; color: #9ca3af; }
.tpl-html-preview { width: 100%; height: 300px; border: 1px solid #e5e7eb; background: #fff; }
.rule-edit-dialog :deep(.el-dialog__body) { max-height: calc(100dvh - 180px); overflow-y: auto; }
.daily-card { margin-bottom: 16px; }
.daily-icon { color: #8b5cf6; }
.daily-body { display: flex; flex-direction: column; gap: 12px; }
.daily-field { display: flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
.daily-label { font-size: 13px; color: #4b5563; flex: none; width: 70px; line-height: 24px; }
.daily-items { flex: 1; min-width: 0; }
.daily-ch-select { flex: 1; min-width: 0; }
/* 空选警告常驻占位槽（DESIGN_SPEC §13：条件提示 min-height 保证卡片等高） */
.daily-warn-slot { min-height: 38px; }
.daily-warn-slot .info-note-bar { margin: 0; }
/* 日报预览弹窗 */
.daily-preview-toolbar { margin-bottom: 10px; }
.daily-html-preview { width: 100%; height: 340px; border: 1px solid #e5e7eb; background: #fff; }
/* 模板长度计数：右对齐贴编辑器；超限红字+info-note-bar 明示（保存侧同口径拦截） */
.tpl-length-row { display: flex; justify-content: flex-end; margin-top: 4px; }
.tpl-length-row .form-hint { margin-top: 0; font-variant-numeric: tabular-nums; }
.tpl-length-over { color: #ef4444; font-weight: 600; }
</style>

<style>
/* 通知中心多选组（日报卡 + 事件/发送至浮层共用同一视觉）。
 * el-popover 内容 teleport 到 body，故用唯一前缀的全局类；bordered 复选组
 * 自适应容器宽度换行（无固定 max-width），长标签换行不撑破浮层。 */
.notif-pick-group { display: flex; flex-wrap: wrap; gap: 8px; }
.notif-pick-group .el-checkbox { margin-right: 0; margin-bottom: 0; }
.notif-pick-group .el-checkbox.is-bordered { height: auto; min-height: 24px; padding: 2px 10px; margin: 0; }
.notif-pick-group .el-checkbox.is-bordered .el-checkbox__label { white-space: normal; line-height: 1.35; word-break: break-word; }
.notif-pick-panel { display: flex; flex-direction: column; gap: 12px; max-height: 380px; overflow-y: auto; padding-top: 2px; }
.notif-pick-hint { font-size: 12px; color: #6b7280; line-height: 1.5; }
.nd-pick-popper.el-popover { padding: 18px 16px 14px; box-sizing: border-box; }
/* 事件浮层按级别分区（严重/警告/信息）：中性样式，仅节标题分组，不着色 */
.notif-pick-group.notif-pick-sections { display: flex; flex-direction: column; gap: 14px; }
.notif-level-section { display: flex; flex-direction: column; gap: 8px; }
.notif-level-section + .notif-level-section { border-top: 1px dashed #eef2f7; padding-top: 12px; }
.notif-level-head { font-size: 12px; font-weight: 600; color: #6b7280; line-height: 1.4; margin-bottom: 2px; }
.notif-level-items { display: flex; flex-wrap: wrap; gap: 8px; }
.notif-level-head { position: relative; padding-left: 12px; }
.notif-level-head::before { content: ''; position: absolute; left: 0; top: 2px; bottom: 2px; width: 3px; background: var(--el-color-primary, #409eff); }
.notif-level-section.is-critical .notif-level-head::before { background: var(--el-color-danger, #f56c6c); }
.notif-level-section.is-warn .notif-level-head::before { background: var(--el-color-warning, #e6a23c); }
.notif-level-section.is-info .notif-level-head::before { background: var(--el-color-primary, #409eff); }
.rule-edit-dialog .el-dialog__body { max-height: calc(100vh - 300px); overflow-y: auto; overflow-x: hidden; }
.daily-preview-dialog .el-dialog__body { max-height: calc(100vh - 280px); overflow-y: auto; overflow-x: hidden; }
.daily-preview-body { height: 420px; max-height: 46vh; overflow-y: auto; overflow-x: hidden; border: 1px solid #eef2f7; }
.daily-preview-body iframe { display: block; width: 100%; height: 100%; border: 0; }
.daily-preview-body .daily-html-preview, .daily-preview-body .tpl-preview, .daily-preview-body .tpl-md-preview { height: 100%; max-height: none; }
.notif-pick-group .el-checkbox.is-bordered .el-checkbox__inner { display: none; }
.notif-pick-group .el-checkbox.is-bordered .el-checkbox__label { padding-left: 0; }
.daily-items .el-checkbox.is-bordered .el-checkbox__inner { display: none; }
.daily-items .el-checkbox.is-bordered .el-checkbox__label { padding-left: 0; }
.notif-pick-group .el-checkbox.is-bordered.is-disabled { border-color: #e4e7ed; }
.notif-pick-group .el-checkbox.is-bordered.is-disabled .el-checkbox__label { color: #a8abb2; }
</style>
