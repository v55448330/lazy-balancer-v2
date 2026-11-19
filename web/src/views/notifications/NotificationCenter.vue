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
                <el-button size="small" link type="primary" @click="openDailyConfig">{{ t('app.notification.daily.configBtn') }}</el-button>
                <el-button size="small" link type="primary" :loading="testingDaily" @click="testDaily">{{ t('app.notification.daily.testSend') }}</el-button>
                <el-button size="small" link type="primary" @click="previewDaily">{{ t('app.notification.rules.preview') }}</el-button>
                <el-switch v-model="dailyRule.enabled" size="small" @change="toggleRule(dailyRule)" />
              </div>
            </div>
          </template>
          <div class="daily-body">
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.dailySendTime') }}</span>
              <span class="daily-value">{{ dailyRule.send_time || '09:00' }}</span>
              <span class="form-hint">{{ t('app.notification.rules.dailyTimeHint') }}</span>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.daily.itemsLabel') }}</span>
              <div class="tag-wrap">
                <el-tag v-for="it in (dailyRule.items || [])" :key="it" size="small" effect="plain">{{ dailyItemLabel(it) }}</el-tag>
              </div>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.sendTo') }}</span>
              <div class="tag-wrap">
                <el-tag v-for="ch in dailyTargetChannels" :key="ch.id" size="small" effect="plain">{{ ch.name }}</el-tag>
                <span v-if="dailyRule.channel_ids && dailyRule.channel_ids.length === 0" class="ev-more">{{ t('app.notification.rules.noDelivery') }}</span>
                <span v-else-if="!userChannels.length" class="ev-more">{{ t('app.notification.rules.noChannelsHint') }}</span>
              </div>
            </div>
            <span class="form-hint">{{ t('app.notification.daily.configHint') }}</span>
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
          <el-table :data="eventRules" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb', color: '#374151', fontWeight: 600 }">
            <el-table-column :label="t('app.notification.rules.trigger')" width="90">
              <template #default="{ row }">
                <span class="rule-name-text">{{ eventGroup(row.title) }}</span>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.events')" min-width="280">
              <template #default="{ row }">
                <div class="tag-wrap">
                  <el-tag v-for="ev in (row.events || [])" :key="ev" size="small" effect="plain" :type="eventTagType(asRule(row), ev)">{{ eventTitle(asRule(row), ev) }}</el-tag>
                </div>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.minLevel')" width="120">
              <template #header>
                <span>{{ t('app.notification.rules.minLevel') }}<FieldHelpIcon :content="t('app.notification.rules.minLevelHint')" /></span>
              </template>
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
                <span v-if="row.channel_ids && row.channel_ids.length === 0" class="ev-more">{{ t('app.notification.rules.noDelivery') }}</span>
                <div v-else class="tag-wrap">
                  <el-tag v-for="ch in (row.channels || [])" :key="ch.id" size="small" effect="plain">{{ ch.name }}</el-tag>
                </div>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.bodyTemplate')" width="90">
              <template #default="{ row }">
                <el-button size="small" link type="primary" @click="editTemplate(asRule(row))">{{ t('app.notification.rules.edit') }}</el-button>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.notification.rules.enabled')" width="65">
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

    <!-- 模板弹框（事件规则与日报每通道共享）：rule 模式=接收通道+每通道规则模板；
         daily 模式=通道正文模板（style_config：机器人 content_template/webhook payload_template/email body_template）。
         机器人格式协议固定（仅高亮/预览样式）；webhook/email 格式可选。 -->
    <el-dialog v-model="tplDialogVisible" append-to-body class="dialog-body-inset rule-edit-dialog" width="min(860px, 94vw)" top="5vh">
      <template #header>
        <DialogHeader :icon="Bell" :title="t('app.notification.rules.editTemplateTitle')" :subtitle="tplMode === 'rule' ? (tplEditingRule?.title || '') : (tplActiveChannel?.name || '')" tone="primary" />
      </template>

      <!-- 接收通道（rule 模式）：勾选=仅发选定通道；全不选=不投递（保存即生效） -->
      <template v-if="tplMode === 'rule'">
        <div class="tpl-section-label">{{ t('app.notification.rules.sendTo') }}</div>
        <div class="rule-ch-select">
          <el-checkbox-group v-model="tplSelectedChannels">
            <el-checkbox v-for="ch in userChannels" :key="ch.id" :value="ch.id" border size="small" :disabled="ch.last_test_ok !== true" :title="ch.last_test_ok !== true ? t('app.notification.rules.channelUntestedHint') : undefined">
              {{ ch.name }}（{{ channelTypeLabel(ch.type) }}）
            </el-checkbox>
          </el-checkbox-group>
          <div class="form-hint">{{ t('app.notification.rules.channelSelectHint') }}</div>
          <div v-if="tplSelectedChannels.length === 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.rules.noDeliveryWarn') }}</span></div>
        </div>
        <el-divider />
      </template>

      <!-- 每通道模板：tab=目标通道（rule 模式=选定通道，未选=全部；daily 模式=全部通道） -->
      <template v-if="userChannels.length">
        <el-radio-group v-model="tplChannelTab" size="small" class="tpl-channel-switch">
          <el-radio-button v-for="ch in tplTabChannels" :key="ch.id" :value="String(ch.id)">{{ ch.name }}</el-radio-button>
        </el-radio-group>

        <div class="tpl-field">
          <div class="tpl-section-head">
            <div class="tpl-section-label">{{ tplEditorLabel }}</div>
            <el-button size="small" link type="primary" @click="resetTplToDefault">{{ t('app.notification.rules.tplDefault') }}</el-button>
          </div>
          <div class="tpl-format-row">
            <span class="daily-config-label">{{ t('app.notification.rules.tplFormatLabel') }}</span>
            <el-tag v-if="isBotChannel(tplActiveChannel?.type || '')" size="small" effect="plain">{{ dailyFormatLabel(tplActiveFormat) }}</el-tag>
            <el-select v-else-if="tplMode === 'daily'" :model-value="dailyRule ? dailyFormatOf(dailyRule, tplActiveChannel?.type || '') : 'auto'" size="small" style="width: 170px" @change="(v: string) => saveDailyFormat(dailyRule, tplActiveChannel?.type || '', v)">
              <el-option v-for="f in dailyFormatOptions" :key="f.value" :value="f.value" :label="f.label" />
            </el-select>
            <el-select v-else :model-value="tplActiveFormat" size="small" style="width: 170px" @change="setTplFormat">
              <el-option v-for="f in tplFormatOptions" :key="f.value" :value="f.value" :label="f.label" />
            </el-select>
          </div>
          <!-- JSON/HTML/Markdown 高亮编辑（CodeEditor 全站单源）；纯文本用 textarea -->
          <CodeEditor v-if="tplEditorLang !== 'text'" v-model="tplText" :language="tplEditorLang" height="220px" :aria-label="tplEditorLabel" />
          <el-input v-else v-model="tplText" type="textarea" :rows="7" :placeholder="tplPlaceholder" />
          <div class="ph-row">
            <el-tag v-for="ph in tplActivePh" :key="ph" size="small" effect="plain" class="ph-tag" @click="tplText += ph">{{ ph }}</el-tag>
          </div>
          <div class="form-hint">{{ t('app.notification.rules.tplPhHint') }}</div>
          <div v-if="tplActiveChannel?.type === 'email'" class="form-hint">{{ t('app.notification.rules.tplSubjectHint') }}</div>
          <div v-if="tplActiveChannel?.type === 'qq'" class="form-hint">{{ t('app.notification.rules.tplQqMdHint') }}</div>
          <div v-if="tplMode === 'rule'" class="form-hint">{{ t('app.notification.rules.templateHint') }}</div>
          <div v-else-if="isBotChannel(tplActiveChannel?.type || '')" class="form-hint">{{ t('app.notification.daily.contentTemplateHint') }}</div>
          <div v-else-if="tplActiveChannel?.type === 'webhook'" class="form-hint">{{ t('app.notification.daily.webhookTplHint') }}</div>
          <div v-else class="form-hint">{{ t('app.notification.daily.emailTplHint') }}</div>
        </div>

        <el-divider />
        <!-- 预览区默认折叠（防弹框超屏）：展开后渲染/源码切换与预览正文 -->
        <el-collapse v-model="tplPreviewOpen" class="tpl-preview-collapse">
          <el-collapse-item name="preview" :title="t('app.notification.rules.preview')">
            <div v-if="tplEditorLang === 'markup'" class="tpl-preview-mode">
              <el-radio-group v-model="htmlPreviewMode" size="small">
                <el-radio-button value="render">{{ t('app.notification.rules.previewRender') }}</el-radio-button>
                <el-radio-button value="source">{{ t('app.notification.rules.previewSource') }}</el-radio-button>
              </el-radio-group>
            </div>
            <!-- HTML：sandbox iframe 渲染预览（无脚本/无同源）；其余格式纯文本 pre -->
            <iframe v-if="tplEditorLang === 'markup' && htmlPreviewMode === 'render'" class="tpl-html-preview" sandbox="" :srcdoc="previewText" :title="t('app.notification.rules.preview')" />
            <pre v-else class="tpl-preview">{{ previewText }}</pre>
          </el-collapse-item>
        </el-collapse>
      </template>
      <el-empty v-else :description="t('app.notification.rules.noChannelsHint')" :image-size="60" />

      <template #footer>
        <el-button @click="tplDialogVisible = false">{{ t('app.notification.rules.cancel') }}</el-button>
        <el-button v-if="tplMode === 'rule'" type="primary" :loading="savingTpl" @click="saveTemplate">{{ t('app.notification.rules.save') }}</el-button>
        <el-button v-else type="primary" :loading="savingTplChannelId !== null" @click="saveChannelTplFromDialog">{{ t('app.notification.rules.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- 日报配置弹窗：基本配置（时间/项目/目标通道）+ 每通道格式与正文模板入口。
         机器人协议固定（QQ=Markdown 高亮/微信=纯文本），webhook/email 格式可选。 -->
    <el-dialog v-model="dailyConfigVisible" class="dialog-body-inset daily-config-dialog" width="min(860px, 94vw)" top="5vh">
      <template #header>
        <DialogHeader :icon="Calendar" :title="t('app.notification.daily.configTitle')" :subtitle="t('app.notification.daily.configSubtitle')" tone="primary" />
      </template>
      <div v-loading="dailyConfigLoading" class="daily-config-body">
        <template v-if="dailyRule">
          <DialogSectionHeader :title="t('app.notification.daily.basicSection')" />
          <div class="daily-config-basic">
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.rules.dailySendTime') }}</span>
              <el-time-select v-model="dailyRule.send_time" start="00:00" end="23:30" step="00:30" size="small" style="width: 120px" @change="saveRuleField(dailyRule)" />
              <span class="form-hint">{{ t('app.notification.rules.dailyTimeHint') }}</span>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.daily.itemsLabel') }}</span>
              <el-checkbox-group v-model="dailyRule.items" size="small" class="daily-items" @change="saveDailyItems(dailyRule)">
                <el-checkbox v-for="opt in dailyItemOptions" :key="opt.id" :value="opt.id">{{ dailyItemLabel(opt.id) }}</el-checkbox>
              </el-checkbox-group>
            </div>
            <div class="daily-field">
              <span class="daily-label">{{ t('app.notification.daily.channelsLabel') }}</span>
              <div class="daily-ch-select">
                <el-checkbox-group v-model="dailyChannelSelection" @change="saveDailyChannels(dailyRule)">
                  <el-checkbox v-for="ch in userChannels" :key="ch.id" :value="ch.id" border size="small" :disabled="ch.last_test_ok !== true" :title="ch.last_test_ok !== true ? t('app.notification.rules.channelUntestedHint') : undefined">
                    {{ ch.name }}（{{ channelTypeLabel(ch.type) }}）
                  </el-checkbox>
                </el-checkbox-group>
                <div class="form-hint">{{ t('app.notification.rules.channelSelectHint') }}</div>
                <div v-if="dailyChannelSelection.length === 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.notification.rules.noDeliveryWarn') }}</span></div>
              </div>
            </div>
          </div>
          <el-divider />
          <DialogSectionHeader :title="t('app.notification.daily.channelSection')" :description="t('app.notification.daily.botFormatHint')" class="daily-section-head" />
          <div class="daily-config-rows">
            <!-- 单行协调布局：名+类型 tag 左、格式右、编辑/预览行内 -->
            <div v-for="ch in userChannels" :key="ch.id" class="daily-config-row">
              <span class="daily-config-name">{{ ch.name }}</span>
              <el-tag size="small" effect="plain" type="info">{{ channelTypeLabel(ch.type) }}</el-tag>
              <div class="daily-config-format">
                <span class="daily-config-label">{{ t('app.notification.daily.formatLabel') }}</span>
                <el-tag v-if="isBotChannel(ch.type)" size="small" effect="plain">{{ dailyFormatLabel(fixedDailyFormat(ch.type)) }}</el-tag>
                <el-select v-else :model-value="dailyFormatOf(dailyRule, ch.type)" size="small" style="width: 170px" @change="(v: string) => saveDailyFormat(dailyRule, ch.type, v)">
                  <el-option v-for="f in dailyFormatOptions" :key="f.value" :value="f.value" :label="f.label" />
                </el-select>
              </div>
              <div class="daily-config-actions">
                <el-button size="small" link type="primary" @click="openChannelTplDialog(ch)">{{ t('app.notification.daily.editTemplate') }}</el-button>
                <el-button size="small" link type="primary" :loading="previewChannelId === ch.id" @click="previewChannelDaily(ch)">{{ t('app.notification.rules.preview') }}</el-button>
              </div>
            </div>
            <el-empty v-if="!dailyConfigLoading && userChannels.length === 0" :description="t('app.notification.rules.noChannelsHint')" :image-size="60" />
          </div>
        </template>
      </div>
      <template #footer>
        <el-button @click="dailyConfigVisible = false">{{ t('app.notification.rules.cancel') }}</el-button>
        <el-button type="primary" :loading="testingDaily" @click="testDaily">{{ t('app.notification.daily.testSend') }}</el-button>
      </template>
    </el-dialog>

    <!-- 日报预览弹窗（卡片预览与通道格式预览共用；html=sandbox iframe，其余纯文本 pre） -->
    <el-dialog v-model="dailyPreviewVisible" append-to-body class="dialog-body-inset" width="min(680px, 92vw)" top="6vh">
      <template #header>
        <DialogHeader :icon="Calendar" :title="t('app.notification.daily.previewTitle')" :subtitle="dailyPreviewSource" tone="primary" />
      </template>
      <div v-if="!dailyPreviewFmtLocked" class="daily-preview-toolbar">
        <el-radio-group v-model="dailyPreviewFmt" size="small" @change="renderDailyPreview">
          <el-radio-button v-for="f in dailyPreviewFormatOptions" :key="f.value" :value="f.value">{{ f.label }}</el-radio-button>
        </el-radio-group>
      </div>
      <iframe v-if="dailyPreviewFmt === 'html'" class="daily-html-preview" sandbox="" :srcdoc="dailyPreviewText" :title="t('app.notification.daily.previewTitle')" />
      <pre v-else v-loading="dailyPreviewLoading" class="tpl-preview">{{ dailyPreviewText || t('app.notification.daily.previewEmpty') }}</pre>
      <template #footer>
        <el-button @click="dailyPreviewVisible = false">{{ t('app.notification.rules.cancel') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Calendar, Bell, ChatDotRound, CircleCheckFilled, DataAnalysis, Odometer, TrendCharts } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import { axisChartBase, barSeries, lineSeries, pieChartBase } from '@/utils/chartBase'
import { securityActionColors } from '@/utils/chartTheme'
import { request, mfaAwareSuccess } from '@/utils/api'
import { hasOwn } from '@/utils/hasOwn'
import type { NotificationChannel } from '@/types/notifications.ts'
import { useAuthStore } from '@/stores/auth'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import FieldHelpIcon from '@/components/common/FieldHelpIcon.vue'
import CodeEditor from '@/components/CodeEditor.vue'
import DeliveryLog from './DeliveryLog.vue'
import ChannelCards from './ChannelCards.vue'
import SystemCredentials from './SystemCredentials.vue'

const { t, tm } = useI18n()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const activeTab = ref('overview')

interface RuleChannel { id: number; type: string; name: string; last_test_ok?: boolean }
interface Rule {
  id: string; trigger: string; title: string; events?: string[]
  event_titles?: Record<string, string>; event_levels?: Record<string, string>; min_level?: string; send_time?: string
  channels: RuleChannel[]; channel_ids?: number[]; channel_templates?: Record<string, string>
  body_template: string; enabled: boolean
  items?: string[]; formats?: Record<string, string>
}

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
// 事件标签按目录默认级别配色（info=蓝/warn=橙/critical=红），直观传达分级。
const eventTagType = (row: Rule, ev: string): 'info' | 'warning' | 'danger' => {
  const lv = row.event_levels?.[ev]
  if (lv === 'critical') return 'danger'
  if (lv === 'warn') return 'warning'
  return 'info'
}

const overviewStats = ref({ channels: 0, rules: 0, deliveries: 0, successRate: 0 })
const rulesUserId = ref<number>(0) // 管理员视角用户（0=未初始化，adminUsers 到达后默认本人）；非管理员恒本人
const adminUsers = ref<{ id: number; username: string }[]>([])
const channelDist = ref<{ type: string; count: number }[]>([])
const userChannels = ref<RuleChannel[]>([])

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
// rule 模式=接收通道选择+每通道规则模板；daily 模式=通道正文模板（style_config）。
const tplDialogVisible = ref(false)
const tplMode = ref<'rule' | 'daily'>('rule')
const tplEditingRule = ref<Rule | null>(null)
const tplSelectedChannels = ref<number[]>([])
const tplChannelTab = ref('') // 通道 ID 字符串
const tplTexts = ref<Record<string, string>>({}) // 通道 ID → 草稿模板
const tplFormats = ref<Record<string, string>>({}) // rule 模式：通道 ID → 正文格式（编辑高亮/预览状态）
const htmlPreviewMode = ref<'render' | 'source'>('render')
const tplPreviewOpen = ref<string[]>([]) // 预览区默认折叠（防弹框超屏），开弹框时复位
const savingTpl = ref(false)
const tplPh = ['{{title}}', '{{body}}', '{{level}}', '{{time}}', '{{event}}', '{{node}}']
const tplFormatOptions = ['text', 'markdown', 'html', 'json'].map(v => ({ value: v, label: dailyFormatLabel(v) }))

// 模板 tab 通道集：rule 模式=选定通道（未选=全部，仍可编辑模板，保存后不投递）；daily 模式=全部通道
const tplTabChannels = computed<RuleChannel[]>(() => {
  if (tplMode.value === 'daily') return userChannels.value
  if (tplSelectedChannels.value.length === 0) return userChannels.value
  return userChannels.value.filter(ch => tplSelectedChannels.value.includes(ch.id))
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
// 占位符集：rule 模式=事件变量；daily 模式机器人=日报+事件变量（content_template
// 两类同时替换），webhook/email=事件变量（renderStyleTemplate 不替换日报变量）。
const tplActivePh = computed<string[]>(() => {
  if (tplMode.value === 'daily' && isBotChannel(tplActiveChannel.value?.type || '')) return [...dailyPh, ...tplPh]
  return tplPh
})
const tplPlaceholder = computed(() => {
  const typ = tplActiveChannel.value?.type || 'wx_clawbot'
  return tplMode.value === 'daily' ? defaultChannelTplFor(typ) : defaultTplFor(typ)
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
    '    <span style="color:#f8fafc;font-size:16px;font-weight:600;">{{brand}}</span>',
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
    '  <p style="text-align:center;font-size:11px;color:#94a3b8;margin:16px 0;">此邮件由 {{brand}} 通知中心自动发送 · {{time}}</p>',
    '</div>',
  ].join('\n')
  if (typ === 'qq') return '# {{title}}\n\n> {{body}}\n\n**级别**：{{level}}　**事件**：{{event}}\n**节点**：{{node}}　**时间**：{{time}}\n\n> {{brand}}'
  return '【{{title}}】\n────────────\n{{body}}\n────────────\n级别：{{level}} | 事件：{{event}}\n节点：{{node}} | 时间：{{time}}\n—— {{brand}}'
}
const resetTplToDefault = (): void => {
  const ch = tplActiveChannel.value
  if (!ch) return
  tplText.value = tplMode.value === 'daily' ? defaultChannelTplFor(ch.type) : defaultTplFor(ch.type)
}
// 日报预览样例值（daily 模式机器人模板预览；键集=后端 dailyValues）
const dailySampleValues = { date: '2026-11-18', requests: '128340', allowed: '120111', logged: '7026', distinct_ips: '3204', blocked: '1203', attack_top: 'SQLi × 321', top_ip: '45.33.32.9', autoban: '17', cert_status: 'OK', cluster_status: '3/3' }
const previewText = computed(() => {
  let text = tplText.value
    .replace(/\{\{title\}\}/g, t('app.notification.rules.previewSampleTitle'))
    .replace(/\{\{body\}\}/g, t('app.notification.rules.previewSampleBody'))
    .replace(/\{\{level\}\}/g, 'critical')
    .replace(/\{\{event\}\}/g, 'cert.failed')
    .replace(/\{\{node\}\}/g, 'node-a')
    .replace(/\{\{time\}\}/g, '2026-11-18 09:00')
    .replace(/\{\{brand\}\}/g, 'Lazy Balancer')
  if (tplMode.value === 'daily' && isBotChannel(tplActiveChannel.value?.type || '')) {
    for (const [k, v] of Object.entries(dailySampleValues)) text = text.split(`{{${k}}}`).join(v)
  }
  return text
})

const fetchRules = async (): Promise<void> => {
  loading.value = true
  try {
    // 默认当前用户；管理员可选其他用户（规则/通道按用户区分，概览才全平台）
    const rulesUrl = isAdmin.value && rulesUserId.value > 0 ? `/notification/rules?user_id=${rulesUserId.value}` : '/notification/rules'
    const res = await request.get<{ code: number; data?: { rules: Rule[]; channels?: RuleChannel[]; daily_items?: { id: string; label: string }[] } }>(rulesUrl)
    rules.value = res.data?.rules ?? []
    // 最低级别预选：空值回退目录默认级别 info（目录各组最低级别，亦为后端
    // 新建订阅行的起始级别）——下拉不再呈现空「请选择」态；仅显示兜底，不写库。
    for (const r of rules.value) {
      if (r.trigger === 'event' && !r.min_level) r.min_level = 'info'
    }
    userChannels.value = res.data?.channels ?? []
    dailyItemOptions.value = res.data?.daily_items ?? []
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
  catch { rule.enabled = !rule.enabled }
}

const saveRuleField = async (rule: Rule): Promise<void> => {
  // 部分更新：只提交变更字段（后端缺省键不动既有值）
  const body = rule.trigger === 'daily' ? { send_time: rule.send_time } : { min_level: rule.min_level }
  try { await request.post(ruleWriteUrl(rule.id), body) } catch { /* */ }
}

// 日报包含项目保存（部分更新：仅提交 items）
const saveDailyItems = async (rule: Rule | null): Promise<void> => {
  if (!rule) return
  if (!rule.items || rule.items.length === 0) { ElMessage.warning(t('app.notification.daily.itemsRequired')); return }
  try { await request.post(ruleWriteUrl(rule.id), { items: rule.items }) } catch { /* */ }
}
// 日报目标通道（与事件规则三态同口径：undefined=全部、[]=不投递、非空=选定）；
// 部分更新仅提交 channel_ids，即时保存
const dailyChannelSelection = computed<number[]>({
  get: () => dailyRule.value?.channel_ids ?? userChannels.value.map(ch => ch.id),
  set: (v) => { if (dailyRule.value) dailyRule.value.channel_ids = v },
})
const dailyTargetChannels = computed<RuleChannel[]>(() => {
  const ids = dailyRule.value?.channel_ids
  if (ids === undefined || ids === null) return userChannels.value
  return userChannels.value.filter(ch => ids.includes(ch.id))
})
const saveDailyChannels = async (rule: Rule | null): Promise<void> => {
  if (!rule) return
  try { await request.post(ruleWriteUrl(rule.id), { channel_ids: rule.channel_ids ?? [] }) } catch { /* */ }
}
// 日报 per-channel 格式保存：formats 键=通道族；auto=删除该键（回退自动映射）
const saveDailyFormat = async (rule: Rule | null, channelType: string, format: string): Promise<void> => {
  if (!rule) return
  const formats: Record<string, string> = { ...(rule.formats || {}) }
  if (format === 'auto') delete formats[channelType]
  else formats[channelType] = format
  rule.formats = formats
  try { await request.post(ruleWriteUrl(rule.id), { formats }) } catch { /* */ }
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
    ElMessage.success(t('app.notification.daily.testSent'))
  } catch (e) { console.error(e) } finally { testingDaily.value = false }
}

// ===== 日报配置弹窗（基本配置 + 每通道格式/内容模板） =====
const dailyConfigVisible = ref(false)
const dailyConfigLoading = ref(false)
const dailyFullChannels = ref<NotificationChannel[]>([])
const dailyTplDrafts = ref<Record<number, string>>({})
const savingTplChannelId = ref<number | null>(null)
const previewChannelId = ref<number | null>(null)

// 机器人协议固定：QQ=Markdown、微信=纯文本（格式不可选，仅决定编辑高亮与预览样式）
const isBotChannel = (typ: string): boolean => typ === 'qq' || typ === 'wx_clawbot'
const fixedDailyFormat = (typ: string): string => (typ === 'qq' ? 'markdown' : 'text')
// 日报变量（后端派发时从日报载荷 values 替换）
const dailyPh = ['{{date}}', '{{requests}}', '{{blocked}}', '{{attack_top}}', '{{autoban}}', '{{cert_status}}', '{{cluster_status}}']
// 精美预置日报模板（对齐后端运营日报视觉：emoji+分节+指标表）：
// QQ=Markdown 分节表格，微信=纯文本分节行（iLink 协议无 markdown 能力）
const defaultDailyTplFor = (typ: string): string => {
  if (typ === 'qq') return [
    '## 📊 {{brand}} 日报（{{date}}）',
    '',
    '### 🌐 全局概览',
    '',
    '| 指标 | 数值 |',
    '| --- | --- |',
    '| 请求数 | {{requests}} |',
    '| 放行次数 | {{allowed}} |',
    '| 观察次数 | {{logged}} |',
    '| 独立 IP 数 | {{distinct_ips}} |',
    '',
    '### 🛡 安全风险',
    '',
    '| 指标 | 数值 |',
    '| --- | --- |',
    '| 拦截次数 | {{blocked}} |',
    '| 攻击 TOP 规则 | {{attack_top}} |',
    '| TOP 攻击源 | {{top_ip}} |',
    '| 自动封禁次数 | {{autoban}} |',
    '',
    '### 🔒 证书状态',
    '',
    '| 指标 | 数值 |',
    '| --- | --- |',
    '| 证书状态 | {{cert_status}} |',
    '',
    '### 🖥 集群状态',
    '',
    '| 指标 | 数值 |',
    '| --- | --- |',
    '| 集群状态 | {{cluster_status}} |',
    '',
    '> {{brand}} · {{time}}',
  ].join('\n')
  return [
    '📊 {{brand}} 日报（{{date}}）',
    '',
    '🌐 全局概览',
    '请求数：{{requests}}',
    '放行次数：{{allowed}}',
    '观察次数：{{logged}}',
    '独立 IP 数：{{distinct_ips}}',
    '',
    '🛡 安全风险',
    '拦截次数：{{blocked}}',
    '攻击 TOP 规则：{{attack_top}}',
    'TOP 攻击源：{{top_ip}}',
    '自动封禁次数：{{autoban}}',
    '',
    '🔒 证书状态',
    '证书状态：{{cert_status}}',
    '',
    '🖥 集群状态',
    '集群状态：{{cluster_status}}',
    '',
    '—— {{brand}} · {{time}}',
  ].join('\n')
}
// 通道模式预置：机器人=精美日报模板；webhook=JSON 载荷模板（占位符不裹引号，
// 与保存侧 probe 校验同口径）；email=内联样式 HTML 卡片（与规则模式预置同源）。
const defaultChannelTplFor = (typ: string): string => {
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
  if (typ === 'email') return defaultTplFor('email')
  return defaultDailyTplFor(typ)
}

const openDailyConfig = async (): Promise<void> => {
  dailyConfigVisible.value = true
  dailyConfigLoading.value = true
  // 先以规则通道摘要预置草稿（每通道类型预置模板），保证编辑器 modelValue 恒为字符串；
  // 全量通道到达后再以既有正文模板覆盖（fetch 失败不致 undefined 传入 CodeEditor）。
  const seed: Record<number, string> = {}
  for (const ch of userChannels.value) seed[ch.id] = defaultChannelTplFor(ch.type)
  dailyTplDrafts.value = seed
  try {
    // rules 端点的通道摘要不含 style_config——正文模板读写需全量通道 DTO
    const res = await request.get<{ data?: { channels?: NotificationChannel[] } }>('/notification/channels', { silent: true })
    const full = res.data?.channels ?? []
    dailyFullChannels.value = full
    const drafts: Record<number, string> = { ...seed }
    for (const ch of full) {
      let style: Record<string, unknown> = {}
      try { style = JSON.parse(ch.style_config || '{}') as Record<string, unknown> } catch { style = {} }
      const tpl = style[channelBodyTplKey(ch.type)]
      const saved = typeof tpl === 'string' ? tpl : ''
      // 未保存过=预置形态，保存后写入通道配置
      drafts[ch.id] = saved || defaultChannelTplFor(ch.type)
    }
    dailyTplDrafts.value = drafts
  } catch (e) { console.error(e) } finally { dailyConfigLoading.value = false }
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
  } catch (e) { console.error(e); return false } finally { savingTplChannelId.value = null }
}

// 通道模式入口（日报配置每通道「编辑模板」）：打开与事件规则共享的模板弹框
const openChannelTplDialog = (ch: RuleChannel): void => {
  tplMode.value = 'daily'
  tplEditingRule.value = null
  const drafts: Record<string, string> = {}
  for (const c of userChannels.value) drafts[String(c.id)] = dailyTplDrafts.value[c.id] ?? defaultChannelTplFor(c.type)
  tplTexts.value = drafts
  tplChannelTab.value = String(ch.id)
  htmlPreviewMode.value = 'render'
  tplPreviewOpen.value = []
  tplDialogVisible.value = true
}
// 通道模式保存：草稿回写日报草稿库后落通道配置；成功关闭弹框
const saveChannelTplFromDialog = async (): Promise<void> => {
  const ch = tplActiveChannel.value
  if (!ch) return
  dailyTplDrafts.value = { ...dailyTplDrafts.value, [ch.id]: tplTexts.value[String(ch.id)] ?? '' }
  if (await saveChannelBodyTemplate(ch)) tplDialogVisible.value = false
}

const editTemplate = (rule: Rule): void => {
  tplMode.value = 'rule'
  tplEditingRule.value = rule
  // channel_ids 三态：undefined=缺省（全部通道，UI 呈现为全选）；[]=显式不投递
  tplSelectedChannels.value = rule.channel_ids === undefined || rule.channel_ids === null
    ? userChannels.value.map(ch => ch.id)
    : [...rule.channel_ids]
  // 草稿初始化：既有每通道模板 > 事件级模板 > 通道形态预置；格式=类型缺省
  const drafts: Record<string, string> = {}
  const formats: Record<string, string> = {}
  for (const ch of userChannels.value) {
    drafts[String(ch.id)] = rule.channel_templates?.[String(ch.id)] || rule.body_template || defaultTplFor(ch.type)
    formats[String(ch.id)] = ch.type === 'webhook' ? 'json' : ch.type === 'email' ? 'html' : fixedDailyFormat(ch.type)
  }
  tplTexts.value = drafts
  tplFormats.value = formats
  const targets = tplSelectedChannels.value.length ? userChannels.value.filter(ch => tplSelectedChannels.value.includes(ch.id)) : userChannels.value
  tplChannelTab.value = targets.length ? String(targets[0].id) : ''
  htmlPreviewMode.value = 'render'
  tplPreviewOpen.value = []
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
  // 保存写库需确认（取消不执行）
  try { await ElMessageBox.confirm(t('app.notification.rules.saveConfirm'), t('app.notification.rules.confirmTitle'), { type: 'warning' }) }
  catch { return }
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

// 通道格式预览：机器人随协议固定格式；webhook/email 按生效格式（日报覆盖 > 类型自动映射）
const previewChannelDaily = (ch: RuleChannel): void => {
  if (previewChannelId.value !== null || dailyPreviewLoading.value) return
  const configured = dailyRule.value ? dailyFormatOf(dailyRule.value, ch.type) : 'auto'
  const fmt = isBotChannel(ch.type) ? fixedDailyFormat(ch.type) : configured === 'auto' ? autoDailyFormat(ch.type) : configured
  dailyPreviewSource.value = ch.name
  dailyPreviewFmt.value = fmt
  dailyPreviewFmtLocked.value = isBotChannel(ch.type)
  dailyPreviewText.value = ''
  dailyPreviewVisible.value = true
  previewChannelId.value = ch.id
  void fetchDailyPreview(fmt).finally(() => { previewChannelId.value = null })
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
.rule-name-text { font-weight: 600; }
.tag-wrap { display: flex; flex-wrap: wrap; gap: 4px; }
.ev-more { font-size: 11px; color: #6b7280; }
.tpl-channel-switch { margin-bottom: 16px; }
.tpl-field { margin-bottom: 12px; }
.tpl-section-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.tpl-section-head .tpl-section-label { margin-bottom: 0; }
.tpl-section-label { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 8px; }
.tpl-format-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.ph-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.ph-tag { cursor: pointer; user-select: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form-hint { font-size: 12px; color: #6b7280; margin-top: 4px; }
.tpl-preview { background: #f9fafb; padding: 10px; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; margin: 0; }
/* 预览折叠区：默认折叠防超屏；头仿节标题形态，去默认边框 */
.tpl-preview-collapse { border: none; --el-collapse-header-height: 36px; }
.tpl-preview-collapse :deep(.el-collapse-item__header) { font-size: 13px; font-weight: 600; color: #374151; border-bottom: none; }
.tpl-preview-collapse :deep(.el-collapse-item__wrap) { border-bottom: none; }
.tpl-preview-collapse :deep(.el-collapse-item__content) { padding-bottom: 0; }
.tpl-preview-mode { margin-bottom: 8px; }
.scope-hint { font-size: 12px; color: #9ca3af; }
.rule-ch-select { margin-bottom: 4px; }
.rule-ch-select :deep(.el-checkbox) { margin-right: 12px; margin-bottom: 6px; }
.tpl-html-preview { width: 100%; height: 300px; border: 1px solid #e5e7eb; background: #fff; }
.rule-edit-dialog :deep(.el-dialog__body) { max-height: calc(100dvh - 180px); overflow-y: auto; }
.daily-card { margin-bottom: 16px; }
.daily-icon { color: #8b5cf6; }
.daily-body { display: flex; flex-direction: column; gap: 12px; }
.daily-field { display: flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
.daily-label { font-size: 13px; color: #4b5563; flex: none; width: 70px; line-height: 24px; }
.daily-items { max-width: 640px; display: flex; flex-wrap: wrap; gap: 6px 16px; }
.daily-items :deep(.el-checkbox) { margin-right: 0; height: 24px; }
.daily-value { font-size: 13px; font-weight: 600; color: #111827; }
.daily-ch-select { flex: 1; min-width: 0; }
.daily-ch-select :deep(.el-checkbox) { margin-right: 12px; margin-bottom: 6px; }
/* 日报配置弹窗：基本配置 + 每通道单行卡（名+类型 tag 左 / 格式右 / 编辑预览行内） */
.daily-config-body { min-height: 80px; }
.daily-config-basic { display: flex; flex-direction: column; gap: 12px; }
.daily-config-dialog :deep(.el-dialog__body) { max-height: calc(100dvh - 180px); overflow-y: auto; }
.daily-config-rows { display: flex; flex-direction: column; gap: 8px; }
.daily-config-row { border: 1px solid #ebeef5; border-radius: 0; padding: 10px 14px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.daily-config-name { font-weight: 600; font-size: 13px; color: #111827; }
.daily-config-format { margin-left: auto; display: flex; align-items: center; gap: 8px; }
.daily-config-label { font-size: 12px; color: #6b7280; flex: none; }
.daily-config-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
/* 节标题与左竖条顶对齐（描述在标题下，不整块居中） */
.daily-config-dialog :deep(.daily-section-head) { align-items: flex-start; }
/* 日报预览弹窗 */
.daily-preview-toolbar { margin-bottom: 10px; }
.daily-html-preview { width: 100%; height: 340px; border: 1px solid #e5e7eb; background: #fff; }
</style>