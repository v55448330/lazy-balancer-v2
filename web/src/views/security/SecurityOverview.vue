<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><DataAnalysis /></el-icon>
          {{ t('app.security.overview.page.title') }}
        </h2>
        <p class="page-desc">{{ t('app.security.overview.page.desc') }}</p>
      </div>
      <el-button type="primary" plain @click="openThreatScreen">
        <el-icon style="margin-right: 6px"><Monitor /></el-icon>
        {{ t('app.security.overview.page.threatScreen') }}
      </el-button>
    </div>

    <el-alert
      v-if="overviewError"
      type="error"
      show-icon
      :closable="false"
      class="polling-error-alert error-banner"
    >
      <template #title>
        <div class="polling-error-title">
          <span>{{ t('app.security.overview.page.loadFailed') }}</span>
          <el-button link type="danger" :loading="reloading" @click="reloadAll">{{ t('app.security.overview.page.retryNow') }}</el-button>
        </div>
      </template>
    </el-alert>

    <!-- 采集健康位（任务已停/连续失败/审计写侧降级）：判据与文案与事件列表/大屏同源 -->
    <div v-if="ingestionWarning" class="info-note-bar">
      <span class="info-note-desc">{{ ingestionWarning }}</span>
    </div>

    <!-- 运行状态条：防护三 KPI（拦截/检测/正常请求）等分栅格 + 规则库四状态合并单面板。
         每列四行同构：标签 / 今日主数值 / 昨日对比 / 协议拆分（防御式：缺字段行隐藏）。 -->
    <div class="mb-5"><el-card shadow="always" class="overview-card status-strip-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Stopwatch /></el-icon>
            <span>{{ t('app.security.overview.status.cardTitle') }}</span>
          </div>
        </div>
      </template>
      <div class="status-strip">
        <div class="status-guard">
          <div class="guard-item">
            <div class="strip-label">
              {{ t('app.security.overview.status.blocked') }}
              <el-tooltip :content="todayCountTip" placement="top">
                <el-icon><InfoFilled /></el-icon>
              </el-tooltip>
            </div>
            <div class="strip-value is-danger">{{ fmtStatNum(overview.today_blocked) }}</div>
            <div v-if="yesterdayBlocked !== null" class="strip-sub"><span class="strip-sub-label">{{ t('app.security.overview.status.yesterday') }}</span> {{ fmtStatNum(yesterdayBlocked) }}</div>
            <!-- 协议拆分（L4 阶段 0/1 披露，今日口径）：HTTP = 合计 − TCP；响应缺字段或 TCP=0 时隐藏 -->
            <div v-if="todayBlockedSplit" class="strip-sub">
              <span class="proto-split-item"><i class="proto-dot proto-dot--http"></i><span class="proto-split-label">HTTP</span><span class="strip-sub-num">{{ fmtStatNum(todayBlockedSplit.http) }}</span></span><span class="proto-split-item proto-split-item--tcp"><i class="proto-dot proto-dot--tcp"></i><span class="proto-split-label">TCP</span><span class="strip-sub-num">{{ fmtStatNum(todayBlockedSplit.tcp) }}</span></span>
            </div>
          </div>
          <div class="strip-divider"></div>
          <div class="guard-item">
            <div class="strip-label">{{ t('app.security.overview.status.detected') }}</div>
            <div class="strip-value is-warning">{{ fmtStatNum(overview.today_detected) }}</div>
            <div v-if="yesterdayDetected !== null" class="strip-sub"><span class="strip-sub-label">{{ t('app.security.overview.status.yesterday') }}</span> {{ fmtStatNum(yesterdayDetected) }}</div>
            <!-- 协议拆分：TCP 检测来自信任检测（trust_detect） logged 事件——可能产生数据就如实显示；
                 字段缺失（旧后端）整行隐藏。HTTP = 合计 − TCP（负值钳 0） -->
            <div v-if="todayDetectedSplit" class="strip-sub">
              <span class="proto-split-item"><i class="proto-dot proto-dot--http"></i><span class="proto-split-label">HTTP</span><span class="strip-sub-num">{{ fmtStatNum(todayDetectedSplit.http) }}</span></span><span class="proto-split-item proto-split-item--tcp"><i class="proto-dot proto-dot--tcp"></i><span class="proto-split-label">TCP</span><span class="strip-sub-num">{{ fmtStatNum(todayDetectedSplit.tcp) }}</span></span>
            </div>
          </div>
        <div class="strip-divider"></div>
          <div class="guard-item">
            <div class="strip-label">{{ t('app.security.overview.status.normal') }}
              <el-tooltip :content="t('app.security.overview.status.normalTip')" placement="top">
                <el-icon><InfoFilled /></el-icon>
              </el-tooltip>
            </div>
            <div class="strip-value">{{ fmtStatNum(overview.normal_today) }}</div>
            <div v-if="normalYesterday !== null" class="strip-sub"><span class="strip-sub-label">{{ t('app.security.overview.status.yesterday') }}</span> {{ fmtStatNum(normalYesterday) }}</div>
            <!-- 字段缺失（旧后端）整行隐藏 -->
            <div v-if="normalTodaySplit" class="strip-sub">
              <span class="proto-split-item"><i class="proto-dot proto-dot--http"></i><span class="proto-split-label">HTTP</span><span class="strip-sub-num">{{ fmtStatNum(normalTodaySplit.http) }}</span></span><span class="proto-split-item proto-split-item--tcp"><i class="proto-dot proto-dot--tcp"></i><span class="proto-split-label">TCP</span><span class="strip-sub-num">{{ fmtStatNum(normalTodaySplit.tcp) }}</span></span>
            </div>
          </div>
          </div>
        <div class="status-lib">
          <div class="lib-row">
            <i class="status-dot" :class="overview.crs_available === false ? 'is-down' : 'is-up'"></i>
            <span class="lib-name">{{ t('app.security.overview.libStatus.crs') }}</span>
            <span class="lib-ver">{{ overview.crs_available === false ? t('app.security.overview.libStatus.notInstalled') : overview.crs_version }}</span>
            <el-tag v-if="overview.crs_available === false" type="danger" size="small" effect="plain" disable-transitions>{{ t('app.security.overview.libStatus.notInstalled') }}</el-tag>
            <el-tag v-else-if="overview.update_status" :type="libraryStatusTagType(overview.update_status)" size="small" effect="plain" disable-transitions>{{ libraryStatusLabel(overview.update_status) }}</el-tag>
          </div>
          <div class="lib-row">
            <i class="status-dot" :class="overview.ip2region_available === false || ip2regionError ? 'is-down' : 'is-up'"></i>
            <span class="lib-name">{{ t('app.security.overview.libStatus.ipGeo') }}</span>
            <span class="lib-ver">{{ overview.ip2region_available === false || ip2regionVersion === 'unknown' ? t('app.security.overview.libStatus.notInstalled') : ip2regionVersion === 'bundled' ? t('app.security.overview.libStatus.bundled') : ip2regionVersion }}</span>
            <el-tag v-if="ip2regionError" type="danger" size="small" effect="plain" disable-transitions>{{ t('app.security.overview.libStatus.loadFailed') }}</el-tag>
            <el-tag v-else-if="overview.ip2region_available === false" type="danger" size="small" effect="plain" disable-transitions>{{ t('app.security.overview.libStatus.notInstalled') }}</el-tag>
            <el-tag v-else-if="ip2regionVersion === 'unknown'" type="info" size="small" effect="plain" disable-transitions>{{ t('app.security.overview.libStatus.notInstalled') }}</el-tag>
            <el-tag v-else-if="ip2regionStatus" :type="libraryStatusTagType(ip2regionStatus)" size="small" effect="plain" disable-transitions>{{ libraryStatusLabel(ip2regionStatus) }}</el-tag>
          </div>
          <div class="lib-row">
            <i class="status-dot" :class="threatError ? 'is-down' : 'is-up'"></i>
            <span class="lib-name">{{ t('app.security.overview.libStatus.threatIntel') }}</span>
            <span class="lib-ver">{{ threatError ? '—' : (threatLatestVersion || t('app.security.overview.libStatus.notUpdated')) }}</span>
            <el-tag v-if="threatError" type="danger" size="small" effect="plain" disable-transitions>{{ t('app.security.overview.libStatus.loadFailed') }}</el-tag>
            <el-tag v-else-if="threatStatus" :type="libraryStatusTagType(threatStatus)" size="small" effect="plain" disable-transitions>{{ libraryStatusLabel(threatStatus) }}</el-tag>
          </div>
          <div class="lib-row">
            <i class="status-dot" :class="crawlerError ? 'is-down' : 'is-up'"></i>
            <span class="lib-name">{{ t('app.security.overview.libStatus.crawlerDb') }}</span>
            <span class="lib-ver">{{ crawlerError ? '—' : (crawlerLatestVersion || t('app.security.overview.libStatus.notUpdated')) }}</span>
            <el-tag v-if="crawlerError" type="danger" size="small" effect="plain" disable-transitions>{{ t('app.security.overview.libStatus.loadFailed') }}</el-tag>
            <el-tag v-else-if="crawlerStatus" :type="libraryStatusTagType(crawlerStatus)" size="small" effect="plain" disable-transitions>{{ libraryStatusLabel(crawlerStatus) }}</el-tag>
          </div>
        </div>
      </div>
    </el-card>
    </div>


    <el-row :gutter="20" class="mb-5 charts-row">
      <el-col :xs="24" :md="16">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><TrendCharts /></el-icon>
                <span>{{ t('app.security.overview.trend.title') }}</span>
              </div>
            </div>
          </template>
          <div class="chart-container">
            <v-chart v-if="overview.trend.length > 0" :option="trendChartOption" autoresize style="height: 260px" />
            <el-empty v-else :description="t('app.security.overview.trend.empty')" :image-size="80" style="height: 260px; display: flex; align-items: center; justify-content: center" />
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="8">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><PieChart /></el-icon>
                <span>{{ t('app.security.overview.trend.attackTitle') }}</span>
                <el-checkbox v-model="attackByStage" size="small" class="header-checkbox">{{ t('app.security.overview.trend.byStage') }}</el-checkbox>
              </div>
            </div>
          </template>
          <div class="chart-container">
            <v-chart v-if="(attackByStage ? overview.attack_types_stage : overview.attack_types).length > 0" :option="attackChartOption" autoresize style="height: 260px" />
            <el-empty v-else :description="t('app.security.overview.trend.emptyAttack')" :image-size="80" style="height: 260px; display: flex; align-items: center; justify-content: center" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog :model-value="challengeLiveVisible" width="min(1120px, 96vw)" top="5vh" class="challenge-live-dialog" @update:model-value="onChallengeVisibleChange">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Odometer /></el-icon>
            <span>{{ t('app.security.overview.cc.liveTitle') }}</span>
          </div>
          <div class="challenge-live-tools">
            <span v-if="challengeLiveUpdated" class="challenge-live-updated">{{ t('app.security.overview.cc.liveUpdated', { time: challengeLiveUpdated }) }}</span>
            <el-switch v-model="challengeAutoRefresh" size="small" @change="syncChallengeTimer" />
            <span class="challenge-live-auto-label">{{ t('app.security.overview.cc.liveAuto') }}</span>
            <el-button size="small" link :loading="challengeLiveLoading" @click="fetchChallengeLive">{{ t('app.security.overview.page.retryNow') }}</el-button>
          </div>
        </div>
      </template>
      <el-alert v-if="challengeLiveError" type="error" show-icon :closable="false" class="mb-3" :title="t('app.security.overview.events.loadFailed')" />
      <div class="challenge-live-toolbar">
        <div class="challenge-live-counter" :class="{ 'is-active': challengeLiveActiveCount > 0 }">
          <span>{{ t('app.security.overview.cc.liveActiveCount') }}</span>
          <strong>{{ challengeLiveActiveCount }}</strong>
        </div>
        <el-radio-group v-model="challengeLiveScope" size="small" @change="fetchChallengeLive">
          <el-radio-button value="active">{{ t('app.security.overview.cc.liveScopeActive') }}</el-radio-button>
          <el-radio-button value="recent">{{ t('app.security.overview.cc.liveScopeRecent') }}</el-radio-button>
        </el-radio-group>
      </div>
      <el-table :data="challengeEvents" v-loading="challengeLiveLoading" size="small" height="430" row-key="id" :empty-text="challengeLiveScope === 'active' ? t('app.security.overview.cc.liveEmptyActive') : t('app.security.overview.cc.liveEmptyRecent')">
        <el-table-column :label="t('app.security.overview.cc.liveColStatus')" width="112" align="center">
          <template #default="{ row }">
            <div class="challenge-live-status">
              <el-tag size="small" :type="challengeStatusTone(row as ChallengeEvent)" effect="light">{{ challengeStatusText(row as ChallengeEvent) }}</el-tag>
              <span class="challenge-live-attempts">{{ formatLiveAttempts(row as ChallengeEvent) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.overview.cc.liveColExpires')" width="128">
          <template #default="{ row }">
            <div v-if="(row as ChallengeEvent).status === 'waiting'" class="challenge-live-countdown">
              <strong>{{ formatLiveRemaining((row as ChallengeEvent).remaining_ms) }}</strong>
              <span>{{ t('app.security.overview.cc.liveExpiresAt', { time: formatLiveClock((row as ChallengeEvent).expires_at_ms) }) }}</span>
            </div>
            <div v-else class="challenge-live-countdown">
              <span>{{ t('app.security.overview.cc.liveIssuedAt', { time: formatLiveClock((row as ChallengeEvent).issued_at_ms) }) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.overview.cc.liveColClient')" min-width="128" show-overflow-tooltip>
          <template #default="{ row }">{{ row.client_ip || '—' }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.overview.cc.liveColRule')" min-width="168" show-overflow-tooltip>
          <template #default="{ row }">
            <div class="challenge-live-attribution">
              <span>{{ row.rule_name || row.rule_id || '—' }}</span>
              <span>{{ [challengeKindText(row as ChallengeEvent), row.policy_name].filter(Boolean).join(' · ') }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.overview.cc.liveColRequest')" min-width="180" show-overflow-tooltip>
          <template #default="{ row }"><span class="challenge-live-method">{{ row.method }}</span> {{ row.uri }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.overview.cc.liveColUA')" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ row.user_agent || '—' }}</template>
        </el-table-column>
      </el-table>
      <div class="challenge-live-footer">{{ t('app.security.overview.cc.liveRetention') }}</div>
    </el-dialog>

    <el-row :gutter="20" class="mb-5 events-row">
      <el-col :xs="24" :md="16">
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Warning /></el-icon>
                <span>{{ t('app.security.overview.events.title') }}</span>
              </div>
              <AccessibleLink type="primary" @click="goToEvents">{{ t('app.security.overview.events.viewAll') }}</AccessibleLink>
            </div>
          </template>
          <el-alert v-if="blockedEventsError" type="error" show-icon :closable="false" class="error-banner">
            <template #title>
              <div class="polling-error-title">
                <span>{{ t('app.security.overview.events.loadFailed') }}</span>
                <el-button link type="danger" :loading="reloading" @click="reloadAll">{{ t('app.security.overview.page.retryNow') }}</el-button>
              </div>
            </template>
          </el-alert>
          <el-table v-else :data="blockedEvents" stripe :header-cell-style="{ background: '#f9fafb', textAlign: 'left' }" :cell-style="{ textAlign: 'left' }" empty-text="">
            <template #empty><el-empty :description="t('app.security.overview.events.empty')" :image-size="60" /></template>
            <el-table-column prop="event_time" :label="t('app.security.overview.events.colTime')" width="170" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
            <el-table-column :label="t('app.security.overview.events.colSourceIp')" min-width="150">
              <template #default="{ row }">
              <IPLocationAction :ip="row.client_ip" :location="row.ip_location" />
              </template>
            </el-table-column>
            <el-table-column :label="t('app.security.overview.events.colProtocol')" width="80">
              <template #default="{ row }">
                <el-tag v-if="row.event_type === 'tcp'" size="small" effect="plain" class="proto-tcp-tag event-proto-tag">TCP</el-tag>
                <el-tag v-else size="small" effect="plain" type="primary" class="event-proto-tag">HTTP</el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.security.overview.events.colRule')" min-width="150" show-overflow-tooltip>
              <template #default="{ row }">{{ row.rule_name || row.rule_caddy_id || '—' }}</template>
            </el-table-column>
            <el-table-column :label="t('app.security.overview.events.colPolicy')" min-width="140" show-overflow-tooltip>
              <template #default="{ row }">{{ row.policy_name || '—' }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="8">
        <el-card shadow="always" class="cc-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Odometer /></el-icon>
                <span>{{ t('app.security.overview.cc.title') }}</span>
              </div>
              <el-button size="small" text type="primary" class="cc-live-button" @click="openChallengeLive">{{ t('app.security.overview.cc.liveButton') }}</el-button>
            </div>
          </template>
          <div class="cc-hero">
            <div class="cc-donut" role="img" :aria-label="t('app.security.overview.cc.passRate')">
              <svg viewBox="0 0 42 42" aria-hidden="true">
                <circle class="cc-donut-track" cx="21" cy="21" r="15.915" />
                <circle v-if="ccPassRatePct && ccPassRatePct > 0" class="cc-donut-value" cx="21" cy="21" r="15.915" :stroke-dasharray="`${ccPassRatePct} 100`" />
              </svg>
              <div class="cc-donut-center">
                <span class="cc-rate-value">{{ humanPassRate }}</span>
                <span class="cc-rate-label">{{ t('app.security.overview.cc.passRate') }}</span>
              </div>
            </div>
            <div class="cc-meta">
              <div class="cc-meta-row">
                <span class="cc-meta-label">{{ t('app.security.overview.cc.challengedToday') }}</span>
                <span class="cc-meta-value is-primary">{{ fmtStatNum(overview.today_challenged) }}</span>
              </div>
              <div class="cc-meta-row">
                <span class="cc-meta-label">{{ t('app.security.overview.cc.passedTotal') }}</span>
                <span class="cc-meta-value is-pass">{{ fmtStatNum(ccPassCount) }}</span>
              </div>
              <div class="cc-meta-row">
                <span class="cc-meta-label">{{ t('app.security.overview.cc.failedTotal') }}</span>
                <span class="cc-meta-value is-fail">{{ fmtStatNum(ccFailCount) }}</span>
              </div>
            </div>
          </div>
          <div class="cc-dist">
            <div class="cc-dist-head">
              <span>{{ t('app.security.overview.cc.resultTitle') }}</span>
              <span>{{ t('app.security.overview.cc.total', { n: ccTotalCount }) }}</span>
            </div>
            <div class="cc-stack" :title="t('app.security.overview.cc.stackTip')">
              <span class="cc-stack-pass" :style="{ width: ccPct(ccPassCount) + '%' }" />
              <span class="cc-stack-fail" :style="{ width: ccPct(ccFailCount) + '%' }" />
              <span class="cc-stack-pending" :style="{ width: ccPct(ccPendingCount) + '%' }" />
            </div>
            <div class="cc-legend">
              <span class="cc-legend-item"><i class="is-pass" />{{ t('app.security.overview.cc.passed') }} {{ fmtStatNum(ccPassCount) }}</span>
              <span class="cc-legend-item"><i class="is-fail" />{{ t('app.security.overview.cc.failed') }} {{ fmtStatNum(ccFailCount) }}</span>
              <span class="cc-legend-item"><i class="is-pending" />{{ t('app.security.overview.cc.pending') }} {{ fmtStatNum(ccPendingCount) }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 自动封禁卡（独立整行）：状态 + 今日封禁/生效名单/监控 IP + 阈值口径摘要 +
         观察建议 Top5（dry-run 候选）；未生效黄条与事件页状态卡同源。 -->
    <el-card shadow="always" class="mb-5 autoban-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Lock /></el-icon>
            <span>{{ t('app.security.overview.autoban.title') }}</span>
            <el-tag :type="autobanStateTone" size="small" effect="light" disable-transitions>{{ autobanStateText }}</el-tag>
          </div>
          <el-button size="small" text type="primary" @click="goToAutobanConfig">{{ t('app.security.overview.autoban.config') }}</el-button>
        </div>
      </template>
      <el-alert v-if="autobanIneffective" type="warning" show-icon :closable="false" class="mb-3" :title="t('app.security.overview.autoban.ineffective')" />
      <el-alert v-if="autobanStatus?.enabled && autobanStatus?.feed_degraded" type="warning" show-icon :closable="false" class="mb-3" :title="autobanStatus?.feed_degraded_reason || t('app.security.overview.autoban.feedDegraded')" />
      <div class="autoban-body">
        <div class="autoban-stats">
          <div class="autoban-stat">
            <div class="autoban-stat-label">{{ t('app.security.overview.autoban.bannedToday') }}</div>
            <div class="autoban-stat-value is-ban">{{ autobanStatValue(autobanError, autobanStatus?.banned_today ?? 0) }}</div>
          </div>
          <div class="autoban-stat">
            <div class="autoban-stat-label">{{ t('app.security.overview.autoban.listEntries') }}</div>
            <div class="autoban-stat-value">{{ autobanStatValue(autobanError, autobanStatus?.list_entries ?? 0) }}</div>
          </div>
          <div class="autoban-stat">
            <div class="autoban-stat-label">{{ t('app.security.overview.autoban.trackedIps') }}</div>
            <div class="autoban-stat-value">{{ autobanStatValue(autobanError, autobanStatus?.tracked_ips ?? 0) }}</div>
          </div>
          <div class="autoban-config-summary">
            <div class="autoban-config-line">{{ t('app.security.overview.autoban.threshold') }}：{{ autobanStatValue(autobanError, autobanStatus?.threshold ?? 0) }} {{ t('app.security.overview.autoban.timesPer') }} {{ autobanStatValue(autobanError, autobanStatus?.window_minutes ?? 0) }} {{ t('app.security.overview.autoban.minutes') }}</div>
            <div class="autoban-config-line">{{ t('app.security.overview.autoban.duration') }}：{{ autobanStatValue(autobanError, autobanStatus?.duration ?? '—') }}</div>
            <div class="autoban-config-line">{{ t('app.security.overview.autoban.scope') }}：{{ autobanError ? '—' : autobanScopeText }}</div>
          </div>
        </div>
        <div class="autoban-suggestions">
          <div class="autoban-suggestions-title">{{ t('app.security.overview.autoban.suggestionsTitle') }}</div>
          <el-table v-if="autobanSuggestions.length > 0" :data="autobanSuggestions" size="small" :show-header="false">
            <el-table-column min-width="160">
              <template #default="{ row }"><IPLocationAction :ip="row.ip" :location="row.ip_location" /></template>
            </el-table-column>
            <el-table-column width="110" align="right">
              <template #default="{ row }"><el-tag :type="autobanSuggestionTone(row.count)" size="small" effect="light">{{ row.count }} {{ t('app.security.overview.autoban.times') }}</el-tag></template>
            </el-table-column>
          </el-table>
          <div v-else class="autoban-suggestions-empty">{{ t('app.security.overview.autoban.suggestionsEmpty') }}</div>
        </div>
      </div>
    </el-card>

    <el-card shadow="always">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Location /></el-icon>
            <span>{{ t('app.security.overview.topIps.title') }}</span>
          </div>
        </div>
      </template>
      <el-table :data="overview.top_ips" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty :description="t('app.security.overview.topIps.empty')" :image-size="60" /></template>
        <el-table-column :label="t('app.security.overview.topIps.colIp')" min-width="160">
          <template #default="{ row }">
            <IPLocationAction :ip="row.ip" :location="row.ip_location" />
          </template>
        </el-table-column>
        <el-table-column prop="blocked" :label="t('app.security.overview.status.blocked')" width="100" align="center">
          <template #default="{ row }"><el-tag type="danger" size="small" effect="plain">{{ row.blocked }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="detected" :label="t('app.security.overview.status.detected')" width="100" align="center">
          <template #default="{ row }"><el-tag type="warning" size="small" effect="plain">{{ row.detected }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="recent_10m" :label="t('app.security.overview.topIps.colRecent10m')" width="120" align="center">
          <template #default="{ row }"><span style="color:#059669;font-weight:600">{{ row.recent_10m }}</span> {{ t('app.security.overview.topIps.unitTimes') }}</template>
        </el-table-column>
        <el-table-column prop="recent_1h" :label="t('app.security.overview.topIps.colRecent1h')" width="128" align="center">
          <template #default="{ row }"><span style="color:#059669;font-weight:600">{{ row.recent_1h }}</span> {{ t('app.security.overview.topIps.unitTimes') }}</template>
        </el-table-column>
        <el-table-column prop="recent_24h" :label="t('app.security.overview.topIps.colRecent24h')" width="110" align="center">
          <template #default="{ row }"><span style="color:#059669;font-weight:600">{{ row.recent_24h }}</span> {{ t('app.security.overview.topIps.unitTimes') }}</template>
        </el-table-column>
        <el-table-column :label="t('app.security.overview.topIps.colAttackType')" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">
            <span>{{ topIpAttackLabel(row as TopIP) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="last_time" :label="t('app.security.overview.topIps.colLastAttack')" width="170" :formatter="(row: TopIP) => formatDate(row.last_time)" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, computed } from 'vue'
import { DataAnalysis, TrendCharts, PieChart, Location, Warning, Odometer, Monitor, InfoFilled, Stopwatch, Lock } from '@element-plus/icons-vue'
import { useI18n } from 'vue-i18n'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { formatDate } from '@/utils/date'
import { pageUrl } from '@/utils/deepLink'
import { libraryStatusLabel, libraryStatusTagType, summarizeLibrarySources, type LibrarySourceRow } from '@/utils/securityLibraries'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import VChart from 'vue-echarts'
import type { APIResponse } from '@/types'
import { securityActionColors } from '@/utils/chartTheme'
import { ingestionWarningMessage, type IngestionHealth } from '@/utils/ingestionHealth'
import { autobanStateLabel, autobanStatValue, isAutobanIneffective, suggestionBand } from '@/utils/autobanStatus'

const { t } = useI18n()


interface TrendPoint { date: string; blocked: number; detected: number }
interface TopIP { ip: string; ip_location: string; blocked: number; detected: number; recent_10m: number; recent_1h: number; recent_24h: number; last_time: string; attack_type: string; attack_type_stage?: string
}
interface AttackType { name: string; value: number }
interface Overview {
  today_blocked: number; today_detected: number; active_policies: number; crs_version: string
  crs_available?: boolean; ip2region_available?: boolean; update_status?: string
  trend: TrendPoint[]; top_ips: TopIP[]; attack_types: AttackType[]; attack_types_stage: AttackType[]
  raw_coverage_from?: string; backfill_incomplete?: boolean
  // 三 KPI 栏契约字段（昨日对比 + 正常请求，防御式消费：旧后端缺字段 → 对应行隐藏）
  yesterday_blocked?: number; yesterday_blocked_tcp?: number
  yesterday_detected?: number; yesterday_detected_tcp?: number
  normal_today?: number; normal_today_http?: number; normal_today_tcp?: number
  normal_yesterday?: number; normal_yesterday_http?: number; normal_yesterday_tcp?: number
  today_challenged?: number; today_human_fail?: number
  // 今日拦截的 TCP（L4 断连）份额：旧后端缺失 → 协议拆分行整行隐藏（防御式）。
  // 原始表直算（不走 rollup——rollup 无 event_type 维度），极端量级下行帽裁剪可能少计。
  today_blocked_tcp?: number
  // 今日检测的 TCP（L4 信任检测 logged）份额：语义同 today_blocked_tcp（防御旧后端）。
  today_detected_tcp?: number
  // includes_reserved：后端口径披露——true=今日计数回退原始表直算（含私网/保留
  // 地址事件）；false=走分钟 rollup 与大屏同口径（不含私网）。tooltip 按此切换文案
  includes_reserved?: boolean
  // ingestion：与事件列表同源的采集健康位（见 utils/ingestionHealth）
  ingestion?: IngestionHealth
}
interface SecurityEvent { id: number; event_time: string; client_ip: string; rule_caddy_id: string; rule_name: string; policy_name: string; ip_location?: string; event_type?: string }
interface ChallengeEvent { id: string; kind: 'slider' | 'js'; status: 'waiting' | 'passed' | 'failed' | 'expired'; last_result: '' | 'pass' | 'fail'; rule_id: string; rule_name: string; policy_name: string; client_ip: string; method: string; uri: string; user_agent: string; issued_at_ms: number; expires_at_ms: number; remaining_ms: number; attempts: number; max_attempts: number }

const attackByStage = ref(true)

// Top 10 攻击类型列与分布图「按阶段展示」勾选联动（微调）：勾选时把
// 具体 family（joinDistinctFamilies 产物）映射到阶段五桶去重展示，取消勾选
// 恢复具体分类文本——与分布图同口径（后端 stageCategorizeAttack 的 family 版）。
// 阶段视图直接消费后端 attack_type_stage(后端 stageCategorizeAttack
// 单源产出)——原前端 familyToStage 硬编码映射已删,后端新增 family 不再静默落「其他」
const topIpAttackLabel = (row: TopIP): string => {
  if (!attackByStage.value) return row.attack_type || '—'
  return row.attack_type_stage || '—'
}
const overview = ref<Overview>({ today_blocked: 0, today_detected: 0, active_policies: 0, crs_version: '', trend: [], top_ips: [], attack_types: [], attack_types_stage: [], raw_coverage_from: '', backfill_incomplete: false })

// 分布图展示模式：勾选=按阶段五桶（默认，与触发阶段口径一致）；取消=具体分类
// 总览加载失败（如 metrics 库故障导致后端 500）时置位：避免把全零面板
// 误当「无攻击」，用户目标与 后端显式报错对齐。
const overviewError = ref(false)
const ingestionWarning = computed(() => ingestionWarningMessage(overview.value.ingestion))
// 今日拦截协议拆分：TCP 份额缺失（旧后端）/为 0 时 null → 整行隐藏；
// 统计数值千分位（7 位数在 20px 卡内不破版式）
const fmtStatNum = (n: number | undefined): string => (typeof n === 'number' ? n.toLocaleString('en-US') : '—')

// today_blocked 是全协议合计，HTTP = 合计 − TCP（负值钳 0，防 rollup 滞后瞬间为负）
const todayBlockedSplit = computed<{ http: number; tcp: number } | null>(() => {
  const tcp = overview.value.today_blocked_tcp
  // 字段存在即显示（TCP=0 也显示，与检测/正常请求列 lockstep）；缺失=旧后端隐藏
  if (typeof tcp !== 'number' || !Number.isFinite(tcp)) return null
  return { http: Math.max(0, overview.value.today_blocked - tcp), tcp }
})

// today_detected 是全协议合计（含 TCP 信任检测 logged），HTTP = 合计 − TCP
//（负值钳 0）；字段存在即显示（TCP=0 也显示——可能产生数据就如实显示），
// 缺失=旧后端隐藏
const todayDetectedSplit = computed<{ http: number; tcp: number } | null>(() => {
  const tcp = overview.value.today_detected_tcp
  if (typeof tcp !== 'number' || !Number.isFinite(tcp)) return null
  return { http: Math.max(0, overview.value.today_detected - tcp), tcp }
})

// 昨日对比行共用门（三列 lockstep）：数值字段缺失/非有限数 → null（行隐藏，防御旧后端）
const statOrNull = (v: number | undefined): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null
const yesterdayBlocked = computed(() => statOrNull(overview.value.yesterday_blocked))
const yesterdayDetected = computed(() => statOrNull(overview.value.yesterday_detected))
const normalYesterday = computed(() => statOrNull(overview.value.normal_yesterday))

// 正常请求协议拆分：HTTP/TCP 两字段齐备才显示（字段缺失整行隐藏，防御旧后端）
const normalTodaySplit = computed<{ http: number; tcp: number } | null>(() => {
  const http = overview.value.normal_today_http
  const tcp = overview.value.normal_today_tcp
  if (typeof http !== 'number' || !Number.isFinite(http)) return null
  if (typeof tcp !== 'number' || !Number.isFinite(tcp)) return null
  return { http, tcp }
})
const todayCountTip = computed(() => overview.value.includes_reserved
  ? t('app.security.overview.status.tipReserved') + t('app.security.overview.status.tipCrawlerNote')
  : t('app.security.overview.status.tipRollup') + t('app.security.overview.status.tipCrawlerNote'))
const trendChartOption = computed(() => {
  const dates = overview.value.trend.map((row) => row.date)
  const blocked = overview.value.trend.map((row) => row.blocked)
  const detected = overview.value.trend.map((row) => row.detected)
  return {
    tooltip: { trigger: 'axis' },
    legend: { data: [t('app.security.overview.status.blocked'), t('app.security.overview.status.detected')], top: 0, itemGap: 24 },
    grid: { left: 40, right: 20, top: 36, bottom: 30, containLabel: false },
    xAxis: { type: 'category', data: dates },
    yAxis: { type: 'value' },
    series: [
      { name: t('app.security.overview.status.blocked'), type: 'bar', data: blocked, itemStyle: { color: securityActionColors.blocked }, stack: 'total' },
      { name: t('app.security.overview.status.detected'), type: 'bar', data: detected, itemStyle: { color: securityActionColors.detected }, stack: 'total' },
    ],
  }
})

const attackChartOption = computed(() => ({
  tooltip: { trigger: 'item' },
  legend: { bottom: 0, type: 'scroll' },
  series: [{
    type: 'pie', radius: ['40%', '65%'], center: ['50%', '42%'],
    data: (attackByStage.value ? overview.value.attack_types_stage : overview.value.attack_types).map(a => ({ name: a.name, value: a.value })),
    itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
    label: { show: true, formatter: '{b}: {c}' },
  }],
}))

// 人机验证统计（lb_human admin 端点；端点缺失=旧二进制，全零不报错）
const humanStats = ref({ challenges: 0, passes: 0, fails: 0 })

// 实时挑战运行态（CC 卡入口）：数据源为 lbhuman 内存会话注册表，
// active=仍在 TTL 内等待验证；recent=最近通过/失败/过期。不是事件日志回放。
const challengeLiveVisible = ref(false)
const challengeLiveScope = ref<'active' | 'recent'>('active')
const challengeEvents = ref<ChallengeEvent[]>([])
const challengeLiveActiveCount = ref(0)
const challengeLiveLoading = ref(false)
const challengeLiveError = ref(false)
const challengeLiveUpdated = ref('')
const challengeAutoRefresh = ref(true)
let challengeLiveTimer: ReturnType<typeof setInterval> | undefined

const challengeStatusTone = (row: ChallengeEvent): 'primary' | 'success' | 'danger' | 'info' => {
  if (row.status === 'passed') return 'success'
  if (row.status === 'failed') return 'danger'
  if (row.status === 'expired') return 'info'
  return 'primary'
}
const challengeStatusText = (row: ChallengeEvent): string => {
  if (row.status === 'passed') return t('app.security.overview.cc.liveStatusPassed')
  if (row.status === 'failed') return t('app.security.overview.cc.liveStatusFailed')
  if (row.status === 'expired') return t('app.security.overview.cc.liveStatusExpired')
  return t('app.security.overview.cc.liveStatusWaiting')
}
const challengeKindText = (row: ChallengeEvent): string => row.kind === 'slider'
  ? t('app.security.overview.cc.liveKindSlider')
  : t('app.security.overview.cc.liveKindJS')
const formatLiveRemaining = (ms: number): string => {
  const total = Math.max(0, Math.ceil(ms / 1000))
  const minutes = Math.floor(total / 60)
  const seconds = total % 60
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
}
const formatLiveClock = (ms: number): string => ms > 0 ? new Date(ms).toLocaleTimeString() : '—'
const formatLiveAttempts = (row: ChallengeEvent): string => row.max_attempts > 1
  ? `${row.attempts}/${row.max_attempts}`
  : String(row.attempts)
const fetchChallengeLive = async (): Promise<void> => {
  if (challengeLiveLoading.value) return
  challengeLiveLoading.value = true
  try {
    const res = await request.get<APIResponse<{ now_ms: number; active_count: number; sessions: ChallengeEvent[] }>>('/security/human/live', {
      params: { scope: challengeLiveScope.value },
      silent: true,
    })
    challengeEvents.value = res.data?.sessions || []
    challengeLiveActiveCount.value = res.data?.active_count || 0
    challengeLiveUpdated.value = new Date().toLocaleTimeString()
    challengeLiveError.value = false
  } catch {
    challengeLiveError.value = true
  } finally {
    challengeLiveLoading.value = false
  }
}
const stopChallengeTimer = () => {
  if (challengeLiveTimer !== undefined) {
    clearInterval(challengeLiveTimer)
    challengeLiveTimer = undefined
  }
}
const syncChallengeTimer = () => {
  stopChallengeTimer()
  if (challengeLiveVisible.value && challengeAutoRefresh.value) {
    challengeLiveTimer = setInterval(() => { void fetchChallengeLive() }, 2000)
  }
}
const openChallengeLive = () => {
  challengeLiveVisible.value = true
  void fetchChallengeLive()
  syncChallengeTimer()
}
const onChallengeVisibleChange = (visible: boolean) => {
  challengeLiveVisible.value = visible
  if (visible) void fetchChallengeLive()
  syncChallengeTimer()
}

// 通过率口径（2026-11-13 用户裁定）：挑战成功（human_pass）不再计入安全事件，
// 通过/失败计数以 admin 端点（humanStats，进程累计）为权威源；事件表仅承载
// 发放/失败。零样本显性 —。
const humanPassRate = computed(() => {
  const passes = humanStats.value.passes
  const fails = humanStats.value.fails
  const total = passes + fails
  return total > 0 ? `${Math.round((passes / total) * 100)}%` : '—'
})

const ccPassCount = computed(() => humanStats.value.passes)
const ccFailCount = computed(() => humanStats.value.fails)
// 未完成 = 累计发放 − 通过 − 失败（同源 humanStats，禁止与今日发放跨口径相减：
// 今日/累计混算会产出负值钳零的假「未完成」）。
const ccPendingCount = computed(() => Math.max(humanStats.value.challenges - ccPassCount.value - ccFailCount.value, 0))
const ccTotalCount = computed(() => ccPassCount.value + ccFailCount.value + ccPendingCount.value)
const ccPassRatePct = computed<number | null>(() => {
  const total = ccPassCount.value + ccFailCount.value
  return total > 0 ? Math.round((ccPassCount.value / total) * 1000) / 10 : null
})
const ccPct = (n: number): number => {
  const total = ccTotalCount.value
  return total > 0 ? (n / total) * 100 : 0
}
const fetchHumanStats = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<{ challenges: number; passes: number; fails: number }>>('/security/human/stats', { silent: true })
    if (res.data) humanStats.value = res.data
  } catch { /* 静默：总览卡不阻塞 */ }
}

const fetchData = async () => {
  void fetchHumanStats()
  try {
    const res = await request.get<APIResponse<Overview>>('/security/overview')
    if (res.data) {
      overview.value = res.data
      overviewError.value = false
    }
  } catch {
    // 后端 500（如 metrics 库故障）不再静默吞掉：置错误状态展示提示条，
    // 全零面板不再冒充「无攻击」。
    overviewError.value = true
  }
}

const blockedEvents = ref<SecurityEvent[]>([])
// 面板级错误态：请求失败时面板内显示「加载失败」，不再静默降级为「暂无」，
// 与 overviewError 的口径一致。
const blockedEventsError = ref(false)

const fetchBlockedEvents = async () => {
  try {
    const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number }>>('/security/events?action=blocked&page_size=5')
    blockedEvents.value = res.data?.events || []
    blockedEventsError.value = false
  } catch {
    blockedEvents.value = []
    blockedEventsError.value = true
  }
}

const goToEvents = () => { window.open(pageUrl('security-events'), '_blank', 'noopener') }

// 自动封禁卡（独立整行）：数据源 /security/autoban/status，与事件页状态卡同源。
// 摘要统计 + 观察建议 Top5（dry-run 候选）；未生效黄条复用 isAutobanIneffective 单源。
interface AutobanSuggestion { ip: string; count: number; ip_location?: string; window_start?: string; last_seen?: string }
interface AutobanStatus {
  enabled: boolean; dry_run: boolean; threshold: number; window_minutes: number
  duration: string; scope: string; banned_today: number; list_entries: number
  ban_effective: boolean; tracked_ips: number; suggestions: AutobanSuggestion[]
  is_master: boolean; feed_degraded: boolean; feed_degraded_reason: string
}
const autobanStatus = ref<AutobanStatus | null>(null)
const autobanError = ref(false)
const fetchAutobanStatus = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<AutobanStatus>>('/security/autoban/status', { silent: true })
    if (res.data) {
      autobanStatus.value = res.data
      autobanError.value = false
    }
  } catch {
    autobanError.value = true
  }
}
const autobanStateText = computed(() => autobanStateLabel(autobanError.value, autobanStatus.value?.enabled ?? false, autobanStatus.value?.dry_run ?? false))
const autobanStateTone = computed<'success' | 'warning' | 'info' | 'danger'>(() => {
  if (autobanError.value) return 'danger'
  if (!autobanStatus.value?.enabled) return 'info'
  return autobanStatus.value.dry_run ? 'warning' : 'success'
})
const autobanIneffective = computed(() => autobanStatus.value !== null && isAutobanIneffective(autobanStatus.value))
const autobanScopeText = computed(() => {
  const labels: Record<string, string> = {
    blocked: t('app.security.overview.autoban.scopeBlocked'),
    logged: t('app.security.overview.autoban.scopeLogged'),
    challenge_issued: t('app.security.overview.autoban.scopeChallengeIssued'),
    challenge_failed: t('app.security.overview.autoban.scopeChallengeFailed'),
  }
  const parts = (autobanStatus.value?.scope || '').split(',').map(s => s.trim()).filter(s => labels[s])
  return parts.length > 0 ? parts.map(s => labels[s]).join(' + ') : '—'
})
const autobanSuggestions = computed(() => (autobanStatus.value?.suggestions || []).slice(0, 5))
const autobanSuggestionTone = (count: number): 'danger' | 'warning' | 'info' => {
  const band = suggestionBand(count, autobanStatus.value?.threshold ?? 1)
  return band === 'high' ? 'danger' : band === 'mid' ? 'warning' : 'info'
}
const goToAutobanConfig = () => { window.open(pageUrl('security-events'), '_blank', 'noopener') }

const ip2regionVersion = ref('—')
const ip2regionStatus = ref('')
const ip2regionError = ref(false)


const fetchIP2RegionInfo = async () => {
  try {
    const res = await request.get<APIResponse<{ version: string; update_status: string }>>('/security/ip2region')
    ip2regionVersion.value = res.data?.version || '—'
    ip2regionStatus.value = res.data?.update_status || ''
    ip2regionError.value = false
  } catch {
    ip2regionVersion.value = '—'
    ip2regionStatus.value = ''
    ip2regionError.value = true
  }
}

// 威胁情报库 stat（v2.3.x）：最近版本（各源 version 最大者）+ 运行状态。
// total_entries 未展示（「合并生效条数」口径需后端去重统计，当前仅版本可呈现）。
const threatLatestVersion = ref('')
const threatError = ref(false)
// 状态由单一聚合源产出（utils/securityLibraries.summarizeLibrarySources）——
// 与「规则集」页同口径；空源/无版本为 never（未更新），不再返回 '' 静默无标签。
const threatStatus = ref('')
const fetchThreatLib = async () => {
  try {
    const res = await request.get<APIResponse<{ sources: LibrarySourceRow[]; total_entries?: number }>>('/security/threat-lib')
    const summary = summarizeLibrarySources(res.data?.sources || [], formatDate)
    threatLatestVersion.value = summary.latestVersion
    threatStatus.value = summary.status
    threatError.value = false
  } catch {
    threatError.value = true
  }
}

// 爬虫地址库 stat：与威胁情报库同口径，但读独立端点/独立任务状态。
const crawlerLatestVersion = ref('')
const crawlerError = ref(false)
const crawlerStatus = ref('')
const fetchCrawlerLib = async () => {
  try {
    const res = await request.get<APIResponse<{ sources: LibrarySourceRow[]; total_entries?: number }>>('/security/crawler-lib')
    const summary = summarizeLibrarySources(res.data?.sources || [], formatDate)
    crawlerLatestVersion.value = summary.latestVersion
    crawlerStatus.value = summary.status
    crawlerError.value = false
  } catch {
    crawlerError.value = true
  }
}

const authStore = useAuthStore()
// 威胁大屏入口：全屏页面（App.vue 独立分支渲染，页内 ESC/按钮退出）
const openThreatScreen = (): void => {
  authStore.setCurrentPage('threat-screen')
}

// 六路数据一次拉齐；失败后页面此前只提供整页刷新这一个恢复入口（瞬态 5xx 后
// 面板长期不可用）。横幅的「立即重试」走同一路径，reloading 兼作并发门——
// 连续点击不会叠发六组请求。
const reloading = ref(false)
const reloadAll = async (): Promise<void> => {
  if (reloading.value) return
  reloading.value = true
  try {
    await Promise.all([
      fetchData(),
      fetchBlockedEvents(),
      fetchAutobanStatus(),
      fetchIP2RegionInfo(),
      fetchThreatLib(),
      fetchCrawlerLib(),
    ])
  } finally {
    reloading.value = false
  }
}

onBeforeUnmount(stopChallengeTimer)
onMounted(() => { void reloadAll() })
</script>

<style scoped>
/* 统一卡体系：全页 el-card 一律直角细边、无投影、卡头 14px/600、body 18×24。
 * 状态条与图表/事件/Top10 卡共用同一容器观感（用户裁定彻底重设计）。 */
.overview-card.el-card,
.el-card { --el-card-border-color: #ebeef5; --el-card-border-radius: 0; }
.status-strip-card.el-card { border: 1px solid #ebeef5; }
.card-header { display: flex; align-items: center; justify-content: space-between; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
/* 等宽统计卡行:flex 五列严格等宽(原 el-col 5/5/5/5/4 末卡窄 20%) */
.overview-card { height: 100%; }
/* 左右分区：左=防护三 KPI（横排大数值，竖分隔线），右=规则库竖清单。
 * 两种信息各自形态，不再互相挤压。 */
.status-strip { display: flex; align-items: stretch; }
.status-guard { flex: 1 1 auto; display: flex; align-items: stretch; min-width: 0; }
.guard-item {
  flex: 1 1 0;
  min-width: 0;
  padding: 2px 28px 0;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
}
.guard-item:first-child { padding-left: 0; }
.strip-divider { width: 1px; background: #f0f0f0; margin: 0 32px; flex-shrink: 0; }
.strip-label { font-size: 13px; font-weight: 600; color: var(--text-secondary); display: flex; align-items: center; }
.strip-value {
  font-size: 24px;
  font-weight: 800;
  line-height: 1.25;
  margin-top: 6px;
  letter-spacing: 0.3px;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  color: #303133;
}
.strip-value.is-danger { color: #f56c6c; }
.strip-value.is-warning { color: #e6a23c; }
.strip-value.is-info { color: #409eff; }
.strip-sub { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-secondary); white-space: nowrap; font-variant-numeric: tabular-nums; }
.strip-sub .proto-split-item--tcp { margin-left: 10px; }
.strip-sub-num { color: var(--text-secondary); }
.strip-sub:first-of-type { margin-top: 2px; }
.strip-sub + .strip-sub { margin-top: 4px; }
.proto-split-label { font-weight: 700; }
/* 「昨日」文案加粗（用户裁定）：数值保持常规粗细，仅标签词加重提升对比 */
.strip-sub-label { font-weight: 700; }
.proto-split-item { display: inline-flex; align-items: center; gap: 4px; }
.proto-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 5px; }
.proto-dot--http { background: #409eff; }
.proto-dot--tcp { background: #0e7490; }
.status-lib { flex: 0 0 430px; border-left: 1px solid #f0f0f0; padding-left: 32px; display: flex; flex-direction: column; justify-content: center; gap: 10px; }
.lib-row { display: flex; align-items: center; gap: 8px; font-size: 13px; min-width: 0; }
.status-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.status-dot.is-up { background: #67c23a; }
.status-dot.is-down { background: #f56c6c; }
.lib-name { color: var(--text-secondary); flex-shrink: 0; }
.lib-ver { font-weight: 600; color: #303133; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-variant-numeric: tabular-nums; }
.lib-row .el-tag { margin-left: auto; flex-shrink: 0; }
@media (max-width: 1500px) {
  .guard-item { padding: 4px 20px 0; }
  .strip-divider { margin: 0 20px; }
  .strip-value { font-size: 22px; }
  .status-lib { flex-basis: 360px; padding-left: 20px; }
}
@media (max-width: 1400px) {
  .status-strip { flex-direction: column; gap: 20px; }
  .status-lib { border-left: none; padding-left: 0; flex-basis: auto; }
}

.chart-container { height: 260px; }
/* 趋势与攻击类型分布同行：两卡 height:100% 拉伸等高（el-col flex 拉伸）。 */
.charts-row .el-card { height: 100%; }
/* 卡头「按阶段展示」checkbox 行内紧凑：高度钉到卡头标题行，不撑高卡头
   （同行等高后，卡头高度差会把两卡内容区顶得参差）。 */
.header-checkbox { height: 20px; margin-left: 12px; }
.events-row .el-card { height: 100%; }
.cc-card { display: flex; flex-direction: column; }
.cc-card :deep(.el-card__body) { flex: 1; display: flex; flex-direction: column; }
.cc-live-button { padding: 0; }
.challenge-live-tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.challenge-live-updated { font-size: 12px; color: var(--text-secondary); }
.challenge-live-auto-label { font-size: 12px; color: var(--text-secondary); }
.challenge-live-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.challenge-live-counter { display: inline-flex; align-items: baseline; gap: 8px; padding: 6px 12px; border-radius: 6px; background: #f5f7fa; color: var(--text-secondary); font-size: 12px; }
.challenge-live-counter strong { font-size: 20px; line-height: 1; font-variant-numeric: tabular-nums; color: #606266; }
.challenge-live-counter.is-active strong { color: #409eff; }
.challenge-live-countdown { display: flex; flex-direction: column; line-height: 1.25; font-variant-numeric: tabular-nums; }
.challenge-live-countdown strong { color: #409eff; font-weight: 700; }
.challenge-live-countdown span { font-size: 11px; color: var(--text-secondary); }
.challenge-live-status { display: flex; flex-direction: column; align-items: center; gap: 3px; }
.challenge-live-attempts { font-size: 11px; color: var(--text-secondary); font-variant-numeric: tabular-nums; }
.challenge-live-muted { color: var(--text-secondary); }
.challenge-live-attribution { display: flex; flex-direction: column; line-height: 1.3; }
.challenge-live-attribution span:last-child { font-size: 11px; color: var(--text-secondary); }
.challenge-live-method { display: inline-block; min-width: 38px; font-weight: 600; color: var(--text-secondary); }
.challenge-live-footer { margin-top: 8px; text-align: right; font-size: 12px; color: var(--text-secondary); }
.cc-hero { flex: 1; display: flex; flex-direction: row; align-items: center; justify-content: center; gap: 24px; padding: 4px 4px 6px; }
.cc-donut { position: relative; width: 136px; height: 136px; flex: none; }
.cc-donut svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.cc-donut-track { fill: none; stroke: #eef2f7; stroke-width: 3.4; }
.cc-donut-value { fill: none; stroke: #67c23a; stroke-width: 3.4; stroke-linecap: round; transition: stroke-dasharray .4s ease; }
.cc-donut-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1px; color: #303133; }
.cc-rate-value { font-size: 22px; font-weight: 700; line-height: 1; }
.cc-rate-label { font-size: 10px; color: var(--text-secondary); line-height: 1.4; }
.cc-meta { display: flex; flex-direction: column; gap: 10px; min-width: 0; flex: 1; }
.cc-meta-row { display: flex; align-items: baseline; justify-content: space-between; gap: 14px; padding: 9px 12px; border-radius: 8px; background: #f7f9fc; }
.cc-meta-label { font-size: 12px; color: var(--text-secondary); white-space: nowrap; }
.cc-meta-value { font-size: 22px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.cc-meta-value.is-primary { color: #409eff; }
.cc-meta-value.is-pass { color: #67c23a; }
.cc-meta-value.is-fail { color: #f56c6c; }
.cc-dist { margin-top: 8px; }
.cc-dist-head { display: flex; align-items: baseline; justify-content: space-between; padding: 0 4px 6px; font-size: 12px; color: var(--text-secondary); }
.cc-dist-head > span:first-child { font-weight: 600; color: #303133; }
.cc-stack { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: #eef2f7; margin: 0 4px 8px; }
.cc-stack span { display: block; height: 100%; transition: width .4s ease; }
.cc-stack-pass { background: #67c23a; }
.cc-stack-fail { background: #f56c6c; }
.cc-stack-pending { background: #cbd5e1; }
.cc-legend { display: flex; flex-wrap: wrap; gap: 10px 14px; padding: 0 4px; font-size: 12px; color: var(--text-secondary); }
.cc-legend-item { display: inline-flex; align-items: center; gap: 5px; }
.cc-legend-item i { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.cc-legend-item i.is-pass { background: #67c23a; }
.cc-legend-item i.is-fail { background: #f56c6c; }
.cc-legend-item i.is-pending { background: #cbd5e1; }
/* 自动封禁卡：左侧统计+配置摘要，右侧观察建议 Top5；窄屏堆叠。 */
.autoban-body { display: flex; gap: 24px; align-items: stretch; }
.autoban-stats { flex: 1; min-width: 0; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
.autoban-stat { display: flex; flex-direction: column; gap: 4px; padding: 10px 16px; border-radius: 8px; background: #f7f9fc; min-width: 110px; }
.autoban-stat-label { font-size: 12px; color: var(--text-secondary); }
.autoban-stat-value { font-size: 24px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; color: #303133; }
.autoban-stat-value.is-ban { color: #f56c6c; }
.autoban-config-summary { display: flex; flex-direction: column; gap: 4px; padding: 4px 8px; font-size: 12px; color: var(--text-secondary); }
.autoban-config-line { white-space: nowrap; }
.autoban-suggestions { flex: 1; min-width: 280px; border-left: 1px solid var(--el-border-color-lighter); padding-left: 20px; }
.autoban-suggestions-title { font-size: 13px; font-weight: 600; color: #303133; margin-bottom: 8px; }
.autoban-suggestions-empty { font-size: 12px; color: var(--text-secondary); padding: 12px 0; }
@media (max-width: 992px) {
  .autoban-body { flex-direction: column; }
  .autoban-suggestions { border-left: none; padding-left: 0; border-top: 1px solid var(--el-border-color-lighter); padding-top: 12px; }
}
</style>
