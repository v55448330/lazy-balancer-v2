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
            <!-- 协议拆分（L4 阶段 0/1 披露，今日口径）：HTTP = today_blocked（含 TCP 的合计）− TCP；
                 字段存在即显示（TCP=0 也显示——可能产生数据就如实呈现），缺失=旧后端整行隐藏 -->
            <div v-if="todayBlockedSplit" class="strip-sub">
              <span class="proto-split-item"><i class="proto-dot proto-dot--http"></i><span class="proto-split-label">HTTP</span><span class="strip-sub-num">{{ fmtStatNum(todayBlockedSplit.http) }}</span></span><span class="proto-split-item proto-split-item--tcp"><i class="proto-dot proto-dot--tcp"></i><span class="proto-split-label">TCP</span><span class="strip-sub-num">{{ fmtStatNum(todayBlockedSplit.tcp) }}</span></span>
            </div>
          </div>
          <div class="strip-divider"></div>
          <div class="guard-item">
            <div class="strip-label">{{ t('app.security.overview.status.detected') }}</div>
            <div class="strip-value is-warning">{{ fmtStatNum(overview.today_detected) }}</div>
            <div v-if="yesterdayDetected !== null" class="strip-sub"><span class="strip-sub-label">{{ t('app.security.overview.status.yesterday') }}</span> {{ fmtStatNum(yesterdayDetected) }}</div>
            <!-- 协议拆分：TCP 检测来自信任检测（trust_detect）logged 事件——可能产生数据就如实显示；
                 字段缺失（旧后端）整行隐藏。HTTP 份额 = today_detected 自身（攻击口径不含 trust，
                 不得按 合计−TCP 推导，后端契约已明示） -->
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
      <el-alert v-if="challengeLiveError" type="error" show-icon :closable="false" class="challenge-live-alert" :title="t('app.security.overview.events.loadFailed')" />
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
            <!-- 已通过：显示放行剩余（cookie 真实到期，策略通过有效期），
                 不是挑战材料 TTL；到期后按已失效呈现。 -->
            <div v-else-if="(row as ChallengeEvent).status === 'passed' && (row as ChallengeEvent).pass_expires_at_ms > 0" class="challenge-live-countdown is-pass">
              <strong>{{ (row as ChallengeEvent).pass_remaining_ms > 0 ? formatLiveRemaining((row as ChallengeEvent).pass_remaining_ms) : t('app.security.overview.cc.livePassExpired') }}</strong>
              <span>{{ t('app.security.overview.cc.livePassExpiresAt', { time: formatLiveClock((row as ChallengeEvent).pass_expires_at_ms) }) }}</span>
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
              <!-- 卡片头部动作按钮统一风格（与仪表盘「连接监控」同款）：
                   size=small + type=primary + plain + 语义图标。 -->
              <el-button size="small" type="primary" plain :icon="Tickets" @click="goToEvents">{{ t('app.security.overview.events.viewAll') }}</el-button>
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
                <el-tag v-if="row.event_type === 'tcp'" size="small" effect="light" class="proto-tcp-tag">TCP</el-tag>
                <el-tag v-else size="small" effect="light" type="primary">HTTP</el-tag>
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
              <el-button size="small" type="primary" plain :icon="Monitor" @click="openChallengeLive">{{ t('app.security.overview.cc.liveButton') }}</el-button>
            </div>
          </template>
          <div class="cc-hero">
            <div class="cc-donut" role="img" :aria-label="t('app.security.overview.cc.passRate')">
              <svg viewBox="0 0 42 42" aria-hidden="true">
                <circle class="cc-donut-track" cx="21" cy="21" r="15.915" />
                <!-- 通过段（绿）+ 失败段（红）：与下方分布条/图例同色同口径。
                     只画通过会让环上缺口被读成「未知」；直角口径用 butt 描边。 -->
                <circle v-if="ccPassRatePct && ccPassRatePct > 0" class="cc-donut-value" cx="21" cy="21" r="15.915" :stroke-dasharray="`${ccPassRatePct} 100`" />
                <circle v-if="ccFailRatePct && ccFailRatePct > 0" class="cc-donut-fail" cx="21" cy="21" r="15.915" :stroke-dasharray="`${ccFailRatePct} 100`" :stroke-dashoffset="-(ccPassRatePct ?? 0)" />
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
          <!-- 丢失对账（lbhuman/events.go 三计数，进程累计）：合计 >0 才披露，
               三分类逐项可对账；零丢失不打扰。 -->
          <div v-if="humanEventsLost > 0" class="info-note-bar"><span class="info-note-desc">{{ t('app.security.overview.cc.eventsLost', { total: humanEventsLost, dropped: humanStats.events_dropped, failed: humanStats.events_deliver_failed, shutdown: humanStats.events_shutdown_lost }) }}</span></div>
          <!-- CC 触发原因分布（cc_triggers，进程累计）：与自动封禁归因词同语义。 -->
          <div class="cc-triggers">
            <div class="cc-dist-head"><span>{{ t('app.security.overview.cc.triggerTitle') }}</span></div>
            <div class="cc-legend">
              <span class="cc-legend-item">{{ t('app.security.overview.cc.triggerRps') }} {{ fmtStatNum(humanStats.cc_triggers.rps_spike) }}</span>
              <span class="cc-legend-item">{{ t('app.security.overview.cc.trigger4xx') }} {{ fmtStatNum(humanStats.cc_triggers['4xx_ratio']) }}</span>
              <span class="cc-legend-item">{{ t('app.security.overview.cc.triggerSession') }} {{ fmtStatNum(humanStats.cc_triggers.session_anomaly) }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 自动封禁卡（独立整行）：系统内置「自动封禁名单」IP 口径——
         四统计卡一行（今日封禁/生效条目/监控身份/累犯升级，累犯可点击下钻）
         + 配置摘要；观察建议 Top5 自适应剩余宽度（IP/命中次数/累犯档）。 -->
    <el-card shadow="always" class="mb-5 autoban-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon class="title-icon"><Lock /></el-icon>
            <span>{{ t('app.security.overview.autoban.title') }}</span>
            <el-tag :type="autobanStateTone" size="small" effect="light" disable-transitions>{{ autobanStateText }}</el-tag>
          </div>
        </div>
      </template>
      <!-- 未生效黄条：判据单源 utils/autobanStatus（enabled ∧ ban_effective===false，
           IP 名单通道：名单为空或未被启用中的 deny 策略引用）。binding 环节且后端给出
           可定位的策略 id 时追加入口「前往绑定规则」（事件页同写法，深链到该策略）；
           文案按就绪策略的实际绑定数区分「尚未关联」与「已关联但规则不转发」。 -->
      <el-alert v-if="autobanIneffective" type="warning" show-icon :closable="false" class="autoban-alert">
        <template #title>{{ autobanIneffectiveText }} <AccessibleLink v-if="autobanBindingPolicyId !== null" type="primary" @click="goToBindingPolicy">{{ t('app.security.events.goToBindingRules') }}</AccessibleLink></template>
      </el-alert>
      <el-alert v-if="autobanStatus?.enabled && autobanStatus?.feed_degraded" type="warning" show-icon :closable="false" class="autoban-alert" :title="autobanStatus?.feed_degraded_reason || t('app.security.overview.autoban.feedDegraded')" />
      <div class="autoban-body">
        <div class="autoban-stats">
          <div class="autoban-stat">
            <el-tooltip :content="t('app.security.overview.autoban.bannedTodayTip')" placement="top">
              <div class="autoban-stat-label">{{ t('app.security.overview.autoban.bannedToday') }}</div>
            </el-tooltip>
            <div class="autoban-stat-value is-ban">{{ autobanStatValue(autobanError, autobanStatus?.banned_today ?? 0) }}</div>
          </div>
          <div class="autoban-stat">
            <el-tooltip :content="t('app.security.overview.autoban.listEntriesTip')" placement="top">
              <div class="autoban-stat-label">{{ t('app.security.overview.autoban.listEntries') }}</div>
            </el-tooltip>
            <div class="autoban-stat-value">{{ autobanStatValue(autobanError, autobanStatus?.list_entries ?? 0) }}</div>
          </div>
          <div class="autoban-stat">
            <el-tooltip :content="t('app.security.overview.autoban.trackedIpsTip')" placement="top">
              <div class="autoban-stat-label">{{ t('app.security.overview.autoban.trackedIps') }}</div>
            </el-tooltip>
            <div class="autoban-stat-value">{{ autobanStatValue(autobanError, autobanStatus?.tracked_ips ?? 0) }}</div>
          </div>
          <div class="autoban-stat">
            <el-tooltip :content="t('app.security.overview.autoban.escalatedCountTip')" placement="top">
              <div class="autoban-stat-label">{{ t('app.security.overview.autoban.escalatedCount') }}</div>
            </el-tooltip>
            <!-- 累犯升级可点击下钻：共享弹框查看逐身份累犯历史（计数/上次封禁/
                 下次封禁预期），并可重置全部历史（二次确认）；加载中/加载失败态
                 禁用（与事件页封禁控制台入口同口径，数值为「—」不可下钻） -->
            <el-button link type="primary" class="autoban-stat-link" :disabled="autobanStatus === null || autobanError" @click="recidivismDialogVisible = true">
              <span class="autoban-stat-value">{{ autobanStatValue(autobanError, autobanStatus?.escalated_count ?? 0) }}</span>
            </el-button>
          </div>
          <div class="autoban-config-summary">
            <div class="autoban-config-line">{{ t('app.security.overview.autoban.threshold') }}：{{ autobanStatValue(autobanError, autobanStatus?.threshold ?? 0) }} {{ t('app.security.overview.autoban.timesPer') }} {{ autobanStatValue(autobanError, autobanStatus?.window_minutes ?? 0) }} {{ t('app.security.overview.autoban.minutes') }}</div>
            <div class="autoban-config-line">{{ t(autobanStatusEscalationOn ? 'app.security.events.firstBanDuration' : 'app.security.overview.autoban.duration') }}：{{ autobanError ? '—' : autobanDurationText }}</div>
            <div class="autoban-config-line">{{ t('app.security.overview.autoban.scope') }}：{{ autobanError ? '—' : autobanScopeText }}</div>
          </div>
        </div>
        <div class="autoban-suggestions">
          <el-tooltip :content="t('app.security.overview.autoban.suggestionsTitle')" placement="top">
            <div class="autoban-suggestions-title">{{ t('app.security.overview.autoban.suggestionsTitle') }}</div>
          </el-tooltip>
          <el-table v-if="autobanSuggestions.length > 0" :data="autobanSuggestions" size="small">
            <el-table-column :label="t('app.security.overview.autoban.colIdentity')" min-width="150">
              <template #default="{ row }">
                <IPLocationAction :ip="row.ip" :location="row.ip_location" />
              </template>
            </el-table-column>
            <el-table-column width="84" align="right">
              <template #default="{ row }"><el-tag :type="autobanSuggestionTone(row.count)" size="small" effect="light">{{ row.count }} {{ t('app.security.overview.autoban.times') }}</el-tag></template>
            </el-table-column>
            <el-table-column :label="t('app.security.overview.autoban.colEscalation')" width="136" align="center">
              <template #default>
                <!-- 状态级累犯档（配置口径）：/status 建议行不携带逐身份
                     offense_count，逐行档位不得虚构——每行都是同一份全局配置，
                     列名据实标「（全局）」 -->
                <span class="autoban-escalation-tier">{{ autobanStatValue(autobanError, t(autobanEscalationShortKey(autobanStatus?.escalation))) }}</span>
              </template>
            </el-table-column>
          </el-table>
          <div v-else class="autoban-suggestions-empty">{{ t('app.security.overview.autoban.suggestionsEmpty') }}</div>
        </div>
      </div>
    </el-card>

    <!-- 累犯历史弹框（共享组件，事件页 autoban 卡同款入口复用）：
         「累犯升级」统计的下钻明细；写门/配置实态由本页传入，
         重置成功后刷新本页状态卡（escalated_count 归零）。 -->
    <RecidivismDialog
      v-model="recidivismDialogVisible"
      :writable="recidivismWritable"
      :blocked-reason="recidivismWriteBlockedReason"
      :duration="autobanStatus?.duration ?? ''"
      :escalation="autobanStatus?.escalation"
      @reset="fetchAutobanStatus"
    />

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
import { DataAnalysis, TrendCharts, PieChart, Location, Warning, Odometer, Monitor, InfoFilled, Stopwatch, Lock, Tickets } from '@element-plus/icons-vue'
import { useI18n } from 'vue-i18n'
import { request } from '@/utils/api'
import RecidivismDialog from '@/components/security/RecidivismDialog.vue'
import { useAuthStore } from '@/stores/auth'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { formatDate, formatChartTimeInConfigTz } from '@/utils/date'
import { DEEP_LINK_PARAMS, pageUrl } from '@/utils/deepLink'
import { libraryStatusLabel, libraryStatusTagType, summarizeLibrarySources, type LibrarySourceRow } from '@/utils/securityLibraries'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import VChart from 'vue-echarts'
import type { APIResponse } from '@/types'
import { securityActionColors } from '@/utils/chartTheme'
import { ingestionWarningMessage, type IngestionHealth } from '@/utils/ingestionHealth'
import { autobanStateLabel, autobanStatValue, isAutobanIneffective, autobanEscalationShortKey, suggestionBand, autobanDurationLabel, autobanScopeLabel, isAutobanScopeMember, autobanMissingPolicyId, isAutobanBoundWithoutTraffic } from '@/utils/autobanStatus'

const { t } = useI18n()


interface TrendPoint { date: string; blocked: number; detected: number }
interface TopIP { ip: string; ip_location: string; blocked: number; detected: number; recent_10m: number; recent_1h: number; recent_24h: number; last_time: string; attack_type: string; attack_type_stage?: string
}
interface AttackType { name: string; value: number }
interface Overview {
  today_blocked: number; today_detected: number; crs_version: string
  crs_available?: boolean; ip2region_available?: boolean; update_status?: string
  trend: TrendPoint[]; top_ips: TopIP[]; attack_types: AttackType[]; attack_types_stage: AttackType[]
  // 后端另有 active_policies/raw_coverage_from/backfill_incomplete/today_human_fail
  // （API 契约保留）——本视图零消费，不再声明（活跃策略 KPI 已退役；覆盖/回填
  // 披露由威胁大屏 stats 消费；今日挑战失败由 CC 卡 human/stats 承载）。
  // 三 KPI 栏契约字段（昨日对比 + 正常请求，防御式消费：旧后端缺字段 → 对应行隐藏）
  yesterday_blocked?: number; yesterday_blocked_tcp?: number
  yesterday_detected?: number; yesterday_detected_tcp?: number
  normal_today?: number; normal_today_http?: number; normal_today_tcp?: number
  normal_yesterday?: number; normal_yesterday_http?: number; normal_yesterday_tcp?: number
  today_challenged?: number
  // 今日拦截的 TCP（L4 断连）份额：旧后端缺失 → 协议拆分行整行隐藏（防御式）。
  // 原始表直算（不走 rollup——rollup 无 event_type 维度），极端量级下行帽裁剪可能少计。
  today_blocked_tcp?: number
  // 今日检测的 TCP（L4 信任检测 logged→trust 升格）份额：可见性拆分列，不计入
  // 攻击口径 today_detected（trust 整类排除）——HTTP 份额以 today_detected 自身为准。
  today_detected_tcp?: number
  // includes_reserved：后端口径披露——true=今日计数回退原始表直算（含私网/保留
  // 地址事件）；false=走分钟 rollup 与大屏同口径（不含私网）。tooltip 按此切换文案
  includes_reserved?: boolean
  // ingestion：与事件列表同源的采集健康位（见 utils/ingestionHealth）
  ingestion?: IngestionHealth
}
interface SecurityEvent { id: number; event_time: string; client_ip: string; rule_caddy_id: string; rule_name: string; policy_name: string; ip_location?: string; event_type?: string }
interface ChallengeEvent { id: string; kind: 'slider' | 'js'; status: 'waiting' | 'passed' | 'failed' | 'expired'; last_result: '' | 'pass' | 'fail'; rule_id: string; rule_name: string; policy_name: string; client_ip: string; method: string; uri: string; user_agent: string; issued_at_ms: number; expires_at_ms: number; remaining_ms: number; attempts: number; max_attempts: number; pass_expires_at_ms: number; pass_remaining_ms: number }

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
const overview = ref<Overview>({ today_blocked: 0, today_detected: 0, crs_version: '', trend: [], top_ips: [], attack_types: [], attack_types_stage: [] })

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

// today_detected 是攻击口径合计（trust 整类排除），today_detected_tcp 是独立的
// TCP 信任检测可见性拆分——不计入合计，HTTP 份额不得按 合计−TCP 推导（会得到
// 负值/错值），HTTP = today_detected 自身（后端 models.SecurityOverview 契约）。
// TCP 字段存在即显示（TCP=0 也显示——可能产生数据就如实显示），缺失=旧后端隐藏。
const todayDetectedSplit = computed<{ http: number; tcp: number } | null>(() => {
  const tcp = overview.value.today_detected_tcp
  if (typeof tcp !== 'number' || !Number.isFinite(tcp)) return null
  return { http: overview.value.today_detected, tcp }
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

// 人机验证统计（lb_human admin 端点；端点缺失=旧二进制，全零不报错）。
// cc_triggers/三丢失计数为对账面（human_stats.go 透传）：旧响应缺省按零防御。
const humanStats = ref({ challenges: 0, passes: 0, fails: 0, cc_triggers: { rps_spike: 0, '4xx_ratio': 0, session_anomaly: 0 }, events_dropped: 0, events_deliver_failed: 0, events_shutdown_lost: 0 })

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
// 请求序号：active/recent 切换或关闭后，旧作用域的迟到响应不得覆盖新视图。
let challengeLiveSeq = 0
let challengeLiveInFlightScope: 'active' | 'recent' | null = null

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
// 挑战会话时刻经配置时区单源（与图表轴同口径）；0/缺失显示占位。
const formatLiveClock = (ms: number): string => ms > 0 ? formatChartTimeInConfigTz(ms) : '—'
const formatLiveAttempts = (row: ChallengeEvent): string => row.max_attempts > 1
  ? `${row.attempts}/${row.max_attempts}`
  : String(row.attempts)
const fetchChallengeLive = async (): Promise<void> => {
  // 作用域快照：参数与响应归属都按发起时的值判定。切换 scope 时若上一个
  // 同 scope 请求仍在途则合并（单飞），否则新开序号让旧响应过期。
  const scope = challengeLiveScope.value
  if (challengeLiveLoading.value && challengeLiveInFlightScope === scope) return
  const seq = ++challengeLiveSeq
  challengeLiveInFlightScope = scope
  challengeLiveLoading.value = true
  try {
    const res = await request.get<APIResponse<{ now_ms: number; active_count: number; sessions: ChallengeEvent[] }>>('/security/human/live', {
      params: { scope },
      silent: true,
    })
    if (seq !== challengeLiveSeq) return
    challengeEvents.value = res.data?.sessions || []
    challengeLiveActiveCount.value = res.data?.active_count || 0
    challengeLiveUpdated.value = formatChartTimeInConfigTz(Date.now())
    challengeLiveError.value = false
  } catch {
    if (seq !== challengeLiveSeq) return
    challengeLiveError.value = true
  } finally {
    if (seq === challengeLiveSeq) {
      challengeLiveLoading.value = false
      challengeLiveInFlightScope = null
    }
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
  if (visible) {
    void fetchChallengeLive()
  } else {
    // 关闭弹框：作废在途响应，避免迟到帧写回已关闭视图的计数/列表。
    challengeLiveSeq++
    challengeLiveInFlightScope = null
    challengeLiveLoading.value = false
  }
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
// 失败段占比（与通过段同源同分母：通过+失败）——圆环双色分布，缺口不再被读成未知。
const ccFailRatePct = computed<number | null>(() => {
  const total = ccPassCount.value + ccFailCount.value
  return total > 0 ? Math.round((ccFailCount.value / total) * 1000) / 10 : null
})
const ccPct = (n: number): number => {
  const total = ccTotalCount.value
  return total > 0 ? (n / total) * 100 : 0
}
// 人机事件丢失合计（队列满丢弃 + 投递失败 + 停机预算内未投递）：>0 时 CC 卡
// 显性披露对账警示，分项计数随文案逐项展示。
const humanEventsLost = computed(() => humanStats.value.events_dropped + humanStats.value.events_deliver_failed + humanStats.value.events_shutdown_lost)
const fetchHumanStats = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<{ challenges: number; passes: number; fails: number; cc_triggers: { rps_spike: number; '4xx_ratio': number; session_anomaly: number }; events_dropped: number; events_deliver_failed: number; events_shutdown_lost: number }>>('/security/human/stats', { silent: true })
    if (res.data) humanStats.value = { ...humanStats.value, ...res.data, cc_triggers: { ...humanStats.value.cc_triggers, ...res.data.cc_triggers } }
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

// 「最近拦截事件」卡的下钻：带动作筛选落到事件页（卡片本身就是拦截口径，
// 不带参数会让用户落在一个全量列表上重新找）。
const goToEvents = () => { window.open(pageUrl('security-events', { [DEEP_LINK_PARAMS.eventsAction]: 'blocked' }), '_blank', 'noopener') }

// 自动封禁卡（独立整行）：数据源 /security/autoban/status，与事件页状态卡同源。
// IP 名单单通道口径：四统计卡（今日封禁/生效条目/监控身份/累犯升级）+ 配置摘要；
// 黄条判据复用 isAutobanIneffective 单源；累犯升级可点击下钻累犯历史弹框。
interface AutobanSuggestion { ip: string; count: number; ip_location?: string; window_start?: string; last_seen?: string }
interface AutobanStatus {
  enabled: boolean; dry_run: boolean; threshold: number; window_minutes: number
  duration: string; scope: string; banned_today: number; list_entries: number
  ban_effective: boolean; ban_missing?: string; tracked_ips: number; suggestions: AutobanSuggestion[]
  // binding 环节的定位目标（就绪策略 id）；其余环节与旧后端缺省为 null——不给「前往绑定规则」入口。
  policy_id?: number | null
  is_master: boolean; feed_degraded: boolean; feed_degraded_reason: string
  // 累犯披露键（旧后端缺省 → 档位按 off、升级数按 0，防御式消费）。
  escalation?: string; escalated_count?: number
}
const autobanStatus = ref<AutobanStatus | null>(null)
const autobanError = ref(false)
// binding 环节黄条的说法按就绪策略的实际绑定数区分（判据单源 isAutobanBoundWithoutTraffic）：
// 后端 binding 同时覆盖「零绑定」与「只绑到 TLS 类 / 已禁用 / 无启用上游的规则」，后者
// 不是「尚未关联」。绑定数取 GET /security/policies/:id 的 bindings（null=读取失败，按原文案）。
const autobanBindingCount = ref<number | null>(null)
const autobanIneffectiveText = computed(() => {
  const status = autobanStatus.value
  const count = autobanBindingCount.value
  if (status !== null && isAutobanBoundWithoutTraffic(status, count)) return t('app.security.events.ineffectiveBoundNotice', { n: count })
  return t(status?.ban_missing === 'binding' ? 'app.security.overview.autoban.ineffectiveBinding' : 'app.security.overview.autoban.ineffective')
})
const loadAutobanBindingCount = async (status: AutobanStatus): Promise<number | null> => {
  const policyId = autobanMissingPolicyId(status)
  if (policyId === null) return null
  try {
    const res = await request.get<APIResponse<{ bindings?: string[] }>>(`/security/policies/${policyId}`, { silent: true })
    return res.data?.bindings?.length ?? 0
  } catch {
    return null
  }
}
const fetchAutobanStatus = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<AutobanStatus>>('/security/autoban/status', { silent: true })
    if (res.data) {
      // 先取到绑定数再落状态：文案与状态同时就位，不先闪「尚未关联」再换成另一种说法
      const bindingCount = await loadAutobanBindingCount(res.data)
      autobanBindingCount.value = bindingCount
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
// 「前往绑定规则」入口的定位目标（判据单源 autobanMissingPolicyId，事件页同写法）：仅 binding
// 环节且后端给出可定位的策略 id 时非空。
const autobanBindingPolicyId = computed(() => autobanStatus.value === null ? null : autobanMissingPolicyId(autobanStatus.value))
const goToBindingPolicy = () => {
  if (autobanBindingPolicyId.value === null) return
  window.open(pageUrl('security-policies', { [DEEP_LINK_PARAMS.policyId]: autobanBindingPolicyId.value }), '_blank', 'noopener')
}
// 累犯升级开启时配置摘要时长行同口径标「首封时长」（与事件页状态卡一致）。
const autobanStatusEscalationOn = computed(() =>
  autobanStatus.value?.escalation === 'standard' || autobanStatus.value?.escalation === 'aggressive')
const autobanDurationText = computed(() => autobanDurationLabel(autobanStatus.value?.duration ?? ''))
// 口径标签单源 utils/autobanStatus.autobanScopeLabel（与事件页同词表）；
// 成员判定走 isAutobanScopeMember（原型键/非法成员不得进入展示）。
const autobanScopeText = computed(() => {
  const parts = (autobanStatus.value?.scope || '').split(',').map(s => s.trim()).filter(isAutobanScopeMember)
  return parts.length > 0 ? parts.map(autobanScopeLabel).join(' + ') : '—'
})
const autobanSuggestions = computed(() => (autobanStatus.value?.suggestions || []).slice(0, 5))
const autobanSuggestionTone = (count: number): 'danger' | 'warning' | 'info' => {
  const band = suggestionBand(count, autobanStatus.value?.threshold ?? 1)
  return band === 'high' ? 'danger' : band === 'mid' ? 'warning' : 'info'
}

// 累犯历史弹框（「累犯升级」统计下钻）：数据/重置/表格在共享组件
// RecidivismDialog（事件页 autoban 卡复用同款）；本页只持有可见态与写门。
const recidivismDialogVisible = ref(false)
// 重置写门与事件页 autobanWritable 同口径：全局只读契约 ∧ 主节点 ∧ 状态已就绪。
const recidivismWritable = computed(() => authStore.readOnlyReason === null && (autobanStatus.value?.is_master ?? false) && !autobanError.value)
const recidivismWriteBlockedReason = computed(() => {
  if (authStore.readOnlyReason !== null) return authStore.readOnlyMessage
  // 加载中与加载失败分开披露（与事件页 autobanConfigTooltip 同口径）：
  // 状态未就绪不得谎称「加载失败」。
  if (autobanStatus.value === null) return t('app.security.events.blockedReasonLoading')
  if (!(autobanStatus.value.is_master ?? false)) return t('app.security.events.blockedReasonMasterOnly')
  if (autobanError.value) return t('app.security.events.blockedReasonLoadFail')
  return ''
})

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
.challenge-live-tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.challenge-live-updated { font-size: 12px; color: var(--text-secondary); }
.challenge-live-auto-label { font-size: 12px; color: var(--text-secondary); }
.challenge-live-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
/* 实时挑战区加载失败条与下表间距：显式声明（全站只有 .mb-5，无 mb-3 工具类，
   原 class="mb-3" 恒 0 间距——错误条贴住工具栏）。 */
.challenge-live-alert { margin-bottom: 12px; }
.challenge-live-counter { display: inline-flex; align-items: baseline; gap: 8px; padding: 6px 12px; border-radius: 0; background: #f5f7fa; color: var(--text-secondary); font-size: 12px; }
.challenge-live-counter strong { font-size: 20px; line-height: 1; font-variant-numeric: tabular-nums; color: #606266; }
.challenge-live-counter.is-active strong { color: #409eff; }
.challenge-live-countdown { display: flex; flex-direction: column; line-height: 1.25; font-variant-numeric: tabular-nums; }
.challenge-live-countdown strong { color: #409eff; font-weight: 700; }
.challenge-live-countdown span { font-size: 11px; color: var(--text-secondary); }
/* 已通过行的放行倒计时用绿色（与通过图例/圆环通过段同色），区别于等待验证的蓝色。 */
.challenge-live-countdown.is-pass strong { color: #15803d; }
.challenge-live-status { display: flex; flex-direction: column; align-items: center; gap: 3px; }
.challenge-live-attempts { font-size: 11px; color: var(--text-secondary); font-variant-numeric: tabular-nums; }
.challenge-live-attribution { display: flex; flex-direction: column; line-height: 1.3; }
.challenge-live-attribution span:last-child { font-size: 11px; color: var(--text-secondary); }
.challenge-live-method { display: inline-block; min-width: 38px; font-weight: 600; color: var(--text-secondary); }
.challenge-live-footer { margin-top: 8px; text-align: right; font-size: 12px; color: var(--text-secondary); }
.cc-hero { flex: 1; display: flex; flex-direction: row; align-items: center; justify-content: center; gap: 24px; padding: 4px 4px 6px; }
.cc-donut { position: relative; width: 136px; height: 136px; flex: none; }
.cc-donut svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.cc-donut-track { fill: none; stroke: #eef2f7; stroke-width: 3.4; }
.cc-donut-value { fill: none; stroke: #67c23a; stroke-width: 3.4; stroke-linecap: butt; transition: stroke-dasharray .4s ease; }
.cc-donut-fail { fill: none; stroke: #f56c6c; stroke-width: 3.4; stroke-linecap: butt; transition: stroke-dasharray .4s ease, stroke-dashoffset .4s ease; }
.cc-donut-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1px; color: #303133; }
.cc-rate-value { font-size: 22px; font-weight: 700; line-height: 1; }
.cc-rate-label { font-size: 10px; color: var(--text-secondary); line-height: 1.4; }
.cc-meta { display: flex; flex-direction: column; gap: 10px; min-width: 0; flex: 1; }
.cc-meta-row { display: flex; align-items: baseline; justify-content: space-between; gap: 14px; padding: 9px 12px; border-radius: 0; background: #f7f9fc; }
.cc-meta-label { font-size: 12px; color: var(--text-secondary); white-space: nowrap; }
.cc-meta-value { font-size: 22px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.cc-meta-value.is-primary { color: #409eff; }
.cc-meta-value.is-pass { color: #67c23a; }
.cc-meta-value.is-fail { color: #f56c6c; }
.cc-dist { margin-top: 8px; }
.cc-triggers { margin-top: 8px; }
.cc-dist-head { display: flex; align-items: baseline; justify-content: space-between; padding: 0 4px 6px; font-size: 12px; color: var(--text-secondary); }
.cc-dist-head > span:first-child { font-weight: 600; color: #303133; }
.cc-stack { display: flex; height: 10px; border-radius: 0; overflow: hidden; background: #eef2f7; margin: 0 4px 8px; }
.cc-stack span { display: block; height: 100%; transition: width .4s ease; }
.cc-stack-pass { background: #67c23a; }
.cc-stack-fail { background: #f56c6c; }
.cc-stack-pending { background: #cbd5e1; }
.cc-legend { display: flex; flex-wrap: wrap; gap: 10px 14px; padding: 0 4px; font-size: 12px; color: var(--text-secondary); }
.cc-legend-item { display: inline-flex; align-items: center; gap: 5px; }
.cc-legend-item i { width: 8px; height: 8px; border-radius: 0; display: inline-block; }
.cc-legend-item i.is-pass { background: #67c23a; }
.cc-legend-item i.is-fail { background: #f56c6c; }
.cc-legend-item i.is-pending { background: #cbd5e1; }
/* 自动封禁卡：左侧四统计卡一行（今日封禁/生效条目/监控身份/累犯升级）+ 配置摘要，
   右侧观察建议 Top5 自适应剩余宽度（标题 ellipsis+tooltip，表列紧凑，无横滚）；
   ≤768px 移动堆叠。 */
.autoban-body { display: flex; gap: 24px; align-items: stretch; }
/* 卡内黄条与卡体的间距单源：黄条曾靠未定义的工具类取间距（恒 0）贴住卡体——
   此处显式声明下间距；双黄条并存时上条收窄，与 info-note-bar 相邻条口径一致。 */
.autoban-alert { margin-bottom: 12px; }
.autoban-alert + .autoban-alert { margin-bottom: 8px; }
/* 四统计卡恒一行（桌面）：grid 4 列；配置摘要独占次行 */
.autoban-stats { flex: 1 1 auto; min-width: 0; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; align-items: stretch; align-content: flex-start; }
.autoban-stat { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 16px; border-radius: 0; background: #f7f9fc; min-width: 0; }
.autoban-stat-label { font-size: 12px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.autoban-stat-value { font-size: 24px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; color: #303133; }
.autoban-stat-value.is-ban { color: #f56c6c; }
/* 累犯升级下钻入口：link 按钮承载统计数值（去按钮内边距，观感同普通数值） */
.autoban-stat-link { height: auto; padding: 0; border: none; justify-content: flex-start; }
.autoban-stat-link .autoban-stat-value { color: inherit; }
.autoban-stat-link:not(:disabled) .autoban-stat-value { color: var(--el-color-primary); }
.autoban-stat-link:not(:disabled):hover .autoban-stat-value { text-decoration: underline; }
.autoban-config-summary { grid-column: 1 / -1; display: flex; flex-direction: column; gap: 4px; padding: 4px 8px; font-size: 12px; color: var(--text-secondary); justify-content: center; }
.autoban-config-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* 建议区定宽 420 不伸缩（min-width 0 防内容撑破），标题 ellipsis+tooltip；
   窄桌面由下方断点整卡堆叠，不在中间宽度带里把建议表挤到不可读 */
.autoban-suggestions { flex: 0 0 420px; min-width: 0; border-left: 1px solid var(--el-border-color-lighter); padding-left: 20px; }
.autoban-suggestions-title { font-size: 13px; font-weight: 600; color: #303133; margin-bottom: 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.autoban-suggestions-empty { font-size: 12px; color: var(--text-secondary); padding: 12px 0; }
.autoban-escalation-tier { font-size: 12px; color: var(--text-secondary); white-space: nowrap; }
/* 窄桌面（侧栏展开后内容区放不下「四统计列 + 420 建议区」）提前堆叠，
   避免观察建议被挤成窄条；768 以下同形态。 */
@media (max-width: 1200px) {
  .autoban-body { flex-direction: column; }
  .autoban-suggestions { flex-basis: auto; border-left: none; padding-left: 0; border-top: 1px solid var(--el-border-color-lighter); padding-top: 12px; }
}
@media (max-width: 768px) {
  .autoban-body { flex-direction: column; }
  .autoban-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  /* 堆叠后建议区占满整行：表格自身横向滚动（el-table--scrollable-x）承担窄屏 */
  .autoban-suggestions { flex-basis: auto; border-left: none; padding-left: 0; border-top: 1px solid var(--el-border-color-lighter); padding-top: 12px; }
}
</style>
