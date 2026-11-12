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
        <el-card shadow="always">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Odometer /></el-icon>
                <span>{{ t('app.security.overview.cc.title') }}</span>
              </div>
              <el-tooltip placement="top" :content="t('app.security.overview.cc.tip')">
                <el-tag type="info" size="small" effect="plain">{{ t('app.security.overview.cc.tag') }}</el-tag>
              </el-tooltip>
            </div>
          </template>
          <div class="cc-stats">
            <div class="cc-stat">
              <span class="stat-label">{{ t('app.security.overview.cc.challengedToday') }}</span>
              <span class="stat-value" style="color: #409eff">{{ fmtStatNum(overview.today_challenged) }}</span>
            </div>
            <div class="cc-stat">
              <span class="stat-label">{{ t('app.security.overview.cc.passRate') }}</span>
              <span class="stat-value">{{ humanPassRate }}</span>
            </div>
            <div class="cc-stat">
              <span class="stat-label">{{ t('app.security.overview.cc.passFail') }}</span>
              <span class="stat-value">{{ fmtStatNum(overview.today_human_pass ?? 0) }} / {{ fmtStatNum(overview.today_human_fail ?? 0) }}</span>
            </div>
            <div class="cc-stat">
              <span class="stat-label">{{ t('app.security.overview.cc.bans') }}</span>
              <span class="stat-value" style="color: #f56c6c">{{ fmtStatNum(humanStats.bans) }}</span>
            </div>
          </div>
          <div class="form-tip-line">{{ t('app.security.overview.cc.note') }}</div>
        </el-card>
      </el-col>
    </el-row>

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
import { ref, onMounted, computed } from 'vue'
import { DataAnalysis, TrendCharts, PieChart, Location, Warning, Odometer, Monitor, InfoFilled, Stopwatch } from '@element-plus/icons-vue'
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
  today_challenged?: number; today_human_pass?: number; today_human_fail?: number
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
const humanStats = ref({ challenges: 0, passes: 0, fails: 0, bans: 0 })
// 通过率口径（2026-11-12）：今日事件（human_pass / human_failed）优先——
// 与"挑战发放"同源可对账；零样本显性 —。admin 端点值仅作兜底。
const humanPassRate = computed(() => {
  const passes = overview.value.today_human_pass ?? 0
  const fails = overview.value.today_human_fail ?? 0
  const total = passes + fails
  if (total > 0) return `${Math.round((passes / total) * 100)}%`
  const fallback = humanStats.value.passes + humanStats.value.fails
  return fallback > 0 ? `${Math.round((humanStats.value.passes / fallback) * 100)}%` : '—'
})
const fetchHumanStats = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<{ challenges: number; passes: number; fails: number; bans: number }>>('/security/human/stats', { silent: true })
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
      fetchIP2RegionInfo(),
      fetchThreatLib(),
      fetchCrawlerLib(),
    ])
  } finally {
    reloading.value = false
  }
}

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
.cc-stats { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 0 4px 10px; }
.cc-stat { display: flex; flex-direction: column; gap: 2px; }
.cc-stat .stat-label { font-size: 13px; color: var(--text-secondary); }
.cc-stat .stat-value { font-size: 20px; font-weight: 600; }
</style>
