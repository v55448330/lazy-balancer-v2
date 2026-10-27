<template>
  <div class="threat-screen" :class="{ 'is-paused': paused, 'mode-globe': isGlobeMode }">
    <div class="globe-wrap hud" aria-label="攻击态势">
      <!-- 引擎专用挂载点：globe.gl 构造时会清空容器 innerHTML，
           绝不可与 HUD 覆盖层同容器（曾致 hud-tl/ticker/返回按钮被清） -->
      <div ref="mapHost" class="stage-mount"></div>
      <div class="vignette"></div>

      <div class="hud-tl">
        <div class="title"><i></i>{{ isGlobeMode ? 'GLOBAL THREAT SPHERE' : 'GLOBAL THREAT MAP' }}</div>
        <div class="readout">CAM <b>{{ camReadout }}</b></div>
        <div class="readout">TGT <b>{{ tgtReadout }}</b></div>
        <div class="readout">FLOW <b>{{ flowSampleLabel }}</b></div>
      </div>
      <div class="hud-tr" aria-label="图例">
        <div class="row">正常请求 <span class="legend-arc normal"></span></div>
        <div class="row">攻击光流 <span class="legend-arc"></span></div>
        <div class="row">国家命中 少 <span class="legend-ramp"></span> 多</div>
      </div>

      <transition name="fade">
        <button v-if="zoomedName" type="button" class="btn back-btn" @click="backToWorld">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
          <span class="btn-text">返回世界</span>
        </button>
      </transition>

      <!-- 攻击事件弹框：feed 新事件到达即弹（最多 3 条，4.5s 淡出） -->
      <transition-group name="toast" tag="div" class="toasts" role="status" aria-live="polite" aria-label="新攻击告警">
        <div v-for="t in attackToasts" :key="t.id" class="toast" :class="t.action === 'blocked' ? 'sev-high' : 'sev-low'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4.5 5.4v6.1c0 4.6 3.2 8.6 7.5 9.9 4.3-1.3 7.5-5.3 7.5-9.9V5.4Z"/><path d="m9 12 2 2 4-4.5"/></svg>
          <b>{{ t.country }}</b>
          <span class="ip">{{ t.ip }}</span>
          <span class="dim">{{ t.attackType }} · {{ t.durationMs }}ms</span>
          <span v-if="(t.count ?? 1) > 1" class="agg">×{{ t.count }}</span>
          <span class="sev" :class="t.action === 'blocked' ? 'sev-high' : 'sev-low'">{{ eventActionFull(t.action) }}</span>
        </div>
      </transition-group>

      <div class="hint">
        <span>拖动{{ isGlobeMode ? '旋转' : '平移' }} · 点击国家下钻 · 点击空白返回</span>
      </div>

      <transition name="fade">
        <div v-if="showEmptyState" class="empty-state">近 {{ bucketTerms.windowLabel }}无安全事件</div>
      </transition>
      <div class="error-stack" role="status" aria-live="polite">
        <div v-if="statsError" class="error-banner">大屏数据加载失败，正在重试…</div>
        <!-- 采集健康位（任务已停/连续失败/审计写侧降级）：判据与文案与事件列表/总览同源 -->
        <div v-if="ingestionWarning" class="info-note-bar">
          <span class="info-note-desc">{{ ingestionWarning }}</span>
        </div>
        <div v-if="stats?.backfill_incomplete" class="error-banner site-unset">
          历史统计回填尚未完成，当前窗口总量可能少计，稍后将继续补齐
        </div>
        <!-- 原始表覆盖受限只作信息提示：窗口聚合来自分钟 rollup，完整性不受影响 -->
        <div v-if="stats?.raw_coverage_limited && !stats?.backfill_incomplete" class="info-note-bar">
          <span class="info-note-desc">原始事件仅保留自 {{ stats?.raw_coverage_from }}，更早明细无法逐条查询；窗口统计来自预聚合，不受影响</span>
        </div>
        <div v-if="stats?.rollup_stale" class="error-banner site-unset">统计汇总更新延迟，当前窗口数据可能不是最新</div>
        <div v-if="engineError" class="error-banner">
          大屏引擎加载失败
          <button type="button" class="btn error-retry" @click="mountEngine">重试</button>
        </div>
        <div v-if="trafficError" class="error-banner traffic-error">流量采集不可用（Caddy admin 不可达），曲线已保留上一帧</div>
        <div v-if="flowError || attackFlowError" class="error-banner site-unset">光流数据加载失败，正在重试…</div>
        <div v-if="flowGap || attackFlowGap" class="info-note-bar">
          <span class="info-note-desc">事件流有空洞：{{ flowGap || attackFlowGap }} 条事件因缓冲溢出未送达，弹道不连续属正常现象</span>
        </div>
        <div v-if="collectorError" class="error-banner site-unset">大屏流量采集续租失败（Caddy 侧逐请求计数已中断），正在重试…</div>
        <div v-if="configLoadFailed" class="error-banner site-unset">
          大屏配置读取失败，暂用默认视图与未设置坐标
          <button type="button" class="btn error-retry" @click="retryConfigLoad">重试</button>
        </div>
        <div v-else-if="!siteConfigured" class="error-banner site-unset">未配置站点坐标，本站信标与攻击弹道已隐藏</div>
      </div>
    </div>

    <!-- 左列：实时威胁事件 -->
    <aside class="panel panel-left hud" aria-label="实时威胁事件">
      <div class="panel-head">
        <h2>实时威胁事件 <span class="en">LIVE FEED</span></h2>
        <span class="live-chip" role="status" :class="{ 'is-error': feedError }"><i></i>{{ feedError ? 'RETRY' : 'LIVE' }}</span>
      </div>
      <div class="filters" role="group" aria-label="按危险等级筛选">
        <button v-for="f in sevFilters" :key="f.key" class="chip" type="button" :aria-pressed="sevFilter === f.key" @click="sevFilter = f.key">
          {{ f.label }} <b>{{ f.count }}</b>
        </button>
      </div>
      <div class="events">
        <transition-group name="feed" tag="div" class="events-inner">
          <div v-for="event in filteredFeed" :key="event.id" class="event" :data-sev="sevOf(event)">
            <div class="ev-top">
              <span>{{ formatFeedTime(event.event_time) }}</span>
              <span class="sev" :class="'sev-' + sevOf(event)">{{ sevLabel(event) }}</span>
              <span class="act" :class="'act-' + event.action">{{ eventActionShort(event.action) }}</span>
            </div>
            <div class="ev-main">
              <span class="ev-ip">{{ event.client_ip }}</span>
              <span class="ev-geo">{{ event.ip_location || '未知' }}</span>
            </div>
            <div class="ev-type">
              <b :style="{ color: typeColorFor(event.attack_type) }">{{ event.attack_type }}</b>
              <span v-if="event.rule_name">{{ event.rule_name }}</span>
              <span class="st">{{ triggerLabel(event) }}</span>
            </div>
          </div>
        </transition-group>
        <div v-if="filteredFeed.length === 0" class="empty">{{ feedError ? '事件流加载失败，正在重试…' : '暂无事件' }}</div>
      </div>
    </aside>

    <!-- 顶栏：品牌 + 核心指标 + 操作 -->
    <header class="topbar hud">
      <div class="brand">
        <div class="brand-icon" aria-hidden="true">
          <svg class="orbit" viewBox="0 0 42 42" fill="none"><circle cx="21" cy="21" r="19" stroke="rgba(58,209,255,.35)" stroke-dasharray="3 5"/><circle cx="21" cy="2" r="2" fill="#3ad1ff"/></svg>
          <svg class="shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4.5 5.4v6.1c0 4.6 3.2 8.6 7.5 9.9 4.3-1.3 7.5-5.3 7.5-9.9V5.4Z"/><path d="m9 12 2 2 4-4.5"/></svg>
        </div>
        <div>
          <h1 class="glitch" data-text="安全威胁大屏">安全威胁大屏</h1>
          <p>近 {{ frameTerms.windowLabel }}安全态势实时监控 <time>{{ clockText }}</time><span class="clock-date">{{ clockDate }}</span><em v-if="staleFrameLabel" class="ov-switch-hint" role="status">{{ staleFrameLabel }}</em></p>
        </div>
      </div>

      <div class="kpis" role="group" aria-label="核心指标">
        <div class="kpi"><span class="kpi-value">{{ displayTotal }}</span><span class="kpi-label">{{ frameTerms.windowLabel }}安全事件 · 拦截 {{ stats?.blocked_events ?? 0 }} / 检测 {{ loggedEvents }}</span></div>
        <div class="kpi"><span class="kpi-value cool">{{ blockRateText }}</span><span class="kpi-label">拦截率 · 拦截 / 全部安全事件</span></div>
        <div class="kpi"><span class="kpi-value">{{ displayRecentRate }}</span><span class="kpi-label">拦截/分钟 · 近 5 分钟</span></div>
        <div class="kpi"><span class="kpi-value">{{ displayActive }}</span><span class="kpi-label">活跃攻击 IP · 近 10 分钟</span></div>
      </div>

      <div class="actions">
        <div class="window-switch" role="group" aria-label="时间窗口">
          <button v-for="opt in windowOptions" :key="opt.value" type="button" class="window-btn" :aria-pressed="windowHours === opt.value" @click="setWindow(opt.value)">{{ opt.label }}</button>
        </div>
        <button type="button" class="btn" title="复位视角" @click="resetView">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>
          <span class="btn-text">复位视角</span>
        </button>
        <button type="button" class="btn" :aria-pressed="paused" :title="paused ? '继续（恢复轮询与服务端流量采集）' : '暂停（同时停止服务端流量采集）'" @click="togglePause">
          <svg v-if="!paused" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
          <svg v-else viewBox="0 0 24 24" fill="currentColor"><path d="M7 4.5v15l12-7.5Z"/></svg>
          <span class="btn-text">{{ paused ? '继续' : '暂停' }}</span>
        </button>
        <button type="button" class="btn" title="退出大屏" @click="exitScreen">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
          <span class="btn-text">退出</span>
        </button>
      </div>
    </header>

    <!-- 右列：安全态势统计 -->
    <aside class="panel panel-right hud" aria-label="安全态势统计">
      <div class="panel-head">
        <h2>安全态势统计 <span class="en">POSTURE</span></h2>
      </div>
      <div class="stats">
        <div class="stat-section overview-section">
          <div class="stat-title"><span>窗口概览</span><em v-if="statsPending" class="ov-switch-hint" role="status">切换中…</em><em v-else-if="staleFrameLabel" class="ov-switch-hint" role="status">{{ staleFrameLabel }}</em></div>
          <div class="overview-grid">
            <div class="ov-item"><span>事件总量</span><b>{{ stats?.total_events ?? 0 }}</b></div>
            <div class="ov-item"><span>拦截 / 检测</span><b>{{ stats?.blocked_events ?? 0 }} / {{ loggedEvents }}</b></div>
            <div class="ov-item">
              <span>{{ frameTerms.peakLabel }}</span>
              <b>{{ peakSlot.value > 0 ? peakSlot.name : '—' }}</b>
              <em v-if="peakSlot.value > 0">{{ peakSlot.value }} 次</em>
            </div>
            <div class="ov-item"><span>{{ frameTerms.countLabel }}</span><b>{{ activeHourCount }}/{{ hourlyHist.length }}</b></div>
          </div>
        </div>

        <div class="stat-section">
          <div class="stat-title"><span>事件族构成</span><span class="n">{{ shareTotal }}</span></div>
          <div class="donut-row">
            <div class="donut">
              <svg viewBox="0 0 36 36" role="img" :aria-label="`攻击类型占比：共 ${shareTotal} 次`">
                <circle class="donut-track" cx="18" cy="18" r="15.9" pathLength="100"></circle>
                <circle
                  v-for="(seg, i) in shareSegments"
                  :key="i"
                  class="donut-seg"
                  cx="18" cy="18" r="15.9" pathLength="100"
                  :stroke="seg.color"
                  :stroke-dasharray="seg.dash"
                  :stroke-dashoffset="seg.offset"
                ></circle>
              </svg>
              <div class="donut-center"><b>{{ shareTotal }}</b><span>事件</span></div>
            </div>
            <ul class="type-legend">
              <li v-for="item in shareTop" :key="item.name">
                <span class="sw" :style="{ background: shareSliceColor(item.name) }"></span>
                <span class="rule-name" :title="item.name">{{ item.name }}</span>
                <span class="cnt">{{ item.value }}</span>
              </li>
              <li v-if="shareRest > 0">
                <span class="sw" :style="{ background: SHARE_REST_COLOR }"></span>
                <span class="rule-name">其余</span>
                <span class="cnt">{{ shareRest }}</span>
              </li>
            </ul>
          </div>
        </div>

        <div class="stat-section">
          <div class="stat-title"><span title="仅统计窗口内具备 GeoIP 归属地的事件来源">有归属地国家 TOP3</span><span class="n">{{ countryCount }}</span></div>
          <ul v-if="topCountries.length" class="rules country-bars">
            <li v-for="item in topCountries" :key="item.name" class="rule" :title="item.name">
              <span class="rule-name">{{ item.name }}</span>
              <span class="cnt">{{ item.value }}</span>
              <span class="rule-bar"><i :style="{ width: countryBarWidth(item.value), background: countryHeat(item.value) }"></i></span>
            </li>
          </ul>
          <div v-else class="empty">暂无归属地数据</div>
        </div>

        <div class="stat-section">
          <div class="stat-title"><span>TOP 目标 / 规则</span><span class="n" title="当前维度前 3 条命中合计">{{ activeStatSum }}</span></div>
          <div class="stat-tabs" role="tablist" aria-label="TOP 排名维度" @keydown="onStatTabKeydown">
            <button id="threat-stat-tab-targets" type="button" class="stat-tab" role="tab" :aria-selected="statTab === 'targets'" aria-controls="threat-stat-panel-targets" :tabindex="statTabindex('targets')" :ref="(el: unknown) => setStatTabRef('targets', el)" @click="statTab = 'targets'">被攻击目标</button>
            <button id="threat-stat-tab-rules" type="button" class="stat-tab" role="tab" :aria-selected="statTab === 'rules'" aria-controls="threat-stat-panel-rules" :tabindex="statTabindex('rules')" :ref="(el: unknown) => setStatTabRef('rules', el)" @click="statTab = 'rules'">命中规则</button>
          </div>
          <div v-if="statTab === 'targets'" id="threat-stat-panel-targets" role="tabpanel" aria-labelledby="threat-stat-tab-targets" tabindex="0">
            <ul v-if="topTargets.length" class="rules">
              <li v-for="item in topTargets" :key="item.name + item.domain" class="rule" :title="item.domain || item.name">
                <span class="rule-name">{{ item.domain || item.name }}</span>
                <span class="cnt">{{ item.value }}</span>
                <span class="rule-bar"><i :style="{ width: targetBarWidth(item.value) }"></i></span>
              </li>
            </ul>
            <div v-else class="empty">暂无目标数据</div>
          </div>
          <div v-else id="threat-stat-panel-rules" role="tabpanel" aria-labelledby="threat-stat-tab-rules" tabindex="0">
            <ul v-if="topRules.length" class="rules">
              <li v-for="item in topRules" :key="item.name" class="rule" :title="item.name">
                <span class="rule-name">{{ ruleLabel(item.name) }}</span>
                <span class="cnt">{{ item.value }}</span>
                <span class="rule-bar"><i :style="{ width: ruleBarWidth(item.value) }"></i></span>
              </li>
            </ul>
            <div v-else class="empty">暂无数据</div>
          </div>
        </div>
      </div>
      <div class="panel-footer" title="自最近一次 Caddy 配置重载/进程启动以来累计；含上游自返 429；不受窗口切换影响">
        <span>限流累计 · 自重载</span>
        <b>{{ ratelimitAvailable ? displayRatelimit : '—' }}</b>
        <em>不受窗口影响</em>
      </div>
    </aside>

    <!-- 底部双图：24h 趋势 + 实时 QPS -->
    <div class="charts-row">
      <div class="panel hud">
        <div class="panel-head">
          <h2>{{ frameTerms.windowLabel }}事件趋势 <span class="en">{{ frameBucketLabel }}</span></h2>
          <span class="meta">合计 <b>{{ hourlyTotal }}</b></span>
        </div>
        <div class="chart-box">
          <svg class="timeline-svg" viewBox="0 0 100 40" preserveAspectRatio="none">
            <polygon class="timeline-fill" :points="histFillPoints"></polygon>
            <polyline class="timeline-stroke" :points="histPoints"></polyline>
            <rect
              v-for="(slot, i) in hourlyHist"
              :key="slot.name"
              class="timeline-slot"
              :x="i * (100 / Math.max(1, hourlyHist.length))"
              y="0"
              :width="100 / Math.max(1, hourlyHist.length) + 0.05"
              height="40"
            ><title>{{ hourlyTooltip(slot.name) }} — {{ slot.value }} 次</title></rect>
          </svg>
          <div class="timeline-axis"><span v-for="label in histAxis" :key="label">{{ label }}</span></div>
        </div>
      </div>
      <div class="panel hud">
        <div class="panel-head">
          <h2>请求流量 <span class="en">TRAFFIC · 90s</span></h2>
          <span class="meta" title="仅统计经过 GeoIP 处理器规则的请求；正常桶含上游透传，不等于 2xx">正常 <b>{{ normalQps }}</b>/s · 攻击 <b class="attack-qps">{{ attackQps }}</b>/s · 累计 正常 {{ normalTotalText }} / 攻击 {{ attackTotalText }}<template v-if="trafficSampled"> · 抽样估算</template><template v-if="trafficFrozen"> · 采集租约未生效，累计已冻结</template></span>
        </div>
        <div class="chart-box">
          <svg class="normal-spark" viewBox="0 0 100 40" preserveAspectRatio="none">
            <polygon class="normal-fill" :points="normalFillPoints"></polygon>
            <polyline class="normal-stroke" :points="normalPoints"></polyline>
            <polyline class="attack-stroke" :points="attackPoints"></polyline>
          </svg>
          <div class="traffic-legend"><span class="sw normal"></span>正常<span class="sw attack"></span>攻击</div>
          <div class="timeline-axis"><span>90s 前</span><span>现在</span></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import { ingestionWarningMessage, type IngestionHealth } from '@/utils/ingestionHealth'
import type { APIResponse } from '@/types'
import { useAuthStore } from '@/stores/auth'
import { usePollingTask } from '@/composables/usePollingTask'
import { createVisibilityIntervals } from '@/composables/useVisibilityIntervals'
import { useCountUp } from '@/composables/useCountUp'
import { formatDate } from '@/utils/date'
import { eventActionFull, eventActionShort } from '@/utils/eventAction'
import { trafficDelta, formatRecentRate, hourlyBucketLabel, bucketTerminology, type TrafficBaseline } from '@/utils/threatScreenMetrics'
import { anomalySeverity, overlayDetectionGrade, zeroScoreSeverity, type AnomalySeverity } from '@/utils/severityScale'
import { displayThreatScreenMode } from '@/utils/configValues'
import { flowTimestamp, normalizeTrafficSampleN, reconstructObservedRate, stepAdaptiveSample, nextFlowCursor, planFlowEvents, freshFlowEvents } from '@/utils/threatFlowRules'
import { nextRadioValue, rovingTabindex } from '@/utils/rovingRadio'
import type { ThreatScene, ThreatSceneOptions } from '@/utils/threatScene'

// 威胁大屏（v2.3.8 Threat Wall 版式）：三栏 HUD 网格（左事件流/中引擎舞台/
// 右态势统计）+ 顶栏 KPI + 底部双图（24h 趋势/正常流量）。视觉体系移植自
// 参考实现（threat-wall，用户友人制作，授权改造）；数据源/引擎全为本仓：
// 中央视觉按设置双模式装载（map=360°地图+雷达扫掠 / globe=旋转地球+垂直
// 扫描，threatGlobe.ts）。轮询复用 usePollingTask（页签隐藏自动暂停）。

interface ThreatScreenStats {
  hours: number
  total_events: number
  blocked_events: number
  logged_events?: number
  block_rate: number
  ratelimit_blocks: number
  ratelimit_available?: boolean
  active_sources: number
  countries: Record<string, number>
  china_provinces: Record<string, number>
  top_countries: { name: string; value: number }[]
  top_rules: { name: string; value: number }[]
  top_targets?: { name: string; domain?: string; value: number }[]
  hourly_hist: { name: string; value: number }[]
  attack_type_share: { name: string; value: number }[]
  recent_rate: number
  window_start?: string
  raw_coverage_from?: string
  // 原始表覆盖受限（保留期/行帽裁剪）：信息提示，不表示窗口少计
  raw_coverage_limited?: boolean
  backfill_incomplete?: boolean
  rollup_stale?: boolean
  // ingestion：与事件列表同源的采集健康位（见 utils/ingestionHealth）
  ingestion?: IngestionHealth
}

interface FeedEvent {
  id: number
  event_time: string
  client_ip: string
  ip_location: string
  action: string
  rule_name: string
  attack_type: string
  rule_triggered?: string
  /** 后端 trigger_type（阶段/触发类型的权威映射，security_threat_screen.go 下发）。 */
  trigger_type?: string
  anomaly_score?: number
}

interface NormalFlowEvent {
  seq: number
  country: string
  province?: string
  at: number
}

interface AttackFlowEvent {
  seq: number
  at: number
  country: string
  province?: string
  action?: string
  rule_triggered?: string
  weight?: number
}

interface ToastSummaryGroup {
  client_ip: string
  ip_location: string
  action: string
  attack_type: string
  count: number
  last_id: number
  avg_duration_us?: number
}

const FEED_LIMIT = 50
const FEED_POLL_MS = 3000
const STATS_POLL_MS = 30000
const ATTACK_FLOW_POLL_MS = 1000
const TOAST_STALE_MS = 30000
const windowOptions = [{ value: 1, label: '1h' }, { value: 24, label: '24h' }, { value: 168, label: '7d' }] as const
const windowHours = ref<number>(24)

const authStore = useAuthStore()
const stats = ref<ThreatScreenStats | null>(null)
const statsError = ref(false)
const ingestionWarning = computed(() => ingestionWarningMessage(stats.value?.ingestion))
const feedItems = ref<FeedEvent[]>([])
const paused = ref(false)
const mapHost = ref<HTMLElement | null>(null)
const zoomedName = ref<string | null>(null)
let threatMap: ThreatScene | null = null

let disposed = false

const displayTotal = useCountUp(computed(() => stats.value?.total_events ?? 0))
const displayRatelimit = useCountUp(computed(() => Math.floor(stats.value?.ratelimit_blocks ?? 0)))
const displayActive = useCountUp(computed(() => stats.value?.active_sources ?? 0))
const loggedEvents = computed(() => stats.value?.logged_events ?? Math.max(0, (stats.value?.total_events ?? 0) - (stats.value?.blocked_events ?? 0)))
const blockRateText = computed(() => {
  const total = stats.value?.total_events ?? 0
  if (total <= 0) return '—'
  return `${(stats.value?.block_rate ?? 0).toFixed(1)}%`
})
const ratelimitAvailable = computed(() => stats.value?.ratelimit_available !== false)
const topCountries = computed(() => stats.value?.top_countries ?? [])
const topRules = computed(() => stats.value?.top_rules ?? [])
const topTargets = computed(() => stats.value?.top_targets ?? [])
const targetHits = computed(() => topTargets.value.reduce((m, item) => m + item.value, 0))
const maxTargetCount = computed(() => topTargets.value.reduce((m, item) => Math.max(m, item.value), 0))
const targetBarWidth = (count: number): string => `${maxTargetCount.value > 0 ? Math.max(5, (count / maxTargetCount.value) * 100) : 0}%`
const hourlyTotal = computed(() => hourlyHist.value.reduce((m, slot) => m + slot.value, 0))
// 口径：top_rules 后端只返回前 3 条——求和不等于「命中规则数」，
// 文案与变量同口径改为「前 3 条命中次数」；真实 distinct 规则数需后端新增字段。
const topRuleHits = computed(() => topRules.value.reduce((m, item) => m + item.value, 0))
const hourlyHist = computed(() => stats.value?.hourly_hist ?? [])
const statTab = ref<'targets' | 'rules'>('targets')
const activeStatSum = computed(() => statTab.value === 'rules' ? topRuleHits.value : targetHits.value)
const statTabValues = ['targets', 'rules'] as const
type StatTab = typeof statTabValues[number]
const statTabRefs = new Map<StatTab, HTMLElement>()
const setStatTabRef = (value: StatTab, el: unknown): void => {
  if (el instanceof HTMLElement) statTabRefs.set(value, el)
  else statTabRefs.delete(value)
}
const statTabindex = (value: StatTab): number =>
  rovingTabindex(statTabValues, statTab.value, () => false, value)
const onStatTabKeydown = (event: KeyboardEvent): void => {
  if (event.repeat) return
  const next = nextRadioValue(statTabValues, statTab.value, () => false, event.key)
  if (next !== 'targets' && next !== 'rules') return
  event.preventDefault()
  statTab.value = next
  statTabRefs.get(next)?.focus()
}
// 峰值时段与有事件小时：窗口概览摆脱不可解释的对数指数，改为可直接读懂的
// 分布指标；并列峰值取时间靠前者（后端桶按时间升序）。
const peakSlot = computed(() => hourlyHist.value.reduce(
  (best, slot) => slot.value > best.value ? slot : best,
  { name: '—', value: 0 },
))
const activeHourCount = computed(() => hourlyHist.value.filter((slot) => slot.value > 0).length)
// 概览口径词随窗口派生（>24h 后端按日桶）——与趋势图 DAILY/HOURLY 同源
const bucketTerms = computed(() => bucketTerminology(windowHours.value))
// 已渲染帧的口径：标题/副标题/KPI/趋势必须描述「画出的那帧」（stats.hours），
// 切窗在途或请求持续失败时旧帧保留，用当前窗口词标注旧数字等于谎报口径。
const frameWindowHours = computed(() => stats.value?.hours ?? windowHours.value)
const frameTerms = computed(() => bucketTerminology(frameWindowHours.value))
const frameBucketLabel = computed(() => frameWindowHours.value > 24 ? 'DAILY' : 'HOURLY')
// 已渲染的统计属于哪个窗口：切换窗口后旧帧保留但必须标注「切换中」，
// 不得让上一窗口的数字冒充当前窗口。失败时不再显示「切换中」（三态互斥）：
// 轮询失败会保留旧帧直到新窗口成功，此时「切换中 + 加载失败」并存会让运维
// 把旧窗口总量读成新窗口结论——改由 staleFrameLabel 明确标注旧帧窗口。
const statsPending = computed(() => !statsError.value && stats.value !== null && stats.value.hours !== windowHours.value)
const staleFrameLabel = computed(() => {
  const hours = stats.value?.hours
  if (hours === undefined || hours === windowHours.value) return ''
  return `上次结果 · ${bucketTerminology(hours).windowLabel}`
})
const attackTypeShare = computed(() => stats.value?.attack_type_share ?? [])
const displayRecentRateX10 = useCountUp(computed(() => Math.round((stats.value?.recent_rate ?? 0) * 10)), 500)
const displayRecentRate = computed(() => formatRecentRate(displayRecentRateX10.value / 10))
// 空态是三态的一部分：stats 属于旧窗口（切窗在途）时不得用旧窗口的
// total_events 给当前窗口下「无安全事件」的结论——与 statsPending/staleFrameLabel
// 同源判据，只在该帧确属当前窗口且无错误时展示。
const showEmptyState = computed(() =>
  !statsError.value && !!stats.value && stats.value.total_events === 0
  && stats.value.hours === windowHours.value)
const countryCount = computed(() => Object.keys(stats.value?.countries ?? {}).length)

const formatFeedTime = (value: string): string => formatDate(value).slice(11) || value

const maxCountryCount = computed(() => topCountries.value.reduce((m, item) => Math.max(m, item.value), 0))
const countryBarWidth = (count: number): string => `${maxCountryCount.value > 0 ? Math.max(5, (count / maxCountryCount.value) * 100) : 0}%`
const countryHeat = (count: number): string => {
  const ratio = maxCountryCount.value > 0 ? count / maxCountryCount.value : 0
  if (ratio > 0.66) return '#ff4d4d'
  if (ratio > 0.33) return '#ff9f1c'
  return '#ffd166'
}
const maxRuleCount = computed(() => topRules.value.reduce((m, item) => Math.max(m, item.value), 0))
const ruleBarWidth = (count: number): string => `${maxRuleCount.value > 0 ? Math.max(5, (count / maxRuleCount.value) * 100) : 0}%`
const ruleLabel = (name: string): string => (/^\d+$/.test(name) ? `规则 #${name}` : name)

// 事件族切片与实时事件类型哈希共用的三主色（原 SHARE_PALETTE/TYPE_PALETTE 两
// 份同值常量，单源后新增色只改一处）。
const THREAT_PALETTE = ['#ff4d4d', '#ff9f1c', '#ffd166']
/** 第 4 段（其余）单色：与三主色区分的中性灰蓝，不参与「切片色哈希」。 */
const SHARE_REST_COLOR = '#6b7fa8'
const shareTop = computed(() => attackTypeShare.value.slice(0, 3))
const shareRest = computed(() => Math.max(0, shareTotal.value - shareTop.value.reduce((m, item) => m + item.value, 0)))
const shareTotal = computed(() => attackTypeShare.value.reduce((m, item) => m + item.value, 0))
const shareSliceColor = (name: string): string => {
  const idx = shareTop.value.findIndex((x) => x.name === name)
  return idx >= 0 ? THREAT_PALETTE[idx] ?? '#ffd166' : '#ffd166'
}
const shareSegments = computed(() => {
  const top = shareTop.value
  const total = shareTotal.value
  if (total === 0 || top.length === 0) return []
  const segments: { color: string; dash: string; offset: number }[] = []
  let cursor = 0
  top.forEach((item, index) => {
    const pct = (item.value / total) * 100
    segments.push({ color: THREAT_PALETTE[index] ?? '#ffd166', dash: `${pct} ${100 - pct}`, offset: 25 - cursor })
    cursor += pct
  })
  const rest = 100 - cursor
  if (rest > 0.01) segments.push({ color: SHARE_REST_COLOR, dash: `${rest} ${100 - rest}`, offset: 25 - cursor })
  return segments
})

const histPoints = computed((): string => {
  const slots = hourlyHist.value
  if (slots.length === 0) return ''
  const max = slots.reduce((m, s) => Math.max(m, s.value), 0)
  return slots
    .map((s, i) => {
      const x = slots.length > 1 ? (i / (slots.length - 1)) * 100 : 50
      const y = max > 0 ? 38 - (s.value / max) * 34 : 38
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
})
const histFillPoints = computed((): string => (histPoints.value ? `0,40 ${histPoints.value} 100,40` : ''))
const hourlyTooltip = (name: string): string => hourlyBucketLabel(name)
const histAxis = computed((): string[] => {
  const slots = hourlyHist.value
  if (slots.length === 0) return []
  const names = slots.map((s) => s.name)
  if (names.length <= 5) return names
  return [names[0], names[Math.floor(names.length / 3)], names[Math.floor((names.length * 2) / 3)], names[names.length - 1]]
})

const feedTypeColorCache = new Map<string, string>()
const typeColorFor = (name: string): string => {
  if (!name) return '#56709f'
  const cached = feedTypeColorCache.get(name)
  if (cached) return cached
  let hash = 0
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) | 0
  const color = THREAT_PALETTE[Math.abs(hash) % THREAT_PALETTE.length]
  feedTypeColorCache.set(name, color)
  return color
}

// ============ 实时时钟（秒级） ============
const clockText = ref('--:--:--')
const clockDate = ref('')
// 实时事件时间窗过滤的时钟源（1h/24h/168h）；每秒推进，旧事件到点即隐藏。
const feedNow = ref(Date.now())
const WEEKDAYS = ['日', '一', '二', '三', '四', '五', '六']
const camReadout = ref('--')
const tgtReadout = ref('--')
function tickClock(): void {
  const now = new Date()
  feedNow.value = now.getTime()
  const p2 = (n: number): string => String(n).padStart(2, '0')
  clockText.value = `${p2(now.getHours())}:${p2(now.getMinutes())}:${p2(now.getSeconds())}`
  clockDate.value = `${now.getFullYear()}-${p2(now.getMonth() + 1)}-${p2(now.getDate())} 星期${WEEKDAYS[now.getDay()]}`
  // HUD 读数：引擎相机地理中心 + 本站坐标
  const cam = threatMap?.cameraState()
  if (cam) camReadout.value = `${cam.cy.toFixed(1)}° ${cam.cx.toFixed(1)}°`
}

// ============ 攻击事件弹框（阶段标签单源=rule_triggered） ============
interface AttackToast {
  id: number
  country: string
  ip: string
  /** 攻击类型（后端 summary 的 attack_type）——与事件列表的「触发类型」区分 */
  attackType: string
  action: string
  durationMs: string
  /** >1 表示同一地区/秒聚合的请求数 */
  count?: number
}
const attackToasts = ref<AttackToast[]>([])
const TOAST_MAX = 3
const TOAST_TTL = 4500
const toastTimers = new Map<number, number>()
/** 事件行触发类型单源=后端 trigger_type：前端原按
 *  rule_triggered 二次猜解阶段（只识别 429/2/8/48x，其余一律 WAF），与后端
 *  trigger_type 映射（800xxx→地域拦截/12→信任/14→威胁情报/11→请求体…）
 *  左右自相矛盾。旧后端缺字段时回退 attack_type。 */
function triggerLabel(ev: FeedEvent): string {
  return ev.trigger_type || ev.attack_type || '—'
}
function pushAttackToasts(groups: ToastSummaryGroup[]): void {
  // 服务端按「IP + 攻击类型 + 动作」精确计数；这里只负责取前 3 组展示。
  if (groups.length === 0) return
  const next = [...groups]
    .filter((g) => g.count > 0 && g.client_ip)
    .sort((a, b) => (b.count - a.count) || (b.last_id - a.last_id))
    .slice(0, TOAST_MAX)
  for (const group of next) {
    const durMs = Math.max(0.1, (group.avg_duration_us ?? 0) / 1000)
    const toast: AttackToast = {
      id: group.last_id,
      country: (group.ip_location.split('·')[0] || '未知'),
      ip: group.client_ip,
      attackType: group.attack_type || '—',
      action: group.action,
      durationMs: durMs >= 100 ? Math.round(durMs).toString() : durMs.toFixed(1),
      count: group.count,
    }
    attackToasts.value = [toast, ...attackToasts.value].slice(0, TOAST_MAX)
    const timer = window.setTimeout(() => {
      attackToasts.value = attackToasts.value.filter((t) => t.id !== toast.id)
      toastTimers.delete(toast.id)
    }, TOAST_TTL)
    toastTimers.set(toast.id, timer)
  }
}

// ============ 流量 sparkline（normal/attack 双线，60 点窗口） ============
const normalWindow = ref<number[]>([])
const attackWindow = ref<number[]>([])
const NORMAL_WINDOW_MAX = 60
const normalTotal = ref(0)
const attackTotal = ref(0)
const trafficMax = computed(() => Math.max(1, ...normalWindow.value, ...attackWindow.value))
function qpsText(value: number): string {
  return value >= 100 ? Math.round(value).toString() : value.toFixed(1)
}
const normalQps = computed(() => {
  const w = normalWindow.value
  if (w.length < 2) return '0.0'
  const recent = w.slice(-10)
  return qpsText(recent.reduce((m, v) => m + v, 0) / recent.length)
})
const attackQps = computed(() => {
  const w = attackWindow.value
  if (w.length < 2) return '0.0'
  const recent = w.slice(-10)
  return qpsText(recent.reduce((m, v) => m + v, 0) / recent.length)
})
const normalTotalText = computed(() => (normalTotal.value >= 10000 ? `${(normalTotal.value / 1000).toFixed(1)}k` : normalTotal.value.toLocaleString()))
const attackTotalText = computed(() => (attackTotal.value >= 10000 ? `${(attackTotal.value / 1000).toFixed(1)}k` : attackTotal.value.toLocaleString()))
function sparkPoints(window: number[]): string {
  if (window.length < 2) return ''
  const max = trafficMax.value
  return window.map((v, i) => `${((i / (window.length - 1)) * 100).toFixed(2)},${(38 - (v / max) * 34).toFixed(2)}`).join(' ')
}
const normalPoints = computed((): string => sparkPoints(normalWindow.value))
const attackPoints = computed((): string => sparkPoints(attackWindow.value))
const normalFillPoints = computed((): string => (normalPoints.value ? `0,40 ${normalPoints.value} 100,40` : ''))

// ============ 事件等级筛选（高危=拦截 高危族 / 中危=限流 / 低危=检测） ============
type Sev = AnomalySeverity
/** 危险等级（v2.3.8 评分优先，用户裁定 2026-10-17）：评分>0 时由评分分档 +
 * 检测模式降级得级；仅 0 分回落阶段定性映射。两段语义都在
 * utils/severityScale（与事件列表评分着色同源），视图只做取值。 */
function sevOf(ev: FeedEvent): Sev {
  const score = ev.anomaly_score ?? 0
  return score > 0
    ? overlayDetectionGrade(anomalySeverity(score), ev.action)
    : zeroScoreSeverity(ev.rule_triggered ?? '', ev.action)
}
function sevLabel(ev: FeedEvent): string {
  const s = sevOf(ev)
  return s === 'high' ? '高危' : s === 'mid' ? '中危' : '低危'
}

const windowFeed = computed(() => {
  const cutoff = feedNow.value - windowHours.value * 3600_000
  return feedItems.value.filter((ev) => {
    const t = flowTimestamp(ev.event_time)
    return !Number.isFinite(t) || t >= cutoff
  })
})
const sevFilter = ref<'all' | Sev>('all')
const sevFilters = computed(() => {
  let high = 0, mid = 0, low = 0
  for (const ev of windowFeed.value) {
    const s = sevOf(ev)
    if (s === 'high') high++
    else if (s === 'mid') mid++
    else low++
  }
  return [
    { key: 'all' as const, label: '全部', count: windowFeed.value.length },
    { key: 'high' as const, label: '高危', count: high },
    { key: 'mid' as const, label: '中危', count: mid },
    { key: 'low' as const, label: '低危', count: low },
  ]
})
const filteredFeed = computed(() =>
  sevFilter.value === 'all' ? windowFeed.value : windowFeed.value.filter((ev) => sevOf(ev) === sevFilter.value),
)

// ============ 正常流量 sparkline（计数器差分 → QPS 采样窗口） ============
// available=false（Caddy admin 不可达）时保留上一帧
// 并显性提示，不再把采集失败渲染为 0 流量；首轮只建基线；QPS 按真实间隔
// （trafficScreenMetrics.trafficDelta）；计数器回退=曲线断开重建。
let trafficBaseline: TrafficBaseline | null = null
const trafficError = ref(false)
const trafficSampled = ref(false)
// collecting=false 表示 Caddy 侧采集租约未生效（累计计数冻结）：此时不得把
// 冻结的累计当作实时流量，也不推进「累计」展示。
const trafficFrozen = ref(false)
const trafficTask = usePollingTask(async ({ signal, isCurrent }) => {
  const res = await request.get<APIResponse<{
    countries: Record<string, { attack: number; normal: number }>
    available?: boolean
    sample_n?: number
    collecting?: boolean
  }>>('/security/overview/threat-screen/traffic', { silent: true, signal })
  if (!isCurrent()) return
  if (res.data?.available === false) {
    trafficError.value = true
    trafficBaseline = null // 恢复可用后重建基线，避免把停机期差值当增量
    return
  }
  trafficError.value = false
  const sampleN = res.data?.sample_n ?? 1
  trafficSampled.value = sampleN > 1
  // 缺字段按「未冻结」处理（旧版 Caddy 插件无该字段）：可用时行为不变。
  const collecting = res.data?.collecting !== false
  trafficFrozen.value = !collecting
  const countries = res.data?.countries ?? {}
  const now = Date.now()
  const sample = trafficDelta(trafficBaseline, countries, now, sampleN)
  // 基线必须取 trafficDelta **归一后**的计数（缺失/非数值→0），
  // 不得从原始响应重建——否则缺字段时基线存 undefined，差分恒 NaN 且静默丢国。
  trafficBaseline = {
    counts: sample.counts,
    at: now,
    sampleN,
  }
  if (sample.baseline) {
    // 首轮/计数器回退/抽样比变化：只建基线；回退同时清空曲线
    if (sample.reset) {
      normalWindow.value = []
      attackWindow.value = []
    }
    return
  }
  if (!collecting) {
    // 采集冻结：计数器不推进，累计与曲线保持上一帧（避免把 0 增量画成断流）。
    return
  }
  // 采样关闭时用累计计数器生成地区聚合正常光流；开启逐请求事件流后，
  // 正常光流由 flowTask 消费事件生成，避免两条数据源重复画弧。
  if (flowSampleN.value === 0) threatMap?.setTraffic(sample.normalDeltas)
  normalTotal.value += sample.normalTotal
  attackTotal.value += sample.attackTotal
  normalWindow.value = [...normalWindow.value, sample.normalQps].slice(-NORMAL_WINDOW_MAX)
  attackWindow.value = [...attackWindow.value, sample.attackQps].slice(-NORMAL_WINDOW_MAX)
}, { interval: 1500, onError: () => { trafficError.value = true } })

function setWindow(hours: number): void {
  if (windowHours.value === hours) return
  windowHours.value = hours
  // 不把上一帧清成 null：全屏 KPI 瞬间归零会被误读为「无攻击/数据被清空」。
  // 保留旧帧并由 statsPending 标「切换中」，新窗口响应到达后自动替换。
  statsError.value = false
  void statsTask.run()
}

// 本站坐标 + 大屏模式（threat_screen_mode：map/globe）——/config 读一次。
// 不阻塞引擎/轮询启动（见 onMounted）。
const screenMode = ref('map')
// 采样配置单源：-1=自适应、0=关闭（全量/固定 2-64 已退役，存量值归一为 -1）。
const flowSampleN = ref(-1)
// 自适应档位（1 全量 / 4 / 8）；非自适应配置直接取配置值，0=关闭不申请逐请求采集。
const activeSampleN = ref(1)
const flowSampleLabel = computed(() => {
  if (flowSampleN.value === 0) return 'OFF'
  const n = activeSampleN.value
  return n <= 1 ? 'FULL' : `1/${n}`
})
const isGlobeMode = computed(() => screenMode.value === 'globe')
const serverLatLon: [number, number] = [0, 0]
const siteConfigured = ref(false)
// /config 读取失败是「未知」而非「未配置」：失败态必须与「未配置站点坐标」
// 区分并给出重试，否则运维会按错误结论去核对本已配置的坐标。
const configLoadFailed = ref(false)
async function loadServerCentroid(): Promise<void> {
  try {
    const res = await request.get<APIResponse<{ server_map_lat?: number; server_map_lon?: number; threat_screen_mode?: string; threat_traffic_sample_n?: number }>>('/config?_ts=' + Date.now(), { silent: true })
    screenMode.value = displayThreatScreenMode(res.data?.threat_screen_mode)
    const rawSample = res.data?.threat_traffic_sample_n ?? -1
    flowSampleN.value = normalizeTrafficSampleN(rawSample)
    // 自适应从全量起步，由事件流速率升/降档；关闭=0；全量=1。
    activeSampleN.value = flowSampleN.value === 0 ? 0 : 1
    acquireCollector()
    serverLatLon[0] = res.data?.server_map_lat ?? 0
    serverLatLon[1] = res.data?.server_map_lon ?? 0
    configLoadFailed.value = false
    siteConfigured.value = serverLatLon[0] !== 0 || serverLatLon[1] !== 0
    if (siteConfigured.value) {
      threatMap?.setServer([serverLatLon[1], serverLatLon[0]])
      tgtReadout.value = `${Math.abs(serverLatLon[0]).toFixed(2)}°${serverLatLon[0] >= 0 ? 'N' : 'S'} ${Math.abs(serverLatLon[1]).toFixed(2)}°${serverLatLon[1] >= 0 ? 'E' : 'W'}`
    } else {
      tgtReadout.value = '--'
    }
  } catch {
    // 配置读取失败：保持缺省（地图模式、本站未配置），但显性化为「读取失败」
    configLoadFailed.value = true
  }
}

// 配置重试：重读 /config 后必须联动引擎重装——地图/地球模式由配置决定，
// 只改 screenMode 会让 HUD（地球标题/竖扫特效/操作提示）宣告地球而舞台仍是
// 地图引擎。mountEngine 幂等（同模式直接返回），装载中则排队一次重装。
async function retryConfigLoad(): Promise<void> {
  await loadServerCentroid()
  if (!disposed) await mountEngine()
}

// ============ 左侧实时列表：安全日志最新 50 条快照 ============
const feedError = ref(false)
const feedTask = usePollingTask(async ({ signal, isCurrent }) => {
  const res = await request.get<APIResponse<{ events: FeedEvent[] }>>(
    `/security/events/feed?since_id=0&limit=${FEED_LIMIT}`,
    { silent: true, signal },
  )
  if (!isCurrent()) return
  feedError.value = false
  feedItems.value = [...(res.data?.events ?? [])].sort((a, b) => b.id - a.id).slice(0, FEED_LIMIT)
}, { interval: FEED_POLL_MS, onError: () => { feedError.value = true } })

// ============ 攻击弹框：安全日志按游标精确聚合（IP + 类型 + 动作） ============
let toastCursor = 0
let toastInitialized = false
let toastLastPollAt = 0
const toastTask = usePollingTask(async ({ signal, isCurrent }) => {
  const now = Date.now()
  // 页面冻结/长时间阻塞后游标可能落后数分钟；直接重新取基线，避免一次
  // 聚合大区间（400/s 上限也挡不住陈旧游标的扫描成本）。
  if (toastInitialized && toastLastPollAt > 0 && now - toastLastPollAt > TOAST_STALE_MS) {
    toastInitialized = false
    toastCursor = 0
  }
  const baseline = !toastInitialized
  const res = await request.get<APIResponse<{ groups?: ToastSummaryGroup[]; next_id?: number }>>(
    `/security/events/toast-summary?since_id=${toastCursor}&limit=50${baseline ? '&baseline=1' : ''}`,
    { silent: true, signal },
  )
  if (!isCurrent()) return
  toastLastPollAt = Date.now()
  const next = res.data?.next_id ?? toastCursor
  const groups = res.data?.groups ?? []
  // 首次调用只取当前高水位，不回放历史事件为弹框；空库也要标记已初始化，
  // 否则第一条真实攻击会被当成基线吞掉。
  if (!toastInitialized) {
    toastInitialized = true
  } else if (groups.length > 0) {
    pushAttackToasts(groups)
  }
  if (typeof next === 'number' && next <= 0 && toastCursor > 0) {
    // DB 重置/游标超前：下一轮重新取基线，避免把历史事件回放成弹框。
    toastInitialized = false
    toastCursor = 0
  } else {
    toastCursor = typeof next === 'number' && next >= 0 ? next : 0
  }
}, { interval: FEED_POLL_MS, onError: () => { /* 弹框不可用不阻断大屏 */ } })

// ============ 攻击光流：独立攻击流环形缓冲（采样只影响本流） ============
// 光流端点可用性位：攻击流/正常流失败此前被 onError 静默吞掉，
// 大屏只剩静态热力，运维无法区分「无流量」与「光流管线故障」——补显性横幅。
const flowError = ref(false)
const attackFlowError = ref(false)
// 环形缓冲溢出造成的永久丢事件数（服务端 gap_skipped）：攻击流与正常流同一
// 披露口径——只说明「有事件未送达」，不再与「加载失败」混为一谈。
const flowGap = ref(0)
const attackFlowGap = ref(0)
const collectorError = ref(false)
let attackFlowSince = 0
const attackFlowTask = usePollingTask(async ({ signal, isCurrent }) => {
  const res = await request.get<APIResponse<{ enabled?: boolean; events?: AttackFlowEvent[]; next_seq?: number; gap?: boolean; gap_skipped?: number }>>(
    `/security/overview/threat-screen/attack-flow?since=${attackFlowSince}&limit=1000`,
    { silent: true, signal },
  )
  if (!isCurrent()) return
  attackFlowError.value = false
  const data = res.data
  if (!data?.enabled) {
    attackFlowSince = 0
    attackFlowGap.value = 0
    return
  }
  attackFlowGap.value = data.gap_skipped ?? (data.gap === true ? 1 : 0)
  // 引擎尚在异步装载：不消费游标，下一轮重新拉取，否则首波爆发的攻击流
  // 会在 threatMap=null 时被静默丢弃（页面刚打开/模式切换后必现）。
  if (!threatMap) return
  const now = Date.now()
  const fresh = freshFlowEvents(data.events ?? [], now)
  for (const item of planFlowEvents(fresh, now)) {
    threatMap?.addArcForLocation(item.region, item.weight, item.tier)
  }
  attackFlowSince = nextFlowCursor(attackFlowSince, { enabled: true, next_seq: data.next_seq })
}, { interval: ATTACK_FLOW_POLL_MS, onError: () => { attackFlowError.value = true } })

const statsTask = usePollingTask(async ({ signal, isCurrent }) => {
  const res = await request.get<APIResponse<ThreatScreenStats>>(`/security/overview/threat-screen?hours=${windowHours.value}`, { silent: true, signal })
  if (!isCurrent()) return
  if (!res.data) throw new Error('threat-screen payload missing')
  if (res.data.hours !== windowHours.value) return
  stats.value = res.data
  statsError.value = false
  threatMap?.setCountries(Object.entries(res.data.countries ?? {}).map(([name, count]) => ({ name, count })))
  threatMap?.setProvinces(Object.entries(res.data.china_provinces ?? {}).map(([name, count]) => ({ name, count })))
}, {
  interval: STATS_POLL_MS,
  onError: () => { statsError.value = true },
})

// ============ 逐请求正常流量事件流（大屏打开时轮询；关闭后停止） ============
let flowSince = 0
let flowCursorEpoch = 0
let adaptiveStable = 0
let adaptiveLastSwitch = 0
// 正在累计确认的目标档位：必须跨轮持久化，否则「连续同向」永远只有 1 次
//（方向反转要靠它识别，丢失后自适应档位将永不切换）。
let adaptivePendingTarget = 0
const flowTask = usePollingTask(async ({ signal, isCurrent }) => {
  const cursorEpoch = flowCursorEpoch
  const res = await request.get<APIResponse<{ enabled?: boolean; events?: NormalFlowEvent[]; next_seq?: number; sample_n?: number; gap?: boolean; gap_skipped?: number }>>(
    `/security/overview/threat-screen/events?since=${flowSince}&limit=1000`,
    { silent: true, signal },
  )
  if (!isCurrent() || cursorEpoch !== flowCursorEpoch) return
  flowError.value = false
  const data = res.data
  if (!data?.enabled) {
    flowSince = 0
    flowGap.value = 0
    return
  }
  // 空洞与「加载失败」是两种信号：前者是环形缓冲溢出（事件永久丢失，光流
  // 仍连续推进），后者是端点不可用。混用一个旗标会让横幅把正常丢样报成故障。
  flowGap.value = data.gap_skipped ?? (data.gap === true ? 1 : 0)
  // 同攻击流：引擎未装载时不得推进游标，否则首轮正常流事件被丢弃。
  if (!threatMap) return
  const events = data.events ?? []
  const now = Date.now()
  // 正常流与攻击流同一计划：1-3 条逐条、4-8 合并粗光流、>8 合并更粗光流。
  // 是否聚合只看采样后条数；weight 只决定线宽/×N。预算超限自动扩大时间桶。
  const sampleFactor = data.sample_n && data.sample_n > 0 ? data.sample_n : Math.max(1, activeSampleN.value)
  const flowEvents = freshFlowEvents(events, now).map((ev) => ({ country: ev.country, province: ev.province, at: ev.at, weight: sampleFactor }))
  for (const item of planFlowEvents(flowEvents, now)) {
    threatMap?.addNormalArcForLocation(item.region, item.weight, item.tier)
  }
  flowSince = nextFlowCursor(flowSince, data)
  if (flowSampleN.value === -1 && activeSampleN.value > 0) {
    // events.length 已被当前采样因子缩小，先用服务端回报的 sample_n 还原真实
    // 速率（1/8 下 125 条不得被误判为低速）；换档需连续 2 次采样同向且距
    // 上次换档 ≥4s（滞回阈值在 utils/threatFlowRules 的自适应切换门内）。
    const observedRate = reconstructObservedRate(events.length, data.sample_n ?? 0, activeSampleN.value)
    const outcome = stepAdaptiveSample(
      { active: activeSampleN.value, stable: adaptiveStable, lastSwitch: adaptiveLastSwitch, pendingTarget: adaptivePendingTarget },
      observedRate,
      now,
    )
    adaptiveStable = outcome.stable
    adaptiveLastSwitch = outcome.lastSwitch
    adaptivePendingTarget = outcome.pendingTarget ?? 0
    if (outcome.changed) {
      activeSampleN.value = outcome.active
      acquireCollector()
    }
  }
}, { interval: 1000, onError: () => { flowError.value = true } })

// ============ 引擎装载（与配置并行，import 失败可重试） ============
const engineError = ref(false)
// 引擎未就绪（装载失败/尚未装载成功）时两条光流没有消费方：游标不能推进，
// 轮询会每秒重复拉取同一批 backlog（各最多 1000 条）。装载失败即暂停，
// 成功装载/恢复可见/取消手动暂停时按引擎状态恢复。
function pauseFlowStreamsForEngine(): void {
  attackFlowTask.pause()
  flowTask.pause()
}
function resumeFlowStreamsForEngine(): void {
  if (engineError.value || !threatMap || paused.value || screenHidden) return
  attackFlowTask.resume()
  flowTask.resume()
}
let mountedMode: 'map' | 'globe' | null = null
let engineMounting = false
let remountRequested = false

async function mountEngine(): Promise<void> {
  if (disposed || !mapHost.value) return
  if (engineMounting) {
    remountRequested = true
    return
  }
  const mode: 'map' | 'globe' = screenMode.value === 'globe' ? 'globe' : 'map'
  if (threatMap && mountedMode === mode) {
    // 同模式重入直接返回。本站坐标由 loadServerCentroid 在 /config 到达时
    // 直接补发；此处再发一次会让 4s 兜底定时器对已装载引擎重复 setServer，
    // 3D 地球表现为自动旋转数秒后「往回转一下」（相机动画回本站坐标）。
    return
  }
  engineMounting = true
  try {
    if (threatMap) {
      threatMap.dispose()
      threatMap = null
      mountedMode = null
    }
    // 引擎重装（地图/地球切换、失败重试）后新实例从世界视角开始：复位下钻态，
    // 否则「返回世界」按钮与 ESC 仍指向上一个引擎的下钻国。
    zoomedName.value = null
    engineError.value = false
    const create: (host: HTMLElement, options?: ThreatSceneOptions) => ThreatScene = mode === 'globe'
      ? (await import('@/utils/threatGlobe')).createThreatGlobe
      : (await import('@/utils/threatScene')).createThreatScene
    if (disposed || !mapHost.value) return
    const engine = create(mapHost.value, {
      serverCentroid: siteConfigured.value ? [serverLatLon[1], serverLatLon[0]] : null,
      siteConfigured: siteConfigured.value,
      // 原硬编码 ['中国'] 使非中国下钻全部被 drillCountryAllowed 拦截
      // （静默无动作），与 admin1Provinces「全球省级行政界」/ admin1Loader「首次
      // 下钻才拉取」及全量国家省层钉测冲突。省略 = 不限国家（threatShared 缺省语义）。
      onDrillChange: (name: string | null) => { zoomedName.value = name },
      onProvinceLoadError: () => { ElMessage.warning('省界数据加载失败，本次下钻未展开；可再次点击国家重试') },
    })
    threatMap = engine
    mountedMode = mode
    ;(window as unknown as Record<string, unknown>).__threatScene = engine
    // 首屏竞态：statsTask 与引擎并行，统计先返回时 threatMap 尚未创建，
    // setCountries 无处落地；引擎创建后必须回放当前快照，否则球面热力
    // 永远是 0（图例/右栏有数、球面无色）。
    if (stats.value) {
      engine.setCountries(Object.entries(stats.value.countries ?? {}).map(([name, count]) => ({ name, count })))
      engine.setProvinces(Object.entries(stats.value.china_provinces ?? {}).map(([name, count]) => ({ name, count })))
    }
    applyMapPause()
    if (siteConfigured.value) engine.setServer([serverLatLon[1], serverLatLon[0]])
    // 引擎就绪：恢复因装载期间/失败而暂停的两条光流（手动暂停/页面隐藏时不恢复）。
    resumeFlowStreamsForEngine()
  } catch (error: unknown) {
    // 动态 chunk 404（发布中途旧页面）/网络失败：显性错误态 + 重试入口，
    // 数据轮询不受影响。
    console.error('threat screen engine load failed', error)
    engineError.value = true
    mountedMode = null
    // 无引擎则光流无消费方——暂停轮询，避免每秒重复拉同一批 backlog。
    pauseFlowStreamsForEngine()
  } finally {
    engineMounting = false
    if (remountRequested && !disposed) {
      remountRequested = false
      void mountEngine()
    }
  }
}

// 页面隐藏也按暂停渲染：与手动暂停取或，恢复可见后回到手动态。
let screenHidden = false
function applyMapPause(): void {
  threatMap?.setPaused(paused.value || screenHidden)
}

function togglePause(): void {
  paused.value = !paused.value
  if (paused.value) {
    feedTask.pause()
    toastTask.pause()
    attackFlowTask.pause()
    statsTask.pause()
    trafficTask.pause()
    flowTask.pause()
    // 暂停=停服务端采集：心跳仍在（时钟要转），租约立即释放，Caddy 不再逐请求
    // 计数——否则「暂停」只冻结画面，服务端开销照旧。
    releaseCollector()
  } else {
    // 暂停期间可能积累大量安全事件；恢复时重新取基线，避免一次性扫描/回放。
    toastCursor = 0
    toastInitialized = false
    toastLastPollAt = 0
    // 暂停期间的计数器差值不能当成本间隔增量：恢复首轮只重建
    // 基线，QPS 曲线从下一轮干净间隔开始，避免被暂停时长摊薄。
    trafficBaseline = null
    feedTask.resume()
    toastTask.resume()
    statsTask.resume()
    trafficTask.resume()
    // 引擎装载失败期间光流保持暂停（恢复后也不空转）；正常时恢复轮询。
    resumeFlowStreamsForEngine()
    acquireCollector()
  }
  applyMapPause()
}

function exitScreen(): void {
  authStore.setCurrentPage('security-overview')
}

function backToWorld(): void {
  if (!zoomedName.value) return
  zoomedName.value = null
  threatMap?.zoomOut()
}

function resetView(): void {
  zoomedName.value = null
  threatMap?.resetView()
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Escape' || event.altKey || event.ctrlKey || event.metaKey) return
  if (zoomedName.value) backToWorld()
  else exitScreen()
}

// 大屏流量采集租约：只在屏幕打开时让 Caddy 计数；关闭/崩溃由 TTL 兜底。
function newCollectorLeaseId(): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID()
  } catch { /* 非安全上下文可能抛 SecurityError */ }
  return `threat-${Date.now()}-${Math.random().toString(36).slice(2)}`
}
const collectorLeaseId = newCollectorLeaseId()
const COLLECTOR_TTL_MS = 30000
const COLLECTOR_HEARTBEAT_MS = 10000

function acquireCollector(): void {
  // 暂停期间不续租（心跳照常触发但直接返回）：租约由 togglePause/onHidden 释放。
  if (disposed || paused.value) return
  request.post(
    '/security/overview/threat-screen/collector',
    { lease_id: collectorLeaseId, ttl_ms: COLLECTOR_TTL_MS, sample_n: activeSampleN.value }, // -1 自适应由 activeSampleN 决定
    { silent: true },
  ).then(() => { collectorError.value = false }).catch(() => { collectorError.value = true })
}

function releaseCollector(): void {
  request.delete('/security/overview/threat-screen/collector', {
    data: { lease_id: collectorLeaseId },
    silent: true,
  }).catch(() => { /* TTL 兜底 */ })
}

// hidden 停摆/visible 恢复纳管单源：时钟、弧光冲刷、采集租约
// 心跳三类间隔随页面可见性启停；hidden 时同步释放采集租约——此前仅暂停渲
// 染，心跳在后台持续续租让 Caddy 空计数。
const screenLoop = createVisibilityIntervals({
  intervals: [
    { tick: tickClock, ms: 1000, immediate: true },
    { tick: acquireCollector, ms: COLLECTOR_HEARTBEAT_MS, immediate: true },
  ],
  onHidden: () => {
    screenHidden = true
    applyMapPause()
    releaseCollector()
  },
  onVisible: () => {
    screenHidden = false
    // 后台节流可能让租约过期并清空后端序号；恢复后从 0 追赶，避免旧高水位
    // 永久过滤新事件。弹框游标同样归零，首次摘要只取高水位、不回放历史。
    flowCursorEpoch++
    flowSince = 0
    attackFlowSince = 0
    // 后台停摆时长不参与 QPS 差分（与手动暂停恢复同口径）。
    trafficBaseline = null
    toastCursor = 0
    toastInitialized = false
    toastLastPollAt = 0
    applyMapPause()
    // 引擎失败期间光流被暂停（visibility 监听已摘除），恢复可见时按引擎状态恢复；
    // 引擎正常时与 polling composable 的可见性恢复同路径，run 去重不重复执行。
    resumeFlowStreamsForEngine()
  },
})

let configTimeout = 0

onMounted(() => {
  // 首屏优先：数据轮询/时钟/引擎并行启动，装饰性 /config 不再阻塞（原实现
  // await /config → await import → 才 start 三个轮询；30s 全局超时时大屏空转）。
  window.addEventListener('keydown', onKeydown)
  screenLoop.start()
  feedTask.start()
  toastTask.start()
  attackFlowTask.start()
  statsTask.start()
  trafficTask.start()
  flowTask.start()
  void Promise.allSettled([feedTask.run(), toastTask.run(), attackFlowTask.run(), statsTask.run(), trafficTask.run(), flowTask.run()])
  // 配置最多等 4s（模式/本站坐标）；到达或超时都立即装载引擎。配置晚到且
  // 模式不同则 mountEngine 内部重装。
  const configPromise = loadServerCentroid().then(() => {
    if (!disposed) void mountEngine()
  })
  // 到达即装；4s 超时兜底（mountEngine 幂等：已装载同模式直接返回）
  void configPromise
  configTimeout = window.setTimeout(() => {
    if (!disposed) void mountEngine()
  }, 4000)
})

onBeforeUnmount(() => {
  disposed = true
  window.removeEventListener('keydown', onKeydown)
  screenLoop.stop()
  clearTimeout(configTimeout)
  configTimeout = 0
  releaseCollector()
  for (const t of toastTimers.values()) clearTimeout(t)
  toastTimers.clear()
  feedTask.stop()
  toastTask.stop()
  attackFlowTask.stop()
  statsTask.stop()
  trafficTask.stop()
  flowTask.stop()
  threatMap?.dispose()
  threatMap = null
  mountedMode = null
  // 调试句柄不钉住引擎对象图
  delete (window as unknown as Record<string, unknown>).__threatScene
})

</script>

<style scoped>
/* ============ Threat Wall 版式（参考实现移植，数据源本仓） ============ */
.threat-screen {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: grid;
  grid-template-columns: 320px minmax(0, 1fr) 320px;
  grid-template-rows: auto minmax(0, 1fr) 176px;
  gap: 12px;
  padding: 12px 16px;
  background:
    radial-gradient(ellipse 60% 50% at 50% 38%, rgba(30, 90, 200, 0.28), transparent 70%),
    radial-gradient(ellipse 35% 40% at 0% 100%, rgba(255, 77, 77, 0.07), transparent 70%),
    #020713;
  color: #e2ecff;
  font-family: 'Noto Sans SC', 'PingFang SC', 'Microsoft YaHei', 'Helvetica Neue', sans-serif;
  font-size: 13px;
  line-height: 1.45;
  overflow: hidden;
}
.threat-screen::before {
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;
  z-index: 50;
  background: repeating-linear-gradient(0deg, rgba(255, 255, 255, 0.025) 0 1px, transparent 1px 3px);
  mix-blend-mode: overlay;
}
.threat-screen::after {
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;
  z-index: 51;
  background: linear-gradient(180deg, transparent 0%, rgba(58, 209, 255, 0.05) 48%, rgba(58, 209, 255, 0.09) 50%, transparent 52%);
  background-size: 100% 300%;
  animation: tw-sweep 9s linear infinite;
}
@keyframes tw-sweep { from { background-position: 0 100%; } to { background-position: 0 -200%; } }
/* 垂直慢扫描仅地球模式（地图版无全局扫描特效——用户裁定 2026-10-17） */
.threat-screen:not(.mode-globe)::after { display: none; }

.topbar { grid-column: 1 / -1; }
.panel-left { grid-column: 1; grid-row: 2; }
.globe-wrap { grid-column: 2; grid-row: 2; }
.panel-right { grid-column: 3; grid-row: 2; }
.charts-row { grid-column: 1 / -1; grid-row: 3; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

/* ---------- HUD 面板（角括号） ---------- */
.hud {
  position: relative;
  --corner: 12px;
  --accent-c: #3ad1ff;
  background:
    linear-gradient(var(--accent-c), var(--accent-c)) left top / var(--corner) 2px no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) left top / 2px var(--corner) no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) right top / var(--corner) 2px no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) right top / 2px var(--corner) no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) left bottom / var(--corner) 2px no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) left bottom / 2px var(--corner) no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) right bottom / var(--corner) 2px no-repeat,
    linear-gradient(var(--accent-c), var(--accent-c)) right bottom / 2px var(--corner) no-repeat,
    linear-gradient(180deg, rgba(10, 30, 70, 0.8), rgba(5, 16, 40, 0.82));
  box-shadow: inset 0 0 0 1px rgba(80, 160, 255, 0.16), inset 0 0 40px rgba(42, 123, 255, 0.06);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}

/* ---------- 顶栏 ---------- */
.topbar { display: flex; align-items: center; gap: 24px; padding: 10px 18px; }
.brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
.brand-icon { position: relative; width: 42px; height: 42px; flex: none; display: grid; place-items: center; color: #3ad1ff; }
.brand-icon svg.shield { width: 22px; height: 22px; filter: drop-shadow(0 0 8px rgba(58, 209, 255, 0.8)); }
.brand-icon svg.orbit { position: absolute; inset: 0; width: 100%; height: 100%; animation: tw-spin 8s linear infinite; }
@keyframes tw-spin { to { transform: rotate(360deg); } }
.glitch {
  position: relative;
  font-size: 24px; font-weight: 700; letter-spacing: 0.12em; line-height: 1.1;
  white-space: nowrap;
  background: linear-gradient(180deg, #ffffff 20%, #9fdcff 100%);
  -webkit-background-clip: text; background-clip: text; color: transparent;
  text-shadow: 0 0 24px rgba(58, 209, 255, 0.35);
}
.glitch::before, .glitch::after {
  content: attr(data-text); position: absolute; inset: 0;
  -webkit-background-clip: text; background-clip: text;
  opacity: 0; pointer-events: none;
}
.glitch::before { color: #ff3b6b; animation: glitch-a 7s infinite steps(1); }
.glitch::after { color: #3ad1ff; animation: glitch-b 7s infinite steps(1); }
@keyframes glitch-a {
  0%, 92%, 100% { opacity: 0; transform: none; clip-path: none; }
  93% { opacity: 0.8; transform: translate(-2px, 0); clip-path: inset(10% 0 55% 0); }
  95% { opacity: 0.8; transform: translate(2px, 0); clip-path: inset(60% 0 8% 0); }
  97% { opacity: 0.6; transform: translate(-1px, 0); clip-path: inset(35% 0 35% 0); }
}
@keyframes glitch-b {
  0%, 92%, 100% { opacity: 0; transform: none; clip-path: none; }
  94% { opacity: 0.8; transform: translate(2px, 0); clip-path: inset(50% 0 20% 0); }
  96% { opacity: 0.7; transform: translate(-2px, 0); clip-path: inset(5% 0 70% 0); }
}
.brand p { font-size: 11px; color: #8ea7d6; letter-spacing: 0.06em; display: flex; gap: 10px; align-items: center; white-space: nowrap; margin-top: 2px; }
.brand p time { color: #3ad1ff; font-size: 13px; }
.clock-date { color: #7d93b8; font-size: 13px; font-variant-numeric: tabular-nums; }

.kpis { flex: 1; display: flex; justify-content: center; min-width: 0; }
.kpi { position: relative; flex: none; display: flex; flex-direction: column; gap: 3px; padding: 2px 26px; }
.kpi + .kpi::before {
  content: ''; position: absolute; left: 0; top: 10%; bottom: 10%; width: 1px;
  background: linear-gradient(180deg, transparent, rgba(80, 170, 255, 0.45), transparent);
}
.kpi-value {
  font-size: 32px; font-weight: 700; line-height: 1;
  color: #ffd166; font-variant-numeric: tabular-nums;
  text-shadow: 0 0 16px rgba(255, 159, 28, 0.55), 0 0 2px rgba(255, 209, 102, 0.9);
}
.kpi-value.cool { color: #8fe6ff; text-shadow: 0 0 16px rgba(58, 209, 255, 0.55); }
.kpi-label { font-size: 11px; color: #8ea7d6; letter-spacing: 0.04em; white-space: nowrap; }

.actions { display: flex; gap: 8px; flex: none; align-items: center; }
.window-switch { display: inline-flex; border: 1px solid rgba(58, 209, 255, 0.22); border-radius: 6px; overflow: hidden; }
.window-btn { appearance: none; border: 0; background: transparent; color: #7d93b8; font: 11px/1 mono, monospace; padding: 7px 9px; cursor: pointer; }
.window-btn + .window-btn { border-left: 1px solid rgba(58, 209, 255, 0.18); }
.window-btn[aria-pressed='true'] { color: #03101f; background: #3ad1ff; }
@media (prefers-reduced-motion: reduce) {
  .threat-screen::before, .threat-screen::after { animation: none !important; }
  .hud { backdrop-filter: none; }
  .glitch, .live-chip i { animation: none !important; }
}
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 12px;
  background: linear-gradient(180deg, rgba(58, 209, 255, 0.1), rgba(58, 209, 255, 0.02));
  border: 1px solid rgba(80, 170, 255, 0.45);
  clip-path: polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px);
  color: #e2ecff; font-size: 12px; cursor: pointer;
  transition: background 0.15s, color 0.15s, box-shadow 0.15s;
}
.btn svg { width: 13px; height: 13px; }
.btn:hover { background: rgba(58, 209, 255, 0.2); color: #fff; box-shadow: 0 0 18px rgba(58, 209, 255, 0.35) inset; }
.btn[aria-pressed='true'] { color: #3ad1ff; background: rgba(58, 209, 255, 0.18); }

/* ---------- 面板 ---------- */
.panel { display: flex; flex-direction: column; min-height: 0; min-width: 0; }
.panel-head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 11px 14px 9px;
  border-bottom: 1px solid rgba(80, 160, 255, 0.16);
  background: linear-gradient(90deg, rgba(58, 209, 255, 0.1), transparent 60%);
}
.panel-head h2 { font-size: 13px; font-weight: 500; letter-spacing: 0.1em; display: flex; align-items: baseline; gap: 8px; margin: 0; }
.panel-head h2 .en { font-family: 'Share Tech Mono', ui-monospace, 'SF Mono', Menlo, monospace; font-size: 10px; color: #56709f; letter-spacing: 0.12em; }
.panel-head .meta { font-size: 11px; color: #8ea7d6; white-space: nowrap; }
.panel-head .meta b { font-size: 16px; color: #ffd166; font-weight: 700; }
.live-chip { display: inline-flex; align-items: center; gap: 6px; font-family: 'Share Tech Mono', ui-monospace, monospace; font-size: 10px; letter-spacing: 0.15em; color: #ff4d5e; }
.live-chip i { width: 7px; height: 7px; border-radius: 50%; background: #ff4d5e; animation: tw-pulse 1.4s ease-out infinite; }
@keyframes tw-pulse { 0% { box-shadow: 0 0 0 0 rgba(255, 77, 94, 0.7); } 100% { box-shadow: 0 0 0 9px rgba(255, 77, 94, 0); } }
.is-paused .live-chip { color: #56709f; }
.is-paused .live-chip i { animation: none; background: #56709f; }

/* ---------- 等级筛选 ---------- */
.filters { display: flex; gap: 6px; padding: 8px 10px 0; flex-wrap: wrap; }
.chip {
  padding: 3px 10px; border-radius: 2px; cursor: pointer;
  background: rgba(58, 209, 255, 0.05); border: 1px solid rgba(80, 160, 255, 0.16);
  font-size: 11px; color: #8ea7d6;
  display: inline-flex; gap: 5px; align-items: center;
  transition: all 0.15s;
}
.chip b { font-size: 13px; color: #e2ecff; }
.chip:hover { border-color: rgba(80, 170, 255, 0.45); color: #e2ecff; }
.chip[aria-pressed='true'] { border-color: #3ad1ff; color: #3ad1ff; background: rgba(58, 209, 255, 0.12); }

/* ---------- 事件流 ---------- */
.events { flex: 1; min-height: 0; overflow-y: auto; padding: 8px 10px 10px; display: flex; flex-direction: column; gap: 6px; scrollbar-width: thin; scrollbar-color: rgba(80, 160, 255, 0.3) transparent; }
.events-inner { display: flex; flex-direction: column; gap: 6px; }
.event {
  position: relative; overflow: hidden; flex: none;
  display: flex; flex-direction: column; gap: 3px;
  padding: 8px 10px;
  background: linear-gradient(90deg, rgba(20, 44, 92, 0.75), rgba(10, 26, 60, 0.55));
  border: 1px solid rgba(80, 160, 255, 0.12);
  transition: border-color 0.15s, background 0.15s;
}
.event::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--sev); box-shadow: 0 0 10px var(--sev); }
.event[data-sev='high'] { --sev: #ff4d5e; }
.event[data-sev='mid'] { --sev: #ffb020; }
.event[data-sev='low'] { --sev: #3ddc84; }
.event:hover { border-color: rgba(80, 170, 255, 0.45); }
.ev-top { display: flex; justify-content: flex-start; align-items: center; gap: 10px; font-size: 11px; color: #56709f; font-variant-numeric: tabular-nums; }
.ev-top .act { margin-left: auto; }
.sev { font-size: 10px; line-height: 1; padding: 3px 6px; border: 1px solid; }
.sev-high { color: #ff4d5e; border-color: rgba(255, 77, 94, 0.5); background: rgba(255, 77, 94, 0.12); }
.sev-mid { color: #ffb020; border-color: rgba(255, 176, 32, 0.5); background: rgba(255, 176, 32, 0.12); }
.sev-low { color: #3ddc84; border-color: rgba(61, 220, 132, 0.5); background: rgba(61, 220, 132, 0.12); }
.ev-main { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
.ev-ip { font-family: 'Share Tech Mono', ui-monospace, monospace; font-size: 15px; color: #fff; flex: none; text-shadow: 0 0 8px rgba(58, 209, 255, 0.4); }
.ev-geo { color: #8ea7d6; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ev-type { font-size: 11px; color: #8ea7d6; display: flex; gap: 6px; align-items: center; min-width: 0; }
.ev-type b { font-weight: 500; }
.ev-type .st { margin-left: auto; color: #56709f; font-size: 10px; letter-spacing: 0.08em; }
.empty { color: #56709f; text-align: center; padding: 24px 0; font-size: 12px; }

/* ---------- 中央舞台 ---------- */
.globe-wrap {
  overflow: hidden; touch-action: none; min-height: 0;
  background:
    linear-gradient(rgba(58, 209, 255, 0.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(58, 209, 255, 0.045) 1px, transparent 1px),
    radial-gradient(ellipse 60% 50% at 50% 40%, rgba(30, 90, 200, 0.22), transparent 75%),
    #030a1c;
  background-size: 64px 64px, 64px 64px, auto, auto;
}
.stage-mount { position: absolute; inset: 0; }
.vignette {
  position: absolute; inset: 0; pointer-events: none; z-index: 1;
  background: radial-gradient(ellipse 72% 68% at 50% 50%, transparent 55%, rgba(1, 4, 12, 0.85) 100%);
}

.hud-tl { position: absolute; top: 14px; left: 16px; z-index: 2; pointer-events: none; display: grid; gap: 4px; }
.hud-tl .title { font-family: 'Share Tech Mono', ui-monospace, monospace; font-size: 12px; letter-spacing: 0.22em; color: #3ad1ff; display: flex; align-items: center; gap: 8px; }
.hud-tl .title i { width: 22px; height: 1px; background: #3ad1ff; box-shadow: 0 0 6px #3ad1ff; }
.hud-tl .readout { font-family: 'Share Tech Mono', ui-monospace, monospace; font-size: 11px; color: #56709f; letter-spacing: 0.06em; }
.hud-tl .readout b { color: #8ea7d6; font-weight: 400; }
.hud-tr { position: absolute; top: 14px; right: 16px; z-index: 2; pointer-events: none; display: grid; gap: 7px; justify-items: end; font-size: 11px; color: #8ea7d6; }
.hud-tr .row { display: flex; align-items: center; gap: 8px; }
.legend-ramp { width: 72px; height: 4px; background: linear-gradient(90deg, #ff9f1c, #ff4d4d); box-shadow: 0 0 10px rgba(255, 106, 61, 0.6); }
.legend-arc { width: 26px; height: 2px; background: linear-gradient(90deg, transparent, #ff9f1c, #fff3c4); box-shadow: 0 0 6px #ff9f1c; }
.legend-arc.normal { background: linear-gradient(90deg, transparent, #38bdf8, #e0f7ff); box-shadow: 0 0 6px #38bdf8; }

.back-btn { position: absolute; z-index: 4; bottom: 52px; left: 50%; transform: translateX(-50%); }
.hint { position: absolute; z-index: 2; right: 16px; bottom: 44px; font-size: 11px; color: #56709f; pointer-events: none; }

.toasts { position: absolute; z-index: 7; top: 14px; left: 50%; transform: translateX(-50%); display: grid; gap: 6px; justify-items: center; pointer-events: none; width: min(460px, calc(100% - 32px)); }
.toast {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 14px;
  background: linear-gradient(90deg, rgba(255, 77, 94, 0.22), rgba(10, 20, 48, 0.9) 60%);
  border: 1px solid rgba(255, 77, 94, 0.55);
  box-shadow: 0 0 24px rgba(255, 77, 94, 0.25);
  clip-path: polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px);
  font-size: 12px; white-space: nowrap; max-width: 100%;
}
.toast svg { width: 16px; height: 16px; color: #ff4d5e; flex: none; }
.toast.sev-low { background: linear-gradient(90deg, rgba(61, 220, 132, 0.18), rgba(10, 20, 48, 0.9) 60%); border-color: rgba(61, 220, 132, 0.45); box-shadow: 0 0 24px rgba(61, 220, 132, 0.18); }
.toast b { font-size: 14px; letter-spacing: 0.1em; color: #e2ecff; }
.toast .ip { font-family: 'Share Tech Mono', ui-monospace, monospace; color: #fff; }
.toast .dim { color: #8ea7d6; overflow: hidden; text-overflow: ellipsis; }
.toast .agg { font: 11px/1 ui-monospace, monospace; color: #ffd166; border: 1px solid rgba(255, 209, 102, 0.45); padding: 2px 4px; }
.toast-enter-active { transition: all 0.35s cubic-bezier(0.16, 1, 0.3, 1); }
.toast-leave-active { transition: all 0.4s ease; position: absolute; }
.toast-leave-to { opacity: 0; transform: translateY(-8px) scale(0.96); }
.toast-enter-from { opacity: 0; transform: translateY(-14px) scale(0.96); }
.toast-move { transition: transform 0.35s ease; }


/* 空态/错误 */
.empty-state {
  position: absolute;
  left: 50%;
  top: 16%;
  transform: translateX(-50%);
  padding: 12px 30px;
  border-radius: 2px;
  border: 1px solid rgba(80, 160, 255, 0.3);
  background: rgba(3, 10, 28, 0.8);
  color: #8ea7d6;
  font-size: 15px;
  letter-spacing: 3px;
  z-index: 4;
}
/* 错误/信息条堆叠区：置顶居中、位于攻击弹框（.toasts z-index 7）之下，
   默认点击穿透（条带自身不遮挡其下弹框/按钮），仅重试按钮恢复可点。 */
.error-stack {
  position: absolute; left: 50%; top: 8px; transform: translateX(-50%);
  display: flex; flex-direction: column; align-items: center; gap: 4px; z-index: 6;
  pointer-events: none; max-width: min(720px, calc(100% - 32px));
}
.error-stack .error-retry { pointer-events: auto; }
.error-banner {
  padding: 4px 14px; border: 1px solid rgba(255, 77, 94, 0.5);
  background: rgba(255, 77, 94, 0.15); color: #ff8f9a; font-size: 12px;
}
.error-retry { margin-left: 8px; padding: 1px 8px; font-size: 11px; }
.live-chip.is-error { color: #ffb020; }
.live-chip.is-error i { animation: none; background: #ffb020; }

/* ---------- 右列统计 ---------- */
.stats { flex: 1; min-height: 0; overflow-y: auto; scrollbar-width: thin; scrollbar-color: rgba(80, 160, 255, 0.3) transparent; }
.stat-section { padding: 10px 14px; border-bottom: 1px solid rgba(80, 160, 255, 0.16); }
.stat-section:last-child { border-bottom: 0; }
.stat-title { display: flex; justify-content: space-between; align-items: baseline; font-size: 12px; color: #8ea7d6; letter-spacing: 0.08em; margin-bottom: 6px; }
.stat-title .n { font-size: 20px; color: #ffd166; font-weight: 700; line-height: 1; }

.overview-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 7px 14px; }
.ov-item { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.ov-item span { font-size: 11px; color: #8ea7d6; }
.ov-item b { font-size: 16px; color: #e2ecff; font-variant-numeric: tabular-nums; white-space: nowrap; }
.ov-item em { font-style: normal; font-size: 10px; color: #56709f; }
.ov-switch-hint { font-style: normal; font-size: 11px; color: #ffd166; letter-spacing: 0.04em; }

.stat-tabs { display: flex; gap: 6px; margin-bottom: 7px; }
.stat-tab {
  padding: 3px 9px; border: 1px solid rgba(80, 160, 255, 0.28);
  background: transparent; color: #8ea7d6; font-size: 11px; cursor: pointer;
}
.stat-tab[aria-selected='true'] { background: #3ad1ff; border-color: #3ad1ff; color: #03101f; font-weight: 700; }

.panel-footer {
  flex: none; display: flex; align-items: baseline; gap: 8px;
  padding: 8px 14px; border-top: 1px solid rgba(80, 160, 255, 0.16);
  font-size: 11px; color: #8ea7d6;
}
.panel-footer b { margin-left: auto; font-size: 16px; color: #e2ecff; font-variant-numeric: tabular-nums; }
.panel-footer em { font-style: normal; font-size: 10px; color: #56709f; }

.rules { display: grid; gap: 9px; margin: 0; padding: 0; list-style: none; }
.rule { display: grid; grid-template-columns: 1fr auto; gap: 4px 10px; font-size: 12px; align-items: baseline; }
.rule-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rule .cnt { font-weight: 700; font-size: 15px; font-variant-numeric: tabular-nums; color: #e2ecff; }
.rule-bar { grid-column: 1 / -1; height: 4px; background: rgba(80, 160, 255, 0.1); overflow: hidden; }
.rule-bar i {
  display: block; height: 100%;
  background: repeating-linear-gradient(90deg, #ff9f1c 0 3px, transparent 3px 4.5px);
  box-shadow: 0 0 8px rgba(255, 159, 28, 0.5);
  transition: width 0.6s ease;
}
.country-bars .rule-bar i { background: linear-gradient(90deg, #ffd166, #ff4d4d); box-shadow: 0 0 8px rgba(255, 106, 61, 0.5); }

.donut-row { display: flex; align-items: center; gap: 12px; }
.donut { position: relative; width: 96px; height: 96px; flex: none; }
.donut svg { position: absolute; inset: 0; width: 100%; height: 100%; }
.donut-track { fill: none; stroke: rgba(80, 160, 255, 0.1); stroke-width: 2.5; }
.donut-seg { fill: none; stroke-width: 2.5; }
.donut-center { position: absolute; inset: 0; display: grid; place-items: center; align-content: center; pointer-events: none; line-height: 1; }
.donut-center b { font-size: 24px; font-weight: 700; color: #ffd166; }
.donut-center span { font-size: 11px; color: #8ea7d6; letter-spacing: 0.12em; margin-top: 3px; }
.type-legend { flex: 1; min-width: 0; display: grid; gap: 5px; margin: 0; padding: 0; list-style: none; }
.type-legend li { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.type-legend .sw { width: 8px; height: 8px; flex: none; transform: rotate(45deg); }
.type-legend .cnt { margin-left: auto; font-weight: 700; font-size: 16px; font-variant-numeric: tabular-nums; color: #e2ecff; }

/* ---------- 底部双图 ---------- */
/* position:relative 为 .traffic-legend 的定位锚点：无定位时绝对定位元素上溯到
   .panel（hud），top:8px 会压住 .panel-head 的 .meta 文字。 */
.chart-box { position: relative; flex: 1; min-height: 0; padding: 6px 14px 4px; display: flex; flex-direction: column; }
.timeline-svg, .normal-spark { width: 100%; flex: 1; min-height: 0; display: block; }
.timeline-stroke { fill: none; stroke: #ff7a2f; stroke-width: 1.6; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 4px rgba(255, 122, 47, 0.5)); }
.timeline-fill { fill: rgba(255, 122, 47, 0.12); }
.timeline-slot { fill: transparent; }
.timeline-slot:hover { fill: rgba(58, 209, 255, 0.08); }
.timeline-axis { display: flex; justify-content: space-between; font-size: 10px; color: #56709f; padding-top: 2px; font-variant-numeric: tabular-nums; }
.normal-stroke { fill: none; stroke: #38bdf8; stroke-width: 1.6; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 4px rgba(56, 189, 248, 0.5)); }
.normal-fill { fill: rgba(56, 189, 248, 0.10); }
.attack-stroke { fill: none; stroke: #e25454; stroke-width: 1.4; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 4px rgba(226, 84, 84, 0.5)); }
.attack-qps { color: #ff7a7a; }
.traffic-legend { position: absolute; right: 10px; top: 8px; display: flex; align-items: center; gap: 6px; font: 10px/1 mono, monospace; color: #8ea7d6; }
.traffic-legend .sw { width: 8px; height: 2px; display: inline-block; }
.traffic-legend .sw.normal { background: #38bdf8; }
.traffic-legend .sw.attack { background: #e25454; margin-left: 6px; }
.act { margin-left: auto; font: 10px/1 mono, monospace; padding: 2px 5px; border-radius: 3px; border: 1px solid; }
.act-blocked { color: #ff8a8a; border-color: rgba(226, 84, 84, 0.5); background: rgba(226, 84, 84, 0.12); }
.act-logged { color: #ffd166; border-color: rgba(255, 209, 102, 0.45); background: rgba(255, 209, 102, 0.08); }
.site-unset { color: #ffd166; }

/* 地图引擎根容器适配（引擎内部自管 canvas/标签层） */
.stage-mount :deep(canvas) { position: absolute !important; inset: 0; outline: none; display: block; }

/* 过渡 */
.fade-enter-active, .fade-leave-active { transition: opacity 0.3s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
.feed-enter-active { transition: all 0.5s ease; }
.feed-enter-from { opacity: 0; transform: translateX(-18px); }

/* 响应式 */
@media (max-width: 1280px) {
  .threat-screen { grid-template-columns: 280px minmax(0, 1fr) 290px; }
  .kpi { padding: 2px 16px; }
  .kpi-value { font-size: 28px; }
}
@media (max-width: 1080px) {
  .actions .btn-text { display: none; }
  .kpi-label { font-size: 10px; }
}
</style>
