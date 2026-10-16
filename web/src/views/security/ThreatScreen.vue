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
      </div>
      <div class="hud-tr" aria-label="图例">
        <div class="row">攻击弹道 <span class="legend-arc"></span></div>
        <div class="row">国家命中 少 <span class="legend-ramp"></span> 多</div>
      </div>

      <transition name="fade">
        <button v-if="zoomedName" type="button" class="btn back-btn" @click="backToWorld">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
          <span class="btn-text">返回世界</span>
        </button>
      </transition>

      <!-- 攻击事件弹框：feed 新事件到达即弹（最多 3 条，4.5s 淡出） -->
      <transition-group name="toast" tag="div" class="toasts">
        <div v-for="t in attackToasts" :key="t.id" class="toast" :class="t.action === 'blocked' ? 'sev-high' : 'sev-low'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4.5 5.4v6.1c0 4.6 3.2 8.6 7.5 9.9 4.3-1.3 7.5-5.3 7.5-9.9V5.4Z"/><path d="m9 12 2 2 4-4.5"/></svg>
          <b>{{ t.country }}</b>
          <span class="ip">{{ t.ip }}</span>
          <span class="dim">{{ t.stage }} · {{ t.durationMs }}ms</span>
          <span class="sev" :class="t.action === 'blocked' ? 'sev-high' : 'sev-low'">{{ t.action === 'blocked' ? '已拦截' : '检测' }}</span>
        </div>
      </transition-group>

      <div class="hint">
        <span class="hint-desktop">拖动{{ isGlobeMode ? '旋转 · 滚轮缩放 · 点击国家下钻 · 点击空白返回' : '平移 · 滚轮缩放 · 点击国家下钻 · 点击空白返回' }}</span>
      </div>

      <transition name="fade">
        <div v-if="showEmptyState" class="empty-state">近 24 小时无攻击事件</div>
      </transition>
      <div v-if="statsError" class="error-banner">大屏数据加载失败，正在重试…</div>
    </div>

    <!-- 左列：实时威胁事件 -->
    <aside class="panel panel-left hud" aria-label="实时威胁事件">
      <div class="panel-head">
        <h2>实时威胁事件 <span class="en">LIVE FEED</span></h2>
        <span class="live-chip"><i></i>LIVE</span>
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
            </div>
            <div class="ev-main">
              <span class="ev-ip">{{ event.client_ip }}</span>
              <span class="ev-geo">{{ event.ip_location || '未知' }}</span>
            </div>
            <div class="ev-type">
              <b :style="{ color: typeColorFor(event.attack_type) }">{{ event.attack_type }}</b>
              <span v-if="event.rule_name">{{ event.rule_name }}</span>
              <span class="st">{{ stageLabel(event) }}</span>
            </div>
          </div>
        </transition-group>
        <div v-if="filteredFeed.length === 0" class="empty">{{ statsError ? '事件流加载失败' : '暂无事件' }}</div>
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
          <p>近 {{ stats?.hours ?? 24 }} 小时安全态势实时监控 <time class="mono">{{ clockText }}</time><span class="mono clock-date">{{ clockDate }}</span></p>
        </div>
      </div>

      <div class="kpis" role="group" aria-label="核心指标">
        <div class="kpi"><span class="kpi-value">{{ displayTotal }}</span><span class="kpi-label">24h 攻击总数</span></div>
        <div class="kpi"><span class="kpi-value cool">{{ displayRate }}<small>%</small></span><span class="kpi-label">拦截率 · 限流 {{ displayRatelimit }}</span></div>
        <div class="kpi"><span class="kpi-value">{{ displayRecentRate }}</span><span class="kpi-label">次/分钟 · 近 5 分钟</span></div>
        <div class="kpi"><span class="kpi-value">{{ displayActive }}</span><span class="kpi-label">活跃攻击源 · 近 10 分钟</span></div>
      </div>

      <div class="actions">
        <button type="button" class="btn" title="复位视角" @click="resetView">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>
          <span class="btn-text">复位视角</span>
        </button>
        <button type="button" class="btn" :aria-pressed="paused" :title="paused ? '继续' : '暂停'" @click="togglePause">
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
        <div class="stat-section">
          <div class="stat-title"><span>威胁指数</span><span class="n">{{ threatGauge.pct }}</span></div>
          <div class="gauge-row">
            <svg class="gauge" viewBox="0 0 120 70" role="img" aria-label="威胁指数">
              <path class="gauge-track" d="M10 62 A50 50 0 0 1 110 62" fill="none"></path>
              <path class="gauge-fill" :stroke="threatGauge.color" :stroke-dasharray="`${threatGauge.pct * 1.571} 157.1`" d="M10 62 A50 50 0 0 1 110 62" fill="none"></path>
              <text x="60" y="52" text-anchor="middle" class="gauge-num">{{ threatGauge.pct }}</text>
            </svg>
            <div class="gauge-side">
              <span class="level" :style="{ '--lv': threatGauge.color }">{{ threatGauge.level }}</span>
              <dl>
                <dt>拦截事件</dt><dd>{{ stats?.blocked_events ?? 0 }}</dd>
                <dt>攻击源国家</dt><dd>{{ countryCount }}</dd>
                <dt>命中规则数</dt><dd>{{ rulesTotal }}</dd>
              </dl>
            </div>
          </div>
        </div>

        <div class="stat-section">
          <div class="stat-title"><span>攻击国家 TOP5</span></div>
          <ul v-if="topCountries.length" class="rules country-bars">
            <li v-for="item in topCountries" :key="item.name" class="rule" :title="item.name">
              <span class="rule-name">{{ item.name }}</span>
              <span class="cnt">{{ item.value }}</span>
              <span class="rule-bar"><i :style="{ width: countryBarWidth(item.value), background: countryBarColor(item.value) }"></i></span>
            </li>
          </ul>
          <div v-else class="empty">暂无归属地数据</div>
        </div>

        <div class="stat-section">
          <div class="stat-title"><span>攻击类型占比</span><span class="n">{{ shareTotal }}</span></div>
          <div class="donut-row">
            <div class="donut">
              <svg viewBox="0 0 36 36" role="img" aria-label="攻击类型占比">
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
              <div class="donut-center"><b>{{ shareTotal }}</b><span>攻击</span></div>
            </div>
            <ul class="type-legend">
              <li v-for="item in shareTop" :key="item.name">
                <span class="sw" :style="{ background: shareSliceColor(item.name) }"></span>
                <span class="rule-name" :title="item.name">{{ item.name }}</span>
                <span class="cnt">{{ item.value }}</span>
              </li>
            </ul>
          </div>
        </div>

        <div class="stat-section">
          <div class="stat-title"><span>TOP 命中规则</span><span class="n">{{ rulesTotal }}</span></div>
          <ul v-if="topRules.length" class="rules">
            <li v-for="item in topRules" :key="item.name" class="rule" :title="item.name">
              <span class="rule-name">{{ item.name }}</span>
              <span class="cnt">{{ item.value }}</span>
              <span class="rule-bar"><i :style="{ width: ruleBarWidth(item.value) }"></i></span>
            </li>
          </ul>
          <div v-else class="empty">暂无数据</div>
        </div>
      </div>
    </aside>

    <!-- 底部双图：24h 趋势 + 实时 QPS -->
    <div class="charts-row">
      <div class="panel hud">
        <div class="panel-head">
          <h2>24h 攻击时段趋势 <span class="en">HOURLY</span></h2>
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
              :x="i * (100 / 24)"
              y="0"
              :width="100 / 24 + 0.05"
              height="40"
            ><title>{{ slot.name }}:00 — {{ slot.value }} 次</title></rect>
          </svg>
          <div class="timeline-axis"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>
        </div>
      </div>
      <div class="panel hud">
        <div class="panel-head">
          <h2>正常请求流量 <span class="en">TRAFFIC · 90s</span></h2>
          <span class="meta">当前 <b>{{ normalQps }}</b> /s · 累计 {{ normalTotalText }}</span>
        </div>
        <div class="chart-box">
          <svg class="normal-spark" viewBox="0 0 100 40" preserveAspectRatio="none">
            <polygon class="normal-fill" :points="normalFillPoints"></polygon>
            <polyline class="normal-stroke" :points="normalPoints"></polyline>
          </svg>
          <div class="timeline-axis"><span>90s 前</span><span>现在</span></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { request } from '@/utils/api'
import type { APIResponse } from '@/types'
import { useAuthStore } from '@/stores/auth'
import { usePollingTask } from '@/composables/usePollingTask'
import { useCountUp } from '@/composables/useCountUp'
import { formatDate } from '@/utils/date'
import type { ThreatScene } from '@/utils/threatScene'

// 威胁大屏（v2.3.8 Threat Wall 版式）：三栏 HUD 网格（左事件流/中引擎舞台/
// 右态势统计）+ 顶栏 KPI + 底部双图（24h 趋势/正常流量）。视觉体系移植自
// 参考实现（threat-wall，用户友人制作，授权改造）；数据源/引擎全为本仓：
// 中央视觉按设置双模式装载（map=360°地图+雷达扫掠 / globe=旋转地球+垂直
// 扫描，threatGlobe.ts）。轮询复用 usePollingTask（页签隐藏自动暂停）。

interface ThreatScreenStats {
  hours: number
  total_events: number
  blocked_events: number
  block_rate: number
  ratelimit_blocks: number
  active_sources: number
  countries: Record<string, number>
  china_provinces: Record<string, number>
  top_countries: { name: string; value: number }[]
  top_attack_types: { name: string; value: number }[]
  top_rules: { name: string; value: number }[]
  hourly_hist: { name: string; value: number }[]
  attack_type_share: { name: string; value: number }[]
  recent_rate: number
}

interface FeedEvent {
  id: number
  event_time: string
  client_ip: string
  ip_location: string
  action: string
  rule_name: string
  attack_type: string
  event_type?: string
  duration_us?: number
  rule_triggered?: string
  anomaly_score?: number
}

const FEED_LIMIT = 50
const FEED_POLL_MS = 3000
const STATS_POLL_MS = 30000
const ARC_FLUSH_MS = 500

const authStore = useAuthStore()
const stats = ref<ThreatScreenStats | null>(null)
const statsError = ref(false)
const feedItems = ref<FeedEvent[]>([])
const sinceId = ref(0)
const paused = ref(false)
const mapHost = ref<HTMLElement | null>(null)
const zoomedName = ref<string | null>(null)
let threatMap: ThreatScene | null = null

let arcQueue: string[] = []
let arcFlushTimer: number | undefined = undefined
let disposed = false

const displayTotal = useCountUp(computed(() => stats.value?.total_events ?? 0))
const displayRateX10 = useCountUp(computed(() => Math.round((stats.value?.block_rate ?? 0) * 10)))
const displayRate = computed(() => (displayRateX10.value / 10).toFixed(1))
const displayRatelimit = useCountUp(computed(() => Math.floor(stats.value?.ratelimit_blocks ?? 0)))
const displayActive = useCountUp(computed(() => stats.value?.active_sources ?? 0))

const topCountries = computed(() => stats.value?.top_countries ?? [])
const topRules = computed(() => stats.value?.top_rules ?? [])
const hourlyTotal = computed(() => hourlyHist.value.reduce((m, slot) => m + slot.value, 0))
const rulesTotal = computed(() => topRules.value.reduce((m, item) => m + item.value, 0))
const hourlyHist = computed(() => stats.value?.hourly_hist ?? [])
const attackTypeShare = computed(() => stats.value?.attack_type_share ?? [])
const displayRecentRate = useCountUp(computed(() => Math.round((stats.value?.recent_rate ?? 0) * 10)), 500)
const showEmptyState = computed(() => !statsError.value && !!stats.value && stats.value.total_events === 0)
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
const countryBarColor = (count: number): string => countryHeat(count)
const maxRuleCount = computed(() => topRules.value.reduce((m, item) => Math.max(m, item.value), 0))
const ruleBarWidth = (count: number): string => `${maxRuleCount.value > 0 ? Math.max(5, (count / maxRuleCount.value) * 100) : 0}%`

const SHARE_PALETTE = ['#ff4d4d', '#ff9f1c', '#ffd166']
const shareTop = computed(() => attackTypeShare.value.slice(0, 3))
const shareTotal = computed(() => attackTypeShare.value.reduce((m, item) => m + item.value, 0))
const shareSliceColor = (name: string): string => {
  const idx = shareTop.value.findIndex((x) => x.name === name)
  return idx >= 0 ? SHARE_PALETTE[idx] ?? '#ffd166' : '#ffd166'
}
const shareSegments = computed(() => {
  const top = shareTop.value
  const total = shareTotal.value
  if (total === 0 || top.length === 0) return []
  const segments: { color: string; dash: string; offset: number }[] = []
  let cursor = 0
  top.forEach((item, index) => {
    const pct = (item.value / total) * 100
    segments.push({ color: SHARE_PALETTE[index] ?? '#ffd166', dash: `${pct} ${100 - pct}`, offset: 25 - cursor })
    cursor += pct
  })
  const rest = 100 - cursor
  if (rest > 0.01) segments.push({ color: '#ffd166', dash: `${rest} ${100 - rest}`, offset: 25 - cursor })
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

const feedTypeColorCache = new Map<string, string>()
const TYPE_PALETTE = ['#ff4d4d', '#ff9f1c', '#ffd166']
const typeColorFor = (name: string): string => {
  if (!name) return '#56709f'
  const cached = feedTypeColorCache.get(name)
  if (cached) return cached
  let hash = 0
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) | 0
  const color = TYPE_PALETTE[Math.abs(hash) % TYPE_PALETTE.length]
  feedTypeColorCache.set(name, color)
  return color
}

// ============ 实时时钟（秒级） ============
const clockText = ref('--:--:--')
const clockDate = ref('')
const WEEKDAYS = ['日', '一', '二', '三', '四', '五', '六']
const camReadout = ref('--')
const tgtReadout = ref('--')
function tickClock(): void {
  const now = new Date()
  const p2 = (n: number): string => String(n).padStart(2, '0')
  clockText.value = `${p2(now.getHours())}:${p2(now.getMinutes())}:${p2(now.getSeconds())}`
  clockDate.value = `${now.getFullYear()}-${p2(now.getMonth() + 1)}-${p2(now.getDate())} 星期${WEEKDAYS[now.getDay()]}`
  // HUD 读数：引擎相机地理中心 + 本站坐标
  const cam = threatMap?.cameraState()
  if (cam) camReadout.value = `${cam.cy.toFixed(1)}° ${((cam.cx + 360) % 360 - 180).toFixed(1)}°`
}
let clockTimer = 0

// ============ 攻击事件弹框（阶段标签单源=rule_triggered） ============
interface AttackToast {
  id: number
  country: string
  ip: string
  stage: string
  action: string
  durationMs: string
}
const attackToasts = ref<AttackToast[]>([])
const TOAST_MAX = 3
const TOAST_TTL = 4500
const toastTimers = new Map<number, number>()
function stageLabel(ev: FeedEvent): string {
  const rt = ev.rule_triggered ?? ''
  if (rt === '429') return '限流'
  if (rt === '2') return 'IP 名单'
  if (rt === '8') return 'GeoIP'
  if (/^48[123]$/.test(rt)) return 'IP 访问控制'
  return 'WAF'
}
function pushAttackToasts(events: FeedEvent[]): void {
  for (const ev of events) {
    if (ev.action !== 'blocked') continue
    const durMs = Math.max(0.1, (ev.duration_us ?? 0) / 1000)
    const toast: AttackToast = {
      id: ev.id,
      country: (ev.ip_location || '未知').split('·')[0] || '未知',
      ip: ev.client_ip,
      stage: stageLabel(ev),
      action: ev.action,
      durationMs: durMs >= 100 ? Math.round(durMs).toString() : durMs.toFixed(1),
    }
    attackToasts.value = [toast, ...attackToasts.value].slice(0, TOAST_MAX)
    const timer = window.setTimeout(() => {
      attackToasts.value = attackToasts.value.filter((t) => t.id !== toast.id)
      toastTimers.delete(toast.id)
    }, TOAST_TTL)
    toastTimers.set(toast.id, timer)
  }
}

// ============ 正常流量 sparkline（traffic 差分 60 点窗口） ============
const normalWindow = ref<number[]>([])
const NORMAL_WINDOW_MAX = 60
let normalTotal = 0
const normalQps = computed(() => {
  const w = normalWindow.value
  if (w.length < 2) return '0.0'
  const recent = w.slice(-10)
  const avg = recent.reduce((m, v) => m + v, 0) / recent.length / 1.5
  return avg >= 100 ? Math.round(avg).toString() : avg.toFixed(1)
})
const normalTotalText = computed(() => (normalTotal >= 10000 ? `${(normalTotal / 1000).toFixed(1)}k` : normalTotal.toLocaleString()))
const normalPoints = computed((): string => {
  const w = normalWindow.value
  if (w.length < 2) return ''
  const max = Math.max(...w, 1)
  return w.map((v, i) => `${((i / (w.length - 1)) * 100).toFixed(2)},${(38 - (v / max) * 34).toFixed(2)}`).join(' ')
})
const normalFillPoints = computed((): string => (normalPoints.value ? `0,40 ${normalPoints.value} 100,40` : ''))

// ============ 事件等级筛选（高危=拦截 高危族 / 中危=限流 / 低危=检测） ============
type Sev = 'high' | 'mid' | 'low'
/** 危险等级（v2.3.8 评分优先，用户裁定 2026-10-17）：事件日志评分列的
 * anomaly_score 对全部阶段事件均有效（含限流/IP 名单/GeoIP）——评分>0 时
 * 直接驱动分级（≥12 高 / 6-11 中 / <6 低，检测模式降一级）；仅 0 分回落
 * 阶段定性映射（IP 名单/预检=高，限流/GeoIP=中）。 */
function sevOf(ev: FeedEvent): Sev {
  const score = ev.anomaly_score ?? 0
  const down = (base: Sev): Sev => (ev.action !== 'blocked' && base === 'high' ? 'mid' : base)
  if (score > 0) {
    if (ev.action !== 'blocked') return score >= 12 ? 'mid' : score >= 6 ? 'low' : 'low'
    return score >= 12 ? 'high' : score >= 6 ? 'mid' : 'low'
  }
  const rt = ev.rule_triggered ?? ''
  if (rt === '2' || /^48[123]$/.test(rt)) return down('high')
  if (rt === '429' || rt === '8') return down('mid')
  return ev.action === 'blocked' ? 'mid' : 'low'
}
function sevLabel(ev: FeedEvent): string {
  const s = sevOf(ev)
  return s === 'high' ? '高危' : s === 'mid' ? '中危' : '低危'
}
const sevFilter = ref<'all' | Sev>('all')
const sevFilters = computed(() => {
  let high = 0, mid = 0, low = 0
  for (const ev of feedItems.value) {
    const s = sevOf(ev)
    if (s === 'high') high++
    else if (s === 'mid') mid++
    else low++
  }
  return [
    { key: 'all' as const, label: '全部', count: feedItems.value.length },
    { key: 'high' as const, label: '高危', count: high },
    { key: 'mid' as const, label: '中危', count: mid },
    { key: 'low' as const, label: '低危', count: low },
  ]
})
const filteredFeed = computed(() =>
  sevFilter.value === 'all' ? feedItems.value : feedItems.value.filter((ev) => sevOf(ev) === sevFilter.value),
)

function enqueueArcs(events: FeedEvent[]): void {
  for (const event of events) {
    if (event.ip_location) arcQueue.push(event.ip_location)
  }
}

function flushArcs(): void {
  if (!threatMap || arcQueue.length === 0) {
    arcQueue = []
    return
  }
  // v2.3.8 同源聚合（100 atk/s 压力设计）：同一归属地合并为一条加权弧——
  // 弧线池上限 30 表达的是「来源分布」而非「逐事件」，同源加粗优于逐条丢弃。
  const byLocation = new Map<string, number>()
  for (const location of arcQueue) byLocation.set(location, (byLocation.get(location) ?? 0) + 1)
  for (const [location, weight] of byLocation) threatMap.addArcForLocation(location, weight)
  arcQueue = []
}

// ============ 威胁指数（0-100，log10 攻击总量） ============
const threatGauge = computed(() => {
  const total = stats.value?.total_events ?? 0
  const pct = Math.min(100, Math.round((Math.log10(Math.max(1, total)) / 3) * 100))
  const level = pct >= 67 ? '严重' : pct >= 34 ? '高' : pct > 0 ? '中' : '低'
  const color = pct >= 67 ? '#ff4d5e' : pct >= 34 ? '#ff7a2f' : pct > 0 ? '#ffb020' : '#3ddc84'
  return { pct, level, color }
})


let prevTraffic = new Map<string, number>()
const trafficTask = usePollingTask(async () => {
  const res = await request.get<APIResponse<{ countries: Record<string, { attack: number; normal: number }>; available: boolean }>>('/security/overview/threat-screen/traffic', { silent: true })
  const countries = res.data?.countries ?? {}
  const deltas: { name: string; count: number }[] = []
  for (const [name, entry] of Object.entries(countries)) {
    const prev = prevTraffic.get(name) ?? 0
    const d = entry.normal - prev
    if (d > 0) deltas.push({ name, count: d })
    prevTraffic.set(name, entry.normal)
  }
  threatMap?.setTraffic(deltas)
  const delta = deltas.reduce((m, d) => m + d.count, 0)
  normalTotal += delta
  normalWindow.value = [...normalWindow.value, delta].slice(-NORMAL_WINDOW_MAX)
}, { interval: 1500 })

// 本站坐标 + 大屏模式（threat_screen_mode：map/globe）——/config 读一次
const screenMode = ref('map')
const isGlobeMode = computed(() => screenMode.value === 'globe')
const serverLatLon: [number, number] = [0, 0]
async function loadServerCentroid(): Promise<void> {
  try {
    const res = await request.get<APIResponse<{ server_map_lat?: number; server_map_lon?: number; threat_screen_mode?: string }>>('/config?_ts=' + Date.now(), { silent: true })
    screenMode.value = res.data?.threat_screen_mode === 'globe' ? 'globe' : 'map'
    serverLatLon[0] = res.data?.server_map_lat ?? 0
    serverLatLon[1] = res.data?.server_map_lon ?? 0
    if (serverLatLon[0] !== 0 || serverLatLon[1] !== 0) {
      threatMap?.setServer([serverLatLon[1], serverLatLon[0]])
      tgtReadout.value = `${Math.abs(serverLatLon[0]).toFixed(2)}°${serverLatLon[0] >= 0 ? 'N' : 'S'} ${Math.abs(serverLatLon[1]).toFixed(2)}°${serverLatLon[1] >= 0 ? 'E' : 'W'}`
    }
  } catch {
    /* 配置读取失败：保持缺省 */
  }
}

const feedTask = usePollingTask(async () => {
  const res = await request.get<APIResponse<{ events: FeedEvent[] }>>(`/security/events/feed?since_id=${sinceId.value}`, { silent: true })
  const events = res.data?.events ?? []
  if (events.length === 0) return
  const isInitialBatch = sinceId.value === 0
  sinceId.value = events[0].id
  // 保留最近 50 条滚动更新（用户裁定 2026-10-17：50 条上限+实时追加即可）
  feedItems.value = [...events, ...feedItems.value].sort((a, b) => b.id - a.id).slice(0, FEED_LIMIT)
  // 弧线/弹框仅对增量批次：首批（入场回溯）不回放——消除「开局三连流光」
  // 演示观感（用户裁定 2026-10-17）。
  if (!isInitialBatch) {
    enqueueArcs(events)
    pushAttackToasts(events)
  }
}, { interval: FEED_POLL_MS })

const statsTask = usePollingTask(async () => {
  const res = await request.get<APIResponse<ThreatScreenStats>>('/security/overview/threat-screen', { silent: true })
  if (!res.data) throw new Error('threat-screen payload missing')
  stats.value = res.data
  statsError.value = false
  threatMap?.setCountries(Object.entries(res.data.countries ?? {}).map(([name, count]) => ({ name, count })))
  threatMap?.setProvinces(Object.entries(res.data.china_provinces ?? {}).map(([name, count]) => ({ name, count })))
}, {
  interval: STATS_POLL_MS,
  onError: () => { statsError.value = true },
})

function applyMapPause(): void {
  threatMap?.setPaused(paused.value)
}

function togglePause(): void {
  paused.value = !paused.value
  if (paused.value) {
    feedTask.pause()
    statsTask.pause()
    trafficTask.pause()
  } else {
    feedTask.resume()
    statsTask.resume()
    trafficTask.resume()
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

function onVisibilityChange(): void {
  if (document.hidden) threatMap?.setPaused(true)
  else applyMapPause()
}

onMounted(async () => {
  await loadServerCentroid()
  if (disposed) return
  const engine = screenMode.value === 'globe'
    ? (await import('@/utils/threatGlobe')).createThreatGlobe
    : (await import('@/utils/threatScene')).createThreatScene
  if (disposed) return
  if (mapHost.value) {
    threatMap = engine(mapHost.value, {
      onDrillChange: (name) => { zoomedName.value = name },
    })
    ;(window as unknown as Record<string, unknown>).__threatScene = threatMap
    applyMapPause()
    if (serverLatLon[0] !== 0 || serverLatLon[1] !== 0) threatMap.setServer([serverLatLon[1], serverLatLon[0]])
  }
  window.addEventListener('keydown', onKeydown)
  document.addEventListener('visibilitychange', onVisibilityChange)
  arcFlushTimer = window.setInterval(flushArcs, ARC_FLUSH_MS)
  tickClock()
  clockTimer = window.setInterval(tickClock, 1000)
  feedTask.start()
  statsTask.start()
  trafficTask.start()
  await Promise.allSettled([feedTask.run(), statsTask.run(), trafficTask.run()])
})

onBeforeUnmount(() => {
  disposed = true
  window.removeEventListener('keydown', onKeydown)
  document.removeEventListener('visibilitychange', onVisibilityChange)
  clearInterval(arcFlushTimer)
  arcFlushTimer = undefined
  clearInterval(clockTimer)
  clockTimer = 0
  for (const t of toastTimers.values()) clearTimeout(t)
  toastTimers.clear()
  feedTask.stop()
  statsTask.stop()
  trafficTask.stop()
  threatMap?.dispose()
  threatMap = null
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
.clock-date { color: #56709f; font-size: 10px; }

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
.kpi-value small { font-size: 16px; margin-left: 2px; }
.kpi-value.cool { color: #8fe6ff; text-shadow: 0 0 16px rgba(58, 209, 255, 0.55); }
.kpi-label { font-size: 11px; color: #8ea7d6; letter-spacing: 0.04em; white-space: nowrap; }

.actions { display: flex; gap: 8px; flex: none; }
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
.ev-icon svg { width: 14px; height: 14px; }
.ev-top { display: flex; justify-content: space-between; align-items: center; font-size: 11px; color: #56709f; font-variant-numeric: tabular-nums; }
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

.back-btn { position: absolute; z-index: 4; bottom: 52px; left: 50%; transform: translateX(-50%); }
.hint { position: absolute; z-index: 2; right: 16px; bottom: 44px; font-size: 11px; color: #56709f; pointer-events: none; }

.toasts { position: absolute; z-index: 5; top: 14px; left: 50%; transform: translateX(-50%); display: grid; gap: 6px; justify-items: center; pointer-events: none; width: min(460px, calc(100% - 32px)); }
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
.error-banner {
  position: absolute; left: 50%; top: 8px; transform: translateX(-50%);
  padding: 4px 14px; border: 1px solid rgba(255, 77, 94, 0.5);
  background: rgba(255, 77, 94, 0.15); color: #ff8f9a; font-size: 12px; z-index: 6;
}

/* ---------- 右列统计 ---------- */
.stats { flex: 1; min-height: 0; overflow-y: auto; scrollbar-width: thin; scrollbar-color: rgba(80, 160, 255, 0.3) transparent; }
.stat-section { padding: 12px 14px; border-bottom: 1px solid rgba(80, 160, 255, 0.16); }
.stat-section:last-child { border-bottom: 0; }
.stat-title { display: flex; justify-content: space-between; align-items: baseline; font-size: 11px; color: #8ea7d6; letter-spacing: 0.12em; margin-bottom: 8px; }
.stat-title .n { font-size: 20px; color: #ffd166; font-weight: 700; line-height: 1; }

.gauge-row { display: grid; grid-template-columns: 130px 1fr; gap: 10px; align-items: center; }
.gauge { width: 130px; height: 74px; }
.gauge-track { stroke: rgba(80, 160, 255, 0.12); stroke-width: 7; }
.gauge-fill { stroke-width: 7; stroke-linecap: round; filter: drop-shadow(0 0 6px currentColor); transition: stroke-dasharray 0.8s ease; }
.gauge-num { fill: #e2ecff; font-size: 17px; font-weight: 700; font-variant-numeric: tabular-nums; }
.gauge-side { display: grid; gap: 8px; }
.level {
  justify-self: start;
  font-weight: 700; font-size: 15px; letter-spacing: 0.2em;
  padding: 3px 10px; border: 1px solid currentColor;
  color: var(--lv, #ffb020);
  background: color-mix(in srgb, var(--lv, #ffb020) 14%, transparent);
  text-shadow: 0 0 10px currentColor;
}
.gauge-side dl { margin: 0; display: grid; grid-template-columns: auto 1fr; gap: 3px 10px; font-size: 11px; color: #8ea7d6; }
.gauge-side dd { margin: 0; text-align: right; font-size: 14px; font-weight: 700; color: #e2ecff; font-variant-numeric: tabular-nums; }

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

.donut-row { display: flex; align-items: center; gap: 14px; }
.donut { position: relative; width: 116px; height: 116px; flex: none; }
.donut svg { position: absolute; inset: 0; width: 100%; height: 100%; }
.donut-track { fill: none; stroke: rgba(80, 160, 255, 0.1); stroke-width: 2.5; }
.donut-seg { fill: none; stroke-width: 2.5; }
.donut-center { position: absolute; inset: 0; display: grid; place-items: center; align-content: center; pointer-events: none; line-height: 1; }
.donut-center b { font-size: 26px; font-weight: 700; color: #ffd166; }
.donut-center span { font-size: 10px; color: #8ea7d6; letter-spacing: 0.12em; margin-top: 3px; }
.type-legend { flex: 1; min-width: 0; display: grid; gap: 6px; margin: 0; padding: 0; list-style: none; }
.type-legend li { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.type-legend .sw { width: 8px; height: 8px; flex: none; transform: rotate(45deg); }
.type-legend .cnt { margin-left: auto; font-weight: 700; font-size: 15px; font-variant-numeric: tabular-nums; color: #e2ecff; }

/* ---------- 底部双图 ---------- */
.chart-box { flex: 1; min-height: 0; padding: 6px 14px 4px; display: flex; flex-direction: column; }
.timeline-svg, .normal-spark { width: 100%; flex: 1; min-height: 0; display: block; }
.timeline-stroke { fill: none; stroke: #ff7a2f; stroke-width: 1.6; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 4px rgba(255, 122, 47, 0.5)); }
.timeline-fill { fill: rgba(255, 122, 47, 0.12); }
.timeline-slot { fill: transparent; }
.timeline-slot:hover { fill: rgba(58, 209, 255, 0.08); }
.timeline-axis { display: flex; justify-content: space-between; font-size: 10px; color: #56709f; padding-top: 2px; font-variant-numeric: tabular-nums; }
.normal-stroke { fill: none; stroke: #3ddc84; stroke-width: 1.6; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 4px rgba(61, 220, 132, 0.5)); }
.normal-fill { fill: rgba(61, 220, 132, 0.12); }

/* 地图引擎根容器适配（引擎内部自管 canvas/标签层） */
.stage-mount :deep(canvas) { position: absolute !important; inset: 0; outline: none; display: block; }
.globe-wrap :deep(.label-layer div) { color: #e2ecff; text-shadow: 0 0 6px rgba(1, 4, 12, 0.9); }

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
