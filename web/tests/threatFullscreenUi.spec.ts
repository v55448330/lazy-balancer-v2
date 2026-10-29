// 威胁大屏全屏布局与隐藏停摆的组件接线钉：App.vue 全屏分支不进布局壳、
// 大屏页把三类定时器交给 createVisibilityIntervals 纳管（行为求值见
// visibilityIntervals.spec.ts），以及死选择器/空态文案清理。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { PAGE_IDS } from '../src/utils/pageIds.ts'
import { code, codeSection, member, repoCode, section } from './_helpers.ts'

test('大屏全屏分支不进 AppLayout（侧栏顶栏不得渲染）', () => {
  const app = code('src/App.vue')
  // 终点用「顶层 template 收尾 + script 起点」而非首个 `</template>`——当前
  // App.vue 无嵌套 template，但模板一引入嵌套（el-table 插槽等）首标记即截断，
  // 断言对象会悄悄变短。
  const template = section(app, '<template>', '\n</template>\n\n<script')
  const threatIdx = template.indexOf(`<ThreatScreen v-else-if="currentPage === 'threat-screen'" />`)
  assert.ok(threatIdx > 0, '缺大屏全屏分支')
  const layoutIdx = template.indexOf('<AppLayout')
  assert.ok(threatIdx < layoutIdx, '大屏分支必须先于 AppLayout（v-else-if 短路）')
  assert.match(template.slice(layoutIdx), /^<AppLayout v-else>/, 'AppLayout 必须是 v-else——大屏页不得套布局壳')
  assert.ok(!section(template, '<AppLayout', '</AppLayout>').includes('ThreatScreen'), '大屏不得在 AppLayout 内部渲染')
  // 页面键唯一事实源含 threat-screen（utils/pageIds 单源，auth store 与 App 同消费）
  assert.ok(PAGE_IDS.includes('threat-screen'), '页面键缺 threat-screen（深链/刷新恢复会失效）')
})

// ---- 组件接线钉（间隔调度行为见 visibilityIntervals.spec.ts） ----
test('ThreatScreen 经 createVisibilityIntervals 接管 hidden 停摆', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  assert.match(page, /import \{ createVisibilityIntervals \} from '@\/composables\/useVisibilityIntervals'/)
  const loopBlock = section(page, 'const screenLoop = createVisibilityIntervals({', '})')
  // 时钟(1s, immediate)/采集租约心跳(immediate) 纳管；攻击光流由独立
  // usePollingTask 轮询（页签隐藏自动暂停），不再使用弧光冲刷间隔。
  assert.match(loopBlock, /\{ tick: tickClock, ms: 1000, immediate: true \}/)
  assert.match(loopBlock, /\{ tick: acquireCollector, ms: COLLECTOR_HEARTBEAT_MS, immediate: true \}/)
  assert.match(page, /attackFlowTask\.start\(\)/)
  assert.match(page, /attackFlowTask\.stop\(\)/)
  assert.match(page, /TOAST_STALE_MS = 30000/)
  assert.match(page, /now - toastLastPollAt > TOAST_STALE_MS/)
  // hidden 回调必须释放租约；visible 回调必须重置流量游标
  const onHidden = section(page, 'onHidden: () => {', 'onVisible: () => {')
  assert.match(onHidden, /releaseCollector\(\)/, 'hidden 不释放租约=Caddy 后台空计数')
  const onVisible = section(page, 'onVisible: () => {', '\n})')
  assert.match(onVisible, /flowCursorEpoch\+\+/)
  assert.match(onVisible, /applyMapPause\(\)/)
  // SFC 内不得再直挂 visibilitychange（单源在 composable）
  assert.doesNotMatch(page, /document\.(add|remove)EventListener\('visibilitychange'/)
  // 渲染暂停判据=手动暂停 ∨ 页面隐藏
  const pauseBlock = section(page, 'function applyMapPause(): void {', '}')
  assert.match(pauseBlock, /setPaused\(paused\.value \|\| screenHidden\)/)
  // 卸载收尾：停 loop + 释放租约
  const unmountBlock = section(page, 'onBeforeUnmount(() => {', '})')
  assert.match(unmountBlock, /screenLoop\.stop\(\)/)
  assert.match(unmountBlock, /releaseCollector\(\)/)
})

test('威胁大屏死选择器清理与「被攻击目标」空态文案', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  assert.doesNotMatch(page, /\.ev-icon svg/)
  assert.doesNotMatch(page, /\.scanline/)
  assert.doesNotMatch(page, /\.viewport-grid/)
  assert.match(page, /<div v-else class="empty">暂无目标数据<\/div>/)
})

test('统计响应窗口与当前窗口不一致时丢弃', () => {
  const statsTask = codeSection('src/views/security/ThreatScreen.vue', 'const statsTask = usePollingTask', '// ============ 逐请求正常流量事件流')
  assert.match(statsTask, /if \(res\.data\.hours !== windowHours\.value\) return/)
})

test('统计轮询周期与后端活跃源缓存 TTL 跨栈对表', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  const pollMatch = page.match(/const STATS_POLL_MS = (\d+)/)
  assert.ok(pollMatch, 'ThreatScreen.vue 缺 STATS_POLL_MS（统计轮询周期单源）')
  const pollMs = Number(pollMatch[1])
  assert.ok(pollMs > 0, `STATS_POLL_MS=${pollMs}, want > 0`)
  // 常量必须真正喂给统计轮询：存在但未接线不构成周期钉。
  const statsTask = codeSection('src/views/security/ThreatScreen.vue', 'const statsTask = usePollingTask', '// ============ 逐请求正常流量事件流')
  assert.match(statsTask, /interval: STATS_POLL_MS/)

  // 后端「活跃攻击源」缓存 TTL 必须覆盖本周期**并留一整轮余量**：等值时第二
  // 轮请求恰落在到期边界（±jitter 即 miss），缓存（连同其全窗口扫描的开销假设）
  // 收益归零，而 `>=` 判据在边界上恒绿。1.5 倍是 Go 侧同一判据的倍数。
  const cache = repoCode('internal/handlers/threat_active_sources_cache.go')
  const ttlMatch = cache.match(/threatActiveSourcesCacheTTL = (\d+) \* time\.Second/)
  assert.ok(ttlMatch, '后端 threatActiveSourcesCacheTTL 声明缺失或形态变化（跨栈对表需同步）')
  const ttlMs = Number(ttlMatch[1]) * 1000
  assert.ok(
    ttlMs >= pollMs * 1.5,
    `后端活跃源缓存 TTL=${ttlMs}ms 未达大屏轮询周期 ${pollMs}ms 的 1.5 倍：到期边界上每轮必 miss（Go 侧同主题用例会一并红）`,
  )
})

test('两条光流的空洞标记贯通到独立横幅（不与加载失败混报）', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  const flowTask = codeSection('src/views/security/ThreatScreen.vue', 'const flowTask = usePollingTask', '// ============ 引擎装载')
  assert.match(flowTask, /gap\?: boolean/)
  assert.match(flowTask, /gap_skipped\?: number/)
  // 空洞（环形缓冲溢出，事件永久丢失）≠ 加载失败：分别落到 flowGap/flowError。
  assert.match(flowTask, /flowGap\.value = data\.gap_skipped \?\? \(data\.gap === true \? 1 : 0\)/)
  assert.doesNotMatch(flowTask, /flowError\.value = data\.gap === true/)
  // 攻击光流同一披露口径（此前只回 enabled/events/next_seq，无 gap）。
  const attackTask = section(page, 'const attackFlowTask = usePollingTask', 'const statsTask')
  assert.match(attackTask, /gap_skipped\?: number/)
  assert.match(attackTask, /attackFlowGap\.value = data\.gap_skipped \?\? \(data\.gap === true \? 1 : 0\)/)
  assert.ok(page.includes('v-if="flowGap || attackFlowGap"'))
})

test('采集租约申请/续租失败独立横幅（不与光流失败混报）', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  const acquire = member(page, 'function acquireCollector(): void')
  assert.ok(acquire.includes('.then(() => { collectorError.value = false })'))
  assert.ok(acquire.includes('.catch(() => { collectorError.value = true })'))
  // 光流失败与采集租约失败是两个排障方向：横幅文案必须分离
  assert.ok(page.includes('v-if="flowError || attackFlowError"'))
  const collectorBanner = section(page, '<div v-if="collectorError"', '</div>')
  assert.match(collectorBanner, /采集续租失败/, '采集租约失败的横幅文案')
})
