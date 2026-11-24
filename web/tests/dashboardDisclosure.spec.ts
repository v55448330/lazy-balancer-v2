// 仪表盘披露口径守卫（规则卡截断提示纯函数 + 图表/指标/重启入口的口径说明接线）。
//
// 运行：cd web && node --test tests/dashboardDisclosure.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ruleCardOverflowHint } from '../src/utils/dashboardHints.ts'
import { code } from './_helpers.ts'
import zh from '../src/locales/zh/common.ts'
import en from '../src/locales/en/common.ts'

const dashboard = code('src/views/Dashboard.vue')
const zhDashboard = zh.app.dashboard
const enDashboard = en.app.dashboard

test('规则卡截断提示：总数不超过已展示条数时不提示', () => {
  assert.equal(ruleCardOverflowHint(0, 0), null)
  assert.equal(ruleCardOverflowHint(7, 7), null)
  assert.equal(ruleCardOverflowHint(10, 10), null)
})

test('规则卡截断提示：恰好 10 条全部展示不提示，第 11 条起披露隐藏条数', () => {
  assert.equal(ruleCardOverflowHint(10, 10), null)
  assert.deepEqual(ruleCardOverflowHint(11, 10), { total: 11, shown: 10, hidden: 1 })
  assert.deepEqual(ruleCardOverflowHint(23, 10), { total: 23, shown: 10, hidden: 13 })
})

test('规则卡截断提示：总数不足 10 条但有未进榜规则时同样提示', () => {
  assert.deepEqual(ruleCardOverflowHint(8, 3), { total: 8, shown: 3, hidden: 5 })
})

test('规则卡截断提示：非法数值一律不提示', () => {
  assert.equal(ruleCardOverflowHint(Number.NaN, 0), null)
  assert.equal(ruleCardOverflowHint(12, Number.NaN), null)
  assert.equal(ruleCardOverflowHint(-1, 0), null)
  assert.equal(ruleCardOverflowHint(12, -1), null)
  assert.equal(ruleCardOverflowHint(12.5, 10), null)
})

test('规则卡底部披露截断口径并提供全部规则入口', () => {
  assert.match(dashboard, /import \{ ruleCardOverflowHint \} from '@\/utils\/dashboardHints'/)
  assert.match(dashboard, /ruleCardOverflowHint\(rules\.value\.length, sortedRules\.value\.length\)/)
  assert.match(dashboard, /form-tip-line[^>]*>[\s\S]{0,400}t\('common\.app\.dashboard\.rulesOverflowHint', \{ shown: ruleCardOverflow\.shown, total: ruleCardOverflow\.total \}\)/)
  assert.match(dashboard, /window\.open\(pageUrl\('rules'\), '_blank', 'noopener'\)/)
  assert.match(dashboard, /@click="openAllRules">[^<]*\{\{ t\('common\.app\.dashboard\.viewAllRules'\) \}\}/)
})

test('概览流量图与连接图各自声明整机口径', () => {
  const trafficCard = dashboard.slice(dashboard.indexOf("t('common.app.dashboard.trafficMonitor')"), dashboard.indexOf("t('common.app.dashboard.connections')"))
  const connectionsCard = dashboard.slice(dashboard.indexOf("t('common.app.dashboard.connections')"), dashboard.indexOf("t('common.app.dashboard.lbRules')"))
  assert.match(trafficCard, /class="chart-scope-note form-tip-line">\{\{ t\('common\.app\.dashboard\.trafficScopeNote'\) \}\}/)
  assert.match(connectionsCard, /class="chart-scope-note form-tip-line">\{\{ t\('common\.app\.dashboard\.connectionsScopeNote'\) \}\}/)
})

test('图表口径说明不臆造为负载规则合计（后端取整机网卡与整机连接）', () => {
  assert.match(zhDashboard.trafficScopeNote, /整机/)
  assert.match(zhDashboard.connectionsScopeNote, /整机/)
  assert.doesNotMatch(zhDashboard.trafficScopeNote, /负载规则合计/)
  assert.doesNotMatch(zhDashboard.connectionsScopeNote, /负载规则合计/)
  assert.match(enDashboard.trafficScopeNote, /[Hh]ost-wide/)
  assert.match(enDashboard.connectionsScopeNote, /[Hh]ost-wide/)
})

test('重启入口统一为进程口径并说明中断范围', () => {
  assert.match(dashboard, /restartScopeNote[\s\S]{0,400}controlCaddy\('restart'\)/)
  assert.equal(zhDashboard.restartBtn, '重启进程')
  assert.equal(enDashboard.restartBtn, 'Restart process')
  assert.match(zhDashboard.caddyServiceTitle, /Caddy 进程/)
  assert.doesNotMatch(zhDashboard.caddyServiceTitle, /Caddy 服务/)
  assert.match(enDashboard.caddyServiceTitle, /Caddy process/)
  assert.match(zhDashboard.confirmRestart, /Caddy 进程/)
  assert.match(zhDashboard.confirmRestart, /短暂中断/)
  assert.match(zhDashboard.confirmRestart, /重新加载配置/)
  assert.match(enDashboard.confirmRestart, /Caddy process/)
  assert.match(enDashboard.confirmRestart, /interrupted/i)
  assert.match(zhDashboard.confirmStop, /Caddy 进程/)
  assert.match(zhDashboard.confirmStart, /Caddy 进程/)
  assert.doesNotMatch(`${zhDashboard.confirmStop}${zhDashboard.confirmStart}`, /Caddy 服务/)
  assert.match(zhDashboard.restartScopeNote, /短暂中断/)
  assert.match(zhDashboard.restartScopeNote, /重载配置/)
})

test('概览七张指标卡各带口径副标题', () => {
  const occurrences = (marker: string): number => dashboard.split(marker).length - 1
  assert.equal(occurrences("stat-scope\">{{ t('common.app.dashboard.totalRequestsScope') }}"), 1)
  assert.equal(occurrences("stat-scope\">{{ t('common.app.dashboard.inFlightScope') }}"), 1)
  assert.equal(occurrences("stat-scope\">{{ t('common.app.dashboard.domainCountScope') }}"), 1)
  assert.equal(occurrences("stat-scope\">{{ t('common.app.dashboard.reqRateScope') }}"), 1)
  assert.equal(occurrences("stat-scope\">{{ t('common.app.dashboard.latencyScope') }}"), 3)
})

test('新增披露文案 zh/en 成对非空且口径用词一致', () => {
  const keys = [
    'rulesOverflowHint', 'viewAllRules', 'trafficScopeNote', 'connectionsScopeNote',
    'restartScopeNote', 'stopScopeNote', 'startScopeNote',
    'totalRequestsScope', 'inFlightScope', 'domainCountScope', 'reqRateScope', 'latencyScope',
  ] as const
  for (const key of keys) {
    assert.ok((zhDashboard[key] ?? '').length > 0, `zh 缺少 ${key}`)
    assert.ok((enDashboard[key] ?? '').length > 0, `en 缺少 ${key}`)
  }
  assert.match(zhDashboard.reqRateScope, /采集周期/)
  assert.match(enDashboard.reqRateScope, /collection interval/i)
  assert.match(zhDashboard.totalRequestsScope, /配置重载/)
  assert.match(zhDashboard.latencyScope, /配置重载/)
  assert.match(zhDashboard.rulesOverflowHint, /\{shown\}/)
  assert.match(zhDashboard.rulesOverflowHint, /\{total\}/)
  assert.match(enDashboard.rulesOverflowHint, /\{shown\}/)
  assert.match(enDashboard.rulesOverflowHint, /\{total\}/)
})
