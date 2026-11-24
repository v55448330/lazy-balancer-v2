// 仪表盘披露口径守卫（规则卡截断提示纯函数 + 指标卡副标题/重启入口的口径说明接线）。
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

// 2026-11-25 用户裁定：概览流量图/连接图下方的两条「整机口径」说明属过度设计，已移除
// （指标卡口径副标题与规则卡截断提示保留）。此钉防止说明或其词条回潮。
test('概览图下方不再有「整机口径」说明，词条同步移除', () => {
  assert.ok(!dashboard.includes('chart-scope-note'), '流量图/连接图下方不得再出现口径说明')
  for (const [locale, catalog] of [['zh', zhDashboard], ['en', enDashboard]] as const) {
    for (const key of ['trafficScopeNote', 'connectionsScopeNote']) {
      assert.ok(!(key in catalog), `${locale} 不得残留已移除的词条 ${key}`)
    }
  }
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

test('规则卡底部只披露截断口径，不提供跳转规则列表的入口（流量排行看的是流量）', () => {
  assert.match(dashboard, /import \{ ruleCardOverflowHint \} from '@\/utils\/dashboardHints'/)
  assert.match(dashboard, /ruleCardOverflowHint\(rules\.value\.length, sortedRules\.value\.length\)/)
  assert.match(
    dashboard,
    /class="rules-card-footer form-tip-line"><span>\{\{ t\('common\.app\.dashboard\.rulesOverflowHint', \{ shown: ruleCardOverflow\.shown, total: ruleCardOverflow\.total \}\) \}\}<\/span><\/div>/,
    '「仅显示前 N 条，共 M 条」的说明保留',
  )
  assert.doesNotMatch(dashboard, /openAllRules|viewAllRules|pageUrl/, '入口、处理函数与其 deepLink 依赖一并移除')
  for (const locale of ['zh', 'en'] as const) {
    assert.equal(code(`src/locales/${locale}/common.ts`).includes('viewAllRules'), false, `${locale} 词条键 viewAllRules 不得残留`)
  }
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
    'rulesOverflowHint',
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
