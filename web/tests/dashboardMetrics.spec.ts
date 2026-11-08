import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRuleMetricsUnavailable, METRIC_RELOAD_RESET_NOTE, ruleMetricCellTitle, TCP_UPSTREAM_GRANULARITY_NOTE } from '../src/utils/dashboardMetrics.ts'
import { code } from './_helpers.ts'

const rules = [
  { caddy_id: 'lb_enabled', enabled: true },
  { caddy_id: 'lb_disabled', enabled: false },
]

test('metrics 先失败、rules 后落地仍逐行显示采集失败', () => {
  assert.deepEqual(buildRuleMetricsUnavailable([], undefined, false), {})
  assert.deepEqual(buildRuleMetricsUnavailable(rules, undefined, false), {
    lb_enabled: true,
    lb_disabled: false,
  })
})

test('成功响应缺失某规则才标失败，已有指标保持可用', () => {
  assert.deepEqual(buildRuleMetricsUnavailable(rules, { lb_enabled: { requests: 3 } }, true), {
    lb_enabled: false,
    lb_disabled: false,
  })
  assert.deepEqual(buildRuleMetricsUnavailable(rules, {}, true), {
    lb_enabled: true,
    lb_disabled: false,
  })
})

test('指标表原型键不得把「无指标」判成「有指标」', () => {
  // caddy_id 来自外部字符串：直接下标会把 Object.prototype 上的函数当成指标值，
  // 采集失败列退化为 0（缺失不得呈现为有值）。
  const protoRules = [
    { caddy_id: 'constructor', enabled: true },
    { caddy_id: 'toString', enabled: true },
    { caddy_id: '__proto__', enabled: true },
  ]
  assert.deepEqual(Object.entries(buildRuleMetricsUnavailable(protoRules, {}, true)), [
    ['constructor', true],
    ['toString', true],
    ['__proto__', true],
  ])
  // 键存在且值为 0 属真实指标（可用），只有 undefined/缺键才算采集失败
  assert.deepEqual(Object.entries(buildRuleMetricsUnavailable(protoRules, { constructor: 0 }, true)), [
    ['constructor', false],
    ['toString', true],
    ['__proto__', true],
  ])
})

test('TCP 行指标 title 明示上游地址口径，HTTP 行/禁用/采集失败不受影响', () => {
  // TCP 行：口径明示 + 值括注
  const tcpTitle = ruleMetricCellTitle({ disabled: false, unavailable: false, tcp: true, value: '1,234' })
  assert.ok(tcpTitle.includes(TCP_UPSTREAM_GRANULARITY_NOTE))
  assert.ok(tcpTitle.includes('1,234'))
  // HTTP 行：值 + 重载归零口径（Caddy registry 每次 /load 重建）
  const httpTitle = ruleMetricCellTitle({ disabled: false, unavailable: false, tcp: false, value: '56' })
  assert.ok(httpTitle.startsWith('56'))
  assert.ok(httpTitle.includes(METRIC_RELOAD_RESET_NOTE))
  // 禁用/采集失败优先于口径明示(修复批次 F 误写:期望值是词条解析后的原文)
  assert.equal(ruleMetricCellTitle({ disabled: true, unavailable: false, tcp: true, value: '1' }), '已禁用')
  assert.equal(ruleMetricCellTitle({ disabled: false, unavailable: true, tcp: true, value: '-' }), '采集失败')
})

// ── 批次 D(metrics 域)双钉:规则指标单元格/口径备注 i18n 接线 ──
// 调用点钉键(common.app.views.metrics.*),zh 母本(locales/zh/views.ts)钉原文。

import { tSafe } from '../src/i18n/tSafe.ts'
import { existsSync } from 'node:fs'

const metrics = (key: string, params?: Record<string, unknown>): string =>
  tSafe(`common.app.views.metrics.${key}`, params)

test('指标口径文案走 i18n 单键(调用点钉键),NOTE 导出签名不变', () => {
  const util = code('src/utils/dashboardMetrics.ts')
  for (const key of ['ruleDisabled', 'collectionFailed', 'tcpUpstreamNote', 'reloadResetNote']) {
    assert.ok(util.includes(`common.app.views.metrics.${key}`), `必须消费 metrics.${key} 词条键`)
  }
  // 导出面不变:两条口径 NOTE 仍以同名常量导出(消费方与行为钉不感知接线)
  assert.match(util, /export const TCP_UPSTREAM_GRANULARITY_NOTE: string = t\('common\.app\.views\.metrics\.tcpUpstreamNote'\)/)
  assert.match(util, /export const METRIC_RELOAD_RESET_NOTE: string = t\('common\.app\.views\.metrics\.reloadResetNote'\)/)
})

test('metrics 词条 zh 母本钉(逐字)', () => {
  assert.ok(existsSync(new URL('../src/locales/zh/views.ts', import.meta.url)), '词条母本 src/locales/zh/views.ts 未落库(integrator 接线)')
  const zhLexicon = code('src/locales/zh/views.ts')
  for (const text of ['已禁用', '采集失败', 'TCP 指标按上游地址汇总；多规则共享同一上游地址时为合计值', '自最近一次配置重载以来累计（保存规则/设置触发重载即归零）']) {
    assert.ok(zhLexicon.includes(text), `metrics 词条 zh 原文「${text.slice(0, 18)}…」必须在母本中`)
  }
  assert.equal(metrics('ruleDisabled'), '已禁用')
  assert.equal(metrics('collectionFailed'), '采集失败')
})
