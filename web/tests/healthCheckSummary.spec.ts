// 健康检查摘要与规则向导预览/单规则查看器的字段一致性钉。
//
// 预览自称「配置核对面」，主动探测分支曾只打印 path/interval/timeout（HTTP）或
// 探测端口（TCP）——失败阈值与恢复阈值改完只能在保存后从单规则 JSON 里发现。
// 现两处共用 utils/healthCheckSummary 单源，本钉同时锁行为与接线。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  activeHealthCheckSummary,
  healthCheckSummary,
  passiveHealthCheckSummary,
} from '../src/utils/healthCheckSummary.ts'
import { code, section } from './_helpers.ts'

const page = code('src/views/Rules.vue')

const httpActive = {
  protocol: 'http',
  enable_active_health_check: true,
  health_check_path: '/healthz',
  health_check_interval: 15,
  health_check_timeout: 3,
  health_check_host: 'probe.internal',
  tcp_health_check_port: 0,
  health_check_healthy_threshold: 5,
  health_check_unhealthy_threshold: 8,
}

test('主动探测摘要点名路径/Host/间隔/超时与失败、恢复阈值', () => {
  const text = activeHealthCheckSummary(httpActive)
  for (const part of ['/healthz', '15s', '3s', 'Host: probe.internal', '失败 8 次', '连续 5 次']) {
    assert.ok(text.includes(part), `主动摘要缺「${part}」：${text}`)
  }
})

test('主动探测摘要（TCP）点名探测端口与两阈值，不混入 HTTP 路径/Host', () => {
  const text = activeHealthCheckSummary({ ...httpActive, protocol: 'tcp', tcp_health_check_port: 8443 })
  assert.ok(text.includes('8443'), text)
  assert.ok(text.includes('失败 8 次') && text.includes('连续 5 次'), text)
  assert.doesNotMatch(text, /healthz|Host:/)
  // 0 = 各上游自身端口
  assert.ok(activeHealthCheckSummary({ ...httpActive, protocol: 'tcp', tcp_health_check_port: 0 }).includes('默认'))
})

test('被动摘要只用失败阈值，恢复窗口是间隔的 3 倍且不宣称超时', () => {
  const text = passiveHealthCheckSummary({ ...httpActive, enable_active_health_check: false })
  assert.ok(text.includes('失败 8 次') && text.includes('45s'), text)
  assert.doesNotMatch(text, /超时|连续 5 次/)
})

test('摘要按开关选分支：主动开启不再打印被动行', () => {
  assert.equal(healthCheckSummary(httpActive), activeHealthCheckSummary(httpActive))
  const passive = { ...httpActive, enable_active_health_check: false }
  assert.equal(healthCheckSummary(passive), passiveHealthCheckSummary(passive))
})

test('向导预览与单规则查看器共用同一摘要单源（不再各拼一份）', () => {
  // i18n 后描述项标签走 t() 键（zh 母本原文已由 rulesUi 双钉承载）
  const preview = section(page, "<el-descriptions-item :label=\"t('common.app.rules.wizard.healthCheck')\"", "<el-descriptions-item :label=\"t('common.app.rules.wizard.connectRetry')\"")
  assert.match(preview, /\{\{ healthCheckSummary\(wizardForm\) \}\}/)
  assert.doesNotMatch(preview, /主动探测端口|被动检查 \(失败/, '预览不得再自行拼装文案')

  const viewer = section(page, "<el-descriptions-item :label=\"t('common.app.rules.wizard.activeHealthCheck')\"", "<el-descriptions-item :label=\"t('common.app.rules.wizard.connectRetry')\"")
  assert.match(viewer, /activeHealthCheckSummary\(ruleConfig\)/)
  assert.match(viewer, /passiveHealthCheckSummary\(ruleConfig\)/)
  assert.doesNotMatch(viewer, /TCP 探测端口/, '查看器不得再自行拼装文案')
})

test('渲染层零写死兜底：查看器不再用 || 默认值掩盖未配置阈值', () => {
  const viewer = section(page, "<el-descriptions-item :label=\"t('common.app.rules.wizard.activeHealthCheck')\"", "<el-descriptions-item :label=\"t('common.app.rules.wizard.connectRetry')\"")
  assert.doesNotMatch(viewer, /health_check_unhealthy_threshold \|\|/)
  assert.doesNotMatch(viewer, /health_check_interval \|\|/)
})
