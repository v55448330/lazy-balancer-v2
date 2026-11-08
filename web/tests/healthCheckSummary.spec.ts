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

// ── 批次 D(ingest 域)双钉:摘要文案 i18n 接线 ──
// utils/healthCheckSummary 的摘要改词条参数化后,rulesUi.spec 对摘要源段
// 「恢复窗口/不得含超时」的源文本钉迁至此处:调用点钉键 + zh 母本钉原文。
// 注:非 settings 族钉,批次 F 重做面不覆盖本文件。

import { tSafe } from '../src/i18n/tSafe.ts'
import { existsSync } from 'node:fs'

const ingest = (key: string, params?: Record<string, unknown>): string =>
  tSafe(`common.app.views.ingest.${key}`, params)

test('摘要文案走 i18n 单键(调用点钉键):数值口径全部参数化注入', () => {
  const util = code('src/utils/healthCheckSummary.ts')
  for (const key of ['activeThresholds', 'activeHttp', 'activeHostSuffix', 'activeTcp', 'probePortDefault', 'passive']) {
    assert.ok(util.includes(`common.app.views.ingest.${key}`), `摘要必须消费 ingest.${key} 词条键`)
  }
  // 行为相位:键必须解析为 zh 原文(tSafe 已挂 views 子树,解析失败=键漂移)
  assert.equal(ingest('passive', { unhealthy: 8, window: 45 }), '被动检查 (失败 8 次视为不健康, 恢复窗口 45s)', 'passive 键解析漂移')
  assert.equal(ingest('probePortDefault'), '默认', 'probePortDefault 键解析漂移')
  // 同域 ingest:满表回落桶展示键(导出符号不变,logStatKeyCap 行为钉按符号求值)
  const capUtil = code('src/utils/logStatCap.ts')
  assert.match(capUtil, /export const OTHER_LOG_STAT_KEY: string = t\('common\.app\.views\.ingest\.otherBucket'\)/)
  assert.equal(ingest('otherBucket'), '其他')
})

test('被动摘要语义钉迁词条:恢复窗口在场、不宣称超时(原 rulesUi 源段钉的词条化迁移)', () => {
  const util = code('src/utils/healthCheckSummary.ts')
  assert.doesNotMatch(util, /超时/, '摘要源不得再写死「超时」语义文案(口径在词条)')
  const zhLexicon = code('src/locales/zh/views.ts')
  assert.ok(existsSync(new URL('../src/locales/zh/views.ts', import.meta.url)), '词条母本 src/locales/zh/views.ts 未落库(integrator 接线)')
  assert.ok(zhLexicon.includes('恢复窗口'), '被动摘要「恢复窗口」原文必须在 zh 母本词条中')
  assert.ok(zhLexicon.includes('视为不健康'), '被动摘要判不健康原文必须在 zh 母本词条中')
  assert.ok(zhLexicon.includes('TCP 主动探测端口'), '主动 TCP 摘要原文必须在 zh 母本词条中')
  assert.ok(zhLexicon.includes('次判不健康，连续'), '主动阈值原文必须在 zh 母本词条中')
  assert.doesNotMatch(zhLexicon.split('\n').filter((l) => l.includes('ingest.passive')).join('\n'), /超时/, '被动词条不得宣称超时语义')
})
