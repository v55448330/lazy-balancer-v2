import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildCaddyConfigPayload } from '../src/utils/caddyConfigPayload.ts'
import { code, section, repoCode } from './_helpers.ts'

// 关闭「自定义 JSON」时后端的跨字段门（internal/handlers/caddy.go
// resolveAccessLogFormatGate）：json=false 且请求显式携带非空格式 → 400；
// json=false + 缺键 + 存量非空 → 清空存量并说明。前端必须走后者，否则保存
// 在预览阶段就被 400 阻断（而清空输入框已随开关隐藏）。

const KEYS = ['caddy_log_level', 'access_log_json', 'access_log_format'] as const

test('关闭且存量格式非空：格式键从载荷剔除，并标记库中映射将被清空', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'info', access_log_json: false, access_log_format: 'request>method -> m' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, true)
  assert.deepEqual(Object.keys(payload), ['caddy_log_level', 'access_log_json'], '载荷不得携带格式键')
  assert.equal(payload.access_log_format, undefined)
  assert.equal(payload.access_log_json, false)
})

test('纯空白格式同样剔除（后端按「存量非空」清空，提交空白会被判显式非空）', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'info', access_log_json: false, access_log_format: '   ' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, true)
  assert.equal('access_log_format' in payload, false)
})

test('开启自定义 JSON：格式原样提交，无清空语义', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'info', access_log_json: true, access_log_format: 'request>method -> m' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, false)
  assert.equal(payload.access_log_format, 'request>method -> m')
})

test('关闭且存量格式为空：键照常提交（空串不触发后端门）', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'warn', access_log_json: false, access_log_format: '' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, false)
  assert.equal(payload.access_log_format, '')
})

test('白名单外的键不会泄露进载荷（兄弟卡片未保存编辑不得连带提交）', () => {
  const settings = { caddy_log_level: 'info', access_log_json: true, access_log_format: '', acme_email: 'a@b.c' }
  const { payload } = buildCaddyConfigPayload(settings, KEYS)
  assert.deepEqual(Object.keys(payload).sort(), [...KEYS].sort())
})

test('视图消费单源：载荷经统一组装，清空语义进确认框且与开关提示同口径', () => {
  const card = code('src/views/settings/CaddyGlobalSettings.vue')
  const save = section(code('src/views/settings/CaddyGlobalSettings.vue'), 'const handleSave = async', 'const handleReloadCaddy')
  assert.match(save, /buildCaddyConfigPayload\(settings\.value, CADDY_CONFIG_KEYS\)/)
  assert.doesNotMatch(save, /Object\.fromEntries\(CADDY_CONFIG_KEYS/, '不得保留第二处白名单展开')
  assert.match(save, /accessLogFormatCleared/, '确认框必须消费清空标记')
  assert.match(save, /app\.settings\.caddy\.messages\.customJsonCleared/)
  assert.match(card, /app\.settings\.caddy\.accessLog\.customJsonHint/, '开关提示与确认框同口径')
})

// 跨栈对表：前端载荷语义（剔除格式键 / 保留空串 / 开启时原样）预测的是后端
// resolveAccessLogFormatGate 的判定顺序。此前该契约只写在注释里——后端改判定
// 顺序时前端 6 条用例全绿，用户却会在保存时收到 400。
test('跨栈对表：后端 access_log 跨字段门仍与前端载荷语义一致', () => {
  const go = repoCode('internal/handlers/caddy.go')
  const gate = section(go, 'func resolveAccessLogFormatGate(', 'func (h *Handlers) PreviewConfigUpdate(')
  assert.match(gate, /effectiveAccessLogJSON := old\.AccessLogJSON/, '未显式携带时按存量生效值判定')
  assert.match(gate, /if effectiveAccessLogJSON \{/, 'json=true 无门')
  assert.match(gate, /strings\.TrimSpace\(\*req\.AccessLogFormat\) != ""/, '显式非空格式必须报错（前端因此剔除键）')
  assert.match(gate, /storedFormat := old\.AccessLogFormat/)
  assert.match(gate, /req\.AccessLogFormat = &emptyFormat/, 'json=false 且有存量/显式格式时净空')
  assert.match(gate, /return true, nil/)
  // 保存与预览共用同一门：只在一侧归一会让预览对「保存必 400」的载荷放行。
  const calls = go.match(/resolveAccessLogFormatGate\(&req, old\)/g) ?? []
  assert.equal(calls.length, 2, '保存与预览都必须经同一跨字段门')
})
