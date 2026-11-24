import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyDynamicUpstreamLimit,
  copyRuleDomain,
  createWizardDraftTracker,
  dnsServerAfterToggle,
  dynamicUpstreamSurplus,
  resetNtlmTakeover,
  wizardDraftFingerprint,
} from '../src/utils/ruleWizard.ts'
import { code } from './_helpers.ts'

test('水合 false 配置不得清空已存 dns_server', () => {
  assert.equal(dnsServerAfterToggle('10.0.0.53', false, true), '10.0.0.53')
})

test('用户主动关闭仍清空，启用与水合 true 保留', () => {
  assert.equal(dnsServerAfterToggle('10.0.0.53', false, false), '')
  assert.equal(dnsServerAfterToggle('10.0.0.53', true, false), '10.0.0.53')
  assert.equal(dnsServerAfterToggle('10.0.0.53', true, true), '10.0.0.53')
})

// 纯函数全绿也拦不住「二三参写反」：实参顺序一旦错位，「水合」会被当成
// 「用户主动关闭」，已存 dns_server 被清空（原缺陷直接回归）。故按位置钉接线。
test('接线：向导以 (当前值, 新值, 是否水合) 顺序调用', () => {
  const page = code('src/views/Rules.vue')
  const calls = [...page.matchAll(/dnsServerAfterToggle\(([^)]*)\)/g)]
  assert.equal(calls.length, 1, `消费点应唯一（实际 ${calls.length}）——新增调用点须同步本断言`)
  const args = calls[0]![1]!.split(',').map((arg) => arg.trim())
  assert.deepEqual(
    args,
    ['wizardForm.dns_server', 'newVal', 'hydratingWizard'],
    '实参顺序必须是 (当前值, 新值, 是否水合)',
  )
})

test('NTLM 关闭 / 切 TCP 的「恢复默认」字段面不变', () => {
  const form = {
    strategy: 'cookie',
    proxy_flush_interval: -1,
    upstream_keepalive_timeout: 300,
    upstream_force_http1: 1,
    tcp_try_duration: -1,
    enable_active_health_check: true,
  }
  resetNtlmTakeover(form)
  assert.deepEqual(form, {
    strategy: 'weighted_round_robin',
    proxy_flush_interval: 0,
    upstream_keepalive_timeout: 0,
    upstream_force_http1: 0,
    tcp_try_duration: 0,
    enable_active_health_check: false,
  })
})

// ── 关闭向导前的未保存检查 ──

test('草稿指纹与键序无关、覆盖嵌套内容、忽略 undefined 属性', () => {
  assert.equal(
    wizardDraftFingerprint({ a: 1, b: { c: [1, 2], d: 'x' } }),
    wizardDraftFingerprint({ b: { d: 'x', c: [1, 2] }, a: 1 }),
  )
  assert.notEqual(wizardDraftFingerprint({ b: { c: [1, 2] } }), wizardDraftFingerprint({ b: { c: [1, 3] } }))
  assert.notEqual(wizardDraftFingerprint({ tls_key: '' }), wizardDraftFingerprint({ tls_key: '-----BEGIN' }))
  assert.equal(wizardDraftFingerprint({ a: undefined, b: 1 }), wizardDraftFingerprint({ b: 1 }))
})

test('未保存检查：看过没改不打扰，改了算脏，改回原样不算脏', () => {
  const form = { name: 'a', upstreams: [{ host: '10.0.0.1', weight: 0 }] }
  const draft = createWizardDraftTracker(() => form)
  assert.equal(draft.isDirty(), false, '向导未打开：没有基线')
  draft.open()
  draft.settle()
  assert.equal(draft.isDirty(), false)
  draft.touch()
  assert.equal(draft.isDirty(), false, '点过内容区但没改任何值')
  form.name = 'b'
  assert.equal(draft.isDirty(), true)
  form.name = 'a'
  assert.equal(draft.isDirty(), false)
  draft.clear()
  assert.equal(draft.isDirty(), false, '关闭即清基线')
})

test('未保存检查：控件的自动归一不算改动（基线在入场动画结束时定稿）', () => {
  const form = { upstreams: [{ host: '10.0.0.1', weight: 0 }] }
  const draft = createWizardDraftTracker(() => form)
  draft.open()
  // el-input-number 挂载后把越界值钳写回表单（禁用行权重 0 → 1）
  form.upstreams[0]!.weight = 1
  draft.settle()
  draft.touch()
  assert.equal(draft.isDirty(), false, '用户没改过值，归一不得被当成未保存修改')
})

test('未保存检查：入场动画期间的修改不会被定稿吞掉', () => {
  const form = { name: 'a' }
  const draft = createWizardDraftTracker(() => form)
  draft.open()
  draft.touch()
  form.name = 'typed-during-fade-in'
  draft.settle()
  assert.equal(draft.isDirty(), true)
})

test('未保存检查：动画未结束就关闭时，没碰过表单不弹确认', () => {
  const form = { upstreams: [{ host: '10.0.0.1', weight: 0 }] }
  const draft = createWizardDraftTracker(() => form)
  draft.open()
  form.upstreams[0]!.weight = 1
  assert.equal(draft.isDirty(), false, '没碰过表单：差异只可能来自控件归一')
})

// ── 动态上游：仅保留首个启用上游 ──

test('将被禁用的是「首个启用上游」之后的启用行（禁用行不算数）', () => {
  const rows = [
    { host: 'a', port: 80, weight: 50, enabled: true },
    { host: 'off', port: 80, weight: 0, enabled: false },
    { host: 'b', port: 80, weight: 30, enabled: true },
    { host: 'c', port: 80, weight: 20, enabled: true },
  ]
  assert.deepEqual(dynamicUpstreamSurplus(rows).map((item) => item.host), ['b', 'c'])
  assert.deepEqual(dynamicUpstreamSurplus([rows[0]!, rows[1]!]), [])
  assert.deepEqual(dynamicUpstreamSurplus([]), [])
})

test('应用后仅首个启用上游在役且权重 100，其余启用行禁用清零，行序不变', () => {
  const rows = [
    { host: 'off', port: 80, weight: 0, enabled: false },
    { host: 'a', port: 80, weight: 50, enabled: true },
    { host: 'b', port: 80, weight: 30, enabled: true },
    { host: 'c', port: 80, weight: 20, enabled: true },
  ]
  applyDynamicUpstreamLimit(rows)
  assert.deepEqual(rows, [
    { host: 'off', port: 80, weight: 0, enabled: false },
    { host: 'a', port: 80, weight: 100, enabled: true },
    { host: 'b', port: 80, weight: 0, enabled: false },
    { host: 'c', port: 80, weight: 0, enabled: false },
  ])
  const single = [{ host: 'a', port: 80, weight: 40, enabled: true }]
  applyDynamicUpstreamLimit(single)
  assert.deepEqual(single, [{ host: 'a', port: 80, weight: 100, enabled: true }])
})

// ── 复制规则：副本的默认态 ──

test('副本不继承 HTTP 域名；TCP 规则没有域名概念，原样返回', () => {
  assert.equal(copyRuleDomain({ protocol: 'http', domain: 'a.example.com' }), '')
  assert.equal(copyRuleDomain({ protocol: 'http', domain: '' }), '')
  assert.equal(copyRuleDomain({ protocol: 'tcp', domain: '' }), '')
  assert.equal(copyRuleDomain({ protocol: 'tcp' }), '')
})
