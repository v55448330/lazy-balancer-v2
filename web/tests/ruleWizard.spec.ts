import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyDynamicUpstreamLimit,
  applyTcpState,
  copyRuleDomain,
  createWizardDraftTracker,
  dnsServerAfterToggle,
  dynamicUpstreamSurplus,
  resetNtlmTakeover,
  restoreHttpState,
  snapshotHttpState,
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

// ── 协议切换：HTTP 态快照 → 切 TCP 清理 → 点回 HTTP 回填 ──
// 向导里误点 TCP 再点回 HTTP，曾只还原监听端口与上游协议：认证网关、自定义
// 路由、动态上游、NTLM 接管、回源域名、TLS 全部丢失。清理面不能取消（后端
// 写侧门硬拒、载荷无条件上送，且 TCP 下没有可见控件可关），能修的只有回转丢失。

type SeedRow = {
  id?: number
  host: string
  port: number
  weight: number
  enabled: boolean
  protocol: 'http' | 'https' | 'tcp' | 'tls'
  origin_domain: string
  max_connections: number
}
type SeedPathRule = {
  id: number
  match_type: string
  path: string
  sort_order: number
  response_mode: string
  upstreams: Array<{ address: string; port: number; weight: number }> | null
}
type SeedForm = {
  name: string
  listen_port: number
  enable_tls: boolean
  strategy: string
  ntlm_compatible: number
  proxy_flush_interval: number
  upstream_keepalive_timeout: number
  upstream_force_http1: number
  tcp_try_duration: number
  enable_active_health_check: boolean
  forward_auth_enabled: number
  forward_auth_upstream: string
  forward_auth_uri: string
  custom_routes_enabled: boolean
  health_check_host: string
  path_rules: SeedPathRule[]
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  upstreams: SeedRow[]
  health_check_interval: number
}

const row = (overrides: Partial<SeedRow>): SeedRow => ({
  host: '10.0.0.1',
  port: 80,
  weight: 50,
  enabled: true,
  protocol: 'http',
  origin_domain: '',
  max_connections: 0,
  ...overrides,
})

// 满配 HTTP 态：每个会被「切 TCP」清掉/改写的字段都带非默认值——回填漏掉任何
// 一个字段，与 seed 的 deepEqual 立刻红。
const httpSeed = (): SeedForm => ({
  name: 'demo',
  listen_port: 443,
  enable_tls: true,
  strategy: 'cookie',
  ntlm_compatible: 1,
  proxy_flush_interval: -1,
  upstream_keepalive_timeout: 300,
  upstream_force_http1: 1,
  tcp_try_duration: -1,
  enable_active_health_check: false,
  forward_auth_enabled: 1,
  forward_auth_upstream: 'http://authelia:9091',
  forward_auth_uri: '/api/authz/forward-auth',
  custom_routes_enabled: true,
  health_check_host: 'health.example.test',
  path_rules: [
    {
      id: 11,
      match_type: 'prefix',
      path: '/api',
      sort_order: 0,
      response_mode: 'forward',
      upstreams: [{ address: '10.0.0.9', port: 8080, weight: 100 }],
    },
    { id: 12, match_type: 'exact', path: '/healthz', sort_order: 1, response_mode: 'static', upstreams: null },
  ],
  dynamic_dns: true,
  enable_dns_server: true,
  dns_server: '10.0.0.53',
  upstreams: [
    row({ id: 1, port: 80, weight: 60, protocol: 'http', origin_domain: 'api.example.test' }),
    row({ id: 2, host: '10.0.0.2', port: 443, weight: 40, protocol: 'https', origin_domain: 'static.example.test' }),
  ],
  health_check_interval: 10,
})

test('切 TCP：HTTP 专属配置整面清空（后端写侧门硬拒的残留一个不留）', () => {
  const form = httpSeed()
  assert.deepEqual(applyTcpState(form), { portRelocated: true })
  assert.equal(form.listen_port, 8080, '80/443 是 HTTP 保留口，TCP 迁到 8080')
  assert.equal(form.enable_tls, false)
  assert.equal(form.strategy, 'weighted_round_robin', 'cookie 会话保持仅 HTTP')
  assert.equal(form.ntlm_compatible, 0)
  assert.deepEqual(
    {
      flush: form.proxy_flush_interval,
      keepalive: form.upstream_keepalive_timeout,
      forceHttp1: form.upstream_force_http1,
      try: form.tcp_try_duration,
      active: form.enable_active_health_check,
    },
    { flush: 0, keepalive: 0, forceHttp1: 0, try: 0, active: false },
    'NTLM 接管字段随开关一起恢复默认',
  )
  assert.equal(form.forward_auth_enabled, 0)
  assert.equal(form.forward_auth_upstream, '')
  assert.equal(form.custom_routes_enabled, false)
  assert.equal(form.health_check_host, '')
  assert.equal(form.path_rules.length, 0)
  assert.equal(form.dynamic_dns, false)
  assert.equal(form.enable_dns_server, false)
  assert.equal(form.dns_server, '')
  assert.deepEqual(form.upstreams.map((item) => item.origin_domain), ['', ''], '逐上游回源域名清空')
  assert.deepEqual(form.upstreams.map((item) => item.protocol), ['tcp', 'tls'], '上游协议落到 TCP 族')
  // 两协议通用的字段不归清理面管
  assert.equal(form.name, 'demo')
  assert.equal(form.health_check_interval, 10)
})

test('切 TCP 的端口迁移只动 80/443，其余端口原样保留', () => {
  for (const [port, expected] of [[80, 8080], [443, 8080], [8443, 8443], [8080, 8080], [10000, 10000]] as const) {
    const form = { ...httpSeed(), listen_port: port }
    const moved = applyTcpState(form)
    assert.equal(form.listen_port, expected)
    assert.equal(moved.portRelocated, port === 80 || port === 443)
  }
})

test('NTLM 未开启时切 TCP 不碰接管字段（它们本就是用户自己的配置）', () => {
  const form = {
    ...httpSeed(),
    strategy: 'ip_hash',
    ntlm_compatible: 0,
    proxy_flush_interval: 5,
    upstream_keepalive_timeout: 7200,
    tcp_try_duration: 3000,
    enable_active_health_check: true,
  }
  applyTcpState(form)
  assert.deepEqual(
    {
      strategy: form.strategy,
      flush: form.proxy_flush_interval,
      keepalive: form.upstream_keepalive_timeout,
      try: form.tcp_try_duration,
      active: form.enable_active_health_check,
    },
    { strategy: 'ip_hash', flush: 5, keepalive: 7200, try: 3000, active: true },
  )
  assert.equal(form.upstream_force_http1, 0, '强制 HTTP/1.1 是 HTTP 传输语义，仍清空')
})

test('快照是深拷贝：拍完快照后表单怎么改都污染不到它', () => {
  const form = httpSeed()
  const snapshot = snapshotHttpState(form)
  const snapRule = snapshot.path_rules[0] as SeedPathRule
  assert.notEqual(snapRule, form.path_rules[0])
  assert.notEqual(snapRule.upstreams, form.path_rules[0]!.upstreams)
  form.path_rules[0]!.path = '/changed'
  form.dns_server = 'changed'
  assert.equal(snapRule.path, '/api')
  assert.equal(snapshot.dns_server, '10.0.0.53')
})

test('误点 TCP 再点回 HTTP：整段回到切换前（含 TLS），回填不与快照共享引用', () => {
  const form = httpSeed()
  const seed = httpSeed()
  const snapshot = snapshotHttpState(form)
  applyTcpState(form)
  // 前置：TCP 态确实被清空
  assert.equal(form.path_rules.length, 0)
  assert.equal(form.forward_auth_enabled, 0)
  assert.equal(form.dynamic_dns, false)
  assert.deepEqual(form.upstreams.map((item) => item.protocol), ['tcp', 'tls'])
  assert.equal(restoreHttpState(form, snapshot), true, '有字段被回填')
  assert.deepEqual(form, seed)
  assert.notEqual(form.path_rules, snapshot.path_rules)
  assert.notEqual(form.path_rules[0], snapshot.path_rules[0])
  assert.notEqual(form.path_rules[0]!.upstreams, (snapshot.path_rules[0] as SeedPathRule).upstreams)
  form.path_rules[0]!.path = '/edited-after-restore'
  assert.equal((snapshot.path_rules[0] as SeedPathRule).path, '/api', '回填后的表单不与快照共享引用')
})

test('回填恢复 TLS 时不把监听端口拖去 443（快照端口优先）', () => {
  const form = { ...httpSeed(), listen_port: 8443 }
  const snapshot = snapshotHttpState(form)
  applyTcpState(form)
  assert.equal(form.enable_tls, false)
  restoreHttpState(form, snapshot)
  assert.equal(form.enable_tls, true)
  assert.equal(form.listen_port, 8443)
})

test('TCP 下改过 NTLM 接管字段：回转不再把 NTLM 拉回，HTTP 专属配置照旧回填', () => {
  const form = httpSeed()
  const snapshot = snapshotHttpState(form)
  applyTcpState(form)
  form.enable_active_health_check = true
  form.tcp_try_duration = 2000
  form.name = 'renamed-in-tcp'
  form.health_check_interval = 20
  restoreHttpState(form, snapshot)
  assert.equal(form.ntlm_compatible, 0, 'NTLM 拉回会强制关闭刚打开的主动检查、禁用刚设的重试窗口')
  assert.equal(form.enable_active_health_check, true)
  assert.equal(form.tcp_try_duration, 2000)
  assert.equal(form.enable_tls, true)
  assert.equal(form.forward_auth_enabled, 1)
  assert.equal(form.forward_auth_upstream, 'http://authelia:9091')
  assert.equal(form.path_rules.length, 2)
  assert.deepEqual(form.upstreams.map((item) => item.origin_domain), ['api.example.test', 'static.example.test'])
  assert.equal(form.name, 'renamed-in-tcp')
  assert.equal(form.health_check_interval, 20)
})

test('TCP 下显式改过的监听端口与负载策略在回转后保留', () => {
  const form = {
    ...httpSeed(),
    ntlm_compatible: 0,
    proxy_flush_interval: 0,
    upstream_keepalive_timeout: 0,
    tcp_try_duration: 0,
  }
  const snapshot = snapshotHttpState(form)
  applyTcpState(form)
  assert.equal(form.listen_port, 8080)
  assert.equal(form.strategy, 'weighted_round_robin')
  form.listen_port = 9000
  form.strategy = 'ip_hash'
  restoreHttpState(form, snapshot)
  assert.equal(form.listen_port, 9000)
  assert.equal(form.strategy, 'ip_hash')
})

test('逐上游回填按后端身份对位：TCP 下增改的行不会被安上别的后端的回源域名', () => {
  const form = httpSeed()
  form.upstreams.push(
    row({ host: '10.0.0.4', origin_domain: 'svc.example.test' }),
    row({ host: '10.0.0.5', port: 81, origin_domain: 'old.example.test' }),
  )
  const snapshot = snapshotHttpState(form)
  applyTcpState(form)
  // 库内行（有 id）改了地址：仍是同一后端
  form.upstreams[0]!.host = '10.0.9.9'
  // 未入库的行在 TCP 下改了协议
  form.upstreams[2]!.protocol = 'tls'
  // 未入库的行在 TCP 下改了地址：与快照对不上号
  form.upstreams[3]!.host = '10.0.0.50'
  // TCP 下新增的行
  form.upstreams.push(row({ host: '10.0.0.3', port: 8080, protocol: 'tcp' }))
  restoreHttpState(form, snapshot)
  assert.deepEqual(
    form.upstreams.map((item) => [item.host, item.protocol, item.origin_domain]),
    [
      ['10.0.9.9', 'http', 'api.example.test'],
      ['10.0.0.2', 'https', 'static.example.test'],
      ['10.0.0.4', 'https', 'svc.example.test'],
      ['10.0.0.50', 'http', ''],
      ['10.0.0.3', 'http', ''],
    ],
  )
})

test('没有可回填的差异时返回 false（视图据此决定是否提示「已恢复」）', () => {
  const form = {
    ...httpSeed(),
    listen_port: 8080,
    enable_tls: false,
    strategy: 'weighted_round_robin',
    ntlm_compatible: 0,
    proxy_flush_interval: 0,
    upstream_keepalive_timeout: 0,
    tcp_try_duration: 0,
    forward_auth_enabled: 0,
    forward_auth_upstream: '',
    upstream_force_http1: 0,
    custom_routes_enabled: false,
    path_rules: [],
    health_check_host: '',
    dynamic_dns: false,
    enable_dns_server: false,
    dns_server: '',
    upstreams: [],
  }
  const snapshot = snapshotHttpState(form)
  applyTcpState(form)
  form.strategy = 'ip_hash'
  assert.equal(restoreHttpState(form, snapshot), false)
  assert.equal(form.strategy, 'ip_hash')
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
