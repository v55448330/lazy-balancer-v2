// 通道复合健康态契约：last_test_ok 后端列默认 0（false），从未测试的
// 通道此前被渲染成「验证失败」——判定顺序必须先看 last_test_at（无=未验证），
// 再看 last_test_ok===false（有验证时间且失败=验证失败）。
//
// 运行：cd web && node --test tests/channelHealth.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { channelHealthState } from '../src/utils/channelHealth.ts'

test('未验证优先于验证失败：从未测试的后端默认 last_test_ok=false 不得误报失败', () => {
  assert.equal(
    channelHealthState({ type: 'webhook', enabled: true, last_test_at: '', last_test_ok: false }),
    'unverified',
  )
  assert.equal(
    channelHealthState({ type: 'webhook', enabled: true, last_test_ok: false }),
    'unverified',
    '缺省 last_test_at 同样=未验证',
  )
  assert.equal(channelHealthState({ type: 'email', enabled: true, last_test_at: '' }), 'unverified')
})

test('已测试失败：有 last_test_at 且 last_test_ok=false → 验证失败', () => {
  assert.equal(
    channelHealthState({ type: 'email', enabled: true, last_test_at: '2026-11-22 10:00', last_test_ok: false }),
    'test_failed',
  )
})

test('其余优先级不受影响：停用/连接离线/会话失效/就绪', () => {
  assert.equal(
    channelHealthState({ type: 'webhook', enabled: false, last_test_at: '', last_test_ok: false }),
    'disabled',
    '停用优先于未验证',
  )
  assert.equal(
    channelHealthState({ type: 'qq', enabled: true, link_connected: false, last_test_at: '2026-11-22 10:00', last_test_ok: true }),
    'link_down',
  )
  assert.equal(
    channelHealthState({ type: 'wx_clawbot', enabled: true, session_ready: false, last_test_at: '2026-11-22 10:00', last_test_ok: true }),
    'session_stale',
  )
  assert.equal(
    channelHealthState({ type: 'wx_clawbot', enabled: true, session_ready: true, last_test_at: '2026-11-22 10:00', last_test_ok: false }),
    'test_failed',
    '微信会话在线但测试失败=验证失败，不得误导为「会话待刷新」',
  )
  assert.equal(
    channelHealthState({ type: 'wx_clawbot', enabled: true, session_ready: true, last_test_at: '2026-11-22 10:00', last_test_ok: true }),
    'ready',
  )
})

test('wx 优先级：会话未就绪优先于测试结果；会话就绪时测试失败=验证失败', () => {
  // 会话未就绪：即使测试通过也无法主动发送 → 会话待刷新
  assert.equal(
    channelHealthState({ type: 'wx_clawbot', enabled: true, session_ready: false, last_test_at: '2026-11-22 10:00', last_test_ok: true }),
    'session_stale',
  )
  // 会话未就绪且测试失败：根因仍是会话（先刷新会话再复测）
  assert.equal(
    channelHealthState({ type: 'wx_clawbot', enabled: true, session_ready: false, last_test_at: '2026-11-22 10:00', last_test_ok: false }),
    'session_stale',
  )
  // 会话就绪但测试失败：暴露真实失败原因（不再折叠成「会话待刷新」）
  assert.equal(
    channelHealthState({ type: 'wx_clawbot', enabled: true, session_ready: true, last_test_at: '2026-11-22 10:00', last_test_ok: false }),
    'test_failed',
  )
})
