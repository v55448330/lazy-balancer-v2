// 从节点同步失败的展示层翻译：机内标记 `apply_ok_reload_failed` 只在
// sync_error_code=apply_failed 时翻译成用户可读文案，其余形态必须原样透出
// （否则真实的同步失败原因会被通用文案盖掉）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { formatSyncErrorDisplay } from '../src/utils/syncErrorDisplay.ts'

import { repoCode } from './_helpers.ts'

test('非 apply_failed 或空状态原样透出 last_sync_error', () => {
  assert.equal(formatSyncErrorDisplay(undefined), '')
  assert.equal(formatSyncErrorDisplay(null), '')
  assert.equal(formatSyncErrorDisplay({}), '')
  assert.equal(formatSyncErrorDisplay({ last_sync_error: 'transport error' }), 'transport error')
  assert.equal(
    formatSyncErrorDisplay({ sync_error_code: 'transport_failed', last_sync_error: 'apply_ok_reload_failed: x' }),
    'apply_ok_reload_failed: x',
    '仅 apply_failed 才翻译，其它错误码不得改写',
  )
  assert.equal(
    formatSyncErrorDisplay({ sync_error_code: 'apply_failed', last_sync_error: '签名校验失败' }),
    '签名校验失败',
    'apply_failed 但无标记时保留原文（不得无中生有）',
  )
})

test('标记翻译：取标记后的原因段，去掉标记与分隔符', () => {
  assert.equal(
    formatSyncErrorDisplay({ sync_error_code: 'apply_failed', last_sync_error: 'apply_ok_reload_failed: caddy down' }),
    '配置已同步但 Caddy 重载失败，系统将自动重试：caddy down',
  )
})

test('标记后无原因时不追加冒号段', () => {
  assert.equal(
    formatSyncErrorDisplay({ sync_error_code: 'apply_failed', last_sync_error: 'apply_ok_reload_failed' }),
    '配置已同步但 Caddy 重载失败，系统将自动重试',
  )
  assert.equal(
    formatSyncErrorDisplay({ sync_error_code: 'apply_failed', last_sync_error: 'apply_ok_reload_failed:   ' }),
    '配置已同步但 Caddy 重载失败，系统将自动重试',
  )
})

test('后续失败段只贡献「第 N 次」，不混进原因', () => {
  assert.equal(
    formatSyncErrorDisplay({
      sync_error_code: 'apply_failed',
      last_sync_error: 'apply_ok_reload_failed: caddy down | 同步失败（已连续 3 次）: EOF',
    }),
    '配置已同步但 Caddy 重载失败，系统将自动重试（第 3 次）：caddy down',
  )
  assert.equal(
    formatSyncErrorDisplay({
      sync_error_code: 'apply_failed',
      last_sync_error: 'apply_ok_reload_failed | 同步失败（已连续 12 次）: EOF',
    }),
    '配置已同步但 Caddy 重载失败，系统将自动重试（第 12 次）',
    '无原因但带重试计数：只给计数',
  )
})

test('机内标记与后端 cluster_sync.go / models 逐字对齐（跨栈钉）', () => {
  // 翻译依赖后端机内标记 apply_ok_reload_failed 与 sync_error_code=apply_failed——
  // 后端改标记/改码即静默退回原文透出。
  const go = repoCode('internal/services/cluster_sync.go')
  assert.ok(go.includes('"apply_ok_reload_failed"'), 'cluster_sync.go 不再产生 apply_ok_reload_failed 标记')
  const models = repoCode('internal/models/cluster.go')
  assert.match(models, /SyncErrorCodeApplyFailed\s+SyncErrorCode\s*=\s*"apply_failed"/, 'apply_failed 码漂移')
})
