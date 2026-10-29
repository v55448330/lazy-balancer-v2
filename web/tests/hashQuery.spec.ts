// hash 查询串单源解析/剥离契约（utils/hashQuery：App 首屏预处理与 auth store
// 深链共用）。
//
// 关键口径：
//   1. 回调入口按路径段**精确**判定——普通深链携带「/oidc/callback」子串
//      （`#/login?next=/oidc/callback`、`#/x/oidc/callback?token=…`）不得被
//      识别成回调入口，否则任意页面可借子串触发令牌接收分支。
//   2. 剥离后剩余为空串时不拼「?」、hash 整段消失（不得残留「#?」）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { readHashQuery, stripHashParams } from '../src/utils/hashQuery.ts'
import { code } from './_helpers.ts'

test('readHashQuery：带路径形态剥路径段并解析查询串', () => {
  const hq = readHashQuery('#/oidc/callback?token=abc&return_to=%2Frules&expires_at=123')
  assert.equal(hq.path, '/oidc/callback')
  assert.equal(hq.params.get('token'), 'abc')
  assert.equal(hq.params.get('return_to'), '/rules')
  assert.equal(hq.params.get('expires_at'), '123')
})

test('readHashQuery：无路径形态整段即查询串', () => {
  const hq = readHashQuery('#login_ticket=t1')
  assert.equal(hq.path, '')
  assert.equal(hq.params.get('login_ticket'), 't1')
})

test('readHashQuery：空 hash 与无查询串路径', () => {
  assert.deepEqual(readHashQuery('').path, '')
  assert.equal(readHashQuery('#/dashboard').path, '/dashboard')
  assert.equal(readHashQuery('#/dashboard').params.get('x'), null)
})

test('回调入口精确判定：携带子串的普通深链不得进入回调分支', () => {
  // 深链路径内含子串
  assert.notEqual(readHashQuery('#/settings/oidc/callback?token=x').path, '/oidc/callback')
  // next/return 参数携带子串（子串在查询串里，路径段是 /login）
  assert.notEqual(readHashQuery('#/login?next=/oidc/callback').path, '/oidc/callback')
  // 恰好完整路径仍命中
  assert.equal(readHashQuery('#/oidc/callback').path, '/oidc/callback')
  // 生产侧钉：App.vue 不得退回子串探测
  const app = code('src/App.vue')
  assert.match(app, /oidcCallback = hashPath === '\/oidc\/callback'/)
  assert.doesNotMatch(app, /includes\('\/oidc\/callback'\)/)
})

test('auth store 深链取键复用同一解析（带查询串只取页面键）', () => {
  assert.equal(readHashQuery('#/rules?x=1').path.replace(/^\//, ''), 'rules')
  assert.equal(readHashQuery('#/rules').path.replace(/^\//, ''), 'rules')
})

test('stripHashParams：剥离命中键、剩余空串不拼「?」、无命中不扰动', () => {
  let lastReplaced: string | null = null
  const host = {
    location: { pathname: '/admin/index.html', search: '', hash: '#/oidc/callback?token=x&keep=y' },
    history: {
      replaceState: (_state: unknown, _title: string, target: string) => { lastReplaced = target },
    },
  }
  ;(globalThis as Record<string, unknown>).window = host
  try {
    stripHashParams(['token', 'expires_at'])
    assert.equal(lastReplaced, '/admin/index.html#keep=y', '剩余非空保留键值；路径段随剥离消失')
    assert.equal(host.location.hash, '#/oidc/callback?token=x&keep=y', '只回写历史，不改运行时 hash')

    lastReplaced = null
    host.location.hash = '#login_ticket=t1'
    stripHashParams(['login_ticket'])
    assert.equal(lastReplaced, '/admin/index.html', '剩余空串不拼「?」且 hash 整段消失')

    lastReplaced = null
    host.location.hash = '#/dashboard'
    stripHashParams(['login_ticket', 'token'])
    assert.equal(lastReplaced, null, '无键命中时不产生 replaceState 扰动')
  } finally {
    delete (globalThis as Record<string, unknown>).window
  }
})
