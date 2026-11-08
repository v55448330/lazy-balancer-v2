import test from 'node:test'
import assert from 'node:assert/strict'
import { isCurrentPasswordRejection } from '../src/utils/profileUpdate.ts'
import { repoCode } from './_helpers.ts'

test('仅当前密码错误的 PATCH /users/me 401 豁免会话失效', () => {
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '当前密码错误'), true)
  assert.equal(isCurrentPasswordRejection('PATCH', '/api/v1/users/me?from=profile', 401, '当前密码错误'), true)
})

test('「当前密码错误」与后端 auth.go 逐字对齐（跨栈钉）', () => {
  // 分类唯一判据是后端字面量——后端改文案即静默失配（真会话过期被误豁免/
  // 密码错误被误判会话失效）。
  const go = repoCode('internal/handlers/auth.go')
  const catalog = repoCode('internal/i18n/catalog_gen.go')
  assert.ok(catalog.includes('Register("k_9561dfdb", "当前密码错误"'), 'catalog 母本漂移:「当前密码错误」')
  assert.ok(go.includes('MessageKey: "k_9561dfdb"'), 'auth.go 不再产生「当前密码错误」键——前端豁免失配')
})

test('同端点的会话过期 401 不得误判为当前密码错误', () => {
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '未登录或登录已过期'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '登录状态已失效'), false)
})

test('其它方法、路径、状态与文案保持原会话处理', () => {
  assert.equal(isCurrentPasswordRejection('get', '/api/v1/users/me', 401, '当前密码错误'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/2', 401, '当前密码错误'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 400, '当前密码错误'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '用户名或密码错误'), false)
})
