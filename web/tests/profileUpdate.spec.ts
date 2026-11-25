import test from 'node:test'
import assert from 'node:assert/strict'
import { isCurrentPasswordRejection } from '../src/utils/profileUpdate.ts'
import { code, repoCode, section } from './_helpers.ts'

test('仅当前密码错误的 PATCH /users/me 401 豁免会话失效', () => {
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '当前密码错误'), true)
  assert.equal(isCurrentPasswordRejection('PATCH', '/api/v1/users/me?from=profile', 401, '当前密码错误'), true)
})

test('「当前密码错误」与后端 auth.go 逐字对齐（跨栈钉）', () => {
  // 分类唯一判据是后端字面量——后端改文案即静默失配（真会话过期被误豁免/
  // 密码错误被误判会话失效）。
  const go = repoCode('internal/handlers/auth.go')
  const catalog = repoCode('internal/i18n/catalog_gen.go')
  assert.ok(catalog.includes('Register("auth.currentPasswordRejected", "当前密码错误"'), 'catalog 母本漂移:「当前密码错误」')
  assert.ok(
    go.includes('MessageKey: "auth.currentPasswordRejected"') || go.includes('apimsg.Envelope(c, 401, "auth.currentPasswordRejected"'),
    'auth.go 不再产生「当前密码错误」键——前端豁免失配',
  )
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

test('en 当前密码 401 经拦截器重建后仍本地 toast（键路径端到端）', () => {
  // 后端 en 响应信封（Accept-Language: en，auth.go auth.currentPasswordRejected）
  const enEnvelope = { code: 401, message: 'The current password is incorrect', message_key: 'auth.currentPasswordRejected' }
  // ApiRequestError 构造同口径：messageKey 从响应体信封解出（api.ts messageKeyOf）
  const rebuiltKey = enEnvelope.message_key
  // en 文案 + 键 → 键路径命中；en 文案无键 → 字面量失配（修复前的零反馈形态）
  assert.equal(isCurrentPasswordRejection('patch', '/users/me', 401, enEnvelope.message, rebuiltKey), true)
  assert.equal(isCurrentPasswordRejection('patch', '/users/me', 401, enEnvelope.message, undefined), false)
  // zh 字面量兜底回归：无键旧响应仍命中
  assert.equal(isCurrentPasswordRejection('patch', '/users/me', 401, '当前密码错误', undefined), true)
})

test('拦截器 credential-rejection 分支携带响应体（messageKey 不丢）', () => {
  // 丢 data → ApiRequestError.messageKey undefined → en 文案失配字面量 → 零 toast。
  // 与 session-expired stale 分支同形：第三参 = 完整响应体信封。
  const api = code('src/utils/api.ts')
  const branch = section(api, "if (kind === 'credential-rejection') {", "if (kind === 'session-expired') {")
  assert.match(branch, /new ApiRequestError\(message, status, error\.response\?\.data\)/,
    'credential-rejection 必须透传响应体（键分类依赖 messageKey）')
})

test('ProfileDialog 分类传 messageKey 第 5 参（键路径接线）', () => {
  const profile = code('src/components/ProfileDialog.vue')
  assert.match(profile, /isCurrentPasswordRejection\('patch', '\/users\/me', error\.status, error\.message, error\.messageKey\)/)
})
