// 请求体空态的陈述口径：服务端对非管理员/只读 API Key 把 request_body 整体置空
// （security.go maskSecurityEventRequestContextIfNeeded）——掩码位在线上契约里不
// 存在，前端把空串一律读成「本来就没记录」，与同弹框请求头区（敏感值 ••••••）给
// 出相反结论。空态文案必须对无权读者如实披露「可能已记录但看不到」。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { requestBodyEmptyNotice, viewerCanReadRequestBody } from '../src/utils/requestBodyAccess.ts'
import { code, repoCode } from './_helpers.ts'

test('管理员：空请求体就是「无记录」', () => {
  assert.equal(viewerCanReadRequestBody('admin'), true)
  assert.equal(requestBodyEmptyNotice(true), '无请求体记录')
})

test('非管理员/未知角色：空态不得断言「没记录」', () => {
  assert.equal(viewerCanReadRequestBody('user'), false)
  assert.equal(viewerCanReadRequestBody(undefined), false)
  assert.equal(viewerCanReadRequestBody(null), false)
  const notice = requestBodyEmptyNotice(false)
  assert.match(notice, /无请求体记录/)
  assert.match(notice, /看不到请求体正文/, '必须说明是权限掩码而非「未记录」')
  assert.match(notice, /不能据此判断/, '不得把掩码读成「本来就没记录」')
})

// 跨栈机械钉：服务端掩码条件（admin 且非只读 Key）与前端判据必须同向——
// 后端一旦扩大掩码受众（如把普通管理员也纳入），前端文案就会重新说谎。
test('后端掩码受众与前端判据同向', () => {
  const backend = repoCode('internal/handlers/security.go')
  assert.match(backend, /func maskSecurityEventRequestContextIfNeeded\(/)
  assert.match(backend, /if c\.GetString\("role"\) == "admin" && !\(c\.GetString\("auth_type"\) == "api_key" && c\.GetBool\("api_key_read_only"\)\) \{/)
  assert.match(backend, /e\.RequestBody = ""/)
})

test('事件页空态消费单源文案', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /viewerCanReadRequestBody\(authStore\.user\?\.role\)/, '角色判据必须走单源')
  assert.match(page, /\{\{ ctxBodyEmptyText \}\}/, '空态文案必须由计算属性给出')
  assert.doesNotMatch(page, /ctxBodyParsed\.state === 'empty'" class="dialog-panel"><div class="ctx-empty">无请求体记录/, '不得再硬编码「无请求体记录」')
})
