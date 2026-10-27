// 请求级会话身份验收：旧令牌的在途请求即使迟到 401，也只能 reject 原调用方，
// 不得把新登录会话误判为失效；当前令牌的真实 401 仍保留全站止损与重登入口。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { codeSection } from './_helpers.ts'
import { isRequestAuthTokenCurrent } from '../src/utils/apiFailure.ts'

test('仅请求发起令牌与当前令牌一致时才按当前会话失效处理', () => {
  assert.equal(isRequestAuthTokenCurrent('tok-old', 'tok-new'), false)
  assert.equal(isRequestAuthTokenCurrent(undefined, 'tok-new'), false)
  assert.equal(isRequestAuthTokenCurrent('tok-new', 'tok-new'), true)
  assert.equal(isRequestAuthTokenCurrent(undefined, null), true)
})

test('请求拦截器记录发起令牌，401 分支先复核再进入会话失效处置', () => {
  const requestInterceptor = codeSection(
    'src/utils/api.ts',
    'service.interceptors.request.use(',
    'service.interceptors.response.use(',
  )
  assert.match(requestInterceptor, /config\._authToken\s*=\s*authToken/)

  const sessionBranch = codeSection(
    'src/utils/api.ts',
    "if (kind === 'session-expired') {",
    "} else if (kind === 'step-up') {",
  )
  assert.match(
    sessionBranch,
    /error\.config\s*&&\s*!isRequestAuthTokenCurrent\(error\.config\._authToken, localStorage\.getItem\('token'\)\)/,
  )
  assert.ok(
    sessionBranch.indexOf('isRequestAuthTokenCurrent(') < sessionBranch.indexOf("await import('@/stores/auth')"),
    '旧会话请求必须在加载认证 store 与弹框前被丢弃',
  )
})

test('请求记录身份代际，428 通过身份守卫编排弹码、刷新与重放', () => {
  const requestInterceptor = codeSection(
    'src/utils/api.ts',
    'service.interceptors.request.use(',
    'service.interceptors.response.use(',
  )
  assert.match(requestInterceptor, /config\._sessionGeneration\s*=\s*currentSessionGeneration\(\)/)

  const stepUp = codeSection('src/utils/api.ts', "} else if (kind === 'step-up') {", '} else if (!isLoginRequest)')
  assert.match(stepUp, /runMfaStepUpRequest\(\{/)
  assert.match(stepUp, /isCurrent,/)
  assert.match(stepUp, /replay: \(\) => \{[\s\S]*?service\.request\(error\.config\)/)

  // 接线只保留窄断言：守卫必须由 createSessionStepUpGate 构造、且拦截器内
  // 不得内联第二份代际比较。比较语义本身由下面的行为用例（apiFailure.spec）
  // 钉住——源码正则无法分辨「比较错变量但仍命中文本」。
  assert.match(
    stepUp,
    /createSessionStepUpGate\(error\.config\?\._sessionGeneration, currentSessionGeneration\)/,
    '428 身份守卫必须经 createSessionStepUpGate 构造（不得内联比较）',
  )
  assert.doesNotMatch(stepUp, /_sessionGeneration\s*===\s*currentSessionGeneration/, '不得内联第二份代际比较')

  const refresh = codeSection('src/stores/auth.ts', 'async function refreshMfaStep', '// v2.1.8 MFA 第二步')
  assert.match(refresh, /applyAuthResponse\(res, true\)/, 'MFA 刷新必须保持同账号身份代际')
})
