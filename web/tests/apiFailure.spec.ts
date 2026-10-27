// 请求失败处置编排的行为验收（utils/apiFailure）：
//   - classifyAuthFailure：401 凭证豁免 / 会话失效 / 428 step-up / 普通错误
//   - createMfaStepUp：并发 428 弹码单飞、验证码消费即作废、同码只刷新一次、
//     新一轮弹码作废旧刷新、刷新失败可重试
//   - createMfaGraceTracker：60s 节流、同文案兜底条去重、刚弹码验证抑制、
//     业务成功提示的 3s 宽限窗判定
//
// 这些判据直接决定「输错验证码会不会被登出」「并发保存会不会弹两次窗」
// 「同码会不会重放」，此前只有源码文本钉。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { classifyAuthFailure, createMfaGraceTracker, createMfaStepUp, runMfaStepUpRequest } from '../src/utils/apiFailure.ts'

const deferred = <T,>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } => {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

const handle = (): { closed: boolean; close: () => void } => {
  const h = { closed: false, close: (): void => { h.closed = true } }
  return h
}

// ── classifyAuthFailure ──────────────────────────────────────────────

const failure = (overrides: Partial<Parameters<typeof classifyAuthFailure>[0]> = {}) => ({
  status: 401,
  dataCode: undefined,
  method: 'post',
  url: '/rules',
  message: '未登录或登录已过期',
  isLoginRequest: false,
  hasConfig: true,
  mfaRetried: false,
  ...overrides,
})

test('401 凭证错误豁免会话失效（MFA 验码 / 本人资料当前密码）', () => {
  assert.equal(classifyAuthFailure(failure({ url: '/auth/mfa/verify-step', message: '验证码错误' })), 'credential-rejection')
  assert.equal(classifyAuthFailure(failure({ url: '/users/3/mfa/reset', message: '验证码错误' })), 'credential-rejection')
  assert.equal(classifyAuthFailure(failure({ method: 'patch', url: '/api/v1/users/me', message: '当前密码错误' })), 'credential-rejection')
})

test('同端点的会话过期 401 仍走会话失效流程', () => {
  assert.equal(classifyAuthFailure(failure({ url: '/auth/mfa/verify-step' })), 'session-expired')
  assert.equal(classifyAuthFailure(failure({ method: 'patch', url: '/api/v1/users/me' })), 'session-expired')
  assert.equal(classifyAuthFailure(failure({ url: '/rules', message: '验证码错误' })), 'session-expired')
})

test('登录请求的 401 不触发会话失效弹窗', () => {
  assert.equal(classifyAuthFailure(failure({ url: '/auth/login', message: '用户名或密码错误', isLoginRequest: true })), 'generic')
  assert.equal(classifyAuthFailure(failure({ url: '/auth/ticket-login', message: '票据无效', isLoginRequest: true })), 'generic')
})

test('428 仅在「HTTP 428 + 业务码 428 + 可重试」时进入 step-up', () => {
  assert.equal(classifyAuthFailure(failure({ status: 428, dataCode: 428 })), 'step-up')
  assert.equal(classifyAuthFailure(failure({ status: 428, dataCode: 428, mfaRetried: true })), 'generic', '已重试过不得再弹码')
  assert.equal(classifyAuthFailure(failure({ status: 428, dataCode: 1 })), 'generic', '业务码不是 428 不弹码')
  assert.equal(classifyAuthFailure(failure({ status: 428, dataCode: 428, hasConfig: false })), 'generic', '无请求配置无法重试')
  assert.equal(classifyAuthFailure(failure({ status: 428 })), 'generic')
})

test('其它状态码一律普通错误', () => {
  for (const status of [400, 403, 409, 429, 500, 502, undefined]) {
    assert.equal(classifyAuthFailure(failure({ status, message: '错误' })), 'generic')
  }
})

// ── createMfaStepUp ────────────────────────────────────────────────

test('并发 428 共享同一弹窗（不再连环弹窗/被误判取消）', async () => {
  const opened = deferred<string | null>()
  let opens = 0
  const stepUp = createMfaStepUp(() => { opens++; return opened.promise })

  const first = stepUp.prompt()
  const second = stepUp.prompt()
  assert.equal(opens, 1, '在途期间只弹一次')
  assert.equal(stepUp.isPromptPending(), true)

  opened.resolve('123456')
  assert.deepEqual(await Promise.all([first, second]), ['123456', '123456'])
  assert.equal(stepUp.isPromptPending(), false)
})

test('验证码消费后立即作废：下一轮 428 必须重新弹窗', async () => {
  let opens = 0
  const stepUp = createMfaStepUp(async () => `code-${++opens}`)
  assert.equal(await stepUp.prompt(), 'code-1')
  assert.equal(stepUp.isPromptPending(), false)
  assert.equal(await stepUp.prompt(), 'code-2')
  assert.equal(await stepUp.prompt(), 'code-3')
  assert.equal(opens, 3)
})

test('用户取消返回 null，且不影响下一轮弹窗', async () => {
  let opens = 0
  const stepUp = createMfaStepUp(async () => { opens++; return opens === 1 ? null : '654321' })
  assert.equal(await stepUp.prompt(), null)
  assert.equal(await stepUp.prompt(), '654321')
  assert.equal(opens, 2)
})

test('弹窗实现抛错时复位在途标记：下一次 428 仍会重新弹窗', async () => {
  const first = deferred<string | null>()
  let opens = 0
  const stepUp = createMfaStepUp(() => { opens++; return opens === 1 ? first.promise : Promise.resolve('222222') })
  const failed = stepUp.prompt()
  assert.equal(stepUp.isPromptPending(), true)
  first.reject(new Error('dialog crashed'))
  await assert.rejects(failed, /dialog crashed/)
  assert.equal(stepUp.isPromptPending(), false, '失败必须复位（否则后续 428 永远共享已 rejection 的 Promise）')
  assert.equal(await stepUp.prompt(), '222222')
  assert.equal(opens, 2)
})

test('同码重放防护：并发等待者共享同一次 verify-step 刷新', async () => {
  const refresh = deferred<void>()
  let refreshes = 0
  const stepUp = createMfaStepUp(async () => '123456')
  const refreshFn = (_code: string): Promise<void> => { refreshes++; return refresh.promise }

  const first = stepUp.ensureRefresh('123456', refreshFn)
  const second = stepUp.ensureRefresh('123456', refreshFn)
  assert.equal(refreshes, 1, '在途刷新必须复用')
  refresh.resolve()
  await Promise.all([first, second])

  await stepUp.ensureRefresh('123456', async () => { refreshes++ })
  assert.equal(refreshes, 2, '完成后下一轮重新刷新')
})

test('verify-step 失败可重试（不缓存失败）', async () => {
  let refreshes = 0
  const stepUp = createMfaStepUp(async () => '123456')
  await assert.rejects(
    stepUp.ensureRefresh('123456', async () => { refreshes++; throw new Error('429 验证码尝试过于频繁') }),
    /429/,
  )
  await stepUp.ensureRefresh('123456', async () => { refreshes++ })
  assert.equal(refreshes, 2)
})

test('新一轮弹码作废旧刷新句柄（旧在途请求仍会跑完但不被复用）', async () => {
  const oldRefresh = deferred<void>()
  let refreshes = 0
  const stepUp = createMfaStepUp(async () => 'new-code')
  const old = stepUp.ensureRefresh('111111', () => { refreshes++; return oldRefresh.promise })
  await stepUp.prompt()
  await stepUp.ensureRefresh('222222', async () => { refreshes++ })
  assert.equal(refreshes, 2, '弹码后必须用新验证码重新刷新')
  oldRefresh.resolve()
  await old
})

test('旧身份迟到的 428 不弹码、不刷新、不重放', async () => {
  let current = false
  const calls: string[] = []
  const result = await runMfaStepUpRequest({
    isCurrent: () => current,
    prompt: async () => { calls.push('prompt'); return '123456' },
    refresh: async () => { calls.push('refresh') },
    replay: async () => { calls.push('replay'); return 'unexpected' },
  })
  assert.deepEqual(result, { kind: 'stale' })
  assert.deepEqual(calls, [])
  current = true
})

test('弹码期间换号后不得刷新；刷新后换号不得重放', async () => {
  let current = true
  const calls: string[] = []
  const switchedBeforeRefresh = runMfaStepUpRequest({
    isCurrent: () => current,
    prompt: async () => { current = false; return '123456' },
    refresh: async () => { calls.push('refresh') },
    replay: async () => { calls.push('replay'); return 'unexpected' },
  })
  assert.deepEqual(await switchedBeforeRefresh, { kind: 'stale' })
  assert.equal(calls.length, 0)

  current = true
  const switchedBeforeReplay = await runMfaStepUpRequest({
    isCurrent: () => current,
    prompt: async () => '123456',
    refresh: async () => { calls.push('refresh'); current = false },
    replay: async () => { calls.push('replay'); return 'unexpected' },
  })
  assert.deepEqual(switchedBeforeReplay, { kind: 'stale' })
  assert.deepEqual(calls, ['refresh'])
})

test('当前身份 428 正常重放；同账号并发刷新后各自只重放一次', async () => {
  let current = true
  const calls: string[] = []
  const run = () => runMfaStepUpRequest({
    isCurrent: () => current,
    prompt: async () => '123456',
    refresh: async () => { calls.push('refresh') },
    replay: async () => { calls.push('replay'); return calls.length },
    onVerified: () => { calls.push('verified') },
  })
  const results = await Promise.all([run(), run()])
  assert.deepEqual(results.map((result) => result.kind), ['replayed', 'replayed'])
  assert.equal(calls.filter((call) => call === 'replay').length, 2)
  assert.equal(calls.filter((call) => call === 'refresh').length, 2, '编排函数本身不伪造单飞；单飞由 createMfaStepUp 注入')
  assert.equal(calls.filter((call) => call === 'verified').length, 2)
})

test('当前身份取消弹码返回 cancelled，且不刷新、不重放', async () => {
  const calls: string[] = []
  const result = await runMfaStepUpRequest({
    isCurrent: () => true,
    prompt: async () => null,
    refresh: async () => { calls.push('refresh') },
    replay: async () => { calls.push('replay'); return 'unexpected' },
  })
  assert.deepEqual(result, { kind: 'cancelled' })
  assert.deepEqual(calls, [])
})

// ── createMfaGraceTracker ──────────────────────────────────────────

test('宽限窗兜底提示：仅 silent 请求、60s 节流、新提示前关闭旧提示', () => {
  const tracker = createMfaGraceTracker()
  const first = handle()
  const second = handle()
  let shown = 0

  assert.equal(tracker.onGraceResponse(true, 1_000, () => { shown++; return first }), true)
  assert.equal(tracker.isNoticeOpen(), true)
  assert.equal(tracker.onGraceResponse(true, 30_000, () => { shown++; return handle() }), false, '60s 内不得重复')
  assert.equal(shown, 1)
  assert.equal(tracker.onGraceResponse(true, 70_000, () => { shown++; return second }), true)
  assert.equal(shown, 2)
  assert.equal(first.closed, true, '新提示发出前必须关闭旧提示')
  assert.equal(tracker.isNoticeOpen(), true)
})

test('宽限窗兜底提示：非 silent 请求不弹（页面级反馈自带提示）', () => {
  const tracker = createMfaGraceTracker()
  let shown = 0
  assert.equal(tracker.onGraceResponse(false, 1_000, () => { shown++; return handle() }), false)
  assert.equal(shown, 0)
  assert.equal(tracker.isNoticeOpen(), false)
})

test('弹码后自动重试（刚验证 3s 内）不发免验证兜底，也不给业务提示加缀', () => {
  const tracker = createMfaGraceTracker()
  let shown = 0
  tracker.markVerifiedJustNow(10_000)
  assert.equal(tracker.onGraceResponse(true, 11_000, () => { shown++; return handle() }), false)
  assert.equal(shown, 0)
  assert.equal(tracker.consumeGraceForSuccess(11_500), false, '用户刚输完码不该再加缀说明')
})

test('页面级成功提示：3s 宽限窗内加缀并关闭同文案兜底条；过期后不加缀', () => {
  const tracker = createMfaGraceTracker()
  const notice = handle()
  assert.equal(tracker.onGraceResponse(true, 1_000, () => notice), true)
  assert.equal(tracker.consumeGraceForSuccess(2_000), true)
  assert.equal(notice.closed, true, '业务提示渲染后关闭兜底条（避免双 toast）')
  assert.equal(tracker.isNoticeOpen(), false)
  assert.equal(tracker.consumeGraceForSuccess(10_000), false, '3s 后不再视为「本次刚经过宽限窗」')
  // 新一次宽限放行重新开窗
  assert.equal(tracker.onGraceResponse(false, 20_000, () => handle()), false)
  assert.equal(tracker.consumeGraceForSuccess(21_000), true)
})
