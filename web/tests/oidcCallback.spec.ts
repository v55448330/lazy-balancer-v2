// OIDC 回跳 fragment 接收契约行为验收（App.vue / Login.vue 共用 utils/oidcCallback）：
//
// 后端回调把登录令牌放在 `#/oidc/callback?token=…` 的 fragment 里，这条通道本身
// 没有任何来源证明——任意链接都能携带**别人的有效 JWT**，让受害者浏览器的会话
// 被换成攻击者账号（登录 CSRF / 会话替换）。契约三道门：
//   1. 来源绑定：本标签页发起登录时写入 sessionStorage 的 nonce 必须与回调
//      return_to 回显的 nonce 一致（构造链接不可能知道受害者浏览器的 nonce）。
//   2. 载荷过滤：auth_method=oidc，且 fragment expires_at 与令牌 exp 一致。
//   3. 失败文案白名单：fragment 的 error 原文不可信，未登记文案不得原样呈现。
//
// 另含跨栈钉：后端 fail() 的固定文案集合与前端白名单逐条对表（漏一条即降级为
// 通用文案，可诊断性无声丢失）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  OIDC_APP_NONCE_KEY,
  OIDC_REJECTION_TEXT,
  createOidcAppNonce,
  oidcErrorMessage,
  splitOidcReturnTo,
  verifyOidcCallbackToken,
  withOidcAppNonce,
} from '../src/utils/oidcCallback.ts'
import { code, repoCode, section } from './_helpers.ts'

const GENERIC = '登录失败，请重新登录'

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')

/** 构造三段式 JWT（签名段不参与前端形状校验）。 */
const jwt = (payload: Record<string, unknown>): string => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.sig`

const now = 1_760_000_000
const oidcPayload = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  user_id: 7,
  username: 'alice',
  auth_method: 'oidc',
  exp: now + 600,
  ...overrides,
})

const verdictOf = (overrides: Partial<Parameters<typeof verifyOidcCallbackToken>[0]> = {}) =>
  verifyOidcCallbackToken({
    token: jwt(oidcPayload()),
    expiresAt: String(now + 600),
    nonce: 'abc123',
    expectedNonce: 'abc123',
    now,
    ...overrides,
  })

test('来源绑定：nonce 命中才建会话（命中返回账号名）', () => {
  assert.deepEqual(verdictOf(), { ok: true, username: 'alice' })
})

test('来源绑定：本浏览器没有发起过登录（无 nonce）一律拒绝', () => {
  assert.deepEqual(verdictOf({ expectedNonce: '' }), { ok: false, reason: 'nonce-missing' })
})

test('来源绑定：回调 nonce 与本次发起不一致（构造链接）拒绝', () => {
  assert.deepEqual(verdictOf({ nonce: 'attacker' }), { ok: false, reason: 'nonce-mismatch' })
  // 缺失 nonce 参数同样不满足（空串 !== 期望值）
  assert.deepEqual(verdictOf({ nonce: '' }), { ok: false, reason: 'nonce-mismatch' })
})

test('载荷过滤：本地账号令牌（无 auth_method=oidc）被拒绝', () => {
  // 攻击者用本地账号登录拿到的 JWT 拼进链接——这条必须挡住
  assert.deepEqual(
    verdictOf({ token: jwt({ username: 'attacker', exp: now + 600 }) }),
    { ok: false, reason: 'not-oidc' },
  )
})

test('载荷过滤：expires_at 与令牌 exp 不一致或缺席一律拒绝', () => {
  assert.deepEqual(verdictOf({ expiresAt: String(now + 9000) }), { ok: false, reason: 'expiry-mismatch' })
  assert.deepEqual(verdictOf({ expiresAt: '' }), { ok: false, reason: 'expiry-mismatch' })
  assert.deepEqual(verdictOf({ token: jwt(oidcPayload({ exp: undefined })) }), { ok: false, reason: 'expiry-mismatch' })
})

test('载荷过滤：已过期令牌拒绝（即使 expires_at 与 exp 自洽）', () => {
  assert.deepEqual(
    verdictOf({ token: jwt(oidcPayload({ exp: now - 1 })), expiresAt: String(now - 1) }),
    { ok: false, reason: 'expired' },
  )
})

test('载荷过滤：非三段式 / 载荷不可解析的令牌拒绝', () => {
  assert.deepEqual(verdictOf({ token: 'not-a-jwt' }), { ok: false, reason: 'malformed' })
  assert.deepEqual(verdictOf({ token: 'a.%%%not-base64%%%.c' }), { ok: false, reason: 'malformed' })
  assert.deepEqual(verdictOf({ token: `${b64url({})}.${b64url([1, 2])}.sig` }), { ok: false, reason: 'malformed' })
})

test('拒绝文案表覆盖全部拒绝原因（否则界面会渲染 undefined）', () => {
  for (const reason of ['malformed', 'not-oidc', 'expiry-mismatch', 'expired', 'nonce-missing', 'nonce-mismatch'] as const) {
    const text = OIDC_REJECTION_TEXT[reason]
    assert.equal(typeof text, 'string')
    assert.ok(text.length > 0, `${reason} 缺文案`)
    assert.notEqual(text, GENERIC, `${reason} 必须有针对性文案，不得统一成通用失败`)
  }
})

test('nonce 往返：随 return_to 携带并在回调侧剥离（页面导航不带内部参数）', () => {
  const nonce = createOidcAppNonce()
  assert.match(nonce, /^[0-9a-f]{32}$/)
  assert.equal(withOidcAppNonce('/rules', nonce), `/rules?app_nonce=${nonce}`)
  assert.equal(withOidcAppNonce('/rules?page=2', nonce), `/rules?page=2&app_nonce=${nonce}`)
  assert.deepEqual(splitOidcReturnTo(`/rules?app_nonce=${nonce}`), { path: '/rules', nonce })
  assert.deepEqual(splitOidcReturnTo(`/rules?page=2&app_nonce=${nonce}`), { path: '/rules?page=2', nonce })
  assert.deepEqual(splitOidcReturnTo('/dashboard'), { path: '/dashboard', nonce: '' })
  // 两次生成不重复（否则同一 nonce 可预置）
  assert.notEqual(createOidcAppNonce(), createOidcAppNonce())
})

// ── 失败文案白名单（fragment 内容不可信） ─────────────────────
test('失败文案：后端固定文案原样透出（保留可诊断性）', () => {
  assert.equal(oidcErrorMessage('账号已被禁用'), '账号已被禁用')
  assert.equal(oidcErrorMessage('OIDC 令牌交换失败，请稍后重试'), 'OIDC 令牌交换失败，请稍后重试')
})

test('失败文案：RFC 标准错误码映射为固定中文文案', () => {
  assert.equal(oidcErrorMessage('access_denied'), '授权被拒绝')
  assert.equal(oidcErrorMessage('invalid_request'), '请求无效')
  // 后端口径「提供商拒绝授权: <标准码>」只翻译标准码，不原文透出后缀
  assert.equal(oidcErrorMessage('提供商拒绝授权: access_denied'), '授权被拒绝')
  assert.equal(oidcErrorMessage('提供商拒绝授权: made-up-code'), '授权被拒绝')
  // 码表补齐的 6 码：客户端配置类故障不得被读成「用户拒绝」
  assert.equal(oidcErrorMessage('提供商拒绝授权: invalid_client'), '客户端凭证无效，请联系管理员检查 OIDC 配置')
  assert.equal(oidcErrorMessage('提供商拒绝授权: expired_token'), '登录令牌已过期，请重新登录')
  assert.notEqual(oidcErrorMessage('提供商拒绝授权: unsupported_grant_type'), '授权被拒绝')
})

test('失败文案：任意链接投放的陌生文案／HTML／超长串归一到通用文案', () => {
  const injected = '会话已过期，请重新登录并联系 IT 分机 8888'
  assert.equal(oidcErrorMessage(injected), GENERIC)
  assert.equal(oidcErrorMessage('<img src=x onerror=alert(1)>'), GENERIC)
  assert.equal(oidcErrorMessage('x'.repeat(200)), GENERIC)
  assert.equal(oidcErrorMessage(''), GENERIC)
})

test('失败文案：原型键不得穿透查表（constructor/toString 等）', () => {
  for (const key of ['constructor', 'toString', '__proto__', 'valueOf', 'hasOwnProperty']) {
    assert.equal(oidcErrorMessage(key), GENERIC, `${key} 命中了原型链`)
  }
})

test('跨栈：后端标准错误码表与前端码表逐键对表（漏一码即落到「授权被拒绝」）', () => {
  // 后端回调 error 参数只放行 oidcStandardErrorCodes，回显为「提供商拒绝授权: <码>」；
  // 前端按后缀查 OIDC_STANDARD_ERRORS。两侧码表原先没有任何机械对表——后端放行
  // 而前端缺码时（invalid_client / expired_token 等），运维看到「授权被拒绝」，
  // 把客户端凭证配置错误当成用户拒绝，只能逐项试。
  const backend = repoCode('internal/handlers/auth_oidc.go')
  const goBlock = section(backend, 'var oidcStandardErrorCodes = map[string]struct{}{', '\n}')
  const backendCodes = [...goBlock.matchAll(/"([a-z_]+)":\s*\{\}/g)].map((m) => m[1]!)
  assert.ok(backendCodes.length >= 10, `后端标准码解析失败（${backendCodes.length} 条）`)
  const frontBlock = section(code('src/utils/oidcCallback.ts'), 'const OIDC_STANDARD_ERRORS: Record<string, string> = {', '\n}')
  const frontCodes = [...frontBlock.matchAll(/^\s*([a-z_]+):\s*'/gm)].map((m) => m[1]!)
  assert.ok(frontCodes.length >= 10, `前端码表解析失败（${frontCodes.length} 条）`)
  const missing = backendCodes.filter((item) => !frontCodes.includes(item))
  assert.deepEqual(missing, [], `前端码表缺后端放行的标准码：${missing.join(', ')}（会一律落到「授权被拒绝」）`)
  // 反向：前端多出的码必须同时进后端白名单，否则是不可达死条目
  const unreachable = frontCodes.filter((item) => !backendCodes.includes(item))
  assert.deepEqual(unreachable, [], `前端码表有后端白名单外的码（永远不可达）：${unreachable.join(', ')}`)
})

test('跨栈：提供商拒绝文案前缀两侧同值（改一侧即整族文案失配）', () => {
  const prefix = /const providerPrefix = '([^']+)'/.exec(code('src/utils/oidcCallback.ts'))?.[1]
  assert.ok(prefix, '前端缺 providerPrefix 常量（「前缀: 码」形态的切分依据）')
  const backend = repoCode('internal/handlers/auth_oidc.go')
  assert.ok(backend.includes(`msg := "${prefix}"`), `后端拒绝文案前缀与前端 providerPrefix「${prefix}」不一致`)
  // 拼接形态本身也钉住：前端按「前缀: 码」切后缀，形态变了就整族落回通用文案
  assert.ok(backend.includes('msg += ": " + code'), '后端必须保持「前缀: 空格式码」拼接形态')
})

test('跨栈：后端 fail() 的每条固定文案都在前端白名单内（文案漂移即红）', () => {
  const backend = repoCode('internal/handlers/auth_oidc.go')
  const literals = [...backend.matchAll(/fail\("([^"]+)"/g)].map((m) => m[1])
  assert.ok(literals.length > 15, `后端失败文案解析失败（${literals.length} 条）`)
  const missing = literals.filter((text) => oidcErrorMessage(text) === GENERIC)
  assert.deepEqual(missing, [], `以下后端文案未纳入前端白名单：${missing.join('；')}`)
})

// ── 接线：App / Login 必须按契约顺序执行 ──────────────────────
test('App：先验令牌再建会话，拒绝分支不得触碰现有会话', () => {
  const app = code('src/App.vue')
  const branch = section(app, 'if (oidcToken) {', '} else if (hasLoginTicket) {')
  const verifyAt = branch.indexOf('verifyOidcCallbackToken({')
  const applyAt = branch.indexOf('authStore.applyOIDCToken(oidcToken)')
  assert.ok(verifyAt > 0 && applyAt > verifyAt, '必须先验来源/载荷，再写会话')
  // 两处 apply 都必须位于 verdict.ok 分支之内（拒绝分支不得替换会话）
  assert.doesNotMatch(branch.slice(branch.indexOf('if (!verdict.ok)'), verifyAt + 400), /applyOIDCToken/)
  assert.match(branch, /sessionStorage\.removeItem\(OIDC_APP_NONCE_KEY\)/, 'nonce 必须一次性消费')
  assert.match(branch, /OIDC_REJECTION_TEXT\[verdict\.reason\]/, '拒绝文案取原因表，不得原文回显')
})

test('App：已登录会话被 URL 令牌替换须显式确认（取消则保持当前登录）', () => {
  const app = code('src/App.vue')
  const branch = section(app, 'if (oidcToken) {', '} else if (hasLoginTicket) {')
  assert.match(branch, /authStore\.token && !isTokenExpired\(authStore\.token\)/, '仅当已有有效会话时要求确认')
  assert.match(branch, /ElMessageBox\.confirm\(/, '换号必须二次确认')
  assert.match(branch, /已保持当前登录/, '取消分支必须明确不切换')
})

test('App：return_to 导航只在令牌真正落地后执行（拒绝/取消都不跳页）', () => {
  const app = code('src/App.vue')
  const branch = section(app, 'if (oidcToken) {', '} else if (hasLoginTicket) {')
  // 两处 applyOIDCToken 各对应一个落地点，都必须置位导航门——漏一处即「拒绝/
  // 取消后仍跳转」（提示与行为矛盾）。
  const applies = [...branch.matchAll(/authStore\.applyOIDCToken\(oidcToken\)/g)]
  assert.equal(applies.length, 2, '令牌落地应有两处（确认换号 / 直接建会话）')
  for (const apply of applies) {
    assert.match(
      branch.slice(apply.index, apply.index + 80),
      /tokenApplied = true/,
      '每次令牌落地都必须置位导航门（tokenApplied）',
    )
  }
  // 导航语句必须落在 if (tokenApplied) 块内：在块外即回到「无条件导航」
  const navAt = branch.indexOf('authStore.setCurrentPage(target)')
  assert.ok(navAt > 0, 'return_to 导航语句缺失')
  const guardAt = branch.lastIndexOf('if (tokenApplied) {', navAt)
  assert.ok(guardAt >= 0 && guardAt < navAt, 'return_to 导航必须受 tokenApplied 门控')
  // 门内不得再出现会提前结束分支的 else 旁路（杜绝「拒绝分支也置位」）
  const rejectBranch = branch.slice(branch.indexOf('if (!verdict.ok) {'), branch.indexOf('} else if (authStore.token'))
  assert.doesNotMatch(rejectBranch, /tokenApplied = true/, '拒绝分支不得置位导航门')
})

test('App：失败文案都经白名单映射，不直接拼接 fragment 原文', () => {
  // 两条失败通道（回调 error / 登录跳转 oidc_error）已统一由 App 的 hash
  // 预处理单源消费，Login 挂载侧读取点已删除（见下一用例）。
  const text = code('src/App.vue')
  assert.match(text, /oidcErrorMessage\(/, 'src/App.vue 未走文案白名单')
  assert.doesNotMatch(text, /OIDC 登录失败：\$\{oidc(?:Error|_error)\}/, 'src/App.vue 仍原样透出 fragment 文案')
})

test('Login：发起登录时写入本标签页 nonce 并随 return_to 往返', () => {
  const login = code('src/views/Login.vue')
  const start = section(login, 'const goOIDCLogin = () => {', 'const onPageShow = (e: PageTransitionEvent) => {')
  assert.match(start, /sessionStorage\.setItem\(OIDC_APP_NONCE_KEY, nonce\)/)
  // 存储键名本身是跨标签页契约：改名会让已在途的 return_to 往返读到空 nonce
  assert.equal(OIDC_APP_NONCE_KEY, 'oidc_app_nonce')
  assert.match(start, /withOidcAppNonce\(`\/\$\{authStore\.currentPage\}`, nonce\)/)
})

// `#/login?oidc_error=` 通道（后端登录跳转失败 302 回前端）必须在 App.vue
// hash 预处理里统一识别并剥离：该预处理先于路由视图执行——已持有效会话的
// 用户 init() 成功、Login 不挂载，旧实现把消费点放在 Login 挂载侧，错误既
// 不提示也不从 hash 清除（刷新/复制链接反复看到过期失败）。
test('App 统一消费 login 通道 oidc_error（不依赖 Login 挂载）', () => {
  const app = code('src/App.vue')
  // 识别：预处理即读取该参数（文案与回调 error 同走白名单映射）
  assert.match(app, /fragment\.get\('oidc_error'\)/, 'App.vue hash 预处理未识别 oidc_error')
  // 剥离：并入统一 delete 分支，且分支条件涵盖「仅 oidc_error」形态
  assert.match(app, /fragment\.delete\('oidc_error'\)/, 'oidc_error 未并入统一剥离')
  assert.match(app, /hasLoginTicket \|\| oidcCallback \|\| oidcErrorParam/, '剥离分支条件未涵盖仅 oidc_error 形态')
  // 通道单源上收：Login 挂载侧消费点删除（App 先行解析并剥离后，二次读取
  // 只会读到空——双消费点让「提示语义」在两条挂载路径间分叉）
  const login = code('src/views/Login.vue')
  assert.ok(!login.includes('oidc_error'), 'Login.vue 不得再消费 oidc_error（通道已上收 App.vue）')
})
