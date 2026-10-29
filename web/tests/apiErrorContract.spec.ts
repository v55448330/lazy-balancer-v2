// 业务码 / HTTP 状态同值契约（前端按 status 分类的前提）。
//
// 前端响应拦截器的业务码失败分支把 **HTTP status** 装进 ApiRequestError
// （api.ts 内注释即契约）：调用方按 `status === 409` 之类分类（如
// useLibUpdateDialog）——若后端出现「HTTP 200 + code≠0」或状态与业务码不同值，
// 分类与重试逻辑会静默绕过。本 spec 双向钉住：
//   ① 前端确实携带 response.status（源码钉）；
//   ② 后端信封（handlers + middleware）每条响应的业务码与 HTTP 状态同义
//      （机械扫描全部非测试文件）。
//
// 扫描必须「零跳过」：状态名未登记、业务码写成非常量（http.StatusX 之外的形态）
// 都算失败——否则一条查不到映射的配对会被 continue 静默跳过，守卫假绿。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'

import { code, repoCode, section } from './_helpers.ts'

/** 生产同一响应信封的目录（前端拦截器对两者一视同仁）。 */
const SCAN_DIRS = ['internal/handlers', 'internal/middleware'] as const

/**
 * 目录内非测试 Go 文件（递归扫描，不手抄清单——新增文件与子目录自动纳入；
 * 单层 readdirSync 会让子目录里的新响应文件整体漏出扫描面）。
 */
const goFiles = (dir: (typeof SCAN_DIRS)[number]): string[] => (readdirSync(new URL(`../../${dir}/`, import.meta.url), { recursive: true }) as string[])
  .map((name) => name.replace(/\\/g, '/'))
  .filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
  .map((name) => `${dir}/${name}`)

/** 状态名 → 数值。键名与 `http.Status<Name>` 的后缀逐字相同（不得带 Status 前缀）。 */
const HTTP_STATUS: Record<string, number> = {
  OK: 200,
  Created: 201,
  Accepted: 202,
  NoContent: 204,
  BadRequest: 400,
  Unauthorized: 401,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  Conflict: 409,
  RequestEntityTooLarge: 413,
  UnprocessableEntity: 422,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  InternalServerError: 500,
  BadGateway: 502,
  ServiceUnavailable: 503,
  GatewayTimeout: 504,
}

// 两种信封形态（models.APIResponse{Code: N} 与 gin.H{"code": N}）都真实存在；
// 业务码既可能是整数字面量/`http.StatusX` 符号，也可能是**助手变量**——
// 失败助手与 2xx 成功助手惯用 `c.JSON(status, …{Code: status})`，这类动态
// 形态必须参与扫描（旧正则要求字面量 `http.StatusX` 打头，动态信封被两个
// 正则同时跳过，`unparsed` 恒空 = 静默假绿）。
//
// 扫描以**调用点**为单位（不是以「能解析的信封」为单位）：信封还可能整个藏在
// 变量里（`resp := models.APIResponse{Code: 500}; c.JSON(http.StatusOK, resp)`）——
// 以信封正则遍历会把这类站点直接漏掉（既不计 head 也不计 unparsed）。调用点
// 枚举 + 载荷分类后，任何站点只有两种归宿：可验证信封，或显式登记的非信封
// 站点；两者合计必须等于调用点总数（见 NON_ENVELOPE_SITES）。
//
// 响应方法含 `c.JSON` 与 `c.AbortWithStatusJSON`（middleware 惯用后者）；
// `\s*` 跨换行：`models.APIResponse{\n\tCode: …` 是仓内惯用多行写法。
const CALL_SITE = /\bc\.(?:JSON|AbortWithStatusJSON)\(\s*((?:http\.Status[A-Za-z]+)|[A-Za-z_][\w.]*)\s*,\s*/g

/**
 * 宽口径响应调用点计数（只认方法名，不看首实参形态）。CALL_SITE 只枚举
 * 「http.StatusX / 标识符首实参」两形态——更复杂的首实参（类型转换、链式
 * 表达式等）在两个集合里同时消失，`calls = pairs + registered` 恒等式仍成立。
 * 宽窄计数必须相等，否则该文件存在未进面的响应站点（显式失败而非静默漏计）。
 */
const RESPONSE_CALL_SITE = /\bc\.(?:JSON|AbortWithStatusJSON)\(/g

/** 载荷首 token 的信封形态（`Code:`/`"code":` 之后必须能解出业务码）。 */
const ENVELOPE_LITERAL = /^(?:models\.APIResponse\{\s*Code:|gin\.H\{\s*"(?:code|Code)"\s*:)\s*((?:http\.Status[A-Za-z]+)|[A-Za-z_][\w.]*|\d+)/

type PayloadKind =
  | { envelope: true; code: string }
  | { envelope: false; shape: string }

/**
 * 载荷分类：只看首 token 形态（整段解析会跨语句，反而引入误判）。
 * `call:` 函数调用（内部失败助手）、`literal:` 其它结构体、`var:` 变量载荷
 * （再尝试解析成信封）、`unclassified` 兜底（必须人工确认后登记）。
 */
const classifyPayload = (rest: string): PayloadKind => {
  const literal = ENVELOPE_LITERAL.exec(rest)
  if (literal) return { envelope: true, code: literal[1] }
  const call = /^([A-Za-z_][\w.]*)\s*\(/.exec(rest)
  if (call) return { envelope: false, shape: `call:${call[1]}` }
  const composite = /^([A-Za-z_][\w.]*)\s*\{/.exec(rest)
  if (composite) return { envelope: false, shape: `literal:${composite[1]}` }
  const variable = /^([A-Za-z_][\w.]*)\s*[,)]/.exec(rest)
  if (variable) return { envelope: false, shape: `var:${variable[1]}` }
  return { envelope: false, shape: 'unclassified' }
}

interface Envelope {
  /** 第一实参原文：`http.StatusX` 字面量或助手变量名 */
  status: string
  /** Code 实参原文：整数字面量、`http.StatusX` 或助手变量名 */
  code: string
  /** 在 Go 源中的偏移（2xx-only 助手白名单按所属函数判定） */
  index: number
}

interface Site {
  /** 非信封载荷形态（`call:` / `literal:` / `var:` / `unclassified`） */
  shape: string
  index: number
}

/**
 * 变量载荷只按调用点前最后一次赋值判定。先定位任意赋值（含多返回值），
 * 再尝试解析这一次 RHS；不得让更早的合法信封覆盖后续函数/拼装载荷。
 */
const resolveVariableEnvelope = (go: string, callIndex: number, status: string, ident: string): Envelope | undefined => {
  const funcStart = Math.max(go.lastIndexOf('\nfunc ', callIndex), 0)
  const body = go.slice(funcStart, callIndex)
  const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const assignments = [...body.matchAll(/^[ \t]*(.+?)\s*:?=\s*/gm)]
    .filter((match) => new RegExp(`(?:^|,)\\s*${escaped}\\s*(?:,|$)`).test(match[1]))
  const last = assignments[assignments.length - 1]
  if (!last) return undefined
  // 多返回值/分支合流不能由单变量信封证明，保守归为非信封站点。
  if (last[1].includes(',')) return undefined
  const rhs = body.slice((last.index ?? 0) + last[0].length)
  const envelope = /^(?:models\.APIResponse\{\s*Code:|gin\.H\{\s*"(?:code|Code)"\s*:)\s*((?:http\.Status[A-Za-z]+)|[A-Za-z_][\w.]*|\d+)/.exec(rhs)
  return envelope ? { status, code: envelope[1], index: callIndex } : undefined
}

interface ScanResult {
  /** 调用点总数（含非信封站点）——与信封数 + 登记站点数对账 */
  calls: number
  /** 可验证的信封（内联 + 变量解析） */
  pairs: Envelope[]
  /** 非信封站点（必须登记在 NON_ENVELOPE_SITES） */
  sites: Site[]
}

const scan = (go: string): ScanResult => {
  const pairs: Envelope[] = []
  const sites: Site[] = []
  const calls = [...go.matchAll(CALL_SITE)]
  for (const call of calls) {
    const index = call.index ?? 0
    const status = call[1]
    const payloadStart = index + call[0].length
    // 200 字符足够覆盖载荷首 token（含多行结构体头），不跨到后续语句。
    const classified = classifyPayload(go.slice(payloadStart, payloadStart + 200))
    if (classified.envelope) {
      pairs.push({ status, code: classified.code, index })
      continue
    }
    if (classified.shape.startsWith('var:')) {
      const resolved = resolveVariableEnvelope(go, index, status, classified.shape.slice(4))
      if (resolved) {
        pairs.push(resolved)
        continue
      }
    }
    sites.push({ shape: classified.shape, index })
  }
  return { calls: calls.length, pairs, sites }
}

/** `http.StatusX` → `X`；动态表达式返回 undefined。 */
const literalStatusName = (expr: string): string | undefined => /^http\.Status([A-Za-z]+)$/.exec(expr)?.[1]

/** 业务码实参 → 数值；动态表达式返回 undefined（同值只能靠同一变量证明）。 */
const codeValue = (expr: string): number | undefined => {
  if (/^\d+$/.test(expr)) return Number(expr)
  const name = literalStatusName(expr)
  return name === undefined ? undefined : HTTP_STATUS[name]
}

/**
 * 业务码与 HTTP 状态是否同义。2xx 是成功信封（业务码 0；200 与前端
 * `code !== 200` 判据等价），其余状态必须逐值相同，调用方的 status 分支才成立。
 *
 * 动态状态（助手变量）唯一可由本函数机械证明的同义形态是「业务码取同一
 * 表达式」；`Code: 0` 属 2xx-only 助手语义，交由调用侧显式白名单放行。
 * 返回 undefined 表示不可判定（不得默认通过）。
 */
const pairConsistent = (pair: Envelope): boolean | undefined => {
  const statusName = literalStatusName(pair.status)
  if (statusName === undefined) {
    if (pair.code === pair.status) return true
    const value = codeValue(pair.code)
    if (value === 0 || value === 200) return undefined
    // 动态状态配异值业务码：无法证明同义，且形态上就是旧门禁要拦的错配
    return value === undefined ? undefined : false
  }
  const httpStatus = HTTP_STATUS[statusName]
  if (httpStatus === undefined) return undefined
  const value = codeValue(pair.code)
  if (value === undefined) return undefined
  return httpStatus < 300 ? value === 0 || value === 200 : value === httpStatus
}

test('前端业务码失败分支携带 HTTP status（api.ts 契约）', () => {
  const api = code('src/utils/api.ts')
  const branch = section(api, 'if (res.code !== undefined && res.code !== 0 && res.code !== 200) {', 'return res')
  assert.match(branch, /new ApiRequestError\(res\.message \|\| '请求失败', response\.status(?:, res)?\)/, '必须携带 response.status')
  assert.doesNotMatch(branch, /new ApiRequestError\([^)]*,\s*res\.code\)/, '不得改携带业务码（调用方按 status 分类）')
  // 两类失败（HTTP 非 2xx / HTTP 2xx + code≠0）的错误对象必须同形：第三参数
  // 携带**响应体信封**，否则消费方（importFailureReport 读 data.data.warnings）
  // 在业务码信封上静默丢失事实披露。业务码分支的 `res` 本身就是 response.data，
  // 传 res.data 会落成载荷（少一层信封）——两分支就此不同形。
  assert.match(
    branch,
    /new ApiRequestError\(res\.message \|\| '请求失败', response\.status, res\)/,
    '业务码失败必须携带完整响应体信封（与 HTTP 失败分支同形）',
  )
  assert.doesNotMatch(branch, /new ApiRequestError\(res\.message \|\| '请求失败', response\.status, res\.data\)/, '不得只传载荷（信封少一层）')
  // HTTP 失败分支已经是三参形态（两类失败同形的前提）
  assert.match(api, /new ApiRequestError\(message, status, error\.response\?\.data\)/, 'HTTP 失败分支必须携带响应体')
})

test('扫描器形态自测：同行/多行、两种方法/信封、字面量/动态/变量载荷都命中', () => {
  const symbolic = 'c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "x"})'
  const dynamic = 'c.JSON(outcome.status, gin.H{"code": outcome.status})'
  const fixtures = [
    'c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "x"})',
    'c.JSON(http.StatusBadGateway, models.APIResponse{\n\t\tCode: 502,\n\t\tMessage: "x",\n\t})',
    'c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "message": "x"})',
    'c.JSON(http.StatusConflict, gin.H{\n\t\t"code": 409,\n\t})',
    symbolic,
    'c.JSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest})',
    'c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "x"})',
    // 动态形态（助手变量）：第一实参与 Code 都非字面量，旧正则两处同时跳过
    'c.JSON(status, models.APIResponse{Code: status, Message: "x"})',
    'c.JSON(statusCode, models.APIResponse{\n\t\tCode: statusCode,\n\t\tMessage: "x",\n\t})',
    dynamic,
    // 变量载荷（信封整个藏在变量里）：两个旧正则都看不到该站点，必须经解析入账
    'resp := models.APIResponse{Code: 500}\n\tc.JSON(http.StatusOK, resp)',
    'resp := models.APIResponse{Code: statusCode}\n\tc.JSON(statusCode, resp)',
    'payload := gin.H{"code": statusCode}\n\tc.AbortWithStatusJSON(statusCode, payload)',
  ]
  for (const fixture of fixtures) {
    assert.equal(scan(fixture).pairs.length, 1, `扫描器漏形态：${fixture}`)
  }
  assert.deepEqual(
    scan(symbolic).pairs.map(({ status, code }) => ({ status, code })),
    [{ status: 'http.StatusConflict', code: 'http.StatusConflict' }],
    '符号业务码必须原样解出',
  )
  assert.deepEqual(
    scan(dynamic).pairs.map(({ status, code }) => ({ status, code })),
    [{ status: 'outcome.status', code: 'outcome.status' }],
    '动态形态必须解出同一表达式',
  )
  // 非信封载荷（登录响应、服务层结构体、自定义 gin.H 键、函数调用、变量）不参与
  assert.equal(scan('c.JSON(http.StatusOK, models.LoginResponse{Token: t})').pairs.length, 0)
  assert.equal(scan('c.JSON(http.StatusOK, gin.H{"status": "ok"})').pairs.length, 0)
  assert.equal(scan('c.AbortWithStatus(http.StatusUnauthorized)').calls, 0)
  // 变量来自函数调用/复合结构体时无法解析 → 必须落进「非信封站点」等登记。
  const unresolved = scan('response, err := h.svc.Login(ctx, claims, time.Now())\n\tc.JSON(http.StatusOK, response)')
  assert.equal(unresolved.pairs.length, 0)
  assert.deepEqual(unresolved.sites.map((site) => site.shape), ['var:response'])
  const helperPayload = scan('c.JSON(http.StatusInternalServerError, systemInternalFailure("读取失败", err))')
  assert.deepEqual(helperPayload.sites.map((site) => site.shape), ['call:systemInternalFailure'])
  // 旧合法信封不得遮蔽最后一次函数/多返回值赋值；只有最后赋值仍为信封才可证明。
  for (const fixture of [
    'resp := models.APIResponse{Code: 0}\n\tresp = buildResponse()\n\tc.JSON(http.StatusOK, resp)',
    'resp := models.APIResponse{Code: 0}\n\tresp, err := buildResponse()\n\tc.JSON(http.StatusOK, resp)',
    'resp := models.APIResponse{Code: 0}\n\tresp = models.OtherResponse{Code: 500}\n\tc.JSON(http.StatusOK, resp)',
  ]) {
    const result = scan(fixture)
    assert.equal(result.pairs.length, 0, `旧信封不得覆写未知载荷：${fixture}`)
    assert.deepEqual(result.sites.map((site) => site.shape), ['var:resp'])
  }
  const latest = scan('resp := models.APIResponse{Code: 0}\n\tresp = models.APIResponse{Code: 409}\n\tc.JSON(http.StatusConflict, resp)')
  assert.deepEqual(latest.pairs.map(({ status, code }) => ({ status, code })), [
    { status: 'http.StatusConflict', code: '409' },
  ], '最后一次仍是信封时只采用最后值')
})

/**
 * 2xx-only 助手白名单：状态取自 `f.SuccessStatus`（0 归一为 200），业务码固定 0。
 * 按「文件 + 所属函数」登记（重排/行号漂移不误报）；条目必须实际命中，
 * 死条目同样失败。
 */
const SUCCESS_ENVELOPE_WHITELIST: Record<string, true> = {
  'internal/handlers/handlers.go#finishTxApply': true,
  'internal/handlers/securityiplists.go#tryIPListHotPathApply': true,
}

/**
 * 非信封响应站点：载荷不是信封（无 `Code` 键，或变量来自函数调用/其它结构体）。
 * 按「文件#函数#载荷形态 → 站点数」登记：新增站点、形态变化、站点数变化都红。
 * 变量载荷会先尝试解析成信封（见 resolveVariableEnvelope），只有确实不是信封的
 * 站点才允许登记；条目必须命中且耗尽（死条目同样失败）。
 */
const NON_ENVELOPE_SITES: Record<string, number> = {
  'internal/handlers/auth.go#Login#literal:gin.H': 1,
  'internal/handlers/auth.go#respondLoginWithMFA#literal:models.LoginResponse': 1,
  'internal/handlers/autoban.go#GetAutobanConfig#var:cfg': 1,
  'internal/handlers/cluster_ticket.go#GenerateClusterLoginTicket#var:response': 1,
  'internal/handlers/crawlerlib.go#GetCrawlerLib#call:crawlerLibInternalError': 4,
  // 威胁库/爬虫库「源开关」端点收敛到共享状态机（门序/三分支错误映射/审计骨架
  // 单源），500 分支的响应体由 spec 注入——三处（读失败/更新失败/审计后重读）
  // 载荷首 token 是函数调用，非可解析信封。
  'internal/handlers/lib_source_flags.go#updateLibSourceFlags#call:spec.InternalError': 5,
  // 行数状态收敛助手：0 行=404、RowsAffected 故障=500，响应体由 spec 注入。
  'internal/handlers/lib_source_flags.go#requireLibSourceFlagRowUpdated#call:spec.InternalError': 1,
  'internal/handlers/system.go#GetSystemMetrics#call:systemInternalFailure': 1,
  'internal/handlers/system.go#GetRealtimeTraffic#call:systemInternalFailure': 1,
  'internal/handlers/system.go#GetConnectionStats#call:systemInternalFailure': 1,
  'internal/handlers/system.go#GetAppLogs#call:systemInternalFailure': 4,
  // 批量签发全失败：响应体经 internalError 装配后补 Data 计数（保留失败明细），
  // 首 token 是局部变量而非可解析信封；底层原因已在同一分支 Logf 留痕。
  'internal/handlers/certificates.go#IssueCertificate#var:response': 1,
  'internal/middleware/middleware.go#SetupRouter#literal:gin.H': 1,
}

/**
 * 目录级信封下限：取当前实测值（不留静默余量）。真正的防漏是下面的调用点对账
 * （`calls = pairs + 登记站点`）——下限只在「整个目录被排除/扫描器被短路」时兜底。
 */
// 阈值是「扫描器失效」的护栏，不是覆盖率目标：5xx 响应改经 writeInternalError
// （固定文案，不再就地拼 APIResponse）会合法降低配对总数，改动来源在下方
// 调用点对账（calls = pairs + registered）里仍被完全约束。
const MIN_ENVELOPES: Record<(typeof SCAN_DIRS)[number], number> = {
  // 实测下限：writeInternalError 等共享装配器把多站点收敛为一个信封，
  // 目录级下限跟随实测（调用点对账仍保证无漏网）。基线 1314 之后的两处
  // 合法收敛：①「还原/下载进入导入核心之前」的 9 处裸信封收敛为
  // failRestoreFileAccess 单源（净 -8）；②V1 导入 6 处事务前 400 收敛为
  // failImportValidation 单源（净 -6）；③自动备份访问族（编号/文件名非法、
  // 行不存在、查询失败）收敛为 failAutoBackupAccess 单源（净 -2）。
  // ④登录里 MFA 标记的独立查询并入 db.UserRowColumns 单源用户查询
  // （fail-closed 500 保留在同一查询的错误分支，净 -1）。
  // ⑤OIDC 写保护门收敛为 oidcManagedWriteGate 单源（两条改密路径各 2 处
  // 内联 500/400 移入门内，净 -4）；MFASetup 两条基础设施故障分支改走
  // mfaInternalFailure（净 -1，另一处移入日志/审计单源）——文件级
  // auth.go -4 / users.go +4 / mfa.go -2 / auth_oidc.go +1。
  // 叠加上其它调用点增补（含证书族与自动备份族继续收敛）后实测 1293；
  // 后续批次把 UpdateSecurityPolicy/CAProvider 等错误出口收敛到共享 helper 后实测 1280。
  'internal/handlers': 1280,
  'internal/middleware': 43,
}

/** 信封所在函数（最近的上一个 `func` 声明）。 */
const enclosingFunc = (go: string, index: number): string => {
  const matches = [...go.slice(0, index).matchAll(/^func (?:\([^)]*\) )?([A-Za-z0-9_]+)/gm)]
  return matches.length ? matches[matches.length - 1][1] : ''
}

test('后端信封：每条业务码与 HTTP 状态同义（handlers + middleware 全量）', () => {
  const mismatched: string[] = []
  const unknown: string[] = []
  const unenumerated: string[] = []
  const usedWhitelist = new Set<string>()
  const siteBudget = new Map<string, number>()
  const perDir: Record<string, number> = {}
  let pairs = 0
  let calls = 0
  for (const dir of SCAN_DIRS) {
    let dirPairs = 0
    for (const file of goFiles(dir)) {
      const go = repoCode(file)
      const result = scan(go)
      // 正向控制：宽口径响应调用点数必须等于已枚举数，任何形态未进面即红。
      const broad = [...go.matchAll(RESPONSE_CALL_SITE)].length
      if (broad !== result.calls) {
        unenumerated.push(`${file}: 响应调用点 ${broad} 处，扫描器只枚举 ${result.calls} 处（首实参形态未进面）`)
      }
      calls += result.calls
      pairs += result.pairs.length
      dirPairs += result.pairs.length
      for (const pair of result.pairs) {
        const verdict = pairConsistent(pair)
        if (verdict === true) continue
        const where = `${file}: ${pair.status} 配 Code ${pair.code}`
        if (verdict === false) {
          mismatched.push(where)
          continue
        }
        // undefined = 动态状态 + Code 0（2xx-only 助手）：必须显式白名单放行
        const key = `${file}#${enclosingFunc(go, pair.index)}`
        if (pair.code === '0' && SUCCESS_ENVELOPE_WHITELIST[key] === true) usedWhitelist.add(key)
        else unknown.push(`${where}（${enclosingFunc(go, pair.index)}）`)
      }
      for (const site of result.sites) {
        const key = `${file}#${enclosingFunc(go, site.index)}#${site.shape}`
        siteBudget.set(key, (siteBudget.get(key) ?? 0) + 1)
      }
    }
    perDir[dir] = dirPairs
  }
  for (const [key, count] of siteBudget) {
    const expected = NON_ENVELOPE_SITES[key]
    if (expected === undefined) unknown.push(`${key}：未登记的非信封站点（${count} 处）`)
    else if (expected !== count) unknown.push(`${key}：实测 ${count} 处 ≠ 登记 ${expected} 处`)
  }
  for (const dir of SCAN_DIRS) {
    assert.ok(perDir[dir] >= MIN_ENVELOPES[dir], `${dir} 配对过少（${perDir[dir]} < ${MIN_ENVELOPES[dir]}）——目录被排除或扫描器失效`)
  }
  // 调用点对账：每条响应都必须「可验证信封」或「已登记非信封站点」，二者不可缺漏。
  const registered = [...siteBudget.values()].reduce((sum, count) => sum + count, 0)
  assert.equal(calls, pairs + registered, `调用点对账失败：${calls} 个调用点 = ${pairs} 条信封 + ${registered} 处登记站点`)
  assert.deepEqual(unenumerated, [], '存在未进扫描面的响应调用点（宽口径计数 > 枚举数）')
  assert.deepEqual(unknown, [], '存在不可判定的信封或未登记的非信封站点——必须显式登记')
  assert.deepEqual(mismatched, [], '状态与业务码不同义——前端按 status 分类会误判')
  assert.deepEqual(
    Object.keys(SUCCESS_ENVELOPE_WHITELIST).filter((key) => !usedWhitelist.has(key)),
    [],
    '白名单条目已无命中——删除死条目',
  )
  assert.deepEqual(
    Object.keys(NON_ENVELOPE_SITES).filter((key) => !siteBudget.has(key)),
    [],
    '非信封站点登记已无命中——删除死条目',
  )
})

test('负断言形态：成功状态配非零业务码 / 动态状态配异值业务码必须被判为不同值', () => {
  for (const fixture of [
    'c.JSON(http.StatusOK, models.APIResponse{Code: 500})',
    'c.JSON(http.StatusOK, gin.H{"code": 500})',
    'c.JSON(http.StatusOK, models.APIResponse{\n\tCode: 500,\n})',
    'c.JSON(http.StatusCreated, models.APIResponse{Code: 400})',
    'c.JSON(http.StatusBadRequest, models.APIResponse{Code: http.StatusConflict})',
    'c.JSON(status, models.APIResponse{Code: 500})',
    'c.JSON(status, models.APIResponse{Code: http.StatusConflict})',
    // 变量载荷：信封藏在变量里时同样必须判定为不同值
    'resp := models.APIResponse{Code: 500}\n\tc.JSON(http.StatusOK, resp)',
    'payload := gin.H{"code": 500}\n\tc.JSON(status, payload)',
  ]) {
    const [pair] = scan(fixture).pairs
    assert.ok(pair, `扫描器漏形态：${fixture}`)
    assert.equal(pairConsistent(pair), false, `守卫必须判定为不同值：${fixture}`)
  }
  // 合法形态（成功信封 0 / 状态同值 / 符号同值 / 动态同表达式）
  for (const fixture of [
    'c.JSON(http.StatusOK, models.APIResponse{Code: 0})',
    'c.JSON(http.StatusCreated, models.APIResponse{Code: 0})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: 409})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict})',
    'c.JSON(status, models.APIResponse{Code: status})',
    'payload := models.APIResponse{Code: status}\n\tc.JSON(status, payload)',
    'payload := models.APIResponse{Code: 0}\n\tc.JSON(http.StatusOK, payload)',
  ]) {
    assert.equal(pairConsistent(scan(fixture).pairs[0]), true, `守卫误报：${fixture}`)
  }
  // 动态状态 + Code 0 = 2xx-only 助手语义，只能由调用侧白名单放行，不得默认通过
  assert.equal(pairConsistent(scan('c.JSON(status, models.APIResponse{Code: 0})').pairs[0]), undefined)
  // 未登记状态名必须不可判定（而非默认通过）
  assert.equal(pairConsistent({ status: 'http.StatusTeapot', code: '418', index: 0 }), undefined)
})
