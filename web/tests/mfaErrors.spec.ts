// MFA 端点 401 分类验收：凭证/挑战错误豁免会话失效流程，
// 同端点经 jwtAuth 发出的会话 401 必须继续走重新登录。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isMfaCredentialRejection, MFA_CREDENTIAL_REJECTION_MESSAGES } from '../src/utils/mfaErrors.ts'
import { MFA_SCOPE_GROUPS } from '../src/utils/mfaScopeGroups.ts'
import { repoCode, section, code } from './_helpers.ts'

// jwtAuth 的真实过期文案（MFA 端点先经它鉴权）；「未登录或登录已过期」只来自
// handlers/auth.go 的资料接口，与这些端点无关。
const SESSION_EXPIRED = '登录状态已过期，请重新登录'

test('验码/挑战错误 → 豁免会话失效（只传播文案供重试）', () => {
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 401, '验证码错误'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/disable', 401, '验证码错误'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/setup', 401, '验证码错误'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/activate', 401, '验证码错误次数过多，绑定已作废，请重新开始绑定'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify', 401, 'MFA 挑战无效或已过期，请重新登录'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify', 401, 'MFA 挑战已被使用，请重新登录'), true)
  // 管理员重置端点（Users.vue 展示后端文案供重试）
  assert.equal(isMfaCredentialRejection('/users/3/mfa/reset', 401, '验证码错误'), true)
})

test('401 豁免白名单与后端 mfa.go 文案逐字对齐（跨栈钉）', () => {
  // 前端按后端中文字面量分类——后端润色文案（改字/加标点）会静默改变分类：
  // 真会话过期被当验码错误不弹重登，或反之误杀会话。逐字钉住 Go 侧出处。
  const go = repoCode('internal/handlers/mfa.go')
  for (const msg of [
    '验证码错误',
    '验证码错误次数过多，绑定已作废，请重新开始绑定',
    'MFA 挑战无效或已过期，请重新登录',
    'MFA 挑战已被使用，请重新登录',
  ]) {
    assert.ok(go.includes(`Message: "${msg}"`), `mfa.go 不再产生 401 文案「${msg}」——前端白名单失配`)
  }
})

test('同端点的会话过期 401 不得被豁免（428→verify-step 窗口）', () => {
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 401, SESSION_EXPIRED), false)
  assert.equal(isMfaCredentialRejection('/auth/mfa/status', 401, SESSION_EXPIRED), false)
  assert.equal(isMfaCredentialRejection('/users/3/mfa/reset', 401, SESSION_EXPIRED), false)
})

// jwtAuth 发出的全部 401 文案（过期/吊销/改密/凭证无效/用户不可用）在 MFA
// 端点必须一律不豁免——这些端点在验码前先经 jwtAuth 鉴权，白名单按文案匹配，
// 误加一条真实会话文案会让过期令牌被判成「验证码错误」，用户卡在弹码循环。
test('jwtAuth 会话 401 文案一律不豁免（真实过期/吊销/改密/凭证无效）', () => {
  const jwtAuth = section(repoCode('internal/middleware/middleware.go'), 'func jwtAuth(', 'func apiKeyAuth(')
  const messages = [
    ...new Set([...jwtAuth.matchAll(/StatusUnauthorized, gin\.H\{[^}]*"message": "([^"]+)"/g)]
      .map((match) => match[1])),
  ]
  // 扫描器鉴别力：派生为空或缺分支时本用例会恒绿，先钉住真实文案集。
  for (const expected of [
    '缺少认证信息',
    '登录状态已过期，请重新登录',
    '登录状态已失效，请重新登录',
    '密码已修改，请重新登录',
    '登录凭证无效',
    '用户不存在或已禁用',
  ]) {
    assert.ok(messages.includes(expected), `jwtAuth 未派生「${expected}」——中间件形态或文案变化，扫描器需跟进`)
  }
  for (const msg of messages) {
    assert.ok(
      !MFA_CREDENTIAL_REJECTION_MESSAGES.includes(msg),
      `「${msg}」是 jwtAuth 的会话失效文案，不得进 MFA 凭证错误白名单`,
    )
    for (const url of ['/auth/mfa/verify-step', '/auth/mfa/status', '/users/3/mfa/reset']) {
      assert.equal(isMfaCredentialRejection(url, 401, msg), false, `${url} 的 401「${msg}」被误判为凭证错误`)
    }
  }
})

test('非 MFA 端点与其它状态码一律不豁免', () => {
  assert.equal(isMfaCredentialRejection('/auth/login', 401, '验证码错误'), false)
  assert.equal(isMfaCredentialRejection('/rules', 401, SESSION_EXPIRED), false)
  // 验证码错误若由非 401（400 表单校验/422）返回，本守卫不参与
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 400, '验证码错误'), false)
  // 未知文案 fail-safe：走会话失效流程（原实现按路径一律豁免，会吞掉真过期）
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 401, '用户不可用'), false)
  assert.equal(isMfaCredentialRejection(undefined, 401, '验证码错误'), false)
})

// 写操作验证「支持的操作」清单必须与后端 mfaStepUpGuard 的拦截面同源。
// 任务监控操作 / 节点服务控制 / 站点坐标 / 指纹补救 / 自动封禁 / 爬虫库 / IP 名单 /
// DNS 凭证连通性测试 等族曾被漏列——用户对这些写操作被要求验码会感到意外（守卫
// 仍生效，不构成绕过）。清单单源在 utils/mfaScopeGroups，测试直接 import。
test('MFA「支持的操作」清单覆盖 middleware 各写端点族', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /v-for="group in MFA_SCOPE_GROUPS"/, '弹框必须直接渲染单源清单')
  // 锚点只对 items 求值：把分组标题并进来时，与标题同名的锚点（如「负载规则」）
  // 会由标题满足——该组 items 被删空也仍绿（清单静默低估报警面）。
  const itemsFlat = MFA_SCOPE_GROUPS.map((g) => g.items.join('、')).join('\n')
  for (const anchor of ['任务监控 运行', '服务控制', '节点站点坐标', '指纹钉', '自动封禁', '爬虫库', 'IP 名单', 'DNS 凭证连通性测试']) {
    assert.ok(itemsFlat.includes(anchor), `MFA 清单缺「${anchor}」——用户对这些写操作会被要求验码`)
  }
  assert.match(page, /subtitle="覆盖全部管理写操作（只读语义写操作与 MFA 验码、登出端点除外）"/)
  // 副标题的豁免集必须与 DecideMFAStepUp 同源：step-up 只豁免 verify-step
  // 与 logout，setup/activate/disable/recovery-codes 全部在覆盖面内（同弹框
  // 清单也列了「启用/禁用/重新生成恢复码（自己的）」）。写成「MFA 自助端点
  // 除外」会让用户以为关写保护后不必验码。
  assert.doesNotMatch(page, /MFA 自助端点除外/, '副标题不得把 MFA 自助端点整体列为豁免')
  assert.doesNotMatch(page, /与 MFA 自身端点/, '注释不得宣称 MFA 自身端点整体豁免')
  const mfa = repoCode('internal/handlers/mfa.go')
  const stepUp = section(mfa, 'if path == "/api/v1/auth/mfa/verify-step"', '\n\t}')
  assert.ok(stepUp.includes('"/api/v1/auth/logout"'), 'DecideMFAStepUp 的豁免集已变化——副标题需同步')
  assert.ok(!stepUp.includes('/api/v1/auth/mfa/disable'), 'DecideMFAStepUp 扩大豁免集——副标题与清单需同步')
  // 证书配置/CA 测试会真实写 DNS/EAB，不得再宣称「测试连接…不受影响」
  assert.doesNotMatch(page, /测试连接、预览、解析类操作不受影响/)
})

// 反查钉：从 middleware.go 的 admin/business 组枚举全部写路由（含与写同级的
// 敏感导出 GET），逐族要求清单有锚点——新增写端点族未登记时本测试红，清单
// 不再靠人肉对齐。豁免面与守卫同一事实源：readOnlyWriteRoutes（只读语义写）
// + /auth/mfa/ 自助端点。
test('MFA 清单反查：middleware 全部写路由族均有清单锚点', () => {
  const mw = repoCode('internal/middleware/middleware.go')
  const policy = repoCode('internal/services/auditpolicy.go')
  // 只对 items 求值（标题不参与）：族锚点「负载规则」与分组标题同名，含标题时
  // 该组动作被删空也仍然命中，反查失去鉴别力。
  const flat = MFA_SCOPE_GROUPS.map((g) => g.items.join('、')).join('\n')

  const exemptBlock = section(policy, 'var readOnlyWriteRoutes = map[string]struct{}{', '\n}')
  const exempt = new Set([...exemptBlock.matchAll(/"([A-Z]+) (\/api\/v1[^"]+)"/g)].map((m) => `${m[1]} ${m[2]}`))
  const sensitiveBlock = section(mw, 'var sensitiveExportGetRoutes = map[string]bool{', '\n}')
  const sensitiveGets = [...sensitiveBlock.matchAll(/"(\/api\/v1[^"]+)":\s*true/g)].map((m) => `GET ${m[1]}`)

  const routes: string[] = [...sensitiveGets]
  for (const m of mw.matchAll(/\b(?:admin|business)\.(POST|PUT|PATCH|DELETE)\("([^"]+)"/g)) {
    routes.push(`${m[1]} /api/v1${m[2]}`)
  }
  assert.ok(routes.length > 60, `写路由枚举失效（仅 ${routes.length} 条）`)

  // 族锚点表（前缀有序，具体先于通用）：新增写端点族须在此登记锚点，
  // 否则落到 unmapped 报红——这就是「清单低估受保护范围」的机械保证。
  const familyAnchors: ReadonlyArray<readonly [string, string]> = [
    ['/api/v1/users/me/api-keys', 'API 密钥'],
    ['/api/v1/users/me', '个人资料修改'],
    ['/api/v1/auth/mfa/', '启用/禁用/重新生成恢复码'],
    ['/api/v1/users/:id/mfa/reset', '重置 MFA'],
    ['/api/v1/users', '用户增删改'],
    ['/api/v1/admin-tls', '管理 TLS'],
    ['/api/v1/system/restart', '系统重启'],
    ['/api/v1/system/tasks/', '任务监控'],
    ['/api/v1/caddy/config', '原始 Caddy 配置覆写（JSON 逃生口）'],
    ['/api/v1/caddy/', 'Caddy 服务启动'],
    ['/api/v1/api-keys', 'API 密钥'],
    ['/api/v1/ca-providers/', 'CA 提供商'],
    ['/api/v1/cluster/register-tokens', '注册令牌'],
    ['/api/v1/cluster/nodes/:id/login-ticket', '登录从节点'],
    ['/api/v1/cluster/nodes/:id/access-url', '访问地址修改'],
    ['/api/v1/cluster/nodes/:id/site', '节点站点坐标'],
    ['/api/v1/cluster/nodes/:id/service', '服务控制'],
    ['/api/v1/cluster/nodes/:id/forget-pin', '指纹钉'],
    ['/api/v1/cluster/nodes', '节点审批'],
    ['/api/v1/cluster/mode', '主从模式切换'],
    ['/api/v1/cluster/promote', '主从模式切换'],
    ['/api/v1/cluster/sync/pull', '手动同步'],
    ['/api/v1/cluster/settings', '集群同步设置'],
    ['/api/v1/cluster/forget-pins', '指纹钉'],
    ['/api/v1/config/export', '配置导出'],
    ['/api/v1/config/import', '配置导入'],
    ['/api/v1/config/reload', '配置重载'],
    ['/api/v1/config/validate', '配置重载'],
    ['/api/v1/config', '基础设置'],
    ['/api/v1/settings/auto-backup', '自动备份'],
    ['/api/v1/auto-backup', '自动备份'],
    ['/api/v1/settings/oidc', 'OIDC 配置'],
    ['/api/v1/security/policies', '安全策略'],
    ['/api/v1/security/rules/', '安全策略'],
    ['/api/v1/security/crs/', 'CRS'],
    ['/api/v1/security/ip2region/', 'IP 库'],
    ['/api/v1/security/threat-lib/', '威胁情报库'],
    ['/api/v1/security/crawler-lib/', '爬虫库'],
    ['/api/v1/security/custom-rules', '自定义规则'],
    ['/api/v1/security/block-pages', '拦截页面'],
    ['/api/v1/security/ip-lists', 'IP 名单'],
    ['/api/v1/security/autoban', '自动封禁'],
    ['/api/v1/rules/batch-block-pages', '拦截页面'],
    // 规则族锚点用该组 item「复制」：原锚点「负载规则」与分组标题同名，只由
    // 标题满足——该组 items 全删后反查仍绿。items 是裸动词（创建/编辑/…/复制），
    // 「复制」在同组内唯一。
    ['/api/v1/rules', '复制'],
    ['/api/v1/certificate-configs/test', 'DNS 凭证连通性测试'],
    ['/api/v1/certificate-configs/:id/test', 'DNS 凭证连通性测试'],
    ['/api/v1/certificate-configs', '证书配置'],
    ['/api/v1/certificates/issue', '触发证书签发'],
    ['/api/v1/certificates/jobs', '证书任务'],
  ]

  const unmapped: string[] = []
  const missingAnchor: string[] = []
  for (const route of routes) {
    if (exempt.has(route)) continue
    const path = route.slice(route.indexOf(' '))
    if (path === ' /api/v1/auth/mfa/verify-step') continue // step-up 机制本体，弹框副标题明示除外
    const family = familyAnchors.find(([prefix]) => path.startsWith(` ${prefix}`))
    if (!family) {
      unmapped.push(route)
    } else if (!flat.includes(family[1])) {
      missingAnchor.push(`${route} → 「${family[1]}」`)
    }
  }
  assert.deepEqual(unmapped, [], '新增写端点族未登记族锚点（清单会低估受保护范围）')
  assert.deepEqual(missingAnchor, [], '清单缺族锚点')
})
