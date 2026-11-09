// MFA 端点 401 分类验收：凭证/挑战错误豁免会话失效流程，
// 同端点经 jwtAuth 发出的会话 401 必须继续走重新登录。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isMfaCredentialRejection, MFA_CREDENTIAL_REJECTION_MESSAGES } from '../src/utils/mfaErrors.ts'
import { MFA_SCOPE_GROUPS } from '../src/utils/mfaScopeGroups.ts'
import { tSafe } from '../src/i18n/tSafe.ts'
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
  // i18n 迁移后契约:文案母本钉在 catalog(zh),调用点钉 message_key——
  // 后端改文案(catalog)或换键(调用点)任一漂移都会红,前端分类链不静默失配。
  const go = repoCode('internal/handlers/mfa.go')
  const catalog = repoCode('internal/i18n/catalog_gen.go')
  for (const [key, msg] of [
    ['k_345a8c4a', '验证码错误'],
    ['k_df527f47', '验证码错误次数过多，绑定已作废，请重新开始绑定'],
    ['k_5c5030a7', 'MFA 挑战无效或已过期，请重新登录'],
    ['k_201b3428', 'MFA 挑战已被使用，请重新登录'],
  ] as const) {
    assert.ok(catalog.includes(`Register("${key}", "${msg}"`), `catalog 母本漂移:「${msg}」`)
    assert.ok(go.includes(`MessageKey: "${key}"`), `mfa.go 调用点不再使用键 ${key}(401 文案「${msg}」)——前端白名单失配`)
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
  const catalog = repoCode('internal/i18n/catalog_gen.go')
  // i18n 后:middleware 消息=apimsg.T 调用点,扫描 message_key 键集,catalog 映射回 zh 母本对表
  const keySet = [
    ...new Set([...jwtAuth.matchAll(/"message_key": "(k_[a-f0-9]+)"/g)].map((m) => m[1])),
  ]
  const zhOf = (key: string): string => {
    const mm = catalog.match(new RegExp('Register\\("' + key + '", "((?:[^"\\\\]|\\\\.)*)"'))
    return mm ? mm[1] : ''
  }
  const messages = keySet.map(zhOf)
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
  // i18n 后双钉：BasicSettings 弹框副标题已键化（app.settings.basic.mfaScope，settings 域）——
  // 调用点钉键，zh 母本（locales/zh/settings.ts）钉原文，任一漂移必红。
  assert.match(page, /:subtitle="t\('app\.settings\.basic\.mfaScope\.subtitle'\)"/)
  assert.ok(code('src/locales/zh/settings.ts').includes('覆盖全部管理写操作（只读语义写操作与 MFA 验码、登出端点除外）'), 'MFA 弹框副标题原文必须在 zh settings 域词条中')
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

// ── 清单词条化（i18n 双钉）────────────────────────────────────────────
// mfaScopeGroups 的 title/items 已键化（views.mfa.*）：zh 母本侧由集成器落盘
// locales/{zh,en}/views.ts。三向钉——任一漂移必红：
//   ① 调用点钉键：mfaScopeGroups.ts 源码逐键出现 t('common.app.views.mfa.<key>')；
//   ② zh 母本钉原文：views.ts 逐键含原 zh 字面量（键↔文案绑定）；
//   ③ 运行时等值：tSafe(key) === 原 zh 字面量（tSafe zh 直出逐字等价，
//      上方族锚点/清单覆盖用例因此不受键化影响）。
test('MFA 清单词条键化：50 键三向对表（调用点/zh 母本/运行时）', () => {
  const src = code('src/utils/mfaScopeGroups.ts')
  const zhViews = code('src/locales/zh/views.ts')
  for (const [key, zh] of Object.entries(MFA_SCOPE_I18N_TABLE) as Array<[string, string]>) {
    assert.ok(src.includes(`t('common.app.views.mfa.${key}')`), `清单源码缺键 ${key} 的 t() 调用`)
    assert.ok(zhViews.includes(zh), `zh 母本词条缺「${zh}」（键 ${key}）`)
    assert.equal(tSafe(`common.app.views.mfa.${key}`), zh, `键 ${key} 的 zh 直出与母本漂移`)
  }
})

// 分组形状钉：6 组标题键序 + 每组 items 键序（防止键位挪动静默改组/漏项）。
test('MFA 清单词条键化：分组标题与 items 键位逐一对表', () => {
  assert.equal(MFA_SCOPE_GROUPS.length, MFA_SCOPE_KEY_LAYOUT.length)
  MFA_SCOPE_GROUPS.forEach((group, gi) => {
    const [titleKey, itemKeys] = MFA_SCOPE_KEY_LAYOUT[gi]!
    assert.equal(group.title, tSafe(`common.app.views.mfa.${titleKey}`), `第 ${gi + 1} 组标题键漂移`)
    assert.equal(group.items.length, itemKeys.length, `第 ${gi + 1} 组 items 数漂移`)
    group.items.forEach((item, ii) => {
      assert.equal(item, tSafe(`common.app.views.mfa.${itemKeys[ii]}`), `第 ${gi + 1} 组第 ${ii + 1} 项键漂移`)
    })
  })
})

const MFA_SCOPE_I18N_TABLE: Record<string, string> = {
  "scopeAccessUrl": "访问地址修改",
  "scopeAdminTls": "管理 TLS 设置修改",
  "scopeApiKeyMgmt": "API 密钥创建/启停/删除（含自己的）",
  "scopeAutobanConfig": "自动封禁配置",
  "scopeBlockPageCrud": "拦截页面增删改",
  "scopeCaProviderChangeTest": "CA 提供商修改/测试",
  "scopeCaddyService": "Caddy 服务启动/停止/重启",
  "scopeCertConfigCrud": "证书配置增删改",
  "scopeCertJobRetryDelete": "证书任务重试/删除",
  "scopeClusterSync": "集群同步设置",
  "scopeConfigExportBackup": "配置导出与自动备份（设置保存/立即备份/删除/还原/下载）",
  "scopeConfigImport": "配置导入（v1/v2）",
  "scopeConfigReloadValidate": "配置重载/校验",
  "scopeCreate": "创建",
  "scopeCustomRuleCrud": "自定义规则增删改",
  "scopeDelete": "删除",
  "scopeDisable": "禁用",
  "scopeDnsConfigCrud": "DNS 配置增删改",
  "scopeDnsCredentialTest": "DNS 凭证连通性测试",
  "scopeDuplicate": "复制",
  "scopeEdit": "编辑",
  "scopeEnable": "启用",
  "scopeForgetPin": "清除节点证书指纹/清空指纹钉",
  "scopeGroupCertDns": "证书与 DNS",
  "scopeGroupCluster": "集群管理",
  "scopeGroupRules": "负载规则",
  "scopeGroupSecurity": "安全防护",
  "scopeGroupSystem": "系统与服务",
  "scopeGroupUsersKeys": "用户与密钥",
  "scopeIpListCrud": "IP 名单增删改与条目增删",
  "scopeLibUpdate": "CRS/IP 库更新与自动更新开关",
  "scopeManualSync": "手动同步",
  "scopeMfaReset": "重置 MFA（含管理员代重置）",
  "scopeModeSwitch": "主从模式切换/提升",
  "scopeNodeApproval": "节点审批/拒绝/删除",
  "scopeNodeService": "服务控制（启动/停止/重启 Caddy、重启应用）",
  "scopeNodeSite": "节点站点坐标配置",
  "scopeOidcConfig": "OIDC 配置修改/删除",
  "scopeProfileUpdate": "个人资料修改",
  "scopeRawCaddyOverwrite": "原始 Caddy 配置覆写（JSON 逃生口）",
  "scopeRecoveryCodes": "启用/禁用/重新生成恢复码（自己的）",
  "scopeRegisterToken": "注册令牌生成",
  "scopeReplicaLogin": "登录从节点（票据签发，每次验证）",
  "scopeSecurityPolicyCrud": "安全策略增删改/绑定/拆分",
  "scopeSettingsSave": "基础设置/Caddy 全局配置保存",
  "scopeSystemRestart": "系统重启",
  "scopeTaskMonitor": "任务监控 运行/停止调度/取消/重启",
  "scopeThreatCrawlerUpdate": "威胁情报库/爬虫库更新与开关",
  "scopeTriggerIssue": "触发证书签发",
  "scopeUserCrud": "用户增删改/启停/重置密码（管理员）",
}

const MFA_SCOPE_KEY_LAYOUT: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['scopeGroupRules', ['scopeCreate', 'scopeEdit', 'scopeDelete', 'scopeEnable', 'scopeDisable', 'scopeDuplicate']],
  ['scopeGroupCertDns', ['scopeDnsConfigCrud', 'scopeCertConfigCrud', 'scopeDnsCredentialTest', 'scopeCaProviderChangeTest', 'scopeTriggerIssue', 'scopeCertJobRetryDelete']],
  ['scopeGroupSecurity', ['scopeSecurityPolicyCrud', 'scopeCustomRuleCrud', 'scopeBlockPageCrud', 'scopeIpListCrud', 'scopeLibUpdate', 'scopeThreatCrawlerUpdate', 'scopeAutobanConfig']],
  ['scopeGroupUsersKeys', ['scopeUserCrud', 'scopeProfileUpdate', 'scopeApiKeyMgmt', 'scopeMfaReset', 'scopeRecoveryCodes']],
  ['scopeGroupSystem', ['scopeSettingsSave', 'scopeConfigReloadValidate', 'scopeConfigImport', 'scopeConfigExportBackup', 'scopeAdminTls', 'scopeOidcConfig', 'scopeCaddyService', 'scopeRawCaddyOverwrite', 'scopeTaskMonitor', 'scopeSystemRestart']],
  ['scopeGroupCluster', ['scopeNodeApproval', 'scopeAccessUrl', 'scopeNodeSite', 'scopeNodeService', 'scopeForgetPin', 'scopeRegisterToken', 'scopeModeSwitch', 'scopeManualSync', 'scopeClusterSync', 'scopeReplicaLogin']],
]
