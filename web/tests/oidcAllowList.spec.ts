// OIDC 访问白名单解析器行为验收（断言解析/格式化两端，而非 SFC 接线文本钉）：
// 邮箱域与用户组的分隔口径**有意不同**——域名单把空白当分隔符，组名允许内部
// 空格（IdP 组名如 "Platform Ops" 不得被切碎）。解析/格式化两端都 trim、去空、
// 保序去重，且文本↔数组往返幂等。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  formatAllowList,
  parseDomainAllowList,
  parseGroupAllowList,
  validateAllowList,
  OIDC_ALLOW_LIST_ENTRY_MAX_CHARS,
  OIDC_ALLOW_LIST_MAX_ENTRIES,
} from '../src/utils/oidcAllowList.ts'
import { repoCode } from './_helpers.ts'

test('邮箱域：空白/半角与全角逗号分号/顿号/换行均作分隔符', () => {
  assert.deepEqual(parseDomainAllowList('a.com; b.com、c.com'), ['a.com', 'b.com', 'c.com'])
  assert.deepEqual(parseDomainAllowList('a.com；\nb.com，c.com'), ['a.com', 'b.com', 'c.com'])
  // 域名单里空白也是分隔符（粘贴自表格/邮件时常见）
  assert.deepEqual(parseDomainAllowList('  a.com   b.com  '), ['a.com', 'b.com'])
})

test('邮箱域：去重保序、去空、空串/纯分隔符得到空数组', () => {
  assert.deepEqual(parseDomainAllowList('b.com,a.com,b.com'), ['b.com', 'a.com'])
  assert.deepEqual(parseDomainAllowList(''), [])
  assert.deepEqual(parseDomainAllowList('  ,;，、\n '), [])
})

test('用户组：组名内部空格必须保留（不得按空白切碎）', () => {
  assert.deepEqual(parseGroupAllowList('Platform Ops, SRE Team'), ['Platform Ops', 'SRE Team'])
  assert.deepEqual(parseGroupAllowList('Platform Ops；数据平台组\n安全组'), ['Platform Ops', '数据平台组', '安全组'])
  // 组名中的多个空格只做首尾 trim，内部原样保留
  assert.deepEqual(parseGroupAllowList('  A  B  '), ['A  B'])
})

test('用户组：顿号不是分隔符（组名可含顿号，只按逗号/分号/换行切分）', () => {
  assert.deepEqual(parseGroupAllowList('Ops、SRE'), ['Ops、SRE'])
  assert.deepEqual(parseGroupAllowList('Ops、SRE, Dev'), ['Ops、SRE', 'Dev'])
})

test('用户组：去重保序、空串/纯分隔符得到空数组', () => {
  assert.deepEqual(parseGroupAllowList('ops,ops,dev'), ['ops', 'dev'])
  assert.deepEqual(parseGroupAllowList(''), [])
  assert.deepEqual(parseGroupAllowList(' , ; ， '), [])
})

test('文本↔数组往返幂等（组名含空格同样无损）', () => {
  const domains = ['example.com', 'corp.example.org']
  const groups = ['Platform Ops', 'SRE Team', '数据平台组']
  assert.deepEqual(parseDomainAllowList(formatAllowList(domains)), domains)
  assert.deepEqual(parseGroupAllowList(formatAllowList(groups)), groups)
  assert.deepEqual(parseGroupAllowList(formatAllowList(parseGroupAllowList('A B, C'))), ['A B', 'C'])
  assert.equal(formatAllowList([]), '')
  assert.equal(formatAllowList(undefined), '')
})

test('字段名与后端 auth_oidc.go 的 json tag 同源（跨栈钉）', () => {
  // 解析器输出直接进 PUT 载荷键；键名漂移会让白名单静默落空（后端按缺省 null
  // 处理=不动），管理员以为已收口却对 IdP 全量开放。
  const go = repoCode('internal/handlers/auth_oidc.go')
  assert.ok(go.includes('json:"allowed_email_domains"'), '后端字段 allowed_email_domains 缺失')
  assert.ok(go.includes('json:"allowed_groups"'), '后端字段 allowed_groups 缺失')
})

// 白名单预算（与后端 normalizeOIDCAllowed* 同口径）：条目数与单条长度是
// 配置体积/回调扫描成本的唯一量门，UI 侧必须在提交前拦下——保存门会先跑一次
// discovery 探测，超限输入不该先花那几秒再吃 400。
test('白名单预算：超过 100 条拒收并点名上限与当前条数', () => {
  const overflow = Array.from({ length: OIDC_ALLOW_LIST_MAX_ENTRIES + 1 }, (_, i) => `g${i}`)
  const message = validateAllowList('允许的组', overflow)
  assert.ok(message, '超限必须返回提示')
  assert.match(message, /最多 100 条/)
  assert.match(message, /当前 101 条/)
  // 边界值合法
  assert.equal(validateAllowList('允许的组', overflow.slice(0, OIDC_ALLOW_LIST_MAX_ENTRIES)), null)
})

test('白名单预算：单条超长拒收（按字符计，中文组名不得按字节误判）', () => {
  assert.equal(validateAllowList('允许的 email 域', ['x'.repeat(OIDC_ALLOW_LIST_ENTRY_MAX_CHARS)]), null)
  const tooLong = validateAllowList('允许的 email 域', ['x'.repeat(OIDC_ALLOW_LIST_ENTRY_MAX_CHARS + 1)])
  assert.ok(tooLong)
  assert.match(tooLong, /最多 128 个字符/)
  // 128 个中文字符 = 384 字节：按字节判定会误拒，必须按字符数
  assert.equal(validateAllowList('允许的组', ['组'.repeat(OIDC_ALLOW_LIST_ENTRY_MAX_CHARS)]), null)
})

test('白名单预算：与后端常量同源（跨栈钉，漂移即两边口径分叉）', () => {
  const go = repoCode('internal/handlers/auth_oidc.go')
  assert.ok(go.includes('oidcAllowListMaxEntries = 100'), '后端条目上限应为 100')
  assert.ok(go.includes('oidcAllowListEntryMaxRunes = 128'), '后端单条上限应为 128 rune')
  assert.equal(OIDC_ALLOW_LIST_MAX_ENTRIES, 100)
  assert.equal(OIDC_ALLOW_LIST_ENTRY_MAX_CHARS, 128)
})
