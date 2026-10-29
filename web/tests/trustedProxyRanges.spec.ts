// 受信代理网段行内校验：判据必须与后端单源，且只在后端必然拒绝
// 的形态上报错（前端误拒会挡住合法配置，故放宽方向一律交给后端兜底）。
//
// 后端：internal/services/caddy.go TrustedProxyMinPrefixBits / PrefixAllSpace、
// internal/handlers/config_trustedproxy.go normalizeTrustedProxyRanges。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  TRUSTED_PROXY_MAX_HEADERS,
  TRUSTED_PROXY_MAX_INLINE_ENTRIES,
  TRUSTED_PROXY_MAX_TOTAL_ENTRIES,
  TRUSTED_PROXY_MIN_PREFIX_BITS,
  trustedProxyExpansion,
  trustedProxyHeadersError,
  trustedProxyRangesError,
  trustedProxyTotalError,
  trustedProxyTotalWarning,
} from '../src/utils/trustedProxyRanges.ts'
import { repoCode, section, code } from './_helpers.ts'

// 单条校验（range/header）与并集键已收敛为模块私有：经整列对外入口间接断言。
// 汇总文案形如 `受信网段不可用：<原文>（<原因>）`——原因自身可含全角括号
// （最小前缀文案），按「前缀 + 已知原文」剥离，不按括号解析。
const rangeError = (value: string): string => {
  const aggregate = trustedProxyRangesError([value])
  if (aggregate === '') return ''
  const prefix = `受信网段不可用：${value.trim() || '(空)'}（`
  return aggregate.startsWith(prefix) ? aggregate.slice(prefix.length, -1) : aggregate
}
const headerError = (value: string): string => {
  const aggregate = trustedProxyHeadersError([value])
  if (aggregate === '') return ''
  const prefix = `受信代理请求头不可用：${value || '(空)'}（`
  return aggregate.startsWith(prefix) ? aggregate.slice(prefix.length, -1) : aggregate
}

test('合法条目零报错（含裸 IP 与 IPv6 官方回源段）', () => {
  for (const value of ['203.0.113.0/24', '1.2.3.4', '  10.0.0.0/8  ', '2001:db8::/32', '2a06:98c0::/29']) {
    assert.equal(rangeError(value), '', `${value} 应被放行`)
  }
})

test('非法形态立即报错', () => {
  assert.match(rangeError('not-a-cidr'), /不是合法的 IP 或 CIDR/)
  assert.match(rangeError('1.2.3.4/33'), /不是合法的 IP 或 CIDR/)
  assert.match(rangeError(''), /不能为空/)
  assert.match(rangeError('   '), /不能为空/)
})

test('过宽网段与后端最小前缀判据一致', () => {
  assert.match(rangeError('10.0.0.0/4'), /最小允许 \/8/)
  assert.match(rangeError('2001:db8::/28'), /\/29（IPv6）/)
  // 全空间形态优先按「覆盖全部地址空间」报（与后端两条判据同序）
  assert.match(rangeError('0.0.0.0/0'), /全部地址空间/)
  assert.match(rangeError('::/0'), /全部地址空间/)
})

test('v4-mapped 变体与后端归一口径一致（mapped /96 折算即全空间）', () => {
  // 主机位变体与 canonical 写法是同一网段；折算后 = 0.0.0.0/0 → 后端必然 400
  for (const value of [
    '::ffff:0.0.0.1/96',
    '::ffff:0:0/96',
    '::ffff:0.0.0.0/96',
    '::ffff:203.0.113.9/96',
    '::ffff:0.0.0.0/104',
    '::ffff:0.0.0.0/95',
  ]) {
    assert.match(rangeError(value), /全部地址空间/, `${value} 应判全空间`)
  }
  // 折算成等价 v4 后低于 /8：按最小前缀报错
  assert.match(rangeError('::ffff:0.0.0.0/97'), /最小允许 \/8/)
  // 合法 mapped 精确段（等价 v4 ≥ /8）不得误拒
  for (const value of ['::ffff:203.0.113.7/120', '::ffff:198.51.100.7', '::ffff:10.0.0.0/104']) {
    assert.equal(rangeError(value), '', `${value} 应放行`)
  }
  // 并集口径同源：同一网段的 mapped 与 v4 写法只计一次（含全空间变体）
  assert.equal(trustedProxyExpansion(['::ffff:203.0.113.0/120', '203.0.113.0/24'], []).union, 1)
  assert.equal(trustedProxyExpansion(['::ffff:0.0.0.1/96', '0.0.0.0/0'], []).union, 1)
})

test('IPv4 主机位变体先规范化再判全空间，与后端 canonical 一致', () => {
  for (const value of ['0.0.0.1/8', '0.5.6.7/8', '127.255.255.255/0']) {
    assert.match(rangeError(value), /全部地址空间/, `${value} 规范化后覆盖全空间，后端必然拒绝`)
  }
  assert.match(rangeError('10.0.0.0/4'), /最小允许 \/8/, '非全空间的过宽网段仍走最小前缀文案')
  assert.equal(rangeError('203.0.113.7/24'), '', '普通主机位变体不得误拒')
})

test('内联网段条数上限与后端 inline 上限一致', () => {
  const atLimit = Array.from({ length: TRUSTED_PROXY_MAX_INLINE_ENTRIES }, (_, i) => `10.${i}.0.0/16`)
  assert.equal(trustedProxyRangesError(atLimit), '')
  const overLimit = [...atLimit, '192.168.0.0/16']
  assert.match(trustedProxyRangesError(overLimit), /最多 64 条/)
})

test('汇总文案逐条点名非法值（用户可定位是哪一条）', () => {
  const message = trustedProxyRangesError(['203.0.113.0/24', '0.0.0.0/0', '10.0.0.0/4'])
  assert.match(message, /0\.0\.0\.0\/0（/)
  assert.match(message, /10\.0\.0\.0\/4（/)
  assert.doesNotMatch(message, /203\.0\.113\.0\/24/)
})

test('跨栈对表：Go 侧判据与前端常量同值', () => {
  const caddy = repoCode('internal/services/caddy.go')
  const minBits = section(caddy, 'func TrustedProxyMinPrefixBits', 'func TrustedProxyPrefixAllSpace')
  assert.match(minBits, /return 29/)
  assert.match(minBits, /return 8/)
  const allSpace = section(caddy, 'func TrustedProxyPrefixAllSpace', 'func TrustedProxyPrefixTooWide')
  // 双向集合法（不是单向包含）：后端新增第 6 个全空间形态而前端不同步时，
  // 用户会在面板写入等同 0.0.0.0/0 的配置且前端零提示（保存后整组被拒）。
  const goForms = [...allSpace.matchAll(/"([^"]+)"/g)].map((match) => match[1]).sort()
  const tsArray = section(code('src/utils/trustedProxyRanges.ts'), 'const ALL_SPACE_PREFIXES: readonly string[] = [', ']')
  const tsForms = [...tsArray.matchAll(/'([^']+)'/g)].map((match) => match[1]).sort()
  assert.deepEqual(tsForms, goForms, '前端 ALL_SPACE_PREFIXES 必须与 Go case 列表逐值相等')
  const handler = repoCode('internal/handlers/config_trustedproxy.go')
  assert.match(handler, /len\(entries\) > 64/, '内联网段条目上限须与常量对表')
  assert.equal(TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4, 8)
  assert.equal(TRUSTED_PROXY_MIN_PREFIX_BITS.ipv6, 29)
  assert.equal(TRUSTED_PROXY_MAX_INLINE_ENTRIES, 64)
})

test('组件接线：行内标红 + 保存门（不再等到 PUT 才被整组拒绝）', () => {
  const card = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /const trustedRangesError = computed\(\(\) => trustedProxyRangesError\(trustedRanges\.value\)\)/)
  assert.match(card, /v-if="trustedRangesError"/, '非法条目必须就地呈现')
  const save = section(card, 'const handleSave = async', 'const preview = await request.post')
  assert.match(save, /if \(trustedRangesError\.value\)/)
  assert.ok(
    save.indexOf('trustedRangesError.value') < save.indexOf('buildCaddyConfigPayload'),
    '校验必须早于载荷组装与任何写请求',
  )
})

// —— 请求头：条数 ≤8、字符集（后端 normalizeTrustedProxyHeaders 逐条对齐） ——

test('请求头合法形态零报错（含 8 条上限与连字符名）', () => {
  for (const value of ['X-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP', 'True-Client-IP', 'A1']) {
    assert.equal(headerError(value), '', `${value} 应被放行`)
  }
  const atLimit = Array.from({ length: TRUSTED_PROXY_MAX_HEADERS }, (_, i) => `X-Forwarded-${i}`)
  assert.equal(trustedProxyHeadersError(atLimit), '')
})

test('请求头非法形态立即报错（空格/下划线/空/超长，与后端字符集一致）', () => {
  assert.match(headerError('X-Forwarded-For '), /非法请求头名/)
  assert.match(headerError('X_Forwarded_For'), /非法请求头名/)
  assert.match(headerError(''), /非法请求头名/)
  assert.match(headerError(`X-${'a'.repeat(63)}`), /非法请求头名/, '超 64 字符必须拒绝')
  assert.match(headerError('X Forwarded For'), /非法请求头名/)
})

test('请求头条数上限按小写去重后条数计（与后端 len(normalized) > 8 同口径）', () => {
  const nine = Array.from({ length: TRUSTED_PROXY_MAX_HEADERS + 1 }, (_, i) => `X-Forwarded-${i}`)
  assert.match(trustedProxyHeadersError(nine), /最多 8 条/)
  // 9 条含 1 条大小写重复 → 后端归一为 8 条并接受，前端不得硬拦
  const dedupedEight = ['X-Forwarded-For', 'x-forwarded-for', 'X-Real-IP', 'A', 'B', 'C', 'D', 'E', 'F']
  assert.equal(trustedProxyHeadersError(dedupedEight), '', '去重后 8 条必须放行（后端 PUT 200）')
  // 10 条含 1 条大小写重复 → 去重后 9 条：后端必然 400，前端须先拦
  const dedupedNine = ['X-Forwarded-For', 'x-forwarded-for', 'X-Real-IP', 'A', 'B', 'C', 'D', 'E', 'F', 'G']
  assert.match(trustedProxyHeadersError(dedupedNine), /最多 8 条（去重后 9 条/, '去重后 9 条后端必然拒绝')
  // 字符集逐条点名不受去重影响（重复项同样要点名，后端逐条校验字符集）
  assert.match(trustedProxyHeadersError(['X_Forwarded_For', 'X_Forwarded_For']), /X_Forwarded_For（/)
})

test('请求头汇总文案逐条点名非法值', () => {
  const message = trustedProxyHeadersError(['CF-Connecting-IP', 'X_Forwarded_For'])
  assert.match(message, /X_Forwarded_For（/)
  assert.doesNotMatch(message, /CF-Connecting-IP（/)
})

// —— 总量门：内联 ∪ 引用展开 ≤2000（后端 trustedProxyTotalGate 去重口径） ——

test('总量门按规范化前缀并集判定：重叠网段不再把合法配置顶过上限', () => {
  const shared = Array.from({ length: 60 }, (_, i) => `203.0.${i}.0/24`)
  const unique = Array.from({ length: 1940 }, (_, i) => `198.${Math.floor(i / 256)}.${i % 256}.0/24`)
  // 内联 60 条同时出现在引用名单内 + 名单另有 1940 条：按条数累加 2060（旧误拒），
  // 按前缀并集恰为 2000（后端实际展开规模）。
  const refs = [{ values: [...shared, ...unique], entryCount: 2000 }]
  assert.equal(trustedProxyTotalError(shared, refs), '', '重叠网段只计一次，恰好 2000 应放行')
  assert.equal(trustedProxyExpansion(shared, refs).union, 2000)
})

test('总量门超限文案给出去重后合计与两个分量（与后端文案同结构）', () => {
  const unique = Array.from({ length: 2000 }, (_, i) => `198.${Math.floor(i / 256)}.${i % 256}.0/24`)
  const message = trustedProxyTotalError(['203.0.113.0/24'], [{ values: unique, entryCount: 2000 }])
  assert.match(message, /超过 2000 上限/)
  assert.match(message, /去重后合计 2001：内联 1 \+ 引用展开 2000/)
  assert.match(message, /重叠网段只计一次/)
})

test('同一前缀的不同书写形态合并计一次（裸 IP、IPv6 大小写与展开形态）', () => {
  const inline = ['203.0.113.4', '203.0.113.4/32', '203.0.113.0/24', '203.0.113.0/24 ']
  assert.equal(trustedProxyExpansion(inline, []).union, 2, '裸 IP 与 /32、重复项必须同键')
  assert.equal(trustedProxyExpansion(['2001:DB8::/32', '2001:db8:0:0:0:0:0:0/32'], []).union, 1)
  assert.equal(trustedProxyExpansion([], [{ values: ['::ffff:203.0.113.0/120', '0:0:0:0:0:ffff:cb00:7100/120'], entryCount: 2 }]).union, 1)
  // 主机位归一（后端 Masked 去重同口径）：同一网段的不同主机位写法只计一次
  assert.equal(trustedProxyExpansion(['192.0.2.129/24', '192.0.2.0/24'], []).union, 1)
  assert.equal(trustedProxyExpansion(['192.0.2.129/27', '192.0.2.128/27'], []).union, 1)
  assert.equal(trustedProxyExpansion(['2001:db8::1/32', '2001:db8::/32'], []).union, 1)
  assert.equal(trustedProxyExpansion(['2001:db8::1/47', '2001:db8:0:1::/47'], []).union, 1)
  // 键形态已收敛为模块私有：经并集入口断言同义行为——裸 IP 前后空白不产生
  // 第二键；非法形态不产生键（不得与任何合法前缀折叠）。
  assert.equal(trustedProxyExpansion([' 203.0.113.4 ', '203.0.113.4/32'], []).union, 1)
  assert.equal(trustedProxyExpansion(['not-a-cidr'], []).union, 0)
})

test('硬门只拦可证超限：未加载条目按条数估算，估算越限降级为提示', () => {
  assert.equal(trustedProxyTotalError(['203.0.113.0/24'], [{ values: null, entryCount: 0 }]), '')
  // 内联 1 + 估算 2000：只是可能超限，不得硬拦（多份未加载名单会重复计数）
  assert.equal(
    trustedProxyTotalError(['203.0.113.0/24'], [{ values: null, entryCount: 2000 }]),
    '',
    '估算值不得触发硬门——前端以估算否掉配置会挡住后端会接受的合法载荷',
  )
  assert.ok(trustedProxyTotalWarning(['203.0.113.0/24'], [{ values: null, entryCount: 2000 }]).length > 0, '估算越限必须给出提示')
  // 单份名单自身超过上限：任何并集都至少包含它 → 可证超限
  assert.match(trustedProxyTotalError(['203.0.113.0/24'], [{ values: null, entryCount: 2100 }]), /按条数估算/)
  assert.equal(trustedProxyTotalWarning([], [{ values: null, entryCount: 2100 }]), '', '可证超限由硬门报错，不重复提示')
  assert.equal(trustedProxyTotalError([], [{ values: null, entryCount: 2000 }]), '', '恰好 2000 应放行')
  assert.equal(trustedProxyTotalError([], [{ values: null, entryCount: 0 }]), '', '未引用名单时不设额外总量门')
})

test('多份未加载引用互相重叠：不得按条数累加硬拦（后端会接受的配置）', () => {
  // 两份各 1500 条、真实并集远低于上限；条目接口在途/失败时前端无法去重。
  const refs = [
    { values: null, entryCount: 1500 },
    { values: null, entryCount: 1500 },
  ]
  assert.equal(trustedProxyTotalError([], refs), '', '估算合计 3000 只是上界，不得拦保存')
  const warning = trustedProxyTotalWarning([], refs)
  assert.match(warning, /可能超过 2000 上限/)
  assert.match(warning, /3000/)
  assert.match(warning, /按条数估算/)
  assert.match(warning, /最终以服务端/, '提示必须声明判定权在服务端')

  // 一份已加载（并集可证）叠加一份未加载：已解析并集超限仍硬拦
  const resolvedOver = Array.from({ length: 2001 }, (_, i) => `198.${Math.floor(i / 256)}.${i % 256}.0/24`)
  assert.match(
    trustedProxyTotalError([], [{ values: resolvedOver, entryCount: 2001 }, { values: null, entryCount: 10 }]),
    /超过 2000 上限/,
    '已解析并集超限是可证事实，必须硬拦',
  )
})

test('非法/空条目不计入并集（由网段判据逐条点名）', () => {
  assert.equal(trustedProxyExpansion(['', '  ', 'not-a-cidr', '203.0.113.0/24'], []).union, 1)
})

test('跨栈对表：请求头与总量判据与 Go 侧同值', () => {
  const handler = repoCode('internal/handlers/config_trustedproxy.go')
  const headers = handler.slice(handler.indexOf('func normalizeTrustedProxyHeaders'))
  assert.match(headers, /len\(normalized\) > 8/, '请求头条数上限须按去重后条目对表')
  assert.match(headers, /strings\.ToLower\(entry\)/, '请求头去重须忽略大小写')
  // 前端条数门必须与后端同一口径（先去重再判数）：按原始条数判会硬拦后端
  // 必然接受的配置（9 条含 1 条大小写重复 → 后端归一为 8 条）。
  const tsHeaders = section(
    code('src/utils/trustedProxyRanges.ts'),
    'export const trustedProxyHeadersError',
    '\n}\n',
  )
  assert.match(
    tsHeaders,
    /new Set\(values\.map\(\(value\) => value\.toLowerCase\(\)\)\)\.size/,
    '请求头条数门须按小写去重后条数判定（与后端 len(normalized) 对表）',
  )
  assert.doesNotMatch(tsHeaders, /values\.length > TRUSTED_PROXY_MAX_HEADERS/, '不得按原始条数判上限')
  assert.match(handler, /\^\[A-Za-z0-9-\]\{1,64\}\$/, '请求头字符集须对表')
  assert.match(handler, /trustedProxyMaxTotalCIDRs = 2000/, '总量上限须对表')
  const gate = section(handler, 'func trustedProxyTotalGate', 'func trustedProxyInlinePrefixes')
  assert.match(gate, /union := len\(inline\)/, '后端按规范化前缀集合大小判总量')
  assert.match(gate, /重叠网段只计一次/, '后端文案口径须与前端一致')
  assert.equal(TRUSTED_PROXY_MAX_HEADERS, 8)
  assert.equal(TRUSTED_PROXY_MAX_TOTAL_ENTRIES, 2000)
})

test('组件接线：请求头与总量行内提示 + 保存门', () => {
  const card = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /const trustedHeadersError = computed\(\(\) => trustedProxyHeadersError\(trustedHeaders\.value\)\)/)
  assert.match(card, /const trustedTotalError = computed\(\(\) => trustedProxyTotalError\(trustedRanges\.value, /)
  assert.match(card, /const trustedTotalWarning = computed\(\(\) => trustedProxyTotalWarning\(trustedRanges\.value, /, '估算越限提示须就地呈现')
  assert.match(card, /const trustedExpansion = computed\(\(\) => trustedProxyExpansion\(trustedRanges\.value, /)
  assert.match(card, /request\.get<APIResponse<TrustedIpListDetail>>\(`\/security\/ip-lists\/\$\{id\}`, \{ silent: true \}\)/, '总量门须拉取引用名单条目以去重')
  assert.match(card, /interface TrustedIpListDetail \{[^}]*id:\s*number/, '详情载荷必须携带 id')
  assert.ok(card.includes('entries?: { value: string }[]'), '条目形状须与 GET /security/ip-lists/:id 对齐')
  assert.match(card, /v-if="trustedHeadersError"/, '非法请求头必须就地呈现')
  assert.match(card, /v-if="trustedTotalError"/, '合计超限必须就地呈现')
  assert.match(card, /v-else-if="trustedTotalWarning"/, '估算越限必须就地呈现且与硬错误互斥')
  assert.match(card, /v-if="refListEntriesRetryIds\.length"/, '条目加载失败须可见')
  assert.match(card, /重新加载名单条目/, '条目加载失败必须给出一键重试入口（不得只让用户刷新整页）')
  assert.match(card, /上限 \{\{ TRUSTED_PROXY_MAX_TOTAL_ENTRIES \}\}/, '展示上限与判据常量同源')
  const save = section(card, 'const handleSave = async', 'const preview = await request.post')
  const headersIdx = save.indexOf('trustedHeadersError.value')
  const errorIdx = save.indexOf('trustedTotalError.value')
  const payloadIdx = save.indexOf('buildCaddyConfigPayload')
  assert.ok(headersIdx > 0, '保存门必须拦非法请求头')
  assert.ok(errorIdx > 0, '保存门必须拦总量超限')
  assert.ok(errorIdx < payloadIdx, '校验必须早于载荷组装与任何写请求')
  // 估算越限只提示不 return：硬门之后紧跟 saving 置位，两者之间不能再有 return。
  // 首尾标记都必须**先证明存在**：indexOf 缺 marker 返回 -1，`save.slice(warnIdx, -1)`
  // 会退化成「从提示到末尾全部内容」，负断言恒真空转（估算提示被提前 return 掉
  // 也判绿）。方向断言保证窗口是 [提示, 置位) 而不是被写反的空窗。
  const warnIdx = save.indexOf('trustedTotalWarning.value')
  const savingIdx = save.indexOf('saving.value = true')
  assert.ok(warnIdx > errorIdx, '提示在硬门之后')
  assert.ok(savingIdx > warnIdx, '终点标记（saving 置位）必须存在且在提示之后（缺失时负断言会空转）')
  const between = save.slice(warnIdx, savingIdx)
  assert.doesNotMatch(between, /\breturn\b/, '估算越限不得拦保存（判定权在后端）')
})
