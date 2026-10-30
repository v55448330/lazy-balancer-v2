// IP / CIDR 解析单源（utils/ipAddress）：v4 八位组、v6 十六进制组、CIDR 判据与
// 长整/大整折算此前在 ruleValidation / trustedProxyRanges / securityStages /
// upstreamKeys 各写一份，边界判据已经分叉（前导零、%zone、`::` 展开）。本 spec
// 钉两件事：①各消费点必须接单源，不得保留平行实现；②宽容度差异由显式参数
// （allowLeadingZeros / allowZone）保留——写侧预校验不得因共享实现而放松。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  canonicalV6Text,
  isValidCidr,
  isValidV4,
  isValidV6,
  parseIPv4Octets,
  parseIPv6Groups,
  toV4Long,
  toV6BigInt,
} from '../src/utils/ipAddress.ts'
import { code } from './_helpers.ts'

test('parseIPv4Octets：前导零由显式参数决定（写侧拒、事件匹配侧收）', () => {
  assert.deepEqual(parseIPv4Octets('203.0.113.9', { allowLeadingZeros: true }), [203, 0, 113, 9])
  assert.deepEqual(parseIPv4Octets('203.000.113.9', { allowLeadingZeros: true }), [203, 0, 113, 9])
  assert.equal(
    parseIPv4Octets('203.000.113.9', { allowLeadingZeros: false }),
    null,
    '写侧预校验必须拒前导零（后端 netip 同口径）',
  )
  for (const bad of ['1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.x', '', '1.2.3.-1', ' 1.2.3.4']) {
    assert.equal(parseIPv4Octets(bad, { allowLeadingZeros: true }), null, `${bad} 必须解析失败`)
  }
})

test('parseIPv6Groups：:: 展开、嵌入 IPv4 尾、非法形态', () => {
  assert.deepEqual(parseIPv6Groups('::1', { allowZone: false }), [0, 0, 0, 0, 0, 0, 0, 1])
  assert.deepEqual(parseIPv6Groups('2001:DB8::80', { allowZone: false }), [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x80])
  assert.deepEqual(parseIPv6Groups('1:2:3:4:5:6:7:8', { allowZone: false }), [1, 2, 3, 4, 5, 6, 7, 8])
  assert.deepEqual(
    parseIPv6Groups('::ffff:1.2.3.4', { allowZone: false }),
    [0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304],
    '嵌入 IPv4 尾按两个十六进制组折算（与 netip 解析后的地址同形）',
  )
  for (const bad of [
    '1:2:3:4:5:6:7:8::',
    '::1::2',
    '1::2::3',
    'zz::1',
    '12345::1',
    '::1 ',
    '[::1]',
    '1.2.3.4::',
    '1:2:3:4:5:6:7',
    '10.0.0.1',
  ]) {
    assert.equal(parseIPv6Groups(bad, { allowZone: false }), null, `${bad} 必须解析失败`)
  }
})

test('parseIPv6Groups：%zone 由显式参数决定（链路匹配侧收、写侧拒）', () => {
  assert.equal(parseIPv6Groups('fe80::1%eth0', { allowZone: false }), null)
  assert.deepEqual(
    parseIPv6Groups('fe80::1%eth0', { allowZone: true }),
    [0xfe80, 0, 0, 0, 0, 0, 0, 1],
    'zone 只丢弃不参与数值',
  )
})

test('toV4Long / toV6BigInt：折叠为整数，非法形态返回哨兵', () => {
  assert.equal(toV4Long('255.255.255.255'), 4294967295)
  assert.equal(toV4Long('10.0.0.1'), 167772161)
  assert.equal(toV4Long('10.0.0'), -1)
  assert.equal(toV4Long('256.0.0.1'), -1)
  assert.equal(toV6BigInt('::1'), 1n)
  assert.equal(toV6BigInt('2001:db8::'), (0x2001n << 112n) | (0x0db8n << 96n))
  assert.equal(toV6BigInt('fe80::1%eth0'), (0xfe80n << 112n) | 1n, '事件侧接受 zone')
  assert.equal(toV6BigInt('zz::1'), null)
})

test('toV4Long 走事件侧宽容单源：zone 宽容、前导零按数值、空段/空白拒绝', () => {
  // 缺陷修复：空段/空白段不得被 Number('')===0 / Number(' ')===0 放行为 0 段
  for (const bad of ['1.2.3.', '1..2.3', '.1.2.3', '1. .2.3', '  .2.3.4', '1.2.3.4.']) {
    assert.equal(toV4Long(bad), -1, `${bad} 必须解析失败（空段/空白段拒绝）`)
  }
  // 事件侧既定口径保留：首尾空白、%zone 丢弃、前导零按十进制数值
  assert.equal(toV4Long(' 1.2.3.4 '), 16909060)
  assert.equal(toV4Long('1.2.3.4%eth0'), 16909060, '引擎上报的链路本地形态带 zone（与 toV6BigInt 同口径）')
  assert.equal(toV4Long('01.002.000.4'), (1 << 24) | (2 << 16) | 4, '前导零按数值收（事件匹配侧不收紧）')
  // 非十进制形态拒绝（Number 的十六进制/指数写法不进事件匹配）
  assert.equal(toV4Long('0x1.2.3.4'), -1)
  assert.equal(toV4Long('1e2.2.3.4'), -1)
  assert.equal(toV4Long('+1.2.3.4'), -1)
  // 单源绑定：toV4Long 必须经宽容单源实现（不得回落 split+Number；单源模块
  // 私有，导出面只有 toV4Long——exportSurface 禁止零外部消费导出）
  const util = code('src/utils/ipAddress.ts')
  assert.match(util, /^const parseIPv4Lenient = /m)
  assert.doesNotMatch(util, /export const parseIPv4Lenient/)
  assert.match(util, /parseIPv4Lenient\(address\)/, 'toV4Long 必须消费宽容单源')
})

test('canonicalV6Text：等价写法归一到同一压缩串，非 IPv6 返回 null', () => {
  const canonical = canonicalV6Text('2001:0db8:0:0:0:0:0:80')
  assert.equal(canonical, '2001:db8::80')
  for (const spelling of ['2001:DB8::80', '2001:db8:0:0:0:0:0:80']) {
    assert.equal(canonicalV6Text(spelling), canonical, `${spelling} 必须与规范形态同串`)
  }
  // 折叠形态与 WHATWG 序列化逐例一致（`::`、单零组不折叠、取最前同长零组）
  assert.equal(canonicalV6Text('::'), '::')
  assert.equal(canonicalV6Text('0:0:0:0:0:0:0:1'), '::1')
  assert.equal(canonicalV6Text('2001:db8::'), '2001:db8::')
  assert.equal(canonicalV6Text('1:2:3:4:5:6:0:8'), '1:2:3:4:5:6:0:8', '单零组不折叠')
  assert.equal(canonicalV6Text('1:0:0:2:0:0:0:3'), '1:0:0:2::3', '取最长零组（并列取最前）')
  assert.equal(canonicalV6Text('::ffff:1.2.3.4'), '::ffff:102:304', '嵌入 IPv4 折算成十六进制组')
  assert.equal(canonicalV6Text('backend.example.com'), null)
  assert.equal(canonicalV6Text('fe80::1%eth0'), null, 'zone 形态不得进入归一键')
})

test('isValidV4 / isValidV6 / isValidCidr：写侧严格口径（拒前导零与 zone）', () => {
  assert.equal(isValidV4('10.0.0.1'), true)
  assert.equal(isValidV4('10.0.0.01'), false, '写侧拒前导零')
  assert.equal(isValidV4('10.0.0'), false)
  assert.equal(isValidV6('2001:db8::1'), true)
  assert.equal(isValidV6('2001:db8::1%eth0'), false, '写侧拒 zone（后端 netip 解析带 zone 的 SNI/网段非法）')
  assert.equal(isValidV6('2001:db8::1 '), false, '判据不做 trim（带空格即非法形态）')
  assert.equal(isValidV6('10.0.0.1'), false)
  assert.equal(isValidCidr(' 203.0.113.0/24 '), true, 'CIDR 判据自带 trim')
  assert.equal(isValidCidr('203.0.113.0/24'), true)
  assert.equal(isValidCidr('203.0.113.0/33'), false)
  assert.equal(isValidCidr('2001:db8::/32'), true)
  assert.equal(isValidCidr('2001:db8::/129'), false)
  assert.equal(isValidCidr('203.0.113.0/24/8'), false)
  assert.equal(isValidCidr(''), false)
})

test('四个消费点都接单源，不得保留平行解析实现', () => {
  for (const path of [
    'src/utils/ruleValidation.ts',
    'src/utils/trustedProxyRanges.ts',
    'src/utils/securityStages.ts',
    'src/utils/upstreamKeys.ts',
  ]) {
    assert.match(code(path), /from '\.\/ipAddress\.ts'/, `${path} 必须从 utils/ipAddress 取解析实现`)
  }
  const forbidden: ReadonlyArray<readonly [string, RegExp]> = [
    ['src/utils/ruleValidation.ts', /const isValidIpv4\s*=/],
    ['src/utils/ruleValidation.ts', /const isValidIpv6\s*=/],
    ['src/utils/ruleValidation.ts', /export const isValidCidr\s*=/],
    ['src/utils/trustedProxyRanges.ts', /const ipv4Octets\s*=/],
    ['src/utils/trustedProxyRanges.ts', /const ipv6Groups\s*=/],
    ['src/utils/securityStages.ts', /const ipv4ToLong\s*=/],
    ['src/utils/securityStages.ts', /const ipv6ToBigInt\s*=/],
    ['src/utils/upstreamKeys.ts', /new URL\(`http:\/\/\[/],
  ]
  for (const [path, pattern] of forbidden) {
    assert.doesNotMatch(code(path), pattern, `${path} 不得保留本地 IP 解析实现`)
  }
  const util = code('src/utils/ipAddress.ts')
  for (const symbol of [
    'parseIPv4Octets',
    'parseIPv6Groups',
    'toV4Long',
    'toV6BigInt',
    'isValidV4',
    'isValidV6',
    'isValidCidr',
  ]) {
    assert.match(util, new RegExp(`export const ${symbol}`), `ipAddress 必须导出 ${symbol}`)
  }
})
