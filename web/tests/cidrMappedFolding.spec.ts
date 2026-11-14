// v4-mapped IPv6 CIDR 折算：事件侧条目匹配与 cidrContains 必须同口径——
// ::ffff:a.b.c.d 双形态（裸 v4 / mapped）命中一致，mapped 前缀折算成等价 v4
// 前缀（/120 ≡ /24），前缀不足 96 不折算；普通 IPv6 与裸 v4 不跨族误命中。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createIpMatcher, entryMatchesIp } from '../src/utils/securityStages.ts'
import { cidrContains } from '../src/utils/ipAddress.ts'
test('v4-mapped CIDR 折算：裸 v4 与 mapped 双形态命中一致', () => {
  const cidr = '::ffff:192.168.0.0/112'
  for (const ip of ['192.168.3.4', '::ffff:192.168.3.4']) {
    assert.equal(entryMatchesIp(cidr, ip), true)
    assert.equal(createIpMatcher(ip)(cidr), true)
    assert.equal(cidrContains(cidr, ip), true)
  }
  for (const ip of ['192.169.3.4', '::ffff:192.169.3.4']) {
    assert.equal(entryMatchesIp(cidr, ip), false)
    assert.equal(createIpMatcher(ip)(cidr), false)
    assert.equal(cidrContains(cidr, ip), false)
  }
})
test('mapped /120 ≡ v4 /24；前缀不足 96 不折算', () => {
  assert.equal(entryMatchesIp('::ffff:203.0.113.0/120', '203.0.113.9'), true)
  assert.equal(entryMatchesIp('::ffff:203.0.113.0/120', '203.0.114.9'), false)
  assert.equal(entryMatchesIp('::ffff:192.168.0.0/95', '192.168.3.4'), false)
})
test('普通 IPv6 与裸 v4 不跨族误命中（回归形状）', () => {
  assert.equal(entryMatchesIp('::/0', '192.168.1.1'), false)
  assert.equal(entryMatchesIp('0.0.0.0/0', '2001:db8::1'), false)
  assert.equal(entryMatchesIp('2001:db8::/32', '2001:db8::1'), true)
})
