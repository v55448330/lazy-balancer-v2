// 规则日志统计的键上限容器：上限判定必须是 O(1)（原实现每次遇到新键都用
// Object.keys(map).length 数整表），满表后计数回落「其他」而非丢弃。
//
// 判定方式为行为求值：直接调用 utils/logStatCap 的纯函数构造满表/敌意键形态，
// 不断言「函数文本里出现某常量」——等价重构（Map/动态桶）不应变红。
//
// 例外：容器必须是**无原型普通对象**。这不是实现细节而是安全不变量——键来自
// 攻击者可控的 IP/UA/URI，原型链上的 `__proto__`/`constructor` 会侵蚀计数或
// 污染全局原型。因此保留 `Object.getPrototypeOf(buckets.x) === null` 断言；
// 若未来换 Map，应同步改写为「敌意键作为普通键计数」的行为断言，而不是放宽本用例。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  MAX_LOG_STAT_KEYS,
  OTHER_LOG_STAT_KEY,
  createLogStatBuckets,
  incrementCappedStat,
  recordLogStatEntry,
} from '../src/utils/logStatCap.ts'
import { code } from './_helpers.ts'

const keyOf = (i: number): string => `10.0.${Math.floor(i / 256)}.${i % 256}`

const bucketSum = (map: Record<string, number>): number =>
  Object.values(map).reduce((sum, count) => sum + count, 0)

test('容量内：新键落库并计数，既有键只自增不重复计数', () => {
  const buckets = createLogStatBuckets()
  incrementCappedStat(buckets, 'ip', '1.1.1.1')
  incrementCappedStat(buckets, 'ip', '1.1.1.1')
  assert.equal(buckets.ip['1.1.1.1'], 2)
  assert.equal(buckets.keyCounts.ip, 1, '既有键不得重复占用容量')
  incrementCappedStat(buckets, 'ip', '2.2.2.2')
  assert.equal(buckets.keyCounts.ip, 2)
  // 三个桶容量独立
  assert.equal(buckets.keyCounts.ua, 0)
  assert.equal(buckets.keyCounts.uri, 0)
  incrementCappedStat(buckets, 'ua', 'Chrome 120')
  assert.deepEqual([buckets.keyCounts.ip, buckets.keyCounts.ua], [2, 1])
})

test('满表回落「其他」：键集合不再增长，计数不丢弃', () => {
  const buckets = createLogStatBuckets()
  const distinct = MAX_LOG_STAT_KEYS - 1
  for (let i = 0; i < distinct; i++) incrementCappedStat(buckets, 'ip', keyOf(i))
  assert.equal(Object.keys(buckets.ip).length, distinct)
  assert.equal(buckets.keyCounts.ip, distinct)

  // 满表后的新键全部归入「其他」，且键集合保持在 MAX 个（自有键 + 其他）
  incrementCappedStat(buckets, 'ip', '203.0.113.9')
  incrementCappedStat(buckets, 'ip', '203.0.113.10')
  assert.equal(buckets.ip[OTHER_LOG_STAT_KEY], 2)
  assert.equal(Object.keys(buckets.ip).length, MAX_LOG_STAT_KEYS)
  assert.equal(buckets.keyCounts.ip, distinct, '回落不得继续占用容量')
  assert.equal(buckets.ip['203.0.113.9'], undefined, '满表后的新键不再单独落库')

  // 已落库键在满表后仍精确自增（不被并入其他）
  incrementCappedStat(buckets, 'ip', keyOf(0))
  assert.equal(buckets.ip[keyOf(0)], 2)
  assert.equal(buckets.ip[OTHER_LOG_STAT_KEY], 2)

  // 「其他」自身是普通键：再次出现只自增，不得被当成新键
  incrementCappedStat(buckets, 'ip', OTHER_LOG_STAT_KEY)
  assert.equal(buckets.ip[OTHER_LOG_STAT_KEY], 3)
})

test('原型链敌意键不得侵蚀计数（容器原型安全）', () => {
  const buckets = createLogStatBuckets()
  for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
    incrementCappedStat(buckets, 'uri', key)
  }
  assert.equal(buckets.keyCounts.uri, 4, '敌意键必须作为普通自有键占用容量')
  for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
    assert.equal((buckets.uri as Record<string, number>)[key], 1)
    incrementCappedStat(buckets, 'uri', key)
    assert.equal((buckets.uri as Record<string, number>)[key], 2)
  }
  assert.equal(Object.getPrototypeOf(buckets.uri), null, '统计桶必须无原型')
  assert.equal(Object.keys(buckets.uri).length, 4)
})

test('摄入单点：total 与三桶计数一致（含满表回落「其他」形态）', () => {
  const buckets = createLogStatBuckets()
  // 混合形态：新键 / 重复键 / 满表回落，各桶独立推进
  recordLogStatEntry(buckets, { ip: '1.1.1.1', uri: '/a', ua: 'Chrome 120' })
  recordLogStatEntry(buckets, { ip: '1.1.1.1', uri: '/a?x=1', ua: 'Chrome 120' })
  recordLogStatEntry(buckets, { ip: '2.2.2.2', uri: '/b', ua: 'curl/8.0' })
  assert.equal(buckets.total, 3)
  assert.equal(bucketSum(buckets.ip), 3)
  assert.equal(bucketSum(buckets.uri), 3)
  assert.equal(bucketSum(buckets.ua), 3)

  // 满表回落「其他」后 total 仍与各桶计数之和一致（回落也是计数，不是丢弃）
  const distinct = MAX_LOG_STAT_KEYS - 1
  for (let i = 0; i < distinct; i++) {
    recordLogStatEntry(buckets, { ip: keyOf(i), uri: `/p${i}`, ua: `UA-${i}` })
  }
  recordLogStatEntry(buckets, { ip: '203.0.113.9', uri: '/overflow', ua: 'UA-overflow' })
  assert.equal(buckets.total, 3 + distinct + 1)
  assert.equal(bucketSum(buckets.ip), buckets.total)
  assert.equal(bucketSum(buckets.uri), buckets.total)
  assert.equal(bucketSum(buckets.ua), buckets.total)
})

test('规则日志视图消费单源容器（不得回流本地实现）', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /from '@\/utils\/logStatCap'/)
  assert.doesNotMatch(rules, /const incrementCappedStat = /, '本地实现必须退役')
  assert.doesNotMatch(rules, /keyCounts: \{ ip: 0, ua: 0, uri: 0 \}/, '本地桶构造必须退役')
})
