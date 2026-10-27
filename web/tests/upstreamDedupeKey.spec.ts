// 上游判重键单源（与后端 internal/handlers/handlers.go upstreamDedupeHost 同口径）：
// 同一个后端的等价写法必须在表单/流程两处都被识别为重复，否则权重翻倍、健康检查
// 对同一地址跑两遍。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { hostPortKey, upstreamDedupeKey, upstreamHostKey } from '../src/utils/upstreamKeys.ts'
import { repoCode } from './_helpers.ts'

test('upstreamHostKey：IPv6 等价写法归一到同一键', () => {
  const canonical = upstreamHostKey('2001:db8::80')
  for (const spelling of ['2001:0db8:0:0:0:0:0:80', '2001:DB8::80', '[2001:db8::80]']) {
    assert.equal(upstreamHostKey(spelling), canonical, `${spelling} 必须与 2001:db8::80 同键`)
  }
  assert.equal(canonical, '2001:db8::80')
})

test('upstreamHostKey：主机名去空白+小写，非 IP 形态保持文本归一', () => {
  assert.equal(upstreamHostKey(' Backend.EXAMPLE.com '), 'backend.example.com')
  assert.equal(upstreamHostKey('my_backend'), 'my_backend')
  // 不同地址不得归并
  assert.notEqual(upstreamHostKey('2001:db8::1'), upstreamHostKey('2001:db8::2'))
  assert.notEqual(upstreamHostKey('10.0.0.1'), upstreamHostKey('10.0.0.2'))
})

test('upstreamDedupeKey：归一主机 + 端口（IPv6 带方括号，与展示键同形）', () => {
  assert.equal(upstreamDedupeKey('2001:0db8:0:0:0:0:0:1', 8080), '[2001:db8::1]:8080')
  assert.equal(upstreamDedupeKey('2001:db8::1', 8080), '[2001:db8::1]:8080')
  assert.equal(upstreamDedupeKey('Backend.example.com', 8080), 'backend.example.com:8080')
  assert.notEqual(upstreamDedupeKey('10.0.0.1', 8080), upstreamDedupeKey('10.0.0.1', 8081))
})

test('hostPortKey 语义不变（健康详情查询键），判重另走 upstreamDedupeKey', () => {
  assert.equal(hostPortKey('::1', 80), '[::1]:80')
  assert.equal(hostPortKey('Example.com', 80), 'Example.com:80')
})

test('两处判重都消费单源（表单与流程弹框不得各自拼键）', () => {
  const rules = repoCode('web/src/views/Rules.vue')
  assert.match(rules, /const key = upstreamDedupeKey\(upstream\.host, upstream\.port\)/, '表单判重必须走 upstreamDedupeKey')
  assert.doesNotMatch(rules, /const key = `\$\{upstream\.host\}:\$\{upstream\.port\}`/, '不得回到裸拼键')
  const validation = repoCode('web/src/utils/ruleValidation.ts')
  assert.match(validation, /upstreamDedupeKey\(address, upstream\.port\)/, '流程弹框判重必须走同一键函数')
  const backend = repoCode('internal/handlers/handlers.go')
  assert.match(backend, /net\.JoinHostPort\(upstreamDedupeHost\(u\.Host\), strconv\.Itoa\(u\.Port\)\)/, '后端判重必须走地址语义归一键')
  const features = repoCode('internal/handlers/rule_features.go')
  assert.match(features, /net\.JoinHostPort\(upstreamDedupeHost\(upstream\.Address\), strconv\.Itoa\(upstream\.Port\)\)/, '路径规则判重必须与主池同口径')
})
