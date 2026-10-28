import { test } from 'node:test'
import assert from 'node:assert/strict'
import { dnsServerAfterToggle } from '../src/utils/ruleWizard.ts'
import { code } from './_helpers.ts'

test('水合 false 配置不得清空已存 dns_server', () => {
  assert.equal(dnsServerAfterToggle('10.0.0.53', false, true), '10.0.0.53')
})

test('用户主动关闭仍清空，启用与水合 true 保留', () => {
  assert.equal(dnsServerAfterToggle('10.0.0.53', false, false), '')
  assert.equal(dnsServerAfterToggle('10.0.0.53', true, false), '10.0.0.53')
  assert.equal(dnsServerAfterToggle('10.0.0.53', true, true), '10.0.0.53')
})

// 纯函数全绿也拦不住「二三参写反」：实参顺序一旦错位，「水合」会被当成
// 「用户主动关闭」，已存 dns_server 被清空（原缺陷直接回归）。故按位置钉接线。
test('接线：向导以 (当前值, 新值, 是否水合) 顺序调用', () => {
  const page = code('src/views/Rules.vue')
  const calls = [...page.matchAll(/dnsServerAfterToggle\(([^)]*)\)/g)]
  assert.equal(calls.length, 1, `消费点应唯一（实际 ${calls.length}）——新增调用点须同步本断言`)
  const args = calls[0]![1]!.split(',').map((arg) => arg.trim())
  assert.deepEqual(
    args,
    ['wizardForm.dns_server', 'newVal', 'hydratingWizard'],
    '实参顺序必须是 (当前值, 新值, 是否水合)',
  )
})
