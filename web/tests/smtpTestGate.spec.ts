import test from 'node:test'
import assert from 'node:assert/strict'
import { createSmtpTestGate, smtpPortError } from '../src/utils/smtpTestGate.ts'
import type { SmtpDeliveryConfig } from '../src/utils/smtpTestGate.ts'

const base: SmtpDeliveryConfig = {
  smtpHost: 'smtp.example.com',
  smtpPort: 465,
  smtpUser: 'ops',
  smtpPass: '',
  smtpFrom: 'lb@example.com',
  smtpTls: true,
  smtpInsecure: false,
}

test('测试在途时改了投递相关字段，旧结果不得放行保存', () => {
  const gate = createSmtpTestGate()
  gate.begin(base)
  assert.equal(gate.appliesTo(base), true)
  assert.equal(gate.appliesTo({ ...base, smtpHost: 'smtp2.example.com' }), false)
  assert.equal(gate.appliesTo({ ...base, smtpPass: 'new-secret' }), false)
  assert.equal(gate.appliesTo({ ...base, smtpPort: 587 }), false)
  assert.equal(gate.appliesTo({ ...base, smtpUser: 'ops2' }), false)
  assert.equal(gate.appliesTo({ ...base, smtpFrom: 'alert@example.com' }), false)
  assert.equal(gate.appliesTo({ ...base, smtpTls: false }), false)
  assert.equal(gate.appliesTo({ ...base, smtpInsecure: true }), false)
})

test('等价写法（host 首尾空白、字符串端口）视为同一配置', () => {
  const gate = createSmtpTestGate()
  gate.begin(base)
  assert.equal(gate.appliesTo({ ...base, smtpHost: '  smtp.example.com ' }), true)
  assert.equal(gate.appliesTo({ ...base, smtpPort: '465' as unknown as number }), true)
})

test('只认最近一次开始的测试', () => {
  const gate = createSmtpTestGate()
  assert.equal(gate.appliesTo(base), false) // 尚无在途/已完成的测试
  gate.begin(base)
  gate.begin({ ...base, smtpPort: 587 })
  assert.equal(gate.appliesTo(base), false)
  assert.equal(gate.appliesTo({ ...base, smtpPort: 587 }), true)
})

test('端口校验：未配置(0)与合法端口无错误，空值/越界/小数/非数值给出错误文案', () => {
  const invalid = '端口必须是 1-65535 的整数'
  assert.equal(smtpPortError(0, invalid), '')
  assert.equal(smtpPortError(1, invalid), '')
  assert.equal(smtpPortError(65535, invalid), '')
  assert.equal(smtpPortError(null, invalid), invalid)
  assert.equal(smtpPortError(undefined, invalid), invalid)
  assert.equal(smtpPortError(65536, invalid), invalid)
  assert.equal(smtpPortError(-1, invalid), invalid)
  assert.equal(smtpPortError(25.5, invalid), invalid)
  assert.equal(smtpPortError('abc', invalid), invalid)
  assert.equal(smtpPortError('465', invalid), '')
})
