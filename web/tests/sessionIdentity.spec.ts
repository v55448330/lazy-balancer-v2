import { test } from 'node:test'
import assert from 'node:assert/strict'

import { advanceSessionGeneration, currentSessionGeneration, isSameTokenIdentity } from '../src/utils/sessionIdentity.ts'

const tokenFor = (userId: number, marker: string): string => {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({ user_id: userId, marker })}.signature`
}

test('会话代际只在显式推进时单调 +1，不因测试顺序改初值', () => {
  const before = currentSessionGeneration()
  assert.equal(currentSessionGeneration(), before)
  advanceSessionGeneration()
  assert.equal(currentSessionGeneration(), before + 1)
  advanceSessionGeneration()
  assert.equal(currentSessionGeneration(), before + 2)
})

test('同一用户的 MFA 新令牌保持身份，不同用户或不可解析令牌不视为同身份', () => {
  assert.equal(isSameTokenIdentity(tokenFor(7, 'before'), tokenFor(7, 'after')), true)
  assert.equal(isSameTokenIdentity('bad.payload.shape', 'bad.payload.shape'), false)
  assert.equal(isSameTokenIdentity(tokenFor(7, 'before'), tokenFor(8, 'after')), false)
  assert.equal(isSameTokenIdentity('opaque-a', 'opaque-b'), false)
  assert.equal(isSameTokenIdentity(null, tokenFor(7, 'after')), false)
})
