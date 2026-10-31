// JWT 载荷解码单源验收（decodeJwtPayload）。
//
// 背景：站内三处各自实现 base64url+JSON 解码——oidcCallback（TextDecoder，
// 非 ASCII 正确）、api.isTokenExpired / sessionIdentity.tokenUserId（atob 直出
// Latin-1，非 ASCII 载荷产出 mojibake，解出的身份串不可信）。收敛为单源
// decodeJwtPayload（TextDecoder 版），消费方只保留各自语义谓词
// （isTokenExpired 的 exp 门、tokenUserId 的 user_id 门）。
//
// 运行：cd web && npm test

import { after, test } from 'node:test'
import assert from 'node:assert/strict'

import { decodeJwtPayload } from '../src/utils/jwt.ts'
import { isSameTokenIdentity } from '../src/utils/sessionIdentity.ts'
import { dataModule } from './_stubs.ts'
import { registerModuleHooks } from './_helpers.ts'

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url')
const jwt = (payload: Record<string, unknown>): string =>
  `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.sig`

test('非 ASCII 载荷（中文 username）解码正确（TextDecoder，非 atob mojibake）', () => {
  const payload = decodeJwtPayload(jwt({ user_id: 7, username: '张三' }))
  assert.ok(payload, '载荷必须可解')
  assert.equal(payload.username, '张三')
  assert.equal(payload.user_id, 7)
})

test('形状门：非三段 / 非 JSON / 非对象载荷一律 null', () => {
  assert.equal(decodeJwtPayload(''), null)
  assert.equal(decodeJwtPayload('not-a-jwt'), null)
  assert.equal(decodeJwtPayload('a.b'), null)
  assert.equal(decodeJwtPayload('a.b.c.d'), null)
  const header = b64url({ alg: 'none' })
  assert.equal(decodeJwtPayload(`${header}.${Buffer.from('["arr"]').toString('base64url')}.sig`), null, '数组载荷不是对象')
  assert.equal(decodeJwtPayload(`${header}.${Buffer.from('"str"').toString('base64url')}.sig`), null, '字符串载荷不是对象')
  assert.equal(decodeJwtPayload(`${header}.@@@@.sig`), null, '非 base64/非 JSON 载荷')
})

test('sessionIdentity：身份比对走共享内核，中文 user_id 全等（语义谓词保持）', () => {
  const tokenFor = (userId: unknown): string => jwt({ user_id: userId, marker: 'm' })
  assert.equal(isSameTokenIdentity(tokenFor('张三'), tokenFor('张三')), true, '同中文账号 = 同身份')
  assert.equal(isSameTokenIdentity(tokenFor('张三'), tokenFor('李四')), false, '不同中文账号不是同身份')
  assert.equal(isSameTokenIdentity(tokenFor(7), tokenFor('7')), true, '数字 7 与字符串 "7" 经 String 归一为同身份（原语义）')
  assert.equal(isSameTokenIdentity('bad.payload.shape', 'bad.payload.shape'), false, '不可解析令牌保守按换身份处理')
})

// isTokenExpired 行为验收：api.ts 顶层拉 element-plus（CSS 导入/DOM），
// 按仓内既有模式（authCrossTabSession）用替身钩子加载真实模块。
registerModuleHooks({
  'element-plus': dataModule(`
export const ElMessage = Object.assign(() => {}, { success: () => {}, error: () => {}, info: () => {}, warning: () => {} })
export const ElMessageBox = { confirm: async () => ({}) }
export const ElInputOtp = {}
`),
  'element-plus/es/components/input-otp/style/css': dataModule(''),
})
const { isTokenExpired } = await import('../src/utils/api.ts')
after(() => { /* 钩子进程级注册，随本 spec 进程退出 */ })

test('isTokenExpired：exp 语义谓词保持，非 ASCII 同载荷段解码不回归', () => {
  const nowSec = Math.floor(Date.now() / 1000)
  assert.equal(isTokenExpired(jwt({ exp: nowSec + 600, username: '张三' })), false, '未过期（含中文载荷段）')
  assert.equal(isTokenExpired(jwt({ exp: nowSec - 1, username: '张三' })), true, '已过期')
  assert.equal(isTokenExpired(jwt({})), true, '无 exp = 过期')
  assert.equal(isTokenExpired(jwt({ exp: '1760000000' })), true, 'exp 非数字 = 过期')
  assert.equal(isTokenExpired(jwt({ exp: Number.NaN })), true, 'exp 非有限数 = 过期')
  assert.equal(isTokenExpired('bad.payload.shape'), true, '非三段 = 过期')
  assert.equal(isTokenExpired('null'), true, '字面哨兵 = 过期')
  assert.equal(isTokenExpired(''), true, '空令牌 = 过期')
})
