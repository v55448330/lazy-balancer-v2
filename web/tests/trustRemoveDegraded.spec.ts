// 移除路径的退化 200 披露：removed=true 但带退化键（en 文案无 zh 标记）时
// 必须经 showSaveResult 呈现常驻警告而非直接成功；普通成功同样经
// showSaveResult（内部 mfaAwareSuccess 单源，宽限窗前缀不丢）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { registerModuleHooks } from './_helpers.ts'
import { installStubHost, STUB_API, STUB_ELEMENT, STUB_SAVE_RESULT } from './_stubs.ts'
type Harness = { __confirm: (...a: unknown[]) => Promise<unknown>; __post: (u: string, b?: unknown) => Promise<unknown>; __get: (u: string, c?: unknown) => Promise<unknown>; __put: (u: string, b?: unknown) => Promise<unknown> }
const g = globalThis as unknown as Harness
const stubHost = installStubHost()
registerModuleHooks({ 'element-plus': STUB_ELEMENT, '@/utils/api': STUB_API, '@/utils/saveResult': STUB_SAVE_RESULT })
// 模块钩子须先于被测模块加载；静态 import 会在替身安装前执行依赖。
const { useTrustAssociation } = await import('../src/composables/useTrustAssociation.ts')
test('移除退化 200（en）：经 showSaveResult 披露，不得直接成功', async () => {
  stubHost.reset()
  g.__confirm = async () => {}
  g.__post = async () => ({ message: 'Removed; but Caddy config apply failed: timeout', messageKey: 'security.savedButCaddyApplyFailed', data: { removed: true } })
  g.__get = async () => ({ data: {} }); g.__put = async () => ({ data: undefined })
  const { removeFromSideRef } = useTrustAssociation({ getList: () => [] })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  const saves = stubHost.callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  const res = saves[0].args?.[0]
  assert.ok(res && typeof res === 'object' && 'messageKey' in res, '首参必须是带 messageKey 的响应对象')
  assert.equal(res.messageKey, 'security.savedButCaddyApplyFailed')
  assert.equal(stubHost.callsOf('mfaAwareSuccess').length, 0)
})
test('移除普通成功：仍经 showSaveResult（内部 mfaAwareSuccess 单源）', async () => {
  stubHost.reset()
  g.__confirm = async () => {}
  g.__post = async () => ({ data: { removed: true } })
  g.__get = async () => ({ data: {} }); g.__put = async () => ({ data: undefined })
  const { removeFromSideRef } = useTrustAssociation({ getList: () => [] })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  const saves = stubHost.callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  const res = saves[0].args?.[0]
  assert.ok(res && typeof res === 'object', '首参必须是响应对象')
  assert.equal('messageKey' in res ? res.messageKey : undefined, undefined)
  assert.match(String(saves[0].args?.[1]), /已从「办公网段」移除/)
})
