// 懒加载状态机验收（第 78 轮 U15-F18）：并发单飞、失败可重试、成功永久命中。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createLazyLoader } from '../src/utils/lazyOnce.ts'

test('并发 ensure 只调用一次 loader（单飞）', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => {
    calls++
    const { promise, resolve } = Promise.withResolvers<void>()
    setTimeout(resolve, 5)
    await promise
    return { 中国: '中国' }
  })
  await Promise.all([loader.ensure(), loader.ensure(), loader.ensure()])
  assert.equal(calls, 1)
  assert.equal(loader.isLoaded(), true)
  assert.deepEqual(loader.get(), { 中国: '中国' })
})

test('成功后不再请求（会话级缓存）', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => { calls++; return 'ok' })
  await loader.ensure()
  await loader.ensure()
  assert.equal(calls, 1)
})

test('失败不闩死：下一次 ensure 重试并成功', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => {
    calls++
    if (calls === 1) throw new Error('network')
    return 'recovered'
  })
  await loader.ensure()
  assert.equal(loader.isLoaded(), false)
  assert.equal(loader.get(), null)
  await loader.ensure()
  assert.equal(calls, 2)
  assert.equal(loader.isLoaded(), true)
  assert.equal(loader.get(), 'recovered')
})

test('失败后并发重试同样单飞', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => {
    calls++
    if (calls === 1) throw new Error('first')
    const { promise, resolve } = Promise.withResolvers<void>()
    setTimeout(resolve, 5)
    await promise
    return 'v'
  })
  await loader.ensure()
  await Promise.all([loader.ensure(), loader.ensure()])
  assert.equal(calls, 2)
  assert.equal(loader.get(), 'v')
})

test('reset 丢弃值，下一次 ensure 重新加载', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => { calls++; return calls })
  await loader.ensure()
  loader.reset()
  assert.equal(loader.isLoaded(), false)
  assert.equal(loader.get(), null)
  await loader.ensure()
  assert.equal(calls, 2)
})
