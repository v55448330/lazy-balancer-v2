// 日志尾部轮询 composable 行为验收（收敛 Rules/CertJobs/TaskMonitor/
// BasicSettings/CaddyGlobalSettings 五份同构实现）：写回+滚底、null 跳过、
// 会话序号作废、单飞 loading 门、错误分流、后台标签页暂停、定时器生命周期。
//
// 运行：cd web && npm test

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { ref } from 'vue'

import { useLogTailPolling } from '../src/composables/useLogTailPolling.ts'

test('refresh 写回内容并滚到底部', async () => {
  const content = ref('')
  const el = { scrollTop: 0, scrollHeight: 999 }
  const container = ref<typeof el | null>(el)
  const tail = useLogTailPolling({
    interval: 60_000,
    content,
    container,
    isActive: () => true,
    fetch: async () => 'line1\nline2',
  })
  await tail.refresh()
  assert.equal(content.value, 'line1\nline2')
  assert.equal(el.scrollTop, 999, '写回后必须滚底')
  tail.stop()
})

test('fetch 返回 null 时不写回（调用方守卫未过/迟到响应）', async () => {
  const content = ref('keep')
  const tail = useLogTailPolling({
    interval: 60_000,
    content,
    isActive: () => true,
    fetch: async () => null,
  })
  await tail.refresh()
  assert.equal(content.value, 'keep')
  tail.stop()
})

test('stop/invalidate 使在途响应作废', async () => {
  for (const cut of ['stop', 'invalidate'] as const) {
    const content = ref('')
    const gate = Promise.withResolvers<string>()
    const tail = useLogTailPolling({
      interval: 60_000,
      content,
      isActive: () => true,
      fetch: () => gate.promise,
    })
    const pending = tail.refresh()
    if (cut === 'stop') tail.stop()
    else tail.invalidate()
    gate.resolve('stale')
    await pending
    assert.equal(content.value, '', `${cut} 后迟到响应不得写回`)
    tail.stop()
  }
})

test('loading 单飞：在途期间重复 refresh 被跳过', async () => {
  let calls = 0
  const gate = Promise.withResolvers<string>()
  const tail = useLogTailPolling({
    interval: 60_000,
    content: ref(''),
    isActive: () => true,
    fetch: () => { calls++; return gate.promise },
  })
  const first = tail.refresh()
  await tail.refresh()
  gate.resolve('x')
  await first
  assert.equal(calls, 1, '在途期间的 refresh 必须被单飞门跳过')
  tail.stop()
})

test('取数失败走 onError 且不写回', async () => {
  const content = ref('keep')
  const errors: unknown[] = []
  const tail = useLogTailPolling({
    interval: 60_000,
    content,
    isActive: () => true,
    fetch: async () => { throw new Error('boom') },
    onError: (e) => { errors.push(e) },
  })
  await tail.refresh()
  assert.equal(errors.length, 1)
  assert.equal(content.value, 'keep')
  tail.stop()
})

test('isActive 为 false 时整轮跳过（不发请求）', async () => {
  let calls = 0
  const tail = useLogTailPolling({
    interval: 60_000,
    content: ref(''),
    isActive: () => false,
    fetch: async () => { calls++; return 'x' },
  })
  await tail.refresh()
  assert.equal(calls, 0)
  tail.stop()
})

test('后台标签页暂停：hidden 时轮次跳过，恢复可见后 refresh 恢复取数', async () => {
  let calls = 0
  const tail = useLogTailPolling({
    interval: 60_000,
    content: ref(''),
    isActive: () => true,
    fetch: async () => { calls++; return 'x' },
  })
  const g = globalThis as { document?: { hidden: boolean } }
  // 假 document 必须「保存→还原并断言」：当前按文件进程隔离，宿主机本就没有
  // document，`delete` 今天无影响；一旦同进程运行（或 helper 装了全局 DOM 宿主），
  // 直接 delete 会抹掉别人的宿主，制造随机顺序才失败的难查问题。
  const previousDocument = g.document
  g.document = { hidden: true }
  try {
    await tail.refresh()
    assert.equal(calls, 0, 'hidden 时不得发请求')
  } finally {
    if (previousDocument === undefined) Reflect.deleteProperty(g, 'document')
    else g.document = previousDocument
    assert.equal(g.document, previousDocument, '假 document 必须还原为原值')
  }
  await tail.refresh()
  assert.equal(calls, 1, '恢复可见后立即补拉')
  tail.stop()
})

test('start 装定时器并立即刷新；stop 冻结后续轮次', async () => {
  // 原实现用真实时钟 sleep(75)/sleep(60) 断言 20ms 定时器——
  // 慢机/CI 负载下可假红。改为 node:test mock timers（只替换 setInterval，
  // setTimeout 仍真实，用于等待异步 refresh 落地），时间推进即断言。
  let calls = 0
  const tail = useLogTailPolling({
    interval: 20,
    content: ref(''),
    isActive: () => true,
    fetch: async () => { calls++; return 'x' },
  })
  const flush = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 0))
  mock.timers.enable({ apis: ['setInterval'] })
  try {
    tail.start()
    await flush()
    assert.equal(calls, 1, 'start 应立即首拉')
    mock.timers.tick(20)
    await flush()
    assert.equal(calls, 2, '按 interval 轮询')
    mock.timers.tick(20)
    await flush()
    assert.equal(calls, 3)
    tail.stop()
    const frozen = calls
    mock.timers.tick(200)
    await flush()
    assert.equal(calls, frozen, 'stop 后不得再有轮次')
  } finally {
    mock.timers.reset()
    tail.stop()
  }
})
