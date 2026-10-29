// 轮询契约（usePollingTask 文件头承诺：「每轮独立 AbortController，pause/stop 可
// 取消真实请求」）——轮次 context.signal 与页级永久 signal 必须分离：pause 只中止
// 在途轮次，resume 后的新轮次拿未中止的 signal。另钉四处轮询页的接线：取数函数
// 必须接收本轮 signal（传永久 signal 会让 pause 取消不了真实请求，见 Dashboard/
// ClusterSettings/CertJobs/Rules 的原实现）。
//
// 运行：cd web && npm test

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import { usePollingTask, type PollingTask } from '../src/composables/usePollingTask.ts'
import { flushMicrotasks, installBrowserHost, mountForLifecycle, waitForMicrotasks, code } from './_helpers.ts'

// onUnmounted 在无组件实例时会打印 Vue 警告——pause 用例在 finally 里恢复
// console.warn；stop/onError/可见性用例经 SSR 渲染提供真实组件实例，不触碰该警告。

test('每轮独立 signal：pause 中止在途轮次并作废序列，resume 立即补跑且不继承取消', async () => {
  const warn = console.warn
  console.warn = () => {}
  try {
    const rounds: Array<{ signal: AbortSignal; isCurrent: () => boolean }> = []
    const releases: Array<() => void> = []
    const polling = usePollingTask((context) => new Promise<void>((resolve) => {
      rounds.push({ signal: context.signal, isCurrent: context.isCurrent })
      releases.push(resolve)
    }))

    const first = polling.run()
    assert.equal(rounds.length, 1, 'run() 立即启动一轮')
    assert.notEqual(rounds[0].signal, polling.signal, '轮次 signal 不得是页级永久 signal')
    assert.equal(rounds[0].isCurrent(), true)
    assert.equal(rounds[0].signal.aborted, false)

    polling.pause()
    assert.equal(rounds[0].signal.aborted, true, 'pause 必须中止在途轮次')
    assert.equal(polling.signal.aborted, false, 'pause 不得中止永久 signal（同页后续轮次继续用）')
    assert.equal(rounds[0].isCurrent(), false, '作废后迟到响应不得写回')

    releases[0]()
    await first

    // resume 自带「恢复即刷新」（与 visibilitychange 恢复路径同口径），不依赖调用方手动 run。
    polling.resume()
    assert.equal(rounds.length, 2, 'resume 必须立即补跑一轮')
    assert.notEqual(rounds[1].signal, rounds[0].signal, '每轮新 controller')
    assert.equal(rounds[1].signal.aborted, false, '新一轮 signal 不继承上一轮的取消')
    releases[1]()
    // resume 的 run() 承诺不外泄——它的收尾是纯微任务链，排空微任务即可，
    // 不得用 setTimeout(0) 猜跳数（真实定时器会把顺序交给事件循环）。
    await flushMicrotasks()

    polling.stop()
    assert.equal(polling.signal.aborted, true, 'stop 终止永久 signal')
    assert.equal(polling.isDisposed(), true)
  } finally {
    console.warn = warn
  }
})

test('usePollingTask.stop 释放：abort 在途、永久终止后续轮次', async () => {
  const gate = Promise.withResolvers<void>()
  let calls = 0
  const seen: { signal?: AbortSignal } = {}
  let polling!: PollingTask
  await renderToString(createSSRApp({
    setup() {
      polling = usePollingTask(async ({ signal }) => {
        calls++
        seen.signal = signal
        await gate.promise
      })
      return () => h('div')
    },
  }))
  const running = polling.run()
  assert.equal(calls, 1, 'run 必须立即执行任务')
  polling.stop()
  assert.equal(polling.isDisposed(), true)
  assert.equal(seen.signal?.aborted, true, 'stop 必须 abort 每轮任务信号')
  gate.resolve()
  await running
  await polling.run()
  assert.equal(calls, 1, 'stop 后 run 不得再执行任务')
})

test('usePollingTask：onError 自身抛错被就地吞掉，不中断后续轮次', async () => {
  const logged: unknown[][] = []
  const originalError = console.error
  console.error = (...args: unknown[]) => { logged.push(args) }
  try {
    let calls = 0
    let polling!: PollingTask
    await renderToString(createSSRApp({
      setup() {
        polling = usePollingTask(
          async () => { calls++; throw new Error('task failed') },
          { onError: () => { throw new Error('callback failed') } },
        )
        return () => h('div')
      },
    }))
    // 回调异常若经 drain→run 的 Promise 拒绝逃逸，这里的 await 会抛错（unhandled rejection 形态）
    await polling.run()
    assert.equal(calls, 1)
    assert.equal(logged.length, 1, 'onError 回调异常必须就地 console.error')
    await polling.run()
    assert.equal(calls, 2, '回调异常不得中断 drain，下一轮照常执行')
    polling.stop()
  } finally {
    console.error = originalError
  }
})

// invalidate 是 usePollingTask 的内部实现（未暴露在 PollingTask 接口上），其可观测
// 契约由 pause()/stop() 用例覆盖（作废序列 + abort 每轮任务信号 + isCurrent 失效）。

test('usePollingTask：document.hidden 停摆定时轮询，恢复可见立即补跑', async () => {
  // 假 document 的安装/还原走 helper 单源（描述符级还原 + 自断言）：
  // 同进程运行时直接 delete 会抹掉别人的宿主，制造随机顺序才失败的难查问题。
  const browser = installBrowserHost({ visibility: true })
  const doc = browser.document
  let calls = 0
  let polling!: PollingTask
  mock.timers.enable({ apis: ['setInterval'] })
  try {
    await renderToString(createSSRApp({
      setup() {
        polling = usePollingTask(async () => { calls++ }, { interval: 50 })
        return () => h('div')
      },
    }))
    polling.start()
    await flushMicrotasks()
    assert.equal(calls, 0, '定时轮询不立即首跑')
    mock.timers.tick(50)
    await waitForMicrotasks(() => calls === 1, '可见时按 interval 轮询')
    doc.hidden = true
    doc.dispatch()
    mock.timers.tick(150)
    await flushMicrotasks()
    assert.equal(calls, 1, 'hidden 后定时轮次必须停摆')
    doc.hidden = false
    doc.dispatch()
    await waitForMicrotasks(() => calls === 2, '恢复可见立即补跑一轮')
    mock.timers.tick(50)
    await waitForMicrotasks(() => calls === 3, '定时器随可见性恢复')
    assert.equal(polling.isDisposed(), false)
    polling.stop()
    assert.equal(doc.listenerCount, 0, 'stop 必须摘除 visibilitychange 监听')
  } finally {
    polling?.stop()
    mock.timers.reset()
    browser.restore()
  }
})

// 卸载清理：页面切换（Dashboard/ClusterSettings/CertJobs/Rules 四个消费页）时必须
// stop——否则定时器继续打后端、visibilitychange 监听残留（重进页面叠加→多倍轮询）。
// SSR 不执行 onUnmounted，必须用真实组件实例 mount 再 unmount。
test('usePollingTask 随组件卸载停止轮询并摘除监听', async () => {
  const browser = installBrowserHost({ visibility: true })
  const doc = browser.document
  let calls = 0
  let polling!: PollingTask
  mock.timers.enable({ apis: ['setInterval'] })
  try {
    const mounted = mountForLifecycle(() => {
      polling = usePollingTask(async () => { calls++ }, { interval: 50 })
      polling.start()
    })
    mock.timers.tick(50)
    await waitForMicrotasks(() => calls === 1, '前置：定时轮询在跑')
    assert.equal(doc.listenerCount, 1, '前置：挂载后有一个 visibilitychange 监听')

    mounted.unmount()
    assert.equal(polling.isDisposed(), true, '卸载必须 stop 轮询（永久终止）')
    assert.equal(doc.listenerCount, 0, '卸载必须摘除 visibilitychange 监听')
    mock.timers.tick(200)
    await flushMicrotasks()
    assert.equal(calls, 1, '卸载后不得再发起轮次')
  } finally {
    mock.timers.reset()
    browser.restore()
  }
})

test('轮询页接线：取数函数接收本轮 signal，永久 signal 只留给跨轮工作', () => {
  const dashboard = code('src/views/Dashboard.vue')
  assert.match(dashboard, /const dashboardPolling = usePollingTask\(async \(task\) => fetchAllData\(task\.signal\)/)
  assert.match(dashboard, /const fetchAllData = \(roundSignal\?: AbortSignal\)/)
  assert.match(dashboard, /const fetchRuleHealth = async \(currentRules: Rule\[\], version: number, roundSignal\?: AbortSignal\)/)
  assert.match(dashboard, /signal: roundSignal \?\? dashboardPolling\.signal/, '轮次取本轮 signal；Caddy 操作后的补偿刷新回落永久 signal')

  const cluster = code('src/views/settings/ClusterSettings.vue')
  assert.match(cluster, /await refreshCluster\(task\.signal\)/)
  assert.match(cluster, /const fetchStatus = async \(roundSignal\?: AbortSignal\)/)
  assert.match(cluster, /const fetchNodes = async \(roundSignal\?: AbortSignal\)/)

  const certJobs = code('src/views/settings/CertJobs.vue')
  assert.match(certJobs, /await fetchJobs\(task\.signal\)/)
  assert.match(certJobs, /const fetchJobs = async \(roundSignal\?: AbortSignal\)/)

  const rules = code('src/views/Rules.vue')
  assert.match(rules, /await fetchHealthStatus\(task\.signal\)/)
  assert.match(rules, /await fetchCertJobs\(task\.signal\)/)
  assert.match(rules, /const fetchHealthStatus = async \(roundSignal\?: AbortSignal\)/)
  assert.match(rules, /const fetchCertJobs = async \(roundSignal\?: AbortSignal\)/)

  // 更新弹框（三库共用）：关闭弹框/终态 stopPolling 时在途状态+日志请求必须可取消
  const libUpdate = code('src/composables/useLibUpdateDialog.ts')
  assert.match(libUpdate, /usePollingTask\(async \(\{ signal \}\) => \{ await refreshStatus\(signal\) \}/,
    '轮询回调必须消费本轮 signal')
  assert.match(libUpdate, /const refreshStatus = async \(signal\?: AbortSignal\)/)
  assert.match(libUpdate, /update\/status`, \{ silent: true, signal \}/)
  assert.match(libUpdate, /update\/logs`, \{ silent: true, signal \}/)
})
