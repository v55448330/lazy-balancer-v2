// 规则库更新弹框（useLibUpdateDialog，CRS / IP 库 / 威胁库 / 爬虫库共用）
// 的会话生命周期行为验收：
//
// 「立即更新」的触发请求最长可吃到全局超时。原实现只在 finally 复位 starting，
// 于是「请求在途时关掉弹框再打开」会继承上一次的 loading（按钮点不动），
// 而那次迟到响应还会把上一次触发的进度当成本次结果驱动 refreshStatus/轮询。
// 契约：starting 随弹框会话复位，跨会话的迟到响应既不写状态也不驱动轮询，
// 也不得复位新会话的 starting。
//
// api.ts / element-plus 用 data: 模块替身（钩子须先注册）。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ref } from 'vue'

import { FakeDocument, registerModuleHooks } from './_helpers.ts'
import { calls, resetCalls } from './_stubs.ts'

type Harness = {
  __gets: Array<{ url: string }>
  __get: (url: string) => Promise<unknown>
  __post: (url: string) => Promise<unknown>
  __puts?: unknown
}
// 替身记录面：data: 模块经 globalThis.__calls 写调用记录，宿主必须指向共享数组
//（否则 ElMessage 断言恒读到空列表）。
;(globalThis as unknown as { __calls: typeof calls }).__calls = calls
const g = globalThis as unknown as Harness
g.__gets = []
g.__get = async () => ({ data: { running: false } })
g.__post = async () => ({ data: { status: 'started', trigger: 'manual' } })

registerModuleHooks({
  '@/utils/api': `data:text/javascript,${encodeURIComponent(`
export class ApiRequestError extends Error {
  constructor(message, status) { super(message); this.status = status }
}
globalThis.__makeApiError = (message, status) => new ApiRequestError(message, status)
export const request = {
  get: (url) => { globalThis.__gets.push({ url }); return globalThis.__get(url) },
  post: (url) => globalThis.__post(url),
  put: (url) => globalThis.__put(url),
}
export const mfaAwareSuccess = (message) => globalThis.__calls?.push({ fn: 'mfaAwareSuccess', arg: message })
`)}`,
  'element-plus': `data:text/javascript,${encodeURIComponent(`
export const ElMessage = Object.assign(
  (arg) => globalThis.__calls?.push({ fn: 'ElMessage', arg }),
  {
    info: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.info', arg }),
    error: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.error', arg }),
    success: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.success', arg }),
  },
)
`)}`,
})

// 动态 import：被测组合子的依赖（api.ts / element-plus）已被上面的 data: 替身
// 顶替，钩子必须先注册再加载模块图——静态 import 会先求值真实依赖（element-plus
// 带 CSS，node 直跑失败）。这是本仓 composable 行为用例的统一形态。
const { useLibUpdateDialog } = await import('../src/composables/useLibUpdateDialog.ts')

interface Info { running: boolean; status?: string }

const deferred = (): { promise: Promise<unknown>; resolve: (value: unknown) => void } => {
  const { promise, resolve } = Promise.withResolvers<unknown>()
  return { promise, resolve }
}
const flush = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 0))

/** 每个用例都一样的三库形状替身：running 为真视为进行中，终态以 status 判定。 */
const makeDialog = () => useLibUpdateDialog<Info>({
  apiPrefix: '/security/crs',
  logContainer: ref(null),
  isRunning: (info) => info?.running ?? false,
  isFinished: (info) => info.running === false && typeof info.status === 'string',
  isSuccess: (info) => info.status === 'ok',
})

const statusCalls = (): number => g.__gets.filter((item) => item.url.endsWith('/update/status')).length

test('关闭后重开：starting 随会话复位，按钮不再卡在 loading', async () => {
  const host = globalThis as { document?: unknown }
  host.document = new FakeDocument()
  const pending = deferred()
  g.__post = () => pending.promise
  g.__get = async () => ({ data: { running: true } })
  const dialog = makeDialog()
  try {
    dialog.open()
    void dialog.confirmUpdate()
    assert.equal(dialog.starting.value, true, '前置：触发请求在途')

    dialog.close()
    dialog.onClosed()
    assert.equal(dialog.starting.value, false, '关闭弹框即释放触发占位')
    dialog.open()
    assert.equal(dialog.starting.value, false, '重开不得继承上一次的 loading')

    pending.resolve({ data: { status: 'started' } })
    await flush()
    assert.equal(dialog.starting.value, false)
  } finally {
    dialog.dispose()
    delete host.document
    g.__post = async () => ({ data: { status: 'started', trigger: 'manual' } })
  }
})

test('跨会话迟到响应不得驱动新会话的 refreshStatus', async () => {
  const host = globalThis as { document?: unknown }
  host.document = new FakeDocument()
  const pending = deferred()
  g.__post = () => pending.promise
  g.__get = async () => ({ data: { running: true } })
  g.__gets = []
  const dialog = makeDialog()
  try {
    dialog.open()
    void dialog.confirmUpdate()
    dialog.close()
    dialog.onClosed()
    dialog.open() // 新会话：尚未触发任何更新
    const before = statusCalls()
    assert.equal(before, 0, '前置：新会话未发过状态请求')

    pending.resolve({ data: { status: 'started' } })
    await flush()
    assert.equal(statusCalls(), 0, '上一次触发的迟到响应不得在新会话里取状态')
  } finally {
    dialog.dispose()
    delete host.document
    g.__post = async () => ({ data: { status: 'started', trigger: 'manual' } })
  }
})

test('跨会话迟到响应不得复位新会话的 starting（新触发仍保持 loading）', async () => {
  const host = globalThis as { document?: unknown }
  host.document = new FakeDocument()
  const first = deferred()
  const second = deferred()
  let post = 0
  g.__post = () => { post += 1; return post === 1 ? first.promise : second.promise }
  g.__get = async () => ({ data: { running: true } })
  const dialog = makeDialog()
  try {
    dialog.open()
    void dialog.confirmUpdate()
    dialog.close()
    dialog.onClosed()
    dialog.open()
    void dialog.confirmUpdate() // 新会话的触发（在途）
    assert.equal(dialog.starting.value, true)

    first.resolve({ data: { status: 'started' } }) // 旧会话的响应迟到
    await flush()
    assert.equal(dialog.starting.value, true, '旧响应收尾不得清掉新会话的 starting')

    second.resolve({ data: { status: 'started' } })
    await flush()
    assert.equal(dialog.starting.value, false, '新会话自己的响应当正常释放占位')
  } finally {
    dialog.dispose()
    delete host.document
    g.__post = async () => ({ data: { status: 'started', trigger: 'manual' } })
  }
})

test('同会话正常路径不变：409 吞并后仍刷新一次状态，非 409 失败复位且不取状态', async () => {
  const host = globalThis as { document?: unknown }
  host.document = new FakeDocument()
  const dialog = makeDialog()
  const makeApiError = (globalThis as unknown as { __makeApiError: (message: string, status: number) => Error }).__makeApiError
  try {
    // 409 = 已有任务在跑：不报错，直接刷新一次状态（running=false 避免起轮询定时器）
    g.__post = async () => { throw makeApiError('已在运行', 409) }
    g.__get = async () => ({ data: { running: false } })
    g.__gets = []
    resetCalls()
    dialog.open()
    await dialog.confirmUpdate()
    assert.equal(dialog.starting.value, false)
    assert.equal(calls.filter((call) => call.fn === 'ElMessage.error').length, 0, '409 不是错误（吞并后走状态刷新）')
    assert.ok(statusCalls() >= 1, '409 路径仍刷新一次状态')

    // 非 409 失败：报错、不取状态、复位占位
    g.__post = async () => { throw new Error('触发更新失败') }
    g.__gets = []
    resetCalls()
    dialog.open()
    await dialog.confirmUpdate()
    assert.equal(dialog.starting.value, false)
    assert.equal(calls.filter((call) => call.fn === 'ElMessage.error').length, 1, '非 409 失败必须报错')
    assert.equal(g.__gets.length, 0, '触发未生效时不得把既有任务进度当结果轮询')
  } finally {
    dialog.dispose()
    delete host.document
    g.__post = async () => ({ data: { status: 'started', trigger: 'manual' } })
  }
})

test('dispose 同样复位 starting（组件卸载后不留 loading 残影）', async () => {
  const host = globalThis as { document?: unknown }
  host.document = new FakeDocument()
  const pending = deferred()
  g.__post = () => pending.promise
  const dialog = makeDialog()
  try {
    dialog.open()
    void dialog.confirmUpdate()
    assert.equal(dialog.starting.value, true)
    dialog.dispose()
    assert.equal(dialog.starting.value, false)
    pending.resolve({ data: { status: 'started' } })
    await flush()
  } finally {
    delete host.document
    g.__post = async () => ({ data: { status: 'started', trigger: 'manual' } })
  }
})
