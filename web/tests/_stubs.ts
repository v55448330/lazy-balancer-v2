// showSaveResult 的行为测试：退化 200（DB 已提交、Caddy 应用失败）必须以常驻警告
// 呈现并保留后端文案；普通成功统一走 mfaAwareSuccess。element-plus 与 api.ts
// 都是字节级依赖（CSS 导入/DOM），测试用本文件的替身记录调用。
//
// 另含 data: 模块替身的共享定义：composable 行为用例（useIpListAdd /
// useTrustAssociation / useCountryNamesCn）此前各持一份逐字相同的 stub，
// 替身契约（如 ElMessage.info）改动需要多处同步。宿主只需提供
// globalThis.__calls / __gets / __get / __post / __put / __confirm。

export interface StubCall {
  fn: string
  arg?: unknown
  args?: unknown[]
}

/** 调用记录面（由 data: 模块替身经 `globalThis.__calls` 写入，宿主指向同一数组）。 */
export const calls: StubCall[] = []

export const resetCalls = (): void => {
  calls.length = 0
}

/** data: 模块替身宿主：安装共享调用记录，并提供重置/查询。 */
export const installStubHost = (): {
  calls: StubCall[]
  reset: () => void
  callsOf: (fn: string) => StubCall[]
} => {
  const hostCalls: StubCall[] = []
  const host = globalThis as unknown as { __calls: StubCall[] }
  host.__calls = hostCalls
  return {
    calls: hostCalls,
    reset: () => { hostCalls.length = 0 },
    callsOf: (fn) => hostCalls.filter((call) => call.fn === fn),
  }
}

/** data: 模块源码包装（node 直接求值，不落盘）。 */
export const dataModule = (code: string): string => `data:text/javascript,${encodeURIComponent(code)}`

/** 真实调用面用到的方法集合（两处替身共用；新增方法只改这里）。 */
export const EL_MESSAGE_METHODS = ['info', 'error', 'success', 'warning'] as const

const elMessageMethodsSource = (): string =>
  EL_MESSAGE_METHODS.map((method) => `    ${method}: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.${method}', arg }),`).join('\n')

/**
 * saveResult 的两个依赖替身（element-plus 的 ElMessage + api 的 mfaAwareSuccess）。
 * 必须与真实调用面同形：ElMessage 是「可调用对象」，方法集由 EL_MESSAGE_METHODS
 * 单源生成（与 STUB_ELEMENT 逐字同源，改一处不会分叉）。
 */
export const STUB_SAVE_RESULT_DEPS = dataModule(`
export const ElMessage = Object.assign(
  (arg) => globalThis.__calls?.push({ fn: 'ElMessage', arg }),
  {
${elMessageMethodsSource()}
  },
)
export const mfaAwareSuccess = (message) => globalThis.__calls?.push({ fn: 'mfaAwareSuccess', arg: message })
`)

/** element-plus 替身：ElMessage 全方法集与 MessageBox.confirm/alert 均记录调用。 */
export const STUB_ELEMENT = dataModule(`
export const ElMessage = Object.assign(
  (arg) => globalThis.__calls?.push({ fn: 'ElMessage', arg }),
  {
${elMessageMethodsSource()}
  },
)
export const ElMessageBox = {
  confirm: (...args) => globalThis.__confirm(...args),
  alert: (...args) => globalThis.__calls?.push({ fn: 'ElMessageBox.alert', args }),
}
`)

/** api 替身：get 额外记录到 __gets（宿主提供时），请求全部委托宿主注入的函数。 */
export const STUB_API = dataModule(`
export class ApiRequestError extends Error {
  constructor(message, status) { super(message); this.status = status }
}
globalThis.__makeApiError = (message, status) => new ApiRequestError(message, status)
export const request = {
  get: (url, config) => { globalThis.__gets?.push({ url, config }); return globalThis.__get(url, config) },
  post: (...args) => globalThis.__post(...args),
  put: (...args) => globalThis.__put(...args),
}
export const mfaAwareSuccess = (message) => globalThis.__calls?.push({ fn: 'mfaAwareSuccess', arg: message })
`)

/** saveResult 替身：记录 showSaveResult 的完整入参。 */
export const STUB_SAVE_RESULT = dataModule(`
export const showSaveResult = (...args) => globalThis.__calls?.push({ fn: 'showSaveResult', args })
`)
