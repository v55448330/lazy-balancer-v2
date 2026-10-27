// 跨标签页会话同步的行为验收：令牌在另一个标签页被登出/改写时，本标签页的
// store 必须跟随——否则内存里的旧 JWT 让界面继续以「已登录」渲染，而请求层
// 只读 localStorage（已无令牌），每次操作静默 401：既不弹错误也回不到登录页。
//
// auth.ts 模块顶层读 location/localStorage，且依赖 pinia 与 element-plus 的
// 字节级链；本 spec 造最小浏览器宿主 + 替身后直测真实 store（不复刻逻辑）。
//
// 运行：cd web && node --test tests/authCrossTabSession.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPinia, setActivePinia } from 'pinia'

import { registerModuleHooks } from './_helpers.ts'
import { dataModule } from './_stubs.ts'

// ── 最小浏览器宿主（只提供 auth store 的消费面） ──
const storage = new Map<string, string>()
const storageListeners: Array<(event: unknown) => void> = []
const timers = new Map<number, () => void>()
let nextTimerId = 1

const locationStub = { search: '', hash: '#/dashboard', href: 'http://panel.test/', pathname: '/' }

const windowStub = {
  location: locationStub,
  history: { replaceState: (): void => {} },
  addEventListener: (type: string, listener: (event: unknown) => void): void => {
    if (type === 'storage') storageListeners.push(listener)
  },
  setTimeout: (callback: () => void): number => {
    const id = nextTimerId++
    timers.set(id, callback)
    return id
  },
  clearTimeout: (id: number): void => {
    timers.delete(id)
  },
}

const host = globalThis as unknown as Record<string, unknown>
host.window = windowStub
host.location = locationStub
host.localStorage = {
  getItem: (key: string): string | null => storage.get(key) ?? null,
  setItem: (key: string, value: string): void => {
    storage.set(key, value)
  },
  removeItem: (key: string): void => {
    storage.delete(key)
  },
  clear: (): void => {
    storage.clear()
  },
}
host.document = { hidden: false, addEventListener: (): void => {} }
host.__authGet = async (url: string) => url === '/users/me'
  ? { data: { id: 7, username: 'alice', role: 'admin', is_enabled: true, display_name: 'Alice', mfa_enabled: false, auth_provider: 'local' } }
  : { data: { is_master: true, timezone: 'Asia/Shanghai', cert_renewal_days: 30, mfa_write_guard: false } }

storage.set('token', 'tok-tab-a')

registerModuleHooks({
  'element-plus': dataModule(`
export const ElMessage = Object.assign(
  () => {},
  { success: () => {}, error: () => {}, info: () => {}, warning: () => {} },
)
`),
  '@/utils/api': dataModule(`
export class ApiRequestError extends Error {
  constructor(message, status) { super(message); this.status = status; this.name = 'ApiRequestError' }
}
export const isTokenExpired = (token) => !token
export const request = { get: (url) => globalThis.__authGet(url), post: async () => ({ data: undefined }) }
`),
})

// 静态 import 不可行：auth.ts 的模块顶层就读 location/localStorage，必须先搭好
// 浏览器宿主再加载（且 element-plus 替身经 registerModuleHooks 注册，同样先于加载）。
const { useAuthStore } = await import('../src/stores/auth.ts')

const newStore = () => {
  // 每个用例只保留当前 store 的监听器；历史实例不得再响应后续 storage 事件。
  storageListeners.length = 0
  // 上一个用例的重试链同样不得计入本用例。
  timers.clear()
  setActivePinia(createPinia())
  const store = useAuthStore()
  assert.equal(storageListeners.length, 1, '每个用例必须只注册当前实例的一个 storage 监听器')
  return store
}

const dispatchStorage = (key: string | null): void => {
  for (const listener of storageListeners) listener({ key })
}

const flush = (): Promise<void> => {
  const { promise, resolve } = Promise.withResolvers<void>()
  setTimeout(resolve, 0)
  return promise
}

test('另一标签页登出：本标签页同步清空令牌/用户/节点模式并停表', () => {
  storage.set('token', 'tok-tab-a')
  const store = newStore()
  assert.equal(store.token, 'tok-tab-a')

  // 另一标签页 logout()：清 localStorage → 本标签页收到 storage 事件
  storage.delete('token')
  dispatchStorage('token')

  assert.equal(store.token, null, '内存令牌必须跟随 localStorage 清空（App.vue 据此回登录页）')
  assert.equal(store.user, null)
  assert.equal(store.nodeMode, null)
  assert.equal(store.intentionalLogout, true, '同步退出属主动登出，须抑制在途请求的会话失效弹窗')
  assert.equal(timers.size, 0, '同步退出必须停掉用户/配置重试定时器')
})

test('另一标签页 localStorage.clear()：key 为 null 同样按会话消失处理', () => {
  storage.set('token', 'tok-tab-a2')
  const store = newStore()
  assert.equal(store.token, 'tok-tab-a2')

  storage.clear()
  dispatchStorage(null)

  assert.equal(store.token, null)
  assert.equal(store.intentionalLogout, true)
})

test('另一标签页建立新会话：跟随令牌并重拉用户与节点模式（不沿用旧账号权限）', async () => {
  storage.set('token', 'tok-tab-b')
  const store = newStore()
  assert.equal(store.token, 'tok-tab-b')

  storage.set('token', 'tok-tab-c')
  dispatchStorage('token')

  assert.equal(store.token, 'tok-tab-c', '新令牌必须立即生效（旧令牌已被服务端吊销）')
  assert.equal(store.intentionalLogout, false)
  await flush()
  assert.equal(store.user?.username, 'alice', '新会话必须重拉用户信息')
  assert.equal(store.nodeMode, 'master', '新会话必须重拉节点模式')
})

test('首屏 init：/users/me 与 /config 并行发出（不叠成两次 30s 超时）', async () => {
  storage.set('token', 'tok-parallel')
  const store = newStore()
  const started: string[] = []
  const deferred = new Map<string, () => void>()
  const defaultGet = host.__authGet
  host.__authGet = (url: string) => {
    started.push(url)
    const { promise, resolve } = Promise.withResolvers<unknown>()
    deferred.set(url, () => resolve(url === '/users/me'
      ? { data: { id: 8, username: 'bob', role: 'admin', is_enabled: true, display_name: 'Bob', mfa_enabled: false, auth_provider: 'local' } }
      : { data: { is_master: true, timezone: 'Asia/Shanghai', cert_renewal_days: 30, mfa_write_guard: false } }))
    return promise
  }
  try {
    const pending = store.init()
    // 两个请求均未落地：串行实现此刻只会发出 /users/me（首屏最坏 30s×2 的来源）
    assert.deepEqual([...started].sort(), ['/config', '/users/me'], '首屏两个请求必须并行')
    for (const resolve of deferred.values()) resolve()
    await pending
    assert.equal(store.user?.username, 'bob')
    assert.equal(store.nodeMode, 'master')
  } finally {
    host.__authGet = defaultGet
  }
})

test('非令牌键的 storage 变更不触碰会话（多标签页导航互不干扰）', () => {
  storage.set('token', 'tok-tab-d')
  const store = newStore()

  storage.set('currentPage', 'rules')
  dispatchStorage('currentPage')

  assert.equal(store.token, 'tok-tab-d')
  assert.equal(store.user, null, '无关键不得触发重拉用户信息')
  assert.equal(store.intentionalLogout, false)
  assert.equal(timers.size, 0)
})

// ── 迟到响应：账号切换后旧 /users/me 不得回写新会话身份 ──
// 无论响应成败，await 之后都必须按发起时的会话身份（令牌 + 代际）比对；
// 否则旧账号的 200 会把 user 重建为上一位用户，readOnlyReason 随之按旧角色
// 渲染写控件（后端仍按新令牌鉴权，故仅 UI 误导，但会持续到刷新）。

const aliceMe = { data: { id: 7, username: 'alice', role: 'admin', is_enabled: true, display_name: 'Alice', mfa_enabled: false, auth_provider: 'local' } }
const bobMe = { data: { id: 9, username: 'bob', role: 'operator', is_enabled: true, display_name: 'Bob', mfa_enabled: false, auth_provider: 'local' } }
const masterConfig = { data: { is_master: true, timezone: 'Asia/Shanghai', cert_renewal_days: 30, mfa_write_guard: false } }

// 手动放行的请求队列：按发出顺序记录 { url, resolve, reject }，由用例决定落地时机。
interface PendingGet { readonly url: string; readonly resolve: (value: unknown) => void; readonly reject: (reason: unknown) => void }
const deferGets = (): { queue: PendingGet[]; restore: () => void } => {
  const queue: PendingGet[] = []
  const original = host.__authGet
  host.__authGet = (url: string) => {
    const { promise, resolve, reject } = Promise.withResolvers<unknown>()
    queue.push({ url, resolve, reject })
    return promise
  }
  return { queue, restore: () => { host.__authGet = original } }
}

// 监听器已在 newStore 中按用例复位：事件只能驱动当前实例，队列必须精确等于
// 首屏请求 + 当前实例换令牌后的一对请求，不再取队尾适应历史污染。
const ownNewSessionGets = (queue: PendingGet[], from: number): PendingGet[] => {
  const own = queue.slice(from)
  assert.equal(own.length, 2, '换令牌只能产生当前实例的一对请求')
  assert.deepEqual(own.map((g) => g.url), ['/users/me', '/config'], '新会话必须重拉身份与节点模式')
  return own
}

test('账号切换：旧 /users/me 的迟到成功响应不得覆盖新会话身份', async () => {
  storage.set('token', 'tok-acc-a')
  const store = newStore()
  const { queue, restore } = deferGets()
  try {
    const firstInit = store.init()
    // 旧 /users/me 保持未落地（正是本用例要构造的迟到响应），init 的等待由用例末尾兜住
    void firstInit.catch(() => {})
    await flush()
    assert.deepEqual(queue.map((g) => g.url), ['/users/me', '/config'], '首屏两请求均未落地')
    // 旧会话的 /config 先落地（节点模式与身份无关），在途门随之释放
    queue[1].resolve(masterConfig)
    await flush()

    // 另一标签页登录 B：本页跟随新令牌并以新代际重拉
    const beforeSwitch = queue.length
    storage.set('token', 'tok-acc-b')
    dispatchStorage('token')
    await flush()
    const fresh = ownNewSessionGets(queue, beforeSwitch)
    fresh[0].resolve(bobMe)
    fresh[1].resolve(masterConfig)
    await flush()
    assert.equal(store.user?.username, 'bob')

    // 旧账号 A（管理员）的响应此刻才到：必须整条丢弃
    queue[0].resolve(aliceMe)
    await flush()
    assert.equal(store.user?.username, 'bob', '旧账号迟到响应不得覆盖新会话身份')
    assert.equal(store.user?.role, 'operator', '角色不得回退到旧账号的管理员权限')
  } finally {
    restore()
  }
})

test('账号切换：旧 /users/me 的迟到失败不得排重试链或清空已知用户', async () => {
  storage.set('token', 'tok-acc-c')
  const store = newStore()
  const { queue, restore } = deferGets()
  try {
    const firstInit = store.init()
    void firstInit.catch(() => {})
    await flush()
    queue[1].resolve(masterConfig)
    await flush()

    const beforeSwitch = queue.length
    storage.set('token', 'tok-acc-d')
    dispatchStorage('token')
    await flush()
    const fresh = ownNewSessionGets(queue, beforeSwitch)
    fresh[0].resolve(bobMe)
    fresh[1].resolve(masterConfig)
    await flush()
    const timersBefore = timers.size
    assert.equal(store.user?.username, 'bob')

    // 旧会话的请求以瞬时失败落地：既不得清空 B 的用户，也不得为 B 排重试链
    queue[0].reject(new Error('network down'))
    await flush()
    assert.equal(store.user?.username, 'bob', '迟到失败不得改动新会话身份')
    assert.equal(timers.size, timersBefore, '迟到失败不得排入重试定时器')
  } finally {
    restore()
  }
})

test('OIDC 换令牌：清空上一账号的用户与节点模式，迟到响应不得复活旧身份', async () => {
  storage.set('token', 'tok-oidc-prev')
  const store = newStore()
  const { queue, restore } = deferGets()
  try {
    const firstInit = store.init()
    await flush()
    queue[0].resolve(aliceMe)
    queue[1].resolve(masterConfig)
    await firstInit
    assert.equal(store.user?.username, 'alice')
    assert.equal(store.nodeMode, 'master')

    // 上一账号的补拉仍在途
    const lateFetch = store.fetchUser()
    await flush()
    const late = queue[2]
    assert.equal(late.url, '/users/me')

    store.applyOIDCToken('tok-oidc-new')
    assert.equal(store.token, 'tok-oidc-new')
    assert.equal(store.user, null, '换令牌即换身份：旧用户不得继续渲染')
    assert.equal(store.nodeMode, null, '节点模式须由 init 重拉（不得沿用旧值）')

    late.resolve(aliceMe)
    await lateFetch
    assert.equal(store.user, null, '旧身份的迟到响应不得复活已清空的用户')
  } finally {
    restore()
  }
})
