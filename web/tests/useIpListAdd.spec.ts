// 「把 IP 加入 IP 名单」组合子的行为验收：确认框 → 幂等 POST → added 短成功 /
// 已存在 info；取消/失败不得谎报完成；重入锁（双击/双动作）只允许一次写入。
//
// element-plus / api / saveResult 均为字节级或跨域依赖，用 data: 模块替身记录
// 调用；被测逻辑本身是真实实现。
//
// 被测模块必须动态 import：钩子注册先于模块求值，静态 import 会先加载真实
// element-plus（CSS/DOM 字节级依赖，node 下不可加载）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks, waitForMicrotasks } from './_helpers.ts'
import { installStubHost, STUB_API, STUB_ELEMENT, STUB_SAVE_RESULT } from './_stubs.ts'
import { i18n } from '../src/i18n/index.ts'

type Harness = {
  __confirm: (...args: unknown[]) => Promise<unknown>
  __post: (...args: unknown[]) => Promise<unknown>
  __get: (...args: unknown[]) => Promise<unknown>
  __put: (...args: unknown[]) => Promise<unknown>
}
const g = globalThis as unknown as Harness
const stubHost = installStubHost()

registerModuleHooks({
  'element-plus': STUB_ELEMENT,
  '@/utils/api': STUB_API,
  '@/utils/saveResult': STUB_SAVE_RESULT,
})
const { useIpListAdd } = await import('../src/composables/useIpListAdd.ts')

const list = { id: 7, name: '办公网', entry_count: 3 }

const reset = (): void => {
  stubHost.reset()
  g.__confirm = async (...args: unknown[]) => {
    stubHost.calls.push({ fn: 'confirm', args })
  }
  g.__post = async () => ({ data: { added: true } })
  g.__get = async () => ({ data: undefined })
  g.__put = async () => ({ data: undefined })
}

const callsOf = stubHost.callsOf

test('确认后幂等 POST：added=true 走 showSaveResult，返回完成并复位重入锁', async () => {
  reset()
  const posted: unknown[] = []
  g.__post = async (url: unknown, body: unknown) => {
    posted.push({ url, body })
    return { data: { added: true } }
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('203.0.113.9', list), true)

  const [confirm] = callsOf('confirm')
  const [message, title] = confirm.args ?? []
  assert.match(String(message), /203\.0\.113\.9/, '确认文案必须点名 IP')
  assert.match(String(message), /办公网/, '确认文案必须点名列表')
  assert.match(String(message), /幂等/, '确认文案必须声明幂等语义')
  assert.equal(title, '加入 IP')
  assert.deepEqual(posted, [{ url: '/security/ip-lists/7/ips', body: { value: '203.0.113.9' } }])

  const saves = callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  assert.deepEqual(saves[0].args, [{ data: { added: true } }, '已在 IP 名单「办公网」中加入该 IP'])
  assert.equal(adding.value, false, '完成后必须释放重入锁')
})

test('确认句/标题/成功句：加入、封禁、放行、信任四个动词代入后动词落在 IP 上，名单只作位置', async () => {
  // IP 快捷处置把「封禁 / 放行 / 信任」当动词传入；动词若紧贴名单会拼成
  // 「将把 1.2.3.4 封禁地址列表」——该动作是把 IP 加入名单，动词必须落在 IP 上。
  const zhRendered: Record<string, [string, string, string]> = {
    '加入': ['将在 IP 名单「办公网」中加入 203.0.113.9（幂等，已存在时不会重复添加）。是否继续？', '加入 IP', '已在 IP 名单「办公网」中加入该 IP'],
    '封禁': ['将在 IP 名单「办公网」中封禁 203.0.113.9（幂等，已存在时不会重复添加）。是否继续？', '封禁 IP', '已在 IP 名单「办公网」中封禁该 IP'],
    '放行': ['将在 IP 名单「办公网」中放行 203.0.113.9（幂等，已存在时不会重复添加）。是否继续？', '放行 IP', '已在 IP 名单「办公网」中放行该 IP'],
    '信任': ['将在 IP 名单「办公网」中信任 203.0.113.9（幂等，已存在时不会重复添加）。是否继续？', '信任 IP', '已在 IP 名单「办公网」中信任该 IP'],
  }
  for (const [verb, [message, title, saved]] of Object.entries(zhRendered)) {
    reset()
    assert.equal(await useIpListAdd().addIpToList('203.0.113.9', list, { verb }), true)
    const [confirm] = callsOf('confirm')
    assert.equal(String(confirm.args?.[0]), message, `${verb}：确认句`)
    assert.equal(confirm.args?.[1], title, `${verb}：标题`)
    assert.equal(String(callsOf('showSaveResult')[0].args?.[1]), saved, `${verb}：成功句`)
  }
  // en 母本同口径：动词置于句首（动词词条首字母大写），名单只作位置
  const render = (path: string, vars: Record<string, string>): string => {
    const value = path.split('.').reduce<unknown>((node, key) => (node as Record<string, unknown> | undefined)?.[key], i18n.global.messages.value.en)
    assert.equal(typeof value, 'string', `en 词条 ${path} 必须是字符串叶子`)
    return (value as string).replace(/\{(\w+)\}/g, (_m, key: string) => vars[key])
  }
  const enRendered: Record<string, [string, string, string]> = {
    Add: ['Add 203.0.113.9 in the IP list "Office" (idempotent — existing entries are not added twice). Continue?', 'Add IP', 'Add: IP list "Office" now contains this IP'],
    Ban: ['Ban 203.0.113.9 in the IP list "Office" (idempotent — existing entries are not added twice). Continue?', 'Ban IP', 'Ban: IP list "Office" now contains this IP'],
    Allow: ['Allow 203.0.113.9 in the IP list "Office" (idempotent — existing entries are not added twice). Continue?', 'Allow IP', 'Allow: IP list "Office" now contains this IP'],
    Trust: ['Trust 203.0.113.9 in the IP list "Office" (idempotent — existing entries are not added twice). Continue?', 'Trust IP', 'Trust: IP list "Office" now contains this IP'],
  }
  for (const [verb, [message, title, saved]] of Object.entries(enRendered)) {
    const vars = { verb, ip: '203.0.113.9', list: 'Office' }
    assert.equal(render('common.app.views.ipAdd.confirmMessage', vars), message, `${verb}: confirm message`)
    assert.equal(render('common.app.views.ipAdd.confirmTitle', vars), title, `${verb}: confirm title`)
    assert.equal(render('common.app.views.ipAdd.successDefault', vars), saved, `${verb}: success message`)
  }
})

test('确认框附加披露（note）：拼在主体文案后；缺省不改变既有文案', async () => {
  reset()
  const { addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('2606:4700:abcd:1234::/64', list, { verb: '封禁', note: 'IPv6 按 /64 前缀封禁：同一 /64 下的其它地址会被连带封禁' }), true)
  const [confirm] = callsOf('confirm')
  const [message] = confirm.args ?? []
  assert.match(String(message), /2606:4700:abcd:1234::\/64/, '确认文案必须点名 CIDR 形态条目值')
  assert.match(String(message), /IPv6 按 \/64 前缀封禁/, '附加披露必须拼进确认文案（/64 连带影响可见）')
  // 缺省 note：文案与无选项形态逐字一致（不引入尾部空格/第二份口径）
  reset()
  assert.equal(await addIpToList('1.2.3.4', list), true)
  const [plain] = callsOf('confirm')
  assert.ok(!String(plain.args?.[0]).endsWith(' '), '缺省 note 不得引入尾部空隙')
})

test('added=false（已存在）以 info 呈现，不弹成功提示', async () => {
  reset()
  g.__post = async (url: unknown) => {
    assert.equal(url, '/security/ip-lists/7/ips')
    return { data: { added: false } }
  }
  const { addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), true, '已存在同样视为动作完成（列表已含该 IP）')
  const infos = callsOf('ElMessage.info')
  assert.equal(infos.length, 1)
  assert.match(String(infos[0].arg), /已在 IP 名单「办公网」中/)
  assert.equal(callsOf('showSaveResult').length, 0)
})

test('取消确认不写库，也不提示成功', async () => {
  reset()
  g.__confirm = async () => {
    throw new Error('cancel')
  }
  const posted: unknown[] = []
  g.__post = async (url: unknown) => {
    posted.push(url)
    return { data: { added: true } }
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), false)
  assert.deepEqual(posted, [])
  assert.equal(adding.value, false)
  assert.equal(callsOf('showSaveResult').length, 0)
})

// 写入口失败（reject）路径：锁复位全靠 finally——若被挪进成功分支，网络抖动后
// 按钮会永久灰死（只能刷新页面），而成功/取消用例仍全绿。
test('POST 失败（reject）：返回 false、释放重入锁、不谎报成功', async () => {
  reset()
  g.__post = async () => {
    throw new Error('boom')
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), false, '写入失败不得回报完成')
  assert.equal(adding.value, false, '失败分支必须释放占位')
  assert.equal(callsOf('showSaveResult').length, 0, '失败不得报成功')
  assert.equal(callsOf('ElMessage.info').length, 0, '失败不得走「已存在」提示')
})

test('写入在途时重入直接拒绝（双击只产生一次 POST）', async () => {
  reset()
  const { promise, resolve } = Promise.withResolvers<unknown>()
  const posted: unknown[] = []
  g.__post = async (url: unknown) => {
    posted.push(url)
    return promise
  }
  const { adding, addIpToList } = useIpListAdd()
  const first = addIpToList('1.2.3.4', list)
  await waitForMicrotasks(() => adding.value, '在途写入置位重入锁')
  assert.equal(adding.value, true, '在途期间重入锁必须置位')
  assert.equal(await addIpToList('1.2.3.4', list), false, '重入必须立即拒绝')
  resolve({ data: { added: true } })
  assert.equal(await first, true)
  assert.deepEqual(posted, ['/security/ip-lists/7/ips'])
  assert.equal(adding.value, false)
})

test('确认框未决时重入直接拒绝（双击只叠一个确认框）', async () => {
  reset()
  const { promise, resolve } = Promise.withResolvers<unknown>()
  let confirms = 0
  g.__confirm = async () => {
    confirms += 1
    return promise
  }
  const posted: unknown[] = []
  g.__post = async (url: unknown) => {
    posted.push(url)
    return { data: { added: true } }
  }
  const { adding, addIpToList } = useIpListAdd()
  const first = addIpToList('1.2.3.4', list)
  await waitForMicrotasks(() => adding.value, '确认框弹出前置位重入锁')
  assert.equal(adding.value, true, '确认框尚未决时锁必须已置位（原实现在确认后才置位）')
  assert.equal(await addIpToList('1.2.3.4', list), false, '确认期间重入必须立即拒绝')
  assert.equal(confirms, 1, '双击不得叠第二个确认框')
  resolve(undefined)
  assert.equal(await first, true)
  assert.deepEqual(posted, ['/security/ip-lists/7/ips'], '只产生一次 POST')
  assert.equal(adding.value, false)
})

test('确认框取消后释放锁（可再次发起）', async () => {
  reset()
  let attempts = 0
  g.__confirm = async () => {
    attempts += 1
    if (attempts === 1) throw new Error('cancel')
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), false)
  assert.equal(adding.value, false, '取消分支必须释放占位')
  assert.equal(await addIpToList('1.2.3.4', list), true)
  assert.equal(attempts, 2)
})
