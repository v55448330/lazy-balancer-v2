// 信任/黑/白三侧快捷处置组合子的行为验收：同侧列表解析（逐引用、排除系统
// 名单）、加入既有列表、无列表时「创建（建单即带 IP）+ 关联」两步完成、同名
// 判据与后端唯一性同口径（ASCII 大小写折叠）、移除后的 removed=false 兜底
// 文案、以及确认取消/重入锁不被跳过。
//
// element-plus / api / saveResult 用 data: 模块替身记录调用；useIpListAdd 使用
// 真实实现（同一条写入链路）。被测模块动态 import：钩子须先注册。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, registerModuleHooks, repoCode, waitForMicrotasks } from './_helpers.ts'
import { installStubHost, STUB_API, STUB_ELEMENT, STUB_SAVE_RESULT } from './_stubs.ts'

type Harness = {
  __confirm: (...args: unknown[]) => Promise<unknown>
  __post: (url: string, body?: unknown) => Promise<unknown>
  __get: (url: string, config?: unknown) => Promise<unknown>
  __put: (url: string, body?: unknown) => Promise<unknown>
}
const g = globalThis as unknown as Harness
const stubHost = installStubHost()

registerModuleHooks({
  'element-plus': STUB_ELEMENT,
  '@/utils/api': STUB_API,
  '@/utils/saveResult': STUB_SAVE_RESULT,
})
const { useTrustAssociation, fitAutoListName } = await import('../src/composables/useTrustAssociation.ts')

interface PostRecord {
  url: string
  body: unknown
}
interface PutRecord {
  url: string
  body: unknown
}

const lists = [
  { id: 1, name: '内联黑名单' },
  { id: 2, name: '威胁情报库', system: 1 },
  { id: 3, name: '办公网段', entry_count: 5 },
  { id: 9, name: '未引用列表' },
]

const reset = (): { posts: PostRecord[]; puts: PutRecord[]; confirmArgs: unknown[][] } => {
  const posts: PostRecord[] = []
  const puts: PutRecord[] = []
  const confirmArgs: unknown[][] = []
  stubHost.reset()
  g.__confirm = async (...args: unknown[]) => {
    confirmArgs.push(args)
  }
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    if (url === '/security/ip-lists') return { data: { id: 42 } }
    if (url.endsWith('/ips')) return { data: { added: true } }
    if (url.endsWith('/remove-ip')) return { data: { removed: true } }
    throw new Error(`unexpected POST ${url}`)
  }
  g.__put = async (url: string, body?: unknown) => {
    puts.push({ url, body })
    return { data: undefined }
  }
  // 默认：确认后的最新 refs 为空（多数用例的点击前快照同为空）；名单详情
  // （复用分支确认后的重读）默认返回「仍只被本策略引用」。
  g.__get = async (url: string) => {
    if (String(url).startsWith('/security/ip-lists/')) {
      return { data: { id: Number(String(url).split('/').pop()), ref_policies: [{ id: 5, name: '策略 A' }], trusted_proxy_referenced: false } }
    }
    return { data: { policy: { ip_acl_list_refs: '[]', ip_whitelist_refs: '[]' } } }
  }
  return { posts, puts, confirmArgs }
}

const callsOf = stubHost.callsOf

/** 新建载荷中的名单名（载荷形状不符即硬失败，避免断言空转）。 */
const assertCreatedListName = (post: PostRecord | undefined): string => {
  assert.ok(post, '必须发起创建请求')
  assert.ok(post.body && typeof post.body === 'object' && 'name' in post.body, '创建载荷必须带 name')
  return String(post.body.name)
}

test('同侧列表解析：按引用逐列表返回、排除系统内置名单、缺失计数归零', () => {
  reset()
  const { resolveSideLists } = useTrustAssociation({ getList: () => lists })
  const policy = {
    id: 5,
    name: '策略 A',
    ip_acl_list_refs: '[1,2,3,9]',
    ip_whitelist_refs: '[2]',
  }
  assert.deepEqual(resolveSideLists(policy, 'deny'), [
    { id: 1, name: '内联黑名单', entry_count: 0 },
    { id: 3, name: '办公网段', entry_count: 5 },
    { id: 9, name: '未引用列表', entry_count: 0 },
  ])
  assert.deepEqual(resolveSideLists(policy, 'trust'), [], '信任侧只关联系统名单时解析为空')
  assert.deepEqual(
    resolveSideLists({ id: 6, name: '策略 B', ip_acl_list_refs: '{bad json' }, 'allow'),
    [],
    '坏 refs 文本回退空集（不炸渲染）',
  )
})

test('加入指定列表：确认 + 幂等 POST + onChanged 回调，返回完成', async () => {
  const { posts, confirmArgs } = reset()
  let changed = 0
  const { joinSpecificList } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  assert.equal(await joinSpecificList({ id: 3, name: '办公网段', entry_count: 5 }, '203.0.113.9', '信任'), true)
  assert.equal(confirmArgs.length, 1)
  assert.match(String(confirmArgs[0][0]), /办公网段/)
  assert.deepEqual(posts, [{ url: '/security/ip-lists/3/ips', body: { value: '203.0.113.9' } }])
  assert.equal(changed, 1, '写入成功后必须通知组件刷新')
  const saves = callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  assert.match(String(saves[0].args?.[1]), /已信任——已加入列表「办公网段」/)
})

test('单击加入：策略已关联同侧非系统列表时直接加入首个列表，不创建', async () => {
  const { posts } = reset()
  let changed = 0
  const { ensureListAndJoin } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  await ensureListAndJoin(
    { id: 5, name: '策略 A', ip_acl_list_refs: '[1,2,3]' },
    '203.0.113.9',
    'deny',
  )
  assert.deepEqual(posts, [{ url: '/security/ip-lists/1/ips', body: { value: '203.0.113.9' } }], '按引用顺序取首个非系统列表')
  assert.equal(changed, 1)
})

test('无同侧列表：确认后创建（建单即带 IP）→ 关联 refs，两步完成', async () => {
  const { posts, puts, confirmArgs } = reset()
  let changed = 0
  const { ensureListAndJoin } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  const policy = { id: 5, name: '策略 A', ip_whitelist_refs: '', ip_whitelist_enabled: false }
  assert.equal(await ensureListAndJoin(policy, '203.0.113.9', 'trust'), true, '完整创建并关联后才返回完成')

  assert.equal(confirmArgs.length, 1)
  const [message, title] = confirmArgs[0]
  assert.match(String(message), /尚未关联信任用地址列表/)
  assert.match(String(message), /暂不生效/, '信任未启用必须提示加入后暂不生效')
  assert.match(String(title), /创建列表并信任/)

  // 建单即播种条目：创建载荷自带 IP，写序收敛为「创建 → 关联」两次请求。
  // 原写序（创建空名单 → 关联 → 加入 IP）在加入失败时会留下已被策略引用的空名单。
  assert.deepEqual(posts, [
    {
      url: '/security/ip-lists',
      body: { name: '策略 A-信任', category: 'custom', entries: JSON.stringify([{ value: '203.0.113.9', remark: '' }]) },
    },
  ])
  assert.deepEqual(puts, [
    { url: '/security/policies/5', body: { ip_whitelist_refs: '[42]' } },
  ])
  const saves = callsOf('mfaAwareSuccess')
  assert.equal(saves.length, 1)
  assert.match(String(saves[0].arg), /已创建「策略 A-信任」并加入 203\.0\.113\.9/)
  assert.equal(changed, 1)
})

test('新建路径关联失败：刷新后重试复用已创建名单，不再撞同名', async () => {
  const { posts, puts } = reset()
  let failAssociation = true
  g.__put = async (url: string, body?: unknown) => {
    puts.push({ url, body })
    if (failAssociation) {
      failAssociation = false
      throw new Error('policy update failed')
    }
    return { data: undefined }
  }
  const refreshedLists: Array<{
    id: number
    name: string
    system?: number
    entry_count?: number
    ref_policies?: Array<{ id: number; name: string }>
  }> = [...lists]
  let changed = 0
  const { ensureListAndJoin } = useTrustAssociation({
    getList: () => refreshedLists,
    onChanged: () => {
      changed += 1
      if (!refreshedLists.some((list) => list.id === 42)) {
        refreshedLists.push({ id: 42, name: '策略 A-黑名单', ref_policies: [] })
      }
    },
  })
  const policy = { id: 5, name: '策略 A', ip_acl_list_refs: '' }
  await ensureListAndJoin(policy, '203.0.113.9', 'deny')

  assert.equal(posts.length, 1, '只应有创建请求（加入条目不单独发起）')
  const body: unknown = posts[0].body
  assert.ok(body && typeof body === 'object' && 'entries' in body, '创建载荷必须是对象')
  assert.deepEqual(JSON.parse(String(body.entries)), [{ value: '203.0.113.9', remark: '' }], '创建载荷必须已带本次 IP')
  assert.equal(puts.length, 1, '关联确实尝试过')
  assert.equal(changed, 1, '关联失败后必须刷新名单快照，供当前弹框重试复用')
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '关联失败不得报成功')
  assert.match(String(callsOf('ElMessage.error')[0]?.arg), /重试将复用该名单/)

  await ensureListAndJoin(policy, '203.0.113.9', 'deny')
  assert.equal(posts.filter((post) => post.url === '/security/ip-lists').length, 1, '重试不得再次创建同名名单')
  assert.deepEqual(posts[1], { url: '/security/ip-lists/42/ips', body: { value: '203.0.113.9' } })
  assert.deepEqual(puts[1], { url: '/security/policies/5', body: { ip_acl_list_refs: '[42]' } })
  assert.equal(changed, 2)
})

test('同名未引用列表复用而非重复创建（仍关联并加入）', async () => {
  const { posts, puts } = reset()
  const sameName = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => sameName })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }], '不得重复创建同名列表')
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_whitelist_refs: '[77]' } }])
  assert.match(String(callsOf('showSaveResult')[0].args?.[1]), /已关联既有/)
})

// 后端判重按 ASCII 大小写折叠（写事务内逐名比对，曾为 SQL 的
// `LOWER(name)=LOWER(?)`）——前端复用既有名单的查找必须同口径，否则策略名仅差
// 大小写时（允许存在）会错过既有名单、转而创建，换来一条 409 且本次加入不发生
// （弹框一次性，无改用既有名单的出口）。
test('同名判据与后端同口径：仅 ASCII 大小写不同也复用既有名单', async () => {
  const { posts, puts } = reset()
  const existing = [...lists, { id: 77, name: 'demo-白名单', ref_policies: [] }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: 'DEMO', ip_acl_list_refs: '' }, '203.0.113.9', 'allow')
  assert.equal(posts.filter((post) => post.url === '/security/ip-lists').length, 0, '不得再创建（后端会 409）')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }])
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_acl_list_refs: '[77]' } }])
})

// 策略名可重复（后端无唯一约束）且超长策略名截断后可能投影到同一自动名——
// 按名字直接复用会让两个策略共享同一份名单：B 的处置改写 A 的拦截/放行面，
// A 后续增删条目又反向影响 B。复用范围收敛为「未被其它引用面引用」。
test('同名名单已被其它策略引用：不复用，改为创建本策略限定名的名单', async () => {
  const { posts, puts, confirmArgs } = reset()
  const existing = [
    ...lists,
    { id: 77, name: '策略 A-信任', ref_policies: [{ id: 9, name: '同名策略' }] },
  ]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.equal(
    posts.filter((post) => post.url === '/security/ip-lists/77/ips').length,
    0,
    '不得把本策略的条目写进其它策略引用的名单',
  )
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.equal(assertCreatedListName(created), '策略 A-信任#5', '限定名以策略 id 区分同名策略')
  assert.match(String(confirmArgs[0][0]), /策略 A-信任#5/, '确认文案必须与实际创建的名单名一致')
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_whitelist_refs: '[42]' } }])
})

test('同名名单仅被本策略引用：仍然复用（补关联并加入）', async () => {
  const { posts, puts } = reset()
  const existing = [
    ...lists,
    { id: 77, name: '策略 A-信任', ref_policies: [{ id: 5, name: '策略 A' }] },
  ]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }])
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_whitelist_refs: '[77]' } }])
})

test('同名名单被受信代理网段引用：不复用（写入会改全局代理信任范围）', async () => {
  const { posts } = reset()
  const existing = [
    ...lists,
    { id: 77, name: '策略 A-信任', ref_policies: [], trusted_proxy_referenced: true },
  ]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.equal(posts.filter((post) => post.url === '/security/ip-lists/77/ips').length, 0)
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.equal(assertCreatedListName(created), '策略 A-信任#5')
})

test('引用视图缺失时不得假设「未被引用」：按不可复用处理', async () => {
  const { posts } = reset()
  const existing = [...lists, { id: 77, name: '策略 A-信任' }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.equal(assertCreatedListName(created), '策略 A-信任#5')
})

test('限定名同样被占用：继续递增直到可用', async () => {
  const { posts } = reset()
  const existing = [
    ...lists,
    { id: 77, name: '策略 A-信任', ref_policies: [{ id: 9, name: '同名策略' }] },
    { id: 78, name: '策略 A-信任#5', ref_policies: [{ id: 10, name: '另一策略' }] },
  ]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.equal(assertCreatedListName(created), '策略 A-信任#5-2')
})

test('非 ASCII 大小写仍视为不同名单（SQLite LOWER 只折叠 ASCII）', async () => {
  const { posts } = reset()
  const existing = [...lists, { id: 77, name: 'ä-白名单' }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: 'Ä', ip_acl_list_refs: '' }, '203.0.113.9', 'allow')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.ok(created, '非 ASCII 大小写变体后端视为新名，前端不得提前合并')
  const body: unknown = created.body
  assert.ok(body && typeof body === 'object' && 'name' in body, '创建载荷必须是对象')
  assert.equal(body.name, 'Ä-白名单')
})

// 写入口失败（reject）路径：creating/adding 的复位全靠 finally——一旦被挪进成功
// 分支，网络抖动后按钮永久灰死，而成功/取消用例仍全绿。
test('创建写入 reject：释放 creating 占位且不谎报成功', async () => {
  const { puts } = reset()
  g.__post = async (url: string) => {
    if (url === '/security/ip-lists') throw new Error('boom')
    throw new Error(`unexpected POST ${url}`)
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  assert.equal(puts.length, 0, '创建失败不得继续关联')
  assert.equal(creating.value, false, '失败分支必须释放占位（否则按钮永久灰死）')
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '创建失败不得报成功')
})

test('关联（PUT）reject：释放 creating 占位', async () => {
  reset()
  g.__put = async () => {
    throw new Error('boom')
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  assert.equal(creating.value, false)
})

test('移除写入 reject：释放 creating 占位且不提示成功', async () => {
  reset()
  g.__post = async () => {
    throw new Error('boom')
  }
  const { creating, removeFromSideRef } = useTrustAssociation({ getList: () => lists })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  assert.equal(creating.value, false, '失败分支必须释放占位')
  assert.equal(callsOf('ElMessage.success').length, 0, '移除失败不得报成功')
})

test('加入指定列表：写入在途时重入被拒（adding 锁经 joinSpecificList 传递）', async () => {
  const { posts } = reset()
  const { promise, resolve } = Promise.withResolvers<unknown>()
  let changed = 0
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    return promise
  }
  const { joinSpecificList } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  const target = { id: 3, name: '办公网段', entry_count: 5 }
  const first = joinSpecificList(target, '203.0.113.9', '信任')
  await waitForMicrotasks(() => posts.length === 1, '在途写入已发出 POST')
  assert.equal(await joinSpecificList(target, '203.0.113.9', '信任'), false, '在途重入必须立即拒绝')
  resolve({ data: { added: true } })
  assert.equal(await first, true)
  assert.deepEqual(posts, [{ url: '/security/ip-lists/3/ips', body: { value: '203.0.113.9' } }], '只产生一次 POST')
  assert.equal(changed, 1, '成功后才通知刷新')
})

test('创建路径取消确认：不创建/不关联/不加入，重入锁释放', async () => {
  const { posts, puts } = reset()
  g.__confirm = async () => {
    throw new Error('cancel')
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  assert.equal(await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust'), false, '取消必须向调用方返回未完成')
  assert.deepEqual(posts, [])
  assert.deepEqual(puts, [])
  assert.equal(creating.value, false)
})

test('既有列表加入不触碰策略 refs（无需补关联）', async () => {
  const { puts } = reset()
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  // 首个非系统列表 id=1 已在 refs 中 → 修正路径不触发 PUT
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '[1]' }, '1.2.3.4', 'deny')
  assert.deepEqual(puts, [], '既有列表加入不触碰策略 refs')
})

test('移除：removed=true 成功提示；removed=false 如实提示 CIDR 覆盖，两者都刷新', async () => {
  const removed = reset()
  let changed = 0
  const { removeFromSideRef } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  assert.deepEqual(removed.posts, [{ url: '/security/ip-lists/3/remove-ip', body: { value: '203.0.113.9' } }])
  // 移除是写事件（MFA step-up 覆盖）：成功提示必须与同文件「加入/创建」同口径
  // 经 mfaAwareSuccess 发出，宽限窗内才会带「免验证」前缀。
  const removeSaves = callsOf('mfaAwareSuccess')
  assert.equal(removeSaves.length, 1, '移除成功必须走 mfaAwareSuccess（不得裸 ElMessage.success）')
  assert.match(String(removeSaves[0].arg), /已从「办公网段」移除/)
  assert.equal(callsOf('ElMessage.success').length, 0, '写成功提示不得绕过 MFA 装饰助手')
  assert.equal(changed, 1)

  const kept = reset()
  g.__post = async (url: string) => {
    kept.posts.push({ url, body: null })
    return { data: { removed: false } }
  }
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  const infos = callsOf('ElMessage.info')
  assert.equal(infos.length, 1)
  assert.match(String(infos[0].arg), /没有 203\.0\.113\.9 的精确条目/, 'removed=false 不得报成功')
  assert.match(String(infos[0].arg), /CIDR/, '必须给出 CIDR 覆盖的解释')
  assert.equal(callsOf('ElMessage.success').length, 0)
  assert.equal(changed, 2, '无精确条目同样改变了列表可见状态，须刷新')
})

test('自动名单名按 50 rune 预算：超长策略名截断且保留后缀', () => {
  // 46 rune 策略名 + 4 rune 后缀 = 50（恰满，不截断）
  const exact = 'a'.repeat(46)
  assert.deepEqual(fitAutoListName(exact, '-黑名单'), { name: `${exact}-黑名单`, truncated: false })
  // 55 rune 策略名 + 后缀 = 58 → 截断策略名部分，后缀完整保留，总长 50
  const long = 'a'.repeat(55)
  const fitted = fitAutoListName(long, '-信任')
  assert.equal(fitted.truncated, true)
  assert.equal(Array.from(fitted.name).length, 50)
  assert.ok(fitted.name.endsWith('-信任'))
  // 多字节字符按 rune 计数，不按 UTF16 编码单元
  const cjk = '策'.repeat(60)
  assert.equal(Array.from(fitAutoListName(cjk, '-黑名单').name).length, 50)
})

test('超长策略名创建并加入：名单名不超 50 且确认文案披露截断', async () => {
  const { posts, confirmArgs } = reset()
  const long = '长'.repeat(55)
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: long, ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.ok(created, '必须发起创建')
  const body: unknown = created.body
  assert.ok(body && typeof body === 'object' && 'name' in body && 'entries' in body, '创建载荷必须是对象')
  assert.equal(Array.from(String(body.name)).length, 50)
  assert.ok(String(body.name).endsWith('-黑名单'))
  assert.deepEqual(JSON.parse(String(body.entries)), [{ value: '203.0.113.9', remark: '' }], '建单载荷必须带本次 IP')
  assert.match(String(confirmArgs[0][0]), /已截断至 50 字符上限/, '确认文案必须披露截断')
  const saves = callsOf('mfaAwareSuccess')
  assert.match(String(saves[0].arg), new RegExp(`已创建「${String(body.name)}」`), '成功文案必须用实际名单名')
})

// —— 写序与新鲜引用（跨会话一致性）——
// 复用既有列表时旧写序是「先关联引用、再加入 IP」：条目写入失败会留下
// 「策略已引用、名单里却没有该 IP」的半态，界面上关联动作报过成功，处置
// 静默失效。反向半态（名单有条目、策略暂未引用）无损——重试只需补关联。

test('复用既有列表：先加入 IP 再关联引用', async () => {
  reset()
  const order: string[] = []
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  g.__post = async (url: string) => {
    order.push(`POST ${url}`)
    return { data: { added: true } }
  }
  g.__put = async (url: string) => {
    order.push(`PUT ${url}`)
    return { data: undefined }
  }
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(order, ['POST /security/ip-lists/77/ips', 'PUT /security/policies/5'], '条目先落库，引用后建立')
})

test('复用路径：IP 已加入但关联失败——显性披露半态且不留「已引用无条目」', async () => {
  const { posts, puts } = reset()
  g.__put = async (url: string, body?: unknown) => {
    puts.push({ url, body })
    throw new Error('policy update failed')
  }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { ensureListAndJoin, creating } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }], '条目必须先写入')
  assert.equal(puts.length, 1, '关联确实尝试过')
  const errors = callsOf('ElMessage.error')
  assert.equal(errors.length, 1, '半态必须显性披露（不得只留全局错误提示）')
  assert.match(String(errors[0].arg), /已把 203\.0\.113\.9 加入列表「策略 A-信任」/)
  assert.match(String(errors[0].arg), /关联失败/)
  assert.match(String(errors[0].arg), /不会重复添加/, '须说明重试不会重复写入条目')
  assert.equal(creating.value, false)
  assert.equal(callsOf('mfaAwareSuccess').length, 0)
})

// 确认框弹出到点「确定」之间，另一会话（并行标签/另一管理员）可能已改动策略
// 引用。用点击前快照拼装 `[...refs, target]` 会把对方新增的引用覆盖掉
// （半途扩容/丢更新），因此写入前必须重读最新 refs。
test('确认后重读最新 refs：并发新增的引用不被覆盖丢弃', async () => {
  const { posts, puts } = reset()
  g.__get = async () => ({ data: { policy: { ip_acl_list_refs: '[3]', ip_whitelist_refs: '[]' } } })
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  assert.equal(posts.length, 1, '新名单仍按建单即带 IP 创建')
  assert.deepEqual(
    puts,
    [{ url: '/security/policies/5', body: { ip_acl_list_refs: '[3,42]' } }],
    '关联载荷必须以确认后的最新 refs 追加，不能覆盖并发新增项',
  )
})

test('最新 refs 读取失败：不写入任何变更并显性提示', async () => {
  const { posts, puts } = reset()
  g.__get = async () => {
    throw new Error('network down')
  }
  const { ensureListAndJoin, creating } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [], '读取失败不得创建/加入')
  assert.deepEqual(puts, [], '读取失败不得基于陈旧引用关联')
  assert.equal(creating.value, false, '失败分支必须释放占位')
  const errors = callsOf('ElMessage.error')
  assert.equal(errors.length, 1)
  assert.match(String(errors[0].arg), /引用状态读取失败/)
})

test('复用路径：确认后目标已被并发关联——不重复写 refs，仍加入 IP', async () => {
  const { posts, puts } = reset()
  g.__get = async (url: string) => String(url).startsWith('/security/ip-lists/')
    ? { data: { id: 77, ref_policies: [{ id: 5, name: '策略 A' }] } }
    : { data: { policy: { ip_acl_list_refs: '[]', ip_whitelist_refs: '[77]' } } }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }])
  assert.deepEqual(puts, [], '最新 refs 已含目标列表时不得再写（无变化写会覆盖并发状态）')
})

// ── 复用判据的新鲜度（名单侧）──
// 复用判据原在弹框打开时求值；确认期间另一管理员/另一标签把同名名单关联到自己
// 的策略后，本次处置会把 IP 写进现已被他人引用的名单，静默改动对方拦截面。
// 因此确认后除策略 refs 外，还必须重读名单的引用面。

test('复用路径：确认后名单被他人引用——改走新建策略限定名单，不写他人名单', async () => {
  const { posts, puts } = reset()
  let listReads = 0
  g.__get = async (url: string) => {
    if (String(url).startsWith('/security/ip-lists/')) {
      listReads += 1
      return { data: { id: 77, ref_policies: [{ id: 5, name: '策略 A' }, { id: 9, name: '策略 B' }] } }
    }
    return { data: { policy: { ip_acl_list_refs: '[]', ip_whitelist_refs: '[]' } } }
  }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')

  assert.equal(listReads, 1, '确认后必须重读一次名单引用面')
  assert.equal(posts.filter((post) => post.url === '/security/ip-lists/77/ips').length, 0, '不得写入已被他人引用的名单')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.ok(created, '必须改走新建')
  assert.equal(assertCreatedListName(created), '策略 A-信任#5', '新建名带策略 id，与既有名单区分')
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_whitelist_refs: '[42]' } }], '只关联新建名单')
  assert.match(String(callsOf('ElMessage.warning')[0]?.arg), /已被其它策略/, '必须显性说明改走新建的原因')
})

test('复用路径：确认后名单被受信代理网段引用——同样改走新建', async () => {
  const { posts } = reset()
  g.__get = async (url: string) => String(url).startsWith('/security/ip-lists/')
    ? { data: { id: 77, ref_policies: [{ id: 5, name: '策略 A' }], trusted_proxy_referenced: true } }
    : { data: { policy: { ip_acl_list_refs: '[]', ip_whitelist_refs: '[]' } } }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.equal(posts.filter((post) => post.url === '/security/ip-lists/77/ips').length, 0)
  assert.ok(posts.find((post) => post.url === '/security/ip-lists'), '受信代理引用同样不可复用')
})

test('复用路径：确认后名单引用面读取失败——不写入任何变更并显性提示', async () => {
  const { posts, puts } = reset()
  g.__get = async (url: string) => {
    if (String(url).startsWith('/security/ip-lists/')) throw new Error('network down')
    return { data: { policy: { ip_acl_list_refs: '[]', ip_whitelist_refs: '[]' } } }
  }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [], '读取失败不得创建/加入（快照不可证）')
  assert.deepEqual(puts, [], '读取失败不得关联')
  assert.equal(creating.value, false)
  assert.match(String(callsOf('ElMessage.error')[0]?.arg), /引用状态读取失败/)
})

test('加入指定列表（显式点按钮）不重读名单：用户已明确选择该名单', async () => {
  reset()
  let listReads = 0
  const { joinSpecificList } = useTrustAssociation({ getList: () => lists })
  const original = g.__get
  g.__get = async (url: string, config?: unknown) => {
    if (String(url).startsWith('/security/ip-lists/')) listReads += 1
    return original(url, config)
  }
  await joinSpecificList({ id: 3, name: '办公网段', entry_count: 5 }, '203.0.113.9')
  assert.equal(listReads, 0, '显式动作不做隐式改道')
})

// —— added 反馈口径（与 useIpListAdd 同源）——
// 后端对「条目已存在且生效中」返回 added=false 且全程无写入
// （securityiplists.go 该分支 rollback 后直接返回）。此时若照旧提示
// 「已加入列表」，用户会以为刚完成一次拦截/放行处置。

test('复用路径：IP 已在列表中（added=false）且已关联——如实提示存在，不报成功', async () => {
  const { posts, puts } = reset()
  g.__get = async (url: string) => String(url).startsWith('/security/ip-lists/')
    ? { data: { id: 77, ref_policies: [{ id: 5, name: '策略 A' }] } }
    : { data: { policy: { ip_acl_list_refs: '[]', ip_whitelist_refs: '[77]' } } }
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    return { data: { added: false } }
  }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  let changed = 0
  const { ensureListAndJoin } = useTrustAssociation({
    getList: () => existing,
    onChanged: () => {
      changed += 1
    },
  })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')

  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }])
  assert.deepEqual(puts, [], '已关联时不得再写 refs')
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '零写入不得报成功')
  assert.equal(callsOf('showSaveResult').length, 0)
  const infos = callsOf('ElMessage.info')
  assert.equal(infos.length, 1, '必须给出「已存在」的事实说明')
  assert.match(String(infos[0].arg), /该 IP 已在列表「策略 A-信任」中/)
  assert.equal(changed, 1, '列表可见状态仍须刷新（entry_count 可能已过期）')
})

test('复用路径：IP 已在列表中但本次补了关联——按关联口径反馈，不声称加入了条目', async () => {
  const { posts, puts } = reset()
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    return { data: { added: false } }
  }
  const existing = [...lists, { id: 77, name: '策略 A-信任', ref_policies: [] }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')

  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }])
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_whitelist_refs: '[77]' } }], '关联确为一次写入')
  assert.equal(callsOf('ElMessage.info').length, 0, '本次确有写入，不能只报「已存在」')
  const saves = callsOf('mfaAwareSuccess')
  assert.equal(saves.length, 1)
  assert.match(String(saves[0].arg), /已关联既有「策略 A-信任」/)
  assert.match(String(saves[0].arg), /未重复添加/, '须说明条目未重复写入')
})

// ── 三条边界路径（此前零覆盖）──
// 名单名尝试次数耗尽、创建响应缺 id、移除动作取消。前两条是用户可见的错误
// 提示分支，第三条是占位释放与「取消无副作用」的契约。

test('自动名 20 次尝试全被占用：回退名由后端 409 拒绝且不继续关联', async () => {
  const { posts, puts } = reset()
  // 自动名与全部 20 个限定名都被占用；创建替身按真实唯一性契约返回 409。
  const taken = ['策略 A-信任']
  for (let attempt = 1; attempt <= 20; attempt++) {
    taken.push(attempt === 1 ? '策略 A-信任#5' : `策略 A-信任#5-${attempt}`)
  }
  const existing = taken.map((name, index) => ({ id: 100 + index, name }))
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    throw Object.assign(new Error('名单名称已存在'), { status: 409 })
  }
  let changed = 0
  const { creating, ensureListAndJoin } = useTrustAssociation({
    getList: () => existing,
    onChanged: () => { changed += 1 },
  })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')

  assert.equal(posts.length, 1, '必须发起一次创建并由后端判定冲突')
  assert.equal(assertCreatedListName(posts[0]), '策略 A-信任#5', '尝试耗尽后回退首个限定名')
  assert.deepEqual(puts, [], '409 后不得继续写策略关联')
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '409 不得报成功')
  assert.equal(callsOf('showSaveResult').length, 0)
  assert.equal(changed, 0, '冲突未写入不得触发成功刷新')
  assert.equal(creating.value, false, '409 后必须释放占位')
})

test('创建响应缺 id：报「创建响应异常」且不再发关联请求', async () => {
  const { posts, puts } = reset()
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    if (url === '/security/ip-lists') return { data: {} }
    throw new Error(`unexpected POST ${url}`)
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')

  assert.deepEqual(puts, [], '没有名单 id 时不得写入 refs（会往引用里塞 undefined）')
  const errors = callsOf('ElMessage.error')
  assert.equal(errors.length, 1, '必须显性报错，不能静默中断')
  assert.match(String(errors[0].arg), /创建响应异常/)
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '失败不得声称成功')
  assert.equal(creating.value, false, '占位必须释放')
})

test('移除动作取消：不发请求、不刷新、释放占位（取消无副作用）', async () => {
  const { posts } = reset()
  g.__confirm = async () => {
    throw new Error('cancel')
  }
  let changed = 0
  const { creating, removeFromSideRef } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')

  assert.deepEqual(posts, [], '取消不得调用 remove-ip')
  assert.equal(callsOf('ElMessage.success').length, 0)
  assert.equal(changed, 0, '取消不触发列表刷新')
  assert.equal(creating.value, false, '占位必须在取消路径释放（否则按钮永久灰死）')
})

test('跨栈：自动名单名上限与查重口径对表后端', () => {
  const go = repoCode('internal/handlers/securityiplists.go')
  assert.match(go, /\bipListMaxNameLength\s*=\s*50\b/, '前端 50 rune 截断预算必须跟随后端写门')
  // 查重落在写事务内的应用层比对（`strings.EqualFold`，Unicode simple folding），
  // 不再是 SQL 的 `LOWER(name)=LOWER(?)`（SQLite 只折叠 ASCII）。两端口径因此只在
  // 「名称仅差非 ASCII 大小写」这一形态上分叉：前端复用判据只折叠 ASCII 而选择新建，
  // 随后被后端 409 拦下（fail-closed，不会产生重名数据）。改动任一端须重判该形态。
  const dedup = member(go, 'func findDuplicateIPListName(')
  assert.match(dedup, /strings\.EqualFold\(name, candidate\)/, '后端查重必须走应用层 EqualFold（SQL LOWER 不折叠非 ASCII）')
  assert.match(dedup, /WHERE id<>\?/, '更新路径的自身排除必须落在查询里（不得靠调用方过滤）')
  assert.doesNotMatch(go, /LOWER\(name\)\s*=\s*LOWER\(\?\)/, '查重不得退回 SQL LOWER 口径')
  const create = member(go, 'func (h *Handlers) CreateIPList(')
  const update = member(go, 'func (h *Handlers) UpdateIPList(')
  for (const [name, body] of [['Create', create], ['Update', update]] as const) {
    assert.match(body, /findDuplicateIPListName\(/, `${name} 必须走同一查重单源（两份实现会分叉 409 文案与口径）`)
  }
  const fe = code('src/composables/useTrustAssociation.ts')
  assert.match(fe, /name\.replace\(\/\[A-Z\]\/g, \(c\) => c\.toLowerCase\(\)\)/, '前端同名复用只折叠 ASCII（与其比较的名单名口径一致）')
})
