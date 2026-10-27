// LogStorageBar 的数据层（useLogStorageStats）行为验收：
// - logKey / caddyId 变化 = 换了一行日志：必须先清空旧统计再取数。后端只返回
//   所看那一行的统计，旧值不会被覆盖——原实现只在 refreshKey 时重取，换行全靠
//   调用方重挂组件，漏挂即渲染上一行的名称/字节/百分比（隐式契约、无声错行）。
// - refreshKey 变化 = 同一行重取（保留/清理改变占用）：保留旧值，避免闪烁。
// - 换行后上一行的迟到响应不得写回（取数序号）。
//
// api.ts 用 data: 模块替身记录请求；被测组合子动态 import（钩子须先注册）。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nextTick, ref } from 'vue'

import { registerModuleHooks, repoCode, section, code } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'

interface GetRecord {
  url: string
  config?: unknown
}

type Harness = {
  __gets: GetRecord[]
  __get: (url: string, config?: unknown) => Promise<unknown>
}
const g = globalThis as unknown as Harness
g.__gets = []
g.__get = async () => ({ data: { logs: [] } })

registerModuleHooks({ '@/utils/api': STUB_API })
const { useLogStorageStats } = await import('../src/composables/useLogStorageStats.ts')

const flush = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 0))

const deferred = (): { promise: Promise<unknown>; resolve: (value: unknown) => void } => {
  let resolve!: (value: unknown) => void
  const promise = new Promise<unknown>((r) => { resolve = r })
  return { promise, resolve }
}

const statsOf = (key: string, name: string): unknown => ({ data: { logs: [{ key, name }] } })

test('换行（logKey 变化）：先清空旧行统计，再取新行数据', async () => {
  const target = ref({ logKey: 'runtime', caddyId: 'main' })
  const pending = deferred()
  const requests: GetRecord[] = []
  g.__gets = requests
  let call = 0
  g.__get = async () => {
    call += 1
    if (call === 1) return statsOf('runtime', '运行日志')
    return pending.promise
  }
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => 0 })
  await flush()
  assert.equal(info.value?.name, '运行日志', '挂载即取当前行（refreshKey 初始触发）')
  assert.deepEqual(requests[0].config, { params: { key: 'runtime', caddy_id: 'main' }, silent: true })

  target.value = { logKey: 'audit', caddyId: 'main' }
  await nextTick()
  const clearedOnKeyChange: unknown = info.value
  assert.equal(clearedOnKeyChange, null, '换行后必须立即清空——不得继续渲染上一行的统计')
  assert.equal(requests.length, 2, '换行必须重新取数（不依赖调用方重挂）')
  assert.deepEqual(requests[1].config, { params: { key: 'audit', caddy_id: 'main' }, silent: true })

  pending.resolve(statsOf('audit', '操作日志'))
  await flush()
  assert.equal(info.value?.name, '操作日志')
})

test('caddyId 变化同样视为换行：清空并按新站点收窄取数', async () => {
  const target = ref<{ logKey: string; caddyId?: string }>({ logKey: 'caddy', caddyId: 'main' })
  const pending = deferred()
  const requests: GetRecord[] = []
  g.__gets = requests
  let call = 0
  g.__get = async () => {
    call += 1
    return call === 1 ? statsOf('caddy', 'Caddy 日志') : pending.promise
  }
  const { info } = useLogStorageStats({ target: () => target.value })
  await flush()
  assert.deepEqual(requests[0].config, { params: { key: 'caddy', caddy_id: 'main' }, silent: true })

  target.value = { logKey: 'caddy', caddyId: 'slave-1' }
  await nextTick()
  const clearedOnSiteChange: unknown = info.value
  assert.equal(clearedOnSiteChange, null, '换站点必须先清空旧站点统计')
  assert.equal(requests.length, 2)
  assert.deepEqual(requests[1].config, { params: { key: 'caddy', caddy_id: 'slave-1' }, silent: true })

  pending.resolve(statsOf('caddy', 'Caddy 日志（slave-1）'))
  await flush()
  assert.equal(info.value?.name, 'Caddy 日志（slave-1）')
})

test('refreshKey 变化：同一行重取且保留旧值（不闪烁）', async () => {
  const target = ref({ logKey: 'audit' })
  const refreshKey = ref(0)
  const pending = deferred()
  g.__gets = []
  let call = 0
  g.__get = async () => {
    call += 1
    return call === 1 ? statsOf('audit', '操作日志') : pending.promise
  }
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  assert.equal(info.value?.name, '操作日志')

  refreshKey.value += 1
  await nextTick()
  assert.equal(info.value?.name, '操作日志', '同一行重取期间保留旧值')
  assert.equal(g.__gets.length, 2)
  assert.deepEqual(g.__gets[1].config, { params: { key: 'audit' }, silent: true }, '重取口径与首次相同（silent 随请求走）')

  pending.resolve(statsOf('audit', '操作日志（新）'))
  await flush()
  assert.equal(info.value?.name, '操作日志（新）')
})

test('迟到响应不写回：换行后上一行的慢响应被丢弃', async () => {
  const target = ref({ logKey: 'runtime' })
  const slow = deferred()
  g.__gets = []
  let call = 0
  g.__get = async () => {
    call += 1
    return call === 1 ? slow.promise : statsOf('audit', '操作日志')
  }
  const { info } = useLogStorageStats({ target: () => target.value })
  await flush()
  const beforeFirstResponse: unknown = info.value
  assert.equal(beforeFirstResponse, null, '首轮未返回前无统计')

  target.value = { logKey: 'audit' }
  await flush()
  assert.equal(info.value?.name, '操作日志')

  slow.resolve(statsOf('runtime', '运行日志'))
  await flush()
  assert.equal(info.value?.name, '操作日志', '旧行迟到响应不得覆盖当前行')
})

test('同一 tick 换行 + 刷新号自增只发一次请求（双 watch 已合并）', async () => {
  const target = ref({ logKey: 'runtime' })
  const refreshKey = ref(0)
  g.__gets = []
  g.__get = async () => statsOf('runtime', '运行日志')
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  assert.equal(g.__gets.length, 1)
  assert.equal(info.value?.name, '运行日志')

  target.value = { logKey: 'audit' }
  refreshKey.value += 1
  await nextTick()
  await flush()
  assert.equal(g.__gets.length, 2, '同一 tick 的两个触发源必须合并为一次取数')
  // 新 key 无对应行（stub 恒返 runtime 行）→ 清空后保持空，不残留上一行
  assert.equal(info.value, null)
  assert.deepEqual(g.__gets[1].config, { params: { key: 'audit' }, silent: true })
})

test('取数失败：置 error 且保留上一次统计（不得整条消失）', async () => {
  const target = ref({ logKey: 'audit' })
  const refreshKey = ref(0)
  g.__gets = []
  let call = 0
  g.__get = async () => {
    call += 1
    if (call === 1) return statsOf('audit', '操作日志')
    throw new Error('network down')
  }
  const { info, error } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  assert.equal(info.value?.name, '操作日志')
  assert.equal(error.value, null, '成功时无错误位')

  refreshKey.value += 1
  await nextTick()
  await flush()
  assert.equal(info.value?.name, '操作日志', '失败必须保留上一次统计（不闪成空白）')
  assert.equal(error.value, 'network down', '失败必须显式暴露错误')

  // 恢复后错误位清除
  g.__get = async () => statsOf('audit', '操作日志（新）')
  refreshKey.value += 1
  await nextTick()
  await flush()
  assert.equal(info.value?.name, '操作日志（新）')
  assert.equal(error.value, null)
})

test('换行同时清空错误位：新行取数期间不得继承上一行的失败提示', async () => {
  const target = ref({ logKey: 'audit' })
  const pending = deferred()
  g.__gets = []
  let call = 0
  g.__get = async () => {
    call += 1
    if (call === 1) throw new Error('network down')
    return pending.promise
  }
  const { info, error } = useLogStorageStats({ target: () => target.value })
  await flush()
  const noStatsYet: unknown = info.value
  assert.equal(noStatsYet, null)
  assert.equal(error.value, 'network down', '上一行取数失败须显式暴露')

  target.value = { logKey: 'runtime' }
  await nextTick()
  // 值已清空但新行请求仍在途：此时若错误位残留，LogStorageBar 会显示
  // 「日志统计暂不可用」并把这条提示错记到新行头上。
  const clearedOnTargetChange: unknown = info.value
  assert.equal(clearedOnTargetChange, null)
  assert.equal(error.value, null, '换行后旧行错误位必须立即清空')
  assert.equal(g.__gets.length, 2, '换行仍须重新取数')

  pending.resolve(statsOf('runtime', '运行日志'))
  await flush()
  assert.equal(error.value, null)
  assert.equal(info.value?.name, '运行日志')
})

test('组合子不导出取数函数（loadStats 无外部消费）', () => {
  const src = code('src/composables/useLogStorageStats.ts')
  assert.match(src, /return \{ info, error, unavailable \}/, '返回值只含消费面（info/error/unavailable）')
  assert.doesNotMatch(src, /return \{ info, loadStats \}/, 'loadStats 零外部消费，不得再作为对外契约')
  assert.match(code('src/components/LogStorageBar.vue'), /const \{ info, error, unavailable \} = useLogStorageStats\(/, '三态（有值/失败/无统计）都必须被消费')
})

// 请求成功但响应里没有所看那一行（后端 key 词表改名/该日志尚未注册）曾与
// 「成功且有值」共用 info=null + error=null：模板的值/失败两分支都不渲染，
// 整条统计静默消失，运维看不到「该日志无统计」这一事实。
test('成功但无该 key：置 unavailable（统计条显式说明，而非整条消失）', async () => {
  const target = ref({ logKey: 'runtime' })
  const refreshKey = ref(0)
  g.__gets = []
  g.__get = async () => ({ data: { logs: [] } })
  const { info, error, unavailable } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  const missingInfo: unknown = info.value
  assert.equal(missingInfo, null)
  assert.equal(error.value, null, '缺行不是取数失败（不得进入可重试的失败口径）')
  assert.equal(unavailable.value, true, '成功但无匹配行必须显式标记')

  // 取到该行后标记清除（同一实例的第二轮）
  g.__get = async () => statsOf('runtime', '运行日志')
  refreshKey.value += 1
  await nextTick()
  await flush()
  assert.equal(unavailable.value, false)
  const hit: { name?: string } | null = info.value
  assert.equal(hit?.name, '运行日志')

  // 换行时旧行的「暂无统计」不得挂到新行上（取数在途期间回到无结论态）
  const pending = deferred()
  g.__get = async () => pending.promise
  target.value = { logKey: 'audit' }
  await nextTick()
  assert.equal(unavailable.value, false, '换行后缺行标记必须立即清空')
  pending.resolve(statsOf('audit', '操作日志'))
  await flush()
  assert.equal(unavailable.value, false)
  const next: { name?: string } | null = info.value
  assert.equal(next?.name, '操作日志')
})

test('无统计数据时渲染显式提示（不是把统计条藏起来）', () => {
  const bar = code('src/components/LogStorageBar.vue')
  assert.match(bar, /v-else-if="unavailable" class="form-tip-line">该日志暂无统计数据</, '缺行必须有可见归宿')
})

test('日志统计条消费 rows_unavailable：保持条数口径并标注不可用', () => {
  // 主题归属：日志统计条用例放在日志统计 spec 中（此前混在管理 TLS 证书
  // spec 里，查日志条不会想到那个文件）。
  const bar = code('src/components/LogStorageBar.vue')
  // 响应类型声明在取数层组合子（LogStorageBar 只消费其 info）。
  assert.match(code('src/composables/useLogStorageStats.ts'), /rows_unavailable\?: boolean/, '响应字段类型必须声明')
  // 出现判定必须真正消费该 flag：后端改为「保留上次行数 + flag=true」时，陈旧
  // 行数不得被当有效值（仅用 rows == null 推导会让 flag 成为死字段）。
  // 该判定是单表达式箭头体（无块体可配对），按行切片。
  const rowsUnavailable = section(bar, 'const rowsUnavailable = computed', '\n')
  assert.match(rowsUnavailable, /rows_unavailable === true/, 'rows_unavailable 必须驱动不可用判定')
  assert.match(rowsUnavailable, /rows == null/, '行数缺席同样按不可用呈现')
  assert.doesNotMatch(rowsUnavailable, /rows != null/, '不得反转为「有行数即可用」')
  const sizeText = section(bar, 'const sizeText = computed(', '\n})\n')
  assert.match(sizeText, /计数暂不可用 \/ /, '行数缺席时保持条数口径文案')
  assert.match(sizeText, /rowsUnavailable\.value/, '文案必须取统一不可用判定（flag 与 null 同口径）')
  assert.doesNotMatch(
    section(bar, 'const sizeText = computed(', '\n})\n'),
    /if \(i\.limit_rows && i\.rows != null\)/,
    '不得在行数缺席时滑回字节口径',
  )
  const noteText = section(bar, 'const noteText = computed(', '\n})\n')
  assert.match(noteText, /行数暂不可用/, '附注必须披露计数不可用')
})

// rows_unavailable 的跨栈对表：前端响应类型与后端 json tag 必须同名字段
// （后端改名时前端类型不会报错，只会静默读 undefined）。
test('rows_unavailable 与后端 logstats.go 的 json tag 同源（跨栈钉）', () => {
  const go = repoCode('internal/handlers/logstats.go')
  assert.match(go, /RowsUnavailable bool\s+`json:"rows_unavailable,omitempty"`/, '后端 json tag 漂移')
  assert.match(
    code('src/composables/useLogStorageStats.ts'),
    /rows_unavailable\?: boolean/,
    '前端类型必须声明同名可选字段',
  )
})
