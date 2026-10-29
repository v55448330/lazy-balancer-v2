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

import { registerModuleHooks, repoCode, section, code, codeSection, deferred, flushMicrotasks } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'

const flush = flushMicrotasks

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

// ── 安全事件待补采缓存（IPC 主路径 + 失败落 spool）────────────────────────
// 指标语义：IPC 正常时恒为 0；>0 表示主路径曾失败、这些事件尚未入库。
// 因此「0 条」「N 条」「计数读不到」「字段缺席」是四个不同事实，界面不得合并：
// 把缺席/失败显示成 0 条 = 把「情况不明」说成「一切正常」，是这指标最危险的误读。

const securityEventsStats = (over: Record<string, unknown> = {}): unknown => ({
  data: {
    logs: [
      {
        key: 'security_events',
        name: '安全事件',
        size_bytes: 0,
        rotated_bytes: 0,
        rotated_count: 0,
        keep_count: 0,
        limit_rows: 1_000_000,
        rows: 42,
        db_bytes: 1_048_576,
        cache_entries: 0,
        cache_bytes: 0,
        cache_limit_entries: 1000,
        cache_limit_bytes: 16_777_216,
        retention_note: '每日清理',
        config_source: '基础设置',
        ...over,
      },
    ],
  },
})

test('缓存计数透传：0 与 N 都原样到消费层（0 是有效值，不是缺席）', async () => {
  const target = ref({ logKey: 'security_events' })
  const refreshKey = ref(0)
  g.__get = async () => securityEventsStats({ cache_entries: 0, cache_bytes: 0 })
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  assert.equal(info.value?.cache_entries, 0, '0 条必须可读（界面据此显示「缓存 0 条」）')
  assert.equal(info.value?.cache_bytes, 0)

  refreshKey.value++
  g.__get = async () => securityEventsStats({ cache_entries: 7, cache_bytes: 4096 })
  await nextTick()
  await flush()
  assert.equal(info.value?.cache_entries, 7, '补采期间 N 条必须可读')
  assert.equal(info.value?.cache_bytes, 4096)
  assert.equal(info.value?.cache_limit_entries, 1000)
  assert.equal(info.value?.cache_limit_bytes, 16_777_216)
})

test('缓存计数失败：cache_unavailable 透传（不得折成 0 条）', async () => {
  const target = ref({ logKey: 'security_events' })
  const refreshKey = ref(0)
  g.__get = async () => securityEventsStats({ cache_entries: null, cache_unavailable: true })
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  assert.equal(info.value?.cache_unavailable, true)
  assert.equal(info.value?.cache_entries, null, '读不到就是 null，不得被改写成 0')
})

test('缓存字段在取数层声明为可选（旧后端 / 非安全事件行可为缺席）', () => {
  const types = code('src/composables/useLogStorageStats.ts')
  for (const decl of [
    'cache_entries?: number | null',
    'cache_bytes?: number | null',
    'cache_limit_entries?: number | null',
    'cache_limit_bytes?: number | null',
    'cache_unavailable?: boolean',
  ]) {
    assert.ok(types.includes(decl), `响应类型必须声明：${decl}`)
  }
})

test('安全事件行内：条数/行帽 + 缓存 N 条 + 库体量；审计日志文件体量退出容量位', () => {
  const sizeText = codeSection('src/components/LogStorageBar.vue', 'const sizeText = computed(', '\n})\n')
  assert.match(sizeText, /if \(i\.limit_rows\) \{/, '安全事件保持条数口径')
  assert.match(sizeText, /cacheCountText\.value/, '缓存条数必须出现在条数口径行内')
  assert.match(sizeText, /库 \$\{humanSize\(i\.db_bytes\)\}/, '库体量保留')
  assert.doesNotMatch(
    sizeText,
    /日志 \$\{humanSize\(i\.size_bytes\)\}/,
    'audit.log 文件体量（size_bytes）不得再当安全事件容量展示',
  )
  // 缓存段与行数可用性正交：行数缺失时仍要给缓存条数——它正是排查补采的入口。
  // 判据是「守卫条件」而不是逐字符等值：追加点的 if 只允许判缓存值本身非空，
  // 不得再叠加 rowsUnavailable（排版/换行/是否带大括号都不影响结论）。
  const cacheGuard = sizeText.match(/if \(([^)]*)\)\s*\{?\s*parts\.push\(cacheCountText\.value\)/)
  assert.ok(cacheGuard !== null, '缓存条数必须由独立的 if 追加（不得并入 rowsUnavailable 三元）')
  assert.equal(cacheGuard[1]!.trim(), 'cacheCountText.value', '缓存段不得挂在 rowsUnavailable 分支下')
})

test('缓存 0 条必须显示：0 不得被真值判断当成缺席', () => {
  const cacheCount = codeSection('src/components/LogStorageBar.vue', 'const cacheCountText = computed', '\n})\n')
  assert.match(cacheCount, /`缓存 \$\{i\.cache_entries\.toLocaleString\(\)\} 条`/, '条数文案单源')
  assert.doesNotMatch(cacheCount, /if \(i\.cache_entries\)/, '真值判断会把 0 条静默吞掉')
  assert.doesNotMatch(cacheCount, /cache_entries > 0/, '0 条是正常态，不得设 >0 门槛')
})

test('缓存计数不可用：显式「计数暂不可用」，不退化成 0 条', () => {
  const cacheCount = codeSection('src/components/LogStorageBar.vue', 'const cacheCountText = computed', '\n})\n')
  assert.match(cacheCount, /缓存计数暂不可用/, '失败态必须有自己的文案')
  assert.match(
    cacheCount,
    /cache_unavailable === true \|\| i\.cache_entries == null/,
    'flag 与缺席同口径（后端只留 flag 时不得当 0）',
  )
})

test('缓存字段缺席（旧后端 / 非安全事件行）：整段不渲染，也不谎称 0 条', () => {
  const cacheKnown = codeSection('src/components/LogStorageBar.vue', 'const cacheKnown = computed', '\n})')
  assert.match(cacheKnown, /i\.cache_entries != null \|\| i\.cache_unavailable === true/, '已知=有计数或有失败披露')
  const cacheCount = codeSection('src/components/LogStorageBar.vue', 'const cacheCountText = computed', '\n})\n')
  assert.match(cacheCount, /if \(!i \|\| !cacheKnown\.value\) return ''/, '缺席时不产出缓存段')
})

test('缓存口径说明：tooltip 讲清「IPC 失败后的待补采条目，正常应为 0」', () => {
  const cacheDetail = codeSection('src/components/LogStorageBar.vue', 'const cacheDetail = computed', '\n})\n')
  assert.match(cacheDetail, /缓存为 IPC 失败后的待补采条目，正常应为 0/, '缓存含义必须显式说明')
  assert.match(cacheDetail, /cache_limit_entries/, '条目上限进入 tooltip')
  assert.match(cacheDetail, /cache_limit_bytes/, '字节上限进入 tooltip')
  assert.match(cacheDetail, /cache_unavailable === true \|\| i\.cache_entries == null/, '失败态在 tooltip 同样披露')
  const tooltip = codeSection('src/components/LogStorageBar.vue', 'const tooltipContent = computed', '\n})\n')
  assert.match(tooltip, /cacheDetail\.value/, 'tooltip 必须带上缓存口径')
})

test('其他日志行口径不回归：字节/轮转文案保持原样', () => {
  const sizeText = codeSection('src/components/LogStorageBar.vue', 'const sizeText = computed(', '\n})\n')
  assert.match(
    sizeText,
    /if \(i\.limit_bytes\) return `\$\{humanSize\(i\.size_bytes\)\} \/ \$\{humanSize\(i\.limit_bytes\)\}`/,
    '字节上限行（Caddy/任务日志等）不变',
  )
  assert.match(sizeText, /return humanSize\(i\.size_bytes\)/, '无上限行仍按字节呈现')
  const noteText = codeSection('src/components/LogStorageBar.vue', 'const noteText = computed(', '\n})\n')
  assert.match(noteText, /满 \$\{humanSize\(i\.limit_bytes\)\} 轮转/, '轮转阈值文案不变')
  assert.match(noteText, /暂无归档（满额保留 \$\{i\.keep_count\} 份）/, '份数上限文案不变')
  assert.match(noteText, /超限按最旧优先清理/, '条数口径附注不变')
  // 缓存段只属于有该指标的日志行：通用路径（无 limit_rows）不得插入缓存字面量。
  const rowsBranch = section(sizeText, 'if (i.limit_rows) {', '\n  }\n')
  assert.match(rowsBranch, /cacheCountText\.value/)
  assert.doesNotMatch(
    sizeText.slice(sizeText.indexOf('if (i.limit_bytes)')),
    /cacheCountText/,
    '通用字节口径（Caddy/任务日志等）不得插入缓存段',
  )
})

// 纯库内行（操作日志=audit_log 表按保留期清理）没有轮转归档概念：keep_count=0
// 的通用分支会渲染「暂无归档」，在审计行上会被读成归档失败。后端以 db_backed
// 显式标记该形态，渲染层必须在归档文案之前消费它——跨栈同源（json tag 与前端
// 类型同名），否则后端加字段前端静默读 undefined，界面照旧说谎。
test('纯库内行 db_backed：keep_count=0 不得渲染「暂无归档」', () => {
  const go = repoCode('internal/handlers/logstats.go')
  assert.match(go, /DBBacked\s+bool\s+`json:"db_backed,omitempty"`/, '后端 json tag 漂移')
  assert.match(go, /Key: "audit"[^\n]*DBBacked: true/, '操作日志行必须带 db_backed 标记')
  assert.match(code('src/composables/useLogStorageStats.ts'), /db_backed\?: boolean/, '前端类型必须声明同名字段')
  const noteText = section(code('src/components/LogStorageBar.vue'), 'const noteText = computed(', '\n})\n')
  assert.match(noteText, /if \(i\.db_backed\)/, '渲染层必须消费 db_backed 标记')
  // 标记分支必须先于份数/时间戳归档文案返回：否则「暂无归档」仍会拼进去。
  const dbBranch = noteText.indexOf('if (i.db_backed)')
  const archiveBranch = noteText.indexOf('if (i.keep_count > 0)')
  assert.ok(dbBranch >= 0 && archiveBranch > dbBranch, 'db_backed 分支必须在归档文案分支之前')
})
