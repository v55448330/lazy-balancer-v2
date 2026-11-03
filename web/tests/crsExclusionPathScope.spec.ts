// CRS 排除规则 path 作用域 + 目标自动补全（目录端点）钉测：
//   A. parseCrsExcludedRules 四态行为——scope:'path' 新增（path 归一/256 上限/非 path 剥离），
//      旧三态（all/ip/list）行为回归钉（ips 逗号串→数组、listRefs 数字过滤、旧字符串行归一 all）
//   B. 目录建议过滤——id 数字前缀 ∪ msg 关键字不分大小写，上限 50，空查询不弹建议
//   C. 目录加载——GET /security/crs-rules（silent）成功落地 / 失败静默降级（自由输入不阻塞、
//      可重试）/ 惰性一次（同会话缓存不重复请求、并发单飞）
//   D. 视图接线钉——scope 路径选项、行内 path 输入、序列化仅 path 带 path 字段、tip 文案、
//      el-autocomplete 接线（级联退役）、WAF 步骤惰性加载、只读详情「路径 /api/x」汇总
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section, member, registerModuleHooks, drainMicrotasks } from './_helpers.ts'
import { installStubHost, STUB_API } from './_stubs.ts'

registerModuleHooks({ '@/utils/api': STUB_API })

interface CrsDirectoryEntry { id: string; msg: string; file: string; category?: string }
interface CrsDirectorySuggestion { value: string; label: string; file: string; fullMsg: string }
interface CrsExcludedRow { target: string; scope: string; ips: string[]; listRefs: number[]; path: string }

// 动态 import：静态 import 会在钩子注册前装载真实 api.ts（axios + DOM 依赖）
const { parseCrsExcludedRules, filterCrsDirectorySuggestions, useCrsRuleDirectory } =
  await import('../src/composables/useCrsRuleIndex.ts') as {
    parseCrsExcludedRules: (raw: string | undefined | null) => CrsExcludedRow[]
    filterCrsDirectorySuggestions: (entries: CrsDirectoryEntry[], query: string, limit?: number) => CrsDirectorySuggestion[]
    useCrsRuleDirectory: () => { loaded: { value: boolean }; ensure: () => Promise<void>; search: (query: string) => CrsDirectorySuggestion[] }
  }

// ── A. parse 四态行为 ──

test('path 作用域：对象行解析出 scope:path + path 字段（前缀匹配语义由渲染层承载）', () => {
  const rows = parseCrsExcludedRules(JSON.stringify([
    { target: '942100', scope: 'path', ips: '', listRefs: [], path: '/api/upload' },
    { target: '949100', scope: 'path', ips: '', listRefs: [], path: ' /ops/metrics ' },
  ]))
  assert.deepEqual(rows, [
    { target: '942100', scope: 'path', ips: [], listRefs: [], path: '/api/upload' },
    { target: '949100', scope: 'path', ips: [], listRefs: [], path: '/ops/metrics' },
  ])
})

test('path 上限 256：超长路径读取侧截断（与编辑器 maxlength 同一口径）', () => {
  const long = '/a'.repeat(200)
  const rows = parseCrsExcludedRules(JSON.stringify([{ target: '942100', scope: 'path', ips: '', listRefs: [], path: long }]))
  assert.equal(rows[0]?.path.length, 256, '超长 path 必须截到 256')
})

test('旧三态回归：all/ip/list 行为不变，path 字段归一为空串', () => {
  const rows = parseCrsExcludedRules(JSON.stringify([
    { target: '942100', scope: 'all', ips: '', listRefs: [], path: '/leaked' },
    { target: '942110', scope: 'ip', ips: '1.1.1.1,10.0.0.0/8', listRefs: [] },
    { target: '59', scope: 'list', ips: '', listRefs: [2, 'x', 0] },
    'REQUEST-942-100-APPLICATION-ATTACK-SQLI.conf',
    { target: '942120' },
  ]))
  assert.deepEqual(rows, [
    { target: '942100', scope: 'all', ips: [], listRefs: [], path: '' },
    { target: '942110', scope: 'ip', ips: ['1.1.1.1', '10.0.0.0/8'], listRefs: [], path: '' },
    { target: '59', scope: 'list', ips: [], listRefs: [2], path: '' },
    { target: 'REQUEST-942-100-APPLICATION-ATTACK-SQLI.conf', scope: 'all', ips: [], listRefs: [], path: '' },
    { target: '942120', scope: 'all', ips: [], listRefs: [], path: '' },
  ])
})

test('未知 scope 与空 path 兜底：scope 归 all、path 不外溢', () => {
  const rows = parseCrsExcludedRules(JSON.stringify([
    { target: '942100', scope: 'subnet', ips: '', listRefs: [], path: '/x' },
    { target: '942110', scope: 'path', ips: '', listRefs: [], path: 42 },
  ]))
  assert.deepEqual(rows, [
    { target: '942100', scope: 'all', ips: [], listRefs: [], path: '' },
    { target: '942110', scope: 'path', ips: [], listRefs: [], path: '' },
  ])
})

// ── B. 目录建议过滤（数据源 = 既有端点 /security/crs/rule-index，id 为字符串数字） ──

const DIRECTORY: CrsDirectoryEntry[] = [
  { id: '901044', msg: 'Init: Exclusion Setup', file: 'REQUEST-901-044-INIT-EXCLUSION.conf', category: 'init' },
  { id: '920100', msg: 'Body Parser: Request Body Missing', file: 'REQUEST-920-100-BODY-PARSING.conf', category: 'body' },
  { id: '942100', msg: 'SQLi: SQL Injection Attack Detected', file: 'REQUEST-942-100-APPLICATION-ATTACK-SQLI.conf', category: 'sqlinj' },
  { id: '942110', msg: 'sqli filter bypass attempt', file: 'REQUEST-942-110-APPLICATION-ATTACK-SQLI.conf', category: 'sqlinj' },
  { id: '949110', msg: 'Blocking Evaluation: anomaly score', file: 'REQUEST-949-110-BLOCKING-EVALUATION.conf', category: 'eval' },
]

test('建议过滤：id 字符串数字前缀命中（942 → 942100/942110，不含 949 组）', () => {
  const hits = filterCrsDirectorySuggestions(DIRECTORY, '942')
  assert.deepEqual(hits.map((s) => s.value), ['942100', '942110'])
  assert.equal(hits[0]?.file, 'REQUEST-942-100-APPLICATION-ATTACK-SQLI.conf')
})

test('建议过滤：msg 关键字不分大小写（SQLI / sqli 均命中两条 SQLi 规则）', () => {
  for (const query of ['SQLI', 'sqli', 'Sqli']) {
    const hits = filterCrsDirectorySuggestions(DIRECTORY, query)
    assert.deepEqual(hits.map((s) => s.value), ['942100', '942110'], `query=${query}`)
  }
})

test('建议过滤：901 初始化规则不出建议（后端硬拒提供，老级联剔除口径延续）', () => {
  const hits = filterCrsDirectorySuggestions(DIRECTORY, '901')
  assert.deepEqual(hits.map((s) => s.value), [], '901xxx 不得进入建议')
  const all = filterCrsDirectorySuggestions(DIRECTORY, '9')
  assert.ok(!all.some((s) => s.value.startsWith('901')), '全量前缀下 901 仍须剔除（949/959 保留可选）')
})

test('建议过滤：无命中与空查询返回空建议（目录缺失时输入框退化为自由输入）', () => {
  assert.deepEqual(filterCrsDirectorySuggestions(DIRECTORY, '不存在'), [])
  assert.deepEqual(filterCrsDirectorySuggestions(DIRECTORY, ''), [])
  assert.deepEqual(filterCrsDirectorySuggestions(DIRECTORY, '   '), [])
  assert.deepEqual(filterCrsDirectorySuggestions([], '942'), [])
})

test('建议上限 50：60 条命中只取前 50（目录按 id 升序截断）', () => {
  const many: CrsDirectoryEntry[] = Array.from({ length: 60 }, (_, i) => ({
    id: String(944000 + i),
    msg: `Generic rule ${i}`,
    file: 'REQUEST-944-100-GENERIC.conf',
  }))
  const hits = filterCrsDirectorySuggestions(many, '944')
  assert.equal(hits.length, 50)
  assert.equal(hits[0]?.value, '944000')
  assert.equal(hits[49]?.value, '944049')
})

// ── C. 目录加载（惰性一次 / 失败降级 / 可重试 / 并发单飞） ──

const g = globalThis as unknown as { __gets?: Array<{ url: string; config?: Record<string, unknown> }>; __get?: (url: string, config?: unknown) => Promise<unknown> }

test('目录加载（rule-index 端点）：失败静默降级 → 重试成功（并发单飞）→ 同会话不再重发', async () => {
  const host = installStubHost()
  host.reset()
  g.__gets = []
  const { loaded, ensure, search } = useCrsRuleDirectory()

  // 1) 首次失败：静默（不抛出），loaded=false，建议恒空（自由输入降级）
  g.__get = async () => { throw new Error('network down') }
  await ensure()
  assert.equal(loaded.value, false, '失败不得置 loaded')
  assert.deepEqual(search('942'), [])
  assert.equal(g.__gets.length, 1)
  assert.equal(g.__gets[0]?.url, '/security/crs/rule-index')
  assert.equal(g.__gets[0]?.config?.silent, true, '目录失败已由组合子降级，不得叠加全局 toast')

  // 2) 重试（loaded=false 允许同会话重试）：并发两路 ensure 单飞一次请求，成功落地
  g.__gets = []
  const { promise: slow, resolve: release } = Promise.withResolvers<{ data: { rules: CrsDirectoryEntry[]; version: string } }>()
  g.__get = () => slow
  const p1 = ensure()
  const p2 = ensure()
  await drainMicrotasks()
  assert.equal(g.__gets.length, 1, '并发 ensure 必须单飞去重')
  release({ data: { rules: DIRECTORY, version: 'v4.15.0' } })
  await Promise.all([p1, p2])
  assert.equal(loaded.value, true)
  assert.deepEqual(search('942100').map((s) => s.value), ['942100'])

  // 3) 已加载后再 ensure：不重复请求（惰性一次）
  g.__gets = []
  await ensure()
  assert.equal(g.__gets.length, 0, '已加载后不得重发目录请求')
})

// ── D. 视图接线钉 ──

const page = code('src/views/security/SecurityPolicies.vue')

test('scope radios 新增路径 URI 选项，行内 path 输入框（前缀匹配提示 + 256 上限）', () => {
  const radios = section(page, '<el-radio-group v-model="row.scope"', '</el-radio-group>')
  assert.match(radios, /<el-radio value="all">全部 IP<\/el-radio>/, '旧选项回归钉')
  assert.match(radios, /<el-radio value="ip">指定 IP<\/el-radio>/, '旧选项回归钉')
  assert.match(radios, /<el-radio value="list">地址列表<\/el-radio>/, '旧选项回归钉')
  assert.match(radios, /<el-radio value="path">路径 URI<\/el-radio>/)

  const pathInput = section(page, 'v-else-if="row.scope === \'path\'"', '/>')
  assert.match(pathInput, /v-model="row\.path"/)
  assert.match(pathInput, /placeholder="如 \/api\/upload（前缀匹配）"/)
  assert.match(pathInput, /class="exclusion-scope-control-path"/)
  assert.match(pathInput, /maxlength="256"/)
})

test('序列化：仅 scope=path 带 path 字段；旧三态序列化形状逐字不变', () => {
  const serialized = member(page, 'const serializedExcludedRules')
  assert.match(serialized, /row\.scope === 'path'/, 'path 作用域必须带 path 字段')
  // 旧三态：非 path 行不得携带 path 键（payload 与历史字节兼容）
  assert.match(serialized, /ips: row\.scope === 'ip' \? \[\.\.\.row\.ips\] : \[\]/)
  assert.match(serialized, /listRefs: row\.scope === 'list' \? \[\.\.\.row\.listRefs\] : \[\]/)
  // 全空行判定含 path（只填了路径未选目标的行不得被静默丢弃）
  assert.match(serialized, /target === '' && row\.ips\.length === 0 && row\.listRefs\.length === 0 && path === ''/)
  // 去重键含 path（同目标同 scope 不同路径是两条不同排除）
  assert.match(serialized, /const key = `[^`]*\$\{path\}`/)
})

test('校验与作用域切换：path 作用域必填路径；切换清残留对称扩展', () => {
  // section 切片（member 的花括号配对不含正则字面量，validate 体内含正则校验）
  const validate = section(page, 'const validateExcludedRules', '\n}')
  assert.match(validate, /（路径 URI）未填写路径/, '必填钉（后端 400 最终裁决，此处前置拦截）')
  assert.match(validate, /以 \/ 开头/, 'BE 契约：路径必须以 / 开头，FE 前置拦截避免保存卡 400')
  assert.match(validate, /含非法字符/, 'BE 契约：无空白/控制字符/双引号/反斜杠，FE 前置拦截')
  assert.match(validate, /（指定 IP）未填写 IP/, '旧校验回归钉')
  assert.match(validate, /（地址列表）未选择列表/, '旧校验回归钉')

  const scopeChange = member(page, 'const onScopeChange')
  assert.match(scopeChange, /row\.path = ''/, '离开 path 作用域必须清残留路径')
  assert.match(scopeChange, /else \{ row\.ips = \[\]; row\.listRefs = \[\] \}/, '进入 path 作用域清 IP/列表残留')
  // 待校验行判定含 path（只填路径的行必须走校验门）
  const filled = section(page, 'const isFilledExclusionRow', '\nconst validateExcludedRules')
  assert.match(filled, /row\.path/)
})

test('tip 文案：两处作用域说明更新为 IP/地址列表/路径', () => {
  assert.equal((page.match(/作用域限定排除仅对所选来源 IP\/地址列表\/路径生效/g) ?? []).length, 2, '空态提示与表尾提示同文案各一处')
})

test('target 自动补全：el-autocomplete 接线目录数据源，级联退役', () => {
  const autocomplete = section(page, '<el-autocomplete', '</el-autocomplete>')
  assert.match(autocomplete, /v-model="row\.target"/)
  assert.match(autocomplete, /:fetch-suggestions="fetchExclusionSuggestions"/)
  assert.match(autocomplete, /popper-class="crs-rule-popper"/)
  assert.match(autocomplete, /class="exclusion-target-select"/)
  // 降级不阻塞：占位符披露自由输入能力（目录缺失/失败时纯输入仍可提交）
  assert.match(autocomplete, /placeholder="[^"]*输入[^"]*"/)
  // 建议项两列：id 列 + 描述列（msg（file））
  assert.match(autocomplete, /crs-rule-suggestion/)
  // 级联退役：排除行单元内不再出现 el-cascader（CRS 规则组/区域选择 cascader 不在本列）
  const rowCell = section(page, '<div class="exclusion-row-cell">', '</el-radio-group>')
  assert.doesNotMatch(rowCell, /<el-cascader/)
  assert.doesNotMatch(page, /crsExclusionCascaderProps/, '排除级联 props 必须移除')
  assert.doesNotMatch(page, /exclusionTargetPath/, '级联回填函数必须移除')
  assert.doesNotMatch(page, /onExclusionTargetChange/, '级联写回函数必须移除')
  // 建议数据源单源：composable 目录搜索
  assert.match(page, /searchCrsDirectory/)
})

test('WAF 步骤首次进入惰性加载目录一次', () => {
  const stepWatch = section(page, 'watch(currentStep, (step) => {', '\n})')
  assert.match(stepWatch, /WIZARD_STEP\.WAF_RULES/)
  assert.match(stepWatch, /ensureCrsDirectory\(\)/)
  assert.match(page, /useCrsRuleDirectory\(\)/)
})

test('新增行与只读详情：addExcludedRule 带 path 空串；详情排除行披露「路径 /api/x」', () => {
  const addRow = member(page, 'const addExcludedRule')
  assert.match(addRow, /path: ''/)

  const detail = member(page, 'const viewPolicySections')
  assert.match(detail, /excludedPaths/, '路径作用域排除必须在只读详情披露')
  assert.match(detail, /（路径 /)
  assert.match(detail, /value: excludedPaths\.length > 0/, '排除规则行值必须按路径作用域展开')
})
