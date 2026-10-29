// securityStages（阶段化流水线投影）中**未被既有 spec 求值**的纯函数行为验收：
// 阶段出组判据（hasGeoIPControl / hasTrustEntries）、条目合并与计数、阶段页覆盖
// 解析、明细附着、版本比较、耗时格式化、宽松 id 解析与缓存订阅退订。
//
// 这些判据直接决定用户可见的阶段抽屉、阈值统计与「已配置」徽标；此前只有
// 源码文本钉或零覆盖。
//
// 运行：cd web && npm test

import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  attachStageDetails,
  compareVersion,
  createIpMatcher,
  ensureSharedEntries,
  entryMatchesIp,
  formatDurationUs,
  hasGeoIPControl,
  hasTrustEntries,
  invalidateSharedEntriesCache,
  IP_LIST_CATEGORIES,
  mergeIpEntries,
  mergeIpEntryCount,
  mergeIpEntryValues,
  parseRefIds,
  parseUnknownIds,
  POLICY_TYPE_LABELS,
  POLICY_TYPE_SHORT_LABELS,
  resolveStageOverride,
  STAGE_TITLES,
  subscribeSharedEntriesCache,
  type RuleStageModel,
  type SecurityPolicyType,
  type SecurityStageIPList,
  type StageGroup,
  type StagePolicyGroup,
} from '../src/utils/securityStages.ts'
import { code, source, webFiles } from './_helpers.ts'
// 夹具单源：policy 的字段清单在 fixtures/stagePolicy.ts 维护（本文件默认值与其一致，无差异 override）
import { stagePolicy as policy } from './fixtures/stagePolicy.ts'

const entryList = (id: number, values: string[], count?: number): SecurityStageIPList => ({
  id,
  name: `名单 ${id}`,
  entry_count: count ?? values.length,
  entries: values.map((value) => ({ value })),
})

test('parseRefIds：JSON 数字数组，坏数据/非正/小数一律丢弃', () => {
  assert.deepEqual(parseRefIds('[1,5]'), [1, 5])
  assert.deepEqual(parseRefIds('["3","7"]'), [3, 7])
  assert.deepEqual(parseRefIds('[0,-2,2.5,4]'), [4])
  assert.deepEqual(parseRefIds('{"a":1}'), [])
  assert.deepEqual(parseRefIds('not-json'), [])
  assert.deepEqual(parseRefIds(''), [])
  assert.deepEqual(parseRefIds(undefined), [])
})

test('parseUnknownIds：数字或 { id } 对象两形态，其余丢弃', () => {
  assert.deepEqual(parseUnknownIds([1, { id: 2 }, { name: 'x' }, '3', 0, { id: '4' }]), [1, 2])
  assert.deepEqual(parseUnknownIds('not-array'), [])
  assert.deepEqual(parseUnknownIds([]), [])
})

test('mergeIpEntryValues：trim + 精确去重 + 空串剔除（跨引用组同口径）', () => {
  assert.deepEqual(
    mergeIpEntryValues([' 1.1.1.1 ', '1.1.1.1', ''], [['2.2.2.2'], [' 2.2.2.2 ', '3.3.3.3']]),
    ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
  )
  assert.deepEqual(mergeIpEntryValues([], []), [])
})

test('mergeIpEntries：缺失的引用列表跳过（防御性回退为仅内联）', () => {
  const lists = [entryList(3, ['2.2.2.2', '3.3.3.3'])]
  assert.deepEqual(mergeIpEntries(lists, ['1.1.1.1'], [3, 99]), ['1.1.1.1', '2.2.2.2', '3.3.3.3'])
})

test('mergeIpEntryCount：内联去重数 + Σ引用 entry_count', () => {
  // 列表载荷不内联 entries 时计数仍可用（只依赖 entry_count）
  const lists: SecurityStageIPList[] = [
    { id: 3, name: 'A', entry_count: 10, entries: [] },
    { id: 4, name: 'B', entry_count: 5, entries: [] },
  ]
  assert.equal(mergeIpEntryCount(lists, ['1.1.1.1', ' 1.1.1.1 ', ''], [3, 4]), 16)
  // 缺失名单不计入；无内联时只计引用
  assert.equal(mergeIpEntryCount(lists, [], [4, 99]), 5)
})

test('hasTrustEntries：内联或引用任一非空即为真（阶段 0 出组判据）', () => {
  assert.equal(hasTrustEntries({ ip_whitelist: '["1.1.1.1"]', ip_whitelist_refs: '[]' }), true)
  assert.equal(hasTrustEntries({ ip_whitelist: '[]', ip_whitelist_refs: '[2]' }), true)
  assert.equal(hasTrustEntries({ ip_whitelist: '[]', ip_whitelist_refs: '[]' }), false)
  assert.equal(hasTrustEntries({}), false)
  assert.equal(hasTrustEntries({ ip_whitelist: 'bad-json' }), false)
})

test('hasGeoIPControl：显式字段按「模式非 off 且区域非空」，缺省回退摘要标志', () => {
  assert.equal(hasGeoIPControl({ geoip_mode: 'deny', geoip_countries: '["CN"]' }), true)
  assert.equal(hasGeoIPControl({ geoip_mode: 'allow', geoip_countries: '["US"]' }), true)
  assert.equal(hasGeoIPControl({ geoip_mode: 'off', geoip_countries: '["CN"]' }), false)
  assert.equal(hasGeoIPControl({ geoip_mode: 'deny', geoip_countries: '[]' }), false)
  assert.equal(hasGeoIPControl({ geoip_mode: '', geoip_countries: '["CN"]' }), false)
  assert.equal(hasGeoIPControl({ geoip_mode: 'deny', geoip_countries: 'bad-json' }), false)
  // 摘要接口形态（无显式字段）只看 has_geoip
  assert.equal(hasGeoIPControl({ has_geoip: true }), true)
  assert.equal(hasGeoIPControl({ has_geoip: false }), false)
})

test('resolveStageOverride：0=跟随策略；页缺失/内容空=broken；状态码兜底 403', () => {
  const pages = [
    { id: 5, name: '自定义拦截页', content: '<html>' },
    { id: 6, name: '空页面', content: '' },
  ]
  assert.equal(resolveStageOverride(0, 403, pages), null)
  assert.equal(resolveStageOverride(undefined, undefined, pages), null)
  assert.deepEqual(resolveStageOverride(5, 0, pages), { pageId: 5, pageName: '自定义拦截页', status: 403, broken: false })
  assert.deepEqual(resolveStageOverride(5, 429, pages), { pageId: 5, pageName: '自定义拦截页', status: 429, broken: false })
  assert.deepEqual(resolveStageOverride(6, 403, pages), { pageId: 6, pageName: '空页面', status: 403, broken: true })
  // 页已删除：名称回退为「页面 #id」且 broken（渲染侧等同未配）
  assert.deepEqual(resolveStageOverride(42, 403, pages), { pageId: 42, pageName: '页面 #42', status: 403, broken: true })
})

const stageGroup = (stage: 0 | 1 | 2 | 3, groups: StagePolicyGroup[]): StageGroup => ({
  stage,
  title: `阶段 ${stage}`,
  enabled: groups.length > 0,
  override: null,
  groups,
})

test('attachStageDetails：按策略 id 附着明细，缺策略的组不附着（不改其余字段）', () => {
  const model: RuleStageModel = {
    ruleDisabled: false,
    hasAnyPolicy: true,
    stages: [
      stageGroup(0, [
        { key: 7, order: 0, name: '信任', enabled: true, rows: [] },
        { key: 8, order: 1, name: '缺失策略', enabled: true, rows: [] },
      ]),
      stageGroup(1, []),
      stageGroup(2, []),
      stageGroup(3, []),
    ],
  }
  const attached = attachStageDetails(model, {
    policies: [policy({ id: 7, ip_whitelist: '["1.1.1.1"]' })],
    ipLists: [],
  })
  const stageZero = attached.stages[0]
  assert.equal(stageZero.groups[0]?.details?.trustEntries?.length, 1)
  assert.equal(stageZero.groups[0]?.details?.trustEntries?.[0]?.value, '1.1.1.1')
  assert.equal(stageZero.groups[1]?.details, undefined)
  // 不可变：原模型不被就地修改
  assert.equal(model.stages[0]?.groups[0]?.details, undefined)
})

test('compareVersion：段数值比较，v 前缀与长短段等价', () => {
  assert.ok(compareVersion('1.10', '1.9') > 0)
  assert.ok(compareVersion('v1.9', '1.10') < 0)
  assert.equal(compareVersion('v1.2.3', '1.2.3'), 0)
  assert.equal(compareVersion('1.2', '1.2.0'), 0)
  assert.ok(compareVersion('2.0.0', '1.99.99') > 0)
  // 设计边界（不是「语义正确」）：非数字段按字符串序比较，因此预发布后缀被
  // 判为更新（'beta' > ''），与 semver「无后缀 > 有后缀」相反。消费方唯一
  // （securityLibraries 的各源 version 最大值）当前只处理日期形态（2026.10.01），
  // 预发布形态不可达；未来若引入 -beta/-rc，必须先改实现并同步本断言。
  assert.ok(compareVersion('1.0.0-beta', '1.0.0') > 0, '设计边界：预发布方向与 semver 相反（消费方仅日期形态）')
})

// 跨栈共享夹具：与 Go internal/services 的 compareLibraryVersion 同读一份
// （web/tests/fixtures/version-compare.tsv）。两端各自维护用例表曾让
// 「缺段 vs 数值 0」判定相反（前端等价、Go 走字符串兜底）而两边都绿。
test('compareVersion：跨栈共享夹具（Go 同源）', () => {
  const fixture = readFileSync(new URL('./fixtures/version-compare.tsv', import.meta.url), 'utf8')
  let checked = 0
  for (const [index, line] of fixture.split('\n').entries()) {
    if (line.startsWith('#') || line.trim() === '') continue
    const fields = line.split('\t')
    assert.equal(fields.length, 3, `夹具第 ${index + 1} 行字段数`)
    const a = fields[0] as string
    const b = fields[1] as string
    const want = Number((fields[2] as string).trim())
    // `|| 0` 把 Math.sign 的 -0 归一为 0，与夹具的 0 可直接比较。
    assert.equal((Math.sign(compareVersion(a, b)) || 0), want, `夹具第 ${index + 1} 行 ${JSON.stringify(a)} vs ${JSON.stringify(b)}`)
    assert.equal((Math.sign(compareVersion(b, a)) || 0), want === 0 ? 0 : -want, `夹具第 ${index + 1} 行反向 ${JSON.stringify(b)} vs ${JSON.stringify(a)}`)
    checked++
  }
  assert.ok(checked > 0, '跨栈夹具为空')
})

// 消费面机械钉：唯一消费方把各源日期 version 交给 compareVersion；新消费方
// 出现时先红并重新评估预发布语义。其它视图允许正常出现 beta/rc 文案。
test('compareVersion 消费面与版本形态约束', () => {
  const lib = code('src/utils/securityLibraries.ts')
  assert.match(lib, /\.sort\(compareVersion\)/, '唯一消费点是各源版本最大值')
  // 文档钉（断言对象是注释文字）：compareVersion 注释必须声明消费形态边界。
  assert.match(source('src/utils/securityStages.ts'), /日期形态/, 'compareVersion 文档必须声明设计边界形态')
  const files = webFiles('src', ['.ts', '.vue'])
  if (files.length < 50) {
    assert.fail(`扫描面过小（src 下仅 ${files.length} 个源文件）——目录遍历失效`)
  }
  const definition = 'src/utils/securityStages.ts'
  const consumers = files.filter((file) => file !== 'src/utils/securityLibraries.ts' && file !== definition && code(file).includes('compareVersion'))
  assert.deepEqual(consumers, [], `compareVersion 出现新消费方（需重新评估预发布形态边界）：${consumers.join(', ')}`)
})

test('formatDurationUs：0/缺省 → 占位，三档精度', () => {
  assert.equal(formatDurationUs(0), '—')
  assert.equal(formatDurationUs(undefined), '—')
  assert.equal(formatDurationUs(-1), '—')
  assert.equal(formatDurationUs(999), '0.999ms')
  assert.equal(formatDurationUs(1500), '1.5ms')
  assert.equal(formatDurationUs(12345), '12ms')
})

test('subscribeSharedEntriesCache：写回通知订阅者，退订后不再回调（无泄漏）', async () => {
  invalidateSharedEntriesCache()
  let hits = 0
  const unsubscribe = subscribeSharedEntriesCache(() => { hits++ })
  await ensureSharedEntries([11], async () => ['1.1.1.1'])
  assert.equal(hits, 1, '写回必须通知订阅者')
  unsubscribe()
  await ensureSharedEntries([12], async () => ['2.2.2.2'])
  assert.equal(hits, 1, '退订后不得再回调')
  invalidateSharedEntriesCache()
})

// 文案即契约：四张用户可见文案表此前零断言——误改/缺键会直出 undefined 或
// 错阶段归属（Vue 模板不报错），且与仓内 settingsPages/strategyLabels 的
// 「可见文案显式钉」口径不一致。
test('阶段标题/策略类型标签/名单类别：文案与键集即契约', () => {
  assert.deepEqual(STAGE_TITLES, {
    0: '阶段 0 · 信任名单',
    1: '阶段 1 · IP 访问控制',
    2: '阶段 2 · 限流',
    3: '阶段 3 · WAF',
  })

  const policyTypes: SecurityPolicyType[] = ['stage0', 'stage1', 'stage2', 'stage3', 'mixed']
  assert.deepEqual(Object.keys(POLICY_TYPE_LABELS).sort(), [...policyTypes].sort(), 'POLICY_TYPE_LABELS 键集必须等于 SecurityPolicyType 全枚举')
  assert.deepEqual(Object.keys(POLICY_TYPE_SHORT_LABELS).sort(), [...policyTypes].sort(), '短标签键集同样必须覆盖全枚举')
  for (const type of policyTypes) {
    const label = POLICY_TYPE_LABELS[type]
    assert.equal(typeof label, 'string')
    assert.ok(label.length > 0, `${type} 标签缺失（模板会渲染空值）`)
    assert.ok(POLICY_TYPE_SHORT_LABELS[type].length > 0, `${type} 短标签缺失`)
  }
  // 阶段类型标签与 STAGE_TITLES 单源（措辞微调不需双处同步）
  assert.equal(POLICY_TYPE_LABELS.stage1, STAGE_TITLES[1])
  assert.equal(POLICY_TYPE_SHORT_LABELS.stage3, '阶段 3')
  assert.equal(POLICY_TYPE_LABELS.mixed, '混合策略（兼容旧版）')

  // 名单类别是写入值（落库 category）与筛选口径：值与顺序都钉住。
  assert.deepEqual([...IP_LIST_CATEGORIES], ['搜索引擎爬虫', 'CDN 节点', '云服务商', '办公网络', '数据中心', '可信地址', '恶意 IP', '其他'])
})

// 事件详情弹框的多结论扫描走 createIpMatcher（IP 只解析一次），逐条路径走
// entryMatchesIp。两者语义必须等价——否则弹框的命中结论与名单判定表分叉，
// 而排障场景下用户只看到结论面。差分用例：同一 (ip, entries) 集合逐个比对，
// 并附命中/未命中样本，防止「两边同时恒 false」的伪等价。
test('createIpMatcher 与 entryMatchesIp 差分等价（v4/v6、CIDR 边界、族隔离、非法条目）', () => {
  const cases: Array<{ ip: string; entries: readonly string[] }> = [
    {
      ip: '10.0.0.5',
      entries: ['10.0.0.5', '10.0.0.6', '10.0.0.0/24', '10.0.1.0/24', '0.0.0.0/0', '10.0.0.5/32',
        '10.0.0.6/32', '::/0', '::1', 'banana', '10.0.0.0/33', '10.0.0.0/-1', ''],
    },
    {
      ip: '2001:db8::1',
      entries: ['2001:db8::1', '2001:db8::2', '2001:db8::/32', '2001:db9::/32', '::/0', '::1/128',
        '2001:db8::1/128', '0.0.0.0/0', '10.0.0.5', '::/129', 'zz::1/64'],
    },
    { ip: '255.255.255.255', entries: ['255.255.255.0/24', '0.0.0.0/1', '128.0.0.0/1'] },
    { ip: 'not-an-ip', entries: ['not-an-ip', 'not-an-ip/8', '10.0.0.0/8'] },
  ]
  for (const { ip, entries } of cases) {
    const matcher = createIpMatcher(ip)
    for (const entry of entries) {
      assert.equal(matcher(entry), entryMatchesIp(entry, ip), `差分不一致：ip=${ip} entry=${entry}`)
    }
  }
  // 真命中样本（差分两侧同变时靠这组守）
  const v4 = createIpMatcher('10.0.0.5')
  assert.equal(v4('10.0.0.0/24'), true)
  assert.equal(v4('10.0.1.0/24'), false)
  assert.equal(v4('10.0.0.5'), true)
  const v6 = createIpMatcher('2001:db8::1')
  assert.equal(v6('2001:db8::/32'), true)
  assert.equal(v6('2001:db9::/32'), false)
  // /0 只在本族生效：IPv6 /0 不得命中 IPv4 地址，反之亦然
  assert.equal(v6('::/0'), true)
  assert.equal(v6('0.0.0.0/0'), false)
  assert.equal(v4('::/0'), false)
})
