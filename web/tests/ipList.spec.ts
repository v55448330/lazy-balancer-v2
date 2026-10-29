// IP 名单弹框守卫与 CSV 往返验收
//   A. 详情在途/失败时保存必须禁用（否则空 entries 全量 PUT 清空名单）
//   B. 已有名单 + 空条目需二次确认；新建空名单不弹
//   C. 导出→导入逐字相等，二次往返不累积漂移（备注含逗号/引号/换行）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { IP_LIST_MAX_ENTRIES, canSaveIpList, needsEmptyListConfirm } from '../src/utils/ipListSaveGuard.ts'
import { formatIpListEntryLine, ipListRemarkMaxLength, parseIpListEntryLine } from '../src/utils/ipListCsv.ts'
// 注入本测试自己的正则会让「IPv6 CIDR」被文档化成
// 非法值，与生产注入的 isValidCidr（SecurityRules.vue CSV 导入）语义相反。
import { isValidCidr } from '../src/utils/ipAddress.ts'
import {
  ensureSharedEntries,
  invalidateSharedEntriesCache,
  missingSharedEntryIds,
  parseIPList,
  sharedEntriesCache,
} from '../src/utils/securityStages.ts'
import { code, member, repoCode } from './_helpers.ts'


test('规则流程只拉本规则阶段 0 策略的信任引用', () => {
  const src = code('src/components/RuleFlowDialog.vue')
  assert.match(src, /boundTrustPolicyIds/)
  assert.match(src, /if \(!boundTrustPolicyIds\.has\(pol\.id\)\) continue/)
})

test('A 保存守卫：加载中/失败两种形态均禁止保存', () => {
  assert.equal(canSaveIpList(false, false), true)
  assert.equal(canSaveIpList(true, false), false, '详情在途：entries 为空，禁止保存')
  assert.equal(canSaveIpList(false, true), false, '详情失败：必须禁止保存')
  assert.equal(canSaveIpList(true, true), false)
})

test('B 空条目确认：仅已有名单触发（新建空名单是合法操作）', () => {
  assert.equal(needsEmptyListConfirm(12, 0), true)
  assert.equal(needsEmptyListConfirm(12, 3), false)
  assert.equal(needsEmptyListConfirm(null, 0), false)
})

test('并发合并差集内核不作为公共导出泄漏', () => {
  assert.doesNotMatch(code('src/utils/ipListSaveGuard.ts'), /export function entriesMissingFromPayload/)
})

// 消费侧接线：守卫被删后纯函数用例仍全绿——详情加载中/失败时保存可点，
// entries 为空 → 全量 PUT 清空既有名单。
test('A/B 守卫接到规则页：保存禁用绑定与空条目二次确认', () => {
  const rules = code('src/views/security/SecurityRules.vue')
  assert.match(
    rules,
    /:disabled="!canSaveIpList\(\s*loadingIpListDetail,\s*ipListDetailFailed\s*\)"/,
    '保存按钮必须绑定 canSaveIpList（否则加载中/失败可保存并清空名单）',
  )
  assert.match(
    rules,
    /if \(needsEmptyListConfirm\(\s*editingIpListId\.value,\s*entries\.length\s*\)\)/,
    '既有名单清空必须走二次确认',
  )
})

test('C1 CSV 往返：备注含逗号/引号逐字相等', () => {
  const value = '10.0.0.1'
  const remark = '备注,含逗号"和引号"'
  const line = formatIpListEntryLine(value, remark)
  assert.equal(line, '10.0.0.1,"备注,含逗号""和引号"""')
  assert.deepEqual(parseIpListEntryLine(line, isValidCidr), { value, remark })
})

test('C2 二次往返不累积漂移', () => {
  let remark = 'a,"b",c'
  let line = formatIpListEntryLine('192.168.1.0/24', remark)
  for (let i = 0; i < 3; i++) {
    const parsed = parseIpListEntryLine(line, isValidCidr)
    assert.ok(parsed && 'value' in parsed)
    assert.equal(parsed.remark, remark)
    line = formatIpListEntryLine(parsed.value, parsed.remark)
  }
})

test('C2b 备注首尾空白往返保真（未加引号会被导入侧 trim 掉）', () => {
  for (const remark of [' x ', ' 前后空白 ', '\t制表符\t']) {
    const line = formatIpListEntryLine('10.0.0.1', remark)
    assert.equal(line, `10.0.0.1,"${remark}"`)
    assert.deepEqual(parseIpListEntryLine(line, isValidCidr), { value: '10.0.0.1', remark })
  }
  // 纯空白备注：加引号后回读为空串以外的原值；空备注仍走无引号形态
  assert.equal(formatIpListEntryLine('10.0.0.1', ' '), '10.0.0.1," "')
  assert.equal(formatIpListEntryLine('10.0.0.1', ''), '10.0.0.1,')
})

test('C3 旧格式（无引号、逗号/空白分隔）保持兼容', () => {
  assert.deepEqual(parseIpListEntryLine('10.0.0.1,普通备注', isValidCidr), { value: '10.0.0.1', remark: '普通备注' })
  assert.deepEqual(parseIpListEntryLine('10.0.0.1 普通备注', isValidCidr), { value: '10.0.0.1', remark: '普通备注' })
  assert.deepEqual(parseIpListEntryLine('10.0.0.1', isValidCidr), { value: '10.0.0.1', remark: '' })
  // IPv6 CIDR 是生产校验器的合法输入（isValidCidr 走 isValidIpv6，
  // prefix≤128）——原测试用替身把它断言成非法值（假前提）。
  assert.deepEqual(parseIpListEntryLine('2001:db8::/32', isValidCidr), { value: '2001:db8::/32', remark: '' })
})

test('C9 IPv6 导入往返与非法形态', () => {
  // 生产注入的真实校验器语义：合法 IPv6 CIDR/单地址可导入并逐字往返
  for (const value of ['2001:db8::/32', '2001:db8::1', 'fe80::/10', '::1']) {
    assert.equal(isValidCidr(value), true, `${value} 应为合法值`)
    const line = formatIpListEntryLine(value, 'v6 备注')
    assert.deepEqual(parseIpListEntryLine(line, isValidCidr), { value, remark: 'v6 备注' }, `${value} 往返漂移`)
  }
  // 非法 IPv6：超界 prefix / 非法字符 / 双斜杠
  for (const value of ['2001:db8::/129', '::gg', '2001:db8::/32/1', '10.0.0.256']) {
    assert.equal(isValidCidr(value), false, `${value} 应为非法值`)
    assert.equal(parseIpListEntryLine(`${value},备注`, isValidCidr), null, `${value} 必须被拒绝`)
  }
})

test('C4 畸形行：未闭合引号/空值返回 null（导入计数为非法，不静默吞）', () => {
  assert.equal(parseIpListEntryLine('"10.0.0.1', isValidCidr), null)
  assert.equal(parseIpListEntryLine(',remark', isValidCidr), null)
  assert.equal(parseIpListEntryLine('   ', isValidCidr), null)
  assert.equal(parseIpListEntryLine('10.0.0.1,"未闭合', isValidCidr), null)
})

test('C5 引号包裹的 IP 字段（外部 CSV 工具产物）可解析', () => {
  assert.deepEqual(parseIpListEntryLine('"10.0.0.2","备注"', isValidCidr), { value: '10.0.0.2', remark: '备注' })
})

test('C6 多行备注导出归一为空格——导入端按行切分，往返不丢备注', () => {
  const line = formatIpListEntryLine('10.0.0.1', '第一行\r\n第二行')
  assert.equal(line, '10.0.0.1,第一行 第二行')
  const parsed = parseIpListEntryLine(line, isValidCidr)
  assert.deepEqual(parsed, { value: '10.0.0.1', remark: '第一行 第二行' })
})

test('C7 备注超过 100 字拒绝导入（带行号报错，不静默截断），边界恰 100 字放行', () => {
  // 恰 100 个 code point（全代理对）仍合法——上限口径不变
  const atLimit = parseIpListEntryLine(`10.0.0.1,${'😀'.repeat(100)}`, isValidCidr)
  assert.deepEqual(atLimit, { value: '10.0.0.1', remark: '😀'.repeat(100) })
  // 101 个 code point：拒绝而非截断（旧实现静默截尾，用户无感知）
  assert.deepEqual(parseIpListEntryLine(`10.0.0.1,${'😀'.repeat(100)}尾`, isValidCidr), { error: 'remark_too_long' })
  assert.deepEqual(parseIpListEntryLine(`10.0.0.1,${'a'.repeat(101)}`, isValidCidr), { error: 'remark_too_long' })
  // 导入流必须带文件行号点名拒绝（脚本存在性：注释里的旧实现不得满足）
  const src = code('src/views/security/SecurityRules.vue')
  const importFlow = member(src, 'const importEntriesFromText')
  assert.match(importFlow, /remarkTooLongLines\.push\(line\.no\)/, '导入流必须按文件行号记录备注超长拒绝')
  assert.match(importFlow, /第 \$\{[^}]+\} 行/, '拒绝信息必须携带文件行号')
})

test('C8 JSON 字符串数组统一 trim 并丢弃空项', () => {
  assert.deepEqual(parseIPList('[" 1.1.1.1 ","","  ",2,"10.0.0.0/8"]'), ['1.1.1.1', '10.0.0.0/8'])
  const crsSource = code('src/composables/useCrsRuleIndex.ts')
  assert.match(crsSource, /normalizeStringEntries\(rec\.ips\)/, 'CRS 排除规则数组必须复用同一 trim 归一')
})

test('D 共享条目缓存：缺失才拉、并发去重、失败可重试、invalidate 后重拉', async () => {
  invalidateSharedEntriesCache()
  const calls: number[] = []
  const loader = async (id: number): Promise<string[]> => {
    calls.push(id)
    if (id === 9) throw new Error('boom')
    return [`10.0.0.${id}`]
  }
  // 并发两次：同一 id 只发一次请求（in-flight 复用）
  await Promise.all([ensureSharedEntries([1, 2, 9], loader), ensureSharedEntries([1, 2, 9], loader)])
  assert.deepEqual(calls.sort((a, b) => a - b), [1, 2, 9])
  assert.deepEqual(sharedEntriesCache[1], ['10.0.0.1'])
  assert.equal(9 in sharedEntriesCache, false, '失败不得写缓存')
  // 已缓存 id 不再请求；失败 id 重试
  calls.length = 0
  await ensureSharedEntries([1, 2, 9], loader)
  assert.deepEqual(calls, [9])
  // 写回与失效通知：走生产写入口 ensureSharedEntries 再断言缓存（此前测试直接
  // 写 sharedEntriesCache 再读同一对象，属自写自断言）
  calls.length = 0
  await ensureSharedEntries([3], loader)
  assert.deepEqual(calls, [3])
  assert.deepEqual(sharedEntriesCache[3], ['10.0.0.3'])
  invalidateSharedEntriesCache()
  calls.length = 0
  await ensureSharedEntries([1], loader)
  assert.deepEqual(calls, [1])
  invalidateSharedEntriesCache()
})

test('D3 代际竞态：失效后复用方必须按新代际补取，await 返回即已缓存', async () => {
  invalidateSharedEntriesCache()
  let release: () => void = () => {}
  const gate = new Promise<void>((resolve) => { release = resolve })
  const calls: string[] = []
  // 首个调用发起请求（代际 g0），请求在途
  const creator = ensureSharedEntries([7], async () => {
    calls.push('old')
    await gate
    return ['10.0.0.7-old']
  })
  // 写动作：失效缓存并递增代际，随后 IP 处置链路立刻 ensure 同一名单
  invalidateSharedEntriesCache()
  const waiter = ensureSharedEntries([7], async () => {
    calls.push('new')
    return ['10.0.0.7-new']
  })
  release()
  await Promise.all([creator, waiter])
  // 等待者不得静默返回空缓存：跨代际在途请求不复用，按当前代际补取并落地
  assert.deepEqual(sharedEntriesCache[7], ['10.0.0.7-new'])
  assert.deepEqual(calls.sort(), ['new', 'old'])
  invalidateSharedEntriesCache()
})

test('D4 失败语义不变：失败不补取、不留缓存（下次调用重试）', async () => {
  invalidateSharedEntriesCache()
  let calls = 0
  const failing = async (): Promise<string[]> => {
    calls += 1
    throw new Error('boom')
  }
  await ensureSharedEntries([11], failing)
  assert.equal(calls, 1, '失败一次即返回，调用方自行重试')
  assert.equal(11 in sharedEntriesCache, false)
  // 并发第二次调用在首次失败后（无在途）→ 再发起一次
  await ensureSharedEntries([11], failing)
  assert.equal(calls, 2)
  invalidateSharedEntriesCache()
})

test('D5 缓存 TTL：超过 60s 按缺失重拉（外部变更不经本页写动作失效）', async () => {
  invalidateSharedEntriesCache()
  const realNow = Date.now
  let now = realNow()
  Date.now = () => now
  try {
    const calls: number[] = []
    const loader = async (id: number): Promise<string[]> => {
      calls.push(id)
      return [`10.0.0.${id}`]
    }
    await ensureSharedEntries([5], loader)
    assert.deepEqual(calls, [5])
    // TTL 内不重拉
    await ensureSharedEntries([5], loader)
    assert.deepEqual(calls, [5], 'TTL 内已缓存 id 不得重复请求')
    assert.deepEqual(missingSharedEntryIds([5]), [], 'TTL 内不算缺失')
    // 超过 TTL：缺失上报 + ensure 重拉（另一标签页/管理员改名单的唯一收敛途径）
    now += 61_000
    assert.deepEqual(missingSharedEntryIds([5]), [5], '过期条目标记为缺失（调用方据此显性化加载失败）')
    await ensureSharedEntries([5], loader)
    assert.deepEqual(calls, [5, 5], '过期后必须重拉')
    assert.deepEqual(sharedEntriesCache[5], ['10.0.0.5'])
  } finally {
    Date.now = realNow
    invalidateSharedEntriesCache()
  }
})

test('D2 代际守卫：失效前发起的在途 loader 落地不得回填缓存', async () => {
  invalidateSharedEntriesCache()
  let release: () => void = () => {}
  const gate = new Promise<void>((resolve) => { release = resolve })
  const pending = ensureSharedEntries([7], async () => {
    await gate
    return ['10.0.0.7-old']
  })
  // 在途期间发生写动作：失效缓存并递增代际
  invalidateSharedEntriesCache()
  release()
  await pending
  assert.equal(7 in sharedEntriesCache, false, '迟到结果必须丢弃，保持未缓存待重取')
  // 重取得到新值
  await ensureSharedEntries([7], async () => ['10.0.0.7-new'])
  assert.deepEqual(sharedEntriesCache[7], ['10.0.0.7-new'])
  invalidateSharedEntriesCache()
})

test('名单条目上限/备注长度与后端 securityiplists.go 同源（跨栈钉）', () => {
  // 上限此前在 SFC 硬编码两处（校验 + 文案），后端单一常量 ipListMaxEntries；
  // 备注长度后端按 rune 计（len([]rune(...)) > 上限），前端按 code point 计。
  const go = repoCode('internal/handlers/securityiplists.go')
  // gofmt 对齐重排会让固定空格数假红——用 \s* 匹配
  assert.match(go, /\bipListMaxEntries\s*=\s*2000\b/, '后端条目上限常量漂移')
  assert.equal(IP_LIST_MAX_ENTRIES, 2000)
  // 备注上限必须**从后端声明派生**再与前端常量对表：写死 `assert.equal(x, 100)`
  // 只是自证（后端扩额到 200 时前端仍按 100 拒绝，导入逐行报「备注超过 100 字」
  // 而这批数据 API 完全接受）。
  const goMax = /ipListMaxRemarkLength\s*=\s*(\d+)/.exec(go)
  assert.ok(goMax !== null, '后端备注上限常量缺失：前端失去对表锚点')
  assert.equal(ipListRemarkMaxLength, Number(goMax[1]), '备注上限两端必须同值')
  // 备注判定必须是「按 rune 计且与备注上限比较」这一**具体形态**：文件里另有
  // 名称/描述/分类三处 rune 计数，宽口径 `includes('len([]rune(')` 会被它们满足，
  // 把备注一路改成字节比较（中文 3 字节/字，34 字即被后端拒绝）也不会红。
  assert.match(
    go,
    /len\(\[\]rune\(entry\.Remark\)\)\s*>\s*ipListMaxRemarkLength/,
    '备注长度必须按 rune 计数并与备注上限比较（字节比较会让中文备注远早于前端上限被拒）',
  )
  // SFC 不得再硬编码条目上限字面量（双源会漂移）：只钉两个**语义形态**——
  // 校验比较与控件上限；不再用「全页任何 `= 2000`」的宽口径（未来合法超时/
  // 分页示例会假红）。
  const rules = code('src/views/security/SecurityRules.vue')
  assert.match(rules, /IP_LIST_MAX_ENTRIES/, 'SecurityRules 必须引用单源常量')
  // 上限按生效条目计（与后端 validateIPListShape / AutobanActiveEntries 同口径）：
  // 已到期条目保存时被剔除、不占名额，原始条数比较会把到期残留顶到上限。
  assert.match(rules, /activeEntryCount > IP_LIST_MAX_ENTRIES/, '条目数校验必须引用单源常量（生效条目口径）')
  assert.match(
    rules,
    /entries\.filter\(\(e\) => !!e\.expires_at && autobanEntryExpired\(e\.expires_at\)\)/,
    '生效条目数必须剔除已到期条目（与后端剔除口同源）',
  )
  assert.doesNotMatch(rules, /length\s*>\s*2000\b/, '条目数比较不得写死 2000')
  assert.doesNotMatch(rules, /:max="\s*2000\s*"/, '控件上限不得写死 2000')
})

// 引号字段闭合后只允许「空白 + 单个逗号 + 空白」；残留一律按非法行拒绝。
// 旧实现把首字段残留整体并入备注、备注字段残留静默丢弃——导入结果与源文件
// 不一致却无任何提示。
test('C11 引号字段闭合后的残留被拒绝（合法/首字段残留/备注残留三形态）', () => {
  // 合法形态：闭合引号后仅有空白或「逗号 + 空白」
  assert.deepEqual(parseIpListEntryLine('"10.0.0.4",备注', isValidCidr), { value: '10.0.0.4', remark: '备注' })
  assert.deepEqual(parseIpListEntryLine('"10.0.0.4" , 备注', isValidCidr), { value: '10.0.0.4', remark: '备注' })
  assert.deepEqual(parseIpListEntryLine('"10.0.0.4"', isValidCidr), { value: '10.0.0.4', remark: '' })
  assert.deepEqual(parseIpListEntryLine('"10.0.0.4",', isValidCidr), { value: '10.0.0.4', remark: '' })
  // 首字段残留（曾被当成备注的一部分）
  assert.equal(parseIpListEntryLine('"10.0.0.4"junk,备注', isValidCidr), null)
  // 备注字段残留（曾被静默丢弃）
  assert.equal(parseIpListEntryLine('"10.0.0.4","备注"junk', isValidCidr), null)
  // 第三列：无论是否有内容都没有对应语义，同样拒绝而非并进备注
  assert.equal(parseIpListEntryLine('"10.0.0.4","备注","多余"', isValidCidr), null)
  assert.equal(parseIpListEntryLine('"10.0.0.4","备注",', isValidCidr), null)
  assert.equal(parseIpListEntryLine('"10.0.0.4","备注",   ', isValidCidr), null)
})

// 导出物会被 Excel/Sheets/WPS 直接打开：备注以 `= + - @ \t \r` 开头时是公式（或
// DDE）入口，纯文本导出即静默求值。中和=前置单引号；导入侧对称剥离以维持逐字
// 往返，且不得吞掉用户真正的字面单引号（按「前导引号串 + 公式字符」判定）。
test('导出中和单元格公式前导字符，导入对称剥离（往返逐字相等）', () => {
  for (const risky of ['=1+1', '+SUM(A1)', '-1+2', '@SUM(A1)']) {
    const line = formatIpListEntryLine('10.0.0.1', risky)
    assert.equal(line, `10.0.0.1,'${risky}`, `${risky} 必须前置单引号中和（表格软件打开即求值）`)
    assert.deepEqual(parseIpListEntryLine(line, isValidCidr), { value: '10.0.0.1', remark: risky }, `${risky} 中和后必须逐字往返`)
  }
  // 非前导形态不受影响（不误加引号）
  assert.equal(formatIpListEntryLine('10.0.0.1', 'a=b'), '10.0.0.1,a=b')
  assert.equal(formatIpListEntryLine('10.0.0.1', 'a-b'), '10.0.0.1,a-b')
  // 制表符前缀的公式形态同样中和（部分工具先剥空白再识别公式），且仍按首尾空白加引号
  const tabbed = formatIpListEntryLine('10.0.0.1', '\t=cmd|/c calc')
  assert.equal(tabbed, '10.0.0.1,"\'\t=cmd|/c calc"')
  assert.deepEqual(parseIpListEntryLine(tabbed, isValidCidr), { value: '10.0.0.1', remark: '\t=cmd|/c calc' })
})

test('字面单引号不被中和标记吞掉（引号串长度判定）', () => {
  for (const remark of ["'=1+1", "''=1", "'普通备注", "'", "'="]) {
    const line = formatIpListEntryLine('10.0.0.1', remark)
    assert.deepEqual(parseIpListEntryLine(line, isValidCidr), { value: '10.0.0.1', remark }, `${JSON.stringify(remark)} 往返漂移（导出 ${JSON.stringify(line)}）`)
  }
})

test('中和与 CSV 引号包裹共存（含逗号的公式形态）', () => {
  const line = formatIpListEntryLine('10.0.0.1', '=1,2')
  assert.equal(line, `10.0.0.1,"'=1,2"`, '先中和再按 RFC4180 包裹')
  assert.deepEqual(parseIpListEntryLine(line, isValidCidr), { value: '10.0.0.1', remark: '=1,2' })
})
