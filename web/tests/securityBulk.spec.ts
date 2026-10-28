// 后端批量端点上限镜像与冲突检测求交
//   A. chunkForBulk 按上限切分、顺序保持、空输入不产生请求
//   B. entriesIntersect 复用 Set 语义且与 filter/includes 结果一致（去重、保序）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  MAX_POLICIES_PER_RULE,
  SECURITY_BULK_LIMITS,
  chunkForBulk,
  entriesIntersect,
} from '../src/utils/securityStages.ts'
import { CADDY_APPLY_FAILED_MARKER, mergeBulkResults } from '../src/utils/bulkApplyResult.ts'
import { code, repoCode, section } from './_helpers.ts'

test('A1 分片：按上限切分且保持原顺序（策略绑定 100 / 批量拦截页 500）', () => {
  const bindings = Array.from({ length: 250 }, (_, i) => `lb_${i}`)
  const chunks = chunkForBulk(bindings, SECURITY_BULK_LIMITS.policyBindings)
  assert.deepEqual(chunks.map((c) => c.length), [100, 100, 50])
  assert.deepEqual(chunks.flat(), bindings, '分片拼接必须等于原序列')
  const pages = Array.from({ length: 1001 }, (_, i) => `lb_${i}`)
  assert.deepEqual(chunkForBulk(pages, SECURITY_BULK_LIMITS.ruleBlockPages).map((c) => c.length), [500, 500, 1])
})

test('A2 分片：单次合计不超过后端上限（每片 ≤100 才满足 bind+unbind 合计门）', () => {
  for (const size of [1, 99, 100, 101, 1000]) {
    const chunks = chunkForBulk(Array.from({ length: size }, (_, i) => i), SECURITY_BULK_LIMITS.policyBindings)
    for (const chunk of chunks) assert.ok(chunk.length <= SECURITY_BULK_LIMITS.policyBindings)
    assert.equal(chunks.reduce((sum, c) => sum + c.length, 0), size)
  }
})

test('A3 分片：空输入/非法上限不产生请求', () => {
  assert.deepEqual(chunkForBulk([], 100), [])
  assert.deepEqual(chunkForBulk(['a'], 0), [])
})

// 后端整批门是 `len(bindIDs)+len(unbindIDs) > 100 → 400`（security.go）：
// 只有「bind、unbind 各自成片提交」才让每片 ≤100 等价于合计 ≤100。把两向合并成
// 一次请求（各 100、合计 200）看起来更省往返，后端整批 400 —— 断言钉住分片策略
// 本身，而不只是单片上限。
test('A4 分片请求按方向独立提交：每片对向数组为空且两向各一片', () => {
  const consumers = [
    {
      file: 'src/components/SecurityBindingEditor.vue',
      start: 'const responses: Array<APIResponse<unknown> | undefined> = []',
      end: 'showSaveResult(mergeBulkResults(responses)',
    },
    {
      file: 'src/views/security/SecurityPolicies.vue',
      start: 'const bindResponses: Array<{ message?: string } | undefined> = []',
      end: 'const mergedBind = mergeBulkResults(bindResponses)',
    },
  ] as const
  for (const { file, start, end } of consumers) {
    const body = section(code(file), start, end)
    const requests = [...body.matchAll(/bind: ([^,}\n]+),\s*unbind: ([^,}\n]+)/g)]
    assert.equal(requests.length, 2, `${file}: 必须恰好两处批量请求（bind 一片源、unbind 一片源）`)
    for (const match of requests) {
      const bind = match[1].trim()
      const unbind = match[2].trim()
      assert.ok(bind === '[]' || unbind === '[]', `${file}: 单次请求不得同时携带 bind 与 unbind（合计会超后端上限）`)
    }
    const [first, second] = requests.map((match) => [match[1].trim(), match[2].trim()])
    assert.ok(first && second, `${file}: 两片必须存在`)
    assert.ok(first[1] === '[]' && second[0] === '[]', `${file}: 两片必须一正一反`)
    assert.equal(first[0], second[1], `${file}: bind/unbind 必须引用同一标识符（允许重命名）`)
  }
})

test('存量多限流绑定保存时收敛为界面展示的首条', () => {
  const editor = code('src/components/SecurityBindingEditor.vue')
  assert.match(editor, /bindStage2\.value\.slice\(0, 1\)/, '提交集不得继续携带界面不可见的第二条限流策略')
  const total = section(editor, 'const ruleModeTotal = computed', 'const pickerHttpRules')
  assert.match(total, /Math\.min\(1, bindStage2\.value\.length\)/, '策略总数必须按唯一化后的限流绑定计数')
})

test('B1 求交：与 filter+includes 结果一致（保序、去重），Set 查表不改变语义', () => {
  const allow = ['10.0.0.1', '10.0.0.2', '10.0.0.1', '10.0.0.3']
  const deny = new Set(['10.0.0.3', '10.0.0.1'])
  const expected = [...new Set(allow.filter((e) => deny.has(e)))]
  assert.deepEqual(entriesIntersect(allow, deny), expected)
  assert.deepEqual(entriesIntersect(allow, deny), ['10.0.0.1', '10.0.0.3'])
})

test('B2 求交：无重叠返回空数组，不误报冲突', () => {
  assert.deepEqual(entriesIntersect(['1.1.1.1'], new Set(['2.2.2.2'])), [])
  assert.deepEqual(entriesIntersect([], new Set(['2.2.2.2'])), [])
})

// 分片响应汇总——
// 退化 200（DB 已提交、Caddy 应用失败）必须常驻警告：原实现把每片响应赋给
// 同一变量，只有末片进入 showSaveResult，早先分片的失败提示被覆盖丢失。
const DEGRADED = `绑定已提交；但${CADDY_APPLY_FAILED_MARKER}：重载中断`

test('C1 分片响应：首片退化 200 不被末片成功覆盖', () => {
  const merged = mergeBulkResults([{ message: DEGRADED }, { message: '已更新 100 条规则的绑定' }])
  assert.equal(merged?.message, DEGRADED)
  assert.ok(merged?.message?.includes(CADDY_APPLY_FAILED_MARKER))
})

test('C2 分片响应：多片退化合并为一条并标注片数，重复后缀去重', () => {
  const duplicated = mergeBulkResults([{ message: DEGRADED }, undefined, { message: DEGRADED }])
  assert.equal(duplicated?.message, DEGRADED)
  const distinct = mergeBulkResults([
    { message: DEGRADED },
    { message: `已提交；但${CADDY_APPLY_FAILED_MARKER}：超时` },
  ])
  assert.ok(distinct?.message?.startsWith(DEGRADED))
  assert.match(distinct?.message ?? '', /另有 1 个分片同样应用失败/)
})

test('C3 分片响应：无退化时保持末片文案；空输入返回 undefined', () => {
  assert.deepEqual(mergeBulkResults([{ message: 'a' }, { message: 'b' }]), { message: 'b' })
  assert.equal(mergeBulkResults([]), undefined)
  assert.equal(mergeBulkResults([undefined, undefined]), undefined)
  // 单响应语义先钉死再判标记：`?? ''` 会让「返回 undefined」同样通过，
  // 而单响应必须原样返回该响应。
  assert.deepEqual(mergeBulkResults([{ message: 'ok' }]), { message: 'ok' })
  assert.ok(!mergeBulkResults([{ message: 'ok' }])!.message!.includes(CADDY_APPLY_FAILED_MARKER))
})

// 上限不得钉字面量：后端常量调整后前端镜像必须同批跟随，否则 UI 放行 9 条、
// 后端 400 拒收（或反之静默截断）。直接读 Go 声明对表。
test('D1 绑定上限单源：与后端 maxBindingsPerRule 同值', () => {
  const go = repoCode('internal/handlers/security.go')
  const declared = /^const maxBindingsPerRule = (\d+)$/m.exec(go)
  assert.ok(declared, '后端缺 maxBindingsPerRule 常量声明')
  assert.equal(MAX_POLICIES_PER_RULE, Number(declared[1]), '前端 MAX_POLICIES_PER_RULE 与后端上限漂移')
})

// D2：分片上限同样跨栈对表——前端按 SECURITY_BULK_LIMITS 切片，切片大于后端
// 上限时整批 400 且重试同败；小于后端上限则浪费往返。三常量（批量绑定 /
// 单策略批量绑定 / 批量拦截页）逐一对表。
test('D2 分片上限单源：与后端批量端点三常量同值', () => {
  const security = repoCode('internal/handlers/security.go')
  const batchBind = /^const maxBatchBindRules = (\d+)$/m.exec(security)
  const bulkBindings = /const maxBulkBindings = (\d+)/.exec(security)
  assert.ok(batchBind && bulkBindings, '后端缺批量绑定上限常量声明')
  assert.equal(SECURITY_BULK_LIMITS.policyBindings, Number(bulkBindings[1]), 'policyBindings 与 maxBulkBindings 漂移')
  assert.equal(SECURITY_BULK_LIMITS.policyBindings, Number(batchBind[1]), 'policyBindings 与 maxBatchBindRules 漂移')
  const rules = repoCode('internal/handlers/rules.go')
  const blockPages = /const maxBatchRuleBlockPages = (\d+)/.exec(rules)
  assert.ok(blockPages, '后端缺批量拦截页上限常量声明')
  assert.equal(SECURITY_BULK_LIMITS.ruleBlockPages, Number(blockPages[1]), 'ruleBlockPages 与 maxBatchRuleBlockPages 漂移')
})

// 退化后缀判定单源：名单直接动作（useTrustAssociation 三侧快捷处置）与批量
// 合并共用同一标记常量——字面量复制会在文案调整时静默失配（后缀不再常驻）。
test('退化后缀判定单源：名单直接动作不复制字面量', () => {
  const composable = code('src/composables/useTrustAssociation.ts')
  assert.match(composable, /import \{ CADDY_APPLY_FAILED_MARKER \} from '@\/utils\/bulkApplyResult'/)
  assert.doesNotMatch(composable, /['"]Caddy 配置应用失败['"]/, '不得复制退化后缀字面量')
})
