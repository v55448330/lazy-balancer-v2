// 策略保存的成功提示只弹一条：原实现在阶段拦截页覆盖同步后先弹「已同步 N 条…」，
// 紧接着 showSaveResult 又弹「保存成功」——两条 toast 叠加。合并后同步数作为后缀
// 附在保存结果消息后（服务端 message 优先，Caddy 应用失败后缀判定不受影响）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, code, registerModuleHooks } from './_helpers.ts'
import { STUB_SAVE_RESULT_DEPS, calls, resetCalls } from './_stubs.ts'
import { CADDY_APPLY_FAILED_MARKER, mergeBulkResults, policySaveResultMessage, stageOverrideDraftPending } from '../src/utils/bulkApplyResult.ts'

const host = globalThis as unknown as { __calls: unknown[] }
host.__calls = calls
registerModuleHooks({ 'element-plus': STUB_SAVE_RESULT_DEPS, '@/utils/api': STUB_SAVE_RESULT_DEPS })
// 模块钩子须先于被测模块加载；静态 import 会在替身安装前执行依赖。
const { showSaveResult } = await import('../src/utils/saveResult.ts')

const page = code('src/views/security/SecurityPolicies.vue')

test('策略保存：合并消息全形状求值，每次保存结果只呈现一条提示', () => {
  const scenarios = [
    { response: undefined, pending: 0, skipped: 0, want: '保存成功' },
    { response: { message: '策略已保存' }, pending: 3, skipped: 0, want: '策略已保存，已同步 3 条规则的阶段拦截页覆盖' },
    { response: { message: '策略已保存' }, pending: 3, skipped: 1, want: '策略已保存，已同步 2 条规则的阶段拦截页覆盖' },
    { response: { message: '服务端自定义消息' }, pending: 0, skipped: 0, want: '服务端自定义消息' },
    { response: { message: `策略已保存${CADDY_APPLY_FAILED_MARKER}：reload 超时` }, pending: 1, skipped: 0, want: `策略已保存${CADDY_APPLY_FAILED_MARKER}：reload 超时，已同步 1 条规则的阶段拦截页覆盖` },
  ]
  for (const scenario of scenarios) {
    resetCalls()
    const message = policySaveResultMessage(scenario.response, scenario.pending, scenario.skipped)
    assert.equal(message, scenario.want)
    showSaveResult({ message }, '保存成功')
    assert.equal(calls.length, 1, '一个保存结果只能产生一次消息调用')
    if (message.includes(CADDY_APPLY_FAILED_MARKER)) {
      assert.equal(calls[0].fn, 'ElMessage')
      assert.deepEqual(calls[0].arg, { type: 'warning', message, duration: 0, showClose: true })
    } else {
      assert.deepEqual(calls[0], { fn: 'mfaAwareSuccess', arg: message })
    }
  }

  const save = section(page, 'let pendingOverrides = pendingOverrideRules.value', 'const mergedBind = mergeBulkResults(')
  assert.doesNotMatch(save, /mfaAwareSuccess\(`已同步/, '不得再单独弹同步成功 toast')
  assert.match(save, /policySaveResultMessage\(saveRes, pendingOverrides\.length, skippedOverrideCount\)/)
  assert.equal(save.match(/showSaveResult\(/g)?.length, 1, '视图必须只接线一次保存结果提示')
})

test('阶段页批量响应：任一分片退化都进入持续警告结果合并', () => {
  const degraded = `阶段页已提交；但${CADDY_APPLY_FAILED_MARKER}：admin 连接中断`
  const merged = mergeBulkResults([{ message: degraded }, { message: '阶段页已更新' }])
  assert.equal(merged?.message, degraded, '末片成功不得覆盖先前分片退化')

  const save = section(page, 'let pendingOverrides = pendingOverrideRules.value', 'const savedType = editorPolicyType.value')
  assert.match(save, /stageOverrideResponses\.push\(res\)/, '每个阶段页分片响应必须被收集')
  assert.match(save, /mergeBulkResults\(stageOverrideResponses\)/, '阶段页响应必须进入统一合并')
  assert.match(save, /mergedStageOverrides\?\.message\?\.includes\(CADDY_APPLY_FAILED_MARKER\)\) showSaveResult\(mergedStageOverrides, ''\)/)
})

test('阶段页写入 skipped：保留弹框与暂存，零 skipped 才允许完成关窗', () => {
  assert.equal(stageOverrideDraftPending(0), false)
  assert.equal(stageOverrideDraftPending(1), true)
  assert.equal(stageOverrideDraftPending(3), true)
  assert.equal(stageOverrideDraftPending(-1), false)

  const save = section(page, 'let pendingOverrides = pendingOverrideRules.value', 'const savedType = editorPolicyType.value')
  const gateAt = save.indexOf('if (stageOverrideDraftPending(skippedOverrideCount)) return')
  assert.ok(gateAt > 0, 'skipped 必须在关窗前进入待重试终态')
  assert.ok(gateAt > save.indexOf('showSaveResult('), '策略保存结果仍须先呈现')
  assert.ok(gateAt > save.indexOf('mergeBulkResults(stageOverrideResponses)'), 'skipped 与 Caddy 退化同时出现时不得吞掉持续警告')
  assert.match(save, /skippedOverrideCount = skippedNotes\.length/)
})
