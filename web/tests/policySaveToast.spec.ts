// 策略保存的成功提示只弹一条：保存结果（服务端 message 优先，Caddy 应用失败
// 后缀常驻）由 showSaveResult 统一呈现；绑定与执行序的分片响应经 mergeBulkResults
// 合并后单独呈现退化警告（有后缀才弹，无后缀不重复 toast）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, code, registerModuleHooks } from './_helpers.ts'
import { STUB_SAVE_RESULT_DEPS, calls, resetCalls } from './_stubs.ts'
import { CADDY_APPLY_FAILED_MARKER, mergeBulkResults } from '../src/utils/bulkApplyResult.ts'

const host = globalThis as unknown as { __calls: unknown[] }
host.__calls = calls
registerModuleHooks({ 'element-plus': STUB_SAVE_RESULT_DEPS, '@/utils/api': STUB_SAVE_RESULT_DEPS })
// 模块钩子须先于被测模块加载；静态 import 会在替身安装前执行依赖。
const { showSaveResult } = await import('../src/utils/saveResult.ts')

const page = code('src/views/security/SecurityPolicies.vue')

test('策略保存：单条结果消息，服务端 message 优先，退化后缀常驻', () => {
  const scenarios: Array<{ message: string | undefined; want: string }> = [
    { message: undefined, want: '保存成功' },
    { message: '策略已保存', want: '策略已保存' },
    { message: '服务端自定义消息', want: '服务端自定义消息' },
    { message: `策略已保存${CADDY_APPLY_FAILED_MARKER}：reload 超时`, want: `策略已保存${CADDY_APPLY_FAILED_MARKER}：reload 超时` },
  ]
  for (const scenario of scenarios) {
    resetCalls()
    const message = scenario.message || '保存成功'
    showSaveResult({ message }, '保存成功')
    assert.equal(calls.length, 1, '一个保存结果只能产生一次消息调用')
    if (message.includes(CADDY_APPLY_FAILED_MARKER)) {
      assert.equal(calls[0].fn, 'ElMessage')
      assert.deepEqual(calls[0].arg, { type: 'warning', message, duration: 0, showClose: true })
    } else {
      assert.deepEqual(calls[0], { fn: 'mfaAwareSuccess', arg: message })
    }
  }

  // 视图接线：保存结果直接取响应 message（阶段页覆盖同步后缀已随功能退役）。
  // 该段内 showSaveResult 恰两次：保存结果一次 + 绑定/执行序退化警告一次。
  const save = section(page, 'const bindResponses', 'const savedType = editorPolicyType.value')
  assert.match(save, /message: saveRes\?\.message \|\| '保存成功'/, '保存结果必须直取响应 message（缺省回落「保存成功」）')
  assert.equal(save.match(/showSaveResult\(/g)?.length, 2, '只允许保存结果 + 退化警告两次呈现')
  assert.doesNotMatch(save, /policySaveResultMessage|stageOverrideDraftPending/, '阶段页覆盖同步消息工具已退役')
})

test('绑定/执行序分片响应：任一分片退化都进入持续警告结果合并', () => {
  const degraded = `绑定已提交；但${CADDY_APPLY_FAILED_MARKER}：admin 连接中断`
  const merged = mergeBulkResults([{ message: degraded }, { message: '绑定已更新' }])
  assert.equal(merged?.message, degraded, '末片成功不得覆盖先前分片退化')

  const save = section(page, 'const bindResponses', 'const savedType = editorPolicyType.value')
  assert.match(save, /mergeBulkResults\(bindResponses\)/, '绑定与执行序响应必须进入统一合并')
  assert.match(save, /mergedBind\?\.message\?\.includes\(CADDY_APPLY_FAILED_MARKER\)\) showSaveResult\(mergedBind, ''\)/)
})
