// 全局兜底错误留痕：渲染/生命周期异常与未处理的 Promise 拒绝都不得静默，
// 且**必须保留原始错误对象**（Error 的 stack 是排障的唯一线索）。
//
// 原实现把渲染分支拼成 `` `${info}: ${String(err)}` `` 再交给 console.error：
// 控制台只剩一行字符串，组件栈/调用栈全丢；而同文件的 unhandledrejection
// 分支传的是原始对象——同一兜底的两条入口诊断能力不一致。
//
// 契约：错误对象原样透传，上下文（生命周期钩子名等）单独成参。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'
import { reportGlobalError } from '../src/utils/globalError.ts'

const captureConsoleError = (): { args: unknown[][]; restore: () => void } => {
  const original = console.error
  const args: unknown[][] = []
  console.error = (...rest: unknown[]) => { args.push(rest) }
  return { args, restore: () => { console.error = original } }
}

test('渲染异常：Error 对象原样进 console.error，info 单独成参（不得字符串化合并）', () => {
  const error = new TypeError('Cannot read properties of null')
  const captured = captureConsoleError()
  try {
    reportGlobalError('render', error, 'render function')
  } finally {
    captured.restore()
  }
  assert.equal(captured.args.length, 1, '必须恰好一条留痕')
  const args = captured.args[0]
  assert.equal(args[0], '[global:render]', '留痕前缀标识来源入口')
  assert.equal(args[1], 'render function', 'info（生命周期钩子名）必须单独成参')
  assert.equal(args[2], error, '原始 Error 对象必须原样透传（stack 不得丢）')
  assert.ok((args[2] as Error).stack?.includes('Cannot read properties of null'), 'stack 可读')
})

test('未处理拒绝：reason 任意形态（非 Error）原样透传，无 info 时不插空参', () => {
  const reason = { code: 'E_FAIL', detail: ['a', 'b'] }
  const captured = captureConsoleError()
  try {
    reportGlobalError('unhandledrejection', reason)
  } finally {
    captured.restore()
  }
  const args = captured.args[0]
  assert.deepEqual(args, ['[global:unhandledrejection]', reason], '原始 reason 作为唯一数据参')
})

test('接线：main.ts 的渲染分支传原始 err 与 info（不得再 String(err) 合并）', () => {
  const main = code('src/main.ts')
  assert.doesNotMatch(main, /String\(err\)/, '渲染错误不得被字符串化（丢 stack）')
  assert.match(
    main,
    /app\.config\.errorHandler = \(err, _instance, info\) => reportGlobalError\('render', err, info\)/,
    '渲染分支必须把 (err, info) 分参透传给留痕单源',
  )
  assert.match(
    main,
    /window\.addEventListener\('unhandledrejection', \(event\) => reportGlobalError\('unhandledrejection', event\.reason\)\)/,
    'rejection 分支保持透传原始 reason',
  )
})
