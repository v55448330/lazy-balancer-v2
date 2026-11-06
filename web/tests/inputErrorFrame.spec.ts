// 输入框校验红框全局单源钉：
//   Element Plus 内置 is-error 样式只作用于 el-form-item 校验链——手动挂在
//   el-input/el-input-number 根上的 is-error 类没有任何渲染。红框形态收敛到
//   main.css 全局规则（历史上 Rules 上游列/PathRulesEditor 行诊断/SecurityRules
//   条件行三处异构实现：两处 scoped 各写一份、一处完全缺失）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, cssDeclarations } from './_helpers.ts'

test('main.css 全局 is-error 红框规则存在：作用于 el-input 与 el-input-number 的 wrapper', () => {
  const mainCss = code('src/styles/main.css')
  // 双选择器组员共享同一声明块：以第二组员取声明集（选择器串后紧跟 `{`）。
  assert.match(
    mainCss,
    /\.el-input\.is-error \.el-input__wrapper,\s*\n\.el-input-number\.is-error \.el-input__wrapper \{/,
    '红框规则必须同时覆盖文本输入与数字输入两种根类',
  )
  const decls = cssDeclarations(mainCss, '.el-input-number.is-error .el-input__wrapper')
  assert.equal(
    decls.get('box-shadow'),
    '0 0 0 1px var(--el-color-danger, #f56c6c) inset',
    '红框形态=1px danger 内嵌描边（与 EP 边框同为 box-shadow，特异性 (0,2,1) 胜 hover/focus 态）',
  )
})

test('三处历史异构红框实现已收敛全局类（无 scoped/别名残留）', () => {
  const rules = code('src/views/Rules.vue')
  assert.doesNotMatch(rules, /\.upstream-input(-small)?\.is-error/, 'Rules.vue scoped 红框必须移除（全局类同视觉）')

  const editor = code('src/components/rules/PathRulesEditor.vue')
  assert.doesNotMatch(editor, /is-error-input/, 'is-error-input 别名类必须退役（绑定与样式一并无残留）')
  assert.match(editor, /'is-error': rowDiagnostics\[index\]\?\.pathError/, '行诊断红框绑定改挂全局类')

  // 条件行红框绑定（谓词钉在 securityRuleHeaderName.spec）：本钉只保证消费的
  // 类名正是全局规则的选择器类名。
  const security = code('src/views/security/SecurityRules.vue')
  assert.match(security, /'is-error': !headerNameSaveAllowed\(cond\.header_name\)/, '头名输入红框绑定在位')
  assert.match(security, /'is-error': \(cond\.operator === 'regex' && !isValidRegex\(cond\.pattern\)\) \|\| patternOverLimit\(cond\.pattern\)/, '匹配值输入红框绑定在位')
})
