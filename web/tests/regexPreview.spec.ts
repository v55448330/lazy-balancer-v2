// 正则预览编译：合法性以后端 RE2(coraza) 为准。中置内联 flag((?i)) 在 JS
// 不识别，须剥离后试编译；剥离正则不得要求 flag 后紧跟非 ')' 字符——RE2 允许
// flag 紧邻分组闭括号（如 `(a(?i)b)`），旧 lookahead `(?=[^)]|$)` 会漏剥离并
// 把合法规则误判语法错误（保存被前端预校验挡住）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { compileJSRegex } from '../src/utils/regexPreview.ts'
import { code } from './_helpers.ts'

test('RE2 合法 flag 形态不误拒：lead/中置/紧邻闭括号/flag 组/命名组/取反', () => {
  const valid = [
    '(?i)abc',
    'a(?m)b',
    '(a(?i)b)',
    '(?:abc(?i))',
    '(?i:abc)',
    '(?P<name>a)',
    '(?-i)a',
    'a(?i)(b)',
    '(?i)(?m)abc',
  ]
  for (const pattern of valid) {
    assert.equal(compileJSRegex(pattern).valid, true, `${pattern} 是 RE2 合法形态，不得误判`)
  }
})

test('真语法错误仍判 invalid（剥离兜底不得掩盖未闭合括号/非法 flag）', () => {
  for (const pattern of ['a(', '(?i', '(?q)abc', '(?=x)', '\\1', '\\k<n>']) {
    assert.equal(compileJSRegex(pattern).valid, false, `${pattern} 必须判非法`)
  }
})

test('SecurityRules 预览编译委托 utils 单源（不再内联第二份剥离逻辑）', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.match(page, /import \{ compileJSRegex \} from '@\/utils\/regexPreview'/, '预览编译必须走共享 util')
  assert.doesNotMatch(page, /const midFlagStripped = src\.replace/, '内联编译实现不得残留（双源会再次漂移）')
})
