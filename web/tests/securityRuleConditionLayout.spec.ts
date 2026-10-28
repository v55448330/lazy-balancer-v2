// 自定义规则弹框的条件行布局钉：
// 提交 39424a3c 把 UA 快捷标签/正则模板移出 `.pattern-col` 并让两条 CSS 块整宽
// 左对齐，但当时没有任何断言——把模板移回 pattern 列内缩、或删掉
// `.regex-extras` 的左侧对齐/整宽，三条 UI spec 全绿（变异探针实测）。
//
// 这里钉两件事：
//   1) 结构：`.preset-section` 必须是条件行的直接子节点，**不在** `.pattern-col`
//      内（模式输入列是 flex:1 的窄列，模板塞进去会被压成内缩的小块，且
//      「左缘 = 行内左缘」的验收随之失效）；
//   2) 样式：`.preset-section` 占满整行（flex 基准 100% + width 100%），
//      `.regex-extras` 内容左对齐（align-items: flex-start）且整宽。
//
// 断言对象是布局契约（结构性 + CSS 声明），不是像素值：换主题色/间距不影响。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, section } from './_helpers.ts'

const SECURITY_RULES = 'src/views/security/SecurityRules.vue'

// pattern 列的闭合点：紧随其后的删除动作（只锚定行为标识，不锚属性书写顺序）。
const PATTERN_COL_END = 'removeCondition(idx)'

test('正则模板与 UA 快捷标签是条件行的整行子块，不再嵌在 pattern 列内', () => {
  const text = code(SECURITY_RULES)

  // section() 对缺失 marker 硬失败：模板被重排到别处时用例红而不是空转。
  const patternColumn = section(text, '<div class="pattern-col">', PATTERN_COL_END)
  assert.doesNotMatch(
    patternColumn,
    /class="preset-section"/,
    'preset-section 不得回退进 .pattern-col（会被 flex:1 窄列压成内缩小块）',
  )
  assert.match(patternColumn, /class="pattern-input-row"/, '前置：pattern 列内应只剩输入行（切片未漂移）')

  // 条件行尾部（删除按钮之后、下一条条件/添加按钮之前）必须是模板区。
  const rowTail = section(text, PATTERN_COL_END, '<div class="add-condition-row">')
  assert.match(rowTail, /class="preset-section"/, 'preset-section 必须是条件行的直接子块（整行左对齐）')
  assert.match(rowTail, /v-if="cond\.target === 'user_agent'"/, 'UA 快捷标签块必须在行级')
  assert.match(rowTail, /v-if="cond\.operator === 'regex'"/, '正则模板块必须在行级')
})

test('.preset-section 占满整行（flex 基准 100% + width 100%）', () => {
  const text = code(SECURITY_RULES)
  const rule = section(text, '.preset-section {', '.preset-header {')
  assert.match(rule, /flex:\s*1 1 100%/, 'preset-section 必须整行占位（缺省会退化为按内容宽度收缩）')
  assert.match(rule, /width:\s*100%/, 'preset-section 必须整宽（否则按钮行不贴行内左缘）')
})

test('.regex-extras 内容左对齐且整宽', () => {
  const text = code(SECURITY_RULES)
  const rule = section(text, '.regex-extras {', '.regex-presets {')
  assert.match(rule, /align-items:\s*flex-start/, 'regex-extras 必须左对齐（居中会把模板按钮推离行内左缘）')
  assert.match(rule, /width:\s*100%/, 'regex-extras 必须整宽（不设置会按内容收缩、与上方输入行错位）')
})
