// 三处对齐修复的机械钉测（2026-11-22 用户裁定样式项）：
//   1) 规则库「定时更新」卡片：时间选择框高度=左侧星期选择框高度且垂直居中；
//   2) IP 地址列表 tab：搜索框与「+新建列表」按钮垂直居中对齐；
//   3) 自定义规则条件行：删除按钮与左侧输入框垂直对齐。
// 断言取声明表（不依赖属性书写顺序），只钉「属性存在且值正确」。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, cssDeclarations, section } from './_helpers.ts'

test('定时更新卡片：两输入框严格同高 32px（原生容器锚定 + 特异性 ≥ 全局输入壳规则）', () => {
  const editor = code('src/components/RuleLibScheduleEditor.vue')
  const controls = cssDeclarations(editor, '.schedule-editor__controls')
  assert.equal(controls.get('align-items'), 'center', '控件行垂直居中')
  // 终版（2026-11-22 用户裁定「不接受一高一低」，浏览器实测 heightDelta=0/centerDelta=0）：
  // ①锚定必须用原生容器（.schedule-editor__controls 有 data-v）——el-time-picker/
  //   el-select 组件根只透传 class 不带 scoped attr，挂在 .schedule-editor__time[data-v]
  //   的 :deep 从不匹配（历轮全灭根因）；
  // ②统一 32px=多选框单行标签自然高度（不压扁）；时间输入壳全局规则是
  //   .el-input.el-input:not(--large) .el-input__wrapper=28px 且特异性 (0,4,0)，
  //   覆写必须 (0,4,0)+（.schedule-editor 前缀）且后源注入。
  const selWrap = cssDeclarations(editor, '.schedule-editor .schedule-editor__controls :deep(.el-select__wrapper)')
  assert.equal(selWrap.get('height'), '32px', '多选壳钉 32px（与时间框自然同高）')
  const inputWrap = cssDeclarations(editor, '.schedule-editor .schedule-editor__controls :deep(.el-input__wrapper)')
  assert.equal(inputWrap.get('height'), '32px', '时间输入壳覆写回 32px（全局 28px 顶对齐分叉根因）')
  assert.ok(!/schedule-editor__time[^{]*:deep/.test(editor), ':deep 不得锚在组件根 class（无 data-v，恒不匹配）')
})

test('IP 地址列表 tab：工具栏 flex 垂直居中（搜索框与新建按钮对齐）', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const toolbar = cssDeclarations(page, '.table-toolbar')
  assert.equal(toolbar.get('align-items'), 'center', '工具栏必须显式垂直居中（默认 stretch 会把按钮拉高错位）')
  assert.equal(toolbar.get('display'), 'flex')
  // 该工具栏确实是 IP 列表 tab 的容器（共用类不得被改名前误伤）
  const ipTab = section(page, 'name="ip-lists"', '</el-tab-pane>')
  assert.match(ipTab, /class="table-toolbar ip-list-toolbar"/)
  assert.match(ipTab, /class="search-input"/)
  assert.match(ipTab, /ipTab\.newList/)
})

test('自定义规则条件行：删除按钮高度=输入框高度（24px small）且内容居中', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const button = cssDeclarations(page, '.rule-condition-row .el-button--danger')
  assert.equal(button.get('align-self'), 'flex-start', '按钮与第一行输入框顶端对齐')
  assert.equal(button.get('height'), '24px', 'link 按钮默认 height:auto（22px）与 small 输入框 24px 错位')
  assert.equal(button.get('padding'), '0 2px')
  // 条件行输入控件确为 small（24px）档位
  const row = section(page, 'class="rule-condition-row"', 'class="add-condition-row"')
  assert.match(row, /size="small"/)
})
