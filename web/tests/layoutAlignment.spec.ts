// 三处对齐修复的机械钉测（2026-11-22 用户裁定样式项）：
//   1) 规则库「定时更新」卡片：时间选择框高度=左侧星期选择框高度且垂直居中；
//   2) IP 地址列表 tab：搜索框与「+新建列表」按钮垂直居中对齐；
//   3) 自定义规则条件行：删除按钮与左侧输入框垂直对齐。
// 断言取声明表（不依赖属性书写顺序），只钉「属性存在且值正确」。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, cssDeclarations, section } from './_helpers.ts'

test('定时更新卡片：控件行垂直居中（多选框换行增高时时间框/按钮中线对齐）', () => {
  const editor = code('src/components/RuleLibScheduleEditor.vue')
  const controls = cssDeclarations(editor, '.schedule-editor__controls')
  // 2026-11-22 三轮纠偏终版：居中而非拉伸——Element 的 .el-date-editor 显式
  // height:32px 压过 align-self:stretch（拉伸恒失效），两行标签时时间框顶部
  // 悬挂。浏览器实测（560px/7 标签两行 92px）：center 语义下时间框/按钮与
  // 星期框中线偏差 0px；单行 32px 全等高。
  assert.equal(controls.get('align-items'), 'center', '控件行必须垂直居中（stretch 被 el-date-editor 显式高度压制=顶部悬挂根因）')
  const time = cssDeclarations(editor, '.schedule-editor__time')
  assert.ok(!time.has('align-self'), '时间框不得再写 stretch 覆写（已被实测证伪）')
  assert.ok(!time.has('height'), '时间框不得覆写 height（保持 Element 原生高度参与居中）')
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
