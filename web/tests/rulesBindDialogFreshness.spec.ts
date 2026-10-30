// 规则页安全绑定弹框的数据新鲜度（2026-10-31 用户裁定，#4 排查结论的钉测）：
//
// 根因：规则页锁 popover / 流程弹框 / 安全绑定弹框共享 securityBindings 单源
// （这部分本就是单一数据源），但该源的刷新时机只有「页面挂载 / 编辑器保存
// @saved / 手动重试」——策略页向导/绑定规则弹框、或他标签页在页面加载之后
// 产生的绑定变更不会到达本页：绑定弹框以挂载时快照预选与算 delta，锁
// popover 与流程弹框投影同快照，直到 F5 才可见。HTTP 规则同病（同一代码
// 路径，无任何协议条件）。
//
// 修复口径（单一数据源 + 到达时机）：
//   ①openBindDialog 打开前重取快照（与策略页 openBindRulesDialog 同门：
//     就绪门 → 刷新 → 失败不打开）；
//   ②页面重新可见（visibilitychange）时静默刷新绑定快照——弹框打开期间跳过
//    （编辑器按打开时快照计算整集替换 delta，中途换快照会干扰行内摘要/预选）；
//   ③@saved → fetchSecurityBindings（既有）保持钉住。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

const rules = code('src/views/Rules.vue')

test('打开绑定弹框前重取快照，失败不打开（旧快照 delta ≠ 当前绑定集）', () => {
  const open = member(rules, 'const openBindDialog = ')
  assert.match(open, /async/, '打开函数必须等刷新完成后再开')
  const refreshAt = open.indexOf('await fetchSecurityBindings(true)')
  const visibleAt = open.indexOf('bindDialogVisible.value = true')
  assert.ok(refreshAt > 0, '必须打开前刷新一次快照（含策略目录：编辑器类型门与投影依赖）')
  assert.ok(visibleAt > refreshAt, '刷新成功后才可打开')
  assert.match(open, /if \(securityBindingsError\.value\) \{/)
  assert.match(open, /ElMessage\.error\(/, '刷新失败必须显性报错并保持弹框关闭')
})

test('打开函数持就绪门：加载中 / 失败 / 打开中 不可重入', () => {
  const open = member(rules, 'const openBindDialog = ')
  assert.match(open, /bindDialogOpening\.value = true/)
  assert.match(open, /finally \{\s*bindDialogOpening\.value = false\s*\}/, 'finally 释放就绪门')
  assert.match(rules, /:disabled="isReadOnly \|\| saving \|\| securityBindingsLoading \|\| securityBindingsError \|\| bindDialogOpening"/, '按钮呈现层同步禁用')
})

test('打开路径无协议条件：HTTP 与 TCP 同门（同病回归钉）', () => {
  const open = member(rules, 'const openBindDialog = ')
  assert.doesNotMatch(open, /protocol/, '协议差异化由编辑器选择侧与后端门承接，打开路径不分支')
})

test('页面重新可见时静默刷新绑定快照（弹框打开期间跳过）', () => {
  assert.match(rules, /document\.addEventListener\('visibilitychange', onSecurityVisibilityChange\)/)
  assert.match(rules, /document\.removeEventListener\('visibilitychange', onSecurityVisibilityChange\)/, '卸载必须摘监听')
  const handler = member(rules, 'const onSecurityVisibilityChange = ')
  assert.match(handler, /visibilityState !== 'visible'/)
  assert.match(handler, /bindDialogVisible\.value \|\| flowDialogVisible\.value/, '任一安全弹框打开期间不刷新（换快照会干扰整集替换 delta）')
  assert.match(handler, /fetchSecurityBindings\(\)/, '可见性刷新只补绑定快照（目录在打开弹框时重取）')
})

test('弹框保存后即时刷新单源：@saved → fetchSecurityBindings（既有行为钉住）', () => {
  assert.match(rules, /@saved="fetchSecurityBindings"/)
})
