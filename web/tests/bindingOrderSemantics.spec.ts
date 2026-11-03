// 绑定执行序与 CRS 排除 UI 语义钉（归一还原反馈/区间 ghost 释义/去重键归一 + 链序展平/orders 合并 消费面）：
//  - 归一还原反馈 moveSelfInChain：相邻 stage0×非 stage0 交换被阶段 0 置顶归一还原 =
//    触发顺序不变的无效点击，必须给 ElMessage.info 显式反馈（保留现状行为不硬禁用）。
//  - 区间 ghost 释义 排除目标 ghost 标签：区间遗留形态（如「942100-942199」手输）补释义
//    title——区间按字面保存并按字面下发（SecRuleRemoveById 区间，security.go:811
//    逐条 scopeAllTargets 直出、不展开组内 ID），作用域限定不支持区间目标
//    （security.go:2708「仅 scope=all」+ 保存侧已拒）。
//  - 去重键归一 排除行去重键元素顺序敏感归一：ips/listRefs 排序后参与键（仅键归一，
//    载荷保持用户输入序）；与后端 dedupeCRSExcludedEntries 的 refs 排序键同族口径。
//  - 链序展平/orders 合并 消费面：编辑器提交序走 flattenBindingOrder、向导 orders 走
//    mergeChainOrder（utils 单源，防死代码 + 残留内联旧实现）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, code } from './_helpers.ts'

const page = code('src/views/security/SecurityPolicies.vue')
const editor = code('src/components/SecurityBindingEditor.vue')

test('归一还原反馈 moveSelfInChain：归一还原分支给 info 反馈，不硬禁用', () => {
  const move = section(page, 'const moveSelfInChain', 'interface MigratePolicyResult')
  // 归一还原检测：交换后 normalizeOrder 逐位比较未变 = 相邻 stage0×非 stage0
  assert.match(move, /JSON\.stringify\(normalizeOrder\(next\)\) === JSON\.stringify\(normalizeOrder\(order\)\)/)
  assert.match(move, /ElMessage\.info\('相邻为信任名单策略（阶段 0 恒置顶），交换不改变触发顺序'\)/)
  // 保留现状行为：暂存照常写入（不硬禁用按钮、不阻断操作）
  assert.match(move, /bindingOrderEdits\.value = \{ \.\.\.bindingOrderEdits\.value, \[caddyId\]: next \}/)
})

test('区间 ghost 释义 排除目标 ghost：区间遗留形态补释义 title', () => {
  // 释义单源函数 + 模板接线（title 不再恒等于裸值）
  assert.match(page, /const exclusionRowGhostTitle = \(target: string\): string =>/, '释义函数必须存在')
  const ghostTag = section(page, 'v-if="exclusionRowGhostLabel(row.target) !== \'\'"', '@close="row.target = \'\'"')
  assert.match(ghostTag, /:title="exclusionRowGhostTitle\(row\.target\)"/, 'ghost 标签 title 必须走释义函数')
  // 区间分支：与保存/发射事实一致的措辞（字面保存下发、不展开组内 ID、仅全部 IP 作用域）
  const ghostTitle = section(page, 'const exclusionRowGhostTitle', 'const crsFieldsOff')
  assert.match(page, /const CRS_RANGE_TARGET_RE = \/\^\(\\d\{6\}\)\\s\*\[-:\]\\s\*\(\\d\{6\}\)\$\//, '区间形态判定须单源共用（6 位数字区间，含 [-:] 分隔）')
  assert.match(ghostTitle, /CRS_RANGE_TARGET_RE\.test\(v\)/)
  assert.match(ghostTitle, /按字面保存/)
  assert.match(ghostTitle, /不展开.{0,6}组内 ID|不展开为规则组内全部规则 ID/)
  assert.match(ghostTitle, /作用域/)
})

test('去重键归一 排除行去重键：ips/listRefs 排序后参与键，载荷保持输入序', () => {
  const serialized = section(page, 'const serializedExcludedRules', 'const isFilledExclusionRow')
  assert.match(serialized, /\[\.\.\.row\.ips\]\.sort\(\)\.join\(','\)/, 'ips 必须排序后参与去重键')
  assert.match(serialized, /\[\.\.\.row\.listRefs\]\.sort\(\(a, b\) => a - b\)\.join\(','\)/, 'listRefs 必须数值排序后参与去重键')
  // 载荷本身保持用户输入序（仅键归一，不做载荷排序）
  assert.match(serialized, /ips: row\.scope === 'ip' \? \[\.\.\.row\.ips\] : \[\]/)
  assert.match(serialized, /listRefs: row\.scope === 'list' \? \[\.\.\.row\.listRefs\] : \[\]/)
})

test('链序展平 消费面：规则侧提交序走 flattenBindingOrder 单源，不再阶段聚集展平', () => {
  assert.match(editor, /flattenBindingOrder\(/, '编辑器提交序必须走 utils 单源')
  assert.doesNotMatch(editor, /\[\.\.\.bindStage0\.value, \.\.\.bindStage1\.value/, '旧阶段聚集展平必须移除')
  // 阶段 2 唯一门保留：提交桶仍按界面可见首条切片
  assert.match(editor, /bindStage2\.value\.slice\(0, 1\)/)
})

test('orders 合并 消费面：向导 orders 走 mergeChainOrder，最新基线为底', () => {
  const tail = section(page, 'const bindResponses', 'const mergedBind')
  assert.match(tail, /mergeChainOrder\(/, 'orders 载荷必须经 mergeChainOrder 与最新基线合并')
  assert.match(tail, /serverChainOrder\(caddyId\)/, '合并底座必须是最新服务端基线链')
  assert.match(tail, /bindingOrderEdits\.value\[caddyId\]/, 'staged 相对重排是合并输入')
})

test('normalizeOrder 单源：组件归一委托 normalizePolicyChainOrder', () => {
  assert.match(page, /normalizePolicyChainOrder\(/, '阶段 0 置顶归一必须单源到 utils')
})
