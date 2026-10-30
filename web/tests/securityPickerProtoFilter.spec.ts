// 策略关联规则 / 绑定规则弹框的协议筛选（2026-10-31 用户裁定）：
//   ①两处选择器加协议筛选控件（全部/HTTP/TCP，默认 HTTP）——TCP（L4 阶段 0/1）
//     放开后选择器混排 HTTP/TCP，默认只看 HTTP 保持既有选择视野；
//   ②列表行显著标注协议类型：TCP 青色徽标走全局 .proto-tcp-tag 单源
//     （原 warning 口径废弃），HTTP 行补蓝徽标——混排后逐行可辨识；
//   ③TCP 行能力门置灰逻辑保持：含限流/WAF 特征的策略对 TCP 不可选，
//     筛选只收窄候选列表，不改判据。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

const policies = code('src/views/security/SecurityPolicies.vue')
const editor = code('src/components/SecurityBindingEditor.vue')

test('策略向导关联规则选择器：协议筛选默认 HTTP，三档可切', () => {
  assert.match(policies, /const pickerProtoFilter = ref<'all' \| 'http' \| 'tcp'>\('http'\)/, '默认档必须是 HTTP（保持既有选择视野）')
  // 控件与三档选项
  assert.match(policies, /v-model="pickerProtoFilter"/)
  assert.match(policies, /<el-option label="全部" value="all" \/>/)
  assert.match(policies, /<el-option label="HTTP" value="http" \/>/)
  assert.match(policies, /<el-option label="TCP" value="tcp" \/>/)
})

test('策略向导关联规则选择器：筛选作用于候选列表并复位分页', () => {
  const filtered = section(policies, 'const pickerFilteredRules = computed', 'const pickerPagedRules')
  assert.match(filtered, /pickerProtoFilter\.value/, '筛选必须消费协议档')
  assert.match(filtered, /=== 'all'/, '全部档不按协议收窄')
  assert.match(filtered, /=== 'tcp'/, 'TCP 档只列 TCP 规则')
  assert.match(filtered, /rule\.protocol/, '按规则协议字段过滤')
  assert.match(policies, /watch\(pickerProtoFilter,/, '切档必须回到第 1 页（同搜索复位先例）')
})

test('策略向导关联规则选择器：打开弹框复位筛选默认档', () => {
  const open = member(policies, 'const openRulePicker = ')
  assert.match(open, /pickerProtoFilter\.value = 'http'/, '每次打开回落默认 HTTP（与搜索复位同型）')
})

test('策略向导关联规则选择器：行协议徽标复用全局单源（TCP 青 / HTTP 蓝）', () => {
  assert.match(policies, /class="proto-tcp-tag rule-picker-proto">TCP<\/el-tag>/, 'TCP 徽标必须走全局 proto-tcp-tag 单源（warning 口径废弃）')
  assert.match(policies, /type="primary" effect="plain" class="rule-picker-proto">HTTP<\/el-tag>/, 'HTTP 行也要有徽标（混排后逐行可辨识）')
  assert.doesNotMatch(policies, /type="warning"[^>]*rule-picker-proto/, '不得残留 warning 口径协议徽标')
})

test('策略向导关联规则选择器：TCP 行能力门置灰逻辑保持', () => {
  const meta = section(policies, 'const pickerMeta = (rule: Rule)', 'return { chain, selfPos:')
  assert.match(meta, /policySupportsTcp\(editorPolicyType\.value\)/)
  assert.match(meta, /TCP_BIND_UNSUPPORTED_REASON/)
})

test('绑定规则弹框（策略侧规则选择器）：协议筛选默认 HTTP，三档可切', () => {
  assert.match(editor, /const pickerProtoFilter = ref<'all' \| 'http' \| 'tcp'>\('http'\)/)
  assert.match(editor, /v-model="pickerProtoFilter"/)
  assert.match(editor, /<el-option label="全部" value="all" \/>/)
  assert.match(editor, /<el-option label="HTTP" value="http" \/>/)
  assert.match(editor, /<el-option label="TCP" value="tcp" \/>/)
})

test('绑定规则弹框（策略侧规则选择器）：筛选作用于候选列表并复位分页', () => {
  const filtered = section(editor, 'const pickerFilteredRules = computed', 'const pickerPagedRules')
  assert.match(filtered, /pickerProtoFilter\.value/)
  assert.match(filtered, /=== 'all'/)
  assert.match(filtered, /=== 'tcp'/)
  assert.match(filtered, /rule\.protocol/)
  assert.match(editor, /watch\(pickerProtoFilter,/)
})

test('绑定规则弹框（策略侧规则选择器）：打开复位筛选默认档', () => {
  const open = member(editor, 'const onOpen = ')
  assert.match(open, /pickerProtoFilter\.value = 'http'/)
})

test('绑定规则弹框（策略侧规则选择器）：行协议徽标复用全局单源（TCP 青 / HTTP 蓝）', () => {
  assert.match(editor, /class="proto-tcp-tag picker-proto-tag">TCP<\/el-tag>/)
  assert.match(editor, /type="primary" effect="plain" class="picker-proto-tag">HTTP<\/el-tag>/)
  assert.doesNotMatch(editor, /type="warning"[^>]*picker-proto-tag/)
})

test('绑定规则弹框：TCP 规则 × 含限流/WAF 特征策略的置灰门保持', () => {
  const reason = member(editor, 'const pickerBlockReason = ')
  assert.match(reason, /rule\.protocol === 'tcp' && !policySupportsTcp\(currentPolicyType\.value \?\? undefined\)/)
  assert.match(reason, /TCP_BIND_UNSUPPORTED_REASON/)
})
