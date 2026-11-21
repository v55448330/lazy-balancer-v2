// 默认策略弹框（POST /security/policies/apply-defaults）接线钉：
//  1) 退化 200 判定键集必须覆盖 k_7d87740a（DB 已提交但重载 Caddy 失败）；
//  2) 成功/退化一律经 showSaveResult（不得再恒 success 掩盖重载失败）；
//  3) 失败分支不得伪造部分进度（单事务整体回滚，失败信封无已建项）；结果集
//     为空时失败名单回落「状态未知」文案（audit153 FE153-02）；
//  4) 任何未走到 done 的路径经 finally 退出 running（否则弹框永久锁死）；
//  5) 打开先清目录快照再拉取（不留上一轮旧状态）；目录加载失败弹框内可重拉；
//  6) 失败项点名（仅在有结果集时）+ 重试按钮；catalog status=disabled 行标签走 warning。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, section } from './_helpers.ts'
import { isCaddyApplyDegraded } from '../src/utils/bulkApplyResult.ts'

const SRC = code('src/views/security/SecurityPolicies.vue')

test('退化 200 判定键集覆盖 k_7d87740a（apply-defaults 重载失败）', () => {
  // 行为钉：两个键同语义（已提交、Caddy 未生效），任一缺登记 = 该端点族失败对 UI 不可见。
  assert.equal(isCaddyApplyDegraded({ message: 'saved; reload failed', messageKey: 'k_7d87740a' }), true)
  assert.equal(isCaddyApplyDegraded({ messageKey: 'k_de8cc6aa' }), true)
  assert.equal(isCaddyApplyDegraded({ message: 'Saved', messageKey: 'k_other' }), false)
  assert.equal(isCaddyApplyDegraded({ message: 'Saved' }), false)
})

test('apply 结果经 showSaveResult 呈现：退化走常驻警告，不再恒 success', () => {
  const fn = section(SRC, 'const runApplyDefaults = async', '\n}')
  assert.match(fn, /showSaveResult\(res, t\('app\.security\.policies\.defaults\.doneToast'\)\)/, '退化 200 必须经 showSaveResult 单源判定')
  assert.doesNotMatch(fn, /ElMessage\.success/, '恒 success 会把「重载失败」伪装成成功')
})

test('失败分支不伪造部分进度（事务整体回滚：失败信封无已建项）', () => {
  const fn = section(SRC, 'const runApplyDefaults = async', '\n}')
  assert.doesNotMatch(fn, /e\.data/, '失败信封 Data 恒空（单事务回滚）——读它恒 undefined（死代码）')
  assert.doesNotMatch(fn, /partial/, '不得保留「部分成功」错觉变量')
  assert.match(fn, /defaultsFlowSettled\(false\)/, '失败必须走纯函数落定（done+failed）')
})

test('失败即完成态：finally 兜底退出 running（弹框可关、可重试）', () => {
  const fn = section(SRC, 'const runApplyDefaults = async', '\n}')
  const finallyBlock = section(fn, 'finally {', '\n  }')
  assert.match(finallyBlock, /defaultsPhase\.value === 'running'/)
  assert.match(finallyBlock, /defaultsFlowSettled\(false\)/, '兜底路径按失败落定（done+failed）')
  // 失败标记经纯函数重置/置位（起始清、失败置）
  assert.match(fn, /defaultsFlowStarting\(\)/)
  assert.match(fn, /defaultsFlowSettled\(true\)/)
})

test('打开弹框先清目录快照再拉取（不残留上一轮状态）；目录失败可重拉', () => {
  const open = section(SRC, 'const openDefaultsDialog = async', '\n}')
  assert.match(open, /defaultsCatalog\.value = null/, '打开时必须清空 defaultsCatalog')
  assert.match(open, /await loadDefaultsCatalog\(\)/, '清空后经单源加载函数拉取')
  const load = section(SRC, 'const loadDefaultsCatalog = async', '\n}')
  assert.match(load, /request\.get<APIResponse<DefaultCatalog>>\('\/security\/policies\/default-catalog'\)/)
  assert.match(load, /defaultsLoadFailed\.value = true/)
  assert.match(load, /defaultsLoading\.value = false/)
})

test('失败项点名（有结果集时）+ 重试按钮；无结果集回落状态未知文案', () => {
  assert.match(SRC, /const defaultsFailedNames = computed<string\[\]>\(\(\) =>\s*\n\s*failedDefaultNames\(/, '失败项差集走 utils 纯函数单源')
  assert.doesNotMatch(SRC, /applied\.has\('list' \+ l\.name\)/, '差集实现不得回落到 SFC 内联')
  assert.match(SRC, /t\('app\.security\.policies\.defaults\.failedItemsTip', \{ count: defaultsFailedNames\.length \}\)/)
  assert.match(SRC, /t\('app\.security\.policies\.defaults\.statusUnknownTip'\)/, '无结果集必须提示状态未知，不穷举名单')
  assert.match(SRC, /v-for="n in defaultsFailedNames"/, '失败项必须逐条展示')
  assert.match(SRC, /t\('app\.security\.policies\.defaults\.retry'\)/, '必须有重试按钮文案')
})

test('catalog disabled 形态：warning 行标签 + 重置可恢复入口（确认文案不静默删重建）', () => {
  // disabled 不属于 missing/exists/created → 落入 warning 分支（显式钉住，防未来改判 info）
  assert.match(SRC, /const defaultsStatusTagType = \(status: string\)[^=]*=>\s*\n\s*status === 'missing' \|\| status === 'exists' \? 'info' : status === 'created' \? 'success' : 'warning'/)
  assert.ok(code('src/locales/zh/security.ts').includes('"disabled": "已存在（已禁用）"'), 'zh 必须显性表达「已禁用」')
  assert.ok(code('src/locales/en/security.ts').includes('"disabled": "Exists (disabled)"'), 'en 对应词条必须在位')
  // disabled 视为「已存在」：apply（非 reset）不改写它（后端约定 disabled 既不算
  // exists 也不算 missing），若仍按严格 exists 判定，含禁用项时永远停在「开始创建」
  // 空操作，reset 入口不可达=禁用态不可恢复。
  assert.match(SRC, /const present = \(s: string\): boolean => s === 'exists' \|\| s === 'disabled'/)
  assert.match(SRC, /cat\.lists\.every\(\(l\) => present\(l\.status\)\) && cat\.policies\.every\(\(p\) => present\(p\.status\)\)/)
  // 重置可恢复必须在两处可见：预览提示 + reset 专用确认文案（不静默删重建）
  assert.match(SRC, /const defaultsDisabledCount = computed/)
  assert.match(SRC, /defaults\.disabledTip/)
  assert.match(SRC, /reConfirmWithDisabled/)
  assert.ok(code('src/locales/zh/security.ts').includes('"reConfirmWithDisabled"'))
  assert.ok(code('src/locales/en/security.ts').includes('"reConfirmWithDisabled"'))
  assert.ok(code('src/locales/zh/security.ts').includes('"disabledTip"'))
  assert.ok(code('src/locales/en/security.ts').includes('"disabledTip"'))
})
