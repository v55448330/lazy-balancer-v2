import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

test('IP 快捷添加统一走共享写入链，只有完成时才收起目标面板', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  const execute = member(page, 'const executeAdd = async')
  assert.match(execute, /joinSpecificList\(/, '名单分支必须复用 useIpListAdd 的共享包装')
  assert.match(execute, /ensureListAndJoin\(/, '自动建单分支继续复用信任关联组合子')
  assert.doesNotMatch(execute, /request\.post<[^>]+>\(`\/security\/ip-lists\/\$\{target\.listId\}\/ips`/, '弹框不得保留第二份名单 POST')
  assert.match(execute, /if \(done\) \{[\s\S]*activeAddSide\.value = null/, '取消或失败时不得收起目标面板')

  const association = code('src/composables/useTrustAssociation.ts')
  assert.match(association, /ensureListAndJoin = async \([^)]*\): Promise<boolean>/, '调用方需要可区分的完成/取消/失败结果')
})

test('IP 弹框首开先完成名单快照，再读取自动封禁，避免重复 GET', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  const show = member(page, 'const onPopoverShow =')
  assert.match(show, /await loadAll\(\)/, '自动封禁读取前必须等待名单快照')
  assert.ok(show.indexOf('await loadAll()') < show.indexOf('loadAutoban()'), 'loadAutoban 不得与首次 loadAll 并发')
  assert.doesNotMatch(show, /void loadAll\(\)\s*void loadAutoban\(\)/, '首开并发会重复请求 /security/ip-lists')
})

test('策略向导关闭前核对完整编辑快照，脏状态需确认放弃', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const snapshot = member(page, 'const wizardStateSnapshot =')
  for (const field of ['form', 'boundRules', 'bindingOrderEdits', 'ipACLList', 'ipWhitelist', 'crsExcludedRows']) {
    assert.match(snapshot, new RegExp(`\\b${field}\\b`), `未保存判定遗漏 ${field}`)
  }
  const close = member(page, 'const beforeWizardClose =')
  assert.match(close, /if \(saving\.value\) return/, '保存中仍禁止关闭')
  assert.match(close, /if \(!wizardDirty\.value\)/, '无修改时直接关闭')
  assert.match(close, /ElMessageBox\.confirm\(/, '有未保存修改时必须确认')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(close, /t\('app\.security\.policies\.msg\.discard'\)/, '确认动作必须明示后果')
  assert.ok(code('src/locales/zh/security.ts').includes('放弃修改'), '放弃修改原文必须在 zh 母本词条中')
})

test('导入条目随保存合并：上限门按合并后生效条数拦截（早于任何 entries.push）', () => {
  // 2026-11-02 交互重设计：点导入即判定重复（弹框点名、不写表），新条目暂存；
  // 保存时合并暂存条目并走同一额度校验（重复条目在导入时已被排除）。
  const page = code('src/views/security/SecurityRules.vue')
  const importFlow = section(page, 'reader.onload = () => {', '\n  }')
  assert.match(importFlow, /computeImportOutcome\(existingValues, importLines/, '导入时必须走判定单源（弹重复框、暂存新条目）')
  assert.match(importFlow, /ipListForm\.value\.entries\.push\(\.\.\.outcome\.newEntries\)/, '新条目导入即渲染进条目表')
  const save = member(page, 'const saveIpList =')
  const cap = save.indexOf('activeEntryCount > IP_LIST_MAX_ENTRIES')
  assert.ok(cap >= 0, '上限门按含导入条目的全量表校验')
  assert.match(save, /autobanEntryExpired/, '现有到期条目不得占用导入额度')
})

test('威胁大屏配置到达前和读取失败时均不默认全量采样', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  assert.match(page, /const activeSampleN = ref\(0\)/, '首帧必须以关闭采样起步')
  const load = member(page, 'async function loadServerCentroid')
  assert.match(load, /activeSampleN\.value = flowSampleN\.value === 0 \? 0 : 1/, '配置到达后再按配置启用采样')
  const failure = load.slice(load.indexOf('} catch {'))
  assert.doesNotMatch(failure, /activeSampleN\.value = 1/, '配置失败不得回退全量')
})

test('拦截页刷新失败横幅区分旧快照与空列表', () => {
  const page = code('src/views/security/SecurityBlockPages.vue')
  // i18n 后双钉:调用点钉键,zh 母本钉两句横幅原文(任一漂移必红)
  assert.match(page, /pages\.length > 0 \? t\('app\.security\.blockPages\.alert\.loadFailedStale'\) : t\('app\.security\.blockPages\.alert\.loadFailedEmpty'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('拦截页面加载失败：当前显示的是上次成功结果'), '旧快照横幅原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('拦截页面加载失败：列表为空不代表没有页面'), '空列表横幅原文必须在 zh 母本词条中')
})

test('安全总览今日计数 tooltip 仅拦截列保留（同一计算文案单源）', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /const todayCountTip = computed\(/)
  assert.equal((page.match(/<el-tooltip :content="todayCountTip"/g) ?? []).length, 1, '重设计后仅拦截列保留口径 tooltip')
  // i18n 后双钉:调用点钉键(全页仅一处),zh 母本钉原文(任一漂移必红)
  assert.equal((page.match(/t\('app\.security\.overview\.status\.tipReserved'\)/g) ?? []).length, 1, '完整口径文案只能保留一份')
  assert.ok(code('src/locales/zh/security.ts').includes('总量含私网/保留地址事件'), '完整口径原文必须在 zh 母本词条中')
})

test('拦截页恒为双档：无响应模式单选，JSON 页签常驻且可高亮编辑', () => {
  const page = code('src/views/security/SecurityBlockPages.vue')
  assert.doesNotMatch(page, /bodyMode|singleContentType|modeSingle|dualModeTip/, '旧单档/响应模式选择必须移除')
  assert.match(page, /<el-tab-pane :label="t\('app.security.blockPages.dialog.labelJson'\)" name="json">/, 'JSON 页签不得再受单/双档条件控制')
  assert.match(page, /<CodeEditor[^>]*v-model="form\.json_content"[^>]*language="json"/, 'JSON 输入必须使用 json 高亮编辑器')
  assert.match(page, /resolvedJson\(row\.json_content \|\| '', content\)/, '预览回退必须从页面 HTML 派生，不得写死文案')
})

test('关联规则链条目：统一序号+阶段色类，不再出现阶段 0 特判文案', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  assert.doesNotMatch(page, /stage0Precedence|isStage0ChainEntry/, '阶段 0 特殊措辞/判定必须移除')
  assert.match(page, /return `\$\{index \+ 1\}\.\$\{name\}`/, '链条目必须统一按序号展示')
  assert.match(page, /\['stage-' \+ chainEntryStageKey\(entry\)/, '每条目必须带阶段色类')
  for (const cls of ['stage-0', 'stage-1', 'stage-2', 'stage-3']) {
    assert.ok(page.includes(`.binding-order-chip.${cls} {`), `${cls} 必须定义独立颜色`)
  }
  assert.match(page, /\.binding-order-chip\.is-self \{ font-weight: 700;/, '本策略必须加粗')
})

test('安全策略可选拦截响应方式（auto/html/json）', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  assert.match(page, /v-model="form\.block_response_mode"/)
  assert.match(page, /value="auto"[\s\S]*value="html"[\s\S]*value="json"/)
  const payload = code('src/utils/policyPayload.ts')
  assert.match(payload, /block_response_mode: input\.blockResponseMode/)
})

test('内置人机验证页（9005 滑块 / 9006 JS）名称/描述支持中英切换', () => {
  const util = code('src/utils/builtinBlockPages.ts')
  assert.match(util, /9005:\s*'human'/, '9005 必须映射到 human 词条，否则英文界面回退中文库存名')
  assert.match(util, /9006:\s*'humanJs'/, '9006 必须映射到 humanJs 词条，否则英文界面回退中文库存名')
  const zh = code('src/locales/zh/security.ts')
  const en = code('src/locales/en/security.ts')
  assert.match(zh, /"human": \{ "name": "滑块人机验证页面"/)
  assert.match(zh, /"humanJs": \{ "name": "JS 人机验证页面"/)
  assert.match(en, /"human": \{ "name": "Slider Human Verification Page"/)
  assert.match(en, /"humanJs": \{ "name": "JS Human Verification Page"/)
})
