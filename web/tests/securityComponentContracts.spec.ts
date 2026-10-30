import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

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
  for (const field of ['form', 'boundRules', 'pendingOverrideRules', 'ipACLList', 'ipWhitelist', 'crsExcludedRows']) {
    assert.match(snapshot, new RegExp(`\\b${field}\\b`), `未保存判定遗漏 ${field}`)
  }
  const close = member(page, 'const beforeWizardClose =')
  assert.match(close, /if \(saving\.value\) return/, '保存中仍禁止关闭')
  assert.match(close, /if \(!wizardDirty\.value\)/, '无修改时直接关闭')
  assert.match(close, /ElMessageBox\.confirm\(/, '有未保存修改时必须确认')
  assert.match(close, /放弃修改/, '确认动作必须明示后果')
})

test('IP 导入在写入表单前按剩余生效额度拒绝超限文件', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const flow = member(page, 'const importEntriesFromText =')
  assert.match(flow, /candidates/, '先解析候选，不得边解析边写入表单')
  assert.match(flow, /IP_LIST_MAX_ENTRIES - activeExistingCount/, '额度必须扣除现有生效条目')
  assert.match(flow, /candidates\.length > remaining/, '超限必须在导入前拦截')
  const gate = flow.indexOf('candidates.length > remaining')
  const push = flow.indexOf('ipListForm.value.entries.push')
  assert.ok(gate >= 0 && push > gate, '上限门必须早于任何 entries.push')
  assert.match(flow, /autobanEntryExpired/, '现有到期条目不得占用导入额度')
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
  assert.match(page, /pages\.length > 0 \? '拦截页面加载失败：当前显示的是上次成功结果' : '拦截页面加载失败：列表为空不代表没有页面'/)
})

test('安全总览今日计数 tooltip 仅拦截列保留（同一计算文案单源）', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /const todayCountTip = computed\(/)
  assert.equal((page.match(/<el-tooltip :content="todayCountTip"/g) ?? []).length, 1, '重设计后仅拦截列保留口径 tooltip')
  assert.equal((page.match(/总量含私网\/保留地址事件/g) ?? []).length, 1, '完整口径文案只能保留一份')
})
