// 钉：
//  1) 失败项差集只在「有结果集」时才有语义——事务回滚/请求失败时结果集为空，
//     拿全目录差集会把「一项都没建」误报成「全部失败」；无结果集必须回落
//     「状态未知」文案（不让穷举名单冒充事实）。
//  2) 重试状态流转（preview→running→done/failed）抽成纯函数，组件只做赋值。
//  3) 目录加载失败：弹框内必须有重拉入口（重试按钮），不能只靠一次打开时的 GET。
//
// 运行：cd web && npm test
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'
import {
  defaultsFlowOpening,
  defaultsFlowSettled,
  defaultsFlowStarting,
  failedDefaultNames,
} from '../src/utils/defaultPolicyApply.ts'

const POLICIES = code('src/views/security/SecurityPolicies.vue')

const catalog = {
  lists: [{ name: '信任名单地址列表' }, { name: '黑名单地址列表' }],
  policies: [{ name: '信任名单' }, { name: 'URL 黑名单' }, { name: 'CC 防护' }],
}

test('失败项差集：无结果集=状态未知（返回空，不穷举目录）；有结果集才做缺项差集', () => {
  // 请求失败/事务回滚：后端不带回任何已建项——一项都没建成 ≠ 全目录失败
  assert.deepEqual(failedDefaultNames(catalog, []), [])
  assert.deepEqual(failedDefaultNames(null, [{ kind: 'policy', name: '信任名单', status: 'exists' }]), [])

  // 有结果集：缺项=失败项（kind+name 复合键，列表与策略同名不串）
  const items = [
    { kind: 'list', name: '信任名单地址列表', status: 'created' },
    { kind: 'policy', name: '信任名单', status: 'exists' },
    { kind: 'policy', name: 'CC 防护', status: 'rebuilt' },
  ]
  assert.deepEqual(failedDefaultNames(catalog, items), ['黑名单地址列表', 'URL 黑名单'])
})

test('重试状态流转：打开重置失败态；开始清失败态进 running；落定后区分成功/失败', () => {
  assert.deepEqual(defaultsFlowOpening(), { phase: 'preview', failed: false })
  assert.deepEqual(defaultsFlowStarting(), { phase: 'running', failed: false })
  assert.deepEqual(defaultsFlowSettled(true), { phase: 'done', failed: false })
  assert.deepEqual(defaultsFlowSettled(false), { phase: 'done', failed: true })
  // 重试入口从完成态（失败/成功）再次进入 running 时，failed 必须回落到 false
  assert.equal(defaultsFlowStarting().failed, false)
})

test('组件接线：失败分支不再读信封 partial（事务回滚无部分进度），失败项走纯函数', () => {
  const fn = member(POLICIES, 'const runApplyDefaults = async')
  assert.doesNotMatch(fn, /e\.data/, '事务整体回滚——失败信封不带已建项，读 e.data 恒空（死代码）')
  assert.doesNotMatch(fn, /partial/, '不得再保留「部分成功」错觉')
  const failedNames = section(POLICIES, 'const defaultsFailedNames =', '\nconst defaultsSections')
  assert.match(failedNames, /failedDefaultNames\(/, '失败项差集必须走 utils 纯函数单源')
})

test('组件接线：有失败名单才列名单，否则显示「状态未知」文案；目录失败弹框内可重试', () => {
  assert.match(POLICIES, /statusUnknownTip/, '无结果集的失败必须提示状态未知（不是穷举名单）')
  assert.match(POLICIES, /v-if="defaultsPhase === 'done' && defaultsApplyFailed && defaultsFailedNames\.length"/)
  const retryLoad = member(POLICIES, 'const loadDefaultsCatalog = async')
  assert.match(retryLoad, /\/security\/policies\/default-catalog/, '重试必须重拉目录')
  const dialog = section(POLICIES, 'v-model="defaultsVisible"', '</el-dialog>')
  assert.match(dialog, /@click="loadDefaultsCatalog"/, '目录为空时弹框内必须有重拉按钮')
})
