import { test } from 'node:test'
import assert from 'node:assert/strict'
import { shouldCloseRegistrationDialog } from '../src/utils/clusterRegistration.ts'
import { section, code } from './_helpers.ts'

test('仅首次注册发生 master→slave 跃迁时自动关闭', () => {
  assert.equal(shouldCloseRegistrationDialog(true, 'master', 'slave'), true)
})

test('从节点重新注册不会被状态轮询关闭', () => {
  assert.equal(shouldCloseRegistrationDialog(true, 'slave', 'slave'), false)
})

test('未打开、未知来源与其它状态不触发跃迁关闭', () => {
  assert.equal(shouldCloseRegistrationDialog(false, 'master', 'slave'), false)
  assert.equal(shouldCloseRegistrationDialog(true, null, 'slave'), false)
  assert.equal(shouldCloseRegistrationDialog(true, 'master', 'master'), false)
})

// 一次性注册令牌不得在 emit 后立即清空——父级二次确认/入口守卫才可能
// 取消，取消后须能直接重试而不必重新粘贴。仅父级 POST 成功或弹框关闭时清空。
test('提交后不即时清空令牌，确认成功/关闭弹框统一清理', () => {
  const page = code('src/views/settings/cluster/ClusterModeCard.vue')
  const submit = section(page, 'const submitRegistration = async', '</script>')
  assert.doesNotMatch(submit, /form\.register_token = ''/, '取消确认/入口守卫早退会丢失已粘贴令牌')
  // 成功受理（父级 POST 成功）后清空；关闭弹框兜底清理
  assert.match(
    page,
    /watch\(\s*\(\) => props\.registrationSucceeded,\s*\(\) => \{\s*form\.register_token = ''\s*\},?\s*\)/,
    '父级受理成功后必须清空一次性令牌',
  )
  const watcher = section(page, 'watch(registrationOpen, (open) => {', 'const handleModeChange')
  assert.match(watcher, /if \(!open\)[\s\S]*form\.register_token = ''/)
  const parent = code('src/views/settings/ClusterSettings.vue')
  assert.match(parent, /:registration-succeeded="registrationSucceeded"/)
  assert.match(section(parent, 'const registerAsSlave = async', '\nconst promoteToMaster'), /registrationSucceeded\.value \+= 1/)
})
