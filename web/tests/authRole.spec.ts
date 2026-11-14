// 全站 nodeMode 必须随 /config 成功响应持续刷新，而非只在登录、
// 失败重试或集群设置页更新。运行：cd web && node --test tests/authRole.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

const authSrc = code('src/stores/auth.ts')

test('成功拉取配置后排下一轮全站角色刷新', () => {
  // 结构边界：花括号配对取函数体（不再用远处的 interface 声明作终点——那样
  // fetchConfig 之后新增的函数会落进切片，让断言被相邻函数满足）。
  const fetchBody = member(authSrc, 'async function fetchConfig')
  const successStart = fetchBody.indexOf('if (res.data) {')
  const successEnd = fetchBody.indexOf('} else {', successStart)
  assert.ok(successStart >= 0 && successEnd > successStart, 'fetchConfig 成功分支边界必须存在')
  const successBranch = fetchBody.slice(successStart, successEnd)
  assert.match(successBranch, /nodeMode\.value = res\.data\.is_master \? 'master' : 'slave'/)
  assert.match(successBranch, /scheduleConfigRetry\(\)/, '成功响应也必须续排刷新，否则其他页面永久保留旧 nodeMode')

  // 回归/异常形状：单定时器防重、空 data 与非 401 失败仍保留原重试链。
  assert.match(authSrc, /if \(configRetryTimer !== null \|\| !token\.value\)\s+return/)
  assert.match(fetchBody, /\} else \{\s*scheduleConfigRetry\(\)/)
  assert.match(fetchBody, /!\(e instanceof ApiRequestError && e\.status === 401\)\)\s+scheduleConfigRetry\(\)/)
  assert.match(member(authSrc, 'function localLogout'), /clearConfigRetryTimer\(\)/, '登出清表必须在 localLogout 函数体内（不得被远处同名调用满足）')
})

test('配置补查在途门：fetchConfig 一轮在飞时新触发直接跳过', () => {
  // 结构边界：花括号配对取函数体（不再用远处的 interface 声明作终点——那样
  // fetchConfig 之后新增的函数会落进切片，让断言被相邻函数满足）。
  const fetchBody = member(authSrc, 'async function fetchConfig')
  assert.match(fetchBody, /\|\| configFetchInFlight\) return/, 'visibilitychange 补查与 15s 轮询可能同时点火，须在途门防双发')
  assert.match(fetchBody, /configFetchInFlight = true/)
  assert.match(fetchBody, /finally \{\s*configFetchInFlight = false\s*\}/, '在途标记必须 finally 复位（含失败路径）')
})

test('隐藏页不得自续 /config 重试定时器（恢复可见由 visibilitychange 补查）', () => {
  const body = member(authSrc, 'const scheduleConfigRetry = ')
  // 隐藏分支必须直接结束本轮：顺延（再次 scheduleConfigRetry）等于隐藏页
  // 每 15s 唤醒一次、永不进入静默。
  const hiddenIdx = body.indexOf('document.hidden')
  assert.ok(hiddenIdx > 0, '必须显式判定隐藏态')
  const hiddenBranch = body.slice(hiddenIdx)
  assert.match(hiddenBranch, /document\.hidden\) return/, '隐藏态必须停止而非顺延定时器')
  const afterHidden = hiddenBranch.slice(hiddenBranch.indexOf('document.hidden) return'))
  assert.doesNotMatch(afterHidden, /scheduleConfigRetry\(\)/, '隐藏态之后不得再自排一轮')
  assert.match(authSrc, /visibilitychange'[\s\S]*?clearConfigRetryTimer\(\)[\s\S]*?fetchConfig\(true\)/, '恢复可见必须立即补查')
})

test('隐藏页不得自续 /users/me 重试定时器（与 /config 同范式：停表 + 恢复可见补查）', () => {
  const body = member(authSrc, 'const scheduleUserRetry = ')
  const hiddenIdx = body.indexOf('document.hidden')
  assert.ok(hiddenIdx > 0, '必须显式判定隐藏态')
  const hiddenBranch = body.slice(hiddenIdx)
  // 隐藏分支只记待补查标记后结束本轮：顺延（再次 scheduleUserRetry）等于
  // 后台标签页每 15s 唤醒一次。
  assert.match(hiddenBranch, /document\.hidden\)\s*\{\s*userRetryDeferred = true\s+return/, '隐藏态必须停表并记待补查标记')
  const afterReturn = hiddenBranch.slice(hiddenBranch.indexOf('return'))
  assert.doesNotMatch(afterReturn, /scheduleUserRetry\(\)/, '隐藏态之后不得再自排一轮')
  assert.match(body, /bindVisibilityRefresh\(\)/, '排表时须确保可见性监听已绑定（config 从未排过表时也能补查）')
  // 补查路径必须真的调用 fetchUser，否则停表等于永久停摆。
  assert.match(authSrc, /visibilitychange'[\s\S]*?if \(userRetryDeferred\)\s*\{\s*userRetryDeferred = false\s+void fetchUser\(\)/, '恢复可见必须补拉用户信息')
  // 登出/会话失效清表时同时复位标记，避免旧标记在下一个会话抢跑。
  assert.match(authSrc, /const clearUserRetryTimer = \(\): void => \{\s*userRetryDeferred = false/, '清表须复位待补查标记')
})

test('两处用户归一化必须搬运 is_setup_admin（缺一即让 store 与列表页判断分叉）', () => {
  // 后端全部用户响应路径（登录/MFA/me/PATCH me/PUT/:id/票据登录）都真实下发
  // is_setup_admin；store 逐字段重建 user.value 时漏搬会让消费方恒读 undefined。
  const fetchBody = member(authSrc, 'async function fetchUser')
  const fetchSuccess = fetchBody.slice(fetchBody.indexOf('if (res.data) {'))
  assert.match(fetchSuccess, /is_setup_admin: res\.data\.is_setup_admin \?\? false/, 'GET /users/me 归一化必须带上 is_setup_admin')
  const applyBody = member(authSrc, 'function applyAuthResponse')
  assert.match(applyBody, /is_setup_admin: res\.user\.is_setup_admin \?\? false/, '登录/票据响应归一化必须带上 is_setup_admin')
})

test('mfa_write_guard 随 /config 投影单源：Users 页不再单独整取 GET /config', () => {
  // 结构边界：花括号配对取函数体（不再用远处的 interface 声明作终点——那样
  // fetchConfig 之后新增的函数会落进切片，让断言被相邻函数满足）。
  const fetchBody = member(authSrc, 'async function fetchConfig')
  // /config 投影复用 GlobalConfigData 声明（Pick），mfa_write_guard 键由该接口提供
  assert.match(authSrc, /Pick<GlobalConfigData, 'timezone' \| 'cert_renewal_days' \| 'mfa_write_guard'>/, '/config 投影必须 Pick GlobalConfigData（单一事实源）')
  assert.match(fetchBody, /mfaWriteGuard\.value = res\.data\.mfa_write_guard === true/)
  assert.match(authSrc, /const mfaWriteGuard = ref\(false\)/, '首值 false = 守卫关闭的保守形态')
  assert.match(authSrc, /^\s+mfaWriteGuard,$/m, 'store 对外暴露 ref')

  const users = code('src/views/Users.vue')
  assert.match(users, /const mfaWriteGuard = computed\(\(\) => authStore\.mfaWriteGuard\)/)
  assert.doesNotMatch(users, /request\.get\('\/config'\)/, '不得再为单键重复拉整份配置')
})
