import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

const page = () => code('src/views/settings/BasicSettings.vue')

test('导出配置备份前必须确认范围与敏感材料', () => {
  const body = section(page(), 'const exportBackup = async', 'const AUTO_BACKUP_WEEKDAYS')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '导出缺确认')
  assert.ok(confirmAt < body.indexOf('exporting.value = true'), '确认必须先于导出请求')
  assert.match(body, /导出内容可能包含证书私钥及敏感凭证/)
})

test('自动备份保存设置与立即备份都必须先确认', () => {
  for (const [fn, saving] of [['saveAutoBackupSettings', 'autoBackupSaving'], ['runAutoBackupNow', 'autoBackupRunning']] as const) {
    const body = section(page(), `const ${fn} = async`, '\nconst ')
    const confirmAt = body.indexOf('await ElMessageBox.confirm(')
    assert.ok(confirmAt > 0, `${fn} 缺确认`)
    assert.ok(confirmAt < body.indexOf(`${saving}.value = true`), `${fn} 确认必须早于写操作`)
  }
})

test('HTTPS 证书配置确定暂存前必须提示仍需保存并重启', () => {
  const body = section(page(), 'const confirmAdminTls =', 'const handleRestart')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '证书配置缺确认')
  assert.match(body, /保存后服务将重启/)
})

test('创建 API 密钥前必须确认只显示一次的明文与权限范围', () => {
  const body = section(code('src/views/Keys.vue'), 'async function createKey', 'const saveFeatures')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '创建密钥缺确认')
  assert.ok(confirmAt < body.indexOf('creating.value = true'), '确认必须先于创建请求')
  assert.match(body, /明文仅展示一次/)
})

test('暂停 OIDC 前必须说明认证入口影响', () => {
  const body = section(code('src/views/settings/OIDCSettings.vue'), 'const toggleEnabled = async', 'const remove = async')
  assert.match(body, /if \(!on\)/)
  assert.match(body, /await ElMessageBox\.confirm\(/)
  assert.match(body, /OIDC 用户将无法通过该入口登录/)
})

test('IP 快捷弹框直接写共享名单前必须确认访问控制影响', () => {
  const body = section(code('src/views/security/IPLocationAction.vue'), 'const executeAdd = async', 'const removeSource')
  const branch = section(body, "target.kind === 'list'", 'actionBusy.value = true')
  assert.match(branch, /await ElMessageBox\.confirm\(/)
  assert.match(branch, /访问控制/)
})

test('API 密钥功能配置保存前必须确认权限与访问范围变更', () => {
  const body = section(code('src/views/Keys.vue'), 'const saveFeatures = async', 'const deleteKey')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '功能配置保存缺确认')
  assert.ok(confirmAt < body.indexOf('featureSaving.value = true'), '确认必须先于保存请求')
  assert.match(body, /MCP 开关、只读权限和 IP 白名单/)
})

test('规则库定时更新保存必须先确认', () => {
  const page = code('src/views/security/SecurityRules.vue')
  for (const fn of ['saveCRSSchedule', 'saveIP2RegionSchedule', 'saveThreatSchedule', 'saveCrawlerSchedule']) {
    const body = section(page, `const ${fn} = async`, '\nconst ')
    assert.match(body, /await confirmScheduleSave\(/, `${fn} 未调用统一保存确认`)
  }
})

test('关闭规则库自动更新前必须确认停止后续更新', () => {
  const page = code('src/views/security/SecurityRules.vue')
  for (const fn of ['toggleSourceFlag', 'toggleLibAutoUpdate']) {
    const body = section(page, `const ${fn} = async`, '\nconst ')
    assert.match(body, /if \(!val\)/, `${fn} 只应在关闭时追加确认`)
    assert.match(body, /await ElMessageBox\.confirm\(/)
  }
})

test('创建或编辑用户前必须确认账号与权限变更', () => {
  const body = section(code('src/views/Users.vue'), 'const handleSubmit = async', 'const editUser')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '用户保存缺确认')
  assert.ok(confirmAt < body.indexOf('submitting.value = true'), '确认必须先于用户写请求')
})

test('确认重置密码前必须提示全部会话将被吊销', () => {
  const body = section(code('src/views/Users.vue'), 'const resetPassword = async', 'const resetMfa')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '确认重置缺最终确认')
  assert.ok(confirmAt > body.indexOf('newPassword = r.newPwd'), '确认必须发生在专用新密码表单之后')
  assert.ok(confirmAt < body.indexOf("request.post(`/users/${row.id}/reset-password`"), '确认必须先于重置请求')
  assert.match(body, /全部登录会话将被吊销/)
})

test('个人资料保存前必须确认资料与密码变更', () => {
  const body = section(code('src/components/ProfileDialog.vue'), 'const saveProfile = async', 'const confirmMfaAction')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(confirmAt > 0, '个人资料保存缺确认')
  assert.ok(confirmAt < body.indexOf('saving.value = true'), '确认必须先于保存请求')
  assert.match(body, /保存后需要重新登录/)
})

test('MFA 向导启用与恢复码保存前必须确认', () => {
  const page = code('src/components/MfaBindingWizard.vue')
  const activate = section(page, 'const activate = async', 'const copyRecovery')
  assert.match(activate, /await ElMessageBox\.confirm\(/)
  assert.match(page, /const confirmRecoverySaved = async/)
  assert.match(page, /@click="confirmRecoverySaved"/)
  assert.match(page, /确认已复制并妥善保存恢复代码/)
})

test('MFA 重置与关闭在写操作验证开启时不再先弹验证码', () => {
  const page = code('src/components/ProfileDialog.vue')
  assert.match(page, /v-if="!mfaWriteGuard"/, '专用验证码输入只在写操作验证关闭时出现')
  const body = section(page, 'const confirmMfaAction = async', 'const onMfaActivated')
  assert.match(body, /mfaWriteGuard\.value \? '' : mfaCode\.value/, '守卫开启时提交空码，由全局 step-up 统一验码')
})
