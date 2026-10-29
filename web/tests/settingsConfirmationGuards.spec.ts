import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'

const page = () => code('src/views/settings/BasicSettings.vue')

test('导出弹框是唯一确认面，确认导出后直接开始下载', () => {
  const source = page()
  const dialog = section(source, '<el-dialog v-model="exportDialogVisible"', '</el-dialog>')
  assert.match(dialog, /包含凭证与证书材料，请加密保管/)
  assert.match(dialog, /确认导出/)
  const body = section(source, 'const exportBackup = async', 'const AUTO_BACKUP_WEEKDAYS')
  assert.doesNotMatch(body, /ElMessageBox\.confirm\(/, '弹框主按钮已经确认，不得再弹同义确认')
  assert.ok(body.indexOf('exporting.value = true') < body.indexOf("request.get<Blob>('/config/export'"), '确认后直接进入导出在途态')
})

test('自动备份保存与立即备份都先占位再确认，取消也释放在途态', () => {
  for (const [fn, saving] of [['saveAutoBackupSettings', 'autoBackupSaving'], ['runAutoBackupNow', 'autoBackupRunning']] as const) {
    const body = section(page(), `const ${fn} = async`, '\nconst ')
    const busyAt = body.indexOf(`${saving}.value = true`)
    const confirmAt = body.indexOf('await ElMessageBox.confirm(')
    assert.ok(busyAt > 0 && confirmAt > busyAt, `${fn} 必须先占位再确认（确认悬挂期即防重）`)
    assert.ok(confirmAt < body.indexOf('request.'), `${fn} 确认必须先于写请求`)
    assert.match(body, new RegExp(`finally \\{\\s*${saving}\\.value = false`), `${fn} 取消与请求结束都必须释放在途态`)
    const cancelAt = body.indexOf('catch { return', busyAt)
    const resetAt = body.search(new RegExp(`finally \\{\\s*${saving}\\.value = false`))
    assert.ok(cancelAt > 0 && resetAt > cancelAt, `${fn} 取消分支必须与占位复位同属一个受保护块`)
    assert.doesNotMatch(body.slice(cancelAt, resetAt), /try \{/, `${fn} 取消分支与 finally 之间不得另起 try（拆层会让取消绕过占位复位）`)
  }
})

test('HTTPS 证书配置仅暂存，弹框静态提示保存与重启而不追加确认', () => {
  const source = page()
  const body = section(source, 'const confirmAdminTls =', 'const handleRestart')
  assert.doesNotMatch(body, /ElMessageBox\.confirm\(/, '本地暂存不得追加危险操作确认')
  const footer = section(source, '<el-dialog v-model="adminTlsDialogVisible"', '</el-dialog>')
  assert.match(footer, /确定后仅暂存，仍需在基础设置页点击「保存」生效；保存后服务将重启/)
})

test('基础设置只在预览有变更或暂存证书时弹保存确认', () => {
  const body = section(page(), 'const handleSave = async', 'const parentRefresh = props.onSave')
  const gate = body.indexOf('if (preview.data?.changed || tlsPending) {')
  assert.ok(gate > 0, '保存确认必须由「预览无变更不弹」的实际变更门控')
  assert.doesNotMatch(body.slice(0, gate), /ElMessageBox\.confirm\(/, '无变更路径不得提前弹确认框')
  const gated = section(body, 'if (preview.data?.changed || tlsPending) {', "const saveResp = await request.put('/config', payload)")
  assert.match(gated, /ElMessageBox\.confirm\(/, '确认必须在变更门内')
  assert.match(body, /const tlsPending = adminTlsDirty\.value/, '暂存的 HTTPS 证书变更必须并入同一变更门')
  assert.ok(
    body.indexOf("request.post<ConfigPreviewResponse>('/config/preview'") < gate,
    '变更判定必须取自保存预览接口，不得本地猜测',
  )
})

test('创建 API 密钥先占位再确认明文与权限范围', () => {
  const body = section(code('src/views/Keys.vue'), 'async function createKey', 'const saveFeatures')
  const busyAt = body.indexOf('creating.value = true')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(busyAt > 0 && confirmAt > busyAt, '创建密钥必须先占位再确认')
  assert.ok(confirmAt < body.indexOf("request.post<CreateAPIKeyResponse>('/users/me/api-keys'"), '确认必须先于创建请求')
  assert.match(body, /明文仅展示一次/)
  assert.match(body, /if \(nodeWriteBlocked\.value \|\| creating\.value\) return/, '确认悬挂期的第二击必须被入口门挡下')
  assert.match(body, /finally \{\s*creating\.value = false/, '取消与请求结束都必须释放占位')
})

test('只有暂停 OIDC 的分支才说明认证入口影响', () => {
  const body = section(code('src/views/settings/OIDCSettings.vue'), 'const toggleEnabled = async', 'const remove = async')
  const disabling = section(body, 'if (!on) {', 'saving.value = true')
  assert.match(disabling, /await ElMessageBox\.confirm\(/)
  assert.match(disabling, /OIDC 用户将无法通过该入口登录/)
})

test('IP 快捷弹框名单写入经共享确认链，不复制第二套写实现', () => {
  const body = section(code('src/views/security/IPLocationAction.vue'), 'const executeAdd = async', 'const removeSource')
  assert.match(body, /joinSpecificList\(/, '名单写入必须经 useTrustAssociation/useIpListAdd 共享链')
  assert.doesNotMatch(body, /request\.post[^\n]*\/security\/ip-lists\/[^\n]*\/ips/, '弹框不得保留直接 POST')
  assert.match(code('src/composables/useIpListAdd.ts'), /ElMessageBox\.confirm\(/)
})

test('API 密钥功能配置先占位再确认权限与访问范围变更', () => {
  const body = section(code('src/views/Keys.vue'), 'const saveFeatures = async', 'const deleteKey')
  const busyAt = body.indexOf('featureSaving.value = true')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(busyAt > 0 && confirmAt > busyAt, '功能配置保存必须先占位再确认')
  assert.ok(confirmAt < body.indexOf('request.patch('), '确认必须先于保存请求')
  assert.match(body, /MCP 开关、只读权限和 IP 白名单/)
  assert.match(body, /finally \{\s*featureSaving\.value = false/, '取消与请求结束都必须释放占位')
})

test('规则库定时更新保存直接提交并显示在途态', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.doesNotMatch(page, /const confirmScheduleSave\s*=/, '可再次修改的排程保存不需要统一确认函数')
  for (const [fn, saving] of [
    ['saveCRSSchedule', 'savingCRSSchedule'],
    ['saveIP2RegionSchedule', 'savingIP2RegionSchedule'],
    ['saveThreatSchedule', 'savingThreatSchedule'],
    ['saveCrawlerSchedule', 'savingCrawlerSchedule'],
  ] as const) {
    const body = section(page, `const ${fn} = async`, '\nconst ')
    assert.doesNotMatch(body, /confirmScheduleSave|ElMessageBox\.confirm\(/, `${fn} 不得追加确认`)
    assert.ok(body.indexOf(`${saving}.value = true`) < body.indexOf('request.put('), `${fn} 必须先进入在途态再保存`)
  }
})

test('只有关闭规则库自动更新的分支才确认停止后续更新', () => {
  const page = code('src/views/security/SecurityRules.vue')
  for (const [fn, busyMarker] of [
    ['toggleSourceFlag', 'const requestSeq ='],
    ['toggleLibAutoUpdate', 'autoUpdateSaving.value.add'],
  ] as const) {
    const body = section(page, `const ${fn} = async`, '\nconst ')
    const disabling = section(body, 'if (!val) {', busyMarker)
    assert.match(disabling, /await ElMessageBox\.confirm\(/, `${fn} 关闭分支缺确认`)
    assert.match(disabling, /确认关闭/, `${fn} 关闭分支文案不完整`)
  }
})

test('创建或编辑用户先占位再确认账号与权限变更', () => {
  const body = section(code('src/views/Users.vue'), 'const handleSubmit = async', 'const editUser')
  const busyAt = body.indexOf('submitting.value = true')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(busyAt > 0 && confirmAt > busyAt, '用户保存必须先占位再确认')
  assert.ok(confirmAt < body.indexOf('request.put('), '确认必须先于用户写请求')
  assert.match(body, /finally \{\s*submitting\.value = false/, '取消与请求结束都必须释放占位')
})

test('重置密码由专用新密码弹框一次确认并提示会话吊销', () => {
  const body = section(code('src/views/Users.vue'), 'const resetPassword = async', 'const resetMfa')
  assert.doesNotMatch(body, /ElMessageBox\.confirm\(/, '专用重置弹框之后不得再弹同义确认')
  assert.match(body, /message: '重置后该用户的全部登录会话将被吊销，账户锁定状态一并清除。'/)
  assert.match(body, /confirmText: '确认重置'/)
  assert.match(body, /if \(!r\.ok\) return/, '弹框取消/关闭不得落成重置请求')
  assert.ok(body.indexOf('newPassword = r.newPwd') < body.indexOf("request.post(`/users/${row.id}/reset-password`"), '密码表单确认必须先于重置请求')
})

test('个人资料仅修改密码时确认，普通资料保存直接提交', () => {
  const body = section(code('src/components/ProfileDialog.vue'), 'const saveProfile = async', 'const confirmMfaAction')
  const passwordBranch = section(body, 'if (passwordChanged) {', 'await request.patch')
  assert.match(passwordBranch, /await ElMessageBox\.confirm\(/, '修改密码仍需确认重新登录')
  assert.match(passwordBranch, /保存后需要重新登录/)
  assert.doesNotMatch(body, /将保存个人资料修改，是否继续/, '仅改显示名不得追加确认')
  const busyAt = body.indexOf('saving.value = true')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(busyAt > 0 && busyAt < confirmAt, '必须先占位再弹密码确认（确认悬挂期即防重）')
  assert.ok(body.indexOf('await request.patch') > confirmAt, '确认必须先于资料写请求')
  assert.match(body, /finally \{\s*saving\.value = false/, '取消与请求结束都必须释放在途态')
  const cancelAt = body.indexOf('catch { return }')
  const resetAt = body.search(/finally \{\s*saving\.value = false/)
  assert.ok(cancelAt > 0 && resetAt > cancelAt, '取消分支必须与占位复位同属一个受保护块')
  assert.doesNotMatch(body.slice(cancelAt, resetAt), /try \{/, '取消分支与 finally 之间不得另起 try（拆层会让取消绕过占位复位）')
})

test('MFA 动态码直接验证启用，恢复码确认后才允许关闭', () => {
  const page = code('src/components/MfaBindingWizard.vue')
  const activate = section(page, 'const activate = async', 'const copyRecovery')
  assert.doesNotMatch(activate, /ElMessageBox\.confirm\(/, '六位动态码与验证按钮已经表达启用意图')
  assert.ok(activate.indexOf('loading.value = true') < activate.indexOf("request.post<APIResponse<{ recovery_codes"), '启用请求前必须进入在途态')
  const recovery = section(page, 'const confirmRecoverySaved = async', '</script>')
  const confirmAt = recovery.indexOf('await ElMessageBox.confirm(')
  const emitAt = recovery.indexOf("emit('update:modelValue', false)")
  assert.ok(confirmAt > 0 && emitAt > confirmAt, '恢复码必须确认已保存后才关闭')
  assert.match(recovery, /确认已复制并妥善保存恢复代码/)
  assert.match(recovery, /catch \{\s*\}/, '取消或返回检查不得关闭恢复码弹框')
  assert.match(page, /@click="confirmRecoverySaved"/)
})

test('证书重签先占位再确认，取消后也释放在途标记', () => {
  const body = section(code('src/views/settings/CertJobs.vue'), 'const retryJob = async', 'const viewLogs')
  const busyAt = body.indexOf('retryingJobIds.value = new Set(retryingJobIds.value).add(row.id)')
  const confirmAt = body.indexOf('await ElMessageBox.confirm(')
  assert.ok(busyAt > 0 && confirmAt > busyAt, '重签必须先占位再弹出确认')
  assert.ok(confirmAt < body.indexOf('request.post('), '确认必须先于重签请求')
  assert.match(body, /finally \{[\s\S]*nextRetryingIds\.delete\(row\.id\)/, '取消与请求结束都必须释放占位')
})

test('MFA 重置与关闭在写操作验证开启时不再先弹验证码', () => {
  const page = code('src/components/ProfileDialog.vue')
  assert.match(page, /v-if="!mfaWriteGuard"/, '专用验证码输入只在写操作验证关闭时出现')
  const body = section(page, 'const confirmMfaAction = async', 'const onMfaActivated')
  assert.match(body, /mfaWriteGuard\.value \? '' : mfaCode\.value/, '守卫开启时提交空码，由全局 step-up 统一验码')
})
