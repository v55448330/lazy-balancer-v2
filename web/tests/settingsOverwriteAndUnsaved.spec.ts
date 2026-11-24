// 设置页「破坏性写请求的后果披露 / 未保存改动守卫」行为契约。
//
// 覆盖三件可观察行为：
//  1. 导入/还原这类分钟级同步写请求在断连后必须显式告知「可能仍在后台执行」并
//     给出操作日志入口——全局拦截器只弹一句「网络连接失败」，会被读成「没执行」。
//  2. 还原确认框必须先请求预览（版本告警/将被禁用的规则/其它告警），预览失败
//     不得阻断还原；分组与过滤逻辑抽成纯函数在此钉住。
//  3. 未保存改动必须能被跨组件读取（侧栏切页拦截与 beforeunload 共用同一登记），
//     且首屏/保存后回填只覆盖「服务端确认值」快照，重挂载不得把未保存编辑当基线。
//
// 运行：cd web && node --test tests/settingsOverwriteAndUnsaved.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computed, nextTick, ref, watch } from 'vue'

import { isConnectionInterruption } from '../src/utils/connectionInterruption.ts'
import { restorePreviewGroups } from '../src/utils/restorePreview.ts'
import { hasDirtySettingsForm, resetSettingsDraft, useSettingsFormTracker } from '../src/composables/useSettingsDraft.ts'
import { code, section } from './_helpers.ts'

// —— 断连判定 ——

test('断连只认「请求已出站但没拿到响应」，4xx/5xx 与取消/止损都不算', () => {
  assert.equal(isConnectionInterruption({ name: 'ApiRequestError', message: '网络连接失败' }), true, '无 status = 没有响应')
  assert.equal(isConnectionInterruption({ name: 'ApiRequestError', message: 'timeout' , status: undefined }), true, '超时同形态（无响应）')
  assert.equal(isConnectionInterruption({ name: 'ApiRequestError', message: '校验失败', status: 400 }), false, '后端已裁决=不是断连')
  assert.equal(isConnectionInterruption({ name: 'ApiRequestError', message: '服务不可用', status: 503 }), false)
  assert.equal(isConnectionInterruption({ name: 'ApiRequestError', message: '会话失效', status: 401, sessionExpiredHalted: true }), false, '未出站的止损拒绝')
  assert.equal(isConnectionInterruption({ name: 'CanceledError', code: 'ERR_CANCELED' }), false, '主动取消')
  assert.equal(isConnectionInterruption(new Error('boom')), false, '普通错误不冒充断连')
  assert.equal(isConnectionInterruption(null), false)
  assert.equal(isConnectionInterruption('network'), false)
})

// —— 还原预览分组 ——

test('还原预览分组：版本告警去空白、告警逐条保序并滤空、冲突明细原序', () => {
  const groups = restorePreviewGroups({
    version_warning: '  备份版本 v2.1.0，当前 v2.4.3  ',
    backup_version: 'v2.1.0',
    current_version: 'v2.4.3',
    disabled_conflicts: [
      { name: 'A', reason: 'same port', conflicts_with: [] },
      { caddy_id: 'b', reason: 'same domain', conflicts_with: [{ name: 'A', reason: 'same domain' }] },
    ],
    warnings: ['规则库元数据已跳过', '', 42, '证书任务悬挂 2 条'],
  })
  assert.equal(groups.versionWarning, '备份版本 v2.1.0，当前 v2.4.3')
  assert.deepEqual(groups.conflicts.map((conflict) => conflict.name ?? conflict.caddy_id), ['A', 'b'])
  assert.deepEqual(groups.warnings, ['规则库元数据已跳过', '证书任务悬挂 2 条'])
})

test('还原预览缺字段/畸形载荷不抛错、不臆造条目（旧后端与半途字段）', () => {
  for (const payload of [null, undefined, {}, { version_warning: 1, warnings: 'oops', disabled_conflicts: {} }]) {
    const groups = restorePreviewGroups(payload)
    assert.equal(groups.versionWarning, '')
    assert.deepEqual(groups.conflicts, [])
    assert.deepEqual(groups.warnings, [])
  }
  const trailing = restorePreviewGroups({ warnings: ['  ', '\tok\t'] })
  assert.deepEqual(trailing.warnings, ['ok'], '逐条去首尾空白后保留内部内容')
})

// —— 未保存改动登记 ——

test('未保存改动登记：initSaved 不覆盖既有基线，markSaved 覆盖，复位后无基线不算脏', () => {
  resetSettingsDraft()
  const tracker = useSettingsFormTracker('basic')
  tracker.initSaved('A')
  assert.equal(tracker.isDirty('A'), false)
  assert.equal(tracker.isDirty('B'), true)
  // 重挂载：initSaved 只在无基线时生效，不得把未保存编辑当已保存基线
  tracker.initSaved('B')
  assert.equal(tracker.isDirty('B'), true, 'configLoaded 重挂不得吞掉脏态')
  tracker.markSaved('B')
  assert.equal(tracker.isDirty('B'), false, '保存后父级回填=新的服务端基线')
  // 无基线（首屏未加载/已复位）不等于脏：不能凭「未知」拦住用户
  resetSettingsDraft()
  assert.equal(tracker.isDirty('C'), false)
})

test('跨卡片脏态登记：任一卡片脏即整体脏，复位清空', () => {
  resetSettingsDraft()
  const basic = useSettingsFormTracker('basic')
  const caddy = useSettingsFormTracker('caddy')
  assert.equal(hasDirtySettingsForm(), false)
  basic.setDirty(true)
  caddy.setDirty(false)
  assert.equal(hasDirtySettingsForm(), true)
  caddy.setDirty(true)
  basic.setDirty(false)
  assert.equal(hasDirtySettingsForm(), true, '另一卡片仍脏')
  basic.setDirty(false)
  caddy.setDirty(false)
  assert.equal(hasDirtySettingsForm(), false)
  caddy.setDirty(true)
  resetSettingsDraft()
  assert.equal(hasDirtySettingsForm(), false, '离开设置页（草稿复位）必须清掉脏态')
})

test('基线变更能驱动脏态重算（保存回填只改基线、不动表单字段）', async () => {
  resetSettingsDraft()
  const tracker = useSettingsFormTracker('saved-baseline')
  const form = ref('v1')
  tracker.markSaved(form.value)
  const dirty = computed(() => tracker.isDirty(form.value))
  const seen: boolean[] = []
  watch(dirty, (value) => seen.push(value), { flush: 'sync' })
  form.value = 'v2'
  await nextTick()
  assert.deepEqual(seen, [true], '表单偏离基线即脏')
  tracker.markSaved(form.value)
  await nextTick()
  assert.deepEqual(seen, [true, false], '保存成功后脏态必须自行回落（不能等字段再变）')
  assert.equal(dirty.value, false)
})

// —— 还原确认框：先预览、失败不阻断 ——

test('还原先请求预览再确认，失败只加一行提示仍可继续', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /\/auto-backup\/\$\{id\}\/preview/, '还原必须请求预览端点（silent，失败不作还原失败提示）')
  const fetchPreview = section(page, 'const fetchRestorePreview', 'const restoreAutoBackup')
  assert.match(fetchPreview, /silent: true/)
  assert.match(fetchPreview, /restorePreviewGroups\(null\)/, '预览失败按空分组继续，不得抛错阻断')
  assert.match(fetchPreview, /failure: reason/, '失败原因必须回传给确认框')
  const restore = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  const previewAt = restore.indexOf('fetchRestorePreview(row.id)')
  const confirmAt = restore.indexOf('ElMessageBox.confirm')
  assert.ok(previewAt > 0, '确认前必须请求预览')
  assert.ok(confirmAt > previewAt, '预览必须在确认框之前')
  assert.match(restore, /preview\.failure/, '预览失败原因必须显性进入确认框')
  assert.match(restore, /confirm-scope-lead/, '后果披露用全局单源类（DESIGN_SPEC §20）')
  assert.match(restore, /confirm-scope-list/)
  assert.match(restore, /restorePreview\.(conflictsLead|warningsLead|fail)/, '分组文案走词条')
})

test('还原确认按钮语义是「仍然还原」（已看到后果后的继续）', () => {
  const zh = code('src/locales/zh/settings.ts')
  const en = code('src/locales/en/settings.ts')
  assert.match(zh, /"restoreConfirmBtn": "仍然还原"/)
  assert.match(en, /"restoreConfirmBtn": "/)
  assert.match(zh, /"restoreTitle": "还原配置"/)
})

// —— 断连提示与操作日志入口 ——

test('导入/还原的断连提示给出操作日志入口（不是只弹一句网络失败）', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const importBody = section(page, 'const confirmImport', 'const DEFAULT_GITHUB_PROXY_URL')
  const restoreBody = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  for (const [name, body, messageKey] of [
    ['导入', importBody, 'import.interrupted'],
    ['还原', restoreBody, 'restore.interrupted'],
  ] as const) {
    assert.match(body, /isConnectionInterruption\(error\)/, `${name}必须识别断连`)
    assert.ok(body.includes(messageKey), `${name}断连文案键`)
    assert.match(body, /showTransferInterruption\(/, `${name}断连提示必须走统一入口（含操作日志跳转）`)
  }
  const handler = section(page, 'const showTransferInterruption', 'const triggerImport')
  assert.match(handler, /ElMessageBox\.confirm/, '入口在确认框里给出（取消=知道了）')
  assert.match(handler, /gotoAuditLog/)
  assert.match(handler, /setCurrentPage\('audit-log'\)/, '确认后跳操作日志')
})

// —— Caddy 日志失败显性化 ——

test('Caddy 日志查看器失败可见：错误态置位/成功清除/工具栏提示', () => {
  const page = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(page, /const caddyLogError = ref\(false\)/)
  const tail = section(page, 'const logTail = useLogTailPolling', 'const logLoading')
  assert.match(tail, /caddyLogError\.value = false/, '任一成功响应清除错误态')
  assert.match(tail, /onError:[\s\S]*?caddyLogError\.value = true/)
  const toolbar = section(page, 'class="log-toolbar"', '</div>')
  assert.match(toolbar, /caddyLogError/, '工具栏必须可见提示')
  assert.match(toolbar, /viewer\.loadFail/)
  assert.match(toolbar, /refreshLogs/, '刷新按钮即重试入口')
})

// —— 备份入口可发现性 ——

test('备份入口改名「备份与还原」，置灰给出原因提示', () => {
  const zh = code('src/locales/zh/settings.ts')
  const en = code('src/locales/en/settings.ts')
  assert.match(zh, /"title": "备份与还原"/)
  assert.match(en, /"title": "Backup & restore"|"title": "Backup and restore"/)
  assert.match(zh, /"backupDisabledTip": "含历史 \/ 下载 \/ 还原；仅主节点可用"/)
  const page = code('src/views/settings/BasicSettings.vue')
  const backupActions = section(page, 'class="backup-actions"', '</el-text>')
  const tooltips = backupActions.match(/<el-tooltip/g) ?? []
  assert.equal(tooltips.length, 3, '三个备份入口都要能解释置灰原因')
  assert.match(backupActions, /backupDisabledTip/)
})

// —— 保存反馈区分「已保存」与「已应用」 ——

test('两张卡保存成功提示消费后端 message（区分已保存/已应用）', () => {
  const basic = code('src/views/settings/BasicSettings.vue')
  const basicSave = section(basic, 'const saveResp = await request.put', '</script>')
  assert.match(basicSave, /mfaAwareSuccess\(message \|\| t\('app\.settings\.basic\.messages\.saved'\)\)/)
  const caddy = code('src/views/settings/CaddyGlobalSettings.vue')
  const caddySave = section(caddy, 'const saved = await request.put', 'await props.onSave()')
  assert.match(caddySave, /mfaAwareSuccess\(\w+ \|\| t\('app\.settings\.caddy\.messages\.saved'\)\)/)
  assert.match(caddySave, /\.message/, '后端 message 必须被读取')
})

// —— 超时项 hint 去掉 0 语义 ——

test('超时项提示不再声称 0 = 无超时/默认（控件与后端都要求 ≥1）', () => {
  for (const locale of ['zh', 'en'] as const) {
    const settings = code(`src/locales/${locale}/settings.ts`)
    const timeout = section(settings, '"timeout": {', '"upstreamKeepalive"')
    for (const key of ['readHint', 'writeHint', 'idleHint']) {
      assert.ok(timeout.includes(`"${key}"`), `${locale} 缺 ${key}`)
    }
    assert.doesNotMatch(timeout, /0 = /, `${locale} 超时提示不得保留 0 的语义`)
    assert.match(timeout, /≥1/)
  }
  // upstream_keepalive 是省略型（0=继承默认），其 0 语义保留
  const zh = code('src/locales/zh/settings.ts')
  assert.match(zh, /"upstreamKeepaliveHint": "[^"]*0 = 默认/)
})

// —— 未保存改动：组件接线与守卫入口 ——

test('卡片暴露 dirty 并登记：快照基线由父级服务端回填版本驱动', () => {
  const basic = code('src/views/settings/BasicSettings.vue')
  assert.match(basic, /useSettingsFormTracker\('basic'\)/)
  assert.match(basic, /defineExpose\(\{ dirty \}\)/)
  assert.match(basic, /watch\(\(\) => props\.revision/, '保存/加载回填即刷新基线')
  const caddy = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(caddy, /useSettingsFormTracker\('caddy'\)/)
  assert.match(caddy, /defineExpose\(\{ dirty \}\)/)
  assert.match(caddy, /watch\(\(\) => props\.revision/)
})

test('Settings.vue 传递回填版本并在卸载前拦截刷新丢失', () => {
  const page = code('src/views/Settings.vue')
  assert.match(page, /:revision="basicRevision"/)
  assert.match(page, /:revision="caddyRevision"/)
  assert.match(page, /basicRevision\.value\+\+/, '任一成功读取/保存回填必须推进基线版本')
  assert.match(page, /beforeunload/)
  assert.match(page, /hasDirtySettingsForm\(\)/)
  assert.match(page, /removeEventListener\('beforeunload'/)
})

test('侧栏切页在有未保存改动时拦截；设置分页互切不拦', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  const goPage = section(layout, 'const goPage', 'const logout')
  const guard = section(layout, 'const leavingSettingsDraft', 'const goPage')
  assert.match(guard, /hasDirtySettingsForm\(\)/, '脏态来自设置域登记')
  assert.match(guard, /settingsTabOfPage/, '必须区分「离开设置域」与「设置分页互切」')
  assert.match(goPage, /leavingSettingsDraft\(page\)/)
  assert.match(goPage, /ElMessageBox\.confirm/)
  assert.match(goPage, /unsavedLeaveConfirm/)
  // 词条成对
  for (const locale of ['zh', 'en'] as const) {
    const views = code(`src/locales/${locale}/views.ts`)
    for (const key of ['unsavedLeaveConfirm', 'unsavedLeaveMessage', 'unsavedLeaveStay', 'unsavedLeaveTitle']) {
      assert.ok(views.includes(`'${key}'`), `${locale} 缺 layout.${key}`)
    }
  }
})
