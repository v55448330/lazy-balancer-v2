// 设置页「破坏性写请求的后果披露 / 未保存改动守卫」行为契约。
//
// 覆盖三件可观察行为：
//  1. 导入/还原这类分钟级同步写请求在断连后必须显式告知「可能仍在后台执行」并
//     给出操作日志入口——全局拦截器只弹一句「网络连接失败」，会被读成「没执行」。
//  2. 还原确认框必须先请求预览（版本告警/将被禁用的规则/其它告警），预览失败
//     不得阻断还原；分组与过滤逻辑抽成纯函数在此钉住。
//  3. 未保存改动必须能被跨组件读取（离开当前设置页的确认与 beforeunload 共用
//     同一登记）：切到任何其它页面（含设置内其它分页）都要确认，确认离开即
//     丢弃全部改动；首屏/保存后回填只覆盖「服务端确认值」快照，重挂载不得把
//     未保存编辑当基线。
//
// 运行：cd web && node --test tests/settingsOverwriteAndUnsaved.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'

import { isConnectionInterruption } from '../src/utils/connectionInterruption.ts'
import { restorePreviewGroups } from '../src/utils/restorePreview.ts'
import {
  discardSettingsDraft,
  hasDirtySettingsForm,
  registerSettingsModelRevert,
  resetSettingsDraft,
  useSettingsDraft,
  useSettingsFormTracker,
} from '../src/composables/useSettingsDraft.ts'
import { code, mountForLifecycle, registerModuleHooks, section } from './_helpers.ts'
import { dataModule, STUB_ELEMENT } from './_stubs.ts'

// 离开守卫组合子的依赖用 data: 模块替身（element-plus 是字节级 CSS/DOM 依赖；
// tSafe 取词条键本身，便于断言确认框用了哪个键）：钩子必须先注册再动态 import。
registerModuleHooks({
  'element-plus': STUB_ELEMENT,
  '../i18n/tSafe.ts': dataModule('export const tSafe = (key) => key'),
})
const loadLeaveGuard = () => import('../src/composables/useSettingsLeaveGuard.ts')
type ConfirmStub = { __confirm: (...args: unknown[]) => Promise<unknown> }
// 确认框替身：记录本次参数；confirmStay=true 模拟「留在本页」（reject）。
let confirmArgs: unknown[] = []
let confirmStay = false
const confirmHost = globalThis as unknown as ConfirmStub
confirmHost.__confirm = async (...args: unknown[]) => {
  confirmArgs = args
  if (confirmStay) throw new Error('stay')
}

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
  // 该入口直接离开设置页，必须与侧栏同一守卫：有未保存改动先确认，留在本页不跳。
  assert.match(
    handler,
    /if \(await confirmLeavingSettingsPage\('audit-log', authStore\.currentPage\)\) authStore\.setCurrentPage\('audit-log'\)/,
    '确认后跳操作日志，且必须先过离开守卫',
  )
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

test('字段描述只说明字段本身（作用、取值范围、默认值），不写变更叙述', () => {
  const changeNarrative = {
    zh: /不再|改为|之前|原来|现已|旧版|升级后/,
    en: /no longer|previously|used to|formerly|legacy|earlier versions/i,
  }
  for (const locale of ['zh', 'en'] as const) {
    const described: string[] = []
    for (const line of code(`src/locales/${locale}/settings.ts`).split('\n')) {
      const field = line.match(/^\s*"([A-Za-z]*(?:Hint|Tip|Desc)[A-Za-z]*)":\s*"(.*)",?$/)
      if (!field) continue
      described.push(field[1])
      assert.doesNotMatch(field[2], changeNarrative[locale], `${locale} 字段描述 ${field[1]} 含变更叙述：${field[2]}`)
    }
    assert.ok(described.length > 50, `${locale} 字段描述键只取到 ${described.length} 个（want >50）：匹配形态漂移会让本门空转`)
  }
  const zh = code('src/locales/zh/settings.ts')
  assert.match(section(zh, '"timeout": {', '"upstreamKeepalive"'), /"bodySizeHint": "MB，单个请求体的大小上限；1–1024，默认 128"/)
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
  const certificates = code('src/views/settings/FreeCertificates.vue')
  assert.match(certificates, /useSettingsFormTracker\('certificates'\)/)
  assert.match(certificates, /watch\(\(\) => props\.revision/, '保存/加载回填即刷新基线')
  assert.match(certificates, /if \(props\.configLoaded\) formTracker\.initSaved\(formSnapshot\(\)\)/, '重挂载只在无基线时初始化')
  // 模板里直绑共享 global 的表单键必须全部进快照（绑定 ↔ 快照键对表）
  const boundFields = [...new Set([...certificates.matchAll(/v-model="global\.([a-z_]+)"/g)].map((match) => match[1]))]
  assert.ok(boundFields.length > 0, '证书卡表单必须直绑共享 global')
  const snapshotKeys = section(certificates, 'const CERT_FORM_KEYS =', 'const formSnapshot')
  for (const field of boundFields) {
    assert.ok(snapshotKeys.includes(`'${field}'`), `证书卡快照缺少表单键 ${field}`)
  }
})

test('Settings.vue 三张卡各传自己的回填版本并在卸载前拦截刷新丢失', () => {
  const page = code('src/views/Settings.vue')
  for (const revision of ['basicRevision', 'caddyRevision', 'certRevision']) {
    assert.match(page, new RegExp(`:revision="${revision}"`), `${revision} 必须传给对应卡片`)
  }
  const fetchAll = section(page, 'const fetchSettings = async', 'const refreshConfigSection')
  for (const revision of ['basicRevision', 'caddyRevision', 'certRevision']) {
    assert.ok(fetchAll.includes(`${revision}.value++`), `整包回填必须推进 ${revision}`)
  }
  assert.match(section(page, 'const handleSaveCertificates', 'const syncActiveTabFromPage'), /refreshConfigSection\(applyCertKeys, certRevision\)/, '证书卡保存回填推进自己的版本，不借用基础卡版本')
  assert.match(page, /beforeunload/)
  assert.match(page, /hasDirtySettingsForm\(\)/)
  assert.match(page, /removeEventListener\('beforeunload'/)
})

test('侧栏切页走共用守卫：有未保存改动时切到任何其它页面都拦截（含设置内其它分页）', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  const goPage = section(layout, 'const goPage', 'const logout')
  assert.match(goPage, /if \(!\(await confirmLeavingSettingsPage\(page, currentPage\.value\)\)\) return/, '「留在本页」不得切页')
  assert.match(goPage, /authStore\.setCurrentPage\(page\)/, '确认后才切页')
  assert.doesNotMatch(layout, /settingsTabOfPage|leavingSettingsDraft/, '不得按「目标是否设置分页」放行：设置内互切同样要拦')
  assert.doesNotMatch(layout, /ElMessageBox/, '确认框只在共用守卫里，侧栏不得另留一份')
  // 词条成对
  for (const locale of ['zh', 'en'] as const) {
    const views = code(`src/locales/${locale}/views.ts`)
    for (const key of ['unsavedLeaveConfirm', 'unsavedLeaveMessage', 'unsavedLeaveStay', 'unsavedLeaveTitle']) {
      assert.ok(views.includes(`'${key}'`), `${locale} 缺 layout.${key}`)
    }
  }
})

test('守卫行为：无未保存改动或点击当前所在页直接放行，不弹确认', async () => {
  resetSettingsDraft()
  const { confirmLeavingSettingsPage } = await loadLeaveGuard()
  confirmArgs = []
  assert.equal(await confirmLeavingSettingsPage('settings-cluster', 'settings-basic'), true, '无改动不拦')
  useSettingsFormTracker('basic').setDirty(true)
  assert.equal(await confirmLeavingSettingsPage('settings-basic', 'settings-basic'), true, '点击当前所在页不拦')
  assert.equal(confirmArgs.length, 0, '两种放行都不得弹确认框')
  resetSettingsDraft()
})

test('守卫行为：有未保存改动时切到其它页面弹确认（设置内其它分页同样拦）；留在本页不丢稿', async () => {
  resetSettingsDraft()
  const { confirmLeavingSettingsPage } = await loadLeaveGuard()
  useSettingsFormTracker('caddy').setDirty(true)
  confirmStay = true
  try {
    assert.equal(await confirmLeavingSettingsPage('settings-cluster', 'settings-basic'), false, '留在本页=不离开')
    assert.equal(hasDirtySettingsForm(), true, '留在本页不得丢稿')
    assert.deepEqual(confirmArgs.slice(0, 2), ['common.app.views.layout.unsavedLeaveMessage', 'common.app.views.layout.unsavedLeaveTitle'])
    const options = confirmArgs[2] as { confirmButtonText?: string; cancelButtonText?: string }
    assert.equal(options.confirmButtonText, 'common.app.views.layout.unsavedLeaveConfirm')
    assert.equal(options.cancelButtonText, 'common.app.views.layout.unsavedLeaveStay')
    confirmArgs = []
    assert.equal(await confirmLeavingSettingsPage('dashboard', 'settings-basic'), false, '离开设置域同样要拦')
    assert.deepEqual(confirmArgs.slice(0, 2), ['common.app.views.layout.unsavedLeaveMessage', 'common.app.views.layout.unsavedLeaveTitle'], '离开设置域也要弹确认')
  } finally {
    confirmStay = false
    resetSettingsDraft()
  }
})

test('守卫行为：确认「放弃并离开」清空草稿登记并回填共享模型（切回来不再看到改动）', async () => {
  resetSettingsDraft()
  const { confirmLeavingSettingsPage } = await loadLeaveGuard()
  let reverts = 0
  registerSettingsModelRevert(() => { reverts += 1 })
  useSettingsDraft().githubTokenInput.value = 'ghp_unsaved'
  useSettingsFormTracker('basic').setDirty(true)
  try {
    assert.equal(await confirmLeavingSettingsPage('settings-cluster', 'settings-basic'), true)
    assert.equal(reverts, 1, '必须让设置页把共享模型回填为服务端值')
    assert.equal(hasDirtySettingsForm(), false, '确认离开=丢弃全部未保存改动')
    assert.equal(useSettingsDraft().githubTokenInput.value, '', '草稿里的暂存输入一并清掉')
  } finally {
    registerSettingsModelRevert(null)
    resetSettingsDraft()
  }
})

test('discardSettingsDraft：清草稿登记并调用已登记的回填入口；未登记时不抛错', () => {
  resetSettingsDraft()
  const draft = useSettingsDraft()
  draft.githubTokenInput.value = 'ghp_unsaved'
  draft.adminTls.value = { enabled: true, mode: 'upload' }
  useSettingsFormTracker('caddy').setDirty(true)
  discardSettingsDraft()
  assert.equal(draft.githubTokenInput.value, '')
  assert.deepEqual(draft.adminTls.value, { enabled: false, mode: 'selfsigned' })
  assert.equal(hasDirtySettingsForm(), false)
  let reverts = 0
  registerSettingsModelRevert(() => { reverts += 1 })
  useSettingsFormTracker('basic').setDirty(true)
  discardSettingsDraft()
  assert.equal(reverts, 1, '已登记回填入口必须被调用')
  assert.equal(hasDirtySettingsForm(), false)
  registerSettingsModelRevert(null)
})

test('Settings.vue 挂载时登记共享模型回填入口，卸载时注销', () => {
  const page = code('src/views/Settings.vue')
  const mounted = section(page, 'onMounted(', 'onUnmounted(')
  assert.match(mounted, /registerSettingsModelRevert\(\(\) => \{ void fetchSettings\(\) \}\)/, '整包回填三张卡并刷新脏态基线')
  const unmounted = section(page, 'onUnmounted(', '</script>')
  assert.match(unmounted, /registerSettingsModelRevert\(null\)/, '卸载即注销，回填入口不得指向已卸载的页面')
})

test('集群管理「同步间隔」：与服务端当前值不同即登记未保存改动；卡片卸载清登记', () => {
  const card = code('src/views/settings/cluster/ClusterModeCard.vue')
  assert.match(card, /useSettingsFormTracker\('cluster'\)/)
  assert.match(card, /const syncIntervalDirty = computed\(\(\) => props\.status !== null && syncInterval\.value !== props\.status\.sync_interval\)/, 'status 未就绪或等于服务端值都不算未保存')
  assert.match(card, /watch\(syncIntervalDirty, \(value\) => formTracker\.setDirty\(value\), \{ immediate: true \}\)/)
  assert.match(card, /onUnmounted\(\(\) => \{ formTracker\.setDirty\(false\) \}\)/, '编辑随卡片卸载消失，登记不得残留')
})

test('证书卡登记行为：编辑共享 global 即脏；留在本页不丢；放弃并离开后回填服务端值且不再算脏', async () => {
  resetSettingsDraft()
  const server = { acme_email: 'ops@example.com', cert_expiry_days: 30 }
  // 父级共享模型（Settings.vue 持有，切分页不卸载）与父级回填版本
  const shared = ref({ ...server })
  const revision = ref(0)
  // 与证书卡同形态：快照基线由父级回填版本驱动，脏态登记到设置域单例。
  mountForLifecycle(() => {
    const tracker = useSettingsFormTracker('certificates')
    const snapshot = (): string => JSON.stringify([shared.value.acme_email, shared.value.cert_expiry_days])
    const isDirty = computed(() => tracker.isDirty(snapshot()))
    watch(isDirty, (value) => tracker.setDirty(value), { immediate: true })
    watch(revision, () => tracker.markSaved(snapshot()))
    tracker.initSaved(snapshot())
  })
  const { confirmLeavingSettingsPage } = await loadLeaveGuard()
  assert.equal(await confirmLeavingSettingsPage('settings-cluster', 'settings-certificates'), true, '未编辑不拦')
  shared.value.acme_email = 'new@example.com'
  await nextTick()
  confirmStay = true
  try {
    assert.equal(await confirmLeavingSettingsPage('settings-cluster', 'settings-certificates'), false, '编辑后切到设置内其它分页也要拦')
    assert.equal(hasDirtySettingsForm(), true, '留在本页不丢')
  } finally {
    confirmStay = false
  }
  registerSettingsModelRevert(() => { Object.assign(shared.value, server); revision.value++ })
  try {
    assert.equal(await confirmLeavingSettingsPage('settings-cluster', 'settings-certificates'), true)
    await nextTick()
    assert.deepEqual({ ...shared.value }, server, '放弃并离开后共享模型回到服务端值')
    assert.equal(hasDirtySettingsForm(), false, '切回来不得还看到改动')
  } finally {
    registerSettingsModelRevert(null)
    resetSettingsDraft()
  }
})

test('集群管理同步间隔登记行为：改成不同于服务端的值即脏，改回或卡片卸载后不算脏', async () => {
  resetSettingsDraft()
  const serverInterval = ref(60)
  const syncInterval = ref<number | null | undefined>(60)
  // 与集群卡片同形态：局部输入与服务端当前值比较，卸载时清登记。
  const host = mountForLifecycle(() => {
    const tracker = useSettingsFormTracker('cluster')
    const isDirty = computed(() => syncInterval.value !== serverInterval.value)
    watch(isDirty, (value) => tracker.setDirty(value), { immediate: true })
    onUnmounted(() => { tracker.setDirty(false) })
  })
  assert.equal(hasDirtySettingsForm(), false, '等于服务端值不算未保存')
  syncInterval.value = 120
  await nextTick()
  assert.equal(hasDirtySettingsForm(), true, '改了没点保存即未保存改动')
  syncInterval.value = 60
  await nextTick()
  assert.equal(hasDirtySettingsForm(), false, '改回服务端值不算未保存')
  syncInterval.value = 120
  await nextTick()
  host.unmount()
  assert.equal(hasDirtySettingsForm(), false, '卡片卸载（切走分页）后编辑消失，登记不得残留')
})

test('切走设置分页后卡片已卸载，脏态登记仍在（守卫覆盖全部分页的草稿）', async () => {
  resetSettingsDraft()
  // 与卡片同形态：基线来自服务端回填值，编辑后把脏态登记到设置域单例。
  const form = ref('loaded')
  const host = mountForLifecycle(() => {
    const tracker = useSettingsFormTracker('basic')
    tracker.initSaved(form.value)
    const isDirty = computed(() => tracker.isDirty(form.value))
    watch(isDirty, (value) => tracker.setDirty(value), { flush: 'sync' })
    form.value = 'edited'
  })
  await nextTick()
  assert.equal(hasDirtySettingsForm(), true, '编辑后即脏')
  host.unmount()
  assert.equal(hasDirtySettingsForm(), true, '卸载（切到别的设置分页）不得清掉脏态——否则从该分页离开时静默丢稿')
  resetSettingsDraft()
  assert.equal(hasDirtySettingsForm(), false, '离开设置页（草稿复位）才清')
})
