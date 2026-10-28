import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  BACKUP_SECTIONS,
  LEGACY_SECTION_ALIASES,
  importConfirmMessage,
  normalizeBackupSectionKeys,
} from '../src/utils/backupSections.ts'
import { code, repoCode, section } from './_helpers.ts'

// 设置页备份面回归守卫：导入入口/超大文件拒绝、lbbak Blob 直传、还原文案按分类、
// 下次备份调度口径、立即备份的卸载收尾，以及备份四分类前后端单源一致性。
const page = code('src/views/settings/BasicSettings.vue')

test('新文件入口先清旧内容，超大拒绝不可回用旧备份', () => {
  // 终点用「下一个函数声明」而非注释文本——注释终点可能落在本函数内部，
  // 切片会延伸到后续函数（该区间出现 48MB 字样即假红）。
  const body = section(code('src/views/settings/BasicSettings.vue'), 'const handleImportFile', 'const postImportValidation')
  const oversized = body.indexOf('if (file.size > IMPORT_MAX_BYTES)')
  assert.ok(oversized > 0)
  const beforeReject = body.slice(0, oversized)
  for (const reset of [
    "importFileContent.value = ''",
    'importFileIsLbbak.value = false',
    'importSections.value = []',
    'importValidation.value = null',
  ]) {
    assert.ok(beforeReject.includes(reset), `missing pre-reject reset: ${reset}`)
  }
  assert.match(page, /const IMPORT_MAX_BYTES = 128 \* 1024 \* 1024/)
  assert.doesNotMatch(body, /48MB|48 \* 1024/)
})

test('导入大小上限与后端 maxConfigImportBytes 同源', () => {
  const go = repoCode('internal/handlers/config_import_v1.go')
  const declared = /var maxConfigImportBytes int64 = (\d+) << (\d+)/.exec(go)
  assert.ok(declared, '后端导入上限常量未解析')
  const goBytes = Number(declared[1]) * 2 ** Number(declared[2])
  const pageBytes = /const IMPORT_MAX_BYTES = (\d+) \* 1024 \* 1024/.exec(page)
  assert.ok(pageBytes, '前端导入上限常量未解析')
  assert.equal(Number(pageBytes[1]) * 1024 * 1024, goBytes, '前后端导入上限漂移会让超限文件在错误的一侧被拦')
})

test('lbbak 以 Blob 直传，不复制成第二个 ArrayBuffer', () => {
  const body = section(page, 'const handleImportFile', 'const postImportValidation')
  assert.match(body, /importFileContent\.value = file\.slice\(bomLen\)/)
  assert.doesNotMatch(body, /file\.slice\(bomLen\)\.arrayBuffer\(\)/)
  assert.match(page, /ref<string \| Blob>\(''\)/)
})

test('还原文案按备份分类，失败行不显示下载', () => {
  const restore = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  assert.match(restore, /autoBackupScopeText\(row\)/)
  assert.match(restore, /覆盖该备份包含的分类/)
  assert.doesNotMatch(restore, /覆盖当前全部配置/)
  assert.match(page, /<el-button v-if="row\.status === 'success'" link type="primary" size="small" :disabled="autoBackupActionBusy" @click="downloadAutoBackup\(row(?: as [A-Za-z]+)?\)">下载<\/el-button>/)
})

test('下次备份只消费调度器返回值并标明补跑', () => {
  const label = section(page, 'const autoBackupNextRunLabel', 'const autoBackupCanRunNow')
  assert.match(label, /autoBackupNextRunAt\.value/)
  assert.match(label, /autoBackupCatchUpDue\.value/)
  assert.match(label, /待补跑/)
  assert.doesNotMatch(label, /autoBackupForm|Intl\.DateTimeFormat/)
  assert.match(page, /next_run_at: string \| null/)
  assert.match(page, /catch_up_due: boolean/)
})

test('立即备份按已保存范围门控，60 秒无结果有提示', () => {
  // 属性序不是契约：两次独立匹配（格式化工具有引入即批量红）。
  assert.match(page, /:disabled="!autoBackupCanRunNow"/)
  assert.match(page, /title="按已保存的自动备份设置执行一次备份/)
  const run = section(page, 'const runAutoBackupNow', 'const downloadAutoBackup')
  assert.match(run, /if \(!autoBackupCanRunNow\.value\)/)
  assert.doesNotMatch(run, /if \(!autoBackupSectionsValid\.value\)/)
  assert.match(run, /else if \(!completed && autoBackupVisible\.value\)/)
  assert.match(run, /60 秒内未检测到本次备份结果/)
  const saved = section(page, 'const saveAutoBackupSettings', 'const runAutoBackupNow')
  assert.match(saved, /autoBackupSavedSections\.value = \[\.\.\.autoBackupSections\.value\]/)
})

// 点「立即备份」后切到其它设置页（组件卸载）：轮询只以弹框可见为门时，
// 卸载后仍每 2s 拉取最多 30 次并在其它页面弹结果 toast。
test('立即备份轮询在组件卸载后终止且不再弹结果', () => {
  const run = section(page, 'const runAutoBackupNow', 'const downloadAutoBackup')
  assert.match(run, /while \(!disposed && autoBackupVisible\.value && Date\.now\(\) < deadline\)/)
  assert.match(run, /if \(disposed\) break/)
  // 循环后的二次复查必须是**顺序**门：切片起点即断言标记属按构造恒真。
  const guardAt = run.lastIndexOf('if (disposed) return')
  const branchAt = run.indexOf("if (completed?.status === 'success')")
  assert.ok(guardAt >= 0, '循环后必须二次复查 disposed')
  assert.ok(branchAt > guardAt, '二次复查必须出现在结果提示分支之前（否则卸载后仍会弹 toast）')
})

// 取消到 0 个分类时，预览摘要/冲突必须与按钮同门：revalidateImport 早退会让
// 面板继续展示上一次选择的摘要，且确认按钮可点（点了才提示）。
test('0 分类选择隐藏陈旧预览并把确认按钮置灰', () => {
  assert.match(page, /const importPreviewSelected = computed<boolean>\(\(\) => importSections\.value\.length > 0\)/)
  assert.match(page, /<template v-if="importValidation\.valid && importPreviewSelected">/)
  assert.match(page, /v-else-if="importValidation\.valid" class="info-note-bar import-alert"><span class="info-note-desc">未选择导入分类/)
  const button = section(page, ':disabled="!importValidation?.valid', ':loading="importing"')
  assert.match(button, /!importPreviewSelected/)
  // 与同卡其余写入口同门：只读 ∪ 非主节点（从节点导入必然 403）
  assert.match(button, /backupDisabled/)
})

test('备份分类恰好四键且标签与后端口径一致', () => {
  assert.deepEqual(
    BACKUP_SECTIONS.map((s) => [s.key, s.label]),
    [['users', '系统数据'], ['rules', '负载规则'], ['security', '安全防护'], ['cluster', '节点拓扑']],
  )
  // 跨栈一致性：后端 configBackupSections 单源派生键/标签必须同集同序
  const go = repoCode('internal/handlers/config_backup.go')
  const goBlock = section(go, 'var configBackupSections = []struct', '\n}\n')
  const goPairs = [...goBlock.matchAll(/\{Key: "(\w+)", Label: "([^"]+)"/g)].map((m) => [m[1], m[2]])
  assert.deepEqual(BACKUP_SECTIONS.map((s) => [s.key, s.label]), goPairs, '前后端分类键/标签漂移会静默改变导出/还原覆盖面')
})

test('legacy 分类键归一行为（映射/去重/保序/未知键透传）', () => {
  assert.deepEqual(LEGACY_SECTION_ALIASES, { global_config: 'users', waf_files: 'security' })
  assert.deepEqual(normalizeBackupSectionKeys(['global_config', 'waf_files']), ['users', 'security'], 'legacy 键读出即归一')
  assert.deepEqual(normalizeBackupSectionKeys(['users', 'global_config']), ['users'], '归一后与显式键去重')
  assert.deepEqual(normalizeBackupSectionKeys(['waf_files', 'global_config']), ['security', 'users'], '保序')
  assert.deepEqual(normalizeBackupSectionKeys(['future_key']), ['future_key'], '未知键透传（向前兼容）')
  assert.deepEqual(normalizeBackupSectionKeys([]), [])
  // 别名表是普通对象：备份文件里的原型键必须原样透传（直接下标会返回函数）
  assert.deepEqual(normalizeBackupSectionKeys(['constructor', 'toString']), ['constructor', 'toString'],
    '原型键归一结果不得变成函数')
})

test('导出/自动备份默认全选四分类，恢复路径必经归一', () => {
  const allKeys = BACKUP_SECTIONS.map((s) => s.key)
  assert.deepEqual(normalizeBackupSectionKeys(allKeys), allKeys)
  const page = code('src/views/settings/BasicSettings.vue')
  // 默认全选两处（导出对话框 + 自动备份表单）
  assert.match(page, /const exportSections = ref<string\[\]>\(BACKUP_SECTIONS\.map\(\(s\) => s\.key\)\)/)
  assert.match(page, /const autoBackupSections = ref<string\[\]>\(BACKUP_SECTIONS\.map\(\(s\) => s\.key\)\)/)
  // 恢复路径两处消费归一：自动备份设置载入 + 历史备份行分类标签
  const loadBlock = section(page, 'const loadedSections', 'autoBackupSavedSections.value = [...loadedSections]')
  assert.match(loadBlock, /normalizeBackupSectionKeys\(d\.sections\)/)
  const labelBlock = section(page, 'const labels = normalizeBackupSectionKeys', '.map((k) => BACKUP_SECTIONS.find')
  assert.match(labelBlock, /row\.sections \|\| \[\]/)
})

// 纯 JSON（v3）的体内 sections 参与校验和：分类选择必须经 ?sections= query，
// 请求体保持原始字节，否则 UI 默认全选注入会被判「已篡改」，导入彻底不可达。
test('分类选择统一走 query，纯 JSON 请求体不被改写', () => {
  const previewBody = section(page, 'const postImportValidation', 'const revalidateImport')
  assert.ok(previewBody.includes('?sections='), '预览必须携带 sections query')
  assert.ok(!previewBody.includes('parsed.sections'), '预览不得改写体内 sections')
  assert.ok(!previewBody.includes('JSON.parse'), '预览不得为注入 sections 重新序列化请求体')

  const importBody = section(page, 'const confirmImport', "const DEFAULT_GITHUB_PROXY_URL")
  assert.ok(importBody.includes('?sections='), '导入必须携带 sections query')
  assert.ok(!importBody.includes('parsed.sections'), '导入不得改写体内 sections')
})

// 自动备份还原与导入同口径：冲突自动禁用的规则必须出现在结果弹框里，
// 否则「还原成功」后流量静默切走。
test('自动备份还原结果展示冲突自动禁用明细', () => {
  const body = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  assert.ok(body.includes('disabled_conflicts'), '还原必须读取 data.disabled_conflicts')
  assert.ok(body.includes('formatImportConflict'), '冲突明细必须复用 formatImportConflict')
  assert.match(body, /冲突置为禁用/)
  assert.match(body, /formatImportConflict\(conflict, true\)/, '还原路径的冲突文案须用已禁用时态')
})

// V1 备份按后端契约只导入规则部分；此前最终确认框沿用「覆盖当前全部配置」
// ——与同一弹框的预览文案自相矛盾，会让人误判破坏范围。
test('导入最终确认文案按备份类型单源：V1 不宣称全量，V2 全量含节点拓扑', () => {
  const v1 = importConfirmMessage('v1', ['rules'])
  assert.match(v1, /全部负载均衡规则及其安全策略绑定/)
  assert.match(v1, /保持不变/)
  assert.doesNotMatch(v1, /节点拓扑|全部凭证/, 'V1 不得宣称覆盖节点拓扑或全部凭证')

  const full = importConfirmMessage('v2', BACKUP_SECTIONS.map((s) => s.key))
  assert.match(full, /节点拓扑/, 'V2 全量必须与预览一致地包含节点拓扑')
  assert.match(full, /全部凭证/)

  const partial = importConfirmMessage('v2', ['rules', 'security'])
  assert.match(partial, /仅覆盖所选分类：负载规则、安全防护/)
  assert.match(partial, /未选分类保持现状/)

  const body = section(page, 'const confirmImport', 'const DEFAULT_GITHUB_PROXY_URL')
  assert.match(body, /importConfirmMessage\(validation\.type, importSections\.value\)/, '视图必须消费单源文案')
  assert.doesNotMatch(body, /isFullImport/, '不得保留第二套覆盖面判断')
})

// 日志端点失败时此前只写 console，模板继续渲染「暂无日志」——排障最需要日志
// 的时刻给出「没有日志」的错误结论。
test('应用运行日志失败显性化：错误提示 + 空态文案切换 + 成功/关闭复位', () => {
  const dialog = section(page, 'v-model="appLogVisible"', '</el-dialog>')
  assert.match(dialog, /<el-text v-if="appLogError"[^>]*>日志加载失败，自动重试中/)
  assert.match(dialog, /\{\{ appLogContent \|\| appLogEmptyText \}\}/)
  assert.doesNotMatch(dialog, /\{\{ appLogContent \|\| '暂无日志' \}\}/, '失败态不得继续显示「暂无日志」')
  assert.match(page, /const appLogEmptyText = computed\(\(\) => appLogError\.value \? '日志加载失败（自动重试中）' : '暂无日志'\)/)

  const tail = section(page, 'const appLogTail = useLogTailPolling', 'const appLogLoading')
  assert.match(tail, /appLogError\.value = false/, '任一成功响应必须清除错误态')
  assert.match(tail, /onError:[\s\S]*?appLogError\.value = true/, '失败必须置位错误态')

  const closed = section(page, 'const onAppLogClosed', 'watch(appLogAutoRefresh')
  assert.match(closed, /appLogError\.value = false/, '关闭弹框复位')
  const opened = section(page, 'const openAppLogDialog', 'const onAppLogOpened')
  assert.match(opened, /appLogError\.value = false/, '重开弹框复位')
})

// 自动备份列表：行内 sections 列损坏（带外改库/旧版本遗留）时后端给
// sections_error。此前前端既未声明该字段也不渲染，损坏行显示「-」——被读成
// 「不含任何分类的备份」而放弃一次内容完整的还原（还原按包内 sections 走）。
test('自动备份范围损坏显性化：sections_error 非空时不得显示为空范围', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /sections_error\?: string/, 'AutoBackupRow 必须声明后端字段')
  const scope = section(page, 'const autoBackupScopeText', 'const autoBackupDetailTip')
  assert.match(scope, /row\.sections_error/, '范围渲染必须消费 sections_error')
  assert.match(scope, /范围损坏/, '损坏必须显式提示，不得渲染成空范围')
  assert.match(page, /is-warning/, '损坏态必须按 warning 着色')
})
