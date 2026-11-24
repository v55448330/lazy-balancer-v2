import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  BACKUP_SECTIONS,
  BACKUP_SECTION_TABLES,
  LEGACY_SECTION_ALIASES,
  backupSectionsInSummary,
  importConfirmMessage,
  normalizeBackupSectionKeys,
} from '../src/utils/backupSections.ts'
import { code, elementSlice, goConstExpr, openTags, repoCode, section } from './_helpers.ts'

// 设置页备份面回归守卫：导入入口/超大文件拒绝、lbbak Blob 直传、还原复用导入弹框、
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
    // 上一份文件的预览会话同样要作废：超大分支此后直接返回，会话留着时点分类
    // 会用旧会话重新校验，缓存命中就把上一份文件的预览显示在新文件名下。
    'importPreviewSession?.dispose()',
    'importPreviewSession = null',
  ]) {
    assert.ok(beforeReject.includes(reset), `missing pre-reject reset: ${reset}`)
  }
  assert.match(page, /const IMPORT_MAX_BYTES = 128 \* 1024 \* 1024/)
  assert.doesNotMatch(body, /48MB|48 \* 1024/)
})

test('导入大小上限与后端 maxConfigImportBytes 同源', () => {
  // 表达式形态（<<）提取与求值走 goConstExpr 单源；前端镜像按 MB 计，对表同值。
  const goBytes = goConstExpr('internal/handlers/config_import_v1.go', 'maxConfigImportBytes')
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

test('还原入口打开导入弹框（服务器备份），失败行不显示下载', () => {
  const restore = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  assert.match(restore, /triggerImport\(row\)/, '还原=打开导入弹框，数据源是该行服务器备份')
  assert.doesNotMatch(restore, /ElMessageBox|autoBackupScopeText|restoreConfirm/, '不再有单独的还原确认框')
  // 属性序与字面空隙不是契约（格式工具栏/换行重排即批量假红）：按「标签 + 属性集」
  // 判定，按钮身份由 @click 处理器认领。
  const downloads = openTags(page, 'el-button').filter((tag) => tag.includes('@click="downloadAutoBackup('))
  assert.equal(downloads.length, 1, '备份行的下载按钮必须唯一')
  const [download] = downloads
  assert.match(download, /\bv-if="row\.status === 'success'"/, '只有成功行显示下载')
  assert.match(download, /(?:^|\s)link(?=\s|\/?>)/, 'link 形态按钮')
  assert.match(download, /\btype="primary"/)
  assert.match(download, /\bsize="small"/)
  assert.match(download, /:disabled="autoBackupActionBusy"/, '执行中必须禁用')
  assert.match(elementSlice(page, page.indexOf(download), 'el-button'), />\{\{ t\('app\.settings\.basic\.autoBackup\.download'\) \}\}<\/el-button>/, '按钮文案(调用点钉键)')
  assert.ok(code('src/locales/zh/settings.ts').includes('"download": "下载"'), 'zh 母本须保留「下载」原文')
})

test('备份历史截断披露：backups_truncated 显式 true 才提示，打开弹框复位', () => {
  assert.match(page, /const autoBackupTruncated = ref\(false\)/)
  assert.match(page, /autoBackupTruncated\.value = d\.backups_truncated === true/, '截断位=显式 true 才提示（缺省/旧后端不臆测）')
  assert.match(page, /<el-alert v-if="autoBackupTruncated" type="warning"[^>]*:title="t\('app\.settings\.basic\.autoBackup\.historyTruncated'\)"/, '截断必须以警告横幅显性披露')
  const openDialog = section(page, 'const openAutoBackupDialog', '\n}')
  assert.match(openDialog, /autoBackupTruncated\.value = false/, '打开弹框必须复位截断态')
  assert.ok(code('src/locales/zh/settings.ts').includes('"historyTruncated": "还有更旧的备份未返回（列表仅显示最近一批）"'), '截断披露原文必须在 zh 母本')
  assert.ok(code('src/locales/en/settings.ts').includes('"historyTruncated"'), '截断披露必须成对在场（en）')
})

test('下次备份只消费调度器返回值并标明补跑', () => {
  const label = section(page, 'const autoBackupNextRunLabel', 'const autoBackupCanRunNow')
  assert.match(label, /autoBackupNextRunAt\.value/)
  assert.match(label, /autoBackupCatchUpDue\.value/)
  assert.match(label, /t\('app\.settings\.basic\.autoBackup\.catchUp'/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"catchUp": "待补跑（{time}）"'), 'zh 母本须保留「待补跑」原文')
  assert.doesNotMatch(label, /autoBackupForm|Intl\.DateTimeFormat/)
  assert.match(page, /next_run_at: string \| null/)
  assert.match(page, /catch_up_due: boolean/)
})

test('立即备份按已保存范围门控，60 秒无结果有提示', () => {
  // 属性序不是契约：两次独立匹配（格式化工具有引入即批量红）。
  assert.match(page, /:disabled="!autoBackupCanRunNow"/)
  assert.match(page, /:title="t\('app\.settings\.basic\.autoBackup\.runNowTip'\)"/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"runNowTip": "按已保存的自动备份设置执行一次备份'), 'zh 母本须保留 runNowTip 原文')
  const run = section(page, 'const runAutoBackupNow', 'const downloadAutoBackup')
  assert.match(run, /if \(!autoBackupCanRunNow\.value\)/)
  assert.doesNotMatch(run, /if \(!autoBackupSectionsValid\.value\)/)
  assert.match(run, /else if \(!completed && autoBackupVisible\.value\)/)
  assert.match(run, /t\('app\.settings\.basic\.autoBackup\.resultTimeout'\)/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"resultTimeout": "60 秒内未检测到本次备份结果'), 'zh 母本须保留 60 秒无结果提示原文')
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

// 取消到 0 个分类时，chip 必须保留以便重新勾选；摘要/冲突与确认按钮同门隐藏，
// 空选择提示替代校验错误，避免继续展示上一次分类集合的预览。
// 显示规则（2026-11-25 用户裁定本地文件模式同样处理）：预览无效且带有具体原因
// 就显示原因，与已选分类数、数据源无关——服务器备份的预览要等成功才知道可导入
// 分类，本地文件超过大小上限被拒时分类也是空的；此前这两种情形都被「未选择
// 导入分类」盖住。取消到 0 个分类时清掉**上一轮预览**留下的旧错误（没有预览
// 会话的失败态如超大文件不在此列，原因继续显示）。
test('0 分类选择保留 chip、隐藏陈旧预览并禁用确认', () => {
  assert.match(page, /const importPreviewSelected = computed<boolean>\(\(\) => importSections\.value\.length > 0\)/)
  assert.match(page, /<template v-if="importValidation && !importValidating">/)
  assert.match(page, /@click="toggleImportSection\(sec\.key\)"/)
  assert.match(page, /v-if="!importValidation\.valid && importValidation\.error" class="info-note-bar import-alert"/, '预览无效且有具体原因即显示原因')
  assert.match(page, /v-else-if="!importValidation\.valid && importPreviewSelected"/)
  assert.match(page, /<template v-if="importValidation\.valid && importPreviewSelected">/)
  assert.match(page, /v-else-if="!importPreviewSelected" class="info-note-bar import-alert"><span class="info-note-desc">\{\{ t\('app\.settings\.basic\.import\.noneSelected'\) \}\}/, '「未选择导入分类」只在没有待显示原因时出现')
  assert.ok(code('src/locales/zh/settings.ts').includes('"noneSelected": "未选择导入分类'), 'zh 母本须保留「未选择导入分类」原文')
  const toggle = section(page, 'const toggleImportSection', 'const toggleExportSection')
  assert.match(toggle, /if \(!importSelectableSections\.value\.includes\(key\)\) return/, '不可选分类（V1 的非规则分类、服务器备份未包含的分类）不可点；V1 取消唯一分类后仍必须允许重新勾选规则')
  assert.match(toggle, /if \(importSections\.value\.length === 0 && importPreviewSession\) importValidation\.value = \{ \.\.\.validation, error: '' \}/, '取消到 0 个分类时清掉上一轮预览的错误原因')
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
  const body = section(page, 'const submitRestore', 'const confirmImport')
  assert.ok(body.includes('disabled_conflicts'), '还原必须读取 data.disabled_conflicts')
  assert.ok(body.includes('formatImportConflict'), '冲突明细必须复用 formatImportConflict')
  assert.match(body, /t\('app\.settings\.basic\.conflictsDisabled', \{ count: disabledConflicts\.length \}\)/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"conflictsDisabled": "冲突置为禁用：{count} 条"'), 'zh 母本须保留「冲突置为禁用」原文')
  assert.match(body, /formatImportConflict\(conflict, true\)/, '还原路径的冲突文案须用已禁用时态')
})

// 还原结果弹框靠「告警文本包含标记子串」决定按钮是「重新登录」还是「刷新页面」。
// 会话吊销告警后端已双语、按动作（导入/还原）各登记一条：标记必须同时命中每条的
// 中、英文案，否则英文界面把「重新登录」降级成「刷新页面」。
test('会话吊销标记同时命中导入/还原告警的中英文案', () => {
  const catalog = repoCode('internal/i18n/catalog_manual.go')
  const marks = (['zh', 'en'] as const).map((locale) => {
    const mark = /"sessionRevokeMark": "([^"]+)"/.exec(code(`src/locales/${locale}/settings.ts`))?.[1]
    assert.ok(mark, `${locale} 须有 restoreResult.sessionRevokeMark`)
    return mark
  })
  for (const key of ['k_dffc3f29', 'k_23e13305']) {
    const line = catalog.split('\n').find((l) => l.includes(`"${key}"`)) ?? ''
    const texts = [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1])
    assert.equal(texts.length, 3, `${key} 须为「键, 中文, 英文」三项`)
    assert.ok(texts[1].includes(marks[0]), `zh 的会话吊销标记须是 ${key} 中文文案的子串`)
    assert.ok(texts[2].includes(marks[1]), `en 的会话吊销标记须是 ${key} 英文文案的子串`)
  }
})

// 备份历史的「还原」复用导入弹框：数据源是服务器上的这份备份——文件区显示文件名
// 与「服务器备份」标注、不出选文件按钮；预览与确认只带 backup_id/所选分类。
test('服务器备份复用导入弹框：预览带 backup_id 空请求体，确认先过导入的最终确认再走还原端点', () => {
  const dialog = section(page, 'v-model="importDialogVisible"', '</el-dialog>')
  assert.match(dialog, /<el-button v-if="importBackupId === null" :icon="Upload" @click="chooseImportFile">/, '服务器备份不显示「选择备份文件」按钮')
  assert.match(dialog, /<el-tag v-if="importBackupId !== null"[^>]*>\{\{ t\('app\.settings\.basic\.import\.serverBackup'\) \}\}<\/el-tag>/, '文件名旁标注「服务器备份」')
  assert.match(dialog, /'is-disabled': !importSelectableSections\.includes\(sec\.key\)/, '备份未包含的分类禁用（与 V1 非规则分类同形态）')
  assert.ok(code('src/locales/zh/settings.ts').includes('"serverBackup": "服务器备份"'), 'zh 母本须有「服务器备份」')
  assert.ok(code('src/locales/en/settings.ts').includes('"serverBackup": "Server backup"'), 'en 成对在场')

  const preview = section(page, 'const postImportValidation', 'const revalidateImport')
  assert.match(preview, /&backup_id=\$\{backupId\}/, '服务器备份预览带 backup_id')
  assert.match(preview, /backupId === null \? importFileContent\.value : undefined/, '服务器备份预览请求体为空')

  const confirm = section(page, 'const confirmImport', 'const DEFAULT_GITHUB_PROXY_URL')
  assert.match(confirm, /importConfirmMessage\(validation\.type, importSections\.value\)/, '先过导入现有的最终二次确认')
  assert.match(confirm, /await submitRestore\(importBackupId\.value\)/, '确认后走还原提交')
  const submit = section(page, 'const submitRestore', 'const confirmImport')
  assert.match(submit, /`\/auto-backup\/\$\{backupId\}\/restore\?sections=\$\{encodeURIComponent\(importSections\.value\.join\(','\)\)\}`, undefined, \{ timeout: 0 \}\)/, '还原按所选分类提交：空请求体、分钟级请求 timeout: 0')
  // 入口必须是调用形态：方法引用写法会把点击事件当成 serverBackup，点「导入配置」
  // 就发一次空体校验并报错。
  assert.match(page, /@click="triggerImport\(\)"/, '导入入口以调用形态绑定（不得写成方法引用）')
  // 预览请求失败（备份文件已不存在 / 超过上限…）：服务器备份模式下失败原因必须留在
  // 弹框内——全局提示几秒即逝，而此时分类全禁用、没有重试入口。
  const failure = section(page, 'const importValidateFailureText', 'const startImportValidation')
  assert.match(failure, /error instanceof Error && error\.message \? error\.message : t\('app\.settings\.basic\.import\.validateRequestFail'\)/, '预览请求失败：两种数据源都在弹框内显示失败原因，没有可用原因时回落通用文案')
  assert.doesNotMatch(failure, /importBackupId/, '本地文件模式不再区别对待')
  assert.equal((page.match(/error: importValidateFailureText\(error\)/g) ?? []).length, 2, '首轮预览与分类重校验两处都经同一取词')
  // 关闭弹框必须清掉服务器备份的数据源状态：否则「还原 → 关闭 → 本地文件导入」
  // 会带着旧的 backup_id 去校验，确认时走 submitRestore(旧 ID)。
  const closed = section(page, 'const onImportDialogClosed', 'const chooseImportFile')
  assert.match(closed, /importBackupId\.value = null/, '关闭即清数据源')
  assert.match(closed, /importBackupSections\.value = \[\]/, '关闭即清可导入分类')
})

// 服务器备份只开放它实际包含的分类：预览 summary 以表名为键，分类所含的表任一在场
// （导出恒带所选分类的全部表，空表计 0）即该分类在场；分类→表为后端
// configBackupSections.Tables 的镜像，跨栈对表。
test('服务器备份实际包含的分类由预览 summary 判定，分类→表与后端同源', () => {
  const go = repoCode('internal/handlers/config_backup.go')
  const goBlock = section(go, 'var configBackupSections = []struct', '\n}\n')
  const goTables = [...goBlock.matchAll(/\{Key: "(\w+)", Label: "[^"]+", Tables: \[\]string\{([^}]*)\}/g)]
    .map((m) => [m[1], [...m[2].matchAll(/"([a-z0-9_]+)"/g)].map((x) => x[1])])
  assert.deepEqual(BACKUP_SECTIONS.map((s) => [s.key, [...BACKUP_SECTION_TABLES[s.key]]]), goTables, '分类→表漂移会让备份包含的分类被误判为未包含')

  const everyTable = Object.fromEntries(Object.values(BACKUP_SECTION_TABLES).flat().map((table) => [table, 0]))
  assert.deepEqual(backupSectionsInSummary(everyTable), ['users', 'rules', 'security', 'cluster'])
  assert.deepEqual(backupSectionsInSummary({ lb_rules: 2, upstreams: 0, path_rules: 0, cert_jobs: 0 }), ['rules'], '空表计 0 也算在场；未含分类不算')
  assert.deepEqual(backupSectionsInSummary({ users: 1, nodes: 1 }), ['users', 'cluster'])
  // summary 缺席（校验未通过/请求失败）：不限制分类，交由后端按备份范围取交集
  assert.deepEqual(backupSectionsInSummary(undefined), ['users', 'rules', 'security', 'cluster'])
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
  assert.match(dialog, /<el-text v-if="appLogError"[^>]*>\{\{ t\('app\.settings\.basic\.appLog\.loadFail'\) \}\}/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"loadFail": "日志加载失败，自动重试中'), 'zh 母本须保留 appLog.loadFail 原文')
  assert.match(dialog, /\{\{ appLogContent \|\| appLogEmptyText \}\}/)
  assert.doesNotMatch(dialog, /\{\{ appLogContent \|\| '暂无日志' \}\}/, '失败态不得继续显示「暂无日志」')
  assert.match(page, /const appLogEmptyText = computed\(\(\) => appLogError\.value \? t\('app\.settings\.basic\.appLog\.emptyFail'\) : t\('app\.settings\.basic\.appLog\.empty'\)\)/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"emptyFail": "日志加载失败（自动重试中）"'), 'zh 母本须保留 appLog.emptyFail 原文')

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
  assert.match(scope, /t\('app\.settings\.basic\.autoBackup\.scopeBroken'\)/, '损坏必须显式提示，不得渲染成空范围')
  assert.ok(code('src/locales/zh/settings.ts').includes('"scopeBroken": "范围损坏（见日志）"'), 'zh 母本须保留「范围损坏」原文')
  assert.match(page, /is-warning/, '损坏态必须按 warning 着色')
})
