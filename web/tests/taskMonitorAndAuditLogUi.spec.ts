// 任务监控 / 操作日志 / 日志统计条 的一批行为契约：
//   - 操作日志深翻页上限（后端 page>500 显式 400）：分页器页码不越界、超限
//     常显提示、该 400 不得报「日志加载失败」；
//   - 任务监控：引擎停调与用户手动停止可区分（红标 + 恢复入口按任务给页面/开关
//     名）、关闭定时/循环调度二次确认、确认框与弹框标题走任务显示名词条；
//   - 日志弹框：自动刷新开关；截断提示由前端按 truncated 渲染（内容不混中文）；
//   - 日志统计条：显示名按稳定 key 查词条（与后端 logstats.go 清单跨栈对账）。
//
// 运行：cd web && node --test tests/taskMonitorAndAuditLogUi.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { i18n } from '../src/i18n/index.ts'
import {
  AUDIT_LOG_DEEP_PAGE_LIMIT,
  AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY,
  auditLogDeepPageExceeded,
  auditLogPaginationTotal,
  isAuditLogDeepPageError,
} from '../src/utils/auditLogPaging.ts'
import { BUSINESS_TASK_RECOVERY_KEYS, businessTaskRecoveryTargetKey } from '../src/utils/businessTaskRecovery.ts'
import { LOG_STORAGE_NAME_KEYS, logStorageDisplayName, logStorageNameKey } from '../src/utils/logStorageName.ts'
import { code, goConstInt, member, openTags, repoCode, section } from './_helpers.ts'

type Tree = { [key: string]: unknown }
const treeOf = (locale: 'zh-CN' | 'en'): Tree =>
  (i18n.global.messages.value as Record<string, Record<string, Tree>>)[locale].app as Tree
const at = (tree: Tree, path: string): unknown => path.split('.').reduce<Tree | undefined>((node, key) => (node && typeof node === 'object' ? (node[key] as Tree | undefined) : undefined), tree)
// 词条值取用：缺失/非字符串硬失败——String(undefined) 会让 doesNotMatch 断言空转（假绿）。
const asString = (value: unknown): string => {
  if (typeof value !== 'string') throw new Error(`词条缺失或非字符串: ${String(value)}`)
  return value
}

const taskMonitor = code('src/views/settings/TaskMonitor.vue')

// ── 操作日志深翻页上限 ────────────────────────────────────────────────

test('深翻页：分页器总数按「上限 × 每页条数」截断，超限才提示', () => {
  assert.equal(auditLogPaginationTotal(20_000, 20), 10_000, 'total 超 10000 行时钳到 500 页 × 20')
  assert.equal(auditLogPaginationTotal(10_001, 20), 10_000)
  assert.equal(auditLogPaginationTotal(10_000, 20), 10_000, '恰好 500 页不截断')
  assert.equal(auditLogPaginationTotal(9_999, 20), 9_999, '未超限原样')
  assert.equal(auditLogPaginationTotal(99_999, 100), 50_000, '每页 100 时上限 50000 行')
  assert.equal(auditLogPaginationTotal(0, 20), 0)
  assert.equal(auditLogDeepPageExceeded(10_001, 20), true)
  assert.equal(auditLogDeepPageExceeded(10_000, 20), false, '恰好到上限不算超限（末页就是全部）')
  assert.equal(auditLogDeepPageExceeded(50_001, 100), true)
})

test('深翻页：按稳定 message_key 判别，旧后端按文案兜底，其它状态/错误不误判', () => {
  const deep = { status: 400, messageKey: AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY, message: '结果过多（超过 500 页）' }
  assert.equal(isAuditLogDeepPageError(deep), true)
  assert.equal(isAuditLogDeepPageError({ status: 400, message: '结果过多（超过 500 页），请使用时间范围/用户/动作筛选缩小范围' }), true, '无 message_key 的旧后端按语义文案兜底')
  assert.equal(isAuditLogDeepPageError({ status: 400, messageKey: 'k_other', message: '结果过多' }), false, '键存在且不同 → 不是深翻页')
  assert.equal(isAuditLogDeepPageError({ status: 400, messageKey: undefined, message: 'page 必须为整数' }), false, '同为 400 的分页参数错误不误判')
  assert.equal(isAuditLogDeepPageError({ status: 500, messageKey: AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY }), false)
  assert.equal(isAuditLogDeepPageError({ status: 401 }), false)
  assert.equal(isAuditLogDeepPageError(new Error('boom')), false)
  assert.equal(isAuditLogDeepPageError(null), false)
  assert.equal(isAuditLogDeepPageError(undefined), false)
})

test('深翻页上限与后端常量、消息键跨栈同值', () => {
  assert.equal(goConstInt('internal/handlers/auditlog.go', 'auditLogDeepPageLimit'), AUDIT_LOG_DEEP_PAGE_LIMIT)
  const catalog = repoCode('internal/i18n/catalog_manual.go')
  assert.ok(catalog.includes(`Register("${AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY}"`), '消息键必须在手工登记表')
  const backend = repoCode('internal/handlers/auditlog.go')
  assert.match(backend, new RegExp(`MessageKey: "${AUDIT_LOG_DEEP_PAGE_MESSAGE_KEY}"`), '后端该 400 必须下发稳定消息键（前端判别依赖）')
})

test('操作日志页：分页器总数走截断值，超限常显提示，上限 400 不报加载失败', () => {
  const page = code('src/views/AuditLog.vue')
  assert.match(page, /:total="paginationTotal"/, '分页器不得按真实 total 渲染页码')
  assert.match(page, /const paginationTotal = computed\(\(\) => auditLogPaginationTotal\(total\.value, pageSize\.value\)\)/)
  assert.match(page, /const deepPageCapped = computed\(\(\) => auditLogDeepPageExceeded\(total\.value, pageSize\.value\)\)/)
  const cappedHints = openTags(page, 'el-text').filter((tag) => tag.includes('v-if="deepPageCapped"'))
  assert.equal(cappedHints.length, 1, '超限提示必须渲染且仅一处')
  // 横幅（独立状态，warning 级，无「重试」——重试到不了那一页）与空态文案分流。
  const exceededAlerts = openTags(page, 'el-alert').filter((tag) => tag.includes('v-if="deepPageExceeded"'))
  assert.equal(exceededAlerts.length, 1)
  assert.match(exceededAlerts[0]!, /type="warning"/)
  assert.match(
    page,
    /deepPageExceeded \? t\('common\.app\.views\.audit\.deepPageExceeded', \{ limit: AUDIT_LOG_DEEP_PAGE_LIMIT \}\) : \(loadError \? t\('common\.app\.views\.audit\.listLoadFailed'\) : t\('common\.app\.views\.audit\.emptyLogs'\)\)/,
    '空态文案必须先判深翻页上限，再判加载失败',
  )
  const fetchBody = section(page, 'const fetchLogs = async', 'onMounted(')
  const classify = member(fetchBody, 'if (currentRequestSeq === requestSeq && isAuditLogDeepPageError(e)) {')
  assert.match(classify, /if \(currentRequestSeq === requestSeq && isAuditLogDeepPageError\(e\)\) \{\s*deepPageExceeded\.value = true\s*loadError\.value = false/, '上限 400 置专门状态且清加载失败态（仍只认最新请求）')
  assert.match(fetchBody, /\} else if \(currentRequestSeq === requestSeq\) loadError\.value = true/, '其余失败仍走加载失败态')
  assert.match(fetchBody, /loadError\.value = false\s*deepPageExceeded\.value = false/, '成功复位两态')
})

test('深翻页文案 zh/en 成对且带 {limit}', () => {
  const zh = treeOf('zh-CN')
  const en = treeOf('en')
  assert.equal(at(zh, 'views.audit.deepPageExceeded'), '已超过第 {limit} 页上限，请缩小筛选范围')
  assert.equal(at(en, 'views.audit.deepPageExceeded'), 'Beyond the {limit}-page limit — narrow the filters')
  for (const tree of [zh, en]) {
    assert.match(String(at(tree, 'views.audit.deepPageCapped')), /\{limit\}/)
    assert.match(String(at(tree, 'views.audit.deepPageCapped')), /筛选|filter|narrow/i)
  }
})

// ── 引擎停调 vs 手动停止 ─────────────────────────────────────────────

test('停调恢复入口：六个业务驱动任务 id 与后端唯一清单同集', () => {
  const wire = repoCode('internal/services/taskengine_wire.go')
  const drivers = section(wire, 'var businessTaskDrivers = []businessTaskDriver{', '\nfunc businessTaskIDForAutoUpdatePrefix')
  const autobanID = repoCode('internal/services/autoban.go').match(/AutobanTaskID = "([^"]+)"/)?.[1]
  assert.ok(autobanID, '后端 AutobanTaskID 常量未解析到')
  const backendIDs = [...drivers.matchAll(/\{id: ("[^"]+"|AutobanTaskID),/g)].map((m) =>
    m[1] === 'AutobanTaskID' ? autobanID : (m[1] as string).slice(1, -1))
  assert.equal(backendIDs.length, 6, `后端业务驱动清单解析到 ${backendIDs.length} 项`)
  assert.deepEqual([...backendIDs].sort(), Object.keys(BUSINESS_TASK_RECOVERY_KEYS).sort(), '前端恢复入口映射必须覆盖且仅覆盖后端业务驱动任务')
})

test('停调恢复入口：按 id 取词条键，未登记/原型键返回 null', () => {
  assert.equal(businessTaskRecoveryTargetKey('auto-backup'), 'app.settings.taskMonitor.stopTip.recoveryTargets.autoBackup')
  assert.equal(businessTaskRecoveryTargetKey('crawlerbot-update'), 'app.settings.taskMonitor.stopTip.recoveryTargets.crawlerbotUpdate')
  assert.equal(businessTaskRecoveryTargetKey('constructor'), null)
  assert.equal(businessTaskRecoveryTargetKey('toString'), null)
  assert.equal(businessTaskRecoveryTargetKey('cert-renew-scan'), null)
})

test('停调恢复文案：模板带 {target}，六个入口词条成对且指向各自的页面/开关', () => {
  const zh = treeOf('zh-CN')
  const en = treeOf('en')
  const zhTip = at(zh, 'settings.taskMonitor.stopTip') as Record<string, unknown>
  assert.match(asString(at(en, 'settings.taskMonitor.stopTip.businessDriven')), /\{target\}/, 'en 模板同样按 {target} 参数化')
  assert.match(asString(zhTip.businessDriven), /\{target\}/)
  assert.doesNotMatch(asString(zhTip.businessDriven), /自动更新/, '恢复提示不得再写死「自动更新」')
  assert.match(asString(zhTip.businessDrivenGeneric), /\{head\}/)
  const zhTargets = at(zh, 'settings.taskMonitor.stopTip.recoveryTargets') as Record<string, string>
  const enTargets = at(en, 'settings.taskMonitor.stopTip.recoveryTargets') as Record<string, string>
  assert.deepEqual(Object.keys(zhTargets).sort(), Object.keys(enTargets).sort())
  assert.equal(Object.keys(zhTargets).length, 6)
  // 四个规则集库：规则集页的「<库名> · 自动更新」开关。
  for (const key of ['threat', 'crs', 'ip2region', 'crawlerbotUpdate']) {
    assert.match(zhTargets[key]!, /「规则集」页的「.+ · 自动更新」开关$/)
    assert.match(enTargets[key]!, /switch on the "Rule sets" page$/)
  }
  assert.match(zhTargets.threat!, /威胁情报库/)
  assert.match(zhTargets.crs!, /CRS 规则库/)
  assert.match(zhTargets.ip2region!, /IP 地理库/)
  assert.match(zhTargets.crawlerbotUpdate!, /爬虫地址库/)
  // 自动备份的入口是基础设置的自动备份弹框「启用」——不是「自动更新」。
  assert.match(zhTargets.autoBackup!, /基础设置.+自动备份.+启用/)
  assert.doesNotMatch(zhTargets.autoBackup!, /自动更新/)
  assert.match(enTargets.autoBackup!, /Enable.+Automatic backup/)
  // 自动封禁的入口是事件日志页的自动封禁开关。
  assert.match(zhTargets.autoban!, /「事件日志」页的「自动封禁」开关$/)
  assert.doesNotMatch(zhTargets.autoban!, /自动更新/)
  assert.match(enTargets.autoban!, /"Event logs" page$/)
})

test('停调恢复提示接线：业务驱动行按 id 取入口，未登记回落通用文案，其余走本页开关', () => {
  const tip = member(taskMonitor, 'const scheduleStoppedTip = ')
  assert.match(tip, /const targetKey = businessTaskRecoveryTargetKey\(row\.id\)/)
  assert.match(tip, /\? t\('app\.settings\.taskMonitor\.stopTip\.businessDriven', \{ head, target: t\(targetKey\) \}\)/)
  assert.match(tip, /: t\('app\.settings\.taskMonitor\.stopTip\.businessDrivenGeneric', \{ head \}\)/)
  assert.match(tip, /if \(!isBusinessDrivenTask\(row\)\) \{\s*return t\('app\.settings\.taskMonitor\.stopTip\.genericFix', \{ head \}\)/)
})

test('调度列：停调红标对所有任务显示；业务驱动停调行无开关，其余停调行保留开关', () => {
  const scheduleColumn = section(taskMonitor, '<el-table-column :label="t(\'app.settings.taskMonitor.col.schedule\')"', '</el-table-column>')
  const stoppedTags = openTags(scheduleColumn, 'el-tag').filter((tag) => tag.includes('v-if="row.schedule_stopped_reason"'))
  assert.equal(stoppedTags.length, 1, '「已停调」标签必须渲染且仅一处')
  assert.match(stoppedTags[0]!, /type="danger"/, '停调是警示态')
  assert.match(
    scheduleColumn,
    /<el-tag v-if="row\.schedule_stopped_reason"[^>]*>\{\{ t\('app\.settings\.taskMonitor\.schedule\.stoppedTag'\) \}\}<\/el-tag>/,
    '标签只以引擎停调为门——非业务驱动任务停调同样显示「已停调」',
  )
  // 标签所在 tooltip 的通用分支：开关的唯一门是「非业务驱动」，停调不再隐藏开关。
  const branch = section(scheduleColumn, 'v-else-if="row.kind !== \'oneshot\'"', '</el-tooltip>')
  const switches = openTags(branch, 'el-switch')
  assert.equal(switches.length, 1)
  assert.match(switches[0]!, /v-if="!isBusinessDrivenTask\(row as TaskInfo\)"/, '业务驱动停调行=只有标签无开关；其余行保留开关用于恢复')
  assert.match(switches[0]!, /@change="\(v: string \| number \| boolean\) => onToggle\(row as TaskInfo, !!v\)"/)
})

// ── 关闭调度二次确认 ─────────────────────────────────────────────────

test('关闭定时/循环/常驻调度均二次确认；开启方向不确认', () => {
  const toggle = member(taskMonitor, 'const onToggle = ')
  assert.match(toggle, /const needConfirm = !enabled && row\.kind !== 'oneshot'/, '非触发类的关闭方向都确认')
  assert.match(toggle, /const confirm = !needConfirm\s*\? undefined/, '开启方向 confirm=undefined（不弹框）')
  assert.match(toggle, /row\.kind === 'daemon'\s*\? \{ message: t\('app\.settings\.taskMonitor\.stopConfirm'/, '常驻沿用 stopConfirm')
  assert.match(toggle, /: \{ message: t\('app\.settings\.taskMonitor\.scheduleStopConfirm', \{ name: taskDisplayName\(row\.name\) \}\), title: t\('app\.settings\.taskMonitor\.actions\.scheduleControlTitle'\)/)
  const zh = treeOf('zh-CN')
  const en = treeOf('en')
  const zhConfirm = String(at(zh, 'settings.taskMonitor.scheduleStopConfirm'))
  const enConfirm = String(at(en, 'settings.taskMonitor.scheduleStopConfirm'))
  assert.match(zhConfirm, /不再自动执行/)
  assert.match(zhConfirm, /\{name\}/)
  assert.match(enConfirm, /no longer run automatically/)
  assert.match(enConfirm, /\{name\}/)
})

// ── 英文界面不混入后端中文名 ─────────────────────────────────────────

test('任务监控：确认框、弹框标题、统计条显示名走任务显示名词条', () => {
  for (const key of ['runConfirm', 'stopConfirm', 'scheduleStopConfirm', 'cancelConfirm', 'restartConfirm']) {
    assert.match(taskMonitor, new RegExp(`t\\('app\\.settings\\.taskMonitor\\.${key}', \\{ name: taskDisplayName\\(row\\.name\\) \\}\\)`), `${key} 的任务名必须走 taskDisplayName`)
  }
  assert.doesNotMatch(taskMonitor, /\{ name: row\.name \}/, '确认框不得直出后端中文名')
  assert.match(taskMonitor, /logDialogTitle', \{ name: taskDisplayName\(logsTask\?\.name \|\| ''\) \}\)/)
  assert.doesNotMatch(taskMonitor, /\{ name: logsTask\?\.name/, '弹框标题不得直出后端中文名')
  assert.match(taskMonitor, /<LogStorageBar :log-key="logsTaskStorageKey" :label="logsStorageLabel" style="margin-right: auto" \/>/)
  assert.match(taskMonitor, /t\('common\.app\.views\.logStorage\.taskLogName', \{ name: taskDisplayName\(logsTask\.value\.name\) \}\)/)
})

test('日志统计条：显示名按稳定 key 查词条，不直出后端 name；规则后缀保留；动态行回落', () => {
  const bar = code('src/components/LogStorageBar.vue')
  assert.match(bar, /<span class="name">\{\{ displayName \}\}<\/span>/)
  assert.doesNotMatch(bar, /\{\{ info\.name \}\}/, '统计条不得直出后端中文名')
  assert.match(bar, /const displayName = computed\(\(\) => props\.label \|\| logStorageDisplayName\(info\.value\?\.key \?\? '', info\.value\?\.name \?\? ''\)\)/)
  assert.match(bar, /defineProps<\{ logKey: string; caddyId\?: string; refreshKey\?: number; label\?: string \}>/, 'label=调用方已本地化的显示名（task:<id> 动态行）')

  const saved = i18n.global.locale.value
  try {
    i18n.global.locale.value = 'zh-CN'
    assert.equal(logStorageDisplayName('runtime', '运行日志'), '运行日志')
    // 英文界面：固定行按词条本地化，带规则 ID 的后缀保留，未登记动态行回落后端 name。
    i18n.global.locale.value = 'en'
    assert.equal(logStorageDisplayName('runtime', '运行日志'), 'Runtime logs', '英文界面不得直出后端中文 name')
    assert.equal(logStorageDisplayName('certjob', '证书任务日志 #lb_abc'), 'Certificate job logs #lb_abc', '规则 ID 后缀必须保留')
    assert.equal(logStorageDisplayName('rule_access', '访问日志 #lb_abc'), 'Rule access logs #lb_abc')
    assert.equal(logStorageDisplayName('task:autoban', '自动封禁日志'), '自动封禁日志', '逐任务动态行由调用方 label 覆盖，函数自身回落原文')
    assert.equal(logStorageDisplayName('constructor', '原型键'), '原型键')
  } finally {
    i18n.global.locale.value = saved
  }
  assert.equal(logStorageNameKey('audit'), 'common.app.views.logStorage.names.audit')
  assert.equal(logStorageNameKey('task:threat'), null)
  assert.equal(logStorageNameKey('__proto__'), null)
})

test('日志统计条固定行词条与后端 logstats.go 清单同集，zh 与后端母本同文', () => {
  const go = repoCode('internal/handlers/logstats.go')
  const infos = section(go, 'infos := []LogStorageInfo{', '\n\tbyKey := func(key string)')
  const backendRows = [...infos.matchAll(/\{Key: "([^"]+)", Name: "([^"]+)"/g)].map((m) => [m[1] as string, m[2] as string] as const)
  assert.equal(backendRows.length, 14, `后端固定行解析到 ${backendRows.length} 项`)
  assert.deepEqual(backendRows.map(([key]) => key).sort(), Object.keys(LOG_STORAGE_NAME_KEYS).sort(), '前端词条映射必须覆盖后端全部固定行')
  const zh = treeOf('zh-CN')
  const en = treeOf('en')
  const zhNames = at(zh, 'views.logStorage.names') as Record<string, string>
  const enNames = at(en, 'views.logStorage.names') as Record<string, string>
  for (const [key, backendName] of backendRows) {
    const suffix = LOG_STORAGE_NAME_KEYS[key]!
    assert.equal(zhNames[suffix], backendName, `zh 显示名应与后端母本同文（${key}）`)
    assert.ok(enNames[suffix] && !/[\u4e00-\u9fff]/.test(enNames[suffix]!), `en 显示名不得含中文（${key}）`)
  }
})

// ── 日志弹框：自动刷新开关 + 截断提示 ─────────────────────────────────

test('任务日志弹框：自动刷新开关关=停轮询、开=重启并立即刷新', () => {
  const switches = openTags(taskMonitor, 'el-switch').filter((tag) => tag.includes('v-model="logAutoRefresh"'))
  assert.equal(switches.length, 1, 'footer 必须有且仅有一个自动刷新开关')
  const open = member(taskMonitor, 'const openLogs = ')
  assert.match(open, /if \(logAutoRefresh\.value\) logsTail\.start\(\)\s*else void logsTail\.refresh\(\)/, '打开弹框：开=装定时器并首拉；关=只拉一轮')
  assert.match(open, /logsTruncated\.value = false/, '换任务必须复位截断提示')
  const watcher = section(taskMonitor, 'watch(logAutoRefresh, (enabled) => {', '\n})')
  assert.match(watcher, /if \(!logsVisible\.value\) return/, '弹框关闭时的开关变化不装定时器')
  assert.match(watcher, /if \(enabled\) logsTail\.start\(\)\s*else logsTail\.stop\(\)/)
})

test('截断提示由前端按 truncated 渲染：任务日志与证书任务日志弹框共用同一键', () => {
  assert.match(taskMonitor, /logsTruncated\.value = res\.data\.truncated === true/)
  assert.match(code('src/views/settings/TaskMonitor.vue'), /<div v-if="logsTruncated" class="tm-log-truncated">\{\{ t\('common\.app\.views\.logStorage\.truncatedNotice'\) \}\}<\/div>/)
  const certJobs = code('src/views/settings/CertJobs.vue')
  assert.match(certJobs, /<div v-if="logTruncated" class="log-truncated">\{\{ t\('common\.app\.views\.logStorage\.truncatedNotice'\) \}\}<\/div>/)
  assert.match(code('src/views/settings/CertJobs.vue'), /logTruncated\.value = res\.data\?\.truncated === true/)
  // 后端两个 handler 不再把提示行写进内容（Go 行为钉见 handlers 包）。
  for (const file of ['internal/handlers/taskmonitor.go', 'internal/handlers/certjobs.go']) {
    assert.doesNotMatch(repoCode(file), /日志过长|仅显示最近/, `${file} 不得把提示行写回响应内容`)
  }
  const docs = repoCode('internal/handlers/apidocs.go')
  const taskLogsDoc = docs.split('\n').find((line) => line.includes('{"GET", "/system/tasks/:id/logs"'))
  assert.ok(taskLogsDoc, 'apidocs 缺 /system/tasks/:id/logs 条目')
  assert.match(taskLogsDoc!, /`[^\n]*"truncated":false[^\n]*`/, '响应示例必须带 truncated')
  const zh = treeOf('zh-CN')
  const en = treeOf('en')
  assert.equal(at(zh, 'views.logStorage.truncatedNotice'), '日志过长，仅显示最近 256KB')
  assert.equal(at(en, 'views.logStorage.truncatedNotice'), 'Log too long — only the most recent 256KB is shown')
})

// ── 「审计日志大小」残留配置项已从设置页删除 ─────────────────────────

test('设置页不再暴露审计文件大小项（后端列保留）', () => {
  const zh = treeOf('zh-CN')
  const en = treeOf('en')
  assert.equal(at(zh, 'settings.basic.log.auditLogSize'), undefined)
  assert.equal(at(zh, 'settings.basic.log.auditLogSizeHint'), undefined)
  assert.equal(at(en, 'settings.basic.log.auditLogSize'), undefined)
  assert.equal(at(en, 'settings.basic.log.auditLogSizeHint'), undefined)
  const basic = code('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(basic, /audit_log_size_mb/, '前端不得再读写该字段')
  assert.doesNotMatch(basic, /auditLogSize/, '不得残留该表单项')
  // 同卡片其它日志项与「操作审计保留」必须仍在
  for (const key of ['taskLogSize', 'runLogSize', 'auditRetention']) {
    assert.ok(basic.includes(`settings.basic.log.${key}`), `${key} 不得随之删除`)
  }
})

test('任务操作成功提示里的任务名走显示名映射（英文界面不混入中文任务名）', () => {
  assert.match(
    taskMonitor,
    /mfaAwareSuccess\(localizeTaskMessage\(res\.message \?\? '', row\.name\) \|\| options\.successFallback\)/,
    '成功提示必须先把后端文案里的原始任务名换成显示名',
  )
  const helper = section(taskMonitor, 'const localizeTaskMessage', 'const taskFamilyCount')
  assert.match(helper, /taskDisplayName\(rawName\)/, '必须复用列表/确认框的同一映射')
  assert.match(helper, /message\.split\(rawName\)\.join\(display\)/, '按原始任务名整词替换')
  assert.match(helper, /if \(!rawName\) return message/, '无任务名（证书行用 id）原样返回')
})

// ── 操作日志 IP 列头 ──────────────────────────────────────────────────

test('操作日志 IP 列头走词条（复用 API 接入页的「来源 IP」键，不硬编码）', () => {
  const page = code('src/views/AuditLog.vue')
  assert.match(
    page,
    /<el-table-column prop="ip_address" :label="t\('common\.app\.views\.keys\.colSourceIp'\)" width="160" show-overflow-tooltip \/>/,
  )
  assert.doesNotMatch(page, /label="IP"/, '列头不得硬编码英文缩写')
  assert.equal(at(treeOf('zh-CN'), 'views.keys.colSourceIp'), '来源 IP')
  assert.equal(at(treeOf('en'), 'views.keys.colSourceIp'), 'Source IP')
})
