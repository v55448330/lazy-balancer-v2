// 视图状态契约钉测：向导协议切换的隐藏字段清理、证书详情重试的会话守卫、
// 规则库排程的未知态、弹框保存中三件套、集群库版本 tooltip、配置/统计的
// 失败三态与只读边界。仅静态源码钉（node --test，无打包器）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, repoCode, section, source } from './_helpers.ts'
import { bucketTerminology } from '../src/utils/threatScreenMetrics.ts'

test('规则向导切 TCP 清空动态上游与 DNS 字段（隐藏控件不得留下恒拒残留）', () => {
  const rules = code('src/views/Rules.vue')
  const branch = section(rules, "if (newVal === 'tcp') {", "} else if (newVal === 'http'")
  assert.match(branch, /wizardForm\.dynamic_dns = false/, 'TCP 下动态上游整段不渲染，必须清残留')
  assert.match(branch, /wizardForm\.enable_dns_server = false/)
  assert.match(branch, /wizardForm\.dns_server = ''/)
})

test('证书详情重试按会话序号丢弃过期响应（编辑与复制态同口径）', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /let tlsDetailSeq = 0/)
  const retry = section(rules, 'async function retryTlsDetail', 'const resetCertInfo')
  assert.match(retry, /const sessionSeq = \+\+tlsDetailSeq/)
  assert.match(retry, /tlsDetailRuleId\.value === caddyId/, '目标规则判据不得依赖 editingRule（复制态恒为 null）')
  assert.doesNotMatch(retry, /editingRule\.value\?\.caddy_id/, '复制态 editingRule 为空：用它判会话会把重试回填全部丢弃')
  assert.match(retry, /if \(!sessionAlive\(\)\) return/)
  const reset = section(rules, 'const resetWizard = ', 'const beforeWizardClose')
  assert.match(reset, /tlsDetailSeq\+\+/, '关闭向导必须作废在途重试会话')
  // 复制入口在请求前清空 editingRule 并记录失败目标 id——两者必须同时成立
  const copy = section(rules, 'const openCopyWizard = async', 'const viewConfig')
  assert.match(copy, /editingRule\.value = null/)
  assert.match(copy, /markTlsDetailFailed\(rule\.caddy_id\)/)
})

test('规则库排程在库信息未落地/读取失败时禁用并提示', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.match(page, /const SCHEDULE_UNKNOWN_HINT = '排程未知/)
  for (const hint of ['crsScheduleHint', 'ip2regionScheduleHint', 'threatScheduleHint', 'crawlerScheduleHint']) {
    assert.match(page, new RegExp(`:unavailable-hint="${hint}"`), `${hint} 必须绑定到排程卡`)
    assert.match(page, new RegExp(`if \\(${hint}\\.value\\)`), `${hint} 未落地时保存入口必须拦截`)
  }
  const editor = code('src/components/RuleLibScheduleEditor.vue')
  assert.match(editor, /unavailableHint\?: string/)
  assert.match(editor, /const controlsDisabled = computed\(\(\) => props\.disabled \|\| props\.saving \|\| Boolean\(props\.unavailableHint\)\)/)
})

test('弹框保存中禁止关闭（遮罩/ESC/关闭按钮与取消一致）', () => {
  const cases: readonly [string, string][] = [
    ['src/views/security/SecurityBlockPages.vue', 'saving'],
    ['src/components/SecurityBindingEditor.vue', 'saving'],
    ['src/views/security/SecurityRules.vue', 'savingRule'],
  ]
  for (const [path, flag] of cases) {
    const text = code(path)
    assert.match(text, new RegExp(`:close-on-press-escape="!${flag}"`), `${path} 缺 ESC 门`)
    assert.match(text, new RegExp(`:show-close="!${flag}"`), `${path} 缺关闭按钮门`)
  }
  const certs = code('src/views/settings/FreeCertificates.vue')
  const caDialog = section(certs, 'v-model="caDialogVisible"', 'class="ca-config-dialog"')
  assert.match(caDialog, /:close-on-click-modal="false"/, 'CA 弹框编辑中不得误点遮罩丢弃输入')
})

test('OIDC 保存在探测与二次确认前即进入在途态', () => {
  const oidc = code('src/views/settings/OIDCSettings.vue')
  const save = section(oidc, 'const save = async () => {', 'const toggleEnabled')
  const savingAt = save.indexOf('saving.value = true')
  const probeAt = save.indexOf('await runProbe()')
  const confirmAt = save.indexOf('ElMessageBox.confirm')
  assert.ok(savingAt > 0 && probeAt > savingAt && confirmAt > probeAt, '在途门必须早于探测与确认')
})

test('时区下拉：常用目录 ∪ 当前值，支持自定义 IANA 名', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /allow-create default-first-option/)
  assert.match(page, /const timezoneOptions = computed/)
  assert.match(page, /（自定义）/, '非枚举存量值必须以自定义项回显')
})

test('自动备份频率切换把日期夹回该频率上界', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const watcher = section(page, "watch(() => autoBackupForm.value.frequency", 'const autoBackupSections')
  assert.match(watcher, /frequency === 'weekly' \? 7 : 28/)
  assert.match(watcher, /Math\.min\(Math\.max\(1, autoBackupForm\.value\.day\), high\)/)
})

test('受信代理关闭态：存量非法值显性可见且保存提示修复路径', () => {
  const page = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(page, /const trustedProxyDisabledStaleError = computed/)
  assert.match(page, /请临时开启「受信代理」修正/, '关闭态错误必须给出可修复路径')
  assert.match(page, /若名单已被删除，保存会被拒绝/, '引用条目未加载的提示不得承诺「不影响保存」')
  // 引用条目拉取限并发，且名单目录刷新时失效缓存
  assert.match(page, /const REF_ENTRY_FETCH_CONCURRENCY = 2/)
  assert.match(page, /invalidateRefListEntries\(\)/)
})

test('自动封禁状态读取仅最新一次可写状态/错误位', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /let autobanStatusSeq = 0/)
  const fetch = section(page, 'const fetchAutobanStatus = async', 'const autobanDialogVisible')
  assert.match(fetch, /if \(requestSeq !== autobanStatusSeq\) return/g)
})

test('规则库信息低频回刷且自动更新开关乐观置值', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.match(page, /createVisibilityIntervals\(\{ intervals: \[\{ tick: refreshLibraryInfo, ms: 60_000 \}\] \}\)/)
  assert.match(page, /const autoUpdateSaving = ref\(new Set<string>\(\)\)/)
  const toggle = section(page, 'const toggleLibAutoUpdate = async', 'const setLibAutoUpdateShown')
  assert.match(toggle, /setLibAutoUpdateShown\(row\.key, val\)/, '点击即置值（不再等响应）')
})

test('威胁与爬虫来源开关：逐来源单飞、请求序号与在途禁用', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.match(page, /const sourceFlagSaving = ref\(new Set<string>\(\)\)/)
  assert.match(page, /const sourceFlagRequestSeq = new Map<string, number>\(\)/)
  const toggle = section(page, 'const toggleSourceFlag = ', 'type CrawlerSource')
  assert.match(toggle, /if \(sourceFlagSaving\.value\.has\(key\)\) return/)
  assert.match(toggle, /const requestSeq = \(sourceFlagRequestSeq\.get\(key\) \?\? 0\) \+ 1/)
  assert.match(toggle, /if \(sourceFlagRequestSeq\.get\(key\) === requestSeq\) row\.update_enabled = !val/)
  assert.match(toggle, /finally \{[\s\S]*sourceFlagSaving\.value\.delete\(key\)/)
  for (const library of ['threat', 'crawler']) {
    assert.match(page, new RegExp(`:loading="sourceFlagPending\\('${library}', row\\.id\\)"`))
    assert.match(page, new RegExp(`:disabled="isReadOnly \\|\\| isSlaveNode \\|\\| sourceFlagPending\\('${library}', row\\.id\\)"`))
  }
})

test('大屏：窗口切换保留上一帧并标注切换中，配置读取失败区别于未配置', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  const setWindow = section(screen, 'function setWindow(hours: number)', 'const screenMode = ref')
  assert.doesNotMatch(setWindow, /stats\.value = null/, '切换窗口不得清空统计（全屏 KPI 归零误读为无攻击）')
  assert.match(screen, /const statsPending = computed/)
  assert.match(screen, /切换中…/)
  assert.match(screen, /const configLoadFailed = ref\(false\)/)
  assert.match(screen, /大屏配置读取失败/, '读取失败不得渲染成「未配置站点坐标」')
  assert.match(screen, /bucketTerminology\(windowHours\.value\)/, '概览口径词随窗口派生')
  assert.match(screen, /role="status" aria-live="polite"/, '故障横幅与攻击弹框需要 live region')
})

test('登录：创建管理员与自动登录分阶段，OIDC 保持深链', () => {
  const login = code('src/views/Login.vue')
  const setup = section(login, 'const handleSetup = async', 'onMounted(async')
  assert.match(setup, /管理员已创建，请手动登录/, '登录失败不得报「创建管理员失败」')
  // 深链 + 来源绑定：return_to 仍按当前页面键组装，同时并入本标签页 nonce
  //（回调侧据此拒绝构造链接投递的令牌）
  assert.match(login, /withOidcAppNonce\(`\/\$\{authStore\.currentPage\}`, nonce\)/, 'OIDC return_to 必须携带当前页面键与本轮 nonce')
  assert.match(login, /sessionStorage\.setItem\(OIDC_APP_NONCE_KEY, nonce\)/, 'nonce 必须落到本标签页 sessionStorage')
  // 清空必须发生在 `watch(mfaUseRecovery, …)` 的回调体内（按回调块配对取段）：
  // 距离窗口会把 120 字符内另一个 handler 的清空算作本 watch 的行为。
  assert.match(member(login, 'watch(mfaUseRecovery, () => {'), /mfaCode\.value = ''/, '通道切换清空验证码')
})

test('集群节点 tooltip：四项库版本名称与规则库列表同源，缺失显示 —', () => {
  const panel = code('src/views/settings/cluster/ClusterMasterPanel.vue')
  for (const label of ['CRS 规则库', 'IP 地理库', '威胁情报库', '爬虫地址库']) {
    assert.match(panel, new RegExp(`label: '${label}'`), `缺少 ${label}`)
  }
  for (const key of ['crs_version', 'ip2region_version', 'threat_version', 'crawler_version']) {
    assert.match(panel, new RegExp(`key: '${key}'`), `缺少 ${key}`)
  }
  assert.match(panel, /health\[key\] \|\| '—'/)
  const types = code('src/types/index.ts')
  assert.match(types, /readonly threat_version\?: string/)
  assert.match(types, /readonly crawler_version\?: string/)
})

test('审计日志分页在总数收缩后自动夹紧', () => {
  const page = code('src/views/AuditLog.vue')
  const fetch = section(page, 'const fetchLogs = async', 'onMounted')
  assert.match(fetch, /const maxPage = Math\.max\(1, Math\.ceil\(nextTotal \/ targetPageSize\)\)/)
  // 夹紧 → 按新页重取 → 提前返回必须同在一个 `if (targetPage > maxPage)` 块内且
  // 顺序固定：距离窗口（≤80 字符）跨不进/跨得进本块都说不清，且漏 `return` 时
  // 仍可能命中（继续落地越界页数据）。
  const clamp = member(fetch, 'if (targetPage > maxPage) {')
  const clampAt = clamp.indexOf('page.value = maxPage')
  const refetchAt = clamp.indexOf('void fetchLogs()')
  const returnAt = clamp.indexOf('return')
  assert.ok(clampAt > 0 && refetchAt > clampAt, '夹紧后必须按新页码重取（el-pagination 不会自己发 current-change）')
  assert.ok(returnAt > refetchAt, '重取后必须提前返回，不得继续落地越界页数据')
  assert.doesNotMatch(clamp, /logs\.value = /, '越界分支不得落地列表数据')
})

test('IP 快捷弹框不再调用不存在的 popover.open()', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.doesNotMatch(page, /openPopover|popoverRef/)
})

test('IP 地理快捷弹框的可点击单元保留键盘可达语义', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.match(page, /role="button"/)
  assert.match(page, /tabindex="0"/)
})

test('视图口径与样式契约：端口门、CA 门、摘要披露、分页夹紧、样式单源', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /80 端口开启 TLS 跳转无意义/, '80+TLS 跳转必须前端镜像后端门')
  const certs = code('src/views/settings/FreeCertificates.vue')
  assert.match(certs, /默认 CA 提供商已被禁用/, '默认 CA 被禁用必须前置中文提示')
  assert.match(certs, /caForm\.min_interval_ms" :min="1"/, '最小间隔下限与写侧门（1..60000）同源')
  const dash = code('src/views/Dashboard.vue')
  assert.match(dash, /零流量规则不进入排行/, '规则卡必须披露截断口径')
  assert.match(dash, /chart-stale-hint/, '采集失败保留曲线并标陈旧')
  const screen = code('src/views/security/ThreatScreen.vue')
  assert.doesNotMatch(screen, /'mixed'/, '动作分支仅 blocked/logged，mixed 不可达')
  assert.match(screen, /eventActionFull\(t\.action\)/, '弹框动作文案复用单源映射')
  const overview = code('src/views/security/SecurityOverview.vue')
  assert.doesNotMatch(overview, /<el-col :span="(16|8)"/, '下两行必须补响应式断点')
  const css = code('src/styles/main.css')
  assert.match(css, /^\.polling-error-alert \{ margin-bottom: 16px; \}$/m, '被 7 页引用的类必须有全局定义')
  const cluster = code('src/views/settings/cluster/ClusterMasterPanel.vue')
  assert.doesNotMatch(cluster, /\.settings-form \.form-tip-inline/, '全局类不得在 scoped 中重定义')
  const task = code('src/views/settings/TaskMonitor.vue')
  assert.doesNotMatch(task, /（不含证书工作项）|（含证书工作项）/)
  assert.match(task, /<div class="tm-filter-group">/)
  assert.match(task, /近 24 小时成功 \/ 失败次数；历史明细最多 50 条/)
  const retry = section(task, 'const retryPolling = async', 'interface CertJobRow')
  assert.match(retry, /refreshing\.value = true/)
})

test('窗口粒度术语：窗口词与峰值/计数词同源派生（7d 不得渲染 168 小时）', () => {
  assert.deepEqual(bucketTerminology(1), { unit: '小时', peakLabel: '峰值时段', countLabel: '有事件小时', windowLabel: '1 小时' })
  assert.deepEqual(bucketTerminology(24), { unit: '小时', peakLabel: '峰值时段', countLabel: '有事件小时', windowLabel: '24 小时' })
  assert.deepEqual(bucketTerminology(168), { unit: '天', peakLabel: '峰值日期', countLabel: '有事件天', windowLabel: '7 天' })
})

test('大屏：配置重试联动引擎重装、切换失败三态互斥、窗口词随粒度派生', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  // 配置重试必须重装引擎：模式（map/globe）由 /config 决定，只改 screenMode 会让
  // HUD（地球标题/竖扫/操作提示）与舞台引擎错配。mountEngine 幂等。
  const retry = section(screen, 'async function retryConfigLoad', 'const feedError = ref(false)')
  assert.match(retry, /await loadServerCentroid\(\)/)
  assert.match(retry, /await mountEngine\(\)/)
  assert.match(screen, /@click="retryConfigLoad"/)
  // 失败时不得同时呈现「切换中」：旧帧改标「上次结果 · 窗口 X」
  assert.match(screen, /const statsPending = computed\(\(\) => !statsError\.value && stats\.value !== null/)
  assert.match(screen, /上次结果 · /)
  // 7d 窗口不得再渲染「168 小时 / 168h」（窗口词由 bucketTerms.windowLabel 派生）
  assert.doesNotMatch(screen, /windowHours \}\} 小时/)
  assert.doesNotMatch(screen, /windowHours \}\}h/)
  assert.match(screen, /bucketTerms\.windowLabel/)
})

test('大屏死样式与重复常量收敛（调色板单源、转发别名已删）', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  assert.doesNotMatch(screen, /\.kpi-value small/, '模板内无 small，规则为死样式')
  assert.doesNotMatch(screen, /class="mono"/, '全仓无 .mono 选择器')
  assert.doesNotMatch(screen, /hint-desktop/, '无匹配规则')
  assert.doesNotMatch(screen, /countryBarColor/, '纯转发别名必须删除')
  assert.doesNotMatch(screen, /SHARE_PALETTE|TYPE_PALETTE/, '两份同值调色板收敛为单源')
  assert.match(screen, /const THREAT_PALETTE = \[/)
})

test('规则库四库回刷：silent 拉取 + 每库请求序号守卫', () => {
  const page = code('src/views/security/SecurityRules.vue')
  const cases = [
    ['fetchThreatLib', 'threatLibInfoSeq'],
    ['fetchCrawlerLib', 'crawlerLibInfoSeq'],
    ['fetchCRS', 'crsInfoSeq'],
    ['fetchIP2RegionInfo', 'ip2regionInfoSeq'],
  ] as const
  for (const [fn, seq] of cases) {
    const body = member(page, `const ${fn} = async`)
    assert.match(body, /, \{ silent: true \}\)/, `${fn} 失败态由健康标签承载，不得逐分钟弹全局 toast`)
    assert.match(body, new RegExp(`const seq = \\+\\+${seq}`), `${fn} 缺请求序号`)
    assert.equal(
      (body.match(new RegExp(`seq !== ${seq}`, 'g')) ?? []).length,
      2,
      `${fn} 成功与失败分支都要守卫（乱序响应不得覆盖新值）`,
    )
  }
})

test('样式契约收敛：scoped 重复删除、main.css 合并、死重量清理', () => {
  for (const file of ['src/views/Rules.vue', 'src/views/settings/CertJobs.vue', 'src/views/AuditLog.vue']) {
    assert.doesNotMatch(
      code(file),
      /^\.polling-error-alert \{ margin-bottom: 16px; \}$/m,
      `${file} 仍逐字重复全局 .polling-error-alert`,
    )
  }
  const css = code('src/styles/main.css')
  assert.match(css, /^\.polling-error-alert \{ margin-bottom: 16px; \}$/m, '全局单源必须保留')
  assert.doesNotMatch(code('src/views/security/SecurityPolicies.vue'), /mb-5/, 'mb-5 被同权重后置声明覆盖，属死重量')
})

test('顶栏消费 /caddy/status 的 status：非仪表盘页可见 Caddy 停摆', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  assert.match(layout, /caddyStopped\.value = res\.data\?\.status === 'stopped'/)
  assert.match(layout, /v-if="caddyStopped"/)
  assert.match(layout, /Caddy 服务未运行/)
  assert.match(layout, /重启服务<\/el-button>|>重启服务</, '横幅必须带恢复入口')
})

test('日志占用条注释指向 utils/formatBytes 单源（不再称 api.ts）', () => {
  const raw = source('src/components/LogStorageBar.vue')
  assert.match(raw, /复用 utils\/formatBytes/)
  assert.doesNotMatch(raw, /复用 api\.ts 的 formatBytes/)
})

test('基础设置时区：自由输入在保存前做 IANA 校验（不连坐整卡 400）', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /new Intl\.DateTimeFormat\(undefined, \{ timeZone: tz \}\)/)
  const save = section(page, 'const handleSave = async () => {', 'saving.value = true')
  assert.match(save, /const tzError = timezoneError\(settings\.value\.timezone\)/)
  assert.match(save, /settings\.value\.timezone = settings\.value\.timezone\.trim\(\)/)
})

test('MFA 自助缺口：激活响应缺 data 显性报错、动态码弹框提交中不可关', () => {
  const wizard = code('src/components/MfaBindingWizard.vue')
  assert.match(wizard, /if \(!res\.data\) \{/, '契约违约不得静默 return')
  assert.match(wizard, /响应异常，请重试/)
  const profile = code('src/components/ProfileDialog.vue')
  assert.match(profile, /:close-on-press-escape="!mfaSubmitting"/)
  assert.match(profile, /:show-close="!mfaSubmitting"/)
})

test('可访问名：CodeEditor 暴露 ariaLabel、帮助角标键盘可达', () => {
  const editor = code('src/components/CodeEditor.vue')
  assert.match(editor, /readonly ariaLabel\?: string/)
  assert.match(editor, /:aria-label="ariaLabel \|\| undefined"/)
  assert.match(code('src/views/security/SecurityBlockPages.vue'), /<CodeEditor[^>]*aria-label="拦截页面内容"/)
  const help = code('src/components/common/FieldHelpIcon.vue')
  assert.match(help, /tabindex="0"/)
  assert.match(help, /role="button"/)
  assert.match(help, /:aria-label="content \|\| '字段说明'"/)
})

test('IP 快捷弹层打开即清旧事件计数（行复用不串上一 IP）', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  const show = member(page, 'const onPopoverShow =')
  assert.ok(show.indexOf('eventCount.value = null') < show.indexOf('loadEventCount()'), '必须先清空再取数')
})

test('触发详情：策略 GET 的 catch 有会话序号守卫（与同函数其余 await 同口径）', () => {
  const dialog = code('src/components/events/TriggerDetailDialog.vue')
  // 按函数体取段（不是定长字符窗口）：守卫必须是该 catch 分支的第一条语句，
  // 这样「插入语句把守卫挤出窗口」不会假红，「守卫被挪到相邻语句之后」也不会假绿。
  const loadAll = member(dialog, 'const loadAll = async')
  const missingAt = loadAll.indexOf('policyMissing.value = err instanceof Error')
  assert.ok(missingAt > 0, '策略缺失判据缺失')
  const catchAt = loadAll.lastIndexOf('catch (', missingAt)
  assert.ok(catchAt > 0 && catchAt < missingAt, '策略 GET 的失败处理必须落在 catch 分支内')
  assert.match(
    loadAll.slice(catchAt, missingAt),
    /^catch \(\w+\) \{\s*if \(seq !== loadSeq\) return\s*$/,
    '旧会话失败不得把新会话标成策略已删除/加载失败（守卫须为 catch 首条语句）',
  )
})

test('拦截页表单与后端同源前置门（名称/描述长度、内容非空与 64KB）', () => {
  const text = code('src/views/security/SecurityBlockPages.vue')
  // 长度上限走 utils/securityLimits 单源（跨栈对表见
  // feViewsEdgeStates.spec.ts 的 SECURITY_NAME_MAX_RUNES/SECURITY_DESCRIPTION_MAX_RUNES），
  // 不得回到字面量
  assert.match(text, /v-model="form\.name"[^>]*:maxlength="SECURITY_NAME_MAX_RUNES"/)
  assert.match(text, /v-model="form\.description"[^>]*:maxlength="SECURITY_DESCRIPTION_MAX_RUNES"/)
  assert.match(text, /const BLOCK_PAGE_CONTENT_MAX_BYTES = 64 << 10/)
  assert.match(text, /if \(!form\.value\.content\.trim\(\)\)/)
  assert.match(text, /new TextEncoder\(\)\.encode\(form\.value\.content\)\.byteLength/)
  assert.match(text, /contentBytes > BLOCK_PAGE_CONTENT_MAX_BYTES/)
  assert.doesNotMatch(text, /\.block-page-form \.content-form-item \.el-form-item__content/, '永不命中的 scoped 选择器已删除')
})


test('处理流程弹框把「证书详情加载失败」与「无可展示证书」分开（含重试）', () => {
  const dialog = code('src/components/RuleFlowDialog.vue')
  assert.match(dialog, /const certFailed = ref\(false\)/)
  const load = section(dialog, 'const loadCertInfo = ', 'const retryCertInfo')
  assert.match(load, /\.catch\(\(\) => \{/, '失败分支必须存在')
  assert.match(load, /certFailed\.value = true/, '失败不得落成「规则禁用或证书未就绪」')
  const template = section(dialog, 'v-if="target.enableTls && !isTcp"', '</template>')
  assert.match(template, /v-else-if="certFailed"/, '失败态须先于 certInfo 空态渲染')
  assert.match(template, /证书信息加载失败/)
  assert.match(template, /@click="retryCertInfo">重试/, '失败必须可重试')
  // 打开弹框重置失败位（上一会话的失败不得污染新会话）
  assert.match(section(dialog, 'const onDialogOpen = ', 'const loadCertInfo'), /certFailed\.value = false/)
})

test('大屏切窗期间标题/KPI/趋势用「已渲染帧」口径（不得用当前窗口词标注旧帧）', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  assert.match(screen, /const frameWindowHours = computed\(\(\) => stats\.value\?\.hours \?\? windowHours\.value\)/)
  assert.match(screen, /const frameTerms = computed\(\(\) => bucketTerminology\(frameWindowHours\.value\)\)/)
  assert.match(screen, /const frameBucketLabel = computed\(\(\) => frameWindowHours\.value > 24 \? 'DAILY' : 'HOURLY'\)/)
  assert.match(screen, /近 \{\{ frameTerms\.windowLabel \}\}安全态势实时监控/, '副标题须用帧口径')
  assert.match(screen, /\{\{ frameTerms\.windowLabel \}\}安全事件 · 拦截/, 'KPI 标签须用帧口径')
  assert.match(screen, /\{\{ frameTerms\.windowLabel \}\}事件趋势 <span class="en">\{\{ frameBucketLabel \}\}/, '趋势标题与桶词须同源')
  assert.match(screen, /\{\{ frameTerms\.peakLabel \}\}/)
  assert.match(screen, /\{\{ frameTerms\.countLabel \}\}/)
  // 陈旧帧仍需明说「上次结果 · 24h」
  assert.match(screen, /<em v-if="staleFrameLabel" class="ov-switch-hint" role="status">\{\{ staleFrameLabel \}\}<\/em>/)
})

test('策略向导保存中冻结表单与步骤导航（payload 组装窗口内的编辑不得被静默丢弃）', () => {
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
  const forms = [...policies.matchAll(/<el-form :model="form" label-width="100px" :disabled="([^"]+)">/g)].map((m) => m[1])
  assert.ok(forms.length >= 5, `向导表单解析失败（${forms.length}）`)
  assert.deepEqual([...new Set(forms)], ['formFrozen'], '所有步骤表单必须同门（漏一处即可在途编辑）')
  assert.match(policies, /:class="\{ 'is-clickable': stepsClickable && !saving \}"/)
  assert.match(policies, /const jumpToStep = \(step: WizardStep\): void => \{\s*if \(!stepsClickable\.value \|\| saving\.value\) return/)
  assert.match(policies, /<el-button v-if="hasPreviousStep" :disabled="saving" @click="prevStep">/)
  assert.match(policies, /<el-button v-if="hasNextStep" type="primary" :disabled="saving" @click="nextStep">/)
})

test('用户编辑弹框对初始化管理员禁用角色下拉并给出原因', () => {
  const users = code('src/views/Users.vue')
  assert.match(users, /const roleLocked = computed\(\(\) => editingSelf\.value \|\| editingUser\.value\?\.is_setup_admin === true\)/)
  assert.match(users, /<el-select v-model="form\.role" style="width: 100%" :disabled="roleLocked">/)
  assert.match(users, /系统初始化管理员不可降级/, '必须给出字段级原因（否则只有全局 400 toast）')
  assert.match(users, /role: roleLocked\.value \? undefined : form\.value\.role/, '锁定态不得把所选角色发给后端')
})

test('Keys 页 MCP 权限说明与后端能力矩阵同口径', () => {
  const keys = code('src/views/Keys.vue')
  assert.match(keys, /export_config 与 get_caddy_config 除外/, '只读 Key 的 GET 排除项必须披露')
  assert.match(keys, /validate_import 与 preview_config 要求 Key 属主为管理员/, '探测 POST 的属主角色轴必须披露')
  assert.match(keys, /需非只读 Key 且 Key 属主为管理员/, '写工具的属主角色轴必须披露')
  assert.match(keys, /lazy-balancer:\/\/docs\/ops-playbook/, '指向后端单源手册')
  // 与后端可见性单源对表：两个隐藏 GET 工具名不得漂移
  assert.match(repoCode('internal/mcpserver/tool_visibility.go'), /"export_config":\s*\{\},\s*"get_caddy_config":\s*\{\},/)
})
