import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, cssDeclarations, enclosingDecl, member, openTags, repoCode, section, stripComments, source } from './_helpers.ts'

test('当前密码错误在页面本地 toast，拦截器复用精确分类', () => {
  const profile = code('src/components/ProfileDialog.vue')
  assert.match(profile, /isCurrentPasswordRejection\('patch', '\/users\/me', error\.status, error\.message\)/)
  assert.match(profile, /authStore\.showToast\('error', error\.message\)/)
  assert.match(code('src/utils/api.ts'), /classifyAuthFailure\(/)
  // 401 分类判据单源在 utils/apiFailure（拦截器只做处置分派）
  assert.match(code('src/utils/apiFailure.ts'), /isCurrentPasswordRejection\(/)
})


test('注册弹框记录打开时节点模式，并在关闭时清空', () => {
  const text = code('src/views/settings/cluster/ClusterModeCard.vue')
  // 两处打开路径（外部注册请求 watch / 手动切换到从节点）各自绑定捕获：
  // 计数式 `length === 2` 连「两处都在同一路径」都察觉不了，位置语义只活在
  // 注释里；名册式缺一处即点名。删掉任一捕获后「首次注册 master→slave 自动
  // 关闭」永久失效，而纯函数 clusterRegistration.spec 仍全绿——这里钉的是接线。
  const captureSource = 'registrationOriginMode = props\\.status\\?\\.node_mode \\?\\? null'
  const requestWatchAt = text.indexOf('() => props.registrationRequest,')
  const requestOpenAt = text.indexOf('registrationOpen.value = true', requestWatchAt)
  assert.ok(requestWatchAt > 0 && requestOpenAt > requestWatchAt, '外部注册请求 watch 缺失')
  assert.ok(new RegExp(captureSource).test(text.slice(requestWatchAt, requestOpenAt)), '外部注册请求路径必须捕获打开时节点模式')
  const handleMode = member(text, 'const handleModeChange =')
  assert.match(handleMode, new RegExp(captureSource), '手动切换路径必须捕获打开时节点模式')
  assert.equal([...text.matchAll(new RegExp(captureSource, 'g'))].length, 2, '不得出现名册外的第三条捕获路径')
  // 关闭清空 + 捕获值参与关闭判定
  const closeWatch = section(text, 'watch(registrationOpen, (open) => {', '\n})')
  assert.match(closeWatch, /if \(!open\) \{/)
  assert.match(closeWatch, /registrationOriginMode = null/)
  assert.match(closeWatch, /form\.register_token = ''/)
  assert.match(text, /shouldCloseRegistrationDialog\(registrationOpen\.value, registrationOriginMode, status\.node_mode\)/)
})

test('OIDC 保存门与响应落地都校验当前探测快照', () => {
  const text = code('src/views/settings/OIDCSettings.vue')
  assert.match(text, /probeGuard\.isCurrent\(/)
  assert.match(text, /probe\.key !== oidcProbeKey\(currentProbeValues\(\)\)/)
})

test('流量游标使用回退检测并在 visibility 恢复时归零', () => {
  const text = code('src/views/security/ThreatScreen.vue')
  assert.match(text, /flowSince = nextFlowCursor\(flowSince, data\)/)
  // visible 恢复语义纳管在 screenLoop.onVisible（原 onVisibilityChange）。
  assert.match(section(text, 'onVisible: () => {', '\n})'), /flowSince = 0/)
  assert.match(text, /flowCursorEpoch/)
  assert.match(text, /cursorEpoch !== flowCursorEpoch/)
})

test('Dashboard 所有落地路径统一重建逐规则失败映射', () => {
  const text = code('src/views/Dashboard.vue')
  // 原断言只数 helper 调用次数 >=4——不证明「所有落地路径」，
  // 原 bug 恰是某一路径绕过 helper 直接赋值且计数仍够。改为反向断言：任何
  // ruleMetricsUnavailable 赋值都必须经 helper（绕过即红），且至少四条落地路径。
  const assignments = [...text.matchAll(/ruleMetricsUnavailable\.value = ([^\n]*)/g)]
  assert.ok(assignments.length >= 4, `指标落地路径不足: ${assignments.length}`)
  for (const assignment of assignments) {
    assert.match(assignment[1], /^buildRuleMetricsUnavailable\(/, `绕过 helper 的落地路径: ${assignment[0]}`)
  }
  assert.doesNotMatch(text, /if \(!caddyMetricsUnavailable\.value\) \{\s*ruleMetricsUnavailable/)
  // 「已落地」与「可用」分离：dashboard 未到达前不得判定采集失败；
  // 成功与失败两条落地路径都要置 landed。两处同在 fetchAllData 内，函数名册
  // 区分不了——按 then/catch 链分支绑定：置位点必须出现在两个分支各自之内
  // （纯计数连「两处都在同一分支」都察觉不了）。
  const dashboardChain = member(text, 'const fetchAllData =')
  // fetchAllData 串联多个请求（traffic 在前）：then 锚定仪表盘指标请求自身。
  const requestAt = dashboardChain.indexOf("request.get<APIResponse<DashboardMetricsResponse>>('/metrics/dashboard'")
  const thenAt = dashboardChain.indexOf('.then((res) => {', requestAt)
  const catchAt = dashboardChain.indexOf('.catch(() => {', thenAt)
  assert.ok(requestAt > 0 && thenAt > requestAt && catchAt > thenAt, '仪表盘请求 then/catch 链缺失')
  assert.ok(dashboardChain.slice(thenAt, catchAt).includes('dashboardMetricsLanded.value = true'), '成功路径必须置「已落地」')
  assert.ok(dashboardChain.slice(catchAt).includes('dashboardMetricsLanded.value = true'), '失败路径必须置「已落地」')
  assert.match(text, /dashboardMetricsLanded\.value && !caddyMetricsUnavailable\.value/,
    '/rules 重建必须用「已落地 && 可用」，避免首轮误标采集失败')
})

test('混合策略只读视图复用独立黑名单生效谓词', () => {
  // 展示口径改为「ip_acl_enabled 开启 或 内容门命中」——
  // 后端 SecurityPolicyHasIPControl 对开启 flag 即算有 AC 管控面，含信任的
  // has_ip_control 摘要标志不得用于本列（会把纯信任策略说成 ACL 生效）。
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(code('src/views/security/SecurityPolicies.vue'), /ip_acl_enabled === true \|\| hasIPACLControl\(d\) \? formatAclModeDetail\(ipLists\.value, d\) : t\('app\.security\.policies\.common\.notEnabled'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('未启用'), '未启用灰态原文必须在 zh 母本词条中')
})

test('只读态隐藏迁移入口并保留函数级守卫', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /<el-button v-if="!isReadOnly" type="warning" @click="openMigrateFromView">/)
  assert.match(section(text, 'const openMigrateDialog', 'const submitMigrate'), /if \(isReadOnly\.value\) return/)
  assert.match(section(text, 'const submitMigrate', 'const viewPolicyVisible'), /if \(isReadOnly\.value \|\| migrateSaving\.value\) return/)
})

test('关联规则与预览步骤同样补齐引用名单条目', () => {
  const watcher = section(code('src/views/security/SecurityPolicies.vue'), 'watch([currentStep, ipACLList', 'const hasContent')
  for (const step of ['IP_ACL', 'TRUST', 'BINDINGS', 'PREVIEW']) {
    assert.match(watcher, new RegExp(`WIZARD_STEP\\.${step}`))
  }
})

test('事件名称搜索命中后自动切换到策略所在 tab', () => {
  assert.match(code('src/views/security/SecurityPolicies.vue'), /activeTypeTab\.value = policyTypeOf\(matched\)/)
})

test('自动封禁卡片主体恢复配置点击入口', () => {
  assert.match(code('src/views/security/SecurityEvents.vue'), /<div\s+class="autoban-main"[^>]*@click="openAutobanConfig"/)
})

test('自动封禁卡片主体与函数入口统一受只读和节点门控', () => {
  // 剥注释视图：这些断言的对象是「守卫仍在」，注释化守卫是最常见的临时停用
  // 手段——raw 视图会让注释里的守卫继续满足断言（假绿）。
  const text = code('src/views/security/SecurityEvents.vue')
  assert.match(text, /<el-tooltip[^>]*:content="autobanConfigTooltip"[^>]*:disabled="autobanWritable"/)
  assert.match(text, /:tabindex="autobanWritable \? 0 : -1"/)
  assert.match(text, /:aria-disabled="!autobanWritable"/)
  const open = section(text, 'const openAutobanConfig', 'const saveAutobanConfig')
  assert.match(open, /if \(!autobanWritable\.value\) return/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.events\.blockedReasonLoading'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('自动封禁状态加载中，暂不可配置'), '加载中文案必须在 zh 母本词条中')
  // 函数级纵深守卫：按钮 :disabled 只是呈现层，保存/禁用直切必须各自带
  // writable 门（与 openAutobanConfig 同构）——键盘/控制台直接调用不得绕过。
  const save = section(text, 'const saveAutobanConfig', 'const autobanEnableConfirmHtml')
  assert.match(save, /if \(!autobanWritable\.value\) return/, '保存必须带函数级 autobanWritable 守卫')
  const toggle = section(text, 'const toggleAutobanEnabled', 'const ctxWafFamily = computed')
  assert.match(toggle, /!autobanWritable\.value/, '禁用直切必须带函数级 autobanWritable 守卫')
})

test('默认上游分支不得显示无启用上游', () => {
  const text = code('src/components/RuleFlowDialog.vue')
  assert.match(text, /v-else-if="pr\.upstreams === null"/)
  // i18n 后双钉:调用点钉键,zh 母本钉文案原文(任一漂移必红)
  assert.ok(code('src/locales/zh/rules.ts').includes("followMainUpstreamTag: '跟随主路由上游'"), '跟随主路由上游原文必须在 zh 母本词条中')
  assert.match(text, /t\('common\.app\.rules\.flow\.followMainUpstreamTag'\)/)
})

test('关闭向导时复位 DNS 开关与服务器', () => {
  const reset = section(code('src/views/Rules.vue'), 'const resetWizard = () =>', 'const beforeWizardClose')
  assert.match(reset, /wizardForm\.enable_dns_server = false/)
  assert.match(reset, /wizardForm\.dns_server = ''/)
})

test('大屏显性披露回填未完成与汇总陈旧', () => {
  // 原断言只钉 `?: boolean` 类型声明（类型契约由 vue-tsc 承担）。
  // 改为钉渲染接线：两个标志各自绑定独立横幅且文案区分（回填未完成 vs 汇总延迟）。
  const text = code('src/views/security/ThreatScreen.vue')
  // i18n 后双钉:调用点钉键,zh 母本钉横幅原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.threat\.backfillNotice'\)/, '回填未完成必须渲染横幅文案（不得静默）')
  assert.match(text, /t\('app\.security\.threat\.rollupStaleNotice'\)/, '汇总陈旧必须渲染独立横幅（不得与回填提示合并或静默）')
  assert.ok(code('src/locales/zh/security.ts').includes('历史统计回填尚未完成'), '回填横幅原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('统计汇总更新延迟'), '汇总陈旧原文必须在 zh 母本词条中')
  // 覆盖受限已撤销横幅（2026-11-02 用户裁定）：窗口统计来自预聚合、无数据丢失，
  // 系统静默处理不打扰用户；明细缺失属保留策略既有行为。横幅与知悉记忆一并移除。
  assert.doesNotMatch(text, /原始事件仅保留自/, '威胁大屏不得再渲染覆盖受限横幅')
  assert.doesNotMatch(text, /rawCoverageAck|raw-coverage-ack/, '知悉记忆代码须随横幅一并移除')
  // 保留的两条横幅（回填/汇总延迟）必须可关闭：关闭入口=info-note-dismiss 按钮
  // 两条横幅元素多行，elementAt 的标签截取不覆盖子内容——按条件到区块尾的窗口断言
  const backfillBlock = text.slice(text.indexOf('v-if="stats?.backfill_incomplete'), text.indexOf('rollup_stale-dismissed'))
  const rollupBlock = text.slice(text.indexOf('v-if="stats?.rollup_stale'), text.indexOf('rollup-stale-dismissed') + 40)
  assert.match(backfillBlock, /info-note-dismiss/, '回填横幅必须带可关闭入口')
  // storage 禁用环境白屏根治——读写统一走 safeSessionStorage*(同语义安全版)
  assert.match(backfillBlock, /sessionStorage|safeSessionStorage/, '回填横幅关闭记忆用 sessionStorage（会话内不重复弹出）')
  assert.match(rollupBlock, /info-note-dismiss/, '汇总延迟横幅必须带可关闭入口')
  assert.match(rollupBlock, /rollup-stale-dismissed/, '汇总延迟横幅关闭记忆用 sessionStorage')
  // 关闭入口样式契约：全局样式必须可见（描边+主题色）且横幅对齐（:has flex）
  const css = code('src/styles/main.css')
  assert.match(css, /\.info-note-bar:has\(\.info-note-dismiss\)[^}]*align-items:\s*center/, '带关闭按钮的横幅必须垂直居中对齐')
  const dismissRule = css.match(/\.info-note-bar \.info-note-dismiss \{[^}]*\}/)?.[0] ?? ''
  assert.ok(dismissRule, '关闭按钮样式必须存在于全局 main.css')
  assert.match(dismissRule, /color:/, '关闭按钮必须有可辨识文字色')
  assert.match(dismissRule, /border:\s*1px solid/, '关闭按钮必须有描边（透明下划线样式不可辨识）')
  assert.doesNotMatch(dismissRule, /text-decoration:\s*underline/, '下划线弱样式必须退役')
})

test('Vite 开发代理默认 HTTP，仅显式环境开关使用 HTTPS', () => {
  const text = code('vite.config.ts')
  // 按「臂结构」断言：条件=显式开关、默认臂（: 之后）=HTTP、开关臂（? 之后）
  // =HTTPS。不钉整段文本/缩进/换行——交换两臂或改写条件都会红，等价重构不会。
  const targetExpr = section(text, 'const devBackendTarget =', '\nexport default')
  const ternary = /const devBackendTarget\s*=\s*([\s\S]*?)\?\s*('[^']*')\s*:\s*('[^']*')\s*$/.exec(targetExpr)
  assert.ok(ternary, `devBackendTarget 必须保持三元形态（实际: ${targetExpr}）`)
  const [, condition, enabledArm, defaultArm] = ternary
  assert.match(condition, /process\.env\.VITE_DEV_BACKEND_HTTPS === '1'/, '条件必须是显式开关')
  assert.match(enabledArm, /^'https:\/\/localhost:8000'$/, '开关臂必须走 HTTPS')
  assert.match(defaultArm, /^'http:\/\/localhost:8000'$/, '默认臂必须走 HTTP')
  // 代理必须消费该表达式，且不得另写内联 target 字符串（绕过开关）
  assert.match(section(text, 'proxy: {', 'secure: false'), /target: devBackendTarget/)
  assert.doesNotMatch(text, /target:\s*'/)
})

// ---- 安全视图接线钉（可纯函数化的
//      语义在 securityLibraries / blockPageAttribution / policyPayload / triggeredFilter
//      各 spec 做行为求值，此处只钉「视图是否真的接了实现」）----

test('库计数列文案与「数量 / 大小」列义', () => {
  const text = code('src/views/security/SecurityRules.vue')
  assert.match(text, /crsRuleCountLabel\(crsInfo\.value\.rule_count\)/)
  assert.doesNotMatch(text, /个文件/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /:label="t\('common\.app\.views\.secRules\.lib\.colCountSize'\)"/)
  assert.ok(code('src/locales/zh/views.ts').includes("'数量 / 大小'"), '列头原文必须在 zh 母本词条中')
  // IP 地理库字节数带单位（formatSize）
  assert.match(text, /formatSize\(ip2regionInfo\.value\.db_size\)/)
})

test('爬虫豁免空引擎保存守卫（单源谓词）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /if \(typeAllowsStage\(1\) && crawlerExemptionNeedsEngines\(\{ geoipEnabled: form\.value\.geoip_enabled, crawlerExempt: form\.value\.geoip_crawler_exempt, engines: form\.value\.geoip_crawler_engines \}\)\)/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.policies\.msg\.crawlerNoneSelected'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('空选等于豁免「全部引擎」'), '空选豁免口径原文必须在 zh 母本词条中')
  // 空选时的行内提示（用户不必点保存才知道语义）
  assert.match(text, /v-if="form\.geoip_crawler_engines\.length === 0"/)
})

test('主列表失败可辨识（错误态 + 横幅重试 + 空态文案切换）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /const policiesLoadError = ref\(false\)/)
  assert.match(text, /v-if="policiesLoadError" type="error"/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /:loading="loading" @click="fetchData">\{\{ t\('app\.security\.policies\.common\.retryNow'\) \}\}/)
  assert.ok(code('src/locales/zh/security.ts').includes('立即重试'), '立即重试原文必须在 zh 母本词条中')
  // 空态：失败与「确实没有策略」不同形
  assert.match(text, /v-if="!policiesLoadError" :description="t\('app\.security\.policies\.list\.empty'\)"/)
  assert.ok(code('src/locales/zh/security.ts').includes('暂无安全策略'), '空态原文必须在 zh 母本词条中')
  // 两条失败路径（rejected / catch）都置错误态，成功路径复位
  const rejected = text.indexOf("if (polRes.status === 'rejected')")
  const setErr = text.indexOf('policiesLoadError.value = true', rejected)
  assert.ok(rejected > 0 && setErr > rejected, 'rejected 分支必须置错误态')
  // 成功路径：主列表按严格阶段序落值（stage0→stage3，mixed 垫底），并复位错误态
  const okPath = text.indexOf('policies.value = (polRes.value.data || [])')
  assert.ok(okPath > 0, '成功路径必须给主列表赋值')
  const reset = text.indexOf('policiesLoadError.value = false', okPath)
  assert.ok(reset > okPath, '成功路径必须复位错误态')
  assert.match(text.slice(okPath, reset), /stage3: 3, mixed: 5/, '阶段序排序必须是四阶段模型（stage0→stage3 + mixed 垫底）')
  assert.doesNotMatch(text.slice(okPath, reset), /stage4/, '旧编号 stage4 已在读入侧归一，排序表不得再留该档')
  assert.match(text.slice(okPath, reset), /localeCompare/, '同阶段必须按名称稳定排序')
})

test('自动封禁口径文案与后端喂入门同口径（四维多选，WAF 两族+挑战发放/失败，其余事件显式声明不计数）', () => {
  const events = code('src/views/security/SecurityEvents.vue')
  // 后端 autobanStage3Eligible 只收 CRS+自定义两族（爬虫豁免独立排除）——
  // 文案必须与真实喂入一致：既不得自缩为「WAF 事件」，也不得宣称 ACL/地域/
  // 威胁情报计数（用户按文案校准阈值必须可达）。
  assert.doesNotMatch(events, /WAF 事件固定窗口计数/)
  // i18n 后双钉:调用点钉键,zh 母本钉口径原文(喂入口径漂移仍必红)
  assert.match(events, /:subtitle="t\('app\.security\.events\.dialogSubtitle'\)"/)
  assert.ok(code('src/locales/zh/security.ts').includes('WAF 命中按拦截/检测计数（已验证爬虫豁免除外）'), 'WAF 计数口径句必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('人机挑战按发放/失败计数（挑战通过不计）'), '挑战计数口径句必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('IP 访问控制、地域拦截与威胁情报事件不参与计数'), '排除口径句必须在 zh 母本词条中')
  // 四维多选 checkbox（单选 radio 已退役）+ 空集校验。
  assert.match(events, /<el-checkbox-group v-model="autobanForm\.scope">/, '口径必须为多选 checkbox 组')
  assert.match(events, /autobanForm\.value\.scope\.length === 0/, '空集必须拦截保存')
  // 跨栈对表（repoCode 剥注释后钉函数体谓词）：后端族门任一谓词改动即红——
  // 文案↔裁定漂移（喂入口径扩/缩而文案不动）不再无声复发。
  const autoban = repoCode('internal/services/autoban.go')
  assert.match(
    autoban,
    /func autobanStage3Eligible\(ruleTriggered string\) bool \{\n\treturn securityEventsRuleIsCustomFamily\(ruleTriggered\) \|\| securityEventsRuleIsCRSFamily\(ruleTriggered\)\n\}/,
    '阶段门必须=自定义族∪CRS 族两谓词（文案计数集的权威来源）',
  )
  assert.match(
    autoban,
    /func autobanSourceEligible\(ruleTriggered string\) bool \{\n\treturn !securityEventsIsCrawlerExemptRule\(ruleTriggered\)\n\}/,
    '爬虫豁免必须保持独立排除条款（文案「已验证爬虫豁免除外」的权威来源）',
  )
})

test('IP 快捷弹框全流程使用 trim 后的地址（无裸 props.ip 消费）', () => {
  const text = code('src/views/security/IPLocationAction.vue')
  assert.match(text, /const trimmedIp = computed\(\(\) => props\.ip\.trim\(\)\)/)
  // 裸 props.ip 的鉴别力要求「消费点」而非「出现次数」：剥注释后除归一化
  // 读取（props.ip.trim()）外不得再有任何读取——新增合法读取/注释不再误红。
  assert.doesNotMatch(
    stripComments(text),
    /props\.ip(?!\.trim\()/,
    '地址只允许经 trimmedIp 归一后消费，禁止直接读 props.ip',
  )
  assert.match(text, /entry !== trimmedIp\.value/)
})

test('拦截页删除重入守卫（确认前占位、finally 释放）', () => {
  const text = code('src/views/security/SecurityBlockPages.vue')
  const guard = text.indexOf('if (deletingId.value !== null) return')
  const confirm = text.indexOf('ElMessageBox.confirm(')
  const release = text.indexOf('deletingId.value = null')
  assert.ok(guard > 0, '必须有重入守卫')
  assert.ok(confirm > guard, '守卫必须先于确认框（先占位再弹）')
  assert.ok(release > confirm, 'finally 必须释放占位')
  assert.match(text, /:loading="deletingId === row\.id"/)
})

test('名单详情 GET 静默，避免与全局拦截器双 toast', () => {
  const text = code('src/views/security/SecurityRules.vue')
  const silentGets = text.match(/security\/ip-lists\/\$\{[^}]+\}`, \{ silent: true \}\)/g) ?? []
  // 详情、失败重试、内置名单保存前的新鲜度核对——三处都走 silent + 本地文案
  assert.equal(silentGets.length, 3, `详情/重试/新鲜度核对三处请求都应 silent，实际 ${silentGets.length}`)
  // 本地提示保留（带「已禁用保存」动作信息）——i18n 后双钉:调用点钉键,zh 母本钉原文
  assert.match(text, /t\('common\.app\.views\.secRules\.msgs\.loadEntriesFailReload'\)/)
  assert.ok(code('src/locales/zh/views.ts').includes('加载列表条目失败，已禁用保存；请重新加载'), '失败提示原文必须在 zh 母本词条中')
})

test('库状态未知时自动更新开关显示「—」而非默认开', () => {
  const text = code('src/views/security/SecurityRules.vue')
  assert.match(text, /autoUpdateKnown: !crsInfoError\.value && crsInfoLoaded\.value/)
  assert.match(text, /autoUpdateKnown: threatLibLoaded\.value && !threatLibError\.value/)
  assert.match(text, /v-if="!row\.autoUpdateKnown"/)
  assert.match(text, /<el-switch v-else :model-value="row\.autoUpdate"/)
})

// ---- 前端展示/契约批次：单源化与首轮误标 ----
test('分页器形态收敛 main.css，四个视图不得再本地重定义', () => {
  const main = code('src/styles/main.css')
  // 选择器块内逐条匹配（不依赖单行排版：引入格式化工具不应批量假红）
  const rule = section(main, '.rules-pagination {', '}')
  assert.match(rule, /display:\s*flex/)
  assert.match(rule, /justify-content:\s*flex-end/)
  assert.match(rule, /margin-top:\s*16px/)
  for (const file of ['src/views/Rules.vue', 'src/views/security/SecurityRules.vue', 'src/views/security/SecurityPolicies.vue', 'src/views/security/SecurityBlockPages.vue']) {
    assert.doesNotMatch(code(file), /\.rules-pagination\s*\{/, `${file} 仍保留本地 .rules-pagination 定义`)
  }
})

test('自定义规则列表：条件关系独立成列、条件列加宽且长正则完整换行', () => {
  const text = code('src/views/security/SecurityRules.vue')
  // 起始锚点按属性集定位「描述」列开标签（不写死属性书写顺序）：整串 marker
  // 会在属性重排/新增属性时假红，而列结构完全没变。
  const descriptionTag = openTags(text, 'el-table-column').find((tag) =>
    /prop="description"/.test(tag) && /:label="t\('common\.app\.views\.secRules\.common\.description'\)"/.test(tag))
  assert.ok(descriptionTag !== undefined, '「描述」列开标签缺失')
  const table = section(text.slice(text.indexOf(descriptionTag)), descriptionTag, `<el-table-column :label="t('common.app.views.secRules.customTab.colAction')"`)
  // 条件关系（AND/OR）独立窄列：与条件内容同列时标签挤占文本宽度
  assert.match(table, /<el-table-column :label="t\('common\.app\.views\.secRules\.customTab\.colConditionLogic'\)" width="140" align="center">/)
  // 条件列显著加宽（原 250）并保留专用 class-name 供全局样式命中
  assert.match(table, /<el-table-column :label="t\('common\.app\.views\.secRules\.customTab\.colConditions'\)" min-width="320" class-name="rule-cond-cell">/)
  // 每条条件一个单行 chip + tooltip 全文
  assert.match(table, /<div class="cond-chip-list">/)
  assert.match(table, /<el-tooltip v-for="cond in row\.conditions" :key="`\$\{cond\.target\} \$\{cond\.header_name \?\? ''\} \$\{cond\.operator\} \$\{cond\.pattern\}`" :content="`\$\{conditionTargetLabel\(cond\.target, cond\.header_name\)\} \$\{cond\.operator\} \$\{cond\.pattern\}`"/)
  assert.match(table, /<el-tag size="small" effect="plain" class="cond-chip">/)
  // 组件侧不得再写局部覆盖（复用全局样式）
  assert.doesNotMatch(text, /:deep\(\.el-table \.cell:has\(\.el-tag\)\)/, '页级全局覆盖必须退役')
  assert.doesNotMatch(text, /\.el-table \.rule-cond-cell \.cell/, '条件列样式必须收敛到 styles/main.css')
  const global = code('src/styles/main.css')
  assert.match(global, /\.el-table \.rule-cond-cell \.cell \{ display: flex; flex: 1 1 auto; min-width: 0; \}/)
  assert.match(global, /\.cond-chip-list \{ display: flex; flex-wrap: wrap; align-items: flex-start; gap: 4px; min-width: 0; width: 100%; \}/)
  // 长正则单行省略 + 全文 tooltip 的机制：chip 内部文本不得换行
  assert.match(global, /\.cond-chip \.el-tag__content \{ display: block; min-width: 0; white-space: normal; overflow-wrap: anywhere; word-break: break-word; line-height: 1\.45; \}/)
})

test('BasicSettings 两处 radio 行回归 el-form-item（自管标签行族已退役）', () => {
  const text = code('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(text, /class="form-radio-row"/, '自管标签行标记必须退役')
  assert.doesNotMatch(text, /^\.form-radio-row/m, '自管标签行样式必须退役')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /<el-form-item :label="t\('app\.settings\.basic\.tls\.source'\)"( for="[^"]*")?>/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"source": "证书来源"'), '证书来源标签原文必须在 zh 母本词条中')
  assert.match(text, /<el-form-item :label="t\('app\.settings\.basic\.autoBackup\.frequency'\)"( for="[^"]*")?>/)
  assert.ok(code('src/locales/zh/settings.ts').includes('"frequency": "频率"'), '频率标签原文必须在 zh 母本词条中')
})

test('BasicSettings 不再局部重复定义全局 .settings-form（main.css 单源）', () => {
  const text = code('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(text, /\.settings-form \{/, 'main.css 已有同名规则，局部重定义必须退役')
})

test('SecurityBindingEditor 先声明 props/emits 再派生 computed', () => {
  const text = code('src/components/SecurityBindingEditor.vue')
  const propsIdx = text.indexOf('const props = defineProps')
  const emitIdx = text.indexOf('const emit = defineEmits')
  const subtitleIdx = text.indexOf('const bindSubtitle = computed')
  assert.ok(propsIdx > 0 && emitIdx > propsIdx, 'props/emits 声明缺失或顺序错误')
  assert.ok(subtitleIdx > emitIdx, 'bindSubtitle 必须在 props 之后声明（不得依赖 TDZ 惰性求值）')
})

test('总览总量卡片按 includes_reserved 切换口径 tooltip（重设计后仅拦截列保留）', () => {
  const text = code('src/views/security/SecurityOverview.vue')
  assert.match(text, /const todayCountTip = computed\(\(\) => overview\.value\.includes_reserved/)
  // i18n 后双钉:调用点钉键,zh 母本钉两句口径原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.overview\.status\.tipReserved'\)/)
  assert.match(text, /t\('app\.security\.overview\.status\.tipRollup'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('总量含私网/保留地址事件'), '含保留地址口径原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('与大屏同口径（分钟汇总）'), '与大屏同口径原文必须在 zh 母本词条中')
  assert.equal([...text.matchAll(/<el-tooltip :content="todayCountTip"/g)].length, 1, '重设计后仅拦截列保留口径 tooltip')
})

test('自动封禁预置名单条目数标注含已到期条目', () => {
  const text = code('src/views/security/SecurityRules.vue')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /v-if="row\.preset_autoban"[^>]*:content="t\('common\.app\.views\.secRules\.ipTab\.presetExpiryTip'\)"/, '预置名单条数须 tooltip 消歧')
  assert.ok(code('src/locales/zh/views.ts').includes('含已到期条目'), '到期条目口径原文必须在 zh 母本词条中')
})

test('useLibUpdateDialog 409 路径不得重复立即轮询', () => {
  const text = code('src/composables/useLibUpdateDialog.ts')
  assert.match(text, /const startPolling = \(\) => \{ polling\.start\(\) \}/, '起轮询只挂定时器（refreshStatus 已拉过本轮）')
  assert.doesNotMatch(text, /startPolling = \(\) => \{ polling\.resume\(\) \}/, 'resume 会立即 run，409/onOpened 路径产生重复请求')
})

test('大屏光流可用性位/恢复基线/重装复位（L8 前端三项）', () => {
  const text = code('src/views/security/ThreatScreen.vue')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)。`\|\|` 必须转义——
  // 未转义的 `||` 是正则交替,会产生可匹配空串的空分支,assert.match 恒绿。
  assert.match(text, /<div v-if="flowError \|\| attackFlowError" class="error-banner site-unset">\{\{ t\('app\.security\.threat\.flowLoadFailed'\) \}\}<\/div>/, '光流端点失败必须显性横幅')
  assert.ok(code('src/locales/zh/security.ts').includes('"flowLoadFailed": "光流数据加载失败，正在重试…"'), '光流失败横幅原文必须在 zh 母本词条中')
  assert.match(text, /interval: ATTACK_FLOW_POLL_MS, onError: \(\) => \{ attackFlowError\.value = true \}/)
  assert.match(text, /interval: 1000, onError: \(\) => \{ flowError\.value = true \}/)
  // 恢复首轮重建基线：手动暂停恢复 + 可见性恢复两处（原仅「不可用」一处）。
  // 名册式断言（每个命中反推所在函数，helper 见 _helpers.enclosingDecl）——
  // 计数式 `>= 3` 无法定位「三处中少一处」。
  const baselineSites = [...text.matchAll(/trafficBaseline = null/g)]
    .map((match) => enclosingDecl(text, match.index ?? 0))
    .sort()
  assert.deepEqual(baselineSites, ['screenLoop', 'togglePause', 'trafficTask'], '暂停恢复/可见性恢复/不可用三处都必须重建基线（名册式：缺一处即点名）')
  assert.match(member(text, 'async function mountEngine('), /zoomedName\.value = null/, '引擎重装必须复位下钻态')
})

// ============ 安全策略拦截页注记 / 阶段页覆盖写路径 / 预取面 ============

test('拦截页汇总必须过阶段能力门（stage3 off / stage1 无能力不得恒绿）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /blockPageStageCanIntercept/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.policies\.bp\.stageIneffective'/)
  assert.ok(code('src/locales/zh/security.ts').includes('当前配置不会产生该阶段拦截，页面不会被使用'), '阶段无效注记原文必须在 zh 母本词条中')
  // 能力门经 capableAttributions 单点调用（归因 + 过门同处）：
  const notes = member(text, 'const capableAttributions = (')
  assert.match(notes, /\.filter\(\(stage\) => stageCapableOf\(stage\)\)/)
  // 汇总卡消费同一能力门：未过门阶段单独出「不会产生拦截」行
  const summary = member(text, 'const blockPageSummary = computed')
  assert.match(summary, /stageCapableOf\(/)
  assert.match(summary, /t\('app\.security\.policies\.bp\.stageIneffective'/)
  // 阶段 2 例外行：挑战与封禁的内置页口径必须保留（配额限流已下线，不再宣称 429）
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(summary, /t\('app\.security\.policies\.bp\.stage2NoPage'/)
  assert.ok(code('src/locales/zh/security.ts').includes('挑战按内置挑战页返回'), '阶段 2 内置页口径原文必须在 zh 母本词条中')
  assert.doesNotMatch(summary, /规则已配置阶段页覆盖/)
})

test('规则级阶段页覆盖写路径退役：无批量端点调用与暂存状态', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  // 触发归因下规则级覆盖已退役：向导不再调 batch-block-pages，暂存/待重试
  // 状态机（stageOverride* / overrideEditOf / pendingOverrideRules）整体移除。
  assert.doesNotMatch(text, /batch-block-pages/)
  assert.doesNotMatch(text, /stageOverride|overrideEditOf|pendingOverrideRules|editableOverrideStages/)
})

test('阶段 0 预览信任名单恒启用（载荷消费侧）', () => {
  // 「computed 声明与 trustEnabledForPolicyType 同形」这条不变量只由
  // frontendWiringContracts 的文档钉持有（见该文件的「文档钉：信任侧冲突警告」
  // 用例 + 本文件末尾的重复声明门）。此处只钉载荷消费：预览/保存都读同一个
  // computed，不得各自再写一份谓词。
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /ip_whitelist_enabled: trustEnabledInEditor\.value/)
  assert.doesNotMatch(
    text,
    /ip_whitelist_enabled: trustEnabledForPolicyType\(/,
    '载荷必须读 computed 单源，不得在提交处重算谓词',
  )
})

test('掩码私钥不得误报「请提供私钥」', () => {
  const text = code('src/views/Rules.vue')
  const validate = member(text, 'const validateCertificate = async (')
  // 分支按花括号配对取段（不是「if 之后 260 字符」）：定长窗口会越过本分支进入
  // 证书格式分支，于是相邻分支的证据也被当成本分支的证据。
  const branch = member(validate, 'if (!keyPEM) {')
  const guardAt = branch.indexOf('if (wizardForm.tlsKeySet) return')
  const errorAt = branch.indexOf('certInfo.error')
  assert.ok(guardAt > 0, '掩码私钥形态必须跳过错误提示')
  assert.ok(errorAt > guardAt, '掩码私钥的 return 必须先于错误文案（顺序倒置即误报）')
  // i18n 后双钉:调用点钉键,zh 母本钉文案原文(任一漂移必红)
  assert.ok(code('src/locales/zh/rules.ts').includes("providePrivKey: '请提供私钥 (KEY)'"), '请提供私钥原文必须在 zh 母本词条中')
  assert.match(branch.slice(errorAt), /^certInfo\.error = t\('common\.app\.rules\.msgs\.providePrivKey'\)/, '非掩码形态仍须提示请提供私钥')
})

test('信任语义单源：事件详情与流程副标题共用 trustHitMode', () => {
  const trigger = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(trigger, /const trustModeText = computed\(\(\) => trustHitMode\(policy\.value\?\.policy_type, policy\.value\?\.trust_detection\)/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(trigger, /t\('common\.app\.views\.trigDetail\.trustDetectionStage0'\)/, 'stage0 保留检测=跳段+独立轻量检测事务记录')
  assert.match(trigger, /t\('common\.app\.views\.trigDetail\.trustDetectionInline'\)/, 'mixed 等其他类型=引擎内降级不跳段')
  assert.ok(code('src/locales/zh/views.ts').includes('保留检测：跳过全部安全阶段，仅由独立轻量检测事务记录（动作=检测）'), 'stage0 口径原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/views.ts').includes('保留检测：引擎内检测降级，仍逐段评估、仅记录不拦截（动作=检测）'), '降级口径原文必须在 zh 母本词条中')
  assert.doesNotMatch(trigger, /继续后续/, '旧「继续后续阶段评估」语义退场')
  assert.doesNotMatch(trigger, /policy\?\.trust_detection === true \? '保留检测/)

  const flow = code('src/components/RuleFlowDialog.vue')
  assert.match(flow, /trustHitMode\(policy\?\.policy_type, policy\?\.trust_detection\) === 'detection'/)
})

test('引擎装载失败暂停两条光流（不再每秒重复拉 backlog）', () => {
  const text = code('src/views/security/ThreatScreen.vue')
  const mount = member(text, 'async function mountEngine(')
  const fail = mount.indexOf('engineError.value = true')
  assert.ok(fail > 0)
  assert.match(mount.slice(fail), /pauseFlowStreamsForEngine\(\)/, '失败分支必须暂停光流')
  assert.match(mount, /resumeFlowStreamsForEngine\(\)/, '成功分支必须恢复光流')
  // 恢复路径按引擎状态门控（手动暂停/页面隐藏/仍失败时不恢复）
  const resume = member(text, 'function resumeFlowStreamsForEngine(')
  assert.match(resume, /if \(engineError\.value \|\| !threatMap \|\| paused\.value \|\| screenHidden\) return/)
  // 手动恢复不得绕过引擎门
  const toggle = member(text, 'function togglePause(')
  assert.doesNotMatch(toggle, /attackFlowTask\.resume\(\)/)
  assert.match(toggle, /resumeFlowStreamsForEngine\(\)/)
})

test('辅助端点部分失败必须有可见横幅', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /const auxLoadFailures = ref<string\[\]>\(\[\]\)/)
  // i18n 后双钉:调用点钉键,zh 母本钉横幅原文(任一漂移必红);条目分隔符亦走单源 sep 键
  assert.match(text, /t\('app\.security\.policies\.list\.auxFailBanner', \{ items: auxLoadFailures\.join\(t\('app\.security\.policies\.common\.sep'\)\) \}\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('部分辅助数据加载失败'), '辅助失败横幅原文必须在 zh 母本词条中')
  assert.match(text, /<el-button link type="warning"[^>]*@click="fetchData">\{\{ t\('app\.security\.policies\.common\.reload'\) \}\}<\/el-button>/)
  // i18n 后双钉:失败源标签走 aux.* 键(调用点钉键,zh 母本钉标签原文)
  const auxLabels: Array<[string, string]> = [
    ['rules', '规则列表'], ['crsOptions', 'CRS 规则选项'], ['blockPages', '拦截页面'], ['customRules', '自定义规则'],
    ['bindings', '规则绑定'], ['users', '用户列表'], ['ipLists', 'IP 地址列表'],
  ]
  for (const [key, label] of auxLabels) {
    assert.ok(text.includes(`failures.push(t('app.security.policies.aux.${key}'))`), `必须归集 ${label} 失败源`)
    assert.ok(code('src/locales/zh/security.ts').includes(label), `${label} 失败源标签必须在 zh 母本词条中`)
  }
})

test('策略顺序区域规则名独占宽度：域名不占行，超长省略且悬浮显示完整名+域名', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  assert.doesNotMatch(page, /bound-rule-meta/, '绑定行不得再展示域名占宽')
  assert.match(page, /class="bound-rule-name" :title="boundRuleTitle\(row\)"/, '规则名悬浮必须带完整信息')
  assert.match(page, /const boundRuleTitle = \(row: BoundRuleRow\): string =>[\s\S]{0,120}row\.name[\s\S]{0,80}row\.domain/, '悬浮内容包含规则名与域名')
  assert.match(page, /\.bound-rule-name \{[^}]*flex: 1;[^}]*text-overflow: ellipsis;/, '规则名让宽并省略')
})

test('CC 卡片维持同行等高，内容纵向填充不改变卡片尺寸', () => {
  const overview = code('src/views/security/SecurityOverview.vue')
  assert.match(overview, /\.events-row \.el-card \{ height: 100%; \}/, '同行卡片必须继续等高')
  assert.match(overview, /class="cc-card"/, 'CC 卡片使用独立弹性布局类')
  assert.match(overview, /\.cc-card :deep\(\.el-card__body\) \{ flex: 1;/, '内容区纵向撑满等高卡片')
  assert.match(overview, /\.cc-donut \{ position: relative; width: 136px; height: 136px;/, '图表放大填充空间')
  assert.doesNotMatch(overview, /cc-kpi/, '通过/失败不再同时出现在指标格与图例（去重）')
  assert.match(overview, /class="cc-dist-head"/, '结果区有标题与总数，填充底部空间')
})

test('阶段 2 复用拦截页步骤：挑战页选择与页面内滑块/JS 组件（CC 封禁响应已退役）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.doesNotMatch(text, /noPageStage2|noPageRateLimit|rateLimitFacet/)
  assert.match(text, /steps\.push\(WIZARD_STEP\.BLOCK_PAGE\)/, '阶段 2 必须包含拦截页步骤')
  assert.doesNotMatch(text, /v-model="form\.cc_response"/, 'CC 响应方式单选已退役（封禁由自动封禁管线承载）')
  assert.doesNotMatch(text, /ccResponseLabel/, '响应方式标签已退役')
  assert.match(text, /challengePageTip/, '挑战页需说明验证组件占位符')
  assert.match(text, /<el-form-item :label="t\('app\.security\.policies\.bp\.pageLabel'\)">/, '挑战页选择器')
  assert.match(text, /<div class="form-tip-line">\{\{ t\('app\.security\.policies\.human\.ccEnabledTip'\) \}\}<\/div>/, 'CC 说明使用换行描述样式')
  assert.doesNotMatch(code('src/locales/zh/security.ts'), /\{\{human_verify_widget\}\}/, 'i18n 文案不得内嵌双花括号：vue-i18n 渲染会抛错并吞掉页面选择器')
  assert.match(text, /v-text="challengePagePlaceholder"/, '占位符用 v-text 原样展示（单源 computed）')
  assert.match(text, /human_verify_type === 'js' \? '\{\{human_js_widget\}\}' : '\{\{human_verify_widget\}\}'/, '占位符按验证方式分流：JS→{{human_js_widget}}，滑块→{{human_verify_widget}}')
  assert.match(text, /challengePageMissingWidget/, '选择页面后必须校验当前验证方式的组件占位符')
  assert.match(text, /challengePageNeedsWidget/, '缺占位符必须有明确提示并阻断保存')
  const editor = code('src/views/security/SecurityBlockPages.vue')
  assert.match(editor, /insertHumanWidget/, '拦截页编辑器保留插入滑块验证组件')
  assert.match(editor, /insertJsWidget/, '拦截页编辑器提供插入 JS 验证组件')
})

test('安全规则预设项可键盘操作（折叠头 button + 标签/模板键盘语义）', () => {
  const text = code('src/views/security/SecurityRules.vue')
  assert.match(text, /<button type="button" class="preset-header" :aria-expanded="!uaCollapsed\[idx\]"/)
  assert.match(text, /<button type="button" class="preset-header" :aria-expanded="!regexCollapsed\[idx\]"/)
  assert.match(text, /class="preset-tag" role="button" tabindex="0" @click="cond\.pattern = t\.value" @keydown\.enter\.prevent="activateOnce\(\$event, \(\) => \{ cond\.pattern = t\.value \}\)" @keydown\.space\.prevent="activateOnce\(\$event, \(\) => \{ cond\.pattern = t\.value \}\)"/, '快捷标签长按不得按重复率反复写入')
  // 预设按钮按「同一个开标签的属性集」判定：属性书写顺序与新增属性都不影响，
  // 而距离窗口（`[\s\S]{0,120}`）在加一个属性时就会假红。
  const presetButton = openTags(text, 'el-button').find((tag) => tag.includes('v-for="p in REGEX_PRESETS"'))
  assert.ok(presetButton !== undefined, 'REGEX_PRESETS 必须逐个渲染为 el-button')
  assert.match(presetButton, /\bclass="regex-preset-link"/, '预设按钮必须复用 regex-preset-link 样式')
  // 焦点环：三个可键盘操作的控件共用同一条规则——选择器逐个列名，声明按属性集比对
  // （不钉选择器书写顺序与单行排版）。
  const focusSelectors = section(text, '.preset-header:focus-visible,', '.regex-preset-link:focus-visible')
  for (const selector of ['.preset-header:focus-visible', '.preset-tag:focus-visible']) {
    assert.ok(focusSelectors.includes(selector), `焦点规则必须覆盖 ${selector}（键盘用户看不到焦点位置）`)
  }
  assert.equal(cssDeclarations(text, '.regex-preset-link:focus-visible').get('outline'), '2px solid #409eff')
})

test('两引擎共享国家点阵空间网格', () => {
  const shared = code('src/utils/threatShared.ts')
  assert.match(shared, /export const countryGridCell = /)
  assert.match(shared, /export function buildCountryCellGrid\(/)
  // 网格构建收敛为懒初始化单例（threatCountryGrid）：两引擎每实例各建一份
  // 是同一份国界的重复扫描；单例同时供相机高度取 bbox（flyAltitudeFor）。
  assert.match(shared, /export function threatCountryGrid\(/)
  assert.match(shared, /threatCountryGridCache \?\?= buildCountryCellGrid\(THREAT_COUNTRIES\)/)
  for (const file of ['src/utils/threatScene.ts', 'src/utils/threatGlobe.ts']) {
    const text = code(file)
    assert.match(text, /threatCountryGrid\(\)/, `${file} 必须走共享网格单例`)
    assert.doesNotMatch(text, /buildCountryCellGrid\(/, `${file} 不得自建第二份网格`)
    assert.match(text, /\.get\(countryGridCell\(lon, lat\)\) \?\? \[\]/, `${file} 候选必须按共享网格单元取`)
    assert.doesNotMatch(text, /for \(let ci = 0; ci < THREAT_COUNTRIES\.length; ci\+\+\) \{\n\s+const b = /, `${file} 不得逐点全表扫描`)
  }
})

test('触发详情按类别/动作收敛预取面（WAF 拦截不下载 ACL 条目）', () => {
  const text = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(text, /const needExemption = row\.action !== 'blocked'/)
  assert.match(text, /const needAclEntries = kind\.value === 'acl' \|\| kind\.value === 'geo' \|\| kind\.value === 'threat'/)
  assert.match(text, /needExemption\s*\n?\s*\? request\.get<APIResponse<PolicyRow\[\]>>\('\/security\/policies\?enabled=true'/)
  assert.match(text, /eventDetailRefIds\(policy\.value, enabledPolicies\.value, \{/)
  assert.match(text, /ownerAcl: needAclEntries/)
  assert.match(text, /otherTrust: needExemption/)
})

test('明细失败位脱离展开区且按钮恒可见（可按类别重试）', () => {
  const text = code('src/components/RuleFlowDialog.vue')
  // 名册式：阶段 0 面板与阶段 1/2/3 面板各自必须齐备失败位/重试入口/解耦按钮
  // （计数式 `>= 2` 无法定位「两处中少一处」）。面板边界由 HTML 注释标记，
  // 先在 raw 视图切片，再剥注释做代码断言。
  const raw = source('src/components/RuleFlowDialog.vue')
  const stageZero = stripComments(section(raw, '<!-- 阶段 0 · 信任名单面板 -->', '<!-- 阶段 1/2/3 面板 -->'))
  const rawPanelsStart = raw.indexOf('<!-- 阶段 1/2/3 面板 -->')
  assert.ok(rawPanelsStart >= 0, '阶段 1/2/3 面板 marker 缺失')
  const stagePanels = stripComments(raw.slice(rawPanelsStart))
  for (const [label, panel] of [['阶段 0', stageZero], ['阶段 1/2/3', stagePanels]] as const) {
    assert.match(panel, /v-if="detailFailedSources\.length > 0" class="flow-detail-line"/, `${label} 失败位必须在面板级`)
    assert.match(panel, /@click="ensureDetails\(true\)"/, `${label} 必须有重试入口`)
    assert.match(panel, /groupHasDetails\(group\) \|\| detailFailedSources\.length > 0/, `${label} 按钮可见性与明细存在性必须解耦`)
  }
  // force 重试同样突破已附着锁
  assert.match(member(text, 'const ensureDetails = async ('), /if \(detailsAttached\.value && !force\) return/)
  // 全源失败分支保留失败位（按 if 块配对取段，不是「锚点 + 260 字符」——窗口
  // 会越出本分支，把紧随其后的成功分支赋值也算进来）。
  const allFailed = member(text, "if (policyRes.status === 'rejected' && customRes.status === 'rejected'")
  assert.match(allFailed, /detailFailedSources\.value = failedSources/, '全源失败必须保留失败位（面板级说明与重试按钮据此可见）')
  assert.match(allFailed, /return/, '全源失败必须提前返回')
  assert.doesNotMatch(allFailed, /detailsAttached\.value = true/, '全源失败不得置已附着（弹框会被锁死且不可重试）')
})

test('计分动作模板分支已删除（后端合法动作仅 block/log/pass）', () => {
  const all = ['src/components/events/TriggerDetailDialog.vue', 'src/views/security/SecurityEvents.vue']
  for (const file of all) {
    assert.equal(stripComments(code(file)).includes("action === 'score'"), false, `${file} 仍有不可达分支`)
  }
})

// ---- 安全域前端可观测性批次：动作门控 / 失败态 / 明细对账 / 单源谓词 ----


test('CRS 规则文件加载失败任何形态都给可见错误态（旧数据标注为上次结果）', () => {
  const text = code('src/views/security/SecurityRules.vue')
  const fetch = member(text, 'const fetchRules = async () => {')
  const catchIdx = fetch.indexOf('} catch {')
  assert.ok(catchIdx > 0, 'fetchRules 必须保留 catch 分支')
  const handler = fetch.slice(catchIdx)
  assert.match(handler, /if \(requestSeq !== rulesRequestSeq\) return/, '过期请求的失败不得污染当前态')
  assert.match(handler, /rulesLoadError\.value = true/)
  assert.doesNotMatch(handler, /rules\.value\.length === 0/, '失败不得按「已有数据」静默跳过错误态')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /rules\.length === 0 \? t\('common\.app\.views\.secRules\.rulesTab\.crsLoadFailEmpty'\) : t\('common\.app\.views\.secRules\.rulesTab\.crsLoadFailStale'\)/)
  assert.ok(code('src/locales/zh/views.ts').includes('CRS 规则文件加载失败，「暂无规则文件」不代表真实状态'), '空态口径原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/views.ts').includes('CRS 规则文件加载失败：当前显示的是上次成功结果（与分页/搜索条件不符）'), '旧数据口径原文必须在 zh 母本词条中')
})

test('大屏分级回退不含限流 429（限流不进安全事件表）', () => {
  const sev = stripComments(member(code('src/views/security/ThreatScreen.vue'), 'function sevOf('))
  assert.doesNotMatch(sev, /'429'/, '429 不进事件表，回退分支不可达')
  assert.match(sev, /zeroScoreSeverity\(ev\.rule_triggered/, '0 分行回退必须走 severityScale 单源')
  assert.doesNotMatch(sev, /\^8\\d\{5\}\$/, '回退族不得回流视图')
})

test('名单条目镜像只在缓存确有新增时重建，跨策略并集/Set 不随增删重算', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  // 根因：补齐步骤此前无条件重建镜像 → 新对象身份使全部依赖 ipListEntries 的
  // computed 失效（含 N 个启用策略 × 万级条目的并集/Set），而每次下拉增删都会
  // 触发该 watcher。镜像重建必须有条件。
  const ensure = section(text, 'const ensureIpListEntries', '\n}\n')
  const assigns = [...ensure.matchAll(/(if \(Object\.keys\(sharedEntriesCache\)\.length !== cachedBefore\) )?ipListEntries\.value = \{ \.\.\.sharedEntriesCache \}/g)]
  assert.equal(assigns.length, 1, 'ensure 内镜像赋值应只有一处')
  assert.ok(assigns[0]?.[1], '镜像重建必须以「缓存确有新增」为前提')
  assert.match(ensure, /const cachedBefore = Object\.keys\(sharedEntriesCache\)\.length/)

  // 双保险：编辑态输入不得进入 peer 视图的依赖面
  const peer = member(text, 'const peerPolicyViews = computed')
  assert.doesNotMatch(peer, /ipACLList\.value|ipWhitelist\.value|form\.value|ipBlacklistSelf/)
  assert.match(peer, /new Set\(sides\.aclAllow\)/)
  assert.match(peer, /new Set\(sides\.trust\)/)
  assert.match(peer, /new Set\(sides\.deny\)/)
})

test('安全事件列表加载失败必须有页内错误条（旧数据标注为上次结果）', () => {
  const text = code('src/views/security/SecurityEvents.vue')
  assert.match(text, /const eventsLoadError = ref\(false\)/)
  const fetch = member(text, 'const fetchEvents = async () => {')
  assert.match(fetch, /eventsLoadError\.value = false/)
  assert.match(fetch, /if \(requestSeq !== fetchEventsSeq\) return\n\s+eventsLoadError\.value = true/)
  assert.match(text, /<el-alert v-if="eventsLoadError" type="error"/)
  // i18n 后双钉:调用点钉键,zh 母本钉降级口径原文
  assert.match(text, /t\('app\.security\.events\.loadErrorStale'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('当前显示的是上次成功结果（与筛选/分页条件不符）'), '降级口径句必须在 zh 母本词条中')
})

test('WAF 耗时族谓词单源（请求上下文弹框与触发详情共用 isWafDurationFamily）', () => {
  assert.match(code('src/utils/securityStages.ts'), /export const isWafDurationFamily = \(family: TriggerStageFamily\): boolean =>/)
  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /isWafDurationFamily\(triggerStageFamily\(ctxEvent\.value\?\.rule_triggered \?\? ''\)\)/)
  const trigger = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(trigger, /isWafDurationFamily\(triggerStageFamily\(props\.row\?\.rule_triggered \?\? ''\)\)/)
  for (const [name, text] of [['SecurityEvents', events], ['TriggerDetailDialog', trigger]] as const) {
    assert.doesNotMatch(text, /\['wafCrs', 'wafCustom', 'body'\]|\['waf-crs', 'waf-custom', 'body'\]/, `${name} 仍各自硬编码 WAF 耗时族`)
  }
})

test('CRS 源码片段定位单源在 securityStages（本地子串匹配实现退役）', () => {
  assert.match(code('src/utils/securityStages.ts'), /export const extractCrsRuleSnippet = /)
  const trigger = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(trigger, /extractCrsRuleSnippet\(res\.data\?\.content \|\| '', ev\.rule_triggered\)/)
  assert.doesNotMatch(trigger, /const extractRuleSnippet = /)
})

// ---- L4 阶段0/1 前端接线批次：TCP 锁同构 / 流程弹框 TCP 渲染 / 事件徽标 / 大屏图例 ----

test('TCP 锁与 HTTP 同构：灰 placeholder 退役，阶段 2/3 恒「不适用」', () => {
  const rules = code('src/views/Rules.vue')
  // 锁 popover 不再按协议分叉：TCP 与 HTTP 共用同一 popover（v-if 分支移除）
  assert.doesNotMatch(rules, /v-if="row\.protocol === 'http'"/)
  // 灰色 placeholder 锁与「不支持」tooltip 退役（含 --tcp 修饰类）
  assert.doesNotMatch(rules, /TCP 规则不支持安全策略/)
  assert.doesNotMatch(rules, /acl-lock-icon--tcp/)
  // 锁色三态（未绑/禁用=黄 is-unbound，已绑=绿 is-allow）对 TCP 与 HTTP 同一表达式
  assert.match(rules, /ruleDisabled \? 'is-unbound' : ruleStageModel\(row as Rule\)\.hasAnyPolicy \? 'is-allow' : 'is-unbound'/)
  // TCP 规则阶段 2/3 恒灰态文案（组有无均不落「未启用」分支）
  // i18n 后双钉:调用点钉键,zh 母本钉文案原文(任一漂移必红)
  assert.ok(code('src/locales/zh/rules.ts').includes("stageNotApplicable: '不适用（TCP 仅支持阶段 0/1）'"), '不适用灰态原文必须在 zh 母本词条中')
  assert.match(rules, /t\('common\.app\.rules\.list\.stageNotApplicable'\)/)
})

test('规则行「安全」绑定入口与流程弹框对 TCP 放开', () => {
  const rules = code('src/views/Rules.vue')
  // 绑定按钮禁用条件不再含 TCP（含 2/3 特征策略的拒绝由后端 400 + 编辑器置灰承接）
  assert.doesNotMatch(rules, /:disabled="row\.protocol === 'tcp'/)
  assert.doesNotMatch(rules, /TCP 规则不经过安全链/)
  // 流程弹框模型不再按协议置空
  assert.match(rules, /flowDialogModel\.value = ruleStageModel\(rule\)/)
})

test('流程弹框 TCP：协议徽标、阶段 0/1 明细、阶段 2/3 整组灰态', () => {
  const dialog = code('src/components/RuleFlowDialog.vue')
  // 标题旁协议徽标：TCP 青（全局 proto-tcp-tag），HTTP 蓝（el-tag primary）
  assert.match(dialog, /proto-tcp-tag/)
  assert.match(dialog, /<el-tag v-else[^>]*type="primary"/)
  // 阶段 0 标注信任双模式语义（直通=零事件；保留检测=记录为检测后直达上游，
  // 与 HTTP 一致）、阶段 1 拒绝动作=断连、阶段 2/3 整组灰态
  // i18n 后双钉:调用点钉键,zh 母本钉文案原文(任一漂移必红)
  const zhLexicon = code('src/locales/zh/rules.ts')
  assert.match(dialog, /t\('common\.app\.rules\.flow\.trustModeTcpNote'\)/)
  const tcpNoteLine = zhLexicon.split('\n').find((l) => l.includes('trustModeTcpNote:'))
  assert.ok(tcpNoteLine, 'trustModeTcpNote 必须在 zh 母本词条中')
  assert.match(tcpNoteLine!, /「直通上游」模式：连接直达上游/)
  assert.match(tcpNoteLine!, /「保留检测记录」模式：命中产检测事件[^]*后直达上游，不拦截/)
  assert.match(dialog, /TCP_STAGE1_FOOTNOTE = t\('common\.app\.rules\.flow\.tcpStage1Footnote'\)/)
  assert.ok(zhLexicon.includes('拒绝动作=断连'), '阶段 1 断连口径必须在 zh 母本词条中')
  assert.match(dialog, /t\('common\.app\.rules\.flow\.tcpStagesNote'\)/)
  assert.ok(zhLexicon.includes('TCP 规则不适用'), '阶段 2/3 灰态原文必须在 zh 母本词条中')
})

test('事件日志 TCP：类型筛选 + 青色徽标 + 详情弹框 TCP 形态', () => {
  const events = code('src/views/security/SecurityEvents.vue')
  // 类型筛选加 TCP（HTTP=waf 口径），筛选值透传 event_type 查询参数
  assert.match(events, /<el-option label="TCP" value="tcp" \/>/)
  assert.match(events, /<el-option label="HTTP" value="waf" \/>/)
  assert.match(events, /p\.set\('event_type', filters\.value\.event_type\)/)
  // TCP 事件行青色徽标
  assert.match(events, /proto-tcp-tag/)
  // 详情弹框：空 method/uri 显示 TCP 连接占位、隐藏请求头/请求体区块
  assert.match(events, /t\('app\.security\.events\.tcpPlaceholder'\)/)
  const ctx = section(events, 'const ctxEvent = ref<SecurityEvent', 'const page = ref(1)')
  assert.match(ctx, /ctxIsTcp/)
})

test('安全总览 TCP：今日拦截协议双胶囊 + 最近事件独立协议列', () => {
  const overview = code('src/views/security/SecurityOverview.vue')
  // 拆分行消费 today_blocked_tcp，响应缺字段（旧后端）整行隐藏；双胶囊形态
  assert.match(overview, /today_blocked_tcp/)
  assert.match(overview, /proto-split-label">HTTP<\/span><span class="strip-sub-num">/)
  assert.match(overview, /proto-split-label">TCP<\/span><span class="strip-sub-num">/)
  // 最近拦截事件：独立「协议」列（TCP 青 / HTTP 蓝），规则列不再放徽标
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(overview, /:label="t\('app\.security\.overview\.events\.colProtocol'\)"/)
  assert.ok(code('src/locales/zh/security.ts').includes('协议'), '协议列名原文必须在 zh 母本词条中')
  assert.match(overview, /proto-tcp-tag event-proto-tag">TCP<\/el-tag>/)
  const ruleColumn = section(overview, ':label="t(\'app.security.overview.events.colRule\')"', ':label="t(\'app.security.overview.events.colPolicy\')"')
  assert.doesNotMatch(ruleColumn, /proto-tcp-tag/, '规则列只剩规则名')
})

test('威胁大屏 TCP：l4 差分并入正常弧 + feed 徽标 + 底部图例「TCP 断连」', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  // l4 键差分（后端已差分）并入 setTraffic 正常弧通道（两种采样模式都覆盖）
  assert.match(screen, /l4TrafficDelta\(/)
  assert.match(screen, /setTraffic\(/)
  // feed 事件 event_type==='tcp' 青色徽标
  assert.match(screen, /event_type === 'tcp'/)
  // 底部流量图例新增「TCP 断连」条目
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(screen, /t\('app\.security\.threat\.tcpDisconnected'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('TCP 断连'), 'TCP 断连图例原文必须在 zh 母本词条中')
})

test('TCP 绑定门谓词与文案单源（securityStages）', () => {
  const stages = code('src/utils/securityStages.ts')
  assert.match(stages, /export const policySupportsTcp = /)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(stages, /export const TCP_BIND_UNSUPPORTED_REASON = t\('common\.app\.views\.stages\.tcpUnsupportedReason'\)/)
  assert.ok(code('src/locales/zh/views.ts').includes('该策略含 TCP 不支持的能力（CC 防护/WAF）'), 'TCP 绑定门文案原文必须在 zh 母本词条中')
  // 两个绑定入口共用谓词，不得各写第二份
  assert.match(code('src/components/SecurityBindingEditor.vue'), /policySupportsTcp/)
  assert.match(code('src/views/security/SecurityPolicies.vue'), /policySupportsTcp/)
  // 编辑器规则侧：TCP 规则的阶段 2/3 分区置灰 + 行内提示（文案走单源常量）
  const editor = code('src/components/SecurityBindingEditor.vue')
  assert.match(editor, /TCP_BIND_UNSUPPORTED_REASON/)
  // 策略向导选择器放开 TCP（不再只列 HTTP）
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.doesNotMatch(policies, /选择器只列 HTTP/)
  // 向导关联规则步骤 TCP 行内标注
  // i18n 后双钉:调用点钉键,zh 母本钉原文(security.ts 为 zh/en 合并词条,原文在 "zh" 行)
  assert.match(policies, /infoHints\.push\(t\('app\.security\.policies\.bind\.tcpHint'\)\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('拦截=断连，无拦截页；CDN 回源需开启 PROXY protocol'), 'TCP 行内标注原文必须在 zh 母本词条中')
})
