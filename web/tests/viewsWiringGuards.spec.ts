// 视图/设置/安全页源码接线守卫：每条对应一个已修行为缺陷的回归断言，关键点用
// 限段（section，缺 marker 即抛错）或带边界的断言，避免跨全文空转。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, openTags, section, repoCode } from './_helpers.ts'
import { shouldToastQuietPollError } from '../src/utils/pollErrorToast.ts'
import {
  CERT_QUEUE_VISIBLE_JOBS,
  certQueueHasLive,
  certQueueIsBusy,
  certQueueMoreCount,
} from '../src/utils/certQueue.ts'
import { credentialFieldVisible, credentialOptionLabel, defaultCredentialsFor } from '../src/utils/dnsProviderFields.ts'

// 「占位先于确认」判据：先证占位赋值存在，再证顺序。
// 只比 indexOf 大小会空转——左操作数缺失时 -1 < 正值 恒真，恰恰放过「双击叠出
// 两个确认框」这条要防的回归；占位变量改名后旧 token 也会静默失效。
const assertPlaceholderBeforeConfirm = (block: string, placeholder: string, where: string): void => {
  const placeholderAt = block.indexOf(placeholder)
  assert.ok(placeholderAt >= 0, `${where}：确认前占位「${placeholder}」不存在（缺失时顺序断言会假绿）`)
  const confirmAt = block.indexOf('confirmAction(')
  assert.ok(confirmAt >= 0, `${where}：本段未调用 confirmAction`)
  assert.ok(placeholderAt < confirmAt, `${where}：占位必须先于 confirmAction`)
}

test('自定义规则编辑深拷贝条件行（取消/保存失败不得污染列表行）', () => {
  const body = section(code('src/views/security/SecurityRules.vue'), 'const openRuleDialog', 'const saveCustomRule')
  assert.match(body, /row\.conditions\.map\(\(c\) => \(\{ \.\.\.c \}\)\)/)
  assert.doesNotMatch(body, /\[\.\.\.row\.conditions\]/, '浅拷贝数组会让弹框 v-model 直接改写列表行对象')
})

test('自动备份 quiet 轮询失败不逐轮弹 toast', () => {
  // 原断言 /if \(!quiet\) \{[\s\S]*?ElMessage\.error/ 从 loading 门
  // 开始惰性匹配，命中的是 **quiet 分支自身**的节流 toast——删掉非 quiet 提示、或
  // 让 quiet 分支每轮无条件弹窗（本条要防的 30 条/60s 刷屏回归）仍然通过。
  // 改为对抽取出的判定做行为断言（单源 src/utils/pollErrorToast.ts）：
  assert.equal(shouldToastQuietPollError(true, 60_000, 0), false, 'quiet 且已加载成功：静默（保存仍可用）')
  assert.equal(shouldToastQuietPollError(false, 100_000, 0), true, 'quiet 且从未加载成功：提示一次')
  assert.equal(shouldToastQuietPollError(false, 100_000 + 29_999, 100_000), false, '窗口内不得重复提示（刷屏回归）')
  assert.equal(shouldToastQuietPollError(false, 100_000 + 30_001, 100_000), true, '窗口过后可再提示一次')
  // 生产接线：quiet 分支先过节流判定；非 quiet 失败由当前读取会话的 onError 披露。
  const body = section(code('src/views/settings/BasicSettings.vue'), 'const fetchAutoBackup', 'const onAutoBackupOpened')
  const catchAt = body.indexOf('} catch {')
  assert.ok(catchAt > 0, '缺 quiet catch 分支')
  const catchBody = body.slice(catchAt)
  const guardAt = catchBody.indexOf('shouldToastQuietPollError(autoBackupLoaded.value, now, lastAutoBackupErrorToastAt)')
  const quietToastAt = catchBody.indexOf('ElMessage.error')
  assert.ok(guardAt > 0, 'quiet 分支必须经节流判定')
  assert.ok(quietToastAt > guardAt, 'quiet 分支的 toast 必须在节流判定之后')
  assert.match(body, /onError: \(\) => \{[\s\S]*?ElMessage\.error\('自动备份设置读取失败，请关闭弹框后重试；读取完成前无法保存'\)/, '非 quiet 失败必须提示')
})

test('健康轮询接入退避门，不可达 onError 已删除', () => {
  const body = section(code('src/views/Rules.vue'), 'const healthPolling = usePollingTask', 'const healthPollingErrorDescription')
  assert.match(body, /healthPollingError\.canRun\(\)/)
  assert.doesNotMatch(body, /onError/, 'fetchHealthStatus 内部捕获不抛出——onError 是不可达死代码')
})

test('证书队列拉取接入轮询 AbortSignal', () => {
  const text = code('src/views/settings/TaskMonitor.vue')
  assert.match(text, /const fetchCertQueue = async \(signal\?: AbortSignal\)/)
  assert.match(text, /fetchCertQueue\(signal\)/)
})

test('任务详情历史与日志加载失败显性化', () => {
  const text = code('src/views/settings/TaskMonitor.vue')
  // 消费点：失败态必须真的渲染出来（原断言只查符号出现——删掉模板分支仍绿）
  // 按开标签属性集逐属性判定（openTags），不把两个属性写进同一条正则的书写
  // 顺序：模板调整属性顺序是纯格式化，界面不变，不得假红。
  const historyAlerts = openTags(text, 'el-alert').filter((tag) => tag.includes('v-if="detailHistoryError"'))
  assert.equal(historyAlerts.length, 1, '运行历史失败分支必须渲染且仅渲染一处 el-alert')
  assert.match(historyAlerts[0]!, /type="error"/, '运行历史失败必须是 error 级告警')
  assert.match(historyAlerts[0]!, /title="运行历史加载失败/, '运行历史失败必须带标题（只留图标不成告警）')
  assert.match(text, /<span v-if="logsLoadError"[^>]*>日志加载失败，自动重试中<\/span>/)
  // 置位路径：详情历史只在最新详情序号下置位，日志失败由轮询 onError 置位
  const detail = section(text, 'const openDetail', 'const logsVisible = ref')
  assert.match(detail, /if \(seq === detailSeq\) detailHistoryError\.value = true/)
  const tail = section(text, 'const logsLoadError = ref(false)', 'const openLogs')
  assert.match(tail, /onError: \(\) => \{ logsLoadError\.value = true \}/)
  assert.match(tail, /logsLoadError\.value = false/, '成功响应必须清除错误态')
  assert.doesNotMatch(detail, /\} catch \{\s*\}/, '详情历史失败不得空 catch')
})

test('规则向导关闭即清空私钥/证书明文', () => {
  const body = section(code('src/views/Rules.vue'), 'const resetWizard = () =>', 'const beforeWizardClose')
  assert.match(body, /wizardForm\.tls_cert = ''/)
  assert.match(body, /wizardForm\.tls_key = ''/)
})

test('库健康标签的加载态由视图接线（三态语义由 securityLibraries 行为用例承担）', () => {
  const page = code('src/views/security/SecurityRules.vue')
  assert.match(page, /loaded: crsInfoLoaded\.value/)
  assert.match(page, /loaded: ip2regionInfoLoaded\.value/)
})

test('死导出 ADAPTIVE_SAMPLE_TIERS 已移除', () => {
  assert.doesNotMatch(code('src/utils/threatFlowRules.ts'), /ADAPTIVE_SAMPLE_TIERS/)
})

test('更新者名称四处复用收敛为 utils/updaterName 单源', () => {
  for (const file of [
    'src/views/Rules.vue',
    'src/views/security/SecurityRules.vue',
    'src/views/security/SecurityBlockPages.vue',
    'src/views/security/SecurityPolicies.vue',
  ]) {
    const text = code(file)
    assert.ok(text.includes("from '@/utils/updaterName'"), `${file} 必须消费单源`)
    // 钉调用点（而非 import）：删掉调用只留 import 仍须失败
    assert.match(
      text,
      /const getUpdaterName = \(userId\?: number\) => updaterName\(users\.value, userId\)/,
      `${file} 更新者显示名必须经 utils/updaterName 求值`,
    )
    // 不得回退到内联「display_name || username」第二实现
    assert.doesNotMatch(text, /const getUpdaterName = [^\n]*display_name/, `${file} 不得内联更新者兜底逻辑`)
  }
})

test('日志尾轮询五处收敛为 useLogTailPolling', () => {
  for (const file of [
    'src/views/Rules.vue',
    'src/views/settings/CertJobs.vue',
    'src/views/settings/TaskMonitor.vue',
    'src/views/settings/BasicSettings.vue',
    'src/views/settings/CaddyGlobalSettings.vue',
  ]) {
    // 钉实际调用形态（`useLogTailPolling({`），仅在注释提及不算消费
    assert.match(code(file), /useLogTailPolling\(\{/, `${file} 必须调用共享 composable`)
  }
  // TaskMonitor 原缺 hidden 暂停——收敛后由 composable 统一保证
  assert.match(code('src/composables/useLogTailPolling.ts'), /document\.hidden/)
})

test('DNS 凭证测试按掩码回传分流（***→库中原值 :id/test）', () => {
  // 原断言匹配注释文本「非 UI 客户端」——注释保留而分流逻辑
  // 被删/改向也通过。改为钉分流语义：只有表单凭证含 *** 时打 :id/test（验证库中
  // 存量），用户实际改过凭证（无 ***）走无 id 的 /test。
  const page = code('src/views/settings/FreeCertificates.vue')
  const block = section(page, 'const hasMaskedCred', 'await request.post(url')
  assert.match(block, /v === '\*\*\*'/, '掩码判定必须是凭证值为 ***')
  assert.match(block, /targetId && hasMaskedCred/, '仅在「编辑既有 + 掩码回传」时走库中原值')
  assert.match(block, /`\/certificate-configs\/\$\{targetId\}\/test`/)
  assert.match(block, /:\s*'\/certificate-configs\/test'/)
})

test('管理 TLS 读取失败显性化，开关禁用至加载成功', () => {
  const text = code('src/views/settings/BasicSettings.vue')
  // 冻结门（只读 ∪ 保存中）必须与加载门并联——只读门不得让「保存中」漏出去
  assert.match(text, /:disabled="formFrozen \|\| !adminTlsLoaded"/)
  assert.match(text, /const formFrozen = computed\(\(\) => isReadOnly\.value \|\| saving\.value\)/)
})

test('Caddy 全局配置卡接入 configLoaded 双重门控', () => {
  const card = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /defineProps<\{ configLoaded: boolean \}>/)
  assert.match(card, /:disabled="isReadOnly \|\| !props\.configLoaded"/)
  const save = section(card, 'const handleSave = async', 'if (isReadOnly.value || saving.value) return')
  assert.match(save, /!props\.configLoaded/, 'configLoaded 门必须早于常规写守卫')
  const page = code('src/views/Settings.vue')
  assert.match(page, /<CaddyGlobalSettings[\s\S]*?:config-loaded="configLoaded"/)
})

test('任一 /config 成功读取恢复 configLoaded，失败可重试', () => {
  const text = code('src/views/Settings.vue')
  const block = section(text, 'const refreshConfigSection', 'const handleSaveBasic')
  assert.match(block, /configLoaded\.value = true/, '卡片保存后刷新成功必须恢复保存门')
  assert.match(text, /configLoadFailed/)
})

test('policy_id=0 展示「无策略归属」而非「策略已删除」', () => {
  const text = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(text, /本次事件无策略归属/)
  // 无策略归属态由 policy_id<=0 判定（后端 securityevents.go 返回 (0, "")）
  assert.match(text, /const noPolicyAttribution = computed\(\(\) => \(props\.row\?\.policy_id \?\? 0\) <= 0\)/)
  // 原实现用「首个 } else { + 下一处 policyMissing」推段——
  // 若 policyMissing 首次出现在段外则 indexOf 得 -1、切片为空，断言空转。
  // 改为语义断言：loadAll 内「策略已删除」的每处赋值都必须落在 policy_id>0 分支，
  // 无策略归属分支（} else { 之后）不得出现任何归因赋值。
  const body = section(text, 'const loadAll', '\nconst ')
  const attributionIf = body.indexOf('row.policy_id > 0')
  const attributionElse = body.indexOf('} else {', attributionIf)
  assert.ok(attributionIf > 0 && attributionElse > attributionIf, '缺 policy_id>0 / else 分支')
  const assignments = [...body.matchAll(/policyMissing\.value = true/g)]
  assert.ok(assignments.length >= 1, '策略拉取失败/缺失必须归因（否则「策略已删除」状态失效）')
  for (const assignment of assignments) {
    assert.ok((assignment.index ?? 0) < attributionElse, 'policy_id<=0 分支不得归因为策略已删除')
  }
})

test('威胁地图 canvas 注册/注销 pointerleave 清理悬停态', () => {
  const text = code('src/utils/threatScene.ts')
  assert.match(text, /addEventListener\('pointerleave', onPointerLeave\)/)
  assert.match(text, /removeEventListener\('pointerleave', onPointerLeave\)/)
  assert.match(section(text, 'function onPointerLeave', '\n  }'), /hoverName = null/, '离开画布必须复位悬停名')
})

// 悬停高亮的世界路径缓存不变量归 threatHotPathCaching.spec（变换/裁剪/等价性更强
// 口径）与 threatEngineParity.spec（构建一次）；此处不重复断言。

test('指标采集失败时规则表空态报「采集失败」', () => {
  assert.match(section(code('src/views/Dashboard.vue'), 'const rulesEmptyText', 'const hasRuleRequests'), /caddyMetricsUnavailable/)
})

test('区域树加载失败保留旧数据并显性提示+重试', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  const fetchRegions = section(text, 'const fetchRegions', 'onMounted')
  assert.doesNotMatch(section(fetchRegions, '} catch {', '}'), /regionTree\.value\s*=/, '失败不得清空区域树')
  const failed = section(text, '<div v-if="regionsError"', '</div>')
  assert.match(failed, /@click="fetchRegions"/, '失败提示必须保留重试入口')
})

test('事件页刷新按钮联动自动封禁状态', () => {
  const text = code('src/views/security/SecurityEvents.vue')
  // 函数级限段：固定字符窗口会被增长后的函数挤出（假红），
  // 也会被窗口内的无关同名文本命中（假绿）；源取剥注释视图。
  const body = member(text, 'const refreshPage')
  const eventsAt = body.indexOf('fetchEvents(')
  const statusAt = body.indexOf('fetchAutobanStatus(')
  assert.ok(eventsAt > 0, 'refreshPage 必须刷新事件列表')
  assert.ok(statusAt > 0, 'refreshPage 必须联动自动封禁状态')
  assert.ok(statusAt > eventsAt, '先刷新列表，再补拉自动封禁状态')
  assert.match(text, /@click="refreshPage"/)
})

test('信任关联写动作确认前即占位（双击不再叠确认框）', () => {
  const text = code('src/composables/useTrustAssociation.ts')
  // 原断言只数 `if (creating.value) return` 出现次数 ≥2——
  // 同一函数里写两次也通过，无法证明「两个写入口都有锁」。改为逐函数限段：
  // 每个写入口的入口守卫必须早于占位与确认框。
  const writers = [
    ['const ensureListAndJoin = async', 'const removeFromSideRef = async'],
    ['const removeFromSideRef = async', 'return { busyTrust'],
  ] as const
  for (const [startMarker, endMarker] of writers) {
    const body = section(text, startMarker, endMarker)
    const guard = body.indexOf('if (creating.value) return')
    const occupy = body.indexOf('creating.value = true')
    const confirm = body.indexOf('ElMessageBox.confirm')
    assert.ok(guard > 0, `${startMarker} 缺重入锁`)
    assert.ok(occupy > guard, `${startMarker} 必须先判锁再占位`)
    assert.ok(confirm > guard, `${startMarker} 必须在弹确认框之前判锁（否则双击叠两个框）`)
    assert.ok(confirm > occupy, `${startMarker} 占位必须先于确认框`)
  }
})

test('restart 就绪响应落地后 reload 前复查 isDisposed', () => {
  // 原断言取 260 字符窗口——isDisposed 与 reload 可来自无关语句。
  // 改为函数级限段 + 顺序断言：状态请求成功后的 dispose 复查必须紧邻 reload。
  const body = section(code('src/utils/restart.ts'), 'const reloadAfterRestart = async', 'interface RestartServiceOptions')
  const statusAt = body.indexOf("await request.get('/caddy/status'")
  assert.ok(statusAt > 0, '缺就绪探测')
  const afterStatus = body.slice(statusAt)
  const reloadAt = afterStatus.indexOf('window.location.reload()')
  assert.ok(reloadAt > 0, '就绪后必须 reload')
  const gateAt = afterStatus.indexOf('if (isDisposed?.()) return false')
  assert.ok(gateAt > 0 && gateAt < reloadAt, 'reload 前必须复查卸载门（在途期间卸载不得刷新页面）')
  // 探测前同样要有卸载门：重启窗口内卸载即停止轮询
  const beforeStatus = body.slice(0, statusAt)
  assert.match(beforeStatus, /if \(isDisposed\?\.\(\)\) return false/)
})

test('死代码清理（灰 tone/死 CSS/死字段/解析器单源）', () => {
  assert.doesNotMatch(code('src/components/RuleFlowDialog.vue'), /tl-dot--gray|\| 'gray'/)
  assert.doesNotMatch(code('src/views/security/SecurityEvents.vue'), /autoban-confirm-list|autoban-confirm-text/)
  assert.doesNotMatch(code('src/views/security/SecurityEvents.vue'), /list_referenced: boolean/, '死字段声明应移除')
  assert.doesNotMatch(code('src/views/security/SecurityPolicies.vue'), /\.exclusion-empty \.el-button/)
  // 自定义规则 ID 解析单源化
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /parseUnknownIds/)
  assert.match(code('src/utils/securityStages.ts'), /export const parseUnknownIds|export function parseUnknownIds/)
})

test('build 门禁：先跑测试与覆盖率门限、再跑 src 基线与 tests 类型检查', () => {
  const pkg = JSON.parse(code('package.json')) as { scripts: Record<string, string> }
  assert.ok(
    pkg.scripts.build.startsWith('npm run test:coverage && npm run typecheck:src && npm run typecheck:test &&'),
    `build 必须先执行覆盖率门限下的测试、typecheck:src 与 typecheck:test，实际: ${pkg.scripts.build}`,
  )
  // 覆盖率必须带阈值：只开 --experimental-test-coverage 会打报告但不拦下滑，
  // 与「可见口径无门禁」等价。三项阈值（行/分支/函数）缺一即弱点。
  const coverage = pkg.scripts['test:coverage']
  for (const flag of ['--experimental-test-coverage', '--test-coverage-lines=', '--test-coverage-branches=', '--test-coverage-functions=']) {
    assert.ok(coverage.includes(flag), `test:coverage 缺少 ${flag}: ${coverage}`)
  }
  // 反向：build 不得退回无覆盖率门限的裸 npm test（快速环仍保留 npm test）。
  assert.doesNotMatch(pkg.scripts.build, /(^|&& )npm test( |$)/, `build 不得退回裸 npm test: ${pkg.scripts.build}`)
  // src 基线门（lib ES2020）与 tests 门（lib ES2024）必须是两个 project：
  // tsconfig.test.json 抬高 lib 是为了 tests 的 Promise.withResolvers 等 API，
  // 若只跑它，src 也只在 ES2024 的 API 面下被检查——等于放宽浏览器兼容基线
  // （restart.ts 明确回避 Promise.withResolvers，旧 Safari 会首屏白屏）。
  assert.equal(pkg.scripts['typecheck:src'], 'vue-tsc -p tsconfig.json --noEmit')
  assert.match(code('tsconfig.json'), /"lib": \["ES2020", "DOM", "DOM\.Iterable"\]/, 'src 基线 lib 不得抬高')
  assert.match(code('tsconfig.test.json'), /"lib": \["ES2024", "DOM", "DOM\.Iterable"\]/, 'tests 需要 ES2024 API')
  assert.doesNotMatch(pkg.scripts.build, /(^|&& )vue-tsc --noEmit/, `build 不得跑无 project 的全量检查: ${pkg.scripts.build}`)
})

test('证书卡：ACME 证书卡接入 configLoaded 双重门控（与 Basic/Caddy 同契约）', () => {
  const card = code('src/views/settings/FreeCertificates.vue')
  assert.match(card, /defineProps<\{ configLoaded: boolean \}>/)
  assert.match(card, /:disabled="isReadOnly \|\| !props\.configLoaded"/)
  const save = section(card, 'const handleSave = async', 'if (isReadOnly.value) return')
  assert.match(save, /!props\.configLoaded/, 'configLoaded 门必须早于常规写守卫')
  const page = code('src/views/Settings.vue')
  assert.match(page, /<FreeCertificates[\s\S]*?:config-loaded="configLoaded"/)
})

// ===== 设置/安全视图接线（证书队列、任务监控、集群、TLS、DNS 凭证、OIDC） =====

test('证书队列非空判据 = 排队 + 进行中 + 等 CA（任何一项 > 0 都非「空闲」）', () => {
  assert.equal(certQueueIsBusy({ queued: 0, running: 0, waiting: 0 }), false)
  assert.equal(certQueueIsBusy({ queued: 3, running: 0, waiting: 0 }), true, '全部排队时曾被误报空闲')
  assert.equal(certQueueIsBusy({ queued: 0, running: 0, waiting: 2 }), true, '等 CA 也是队列非空')
  assert.equal(certQueueIsBusy({ queued: 0, running: 1, waiting: 0 }), true)
  // 正文空态与「+N」不再依赖首页可见行
  assert.equal(certQueueHasLive({ total: 3 }), true)
  assert.equal(certQueueHasLive({ total: 0 }), false)
  assert.equal(CERT_QUEUE_VISIBLE_JOBS, 4)
  const base = { queued: 0, running: 5, waiting: 0 }
  assert.equal(certQueueMoreCount({ ...base, total: 10, jobs: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }, { id: 5 }] }), 6)
  // 行数不足 4：原实现 total-4 会偏小/错位
  assert.equal(certQueueMoreCount({ ...base, total: 3, jobs: [{ id: 1 }] }), 2)
  assert.equal(certQueueMoreCount({ ...base, total: 0, jobs: [] }), 0)
})

test('证书队列横幅接线与 page_size=6', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  assert.match(page, /certQueueIsBusy\(certQueue\) \? 'primary' : 'success'/)
  assert.match(page, /v-else-if="certQueueHasLive\(certQueue\)"/)
  assert.match(page, /certQueue\.jobs\.slice\(0, CERT_QUEUE_VISIBLE_JOBS\)/)
  assert.match(page, /certQueueMoreCount\(certQueue\)/)
  assert.match(page, /const CERT_QUEUE_PAGE_SIZE = 6/)
  assert.match(page, /page_size: CERT_QUEUE_PAGE_SIZE/)
})

test('任务监控三份轮询请求缺 data 一律抛 TypeError（进入契约退避）', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  const tasks = section(page, 'const fetchTasks = async', 'const refreshNow =')
  assert.match(tasks, /if \(!res\.data\) throw new TypeError\('任务列表响应缺少 data'\)/)
  assert.match(tasks, /throw new TypeError\('任务统计响应缺少 data'\)/)
  const queue = section(page, 'const fetchCertQueue = async', 'const taskFamilyCount = computed')
  assert.match(queue, /if \(!res\.data\) throw new TypeError\('证书队列响应缺少 data'\)/)
  // 必须在自身 catch 中继续向上抛，否则轮询入口永远看不到契约违约
  assert.match(queue, /if \(error instanceof TypeError\) throw error/)
})

test('任务详情弹框适配窄屏：优先实时行，退役行保留打开时快照', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  assert.match(page, /<el-dialog v-model="detailVisible" width="min\(720px, 92vw\)"/)
  const block = section(page, 'const detailTask = computed<TaskInfo | null>', 'const history = ref')
  const live = block.indexOf('tasks.value.find(t => t.id === id)')
  const fallback = block.indexOf('?? detailSeed.value')
  assert.ok(live >= 0 && fallback > live, '列表命中优先实时行；行退役时回退打开时快照')
  assert.match(section(page, 'const openDetail = async', 'const logsVisible = ref'), /detailTaskId\.value = row\.id/)
})

test('节点审批/拒绝/删除在确认弹框之前取得占位', () => {
  const block = section(code('src/views/settings/ClusterSettings.vue'), 'const confirmAndRunNodeAction = async', 'const approveNode = (node: ClusterNode)')
  const takePlaceholder = block.indexOf('pendingNodeId.value = node.id')
  const confirm = block.indexOf('confirmAction(')
  assert.ok(takePlaceholder >= 0 && confirm > takePlaceholder, '占位必须先于 confirmAction')
  assert.match(block, /pendingNodeId\.value !== null/, '第二请求必须被显式拒绝而非静默丢弃')
  const page = code('src/views/settings/ClusterSettings.vue')
  // 箭头体必须直接委托 confirmAndRunNodeAction——不要求换行/缩进形态
  // （纯格式化把调用提到 `=>` 同行时不得假红）；中间也不允许夹别的判断。
  for (const name of ['approveNode', 'removeNode']) {
    const at = page.indexOf(`const ${name} = (node: ClusterNode): Promise<void> =>`)
    assert.ok(at > 0, `${name} 的委托形态被改（本钉需同步）`)
    const rest = page.slice(at)
    const callAt = rest.indexOf('confirmAndRunNodeAction(')
    assert.ok(callAt > 0, `${name} 必须走确认+执行单源`)
    assert.match(rest.slice(0, callAt), /=>\s*$/, `${name} 的箭头体必须直接委托，不得在中间插入判断`)
  }
})

test('服务控制/同步/同步设置/清钉同样在确认前占位', () => {
  const page = code('src/views/settings/ClusterSettings.vue')
  const service = section(page, 'const executeServiceControl = async', 'const forgetNodePin = async')
  assertPlaceholderBeforeConfirm(service, 'serviceControlLoading.value = true', '服务控制')
  const forgetPin = section(page, 'const forgetNodePin = async', 'const registerToken = ref')
  assertPlaceholderBeforeConfirm(forgetPin, 'nodePinForgetting.value = true', '忘记节点 PIN')
  const sync = section(page, 'const syncNow = async', 'const forgetPins = async')
  assertPlaceholderBeforeConfirm(sync, 'syncing.value = true', '立即同步')
  // 占位变量名为 clusterSettingsSaving：此前这里钉的是已不存在的
  // settingsLoading，indexOf 恒 -1 使「同步设置」这一格从未真正被守住。
  const syncField = section(page, 'const updateSyncField = async', 'const updateSyncInterval = async')
  assertPlaceholderBeforeConfirm(syncField, 'clusterSettingsSaving.value = true', '同步设置')
  const pins = section(page, 'const forgetPins = async', 'const generateRegisterToken = async')
  assertPlaceholderBeforeConfirm(pins, 'forgettingPins.value = true', '清钉')
})

test('占位顺序判据自身不空转（元测试）', () => {
  const ok = 'const f = async () => {\n  syncing.value = true\n  const ok = await confirmAction()\n}'
  assertPlaceholderBeforeConfirm(ok, 'syncing.value = true', '样本')
  // 占位被删 → 旧写法（-1 < 正值）仍通过，新判据必须变红
  const missing = 'const f = async () => {\n  const ok = await confirmAction()\n}'
  assert.throws(() => assertPlaceholderBeforeConfirm(missing, 'syncing.value = true', '样本'), /不存在/)
  // 占位挪到确认之后（双击叠加确认框）必须变红
  const reversed = 'const f = async () => {\n  const ok = await confirmAction()\n  syncing.value = true\n}'
  assert.throws(() => assertPlaceholderBeforeConfirm(reversed, 'syncing.value = true', '样本'), /必须先于/)
  // 段内根本没有确认框（section 切错段）必须变红，而不是静默通过
  assert.throws(() => assertPlaceholderBeforeConfirm('syncing.value = true', 'syncing.value = true', '样本'), /未调用/)
})

test('TLS 文件选择器读完即复位（同路径重选可再次触发 change）', () => {
  const block = section(code('src/views/settings/BasicSettings.vue'), 'const onTlsFile = async', 'const notifyTlsRestarting')
  const reset = block.indexOf("input.value = ''")
  const firstUse = block.indexOf('adminTlsForm.value.certFile')
  assert.ok(reset >= 0 && reset < firstUse, 'file input 必须在读取后立即复位')
})

test('/admin-tls 读取失败显性化并提供重试', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /const adminTlsLoadFailed = ref\(false\)/)
  const load = section(page, 'const loadAdminTls = async', 'const retryLoadAdminTls')
  assert.match(load, /catch \{[\s\S]*adminTlsLoadFailed\.value = true/, '读取失败必须置显性失败态')
  assert.match(page, /const retryLoadAdminTls = \(\): void => \{ void loadAdminTls\(\) \}/)
  const failedBlock = section(page, '<template v-else-if="adminTlsLoadFailed">', '</template>')
  assert.match(failedBlock, /TLS 配置读取失败/, '开关旁必须有错误文案')
  assert.match(failedBlock, /@click="retryLoadAdminTls"/, '开关旁必须有重试入口')
})

test('兜底提醒不承诺不会发生的自动跳转', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(page, /若未自动跳转/)
  assert.match(page, /ElMessage\.warning\(`请手动访问新地址：\$\{target\}`\)/)
})

test('各写函数入口自带只读/在途守卫（纵深防御）', () => {
  const basic = code('src/views/settings/BasicSettings.vue')
  const checks: Array<[string, string, RegExp]> = [
    ['const saveAutoBackupSettings = async', '\nconst ', /if \(backupDisabled\.value \|\| !autoBackupSectionsValid\.value/],
    ['const restoreAutoBackup = async', '\nconst ', /if \(backupDisabled\.value \|\| autoBackupActionBusy\.value\) return/],
    ['const deleteAutoBackup = async', '\nconst ', /if \(backupDisabled\.value \|\| autoBackupActionBusy\.value\) return/],
    ['const confirmImport = async', '\nconst ', /if \(backupDisabled\.value\) return/],
  ]
  for (const [start, end, pattern] of checks) {
    assert.match(section(basic, start, end), pattern, `${start} 缺函数级写守卫`)
  }
  // 导入是全卡破坏性最强的动作：确认与「勾分类重校验」都要节点模式门（从节点上
  // 两条端点必然 403 master_required），入口按钮同口径，不得只判只读。
  assert.match(basic, /<el-button type="primary" :disabled="!importValidation\?\.valid \|\| !importPreviewSelected \|\| backupDisabled" :loading="importing" @click="confirmImport">确认导入<\/el-button>/, '确认导入按钮必须含节点模式门')
  assert.match(section(basic, 'const revalidateImport = async', '\nconst '), /if \(backupDisabled\.value\) \{/, '勾分类重校验必须早退（从节点必 403）')
  const caddy = code('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(section(caddy, 'const confirmSaveAsList = async', '\nconst '), /if \(isReadOnly\.value \|\| savingList\.value\) return/)
  const free = code('src/views/settings/FreeCertificates.vue')
  assert.match(section(free, 'const saveCAProvider = async', '\nconst '), /if \(isReadOnly\.value \|\| savingCA\.value\) return/)
  assert.match(section(free, 'const saveConfig = async', '\nconst '), /if \(isReadOnly\.value \|\| savingConfig\.value\) return/)
  assert.match(section(free, 'const deleteConfig = async', '\nconst '), /if \(isReadOnly\.value \|\| savingConfig\.value \|\| deletingId\.value !== null\) return/)
  // 两个「测试」端点会真实写 DNS TXT / 申请 EAB（后端非只读豁免）
  assert.match(section(free, 'const testCAProvider = async', '\nconst '), /if \(isReadOnly\.value \|\| isTesting\.value\) return/)
  assert.match(section(free, 'const testConfig = async', '\nconst '), /if \(isReadOnly\.value \|\| isTesting\.value \|\| !config\.id\) return/)
  assert.match(section(basic, 'const openAdminTlsDialog = () => {', '\nconst '), /if \(isReadOnly\.value\) return/)
  const oidc = code('src/views/settings/OIDCSettings.vue')
  assert.match(section(oidc, 'const save = async', '\nconst '), /if \(isReadOnly\.value \|\| saving\.value\) return/)
  assert.match(section(oidc, 'const toggleEnabled = async', '\nconst '), /if \(isReadOnly\.value \|\| saving\.value \|\| loadFailed\.value\) return/)
  assert.match(section(oidc, 'const remove = async', '\nconst '), /if \(isReadOnly\.value \|\| saving\.value \|\| loadFailed\.value\) return/)
  // TaskMonitor：四个写动作（触发/启停/取消/重启）共用 runTaskAction，唯一的下发
  // 通道必须自带权限门——按钮 :disabled 只是入口层，角色/只读态可在页面停留期间
  // 变化（另标签降权、整机切从节点），重渲染窗口内的点击会直发写请求。
  const tasks = code('src/views/settings/TaskMonitor.vue')
  const runAction = section(tasks, 'async function runTaskAction(', '\n}\n')
  assert.match(runAction, /if \(!canOperate\.value\) return/, 'runTaskAction 必须带函数级 canOperate 门')
  const pendingAt = runAction.indexOf('taskActionPendingId.value !== null')
  const guardAt = runAction.indexOf('if (!canOperate.value) return')
  assert.ok(guardAt > pendingAt, '权限门位于重入占位守卫之后（保持占位先于确认的既有顺序）')
  for (const handler of ['const onTrigger = ', 'const onToggle = ', 'const onCancel = ', 'const onRestart = ']) {
    const body = section(tasks, handler, '\nconst ')
    assert.match(body, /runTaskAction\(/, `${handler} 必须走统一执行器（不得绕过函数级门）`)
  }
})

test('CA 表单不再持有零读取的 credentials / id 副本', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  const block = section(page, 'const caForm = reactive', 'const caCreds = reactive')
  assert.doesNotMatch(block, /credentials: '\{\}'/, 'caForm 初始值不得再含零读取的 credentials')
  assert.doesNotMatch(block, /\bid: 0,/, 'caForm 初始值不得再含零读取的 id（保存走 editingCAProvider.id）')
  assert.match(page, /reactive<Omit<CAProvider, 'credentials' \| 'id'>>/)
})

test('DNS 凭证字段可见性按 visible_when 求值，无元数据时恒显示', () => {
  const fields = [
    { name: 'auth_mode', label: '认证方式', type: 'select', required: true, options: ['dnspod', 'tencent_cloud'], option_labels: { dnspod: 'DNSPod API', tencent_cloud: '腾讯云 API' } },
    { name: 'app_id', label: 'App ID', type: 'text', required: false, visible_when: { auth_mode: ['dnspod'] } },
    { name: 'secret_id', label: 'SecretId', type: 'text', required: false, visible_when: { auth_mode: ['tencent_cloud'] } },
    { name: 'future_field', label: '未来字段', type: 'text', required: false },
  ]
  assert.equal(credentialFieldVisible(fields[1], { auth_mode: 'dnspod' }), true)
  assert.equal(credentialFieldVisible(fields[1], { auth_mode: 'tencent_cloud' }), false)
  assert.equal(credentialFieldVisible(fields[2], { auth_mode: 'tencent_cloud' }), true)
  assert.equal(credentialFieldVisible(fields[3], {}), true, '新 provider 无元数据字段不得被隐藏')
  assert.equal(credentialOptionLabel(fields[0], 'dnspod'), 'DNSPod API')
  assert.equal(credentialOptionLabel(fields[0], 'unknown'), 'unknown')
  // option_labels 是普通对象：原型键必须回退原始值（直接下标会渲染出函数源码）
  for (const key of ['constructor', 'toString', '__proto__']) {
    assert.equal(credentialOptionLabel(fields[0], key), key)
  }
  assert.deepEqual(defaultCredentialsFor(fields), { auth_mode: 'dnspod' })
  assert.deepEqual(defaultCredentialsFor([]), {})
})

test('后端下发 visible_when/option_labels，前端不再硬编码 dnspod 字段名', () => {
  const go = repoCode('internal/services/dnsproviders/dnspod.go')
  const cf = section(go, 'func (d *DNSPod) CredentialFields()', '\nfunc (d *DNSPod) CredentialFieldOptions')
  assert.match(cf, /VisibleWhen: visibleOnly\("dnspod"\)/)
  assert.match(cf, /VisibleWhen: visibleOnly\("tencent_cloud"\)/)
  assert.match(cf, /OptionLabels: map\[string\]string\{"dnspod": "DNSPod API", "tencent_cloud": "腾讯云 API"\}/)
  const handler = repoCode('internal/handlers/certificates.go')
  const list = section(handler, 'func (h *Handlers) ListDNSProviders', 'func (h *Handlers) TestCertificateConfig')
  assert.match(list, /field\["visible_when"\] = f\.VisibleWhen/)
  assert.match(list, /field\["option_labels"\] = f\.OptionLabels/)
  const vue = code('src/views/settings/FreeCertificates.vue')
  assert.match(vue, /credentialFieldVisible\(field, form\.value\.dns_credentials\)/)
  assert.match(vue, /:label="credentialOptionLabel\(field, opt\)"/)
  assert.doesNotMatch(vue, /field\.name === 'auth_mode'\) return true/)
  assert.doesNotMatch(vue, /opt === 'dnspod' \? 'DNSPod API' : '腾讯云 API'/)
})

test('OIDC GET 失败清空为未配置态并禁止保存（不得回填上一轮状态）', () => {
  const page = code('src/views/settings/OIDCSettings.vue')
  const load = section(page, 'const load = async', 'let probeInFlight')
  const failureAt = load.indexOf('onError: () => {')
  assert.ok(failureAt > 0, 'load 缺最新会话 onError 分支')
  const failureBlock = load.slice(failureAt)
  for (const cleared of ['enabled.value = false', 'hasSecret.value = false', 'hasFetchedConfig.value = false', "form.issuer = ''", 'loadFailed.value = true']) {
    assert.ok(failureBlock.includes(cleared), `load onError 未复位 ${cleared}——父级会回填陈旧状态`)
  }
  assert.match(page, /v-if="loadFailed" type="error"/)
  assert.match(section(page, 'const save = async', '\nconst '), /if \(loadFailed\.value\)/)
})

// ── 本批视图接线守卫（数据就绪门 / 请求门 / 单源）──

test('集群模式卡：status 未就绪时写控件 fail-closed（默认值不得覆盖真实配置）', () => {
  const card = code('src/views/settings/cluster/ClusterModeCard.vue')
  assert.match(
    card,
    /const intervalDisabled = computed\(\(\) => props\.readOnly \|\| props\.intervalSaving \|\| isSlave\.value \|\| !props\.status\)/,
    '缺 status 门时 syncInterval(60) !== undefined 恒真，保存按钮可点',
  )
  assert.match(section(card, 'const saveSyncInterval', '\n}'), /if \(props\.readOnly \|\| !props\.status\) return/)
  assert.match(section(card, 'const handleModeChange', '\n}'), /if \(props\.readOnly \|\| props\.loading \|\| !props\.status\) return/)
  assert.match(card, /:disabled="loading \|\| readOnly \|\| !status"/)
})

test('集群同步间隔：清空输入不得提交（后端把缺失值当「未提供」并回 200）', () => {
  const card = code('src/views/settings/cluster/ClusterModeCard.vue')
  // el-input-number 清空后回写 null/undefined——值域必须显式包含空，否则
  // 空值被当成合法数字一路发到后端。
  assert.match(card, /const syncInterval = ref<number \| null \| undefined>\(60\)/, '清空后 v-model 为 null/undefined')
  assert.match(card, /const syncIntervalValid = computed\(/, '空值判据必须单源')
  const save = section(card, 'const saveSyncInterval', '\n}')
  assert.ok(save.indexOf('syncIntervalValid.value') > 0, '提交门必须拦截空值')
  assert.ok(save.indexOf('syncIntervalValid.value') < save.indexOf("emit('update-interval'"), '拦截必须先于 emit')
  assert.match(card, /:disabled="intervalDisabled \|\| !syncIntervalValid \|\| syncInterval === status\?\.sync_interval"/, '空值时保存按钮必须灰置')
  assert.match(card, /v-if="!syncIntervalValid"/, '清空后须有可见提示，而非静默灰置')

  const page = code('src/views/settings/ClusterSettings.vue')
  const write = section(page, 'const updateSyncInterval = async', 'const runNodeAction = async')
  assert.match(write, /typeof value !== 'number' \|\| !Number\.isFinite\(value\)/, '写侧必须再判空（防未来调用方直传）')
  const guard = write.indexOf('Number.isFinite')
  const put = write.indexOf("request.put<ActionResponse>('/cluster/settings'")
  assert.ok(guard > 0 && put > guard, '空值拒绝必须先于 PUT——否则后端保持现值、前端提示「已更新」')
})

test('仪表盘：/caddy/status 失败置采集失败并阻断陈旧状态呈现', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /const caddyStatusUnavailable = ref\(false\)/)
  const requestBlock = section(page, "request.get('/caddy/status'", ']).then(')
  assert.match(requestBlock, /caddyStatusUnavailable\.value = false/)
  assert.match(
    requestBlock,
    /\}\)\.catch\(\(\) => \{ if \(!disposed\) caddyStatusUnavailable\.value = true \}\)/,
    '缺 catch 时状态标签/一致性静默陈旧',
  )
  assert.match(page, /v-if="caddyStatusUnavailable" type="info"[^>]*>状态采集失败/)
  assert.match(page, /v-if="caddyApplyError && !caddyStatusUnavailable"/)
  assert.match(page, /v-if="caddyBackgroundApplyError && !caddyStatusUnavailable"/)
  assert.match(page, /configConsistent === 'true' && !caddyStatusUnavailable/)
})

test('设置页：分页初值即由页键派生，且仅消费方分页拉 /config', () => {
  const page = code('src/views/Settings.vue')
  assert.match(page, /const activeTab = ref<SettingsTabId>\(settingsTabOfPage\(authStore\.currentPage\) \?\? 'basic'\)/)
  // 判据单源：横幅与拉取门同用 settingsTabConsumesConfig（本地再写一份会让
  // 两者在调整「消费 /config」分页时静默分叉）。
  assert.doesNotMatch(page, /tab === 'basic' \|\| tab === 'certificates'/, '不得在视图内重复枚举消费 /config 的分页')
  assert.match(page, /if \(settingsTabConsumesConfig\(activeTab\.value\) && !configLoaded\.value\) void fetchSettings\(\)/, '切回 basic/certificates 须补拉')
  const onMounted = section(page, 'onMounted(', '</script>')
  assert.match(onMounted, /if \(settingsTabConsumesConfig\(activeTab\.value\)\) void fetchSettings\(\)/)
  assert.doesNotMatch(onMounted, /syncActiveTabFromPage\(\)\s*\n\s*fetchSettings\(\)/, '不得再无条件整取 /config')
})

test('usePollingErrorState 全部消费点同口径接线（退避门 + 立即重试重置）', () => {
  // 4 个消费页共 5 个状态：任一页漏接 canRun 会在契约违约时继续每秒打后端；
  // 漏接 resetBackoff 会让横幅「重试」按钮无效（退避仍在）。
  const sites: Array<[string, string]> = [
    ['src/views/Rules.vue', 'healthPollingError'],
    ['src/views/Rules.vue', 'certPollingError'],
    ['src/views/settings/CertJobs.vue', 'jobsPollingError'],
    ['src/views/settings/ClusterSettings.vue', 'clusterPollingError'],
    ['src/views/settings/TaskMonitor.vue', 'pollingError'],
  ]
  const cache = new Map<string, string>()
  for (const [path, state] of sites) {
    const text = cache.get(path) ?? code(path)
    cache.set(path, text)
    assert.match(text, new RegExp(`const ${state} = usePollingErrorState\\(\\)`), `${path} 缺 ${state} 实例`)
    assert.match(text, new RegExp(`if \\(!${state}\\.canRun\\(\\)\\) return`), `${path} 轮询闭包缺 canRun 退避门`)
    assert.match(text, new RegExp(`${state}\\.resetBackoff\\(\\)`), `${path} 「立即重试」未重置退避`)
  }
})

test('用户页：OIDC 状态请求与消费面同门（非管理员不发 403 请求）', () => {
  const page = code('src/views/Users.vue')
  // 角色以 store 为响应式通道（immediate）：fetchUser 瞬时失败时角色先为
  // undefined，一次性 onMounted 判定会永久错过补回窗口。
  const gate = section(page, 'watch(() => authStore.user?.role,', 'onMounted(')
  assert.match(gate, /if \(role === 'admin'\) void fetchOIDCStatus\(\)/)
  assert.match(gate, /immediate: true/)
  assert.doesNotMatch(section(page, 'onMounted(', '})'), /fetchOIDCStatus/, 'onMounted 不得无条件拉取（非管理员必 403）')
})

test('集群同步三分类标签单源（父级确认文案与子级开关行同表）', () => {
  const master = code('src/views/settings/cluster/ClusterMasterPanel.vue')
  const settings = code('src/views/settings/ClusterSettings.vue')
  assert.match(master, /import \{ CLUSTER_SYNC_SWITCHES \} from '@\/utils\/clusterSyncSwitches'/)
  assert.match(master, /const syncSwitchItems = CLUSTER_SYNC_SWITCHES/)
  assert.match(settings, /import \{ CLUSTER_SYNC_SWITCHES \} from '@\/utils\/clusterSyncSwitches'/)
  assert.match(settings, /CLUSTER_SYNC_SWITCHES\.map\(\(item\) => \[item\.key, item\.label\]\)/)
  for (const [name, text] of [['子级', master], ['父级', settings]] as const) {
    assert.doesNotMatch(text, /sync_users: '系统数据'|sync_rules: '负载均衡规则'|sync_security: '安全防护'/, `${name}仍有第二份字面量`)
  }
  // 只读态必须显式落到每个开关：`:disabled="item.locked === true"` 恒为 false，
  // 会压过外层 <el-form :disabled="readOnly">（Element Plus 取 disabled ?? form.disabled），
  // 从节点/非管理员看到的开关呈可点态，点了被 handleSwitchChange 静默丢弃后回弹。
  assert.match(master, /:disabled="readOnly \|\| item\.locked === true"/, '只读态必须显式禁用同步开关')
})

test('策略向导：阶段覆盖编辑态稀疏持有（不得物化库值 seed）', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const watcher = section(page, 'watch([boundRules, allRules], () => {', '}, { immediate: true })')
  assert.match(watcher, /const existing = stageOverrideEdits\.value\[cid\]/)
  assert.match(watcher, /if \(existing\) next\[cid\] = existing/)
  assert.doesNotMatch(
    watcher,
    /\?\? stageOverrideSeed\(cid\)/,
    '物化 seed 会在 /rules 新快照到达后把旧库值钉成待保存覆盖，保存时静默回退他处变更',
  )
})

test('安全事件：tooltip 死条件删除，crawler 族展示词单源，旧 id 8 中和文案', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  const show = section(page, 'const showTriggeredMsg', '\n\n')
  assert.match(show, /!!row\.rule_triggered && !!row\.rule_msg/)
  assert.doesNotMatch(show, /!== '2'|!== '3'|!== '4'|!== '5'|\^949/, '这些排除项永不命中（前两个 el-link 分支已截走）')
  assert.match(page, /case 'crawler': return CRAWLER_FAMILY_LABEL/)
  assert.match(page, /if \(row\.rule_triggered === '8'\) return '地域拦截（旧 id）'/)
  // 分类例外保持不变（triggerStageFamily 对 8 归 ipAcl）
  assert.match(page, /switch \(triggerStageFamily\(t\)\)/)
})

test('OIDC 设置卡：访问白名单字段（email 域 / 用户组）读回显与整表保存', () => {
  const page = code('src/views/settings/OIDCSettings.vue')
  // 解析器已抽到 utils/oidcAllowList（域/组分隔口径不同，行为由 oidcAllowList.spec
  // 覆盖）：SFC 只做接线，不得再内联第二份正则。
  assert.match(page, /from '@\/utils\/oidcAllowList'/)
  assert.match(page, /parseDomainAllowList/)
  assert.match(page, /parseGroupAllowList/)
  assert.doesNotMatch(page, /raw\.split\(\/\[\\s,;，、\]\+\//, '不得回退到 SFC 内联分隔正则')
  const load = section(page, 'const load = async', 'let probeInFlight')
  assert.match(load, /form\.allowedEmailDomains = formatAllowList\(res\.data\.allowed_email_domains\)/)
  assert.match(load, /form\.allowedGroups = formatAllowList\(res\.data\.allowed_groups\)/)
  const save = section(page, 'const save = async', '\nconst ')
  assert.match(save, /allowed_email_domains: parseDomainAllowList\(form\.allowedEmailDomains\)/)
  assert.match(save, /allowed_groups: parseGroupAllowList\(form\.allowedGroups\)/)
  // 局部 PUT（启用/暂停/删除）不得携带键——契约：缺省=不动、[]=清除
  const toggle = section(page, 'const toggleEnabled', '\nconst ')
  assert.match(toggle, /request\.put\('\/settings\/oidc', \{ enabled: on \}\)/)
  assert.doesNotMatch(toggle, /allowed_/)
  // 表单区可见（步骤 4）
  assert.match(page, /v-model="form\.allowedEmailDomains"/)
  assert.match(page, /v-model="form\.allowedGroups"/)
})

test('CA 提供商测试成功后刷新列表（陈旧凭证表单不得覆盖刚申请的 EAB）', () => {
  // testCAProvider 会触发 ZeroSSL EAB 自动申请并写库；列表不刷新时后续
  // 「编辑 → 保存」提交的是测试前的空 EAB 快照，会把刚拿到的凭证覆盖为空。
  const page = code('src/views/settings/FreeCertificates.vue')
  const body = section(page, 'const testCAProvider', 'const openConfigDialog')
  const requestAt = body.indexOf('await request.post')
  assert.ok(requestAt > 0, '缺测试请求')
  const refetchAt = body.indexOf('await fetchCAProviders()')
  assert.ok(refetchAt > requestAt, '测试成功后必须重新拉取 CA 提供商列表')
})
