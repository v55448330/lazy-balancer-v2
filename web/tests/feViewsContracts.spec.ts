import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, openTags, section } from './_helpers.ts'
import { parseWhitelist, serializeWhitelist } from '../src/utils/apiKeyWhitelist.ts'

const rules = code('src/views/Rules.vue')
const keys = code('src/views/Keys.vue')
const users = code('src/views/Users.vue')
const certJobs = code('src/views/settings/CertJobs.vue')
const auditLog = code('src/views/AuditLog.vue')

test('实时统计轮询失败进入可见错误态，后续成功可自愈', () => {
  const fetchStream = section(rules, 'const fetchLogStream = async', 'const startLogStats')
  assert.match(fetchStream, /logStatsOffset\.value = res\.data\?\.offset \?\? targetOffset\s*ruleLogStatsError\.value = ''/)
  assert.match(fetchStream, /catch \(error: unknown\)[\s\S]*?requestSeq !== ruleLogRequestSeq[\s\S]*?ruleLogStatsError\.value = error instanceof Error \? error\.message : '请稍后重试'/)
})

test('downloaded 锁提示与启停/删除禁用口径一致', () => {
  const tooltip = section(rules, 'const certJobLockTooltip', 'const canEditRule')
  const downloaded = section(tooltip, "if (status === 'downloaded')", 'return activeText')
  assert.match(downloaded, /不阻塞编辑/)
  assert.match(downloaded, /启停\/删除待部署收敛/)
  assert.doesNotMatch(downloaded, /不阻塞规则启停、删除/)
  const active = section(rules, 'const isCertJobActive', 'const isCertJobEditLocked')
  assert.doesNotMatch(active, /'downloaded'/, 'downloaded 必须继续阻塞启停/删除')
})

test('规则状态开关的禁用原因复用证书任务锁提示', () => {
  const statusColumn = section(rules, '<el-table-column label="状态"', '</el-table-column>')
  const tooltip = section(statusColumn, '<el-tooltip', '</el-tooltip>')
  assert.match(tooltip, /:disabled="!isReadOnly && !isCertJobActive\(certJobMap\[row\.caddy_id\]\?\.status\) && !ruleTogglePending\[row\.caddy_id\]"/)
  assert.match(tooltip, /:content="isReadOnly \? readOnlyMessage : ruleTogglePending\[row\.caddy_id\] \? '规则状态更新中，请稍候' : certJobLockTooltip\(row as Rule, '证书申请中，请等待完成或失败后再启停规则'\)"/)
  assert.match(statusColumn, /<el-switch[\s\S]*?:disabled="isReadOnly \|\| isCertJobActive\(certJobMap\[row\.caddy_id\]\?\.status\) \|\| ruleTogglePending\[row\.caddy_id\]"/)
})

test('旧请求失败不得覆盖新请求的错误状态', () => {
  const fetchRules = section(rules, 'const fetchRules = async', 'const fetchCertInfo')
  assert.match(fetchRules, /catch \(error: unknown\)[\s\S]*?if \(axios\.isCancel\(error\) \|\| disposed \|\| requestSeq !== rulesRequestSeq\) return[\s\S]*?rulesLoadError\.value = true/)

  const fetchCertInfo = section(rules, 'const fetchCertInfo = async', 'const retryCertInfo')
  assert.match(fetchCertInfo, /if \(!axios\.isCancel\(error\) && !disposed && generation === certInfoGeneration\)/)
})

test('锁 popover 卸载回调 null 时删除登记', () => {
  const register = section(rules, 'const setLockPopover', 'const openFlowFromLock')
  assert.match(register, /else delete lockPopovers\[caddyId\]/)
})

test('Caddy 配置失败使用独立错误态与重试，不伪造 JSON', () => {
  assert.match(rules, /const configLoadError = ref\(''\)/)
  const dialog = section(rules, '<el-dialog v-model="configDialogVisible"', '</el-dialog>')
  assert.match(dialog, /v-else-if="configLoadError"/)
  assert.match(dialog, /<el-result[\s\S]*?@click="retryViewConfig"/)
  const viewConfig = section(rules, 'const viewConfig = async', 'const onConfigDialogClosed')
  assert.match(viewConfig, /configLoadError\.value = ''/)
  assert.match(viewConfig, /configLoadError\.value = error instanceof Error \? error\.message : '获取配置失败'/)
  assert.doesNotMatch(viewConfig, /\{ error: '获取配置失败', details:/)
})

test('五个错误横幅重试按钮绑定各自真实在途状态', () => {
  for (const [handler, flag] of [
    ['retryCertPolling', 'certRetryLoading'],
    ['retryCertInfo', 'certInfoRetryLoading'],
    ['retryHealthPolling', 'healthRetryLoading'],
    ['fetchRules', 'loading'],
    ['retryAuxData', 'auxDataRetryLoading'],
  ] as const) {
    assert.match(rules, new RegExp(`<el-button link type="danger" :loading="${flag}" @click="${handler}(?:\\(\\))?">立即重试</el-button>`), `${handler} 必须绑定 ${flag}`)
  }
  for (const handler of ['retryCertPolling', 'retryCertInfo', 'retryHealthPolling', 'retryAuxData']) {
    const body = member(rules, `const ${handler} =`)
    assert.match(body, /Loading\.value = true|loading\.value = true/, `${handler} 必须置在途`)
    assert.match(body, /finally[\s\S]*?Loading\.value = false|finally[\s\S]*?loading\.value = false/, `${handler} 必须收尾在途`)
  }
})

// 安全策略绑定横幅的重试按钮此前借用规则列表的 loading：点「重新加载」在途零
// 反馈；反过来规则列表轮询时它显示与本次重试无关的 loading。
test('安全策略绑定横幅重试按钮绑定绑定数据自身的在途状态', () => {
  assert.match(
    rules,
    /<el-button link type="warning" :loading="securityBindingsLoading" @click="retrySecurityBindings">重新加载<\/el-button>/,
    '重试按钮必须绑定 securityBindingsLoading',
  )
  const fetch = section(rules, 'const fetchSecurityBindings =', 'const retrySecurityBindings')
  assert.match(fetch, /securityBindingsLoading\.value = true/, '取数入口必须置在途')
  assert.match(fetch, /finally[\s\S]*?securityBindingsLoading\.value = false/, '取数入口必须收尾在途')
})

test('规则写后只刷新绑定，安全目录仅首屏与显式重试加载', () => {
  const fetchRules = section(rules, 'const fetchRules = async', 'const fetchCertInfo')
  assert.match(fetchRules, /includeSecurityCatalog = false/, '常规规则刷新默认不得加载安全目录')
  assert.match(fetchRules, /void fetchSecurityBindings\(includeSecurityCatalog\)/)

  const fetchBindings = section(rules, 'const fetchSecurityBindings =', 'const retrySecurityBindings')
  for (const type of ['SecurityStagePolicy\\[\\]', 'SecurityStageIPList\\[\\]', 'SecurityStageBlockPage\\[\\]']) {
    assert.match(fetchBindings, new RegExp(`includeSecurityCatalog \\? request\\.get<APIResponse<${type}>>`), '安全目录请求必须由首屏/显式重试开关门控')
  }
  assert.equal((fetchBindings.match(/: Promise\.resolve\(null\)/g) ?? []).length, 3, '默认绑定刷新不得发起三个安全目录请求')
  assert.match(section(rules, 'const retrySecurityBindings =', 'const lockPopovers'), /fetchSecurityBindings\(true\)/, '显式重试必须同时恢复失败的安全目录')
  assert.match(section(rules, 'onMounted\(\(\) =>', 'onUnmounted'), /void fetchRules\(true\)/, '首屏必须加载安全目录以构建锁摘要')
})

test('Keys 从节点判据走 isSlaveNode，四个写控件均解释禁用原因', () => {
  assert.match(keys, /authStore\.isSlaveNode/)
  assert.doesNotMatch(keys, /nodeMode !== 'master'/)
  assert.match(keys, /const nodeWriteBlockedReason = computed/)
  const tooltips = openTags(keys, 'el-tooltip').filter((tag) => tag.includes(':content="nodeWriteBlockedReason"'))
  assert.ok(tooltips.length >= 4, `创建/功能配置/启停/删除至少需要 4 个原因 tooltip，实际 ${tooltips.length}`)
  assert.ok(tooltips.every((tag) => tag.includes(':disabled="!nodeWriteBlocked"')), '只有节点写禁用才显示节点原因')
})

test('白名单 parse/serialize 单源往返覆盖空行、重复与原型键', () => {
  const serialized = serializeWhitelist('192.168.1.10\n\n10.0.0.0/8\n192.168.1.10\n')
  assert.deepEqual(serialized, {
    value: ['192.168.1.10/32', '10.0.0.0/8', '192.168.1.10/32'],
    error: '',
  }, '空行忽略且重复项保持原有语义')
  const roundTripText = parseWhitelist(serialized.value)
  assert.equal(roundTripText, '192.168.1.10/32\n10.0.0.0/8\n192.168.1.10/32')
  assert.deepEqual(serializeWhitelist(roundTripText), serialized)

  assert.equal(parseWhitelist(['__proto__', 'constructor', 'prototype']), '__proto__\nconstructor\nprototype')
  for (const value of ['__proto__', 'constructor', 'prototype']) {
    const result = serializeWhitelist(value)
    assert.equal(result.value.length, 0)
    assert.match(result.error, /格式不正确/)
  }
  assert.match(keys, /import \{ parseWhitelist \} from '@\/utils\/apiKeyWhitelist'/)
  assert.match(keys, /import \{ serializeWhitelist \} from '@\/utils\/apiKeyWhitelist'/)
  assert.doesNotMatch(keys, /const parseWhitelist =/)
})

test('用户删除区分确认取消与真实请求失败', () => {
  assert.match(users, /const isCancelError = \(error: unknown\): boolean =>/)
  const remove = section(users, 'const deleteUser = async', 'const handleToggleStatus')
  assert.match(remove, /catch \(error: unknown\)[\s\S]*?if \(isCancelError\(error\)\) return[\s\S]*?console\.error\('Failed to delete user:', error\)/)
})

test('重置密码/删除/重置 MFA 统一受 submitting 写门保护', () => {
  for (const [start, end] of [
    ['const resetPassword = async', 'const resetMfa = async'],
    ['const deleteUser = async', 'const handleToggleStatus'],
    ['const resetMfa = async', 'onMounted'],
  ] as const) {
    const body = section(users, start, end)
    assert.match(body, /if \(isReadOnly\.value \|\| submitting\.value \|\|/, `${start} 缺少 submitting 门`)
  }
  const buttons = openTags(users, 'el-button')
  // 调用点带 `as UserListItem` 断言（插槽 row 是 DefaultRow），仍是整行对象
  const resetButton = buttons.find((tag) => /@click="resetPassword\(row(?: as [A-Za-z]+)?\)"/.test(tag))
  const deleteButton = buttons.find((tag) => /@click="deleteUser\(row(?: as [A-Za-z]+)?\)"/.test(tag))
  assert.ok(resetButton)
  assert.ok(deleteButton)
  assert.match(resetButton, /:disabled="[^"]*\bsubmitting\b/)
  assert.match(deleteButton, /:disabled="[^"]*\bsubmitting\b/)
})

test('未测量或无 ResizeObserver 时默认横向滚动，不裁操作列', () => {
  assert.match(certJobs, /typeof ResizeObserver === 'undefined'\) \{\s*tableWrapWidth\.value = 0/)
  assert.match(certJobs, /tableWrapWidth\.value = width > 0 \? width : 0/)
  assert.match(certJobs, /:class="\{ 'cert-jobs-wrap--scroll': tableBelowMinWidth \}"/)
})

test('日志弹框使用独立 AbortController，关闭即取消在途请求', () => {
  const fetchLog = section(certJobs, 'const logTail = useLogTailPolling', 'const logLoading')
  assert.match(fetchLog, /signal: logDialogController\?\.signal/)
  assert.doesNotMatch(fetchLog, /jobsPolling\.signal/)
  assert.match(certJobs, /let logDialogController: AbortController \| null = null/)
  assert.match(certJobs, /logDialogController = new AbortController\(\)/)
  const closed = section(certJobs, 'const onLogDialogClosed', 'const refreshLogs')
  assert.match(closed, /logDialogController\?\.abort\(\)/)
})

test('页大小改变引发 current-change 时同参请求只发一次', () => {
  assert.match(auditLog, /@size-change="onPageSizeChange"/)
  assert.match(auditLog, /@current-change="onCurrentPageChange"/)
  const sizeChange = section(auditLog, 'const onPageSizeChange', 'const resetFilters')
  assert.match(sizeChange, /page\.value = 1\s*if \(logsRequestKey\(\) === lastLogsRequestKey\) return\s*fetchLogs\(\)/)
  const currentChange = section(auditLog, 'const onCurrentPageChange', 'const resetFilters')
  assert.match(currentChange, /if \(logsRequestKey\(\) === lastLogsRequestKey\) return/)
  const fetchLogs = section(auditLog, 'const fetchLogs = async', 'onMounted')
  assert.match(fetchLogs, /lastLogsRequestKey = logsRequestKey\(\)/)
})
