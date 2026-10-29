// 历史 WEB-VIEWS-CORE 验收：
//   A. 可抽出的纯逻辑做 node 行为测试（向导阶段覆盖/复制 Host、审计筛选参数、
//      API 密钥白名单归一、分页夹紧）；
//   B. 视图内行为（错误态/CSS 映射/权限态）沿用本仓既有「源码钉」形态。
//      真实前提：node --test 没有 .vue 装载器（本套件禁止静态 import .vue），
//      且这些模板依赖 element-plus 全局组件与样式——不可在 node 下挂载；
//      可判定的语义一律抽 utils 行为求值，其余用「限段 + 调用点」文本钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { nextTick, ref } from 'vue'

import { copyRuleHostHeader, newRuleWizardStageOverrides, stageBlockPageOverrides, stageBlockPagePatch } from '../src/utils/ruleWizard.ts'
import { buildAuditLogParams } from '../src/utils/auditLogFilters.ts'
import { normalizeCidr, serializeWhitelist } from '../src/utils/apiKeyWhitelist.ts'
import { useClampedPagination } from '../src/composables/useClampedPagination.ts'
import { repoCode, section, code, openTags, stripComments, codeSection } from './_helpers.ts'

const rules = code('src/views/Rules.vue')
const dashboard = code('src/views/Dashboard.vue')
const auditLog = code('src/views/AuditLog.vue')
const caddyConfig = code('src/views/CaddyConfig.vue')
const users = code('src/views/Users.vue')
const keys = code('src/views/Keys.vue')

// ============ 阶段拦截页覆盖的共享键集 ============

test('新建规则的阶段拦截页覆盖恒为 0（4 键全零）', () => {
  assert.deepEqual(newRuleWizardStageOverrides(), {
    block_page_stage1_id: 0,
    block_page_stage1_status: 0,
    block_page_stage3_id: 0,
    block_page_stage3_status: 0,
  })
})

test('编辑/复制水合保留源规则的阶段覆盖，缺键按 0', () => {
  assert.deepEqual(stageBlockPageOverrides({
    block_page_stage1_id: 7,
    block_page_stage1_status: 403,
    block_page_stage3_id: 9,
    block_page_stage3_status: 451,
  }), {
    block_page_stage1_id: 7,
    block_page_stage1_status: 403,
    block_page_stage3_id: 9,
    block_page_stage3_status: 451,
  })
  assert.deepEqual(stageBlockPageOverrides({}), newRuleWizardStageOverrides())
  assert.deepEqual(stageBlockPageOverrides({ block_page_stage1_id: null }), newRuleWizardStageOverrides())
})

test('水合/新建/重置三处共用同一键集（双向清单，防再次分叉）', () => {
  const hydrate = section(rules, 'const wizardFormFromRule', 'const buildRuleConfigView')
  assert.match(hydrate, /\.\.\.stageBlockPageOverrides\(fullRule\)/)
  // 水合里不得再逐键手写（逐键手写正是与重置清单分叉的根因）
  assert.doesNotMatch(hydrate, /block_page_stage1_id: fullRule\./)

  const openWizard = section(rules, 'const openWizard = async', 'const resetWizard')
  const newBranch = openWizard.slice(openWizard.indexOf('} else {', openWizard.indexOf('if (rule) {')))
  assert.ok(newBranch.length > 0, 'missing new-rule branch')
  assert.match(newBranch, /\.\.\.newRuleWizardStageOverrides\(\)/)

  const reset = section(rules, 'const resetWizard = () => {', 'const beforeWizardClose')
  assert.match(reset, /Object\.assign\(wizardForm, newRuleWizardStageOverrides\(\)\)/)

  // 编辑载荷只提交相对快照变化的键（后端 nil=保留）；新建/复制显式全量
  const payload = section(rules, 'const data: UpdateRuleRequest = {', 'request.')
  assert.match(payload, /isCopyMode\.value \|\| !editingRule\.value/)
  assert.match(payload, /\.\.\.\(\(isCopyMode\.value \|\| !editingRule\.value\)/)
  assert.match(payload, /stageBlockPageOverrides\(wizardForm\)/)
  assert.match(payload, /stageBlockPagePatch\(wizardForm, wizardStagePageSnapshot\.value\)/)
  assert.doesNotMatch(payload, /block_page_stage1_id: wizardForm\.block_page_stage1_id \|\| 0/, '编辑态不得无条件回写四字段（旧快照回退）')
})

test('阶段页覆盖差异门：只提交相对打开快照变化的键', () => {
  const snapshot = {
    block_page_stage1_id: 7,
    block_page_stage1_status: 403,
    block_page_stage3_id: 9,
    block_page_stage3_status: 451,
  }
  // 未修改 → 空 patch（后端 nil=保留）
  assert.deepEqual(stageBlockPagePatch({ ...snapshot }, snapshot), {})
  // 仅阶段 1 改页 → 只提交 stage1 两个键
  assert.deepEqual(stageBlockPagePatch({ ...snapshot, block_page_stage1_id: 8 }, snapshot), { block_page_stage1_id: 8 })
  // 清空覆盖（id/status 归 0）
  assert.deepEqual(
    stageBlockPagePatch({ ...snapshot, block_page_stage3_id: 0, block_page_stage3_status: 0 }, snapshot),
    { block_page_stage3_id: 0, block_page_stage3_status: 0 },
  )
  // 缺键的当前值按 0 归一（与保存载荷同口径）
  assert.deepEqual(stageBlockPagePatch({}, newRuleWizardStageOverrides()), {})
  assert.deepEqual(
    stageBlockPagePatch({ block_page_stage1_id: 3 }, newRuleWizardStageOverrides()),
    { block_page_stage1_id: 3 },
  )
})

// ============ 复制路径携带规则级回源 Host ============

test('复制载荷的 host_header 取源规则值（空/缺省→空串）', () => {
  assert.equal(copyRuleHostHeader({ host_header: 'backend.internal' }), 'backend.internal')
  assert.equal(copyRuleHostHeader({ host_header: '' }), '')
  assert.equal(copyRuleHostHeader({ host_header: null }), '')
  assert.equal(copyRuleHostHeader({}), '')
})

test('复制向导从源规则取值，仅复制分支把 host_header 编入载荷', () => {
  const copyWizard = section(rules, 'const openCopyWizard', 'const viewConfig')
  assert.match(copyWizard, /copySourceHostHeader\.value = copyRuleHostHeader\(fullRule\)/)
  assert.match(rules, /\.\.\.\(isCopyMode\.value \? \{ host_header: copySourceHostHeader\.value \} : \{\}\)/)
  // 新建/编辑不得发送该键（Update 的 nil=保留语义，新建本就无覆盖）
  const payload = section(rules, 'const data: UpdateRuleRequest = {', 'request.')
  assert.equal((payload.match(/host_header:/g) ?? []).length, 1, 'payload must carry host_header only via the copy spread')
})

// ============ 关闭规则日志弹框即停定时器 ============

test('onRuleLogDialogClosed 停本地轮询定时器（不再 5s 空转）', () => {
  const closed = codeSection('src/views/Rules.vue', 'const onRuleLogDialogClosed = () => {', '// 日志尾轮询收敛')
  assert.match(closed, /stopRuleLogPolling\(\)/)
  assert.match(closed, /ruleLogTail\.stop\(\)/)
})

test('日志与统计共用弹框级自动刷新工具栏', () => {
  const dialog = section(rules, 'v-model="ruleLogDialogVisible"', '</el-dialog>')
  const toolbarAt = dialog.indexOf('<div class="log-toolbar">')
  const tabsAt = dialog.indexOf('<el-tabs')
  assert.ok(toolbarAt >= 0 && tabsAt >= 0, '日志弹框必须有共享工具栏与标签页')
  assert.ok(toolbarAt < tabsAt, '自动刷新与手动刷新必须位于两个标签页之外，切到统计仍可见可操作')
  assert.equal((dialog.match(/v-model="ruleLogAutoRefresh"/g) ?? []).length, 1, '两个标签页必须复用同一开关实例')
  assert.equal((dialog.match(/@click="refreshRuleLogs"/g) ?? []).length, 1, '两个标签页必须复用同一手动刷新入口')
})

// ============ 配置预览负载策略走标签单源 ============

test('配置预览使用 getStrategyLabel，不再直出枚举键', () => {
  assert.match(rules, /\{\{ getStrategyLabel\(ruleConfig\.strategy\) \}\}/)
  assert.doesNotMatch(rules, /\{\{ ruleConfig\.strategy \}\}/)
})

// ============ 采集失败的规则行必须可见 ============

test('排行榜纳入采集失败行并排在正常行之后（逐列「采集失败」可达）', () => {
  const rank = section(dashboard, 'const rankableRules = computed', 'const sortedRules')
  assert.match(rank, /ruleMetricsUnavailable\.value\[rule\.caddy_id\] === true/, '失败行必须进入可排行集合')
  assert.match(rank, /if \(aUnavailable !== bUnavailable\) return aUnavailable \? 1 : -1/, '失败行排末尾')
  assert.match(rank, /return ruleRankValue\(b\.caddy_id\) - ruleRankValue\(a\.caddy_id\)/, '正常行仍按指标降序')
  const sorted = section(dashboard, 'const sortedRules = computed', 'const rulesEmptyText')
  assert.match(sorted, /ranked\.slice\(0, 10\), \.\.\.failed/, '失败行不占 10 个名额，恒追加在末尾')
  // 逐列「采集失败」分支保持存在（现为可达态）。必须逐列判定：按出现次数
  // 代理时，两列各有 title+文案两处命中，删掉整列后仍有 6 处 ≥ 5 → 守卫假绿，
  // 该列采集失败会静默渲染成 `-`（把「没采到」读成「零流量」）。
  for (const label of ['请求数', '状态码', '入站流量', '出站流量', '处理中']) {
    const column = section(dashboard, `<el-table-column label="${label}"`, '</el-table-column>')
    assert.match(
      column,
      /ruleMetricsUnavailable\[row\.caddy_id\]/,
      `「${label}」列缺采集失败分支——采不到的单元格会渲染成 -（与零流量不可区分）`,
    )
  }
})

// ============ 历史弹框错误态与空态分文案 ============

test('历史统计失败置错误态并给重试，空态文案不再代表失败', () => {
  assert.match(dashboard, /ruleHistoryError\.value = error instanceof Error \? error\.message/)
  const dialog = section(dashboard, '<el-dialog v-model="ruleHistoryVisible"', '</el-dialog>')
  assert.match(dialog, /v-if="ruleHistoryError"/)
  assert.match(dialog, /@click="fetchRuleHistory"/)
  // 错误态分支内不得再出现「该时间范围内暂无数据」
  const errorBranch = dialog.slice(dialog.indexOf('v-if="ruleHistoryError"'), dialog.indexOf('<template v-else>', dialog.indexOf('v-if="ruleHistoryError"')))
  assert.doesNotMatch(errorBranch, /该时间范围内暂无数据/)
  assert.match(dialog, /图表为空不代表该时间范围没有流量/)
})

// ============ 节点角色三态的派生/渲染由 dashboardNodeRole.spec 唯一承担 ============

// ============ 未知状态兑现灰底样式 ============

test('caddyStatus 映射样式类，unknown→info（.status-tag.info 生效）', () => {
  assert.match(dashboard, /const caddyStatusClass = computed\(\(\) => caddyStatus\.value === 'running' \? 'running' : caddyStatus\.value === 'stopped' \? 'stopped' : 'info'\)/)
  assert.match(dashboard, /:class="\['status-tag', caddyStatusClass\]"/)
  assert.match(dashboard, /\.status-tag\.info \{/)
})

// ============ 审计日志列表错误态 ============

test('审计日志加载失败显性化（横幅 + 重试 + 空态分文案）', () => {
  const fetchLogs = section(auditLog, 'const fetchLogs = async', 'onMounted(')
  assert.match(fetchLogs, /loadError\.value = false/)
  assert.match(fetchLogs, /if \(currentRequestSeq === requestSeq\) loadError\.value = true/, '仅最新请求可置错误态')
  assert.match(auditLog, /v-if="loadError"/)
  assert.match(auditLog, /@click="fetchLogs"/)
  assert.match(auditLog, /操作日志加载失败：列表为空不代表没有日志/)
  assert.match(auditLog, /loadError \? '日志加载失败' : '暂无操作日志'/)
})

// ============ 消费 /audit-logs/options 的 partial ============

test('部分下拉（partial）与整体失败都有可见提示与重试', () => {
  assert.match(auditLog, /optionsPartial\.value = d\?\.partial === true/)
  assert.match(auditLog, /optionsError\.value = true/)
  assert.match(auditLog, /const optionsIncomplete = computed\(\(\) => optionsPartial\.value \|\| optionsError\.value\)/)
  const selects = auditLog.slice(auditLog.indexOf('<div class="filter-bar">'), auditLog.indexOf('<el-table'))
  assert.equal((selects.match(/optionsIncomplete \?/g) ?? []).length, 3, '三个下拉的 placeholder 都要显性化')
  assert.match(auditLog, /@click="fetchOptions"/)
})

// 日期范围筛选的非 scoped 全局类必须按页前缀命名：两页曾共用
// .filter-date-range 但宽度不同（360/320），非 scoped 块互相覆盖，渲染结果
// 取决于导航顺序。Ruling：按页前缀改名（宽度不一，不上提 main.css 统一）。
test('日期范围筛选全局类按页前缀命名（同名全局类冲突清零）', () => {
  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(auditLog, /class="audit-filter-date-range"/)
  assert.match(auditLog, /\.audit-filter-date-range\.el-date-editor/)
  assert.match(events, /class="events-filter-date-range"/)
  assert.match(events, /\.events-filter-date-range\.el-date-editor/)
  for (const [name, text] of [['AuditLog', auditLog], ['SecurityEvents', events]] as const) {
    assert.doesNotMatch(text, /class="filter-date-range"|\.filter-date-range\./, `${name} 不得再使用无前缀全局类`)
  }
})

// ============ 配置预览按角色收口 ============

test('非管理员渲染权限空态且不发请求（深链同样覆盖）', () => {
  assert.match(caddyConfig, /const canViewConfig = computed\(\(\) => authStore\.user\?\.role === 'admin'\)/)
  assert.match(caddyConfig, /v-if="!canViewConfig"/)
  assert.match(caddyConfig, /仅管理员可查看 Caddy 配置预览/)
  assert.match(caddyConfig, /if \(canViewConfig\.value\) void fetchCaddyConfig\(\)/)
  assert.doesNotMatch(caddyConfig, /onMounted\(\(\) => void fetchCaddyConfig\(\)\)/)
  // 角色补齐后自动补拉
  assert.match(caddyConfig, /watch\(canViewConfig, \(allowed\) =>/)
})

// ============ 用户页职责边界与 MFA 自助归属 ============

test('用户页：非管理员只读——操作位保留仅禁用，个人自助迁出', () => {
  assert.doesNotMatch(users, /openMfaBinding|mfaBinding|isSelfRow|selfServiceBlocked/, '个人自助与本人行特例已迁出用户页')
  // 只读语义=可见但禁用，不是隐藏：操作列常驻，按钮门为 isReadOnly。
  assert.match(users, /<el-table-column label="操作" width="200"/, '操作列必须常驻')
  // 绑定目标元素：操作列内 @click="editUser(row)" 的开标签（文件级定长窗口会把
  // 「某处 disabled + 附近出现编辑」当命中——同文件新建按钮/弹框表单也是同一
  // 表达式，按钮加一个属性即越窗假红）。
  const actions = section(users, '<el-table-column label="操作"', '</el-table-column>')
  const editButtons = openTags(actions, 'el-button').filter((tag) => /@click="editUser\(row(?: as [A-Za-z]+)?\)"/.test(tag))
  assert.equal(editButtons.length, 1, '操作列里的编辑按钮必须唯一可定位')
  assert.match(editButtons[0]!, /:disabled="[^"]*isReadOnly/, '编辑按钮只读禁用')
  assert.match(users, /:disabled="isReadOnly \|\| row\.auth_provider === 'oidc' \|\| !row\.mfa_enabled/, 'MFA 按钮只读/不可用态禁用')
  assert.doesNotMatch(users, /v-if="isAdmin"/, '不得用隐藏替代只读')
  assert.match(users, /\/users\/\$\{row\.id\}\/mfa\/reset/, '管理员重置 MFA 仍走用户管理端点')
})

test('MFA 绑定向导：6 位门、在途禁关、恢复码关闭确认', () => {
  const wizard = code('src/components/MfaBindingWizard.vue')
  assert.match(wizard, /:disabled="code\.length !== 6"/)
  assert.match(wizard, /if \(code\.value\.length !== 6 \|\| loading\.value\) return/)
  // 在途禁关与恢复码步确认收敛进一次性凭据守卫单源（utils/oneTimeSecretGuard）
  assert.match(wizard, /blocked: \(\) => loading\.value/, '在途提交期间禁止关闭')
  assert.match(wizard, /skip: \(\) => step\.value !== 2/, '未到恢复码步（无秘密可丢）直接关闭')
  assert.match(wizard, /恢复代码仅此一次显示/, '恢复码步关闭必须确认已保存')
  assert.match(wizard, /:before-close="beforeClose"/)
})

test('个人资料：MFA 自助（启用/关闭/重置）走 /auth/mfa 端点', () => {
  const profile = code('src/components/ProfileDialog.vue')
  assert.match(profile, /\/auth\/mfa\/setup/)
  assert.match(profile, /\/auth\/mfa\/disable/)
  assert.match(profile, /const mfaEnabled = computed/)
  assert.match(profile, /:disabled="isReadOnly"/, '从节点/未知态保持只读')
})

test('resetPassword 删除 lbOpen 时代残留的 cancel/close 分支', () => {
  const reset = section(users, 'const resetPassword = async', 'const resetMfa = async')
  assert.doesNotMatch(reset, /e === 'cancel' \|\| e === 'close'/, 'lbOpen 以 {ok:false} resolve，不会 reject 字符串')
  assert.match(reset, /if \(!r\.ok\) return/)
})

test('用户页重置密码：行对象签名 + 请求路径内插数字 id', () => {
  // 回归原型：模板传整行、签名收 id——请求路径变成 /users/[object Object]/reset-password，
  // 确认框目标名也恒空（当时模板属性不参与类型检查）。类型门开启后插槽 row 由
  // `as UserListItem` 收窄、签名漂移会在 vue-tsc 报错，但「请求路径用 row.id」
  // 属运行期拼接，仍须由本断言钉住——断言落在实际请求路径与被点名的目标上，
  // 而非「函数存在」。
  const reset = section(users, 'const resetPassword = async', 'const resetMfa = async')
  assert.match(reset, /const resetPassword = async \(row: UserListItem\)/, '签名收整行（与 deleteUser/resetMfa 同口径）')
  assert.match(reset, /request\.post\(`\/users\/\$\{row\.id\}\/reset-password`/, '请求路径必须内插行对象 id')
  assert.doesNotMatch(reset, /\/users\/\$\{id\}\/reset-password/, '不得再内插局部 id（签名与调用点漂移即回归）')
  assert.match(reset, /为「\$\{row\.username\}」设置新密码/, '确认框必须点名目标用户')
  assert.match(users, /@click="resetPassword\(row(?: as [A-Za-z]+)?\)"/, '调用点传整行对象（断言只抹平 DefaultRow 类型，不改变实参）')
})

// ============ 纯逻辑抽出后的行为测试 ============

test('审计筛选参数——空值不上送、空白剥离、时间半开区间', () => {
  assert.deepEqual(buildAuditLogParams({
    timeRange: null, username: '', action: '', resource: '', ip: '', keyword: '',
  }, 1, 20), { page: 1, page_size: 20 })

  assert.deepEqual(buildAuditLogParams({
    timeRange: ['2026-01-01 00:00:00', ''],
    username: '  admin ',
    action: '',
    resource: '规则 ',
    ip: '',
    keyword: '  ',
  }, 3, 50), {
    page: 3,
    page_size: 50,
    start_time: '2026-01-01 00:00:00',
    username: 'admin',
    resource: '规则',
  })
})

test('审计筛选参数——时间半开区间两端各自独立上送', () => {
  const empty = { username: '', action: '', resource: '', ip: '', keyword: '' }
  // 仅 end：半开区间的右端必须能单独上送（后端对空端不加条件）
  assert.deepEqual(buildAuditLogParams({ ...empty, timeRange: ['', '2026-02-01 00:00:00'] }, 1, 20), {
    page: 1,
    page_size: 20,
    end_time: '2026-02-01 00:00:00',
  })
  // 两端都填：逐字上送
  assert.deepEqual(
    buildAuditLogParams({ ...empty, timeRange: ['2026-01-01 00:00:00', '2026-01-31 23:59:59'] }, 1, 20),
    { page: 1, page_size: 20, start_time: '2026-01-01 00:00:00', end_time: '2026-01-31 23:59:59' },
  )
  // 时间串不做前端 trim：空白/畸形值由后端解析层统一 TrimSpace 后归空或 400
  // （「静默丢弃时间条件」已在后端按畸形输入改 400 收敛）——前端另加一套 trim 只会
  // 形成第二份边界语义。
  assert.match(
    repoCode('internal/handlers/auditlog.go'),
    /parseBoundary := func\(raw, endOfDay string\)[\s\S]*?raw = strings\.TrimSpace\(raw\)/,
    '时间边界的前端免 trim 前提是后端解析层自行 TrimSpace——该前提消失则本用例与前端实现都要重估',
  )
})

test('白名单 CIDR 归一（IPv4→/32、IPv6→/128、已带前缀保留）', () => {
  assert.equal(normalizeCidr(' 192.168.1.10 '), '192.168.1.10/32')
  assert.equal(normalizeCidr('2001:db8::1'), '2001:db8::1/128')
  assert.equal(normalizeCidr('10.0.0.0/8'), '10.0.0.0/8')
  assert.equal(normalizeCidr('   '), '')
})

test('白名单序列化——忽略空行、报错带原始行号、非法行不落任何值', () => {
  assert.deepEqual(serializeWhitelist('192.168.1.10\n\n10.0.0.0/8\n'), {
    value: ['192.168.1.10/32', '10.0.0.0/8'],
    error: '',
  })
  assert.deepEqual(serializeWhitelist('192.168.1.10\n\nnot-an-ip'), {
    value: [],
    error: '第 3 行 IP 或 CIDR 格式不正确',
  })
  assert.deepEqual(serializeWhitelist(''), { value: [], error: '' })
})

test('分页越界自动回夹（用户列表改用共享 composable）', async () => {
  const items = ref(Array.from({ length: 12 }, (_, index) => ({ id: index + 1 })))
  const page = ref(3)
  const pageSize = ref(10)
  // useClampedPagination 只用 watch/computed（无生命周期钩子），脱离组件实例直接
  // 调用即可测真实回夹行为（SSR 渲染结束会销毁 effect scope，watch 不再触发）。
  const { pagedItems } = useClampedPagination(items, page, pageSize)
  assert.equal(page.value, 2, '初始越界页立即回夹到最大页')
  assert.deepEqual(pagedItems.value.map((row) => row.id), [11, 12])

  items.value = items.value.slice(0, 5)
  await nextTick()
  assert.equal(page.value, 1, '列表收缩后回夹')
  assert.equal(pagedItems.value.length, 5)

  assert.match(users, /useClampedPagination\(users, currentPage, pageSize\)/)
  assert.doesNotMatch(users, /users\.value\.slice\(start, start \+ pageSize\.value\)/, '不得保留手写切片')
})

test('分页边界双向夹紧：page<1 不回落到列表尾部', async () => {
  const items = ref(Array.from({ length: 25 }, (_, index) => ({ id: index + 1 })))
  const pageSize = ref(10)
  // page=-1 在只做上界夹紧的实现里会让 slice 的负下标算出倒数第二页（静默错行），
  // page=0 则是负下标 + 空切片（看似「没数据」）。
  for (const initial of [0, -1, -99]) {
    const page = ref(initial)
    const { pagedItems } = useClampedPagination(items, page, pageSize)
    assert.equal(page.value, 1, `初始 page=${initial} 必须夹到 1`)
    assert.deepEqual(pagedItems.value.map((row) => row.id), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], `page=${initial} 必须返回首页切片`)
  }
  // 运行时写入越界（外部把 page 置 0/-1）同样立即回夹
  const page = ref(2)
  const { pagedItems } = useClampedPagination(items, page, pageSize)
  assert.deepEqual(pagedItems.value.map((row) => row.id), [11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
  page.value = -1
  await nextTick()
  assert.equal(page.value, 1)
  assert.equal(pagedItems.value[0].id, 1, '越界写入后切片必须回到首页，不得落到尾部')
})

test('白名单逻辑单源（视图不再内联实现）', () => {
  assert.match(keys, /import \{ parseWhitelist, serializeWhitelist \} from '@\/utils\/apiKeyWhitelist'/)
  assert.doesNotMatch(keys, /const serializeWhitelist = /)
  assert.doesNotMatch(keys, /const normalizeCidr = /)
  // 审计筛选参数同样单源
  assert.match(auditLog, /import \{ buildAuditLogParams \} from '@\/utils\/auditLogFilters'/)
  assert.doesNotMatch(auditLog, /const buildParams = \(\) => \{\n/)
})

// 只读 Key 的可见工具集与后端单一事实源（3 个读探测）一致：写语义的
// test_ca_provider / test_certificate_config 不得再被宣称为可用。
test('只读 Key 工具清单与后端只读探测集一致', () => {
  // 权威集合 = internal/mcpserver/tool_visibility.go 的 ReadOnlyProbeTools
  // （读探测 POST 白名单）。此前只钉 Keys.vue 自己的文案（模板文本与自身一致），
  // 后端增删探测工具时文案零感知——这里逐名对表 + 数量对表。
  const visibility = repoCode('internal/mcpserver/tool_visibility.go')
  const block = section(visibility, 'var ReadOnlyProbeTools = map[string]struct{}{', '\n}')
  const probeTools = [...block.matchAll(/"([a-z0-9_]+)":\s*\{\},/g)].map((match) => match[1]).sort()
  assert.ok(probeTools.length > 0, '后端只读探测集必须可解析（marker 漂移会让守卫静默失效）')
  const claim = keys.match(/(\d+) 个读探测 POST 工具（([^）]*)）/)
  assert.ok(claim, 'Keys.vue 必须声明只读探测 POST 工具清单')
  // 括号内先以「；」接说明（写语义工具不在此列），清单本体在其前。
  const claimed = claim[2].split('；')[0].split(' / ').map((name) => name.trim()).sort()
  assert.deepEqual(claimed, probeTools, '文案清单必须与后端只读探测集逐一相同')
  assert.equal(Number(claim[1]), probeTools.length, '文案数量必须等于后端集合成员数')
  // 不再负钉历史数值（原 `/5 个读探测 POST 工具/`）：上面两条正反双向对表已完整
  // 覆盖该不变量，硬编码「5」只会让后端合法扩展到 5 个探针时假红。
})

// 本套件的前提守卫：node --test 没有 .vue 装载器，spec 一律不得 import SFC
// （引入 loader 时本用例转红，提醒同步更正各 spec 的「文本钉」前提注释）。
// 三种形态都要拦：单行静态 import、跨行静态 import、动态 import()。
const VUE_STATIC_IMPORT = /(?:^|\n)\s*(?:import|export)\b[\s\S]*?from\s+['"][^'"]+\.vue['"]/
const VUE_SIDE_EFFECT_IMPORT = /(?:^|\n)\s*import\s+['"][^'"]+\.vue['"]/
const VUE_DYNAMIC_IMPORT = /\bimport\s*\(\s*['"][^'"]+\.vue['"]\s*\)/
const vueImportOffender = (text: string): boolean => {
  const body = stripComments(text)
  return VUE_STATIC_IMPORT.test(body) || VUE_SIDE_EFFECT_IMPORT.test(body) || VUE_DYNAMIC_IMPORT.test(body)
}

test('spec 不得 import .vue（SFC 无 node 装载器）', () => {
  const offenders: string[] = []
  const specDir = new URL('./', import.meta.url)
  // 只扫 spec 文件：tests/ 下可有 fixtures 子目录（跨栈数据表），直接读目录会 EISDIR。
  for (const entry of readdirSync(specDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue
    if (vueImportOffender(readFileSync(new URL(entry.name, specDir), 'utf8'))) offenders.push(entry.name)
  }
  assert.deepEqual(offenders, [], 'spec 出现 .vue 导入——node 无法装载，需改为 utils 行为求值或文本钉')
})

test('.vue 导入守卫覆盖单行/跨行/副作用/动态四形态（元测试）', () => {
  // 样本文本用 <vue> 占位再替换：否则本文件自己含被禁字面量，会被上方守卫判红。
  const sample = (text: string): string => text.split('<vue>').join('.vue')
  assert.equal(vueImportOffender(sample("import Rules from '../src/views/Rules<vue>'")), true)
  assert.equal(
    vueImportOffender(sample("import {\n  Rules,\n} from '../src/views/Rules<vue>'")),
    true,
    '跨行静态 import 曾被放过（原正则要求整句同行）',
  )
  assert.equal(vueImportOffender(sample("import '../src/views/Rules<vue>'")), true)
  assert.equal(vueImportOffender(sample("const mod = await import('../src/views/Rules<vue>')")), true)
  // 注释里的写法不得误伤（剥注释后不应命中）
  assert.equal(vueImportOffender(sample("// import Rules from '../src/views/Rules<vue>'\nconst a = 1")), false)
  // 非 .vue 的导入照常放行
  assert.equal(vueImportOffender("import { ref } from 'vue'"), false)
  assert.equal(vueImportOffender("import { section } from './_helpers.ts'"), false)
  assert.equal(vueImportOffender(sample("const doc = 'src/views/Rules<vue>'")), false)
})

test('用户页：初始化管理员不可删除/禁用（标记由列表响应透出）', () => {
  const users = code('src/views/Users.vue')
  const types = code('src/types/index.ts')
  // 列表响应必须携带标记，否则前端无法区分「保护行」与普通管理员。
  assert.match(types, /is_setup_admin\?: boolean/, 'UserListItem 必须声明 is_setup_admin')
  // 启停与删除两处：内容提示 + 禁用条件都要覆盖初始化管理员。
  assert.match(users, /系统初始化管理员不可禁用/, '状态开关须给出不可禁用原因')
  assert.match(users, /isReadOnly \|\| row\.is_setup_admin \|\| switchingIds\.has\(row\.id\)/, '状态开关须对初始化管理员禁用')
  assert.match(users, /系统初始化管理员不可删除/, '删除按钮须给出不可删除原因')
  assert.match(users, /isReadOnly \|\| row\.is_setup_admin \|\| row\.id === authStore\.user\?\.id/, '删除按钮须对初始化管理员禁用')
  // 第三个保护面：编辑弹框的角色下拉（后端 protected 恒 400「不可降级」）
  assert.match(users, /const roleLocked = computed\(\(\) => editingSelf\.value \|\| editingUser\.value\?\.is_setup_admin === true\)/)
  assert.match(users, /<el-select v-model="form\.role" style="width: 100%" :disabled="roleLocked">/)
  assert.match(users, /系统初始化管理员不可降级/)
})
