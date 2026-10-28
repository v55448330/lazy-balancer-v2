// IP 处置弹框（IPLocationAction）的「自动封禁」区块：IP 命中预置「自动封禁
// 名单」时显示名单/命中条目/到期时间，并可直接取消封禁。
//
// 关键契约：区块**独立于策略面**——策略加载中/加载失败/无策略（例如只有一条
// WAF 规则命中而没有任何 IP 管控策略）时同样必须可见可用，否则运维从安全日志
// 点开的 IP 弹框看不到「已被自动封禁」，解封动作只能绕道安全策略页。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），模板依赖
// element-plus 全局组件——不可在 node 下挂载，故用「行为单源 + 限段文本钉」。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { autobanEntryExpired, autobanEntryRemaining } from '../src/utils/autobanEntry.ts'
import { code, repoCode, section } from './_helpers.ts'

const page = code('src/views/security/IPLocationAction.vue')

const wallClock = (msFromNow: number): string =>
  new Date(Date.now() + msFromNow).toISOString().slice(0, 19).replace('T', ' ')

test('到期判据：DB 墙钟按 UTC 解析，空值/脏值不算到期', () => {
  assert.equal(autobanEntryExpired(wallClock(3 * 3600_000)), false, '未来到期不得判为已到期')
  assert.equal(autobanEntryExpired(wallClock(-60_000)), true, '已过到期时刻必须判为已到期')
  assert.equal(autobanEntryExpired(''), false, '空 expires_at=永久条目')
  assert.equal(autobanEntryExpired('not-a-timestamp'), false, '脏值不得误判到期（后端投影才是真值）')
})

test('剩余时长文案：分钟/小时分钟/天时三档与兜底', () => {
  assert.match(autobanEntryRemaining(wallClock(10 * 60_000)), /^\d+ 分钟$/)
  assert.match(autobanEntryRemaining(wallClock(3 * 3600_000 + 60_000)), /^\d+ 小时 \d+ 分$/)
  assert.match(autobanEntryRemaining(wallClock(2 * 86_400_000 + 3600_000)), /^\d+ 天 \d+ 时$/)
  assert.equal(autobanEntryRemaining(''), '—')
  assert.equal(autobanEntryRemaining('not-a-timestamp'), '—')
  // 已到期不得呈现负剩余（`-3 分钟`）
  assert.equal(autobanEntryRemaining(wallClock(-5 * 60_000)), '0 分钟')
})

test('名单弹框与快捷弹框共用到期判据单源（不得各写一份）', () => {
  const rules = code('src/views/security/SecurityRules.vue')
  assert.match(rules, /import \{[^}]*autobanEntryExpired[^}]*\} from '@\/utils\/autobanEntry'/, 'SecurityRules 必须消费单源')
  assert.doesNotMatch(rules, /const autobanEntryExpired = /, '本地实现必须删除（第二实现会漂移）')
  assert.match(page, /autobanEntryExpired|autobanEntryRemaining/, '快捷弹框必须消费同一单源')
})

test('区块独立于策略面：不在 rows 分支内，且 onPopoverShow 独立加载', () => {
  // 模板：自动封禁区块必须出现在策略卡片分支之前（同一弹层内），而不是
  // `rows.length > 0` 的 else-if 分支或其中
  const rowsAt = page.indexOf('<template v-else-if="rows.length > 0">')
  const blockAt = page.indexOf('class="ipo-sec ipo-autoban"')
  assert.ok(rowsAt > 0 && blockAt > 0, '自动封禁区块与策略卡片分支都必须存在')
  assert.ok(blockAt < rowsAt, '区块必须在策略卡片之前渲染（策略为空/加载中也可见）')
  const block = section(page, '<div v-if="autobanLoading && !autobanHit"', '<div v-if="filterablePolicies.length > 1"')
  assert.doesNotMatch(block, /policiesLoading/, '区块不得依赖策略加载态')

  const show = section(page, 'const onPopoverShow', 'void loadEventCount()')
  assert.match(show, /void loadAutoban\(\)/, '弹层打开必须独立触发自动封禁加载')
})

test('加载路径：preset_autoban 定位名单 → 详情取条目 → entryMatchesIp 匹配', () => {
  assert.match(page, /interface IpListSummary extends IpListOption \{\s*preset_autoban\?: boolean/, '列表行契约须显式声明预置标记')
  const load = section(page, 'const loadAutoban = async', '\n}\n')
  assert.match(load, /preset_autoban === true/, '必须按预置标记识别（不得按名单名硬编码）')
  assert.match(load, /await loadListDetail\(list\.id\)/, '条目（含到期时间）必须走单名单详情请求')
  assert.match(load, /autobanError\.value = true/, '详情/清单失败必须显性化（不得静默当作「未封禁」）')
  assert.match(load, /if \(seq !== autobanSeq\) return/, '快速关开必须丢弃迟到响应')

  const hit = section(page, 'const autobanHit = computed', '\n})')
  assert.match(hit, /\.find\(\(e\) => entryMatchesIp\(e\.value,/, '命中判定必须复用 securityStages 单源（含 CIDR）')
  assert.match(hit, /trimmedIp\.value/, '匹配对象必须是 trim 后的 IP')
})

test('单名单详情请求仍只有一处实现（条目加载器复用同一请求）', () => {
  assert.equal(
    (page.match(/\/security\/ip-lists\/\$\{id\}/g) ?? []).length,
    1,
    '新增的自动封禁详情请求不得复制一份 URLs（契约变化会漂移）',
  )
  assert.match(page, /const loadListDetail = async \(id: number\): Promise<IpListDetailPayload> =>/)
  const entries = section(page, 'const loadListEntries = async \\(id: number\\): Promise<string\\[\\]> =>'.replace(/\\/g, ''), '\n}\n')
  assert.match(entries, /await loadListDetail\(id\)/, '条目加载器必须走同一详情请求')
})

test('取消封禁：确认 → remove-ip → 失效缓存并重取策略与封禁态', () => {
  const unban = section(page, 'const unbanAutoban = async', '\n}\n')
  // 占位先于确认（双击不再叠加两个确认框），finally 释放
  const lockAt = unban.indexOf('autobanUnbanning.value = true')
  const confirmAt = unban.indexOf('ElMessageBox.confirm(')
  assert.ok(lockAt > 0 && confirmAt > lockAt, '在途锁必须先于确认弹框取得')
  assert.match(unban, /finally \{\s*autobanUnbanning\.value = false/, '结束（含取消/失败）必须释放锁')
  assert.match(unban, /remove-ip`, \{ value: hit\.value \}\)/, '按 exact value 调 remove-ip')
  // 写入后：失效共享条目缓存 → 重取策略面 → 重取封禁态（顺序不可倒）
  const invalidateAt = unban.indexOf('invalidateSharedEntriesCache()')
  const policiesAt = unban.indexOf('await loadPolicies()')
  const autobanAt = unban.indexOf('await loadAutoban()')
  assert.ok(invalidateAt > 0 && policiesAt > invalidateAt && autobanAt > policiesAt, '缓存失效→策略→封禁态的顺序')
  // 动作按钮在途锁与重试入口
  assert.match(page, /:loading="autobanUnbanning" @click="unbanAutoban"/)
  assert.match(page, /const retryAutoban = \(\): void => \{ void loadAutoban\(\) \}/)
  // 与 listsError 横幅的唯一重试入口（retryLists）区分：文案不得撞车
  assert.equal((page.match(/@click="retryLists"/g) ?? []).length, 1, '策略区重试入口仍唯一')
})

test('区块呈现名单名/命中条目/到期时间，永久条目不显示剩余', () => {
  const block = section(page, '<div v-if="autobanLoading && !autobanHit"', '<div v-if="filterablePolicies.length > 1"')
  assert.match(block, /自动封禁/, '区块标题')
  assert.match(block, /autoban\?\.listName/, '必须显示名单名')
  assert.match(block, /命中条目：\{\{ autobanHit\.value \}\}/, '必须显示命中的条目值')
  assert.match(block, /到期时间/, '必须显示到期时间')
  assert.match(block, /v-if="!autobanHit\.expires_at"[^>]*>永久/, '永久条目显示「永久」而非空')
  assert.match(block, /formatDate\(autobanHit\.expires_at\)/, '绝对到期时间按站内时区格式化')
  assert.match(block, /解除自动封禁/, '必须提供解除自动封禁动作')
})

test('跨栈：预置名单由 preset_autoban 标记，remove-ip 允许自动封禁名单', () => {
  const go = repoCode('internal/handlers/securityiplists.go')
  assert.match(go, /PresetAutoban bool `json:"preset_autoban"`/, '接口字段名须与前端消费一致')
  assert.match(go, /listName != services\.AutobanPresetListName/, 'remove-ip 的 system 白名单只放行自动封禁名单')
})

// 自动封禁名单编辑弹框（SecurityRules）的「加入时间」列：`formatDate` 输出
// "YYYY-MM-DD HH:mm:ss"（19 字符），原 width=140 在等宽字体下换行成两行。
test('名单弹框「加入时间」列加宽并强制不换行', () => {
  const rules = code('src/views/security/SecurityRules.vue')
  assert.match(rules, /<el-table-column label="加入时间" width="170" align="center" class-name="ip-entry-created">/, '列宽 170 + 单元格 nowrap 类')
  assert.match(rules, /\.ip-entry-created \{ white-space: nowrap; \}/, 'nowrap 必须由表格单元格类提供（el-table 单元格默认换行）')
})

test('自动封禁名单编辑弹框不再显示多余的内置字段说明', () => {
  const rules = code('src/views/security/SecurityRules.vue')
  assert.doesNotMatch(rules, /内置名单字段不可修改/, '冗余描述已删除；字段禁用状态本身已表达该语义')
})


test('自动封禁区块与下方策略筛选/策略区有独立分隔', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.match(page, /\.ipo-autoban \{ margin-bottom: 12px; padding-bottom: 12px; border-bottom:/, '自动封禁区块必须有底部间距和分隔线')
})

test('状态摘要覆盖自动封禁、黑白名单、信任、地域与未命中', () => {
  const headAt = page.indexOf('class="ipo-head"')
  const summaryAt = page.indexOf('class="ipo-summary"')
  const autobanAt = page.indexOf('class="ipo-sec ipo-autoban"')
  assert.ok(headAt > 0 && summaryAt > headAt && autobanAt > summaryAt, '摘要位于头部之后、自动封禁之前')
  for (const label of ['自动封禁生效', '自动封禁未生效', '自动封禁状态未知', '手动黑名单命中', '白名单命中', '信任豁免', '地域策略在用', '未命中当前管控']) {
    assert.ok(page.includes(label), `缺少状态摘要：${label}`)
  }
  const chips = section(page, 'const statusChips = computed', 'const statusIncomplete = computed')
  assert.match(chips, /allRows\.value/, '摘要必须基于未筛选策略，筛选卡片不得隐藏全局命中')
  assert.doesNotMatch(chips, /lastPolicyFilter/, '摘要不得受当前策略筛选影响')
})

test('自动封禁分别读取配置与生效态，名单命中不冒充已封禁', () => {
  const runtime = section(page, 'const loadAutobanRuntime = async', '\n}\n')
  assert.match(runtime, /\/security\/autoban\/status/)
  assert.match(runtime, /\/security\/autoban'/)
  assert.match(runtime, /Promise\.allSettled/, '状态与配置失败不得互相拖垮')
  assert.match(page, /ban_effective \? '已封禁' : '名单命中（未生效）'/)
  assert.match(page, /autobanStatusError\.value \|\| !autobanRuntime\.value\) return '生效状态未知'/)
  const summary = section(page, 'const autobanRuleSummary = computed', '\n})')
  for (const field of ['window_minutes', 'threshold', 'duration', 'scope', 'dry_run']) assert.ok(summary.includes(field), `规则摘要缺少 ${field}`)
  assert.match(summary, /观察模式/)
})

test('到期条目可清理，CIDR 只能跳名单编辑且解除确认限定作用域', () => {
  assert.match(page, /autobanExpired \? '清理过期条目' : '解除自动封禁'/)
  assert.match(page, /autobanExpired \? '已到期，可清理'/)
  assert.match(page, /v-if="autobanHitIsCidr"[^>]*href="#\/security-rules\?tab=ip-lists"/)
  assert.match(page, />编辑 CIDR<\/el-button>/)
  const unban = section(page, 'const unbanAutoban = async', '\n}\n')
  assert.match(unban, /autobanHitIsCidr\.value/, '写入口也必须拒绝静默删除 CIDR 整段')
  assert.match(unban, /只解除自动封禁/)
  assert.match(unban, /清空该 IP 的自动封禁计数/)
  assert.match(unban, /其它拦截源仍可能拦截/)
})

test('快捷动作按当前筛选选策略，无候选禁用且不自动建策略', () => {
  const quickAt = page.indexOf('class="ipo-quick"')
  const filterAt = page.indexOf('class="ipo-filter"')
  const autobanAt = page.indexOf('class="ipo-sec ipo-autoban"')
  assert.ok(autobanAt > 0 && quickAt > autobanAt && filterAt > quickAt, '快捷区位于自动封禁之后、策略筛选之前')
  for (const label of ['加入黑名单', '加入白名单', '加入信任']) assert.ok(page.includes(label), `缺少${label}`)
  const candidates = section(page, 'const selectedPolicyCandidates = computed', 'const trustedSourceRows = computed')
  assert.match(candidates, /lastPolicyFilter\.value === 'all' \|\| p\.id === lastPolicyFilter\.value/)
  for (const name of ['quickDenyPolicy', 'quickAllowPolicy', 'quickTrustPolicy']) assert.ok(candidates.includes(`const ${name}`), `缺少${name}`)
  assert.match(page, /!quickDenyPolicy\.value/)
  assert.match(page, /!quickAllowPolicy\.value/)
  assert.match(page, /!quickTrustPolicy\.value/)
  assert.match(page, /请先创建并绑定/)
  const run = section(page, 'const runQuickAction =', '\n}\n')
  assert.match(run, /ensureListAndJoin\(policy, trimmedIp\.value, side\)/, '三侧必须复用确认/幂等/刷新共享实现')
  assert.match(page, /不会自动创建策略/)
})

test('快捷动作抑制策略卡重复添加，但保留移除与取消信任', () => {
  const actions = section(page, 'const rowActions = (row: RowView)', '\n}\n')
  assert.match(actions, /row\.canAddTrust && row\.policy\.id !== quickTrustPolicy\.value\?\.id/)
  assert.match(actions, /row\.canAssociate && row\.policy\.id !== quickDenyPolicy\.value\?\.id/)
  assert.match(actions, /row\.canAssociateAllow && row\.policy\.id !== quickAllowPolicy\.value\?\.id/)
  assert.match(actions, /if \(row\.canRemove\)/, '黑名单/白名单移除动作不得被快捷区抑制')
  assert.match(actions, /key: 'cancel-trust'/, '策略卡取消信任仍需保留')
})

test('全局信任展示所有来源并提供取消，不再重复加入或承诺恢复拦截', () => {
  assert.match(page, /const trustedSourceRows = computed\(\(\) => allRows\.value\.filter\(\(row\) => row\.inTrust && row\.trustEnabled\)\)/)
  assert.match(page, /信任来源：\{\{ trustSourceNames \}\}/)
  assert.match(page, /v-if="!ipTrustedAnywhere"[^>]*:content="quickTrustTip"/)
  assert.match(page, /v-for="row in trustedSourceRows" v-else/)
  assert.match(page, />取消信任 · \{\{ row\.policy\.name \}\}<\/el-button>/)
  assert.match(page, /取消信任（恢复常规安全评估）/)
  assert.doesNotMatch(page, /恢复拦截/)
})

test('白名单命中不追加信任后缀，deny 命中与 allow 交集外仍追加', () => {
  const allow = section(page, "} else if (policy.ip_acl_mode === 'allow')", "} else if (policy.ip_acl_mode === '绕过')")
  const allowHit = section(allow, 'if (inList) {', '} else {')
  assert.doesNotMatch(allowHit, /exemptHitSuffix|passthruSuffix/)
  const allowMiss = allow.slice(allow.indexOf('} else {'))
  assert.match(allowMiss, /exemptHitSuffix \+ passthruSuffix/)
  const deny = section(page, "if (policy.ip_acl_mode === 'deny')", "} else if (policy.ip_acl_mode === 'allow')")
  assert.match(deny, /exemptHitSuffix \+ passthruSuffix/)
})

test('策略失败可重载，阶段 0 空态位置与 offstage 文案符合可见分组', () => {
  assert.match(page, /@click="retryPolicies">重新加载<\/el-button>/)
  assert.match(page, /const retryPolicies = \(\): void => \{ void loadPolicies\(\) \}/)
  const groupAt = page.indexOf('v-for="group in visibleGroups"')
  const stage0At = page.indexOf('v-if="!stage0BoundAny && lastPolicyFilter === \'all\' && visibleGroups.length > 0"')
  assert.ok(groupAt > 0 && stage0At > groupAt, '阶段 0 空态必须位于策略组之后')
  assert.match(page, /当前仅有限流\/WAF 策略，不涉及 IP 管控/)
})

test('键盘可打开，弹框按视口限宽且自动封禁/快捷区保留分隔', () => {
  assert.match(page, /@keydown\.enter\.prevent="activateOnce\(\$event, \(\) => openFromKeyboard\(\$event\)\)"/)
  assert.match(page, /@keydown\.space\.prevent="activateOnce\(\$event, \(\) => openFromKeyboard\(\$event\)\)"/)
  assert.match(page, /const openFromKeyboard = \(event: KeyboardEvent\)/)
  assert.match(page, /:width="400"/)
  assert.match(page, /max-width: calc\(100vw - 24px\)/)
  assert.match(page, /@media \(max-width: 420px\)/)
  assert.match(page, /\.ipo-quick \{[^}]*border-bottom:/)
  assert.match(page, /\.ip-clickable:focus-visible/)
})

test('快捷黑白名单动作不重复添加：已在名单中时禁用并显示已在名单', () => {
  const page = code('src/views/security/IPLocationAction.vue')
  assert.match(page, /const hasDenyHit = computed/)
  assert.match(page, /const hasAllowHit = computed/)
  assert.match(page, /hasDenyHit\.value \? null : selectedPolicyCandidates/)
  assert.match(page, /hasAllowHit\.value \? null : selectedPolicyCandidates/)
  assert.match(page, /quickDenyLabel = computed\(\(\) => hasDenyHit\.value \? '已在黑名单' : '加入黑名单'/)
  assert.match(page, /quickAllowLabel = computed\(\(\) => hasAllowHit\.value \? '已在白名单' : '加入白名单'/)
})
