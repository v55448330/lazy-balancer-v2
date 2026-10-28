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
  assert.match(block, /取消封禁/, '必须提供取消封禁动作')
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
