// 自动封禁状态卡黄条判据（行为化：原源码
// 正则断言改为纯函数行为断言）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { autobanStateLabel, autobanStatValue, isAutobanIneffective, suggestionBand } from '../src/utils/autobanStatus.ts'
import { code, elementSlice, repoCode, section } from './_helpers.ts'

test('启用且 ban_effective === false 时展示黄条', () => {
  assert.equal(isAutobanIneffective({ enabled: true, ban_effective: false }), true)
})

test('list_referenced 形态不再驱动黄条（判据只看 ban_effective）', () => {
  // 历史回归：仅被白名单/受信代理引用时 list_referenced=true，但名单未被 deny
  // 策略引用 → ban_effective=false。若判据误用 list_referenced 会两头都错：
  const onlyReferencedButEffective = { enabled: true, ban_effective: true } as const
  assert.equal(isAutobanIneffective(onlyReferencedButEffective), false)
  const referencedButNotEffective = { enabled: true, ban_effective: false } as const
  assert.equal(isAutobanIneffective(referencedButNotEffective), true)
})

// 建议行色深与进度条配色的同一判据：≥4× 阈值 high、≥2× mid、其余 low。
test('建议档位边界：4×/2× 为闭区间，阈值缺省按 1', () => {
  assert.equal(suggestionBand(1, 1), 'low', '不足 2× 为低档')
  assert.equal(suggestionBand(2, 1), 'mid', '恰好 2× 属中档')
  assert.equal(suggestionBand(4, 1), 'high', '4 次即高亮（>= 而非 >）')
  assert.equal(suggestionBand(8, 2), 'high')
  assert.equal(suggestionBand(3, 2), 'low')
  assert.equal(suggestionBand(4, 2), 'mid')
  assert.equal(suggestionBand(7, 2), 'mid')
  assert.equal(suggestionBand(8, 2), 'high', '恰好 4× 阈值属高档')
  // 阈值 0 按 1 兜底（后端可能下发 0 表示未配置）
  assert.equal(suggestionBand(4, 0), 'high')
  assert.equal(suggestionBand(1, 0), 'low')
  // 负数只有 `threshold || 1` 的口径：0/NaN 才落缺省，负数按字面量比较（恒高档）。
  // 后端校验阈值 ≥1，负数只可能来自带外数据——此处把现状钉住而非当 bug 修。
  assert.equal(suggestionBand(1, -1), 'high')
})

// 消费侧接线：档位单源被两个呈现点共同消费（色深 / 进度条），不得各自判阈值。
test('事件页两处建议样式都从档位单源派生', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  const style = section(page, 'const suggestionCountStyle', 'const suggestionProgressColor')
  assert.match(style, /suggestionBand\(/, '命中次数色深必须来自档位单源')
  // 行首 `const` 终点：声明换行重排后切片仍完整（'\n' 会把多行声明截成首行）。
  const progress = section(page, 'const suggestionProgressColor', '\nconst ')
  assert.match(progress, /suggestionBand\(/, '进度条配色必须来自同一档位单源')
})

test('未启用时不提示（黄条仅针对已启用但未生效）', () => {
  assert.equal(isAutobanIneffective({ enabled: false, ban_effective: false }), false)
  assert.equal(isAutobanIneffective({ enabled: false, ban_effective: true }), false)
})

test('fail-closed 默认：成功响应前 ban_effective 缺省不弹黄条', () => {
  assert.equal(isAutobanIneffective({ enabled: true }), false)
})

// 消费侧接线：纯函数用例拦不住「黄条绑定被删」——告警静默消失，用户以为封禁在生效。
test('事件页黄条由该判据派生（绑定与计算属性都在）', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(
    page,
    /const autobanIneffective = computed\(\(\) => isAutobanIneffective\(autobanStatus\.value\)\)/,
    '黄条判据必须来自共享纯函数',
  )
  assert.match(page, /v-if="autobanIneffective"/, '模板必须渲染该判据驱动的提示条')
})

// 状态接口失败时，状态条此前仍按前端初值渲染确定态数值（未启用 / 阈值 100 /
// 今日封禁 0），与错误提示条并列——读者据此判断「没开、今天没封过」。
test('状态读取失败：状态标签与六项数值一律显示「—」，不回落到本地初值', () => {
  assert.equal(autobanStatValue(true, 100, ' 次'), '—')
  assert.equal(autobanStatValue(false, 100, ' 次'), '100 次')
  assert.equal(autobanStatValue(false, '全部事件'), '全部事件')
  assert.equal(autobanStateLabel(true, false, true), '状态未知')
  assert.equal(autobanStateLabel(false, false, true), '未启用')
  assert.equal(autobanStateLabel(false, true, false), '运行中')
  assert.equal(autobanStateLabel(false, true, true), '观察模式')

  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /autobanStatValue\(autobanStatusError, autobanStatus\.window_minutes/, '窗口必须走未知态单源')
  assert.match(page, /autobanStatValue\(autobanStatusError, autobanStatus\.threshold/, '阈值必须走未知态单源')
  assert.match(page, /autobanStatValue\(autobanStatusError, autobanStatus\.banned_today/, '今日封禁必须走未知态单源')
  assert.match(page, /autobanStatValue\(autobanStatusError, autobanStatus\.list_entries/, '名单数必须走未知态单源')
  assert.match(page, /autobanStateLabel\(autobanStatusError, autobanStatus\.enabled, autobanStatus\.dry_run\)/, '状态标签必须区分未知')
  // 主节点徽章在错误态同样不可信——徽章判据（含错误态门）在下方专用用例里按条件集判定。
})

test('状态首次加载期间不渲染主节点徽章，避免刷新时参数区先右移再回位', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  // 按「条件集」判定：徽章渲染必须同时要求「非加载中 ∧ 非错误 ∧ 已确认为从节点」。
  // 逐字整串钉（含条件顺序）在调整顺序或改用计算属性时假红，而这三条缺任何一条
  // 都会让初值（loading=true / is_master=false）把参数区先右移再回位。
  const labelAt = page.indexOf("t('app.security.events.masterOnlyBadge')")
  assert.ok(labelAt > 0, '前置：从节点徽章必须存在（否则本断言空转）')
  const badge = elementSlice(page, page.lastIndexOf('<el-tag', labelAt), 'el-tag')
  const guard = /v-if="([^"]+)"/.exec(badge)
  assert.ok(guard !== null, '徽章必须由 v-if 守卫')
  const conditions = guard[1].split('&&').map((part) => part.trim())
  assert.deepEqual(
    [...conditions].sort(),
    ['!autobanStatus.is_master', '!autobanStatusError', '!autobanStatusLoading'],
    '徽章三个条件缺一不可（加载中/错误态都不得按初值渲染）',
  )
})

test('参数区按内容自然宽度紧跟标题，不用 flex:1 抢占剩余空间', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  const stats = section(page, '.autoban-stats {', '}')
  assert.match(stats, /flex: 0 1 auto/)
})

test('首帧即处于状态加载中，禁止 is_master 初值触发徽章闪现', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /const autobanStatusLoading = ref\(true\)/)
})

// ── 批次 D(autoban 域)双钉:状态标签与名单剩余时长文案 i18n 接线 ──
// 调用点钉键(common.app.views.autoban.*),zh 母本(locales/zh/views.ts)钉原文;
// 非 settings 族钉,批次 F 重做面不覆盖本文件。

import { tSafe } from '../src/i18n/tSafe.ts'
import { existsSync } from 'node:fs'

const autoban = (key: string, params?: Record<string, unknown>): string =>
  tSafe(`common.app.views.autoban.${key}`, params)

test('autoban 文案走 i18n 单键(调用点钉键):状态四态 + 剩余时长三档', () => {
  const statusUtil = code('src/utils/autobanStatus.ts')
  for (const key of ['stateUnknown', 'stateNotEnabled', 'stateDryRun', 'stateRunning']) {
    assert.ok(statusUtil.includes(`common.app.views.autoban.${key}`), `autobanStateLabel 必须消费 autoban.${key} 词条键`)
  }
  assert.doesNotMatch(statusUtil, /'[状态观运][态察行]?'/, '状态标签不得再写中文文案字面量(词条外第二份)')
  const entryUtil = code('src/utils/autobanEntry.ts')
  for (const key of ['remainingMinutes', 'remainingHoursMinutes', 'remainingDaysHours']) {
    assert.ok(entryUtil.includes(`common.app.views.autoban.${key}`), `autobanEntryRemaining 必须消费 autoban.${key} 词条键`)
  }
  // 行为相位:键解析为 zh 原文(解析失败=键漂移)
  assert.equal(autoban('stateUnknown'), '状态未知')
  assert.equal(autoban('stateNotEnabled'), '未启用')
  assert.equal(autoban('stateDryRun'), '观察模式')
  assert.equal(autoban('stateRunning'), '运行中')
  assert.equal(autoban('remainingMinutes', { count: 0 }), '0 分钟')
  assert.equal(autoban('remainingHoursMinutes', { hours: 3, minutes: 5 }), '3 小时 5 分')
  assert.equal(autoban('remainingDaysHours', { days: 2, hours: 5 }), '2 天 5 时')
})

test('autoban 词条 zh 母本钉(逐字)', () => {
  assert.ok(existsSync(new URL('../src/locales/zh/views.ts', import.meta.url)), '词条母本 src/locales/zh/views.ts 未落库(integrator 接线)')
  const zhLexicon = code('src/locales/zh/views.ts')
  for (const text of ['状态未知', '未启用', '观察模式', '运行中', '{count} 分钟', '{hours} 小时 {minutes} 分', '{days} 天 {hours} 时']) {
    assert.ok(zhLexicon.includes(text), `autoban 词条 zh 原文「${text}」必须在母本中`)
  }
})

// ── IP 单通道：黄条判据 / 建议时长 / 累犯档（NAT 会话通道已退役）──

import {
  autobanEscalationShortKey, autobanSuggestedDurationKey,
} from '../src/utils/autobanStatus.ts'

test('累犯档短键：状态级配置口径（不虚构逐行档位），非法/缺省按 off', () => {
  assert.equal(autobanEscalationShortKey('off'), 'app.security.overview.autoban.escalationOffShort')
  assert.equal(autobanEscalationShortKey('standard'), 'app.security.overview.autoban.escalationStandardShort')
  assert.equal(autobanEscalationShortKey('aggressive'), 'app.security.overview.autoban.escalationAggressiveShort')
  assert.equal(autobanEscalationShortKey(undefined), 'app.security.overview.autoban.escalationOffShort')
  assert.equal(autobanEscalationShortKey('bogus'), 'app.security.overview.autoban.escalationOffShort')
})

test('建议时长键：一律按配置时长词条（未知值原样回显，与事件页同口径）', () => {
  assert.equal(autobanSuggestedDurationKey('1h'), 'app.security.events.duration1h')
  assert.equal(autobanSuggestedDurationKey('permanent'), 'app.security.events.durationPermanent')
  assert.equal(autobanSuggestedDurationKey('weird'), 'app.security.events.weird')
})

// 消费侧接线：总览卡四统计卡一行/单黄条/建议表/累犯下钻必须真实绑定，
// NAT 会话形态不得残留（徽标/分列/身份拆解/执法层）。
test('总览卡：四统计卡一行 + 单黄条 + IP 建议表 + 累犯下钻接线', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /const autobanIneffective = computed\(\(\) => autobanStatus\.value !== null && isAutobanIneffective\(autobanStatus\.value\)\)/)
  assert.match(page, /v-if="autobanIneffective"/, '单黄条必须绑定判据')
  assert.match(page, /autobanStatus\?\.escalated_count/, '累犯升级数必须消费 escalated_count 键')
  assert.match(page, /autobanStatus\?\.banned_today/, '今日封禁必须消费 banned_today 键')
  assert.match(page, /autobanEscalationShortKey\(autobanStatus\?\.escalation\)/, '累犯档列必须消费状态级 escalation')
  // 四统计卡一行（grid 4 列）+ 移动端堆叠
  assert.match(page, /\.autoban-stats \{[^}]*grid-template-columns: repeat\(4, minmax\(0, 1fr\)\)/, '四统计卡必须 grid 4 列一行')
  assert.match(page, /@media \(max-width: 768px\) \{[\s\S]*?\.autoban-body \{ flex-direction: column; \}/, '移动端必须堆叠')
  // 黄条与卡体间距必须显式声明（mb-3 工具类全站未定义，曾零间距贴住卡体）
  assert.match(page, /class="autoban-alert"/, '卡内黄条必须挂间距类')
  assert.match(page, /\.autoban-alert \{[^}]*margin-bottom: 12px/, '黄条下间距必须显式声明')
  // 建议区定宽不伸缩 + 窄桌面提前堆叠（中间宽度带不再把建议表挤成窄条）
  assert.match(page, /\.autoban-suggestions \{[^}]*flex: 0 0 420px/, '建议区必须定宽不伸缩')
  assert.match(page, /@media \(max-width: 1200px\) \{[\s\S]*?\.autoban-body \{ flex-direction: column; \}/, '窄桌面必须提前堆叠')
  // 建议区自适应剩余宽度：标题 ellipsis+tooltip，无水平滚动
  assert.match(page, /\.autoban-suggestions-title \{[^}]*text-overflow: ellipsis/, '建议标题必须 ellipsis 不换行')
  assert.match(page, /\.autoban-suggestions \{[^}]*min-width: 0/, '建议区必须可收缩（不撑破卡体）')
  const card = section(page, 'class="mb-5 autoban-card"', '</el-card>')
  assert.match(card, /:ip="row\.ip"/, '建议行 IP 处置直接消费 IP（单通道无复合身份）')
  // NAT 形态退役：徽标/会话分列/身份拆解/执法层/配置按钮不得残留
  for (const gone of ['natActiveBadge', 'session_bans', 'autobanIdentityIp', 'autobanEnforcementLayer', 'autobanChannelSplit', 'goToAutobanConfig', 'autoban-stat-split']) {
    assert.ok(!page.includes(gone), `NAT/旧形态残留：${gone}`)
  }
  // 累犯下钻：统计值可点击 → 共享弹框组件（数据/重置/表格在组件内，下方钉）
  assert.match(page, /class="autoban-stat-link" :disabled="autobanError" @click="recidivismDialogVisible = true"/, '累犯升级统计必须可点击下钻')
  assert.match(page, /<RecidivismDialog[\s\S]*?v-model="recidivismDialogVisible"/, '下钻必须挂共享弹框组件')
})

// 共享累犯弹框（总览下钻 + 事件页入口复用）：数据源/重置/表格列/footer 布局
// 在组件内单源钉住；两页只传写门与配置实态。
test('累犯弹框共享组件：端点/七列/状态三态/下次封禁单源/footer 破坏性左置', () => {
  const dialog = code('src/components/security/RecidivismDialog.vue')
  assert.match(dialog, /request\.get<APIResponse<\{ records: RecidivismRecord\[\]; total: number \}>>\(`\/security\/autoban\/recidivism\?\$\{params\}`/, '弹框数据源必须是 GET /security/autoban/recidivism 携参')
  assert.match(dialog, /await request\.delete\('\/security\/autoban\/recidivism'\)/, '重置必须走 DELETE 同端点')
  assert.match(dialog, /ElMessageBox\.confirm\(\s*t\('app\.security\.overview\.autoban\.recidivismResetConfirm'\)/, '重置必须二次确认')
  for (const col of ['recidivismColIdentity', 'recidivismColStatus', 'recidivismColHits24h', 'recidivismColOffenses', 'recidivismColLastBan', 'recidivismColNextBan', 'recidivismColLastEvent']) {
    assert.ok(dialog.includes(col), `弹框缺列键 ${col}`)
  }
  // 操作列退役（处置由 IP 快捷弹框覆盖）：单条取消的按钮/确认/DELETE 调用不得残留
  for (const gone of ['recidivismColActions', 'recidivismCancel', 'cancelRecord', 'cancelingIdentity']) {
    assert.ok(!dialog.includes(gone), `操作列残留：${gone}`)
  }
  // 表格内容优化：身份 CIDR 形态单源 / 累计加「次」单位 / 下次封禁预期单源 /
  // 上次执法时长 tooltip 披露（历史留痕不丢）
  assert.match(dialog, /autobanIdentityDisplay\(row\.identity\)/, '身份列必须经 CIDR 形态单源')
  assert.match(dialog, /row\.offense_count \}\} \{\{ t\('app\.security\.overview\.autoban\.times'\)/, '累计封禁必须带单位')
  assert.match(dialog, /autobanNextBanDuration\(/, '下次封禁必须走预期时长单源')
  assert.match(dialog, /recidivismLastDurationTip', \{ duration: autobanDurationLabel\(row\.escalated_duration\) \}/, '上次执法时长必须 tooltip 披露')
  // 重做形态（参照连接弹框）：1280 宽 + 筛选工具行 + 固定表高 + 分页
  assert.match(dialog, /v-model="hidePermanent"/, '必须有隐藏永久封禁开关')
  assert.match(dialog, /v-model="ipQuery"/, '必须有 IP 搜索框')
  // 服务端分页契约：筛选/搜索/分页携参（hide_permanent/ip/page/page_size），
  // total 取响应驱动分页；前端不得残留客户端切片/兜底筛选。
  assert.match(dialog, /useRecidivismList\(/, '数据面必须走服务端分页状态单源')
  assert.match(dialog, /hide_permanent: String\(hide\), page: String\(p\), page_size: String\(size\)/, '分页请求必须携 hide_permanent/page/page_size 参数')
  assert.match(dialog, /if \(ip\) params\.set\('ip', ip\)/, 'IP 搜索必须携 ip 参数（后端 identity 子串匹配）')
  assert.match(dialog, /total: res\.data\?\.total \|\| 0/, 'total 必须取响应（筛选后总数）')
  assert.ok(!dialog.includes('filteredRecords') && !dialog.includes('pagedRecords'), '不得残留前端兜底筛选/切片')
  assert.match(dialog, /:data="records"/, '表格必须直渲服务端页（无二次切片）')
  assert.match(dialog, /<el-pagination/, '必须有分页控件')
  assert.match(dialog, /:height="TABLE_HEIGHT"/, '表格必须固定高度')
  // IP 列复用 IP 快捷弹框（用户裁定：与事件页同逻辑）——身份经 CIDR 形态单源
  // 传入（后端 AutobanEntryIdentity 归一后清累犯行），写完成回调重取列表并
  // 联动宿主状态卡；紧凑归属地由 IPLocationAction 内部经 compactIpLocation 呈现。
  assert.match(dialog, /import IPLocationAction from '@\/views\/security\/IPLocationAction\.vue'/, 'IP 列必须复用 IP 快捷弹框组件')
  assert.match(dialog, /<IPLocationAction :ip="autobanIdentityDisplay\(row\.identity\)" :location="row\.ip_location \|\| ''" @changed="onIpActionChanged" \/>/, 'IP 列必须挂快捷弹框（CIDR 形态身份 + 归属地 + changed 回调）')
  assert.match(dialog, /const onIpActionChanged = \(\): void => \{\s*void fetchRecords\(\)\s*emit\('reset'\)\s*\}/, '写完成必须重取累犯列表并 emit reset 联动宿主状态卡')
  assert.match(dialog, /recidivismCleanupNote/, '必须披露定期清理（30 天无再犯自动清理）')
  // 当前状态列：ban_status 三态 tag（限时=warning+剩余时长单源、永久=danger、
  // 未封禁=info）；限时到期时刻 tooltip 披露；24h 命中/最近事件直渲后端富化字段
  assert.match(dialog, /row\.ban_status === 'permanent'/, '状态列必须区分永久封禁')
  assert.match(dialog, /row\.ban_status === 'timed'/, '状态列必须区分限时封禁')
  assert.match(dialog, /autobanEntryRemaining\(row\.ban_expires_at \|\| ''\)/, '限时封禁剩余时长必须走名单条目展示单源')
  assert.match(dialog, /:content="formatDate\(row\.ban_expires_at\)"/, '限时封禁必须 tooltip 披露到期时刻')
  assert.match(dialog, /recidivismStatusNone/, '未封禁态必须有文案键')
  assert.match(dialog, /row\.hits_24h \?\? 0/, '24h 命中必须直渲后端字段（旧后端缺省 0）')
  assert.match(dialog, /row\.last_event_at \? formatDate\(row\.last_event_at\) : '—'/, '最近事件缺失必须占位')
  // footer：破坏性操作（重置）左对齐分离、关闭右对齐（flex justify-between）
  const footer = section(dialog, '<template #footer>', '</template>')
  assert.match(footer, /class="recidivism-footer"/, 'footer 必须挂布局类')
  assert.ok(footer.indexOf('recidivismReset') < footer.indexOf('recidivismClose'), '重置必须在关闭之前（左→右）')
  const footerCss = section(dialog, '.recidivism-footer {', '}')
  assert.match(footerCss, /justify-content: space-between/, 'footer 必须两端对齐')
  // 打开即复位筛选并拉取（每次打开取最新历史，不沿用陈旧快照/筛选）
  assert.match(dialog, /watch\(\(\) => props\.modelValue, \(visible\) => \{ if \(visible\) open\(\); else invalidate\(\) \}\)/)
})

test('两页累犯入口复用同一共享组件（写门/配置实态传入，重置联动状态卡）', () => {
  for (const file of ['src/views/security/SecurityOverview.vue', 'src/views/security/SecurityEvents.vue']) {
    const page = code(file)
    assert.match(page, /import RecidivismDialog from '@\/components\/security\/RecidivismDialog\.vue'/, `${file} 必须引共享组件`)
    assert.match(page, /<RecidivismDialog[\s\S]*?:writable="[\s\S]*?:blocked-reason="[\s\S]*?:duration="[\s\S]*?:escalation="[\s\S]*?@reset="fetchAutobanStatus"/, `${file} 必须传写门/配置实态并联动重置刷新`)
    assert.ok(!page.includes('recidivismColDuration'), `${file} 不得残留旧「执法时长」列`)
  }
  // 事件页入口在配置主热区之外（点击不触发配置弹框）；加载/失败态禁用
  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /size="small" type="primary" plain :disabled="autobanStatusError \|\| autobanStatusLoading" @click="recidivismDialogVisible = true"/, '事件页累犯入口必须是按钮（与禁用/编辑同规格）')
  assert.doesNotMatch(events, /autoban-recidivism-link/, '旧 link 入口形态必须退役')
  const actions = section(events, '<div class="autoban-actions">', '</div>')
  assert.match(actions, /statRecidivism/, '累犯入口必须与禁用/编辑同组（autoban-actions）')
  assert.ok(events.indexOf('</el-tooltip>') < events.indexOf('<div class="autoban-actions">'), '入口必须在配置主热区（tooltip 包裹）之外')
})

test('事件页：单黄条 + IP 建议表 + 七项配置弹框接线', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /v-if="autobanIneffective"/)
  assert.match(page, /autobanSuggestedDurationKey\(autobanStatus\.duration\)/, '建议时长按配置派生')
  assert.match(page, /:ip="row\.ip"/, '建议行 IP 处置直接消费 IP')
  // 配置预览行必须含累犯升级档位（状态级口径，短文案单源）
  const statsRow = section(page, '<div class="autoban-stats">', '</div>')
  assert.match(statsRow, /t\('app\.security\.events\.escalationLabel'\)/, '配置预览必须含累犯升级标签')
  assert.match(statsRow, /autobanEscalationShortKey\(autobanStatus\.escalation\)/, '累犯升级档位必须消费状态级 escalation')
  // 配置弹框七项（六基础 + 累犯升级）；NAT 段整体退役
  assert.match(page, /v-model="autobanForm\.escalation"/, '累犯升级选择必须绑定')
  for (const gone of ['nat_detection', 'nat_fingerprint_threshold', 'natPrivacyNotice', 'autobanNatActive', 'autobanChannelSplit', 'autobanEnforcementLayer', 'autobanIdentityIp', 'session_bans', 'ban_effective_session']) {
    assert.ok(!page.includes(gone), `NAT 残留：${gone}`)
  }
  // 保存/禁用直切必须携带 escalation（PUT 全量七项）
  const save = section(page, 'const saveAutobanConfig', 'const autobanEnableConfirmHtml')
  assert.match(save, /\.\.\.autobanForm\.value/, '保存必须展开完整表单')
  const toggle = section(page, 'const toggleAutobanEnabled', '\nconst ')
  assert.match(toggle, /escalation: autobanStatus\.value\.escalation/, '禁用直切必须回填 escalation')
})

// 双语 parity：保留/新增键 zh/en 齐备（security 域整树比对由
// ccProtectionContracts 承担；此处钉关键键的 zh 原文与 en 存在性）。
test('autoban 词条 zh 母本钉 + en 侧齐备（NAT 键退役）', () => {
  const zhSec = code('src/locales/zh/security.ts')
  const enSec = code('src/locales/en/security.ts')
  const zhTexts = [
    '"escalationLabel": "累犯升级"',
    '"colIdentity": "IP 地址"', '"colEscalation": "累犯档"',
    '"recidivismDialogTitle": "累犯升级记录"',
    '"recidivismReset": "重置累犯记录"',
    '"bannedTodayTip": "今日写入自动封禁名单的 IP 数"',
    '"recidivismColIdentity": "IP地址"',
    '"recidivismColStatus": "当前状态"',
    '"recidivismStatusNone": "未封禁"',
    '"recidivismColHits24h": "24h命中"',
    '"recidivismColLastEvent": "最近事件"',
    '"recidivismHidePermanent": "隐藏永久封禁"',
  ]
  for (const text of zhTexts) assert.ok(zhSec.includes(text), `zh 母本缺「${text}」`)
  const enKeys = ['escalationLabel', 'colIdentity', 'colEscalation', 'recidivismDialogTitle', 'recidivismDialogSubtitle', 'recidivismColIdentity', 'recidivismColStatus', 'recidivismStatusNone', 'recidivismColHits24h', 'recidivismColOffenses', 'recidivismColLastBan', 'recidivismColNextBan', 'recidivismColLastEvent', 'recidivismHidePermanent', 'recidivismIpPlaceholder', 'recidivismCleanupNote', 'recidivismLastDurationTip', 'recidivismEmpty', 'recidivismLoadFailed', 'recidivismRetry', 'recidivismReset', 'recidivismResetTitle', 'recidivismResetConfirm', 'recidivismResetConfirmBtn', 'recidivismResetDone', 'recidivismClose', 'bannedTodayTip', 'statRecidivism', 'escalationPermanentDisabledHint']
  for (const key of enKeys) assert.ok(enSec.includes(`"${key}"`), `en 侧缺键 ${key}`)
  // NAT 键与操作列词条双语同步退役（漏删一侧 = 键集漂移）
  for (const gone of ['natDetectionLabel', 'natThresholdLabel', 'natPrivacyNotice', 'natActiveBadge', 'ineffectiveSession', 'ineffectiveIp', 'durationSession', 'identitySession', 'enforcementSession', 'bannedTodaySession', 'listEntriesSession', 'recidivismColActions', 'recidivismCancel', 'recidivismCancelTitle', 'recidivismCancelConfirm', 'recidivismCancelConfirmBtn', 'recidivismCancelDone']) {
    assert.ok(!zhSec.includes(`"${gone}"`), `zh 侧退役键残留 ${gone}`)
    assert.ok(!enSec.includes(`"${gone}"`), `en 侧退役键残留 ${gone}`)
  }
})

// ── 首封时长语义收窄（累犯升级开启时标签/tooltip/状态卡摘要同口径）──

test('首封时长：弹框标签随 escalation 切换（阶梯口径在下拉选项标签披露，时长项不挂角标）', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  const durationItem = elementSlice(page, page.indexOf('<el-form-item>\n          <template #label><span>{{ t(autobanFormEscalationOn'), 'el-form-item')
  assert.match(durationItem, /t\(autobanFormEscalationOn \? 'app\.security\.events\.firstBanDuration' : 'app\.security\.events\.durationLabel'\)/, '时长标签必须按 escalation 档位切换')
  assert.match(durationItem, /v-model="autobanForm\.duration"/, '切片必须是时长配置项本体')
  assert.doesNotMatch(durationItem, /FieldHelpIcon/, '时长项不挂角标图标（用户裁定移除无用叹号）')
  // 判据单源：状态卡与弹框各自消费实态/表单的 escalation，仅 standard/aggressive 算开启
  assert.match(page, /const autobanStatusEscalationOn = computed\(\(\) =>\s*autobanStatus\.value\.escalation === 'standard' \|\| autobanStatus\.value\.escalation === 'aggressive'\)/)
  assert.match(page, /const autobanFormEscalationOn = computed\(\(\) =>\s*autobanForm\.value\.escalation === 'standard' \|\| autobanForm\.value\.escalation === 'aggressive'\)/)
  // 状态卡摘要同口径：escalation≠off 时时长行标「首封时长」
  assert.match(page, /t\(autobanStatusEscalationOn \? 'app\.security\.events\.firstBanDuration' : 'app\.security\.events\.statDuration'\)/, '状态卡时长行必须随档位切换标签')
  // 总览卡配置摘要同口径（时长行随档位切换）
  const overview = code('src/views/security/SecurityOverview.vue')
  assert.match(overview, /t\(autobanStatusEscalationOn \? 'app\.security\.events\.firstBanDuration' : 'app\.security\.overview\.autoban\.duration'\)/, '总览卡时长行必须随档位切换标签')
})

test('首封时长词条：zh 母本钉原文 + en 侧齐备 + 阶梯口径与后端档位映射一致', () => {
  const zhSec = code('src/locales/zh/security.ts')
  const enSec = code('src/locales/en/security.ts')
  const zhTexts = [
    '"firstBanDuration": "首封时长"',
    '"escalationStandard": "标准（二次 24h，三次起永久）"',
    '"escalationAggressive": "激进（二次起永久）"',
  ]
  for (const text of zhTexts) assert.ok(zhSec.includes(text), `zh 母本缺「${text}」`)
  for (const key of ['firstBanDuration', 'escalationStandard', 'escalationAggressive']) {
    assert.ok(enSec.includes(`"${key}"`), `en 侧缺键 ${key}`)
  }
  // 孤立 tip 键已退役（阶梯口径在下拉选项标签披露，时长项不挂角标）
  for (const gone of ['escalationStandardTip', 'escalationAggressiveTip']) {
    assert.ok(!zhSec.includes(`"${gone}"`) && !enSec.includes(`"${gone}"`), `tip 键 ${gone} 应已删除`)
  }
  // 阶梯口径跨栈对表：后端 autobanEscalatedDuration 档位映射漂移即红
  const backend = repoCode('internal/services/autoban.go')
  const tiers = section(backend, 'func autobanEscalatedDuration', 'func ')
  assert.match(tiers, /case offense <= 1:\s*d = autobanDurations\[cfg\.Duration\]/, '首封=配置时长')
  assert.match(tiers, /case offense == 2:\s*d = 24 \* time\.Hour/, 'standard 二次=24h')
  assert.match(tiers, /case AutobanEscalationAggressive:\s*if offense <= 1 \{\s*d = autobanDurations\[cfg\.Duration\]\s*\} else \{\s*d = 0\s*\}/, 'aggressive 二次起=永久')
})

// ── 方案 A：永久时长下累犯升级无意义（UI 禁用+自动归 off；后端消费侧兜底）──

test('方案 A 接线：切永久自动归 off + escalation 选择禁用提示', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /const autobanFormPermanentDuration = computed\(\(\) => autobanForm\.value\.duration === 'permanent'\)/)
  assert.match(page, /watch\(\(\) => autobanForm\.value\.duration, \(duration\) => \{\s*if \(duration === 'permanent' && autobanForm\.value\.escalation !== 'off'\) autobanForm\.value\.escalation = 'off'\s*\}\)/, '切 permanent 必须自动归 off')
  const escalationItem = elementSlice(page, page.indexOf('<el-form-item :label="t(\'app.security.events.escalationLabel\')">'), 'el-form-item')
  assert.match(escalationItem, /v-model="autobanForm\.escalation"/, '切片必须是累犯升级配置项本体')
  assert.match(escalationItem, /:disabled="autobanFormPermanentDuration"/, '永久时长下选择必须禁用')
  assert.match(escalationItem, /t\(autobanFormPermanentDuration \? 'app\.security\.events\.escalationPermanentDisabledHint' : 'app\.security\.events\.escalationHint'\)/, '禁用时必须切换提示文案')
})

test('方案 A 词条：zh 母本钉原文 + en 侧齐备', () => {
  const zhSec = code('src/locales/zh/security.ts')
  const enSec = code('src/locales/en/security.ts')
  assert.ok(zhSec.includes('"escalationPermanentDisabledHint": "永久时长下首封即顶格，累犯升级无意义，已自动关闭"'), 'zh 母本缺禁用提示')
  assert.ok(zhSec.includes('"statRecidivism": "累犯记录"'), 'zh 母本缺入口文案')
  assert.ok(zhSec.includes('"recidivismColNextBan": "下次封禁"'), 'zh 母本缺下次封禁列名')
  assert.ok(zhSec.includes('"recidivismLastDurationTip": "上次执法时长：{duration}"'), 'zh 母本缺上次时长 tooltip')
  for (const key of ['escalationPermanentDisabledHint', 'statRecidivism', 'recidivismColNextBan', 'recidivismLastDurationTip']) {
    assert.ok(enSec.includes(`"${key}"`), `en 侧缺键 ${key}`)
  }
})

test('方案 A 后端消费侧兜底：permanent+非 off 按 off 消费（跨栈对表）', () => {
  const backend = repoCode('internal/services/autoban.go')
  const merge = section(backend, 'func autobanMergeEntries', '\nfunc ')
  assert.match(merge, /if cfg\.Duration == "permanent" \{\s*cfg\.Escalation = AutobanEscalationOff\s*\}/, '消费侧必须对 permanent 兜底归 off（防绕过 UI 直 PUT）')
  // 行为钉在 internal/services/autoban_escalation_test.go
  // TestAutobanEscalation_permanentDurationConsumesAsOff（Go 侧）。
})

// ── 下次封禁预期时长 / 身份 CIDR 形态 / 时长标签单源（行为断言）──

import { autobanNextBanDuration, autobanIdentityDisplay, autobanDurationLabel } from '../src/utils/autobanStatus.ts'

const NOW = Date.UTC(2026, 10, 15, 10, 0, 0)
const lastBan = (daysAgo: number): number => NOW - daysAgo * 24 * 60 * 60 * 1000

test('下次封禁：standard 阶梯（首封配置时长→二次 24h→三次起永久）', () => {
  const cfg = { duration: '1h', escalation: 'standard' }
  assert.equal(autobanNextBanDuration(cfg, { offense_count: 1, last_ban_at: '' }, NOW, lastBan(0)), '24h')
  assert.equal(autobanNextBanDuration(cfg, { offense_count: 2, last_ban_at: '' }, NOW, lastBan(0)), 'permanent')
  assert.equal(autobanNextBanDuration(cfg, { offense_count: 5, last_ban_at: '' }, NOW, lastBan(0)), 'permanent')
})

test('下次封禁：aggressive 二次起永久；off/非法/缺省按固定配置时长', () => {
  assert.equal(autobanNextBanDuration({ duration: '1h', escalation: 'aggressive' }, { offense_count: 1, last_ban_at: '' }, NOW, lastBan(0)), 'permanent')
  for (const escalation of ['off', 'bogus', undefined]) {
    assert.equal(autobanNextBanDuration({ duration: '6h', escalation }, { offense_count: 9, last_ban_at: '' }, NOW, lastBan(0)), '6h')
  }
})

test('下次封禁：permanent 配置恒永久（升级无意义，与后端兜底同口径）', () => {
  for (const escalation of ['off', 'standard', 'aggressive']) {
    assert.equal(autobanNextBanDuration({ duration: 'permanent', escalation }, { offense_count: 1, last_ban_at: '' }, NOW, lastBan(0)), 'permanent')
  }
})

test('下次封禁：30 天衰减近似（超窗按首次档；恰 30 天不衰减；时刻缺失不衰减）', () => {
  const cfg = { duration: '1h', escalation: 'standard' }
  const row = { offense_count: 3, last_ban_at: '' }
  assert.equal(autobanNextBanDuration(cfg, row, NOW, lastBan(31)), '1h', '超窗历史清零按首次档')
  assert.equal(autobanNextBanDuration(cfg, row, NOW, lastBan(30)), 'permanent', '恰 30 天不衰减（> 才清零，与后端同口径）')
  assert.equal(autobanNextBanDuration(cfg, row, NOW, null), 'permanent', 'last_ban_at 缺失不做衰减推算')
})

test('下次封禁与后端档位映射跨栈对表（standard/aggressive 阶梯字面量）', () => {
  const backend = repoCode('internal/services/autoban.go')
  const tiers = section(backend, 'func autobanEscalatedDuration', '\nfunc ')
  assert.match(tiers, /case offense <= 1:\s*d = autobanDurations\[cfg\.Duration\]/)
  assert.match(tiers, /case offense == 2:\s*d = 24 \* time\.Hour/)
  assert.match(tiers, /case AutobanEscalationAggressive:\s*if offense <= 1 \{\s*d = autobanDurations\[cfg\.Duration\]\s*\} else \{\s*d = 0\s*\}/)
})

test('身份 CIDR 形态：IPv6 /64 网络地址加 /64，IPv4/非网络地址原样', () => {
  assert.equal(autobanIdentityDisplay('2606:4700:abcd:1234::'), '2606:4700:abcd:1234::/64')
  assert.equal(autobanIdentityDisplay('2606:4700:abcd:1234:0:0:0:0'), '2606:4700:abcd:1234:0:0:0:0/64')
  assert.equal(autobanIdentityDisplay('2606:4700:abcd:1234::1'), '2606:4700:abcd:1234::1', '非 /64 网络地址不得加后缀')
  assert.equal(autobanIdentityDisplay('2606:4700:abcd:1234:1:0:0:0'), '2606:4700:abcd:1234:1:0:0:0')
  assert.equal(autobanIdentityDisplay('45.33.32.10'), '45.33.32.10')
  assert.equal(autobanIdentityDisplay('not-an-ip'), 'not-an-ip')
  assert.equal(autobanIdentityDisplay(''), '')
})

test('时长标签单源：库值→词条，未知值原样回显，空值占位', () => {
  assert.equal(autobanDurationLabel('permanent'), '永久')
  assert.equal(autobanDurationLabel('24h'), '24 小时')
  assert.equal(autobanDurationLabel('weird'), 'weird')
  assert.equal(autobanDurationLabel(''), '—')
})
