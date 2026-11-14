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
  // 建议区自适应剩余宽度：标题 ellipsis+tooltip，无水平滚动
  assert.match(page, /\.autoban-suggestions-title \{[^}]*text-overflow: ellipsis/, '建议标题必须 ellipsis 不换行')
  assert.match(page, /\.autoban-suggestions \{[^}]*min-width: 0/, '建议区必须可收缩（不撑破卡体）')
  const card = section(page, 'class="mb-5 autoban-card"', '</el-card>')
  assert.match(card, /:ip="row\.ip"/, '建议行 IP 处置直接消费 IP（单通道无复合身份）')
  // NAT 形态退役：徽标/会话分列/身份拆解/执法层/配置按钮不得残留
  for (const gone of ['natActiveBadge', 'session_bans', 'autobanIdentityIp', 'autobanEnforcementLayer', 'autobanChannelSplit', 'goToAutobanConfig', 'autoban-stat-split']) {
    assert.ok(!page.includes(gone), `NAT/旧形态残留：${gone}`)
  }
  // 累犯下钻：统计值可点击 → 弹框列表 + 重置（确认框）
  assert.match(page, /@click="openRecidivismDialog"/, '累犯升级统计必须可点击下钻')
  assert.match(page, /request\.get<APIResponse<\{ records: RecidivismRecord\[\] \}>>\('\/security\/autoban\/recidivism'/, '弹框数据源必须是 GET /security/autoban/recidivism')
  assert.match(page, /await request\.delete\('\/security\/autoban\/recidivism'\)/, '重置必须走 DELETE 同端点')
  assert.match(page, /ElMessageBox\.confirm\(\s*t\('app\.security\.overview\.autoban\.recidivismResetConfirm'\)/, '重置必须二次确认')
  for (const col of ['recidivismColIdentity', 'recidivismColOffenses', 'recidivismColLastBan', 'recidivismColDuration']) {
    assert.ok(page.includes(col), `弹框缺列键 ${col}`)
  }
})

test('事件页：单黄条 + IP 建议表 + 七项配置弹框接线', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /v-if="autobanIneffective"/)
  assert.match(page, /autobanSuggestedDurationKey\(autobanStatus\.duration\)/, '建议时长按配置派生')
  assert.match(page, /:ip="row\.ip"/, '建议行 IP 处置直接消费 IP')
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
  ]
  for (const text of zhTexts) assert.ok(zhSec.includes(text), `zh 母本缺「${text}」`)
  const enKeys = ['escalationLabel', 'colIdentity', 'colEscalation', 'recidivismDialogTitle', 'recidivismDialogSubtitle', 'recidivismColIdentity', 'recidivismColOffenses', 'recidivismColLastBan', 'recidivismColDuration', 'recidivismEmpty', 'recidivismLoadFailed', 'recidivismRetry', 'recidivismReset', 'recidivismResetTitle', 'recidivismResetConfirm', 'recidivismResetConfirmBtn', 'recidivismResetDone', 'recidivismClose', 'bannedTodayTip']
  for (const key of enKeys) assert.ok(enSec.includes(`"${key}"`), `en 侧缺键 ${key}`)
  // NAT 键双语同步退役（漏删一侧 = 键集漂移）
  for (const gone of ['natDetectionLabel', 'natThresholdLabel', 'natPrivacyNotice', 'natActiveBadge', 'ineffectiveSession', 'ineffectiveIp', 'durationSession', 'identitySession', 'enforcementSession', 'bannedTodaySession', 'listEntriesSession']) {
    assert.ok(!zhSec.includes(`"${gone}"`), `zh 侧 NAT 键残留 ${gone}`)
    assert.ok(!enSec.includes(`"${gone}"`), `en 侧 NAT 键残留 ${gone}`)
  }
})

// ── 首封时长语义收窄（累犯升级开启时标签/tooltip/状态卡摘要同口径）──

test('首封时长：弹框标签随 escalation 切换 + 阶梯 tooltip 角标接线', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  const durationItem = elementSlice(page, page.indexOf('<el-form-item>\n          <template #label><span>{{ t(autobanFormEscalationOn'), 'el-form-item')
  assert.match(durationItem, /t\(autobanFormEscalationOn \? 'app\.security\.events\.firstBanDuration' : 'app\.security\.events\.durationLabel'\)/, '时长标签必须按 escalation 档位切换')
  assert.match(durationItem, /v-model="autobanForm\.duration"/, '切片必须是时长配置项本体')
  assert.match(durationItem, /<FieldHelpIcon v-if="autobanFormEscalationOn" :content="autobanFormEscalationTip" \/>/, 'off 不渲染角标；开启时 tooltip 披露阶梯')
  // 判据单源：状态卡与弹框各自消费实态/表单的 escalation，仅 standard/aggressive 算开启
  assert.match(page, /const autobanStatusEscalationOn = computed\(\(\) =>\s*autobanStatus\.value\.escalation === 'standard' \|\| autobanStatus\.value\.escalation === 'aggressive'\)/)
  assert.match(page, /const autobanFormEscalationOn = computed\(\(\) =>\s*autobanForm\.value\.escalation === 'standard' \|\| autobanForm\.value\.escalation === 'aggressive'\)/)
  assert.match(page, /const autobanFormEscalationTip = computed\(\(\) =>\s*autobanForm\.value\.escalation === 'aggressive'\s*\? t\('app\.security\.events\.escalationAggressiveTip'\)\s*: t\('app\.security\.events\.escalationStandardTip'\)/)
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
    '"escalationStandardTip": "累犯升级（标准档）：首封用配置时长，二次 24h，三次起永久"',
    '"escalationAggressiveTip": "累犯升级（激进档）：首封用配置时长，二次起永久"',
  ]
  for (const text of zhTexts) assert.ok(zhSec.includes(text), `zh 母本缺「${text}」`)
  for (const key of ['firstBanDuration', 'escalationStandardTip', 'escalationAggressiveTip']) {
    assert.ok(enSec.includes(`"${key}"`), `en 侧缺键 ${key}`)
  }
  // 阶梯口径跨栈对表：后端 autobanEscalatedDuration 档位映射漂移即红
  const backend = repoCode('internal/services/autoban.go')
  const tiers = section(backend, 'func autobanEscalatedDuration', 'func ')
  assert.match(tiers, /case offense <= 1:\s*d = autobanDurations\[cfg\.Duration\]/, '首封=配置时长')
  assert.match(tiers, /case offense == 2:\s*d = 24 \* time\.Hour/, 'standard 二次=24h')
  assert.match(tiers, /case AutobanEscalationAggressive:\s*if offense <= 1 \{\s*d = autobanDurations\[cfg\.Duration\]\s*\} else \{\s*d = 0\s*\}/, 'aggressive 二次起=永久')
})
