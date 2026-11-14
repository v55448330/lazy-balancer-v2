// 自动封禁状态卡黄条判据（行为化：原源码
// 正则断言改为纯函数行为断言）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { autobanStateLabel, autobanStatValue, isAutobanIneffective, suggestionBand } from '../src/utils/autobanStatus.ts'
import { code, elementSlice, section } from './_helpers.ts'

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

// ── A+C 双通道：分通道黄条判据 / NAT 徽标 / 身份拆解 / 执法层 / 累犯档 ──

import {
  isAutobanIpIneffective, isAutobanSessionIneffective, isAutobanNatActive,
  splitAutobanIdentity, autobanEnforcementLayer, autobanEscalationShortKey,
  autobanSuggestedDurationKey,
} from '../src/utils/autobanStatus.ts'

test('IP 通道黄条：仅 enabled ∧ ban_effective_ip===false（缺键 fail-closed 不提示）', () => {
  assert.equal(isAutobanIpIneffective({ enabled: true, ban_effective_ip: false }), true)
  assert.equal(isAutobanIpIneffective({ enabled: true, ban_effective_ip: true }), false)
  assert.equal(isAutobanIpIneffective({ enabled: false, ban_effective_ip: false }), false)
  assert.equal(isAutobanIpIneffective({ enabled: true }), false, '旧后端缺分通道键不得误报')
})

test('会话通道黄条：仅 NAT 态 ∧ 有会话封禁 ∧ ban_effective_session===false', () => {
  const base = { enabled: true, nat_detection: true, session_bans: 2 }
  assert.equal(isAutobanSessionIneffective({ ...base, ban_effective_session: false }), true)
  assert.equal(isAutobanSessionIneffective({ ...base, ban_effective_session: true }), false)
  assert.equal(isAutobanSessionIneffective({ ...base, session_bans: 0, ban_effective_session: false }), false, '无会话封禁不提示')
  assert.equal(isAutobanSessionIneffective({ enabled: true, session_bans: 2, ban_effective_session: false }), false, '非 NAT 态不提示')
  assert.equal(isAutobanSessionIneffective({ enabled: false, nat_detection: true, session_bans: 2, ban_effective_session: false }), false)
})

test('NAT 徽标判据：enabled ∧ nat_detection ∧ 会话封禁非空', () => {
  assert.equal(isAutobanNatActive({ enabled: true, nat_detection: true, session_bans: 1 }), true)
  assert.equal(isAutobanNatActive({ enabled: true, nat_detection: true, session_bans: 0 }), false)
  assert.equal(isAutobanNatActive({ enabled: true, nat_detection: false, session_bans: 3 }), false)
  assert.equal(isAutobanNatActive({ enabled: false, nat_detection: true, session_bans: 3 }), false)
  assert.equal(isAutobanNatActive({ enabled: true }), false, '旧后端缺键不渲染徽标')
})

test('身份键拆解与后端 autobanCompositeKeyParts 同形（首个 | 为边界）', () => {
  assert.deepEqual(splitAutobanIdentity('203.0.113.7'), { ip: '203.0.113.7', fingerprint: '', composite: false })
  assert.deepEqual(splitAutobanIdentity('2001:db8::'), { ip: '2001:db8::', fingerprint: '', composite: false })
  assert.deepEqual(splitAutobanIdentity('2001:db8::|c:abcdef0123456789'), { ip: '2001:db8::', fingerprint: 'c:abcdef0123456789', composite: true })
  // 边界形态与后端一致：| 在首位/末位不构成复合键
  assert.equal(splitAutobanIdentity('|abc').composite, false)
  assert.equal(splitAutobanIdentity('2001:db8::|').composite, false)
  // 指纹内含 | 时只按首个 | 拆（后端 IndexByte 同口径）
  assert.deepEqual(splitAutobanIdentity('2001:db8::|a|b'), { ip: '2001:db8::', fingerprint: 'a|b', composite: true })
})

test('执法层判据：复合身份=会话挑战，IP 身份=IP 封禁', () => {
  assert.equal(autobanEnforcementLayer('203.0.113.7'), 'ip')
  assert.equal(autobanEnforcementLayer('2001:db8::|c:abcdef0123456789'), 'session')
})

test('累犯档短键：状态级配置口径（不虚构逐行档位），非法/缺省按 off', () => {
  assert.equal(autobanEscalationShortKey('off'), 'app.security.overview.autoban.escalationOffShort')
  assert.equal(autobanEscalationShortKey('standard'), 'app.security.overview.autoban.escalationStandardShort')
  assert.equal(autobanEscalationShortKey('aggressive'), 'app.security.overview.autoban.escalationAggressiveShort')
  assert.equal(autobanEscalationShortKey(undefined), 'app.security.overview.autoban.escalationOffShort')
  assert.equal(autobanEscalationShortKey('bogus'), 'app.security.overview.autoban.escalationOffShort')
})

test('建议时长键：会话身份=会话短时长词条；IP 身份=配置时长词条', () => {
  assert.equal(autobanSuggestedDurationKey('2001:db8::|c:abc', '1h'), 'app.security.overview.autoban.durationSession')
  assert.equal(autobanSuggestedDurationKey('203.0.113.7', '1h'), 'app.security.events.duration1h')
  assert.equal(autobanSuggestedDurationKey('203.0.113.7', 'permanent'), 'app.security.events.durationPermanent')
  assert.equal(autobanSuggestedDurationKey('203.0.113.7', 'weird'), 'app.security.events.weird', '未知时长原样回显（与事件页同口径）')
})

// 消费侧接线：总览卡分通道黄条/NAT 徽标/统计分列/建议增列必须真实绑定。
test('总览卡：分通道黄条 + NAT 徽标 + IP/会话分列 + 建议增列接线', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  assert.match(page, /const autobanIneffective = computed\(\(\) => autobanStatus\.value !== null && isAutobanIneffective\(autobanStatus\.value\)\)/)
  assert.match(page, /v-if="autobanIpIneffective"/, 'IP 通道黄条必须绑定')
  assert.match(page, /v-if="autobanSessionIneffective"/, '会话通道黄条必须绑定')
  assert.match(page, /v-if="autobanNatActive"/, 'NAT 徽标必须绑定判据')
  assert.match(page, /autobanStatus\?\.session_bans/, '会话封禁数必须消费 session_bans 键')
  assert.match(page, /autobanStatus\?\.escalated_count/, '累犯升级数必须消费 escalated_count 键')
  assert.match(page, /autobanStatus\?\.banned_today/, '今日 IP 封禁必须消费 banned_today 键')
  assert.match(page, /autobanEnforcementLayer\(row\.ip\)/, '执法层列必须按身份键派生')
  assert.match(page, /autobanEscalationShortKey\(autobanStatus\?\.escalation\)/, '累犯档列必须消费状态级 escalation')
  // 复合身份不得整键传入 IP 处置组件（限自动封禁卡切片——Top10 表的 row.ip
  // 是纯 IP，属合法消费，不在本判据范围）
  const card = section(page, 'class="mb-5 autoban-card"', '</el-card>')
  assert.match(card, /:ip="autobanIdentityIp\(row\.ip\)"/, '建议行 IP 处置必须只传身份键的 IP 部分')
  assert.doesNotMatch(card, /:ip="row\.ip"/, '不得把复合身份键当 IP 传入处置组件')
})

test('事件页：分通道黄条 + NAT 徽标 + 建议增列 + 九项配置弹框接线', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /v-if="autobanIpIneffective"/)
  assert.match(page, /v-if="autobanSessionIneffective"/)
  assert.match(page, /autobanNatActive/, 'NAT 徽标判据必须在场')
  assert.match(page, /autobanEnforcementLayer\(row\.ip\)/)
  assert.match(page, /autobanSuggestedDurationKey\(row\.ip, autobanStatus\.duration\)/, '建议时长按身份/配置派生')
  assert.match(page, /:ip="autobanIdentityIp\(row\.ip\)"/)
  assert.doesNotMatch(page, /:ip="row\.ip"/)
  // 配置弹框三新项
  assert.match(page, /v-model="autobanForm\.escalation"/, '累犯升级选择必须绑定')
  assert.match(page, /v-model="autobanForm\.nat_detection"/, 'NAT 检测开关必须绑定')
  assert.match(page, /v-model="autobanForm\.nat_fingerprint_threshold"/, '指纹阈值输入必须绑定')
  assert.match(page, /t\('app\.security\.events\.natPrivacyNotice'\)/, '隐私告知必须在弹框内披露')
  assert.match(page, /autobanForm\.value\.nat_fingerprint_threshold < 2 \|\| autobanForm\.value\.nat_fingerprint_threshold > 100/, '指纹阈值保存校验 2-100')
  // 保存/禁用直切必须携带新三项（PUT 全量九项）
  const save = section(page, 'const saveAutobanConfig', 'const autobanEnableConfirmHtml')
  assert.match(save, /\.\.\.autobanForm\.value/, '保存必须展开完整表单（含新三项）')
  const toggle = section(page, 'const toggleAutobanEnabled', '\nconst ')
  assert.match(toggle, /escalation: autobanStatus\.value\.escalation/, '禁用直切必须回填 escalation')
  assert.match(toggle, /nat_detection: autobanStatus\.value\.nat_detection/, '禁用直切必须回填 nat_detection')
  assert.match(toggle, /nat_fingerprint_threshold: autobanStatus\.value\.nat_fingerprint_threshold/, '禁用直切必须回填指纹阈值')
})

// 双语 parity：本次新增/改动键 zh/en 齐备（security 域整树比对由
// ccProtectionContracts 承担；此处钉新增键的 zh 原文与 en 存在性）。
test('A+C 新词条 zh 母本钉 + en 侧齐备', () => {
  const zhSec = code('src/locales/zh/security.ts')
  const enSec = code('src/locales/en/security.ts')
  const zhTexts = [
    '"natActiveBadge": "NAT 会话精修"',
    '"ineffectiveIp":', '"ineffectiveSession":',
    '"escalationLabel": "累犯升级"', '"natDetectionLabel": "NAT 检测"',
    '"natThresholdLabel": "指纹阈值"', '"natPrivacyNotice":',
    '"durationSession": "会话 10 分钟"',
    '"colIdentity": "身份类型"', '"colEnforcement": "执法层"', '"colEscalation": "累犯档"',
  ]
  for (const text of zhTexts) assert.ok(zhSec.includes(text), `zh 母本缺「${text}」`)
  const enKeys = ['natActiveBadge', 'ineffectiveIp', 'ineffectiveSession', 'escalationLabel', 'natDetectionLabel', 'natThresholdLabel', 'natPrivacyNotice', 'durationSession', 'colIdentity', 'colEnforcement', 'colEscalation']
  for (const key of enKeys) assert.ok(enSec.includes(`"${key}"`), `en 侧缺键 ${key}`)
})
