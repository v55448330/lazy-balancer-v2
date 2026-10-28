// 自动封禁状态卡黄条判据（行为化：原源码
// 正则断言改为纯函数行为断言）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { autobanStateLabel, autobanStatValue, isAutobanIneffective, suggestionBand } from '../src/utils/autobanStatus.ts'
import { code, section } from './_helpers.ts'

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
  const progress = section(page, 'const suggestionProgressColor', '\n')
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
  // 主节点徽章在错误态同样不可信（is_master 初值 false 会显示「仅主节点调度」）
  assert.match(page, /v-if="!autobanStatusLoading && !autobanStatusError && !autobanStatus\.is_master"/)
})

test('状态首次加载期间不渲染主节点徽章，避免刷新时参数区先右移再回位', () => {
  const page = code('src/views/security/SecurityEvents.vue')
  assert.match(page, /v-if="!autobanStatusLoading && !autobanStatusError && !autobanStatus\.is_master"/)
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
