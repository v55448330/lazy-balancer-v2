// 安全事件动作文案单源（utils/eventAction）行为 + 四处消费接线。
//
// 原四处独立映射且措辞互斥（拦截/检测、已拦截/已记录、已拦截/仅检测、
// 已拦截/已记录（检测））：同一事件在列表→请求详情→大屏→触发详情要读者自行
// 翻译。行为断言落在纯函数上，接线断言落在各视图的调用点。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { eventActionFull, eventActionShort, eventActionTone } from '../src/utils/eventAction.ts'
import { tSafe as t } from '../src/i18n/tSafe.ts'
import { code, section } from './_helpers.ts'

// i18n 后双钉：函数输出钉词条键值（t() 现取，与输出恒等——集成落 views.ts 前后
// 两侧同步从键形态切换为文案形态，任一侧漂移必红）。
test('动作文案：两值枚举的短/全长标签与色调', () => {
  assert.equal(eventActionShort('blocked'), t('common.app.views.eventAction.blockedShort'))
  assert.equal(eventActionShort('logged'), t('common.app.views.eventAction.loggedShort'))
  assert.equal(eventActionFull('blocked'), t('common.app.views.eventAction.blockedFull'))
  assert.equal(eventActionFull('logged'), t('common.app.views.eventAction.loggedFull'))
  assert.equal(eventActionTone('blocked'), 'danger')
  assert.equal(eventActionTone('logged'), 'warning')
})

test('挑战三态用不同标签与色调（发放蓝/通过绿/失败红）', () => {
  assert.equal(eventActionTone('challenged', 'human_challenge'), 'primary')
  assert.equal(eventActionTone('challenged', 'human_pass'), 'success')
  assert.equal(eventActionTone('challenged', 'human_failed'), 'danger')
  assert.equal(eventActionShort('challenged'), t('common.app.views.eventAction.challengedShort'))
  assert.equal(eventActionShort('challenged', 'human_pass'), t('common.app.views.eventAction.challengedShort'))
  assert.equal(eventActionShort('challenged', 'human_failed'), t('common.app.views.eventAction.challengedShort'))
  assert.equal(eventActionFull('challenged', 'human_pass'), t('common.app.views.eventAction.challengedFull'))
  assert.equal(eventActionFull('challenged', 'human_failed'), t('common.app.views.eventAction.challengedFull'))
})

test('未知动作 fail-visible：原样回显，不回落到「检测」', () => {
  assert.equal(eventActionShort('throttled'), 'throttled')
  assert.equal(eventActionFull('throttled'), 'throttled')
  assert.equal(eventActionShort(''), '—')
  assert.equal(eventActionFull(null), '—')
  assert.equal(eventActionTone(undefined), 'warning', '未知动作按未拦截色调渲染')
})

test('四个视图共用单源映射，本地副本已删除', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  assert.match(screen, /from '@\/utils\/eventAction'/)
  assert.match(screen, /eventActionFull\(t\.action\)/, '大屏告警弹框使用全长标签')
  assert.match(screen, /eventActionShort\(event\.action\)/, '事件流紧凑位使用短标签')
  assert.doesNotMatch(screen, /function actionLabel/, '本地映射函数必须删除')

  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /from '@\/utils\/eventAction'/)
  assert.match(events, /eventActionShort\(row\.action, row\.rule_triggered\)/)
  assert.match(events, /eventActionFull\(ctxEvent\.action, ctxEvent\.rule_triggered\)/)
  assert.doesNotMatch(events, /row\.action === 'blocked' \? '拦截' : '检测'/, '列表本地三元必须退役')

  const trigger = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(trigger, /from '@\/utils\/eventAction'/)
  assert.match(trigger, /eventActionFull\(row\?\.action, row\?\.rule_triggered\)/)
  assert.doesNotMatch(trigger, /:type="ccResultTone"/, '挑战结果由 hero 动作标签唯一展示，明细不再重复 ccResult 标签')
  assert.doesNotMatch(trigger, /trigDetail\.sourceIp/, '来源 IP 已在 hero 区展示，meta 不得重复')
  assert.match(trigger, /case 'human': return t\('common\.app\.views\.trigDetail\.humanSummary'/, 'human 专属配置摘要，不误用 ACL 摘要')
  assert.match(events, /colAction'\)" width="85"/, '英文 Challenge 需要 5px 余量')
  assert.doesNotMatch(trigger, /已记录（检测）/, '第四份措辞必须退役')
  // 2026-11-13 用户裁定：彩色类别标签对 human 显示验证模式（智能触发/始终验证），
  // 不再与右侧 heroStage「阶段 2 · CC 防护」重复同一文案。断言限定 categoryLabel
  // 块内——heroStage 合法使用阶段文案，不得被全局否定断言误伤。
  const categoryBlock = section(trigger, 'const categoryLabel = computed(() => {', '\n})')
  assert.match(categoryBlock, /case 'human': \{[\s\S]*?stages\.humanMode_force[\s\S]*?stages\.humanMode_auto/, 'human 彩色标签必须显示验证模式')
  assert.doesNotMatch(categoryBlock, /trigDetail\.stageHuman/, 'human 彩色标签不得复用阶段文案（与 heroStage 重复）')
})
