// CC 结果词（触发详情 hero 命中源）：cc_rate_reject（429 限流拒绝）必须显示
// 拒绝词，不得回落「发放挑战」。带外/集群回插的 CC 拒绝事件 rule_name 为空，
// hero 走 heroHumanHit({result}) 路径——结果词错译即用户可见误报。
// 归因词与后端 autobanBanReason（限流拒绝）同语义，跨栈钉。
//
// 运行：cd web && node --test tests/ccRateRejectResult.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tSafe as t } from '../src/i18n/tSafe.ts'
import { code, member, repoCode } from './_helpers.ts'

const trigger = code('src/components/events/TriggerDetailDialog.vue')

test('ccResultText 四分支：拒绝/通过/失败/发放（拒绝先于兜底）', () => {
  const body = member(trigger, 'const ccResultText = computed')
  assert.match(body, /if \(rule === 'cc_rate_reject'\) return t\('common\.app\.views\.trigDetail\.ccResultRateReject'\)/, 'cc_rate_reject 必须有专属拒绝词分支')
  assert.match(body, /if \(rule === 'human_pass'\) return t\('common\.app\.views\.trigDetail\.ccResultPass'\)/)
  assert.match(body, /if \(rule === 'human_failed'\) return t\('common\.app\.views\.trigDetail\.ccResultFail'\)/)
  assert.match(body, /return t\('common\.app\.views\.trigDetail\.ccResultChallenge'\)/, '其余 token 保持发放兜底')
  // 空 rule_name × cc_rate_reject：hero 命中源消费结果词（拒绝词可达路径）
  assert.match(trigger, /ev\.rule_name \? t\('common\.app\.views\.trigDetail\.heroHumanRule', \{ name: ev\.rule_name \}\) : t\('common\.app\.views\.trigDetail\.heroHumanHit', \{ result: ccResultText\.value \}\)/)
})

test('拒绝词词条 zh/en 成对，且与后端归因词同语义', () => {
  const zh = t('common.app.views.trigDetail.ccResultRateReject')
  assert.equal(zh, '限流拒绝', 'zh 拒绝词与 autobanBanReason 归因词逐字一致')
  assert.notEqual(zh, 'common.app.views.trigDetail.ccResultRateReject', '键必须已注册（不得裸键回显）')
  const en = code('src/locales/en/views.ts')
  assert.match(en, /'ccResultRateReject': 'Rate-limited rejection'/, 'en 拒绝词成对在场')
  const go = repoCode('internal/services/autoban.go')
  assert.ok(go.includes('ruleTriggered == "cc_rate_reject"'), '后端 cc_rate_reject 归因分支必须在场')
  assert.ok(go.includes('return "限流拒绝"'), '后端归因词漂移即跨栈失配')
})
