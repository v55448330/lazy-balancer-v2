// 处理流程弹框 TCP（L4）明细口径（2026-10-31 用户裁定）：
//   ①删除「TCP 规则支持阶段 0/1 安全能力…」信息块——能力边界已由阶段行灰态
//     （阶段 2/3「TCP 规则不适用」）与脚注承载，头部说明属重复信息；
//   ②阶段 1 策略明细的「拦截页」行在 TCP 规则下显示「不支持」——现文案
//     「未配置（跟随绑定链首个有效页…）」是 HTTP 渲染语义（403/429 错误路由），
//     L4 拒绝=断连，拦截页整族不参与；
//   ③阶段面板右上「拦截页跟随策略」tag 在 TCP 下改「拦截页不支持」。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildStageModel } from '../src/utils/securityStages.ts'
import type { SecurityStageBinding, SecurityStagePolicy } from '../src/utils/securityStages.ts'
import { code } from './_helpers.ts'
import { stagePolicy } from './fixtures/stagePolicy.ts'

const dialog = code('src/components/RuleFlowDialog.vue')

test('信息块已删除：TCP 能力说明不再整块重复（灰态与脚注已承载）', () => {
  assert.doesNotMatch(dialog, /TCP 规则支持阶段 0\/1 安全能力/)
  assert.doesNotMatch(dialog, /拒绝动作=断连（无拦截页），限流与 WAF 阶段不适用/, '信息块副文案随块删除')
})

test('阶段 1 面板头 tag：TCP 下显示「拦截页不支持」，HTTP 保持「拦截页跟随策略」', () => {
  assert.match(dialog, /isTcp \? '拦截页不支持' : '拦截页跟随策略'/)
})

// ── 模型行为：拦截页行的 TCP 口径 ──

const binding = (): SecurityStageBinding => ({
  policy_id: 1,
  name: '策略 A',
  mode: 'off',
  enabled: true,
  rate_limit_enabled: false,
})

const aclPolicy = (): SecurityStagePolicy =>
  stagePolicy({
    id: 1,
    name: '策略 A',
    mode: 'off',
    has_ip_control: true,
    ip_acl_enabled: true,
    ip_acl_list: '["10.0.0.0/8"]',
    block_page_id: 7,
    block_status_code: 403,
  })

const pages = [{ id: 7, name: '页七', content: '<p>x</p>' }]

const stage1Rows = (protocol: string): Array<{ label: string; detail: string }> =>
  buildStageModel([binding()], [aclPolicy()], [], pages, {
    // 规则形状 = lb_rules 行的消费面（buildStageModel 第 5 参）：协议 + 阶段页覆盖 4 字段
    protocol,
    block_page_stage1_id: 0,
    block_page_stage1_status: 0,
    block_page_stage3_id: 0,
    block_page_stage3_status: 0,
  }).stages[1].groups[0]?.rows ?? []

test('TCP 规则：阶段 1「拦截页」行显示「不支持」，HTTP 语义文案整族退场', () => {
  const rows = stage1Rows('tcp')
  assert.deepEqual(rows.find((row) => row.label === '拦截页'), { label: '拦截页', detail: '不支持' })
  assert.equal(rows.some((row) => row.detail.includes('跟随绑定链')), false, '「跟随绑定链首个有效页」是 HTTP 错误路由语义，TCP 下不得出现')
  assert.equal(rows.some((row) => row.label === '拦截页（策略页）'), false, '策略页行同为 HTTP 渲染面，TCP 下并入「不支持」口径')
})

test('HTTP 规则：拦截页行保持既有文案（回归钉）', () => {
  const rows = stage1Rows('http')
  assert.deepEqual(rows.find((row) => row.label === '拦截页'), { label: '拦截页', detail: '未配置（跟随绑定链首个有效页，无则默认 403）' })
  assert.deepEqual(rows.find((row) => row.label === '拦截页（策略页）'), { label: '拦截页（策略页）', detail: '页七（状态码 403）' })
})

test('协议缺省（旧调用形状）：按 HTTP 口径不回退', () => {
  // SecurityPolicies 向导预览传 null——无协议字段的调用面必须保持既有行为
  const rows = buildStageModel([binding()], [aclPolicy()], [], pages, null).stages[1].groups[0]?.rows ?? []
  assert.equal(rows.find((row) => row.label === '拦截页')?.detail, '未配置（跟随绑定链首个有效页，无则默认 403）')
})

test('锁摘要与流程弹框共用模型：TCP 行为钉在单源（buildStageModel）上', () => {
  // Rules.vue 两处 buildStageModel 直接传规则行（含 protocol）——协议无需调用方额外传参
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /securityBindings\.value\[rule\.caddy_id\] \|\| \[\],\n\s*securityPolicies\.value,\n\s*ipLists\.value,\n\s*blockPages\.value,\n\s*rule,/, '锁摘要模型以规则行为 stagePages（协议随行携带）')
})
