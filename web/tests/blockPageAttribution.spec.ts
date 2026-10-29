// 拦截页归因行为验收：逐条对照后端渲染事实
//   internal/services/caddy.go —— buildBlockPageErrorRoute（阶段 1 预检合并 403 兜底）、
//   buildRateLimitErrorRoute（阶段 2 恒 429）、blockStatusForPolicy（阶段 3 逐策略
//   合成码 483+，规则级 stage3 覆盖 → 恒 482）、阶段 1/3 规则级覆盖路由（481/482）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  blockPageMissing,
  resolveBlockPageAttribution,
  type BlockPageChainPolicy,
} from '../src/utils/securityStages.ts'
import { code, repoCode, section } from './_helpers.ts'

const peer = (over: Partial<BlockPageChainPolicy> = {}): BlockPageChainPolicy => ({
  policyId: 1,
  name: 'peer',
  enabled: true,
  isSelf: false,
  blockPageId: 0,
  pageHasContent: false,
  rateLimitEnabled: false,
  ...over,
})
const self = (over: Partial<BlockPageChainPolicy> = {}): BlockPageChainPolicy => ({
  policyId: 9,
  name: 'self',
  enabled: true,
  isSelf: true,
  blockPageId: 0,
  pageHasContent: false,
  rateLimitEnabled: false,
  ...over,
})

test('阶段 3：本策略有有效页即本策略页（逐策略合成码，与绑定序无关）', () => {
  // 对端 id 更小且也有页——阶段 3 仍是「哪条策略触发就显示哪条策略的页」
  const chain = [peer({ policyId: 1, blockPageId: 5, pageHasContent: true }), self({ blockPageId: 7, pageHasContent: true })]
  assert.deepEqual(resolveBlockPageAttribution(3, chain), { stage: 3, effective: 'self' })
})

test('阶段 3：本策略无页/页失效 → 回落首个有页策略的 403 兜底页', () => {
  const chain = [peer({ policyId: 1, blockPageId: 5, pageHasContent: true }), self({ blockPageId: 7, pageHasContent: false })]
  const result = resolveBlockPageAttribution(3, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, 'peer')
})

test('阶段 3：规则级 stage3 覆盖在场时压过逐策略归因', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: true })]
  const result = resolveBlockPageAttribution(3, chain, { pageId: 11, pageHasContent: true })
  assert.equal(result.effective, 'rule-override')
})

test('阶段 1：取绑定链首个启用且有非空页的策略（幂等排序即 policy_id ASC）', () => {
  const chain = [
    self({ policyId: 9, blockPageId: 7, pageHasContent: true }),
    peer({ policyId: 1, blockPageId: 0 }),          // 无页不参与
    peer({ policyId: 2, blockPageId: 5, pageHasContent: false }), // 空内容页视为无页
    peer({ policyId: 3, blockPageId: 6, pageHasContent: true, name: '首绑定有页策略' }),
  ]
  const result = resolveBlockPageAttribution(1, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '首绑定有页策略', '必须是链上首个有页策略，而不是本策略')
})

test('阶段 1：本策略即首个有页策略时页面生效', () => {
  const chain = [peer({ policyId: 2, blockPageId: 0 }), self({ policyId: 9, blockPageId: 7, pageHasContent: true })]
  assert.equal(resolveBlockPageAttribution(1, chain).effective, 'self')
})

test('阶段 1：规则级 stage1 覆盖（481）压过策略页', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: true })]
  assert.equal(resolveBlockPageAttribution(1, chain, { pageId: 4, pageHasContent: true }).effective, 'rule-override')
})

test('规则级覆盖页内容为空 = 覆盖无效（后端按无覆盖渲染）', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: true })]
  assert.equal(resolveBlockPageAttribution(1, chain, { pageId: 4, pageHasContent: false }).effective, 'self')
  assert.equal(resolveBlockPageAttribution(3, chain, { pageId: 4, pageHasContent: false }).effective, 'self')
})

test('阶段 2：无启用限流策略时不产生 429 → none', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: true, rateLimitEnabled: false })]
  assert.equal(resolveBlockPageAttribution(2, chain).effective, 'none')
})

test('阶段 2：429 页取首个有页策略（即使该策略未开启限流，与后端同口径）', () => {
  const chain = [
    self({ policyId: 9, blockPageId: 7, pageHasContent: true, rateLimitEnabled: true }),
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, rateLimitEnabled: false, name: '首个有页策略' }),
  ]
  const result = resolveBlockPageAttribution(2, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '首个有页策略')
})

test('阶段 2：规则级覆盖不参与（限流页面无阶段页覆盖层）', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: true, rateLimitEnabled: true })]
  const result = resolveBlockPageAttribution(2, chain, { pageId: 4, pageHasContent: true })
  assert.equal(result.effective, 'self')
})

test('禁用策略不参与链路（后端只加载 enabled 策略）', () => {
  const chain = [
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, enabled: false }),
    self({ policyId: 9, blockPageId: 7, pageHasContent: true }),
  ]
  assert.equal(resolveBlockPageAttribution(1, chain).effective, 'self')
  // 自身禁用 → 无页面生效
  const disabledSelf = [self({ blockPageId: 7, pageHasContent: true, enabled: false })]
  assert.equal(resolveBlockPageAttribution(3, disabledSelf).effective, 'none')
})

test('全链无有效页 → none（回落 Caddy 默认 403）', () => {
  const chain = [peer({ blockPageId: 0 }), self({ blockPageId: 7, pageHasContent: false })]
  assert.equal(resolveBlockPageAttribution(1, chain).effective, 'none')
  assert.equal(resolveBlockPageAttribution(3, chain).effective, 'none')
})

test('拦截页列表未落地时不得判定缺失（不出假警告）', () => {
  const pages = [{ id: 7, content: '<p>blocked</p>' }]
  // 未落地：任何判定都返回 false（「未知」而非「已删除」）
  assert.equal(blockPageMissing(7, pages, false), false)
  assert.equal(blockPageMissing(9, pages, false), false)
  // 已落地：存在且内容非空 → 不缺失
  assert.equal(blockPageMissing(7, pages, true), false)
  // 页被删除 / 内容为空 → 缺失
  assert.equal(blockPageMissing(9, pages, true), true)
  assert.equal(blockPageMissing(8, [{ id: 8, content: '' }], true), true)
  // 未配置自定义页（id<=0）不是缺失
  assert.equal(blockPageMissing(0, pages, true), false)
})

// 跨栈对表：上面十几条行为用例预测的是「后端会渲染哪个页」——后端改阶段码或
// 归因分支时，纯函数用例不会红。此处钉住后端函数/常量/分支仍在，Go 侧改动即红
// 并强制人工复核前端预测。
test('跨栈对表：后端阶段码与归因分支仍与前端预测同口径', () => {
  const go = repoCode('internal/services/caddy.go')
  // 合成码域：阶段 1=481、阶段 3=482、逐策略 483+
  assert.match(go, /blockPageStage1Code\s*=\s*481/)
  assert.match(go, /blockPageStage3Code\s*=\s*482/)
  assert.match(go, /blockPageSyntheticBase\s*=\s*483/)
  // 阶段 1：仅规则级覆盖页内容非空时抬 481
  const stage1 = section(go, 'func stage1BlockStatus(', '\nfunc ')
  assert.match(stage1, /rule\.BlockPageStage1ID > 0/)
  assert.match(stage1, /securityCtx\.blockPageByID\[rule\.BlockPageStage1ID\]/)
  assert.match(stage1, /return blockPageStage1Code/)
  // 阶段 3：规则级覆盖压过逐策略合成码（前端「覆盖 > self」的前提）
  const stage3 = section(go, 'func blockStatusForPolicy(', '\nfunc ')
  assert.match(stage3, /rule\.BlockPageStage3ID > 0/)
  assert.match(stage3, /return blockPageStage3Code/)
  assert.match(stage3, /return securityCtx\.policySynthetic\[policy\.ID\]/)
  // 兜底路由：取首个「内容非空」页（空内容页不得遮蔽后续），状态码 0 归一 403
  const fallback = section(go, 'func buildBlockPageErrorRoute(', '\nfunc ')
  // 首个非空页选择已抽为单源 helper（43 行内联扫描 ×2 → firstPolicyWithBlockPage）
  assert.match(fallback, /firstPolicyWithBlockPage\(policies, securityCtx\.blockPageByID\)/)
  assert.match(fallback, /statusCode = 403/)
  // 阶段 2：至少一条启用策略开启限流才产生该路由；页取首个有页策略
  const rate = section(go, 'func buildRateLimitErrorRoute(', '\nfunc ')
  assert.match(rate, /if policy\.RateLimitEnabled \{/)
  assert.match(rate, /if !rateLimited \|\| pagePolicy == nil \{/)
})

// ---- 接线钉：视图是否真的消费上面的单源实现（纯函数测试全绿但视图回退不会红）----

test('接线：SecurityPolicies 逐阶段归因消费 resolveBlockPageAttribution', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /import \{[^}]*resolveBlockPageAttribution[^}]*\} from '@\/utils\/securityStages'/)
  assert.match(text, /const results = stages\.map\(\(stage\) =>\s*resolveBlockPageAttribution\(/)
  // 旧恒绿表达式必须消失（enabled && block_page_id>0 即「生效中」）
  assert.doesNotMatch(text, /selfBlockPageActive/)
  assert.match(text, /blockPageNotes: blockPageNotes\(caddyId, chain\)/)
  // 模板按 note.kind 渲染（active/disabled/warning/info）
  assert.match(text, /v-for="\(note, i\) in row\.blockPageNotes"/)
})

test('接线：拦截页缺失判定消费单源谓词且受加载门约束', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /blockPageMissing\(e\.blockPageId \?\? 0, blockPages\.value, blockPagesLoaded\.value\)/)
  assert.match(text, /if \(bpRes\.status === 'fulfilled'\) \{ blockPages\.value = bpRes\.value\.data \|\| \[\]; blockPagesLoaded\.value = true \}/)
  // 归因侧同样不得在列表未落地时假设页面存在
  assert.match(text, /blockPagesLoaded\.value && id > 0 && !blockPageMissing\(/)
})
