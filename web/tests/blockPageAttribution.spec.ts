// 拦截页归因行为验收：触发归因口径（用户裁定：触发哪条策略 → 显示该策略自己
// 配置的拦截页；未配置 → 兜底 = 绑定链首个「启用且有非空页」策略）。
//
// 后端渲染事实（internal/services/caddy.go，Go 侧同步改造）：
//   - 阶段 1 按触发子源分流：ACL deny 链 / 独立黑名单链 / GeoIP 链逐策略归因
//     （触发策略有页 → 逐策略合成码显示该策略页）；allow 白名单交集外恒拒
//     （id:7）走兜底路由（绑定链首个有页策略），无归属语义。
//   - 阶段 2：429 恒走兜底路由（至少一条启用策略开启限流才产生）。
//   - 阶段 3：WAF 段逐策略合成码（483+），触发策略有页 → 该策略页。
//   - 规则级阶段页覆盖（481/482）已退役：无规则级覆盖层。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
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
  ...over,
})
const self = (over: Partial<BlockPageChainPolicy> = {}): BlockPageChainPolicy => ({
  policyId: 9,
  name: 'self',
  enabled: true,
  isSelf: true,
  blockPageId: 0,
  pageHasContent: false,
  ...over,
})

test('阶段 3：本策略有有效页即本策略页（逐策略合成码，与绑定序无关）', () => {
  // 对端 id 更小且也有页——仍是「哪条策略触发就显示哪条策略的页」
  const chain = [peer({ policyId: 1, blockPageId: 5, pageHasContent: true }), self({ blockPageId: 7, pageHasContent: true })]
  assert.deepEqual(resolveBlockPageAttribution(3, chain), { stage: 3, effective: 'self' })
})

test('阶段 3：本策略无页/页失效 → 兜底首个有页策略', () => {
  const chain = [peer({ policyId: 1, blockPageId: 5, pageHasContent: true }), self({ blockPageId: 7, pageHasContent: false })]
  const result = resolveBlockPageAttribution(3, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, 'peer')
})

test('阶段 3：空内容页视为无页（后端 blockPageByID 非空才算有效页）', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: false }), peer({ policyId: 2, blockPageId: 5, pageHasContent: true, name: '有效页策略' })]
  const result = resolveBlockPageAttribution(3, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '有效页策略')
})

// ── 阶段 1：按触发子源分流（deny 链逐策略归因 / allow 交集恒拒走兜底） ──

test('阶段 1：本策略发射 deny 链（ACL deny/黑名单/GeoIP）且有有效页 → 本策略页', () => {
  // 对端 id 更小且在链首有页——deny 触发仍按触发策略归因，不做链首位抢页
  const chain = [
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true }),
    self({ policyId: 9, blockPageId: 7, pageHasContent: true, stage1DenyContributor: true }),
  ]
  assert.deepEqual(resolveBlockPageAttribution(1, chain), { stage: 1, effective: 'self' })
})

test('阶段 1：deny 策略无页 → 兜底链首个有页策略', () => {
  const chain = [
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, name: '兜底策略' }),
    self({ policyId: 9, blockPageId: 7, pageHasContent: false, stage1DenyContributor: true }),
  ]
  const result = resolveBlockPageAttribution(1, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '兜底策略')
})

test('阶段 1：allow 白名单策略无归属语义（交集恒拒走兜底路由）', () => {
  // allow-only 策略自身不发射 deny 链：即便配置了页，阶段 1 归因也不因「本策略触发」
  // 而生效——只有当它恰为链首有页策略（兜底路由目标）时才判 self。
  const chain = [
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, name: '链首有页策略' }),
    self({ policyId: 9, blockPageId: 7, pageHasContent: true, stage1DenyContributor: false }),
  ]
  const result = resolveBlockPageAttribution(1, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '链首有页策略')
})

test('阶段 1：allow 策略恰为链首有页策略时，兜底显示本策略页（判 self）', () => {
  const chain = [
    self({ policyId: 1, blockPageId: 7, pageHasContent: true, stage1DenyContributor: false }),
    peer({ policyId: 2, blockPageId: 0, stage1DenyContributor: true }),
  ]
  // peer 的 deny 链触发且无页 → 403 落兜底路由 = 链首个有页策略 = 本策略
  assert.deepEqual(resolveBlockPageAttribution(1, chain), { stage: 1, effective: 'self' })
})

test('阶段 1：allow 策略无归属语义，页显示只由兜底路由决定', () => {
  // allow-only 策略自身不发射 deny 链：即便配置了页，阶段 1 归因也不因「本策略触发」
  // 而生效——链首有页策略是对端时判 peer。
  const chain = [
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, name: '链首有页策略' }),
    self({ policyId: 9, blockPageId: 7, pageHasContent: true, stage1DenyContributor: false }),
  ]
  const result = resolveBlockPageAttribution(1, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '链首有页策略')
})

test('阶段 2：配额限流已下线 → 拦截页恒 none', () => {
  const chain = [
    self({ blockPageId: 7, pageHasContent: true }),
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, name: '其他策略' }),
  ]
  assert.deepEqual(resolveBlockPageAttribution(2, chain), { stage: 2, effective: 'none' })
})

test('跨栈对表：规则级覆盖退役 + 兜底路由与限流门仍在', () => {
  const go = repoCode('internal/services/caddy.go')
  // 规则级阶段页覆盖（481/482 抬码与路由）已退役——回归即红
  assert.doesNotMatch(go, /blockPageStage1Code\s*=\s*481/)
  assert.doesNotMatch(go, /blockPageStage3Code\s*=\s*482/)
  assert.doesNotMatch(go, /func stage1BlockStatus\(/)
  // 逐策略合成码域保留（阶段 1 deny 链 / 阶段 3 归因）
  assert.match(go, /blockPageSyntheticBase\s*=\s*483/)
  // 兜底路由：取首个「内容非空」页（空内容页不得遮蔽后续），状态码 0 归一 403
  const fallback = section(go, 'func buildBlockPageErrorRoute(', '\nfunc ')
  assert.match(fallback, /firstPolicyWithBlockPage\(policies, securityCtx\.blockPageByID\)/)
  assert.match(fallback, /statusCode = 403/)
  // 配额限流已下线：生成层不得再出现 rate_limit handler / 429 错误路由
  assert.doesNotMatch(go, /func buildRateLimitErrorRoute\(/)
  assert.doesNotMatch(go, /func buildRateLimitHandler\(/)
  assert.doesNotMatch(go, /"handler":\s*"rate_limit"/)
})

// ---- 接线钉：视图是否真的消费上面的单源实现（纯函数测试全绿但视图回退不会红）----

test('接线：SecurityPolicies 逐阶段归因消费 resolveBlockPageAttribution（无覆盖层入参）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /import \{[^}]*resolveBlockPageAttribution[^}]*\} from '@\/utils\/securityStages'/)
  // 逐阶段归因经 capableAttributions 单点调用（能力门过滤 + 单源判定同处）：
  assert.match(text, /\.map\(\(stage\) => resolveBlockPageAttribution\(stage, attributionInput\(chain\)\)\)/)
  // 规则级覆盖层入参与暂存读路径必须退役（触发归因无第三参）
  assert.doesNotMatch(text, /overrideFor/)
  assert.doesNotMatch(text, /rule-override/)
  assert.doesNotMatch(text, /rowAttributionBadge/, '逐行徽标判定已随拦截页必选退役（用户裁定：常态无信息量）')
})

test('拦截页步骤：汇总卡替代逐条重复提示（主行 + 例外分面 + 能力门行）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  // 顶部说明一句话直白化（去括号嵌套/内部术语/阶段编号），右侧计数小标签。
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.policies\.bp\.projection'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('触发本策略拦截时，向客户端返回下方选择的拦截页'), '顶部说明原文必须在 zh 母本词条中')
  assert.doesNotMatch(text, /恒走兜底路由/, '内部术语不得回流')
  assert.match(text, /t\('app\.security\.policies\.bind\.relatedCount', \{ n: boundRules\.length \}\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('已关联 {n} 条规则'), '计数小标签原文必须在 zh 母本词条中')
  // 汇总卡：主行 + 例外分面（仅存在才渲染）+ 数据源复用绑定链/归因单源
  assert.match(text, /const blockPageSummary = computed/)
  assert.match(text, /t\('app\.security\.policies\.bp\.pageActive', \{ n: total, page: pageName \}\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('均显示本拦截页「{page}」'), '汇总主行原文必须在 zh 母本词条中')
  assert.match(text, /if \(tcpCount > 0\)/, 'TCP 例外行条件渲染')
  assert.match(text, /if \(fallbackCount > 0\)/, '兜底差异例外行条件渲染')
  assert.match(text, /boundRuleRows\.value\)/, '汇总数据源=绑定列表单源（禁平行实现）')
  assert.match(text, /t\('app\.security\.policies\.bp\.stageIneffective', \{ stage: BLOCK_PAGE_STAGE_LABEL\[stage\] \}\)/, '能力门警告行保留')
  assert.ok(code('src/locales/zh/security.ts').includes('当前配置不会产生该阶段拦截，页面不会被使用'), '能力门警告原文必须在 zh 母本词条中')
  assert.match(text, /v-for="line in blockPageSummary\.lines"/)
  // 逐条重复渲染退役
  assert.doesNotMatch(text, /block-page-rule-annotations/)
  assert.doesNotMatch(text, /row\.blockPageNotes/)
  assert.doesNotMatch(text, /const blockPageNotes = /)
})

test('接线：关联规则归属提示退役（常态信息由汇总行承载，逐条徽标/整句退役）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.doesNotMatch(text, /rowAttributionBadge/, '徽标判定单源已退役')
  assert.doesNotMatch(text, /显示本策略页/, '两态徽标文案退役（拦截页必选，常态恒 self 无信息量）')
  assert.doesNotMatch(text, /bound-rule-attribution/, '徽标样式随行退役')
  // 汇总行保留（info-note 规范）：N 条规则 + 兜底归属一句话。
  // i18n 后双钉:调用点钉键,zh 母本钉两句原文(任一漂移必红)
  assert.match(text, /t\('app\.security\.policies\.bp\.bindingsAttribution', \{ n: total, winner: winnerPart \}\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('触发各策略拦截时，分别显示该策略自己配置的拦截页'), '归属汇总原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('显示兜底页（首个启用拦截页的策略'), '兜底归属原文必须在 zh 母本词条中')
})

test('接线：拦截页缺失判定消费单源谓词且受加载门约束', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /blockPageMissing\(e\.blockPageId \?\? 0, blockPages\.value, blockPagesLoaded\.value\)/)
  assert.match(text, /if \(bpRes\.status === 'fulfilled'\) \{ blockPages\.value = bpRes\.value\.data \|\| \[\]; blockPagesLoaded\.value = true \}/)
  // 归因侧同样不得在列表未落地时假设页面存在
  assert.match(text, /blockPagesLoaded\.value && id > 0 && !blockPageMissing\(/)
})
