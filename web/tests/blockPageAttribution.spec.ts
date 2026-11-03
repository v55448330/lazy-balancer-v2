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

test('阶段 2：无启用限流策略时不产生 429 → none', () => {
  const chain = [self({ blockPageId: 7, pageHasContent: true, rateLimitEnabled: false })]
  assert.equal(resolveBlockPageAttribution(2, chain).effective, 'none')
})

test('阶段 2：429 恒走兜底路由（链首个有页策略），与本策略是否触发无关', () => {
  // 链序（入参序）=绑定执行序：peer 在前即兜底目标为 peer
  const chain = [
    peer({ policyId: 1, blockPageId: 5, pageHasContent: true, rateLimitEnabled: false, name: '首个有页策略' }),
    self({ policyId: 9, blockPageId: 7, pageHasContent: true, rateLimitEnabled: true }),
  ]
  const result = resolveBlockPageAttribution(2, chain)
  assert.equal(result.effective, 'peer')
  assert.equal(result.winnerName, '首个有页策略')
})

test('阶段 2：本策略为链首个有页策略时判 self（兜底路由目标即本策略）', () => {
  const chain = [
    self({ policyId: 9, blockPageId: 7, pageHasContent: true, rateLimitEnabled: true }),
    peer({ policyId: 1, blockPageId: 0, rateLimitEnabled: false }),
  ]
  assert.deepEqual(resolveBlockPageAttribution(2, chain), { stage: 2, effective: 'self' })
})

test('禁用策略不参与链路（后端只加载 enabled 策略）', () => {
  // 对端禁用不参与兜底扫描；本策略是链内唯一有效页 → 兜底目标=本策略（判 self）
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

// 跨栈对表：上面行为用例预测「后端会渲染哪个页」——后端改归因分支时，纯函数
// 用例不会红。此处钉住新契约的后端形状（481/482 规则级覆盖退役 + 兜底路由仍在），
// Go 侧改动即红并强制人工复核前端预测。
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
  // 阶段 2：至少一条启用策略开启限流才产生该路由；页取首个有页策略
  const rate = section(go, 'func buildRateLimitErrorRoute(', '\nfunc ')
  assert.match(rate, /if policy\.RateLimitEnabled \{/)
  assert.match(rate, /if !rateLimited \|\| pagePolicy == nil \{/)
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
  assert.match(text, /attributionBadge: rowAttributionBadge\(chain\)/)
})

test('拦截页步骤：汇总卡替代逐条重复提示（主行 + 例外分面 + 能力门行）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  // 顶部说明一句话直白化（去括号嵌套/内部术语/阶段编号），右侧计数小标签
  assert.match(text, /触发本策略拦截时，向客户端返回下方选择的拦截页/)
  assert.doesNotMatch(text, /恒走兜底路由/, '内部术语不得回流')
  assert.match(text, /已关联 \{\{ boundRules\.length \}\} 条规则/)
  // 汇总卡：主行 + 例外分面（仅存在才渲染）+ 数据源复用绑定链/归因单源
  assert.match(text, /const blockPageSummary = computed/)
  assert.match(text, /均显示本拦截页「/)
  assert.match(text, /if \(rateLimitCount > 0\)/, '限流例外行条件渲染')
  assert.match(text, /if \(tcpCount > 0\)/, 'TCP 例外行条件渲染')
  assert.match(text, /if \(fallbackCount > 0\)/, '兜底差异例外行条件渲染')
  assert.match(text, /boundRuleRows\.value\)/, '汇总数据源=绑定列表单源（禁平行实现）')
  assert.match(text, /当前配置不会产生该阶段拦截，页面不会被使用/, '能力门警告行保留')
  assert.match(text, /v-for="line in blockPageSummary\.lines"/)
  // 逐条重复渲染退役
  assert.doesNotMatch(text, /block-page-rule-annotations/)
  assert.doesNotMatch(text, /row\.blockPageNotes/)
  assert.doesNotMatch(text, /const blockPageNotes = /)
})

test('接线：关联规则行内紧凑标识 + 汇总行（逐条整句退役）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  // 行内归属描述收敛为两态小标签（不再每行重复整句）
  assert.match(text, /rowAttributionBadge\(chain\)/)
  assert.match(text, /显示本策略页/)
  assert.match(text, /显示兜底页/)
  assert.doesNotMatch(text, /触发该策略拦截时：显示本策略配置的拦截页/, '逐条整句已退役')
  assert.doesNotMatch(text, /bound-rule-attribution-item/, '整句行样式随行退役')
  // 汇总行（info-note 规范）：N 条规则 + 兜底归属一句话
  assert.match(text, /触发各策略拦截时，分别显示该策略自己配置的拦截页/)
  assert.match(text, /显示兜底页（首个启用拦截页的策略/)
})

test('接线：拦截页缺失判定消费单源谓词且受加载门约束', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  assert.match(text, /blockPageMissing\(e\.blockPageId \?\? 0, blockPages\.value, blockPagesLoaded\.value\)/)
  assert.match(text, /if \(bpRes\.status === 'fulfilled'\) \{ blockPages\.value = bpRes\.value\.data \|\| \[\]; blockPagesLoaded\.value = true \}/)
  // 归因侧同样不得在列表未落地时假设页面存在
  assert.match(text, /blockPagesLoaded\.value && id > 0 && !blockPageMissing\(/)
})
