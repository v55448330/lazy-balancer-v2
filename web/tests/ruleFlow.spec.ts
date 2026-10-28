import { test } from 'node:test'
import assert from 'node:assert/strict'
import { projectRuleFlowPath } from '../src/utils/ruleFlow.ts'
import { stage1FootnoteText, stageSubLabel } from '../src/utils/securityStages.ts'
import type { PathRule } from '../src/types/rules.ts'
import { repoCode } from './_helpers.ts'

const base: PathRule = {
  match_type: 'prefix', path: '/api', upstream_path: '', sort_order: 0, upstreams: null,
}

test('upstreams=null 投影保留默认上游语义', () => {
  assert.deepEqual(projectRuleFlowPath(base), {
    path: '/api', match_type: 'prefix', upstreams: null,
  })
})

test('自定义上游仍投影为启用明细', () => {
  assert.deepEqual(projectRuleFlowPath({
    ...base,
    upstreams: [{ protocol: 'http', address: '10.0.0.2', port: 8080, weight: 100 }],
  }), {
    path: '/api', match_type: 'prefix',
    upstreams: [{ host: '10.0.0.2', port: 8080, enabled: true }],
  })
})

test('静态返回与 301 回归形状保持', () => {
  assert.deepEqual(projectRuleFlowPath({ ...base, response_mode: 'static', response_status: 204 }), {
    path: '/api', match_type: 'prefix', upstreams: null,
    response_mode: 'static', response_status: 204, redirect_to: '',
  })
  assert.equal(projectRuleFlowPath({ ...base, response_mode: 'redirect', redirect_to: 'https://example.com' }).response_mode, 'redirect')
})

// 处理流程弹框的阶段 1 文案：副标题与脚注必须覆盖渲染链全部拦截
// 来源——遗留黑名单字段 ip_blacklist（id:4 仍发射）与 v2.3.8 爬虫校验
// （豁免 810000-849999 / 伪装拦截 850000-899999），链序按发射顺序。
test('阶段 1 文案：副标题与脚注含爬虫校验，脚注含遗留黑名单且链序正确', () => {
  assert.match(stageSubLabel(1), /爬虫校验/)
  const footnote = stage1FootnoteText(false)
  assert.match(footnote, /遗留黑名单（旧字段）/)
  assert.match(footnote, /爬虫校验/)
  // 地域拦截取最后一次出现（「白名单命中豁免地域拦截」括号内先出现一次）
  const order: Array<[string, number]> = [
    ['信任', footnote.indexOf('信任')],
    ['黑名单', footnote.indexOf('黑名单')],
    ['遗留黑名单', footnote.indexOf('遗留黑名单')],
    ['白名单外拒绝', footnote.indexOf('白名单外拒绝')],
    ['爬虫校验', footnote.indexOf('爬虫校验')],
    ['地域拦截', footnote.lastIndexOf('地域拦截')],
  ]
  for (const [token, position] of order) assert.ok(position >= 0, `脚注缺少环节：${token}`)
  const positions = order.map(([, position]) => position)
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b), '阶段 1 链序与渲染发射顺序不一致')

  // 跨栈机械钉：脚注的环节顺序必须等于渲染器的实际发射顺序。锚点取
  // buildIPPrecheckDirectives 内的规则动作/消息（id:3 信任 → id:2 黑名单 →
  // id:4 遗留黑名单 → 白名单外拒绝 id:7 → 爬虫校验 → GeoIP 地域链）。Go
  // 单侧改序而脚注未同步、或脚注改序而发射未变，都会在此变红。
  const goBlock = repoCode('internal/services/security.go')
  const precheck = goBlock.slice(
    goBlock.indexOf('func buildIPPrecheckDirectives('),
    goBlock.indexOf('\nfunc ', goBlock.indexOf('func buildIPPrecheckDirectives(') + 1),
  )
  assert.ok(precheck.includes('func buildIPPrecheckDirectives(') && !precheck.includes('\nfunc '), '预检函数切片必须闭合')
  const anchors: Record<string, RegExp> = {
    信任: /id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly/,
    黑名单: /msg:'IP 黑名单拒绝'/,
    遗留黑名单: /msg:'IP 黑名单'(?!拒)/,
    白名单外拒绝: /msg:'IP 白名单拒绝'/,
    爬虫校验: /X-LB-Crawler-Verified/,
    地域拦截: /msg:'GeoIP 区域拦截'/,
  }
  const emission = order.map(([token]) => {
    const hit = anchors[token]
    assert.ok(hit, `缺少环节锚点：${token}`)
    const at = precheck.search(hit)
    assert.ok(at >= 0, `渲染器未发射环节：${token}`)
    return at
  })
  assert.deepEqual(emission, [...emission].sort((a, b) => a - b), '脚注环节顺序与渲染器发射顺序不一致')
})

test('阶段 1 脚注：绑定保留检测信任策略时追加降级说明', () => {
  assert.match(stage1FootnoteText(true), /绑定「保留检测」信任策略时命中降级为检测事件，不终止/)
  assert.ok(stage1FootnoteText(true).length > stage1FootnoteText(false).length)
})

// 白名单命中后的豁免面：引擎发射的豁免规则是 pass + skipAfter:SECURITY_RULES_END
// （跳过预检段内其后的一切规则，含爬虫伪装族与逐策略 GeoIP 链）。脚注只写
// 「豁免地域拦截」会让管理员以为白名单成员仍被爬虫校验拦下。
test('阶段 1 脚注：白名单豁免面写成「其后全部预检」', () => {
  const footnote = stage1FootnoteText(false)
  assert.match(footnote, /白名单命中豁免其后全部预检/)
  assert.doesNotMatch(footnote, /白名单命中豁免地域拦截/, '旧文案把豁免面缩小成只有地域拦截')

  // 跨栈机械钉：豁免规则的 id 与动作必须支撑「全部预检」这一措辞。Go 侧把
  // skipAfter 去掉或改成只跳过 GeoIP，都会在此变红。
  const precheck = repoCode('internal/services/security.go')
  assert.match(precheck, /const ipPrecheckAllowExemptRuleID = 13/)
  assert.match(precheck, /id:%d,phase:1,pass,nolog,skipAfter:SECURITY_RULES_END/)
})
