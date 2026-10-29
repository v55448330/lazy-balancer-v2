import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { PathRule } from '../src/types/rules.ts'
import {
  applyResponseMode,
  isForwardResponseMode,
  pathRuleResponseError,
  pathRuleRowError,
  pathRuleShadowWarning,
  shadowedByIndex,
} from '../src/utils/pathRulesEditor.ts'
import { code, member } from './_helpers.ts'

// 路径规则编辑器（向导「自定义路由」）的行内判定：重复/互相遮蔽/模式切换归一/
// 跳转地址校验。组件此前把这四段逻辑写死在 SFC 里，零测试覆盖——遮蔽提示错了
// 用户会以为规则生效（实际被前序规则吞掉），模式切换归一错了会静默丢配置。

const rule = (over: Partial<PathRule> = {}): PathRule => ({
  match_type: 'prefix',
  path: '/api',
  upstream_path: '',
  sort_order: 0,
  upstreams: null,
  response_mode: 'forward',
  response_status: 200,
  response_body: '',
  response_content_type: '',
  redirect_to: '',
  ...over,
})

test('行内错误：同类型查重按后端口径，exact 不剥尾斜杠', () => {
  const rules = [rule({ match_type: 'exact', path: '/a' }), rule({ match_type: 'exact', path: '/a/' })]
  assert.equal(pathRuleRowError(rules, 0), '', '/a 与 /a/ 是两条独立 exact matcher')
  assert.equal(pathRuleRowError(rules, 1), '')
})

test('行内错误：同类型重复与跨类型互相遮蔽给出不同文案', () => {
  const sameType = [rule({ path: '/api' }), rule({ path: '/api/' })]
  assert.equal(pathRuleRowError(sameType, 1), '与规则 1 重复')

  const crossType = [rule({ match_type: 'exact', path: '/a' }), rule({ path: '/a/' })]
  assert.equal(pathRuleRowError(crossType, 1), '与规则 1 同路径前缀+精确互相遮蔽')
})

test('行内错误：字段级问题先于重复/遮蔽（清空路径立即标红）', () => {
  const rules = [rule({ path: '/api' }), rule({ path: 'api' })]
  assert.equal(pathRuleRowError(rules, 1), '必须以 / 开头')
  assert.equal(pathRuleRowError(rules, 9), '', '越界行不报错')
})

test('遮蔽：前序 prefix 遮蔽后续子路径与同路径规则', () => {
  const rules = [rule({ path: '/api' }), rule({ match_type: 'exact', path: '/api' }), rule({ path: '/api/x' })]
  assert.equal(shadowedByIndex(rules, 1), 0)
  assert.equal(shadowedByIndex(rules, 2), 0)
  assert.match(pathRuleShadowWarning(rules, 2), /被前序前缀规则 1（\/api）遮蔽/)
})

test('遮蔽：含通配符的路径不参与提示（既有语义，避免噪音）', () => {
  // 审计建议的「/api 遮蔽 /api/*」与本实现有意冲突：含 *?{} 的路径不入遮蔽
  // 判定（后端 matcher 归一后语义不同，提示会误报）。按既有语义钉住。
  const rules = [rule({ path: '/api' }), rule({ path: '/api/*' }), rule({ path: '/x/*' })]
  assert.equal(shadowedByIndex(rules, 1), -1)
  assert.equal(pathRuleShadowWarning(rules, 1), '')
  assert.equal(shadowedByIndex(rules, 2), -1)
})

test('遮蔽：root=/ 遮蔽全部后续规则；后序规则不反向遮蔽前序', () => {
  const rules = [rule({ path: '/' }), rule({ path: '/anything/deep' })]
  assert.equal(shadowedByIndex(rules, 1), 0)
  const reverse = [rule({ path: '/api/x' }), rule({ path: '/api' })]
  assert.equal(shadowedByIndex(reverse, 1), -1, '前序更深路径不遮蔽后序更短前缀')
})

test('遮蔽：非法/空路径与 exact 前序不参与判定', () => {
  const invalid = [rule({ path: '/api' }), rule({ path: '' }), rule({ path: 'relative' })]
  assert.equal(shadowedByIndex(invalid, 1), -1)
  assert.equal(shadowedByIndex(invalid, 2), -1)
  const exactPrior = [rule({ match_type: 'exact', path: '/api' }), rule({ path: '/api/x' })]
  assert.equal(shadowedByIndex(exactPrior, 1), -1)
})

test('模式归一：转发 → 直接返回，清空上游并补静态默认值', () => {
  const target = rule({ upstream_path: '/v1', upstreams: [{ protocol: 'http', address: 'a', port: 80, weight: 100 }], response_mode: 'static', redirect_to: 'https://old' })
  applyResponseMode(target)
  assert.equal(target.upstream_path, '')
  assert.equal(target.upstreams, null)
  assert.equal(target.redirect_to, '')
  assert.equal(target.response_status, 200)
  assert.equal(target.response_content_type, 'text/plain')
})

test('模式归一：直接返回 → 301 跳转，清空响应体与格式，已填跳转地址保留', () => {
  const target = rule({ response_mode: 'redirect', response_body: 'hello', response_content_type: 'text/plain' })
  applyResponseMode(target)
  assert.equal(target.response_body, '')
  assert.equal(target.response_content_type, '')
  assert.equal(isForwardResponseMode(target), false)
  assert.equal(target.redirect_to, '', '进入跳转模式时不得残留上一次跳转地址（进入 static 时已被清空）')

  const fresh = rule({ response_mode: 'redirect', redirect_to: '/new/' })
  applyResponseMode(fresh)
  assert.equal(fresh.redirect_to, '/new/', '刚填的跳转地址不得被再次切换清掉')
})

test('模式归一：切回转发清空静态/跳转专属字段并复位状态码', () => {
  const target = rule({ response_mode: 'forward', response_status: 404, response_body: 'x', response_content_type: 'text/html', redirect_to: '/old' })
  applyResponseMode(target)
  assert.equal(target.response_status, 200)
  assert.equal(target.response_body, '')
  assert.equal(target.response_content_type, '')
  assert.equal(target.redirect_to, '')
  assert.equal(isForwardResponseMode(target), true, 'forward 哨兵与空串同义')
})

test('跳转地址校验：空/相对路径/控制字符被拒，绝对地址与站内路径通过', () => {
  assert.equal(pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: '' })), '301 跳转需要填写跳转地址')
  assert.equal(pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: 'example.com' })), '跳转地址须为 http(s):// 绝对地址或 / 开头路径')
  assert.equal(pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: '/a\u0007b' })), '跳转地址含非法字符')
  assert.equal(pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: '/new/' })), '')
  assert.equal(pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: 'https://example.com/x' })), '')
  assert.equal(pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: 'http://example.com' })), '')
  assert.equal(pathRuleResponseError(rule({ response_mode: 'static' })), '', '静态返回不校验跳转地址')
})

test('跳转地址形状按原串判定（前导空格行内即拒，不拖到整组校验）', () => {
  // 后端按原串 HasPrefix；行内若 trim 后放行，" http://x" 会在离开该步时被整组
  // 拒绝——正是「行内已修漂移」在行内层复发的形态。
  assert.equal(
    pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: ' http://example.com' })),
    '跳转地址须为 http(s):// 绝对地址或 / 开头路径',
  )
  assert.equal(
    pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: ' /x' })),
    '跳转地址须为 http(s):// 绝对地址或 / 开头路径',
  )
  assert.equal(
    pathRuleResponseError(rule({ response_mode: 'redirect', redirect_to: '   ' })),
    '301 跳转需要填写跳转地址',
    '仅空判使用 trim（纯空白仍算未填）',
  )
})

test('行内诊断按行缓存，模板不重复调用全表校验函数', () => {
  const editor = code('src/components/rules/PathRulesEditor.vue')
  const diagnostics = member(editor, 'const rowDiagnostics = computed')
  assert.match(diagnostics, /pathRules\.value\.map/, '每次响应式求值应只生成一次行级诊断数组')
  assert.match(diagnostics, /pathRuleRowError\(pathRules\.value, index\)/)
  assert.match(diagnostics, /pathRuleShadowWarning\(pathRules\.value, index\)/)
  assert.match(diagnostics, /upstreamError\(index\)/)
  assert.match(diagnostics, /pathRuleResponseError\(pathRules\.value\[index\]\)/)
  assert.doesNotMatch(editor, /pathRuleRowError\(pathRules, index\)|pathRuleShadowWarning\(pathRules, index\)|pathRuleResponseError\(rule\)/, '模板不得再逐属性重复求值')
})
