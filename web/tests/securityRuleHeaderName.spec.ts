// 自定义规则「请求头」条件的头名契约钉：
//   A. 头名 token 规则与后端 validateHeaderNameToken 同源（字母数字与 '-'，1-64 字符），
//      两端字面量硬编码对表——任一端单独改动字符集/长度边界即红。
//   B. 空头名三态一致：空串=匹配全部头的值（后端对空 header_name 跳过 token 校验），
//      保存门/红框/提示文案不得互相矛盾（此前保存门拦空串、文案却说留空匹配全部）。
//   C. 切走 target 必须清残留 header_name——后端对非 headers target 携带头名恒 400，
//      且 400 文案指向用户已不可见的字段。
//   D. 布局与警示样式：弹框 880px/头名输入 180px 宽度钉；port-warning 警示色收敛
//      全局 main.css 单源（Rules.vue scoped 定义跨组件不生效）；regex-error-icon
//      有警示色；ip-query-bar 逐字重复声明去重。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { HEADER_NAME_RE, headerNameSaveAllowed, isValidHeaderName } from '../src/utils/customRuleLimits.ts'
import { code, cssDeclarations, openTags, repoCode, section } from './_helpers.ts'

const SECURITY_RULES = 'src/views/security/SecurityRules.vue'
const page = code(SECURITY_RULES)
const mainCss = code('src/styles/main.css')
const securityGo = repoCode('internal/services/security.go')

const headerNameInput = (): string | undefined =>
  openTags(page, 'el-input').find((tag) => tag.includes('header-name-input'))

test('头名 token 正则与后端 validateHeaderNameToken 逐字一致（改端即红）', () => {
  // 前端字面量硬编码：共享 util 的字符集/长度边界单独漂移即红。
  assert.equal(HEADER_NAME_RE.source, '^[A-Za-z0-9-]{1,64}$')
  // 后端投影字面量硬编码：Go 侧是命令式逐字符白名单 + 长度边界，这里钉其等价形状。
  assert.ok(securityGo.includes("r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-'"), '后端字符白名单漂移')
  assert.ok(securityGo.includes('len(name) < 1 || len(name) > 64'), '后端长度边界漂移')
  assert.match(securityGo, /validateHeaderNameToken/, '后端校验入口缺失')
})

test('头名校验逻辑：非空 token 合法性 + 空串语义（空=匹配全部头的值）', () => {
  assert.equal(isValidHeaderName('Content-Encoding'), true)
  assert.equal(isValidHeaderName('a'.repeat(64)), true, '恰 64 字符合法')
  assert.equal(isValidHeaderName('a'.repeat(65)), false, '超 64 字符非法')
  assert.equal(isValidHeaderName('Content_Type'), false, '下划线不在 token 字符集')
  assert.equal(isValidHeaderName(' 中文'), false, '空白/非 ASCII 非法')
  assert.equal(isValidHeaderName(''), false, '空串不是合法 token（放行语义在保存门谓词）')

  assert.equal(headerNameSaveAllowed(undefined), true, '未填=空语义')
  assert.equal(headerNameSaveAllowed(''), true, '留空=匹配全部头的值，与模板文案/后端契约一致')
  assert.equal(headerNameSaveAllowed('Content-Encoding'), true)
  assert.equal(headerNameSaveAllowed('bad name'), false)
  assert.equal(headerNameSaveAllowed('a'.repeat(65)), false)
})

test('保存门与红框消费同一谓词，拒绝文案说明空串语义', () => {
  const save = section(page, 'const saveCustomRule = async', 'const deletingCustomRuleId')
  assert.match(save, /cond\.target === 'headers' && !headerNameSaveAllowed\(cond\.header_name\)/, '保存门必须经共享谓词（空串放行、非空校验 token）')
  assert.match(save, /留空则匹配全部头的值/, '拒绝文案必须说明空串语义')
  // 红框与保存门同一谓词：非空非法才标错，空串不标错。
  const inputTag = headerNameInput()
  assert.ok(inputTag, '头名输入框必须存在')
  assert.match(inputTag ?? '', /!headerNameSaveAllowed\(cond\.header_name\)/, '红框谓词必须与保存门同源')
})

test('切走 target 清残留 header_name（非 headers 携带头名后端恒 400）', () => {
  assert.match(securityGo, /header_name 仅 target=headers 时支持/, '后端 400 契约前提')
  const selectTag = openTags(page, 'el-select').find((tag) => tag.includes('cond.target'))
  assert.ok(selectTag, 'target 下拉必须存在')
  assert.match(selectTag ?? '', /@change="onConditionTargetChange\(cond\)"/, 'target 切换必须挂清理回调')
  const helper = section(page, 'const onConditionTargetChange', 'const removeCondition')
  assert.match(helper, /cond\.target !== 'headers'/)
  assert.match(helper, /cond\.header_name = undefined/, '切走 headers 必须清残留头名')
})

test('弹框与头名输入宽度钉（880px/180px）', () => {
  assert.match(page, /width="min\(880px, 94vw\)"/, '自定义规则弹框宽度')
  const decls = cssDeclarations(page, '.header-name-input')
  assert.equal(decls.get('width'), '180px', '头名输入宽度收敛进类样式（类名兼作语义锚）')
  const inputTag = headerNameInput()
  assert.ok(inputTag && !inputTag.includes('style="width'), '内联宽度不得残留（单源类样式）')
})

test('警示样式单源：port-warning 全局类、regex-error-icon 警示色、ip-query-bar 去重', () => {
  const portDecls = cssDeclarations(mainCss, '.port-warning')
  assert.equal(portDecls.get('color'), '#eab308', '全局警示色类收敛 main.css')
  // 级联钉：与 .form-tip-line 同特异性（0,1,0），必须声明在后才能覆盖其灰字色。
  assert.ok(mainCss.indexOf('.port-warning {') > mainCss.indexOf('.form-tip-line {'), 'port-warning 必须声明在 form-tip-line 之后（同特异性靠源序覆盖）')
  const rulesScoped = code('src/views/Rules.vue')
  assert.doesNotMatch(rulesScoped, /\.port-warning\s*\{/, 'Rules.vue scoped 重复定义必须移除（禁止组件内重复定义全局类）')
  assert.match(page, /class="form-tip-line port-warning"/, 'SecurityRules 引用全局类')

  const iconDecls = cssDeclarations(page, '.regex-error-icon')
  assert.ok(iconDecls.get('color'), 'regex-error-icon 必须有警示色声明')

  const occurrences = page.match(/\.ip-query-bar \.ip-query-input \{/g)?.length ?? 0
  assert.equal(occurrences, 1, 'ip-query-input 声明组逐字重复必须去重')
  const ipDecls = cssDeclarations(page, '.ip-query-bar .ip-query-input')
  assert.equal(ipDecls.get('width'), '260px', '去重保留级联实际生效值 260px')
})
