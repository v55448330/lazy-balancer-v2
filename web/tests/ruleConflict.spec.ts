import test from 'node:test'
import assert from 'node:assert/strict'
import { RULE_VERSION_CONFLICT_MESSAGE_KEY, isRuleVersionConflict } from '../src/utils/ruleConflict.ts'
import { repoCode } from './_helpers.ts'

test('规则版本冲突按稳定语义键识别，与界面语言无关', () => {
  // en 响应信封（Accept-Language: en）：后端英文文案与前端 en 词条并不逐字相同，
  // 靠本地化文案子串识别必然漏判。
  assert.equal(isRuleVersionConflict(409, 'rule.versionConflict', 'The rule was modified by someone else; please refresh and try again'), true)
  assert.equal(isRuleVersionConflict(409, 'rule.versionConflict', '规则已被他人修改，请刷新后重试'), true)
})

test('无键旧响应按后端中文母本兜底（不是前端词条）', () => {
  assert.equal(isRuleVersionConflict(409, undefined, '规则已被他人修改，请刷新后重试'), true)
  assert.equal(isRuleVersionConflict(409, undefined, 'The rule was modified by someone else; please refresh and try again'), false)
  assert.equal(isRuleVersionConflict(409, undefined, '规则已被他人修改'), false)
})

test('同端点的其它 409 与非 409 不按版本冲突处理', () => {
  assert.equal(isRuleVersionConflict(409, 'k_other', '规则已被他人修改，请刷新后重试'), false)
  assert.equal(isRuleVersionConflict(400, 'rule.versionConflict', '规则已被他人修改，请刷新后重试'), false)
  assert.equal(isRuleVersionConflict(undefined, 'rule.versionConflict', '规则已被他人修改，请刷新后重试'), false)
})

test('语义键与后端 catalog 逐字对齐（跨栈钉）', () => {
  assert.equal(RULE_VERSION_CONFLICT_MESSAGE_KEY, 'rule.versionConflict')
  const catalog = repoCode('internal/i18n/catalog_gen.go')
  assert.ok(catalog.includes('Register("rule.versionConflict", "规则已被他人修改，请刷新后重试"'), 'catalog 母本漂移：版本冲突键或中文母本已变')
  const go = repoCode('internal/handlers/rules.go')
  assert.ok(
    go.includes('MessageKey: "rule.versionConflict"') || go.includes('apimsg.Envelope(http.StatusConflict, "rule.versionConflict"'),
    'rules.go 不再随版本冲突响应返回 message_key——前端冲突识别失配',
  )
})
