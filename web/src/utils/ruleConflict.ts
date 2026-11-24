/**
 * 规则提交的唯一业务 409：版本前置条件冲突——他人已提交该规则，本表单是
 * 陈旧快照。同一路径的其它 409 与非 409 响应不按版本冲突处理。
 */
// i18n:判定首选 message_key(k_60ab0761,钉测见 tests/ruleConflict.spec.ts),
// 字面量仅作无键旧响应兜底。
export const RULE_VERSION_CONFLICT_MESSAGE_KEY = 'k_60ab0761'

export const isRuleVersionConflict = (
  status: number | undefined,
  messageKey: string | undefined,
  message: string,
): boolean => status === 409
  && (messageKey !== undefined ? messageKey === RULE_VERSION_CONFLICT_MESSAGE_KEY : message === '规则已被他人修改，请刷新后重试')
