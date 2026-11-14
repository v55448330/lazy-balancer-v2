// 路径规则编辑器（向导「自定义路由」步骤）的行内判定单源。
//
// 组件只做取值与渲染，判定全部在此——纯函数可被 node 行为求值，避免把
// 用户可见的重复/遮蔽/模式归一语义埋在 SFC 里只能靠文本钉。
import type { PathRule } from '@/types'
import { canonicalPathKey, pathDuplicateKey, pathRuleError } from './ruleValidation.ts'
import { tSafe as t } from '../i18n/tSafe.ts'

/** 行内错误：字段级（空/非法/上游路径）+ 同类型查重 + 跨类型遮蔽互查。 */
export const pathRuleRowError = (rules: readonly PathRule[], index: number): string => {
  const rule = rules[index]
  if (!rule) return ''
  // 字段级判据与整组校验单源（ruleValidation.pathRuleError）：清空路径
  // 立即在行内标红，不再等到点保存才被整组拒绝（晚失败）。
  const fieldError = pathRuleError(rule)
  if (fieldError) return fieldError
  const canonical = canonicalPathKey(rule.match_type, rule.path)
  const duplicateKey = pathDuplicateKey(rule.match_type, rule.path)
  // 同类型查重按后端口径（exact 不剥尾 /，/a 与 /a/ 是两条独立 matcher）；
  // canonicalPathKey 归一键只用于跨类型遮蔽互查。
  const duplicateIndex = rules.findIndex((other, otherIndex) =>
    otherIndex !== index && other.path.trim() !== ''
      && (other.match_type === rule.match_type
        ? pathDuplicateKey(other.match_type, other.path) === duplicateKey
        : canonicalPathKey(other.match_type, other.path) === canonical))
  if (duplicateIndex >= 0) {
    const other = rules[duplicateIndex]
    if (!other) return ''
    return other.match_type === rule.match_type
      ? t('common.app.pathRules.duplicateRule', { n: duplicateIndex + 1 })
      : t('common.app.pathRules.shadowRule', { n: duplicateIndex + 1 })
  }
  return ''
}

// 前序 prefix 规则遮蔽提示——后端有意放行（测试钉住），仅 UI 非阻断警告。
// 判定口径与 services/caddy.go pathMatcherSpecs + terminal 路由一致：prefix
// 渲染 [root, root/*] 双 matcher（root=剥尾 / 与 *，剥空 = /* 全匹配），路由按
// sort_order 稳定排序、先命中即终结，故前序 prefix P 遮蔽后序规则 Q 当且仅当
// canonical(Q)===root(P) 或以 root(P)+"/" 开头。
export const shadowedByIndex = (rules: readonly PathRule[], index: number): number => {
  const rule = rules[index]
  if (!rule) return -1
  // 非法/空路径由行内错误负责，不参与遮蔽判定（避免提示噪音）
  if (rule.path !== '' && !rule.path.startsWith('/')) return -1
  if (/[*?{}]/.test(rule.path)) return -1
  if (rule.path.trim() === '') return -1
  const canonical = canonicalPathKey(rule.match_type, rule.path)
  for (let priorIndex = 0; priorIndex < index; priorIndex++) {
    const prior = rules[priorIndex]
    if (!prior || prior.match_type !== 'prefix') continue
    if (prior.path.trim() === '' || !prior.path.startsWith('/') || /[*?{}]/.test(prior.path)) continue
    const root = canonicalPathKey('prefix', prior.path)
    if (root === '/' || canonical === root || canonical.startsWith(`${root}/`)) return priorIndex
  }
  return -1
}

export const pathRuleShadowWarning = (rules: readonly PathRule[], index: number): string => {
  const priorIndex = shadowedByIndex(rules, index)
  if (priorIndex < 0) return ''
  const prior = rules[priorIndex]
  return t('common.app.pathRules.shadowedByPrior', { n: priorIndex + 1, path: prior?.path.trim() ?? '' })
}

// isForwardResponseMode 转发判定：''（API 形态）与 'forward'（UI 哨兵——el-select
// 空串选项不显示标签）同为转发；提交时归一为 ''。
export const isForwardResponseMode = (rule: PathRule): boolean =>
  !rule.response_mode || rule.response_mode === 'forward'

// applyResponseMode 模式切换归一：非转发模式清空转发专属字段（上游路径/自定义
// 上游），跳转/静态互清对方字段，静态进场补默认值（后端写侧同口径归一）。
export const applyResponseMode = (rule: PathRule): void => {
  if (!isForwardResponseMode(rule)) {
    rule.upstream_path = ''
    rule.upstreams = null
  }
  if (rule.response_mode === 'static') {
    rule.redirect_to = ''
    if (!rule.response_status) rule.response_status = 200
    if (!rule.response_content_type) rule.response_content_type = 'text/plain'
  } else if (rule.response_mode === 'redirect') {
    rule.response_body = ''
    rule.response_content_type = ''
  } else {
    rule.response_status = 200
    rule.response_body = ''
    rule.response_content_type = ''
    rule.redirect_to = ''
  }
}

/** 行内校验（与后端 validateRuleFeatures / ruleValidation.ts 同口径）。 */
export const pathRuleResponseError = (rule: PathRule): string => {
  if (rule.response_mode === 'redirect') {
    // 形状判定查原串（仅空判用 trim）：后端 HasPrefix 按原串——`" http://x"`
    // 若前端 trim 后放行，会在离开该步时被整组拒绝（late failure 复发）。
    const raw = rule.redirect_to ?? ''
    if (!raw.trim()) return t('common.app.pathRules.redirectAddressRequired')
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(raw)) return t('common.app.pathRules.redirectInvalidChars')
    if (!raw.startsWith('/') && !raw.startsWith('http://') && !raw.startsWith('https://')) return t('common.app.pathRules.redirectAbsoluteRequired')
  }
  return ''
}
