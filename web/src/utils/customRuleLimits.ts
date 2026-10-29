// 自定义安全规则的写侧上限（与后端 internal/services/security.go 同源）：
//   customRuleMaxConditions = 64      —— 单规则匹配条件数
//   customRuleMaxPatternBytes = 4KiB  —— 单条条件 pattern 的 UTF-8 字节数
// 超限后端恒 400。前端若只等全局 toast，用户既无法定位哪条条件越界，也会困惑
// 「字符数没超为什么被拒」——上限按字节计（中日韩字符 3 字节），故这里按
// TextEncoder 的字节长度求值，而不是输入框的字符数计数。
export const CUSTOM_RULE_MAX_CONDITIONS = 64
export const CUSTOM_RULE_MAX_PATTERN_BYTES = 4 << 10

// TextEncoder 无状态可复用：逐键输入路径每次调用 new 一次纯属浪费。
const utf8Encoder = new TextEncoder()

/** 与后端 len(pattern) 同口径的 UTF-8 字节长度。 */
export const patternByteLength = (value: string): number => utf8Encoder.encode(value).length

export const canAddCondition = (count: number): boolean => count < CUSTOM_RULE_MAX_CONDITIONS

export const patternOverLimit = (value: string): boolean => patternByteLength(value) > CUSTOM_RULE_MAX_PATTERN_BYTES
