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

// 头名 token 规则与后端 validateHeaderNameToken 同源（internal/services/security.go）：
// 仅允许字母、数字与 '-'，1-64 字符——嵌入 SecRule REQUEST_HEADERS:<name> 形状必需。
// 空串不是合法 token，但保存门放行：留空头名=匹配全部头的值（后端对空 header_name
// 跳过 token 校验，语义一致）。两端字面量一致性由 tests/securityRuleHeaderName.spec.ts 钉住。
export const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/

export const isValidHeaderName = (name: string): boolean => HEADER_NAME_RE.test(name)

/** 保存门谓词：空串放行（=匹配全部头的值）；非空必须是合法 token。 */
export const headerNameSaveAllowed = (name: string | undefined): boolean => !name || isValidHeaderName(name)

// 条件目标的展示 token 单源：headers 条件带头名=限单头（headers[头名]），
// 空头名=匹配全部头的值（无后缀）。两种拦截语义在只读展示面必须可区分，
// 各消费面自持 target 拼接曾使头名限定不可见（规则列表条件 chips 与流程
// 弹框 targets 投影共用本 token）。
export const conditionTargetLabel = (target: string, headerName?: string): string =>
  target === 'headers' && headerName ? `headers[${headerName}]` : target
