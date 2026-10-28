// API 密钥 MCP IP 白名单文本 ⇄ string[] 单源：从 Keys.vue 抽出的
// 纯函数，便于 node 行为测试（校验/归一/行号报错三项原本只能源码钉）。
//
// 归一规则：单个地址补全前缀（IPv4 → /32，IPv6 → /128），已带前缀原样保留。
// 校验：逐行 isValidCidr（与安全策略同一实现）；空行忽略；报错带原始行号。
import { isValidCidr } from './ruleValidation.ts'

export const normalizeCidr = (rawValue: string): string => {
  const value = rawValue.trim()
  if (!value || value.includes('/')) return value
  return value.includes(':') ? `${value}/128` : `${value}/32`
}

interface SerializedWhitelist {
  readonly value: string[]
  readonly error: string
}

// 后端契约恒为 string[]；编辑表单统一换行文本，往返语义由本模块单源持有。
export const parseWhitelist = (value: readonly string[]): string => value.join('\n')

export const serializeWhitelist = (rawText: string): SerializedWhitelist => {
  const rows = rawText.split(/\r?\n/)
    .map((cidr, originalIndex) => ({ cidr: normalizeCidr(cidr), originalIndex }))
    .filter((row) => row.cidr !== '')
  const invalidRow = rows.find((row) => !isValidCidr(row.cidr))
  if (invalidRow) return { value: [], error: `第 ${invalidRow.originalIndex + 1} 行 IP 或 CIDR 格式不正确` }
  return { value: rows.map((row) => row.cidr), error: '' }
}
