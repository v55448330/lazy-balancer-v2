/**
 * DNS 提供商凭证字段的展示口径。
 *
 * 字段可见性与选项文案此前在前端按 dnspod 的两种认证模式硬编码
 * （`auth_mode/secret_id/secret_key/app_id/app_token` 逐个判断），而后端新增
 * 提供商时其 `credential_fields` 会被整体隐藏、选项只能显示原始值。现由
 * `/dns-providers` 下发的字段元数据驱动：
 *
 * - `visible_when`: { 其它字段名: 允许的取值[] }——全部条件命中才显示；
 * - `option_labels`: { 选项值: 显示文案 }——缺失时回退原始值。
 */
import { hasOwn } from './hasOwn.ts'

export interface CredentialFieldMeta {
  readonly name: string
  readonly label: string
  readonly type: string
  readonly required: boolean
  readonly placeholder?: string
  readonly description?: string
  readonly options?: readonly string[]
  readonly visible_when?: Readonly<Record<string, readonly string[]>>
  readonly option_labels?: Readonly<Record<string, string>>
}

/** 字段是否应显示：无 `visible_when` 元数据 → 恒显示（不再按 provider 硬编码）。 */
export const credentialFieldVisible = (
  field: CredentialFieldMeta,
  credentials: Readonly<Record<string, string>>,
): boolean => {
  const conditions = field.visible_when
  if (!conditions) return true
  return Object.entries(conditions).every(([key, allowed]) => allowed.includes(credentials[key] ?? ''))
}

/** 选项显示文案：优先元数据 label，缺失回退选项值。 */
export const credentialOptionLabel = (field: CredentialFieldMeta, option: string): string => {
  const labels = field.option_labels
  // 元数据是普通对象且 option 来自提供商字段定义（后端下发）：原型键直接下标
  // 会返回函数，下拉文案渲染出函数源码。
  return (labels && hasOwn(labels, option) ? labels[option] : undefined) ?? option
}

/**
 * 新建/切换提供商时的凭证初始值：每个 select 字段取首个选项。
 * （原实现固定写死 `{ auth_mode: 'dnspod' }`——新增无 auth_mode 的 provider
 * 会带入多余键，且 select 初值与其 options 脱节。）
 */
export const defaultCredentialsFor = (
  fields: readonly CredentialFieldMeta[],
): Record<string, string> => {
  const credentials: Record<string, string> = {}
  for (const field of fields) {
    if (field.type === 'select' && field.options?.length) credentials[field.name] = field.options[0]
  }
  return credentials
}

/**
 * select 字段变更后的凭证集合：只清理被 `visible_when` 隐藏的字段，仍可见的
 * 值（含其它 select 与文本字段）保留。
 *
 * 原实现把整个 `dns_credentials` 重置为 `{ auth_mode: 新值 }`——假定唯一 select
 * 名为 `auth_mode`，而契约是「字段由后端元数据驱动」。若新增含两个 select 的
 * provider（如「区域 + 认证模式」），改第二个 select 会把第一个 select 的取值与
 * 全部文本字段一并清空。可见性求值用同一快照，结果与字段顺序无关；变更字段的
 * 新值此时已由 v-model 写入 credentials，故无需单独传参。
 */
export const applyCredentialFieldChange = (
  fields: readonly CredentialFieldMeta[],
  credentials: Readonly<Record<string, string>>,
): Record<string, string> => {
  const snapshot = { ...credentials }
  const next: Record<string, string> = { ...snapshot }
  for (const field of fields) {
    if (!credentialFieldVisible(field, snapshot)) delete next[field.name]
  }
  return next
}
