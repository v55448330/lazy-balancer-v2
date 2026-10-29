// OIDC 访问白名单文本 ↔ 数组解析单源（OIDCSettings.vue 的 load/save 共用）。
//
// 两个字段的分隔口径**有意不同**：
// - 邮箱域：条目本身不含空白，故空白/半角逗号/分号/全角逗号/顿号一律当分隔符
//   （管理员从表格/邮件里粘贴常带空格与中英文标点）；
// - 用户组：IdP 组名可以含内部空格（如 "Platform Ops"）与顿号，空白/顿号
//   **不得**当分隔符，只按逗号/分号（含全角）与换行切分。
// 两侧都 trim、去空、保序去重；formatAllowList 用换行拼接，两种字段都能无损往返。

const EMAIL_DOMAIN_SEPARATORS = /[\s,;，、；]+/
const GROUP_SEPARATORS = /[,;，；\r\n]+/

const splitAllowList = (raw: string, separators: RegExp): string[] => {
  const seen = new Set<string>()
  const result: string[] = []
  for (const item of raw.split(separators)) {
    const trimmed = item.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    result.push(trimmed)
  }
  return result
}

/** 邮箱域白名单：空白与中英文逗号/分号/顿号均为分隔符。 */
export const parseDomainAllowList = (raw: string): string[] =>
  splitAllowList(raw, EMAIL_DOMAIN_SEPARATORS)

/** 用户组白名单：仅按中英文逗号/分号与换行切分——组名允许内部空格。 */
export const parseGroupAllowList = (raw: string): string[] =>
  splitAllowList(raw, GROUP_SEPARATORS)

/** 数组 → 编辑文本（换行分隔，组名含空格也能无损往返）。 */
export const formatAllowList = (values?: readonly string[]): string => (values ?? []).join('\n')

// 面板侧白名单预算：名单整块落库并随集群快照搬运，OIDC 回调按
// 组名单条数 × 声明条数线性扫描。数值与后端 normalizeOIDCAllowed*
// （oidcAllowListMaxEntries / oidcAllowListEntryMaxRunes）同口径——
// web/tests/oidcAllowList.spec.ts 有跨栈常量钉，改一处必须同步另一处。
export const OIDC_ALLOW_LIST_MAX_ENTRIES = 100
export const OIDC_ALLOW_LIST_ENTRY_MAX_CHARS = 128

/**
 * 预算校验：合法返回 null，超限返回可直接展示的中文提示（与后端 400 文案同
 * 口径：条目数点位上限与当前条数，单条按**字符**计而非字节）。
 */
export const validateAllowList = (label: string, values: readonly string[]): string | null => {
  if (values.length > OIDC_ALLOW_LIST_MAX_ENTRIES) {
    return `${label}最多 ${OIDC_ALLOW_LIST_MAX_ENTRIES} 条（当前 ${values.length} 条）`
  }
  for (const value of values) {
    if ([...value].length > OIDC_ALLOW_LIST_ENTRY_MAX_CHARS) {
      return `${label}单条最多 ${OIDC_ALLOW_LIST_ENTRY_MAX_CHARS} 个字符`
    }
  }
  return null
}
