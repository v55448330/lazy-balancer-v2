/**
 * DNS 配置保存前的「真实挑战」门：临时写入并删除 `_acme-challenge.lb-test`
 * 只在凭证需要重新验证时才必要。
 *
 * 需要挑战的四类变更：
 * - 新建配置（凭证从未验证过）；
 * - DNS 提供商变更（凭证语义随提供商变化）；
 * - 凭证值变更或键增删；
 * - 禁用 → 启用（签发链会立刻用上这份凭证）。
 *
 * 仅改名 / 仅禁用 / 未触碰敏感项**不挑战**：编辑既有配置的降级操作不应向 DNS
 * 账户写记录——凭证已失效或账户已注销时，强制挑战会让「停用」永远失败。
 */

/** 打开弹框时的库内快照（判定基线；不得用保存时的表单自比）。 */
export interface DnsConfigBaseline {
  readonly dnsProvider: string
  /** 库内凭证快照；null = 凭证为空（遗留「尚未配置」形态，保存载荷可省略）。 */
  readonly dnsCredentials: Readonly<Record<string, string>> | null
  readonly enabled: boolean
}

/** 当前表单（保存载荷的来源）。 */
export interface DnsConfigDraft {
  readonly dnsProvider: string
  readonly dnsCredentials: Readonly<Record<string, string>>
  readonly enabled: boolean
}

/** 保存前是否需要真实 DNS 挑战（true=弹域名框并写临时记录验证）。 */
export const dnsConfigNeedsChallenge = (
  baseline: DnsConfigBaseline | null,
  draft: DnsConfigDraft,
): boolean => {
  if (!baseline) return true
  if (draft.dnsProvider !== baseline.dnsProvider) return true
  if (draft.enabled && !baseline.enabled) return true
  const draftKeys = Object.keys(draft.dnsCredentials).sort()
  const stored = baseline.dnsCredentials
  if (stored === null) {
    // 遗留空凭证：只有用户真的填入凭证值才需要验证（改名/禁用不受阻）
    return draftKeys.some((key) => (draft.dnsCredentials[key] ?? '').trim() !== '')
  }
  const storedKeys = Object.keys(stored).sort()
  if (draftKeys.length !== storedKeys.length) return true
  // 严格逐键比较（不做 trim 归一：载荷原样回传，空白改动同样是变更）
  return !draftKeys.every((key, index) => key === storedKeys[index] && (draft.dnsCredentials[key] ?? '') === (stored[key] ?? ''))
}
