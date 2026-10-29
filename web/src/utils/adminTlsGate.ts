/**
 * 管理面板 HTTPS「配置证书」弹框的确认门（零 Vue 依赖，node --test 可直接求值）。
 *
 * 后端 PUT /admin-tls 默认继承库内证书材料，仅在 `mode=upload` 且本次携带
 * cert_file/key_file 时才替换（internal/handlers/admintls.go），即「已保存的
 * 上传证书」本可被直接沿用。前端曾把「弹框里有 certInfo」当作唯一放行条件，
 * 而 staged 证书在保存成功后即清空——于是「关闭强制加密 → 再开启」时「确定」
 * 恒灰，用户只能重传文件或改用自签（后者会按后端语义清空上传证书材料）。
 */

interface AdminTlsStoredCertState {
  /** GET /admin-tls 的 mode：库内已保存形态（不受弹框内未提交切换影响） */
  readonly savedMode: string
  /** 库内证书可解析（cert_info 非空）或 selfsigned（由渲染层自愈） */
  readonly hasSavedCert: boolean
  /** 库内证书解析失败原因（后端 cert_info_error）；非空=必须重传 */
  readonly certError: string
}

interface AdminTlsDialogCertState {
  readonly mode: string
  readonly certFile: unknown
  readonly keyFile: unknown
  readonly certInfo: { readonly days_left: number; readonly expired?: boolean } | null
}

/**
 * 是否沿用库内已保存的上传证书：库内证书可解析且未损坏，且用户本次未选择
 * 新文件（选了文件但解析失败时不得静默回退到旧证书——那会与用户意图相反）。
 */
export const adminTlsReusesSavedCert = (
  stored: AdminTlsStoredCertState,
  form: AdminTlsDialogCertState,
): boolean =>
  stored.savedMode === 'upload' &&
  stored.hasSavedCert &&
  stored.certError === '' &&
  form.mode === 'upload' &&
  form.certFile == null &&
  form.keyFile == null

/**
 * 「确定」禁用判据：上传模式须「新证书已校验且未过期」或「沿用库内证书」。
 * 自签模式无需材料。
 */
export const adminTlsConfirmDisabled = (
  stored: AdminTlsStoredCertState,
  form: AdminTlsDialogCertState,
): boolean => {
  if (form.mode !== 'upload') return false
  if (adminTlsReusesSavedCert(stored, form)) return false
  if (form.certInfo == null) return true
  // 后端 expired 是权威有效期判据；days_left 向零截断，0 仍可能表示不足 24 小时的有效证书。
  return form.certInfo.expired ?? form.certInfo.days_left < 0
}

interface AdminTlsPendingState {
  readonly enabled: boolean
  readonly mode: string
  readonly savedEnabled: boolean
  readonly savedMode: string
  /** 弹框「确定」后暂存、随底部「保存」统一提交的上传证书材料 */
  readonly hasStagedCert: boolean
}

/**
 * 「下方保存」是否有待提交的 HTTPS 变更（原 adminTlsDirty 的纯函数形态）。
 *
 * 暂存证书本身即待提交变更，与 enabled 无关：原实现在 `!enabled` 处提前
 * 返回 false——用户在启用态选好并校验了上传证书后把开关关回禁用态，暂存材料
 * 既不算变更也不随保存发送，界面却回「保存成功」，材料静默丢失。
 *
 * 禁用态下来源（mode）不参与生效判定，保持原判净口径。
 */
export const adminTlsPendingChange = (state: AdminTlsPendingState): boolean => {
  if (state.hasStagedCert) return true
  if (state.enabled !== state.savedEnabled) return true
  if (!state.enabled) return false
  return state.mode !== state.savedMode
}

/**
 * 保存时是否随 /admin-tls 提交暂存证书材料。
 *
 * 只认「有暂存材料 + upload 来源」，不串 enabled：后端对「禁用态但本次上传了
 * 新证书材料」同样校验配对/有效期并落库（internal/handlers/admintls.go）；
 * 非 upload 来源携带材料会被后端 400 拒绝。
 */
export const adminTlsSendsStagedCert = (state: {
  readonly mode: string
  readonly hasStagedCert: boolean
}): boolean => state.hasStagedCert && state.mode === 'upload'
