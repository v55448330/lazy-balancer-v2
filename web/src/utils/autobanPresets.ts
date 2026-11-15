// 自动封禁配置预设档位（纯前端映射单源）：保守/标准/强化三档人话预设，
// 落既有 PUT /security/autoban。标准档=现默认参数（存量无感）；强化档=
// 证据分层计数（evidence）。预设不是新持久化字段——手动改参数即「自定义」。
//
// 参数值与后端 db.DefaultAutoban* / services 校验域跨栈对账（autobanPresets.spec）。

interface AutobanPresetValues {
  threshold: number
  window_minutes: number
  duration: string
  scope: string[]
  escalation: string
  counting_mode: string
  suspicion_multiplier: number
  confirm_floor_ratio: string
}

export type AutobanPresetId = 'conservative' | 'standard' | 'enhanced'

const ALL_SCOPES = ['blocked', 'logged', 'challenge_issued', 'challenge_failed']
const CONFIRMED_SCOPES = ['blocked', 'challenge_failed']

// 三档预设映射（dry_run 不随预设——观察/执法是独立开关，由卡片/闭环控制）。
export const AUTOBAN_PRESETS: Record<AutobanPresetId, AutobanPresetValues> = {
  // 保守：只计攻击确证（拦截+挑战失败），不升级，等权。
  conservative: {
    threshold: 100, window_minutes: 5, duration: '1h',
    scope: [...CONFIRMED_SCOPES], escalation: 'off',
    counting_mode: 'classic', suspicion_multiplier: 4, confirm_floor_ratio: '0.4',
  },
  // 标准：现默认（四口径全选+等权+standard 升级）——存量配置无感。
  standard: {
    threshold: 100, window_minutes: 5, duration: '1h',
    scope: [...ALL_SCOPES], escalation: 'standard',
    counting_mode: 'classic', suspicion_multiplier: 4, confirm_floor_ratio: '0.4',
  },
  // 强化：证据分层（纯嫌疑永不封）+阈值减半+standard 升级。
  enhanced: {
    threshold: 50, window_minutes: 5, duration: '1h',
    scope: [...ALL_SCOPES], escalation: 'standard',
    counting_mode: 'evidence', suspicion_multiplier: 4, confirm_floor_ratio: '0.4',
  },
}

export const AUTOBAN_PRESET_IDS: AutobanPresetId[] = ['conservative', 'standard', 'enhanced']

// 证据分层参数域（与后端 services 校验单源同口径）。
export const AUTOBAN_SUSPICION_MULTIPLIER_MIN = 2
export const AUTOBAN_SUSPICION_MULTIPLIER_MAX = 20
export const AUTOBAN_CONFIRM_FLOOR_RATIOS = ['0.2', '0.4', '0.6']

/** 当前表单值匹配哪档预设（全字段相等）；无匹配返回 null（自定义态）。 */
export const matchAutobanPreset = (form: AutobanPresetValues): AutobanPresetId | null => {
  for (const id of AUTOBAN_PRESET_IDS) {
    const p = AUTOBAN_PRESETS[id]
    if (
      form.threshold === p.threshold &&
      form.window_minutes === p.window_minutes &&
      form.duration === p.duration &&
      form.escalation === p.escalation &&
      form.counting_mode === p.counting_mode &&
      form.suspicion_multiplier === p.suspicion_multiplier &&
      form.confirm_floor_ratio === p.confirm_floor_ratio &&
      form.scope.length === p.scope.length &&
      p.scope.every((s) => form.scope.includes(s))
    ) return id
  }
  return null
}
