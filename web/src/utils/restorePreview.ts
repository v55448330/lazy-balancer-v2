/**
 * 自动备份还原预览的分组归一。
 *
 * `GET /auto-backup/:id/preview` 的 data 与导入结果同形（version_warning /
 * disabled_conflicts / warnings）。预览是「锦上添花」：字段缺失、旧后端、半途
 * 载荷都不得抛错或臆造条目——确认框必须照常出现，只是少了相应分组。
 *
 * 归一保持后端顺序（版本告警一句、冲突明细按链内顺序、warnings 按生产顺序），
 * 渲染层只负责把非空分组变成 `.confirm-scope-lead` / `.confirm-scope-list`。
 */
interface RestorePreviewConflictOpponent {
  name?: string
  caddy_id?: string
  reason: string
}

interface RestorePreviewConflict {
  name?: string
  caddy_id?: string
  reason: string
  /** 后端恒发射该键；带外载荷缺省时归一为空数组（渲染层直接 map，不再判空）。 */
  conflicts_with: RestorePreviewConflictOpponent[]
}

export interface AutoBackupPreviewPayload {
  version_warning?: unknown
  backup_version?: unknown
  current_version?: unknown
  disabled_conflicts?: unknown
  warnings?: unknown
}

export interface RestorePreviewGroups {
  /** 跨版本告警（已去首尾空白；空串=无告警）。 */
  readonly versionWarning: string
  /** 将被置为禁用的规则（与导入结果 data.disabled_conflicts 同形）。 */
  readonly conflicts: readonly RestorePreviewConflict[]
  /** 其它软告警（逐条保序，滤掉空串与非字符串）。 */
  readonly warnings: readonly string[]
}

export const restorePreviewGroups = (payload: AutoBackupPreviewPayload | null | undefined): RestorePreviewGroups => {
  const source = typeof payload === 'object' && payload !== null ? payload : {}
  return {
    versionWarning: typeof source.version_warning === 'string' ? source.version_warning.trim() : '',
    conflicts: Array.isArray(source.disabled_conflicts)
      ? source.disabled_conflicts
          .filter(
            (item): item is RestorePreviewConflict =>
              typeof item === 'object' && item !== null && 'reason' in item && typeof item.reason === 'string',
          )
          .map((conflict) => ({
            ...conflict,
            conflicts_with: Array.isArray(conflict.conflicts_with) ? conflict.conflicts_with : [],
          }))
      : [],
    warnings: Array.isArray(source.warnings)
      ? source.warnings
          .filter((warning): warning is string => typeof warning === 'string')
          .map((warning) => warning.trim())
          .filter((warning) => warning !== '')
      : [],
  }
}
