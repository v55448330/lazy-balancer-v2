interface UserStatusRow {
  readonly id: number
  is_enabled: boolean
}

/** el-switch 已先改变行值；写失败或取消禁用时恢复请求前状态。 */
export const rollbackUserStatus = <T extends UserStatusRow>(rows: T[], id: number, attempted: boolean): void => {
  const row = rows.find((candidate) => candidate.id === id)
  if (row) row.is_enabled = !attempted
}
