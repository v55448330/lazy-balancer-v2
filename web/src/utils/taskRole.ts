// 任务角色适用范围（任务监控 UI 三态）：后端只下发 role_applicable 布尔
// （本节点角色是否允许该任务运行），不带原始 runs_on——方向由当前节点角色
// 补全：主节点上 false=仅从节点任务（slave-only），从节点上 false=仅主节点
// 任务（master-only）。角色未判定时不猜方向（避免再次标反）。
export type NodeRole = 'master' | 'slave' | 'unknown'
export type TaskRoleScope = 'any' | 'master-only' | 'slave-only' | 'unknown'

export const taskRoleScope = (roleApplicable: boolean | undefined, nodeRole: NodeRole): TaskRoleScope => {
  if (roleApplicable !== false) return 'any'
  if (nodeRole === 'slave') return 'master-only'
  if (nodeRole === 'master') return 'slave-only'
  return 'unknown'
}
