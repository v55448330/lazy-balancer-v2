// 节点角色派生（三态 fail-closed）：/config 首拉失败或 15s 重试期内
// authStore.nodeMode 为 null，此时角色未知——展示层不得宣告「主节点/从节点」，
// 也不得据此判定配置一致性。
//
// 判据此前写在 Dashboard.vue 的 computed 里，用例只能钉「=== 'master' 与
// === 'slave' 出现过」，两支互换仍然全绿（存在性不等于方向）。抽成纯函数后
// 由行为用例穷举四态钉住方向。

import { tSafe as t } from '../i18n/tSafe.ts'

// 后端 node_mode 是 'master' | 'slave' | 'unknown'（types/ClusterNodeMode）；
// 展示侧再叠两种「还没取到」：null（/config 首拉失败或重试期）与 undefined。
type NodeModeInput = 'master' | 'slave' | 'unknown' | null | undefined

type NodeRole = 'master' | 'slave' | 'unknown'

interface NodeRoleView {
  role: NodeRole
  /** 展示文案（系统概览页的一致性 tag 文本） */
  label: string
  /** el-tag 形态：主=success / 从=warning / 未知=info（灰态，与「未知」互斥于二态色） */
  tagType: 'success' | 'warning' | 'info'
}

// 展示文案走 i18n（批次 D cluster 域）：label 在调用时刻解析（与 certJobStatus
// 同款 tSafe 兜底链），键形与 zh 母本原文由 nodeRole.spec 双钉。
export const resolveNodeRole = (mode: NodeModeInput): NodeRoleView => {
  if (mode === 'master') return { role: 'master', label: t('common.app.views.cluster.master'), tagType: 'success' }
  if (mode === 'slave') return { role: 'slave', label: t('common.app.views.cluster.slave'), tagType: 'warning' }
  return { role: 'unknown', label: t('common.app.views.cluster.roleUnknown'), tagType: 'info' }
}
