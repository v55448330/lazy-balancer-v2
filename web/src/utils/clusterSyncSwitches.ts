// 集群同步开关三分类单源：ClusterMasterPanel 的开关行（label+tip）与
// ClusterSettings 的变更确认文案（label）原各持一份「系统数据/负载均衡规则/
// 安全防护」，改名/新增必漏一侧。此处收敛为唯一事实源，两侧只做取值。
import { tSafe as t } from '../i18n/tSafe.ts'

interface ClusterSyncSwitch {
  readonly key: string
  readonly label: string
  readonly tip: string
  /** true=恒同步、不可禁用（元数据承载，避免消费方写死 key 特例） */
  readonly locked?: boolean
}

export const CLUSTER_SYNC_SWITCHES = [
  // (三分类合并:全局配置并入系统数据节)确保系统基本运行的数据不可禁用同步。
  // 2026-09-19 文案整理:「证书文件随负载规则开关同步」属 rules 开关管辖
  // 不在本行尾注。
  { key: 'sync_users', label: t('common.app.views.sysOps.syncSystemData'), tip: t('common.app.views.sysOps.syncSystemDataTip'), locked: true },
  // 证书任务行与证书文件随本开关:关闭时从节点保留本地规则,
  // 其证书行/文件不按主节点快照删改。
  { key: 'sync_rules', label: t('common.app.views.sysOps.syncLbRules'), tip: t('common.app.views.sysOps.syncLbRulesTip'), locked: false },
  // 三分类合并:规则库文件差量通道并入安全防护开关(单开关统策略行与文件)。
  { key: 'sync_security', label: t('common.app.views.sysOps.syncSecurity'), tip: t('common.app.views.sysOps.syncSecurityTip'), locked: false },
] as const satisfies readonly ClusterSyncSwitch[]
