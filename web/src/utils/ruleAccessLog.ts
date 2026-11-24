// 规则行「访问日志」入口的三态判定。
//
// 后端对全部登录用户（含非管理员与从节点）开放规则访问日志的读端点，只读不构成
// 禁用理由；能否「去开启」取决于该规则有没有访问日志开关（仅 HTTP 规则——TCP
// 规则后端恒关闭）以及当前用户是否可编辑该规则。

type RuleLogEntryState =
  /** 已开启访问日志：查看 */
  | 'view'
  /** 未开启且可编辑：给「去开启」入口 */
  | 'enable'
  /** 未开启且不可编辑（只读/从节点/证书任务锁定）：禁用并说明未开启 */
  | 'logOff'
  /** TCP 规则不支持访问日志：禁用并说明不支持（没有可开启的开关） */
  | 'tcpUnsupported'

export const ruleLogEntryState = (
  rule: { log_enabled: boolean; protocol: string },
  editable: boolean,
): RuleLogEntryState => {
  if (rule.log_enabled) return 'view'
  if (rule.protocol === 'tcp') return 'tcpUnsupported'
  return editable ? 'enable' : 'logOff'
}
