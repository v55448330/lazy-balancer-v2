/**
 * 「200 但缺 data」契约违约守卫单源。
 *
 * 语义：后端 200 但载荷缺 data（弱网截断/网关改包）属契约违约——静默 return
 * 会让按钮从 loading 复位、弹框停在原地，与「没点上」不可区分，用户只能重复
 * 提交。此处抛带指定文案的 Error，由调用方既有 catch 以 error.message 提示，
 * 控制流与显性报错分支一致（弹框保持打开/凭据不复位/按钮复位）。
 *
 * 零 Vue/Element 依赖，node --test 可直接求值。
 */
export const requireData = <T>(data: T | undefined | null, message: string): T => {
  if (data == null) throw new Error(message)
  return data
}
