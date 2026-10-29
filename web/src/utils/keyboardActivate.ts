/**
 * 键盘激活去重：长按 Enter/Space 时浏览器按系统重复率连发 keydown，
 * 未过滤的业务入口会跟着连发（折叠/展开、开关、选择）——按住多久决定
 * 最终状态，用户无法预期。AccessibleLink 与其余 `@keydown.enter/space`
 * 入口统一经本函数收敛，避免各写一份。
 */
export function activateOnce(event: KeyboardEvent, action: () => void): void {
  if (event.repeat) return
  action()
}
