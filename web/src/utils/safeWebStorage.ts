/**
 * storage 禁用环境（隐私模式极端配置/嵌入式 webview 禁存储）安全读写。
 *
 * audit136-W1：module import 顶层裸 `localStorage.getItem` 在 storage 抛
 * SecurityError 时直接 boot 白屏——全仓既有 5+ 处调用点各自 try/catch 防护，
 * 唯 boot 首屏执行点裸奔。本 helper 为读/写的单一收口：任何 storage 异常
 * 静默降级（读=null/写=忽略），业务语义与「无存储」一致（token 空=未登录、
 * 偏好回落默认），不影响正常环境行为。
 */

/** 安全读 localStorage；任何异常返回 null。 */
export const safeLocalStorageGet = (key: string): string | null => {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

/** 安全写 localStorage；任何异常静默忽略（storage 禁用时偏好不持久化可接受）。 */
export const safeLocalStorageSet = (key: string, value: string): void => {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* storage 禁用：忽略 */
  }
}

/** 安全删 localStorage；任何异常静默忽略。 */
export const safeLocalStorageRemove = (key: string): void => {
  try {
    localStorage.removeItem(key)
  } catch {
    /* storage 禁用：忽略 */
  }
}

/** 安全读 sessionStorage；任何异常返回 null。 */
export const safeSessionStorageGet = (key: string): string | null => {
  try {
    return sessionStorage.getItem(key)
  } catch {
    return null
  }
}

/** 安全写 sessionStorage；任何异常静默忽略。 */
export const safeSessionStorageSet = (key: string, value: string): void => {
  try {
    sessionStorage.setItem(key, value)
  } catch {
    /* storage 禁用：忽略 */
  }
}
