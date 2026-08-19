import { request } from '@/utils/api'
import { ElMessage } from 'element-plus'

// W1：POST /system/restart 返回后固定等 10s 再 reload 与容器冷启动时长无契约——
// 冷启动（DB 迁移/CRS 对账/Caddy 启动）超过 10s 时 reload 命中连接拒绝，落入浏览器原生错误页。
// 改为每 2s 静默轮询 /caddy/status，服务就绪（任意 200 响应）即触发 reload；
// 超过 60s 上限提示手动刷新。isDisposed 供组件卸载时提前终止轮询（不触发 reload/提示）。
export const reloadAfterRestart = async (isDisposed?: () => boolean): Promise<boolean> => {
  const deadline = Date.now() + 60_000
  const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))
  while (Date.now() < deadline) {
    await sleep(2000)
    if (isDisposed?.()) return false
    try {
      await request.get('/caddy/status', { silent: true })
      window.location.reload()
      return true
    } catch {
      // 服务未就绪（连接拒绝/超时），继续轮询
    }
  }
  if (!isDisposed?.()) ElMessage.warning('服务重启时间较长，请稍后手动刷新')
  return false
}
