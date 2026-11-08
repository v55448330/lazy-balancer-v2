import { request, mfaAwareSuccess } from '@/utils/api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { tSafe as t } from '../i18n/tSafe.ts'

// POST /system/restart 返回后固定等 10s 再 reload 与容器冷启动时长无契约——
// 冷启动（DB 迁移/CRS 对账/Caddy 启动）超过 10s 时 reload 命中连接拒绝，落入浏览器原生错误页。
// 改为每 2s 静默轮询 /caddy/status，服务就绪（任意 200 响应）即触发 reload；
// 超过 60s 上限提示手动刷新。isDisposed 供组件卸载时提前终止轮询（不触发 reload/提示）。
const reloadAfterRestart = async (isDisposed?: () => boolean): Promise<boolean> => {
  const deadline = Date.now() + 60_000
  // 不用 Promise.withResolvers（Safari 17.4+/Chrome 119+）：旧浏览器会在
  // 重启成功后抛错，导致页面永不刷新。
  const sleep = (ms: number): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, ms))
  while (Date.now() < deadline) {
    await sleep(2000)
    if (isDisposed?.()) return false
    try {
      await request.get('/caddy/status', { silent: true })
      // 状态请求在途期间组件可能已卸载——reload 前复查，
      // 兑现「isDisposed 提前终止轮询（不触发 reload）」契约。
      if (isDisposed?.()) return false
      window.location.reload()
      return true
    } catch {
      // 服务未就绪（连接拒绝/超时），继续轮询
    }
  }
  if (!isDisposed?.()) ElMessage.warning(t('common.app.views.sysOps.restartSlowWarning'))
  return false
}

interface RestartServiceOptions {
  /** 确认框正文（各入口按场景自述：漂移恢复 vs 设置页手动重启） */
  readonly confirmMessage: string
  readonly confirmTitle: string
  readonly successMessage: string
  /** 取消文案缺省「取消」；确认文案缺省「重启」 */
  readonly confirmButtonText?: string
  /** 组件卸载守卫：提前终止就绪轮询 */
  readonly isDisposed?: () => boolean
}

/**
 * 重启服务统一流程：确认 → POST /system/restart → 成功提示 →
 * 就绪轮询 reload。此前 AppLayout（漂移恢复）与 BasicSettings（设置页）逐字
 * 重复同一流程，仅确认文案不同——任一入口改文案/错误处理都易漏改另一入口。
 *
 * 返回值：'cancelled'=用户取消；'failed'=请求失败或就绪超时（调用方复位按钮）；
 * 'reloaded'=页面将 reload（保持按钮 loading 直到卸载）。
 */
export const restartServiceWithFeedback = async (options: RestartServiceOptions): Promise<'cancelled' | 'failed' | 'reloaded'> => {
  try {
    await ElMessageBox.confirm(options.confirmMessage, options.confirmTitle, {
      confirmButtonText: options.confirmButtonText ?? t('common.app.views.sysOps.confirmDefaultBtn'),
      cancelButtonText: t('common.app.views.sysOps.cancelBtn'),
      type: 'warning',
    })
  } catch {
    // 取消/关闭：不重启
    return 'cancelled'
  }
  try {
    await request.post('/system/restart')
  } catch {
    // 请求失败（全局拦截器已提示），复位按钮允许重试
    return 'failed'
  }
  mfaAwareSuccess(options.successMessage)
  // 保持 loading 直到 reload（防就绪等待窗口内二次点击）；超时或失败才复位
  const reloaded = await reloadAfterRestart(options.isDisposed)
  return reloaded ? 'reloaded' : 'failed'
}
