/**
 * 一次性凭据（API 密钥明文 / MFA 恢复代码 / 集群注册令牌）的关闭守卫单源。
 *
 * 三者都是「关掉弹框后再也取不回来」的秘密（库内只存哈希或仅内存态），而
 * el-dialog 的 ESC / 右上角 X 默认静默关闭。三处各写一遍 before-close 会复制
 * 同一份确认文案与并发门（提交中不得关闭），语义一分散就出现「第三处漏守卫」。
 *
 * 用法：
 *   const closeTokenDialog = createOneTimeSecretCloseGuard({
 *     message: '注册令牌仅此一次显示，关闭后将无法再次查看。确认已保存？',
 *     title: '保存注册令牌',
 *   })
 *   <el-dialog :before-close="closeTokenDialog" @closed="secret = ''">
 *
 * @param options.message 确认框正文（点明「仅此一次、关闭后不可再取」）
 * @param options.title 确认框标题
 * @param options.confirmText/cancelText 按钮文案（默认「我已保存 / 继续查看」）
 * @param options.blocked 返回 true 表示当前不可关闭（如提交在途）——静默拒绝
 * @param options.skip 返回 true 表示当前没有待保存秘密（如尚未走到凭据步）——直接关闭
 * @param confirm 确认框实现（默认 ElMessageBox.confirm；测试可注入替身）
 */
import { ElMessageBox } from 'element-plus'
import { tSafe as t } from '../i18n/tSafe.ts'

interface OneTimeSecretGuardOptions {
  readonly message: string
  readonly title: string
  readonly confirmText?: string
  readonly cancelText?: string
  readonly blocked?: () => boolean
  readonly skip?: () => boolean
}

/** 确认框形态：与 ElMessageBox.confirm 同签名的可注入子集。 */
type SecretCloseConfirmer = (
  message: string,
  title: string,
  options: Record<string, unknown>,
) => Promise<unknown>

const elementPlusConfirmer: SecretCloseConfirmer = (message, title, options) =>
  ElMessageBox.confirm(message, title, options)

/**
 * 生成 el-dialog 的 before-close 回调：仅当用户确认「已保存」时才调用 done()。
 * 取消/关闭确认框（reject）时什么也不做——弹框保持打开，秘密仍在屏上。
 */
export const createOneTimeSecretCloseGuard = (
  options: OneTimeSecretGuardOptions,
  confirm: SecretCloseConfirmer = elementPlusConfirmer,
): ((done: () => void) => void) => {
  return (done: () => void): void => {
    if (options.blocked?.()) return
    if (options.skip?.()) {
      done()
      return
    }
    confirm(options.message, options.title, {
      type: 'warning',
      confirmButtonText: options.confirmText ?? t('common.app.views.mfa.guardConfirmDefault'),
      cancelButtonText: options.cancelText ?? t('common.app.views.mfa.guardCancelDefault'),
    }).then(
      () => done(),
      () => undefined,
    )
  }
}
