// 证书有效期结论单源：规则向导预览行、TLS 步骤提示框、规则列表 TLS 列的证书提示、
// 处理流程弹框的剩余天数行、证书任务页的有效期列共用同一结论与同一色阶。带符号的剩余天数
// 不得上屏（「-1 天」易被误读为已过期一整天），阈值与配色只在这里定义。
import { tSafe as t } from '../i18n/tSafe.ts'

/** 临期阈值（天）：不超过它按警示色展示。 */
const CERT_EXPIRY_WARNING_DAYS = 30

type CertExpiryTone = 'is-danger' | 'is-warning' | 'is-success'

export interface CertExpiryConclusion {
  /** 上屏结论：已过期 N 天 / 今天到期 / N 天后 */
  readonly text: string
  /** 色阶修饰类（与向导证书事实框同一套类名） */
  readonly tone: CertExpiryTone
}

/** certExpiryConclusion 把带符号的剩余天数收敛成结论与色阶。
 * expired：调用方手里的过期状态位。后端的天数按整天截断，刚过期几小时的证书
 * 天数也是 0——只看天数会把它显示成「今天到期」。 */
export const certExpiryConclusion = (daysUntilExpiry: number, expired = false): CertExpiryConclusion => {
  if (daysUntilExpiry < 0 || expired) {
    return { text: t('common.app.rules.wizard.expiredDaysAgo', { n: Math.abs(daysUntilExpiry) }), tone: 'is-danger' }
  }
  if (daysUntilExpiry === 0) return { text: t('common.app.rules.wizard.expiresToday'), tone: 'is-warning' }
  return {
    text: t('common.app.rules.wizard.expiresInDays', { n: daysUntilExpiry }),
    tone: daysUntilExpiry <= CERT_EXPIRY_WARNING_DAYS ? 'is-warning' : 'is-success',
  }
}
