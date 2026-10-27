// 请求失败处置的编排单源（api.ts 的拦截器把状态判据与状态机委托到这里）：
//   - classifyAuthFailure：HTTP/业务码 → 处置种类（401 凭证豁免 / 会话失效 /
//     428 step-up / 普通错误）。分类是安全契约（误判会误杀会话或漏弹重登），
//     抽成纯函数后可用表驱动用例钉住；
//   - createMfaStepUp：428 弹码与 verify-step 刷新的单飞状态机（并发 428 只弹
//     一次、同一验证码只刷新一次、新弹码作废旧刷新、已解析未清空窗口不得复用）；
//   - createMfaGraceTracker：宽限窗提示的 60s 节流、同文案兜底条去重与「刚弹码
//     验证」抑制。
//
// 本模块零 Vue/Element 依赖（提示由调用方注入），node --test 可直接求值。

import { isCurrentPasswordRejection } from './profileUpdate.ts'
import { isMfaCredentialRejection } from './mfaErrors.ts'

type AuthFailureKind =
  | 'credential-rejection'
  | 'session-expired'
  | 'step-up'
  | 'generic'

interface AuthFailureInput {
  readonly status?: number
  /** 响应体的业务码（data.code） */
  readonly dataCode?: number
  readonly method?: string
  readonly url?: string
  readonly message: string
  readonly isLoginRequest: boolean
  /** 是否携带请求配置（428 重试与 _mfaRetried 标记都依赖它） */
  readonly hasConfig: boolean
  readonly mfaRetried: boolean
}

/**
 * 失败分类：顺序即语义优先级。
 * 401 的两个白名单（MFA 凭证错误 / 本人资料当前密码错误）必须早于会话失效，
 * 否则输错验证码会触发全站登出；登录请求本身的 401 只展示后端文案。
 * 传输层事件（会话止损拒绝、axios 取消）在调用方更早短路，不参与本分类。
 */
export const classifyAuthFailure = (input: AuthFailureInput): AuthFailureKind => {
  if (input.status === 401) {
    if (isMfaCredentialRejection(input.url, input.status, input.message)) return 'credential-rejection'
    if (isCurrentPasswordRejection(input.method, input.url, input.status, input.message)) return 'credential-rejection'
    if (!input.isLoginRequest) return 'session-expired'
    return 'generic'
  }
  if (input.status === 428 && input.dataCode === 428 && input.hasConfig && !input.mfaRetried) return 'step-up'
  return 'generic'
}

/** 401 是否仍属于发起请求的会话：跨登出/登录后，旧请求的迟到响应不得处置新会话。 */
export const isRequestAuthTokenCurrent = (requestToken: string | undefined, currentToken: string | null): boolean =>
  requestToken === (currentToken ?? undefined)


/**
 * 单个 428 的处置链：进入弹码前、验码后刷新前、刷新后重放前都复核身份。
 * 返回 stale 时调用方只 reject 原请求，不产生任何面向新会话的副作用。
 */
export const runMfaStepUpRequest = async <T>(operations: {
  readonly isCurrent: () => boolean
  readonly prompt: () => Promise<string | null>
  readonly refresh: (code: string) => Promise<void>
  readonly replay: () => Promise<T>
  readonly onVerified?: () => void
}): Promise<{ readonly kind: 'replayed'; readonly value: T } | { readonly kind: 'cancelled' | 'stale' }> => {
  if (!operations.isCurrent()) return { kind: 'stale' }
  const code = await operations.prompt()
  if (!operations.isCurrent()) return { kind: 'stale' }
  if (!code) return { kind: 'cancelled' }
  await operations.refresh(code)
  if (!operations.isCurrent()) return { kind: 'stale' }
  operations.onVerified?.()
  return { kind: 'replayed', value: await operations.replay() }
}
interface MfaStepUpCoordinator {
  /** 弹码（单飞）：在途时并发 428 共享同一 Promise，不连环弹窗。 */
  readonly prompt: () => Promise<string | null>
  /** 验证码刷新（单飞）：同一轮在途提供者共享同一次 verify-step（同码重放会被
   *  后端按 mfa_last_timestep 拒绝并计失败）。 */
  readonly ensureRefresh: (code: string, refresh: (code: string) => Promise<void>) => Promise<void>
  /** 诊断/测试用：弹窗是否在途（生产代码零消费）。 */
  readonly isPromptPending: () => boolean
}

/**
 * @param openPrompt 真正的弹窗实现（返回验证码或 null=用户取消）。
 *   `prompt()` 保证它在同一时刻最多被调用一次。
 */
export const createMfaStepUp = (openPrompt: () => Promise<string | null>): MfaStepUpCoordinator => {
  let pending: Promise<string | null> | null = null
  let refresh: Promise<void> | null = null

  const prompt = (): Promise<string | null> => {
    if (pending) return pending
    // 新一轮弹码意味着新验证码：作废旧刷新句柄，确认后的等待者各自重试原请求。
    refresh = null
    const created = openPrompt().then(
      (code) => {
        // 必须在 resolve 之前同步清空——「已解析未清空」窗口里新到的 428 会共享
        // 到已消耗的验证码 Promise，进而在同一 timestep 内发起第二次 verify-step。
        pending = null
        return code
      },
      (error: unknown) => {
        pending = null
        throw error
      },
    )
    pending = created
    return created
  }

  const ensureRefresh = (code: string, refreshFn: (code: string) => Promise<void>): Promise<void> => {
    if (!refresh) {
      refresh = refreshFn(code).finally(() => {
        refresh = null
      })
    }
    return refresh
  }

  return {
    prompt,
    ensureRefresh,
    isPromptPending: () => pending !== null,
  }
}

interface MfaGraceNoticeHandle {
  close: () => void
}

interface MfaGraceTracker {
  /**
   * 响应携带宽限头（x-mfa-verified-seconds-ago）时记账。silent 请求（无页面级
   * 反馈）在 60s 节流内只发一条兜底提示；返回 true 表示本次真的发了。
   */
  readonly onGraceResponse: (silent: boolean, now: number, showNotice: () => MfaGraceNoticeHandle) => boolean
  /** 弹码后重试成功：标记「用户刚完成验证」（3s 内不再发免验证兜底）。 */
  readonly markVerifiedJustNow: (now: number) => void
  /**
   * 页面级成功提示前调用：3s 内经过宽限窗且不是「刚弹码验证」时返回 true，
   * 调用方加缀「MFA 在验证窗口期…」并关闭同文案兜底条（避免双 toast）。
   */
  readonly consumeGraceForSuccess: (now: number) => boolean
  /** 诊断/测试用：兜底条是否仍打开。 */
  readonly isNoticeOpen: () => boolean
}

export const createMfaGraceTracker = (): MfaGraceTracker => {
  // 时刻哨兵用 null 表示「从未发生」——0 会让注入时钟的测试把「第一次」误判成
  // 刚发生过（now - 0 可能落在窗口内）。
  let lastGraceAt: number | null = null
  let verifiedJustNowAt: number | null = null
  let noticeAt: number | null = null
  let notice: MfaGraceNoticeHandle | null = null

  const noticeIsOpen = (): boolean => notice !== null
  const closeNotice = (): void => {
    notice?.close()
    notice = null
  }
  const inGraceWindow = (now: number): boolean => lastGraceAt !== null && now - lastGraceAt < 3_000
  const isJustVerified = (now: number): boolean => verifiedJustNowAt !== null && now - verifiedJustNowAt <= 3_000

  return {
    onGraceResponse: (silent, now, showNotice) => {
      lastGraceAt = now
      if (!silent || isJustVerified(now)) return false
      if (noticeAt !== null && now - noticeAt <= 60_000) return false
      noticeAt = now
      // 新 toast 发出前关闭上一条，避免连发重复提示
      closeNotice()
      notice = showNotice()
      return true
    },
    markVerifiedJustNow: (now) => { verifiedJustNowAt = now },
    consumeGraceForSuccess: (now) => {
      if (!inGraceWindow(now) || isJustVerified(now)) return false
      closeNotice()
      return true
    },
    isNoticeOpen: noticeIsOpen,
  }
}
