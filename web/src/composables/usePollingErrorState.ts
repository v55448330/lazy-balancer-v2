import { ref } from 'vue'
import type { Ref } from 'vue'

const INITIAL_CONTRACT_BACKOFF_MS = 30_000
const MAX_CONTRACT_BACKOFF_MS = 300_000
const VISIBLE_ERROR_UPDATE_INTERVAL_MS = 30_000

export interface PollingErrorState {
  readonly errorMessage: Readonly<Ref<string | null>>
  readonly lastErrorAt: Readonly<Ref<string>>
  readonly retryAt: Readonly<Ref<string>>
  readonly canRun: () => boolean
  readonly recordError: (error: unknown) => void
  readonly clear: () => void
  readonly resetBackoff: () => void
}

export const usePollingErrorState = (): PollingErrorState => {
  const errorMessage = ref<string | null>(null)
  const lastErrorAt = ref('')
  const retryAt = ref('')
  let contractFailureCount = 0
  let blockedUntil = 0
  let lastVisibleUpdateAt = 0

  const canRun = (): boolean => Date.now() >= blockedUntil

  const recordError = (error: unknown): void => {
    const now = Date.now()
    const message = error instanceof Error ? error.message : '未知错误'
    if (error instanceof TypeError) {
      contractFailureCount += 1
      const delay = Math.min(
        INITIAL_CONTRACT_BACKOFF_MS * 2 ** (contractFailureCount - 1),
        MAX_CONTRACT_BACKOFF_MS,
      )
      blockedUntil = now + delay
      retryAt.value = new Date(blockedUntil).toISOString()
    } else {
      contractFailureCount = 0
      blockedUntil = 0
      retryAt.value = ''
    }

    if (message !== errorMessage.value || now - lastVisibleUpdateAt >= VISIBLE_ERROR_UPDATE_INTERVAL_MS) {
      errorMessage.value = message
      lastErrorAt.value = new Date(now).toISOString()
      lastVisibleUpdateAt = now
    }
  }

  const clear = (): void => {
    errorMessage.value = null
    lastErrorAt.value = ''
    retryAt.value = ''
    contractFailureCount = 0
    blockedUntil = 0
    lastVisibleUpdateAt = 0
  }

  const resetBackoff = (): void => {
    contractFailureCount = 0
    blockedUntil = 0
    retryAt.value = ''
  }

  return { errorMessage, lastErrorAt, retryAt, canRun, recordError, clear, resetBackoff }
}
