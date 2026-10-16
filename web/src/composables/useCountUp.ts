import { ref, watch, onUnmounted, type Ref } from 'vue'

// 数字滚动（威胁大屏统计卡）：源值变化时经 rAF 缓动补间到新值。
// - 首次/大跨度用 ease-out（先快后慢的滚动感）
// - 页签隐藏或组件卸载即停帧；恢复可见时直接落到源值（无积压补间）
// - 整数展示（大屏计数无小数语义），源值为非有限数时落 0
export function useCountUp(source: Ref<number>, durationMs = 800): Ref<number> {
  const display = ref(Math.max(0, Math.floor(Number.isFinite(source.value) ? source.value : 0)))
  let rafId = 0

  const stop = (): void => {
    if (rafId) {
      cancelAnimationFrame(rafId)
      rafId = 0
    }
  }

  watch(source, (target) => {
    stop()
    const goal = Math.max(0, Math.floor(Number.isFinite(target) ? target : 0))
    const from = display.value
    if (goal === from) {
      display.value = goal
      return
    }
    const startAt = performance.now()
    const step = (now: number): void => {
      const t = Math.min(1, (now - startAt) / durationMs)
      const eased = 1 - Math.pow(1 - t, 3)
      display.value = Math.round(from + (goal - from) * eased)
      if (t < 1) rafId = requestAnimationFrame(step)
      else rafId = 0
    }
    rafId = requestAnimationFrame(step)
  })

  onUnmounted(stop)
  return display
}
