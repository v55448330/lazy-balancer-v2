<template>
  <!-- 视觉沿用 el-link；语义必须是可聚焦控件。无 href 的 <a> 不进 Tab 序、回车
       无动作（element-plus 的 link 只在 href 存在时渲染 href，也不补
       tabindex/role）——键盘与读屏用户会丢失该操作入口。键盘激活统一合成
       click，复用调用方已有的 @click（不引入第二套回调契约）。 -->
  <el-link
    v-bind="props"
    role="button"
    tabindex="0"
    @keydown.enter.prevent="activate"
    @keydown.space.prevent="activate"
  >
    <slot />
  </el-link>
</template>

<script setup lang="ts">
import { activateOnce } from '@/utils/keyboardActivate'

// 外观契约与 el-link 一致：这些 props 必须声明（未声明的属性会落进 attrs 被
// 静默吞掉，模板类型检查也看不到调用方传了什么），声明后显式转发给 el-link。
const props = withDefaults(defineProps<{
  readonly type?: 'default' | 'primary' | 'success' | 'warning' | 'info' | 'danger'
  readonly underline?: 'always' | 'hover' | 'never'
  readonly size?: '' | 'small' | 'default' | 'large'
}>(), {
  // 统一表格/弹框链接：平时无下划线，hover 与 IP 快捷入口同视觉。
  underline: 'never',
})

// 键盘激活：Enter/Space → 合成 click（浏览器对无 href 的 <a> 不提供默认激活行为），
// 长按过滤统一走 activateOnce，避免与其它键盘入口产生第二套守卫语义。
const activate = (event: KeyboardEvent): void => {
  activateOnce(event, () => {
    const target = event.currentTarget
    if (target instanceof HTMLElement) target.click()
  })
}
</script>

<style scoped>
/* 键盘焦点必须可见；浅底统一，文字色仅 primary/danger 使用主色，其余保留类型语义。 */
.el-link { padding: 1px 3px; margin: -1px -3px; border-radius: 3px; transition: background .15s, color .15s; }
.el-link:hover { background: var(--el-color-primary-light-9, #ecf5ff); text-decoration: none; }
.el-link--primary:hover, .el-link--danger:hover { color: var(--el-color-primary, #409eff); }
.el-link:active { background: var(--el-color-primary-light-8, #d9ecff); }
.el-link:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }
</style>