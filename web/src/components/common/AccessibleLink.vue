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
// 外观契约与 el-link 一致：这些 props 必须声明（未声明的属性会落进 attrs 被
// 静默吞掉，模板类型检查也看不到调用方传了什么），声明后显式转发给 el-link。
const props = withDefaults(defineProps<{
  readonly type?: 'default' | 'primary' | 'success' | 'warning' | 'info' | 'danger'
  readonly underline?: 'always' | 'hover' | 'never'
  readonly size?: '' | 'small' | 'default' | 'large'
}>(), {
  // Element Plus 3 将弃用布尔 underline；默认 always 与原 el-link 默认 true 同视觉。
  underline: 'always',
})

// 键盘激活：Enter/Space → 合成 click（浏览器对无 href 的 <a> 不提供默认激活行为）。
// 必须过滤按键自动重复：长按会按系统重复率反复合成 click，落到切换/取数类动作上
// 会来回切换（结果取决于按住多久）或重复发请求。
const activate = (event: KeyboardEvent): void => {
  if (event.repeat) return
  const target = event.currentTarget
  if (target instanceof HTMLElement) target.click()
}
</script>

<style scoped>
/* 键盘焦点必须可见：el-link 默认无焦点环 */
.el-link:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }
</style>
