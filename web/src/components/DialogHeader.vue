<template>
  <div class="dh-header">
    <div class="dh-icon" :class="iconClass">
      <el-icon :size="18"><component :is="icon" /></el-icon>
    </div>
    <span class="dh-bar" :class="barClass"></span>
    <div>
      <div class="dh-title">{{ title }}</div>
      <div v-if="subtitle" class="dh-sub">{{ subtitle }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'

const props = defineProps<{
  icon: Component
  title: string
  subtitle?: string
  tone?: 'primary' | 'success' | 'warning' | 'danger'
  /** 自定义图标底色类（超出四 tone 的专属色族——消费侧经 :deep() 定义，如 lib-icon--crs） */
  toneClass?: string
}>()

const iconClass = computed(() => [props.tone ? `dh-icon--${props.tone}` : '', props.toneClass || ''])
const barClass = computed(() => props.tone ? `dh-bar--${props.tone}` : '')
</script>

<style scoped>
/* 弹框头统一组件视觉：图标 + 标题 + 副标题（tone 四色 + toneClass 自定义底色） */
.dh-header { display: flex; align-items: center; gap: 12px; }
.dh-icon {
  width: 38px; height: 38px; border-radius: 0;
  display: flex; align-items: center; justify-content: center;
  background: var(--el-color-primary-light-8); color: var(--el-color-primary-dark-2); border: 1px solid var(--el-color-primary-light-7);
  font-size: 18px; flex-shrink: 0;
}
.dh-icon--success { background: var(--el-color-success-light-8); color: var(--el-color-success-dark-2); border: 1px solid var(--el-color-success-light-7); }
.dh-icon--warning { background: var(--el-color-warning-light-8); color: var(--el-color-warning-dark-2); border: 1px solid var(--el-color-warning-light-7); }
.dh-icon--danger { background: var(--el-color-danger-light-8); color: var(--el-color-danger-dark-2); border: 1px solid var(--el-color-danger-light-7); }
.dh-title { font-size: 16px; font-weight: 600; color: var(--el-text-color-primary); }
.dh-sub { font-size: 12.5px; color: var(--el-text-color-secondary); margin-top: 2px; }
.dh-bar { width: 3px; height: 30px; flex-shrink: 0; background: var(--el-color-primary); margin: 0 2px 0 -4px; }
.dh-bar--success { background: var(--el-color-success); }
.dh-bar--warning { background: var(--el-color-warning); }
.dh-bar--danger { background: var(--el-color-danger); }
</style>
