<template>
  <div class="dsh-head">
    <span class="dsh-mark" :class="`is-${tone}`" aria-hidden="true"></span>
    <div class="dsh-copy">
      <h3>{{ title }}</h3>
      <p v-if="description">{{ description }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  title: string
  description?: string
  tone?: 'primary' | 'danger' | 'success' | 'warning'
}>(), { tone: 'primary' })
</script>

<style scoped>
.dsh-head { display: flex; align-items: center; gap: 9px; margin: 0 0 10px; }
.dsh-head + * { margin-top: 0; }
.dsh-mark { width: 7px; height: 24px; flex: none; background: var(--el-color-primary, #4d8fe8); }
.dsh-mark.is-danger { background: var(--el-color-danger, #e06565); }
.dsh-mark.is-success { background: var(--el-color-success, #43a580); }
.dsh-mark.is-warning { background: var(--el-color-warning, #d99a3d); }
.dsh-copy { min-width: 0; }
.dsh-copy h3 { margin: 0; color: var(--el-text-color-primary, #1f2937); font-size: 13px; font-weight: 650; line-height: 1.35; }
.dsh-copy p { margin: 2px 0 0; color: var(--el-text-color-secondary, #8a94a6); font-size: 11px; line-height: 1.45; }
</style>
