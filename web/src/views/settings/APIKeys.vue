<template>
  <div class="api-keys-wrapper">
    <Keys />
  </div>
</template>

<script setup lang="ts">
import Keys from '@/views/Keys.vue'
</script>

<style scoped>
.api-keys-wrapper :deep(.page) {
  max-width: none;
  margin: 0;
}
.api-keys-wrapper :deep(.page-header) {
  margin-bottom: 16px;
}
</style>
