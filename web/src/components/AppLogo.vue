<template>
  <svg :width="size" :height="size" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" class="app-logo" aria-hidden="true">
    <defs>
      <linearGradient id="lb-logo-grad" x1="0" y1="0" x2="40" y2="40" gradientUnits="userSpaceOnUse">
        <stop offset="0" stop-color="#3b82f6" />
        <stop offset="1" stop-color="#2563eb" />
      </linearGradient>
    </defs>
    <rect width="40" height="40" rx="9" fill="url(#lb-logo-grad)" />
    <g stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" fill="none" opacity="0.95">
      <path d="M12 20 C 17 20, 21 13, 26 11.5" />
      <path d="M12 20 L26 20" />
      <path d="M12 20 C 17 20, 21 27, 26 28.5" />
    </g>
    <circle cx="9.5" cy="20" r="3.2" fill="#ffffff" />
    <circle cx="30" cy="10.5" r="2.8" fill="#ffffff" />
    <circle cx="30" cy="20" r="2.8" fill="#ffffff" />
    <circle cx="30" cy="29.5" r="2.8" fill="#ffffff" />
  </svg>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ size?: number | string }>(), { size: 40 })
</script>

<style scoped>
.app-logo { display: block; flex-shrink: 0; }
</style>
