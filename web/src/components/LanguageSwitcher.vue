<template>
  <el-dropdown trigger="click" @command="onPick">
    <button class="lang-switch" type="button" :title="t('common.app.language')">
      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
        <path fill="currentColor" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm7.9 9h-3a15.6 15.6 0 0 0-1.1-5.2A8 8 0 0 1 19.9 11zM12 4c.9 1.2 1.8 3.6 2 7h-4c.2-3.4 1.1-5.8 2-7zM4.1 13h3c.2 1.9.6 3.7 1.1 5.2A8 8 0 0 1 4.1 13zm3-2h-3a8 8 0 0 1 4.1-5.2A15.6 15.6 0 0 0 7.1 11zm2 2h5.8c-.2 3.4-1.1 5.8-2 7H12c-.9-1.2-1.8-3.6-2-7h-1zm7 0h3a8 8 0 0 1-4.1 5.2c.5-1.5.9-3.3 1.1-5.2z"/>
      </svg>
      <span class="lang-switch__label">{{ current === 'zh-CN' ? '中' : 'EN' }}</span>
    </button>
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item command="zh-CN" :class="{ active: current === 'zh-CN' }">中文</el-dropdown-item>
        <el-dropdown-item command="en" :class="{ active: current === 'en' }">English</el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { setLocale, type Locale } from '@/i18n'

const { t, locale } = useI18n()
const current = computed(() => (locale.value === 'en' ? 'en' : 'zh-CN'))
const onPick = (l: Locale) => {
  if (l !== locale.value) setLocale(l)
}
</script>

<style scoped>
.lang-switch {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  border: none;
  background: transparent;
  color: inherit;
  cursor: pointer;
  padding: 4px 6px;
  font-size: 13px;
}
.lang-switch:hover { opacity: 0.8; }
</style>
