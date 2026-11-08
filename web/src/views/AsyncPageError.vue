<template>
  <el-result icon="error" :title="t('common.app.pageError.title')" :sub-title="t('common.app.pageError.hint')">
    <template #extra>
      <el-button type="primary" @click="reloadPage">{{ t('common.app.pageError.reload') }}</el-button>
    </template>
  </el-result>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const reloadPage = (): void => window.location.reload()
</script>
