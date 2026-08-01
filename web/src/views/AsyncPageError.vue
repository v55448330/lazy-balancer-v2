<template>
  <el-result icon="error" title="页面加载失败" sub-title="请刷新页面后重试">
    <template #extra>
      <el-button type="primary" @click="reloadPage">刷新页面</el-button>
    </template>
  </el-result>
</template>

<script setup lang="ts">
const reloadPage = (): void => window.location.reload()
</script>
