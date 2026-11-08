<template>
  <el-tooltip placement="top" :popper-class="popperClass" :disabled="!content && !$slots.content">
    <template #content>
      <slot name="content">{{ content }}</slot>
    </template>
    <!-- 键盘/读屏可达：hover-only 的角标对键盘用户不存在（EP tooltip 在
         reference 聚焦后按 Enter/Space 展开，triggerKeys 默认即如此）。 -->
    <el-icon
      class="field-help-icon"
      role="button"
      tabindex="0"
      :aria-label="content || t('common.app.views.common.fieldHelpAria')"
    ><QuestionFilled /></el-icon>
  </el-tooltip>
</template>

<script setup lang="ts">
import { QuestionFilled } from '@element-plus/icons-vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// 统一字段帮助角标（2026-10-12 用户裁定：角标应有统一规范及实现，不再各处手写 icon+CSS）。
// 规范：紧跟标题文字后、默认 inline 形态（无额外定位——与表头原生态逐像素一致）、
// 灰色 QuestionFilled 14px、hover 提示（支持纯文本 content 或 #content 插槽多行）。
// 全部消费方迁移自此（表头/表单 label/开关行）；新增 ？ 角标一律用本组件，禁止手写。
withDefaults(defineProps<{
  readonly content?: string
  readonly popperClass?: string
}>(), { content: '' })
</script>

<style scoped>
.field-help-icon {
  color: #9ca3af;
  font-size: 14px;
}
.field-help-icon:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: 2px;
  border-radius: 2px;
}
</style>
