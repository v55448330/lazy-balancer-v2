<template>
  <!-- 累犯历史弹框（总览「累犯升级」统计下钻）：薄壳弹框 + RecidivismTable
       共享组件（与事件页「封禁与累犯」合并弹框 tab2 同一实现）。
       写门与宿主 autobanWritable 同口径（writable/blockedReason 由宿主传入）。 -->
  <el-dialog :model-value="modelValue" width="min(1280px, 96vw)" top="5vh" append-to-body class="dialog-body-inset" :close-on-click-modal="false" @update:model-value="emit('update:modelValue', $event)">
    <template #header>
      <DialogHeader :icon="Lock" :title="t('app.security.overview.autoban.recidivismDialogTitle')" :subtitle="t('app.security.overview.autoban.recidivismDialogSubtitle')" />
    </template>
    <RecidivismTable :active="modelValue" :writable="writable" :blocked-reason="blockedReason" :duration="duration" :escalation="escalation" @reset="emit('reset')" />
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">{{ t('app.security.overview.autoban.recidivismClose') }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { Lock } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import RecidivismTable from '@/components/security/RecidivismTable.vue'

// 宿主契约：writable/blockedReason 与宿主 autoban 写门同口径；duration/escalation
// 为当前配置实态；重置/快捷弹框写动作成功后 emit('reset') 由宿主刷新状态卡。
defineProps<{
  readonly modelValue: boolean
  readonly writable: boolean
  readonly blockedReason: string
  readonly duration: string
  readonly escalation?: string
}>()
const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'reset'): void
}>()

const { t } = useI18n()
</script>
