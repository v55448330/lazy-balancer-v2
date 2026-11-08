<template>
  <div class="schedule-editor">
    <div class="schedule-editor__head">
      <span class="schedule-editor__title">{{ t('common.app.rules.sched.title') }}</span>
      <span class="schedule-editor__hint">{{ t('common.app.rules.sched.tzHint', { tz: tz || '…' }) }}</span>
    </div>
    <div class="schedule-editor__controls">
      <el-select
        v-model="editDays"
        multiple
        :disabled="controlsDisabled"
        class="schedule-editor__days"
        :placeholder="t('common.app.rules.sched.selectDays')"
      >
        <el-option v-for="d in weekdayOptions" :key="d.value" :label="d.label" :value="d.value" />
      </el-select>
      <el-time-picker
        v-model="editTime"
        :disabled="controlsDisabled"
        format="HH:mm"
        value-format="HH:mm"
        :placeholder="t('common.app.rules.sched.time')"
        class="schedule-editor__time"
      />
      <el-button size="small" type="primary" :disabled="controlsDisabled" :loading="saving" @click="emitSave">{{ t('common.app.rules.sched.save') }}</el-button>
    </div>
    <div v-if="unavailableHint" class="schedule-editor__tip schedule-editor__tip--error" role="status">{{ unavailableHint }}</div>
    <div v-else class="schedule-editor__tip">{{ t('common.app.rules.sched.autoUpdateOffHint') }}</div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { libraryScheduleError, scheduleEditUntouched } from '@/utils/securityLibraries'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// 规则库（CRS/IP2Region/威胁情报库/爬虫地址库）更新弹框共享的「定时更新」卡片区：
// 星期多选（1=周一…7=周日）+ HH:MM 时间，保存即由后端重排下次更新。
// 库信息读取失败/未落地时传 unavailableHint：控件与保存按钮一并禁用，
// 不得用默认值（周一–周日 04:00）冒充库内排程并可保存覆盖真实排程。

const props = withDefaults(defineProps<{
  days: number[]
  time: string
  disabled?: boolean
  saving?: boolean
  tz?: string
  unavailableHint?: string
}>(), { disabled: false, saving: false, tz: '', unavailableHint: '' })

const emit = defineEmits<{ save: [payload: { days: number[]; time: string }] }>()

const controlsDisabled = computed(() => props.disabled || props.saving || Boolean(props.unavailableHint))

const weekdayOptions = [
  { value: 1, label: t('common.app.rules.sched.mon') },
  { value: 2, label: t('common.app.rules.sched.tue') },
  { value: 3, label: t('common.app.rules.sched.wed') },
  { value: 4, label: t('common.app.rules.sched.thu') },
  { value: 5, label: t('common.app.rules.sched.fri') },
  { value: 6, label: t('common.app.rules.sched.sat') },
  { value: 7, label: t('common.app.rules.sched.sun') },
]

const editDays = ref<number[]>([...props.days])
const editTime = ref(props.time || '04:00')

// 保存成功后父级刷新库信息 → props 变化时回填（不覆盖用户未保存的编辑：
// 仅当与父级值一致时才同步——编辑中父级轮询刷新不丢输入）
watch(() => [props.days, props.time] as const, ([days, time], prev) => {
  const untouched = scheduleEditUntouched(
    { days: editDays.value, time: editTime.value },
    { days: prev?.[0] ?? [], time: prev?.[1] ?? '' },
  )
  if (untouched) {
    editDays.value = [...days]
    editTime.value = time || '04:00'
  }
})

const emitSave = () => {
  if (props.saving) return
  // 时间被清空时不得静默回落 04:00（原 `editTime.value || '04:00'`
  // 让输入框显示空、落库却是 04:00）；校验单源 utils/securityLibraries。
  const time = editTime.value
  const error = libraryScheduleError(editDays.value, time)
  if (error) {
    ElMessage.warning(error)
    return
  }
  emit('save', { days: [...editDays.value], time })
}
</script>

<style scoped>
.schedule-editor {
  margin-bottom: 14px;
  padding: 12px 14px;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  background: #f9fafb;
}
.schedule-editor__head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.schedule-editor__title { font-size: 13px; font-weight: 600; color: #1f2937; }
.schedule-editor__hint { font-size: 12px; color: #909399; }
.schedule-editor__controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.schedule-editor__days { flex: 1 1 220px; min-width: 180px; }
.schedule-editor__time { width: 110px; }
.schedule-editor__tip { margin-top: 8px; font-size: 12px; color: #909399; line-height: 1.6; }
.schedule-editor__tip--error { color: var(--el-color-danger); }
</style>
