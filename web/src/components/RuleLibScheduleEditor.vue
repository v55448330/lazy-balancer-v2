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
  background: #f9fafb;
}
.schedule-editor__head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.schedule-editor__title { font-size: 13px; font-weight: 600; color: #1f2937; }
.schedule-editor__hint { font-size: 12px; color: #909399; }
/* 控件行两输入框严格同高（2026-11-22 用户裁定：「不接受一行两个输入框一高一低」）：
 * 统一 32px——多选框单行标签的**自然高度**就是 32（不压扁、不裁标签），
 * 时间框把全局 28px 输入壳覆写回 32 填满 .el-date-editor 外层（此前 28 顶对齐
 * 于 32 外层=2px 偏差根因）。窄容器标签不换行（nowrap+hidden），高度恒定。
 * 历轮失败根因备案：stretch 被 .el-date-editor 显式高度压制；28px 钉高造成
 * 外层 32/内层 28 顶对齐分叉——同高必须「两框都回到同一自然高度」。 */
.schedule-editor__controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.schedule-editor__days { flex: 1 1 220px; min-width: 180px; }
.schedule-editor__time { width: 110px; }
/* 锚定必须用**原生元素**（controls 容器有 data-v）：el-time-picker/el-select
 * 组件根只透传 class 不带 scoped attr——挂在 .schedule-editor__time[data-v]
 * 上的 :deep 规则从不匹配（历轮修复全灭的最终根因）。统一 32px 自然同高。 */
.schedule-editor .schedule-editor__controls :deep(.el-select__wrapper) { height: 32px; min-height: 32px; }
.schedule-editor__controls :deep(.el-select__selection) { flex-wrap: nowrap; overflow: hidden; }
.schedule-editor .schedule-editor__controls :deep(.el-input__wrapper) { height: 32px; box-sizing: border-box; }
.schedule-editor__tip { margin-top: 8px; font-size: 12px; color: #909399; line-height: 1.6; }
.schedule-editor__tip--error { color: var(--el-color-danger); }
</style>
