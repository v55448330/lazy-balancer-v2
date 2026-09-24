<template>
  <div class="schedule-editor">
    <div class="schedule-editor__head">
      <span class="schedule-editor__title">定时更新</span>
      <span class="schedule-editor__hint">按基础设置时区（{{ tz || '…' }}）执行</span>
    </div>
    <div class="schedule-editor__controls">
      <el-select
        v-model="editDays"
        multiple
        :disabled="disabled"
        class="schedule-editor__days"
        placeholder="选择星期"
      >
        <el-option v-for="d in weekdayOptions" :key="d.value" :label="d.label" :value="d.value" />
      </el-select>
      <el-time-picker
        v-model="editTime"
        :disabled="disabled"
        format="HH:mm"
        value-format="HH:mm"
        placeholder="时间"
        class="schedule-editor__time"
      />
      <el-button size="small" type="primary" :disabled="disabled" :loading="saving" @click="emitSave">保存定时</el-button>
    </div>
    <div class="schedule-editor__tip">自动更新开关关闭时不执行；手动「立即更新」不受影响</div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

// 规则库（CRS/IP2Region/威胁情报库）更新弹框共享的「定时更新」卡片区：
// 星期多选（1=周一…7=周日）+ HH:MM 时间，保存即由后端重排下次更新。

const props = withDefaults(defineProps<{
  days: number[]
  time: string
  disabled?: boolean
  saving?: boolean
  tz?: string
}>(), { disabled: false, saving: false, tz: '' })

const emit = defineEmits<{ save: [payload: { days: number[]; time: string }] }>()

const weekdayOptions = [
  { value: 1, label: '周一' },
  { value: 2, label: '周二' },
  { value: 3, label: '周三' },
  { value: 4, label: '周四' },
  { value: 5, label: '周五' },
  { value: 6, label: '周六' },
  { value: 7, label: '周日' },
]

const editDays = ref<number[]>([...props.days])
const editTime = ref(props.time || '04:00')

// 保存成功后父级刷新库信息 → props 变化时回填（不覆盖用户未保存的编辑：
// 仅当与父级值一致时才同步——编辑中父级轮询刷新不丢输入）
watch(() => [props.days, props.time] as const, ([days, time], prev) => {
  const prevDays = prev?.[0] ?? []
  const prevTime = prev?.[1] ?? ''
  const untouched = editDays.value.join() === prevDays.join() && editTime.value === (prevTime || '04:00')
  if (untouched) {
    editDays.value = [...days]
    editTime.value = time || '04:00'
  }
})

const emitSave = () => {
  if (!editDays.value.length) {
    ElMessage.warning('至少选择一天')
    return
  }
  emit('save', { days: [...editDays.value], time: editTime.value || '04:00' })
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
</style>
