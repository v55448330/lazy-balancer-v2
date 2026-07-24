<template>
  <el-dialog
    :model-value="visible"
    :title="`访问控制 — ${ruleName}`"
    width="min(620px, 92vw)"
    :close-on-click-modal="false"
    @update:model-value="emit('update:visible', $event)"
  >
    <el-form label-width="100px">
      <el-form-item label="访问模式">
        <el-radio-group v-model="mode" class="acl-mode-group">
          <el-radio value="">全部允许（默认）</el-radio>
          <el-radio value="allow">白名单（仅允许列表 IP）</el-radio>
          <el-radio value="deny">黑名单（拒绝列表 IP）</el-radio>
        </el-radio-group>
      </el-form-item>

      <template v-if="mode">
        <el-form-item label="CIDR 列表" :error="validationError">
          <div class="cidr-editor">
            <div v-for="(_, index) in cidrs" :key="index" class="cidr-row">
              <el-input v-model="cidrs[index]" placeholder="例如：10.0.0.0/8 或 192.168.1.10" clearable />
              <el-button type="danger" plain :icon="Delete" aria-label="删除 CIDR" @click="removeCidr(index)" />
            </div>
            <el-button plain :icon="Plus" @click="addCidr">添加 CIDR</el-button>
          </div>
        </el-form-item>
        <el-alert :title="modeHint" type="info" :closable="false" show-icon />
      </template>
    </el-form>

    <template #footer>
      <el-button @click="emit('update:visible', false)">取消</el-button>
      <el-button type="primary" :loading="saving" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Delete, Plus } from '@element-plus/icons-vue'
import type { IpAclMode } from '@/types'
import { isValidCidr } from '@/utils/ruleValidation'

const props = defineProps<{
  readonly visible: boolean
  readonly ruleName: string
  readonly initialMode: IpAclMode
  readonly initialCidrs: readonly string[]
  readonly saving: boolean
}>()

const emit = defineEmits<{
  (event: 'update:visible', visible: boolean): void
  (event: 'save', value: { readonly mode: IpAclMode; readonly cidrs: readonly string[] }): void
}>()

const mode = ref<IpAclMode>('')
const cidrs = ref<string[]>([])
const validationError = ref('')

const modeHint = computed(() => mode.value === 'allow'
  ? '白名单 = 仅列表内 IP 可访问，其余连接将被拒绝。'
  : '黑名单 = 仅拒绝列表内 IP。')

watch(() => props.visible, (visible) => {
  if (!visible) return
  mode.value = props.initialMode
  cidrs.value = [...props.initialCidrs]
  validationError.value = ''
})

watch(mode, () => { validationError.value = '' })
watch(cidrs, () => { validationError.value = '' }, { deep: true })

const addCidr = (): void => {
  cidrs.value.push('')
}

const removeCidr = (index: number): void => {
  cidrs.value.splice(index, 1)
  validationError.value = ''
}

const submit = (): void => {
  const normalizedCidrs = cidrs.value.map((cidr) => cidr.trim())
  if (mode.value && normalizedCidrs.length === 0) {
    validationError.value = '请至少添加一个 CIDR'
    return
  }
  const invalidIndex = normalizedCidrs.findIndex((cidr) => !isValidCidr(cidr))
  if (mode.value && invalidIndex >= 0) {
    validationError.value = `第 ${invalidIndex + 1} 行 CIDR 格式不正确`
    return
  }
  validationError.value = ''
  emit('save', { mode: mode.value, cidrs: mode.value ? normalizedCidrs : [] })
}
</script>

<style scoped>
.cidr-editor { display: flex; flex: 1; min-width: 0; flex-direction: column; gap: 12px; }
.cidr-row { display: flex; gap: 8px; }
.acl-mode-group { display: flex; align-items: flex-start; flex-direction: column; gap: 10px; }
.acl-mode-group :deep(.el-radio) { margin-right: 0; }

@media (max-width: 767px) {
  .cidr-row { align-items: stretch; }
}
</style>
