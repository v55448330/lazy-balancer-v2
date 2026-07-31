<template>
  <el-dialog
    :model-value="visible"
    title="编辑访问地址"
    width="min(480px, 92vw)"
    :close-on-click-modal="false"
    :close-on-press-escape="!saving"
    :show-close="!saving"
    @update:model-value="handleVisibilityChange"
    @opened="focusInput"
    @closed="resetForm"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-position="top" @submit.prevent="save">
      <el-form-item label="访问地址" prop="access_url">
        <el-input
          ref="inputRef"
          v-model="form.access_url"
          placeholder="例如：https://127.0.0.1:8001"
          clearable
          :disabled="saving"
          @keyup.enter="save"
        />
        <div class="form-tip">
          {{ form.access_url.trim() ? '请输入可从浏览器访问的 HTTP 或 HTTPS 地址' : '留空将回退使用注册地址' }}
        </div>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button :disabled="saving" @click="close">取消</el-button>
      <el-button type="primary" :loading="saving" @click="save">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { nextTick, reactive, ref, watch } from 'vue'
import type { FormInstance, FormRules, InputInstance } from 'element-plus'
import type { ClusterNode } from '@/types'

interface AccessUrlForm {
  access_url: string
}

const props = defineProps<{
  readonly visible: boolean
  readonly node: ClusterNode | null
  readonly saving: boolean
}>()

const emit = defineEmits<{
  (event: 'close'): void
  (event: 'save', accessUrl: string): void
}>()

const formRef = ref<FormInstance>()
const inputRef = ref<InputInstance>()
const form = reactive<AccessUrlForm>({ access_url: '' })

const validateAccessUrl = (_rule: unknown, value: string, callback: (error?: Error) => void): void => {
  const normalized = value.trim()
  if (!normalized) {
    callback()
    return
  }
  try {
    const parsed = new URL(normalized)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      callback(new Error('访问地址必须使用 HTTP 或 HTTPS'))
      return
    }
    if (parsed.username || parsed.password) {
      callback(new Error('访问地址不能包含用户名或密码'))
      return
    }
    callback()
  } catch (error: unknown) {
    if (error instanceof TypeError) {
      callback(new Error('访问地址格式不正确'))
      return
    }
    throw error
  }
}

const rules: FormRules<AccessUrlForm> = {
  access_url: [{ validator: validateAccessUrl, trigger: ['blur', 'change'] }],
}

watch(
  () => [props.visible, props.node] as const,
  ([visible, node]) => {
    if (visible && node) form.access_url = node.access_url
  },
  { immediate: true },
)

const focusInput = async (): Promise<void> => {
  await nextTick()
  inputRef.value?.focus()
}

const resetForm = (): void => {
  form.access_url = ''
  formRef.value?.clearValidate()
}

const close = (): void => {
  if (!props.saving) emit('close')
}

const handleVisibilityChange = (visible: boolean): void => {
  if (!visible) close()
}

const save = async (): Promise<void> => {
  if (props.saving || !formRef.value) return
  let valid = false
  await formRef.value.validate((result) => {
    valid = result
  })
  if (valid) emit('save', form.access_url.trim())
}
</script>

<style scoped>
.form-tip { width: 100%; margin-top: 4px; color: var(--text-muted); font-size: 12px; }
</style>
