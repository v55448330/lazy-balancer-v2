<template>
  <div class="proxy-timeout-fields">
    <el-form-item v-for="field in fields" :key="field.key" :label="field.label">
      <el-input-number
        :model-value="value[field.key]"
        :min="field.min"
        :placeholder="inheritLabel"
        :disabled="disabled || fieldOverrides?.[field.key]?.disabled === true"
        controls-position="right"
        class="number-input"
        @update:model-value="update(field.key, $event)"
      />
      <!-- 字段说明英文多超 40 字符（§26-5 同行阈值）→ 一律块级说明；
           完整说明（0=继承 + 建议值）仍在 :title 悬浮。 -->
      <div v-if="fieldOverrides?.[field.key]" class="form-tip-line">
        <TakeoverBadge v-if="fieldOverrides[field.key]!.badge" :label="fieldOverrides[field.key]!.badge" />
        {{ fieldOverrides[field.key]!.note }}
      </div>
      <div v-else class="form-tip-line" :title="fieldFullTip(field)">{{ field.desc }}</div>
    </el-form-item>
  </div>
</template>

<script setup lang="ts">
import TakeoverBadge from '@/components/common/TakeoverBadge.vue'
import type { ProxyTimeoutConfig } from '@/types'
import { PROXY_TIMEOUT_FIELDS } from '@/utils/proxyTimeouts.ts'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = withDefaults(defineProps<{
  readonly value: ProxyTimeoutConfig
  readonly inheritLabel: string
  readonly disabled?: boolean
  readonly showSuggested?: boolean
  // 逐字段接管态（如 NTLM 兼容）：disabled=禁用输入；note 存在时以接管说明
  // 替换默认 tip；badge 为前置徽标文案
  readonly fieldOverrides?: Partial<Record<keyof ProxyTimeoutConfig, {
    readonly disabled?: boolean
    readonly badge?: string
    readonly note?: string
  }>>
}>(), { showSuggested: false })

const emit = defineEmits<{
  (event: 'update', field: keyof ProxyTimeoutConfig, value: number): void
}>()

type TimeoutField = (typeof PROXY_TIMEOUT_FIELDS)[number]

// 字段定义（标签/下限/说明/建议值）与向导预览摘要同源，见 utils/proxyTimeouts.ts。
const fields: readonly TimeoutField[] = PROXY_TIMEOUT_FIELDS

// 提示行语义分层：说明行放通俗功能描述（这个超时控制什么），「0=继承 + 建议值」
// 是占位符语义属次要信息，连同说明全文移 :title 悬浮。说明行按 §26-5 一律块级
// （英文描述多超 40 字符同行阈值）。整行走词条：i18n 抽词后由词条给出各段分隔符，
// 模板不拼字面片段。
const fieldInheritTip = (field: TimeoutField): string => {
  let tip = t('common.app.views.proxyTimeout.tipZeroInherit', { inherit: props.inheritLabel })
  if (props.showSuggested && field.suggest !== undefined) tip += t('common.app.views.proxyTimeout.tipSuggest', { suggest: field.suggest })
  return tip
}
const fieldFullTip = (field: TimeoutField): string => {
  const inherit = fieldInheritTip(field)
  return field.desc ? (inherit ? inherit + t('common.app.views.proxyTimeout.tipDesc', { desc: field.desc }) : field.desc) : inherit
}

const update = (field: keyof ProxyTimeoutConfig, value: number | undefined): void => {
  emit('update', field, value ?? 0)
}
</script>

<style scoped>
.number-input { width: 120px; }
</style>
