<template>
  <div class="proxy-timeout-fields">
    <el-form-item v-for="field in fields" :key="field.key" :label="field.label">
      <el-input-number
        :model-value="value[field.key]"
        :min="field.min"
        :max="86400"
        :placeholder="inheritLabel"
        :disabled="disabled"
        controls-position="right"
        class="number-input"
        @update:model-value="update(field.key, $event)"
      />
      <el-text type="info" size="small" class="tip-inline">
        秒，0 = {{ inheritLabel }}<template v-if="showSuggested && field.suggest">；非流式建议 {{ field.suggest }}</template><template v-if="field.desc">；{{ field.desc }}</template>
      </el-text>
    </el-form-item>
  </div>
</template>

<script setup lang="ts">
import type { ProxyTimeoutConfig } from '@/types'

withDefaults(defineProps<{
  readonly value: ProxyTimeoutConfig
  readonly inheritLabel: string
  readonly disabled?: boolean
  readonly showSuggested?: boolean
}>(), { showSuggested: false })

const emit = defineEmits<{
  (event: 'update', field: keyof ProxyTimeoutConfig, value: number): void
}>()

type TimeoutField = {
  readonly key: keyof ProxyTimeoutConfig
  readonly label: string
  readonly min: number
  readonly desc: string
  readonly suggest?: number
}

const fields: readonly TimeoutField[] = [
  { key: 'proxy_dial_timeout', label: '连接超时', min: 0, desc: '建立到上游 TCP 连接', suggest: 10 },
  { key: 'proxy_response_header_timeout', label: '响应头超时', min: 0, desc: '等待上游响应头返回', suggest: 30 },
  { key: 'proxy_read_timeout', label: '读超时', min: 0, desc: '两次读上游数据的间隔；流式需大于静默期', suggest: 60 },
  { key: 'proxy_write_timeout', label: '写超时', min: 0, desc: '两次写客户端的间隔；流式需大于静默期', suggest: 60 },
  { key: 'proxy_stream_timeout', label: '流式超时', min: 0, desc: '整个流式会话总时长；用于 SSE/LLM' },
  { key: 'proxy_flush_interval', label: '刷新间隔', min: -1, desc: '默认仅 SSE 无缓冲；-1=所有响应无缓冲；>0=每 N 秒一次' },
  { key: 'proxy_stream_close_delay', label: '流关闭延迟', min: 0, desc: '>0=reload 时延迟 N 秒关旧 WebSocket/SSE' },
]

const update = (field: keyof ProxyTimeoutConfig, value: number | undefined): void => {
  emit('update', field, value ?? 0)
}
</script>

<style scoped>
.number-input { width: 120px; }
.tip-inline { margin-left: 8px; line-height: 1.5; }

@media (max-width: 767px) {
  .tip-inline { flex-basis: 100%; margin-top: 4px; margin-left: 0; }
}
</style>
