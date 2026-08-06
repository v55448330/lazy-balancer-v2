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
        秒，0 = {{ inheritLabel }}<template v-if="field.key === 'proxy_stream_timeout'">；用于 SSE/LLM 等长流式响应</template><template v-if="field.key === 'proxy_read_timeout' || field.key === 'proxy_write_timeout'">；SSE/WebSocket/LLM 场景需大于上游最长静默期，否则连接会被强制断开</template><template v-if="field.key === 'proxy_flush_interval'">；-1 = 立即刷新所有响应（无缓冲，强制对非 text/event-stream 流式也生效），&gt;0 = 每 N 秒刷新一次</template><template v-if="field.key === 'proxy_stream_close_delay'">；&gt;0 = 配置 reload 时延迟 N 秒关闭旧 WebSocket/SSE 连接，平滑过渡</template>
      </el-text>
    </el-form-item>
  </div>
</template>

<script setup lang="ts">
import type { ProxyTimeoutConfig } from '@/types'

defineProps<{
  readonly value: ProxyTimeoutConfig
  readonly inheritLabel: string
  readonly disabled?: boolean
}>()

const emit = defineEmits<{
  (event: 'update', field: keyof ProxyTimeoutConfig, value: number): void
}>()

const fields = [
  { key: 'proxy_dial_timeout', label: '连接超时', min: 0 },
  { key: 'proxy_response_header_timeout', label: '响应头超时', min: 0 },
  { key: 'proxy_read_timeout', label: '读超时', min: 0 },
  { key: 'proxy_write_timeout', label: '写超时', min: 0 },
  { key: 'proxy_stream_timeout', label: '流式超时', min: 0 },
  { key: 'proxy_flush_interval', label: '刷新间隔', min: -1 },
  { key: 'proxy_stream_close_delay', label: '流关闭延迟', min: 0 },
] as const satisfies readonly { readonly key: keyof ProxyTimeoutConfig; readonly label: string; readonly min: number }[]

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
