<template>
  <el-dialog
    :model-value="modelValue"
    :title="`触发详情 · WAF 自定义规则`"
    width="min(620px, 94vw)"
    append-to-body
    @close="emit('update:modelValue', false)"
  >
    <div v-loading="loading">
      <div class="crd-head">
        <span class="crd-name">{{ rule?.name ?? `自定义规则 #${dbId}` }}</span>
        <el-tag size="small" :type="actionTagType" effect="dark">{{ actionLabel }}</el-tag>
      </div>
      <div v-if="rule" class="crd-body">
        <div class="crd-kv"><span class="k">描述</span><span>{{ rule.description || '—' }}</span></div>
        <div class="crd-kv">
          <span class="k">匹配条件</span>
          <span>
            <div v-for="(c, i) in conditions" :key="i" class="crd-cond">
              {{ c.target }} {{ c.operator }} <code>{{ c.pattern }}</code>
            </div>
            <span v-if="conditions.length === 0">—</span>
          </span>
        </div>
        <div class="crd-kv"><span class="k">动作</span><span>{{ actionLabel }}<template v-if="rule.action === 'score'">（{{ rule.score }} 分）</template></span></div>
        <div class="crd-kv"><span class="k">状态</span><span>{{ rule.enabled ? '启用' : '禁用' }}</span></div>
      </div>
      <el-empty v-else description="未找到该自定义规则（可能已被删除）" :image-size="60" />
      <div class="crd-tip">自定义规则 id {{ dbId }}（事件携带的触发 id = 规则 id + 10000）。编辑请前往 安全防护 → 自定义规则。</div>
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">关闭</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { request } from '@/utils/api'
import type { APIResponse } from '@/types'

const props = defineProps<{
  modelValue: boolean
  triggeredId: string
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

interface CustomRule {
  id: number
  name: string
  description: string
  action: string
  score?: number
  enabled: boolean
  conditions?: Array<{ target: string; operator: string; pattern: string }>
}

const dbId = computed(() => {
  const n = Number(props.triggeredId)
  return Number.isFinite(n) && n >= 10000 ? n - 10000 : NaN
})

const loading = ref(false)
const rule = ref<CustomRule | null>(null)

const ACTION_LABELS: Record<string, string> = {
  block: '拦截',
  log: '仅记录',
  score: '计分',
}

const actionLabel = computed(() => {
  const a = rule.value?.action ?? ''
  return ACTION_LABELS[a] ?? a
})
const actionTagType = computed(() => (rule.value?.action === 'block' ? 'danger' : rule.value?.action === 'score' ? 'warning' : 'info'))

const load = async (): Promise<void> => {
  if (!Number.isFinite(dbId.value)) return
  loading.value = true
  try {
    const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules')
    rule.value = (res.data || []).find((r) => r.id === dbId.value) ?? null
  } finally {
    loading.value = false
  }
}

// 后端 conditions 为 JSON 字符串（数组文本），此处解析为结构化条件
const conditions = computed<Array<{ target: string; operator: string; pattern: string }>>(() => {
  const rawCond = (rule.value as unknown as { conditions?: string } | null)?.conditions
  if (!rawCond) return []
  try {
    const parsed: unknown = JSON.parse(rawCond)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((c): c is { target: string; operator: string; pattern: string } =>
      !!c && typeof c === 'object' && typeof (c as any).target === 'string')
  } catch {
    return []
  }
})

watch(() => props.modelValue, (v) => {
  if (v) void load()
})
</script>

<style scoped>
.crd-head { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.crd-name { font-weight: 700; font-size: 14px; }
.crd-body { display: grid; gap: 8px; }
.crd-kv { display: flex; gap: 8px; font-size: 13px; }
.crd-kv .k { color: var(--el-text-color-secondary); flex-shrink: 0; width: 64px; }
.crd-cond { font-size: 13px; }
.crd-tip { margin-top: 8px; font-size: 12px; color: var(--el-text-color-secondary); }
</style>
