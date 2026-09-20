<template>
  <el-dialog
    :model-value="modelValue"
    width="min(640px, 94vw)"
    top="8vh"
    :close-on-click-modal="false"
    @update:model-value="emit('update:modelValue', $event)"
    @open="onOpen"
  >
    <template #header>
      <div class="dialog-header">
        <div class="dialog-header__icon"><el-icon :size="18"><Lock /></el-icon></div>
        <div class="dialog-header__text">
          <div class="dialog-header__title">{{ mode === 'rule' ? '安全策略绑定' : '绑定规则' }}</div>
          <div class="dialog-header__subtitle">
            {{ mode === 'rule'
              ? `${rule?.name ?? ''} · 按阶段分区选择，多条策略按策略 ID 升序执行`
              : `${policyName ?? ''} · 选择要绑定该策略的 HTTP 规则（全量重置该策略的绑定集）` }}
          </div>
        </div>
      </div>
    </template>

    <!-- 规则侧：按阶段分区选策略 -->
    <div v-if="mode === 'rule'" class="bind-stage-groups">
      <div v-for="section in stageSections" :key="section.type" class="bind-stage-group">
        <div class="bind-stage-head">
          <span class="bind-stage-title">{{ section.title }}</span>
          <span class="bind-stage-count">已选 {{ section.selection.value.length }} 条</span>
        </div>
        <el-select
          :model-value="section.single ? (section.selection.value[0] ?? null) : section.selection.value"
          :multiple="!section.single"
          :clearable="section.single"
          :placeholder="section.single ? '选择策略（单选，换选=替换）' : '选择策略（可多选）'"
          style="width: 100%"
          @update:model-value="section.single ? (section.selection.value = $event == null ? [] : [Number($event)]) : (section.selection.value = $event)"
        >
          <el-option v-for="policy in section.options" :key="policy.id" :value="policy.id" :label="policy.name">
            <span>{{ policy.name }}</span>
            <el-tag size="small" effect="plain" :type="policy.enabled ? 'success' : 'info'" class="bind-state-tag">{{ policy.enabled ? '启用' : '已禁用' }}</el-tag>
          </el-option>
        </el-select>
        <div v-if="section.single" class="form-tip-line">每条规则最多绑定一条限流策略（后端对多限流绑定一律 400，消息原样透出）</div>
        <div v-if="section.options.length === 0" class="form-tip-line">暂无该类策略，到「安全防护 → 安全策略」页创建</div>
      </div>
      <!-- 混合策略（兼容旧版）：可选策略中过滤 mixed；当前已绑定的只读展示，不可增减选择，
           保存时不携带（后端拒绝新增 mixed 绑定，错误消息原样透出） -->
      <div v-if="boundMixedPolicies.length > 0" class="bind-stage-group bind-stage-group--readonly">
        <div class="bind-stage-head">
          <span class="bind-stage-title">混合策略（兼容旧版）</span>
          <span class="bind-stage-count">{{ boundMixedPolicies.length }} 条</span>
        </div>
        <div class="bind-mixed-tags">
          <el-tag v-for="policy in boundMixedPolicies" :key="policy.id" type="warning" size="small" effect="plain">{{ policy.name }}</el-tag>
        </div>
        <div class="form-tip-line">混合策略（兼容旧版）· 仅可更新迁移——到「安全防护 → 安全策略」页对该策略执行「更新迁移」拆分为单职策略</div>
      </div>
    </div>

    <!-- 策略侧：规则选择器（复用 rule picker 交互；每行显示当前绑定集合与阶段页覆盖徽标） -->
    <template v-else>
      <el-input v-model="pickerSearch" placeholder="搜索规则名 / 域名 / 规则 ID" clearable :prefix-icon="Search" class="picker-search" />
      <div class="picker-header">
        <el-checkbox
          :model-value="pickerAllChecked"
          :indeterminate="pickerIndeterminate"
          :disabled="pickerSelectableRules.length === 0"
          @change="toggleSelectAll"
        >全选</el-checkbox>
        <span class="picker-header-meta">筛选 {{ pickerFilteredRules.length }} 条</span>
      </div>
      <div class="picker-list">
        <div v-for="rule in pickerPagedRules" :key="rule.caddy_id" class="picker-rule-item">
          <div class="picker-rule-main">
            <el-checkbox
              :model-value="pickerSelected.includes(rule.caddy_id)"
              :disabled="pickerWouldExceed(rule)"
              @change="toggleRule(rule.caddy_id, $event)"
            >
              <span class="picker-rule-name">{{ rule.name }}</span>
              <span class="picker-rule-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
            </el-checkbox>
            <el-tooltip v-if="pickerWouldExceed(rule)" content="该规则已绑定 5 条策略（上限），需先解绑" placement="top">
              <el-icon class="picker-cap-icon"><WarningFilled /></el-icon>
            </el-tooltip>
          </div>
          <div class="picker-rule-detail">
            <template v-for="stage in STAGE_ORDER" :key="stage">
              <span v-if="boundPoliciesByType(rule, stage).length > 0" class="picker-bind-group">
                <em class="picker-bind-stage">{{ POLICY_TYPE_SHORT_LABELS[stage] }}</em>
                <el-tag
                  v-for="binding in boundPoliciesByType(rule, stage)"
                  :key="binding.policy_id"
                  size="small"
                  effect="plain"
                  :type="binding.enabled ? 'primary' : 'info'"
                  class="picker-bind-tag"
                >{{ binding.name }}</el-tag>
              </span>
            </template>
            <span v-if="(bindings[rule.caddy_id] || []).length === 0" class="picker-bind-none">未绑定策略</span>
            <el-tooltip v-if="overrideBadge(rule, 1)" :content="overrideBadge(rule, 1)!.title" placement="top">
              <el-tag size="small" :type="overrideBadge(rule, 1)!.broken ? 'danger' : 'warning'" effect="plain" class="picker-override-tag">阶段 1 页：{{ overrideBadge(rule, 1)!.text }}</el-tag>
            </el-tooltip>
            <el-tooltip v-if="overrideBadge(rule, 3)" :content="overrideBadge(rule, 3)!.title" placement="top">
              <el-tag size="small" :type="overrideBadge(rule, 3)!.broken ? 'danger' : 'warning'" effect="plain" class="picker-override-tag">阶段 3 页：{{ overrideBadge(rule, 3)!.text }}</el-tag>
            </el-tooltip>
          </div>
        </div>
        <el-empty v-if="pickerFilteredRules.length === 0" description="无可选 HTTP 规则" :image-size="60" />
      </div>
      <el-pagination
        v-model:current-page="pickerPage"
        :page-size="PICKER_PAGE_SIZE"
        :total="pickerFilteredRules.length"
        layout="prev, pager, next"
        small
        class="picker-pagination"
      />
    </template>

    <template #footer>
      <div class="bind-editor-footer">
        <span v-if="mode === 'rule'" class="bind-total" :class="{ 'is-over': ruleModeTotal > MAX_POLICY_BINDINGS }">
          已选合计 {{ ruleModeTotal }} 条（每条规则上限 {{ MAX_POLICY_BINDINGS }} 条）
        </span>
        <span v-else class="bind-total">已选 {{ pickerSelected.length }} 条规则</span>
        <div class="bind-footer-buttons">
          <el-button @click="emit('update:modelValue', false)">取消</el-button>
          <el-button
            type="primary"
            :loading="saving"
            :disabled="mode === 'rule' && ruleModeTotal > MAX_POLICY_BINDINGS"
            @click="submit"
          >保存绑定</el-button>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Lock, Search, WarningFilled } from '@element-plus/icons-vue'
import { request, mfaAwareSuccess } from '@/utils/api'
import type { APIResponse } from '@/types'
import {
  POLICY_TYPE_SHORT_LABELS,
  inferPolicyType,
  resolveStageOverride,
} from '@/utils/securityStages'
import type {
  SecurityPolicyType,
  SecurityPolicyTypeInput,
  SecurityStageBinding,
  SecurityStageBlockPage,
} from '@/utils/securityStages'

// 与后端 SetRuleSecurityPolicies 上限同口径
const MAX_POLICY_BINDINGS = 5
const PICKER_PAGE_SIZE = 20
// 绑定摘要排序严格按处理流程（任务 7）：阶段 0（最高优先）→ 1 → 2 → 3 → mixed
const STAGE_ORDER: readonly SecurityPolicyType[] = ['stage0', 'stage1', 'stage2', 'stage3', 'mixed']

interface BindingEditorPolicy extends SecurityPolicyTypeInput {
  id: number
  name: string
  enabled: boolean
}

interface BindingEditorRule {
  caddy_id: string
  name: string
  domain: string
  listen_port: number
  protocol: string
  block_page_stage1_id?: number
  block_page_stage1_status?: number
  block_page_stage3_id?: number
  block_page_stage3_status?: number
}

const props = defineProps<{
  modelValue: boolean
  mode: 'rule' | 'policy'
  rule?: BindingEditorRule | null
  policyId?: number | null
  policyName?: string
  policies: readonly BindingEditorPolicy[]
  bindings: Record<string, SecurityStageBinding[]>
  rules: readonly BindingEditorRule[]
  blockPages: readonly SecurityStageBlockPage[]
}>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  saved: []
}>()

const saving = ref(false)

// ── 规则模式：按阶段分区选策略（阶段 0 置最前；打开时按现有绑定回填） ──
const bindStage0 = ref<number[]>([])
const bindStage1 = ref<number[]>([])
const bindStage2 = ref<number[]>([])
const bindStage3 = ref<number[]>([])

const policiesByType = computed<Record<SecurityPolicyType, BindingEditorPolicy[]>>(() => {
  const grouped: Record<SecurityPolicyType, BindingEditorPolicy[]> = { stage0: [], stage1: [], stage2: [], stage3: [], mixed: [] }
  for (const policy of props.policies) grouped[inferPolicyType(policy)].push(policy)
  return grouped
})

// 可选策略过滤 mixed：混合组不出现在可选区（已绑定的 mixed 由只读区展示）
const stageSections = computed(() => [
  { type: 'stage0' as const, title: '阶段 0 · 信任名单（直通上游 / 保留检测记录）', options: policiesByType.value.stage0, selection: bindStage0 },
  { type: 'stage1' as const, title: '阶段 1 · IP 访问控制', options: policiesByType.value.stage1, selection: bindStage1 },
  { type: 'stage2' as const, title: '阶段 2 · 限流（拦截恒 429）', options: policiesByType.value.stage2, selection: bindStage2, single: true as const },
  { type: 'stage3' as const, title: '阶段 3 · WAF（自定义规则 / CRS）', options: policiesByType.value.stage3, selection: bindStage3 },
])

// 当前规则已绑定的 mixed 策略（只读 tag，不可增减）
const boundMixedPolicies = computed(() => {
  if (props.mode !== 'rule' || !props.rule) return []
  const boundIds = new Set((props.bindings[props.rule.caddy_id] || []).map((b) => b.policy_id))
  return props.policies.filter((p) => boundIds.has(p.id) && inferPolicyType(p) === 'mixed')
})

const ruleModeTotal = computed(() => bindStage0.value.length + bindStage1.value.length + bindStage2.value.length + bindStage3.value.length)

// ── 策略模式：规则选择器（搜索 + 全选筛选 + 分页 + 行内绑定集合/覆盖徽标） ──
const pickerSearch = ref('')
const pickerPage = ref(1)
const pickerSelected = ref<string[]>([])

// 安全策略仅对 HTTP 规则生效（TCP 走 L4 链不经过 WAF/ACL/限流）
const pickerHttpRules = computed(() => props.rules.filter((rule) => rule.protocol === 'http'))
const pickerFilteredRules = computed(() => {
  const query = pickerSearch.value.trim().toLowerCase()
  if (!query) return pickerHttpRules.value
  return pickerHttpRules.value.filter((rule) =>
    rule.name.toLowerCase().includes(query)
    || (rule.domain || '').toLowerCase().includes(query)
    || rule.caddy_id.toLowerCase().includes(query))
})
const pickerPagedRules = computed(() => {
  const start = (pickerPage.value - 1) * PICKER_PAGE_SIZE
  return pickerFilteredRules.value.slice(start, start + PICKER_PAGE_SIZE)
})

// 已达绑定上限且未绑定本策略的规则不可再选
const pickerWouldExceed = (rule: BindingEditorRule): boolean => {
  if (props.mode !== 'policy' || props.policyId == null) return false
  const current = props.bindings[rule.caddy_id] || []
  if (current.some((b) => b.policy_id === props.policyId)) return false
  if (pickerSelected.value.includes(rule.caddy_id)) return false
  return current.length >= MAX_POLICY_BINDINGS
}

const pickerSelectableRules = computed(() => pickerFilteredRules.value.filter((rule) => !pickerWouldExceed(rule)))
const pickerAllChecked = computed(() =>
  pickerSelectableRules.value.length > 0
  && pickerSelectableRules.value.every((rule) => pickerSelected.value.includes(rule.caddy_id)))
const pickerIndeterminate = computed(() => {
  const selected = new Set(pickerSelected.value)
  const count = pickerSelectableRules.value.reduce((sum, rule) => sum + (selected.has(rule.caddy_id) ? 1 : 0), 0)
  return count > 0 && !pickerAllChecked.value
})

const toggleRule = (caddyId: string, checked: string | number | boolean): void => {
  if (checked === true) {
    if (!pickerSelected.value.includes(caddyId)) pickerSelected.value = [...pickerSelected.value, caddyId]
    return
  }
  pickerSelected.value = pickerSelected.value.filter((id) => id !== caddyId)
}

const toggleSelectAll = (checked: string | number | boolean): void => {
  const selectableIds = pickerSelectableRules.value.map((rule) => rule.caddy_id)
  if (checked === true) {
    pickerSelected.value = [...new Set([...pickerSelected.value, ...selectableIds])]
    return
  }
  const selectableIdSet = new Set(selectableIds)
  pickerSelected.value = pickerSelected.value.filter((id) => !selectableIdSet.has(id))
}

// 规则行内当前绑定集合（按策略类型分区）
const boundPoliciesByType = (rule: BindingEditorRule, type: SecurityPolicyType): SecurityStageBinding[] => {
  const policyTypeById = new Map<number, SecurityPolicyType>()
  for (const policy of props.policies) policyTypeById.set(policy.id, inferPolicyType(policy))
  return (props.bindings[rule.caddy_id] || []).filter((binding) => policyTypeById.get(binding.policy_id) === type)
}

// 阶段页覆盖徽标（页已删/内容空 = broken）
const overrideBadge = (rule: BindingEditorRule, stage: 1 | 3): { text: string; title: string; broken: boolean } | null => {
  const override = resolveStageOverride(
    stage === 1 ? rule.block_page_stage1_id : rule.block_page_stage3_id,
    stage === 1 ? rule.block_page_stage1_status : rule.block_page_stage3_status,
    props.blockPages,
  )
  if (!override) return null
  if (override.broken) return { text: '已失效', title: `配置的拦截页（#${override.pageId}）已删除或内容为空，回落跟随策略`, broken: true }
  return { text: `${override.pageName}（${override.status}）`, title: `阶段 ${stage} 拦截页覆盖：${override.pageName}（状态码 ${override.status}）`, broken: false }
}

const onOpen = (): void => {
  saving.value = false
  if (props.mode === 'rule') {
    bindStage0.value = []
    bindStage1.value = []
    bindStage2.value = []
    bindStage3.value = []
    // 当前绑定预选：按策略类型分桶回填；mixed 不进可选桶（只读区另行展示，
    // 绑定引用了已删除策略时静默落出——保存即清理死绑定）
    const boundIdSet = new Set((props.rule ? props.bindings[props.rule.caddy_id] : null)?.map((b) => b.policy_id) ?? [])
    const buckets: Record<'stage0' | 'stage1' | 'stage2' | 'stage3', typeof bindStage0> = { stage0: bindStage0, stage1: bindStage1, stage2: bindStage2, stage3: bindStage3 }
    for (const policy of props.policies) {
      const type = inferPolicyType(policy)
      if (type === 'mixed') continue
      if (boundIdSet.has(policy.id)) buckets[type].value.push(policy.id)
    }
    return
  }
  // 策略模式：预选 = 当前绑定该策略的规则
  const pid = props.policyId
  pickerSearch.value = ''
  pickerPage.value = 1
  pickerSelected.value = pid == null
    ? []
    : pickerHttpRules.value
        .filter((rule) => (props.bindings[rule.caddy_id] || []).some((b) => b.policy_id === pid))
        .map((rule) => rule.caddy_id)
}

const submit = async (): Promise<void> => {
  if (props.mode === 'rule') {
    const rule = props.rule
    if (!rule) return
    if (ruleModeTotal.value > MAX_POLICY_BINDINGS) {
      ElMessage.warning(`每条规则最多绑定 ${MAX_POLICY_BINDINGS} 条策略，当前已选 ${ruleModeTotal.value} 条`)
      return
    }
    saving.value = true
    try {
      // mixed 不携带提交（后端拒绝新增 mixed 绑定，错误消息原样透出）
      await request.put<APIResponse>(`/security/rules/${encodeURIComponent(rule.caddy_id)}/policies`, {
        policy_ids: [...bindStage0.value, ...bindStage1.value, ...bindStage2.value, ...bindStage3.value],
      })
      mfaAwareSuccess('安全策略绑定已保存')
      emit('update:modelValue', false)
      emit('saved')
    } catch (error: unknown) {
      // 错误提示已由全局拦截器展示
      console.error('save rule bindings failed', error)
    } finally {
      saving.value = false
    }
    return
  }

  // 策略模式：全量重置该策略的绑定集——逐规则 PUT（新选中补绑、被取消解绑），
  // 其他策略在这些规则上的绑定保持不动
  const pid = props.policyId
  if (pid == null) return
  const selected = new Set(pickerSelected.value)
  const ops: Array<Promise<unknown>> = []
  for (const rule of pickerHttpRules.value) {
    const current = (props.bindings[rule.caddy_id] || []).map((b) => b.policy_id)
    const has = current.includes(pid)
    const want = selected.has(rule.caddy_id)
    if (has === want) continue
    const next = want ? [...current, pid] : current.filter((id) => id !== pid)
    ops.push(request.put<APIResponse>(`/security/rules/${encodeURIComponent(rule.caddy_id)}/policies`, { policy_ids: next }))
  }
  if (ops.length === 0) {
    ElMessage.info('绑定关系无变化')
    emit('update:modelValue', false)
    return
  }
  saving.value = true
  try {
    const results = await Promise.allSettled(ops)
    const failed = results.filter((r) => r.status === 'rejected').length
    const succeeded = results.length - failed
    if (succeeded > 0) mfaAwareSuccess(`已更新 ${succeeded} 条规则的绑定`)
    if (failed > 0) ElMessage.error(`${failed} 条规则绑定更新失败`)
    if (failed === 0) emit('update:modelValue', false)
    emit('saved')
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.dialog-header { display: flex; align-items: flex-start; gap: 12px; }
.dialog-header__icon { flex: 0 0 auto; width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; background: var(--el-color-primary-light-9); color: var(--el-color-primary); }
.dialog-header__title { font-size: 16px; font-weight: 600; color: #1f2937; line-height: 1.4; }
.dialog-header__subtitle { font-size: 12px; color: #6b7280; margin-top: 2px; }

.bind-stage-groups { display: flex; flex-direction: column; gap: 16px; }
.bind-stage-group { border: 1px solid #ebeef5; border-radius: 8px; padding: 10px 12px; }
.bind-stage-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.bind-stage-title { font-size: 13px; font-weight: 600; color: #1f2937; }
.bind-stage-count { font-size: 12px; color: #6b7280; }
.bind-state-tag { margin-left: 8px; }
.form-tip-line { font-size: 12px; color: #9ca3af; margin-top: 6px; }

.picker-search { margin-bottom: 10px; }
.picker-header { display: flex; align-items: center; gap: 12px; padding: 6px 4px; border-bottom: 1px solid #f0f1f3; }
.picker-header-meta { font-size: 12px; color: #9ca3af; }
.picker-list { max-height: min(380px, 50vh); overflow-y: auto; padding: 4px 0; }
.picker-rule-item { padding: 6px 4px; border-bottom: 1px dashed #f3f4f6; }
.picker-rule-item:last-child { border-bottom: none; }
.picker-rule-main { display: flex; align-items: center; gap: 6px; }
.picker-rule-name { font-weight: 500; color: #1f2937; }
.picker-rule-meta { margin-left: 8px; font-size: 12px; color: #9ca3af; }
.picker-cap-icon { color: var(--el-color-warning); }
.picker-rule-detail { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; margin: 2px 0 2px 24px; }
.picker-bind-group { display: inline-flex; align-items: center; gap: 4px; }
.picker-bind-stage { font-style: normal; font-size: 12px; color: #6b7280; }
.picker-bind-none { font-size: 12px; color: #c0c4cc; }
.picker-override-tag { margin-left: 2px; }
.picker-pagination { display: flex; justify-content: flex-end; margin-top: 8px; }

.bind-editor-footer { display: flex; align-items: center; justify-content: space-between; }
.bind-total { font-size: 13px; color: #6b7280; }
.bind-total.is-over { color: var(--el-color-danger); font-weight: 600; }
.bind-footer-buttons { display: flex; gap: 12px; }

.bind-stage-group--readonly { background: #fafafa; border-style: dashed; }
.bind-mixed-tags { display: flex; flex-wrap: wrap; gap: 6px; }
</style>
