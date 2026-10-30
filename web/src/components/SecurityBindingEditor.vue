<template>
  <el-dialog
    :model-value="modelValue"
    width="min(640px, 94vw)"
    top="8vh"
    :close-on-click-modal="false"
    :close-on-press-escape="!saving"
    :show-close="!saving"
    @update:model-value="emit('update:modelValue', $event)"
    @open="onOpen"
  >
    <template #header>
      <DialogHeader :icon="Lock" :title="mode === 'rule' ? '安全策略绑定' : '绑定规则'" :subtitle="bindSubtitle" />
    </template>

    <!-- 规则侧：按阶段分区选策略 -->
    <div v-if="mode === 'rule'" class="bind-stage-groups">
      <div v-for="section in stageSections" :key="section.type" class="bind-stage-group dialog-panel">
        <div class="bind-stage-head">
          <DialogSectionHeader :title="section.title" />
          <span class="bind-stage-head-meta">
            <span class="bind-stage-count">已选 {{ section.selection.value.length }} 条</span>
            <!-- 存量多限流绑定（裁定：运行兼容 + 保存即引导清理）：单选控件
                 仅展示首条，徽标使显示与 ruleModeTotal 计数口径一致-->
            <el-tag
              v-if="section.single && section.selection.value.length > 1"
              type="warning"
              size="small"
              effect="plain"
            >
              已绑定 {{ section.selection.value.length }} 条限流策略 · 单选仅显示首条（保存即引导清理）
            </el-tag>
          </span>
        </div>
        <el-select
          :model-value="section.single ? (section.selection.value[0] ?? null) : section.selection.value"
          :multiple="!section.single"
          :clearable="section.single"
          :disabled="saving || section.tcpLocked === true"
          :placeholder="section.single ? '选择策略（单选，换选=替换）' : '选择策略（可多选）'"
          style="width: 100%"
          @update:model-value="section.single ? (section.selection.value = $event == null ? [] : [Number($event)]) : (section.selection.value = $event)"
        >
          <el-option v-for="policy in section.options" :key="policy.id" :value="policy.id" :label="policy.name" :disabled="section.tcpLocked === true">
            <span>{{ policy.name }}</span>
            <el-tag size="small" effect="plain" :type="policy.enabled ? 'success' : 'info'" class="bind-state-tag">{{ policy.enabled ? '启用' : '已禁用' }}</el-tag>
          </el-option>
        </el-select>
        <!-- TCP 规则的阶段 2/3 分区置灰 + 行内原因（L4 无 429/WAF 引擎面，后端同门 400） -->
        <div v-if="section.tcpLocked === true" class="form-tip-line">{{ TCP_BIND_UNSUPPORTED_REASON }}</div>
        <div v-if="section.single" class="form-tip-line">每条规则最多绑定一条限流策略（后端对多限流绑定一律 400，消息原样透出）</div>
        <div v-if="section.options.length === 0" class="form-tip-line">暂无该类策略，到「安全防护 → 安全策略」页创建</div>
      </div>
      <!-- 混合策略（兼容旧版）：可选策略中过滤 mixed；当前已绑定的只读展示，不可增减选择。
           存在绑定 mixed 时保存禁用——后端按提交集全量替换绑定，照常提交会静默剥离 mixed -->
      <div v-if="boundMixedPolicies.length > 0" class="bind-stage-group bind-stage-group--readonly dialog-panel">
        <div class="bind-stage-head">
          <DialogSectionHeader title="混合策略（兼容旧版）" />
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
      <div class="picker-toolbar">
        <el-input v-model="pickerSearch" placeholder="搜索规则名 / 域名 / 规则 ID" clearable :prefix-icon="Search" class="picker-search" :disabled="saving" />
        <!-- 协议筛选（默认 HTTP）：TCP（阶段 0/1）放开后候选混排，默认档保持既有 HTTP 选择视野 -->
        <el-select v-model="pickerProtoFilter" class="picker-proto-filter" aria-label="按协议筛选规则" :disabled="saving">
          <el-option label="全部" value="all" />
          <el-option label="HTTP" value="http" />
          <el-option label="TCP" value="tcp" />
        </el-select>
      </div>
      <div class="picker-header">
        <el-checkbox
          :model-value="pickerAllChecked"
          :indeterminate="pickerIndeterminate"
          :disabled="pickerSelectableRules.length === 0 || saving"
          @change="toggleSelectAll"
        >全选</el-checkbox>
        <span class="picker-header-meta">筛选 {{ pickerFilteredRules.length }} 条</span>
      </div>
      <div class="picker-list">
        <div v-for="rule in pickerPagedRules" :key="rule.caddy_id" class="picker-rule-item">
          <div class="picker-rule-main">
            <el-checkbox
              :model-value="pickerSelected.includes(rule.caddy_id)"
              :disabled="saving || pickerWouldExceed(rule)"
              @change="toggleRule(rule.caddy_id, $event)"
            >
              <!-- 行协议徽标在规则名左（用户裁定）：事件日志方法列同款 el-tag -->
              <el-tag v-if="rule.protocol === 'tcp'" size="small" effect="plain" class="proto-tcp-tag picker-proto-tag">TCP</el-tag>
              <el-tag v-else size="small" type="primary" effect="plain" class="picker-proto-tag">HTTP</el-tag>
              <span class="picker-rule-name">{{ rule.name }}</span>
              <span class="picker-rule-meta">{{ rule.domain || '-' }}:{{ rule.listen_port }}</span>
            </el-checkbox>
            <el-tooltip v-if="pickerWouldExceed(rule)" :content="rowBlockReasons.get(rule.caddy_id) ?? ''" placement="top">
              <el-icon class="picker-cap-icon"><WarningFilled /></el-icon>
            </el-tooltip>
          </div>
          <!-- 不可选原因行内直出（与 SecurityPolicies 选择器同口径）：tooltip 对触屏/读屏不足 -->
          <div class="picker-rule-detail">
            <span v-if="pickerWouldExceed(rule)" class="picker-bind-none picker-rule-block">{{ rowBlockReasons.get(rule.caddy_id) }}</span>
            <template v-else>
            <template v-for="stage in STAGE_ORDER" :key="stage">
              <span v-if="boundPoliciesByType(rule, stage).length > 0" class="picker-bind-group">
                <em class="picker-bind-stage">{{ POLICY_TYPE_SHORT_LABELS[stage] }}</em>
                <el-tag
                  v-for="binding in boundPoliciesByType(rule, stage)"
                  :key="binding.policy_id"
                  size="small"
                  effect="plain"
                  :type="binding.enabled ? 'primary' : 'info'"
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
            </template>
          </div>
        </div>
        <el-empty v-if="pickerFilteredRules.length === 0" description="无可选规则" :image-size="60" />
      </div>
      <el-pagination
        v-model:current-page="pickerPage"
        :page-size="PICKER_PAGE_SIZE"
        :total="pickerFilteredRules.length"
        layout="prev, pager, next"
        small
        :disabled="saving"
        class="picker-pagination"
      />
    </template>

    <template #footer>
      <div class="bind-editor-footer">
        <span v-if="mode === 'rule'" class="bind-total" :class="{ 'is-over': ruleModeTotal > MAX_POLICIES_PER_RULE }">
          已选合计 {{ ruleModeTotal }} 条（每条规则上限 {{ MAX_POLICIES_PER_RULE }} 条）
        </span>
        <span v-else class="bind-total">已选 {{ pickerSelected.length }} 条规则</span>
        <div class="bind-footer-buttons">
          <el-button :disabled="saving" @click="emit('update:modelValue', false)">取消</el-button>
          <el-tooltip
            :disabled="!(mode === 'rule' && boundMixedPolicies.length > 0)"
            content="存在已绑定的混合策略（只读），请先在策略页对其执行「更新迁移」，再调整绑定"
            placement="top"
          >
            <span>
              <el-button
                type="primary"
                :loading="saving"
                :disabled="mode === 'rule' && (ruleModeTotal > MAX_POLICIES_PER_RULE || boundMixedPolicies.length > 0)"
                @click="submit"
              >保存绑定</el-button>
            </span>
          </el-tooltip>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Lock, Search, WarningFilled } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import type { APIResponse } from '@/types'
import {
  POLICY_TYPE_SHORT_LABELS,
  inferPolicyType,
  hasOtherStage2Binding,
  policySupportsTcp,
  TCP_BIND_UNSUPPORTED_REASON,
  resolveStageOverride,
  chunkForBulk,
  SECURITY_BULK_LIMITS,
  MAX_POLICIES_PER_RULE,
} from '@/utils/securityStages'
import type {
  SecurityPolicyType,
  SecurityPolicyTypeInput,
  SecurityStageBinding,
  SecurityStageBlockPage,
} from '@/utils/securityStages'
import { mergeBulkResults } from '@/utils/bulkApplyResult'

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

const bindSubtitle = computed(() =>
  props.mode === 'rule'
    ? `${props.rule?.name ?? ''} · 按阶段分区选择，多条策略按阶段 0→3 顺序、同阶段内按策略 ID 升序执行`
    : `${props.policyName ?? ''} · 选择要绑定该策略的规则（全量重置该策略的绑定集；TCP 规则仅可绑阶段 0/1 策略）`
)

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
// TCP 规则（阶段 0/1 放开）：阶段 2/3 分区整体置灰（tcpLocked）——限流/WAF
// 在 L4 无引擎面，后端同门 400；行内原因 = TCP_BIND_UNSUPPORTED_REASON 单源。
const isTcpRule = computed(() => props.rule?.protocol === 'tcp')
interface StageSection { type: SecurityPolicyType; title: string; options: BindingEditorPolicy[]; selection: typeof bindStage0; single?: boolean; tcpLocked?: boolean }
const stageSections = computed<StageSection[]>(() => [
  { type: 'stage0' as const, title: '阶段 0 · 信任名单（直通上游 / 保留检测记录）', options: policiesByType.value.stage0, selection: bindStage0 },
  { type: 'stage1' as const, title: '阶段 1 · IP 访问控制', options: policiesByType.value.stage1, selection: bindStage1 },
  { type: 'stage2' as const, title: '阶段 2 · 限流（拦截恒 429）', options: policiesByType.value.stage2, selection: bindStage2, single: true as const, tcpLocked: isTcpRule.value },
  { type: 'stage3' as const, title: '阶段 3 · WAF（自定义规则 / CRS）', options: policiesByType.value.stage3, selection: bindStage3, tcpLocked: isTcpRule.value },
])

// 当前规则已绑定的 mixed 策略（只读 tag，不可增减）
const boundMixedPolicies = computed(() => {
  if (props.mode !== 'rule' || !props.rule) return []
  const boundIds = new Set((props.bindings[props.rule.caddy_id] || []).map((b) => b.policy_id))
  return props.policies.filter((p) => boundIds.has(p.id) && inferPolicyType(p) === 'mixed')
})

const ruleModeTotal = computed(() => bindStage0.value.length + bindStage1.value.length + Math.min(1, bindStage2.value.length) + bindStage3.value.length)

// ── 策略模式：规则选择器（搜索 + 协议筛选 + 全选筛选 + 分页 + 行内绑定集合/覆盖徽标） ──
const pickerSearch = ref('')
// 协议筛选（默认 HTTP）：全部/HTTP/TCP 三档——TCP（L4 阶段 0/1）放开后候选混排，
// 默认 HTTP 保持既有选择视野（与 SecurityPolicies 关联规则选择器同裁定同形状）。
const pickerProtoFilter = ref<'all' | 'http' | 'tcp'>('http')
const pickerPage = ref(1)
const pickerSelected = ref<string[]>([])

// 阶段 0/1 放开后 TCP 规则可绑定；含限流/WAF 特征的策略（stage2/3/混合）对 TCP
// 不可绑——选择器混列 HTTP/TCP，TCP 形态在 pickerBlockReason 置灰并给行内原因
const pickerCandidateRules = computed(() => props.rules)
const pickerFilteredRules = computed(() => {
  // 协议筛选先收窄候选（默认 HTTP），搜索再在档内匹配
  const proto = pickerProtoFilter.value
  const candidates = proto === 'all'
    ? pickerCandidateRules.value
    : pickerCandidateRules.value.filter((rule) => rule.protocol === (proto === 'tcp' ? 'tcp' : 'http'))
  const query = pickerSearch.value.trim().toLowerCase()
  if (!query) return candidates
  return candidates.filter((rule) =>
    rule.name.toLowerCase().includes(query)
    || (rule.domain || '').toLowerCase().includes(query)
    || rule.caddy_id.toLowerCase().includes(query))
})
const pickerPagedRules = computed(() => {
  const start = (pickerPage.value - 1) * PICKER_PAGE_SIZE
  return pickerFilteredRules.value.slice(start, start + PICKER_PAGE_SIZE)
})

// （同族，对照 SecurityPolicies 同名选择器先例）：搜索收窄后高页码
// 会落在空页，回到第 1 页
watch(pickerSearch, () => {
  pickerPage.value = 1
})

// 切协议档同样回到第 1 页（收窄后高页码落空页）
watch(pickerProtoFilter, () => {
  pickerPage.value = 1
})

// 当前策略的阶段类型（策略侧批量绑定的后端判据需要它：阶段 2 限流每规则仅一条）
const currentPolicyType = computed<SecurityPolicyType | null>(() => {
  if (props.policyId == null) return null
  return policyTypeById.value.get(props.policyId) ?? null
})

// 规则不可选原因（空串=可选）。判据与后端 bulk 校验同源：批量提交整批拒绝，
// 故凡后端必然拒绝的形态都在选择阶段置灰，避免「全选→保存→整片不生效」。
// ①TCP 规则 × 含限流/WAF 特征策略（stage2/3/混合）→ TCP_BIND_UNSUPPORTED_REASON
// （与 SecurityPolicies.pickerMeta 同谓词同文案）；
// ②阶段 2（限流）策略：该规则已绑定其它限流策略；③每规则策略总数已达上限。
const pickerBlockReason = (rule: BindingEditorRule): string => {
  if (props.mode !== 'policy' || props.policyId == null) return ''
  const current = props.bindings[rule.caddy_id] || []
  if (current.some((b) => b.policy_id === props.policyId)) return ''
  if (pickerSelected.value.includes(rule.caddy_id)) return ''
  if (rule.protocol === 'tcp' && !policySupportsTcp(currentPolicyType.value ?? undefined)) {
    return TCP_BIND_UNSUPPORTED_REASON
  }
  if (currentPolicyType.value === 'stage2'
    && hasOtherStage2Binding(current, props.policyId, (id) => policyTypeById.value.get(id))) {
    return '该规则已绑定其它限流策略（每规则仅一条），需先解绑'
  }
  if (current.length >= MAX_POLICIES_PER_RULE) {
    return `该规则已绑定 ${MAX_POLICIES_PER_RULE} 条策略（上限），需先解绑`
  }
  return ''
}
// 每行不可选原因一次算全表（模板 tooltip 与 pickerSelectableRules 共用）：
// 原实现每行至少重算两遍 pickerBlockReason（disabled 判定 + tooltip），其中
// hasOtherStage2Binding 逐绑定查类型。依赖（props.bindings / pickerSelected /
// policyTypeById / 过滤结果）任一变化时 computed 自动重算，行为不变。
const rowBlockReasons = computed(() => {
  const map = new Map<string, string>()
  for (const rule of pickerFilteredRules.value) map.set(rule.caddy_id, pickerBlockReason(rule))
  return map
})
const pickerWouldExceed = (rule: BindingEditorRule): boolean => (rowBlockReasons.value.get(rule.caddy_id) ?? '') !== ''

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
  if (saving.value) return // 保存中冻结选择：在途改动不进本次载荷，关窗即丢失
  if (checked === true) {
    if (!pickerSelected.value.includes(caddyId)) pickerSelected.value = [...pickerSelected.value, caddyId]
    return
  }
  pickerSelected.value = pickerSelected.value.filter((id) => id !== caddyId)
}

const toggleSelectAll = (checked: string | number | boolean): void => {
  if (saving.value) return
  const selectableIds = pickerSelectableRules.value.map((rule) => rule.caddy_id)
  if (checked === true) {
    pickerSelected.value = [...new Set([...pickerSelected.value, ...selectableIds])]
    return
  }
  const selectableIdSet = new Set(selectableIds)
  pickerSelected.value = pickerSelected.value.filter((id) => !selectableIdSet.has(id))
}

// 策略 id → 类型映射：策略集变化时重建一次（原实现每行每类型调用都全量构建 Map）
const policyTypeById = computed<ReadonlyMap<number, SecurityPolicyType>>(() => {
  const map = new Map<number, SecurityPolicyType>()
  for (const policy of props.policies) map.set(policy.id, inferPolicyType(policy))
  return map
})

// 规则行内当前绑定集合（按策略类型分区）
const boundPoliciesByType = (rule: BindingEditorRule, type: SecurityPolicyType): SecurityStageBinding[] =>
  (props.bindings[rule.caddy_id] || []).filter((binding) => policyTypeById.value.get(binding.policy_id) === type)

// 阶段页覆盖徽标（页已删/内容空 = broken）。失效后的真实回落目标按阶段不同：
// 阶段 1 由引擎兜底错误路由取「绑定链首个启用且内容非空」策略的页面（可能不是
// 本策略），阶段 3 才逐策略回落各自页面——同一句话覆盖两种语义会误导排障。
const overrideBadge = (rule: BindingEditorRule, stage: 1 | 3): { text: string; title: string; broken: boolean } | null => {
  const override = resolveStageOverride(
    stage === 1 ? rule.block_page_stage1_id : rule.block_page_stage3_id,
    stage === 1 ? rule.block_page_stage1_status : rule.block_page_stage3_status,
    props.blockPages,
  )
  if (!override) return null
  if (override.broken) {
    return {
      text: '已失效',
      title: stage === 1
        ? `配置的拦截页（#${override.pageId}）已删除或内容为空，回落绑定链首个有效页（无则默认 403）`
        : `配置的拦截页（#${override.pageId}）已删除或内容为空，回落跟随策略`,
      broken: true,
    }
  }
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
    // 绑定引用了已删除策略时静默落出——保存即清理死绑定）。
    // TCP 规则的阶段 2/3 分区已置灰：旧数据残留的此类绑定不回填可写桶
    //（不可选状态下的预选值会被「保存」全量替换语义静默清掉——与后端同门清理一致）
    const tcpLocked = props.rule?.protocol === 'tcp'
    const boundIdSet = new Set((props.rule ? props.bindings[props.rule.caddy_id] : null)?.map((b) => b.policy_id) ?? [])
    const buckets: Record<'stage0' | 'stage1' | 'stage2' | 'stage3', typeof bindStage0> = { stage0: bindStage0, stage1: bindStage1, stage2: bindStage2, stage3: bindStage3 }
    for (const policy of props.policies) {
      const type = inferPolicyType(policy)
      if (type === 'mixed') continue
      if (tcpLocked && (type === 'stage2' || type === 'stage3')) continue
      if (boundIdSet.has(policy.id)) buckets[type].value.push(policy.id)
    }
    return
  }
  // 策略模式：预选 = 当前绑定该策略的规则
  const pid = props.policyId
  pickerSearch.value = ''
  pickerProtoFilter.value = 'http'
  pickerPage.value = 1
  pickerSelected.value = pid == null
    ? []
    : pickerCandidateRules.value
        .filter((rule) => (props.bindings[rule.caddy_id] || []).some((b) => b.policy_id === pid))
        .map((rule) => rule.caddy_id)
}

// 绑定写路径的并发口径（显式声明，避免被当作漏项）：
// - 规则侧 PUT /security/rules/:caddy_id/policies 与策略侧 bulk 端点都是
//   「整集替换 + 最后写入生效」，后端不接受乐观并发前置条件（规则编辑的
//   expected_updated_at 是另一条契约，绑定端点未实现）——多标签页/多管理员
//   同时改同一规则绑定时，后写覆盖前写且无冲突提示。
// - 单管理员主节点语境下可接受；若未来需要并发护栏，必须先在绑定端点引入
//   版本前置条件（409），前端再随请求携带打开时的版本，不能只在前端比对。
const submit = async (): Promise<void> => {
  if (props.mode === 'rule') {
    const rule = props.rule
    if (!rule) return
    if (ruleModeTotal.value > MAX_POLICIES_PER_RULE) {
      ElMessage.warning(`每条规则最多绑定 ${MAX_POLICIES_PER_RULE} 条策略，当前已选 ${ruleModeTotal.value} 条`)
      return
    }
    saving.value = true
    try {
      // mixed 不携带提交：后端按提交集全量替换绑定（携带 mixed 会被拒绝，不含
      // mixed 的提交会静默剥离）；存在已绑 mixed 时保存按钮已禁用，不会走到这里。
      // 响应经 showSaveResult 统一呈现：退化 200（DB 已提交
      // 但 Caddy 应用失败）带 message 后缀时必须常驻警告，原实现丢弃返回值。
      const res = await request.put<APIResponse>(`/security/rules/${encodeURIComponent(rule.caddy_id)}/policies`, {
        policy_ids: [...bindStage0.value, ...bindStage1.value, ...bindStage2.value.slice(0, 1), ...bindStage3.value],
      })
      showSaveResult(res, '安全策略绑定已保存')
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

  // 策略模式：全量重置该策略的绑定集——策略侧批量端点一次提交（
  // 原逐规则 PUT 规则侧全量端点，每条独立全链渲染，N 规则=N×~500ms；bulk
  // 单事务只增删本策略绑定行、不触碰兄弟绑定，语义与原循环一致，单渲染）。
  const pid = props.policyId
  if (pid == null) return
  const selected = new Set(pickerSelected.value)
  const toBind: string[] = []
  const toUnbind: string[] = []
  for (const rule of pickerCandidateRules.value) {
    const current = (props.bindings[rule.caddy_id] || []).map((b) => b.policy_id)
    const has = current.includes(pid)
    const want = selected.has(rule.caddy_id)
    if (has === want) continue
    if (want) toBind.push(rule.caddy_id)
    else toUnbind.push(rule.caddy_id)
  }
  if (toBind.length === 0 && toUnbind.length === 0) {
    ElMessage.info('绑定关系无变化')
    emit('update:modelValue', false)
    return
  }
  saving.value = true
  try {
    // bulk 端点单次 bind+unbind 合计 ≤100——按方向分片提交（每片 ≤100
    // 天然满足合计上限）；端点幂等，部分失败后重试安全。
    // 逐片响应必须汇总后再呈现——原实现只保留末片，早先分片的退化
    // 200（DB 已提交但 Caddy 应用失败）被覆盖，常驻警告丢失。
    const responses: Array<APIResponse<unknown> | undefined> = []
    for (const ids of chunkForBulk(toBind, SECURITY_BULK_LIMITS.policyBindings)) {
      responses.push(await request.post<APIResponse>(`/security/policies/${pid}/bindings/bulk`, { bind: ids, unbind: [] }))
    }
    for (const ids of chunkForBulk(toUnbind, SECURITY_BULK_LIMITS.policyBindings)) {
      responses.push(await request.post<APIResponse>(`/security/policies/${pid}/bindings/bulk`, { bind: [], unbind: ids }))
    }
    showSaveResult(mergeBulkResults(responses), `已更新 ${toBind.length + toUnbind.length} 条规则的绑定`)
    emit('update:modelValue', false)
    emit('saved')
  } catch (error: unknown) {
    // 与规则侧对齐：原无 catch → 请求失败产生 unhandled
    // rejection（全局拦截器已 toast，这里仅记录并保持弹框可重试）
    console.error('save policy bindings failed', error)
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.bind-stage-groups { display: flex; flex-direction: column; }
.bind-stage-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
.bind-stage-count { font-size: 12px; color: #6b7280; }
.bind-stage-head-meta { display: inline-flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.bind-state-tag { margin-left: 8px; }

.picker-search { margin-bottom: 0; flex: 1; }
.picker-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.picker-proto-filter { width: 104px; flex-shrink: 0; }
.picker-header { display: flex; align-items: center; gap: 12px; padding: 6px 4px; border-bottom: 1px solid #f0f1f3; }
.picker-header-meta { font-size: 12px; color: #9ca3af; }
.picker-list { max-height: min(380px, 50vh); overflow-y: auto; padding: 4px 0; }
.picker-rule-item { padding: 6px 4px; border-bottom: 1px dashed #f3f4f6; }
.picker-rule-item:last-child { border-bottom: none; }
.picker-rule-main { display: flex; align-items: center; gap: 6px; }
.picker-rule-name { font-weight: 500; color: #1f2937; }
.picker-rule-meta { margin-left: 8px; font-size: 12px; color: #9ca3af; }
.picker-cap-icon { color: var(--el-color-warning); }
.picker-proto-tag { margin-right: 8px; vertical-align: middle; }
.picker-rule-block { color: #e6a23c; }
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

.bind-stage-group--readonly { border-style: dashed; }
.bind-mixed-tags { display: flex; flex-wrap: wrap; gap: 6px; }
</style>
