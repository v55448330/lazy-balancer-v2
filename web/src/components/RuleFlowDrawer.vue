<template>
  <el-drawer
    :model-value="modelValue"
    direction="rtl"
    size="min(760px, 96vw)"
    destroy-on-close
    class="rule-flow-drawer"
    @update:model-value="emit('update:modelValue', $event)"
    @open="onDrawerOpen"
  >
    <template #header>
      <div class="flow-header">
        <span class="flow-header-title">处理流程</span>
        <span v-if="target" class="flow-header-name" :title="target.name">{{ target.name }}</span>
      </div>
    </template>

    <div v-if="target" class="flow-body">
      <el-alert
        v-if="isTcp"
        type="info"
        :closable="false"
        show-icon
        title="TCP 规则无 HTTP 安全链"
        description="TCP（L4）流量不经预检、限流与 WAF 阶段，接入后直接转发至上游。"
        class="flow-tcp-alert"
      />

      <svg class="flow-svg" :viewBox="`0 0 720 ${SVG_H}`" role="list" :aria-label="`规则 ${target.name} 的处理流程`">
        <template v-for="(node, index) in flowNodes" :key="node.key">
          <template v-if="index > 0">
            <line
              :x1="nodeLineX1(index)" :y1="LINE_Y" :x2="nodeLineX2(index)" :y2="LINE_Y"
              pathLength="100"
              class="flow-line-base"
              :class="{ 'is-inactive': node.prevInactive }"
              :style="{ animationDelay: `${index * 110 + 80}ms` }"
            />
            <line
              v-if="!node.prevInactive"
              :x1="nodeLineX1(index)" :y1="LINE_Y" :x2="nodeLineX2(index)" :y2="LINE_Y"
              pathLength="100"
              class="flow-line-particles"
              :style="{ animationDelay: `0s, ${index * 110 + 560}ms` }"
            />
          </template>
          <g
            class="flow-node"
            :class="{ 'is-selected': activeNode === node.key, 'is-off': node.disabled }"
            :style="{ animationDelay: `${index * 110}ms` }"
            role="listitem"
            tabindex="0"
            :aria-label="node.title"
            @click="toggleNode(node.key)"
            @keydown.enter.prevent="toggleNode(node.key)"
            @keydown.space.prevent="toggleNode(node.key)"
          >
            <rect :x="nodeX(index)" :y="NODE_Y" :width="NODE_W" :height="NODE_H" rx="10" class="flow-node-rect" />
            <text :x="nodeX(index) + NODE_W / 2" :y="NODE_Y + 22" text-anchor="middle" class="flow-node-title">{{ node.title }}</text>
            <text
              v-for="(line, li) in node.lines"
              :key="li"
              :x="nodeX(index) + NODE_W / 2"
              :y="NODE_Y + 40 + li * 15"
              text-anchor="middle"
              class="flow-node-sub"
            >{{ line }}</text>
            <g v-if="node.chip" class="flow-node-chip-group">
              <rect
                :x="nodeX(index) + NODE_W / 2 - chipWidth(node.chip) / 2"
                :y="NODE_Y + NODE_H - 32"
                :width="chipWidth(node.chip)"
                height="18"
                rx="9"
                class="flow-node-chip"
              />
              <text :x="nodeX(index) + NODE_W / 2" :y="NODE_Y + NODE_H - 19" text-anchor="middle" class="flow-node-chip-text">{{ node.chip }}</text>
            </g>
            <text v-if="node.chipCaption" :x="nodeX(index) + NODE_W / 2" :y="NODE_Y + NODE_H - 4" text-anchor="middle" class="flow-node-chip-caption">{{ node.chipCaption }}</text>
          </g>
        </template>
      </svg>

      <!-- 手风琴下钻（点击节点展开，再次点击收起；数据来自共享投影 util） -->
      <el-collapse-transition>
        <div v-if="activeNode === 'access'" class="flow-panel">
          <div class="flow-panel-head"><span class="flow-panel-title">接入</span></div>
          <div class="flow-row"><span class="flow-row-label">协议</span><span class="flow-row-detail">{{ protocolLabel }}</span></div>
          <div class="flow-row"><span class="flow-row-label">监听端口</span><span class="flow-row-detail">{{ target.listenPort }}</span></div>
          <div v-if="!isTcp" class="flow-row"><span class="flow-row-label">TLS</span><span class="flow-row-detail">{{ target.enableTls ? '启用（TLS 终止后进入安全流水线）' : '关闭' }}</span></div>
        </div>
      </el-collapse-transition>

      <el-collapse-transition v-for="stage in stagePanels" :key="stage.stage">
        <div v-if="activeNode === `stage${stage.stage}`" class="flow-panel">
          <div class="flow-panel-head">
            <span class="flow-panel-title">{{ stage.title }}</span>
            <el-tag v-if="stage.override && !stage.override.broken" type="warning" size="small" effect="plain">阶段页：{{ stage.override.pageName }}（{{ stage.override.status }}）</el-tag>
            <el-tag v-else-if="stage.override?.broken" type="danger" size="small" effect="plain">阶段页已失效（回落跟随策略）</el-tag>
            <el-tag v-else-if="stage.stage !== 2" type="info" size="small" effect="plain">拦截页跟随策略</el-tag>
            <el-tag v-if="!stage.enabled" type="info" size="small" effect="plain">未启用</el-tag>
          </div>
          <div v-if="stageStatsText(stage.stage)" class="flow-panel-stats">{{ stageStatsText(stage.stage) }}</div>
          <template v-if="stage.enabled">
            <div
              v-for="group in stage.groups"
              :key="group.key"
              class="flow-policy-block"
              :class="{ 'is-disabled': !group.enabled }"
            >
              <div class="flow-policy-head">
                <span class="flow-policy-order">#{{ group.order }}</span>
                <span class="flow-policy-name" :title="group.name">{{ group.name }}</span>
                <el-tag v-if="policyTypeOf(group.key) === 'mixed'" type="warning" size="small" effect="plain">混合</el-tag>
                <el-tag v-if="!group.enabled" type="info" size="small" effect="plain">已禁用</el-tag>
                <el-button
                  v-if="groupHasDetails(group)"
                  link
                  type="primary"
                  size="small"
                  class="flow-detail-toggle"
                  @click="togglePolicyDetail(stage.stage, group.key)"
                >{{ expandedPolicyKey === `${stage.stage}:${group.key}` ? '收起明细' : '明细' }}</el-button>
              </div>
              <div v-for="row in group.rows" :key="row.label" class="flow-row">
                <span class="flow-row-label">{{ row.label }}</span>
                <span class="flow-row-detail" :title="row.detail">{{ row.detail }}</span>
              </div>
              <!-- 二级明细区（懒加载附着；max-height 滚动） -->
              <el-collapse-transition>
                <div v-if="expandedPolicyKey === `${stage.stage}:${group.key}`" class="flow-policy-details">
                  <template v-if="group.details">
                    <template v-if="group.details.aclEntries">
                      <div class="flow-detail-block-title">IP 访问控制列表（{{ group.details.aclEntries.length }} 条）</div>
                      <div v-for="entry in group.details.aclEntries" :key="`acl:${entry.value}`" class="flow-detail-entry">
                        <span class="flow-detail-value">{{ entry.value }}</span>
                        <span class="flow-detail-meta">{{ entry.source }}<template v-if="entry.remark"> · {{ entry.remark }}</template></span>
                      </div>
                    </template>
                    <template v-if="group.details.trustEntries">
                      <div class="flow-detail-block-title">信任名单（{{ group.details.trustEntries.length }} 条）</div>
                      <div v-for="entry in group.details.trustEntries" :key="`trust:${entry.value}`" class="flow-detail-entry">
                        <span class="flow-detail-value">{{ entry.value }}</span>
                        <span class="flow-detail-meta">{{ entry.source }}<template v-if="entry.remark"> · {{ entry.remark }}</template></span>
                      </div>
                    </template>
                    <template v-if="group.details.geoipRegions && group.details.geoipRegions.length > 0">
                      <div class="flow-detail-block-title">地域拦截区域（{{ group.details.geoipRegions.length }} 个）</div>
                      <div class="flow-detail-chips">
                        <el-tag v-for="region in group.details.geoipRegions" :key="region" size="small" effect="plain" class="flow-detail-chip">{{ region }}</el-tag>
                      </div>
                    </template>
                    <template v-if="group.details.rateLimit">
                      <div class="flow-detail-block-title">限流窗口口径</div>
                      <div class="flow-detail-line">{{ group.details.rateLimit.caption }}</div>
                    </template>
                    <template v-if="group.details.customRules">
                      <div class="flow-detail-block-title">自定义规则（{{ group.details.customRules.length }} 条）</div>
                      <div v-for="rule in group.details.customRules" :key="rule.id" class="flow-detail-entry" :class="{ 'is-disabled': !rule.enabled }">
                        <span class="flow-detail-value">{{ rule.name }}<span class="flow-detail-score">计分 {{ rule.score }}</span></span>
                        <span class="flow-detail-meta">{{ rule.action === 'pass' ? '放行' : '拦截' }}<template v-if="rule.targets"> · {{ rule.targets }}</template></span>
                      </div>
                    </template>
                    <template v-if="group.details.crsGroups && group.details.crsGroups.length > 0">
                      <div class="flow-detail-block-title">CRS 规则组（{{ group.details.crsGroups.length }} 组）</div>
                      <div class="flow-detail-chips">
                        <el-tag v-for="groupLabel in group.details.crsGroups" :key="groupLabel" size="small" effect="plain" class="flow-detail-chip">{{ groupLabel }}</el-tag>
                      </div>
                    </template>
                  </template>
                  <div v-else-if="detailLoading" class="flow-detail-line">明细加载中…</div>
                  <div v-else class="flow-detail-line">该阶段此策略无更多明细</div>
                </div>
              </el-collapse-transition>
            </div>
          </template>
          <div v-else class="flow-stage-empty">该阶段未启用（无策略配置对应能力）</div>
          <div class="flow-panel-footnote">未通过即终止{{ stage.footnote ? `；${stage.footnote}` : '' }}</div>
        </div>
      </el-collapse-transition>

      <el-collapse-transition>
        <div v-if="activeNode === 'upstream'" class="flow-panel">
          <div class="flow-panel-head"><span class="flow-panel-title">上游</span></div>
          <div class="flow-row"><span class="flow-row-label">上游</span><span class="flow-row-detail">{{ target.upstreamSummary }}</span></div>
          <div class="flow-panel-footnote">通过全部阶段后按负载策略转发至上游</div>
        </div>
      </el-collapse-transition>
    </div>
  </el-drawer>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { request } from '@/utils/api'
import type { APIResponse } from '@/types'
import { STAGE_SHORT_TITLES, attachStageDetails, inferPolicyType } from '@/utils/securityStages'
import type {
  CrsRuleFileOption,
  RuleFlowTarget,
  RuleStageModel,
  SecurityStageCustomRule,
  SecurityStageIPList,
  SecurityStagePolicy,
  SecurityStagePolicyDetail,
  StageGroup,
  StagePolicyGroup,
} from '@/utils/securityStages'

const props = defineProps<{
  modelValue: boolean
  target: RuleFlowTarget | null
  model: RuleStageModel | null
  policies: readonly SecurityStagePolicy[]
  ipLists: readonly SecurityStageIPList[]
}>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()

// ── 流水线几何 ──
const NODE_W = 128
const NODE_H = 104
const NODE_Y = 24
const SVG_H = 152
const LINE_Y = NODE_Y + NODE_H / 2

const isTcp = computed(() => props.target?.protocol === 'tcp')
const protocolLabel = computed(() => {
  if (!props.target) return '-'
  if (props.target.protocol === 'tcp') return 'TCP'
  return props.target.enableTls ? 'HTTPS' : 'HTTP'
})

interface StageStats {
  stage1_blocked_24h: number
  stage3_blocked_24h: number
  ratelimit_blocks_reload: number
}

const stats = ref<StageStats | null>(null)
const statsLoading = ref(false)
let statsSeq = 0

const activeNode = ref('')

// ── 明细懒加载（决策 C：现有只读端点前端拼装）——阶段面板首次展开时拉取三源并附着，
// 一次抽屉会话拉一次；失败源回退空集（对应明细块不渲染），不阻断面板
const detailLoading = ref(false)
const detailsAttached = ref(false)
const fullPolicies = ref<Map<number, SecurityStagePolicyDetail>>(new Map())
const customRules = ref<SecurityStageCustomRule[]>([])
const crsFiles = ref<CrsRuleFileOption[]>([])
const expandedPolicyKey = ref('')

const displayModel = computed<RuleStageModel | null>(() => {
  if (!props.model) return null
  if (!detailsAttached.value) return props.model
  return attachStageDetails(props.model, {
    policies: props.policies,
    ipLists: props.ipLists,
    sources: { fullPolicies: fullPolicies.value, customRules: customRules.value, crsFiles: crsFiles.value },
  })
})

const stagePanels = computed<StageGroup[]>(() => displayModel.value?.stages ?? [])

const policyTypeOf = (policyId: number) =>
  inferPolicyType(props.policies.find((p) => p.id === policyId) ?? { has_ip_control: false, has_rate_limit: false, has_custom_rules: false })

const groupHasDetails = (group: StagePolicyGroup): boolean => {
  const d = group.details
  if (!d) return false
  return (d.aclEntries?.length ?? 0) > 0
    || (d.trustEntries?.length ?? 0) > 0
    || (d.geoipRegions?.length ?? 0) > 0
    || d.rateLimit !== undefined
    || (d.customRules?.length ?? 0) > 0
    || (d.crsGroups?.length ?? 0) > 0
}

const ensureDetails = async (): Promise<void> => {
  if (detailsAttached.value || detailLoading.value) return
  detailLoading.value = true
  try {
    const caddyId = props.target?.caddyId
    const requests = [
      request.get<APIResponse<SecurityStageCustomRule[]>>('/security/custom-rules', { silent: true }),
      request.get<APIResponse<{ rules: CrsRuleFileOption[] }>>('/security/crs/rules?page_size=50', { silent: true }),
    ] as const
    const [policyRes, customRes, crsRes] = await Promise.allSettled([
      caddyId
        ? request.get<APIResponse<SecurityStagePolicyDetail[]>>(`/security/rules/${encodeURIComponent(caddyId)}/policy`, { silent: true })
        : Promise.resolve<APIResponse<SecurityStagePolicyDetail[]>>({ code: 0, data: [] }),
      ...requests,
    ])
    if (policyRes.status === 'fulfilled') {
      fullPolicies.value = new Map((policyRes.value.data ?? []).map((p) => [p.id, p]))
    }
    if (customRes.status === 'fulfilled') customRules.value = customRes.value.data ?? []
    if (crsRes.status === 'fulfilled') crsFiles.value = crsRes.value.data?.rules ?? []
    detailsAttached.value = true
  } finally {
    detailLoading.value = false
  }
}

const togglePolicyDetail = (stage: 1 | 2 | 3, policyId: number): void => {
  const key = `${stage}:${policyId}`
  expandedPolicyKey.value = expandedPolicyKey.value === key ? '' : key
}

const toggleNode = (key: string): void => {
  activeNode.value = activeNode.value === key ? '' : key
  expandedPolicyKey.value = ''
  // 阶段面板首次展开触发明细拉取（接入/上游面板无明细）
  if (activeNode.value.startsWith('stage')) void ensureDetails()
}

// 计数 chip 文案：阶段 1/3 = 24h 事件数；阶段 2 = 重载口径（chip 下标注「自最近重载」）
const stageChip = (stage: 1 | 2 | 3): { chip?: string; caption?: string } => {
  if (!props.target?.caddyId || isTcp.value) return {}
  if (statsLoading.value) return { chip: '计数加载中…' }
  if (!stats.value) return { chip: '暂无计数' }
  if (stage === 1) return { chip: `24h 拦截 ${stats.value.stage1_blocked_24h}` }
  if (stage === 2) return { chip: `429 拦截 ${stats.value.ratelimit_blocks_reload}`, caption: '自最近重载' }
  return { chip: `24h 拦截 ${stats.value.stage3_blocked_24h}` }
}

const stageStatsText = (stage: 1 | 2 | 3): string => {
  if (!props.target?.caddyId || isTcp.value) return ''
  if (statsLoading.value) return '拦截计数加载中…'
  if (!stats.value) return ''
  if (stage === 1) return `近 24 小时本阶段拦截 ${stats.value.stage1_blocked_24h} 次`
  if (stage === 2) return `自最近重载以来限流拦截 ${stats.value.ratelimit_blocks_reload} 次（恒 429）`
  return `近 24 小时本阶段拦截 ${stats.value.stage3_blocked_24h} 次`
}

interface FlowNode {
  key: string
  title: string
  lines: string[]
  disabled?: boolean
  chip?: string
  chipCaption?: string
  prevInactive?: boolean
}

const flowNodes = computed<FlowNode[]>(() => {
  const target = props.target
  if (!target) return []
  const access: FlowNode = { key: 'access', title: '接入', lines: [protocolLabel.value, `端口 ${target.listenPort}`, ...(isTcp.value ? [] : [target.enableTls ? 'TLS 启用' : 'TLS 关闭'])] }
  const upstream: FlowNode = { key: 'upstream', title: '上游', lines: [target.upstreamSummary] }
  if (isTcp.value) return [access, upstream]
  const nodes: FlowNode[] = [access]
  for (const stage of stagePanels.value) {
    const { chip, caption } = stageChip(stage.stage)
    nodes.push({
      key: `stage${stage.stage}`,
      title: STAGE_SHORT_TITLES[stage.stage],
      lines: [stage.enabled ? stageSub(stage.stage) : '未启用'],
      disabled: !stage.enabled,
      chip,
      chipCaption: caption,
    })
  }
  nodes.push(upstream)
  nodes.forEach((node, index) => {
    node.prevInactive = index > 0 && (node.disabled === true || nodes[index - 1].disabled === true)
  })
  return nodes
})

const stageSub = (stage: 1 | 2 | 3): string => {
  if (stage === 1) return 'IP 控制 · 地域拦截'
  if (stage === 2) return '速率限制'
  return '自定义 · CRS'
}

const nodeGap = computed(() => {
  const count = flowNodes.value.length
  if (count <= 1) return 0
  return (720 - 16 - count * NODE_W) / (count - 1)
})
const nodeX = (index: number): number => 8 + index * (NODE_W + nodeGap.value)
const nodeLineX1 = (index: number): number => nodeX(index - 1) + NODE_W
const nodeLineX2 = (index: number): number => nodeX(index)

// chip 宽度估算：中文约 11.5px/字，ASCII 约 6.5px/字（11px 字号的视觉近似）
const chipWidth = (text: string): number =>
  Math.max(52, [...text].reduce((w, ch) => w + ((ch.codePointAt(0) ?? 0) > 255 ? 11.5 : 6.5), 0) + 18)

const onDrawerOpen = (): void => {
  activeNode.value = ''
  expandedPolicyKey.value = ''
  stats.value = null
  statsLoading.value = false
  // 明细缓存随抽屉会话重置（规则绑定/策略内容可能已在页间变更）
  detailsAttached.value = false
  fullPolicies.value = new Map()
  customRules.value = []
  crsFiles.value = []
  const caddyId = props.target?.caddyId
  if (!caddyId || isTcp.value) return
  const seq = ++statsSeq
  statsLoading.value = true
  request.get<APIResponse<StageStats>>(`/security/rules/${encodeURIComponent(caddyId)}/stage-stats`, { silent: true })
    .then((res) => { if (seq === statsSeq) stats.value = res.data ?? null })
    .catch(() => { if (seq === statsSeq) stats.value = null })
    .finally(() => { if (seq === statsSeq) statsLoading.value = false })
}
</script>

<style scoped>
.flow-header { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
.flow-header-title { font-size: 16px; font-weight: 600; color: #1f2937; }
.flow-header-name { font-size: 13px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.flow-body { display: flex; flex-direction: column; gap: 16px; }
.flow-tcp-alert { flex: 0 0 auto; }
.flow-svg { width: 100%; height: auto; display: block; }

/* ── 节点错峰进场（一次性） ── */
@keyframes flow-node-in {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: none; }
}
.flow-node { cursor: pointer; outline: none; animation: flow-node-in 0.45s ease both; }
.flow-node-rect { fill: #ffffff; stroke: #c6e2ff; stroke-width: 1.5; transition: stroke 0.15s ease; }
.flow-node:hover .flow-node-rect,
.flow-node:focus-visible .flow-node-rect { stroke: var(--el-color-primary); }
.flow-node.is-selected .flow-node-rect { stroke: var(--el-color-primary); stroke-width: 2; }
.flow-node.is-off .flow-node-rect { fill: #fafafa; stroke: #dcdfe6; stroke-dasharray: 4 4; }
.flow-node-title { font-size: 13px; font-weight: 600; fill: #1f2937; }
.flow-node.is-off .flow-node-title { fill: #9ca3af; }
.flow-node-sub { font-size: 11px; fill: #6b7280; }
.flow-node.is-off .flow-node-sub { fill: #b1b5bd; }
.flow-node-chip { fill: #ecf5ff; stroke: #b3d8ff; }
.flow-node-chip-text { font-size: 11px; fill: #1f6fbd; }
.flow-node-chip-caption { font-size: 10px; fill: #9ca3af; }

/* ── 连接线：基线 draw-on（一次性）+ 粒子流动（无限）；未启用段虚线灰态停粒子 ── */
@keyframes flow-line-draw {
  from { stroke-dashoffset: 100; }
  to { stroke-dashoffset: 0; }
}
@keyframes flow-fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}
@keyframes flow-march {
  from { stroke-dashoffset: 12; }
  to { stroke-dashoffset: 0; }
}
.flow-line-base {
  stroke: #c0c4cc;
  stroke-width: 1.5;
  stroke-dasharray: 100;
  stroke-dashoffset: 100;
  animation: flow-line-draw 0.5s ease-out forwards;
}
.flow-line-base.is-inactive {
  stroke: #dcdfe6;
  stroke-dasharray: 4 6;
  stroke-dashoffset: 0;
  animation: flow-fade-in 0.3s ease both;
}
.flow-line-particles {
  stroke: var(--el-color-primary);
  stroke-width: 1.5;
  stroke-linecap: round;
  stroke-dasharray: 4 8;
  animation: flow-march 0.9s linear infinite, flow-fade-in 0.3s ease both;
}

/* ── 下钻面板 ── */
.flow-panel { border: 1px solid #ebeef5; border-radius: 8px; padding: 12px 16px; background: #fafafa; }
.flow-panel-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
.flow-panel-title { font-size: 14px; font-weight: 600; color: #1f2937; }
.flow-panel-stats { font-size: 12px; color: #1f6fbd; margin-bottom: 8px; }
.flow-policy-block + .flow-policy-block { margin-top: 8px; padding-top: 8px; border-top: 1px dashed #e5e7eb; }
.flow-policy-block.is-disabled { opacity: 0.45; }
.flow-policy-head { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; font-weight: 600; }
.flow-policy-order { color: #6b7280; font-variant-numeric: tabular-nums; }
.flow-policy-name { color: #1f2937; }
.flow-detail-toggle { margin-left: auto; }
.flow-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; font-size: 13px; line-height: 1.8; }
.flow-row-label { color: #6b7280; flex-shrink: 0; }
.flow-row-detail { color: #1f2937; text-align: right; overflow: hidden; text-overflow: ellipsis; }
.flow-stage-empty { font-size: 13px; color: #9ca3af; padding: 8px 0; }
.flow-panel-footnote { margin-top: 10px; padding-top: 8px; border-top: 1px dashed #e5e7eb; font-size: 12px; color: #9ca3af; }

/* ── 二级明细区（max-height 滚动） ── */
.flow-policy-details { max-height: 260px; overflow-y: auto; margin-top: 6px; border-top: 1px dashed #e5e7eb; padding-top: 8px; }
.flow-detail-block-title { font-size: 12px; font-weight: 600; color: #4b5563; margin: 8px 0 4px; }
.flow-detail-block-title:first-child { margin-top: 0; }
.flow-detail-entry { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; font-size: 12px; line-height: 1.8; }
.flow-detail-entry.is-disabled { opacity: 0.45; }
.flow-detail-value { color: #1f2937; font-family: monospace; }
.flow-detail-score { margin-left: 6px; font-family: inherit; font-size: 11px; color: #9ca3af; }
.flow-detail-meta { color: #9ca3af; text-align: right; }
.flow-detail-chips { display: flex; flex-wrap: wrap; gap: 4px; }
.flow-detail-line { font-size: 12px; color: #6b7280; line-height: 1.8; }
</style>
