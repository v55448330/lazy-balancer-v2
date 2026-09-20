<template>
  <el-dialog
    :model-value="modelValue"
    width="min(920px, 95vw)"
    top="5vh"
    destroy-on-close
    class="rule-flow-dialog"
    @update:model-value="emit('update:modelValue', $event)"
    @open="onDialogOpen"
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

      <!-- 节点选择器：卡片化导航（选中高亮 + 连接线暗示流向；打开默认选中「接入」） -->
      <div class="flow-nav" role="tablist" aria-label="处理流程节点">
        <template v-for="(node, index) in flowNodes" :key="node.key">
          <div v-if="index > 0" class="flow-nav-connector" :class="{ 'is-inactive': node.prevInactive }" aria-hidden="true" />
          <button
            type="button"
            class="flow-nav-card"
            :class="{ 'is-active': activeNode === node.key, 'is-off': node.disabled }"
            role="tab"
            :aria-selected="activeNode === node.key"
            @click="toggleNode(node.key)"
          >
            <span class="flow-nav-title">{{ node.title }}</span>
            <span class="flow-nav-sub">{{ node.subtitle }}</span>
            <span v-if="node.chip" class="flow-nav-chip">{{ node.chip }}<em v-if="node.chipCaption" class="flow-nav-chip-caption">{{ node.chipCaption }}</em></span>
          </button>
        </template>
      </div>

      <!-- 接入信息（默认展开）：协议/端口/TLS 状态与来源 + 证书信息 -->
      <div v-if="activeNode === 'access'" class="flow-panel">
        <div class="flow-panel-head"><span class="flow-panel-title">接入</span></div>
        <div class="flow-kv-grid">
          <div class="flow-kv"><span class="flow-kv-label">协议</span><span class="flow-kv-value">{{ protocolLabel }}</span></div>
          <div class="flow-kv"><span class="flow-kv-label">监听端口</span><span class="flow-kv-value">{{ target.listenPort }}</span></div>
          <div class="flow-kv">
            <span class="flow-kv-label">TLS</span>
            <span class="flow-kv-value">{{ target.enableTls ? `启用（${target.tlsSource === 'acme_dns' ? 'ACME 自动' : '手动上传'}）` : '关闭' }}</span>
          </div>
          <div v-if="!isTcp" class="flow-kv">
            <span class="flow-kv-label">后端域名</span>
            <span class="flow-kv-value">{{ target.hostHeader || '透传原始 Host' }}</span>
          </div>
        </div>
        <template v-if="target.enableTls && !isTcp">
          <div v-if="certLoading" class="flow-cert-loading"><el-skeleton :rows="2" animated /></div>
          <template v-else-if="certInfo">
            <div class="flow-cert-title">TLS 证书</div>
            <div class="flow-kv-grid">
              <div class="flow-kv"><span class="flow-kv-label">签发者</span><span class="flow-kv-value" :title="certInfo.issuer">{{ certInfo.issuer || '-' }}</span></div>
              <div class="flow-kv"><span class="flow-kv-label">证书域名</span><span class="flow-kv-value" :title="certInfo.domains">{{ certInfo.domains || '-' }}</span></div>
              <div class="flow-kv"><span class="flow-kv-label">到期时间</span><span class="flow-kv-value">{{ certInfo.not_after || '-' }}</span></div>
              <div class="flow-kv">
                <span class="flow-kv-label">剩余天数</span>
                <span class="flow-kv-value" :class="{ 'is-expired': certInfo.status === 'expired' }">
                  {{ certInfo.status === 'expired' ? `已过期 ${Math.abs(certInfo.days_remaining)} 天` : `${certInfo.days_remaining} 天` }}
                </span>
              </div>
              <div v-if="certInfo.source === 'acme_dns' && target.acmeConfigName" class="flow-kv">
                <span class="flow-kv-label">ACME 配置</span>
                <span class="flow-kv-value">{{ target.acmeConfigName }}</span>
              </div>
              <div v-if="certInfo.error" class="flow-kv">
                <span class="flow-kv-label">解析错误</span>
                <span class="flow-kv-value is-expired" :title="certInfo.error">{{ certInfo.error }}</span>
              </div>
            </div>
          </template>
          <div v-else class="flow-detail-line">证书信息不可用（规则禁用或证书未就绪）</div>
        </template>
      </div>

      <!-- 阶段面板：分组 + 明细手风琴 + 计数 chip（口径同前） -->
      <template v-for="stage in stagePanels" :key="stage.stage">
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
      </template>

      <!-- 上游信息：逐上游明细 + 规则级健康计数（无逐上游实时探针数据时的口径注明） -->
      <div v-if="activeNode === 'upstream'" class="flow-panel">
        <div class="flow-panel-head">
          <span class="flow-panel-title">上游</span>
          <el-tag v-if="target.health" size="small" effect="plain" :type="target.health.unhealthy + target.health.degraded > 0 ? 'warning' : 'success'">
            健康 {{ target.health.healthy }}/{{ target.health.total }}
          </el-tag>
        </div>
        <el-table v-if="target.upstreams && target.upstreams.length > 0" :data="target.upstreams" size="small" class="flow-upstream-table">
          <el-table-column label="上游" min-width="170">
            <template #default="{ row }"><span class="flow-upstream-addr">{{ row.host }}:{{ row.port }}</span></template>
          </el-table-column>
          <el-table-column label="协议" width="70" align="center">
            <template #default="{ row }"><el-tag size="small" effect="plain" :type="row.protocol === 'https' || row.protocol === 'tls' ? 'warning' : 'primary'">{{ (row.protocol || 'http').toUpperCase() }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="weight" label="权重 %" width="70" align="center" />
          <el-table-column prop="max_connections" :label="isTcp ? '最大连接' : '最大请求数'" width="90" align="center">
            <template #default="{ row }">{{ row.max_connections > 0 ? row.max_connections : '不限' }}</template>
          </el-table-column>
          <el-table-column label="状态" width="110" align="center">
            <template #default="{ row }">
              <el-tag size="small" effect="plain" :type="upstreamStateType(row)">{{ upstreamStateText(row) }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        <div v-else class="flow-detail-line">{{ target.upstreamSummary }}</div>
        <div class="flow-panel-footnote">健康口径：规则级计数（健康 {{ target.health?.healthy ?? 0 }}/共 {{ target.health?.total ?? 0 }}）；无逐上游实时探针数据时按「上游启用/禁用 + 规则健康计数」呈现——逐上游状态为最近一次轮询快照</div>
      </div>
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { request } from '@/utils/api'
import type { APIResponse } from '@/types'
import { hostPortKey } from '@/utils/upstreamKeys'
import { STAGE_SHORT_TITLES, attachStageDetails, inferPolicyType } from '@/utils/securityStages'
import type {
  CrsRuleFileOption,
  RuleFlowTarget,
  RuleFlowUpstream,
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

interface FlowCertInfo {
  source: string
  domains: string
  issuer: string
  not_before: string
  not_after: string
  days_remaining: number
  status: string
  error?: string
}

const stats = ref<StageStats | null>(null)
const statsLoading = ref(false)
const certInfo = ref<FlowCertInfo | null>(null)
const certLoading = ref(false)
let statsSeq = 0

// 打开即见接入信息（用户裁定：默认选中「接入」，非空白）
const activeNode = ref('access')

// ── 明细懒加载（决策 C：现有只读端点前端拼装）——阶段面板首次展开时拉取三源并附着 ──
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
    const [policyRes, customRes, crsRes] = await Promise.allSettled([
      caddyId
        ? request.get<APIResponse<SecurityStagePolicyDetail[]>>(`/security/rules/${encodeURIComponent(caddyId)}/policy`, { silent: true })
        : Promise.resolve<APIResponse<SecurityStagePolicyDetail[]>>({ code: 0, data: [] }),
      request.get<APIResponse<SecurityStageCustomRule[]>>('/security/custom-rules', { silent: true }),
      request.get<APIResponse<{ rules: CrsRuleFileOption[] }>>('/security/crs/rules?page_size=50', { silent: true }),
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
  activeNode.value = key
  expandedPolicyKey.value = ''
  // 阶段面板首次选中触发明细拉取（接入/上游面板无明细）
  if (key.startsWith('stage')) void ensureDetails()
}

// 上游行状态：禁用优先；有逐上游快照按快照（healthy/degraded/unknown），无快照回落启用态口径
const upstreamStateText = (row: RuleFlowUpstream): string => {
  if (!row.enabled) return '禁用'
  const snapshot = props.target?.upstreamHealth?.[hostPortKey(row.host, row.port)]
  if (!snapshot || snapshot.unknown) return '启用'
  if (snapshot.degraded) return '降级'
  return snapshot.healthy ? '健康' : '异常'
}
const upstreamStateType = (row: RuleFlowUpstream): 'success' | 'warning' | 'danger' | 'info' => {
  if (!row.enabled) return 'info'
  const snapshot = props.target?.upstreamHealth?.[hostPortKey(row.host, row.port)]
  if (!snapshot || snapshot.unknown) return 'info'
  if (snapshot.degraded) return 'warning'
  return snapshot.healthy ? 'success' : 'danger'
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
  subtitle: string
  disabled?: boolean
  chip?: string
  chipCaption?: string
  prevInactive?: boolean
}

const flowNodes = computed<FlowNode[]>(() => {
  const target = props.target
  if (!target) return []
  const access: FlowNode = { key: 'access', title: '接入', subtitle: `${protocolLabel.value} · 端口 ${target.listenPort}` }
  const upstream: FlowNode = { key: 'upstream', title: '上游', subtitle: target.upstreamSummary }
  if (isTcp.value) return [access, upstream]
  const nodes: FlowNode[] = [access]
  for (const stage of stagePanels.value) {
    const { chip, caption } = stageChip(stage.stage)
    nodes.push({
      key: `stage${stage.stage}`,
      title: STAGE_SHORT_TITLES[stage.stage],
      subtitle: stage.enabled ? stageSub(stage.stage) : '未启用',
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
  if (stage === 1) return 'IP 名单 · 地域拦截'
  if (stage === 2) return '速率限制'
  return '自定义 · CRS'
}

const onDialogOpen = (): void => {
  activeNode.value = 'access'
  expandedPolicyKey.value = ''
  stats.value = null
  statsLoading.value = false
  certInfo.value = null
  certLoading.value = false
  // 明细缓存随弹框会话重置（规则绑定/策略内容可能已在页间变更）
  detailsAttached.value = false
  fullPolicies.value = new Map()
  customRules.value = []
  crsFiles.value = []
  const caddyId = props.target?.caddyId
  if (!caddyId) return
  if (!isTcp.value) {
    const seq = ++statsSeq
    statsLoading.value = true
    request.get<APIResponse<StageStats>>(`/security/rules/${encodeURIComponent(caddyId)}/stage-stats`, { silent: true })
      .then((res) => { if (seq === statsSeq) stats.value = res.data ?? null })
      .catch(() => { if (seq === statsSeq) stats.value = null })
      .finally(() => { if (seq === statsSeq) statsLoading.value = false })
  }
  // TLS 启用时拉取证书信息（接入卡富化）
  if (props.target?.enableTls && !isTcp.value) {
    const seq = ++statsSeq
    certLoading.value = true
    request.get<APIResponse<FlowCertInfo>>(`/rules/${encodeURIComponent(caddyId)}/cert-info`, { silent: true })
      .then((res) => { if (seq === statsSeq) certInfo.value = res.data ?? null })
      .catch(() => { if (seq === statsSeq) certInfo.value = null })
      .finally(() => { if (seq === statsSeq) certLoading.value = false })
  }
}
</script>

<style scoped>
.flow-header { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
.flow-header-title { font-size: 16px; font-weight: 600; color: #1f2937; }
.flow-header-name { font-size: 13px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.flow-body { display: flex; flex-direction: column; gap: 16px; }
.flow-tcp-alert { flex: 0 0 auto; }

/* ── 节点卡片导航（选中态高亮 + 连接线暗示流向；阶段名统一 nowrap 防换行） ── */
.flow-nav { display: flex; align-items: stretch; gap: 0; }
.flow-nav-card {
  flex: 1 1 0;
  min-width: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 12px 8px;
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  cursor: pointer;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
  font-family: inherit;
}
.flow-nav-card:hover { border-color: var(--el-color-primary-light-5); }
.flow-nav-card.is-active { border-color: var(--el-color-primary); box-shadow: 0 0 0 2px var(--el-color-primary-light-8); }
.flow-nav-card.is-off { background: #fafafa; }
.flow-nav-card.is-off .flow-nav-title,
.flow-nav-card.is-off .flow-nav-sub { color: #b1b5bd; }
.flow-nav-title { font-size: 13px; font-weight: 600; color: #1f2937; white-space: nowrap; }
.flow-nav-sub { font-size: 11px; color: #6b7280; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }
.flow-nav-chip {
  font-style: normal;
  font-size: 11px;
  color: #1f6fbd;
  background: #ecf5ff;
  border: 1px solid #b3d8ff;
  border-radius: 9px;
  padding: 1px 8px;
  white-space: nowrap;
}
.flow-nav-chip-caption { font-style: normal; color: #9ca3af; margin-left: 4px; }
.flow-nav-connector {
  flex: 0 0 18px;
  align-self: center;
  height: 0;
  border-top: 2px solid #c0c4cc;
  position: relative;
}
.flow-nav-connector::after {
  content: '';
  position: absolute;
  right: -1px;
  top: -5px;
  border: 4px solid transparent;
  border-left-color: #c0c4cc;
}
.flow-nav-connector.is-inactive { border-top-style: dashed; border-top-color: #dcdfe6; }
.flow-nav-connector.is-inactive::after { border-left-color: #dcdfe6; }

/* ── 信息区：key-value 栅格 + 字级层次 ── */
.flow-panel { border: 1px solid #ebeef5; border-radius: 8px; padding: 14px 18px; background: #fafafa; }
.flow-panel-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.flow-panel-title { font-size: 14px; font-weight: 600; color: #1f2937; }
.flow-panel-stats { font-size: 12px; color: #1f6fbd; margin-bottom: 8px; }
.flow-kv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 8px 24px; }
.flow-kv { display: flex; align-items: baseline; gap: 12px; font-size: 13px; line-height: 1.8; min-width: 0; }
.flow-kv-label { color: #6b7280; flex: 0 0 72px; }
.flow-kv-value { color: #1f2937; overflow: hidden; text-overflow: ellipsis; }
.flow-kv-value.is-expired { color: var(--el-color-danger); }
.flow-cert-title { font-size: 13px; font-weight: 600; color: #4b5563; margin: 12px 0 6px; padding-top: 10px; border-top: 1px dashed #e5e7eb; }
.flow-cert-loading { margin-top: 12px; }
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
.flow-upstream-table { width: 100%; }
.flow-upstream-addr { font-family: monospace; font-size: 12px; color: #1f2937; }

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
