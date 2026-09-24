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
      <div v-if="isTcp" class="info-note-bar info-note-bar--inset">
        <span class="info-note-desc">TCP 规则无 HTTP 安全链</span>
        <span class="info-note-sub">TCP（L4）流量不经信任名单、IP 访问控制、限流与 WAF 阶段，接入后直接转发至上游。</span>
      </div>

      <!-- 纵向时间线：接入 → 阶段 0 → 阶段 1 → 阶段 2 → 阶段 3 → 上游 -->
      <template v-for="(node, index) in flowNodes" :key="node.key">
        <div class="tl-row" :class="{ 'is-off': node.disabled }" :style="{ animationDelay: `${index * 90}ms` }">
          <div class="tl-rail">
            <span class="tl-dot" :class="`tl-dot--${node.tone}`"><el-icon :size="14"><component :is="node.icon" /></el-icon></span>
            <span v-if="index < flowNodes.length - 1" class="tl-line" aria-hidden="true" />
          </div>
          <div class="tl-main">
          <!-- 连线=流量路径（2026-09-21 用户裁定）：流量恒从接入到上游，连线无灰态，
               恒为流动主线；阶段启用与否由节点灰态（is-off）承载 -->
          <button
            type="button"
            class="tl-card"
            :class="{ 'is-active': activeNode === node.key }"
            :aria-expanded="activeNode === node.key"
            @click="toggleNode(node.key)"
          >
            <span class="tl-card-head">
              <span class="tl-title">{{ node.title }}</span>
              <span v-if="node.chip" class="tl-chip">{{ node.chip }}<em v-if="node.chipCaption" class="tl-chip-caption">{{ node.chipCaption }}</em></span>
            </span>
            <span class="tl-sub">{{ node.subtitle }}</span>
          </button>

        <!-- 接入信息（选中节点下方展开）：我们收到什么样的请求 -->
        <el-collapse-transition v-if="node.key === 'access'">
          <div v-if="activeNode === 'access'" class="flow-panel tl-panel">
            <div class="flow-panel-head"><span class="flow-panel-title">接入 · 收到的请求</span></div>
            <div class="flow-kv-grid">
              <div class="flow-kv flow-kv--wide">
                <span class="flow-kv-label">域名</span>
                <span class="flow-kv-value">
                  <template v-if="target.domains && target.domains.length > 0">
                    <el-tag v-for="domain in target.domains" :key="domain" size="small" effect="plain" class="flow-domain-chip">{{ domain }}</el-tag>
                  </template>
                  <template v-else>-</template>
                </span>
              </div>
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
        </el-collapse-transition>

        <!-- 阶段 0 · 信任名单面板 -->
        <el-collapse-transition v-if="node.key === 'stage0'">
          <div v-if="activeNode === 'stage0'" class="flow-panel tl-panel">
            <template v-if="stageZero">
            <div class="flow-panel-head"><span class="flow-panel-title">{{ stageZero.title }}</span></div>
            <div
              v-for="group in stageZero.groups"
              :key="group.key"
              class="flow-policy-block"
              :class="{ 'is-disabled': !group.enabled }"
            >
              <div class="flow-policy-head">
                <span class="flow-policy-order">#{{ group.order }}</span>
                <span class="flow-policy-name" :title="group.name">{{ group.name }}</span>
                <el-tag v-if="!group.enabled" type="info" size="small" effect="plain">已禁用</el-tag>
                <el-button
                  v-if="groupHasDetails(group)"
                  link
                  type="primary"
                  size="small"
                  class="flow-detail-toggle"
                  @click="togglePolicyDetail(0, group.key)"
                >{{ expandedPolicyKey === `0:${group.key}` ? '收起明细' : '明细' }}</el-button>
              </div>
              <div v-for="row in group.rows" :key="row.label" class="flow-row">
                <span class="flow-row-label">{{ row.label }}</span>
                <span class="flow-row-detail" :title="row.detail">{{ row.detail }}</span>
              </div>
              <div v-if="trustPreview(group.key)" class="flow-row">
                <span class="flow-row-label">条目预览</span>
                <span class="flow-row-detail" :title="trustPreview(group.key)">{{ trustPreview(group.key) }}</span>
              </div>
              <el-collapse-transition>
                <div v-if="expandedPolicyKey === `0:${group.key}`" class="flow-policy-details">
                  <template v-if="group.details?.trustEntries">
                    <div class="flow-detail-block-title">信任名单（{{ group.details.trustEntries.length }} 条{{ group.details.trustEntries.length > 200 ? '，仅显示前 200 条' : '' }}）</div>
                    <div v-for="entry in group.details.trustEntries.slice(0, 200)" :key="`trust:${entry.value}`" class="flow-detail-entry">
                      <span class="flow-detail-value">{{ entry.value }}</span>
                      <span class="flow-detail-meta">{{ entry.source }}<template v-if="entry.remark"> · {{ entry.remark }}</template></span>
                    </div>
                  </template>
                  <div v-else class="flow-detail-line">该策略无更多明细</div>
                </div>
              </el-collapse-transition>
            </div>
            <div class="flow-panel-footnote">信任 IP 命中后跳过全部后续安全阶段；「直通上游」模式不产生任何安全事件（故无计数 chip），「保留检测记录」模式事件动作记为检测</div>
            </template>
            <div v-else class="flow-detail-line">未启用——未绑定信任名单策略，请求直接进入阶段 1</div>
          </div>
        </el-collapse-transition>

        <!-- 阶段 1/2/3 面板 -->
        <el-collapse-transition v-if="node.key.startsWith('stage') && node.key !== 'stage0'">
          <div v-if="activeNode === node.key && typedStageByKey(node.key)" class="flow-panel tl-panel">
              <div class="flow-panel-head">
                <span class="flow-panel-title">{{ typedStageByKey(node.key)!.title }}</span>
                <el-tag v-if="typedStageByKey(node.key)!.override && !typedStageByKey(node.key)!.override!.broken" type="warning" size="small" effect="plain">阶段页：{{ typedStageByKey(node.key)!.override!.pageName }}（{{ typedStageByKey(node.key)!.override!.status }}）</el-tag>
                <el-tag v-else-if="typedStageByKey(node.key)!.override?.broken" type="danger" size="small" effect="plain">阶段页已失效（回落跟随策略）</el-tag>
                <el-tag v-else-if="typedStageByKey(node.key)!.stage !== 2" type="info" size="small" effect="plain">拦截页跟随策略</el-tag>
                <el-tag v-if="!typedStageByKey(node.key)!.enabled" type="info" size="small" effect="plain">未启用</el-tag>
              </div>
              <div v-if="stageStatsText(typedStageByKey(node.key)!.stage)" class="flow-panel-stats">{{ stageStatsText(typedStageByKey(node.key)!.stage) }}</div>
              <template v-if="typedStageByKey(node.key)!.enabled">
                <div
                  v-for="group in typedStageByKey(node.key)!.groups"
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
                      @click="togglePolicyDetail(typedStageByKey(node.key)!.stage, group.key)"
                    >{{ expandedPolicyKey === `${typedStageByKey(node.key)!.stage}:${group.key}` ? '收起明细' : '明细' }}</el-button>
                  </div>
                  <div v-for="row in group.rows" :key="row.label" class="flow-row">
                    <span class="flow-row-label">{{ row.label }}</span>
                    <span class="flow-row-detail" :title="row.detail">{{ row.detail }}</span>
                  </div>
                  <!-- 二级明细区（懒加载附着；max-height 滚动） -->
                  <el-collapse-transition>
                    <div v-if="expandedPolicyKey === `${typedStageByKey(node.key)!.stage}:${group.key}`" class="flow-policy-details">
                      <template v-if="group.details">
                        <!-- ACL 明细=列表级汇总（2026-09-24 用户裁定）：不逐条列 IP，
                             只列内联条数+各引用名单的名称/条数（威胁库上万条逐条渲染不可行） -->
                        <template v-if="group.details.aclInlineCount || (group.details.aclLists && group.details.aclLists.length > 0)">
                          <div class="flow-detail-block-title">IP 访问控制列表（合计 {{ (group.details.aclInlineCount ?? 0) + (group.details.aclLists ?? []).reduce((sum, l) => sum + l.count, 0) }} 条）</div>
                          <div v-if="group.details.aclInlineCount" class="flow-detail-entry">
                            <span class="flow-detail-value">直接填写</span>
                            <span class="flow-detail-meta">{{ group.details.aclInlineCount }} 条</span>
                          </div>
                          <div v-for="list in group.details.aclLists" :key="`acl-list:${list.name}`" class="flow-detail-entry">
                            <span class="flow-detail-value">{{ list.name }}</span>
                            <span class="flow-detail-meta">{{ list.count }} 条</span>
                          </div>
                        </template>
                        <template v-if="group.details.trustEntries">
                          <div class="flow-detail-block-title">信任名单（{{ group.details.trustEntries.length }} 条{{ group.details.trustEntries.length > 200 ? '，仅显示前 200 条' : '' }}）</div>
                          <div v-for="entry in group.details.trustEntries.slice(0, 200)" :key="`trust:${entry.value}`" class="flow-detail-entry">
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
                            <span class="flow-detail-meta">{{ rule.action === 'pass' ? '放行' : rule.action === 'log' ? '仅记录' : '拦截' }}<template v-if="rule.targets"> · {{ rule.targets }}</template></span>
                          </div>
                        </template>
                        <template v-if="group.details.crsGroups && group.details.crsGroups.length > 0">
                          <div class="flow-detail-block-title">CRS 规则组（{{ group.details.crsGroups.length }} 组）</div>
                          <div class="flow-detail-chips">
                            <el-tag v-for="groupLabel in group.details.crsGroups" :key="groupLabel" size="small" effect="plain" class="flow-detail-chip">{{ groupLabel }}</el-tag>
                          </div>
                        </template>
                      </template>
                      <div v-else class="flow-detail-line">该阶段此策略无更多明细</div>
                    </div>
                  </el-collapse-transition>
                </div>
              </template>
              <div v-else class="flow-stage-empty">该阶段未启用（无策略配置对应能力）</div>
              <div class="flow-panel-footnote">
                {{ typedStageByKey(node.key)!.stage === 1 ? '信任名单归阶段 0 独立生效（拦截判定前）；本阶段未通过即终止' : `未通过即终止${typedStageByKey(node.key)!.footnote ? `；${typedStageByKey(node.key)!.footnote}` : ''}` }}
              </div>
          </div>
        </el-collapse-transition>

        <!-- 上游信息（发给什么样的上游） -->
        <el-collapse-transition v-if="node.key === 'upstream'">
          <div v-if="activeNode === 'upstream'" class="flow-panel tl-panel">
            <div class="flow-panel-head">
              <span class="flow-panel-title">上游 · 转发目标</span>
              <el-tag v-if="target.health" size="small" effect="plain" :type="target.health.unhealthy + target.health.degraded > 0 ? 'warning' : 'success'">
                健康 {{ target.health.healthy }}/{{ target.health.total }}
              </el-tag>
            </div>
            <div v-if="!isTcp" class="flow-kv" style="margin-bottom: 10px;">
              <span class="flow-kv-label">后端域名</span>
              <span class="flow-kv-value">{{ target.hostHeader || '透传原始 Host' }}</span>
            </div>
            <el-table v-if="target.upstreams && target.upstreams.length > 0" :data="target.upstreams" size="small" class="flow-upstream-table">
              <el-table-column label="上游" min-width="170">
                <template #default="{ row }"><span class="flow-upstream-addr">{{ row.host }}:{{ row.port }}</span></template>
              </el-table-column>
              <el-table-column label="协议" width="70" align="center">
                <template #default="{ row }"><el-tag size="small" effect="plain" :type="row.protocol === 'https' || row.protocol === 'tls' ? 'warning' : 'primary'">{{ (row.protocol || 'http').toUpperCase() }}</el-tag></template>
              </el-table-column>
              <el-table-column label="权重 %" width="70" align="center">
                <template #default="{ row }">{{ upstreamWeightPercent(target.upstreams ?? [], row) }}</template>
              </el-table-column>
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
            <!-- 路由分发明细分组：主路由+逐条路径行的健康明细（自定义路由信息唯一呈现处，
                 不再设独立流程节点）；主路由行含禁用位（主上游表上方已列全量，明细口径一致） -->
            <div v-if="target.pathRules && target.pathRules.length > 0" class="flow-route-group">
              <div class="flow-route-group-head">
                <span class="flow-route-group-title">路由分发</span>
                <span class="flow-route-group-sub">{{ target.pathRules.length }} 条自定义路由 · 未命中走主路由</span>
              </div>
              <div class="flow-route-row">
                <span class="flow-route-match">/<em class="flow-route-type">主路由</em></span>
                <span class="flow-route-arrow">→</span>
                <span class="flow-route-targets">
                  <template v-if="target.upstreams && target.upstreams.length > 0">
                    <span v-for="u in target.upstreams" :key="`${u.host}:${u.port}`" class="flow-route-target">
                      <span class="flow-upstream-addr">{{ u.host }}:{{ u.port }}</span>
                      <el-tag size="small" effect="plain" :type="upstreamStateType(u)">{{ upstreamStateText(u) }}</el-tag>
                    </span>
                  </template>
                  <span v-else class="flow-route-none">无主上游</span>
                </span>
              </div>
              <div v-for="pr in target.pathRules" :key="`${pr.match_type}:${pr.path}`" class="flow-route-row">
                <span class="flow-route-match">{{ pr.path }}<em class="flow-route-type">{{ pathMatchLabel(pr.match_type) }}</em></span>
                <span class="flow-route-arrow">→</span>
                <span class="flow-route-targets">
                  <template v-if="enabledPathUpstreams(pr).length > 0">
                    <span v-for="u in enabledPathUpstreams(pr)" :key="`${u.host}:${u.port}`" class="flow-route-target">
                      <span class="flow-upstream-addr">{{ u.host }}:{{ u.port }}</span>
                      <el-tag size="small" effect="plain" :type="upstreamStateType(u)">{{ upstreamStateText(u) }}</el-tag>
                    </span>
                  </template>
                  <span v-else class="flow-route-none">无启用上游</span>
                </span>
              </div>
            </div>
            <div class="flow-panel-footnote">健康口径：规则级计数（健康 {{ target.health?.healthy ?? 0 }}/共 {{ target.health?.total ?? 0 }}）；无逐上游实时探针数据时按「上游启用/禁用 + 规则健康计数」呈现——逐上游状态为最近一次轮询快照；自定义路由上游与主路由同享规则级健康检查</div>
          </div>
        </el-collapse-transition>
          </div>
        </div>
      </template>
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { Connection, CircleCheck, Key, Odometer, Aim, TopRight } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import type { APIResponse } from '@/types'
import type { RuleFlowPathRule } from '@/types/rules'
import { hostPortKey } from '@/utils/upstreamKeys'
import { STAGE_TITLES, attachStageDetails, inferPolicyType, mergeIpEntries, parseIPList, parseRefIds } from '@/utils/securityStages'
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
const statsSettled = ref(false)
const certInfo = ref<FlowCertInfo | null>(null)
const certLoading = ref(false)
let statsSeq = 0
// 证书拉取用独立序列计数器：与 statsSeq 共用时，TLS 规则的 cert-info 请求
// ++ 会让先发的 stage-stats 响应 seq 失配被丢弃、statsSettled 恒 false——
// 阶段计数 chip 在 TLS 规则上永不渲染（2026-09-21 生产报障根因）
let certSeq = 0
// 明细拉取会话序号：弹框每次打开自增，使上一会话在途明细续体落地前失配被弃
// （A→B 快速切换后，A 的明细数据不得附着到 B 的模型、也不得置位 detailsAttached
// 把 B 锁死在「明细按钮缺失且不可重试」状态）
let detailsSeq = 0

// 打开即见接入信息（用户裁定：默认选中「接入」，非空白）
const activeNode = ref('access')

// ── 明细懒加载（决策 C：现有只读端点前端拼装）——阶段面板首次选中时拉取三源并附着 ──
const detailLoading = ref(false)
const detailsAttached = ref(false)
const fullPolicies = ref<Map<number, SecurityStagePolicyDetail>>(new Map())
// 引用名单条目按需缓存（2026-09-24：列表载荷不再内联 entries——大名单
// 460KB/行；明细展开时按引用 id 拉 GET /security/ip-lists/:id）
const ipListEntryCache = ref<Map<number, Array<{ value: string; remark?: string }>>>(new Map())
// 富化名单视图 = 摘要列表 + 已拉取条目的覆盖层（attachStageDetails/trustPreview 消费）
const enrichedIpLists = computed(() => props.ipLists.map((l) =>
  ipListEntryCache.value.has(l.id) ? { ...l, entries: ipListEntryCache.value.get(l.id) } : l,
))
const customRules = ref<SecurityStageCustomRule[]>([])
const crsFiles = ref<CrsRuleFileOption[]>([])
const expandedPolicyKey = ref('')

const displayModel = computed<RuleStageModel | null>(() => {
  if (!props.model) return null
  if (!detailsAttached.value) return props.model
  return attachStageDetails(props.model, {
    policies: props.policies,
    ipLists: enrichedIpLists.value,
    sources: { fullPolicies: fullPolicies.value, customRules: customRules.value, crsFiles: crsFiles.value },
  })
})

// 阶段 0 卡与 1/2/3 同构恒出（未绑定信任策略=灰态「未启用」，面板显示未启用说明）
const stageZero = computed<StageGroup | undefined>(() => displayModel.value?.stages.find((s) => s.stage === 0 && s.enabled))
const typedStagePanels = computed<StageGroup[]>(() => (displayModel.value?.stages ?? []).filter((s) => s.stage !== 0))
const typedStageByKey = (key: string): StageGroup | undefined => typedStagePanels.value.find((s) => `stage${s.stage}` === key)

// 阶段 0 导航副标题按该规则 stage0 策略的实际模式聚合：全直通/全保留检测/混合
const stageZeroSubtitle = computed(() => {
  if (!stageZero.value) return ''
  const states = stageZero.value.groups.map((g) => props.policies.find((p) => p.id === g.key)?.trust_detection === true)
  if (states.every(Boolean)) return '保留检测记录'
  if (states.every((v) => !v)) return '直通上游'
  return '直通 + 保留检测'
})

// 阶段 0 概览：信任条目前两条预览（内联∪引用合并口径）
const trustPreview = (policyId: number): string => {
  const policy = props.policies.find((p) => p.id === policyId)
  if (!policy) return ''
  const entries = mergeIpEntries(enrichedIpLists.value, parseIPList(policy.ip_whitelist), parseRefIds(policy.ip_whitelist_refs))
  if (entries.length === 0) return ''
  const preview = entries.slice(0, 2).join('、')
  return entries.length > 2 ? `${preview} 等` : preview
}

const policyTypeOf = (policyId: number) =>
  inferPolicyType(props.policies.find((p) => p.id === policyId) ?? { has_ip_control: false, has_rate_limit: false, has_custom_rules: false })

const groupHasDetails = (group: StagePolicyGroup): boolean => {
  const d = group.details
  if (!d) return false
  return (d.aclInlineCount ?? 0) > 0 || (d.aclLists?.length ?? 0) > 0
    || (d.trustEntries?.length ?? 0) > 0
    || (d.geoipRegions?.length ?? 0) > 0
    || d.rateLimit !== undefined
    || (d.customRules?.length ?? 0) > 0
    || (d.crsGroups?.length ?? 0) > 0
}

const ensureDetails = async (): Promise<void> => {
  if (detailsAttached.value || detailLoading.value) return
  const seq = ++detailsSeq
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
    // 续体落地前校验会话序号：弹框已切换（onDialogOpen ++）或更新一次拉取已发起
    // 时丢弃过期结果，避免旧会话数据附着或抢置 detailsAttached
    if (seq !== detailsSeq) return
    if (policyRes.status === 'fulfilled') {
      fullPolicies.value = new Map((policyRes.value.data ?? []).map((p) => [p.id, p]))
    }
    if (customRes.status === 'fulfilled') customRules.value = customRes.value.data ?? []
    if (crsRes.status === 'fulfilled') crsFiles.value = crsRes.value.data?.rules ?? []
    // 引用名单条目：仅信任名单引用需条目值（阶段 0 明细逐条展示）；
    // ACL 明细为列表级汇总（名称+entry_count），不拉条目
    const refIds = new Set<number>()
    for (const pol of props.policies) {
      for (const id of parseRefIds(pol.ip_whitelist_refs)) refIds.add(id)
    }
    const missing = [...refIds].filter((id) => !ipListEntryCache.value.has(id))
    if (missing.length > 0) {
      const listRes = await Promise.allSettled(
        missing.map((id) => request.get<APIResponse<{ id: number; entries?: Array<{ value: string; remark?: string }> }>>(`/security/ip-lists/${id}`, { silent: true })),
      )
      if (seq !== detailsSeq) return
      const cache = new Map(ipListEntryCache.value)
      listRes.forEach((r, i) => {
        if (r.status === 'fulfilled' && r.value.data) cache.set(missing[i], r.value.data.entries ?? [])
      })
      ipListEntryCache.value = cache
    }
    // F-47-36：三端点全部 rejected 时不置 detailsAttached——原无条件置位会把弹框
    // 锁死在「明细按钮缺失且不可重试」且 silent 请求零反馈；保持可重试（下次点击
    // 重新拉取）并显式提示一次；部分成功仍置 attached（可用数据降级展示，保持现状语义）
    if (policyRes.status === 'rejected' && customRes.status === 'rejected' && crsRes.status === 'rejected') {
      ElMessage.warning('明细数据加载失败，可重试')
      return
    }
    detailsAttached.value = true
  } finally {
    // 失配会话不回落 detailLoading——现行会话（重置区或新一次拉取）自行管理该锁
    if (seq === detailsSeq) detailLoading.value = false
  }
}

const togglePolicyDetail = (stage: 0 | 1 | 2 | 3, policyId: number): void => {
  const key = `${stage}:${policyId}`
  expandedPolicyKey.value = expandedPolicyKey.value === key ? '' : key
}

const toggleNode = (key: string): void => {
  activeNode.value = key
  expandedPolicyKey.value = ''
  // 阶段面板首次选中触发明细拉取（接入/上游面板无明细）
  if (key.startsWith('stage')) void ensureDetails()
}

// 上游行状态：禁用优先；有逐上游快照按快照（healthy/degraded/unknown），无快照回落启用态口径。
// 「启用·待观测」：unknown = 尚无真实流量经该上游，被动熔断无样本可判——属数据可用性
// 而非健康异常（2026-09-21 用户问询口径）；触发过流量后被动熔断数据到位即转「健康/异常」。
// 参数取结构子集（host/port/enabled）——主上游表行与上游面板路由分发分组行共用
const upstreamStateText = (row: Pick<RuleFlowUpstream, 'host' | 'port' | 'enabled'>): string => {
  if (!row.enabled) return '禁用'
  const snapshot = props.target?.upstreamHealth?.[hostPortKey(row.host, row.port)]
  if (!snapshot || snapshot.unknown) return '启用·待观测'
  if (snapshot.degraded) return '降级'
  return snapshot.healthy ? '健康' : '异常'
}
const upstreamStateType = (row: Pick<RuleFlowUpstream, 'host' | 'port' | 'enabled'>): 'success' | 'warning' | 'danger' | 'info' => {
  if (!row.enabled) return 'info'
  const snapshot = props.target?.upstreamHealth?.[hostPortKey(row.host, row.port)]
  if (!snapshot || snapshot.unknown) return 'info'
  if (snapshot.degraded) return 'warning'
  return snapshot.healthy ? 'success' : 'danger'
}

// 自定义路由路径行辅助（上游面板路由分发明细分组共用）
const enabledPathUpstreams = (pr: RuleFlowPathRule): Array<{ host: string; port: number; enabled: boolean }> =>
  pr.upstreams.filter((u) => u.enabled)

// 权重 % 与 Rules.vue weightPercent 同口径（启用上游权重占比；禁用行与总和 ≤0 时 0）。
// Rules.vue 的 weightPercent 为视图内本地函数、共享 utils 归本批次其他归属文件，
// 此处同口径复刻，避免越界改动（F50-5）。
const upstreamWeightPercent = (upstreams: readonly RuleFlowUpstream[], row: RuleFlowUpstream): number => {
  if (upstreams.length === 0) return 0
  if (row.enabled === false) return 0
  const sum = upstreams.filter((u) => u.enabled !== false).reduce((s, u) => s + (u.weight || 0), 0)
  if (sum <= 0) return 0
  return Math.round(((row.weight || 0) / sum) * 100)
}
const pathMatchLabel = (matchType: string): string => (matchType === 'exact' ? '精确' : '前缀')

// 计数 chip：静默拉取（未到数不渲染 chip；绝不渲染加载态字面）；
const stageChip = (stage: 1 | 2 | 3): { chip?: string; caption?: string } => {
  if (!props.target?.caddyId || isTcp.value || !statsSettled.value) return {}
  if (!stats.value) return { chip: '—' }
  if (stage === 1) return { chip: `24h 拦截 ${stats.value.stage1_blocked_24h}` }
  if (stage === 2) return { chip: `429 拦截 ${stats.value.ratelimit_blocks_reload}`, caption: '自最近重载' }
  return { chip: `24h 拦截 ${stats.value.stage3_blocked_24h}` }
}

// 面板统计行：同样静默口径（无数据不占行，绝不渲染加载态文本）
const stageStatsText = (stage: 0 | 1 | 2 | 3): string => {
  if (stage === 0 || !props.target?.caddyId || isTcp.value || !statsSettled.value || !stats.value) return ''
  if (stage === 1) return `近 24 小时本阶段拦截 ${stats.value.stage1_blocked_24h} 次`
  if (stage === 2) return `自最近重载以来限流拦截 ${stats.value.ratelimit_blocks_reload} 次（恒 429）`
  return `近 24 小时本阶段拦截 ${stats.value.stage3_blocked_24h} 次`
}

interface FlowNode {
  key: string
  title: string
  subtitle: string
  tone: 'blue' | 'green' | 'primary' | 'orange' | 'red' | 'gray'
  icon: typeof Connection
  disabled?: boolean
  chip?: string
  chipCaption?: string
}

const flowNodes = computed<FlowNode[]>(() => {
  const target = props.target
  if (!target) return []
  const access: FlowNode = { key: 'access', title: '接入', subtitle: `${protocolLabel.value} · 端口 ${target.listenPort}`, tone: 'primary', icon: Connection }
  const upstream: FlowNode = { key: 'upstream', title: '上游', subtitle: target.upstreamSummary, tone: 'primary', icon: TopRight }
  if (isTcp.value) return [access, upstream]
  const nodes: FlowNode[] = [access]
  // 阶段 0 与 1/2/3 同构恒出：未绑定信任策略时灰态「未启用」（用户裁定 2026-09-21——
  // 流程图必须完整呈现五个环节，缺环节比灰态更误导）
  nodes.push({
    key: 'stage0',
    title: STAGE_TITLES[0],
    subtitle: stageZero.value ? stageZeroSubtitle.value : '未启用',
    tone: 'green',
    icon: CircleCheck,
    disabled: !stageZero.value,
  })
  for (const stage of typedStagePanels.value) {
    const stageNo = stage.stage as 1 | 2 | 3
    const { chip, caption } = stageChip(stageNo)
    nodes.push({
      key: `stage${stage.stage}`,
      title: STAGE_TITLES[stage.stage],
      subtitle: stage.enabled ? stageSub(stageNo) : '未启用',
      tone: stageNo === 1 ? 'blue' : stageNo === 2 ? 'orange' : 'red',
      icon: stageNo === 1 ? Key : stageNo === 2 ? Odometer : Aim,
      disabled: !stage.enabled,
      chip,
      chipCaption: caption,
    })
  }
  nodes.push(upstream)
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
  statsSettled.value = false
  certInfo.value = null
  certLoading.value = false
  // 明细缓存随弹框会话重置（规则绑定/策略内容可能已在页间变更）；序号自增使
  // 上一会话在途明细续体失配（修复 A→B 快速切换后 B 明细被 A 续体占死/残留）
  detailsSeq++
  detailLoading.value = false
  detailsAttached.value = false
  fullPolicies.value = new Map()
  customRules.value = []
  crsFiles.value = []
  const caddyId = props.target?.caddyId
  if (!caddyId) {
    statsSettled.value = true
    return
  }
  if (!isTcp.value) {
    const seq = ++statsSeq
    request.get<APIResponse<StageStats>>(`/security/rules/${encodeURIComponent(caddyId)}/stage-stats`, { silent: true })
      .then((res) => { if (seq === statsSeq) stats.value = res.data ?? null })
      .catch(() => { if (seq === statsSeq) stats.value = null })
      .finally(() => { if (seq === statsSeq) statsSettled.value = true })
  } else {
    statsSettled.value = true
  }
  // TLS 启用时拉取证书信息（接入卡富化）
  if (props.target?.enableTls && !isTcp.value) {
    const seq = ++certSeq
    certLoading.value = true
    request.get<APIResponse<FlowCertInfo>>(`/rules/${encodeURIComponent(caddyId)}/cert-info`, { silent: true })
      .then((res) => { if (seq === certSeq) certInfo.value = res.data ?? null })
      .catch(() => { if (seq === certSeq) certInfo.value = null })
      .finally(() => { if (seq === certSeq) certLoading.value = false })
  }
}
</script>

<style scoped>
.flow-header { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
.flow-header-title { font-size: 16px; font-weight: 600; color: #1f2937; }
.flow-header-name { font-size: 13px; color: #6b7280; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.flow-body { display: flex; flex-direction: column; gap: 0; }

/* ── 纵向时间线：图标圆点 + 阶段色阶 + 竖向连接线流动粒子 + 错峰进场 ── */
@keyframes tl-row-in {
  from { opacity: 0; transform: translateX(-8px); }
  to { opacity: 1; transform: none; }
}
@keyframes tl-flow-down {
  from { background-position-y: 0; }
  to { background-position-y: 12px; }
}
.tl-row { display: flex; align-items: stretch; gap: 12px; animation: tl-row-in 0.35s ease both; }
.tl-rail { display: flex; flex-direction: column; align-items: center; flex: 0 0 28px; }
.tl-dot {
  flex: 0 0 auto;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  box-shadow: 0 0 0 3px var(--el-color-primary-light-9);
}
.tl-dot--primary { background: var(--el-color-primary-dark-2); }
.tl-dot--green { background: var(--el-color-success); }
.tl-dot--blue { background: var(--el-color-primary); }
.tl-dot--orange { background: var(--el-color-warning); }
.tl-dot--red { background: var(--el-color-danger); }
.tl-dot--gray { background: var(--el-color-info); }
.tl-row.is-off .tl-dot { background: #c9cdd4; box-shadow: 0 0 0 3px #f3f4f6; }
.tl-line {
  flex: 1 1 auto;
  width: 2px;
  min-height: 12px;
  margin: 2px 0;
  background-image: repeating-linear-gradient(180deg, var(--el-color-primary) 0 3px, transparent 3px 12px);
  background-size: 2px 12px;
  animation: tl-flow-down 0.7s linear infinite;
}
.tl-card {
  flex: 1 1 auto;
  min-width: 0;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 3px;
  margin-bottom: 14px;
  padding: 10px 14px;
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  box-shadow: var(--el-box-shadow-light);
  cursor: pointer;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
  font-family: inherit;
  text-align: left;
}
.tl-card:hover { border-color: var(--el-color-primary-light-5); box-shadow: var(--el-box-shadow); }
.tl-card.is-active { border-color: var(--el-color-primary); box-shadow: 0 0 0 2px var(--el-color-primary-light-8); }
.tl-row.is-off .tl-card { background: #fafafa; box-shadow: none; }
.tl-row.is-off .tl-title,
.tl-row.is-off .tl-sub { color: #b1b5bd; }
.tl-card-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.tl-title { font-size: 14px; font-weight: 600; color: #1f2937; }
.tl-chip {
  font-style: normal;
  font-size: 11px;
  color: #1f6fbd;
  border-radius: 9px;
  padding: 1px 8px;
  white-space: nowrap;
}
.tl-chip-caption { font-style: normal; color: #9ca3af; margin-left: 4px; }
.tl-sub { font-size: 12px; color: #6b7280; }

/* 卡片+面板同列容器：面板展开时整行撑高，轨道连接线随之连续（用户报告：面板
   在行间时连接线断开——面板必须是行内成员才能让 flex 轨道线贯穿） */
.tl-main { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; }
/* 选中节点下方展开面板（与卡片同列，负顶边距吸收卡片下间距） */
.tl-panel { margin: -6px 0 14px 0; }

/* ── 信息区：定义列表双列栅格 + 字级层次 ── */
.flow-panel { border: 1px solid #ebeef5; border-radius: 8px; padding: 14px 18px; background: #fafafa; box-shadow: var(--el-box-shadow-lighter); }
.flow-panel-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.flow-panel-title { font-size: 14px; font-weight: 600; color: #1f2937; }
.flow-panel-stats { font-size: 12px; color: #1f6fbd; margin-bottom: 8px; }
.flow-kv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 8px 24px; }
.flow-kv { display: flex; align-items: baseline; gap: 12px; font-size: 13px; line-height: 1.8; min-width: 0; }
.flow-kv--wide { grid-column: 1 / -1; }
.flow-kv-label { color: #6b7280; flex: 0 0 72px; }
.flow-kv-value { color: #1f2937; overflow: hidden; text-overflow: ellipsis; }
.flow-kv-value.is-expired { color: var(--el-color-danger); }
.flow-domain-chip { margin: 0 6px 4px 0; }
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

/* ── 上游面板「路由分发」分组：「match(类型) → 启用上游列表(健康 tag)」行 ── */
.flow-route-row { display: flex; align-items: baseline; gap: 8px; font-size: 12px; line-height: 1.9; }
.flow-route-match { font-family: monospace; color: #1f2937; flex-shrink: 0; }
.flow-route-type { font-style: normal; font-family: inherit; color: #9ca3af; margin-left: 4px; }
.flow-route-arrow { color: #9ca3af; flex-shrink: 0; }
.flow-route-targets { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 12px; min-width: 0; }
.flow-route-target { display: inline-flex; align-items: center; gap: 4px; }
.flow-route-none { color: #9ca3af; }
.flow-route-group { margin-top: 12px; padding-top: 10px; border-top: 1px dashed #e5e7eb; }
.flow-route-group .flow-route-row + .flow-route-row { margin-top: 2px; }
.flow-route-group-head { display: flex; align-items: baseline; gap: 8px; margin-bottom: 2px; }
.flow-route-group-title { font-size: 13px; font-weight: 600; color: #4b5563; }
.flow-route-group-sub { font-size: 12px; color: #9ca3af; }

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
