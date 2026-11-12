<template>
  <el-dialog
    :model-value="modelValue"
    class="dialog-body-inset"
    @update:model-value="emit('update:modelValue', $event)"
    width="min(680px, 94vw)"
    top="5vh"
    append-to-body
    @close="emit('update:modelValue', false)"
  >
    <template #header>
      <DialogHeader :icon="Document" :title="t('common.app.views.trigDetail.title')" :subtitle="t('common.app.views.trigDetail.subtitle')" />
    </template>
    <div v-loading="loading">
      <!-- ① 命中概览：阶段 → 策略 → 命中源（一眼可读） -->
      <div class="trg-hero dialog-panel" :class="`trg-source--${kind}`">
        <DialogSectionHeader :title="t('common.app.views.trigDetail.overview')" />
        <div class="trg-hero-row">
          <!-- 规则协议徽标（数据源=event_type；字段缺失不显示——防御式）：
               TCP 青 = 全局 proto-tcp-tag 单源，HTTP 蓝 = el-tag primary -->
          <el-tag v-if="row?.event_type === 'tcp'" size="small" effect="plain" class="proto-tcp-tag trg-proto-tag">TCP</el-tag>
          <el-tag v-else-if="row?.event_type" size="small" type="primary" effect="plain" class="trg-proto-tag">HTTP</el-tag>
          <el-tag size="small" :type="sourceTagType" effect="dark">{{ categoryLabel }}</el-tag>
          <span class="trg-hero-stage">{{ heroStage }}</span>

          <!-- geoLabel 回退已移至 trg-hero-ip-row（归属地优先、区域清单兜底） -->
        </div>
        <div class="trg-hero-policy">
          <span class="trg-hero-policy-name">{{ policy?.name ?? (loading ? t('common.app.views.trigDetail.loading') : noPolicyAttribution ? t('common.app.views.trigDetail.noAttribution') : policyMissing ? t('common.app.views.trigDetail.policyDeletedParen') : t('common.app.views.trigDetail.policyUnavailableParen')) }}</span>
          <el-tag size="small" :type="policyStatusTag.type" effect="plain">
            {{ policyStatusTag.label }}
          </el-tag>
        </div>
        <div class="trg-hero-ip-row">
          <span class="trg-hero-ip">{{ row?.client_ip }}</span>
          <!-- 归属地优先展示；地域事件且归属地为空（xdb 未装）回退区域清单
               geoLabel（kind 门控，语义见 trg-hero-row 注释） -->
          <span v-if="row?.ip_location" class="trg-source-geo">{{ row.ip_location }}</span>
          <span v-else-if="kind === 'geo' && geoLabel" class="trg-source-geo">{{ geoLabel }}</span>
        </div>
        <div class="trg-hero-hit">{{ heroHitSource }}</div>
        <div v-if="row?.event_time" class="trg-hero-time">{{ t('common.app.views.trigDetail.eventTime', { time: formatTriggerTime(row.event_time) }) }}</div>
        <div class="trg-hero-meta">
          <span>{{ t('common.app.views.trigDetail.sourceIp', { ip: row?.client_ip }) }}</span>
          <span v-if="(row?.duration_us ?? 0) > 0"><template v-if="isWafFamily">{{ t('common.app.views.trigDetail.wafDuration', { total: formatDurationUs((row?.duration_us ?? 0) + (row?.precheck_us ?? 0)) }) }}<template v-if="(row?.precheck_us ?? 0) > 0">{{ t('common.app.views.trigDetail.wafDurationSplit', { precheck: formatDurationUs(row?.precheck_us), waf: formatDurationUs(row?.duration_us) }) }}</template></template><template v-else>{{ t('common.app.views.trigDetail.precheckDuration', { total: formatDurationUs(row?.duration_us ?? 0) }) }}</template></span>
          <el-tag size="small" :type="eventActionTone(row?.action, row?.rule_triggered)" effect="plain">
            {{ eventActionFull(row?.action, row?.rule_triggered) }}
          </el-tag>
          <span v-if="detectionNote">{{ detectionNote }}</span>
        </div>
      </div>

      <!-- ② 策略配置与命中明细（仅展示与本次触发相关的维度；零操作，处置在 IP 快捷弹框） -->
      <!-- 加载失败面：策略信息与名单条目分开呈现（依据不同：前者是配置，
           后者决定命中/豁免归因）。两者都可原地重取——弹框内不必关闭重开。 -->
      <div v-if="loadError" class="info-note-bar">
        <span class="info-note-desc">{{ t('common.app.views.trigDetail.policyLoadFailed') }}</span>
        <el-button size="small" type="primary" plain :loading="loading" @click="retryLists">{{ t('common.app.views.trigDetail.reload') }}</el-button>
      </div>
      <div v-if="entriesError && !loadError" class="info-note-bar">
        <span class="info-note-desc">{{ t('common.app.views.trigDetail.entriesLoadFailed') }}</span>
        <el-button size="small" type="primary" plain :loading="loading" @click="retryLists">{{ t('common.app.views.trigDetail.reload') }}</el-button>
      </div>
      <div class="trg-card dialog-panel">
        <DialogSectionHeader :title="t('common.app.views.trigDetail.policyConfig', { dimension: dimensionTitle })" />
        <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.currentConfig') }}</span><span>{{ relevantSummary }}</span></div>

        <!-- 命中的地址列表与内联名单（只读信息） -->
        <template v-if="kind === 'acl' || kind === 'geo' || kind === 'threat'">
          <div v-for="m in allHitLists" :key="m.id" class="trg-kv">
            <span class="k">{{ t('common.app.views.trigDetail.hitLists') }}</span>
            <span>{{ m.name }}<el-tag v-if="m.system" size="small" effect="plain" style="margin-left: 6px">{{ t('common.app.views.trigDetail.builtinReadonly') }}</el-tag></span>
          </div>
          <div v-if="inlineAclHit" class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.hitPosition') }}</span><span>{{ t('common.app.views.trigDetail.inlineAclList', { mode: policy?.ip_acl_mode === 'allow' ? t('common.app.views.trigDetail.sideWhite') : t('common.app.views.trigDetail.sideBlack') }) }}</span></div>
          <div v-if="trustHitNote" class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.trustExemption') }}</span><span>{{ trustHitNote }}</span></div>
          <div v-if="memberSystemTip" class="info-note-bar"><span class="info-note-desc">{{ memberSystemTip }}</span></div>
          <div v-if="allHitLists.length === 0 && !inlineAclHit && kind === 'acl' && !isAllowOutside && !loadError && !entriesError" class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.trigDetail.noHitListFound') }}</span></div>
        </template>

        <!-- 爬虫校验：验证结果与豁免引擎（v2.3.8 独立族，不再误标地域） -->
        <template v-else-if="kind === 'crawler'">
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.verdict') }}</span><span>{{ Number(row?.rule_triggered) >= 850000 ? t('common.app.views.trigDetail.crawlerSpoofVerdict') : t('common.app.views.trigDetail.crawlerVerifiedVerdict') }}</span></div>
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.exemptEngines') }}</span><span>{{ crawlerEngineIds.length > 0 ? crawlerEngineIds.join('、') : t('common.app.views.trigDetail.notConfigured') }}</span></div>
          <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.trigDetail.crawlerVerifyNote') }}</span></div>
        </template>

        <!-- 阶段 2 · CC 防护（人机挑战）：本次结果 + 策略配置（只读） -->
        <template v-else-if="kind === 'human'">
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ccResult') }}</span><el-tag size="small" :type="ccResultTone" effect="light">{{ ccResultText }}</el-tag></div>
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ccMode') }}</span><span>{{ ccModeText }}</span></div>
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ccType') }}</span><span>{{ ccTypeText }}</span></div>
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ccTtl') }}</span><span>{{ policy?.human_verify_ttl ? t('common.app.views.trigDetail.ccTtlValue', { ttl: policy.human_verify_ttl }) : '—' }}</span></div>
          <div v-if="policy?.cc_detect_enabled" class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ccSpike') }}</span><span>{{ t('common.app.views.trigDetail.ccSpikeValue', { n: policy.cc_rps_limit ?? 0, sec: policy.cc_rps_window ?? 0 }) }}</span></div>
          <div class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.trigDetail.ccNote') }}</span></div>
        </template>

        <!-- 信任名单：直通/保留检测语义说明 -->
        <template v-else-if="kind === 'trust'">
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.hitListName') }}</span><span>{{ trustHitListsText || t('common.app.views.trigDetail.trustInlineFallback') }}</span></div>
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.trustSemantics') }}</span><span>{{ trustModeText }}</span></div>
        </template>

        <!-- WAF · CRS：规则信息 + 源码折叠（只读） -->
        <template v-else-if="kind === 'waf-crs'">
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ruleId') }}</span><span>{{ row?.rule_triggered }}</span></div>
          <div class="trg-kv">
            <span class="k">{{ t('common.app.views.trigDetail.description') }}</span>
            <span v-if="crsIndexLoading">{{ t('common.app.views.trigDetail.loading') }}</span>
            <template v-else-if="crsEntry">{{ crsEntry.msg || t('common.app.views.trigDetail.noDescription') }}</template>
            <template v-else>—</template>
          </div>
          <div class="trg-kv">
            <span class="k">{{ t('common.app.views.trigDetail.fileCategory') }}</span>
            <span v-if="crsIndexLoading">{{ t('common.app.views.trigDetail.loading') }}</span>
            <template v-else-if="crsEntry">{{ crsEntry.file }} · {{ crsCategoryLabel(crsEntry.category) }}</template>
            <template v-else>—</template>
          </div>
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ruleMessage') }}</span><span>{{ row?.rule_msg || '—' }}</span></div>
          <div v-if="!crsIndexLoading && !crsEntry" class="info-note-bar" style="margin-top: 10px">
            <span class="info-note-desc">{{ crsIndexReady
              ? t('common.app.views.trigDetail.crsRemovedNote')
              : t('common.app.views.trigDetail.crsIndexFailed') }}</span>
          </div>
          <template v-if="crsEntry">
            <div class="crs-snippet-toggle" role="button" tabindex="0" :aria-expanded="crsSnippetExpanded" :aria-label="t('common.app.views.trigDetail.crsSnippetToggleAria')" @click="toggleCrsSnippet" @keydown.enter.prevent="activateOnce($event, toggleCrsSnippet)" @keydown.space.prevent="activateOnce($event, toggleCrsSnippet)">
              <el-icon class="crs-snippet-toggle-icon" :class="{ 'is-expanded': crsSnippetExpanded }"><ArrowRight /></el-icon>
              <span>{{ crsSnippetExpanded ? t('common.app.views.trigDetail.collapseSnippet') : t('common.app.views.trigDetail.expandSnippet') }}</span>
              <span class="crs-snippet-toggle-file">{{ t('common.app.views.trigDetail.snippetFileLine', { file: crsEntry.file, id: row?.rule_triggered }) }}</span>
            </div>
            <div v-if="crsSnippetExpanded" v-loading="crsSnippetLoading" class="crs-snippet-body">
              <SyntaxHighlight v-if="crsSnippet" :content="crsSnippet" language="apacheconf" />
              <div v-else-if="crsSnippetError" class="crs-snippet-empty">{{ t('common.app.views.trigDetail.snippetLoadFailed') }}</div>
              <div v-else-if="!crsSnippetLoading" class="crs-snippet-empty">{{ t('common.app.views.trigDetail.snippetNotFound') }}</div>
            </div>
          </template>
        </template>

        <!-- WAF · 自定义规则：规则完整明细 -->
        <template v-else-if="kind === 'waf-custom'">
          <template v-if="customRule">
            <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.ruleName') }}</span><span>{{ customRule.name }}</span></div>
            <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.conditionLogic') }}</span><span>{{ customRule.condition_logic === 'or' ? t('common.app.views.trigDetail.conditionOr') : t('common.app.views.trigDetail.conditionAnd') }}</span></div>
            <div class="trg-kv">
              <span class="k">{{ t('common.app.views.trigDetail.matchConditions') }}</span>
              <span>
                <div v-for="(c, i) in customConditions" :key="i" class="trg-cond">
                  {{ conditionTargetLabel(c.target, c.header_name) }} {{ c.operator }} <code>{{ c.pattern }}</code>
                </div>
                <span v-if="customConditions.length === 0">—</span>
              </span>
            </div>
            <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.actionLabel') }}</span><span>{{ customActionLabel }}</span></div>
            <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.status') }}</span><span>{{ customRule.enabled ? t('common.app.views.trigDetail.enabled') : t('common.app.views.trigDetail.disabled') }}</span></div>
          </template>
          <div v-else-if="!loading && customRuleLoadError" class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.trigDetail.customRuleLoadFailed') }}</span></div>
          <div v-else-if="!loading && customHasDbParent" class="info-note-bar"><span class="info-note-desc">{{ t('common.app.views.trigDetail.customRuleNotFound') }}</span></div>
          <div class="info-note-bar"><span class="info-note-desc">
            <template v-if="customHasDbParent">{{ t('common.app.views.trigDetail.customRuleEditHint', { id: customDisplayID }) }}</template>
            <template v-else>{{ t('common.app.views.trigDetail.legacySyntheticHint', { id: customDisplayID }) }}</template>
          </span></div>
        </template>

        <!-- 请求体异常 -->
        <template v-else-if="kind === 'body'">
          <div class="trg-kv"><span class="k">{{ t('common.app.views.trigDetail.noteLabel') }}</span><span>{{ t('common.app.views.trigDetail.bodyAnomalyNote') }}</span></div>
        </template>
      </div>

      <!-- 处置指引：IP 处置统一在快捷弹框（用户裁定） -->
      <div class="info-note-bar">
        <span class="info-note-desc">{{ t('common.app.views.trigDetail.ipActionHint') }}</span>
      </div>
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">{{ t('common.app.views.trigDetail.close') }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ArrowRight, Document } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { hasOwn } from '@/utils/hasOwn'
import { conditionTargetLabel } from '@/utils/customRuleLimits'
import { eventActionFull, eventActionTone } from '@/utils/eventAction'
import { parseIPList, parseRefIds, createIpMatcher, triggerStageFamily, customRuleEventDbID, sharedEntriesCache, subscribeSharedEntriesCache, ensureSharedEntries, missingSharedEntryIds, formatDurationUs, eventDetailRefIds, detectionModeExplains, isTrustExemptionCandidate, trustHitMode, isWafDurationFamily, extractCrsRuleSnippet, wafModeLabel } from '@/utils/securityStages'
import { issueCrsIndexSession, useCrsRuleIndex } from '@/composables/useCrsRuleIndex'
import { activateOnce } from '@/utils/keyboardActivate'
import { useCountryNamesCn, countryLabel } from '@/composables/useCountryNamesCn'
import type { APIResponse } from '@/types'
import { crsCategoryLabel } from '@/utils/crsCategories.ts'

// 历史（用户裁定）：统一触发详情弹框——全部触发类型（IP 黑白名单/地域/威胁
// 情报库/信任/WAF·CRS/WAF·自定义/请求体异常）共用同一风格与交互；信息优先，
// IP 处置动作收敛到 IP 快捷弹框（裁定：触发详情零操作，
// CRS 排除管理位于 安全防护 → 安全策略 → 策略编辑 → 排除规则）。
interface TriggerRow {
  id: number
  event_time?: string
  rule_caddy_id: string
  rule_name: string
  policy_id: number
  policy_name: string
  client_ip: string
  ip_location: string
  event_type: string
  rule_triggered: string
  rule_msg: string
  action: string
  duration_us?: number
  precheck_us?: number
}

const props = defineProps<{
  modelValue: boolean
  row: TriggerRow | null
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

// 词条键 common.app.views.trigDetail.*（母本由批次 D 集成落 locales views.ts）
const { t } = useI18n()

type Kind = 'acl' | 'geo' | 'crawler' | 'threat' | 'trust' | 'waf-crs' | 'waf-custom' | 'body' | 'human' | 'other'

// kind 改由共享 triggerStageFamily 投影（securityStages 唯一实现，原
// 双实现并存欠账）——细粒度族映射到本弹框展示 Kind（geoip→geo、
// threat→threat、wafCrs→waf-crs、wafCustom→waf-custom，其余同名）。
// 空 id 恒 other；存量 id 8 单独标为「地域拦截（旧 id）」，其余未匹配非空值兜底 acl。
const legacyGeo = computed(() => (props.row?.rule_triggered ?? '') === '8')

const kind = computed<Kind>(() => {
  // 局部名避开 i18n composer t（本文件多处经 t() 取词条）
  const triggered = props.row?.rule_triggered ?? ''
  if (!triggered) return 'other'
  if (legacyGeo.value) return 'geo'
  switch (triggerStageFamily(triggered)) {
    case 'trust': return 'trust'
    case 'ipAcl': return 'acl'
    case 'geoip': return 'geo'
    case 'crawler': return 'crawler'
    case 'threat': return 'threat'
    case 'wafCrs': return 'waf-crs'
    case 'wafCustom': return 'waf-custom'
    case 'body': return 'body'
    case 'human': return 'human'
    default: return 'acl'
  }
})

// （2026-10-03）：加和式仅 WAF 族——预检族（IP ACL/信任/
// GeoIP/威胁）duration_us≡precheck_us 同值（securityevents.go:202），加和
// 会翻倍并误标 WAF 段。族谓词单源 securityStages.isWafDurationFamily
//（与事件列表请求上下文弹框同一实现）。
const isWafFamily = computed(() => isWafDurationFamily(triggerStageFamily(props.row?.rule_triggered ?? '')))

const categoryLabel = computed(() => {
  if (legacyGeo.value) return t('common.app.views.trigDetail.categoryLegacyGeo')
  switch (kind.value) {
    case 'geo': return t('common.app.views.trigDetail.categoryGeo')
    case 'crawler': return t('common.app.views.trigDetail.categoryCrawler')
    case 'threat': return t('common.app.views.trigDetail.categoryThreat')
    case 'trust': return t('common.app.views.trigDetail.categoryTrust')
    case 'waf-crs': return t('common.app.views.trigDetail.categoryWafCrs')
    case 'waf-custom': return t('common.app.views.trigDetail.categoryWafCustom')
    case 'body': return t('common.app.views.trigDetail.categoryBody')
    // 人机挑战属阶段 2 · CC 防护（2026-11-12 四阶段）
    case 'human': return t('common.app.views.trigDetail.stageHuman')
    default: return t('common.app.views.trigDetail.categoryAcl')
  }
})
const sourceTagType = computed(() =>
  kind.value === 'geo' ? 'warning'
    : kind.value === 'crawler' ? 'info'
      : kind.value === 'threat' || kind.value === 'waf-crs' ? 'danger'
        : kind.value === 'trust' ? 'success'
          : kind.value === 'waf-custom' || kind.value === 'acl' ? 'danger' : 'info')

// 命中概览（用户裁定：一眼可读）——阶段名 / 命中源
const formatTriggerTime = (v: string): string => formatDate(v)

// 组合语义说明：logged 事件的「为什么不拦」——检测模式策略 或
// 信任保留检测（含跨策略豁免：预检 DetectionOnly 为事务级全局，命中策略与
// 豁免信任策略可以是两条不同策略——「黑名单命中但被另一策略的信任放行为检测」）。
const exemptingTrustPolicy = computed<string | null>(() => ipHitScan.value.exemptingPolicy)
const detectionNote = computed<string>(() => {
  if (!props.row || props.row.action === 'blocked') return ''
  if (kind.value === 'trust') return ''
  // 检测模式的 DetectionOnly 切换只覆盖 WAF 段（CRS/自定义含 body
  // 目标）——阶段 1 族（IP ACL/地域/威胁/爬虫）的 logged 与模式无关，成因是
  // 信任保留检测，不能归因「检测模式」。
  if (detectionModeExplains(kind.value) && policy.value?.mode === 'detection') return t('common.app.views.trigDetail.detectionModeNote')
  if (exemptingTrustPolicy.value) return t('common.app.views.trigDetail.trustExemptNote', { policy: exemptingTrustPolicy.value })
  return ''
})

const heroStage = computed(() => {
  if (legacyGeo.value) return t('common.app.views.trigDetail.stageLegacyGeo')
  switch (kind.value) {
    case 'trust': return t('common.app.views.trigDetail.stageTrust')
    case 'acl': return t('common.app.views.trigDetail.stageAcl')
    case 'geo': return t('common.app.views.trigDetail.stageGeo')
    case 'crawler': return t('common.app.views.trigDetail.stageCrawler')
    case 'threat': return t('common.app.views.trigDetail.stageThreat')
    case 'waf-crs': case 'waf-custom': return t('common.app.views.trigDetail.stageWaf')
    // 人机挑战属阶段 2 · CC 防护（2026-11-12 四阶段）
    case 'human': return t('common.app.views.trigDetail.stageHuman')
    case 'body': return t('common.app.views.trigDetail.stageBody')
    default: return t('common.app.views.trigDetail.stageDefault')
  }
})
const dimensionTitle = computed(() => {
  if (legacyGeo.value) return t('common.app.views.trigDetail.categoryLegacyGeo')
  switch (kind.value) {
    case 'trust': return t('common.app.views.trigDetail.categoryTrust')
    case 'acl': return t('common.app.views.trigDetail.categoryAcl')
    case 'geo': return t('common.app.views.trigDetail.categoryGeo')
    case 'crawler': return t('common.app.views.trigDetail.dimCrawler')
    case 'threat': return t('common.app.views.trigDetail.categoryThreat')
    case 'waf-crs': case 'waf-custom': return t('common.app.views.trigDetail.dimWaf')
    case 'human': return t('common.app.views.trigDetail.dimHuman')
    case 'body': return t('common.app.views.trigDetail.dimBody')
    default: return t('common.app.views.trigDetail.categoryAcl')
  }
})
// 相关维度配置摘要：只展示与本次触发相关的维度
const relevantSummary = computed(() => {
  switch (kind.value) {
    case 'trust': return trustSummary.value
    case 'geo': return geoSummary.value
    case 'crawler': return crawlerSummary.value
    case 'threat': return t('common.app.views.trigDetail.threatRefSummary', { summary: aclSummary.value })
    case 'waf-crs': case 'waf-custom': return wafSummary.value
    case 'body': return '—'
    default: return aclSummary.value
  }
})

// 命中源：具体到规则或地址列表（用户裁定：一眼看出触发了哪条规则/哪个列表）
const heroHitSource = computed(() => {
  const ev = props.row
  if (!ev) return '—'
  switch (kind.value) {
    case 'human':
      // 挑战是独立结果：命中源直接给出本次结果，避免「id:human_challenge」
      // 这类内部标识出现在读者面前。
      return t('common.app.views.trigDetail.heroHumanHit', { result: ccResultText.value })
    case 'acl': {
      if (isAllowOutside.value) return t('common.app.views.trigDetail.allowOutsideNote')
      if (inlineAclHit.value) {
        const mode = policy.value?.ip_acl_mode === 'allow' ? t('common.app.views.trigDetail.sideWhite') : t('common.app.views.trigDetail.sideBlack')
        return t('common.app.views.trigDetail.heroInlineAcl', { mode, id: ev.rule_triggered })
      }
      if (allHitLists.value.length > 0) {
        return allHitLists.value.map((m) => t('common.app.views.trigDetail.heroListHit', { name: m.name }) + (m.system ? t('common.app.views.trigDetail.builtinSuffix') : '')).join('、')
      }
      if (ev.rule_triggered === '4') return t('common.app.views.trigDetail.legacyBlacklistField') + (ev.rule_name ? ` · ${ev.rule_name}` : '')
      return t('common.app.views.trigDetail.ruleIdBase', { id: ev.rule_triggered }) + (ev.rule_name ? ` · ${ev.rule_name}` : '')
    }
    case 'geo':
      return t('common.app.views.trigDetail.heroGeoRule', { id: ev.rule_triggered, region: geoLabel.value || t('common.app.views.trigDetail.unknownRegion') })
    case 'crawler': {
      // 810000-849999 = 已验证爬虫豁免（放行）；850000-899999 = 爬虫伪装拦截
      const n = Number(ev.rule_triggered)
      if (n >= 850000) return t('common.app.views.trigDetail.heroCrawlerSpoof', { id: ev.rule_triggered })
      return t('common.app.views.trigDetail.heroCrawlerVerified', { id: ev.rule_triggered })
    }
    case 'threat': {
      const names = allHitLists.value.filter((l) => l.system).map((l) => `「${l.name}」`)
      return names.length > 0
        ? t('common.app.views.trigDetail.heroThreatLists', { lists: names.join('、') })
        : t('common.app.views.trigDetail.heroThreatPrecheck', { id: ev.rule_triggered })
    }
    case 'trust': {
      // 局部名避开 i18n composer t
      const trustNames = trustHitListsText.value
      return trustNames ? t('common.app.views.trigDetail.heroTrustLists', { lists: trustNames }) : t('common.app.views.trigDetail.heroTrustInline')
    }
    case 'waf-crs':
      return t('common.app.views.trigDetail.heroCrsRule', { id: ev.rule_triggered }) + (crsEntry.value?.msg ? ` · ${crsEntry.value.msg}` : '')
    case 'waf-custom':
      return customRule.value
        ? t('common.app.views.trigDetail.heroCustomRule', { name: customRule.value.name })
        : t('common.app.views.trigDetail.heroCustomRuleId', { id: customDisplayID.value })
    case 'body':
      return t('common.app.views.trigDetail.heroBodyParseFail')
    default:
      return t('common.app.views.trigDetail.ruleIdBase', { id: ev.rule_triggered })
  }
})

// —— 策略与地址列表装载（直取策略详情，禁用/删除态可见）——
const loading = ref(false)
const policyMissing = ref(false)
const loadError = ref(false)
// 名单条目加载失败态：ensureSharedEntries 对单名单失败保持「未缓存」且不抛出，
// 故失败信号只能按「引用名单是否全部落地」判定。不显性化时条目缺失会被渲染成
// 「未定位到命中的地址列表」的业务结论（与真实未命中无法区分）——与 IP 处置
// 弹框的 listsError 同口径：横幅 + 重试，「未定位」结论在失败态不可达。
const entriesError = ref(false)
// policy_id<=0 是后端归因的合法「无策略归属」态（规则未绑定策略时
// securityevents.go 返回 (0, "")），不是「策略已删除」——文案分离。
const noPolicyAttribution = computed(() => (props.row?.policy_id ?? 0) <= 0)
// hero 状态标签四态：加载/无归属/已删除/加载失败 不得都显示「已禁用」
// （「已禁用」会被读成「策略存在但关闭」，与同屏「策略已删除/信息不可用」矛盾）。
const policyStatusTag = computed<{ label: string; type: 'success' | 'info' }>(() => {
  if (loading.value) return { label: '…', type: 'info' }
  if (!policy.value) {
    if (noPolicyAttribution.value) return { label: '—', type: 'info' }
    if (policyMissing.value) return { label: t('common.app.views.trigDetail.statusPolicyDeleted'), type: 'info' }
    return { label: t('common.app.views.trigDetail.statusUnknown'), type: 'info' }
  }
  return policy.value.enabled
    ? { label: t('common.app.views.trigDetail.statusEnabled'), type: 'success' }
    : { label: t('common.app.views.trigDetail.statusDisabled'), type: 'info' }
})
// 弹框会话序号：快速关开换行时丢弃在途响应（同文件 crsDialogSeq
// / IPLocationAction loadPoliciesSeq 同仓模式）
let loadSeq = 0
interface PolicyRow {
  id: number
  name: string
  enabled: boolean
  policy_type?: string
  mode?: string
  anomaly_threshold?: number
  ip_acl_enabled?: boolean
  ip_acl_mode?: string
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_whitelist?: string
  ip_whitelist_enabled?: boolean
  ip_whitelist_refs?: string
  ip_blacklist?: string
  geoip_mode?: string
  geoip_countries?: string
  crs_rule_groups?: string
  custom_rules?: string
  trust_detection?: boolean
  geoip_crawler_exempt?: boolean
  geoip_crawler_engines?: string
  human_verify_mode?: string
  human_verify_type?: string
  human_verify_ttl?: number
  cc_detect_enabled?: boolean
  cc_rps_limit?: number
  cc_rps_window?: number
}
const policy = ref<PolicyRow | null>(null)
// CC 防护（人机挑战）明细：结果由规则 id 区分（human_challenge/pass/failed）。
const ccResultText = computed(() => {
  const rule = props.row?.rule_triggered ?? ''
  if (rule === 'human_pass') return t('common.app.views.trigDetail.ccResultPass')
  if (rule === 'human_failed') return t('common.app.views.trigDetail.ccResultFail')
  return t('common.app.views.trigDetail.ccResultChallenge')
})
const ccResultTone = computed<'info' | 'success' | 'danger'>(() => {
  const rule = props.row?.rule_triggered ?? ''
  if (rule === 'human_pass') return 'success'
  if (rule === 'human_failed') return 'danger'
  return 'info'
})
const ccModeText = computed(() => {
  const mode = policy.value?.human_verify_mode ?? 'off'
  if (mode === 'force') return t('common.app.views.trigDetail.ccModeForce')
  if (mode === 'auto') return t('common.app.views.trigDetail.ccModeAuto')
  return t('common.app.views.trigDetail.ccModeOff')
})
const ccTypeText = computed(() => (policy.value?.human_verify_type === 'js'
  ? t('common.app.views.trigDetail.ccTypeJs')
  : t('common.app.views.trigDetail.ccTypeSlider')))
// 全部启用策略（追加修复：跨策略信任豁免判定——预检 DetectionOnly
// 为事务级全局，命中策略与豁免信任策略可以是两条不同策略）
const enabledPolicies = ref<PolicyRow[]>([])
const lists = ref<Array<{ id: number; name: string; system?: number | boolean }>>([])
// 跨组件共享条目缓存（修复：提升到 securityStages 模块级，
// IPLocationAction 写入动作经 invalidateSharedEntriesCache 清空——原实现
// 缓存在本组件 setup 内，快捷弹框的 onChanged 清不到它导致展示恒陈旧）
const entriesCache = ref<Record<number, string[]>>({ ...sharedEntriesCache })
// 共享缓存失效即重拷本地副本（叠开 IP 处置改名单后徽标/列表即时
// 刷新——曾仅 loadAll 重拷，开放窗口滞留旧值）
let unregisterEntriesCache: (() => void) | null = null
onMounted(() => {
  unregisterEntriesCache = subscribeSharedEntriesCache(() => {
    entriesCache.value = { ...sharedEntriesCache }
  })
})
onUnmounted(() => {
  unregisterEntriesCache?.()
  unregisterEntriesCache = null
})

const loadAll = async (): Promise<void> => {
  const row = props.row
  if (!row) return
  const seq = ++loadSeq
  loading.value = true
  policyMissing.value = false
  loadError.value = false
  entriesError.value = false
  policy.value = null
  enabledPolicies.value = []
  lists.value = []
  entriesCache.value = { ...sharedEntriesCache } // 从共享缓存起步，只补拉缺失
  try {
    if (row.policy_id > 0) {
      try {
        const res = await request.get<APIResponse<{ policy: PolicyRow }>>(`/security/policies/${row.policy_id}`, { silent: true })
        if (seq !== loadSeq) return // 首个 await 同样需竞态守卫
        policy.value = res.data?.policy ?? null
        if (!res.data?.policy) policyMissing.value = true
      } catch (err) {
        if (seq !== loadSeq) return // 会话已被新一代接管：不得把旧会话失败写进新会话
        // 网络/5xx 与「策略已删除」不可混同——404 归缺失，
        // 其余按加载失败提示（hero 不误标「已删除」）。
        policyMissing.value = err instanceof Error && 'status' in err && (err as { status?: number }).status === 404
        if (!policyMissing.value) loadError.value = true
      }
    } else {
      // policy_id<=0 = 无策略归属（合法态），展示文案由 noPolicyAttribution 承载，
      // 不归入「策略已删除」
    }
    // 全部启用策略 + 名单/条目：ACL 与信任 refs 的条目缓存（信息展示用 +
    // 跨策略信任成员判定——历史追加修复）
    // 预取面按事件类别/动作收敛（详见 eventDetailRefIds 注释）：
    //  - 豁免归因只在未拦截事件需要（blocked 事件不会由信任放行）；
    //  - ACL 条目只被 kind∈{acl,geo,threat} 消费，WAF/请求体/爬虫事件引用
    //    威胁库时曾每次无谓下载数百 KB~数 MB。
    const needExemption = row.action !== 'blocked'
    const needAclEntries = kind.value === 'acl' || kind.value === 'geo' || kind.value === 'threat'
    const needOwnerTrust = needAclEntries || kind.value === 'trust' || needExemption
    const [polRes, listRes] = await Promise.allSettled([
      needExemption
        ? request.get<APIResponse<PolicyRow[]>>('/security/policies?enabled=true', { silent: true })
        : Promise.resolve<APIResponse<PolicyRow[]>>({ code: 0, data: [] }),
      request.get<APIResponse<Array<{ id: number; name: string; system?: number | boolean }>>>('/security/ip-lists', { silent: true }),
    ])
    if (seq !== loadSeq) return
    if (polRes.status === 'fulfilled') enabledPolicies.value = polRes.value.data || []
    else loadError.value = true
    if (listRes.status === 'fulfilled') lists.value = listRes.value.data || []
    else {
      loadError.value = true
      lists.value = []
    }
    // 只补拉详情弹框真实消费的名单——范围由类别/动作决定。
    const refIds = eventDetailRefIds(policy.value, enabledPolicies.value, {
      ownerAcl: needAclEntries,
      ownerTrust: needOwnerTrust,
      otherTrust: needExemption,
    })
    // 只补拉共享缓存缺失的名单：原实现对全部 refIds 无条件
    // 并发 GET——连续打开事件详情时同一批名单反复下载。写回/通知由缓存单源负责。
    // ensureSharedEntries 对单名单失败保持「未缓存」且不抛出（下次调用可重试）——
    // 失败信号只能按「引用名单是否全部落地」判定，否则条目缺失会退化成
    // 「未命中名单」的业务结论（不能伪装成业务结论）。
    await ensureSharedEntries(refIds, async (id) => {
      const res = await request.get<APIResponse<{ id: number; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`, { silent: true })
      return (res.data?.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
    })
    if (seq !== loadSeq) return
    entriesError.value = missingSharedEntryIds(refIds).length > 0
    entriesCache.value = { ...sharedEntriesCache }
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

// 加载失败横幅的重试入口：策略/名单/条目同轮重取（loadAll 内含会话竞态守卫）
const retryLists = (): void => { void loadAll() }

// 区域清单展示层翻译——country_names_cn 单源映射，未命中
// （省份/省市联值/海外哨兵）回退原文；geoip_countries 值零改动。
const countryZh = useCountryNamesCn()
const geoLabel = computed(() => {
  try {
    const zh = countryZh.value
    return ((JSON.parse(policy.value?.geoip_countries ?? '[]') as string[]) || []).filter(Boolean).map((r) => countryLabel(zh, r)).join('、')
  } catch {
    return ''
  }
})

// 各名单摘要（与策略向导口径一致）
const listSummary = (inline: string | undefined, refs: string | undefined): string => {
  const inlineCount = parseIPList(inline).length
  const refIds = parseRefIds(refs)
  const names = lists.value.filter((l) => refIds.includes(l.id)).map((l) => l.name)
  return t('common.app.views.trigDetail.inlineCount', { count: inlineCount }) + (names.length > 0 ? t('common.app.views.trigDetail.refListsSuffix', { names: names.join('、') }) : '')
}
const aclSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (!p.ip_acl_enabled) return t('common.app.views.trigDetail.notEnabled')
  const mode = p.ip_acl_mode === 'allow'
    ? t('common.app.views.trigDetail.modeAllow')
    : p.ip_acl_mode === '绕过' ? t('common.app.views.trigDetail.modeBypass') : t('common.app.views.trigDetail.modeDeny')
  return `${mode} · ${listSummary(p.ip_acl_list, p.ip_acl_list_refs)}`
})
const trustSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (!p.ip_whitelist_enabled) return t('common.app.views.trigDetail.notEnabled')
  return listSummary(p.ip_whitelist, p.ip_whitelist_refs)
})
const geoSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (!p.geoip_mode || p.geoip_mode === 'off') return t('common.app.views.trigDetail.notEnabled')
  return t('common.app.views.trigDetail.geoScope', {
    mode: p.geoip_mode === 'allow' ? t('common.app.views.trigDetail.geoModeAllow') : t('common.app.views.trigDetail.geoModeBlock'),
    region: geoLabel.value || '—',
  })
})
// 爬虫豁免维度：事件来自 v2.3.8 爬虫两族，展示本策略的豁免引擎
const crawlerEngineIds = computed<string[]>(() => {
  try {
    const raw = JSON.parse(policy.value?.geoip_crawler_engines ?? '[]') as unknown
    return Array.isArray(raw) ? raw.filter((v): v is string => typeof v === 'string' && v !== '') : []
  } catch {
    return []
  }
})
const crawlerSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (p.geoip_crawler_exempt !== true) return t('common.app.views.trigDetail.crawlerExemptOff')
  const engines = crawlerEngineIds.value.length > 0 ? `（${crawlerEngineIds.value.join('、')}）` : ''
  return t('common.app.views.trigDetail.crawlerExemptOn', { count: crawlerEngineIds.value.length }) + engines
})
const wafSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  // 模式词取 securityStages.WAF_MODE_TEXT 单源（与策略列表摘要/流程投影同词）
  const mode = wafModeLabel(p.mode) || '—'
  let groups = ''
  try {
    const g = (JSON.parse(p.crs_rule_groups ?? '[]') as string[]) || []
    if (p.mode !== 'off' && p.mode !== 'custom_only' && g.length > 0) groups = t('common.app.views.trigDetail.crsGroupsSuffix', { count: g.length })
  } catch { /* 畸形按无组处理 */ }
  let custom = ''
  try {
    const c = (JSON.parse(p.custom_rules ?? '[]') as string[]) || []
    if ((p.mode === 'custom_only' || p.mode === 'blocking') && c.length > 0) custom = t('common.app.views.trigDetail.customRulesSuffix', { count: c.length })
  } catch { /* 畸形按无规则处理 */ }
  return `${mode}${groups}${custom}`
})

// —— 来源语义行 ——

// —— ACL/威胁/信任命中明细（只读信息） ——
// 全部命中列表（补漏1）：自定义 + 内置威胁名单（只读展示名单名，
// 原实现只对自定义列表出「命中列表」行、内置名单仅泛化 tip——同一 IP 同时
// 命中 测试列表+中科大恶意IP名单 时内置侧不可见）。
// 单次扫描产出全部命中结论（FE 性能收敛）：此前 allHitLists/inlineAclHit/
// trustHitListsText/trustHitNote/memberSystemTip/exemptingTrustPolicy 各自整表
// 扫描且每个 CIDR 条目即时重解析。此处 IP 预解析一次（createIpMatcher）、
// 每个名单只判定一次（hitById 记忆化），六个消费方共享同一次遍历。
// CIDR 感知匹配是历史用户验收口径——威胁库条目为 CIDR（如 45.148.10.0/24），
// 精确串匹配漏报导致「未定位到命中的地址列表」误显。
const ipHitScan = computed(() => {
  const p = policy.value
  const ip = props.row?.client_ip.trim() ?? ''
  const empty = {
    aclHit: [] as Array<{ id: number; name: string; system?: number | boolean }>,
    trustHit: [] as Array<{ id: number; name: string; system?: number | boolean }>,
    inlineAcl: false,
    ownerTrust: false,
    sysAclHit: false,
    exemptingPolicy: null as string | null,
  }
  if (!ip) return empty
  const matcher = createIpMatcher(ip)
  const hitById = new Map<number, boolean>()
  const listHit = (id: number): boolean => {
    const cached = hitById.get(id)
    if (cached !== undefined) return cached
    const hit = (entriesCache.value[id] ?? []).some(matcher)
    hitById.set(id, hit)
    return hit
  }
  // 属主策略详情可能缺失（已删除/瞬时失败）：命中明细退化为空，但跨策略豁免
  // 归因仍须基于已取回的启用策略集给出——故不做 `!p` 早退（否则历史事件只剩
  // 「已记录」而丢失「为何不拦」）。
  const aclRefs = p ? parseRefIds(p.ip_acl_list_refs) : []
  const trustRefs = p ? parseRefIds(p.ip_whitelist_refs) : []
  const aclHit = p ? lists.value.filter((l) => aclRefs.includes(l.id) && listHit(l.id)) : []
  const trustHit = p ? lists.value.filter((l) => trustRefs.includes(l.id) && listHit(l.id)) : []
  const inlineAcl = p ? parseIPList(p.ip_acl_list).some(matcher) : false
  // 信任已关闭时条目不生效（trustDead 同口径）
  const ownerTrust = !p || p.ip_whitelist_enabled === false
    ? false
    : parseIPList(p.ip_whitelist).some(matcher) || trustRefs.some((id) => listHit(id))
  // 跨策略信任豁免归因：策略详情端点不过滤 enabled——属主策略可能事后被禁用，
  // 禁用策略不渲染、不可能放行，不得参与豁免归因（判定单源 isTrustExemptionCandidate）。
  let exemptingPolicy: string | null = null
  if (props.row && props.row.action !== 'blocked') {
    for (const candidate of [p, ...enabledPolicies.value].filter((x): x is PolicyRow => !!x && isTrustExemptionCandidate(x))) {
      if (parseIPList(candidate.ip_whitelist).some(matcher)) { exemptingPolicy = candidate.name; break }
      if (parseRefIds(candidate.ip_whitelist_refs).some((id) => listHit(id))) { exemptingPolicy = candidate.name; break }
    }
  }
  return { aclHit, trustHit, inlineAcl, ownerTrust, sysAclHit: aclHit.some((l) => l.system), exemptingPolicy }
})
const allHitLists = computed(() => ipHitScan.value.aclHit)
// 白名单外拒绝形态（补漏2）：id:7 = allow 交集外（security.go
// ipPrecheckAllowRuleID）——IP 不在任何名单中，「命中列表」恒空是正确语义，
// 须显式说明而非「未定位到」。id:5 不在此列：它是绕过模式占用 id:3 时的
// 信任名单并集（归信任族，见 triggerStageFamily）。
const isAllowOutside = computed(() => {
  const n = Number(props.row?.rule_triggered)
  return kind.value === 'acl' && n === 7
})

const inlineAclHit = computed(() => ipHitScan.value.inlineAcl)
const trustHitListsText = computed(() => ipHitScan.value.trustHit.map((l) => l.name).join('、'))
const trustHitNote = computed(() => {
  if (!policy.value || kind.value === 'trust') return ''
  return ipHitScan.value.ownerTrust ? t('common.app.views.trigDetail.ownerTrustNote') : ''
})
// 信任命中语义按策略类型单源（非阶段 0 存量信任引擎恒 DetectionOnly）；
// 文案随类型分流：stage0 跳过全部安全阶段（独立轻量检测事务记录），mixed
// 等其他类型为引擎内检测降级、不跳段（与 stage1FootnoteText 同口径）。
const trustModeText = computed(() => trustHitMode(policy.value?.policy_type, policy.value?.trust_detection) === 'detection'
  ? (policy.value?.policy_type !== undefined && policy.value.policy_type !== 'stage0'
    ? t('common.app.views.trigDetail.trustDetectionInline')
    : t('common.app.views.trigDetail.trustDetectionStage0'))
  : t('common.app.views.trigDetail.trustPassthrough'))
const memberSystemTip = computed(() =>
  policy.value && ipHitScan.value.sysAclHit ? t('common.app.views.trigDetail.memberSystemTip') : ''
)

// —— WAF · 自定义规则明细 ——
interface CustomRule {
  id: number
  name: string
  description: string
  action: string
  score?: number
  enabled: boolean
  condition_logic?: 'and' | 'or'
  conditions?: Array<{ target: string; operator: string; pattern: string; header_name?: string }>
}
const customRule = ref<CustomRule | null>(null)
const customDbId = computed(() => customRuleEventDbID(props.row?.rule_triggered ?? ''))
const customHasDbParent = computed(() => Number.isFinite(customDbId.value))
const customDisplayID = computed(() => customHasDbParent.value ? String(customDbId.value) : (props.row?.rule_triggered || '—'))
// 后端合法动作仅 block/log/pass（score 为不可达映射，已删）
const customActionLabel = computed(() => {
  const a = customRule.value?.action ?? ''
  // 查表过 hasOwn：动作来自库值，原型键命中原生函数会渲染成源码文本，
  // 「未知值回显原文」的兜底形同失效。词条值调用点现取（不入模块快照）。
  const labels: Record<string, string> = {
    block: t('common.app.views.trigDetail.actionBlock'),
    log: t('common.app.views.trigDetail.actionLog'),
    pass: t('common.app.views.trigDetail.actionPass'),
  }
  return hasOwn(labels, a) ? labels[a] : a
})
const customConditions = computed<Array<{ target: string; operator: string; pattern: string; header_name?: string }>>(() => {
  // 后端列表接口 conditions 已是结构化数组（非 JSON 字符串）
  return (customRule.value?.conditions ?? []).filter((c) => !!c && typeof c.target === 'string')
})
// 补会话序号守卫(同 crsDialogSeq 范式)+try/catch——
// 快速关开弹框时在途响应晚到不再覆盖当前;加载失败不再误标「规则已删除」。
// 纯计数器无响应式消费，用普通变量（与同文件 loadSeq/crsDialogSeq 一致）。
let customRuleSeq = 0
const customRuleLoadError = ref(false)
const loadCustomRule = async (): Promise<void> => {
  customRule.value = null
  customRuleLoadError.value = false
  if (!customHasDbParent.value) return
  const seq = ++customRuleSeq
  try {
    const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules', { silent: true })
    if (seq !== customRuleSeq) return
    customRule.value = (res.data || []).find((r) => r.id === customDbId.value) ?? null
  } catch {
    if (seq !== customRuleSeq) return
    customRuleLoadError.value = true
  }
}

// —— WAF · CRS：索引 + 源码片段 + 快捷排除（自 SecurityEvents CRS 弹框整体迁入）——
const { loading: crsIndexLoading, loaded: crsIndexReady, byId: crsIndexById, ensureForDialog: ensureCrsRuleIndex } = useCrsRuleIndex()
let crsDialogSeq = 0

const crsEntry = computed(() => (props.row ? crsIndexById.value.get(props.row.rule_triggered) ?? null : null))

// 源码片段状态（只读展示；展开时按需拉取）
const crsSnippet = ref('')
const crsSnippetLoading = ref(false)
const crsSnippetExpanded = ref(false)
const crsSnippetFetched = ref(false)
const crsSnippetError = ref(false)
// 弹框会话序号：关闭/重开丢弃在途的索引与源码返回

const toggleCrsSnippet = async (): Promise<void> => {
  crsSnippetExpanded.value = !crsSnippetExpanded.value
  const ev = props.row
  const entry = ev ? crsIndexById.value.get(ev.rule_triggered) : null
  if (!crsSnippetExpanded.value || !ev || !entry?.file || crsSnippetFetched.value) return
  const seq = crsDialogSeq
  crsSnippetFetched.value = true
  crsSnippetError.value = false
  crsSnippetLoading.value = true
  try {
    const res = await request.get<APIResponse<{ content: string }>>(`/security/crs/rules/${encodeURIComponent(entry.file)}`)
    if (seq !== crsDialogSeq) return
    crsSnippet.value = extractCrsRuleSnippet(res.data?.content || '', ev.rule_triggered)
  } catch {
    if (seq !== crsDialogSeq) return
    crsSnippet.value = ''
    crsSnippetFetched.value = false
    crsSnippetError.value = true
  } finally {
    if (seq === crsDialogSeq) crsSnippetLoading.value = false
  }
}

// —— 装载编排 ——
watch(() => props.modelValue, (v) => {
  if (!v) return
  void loadAll()
  if (kind.value === 'waf-crs') {
    const seq = (crsDialogSeq = issueCrsIndexSession())
    crsSnippet.value = ''
    crsSnippetLoading.value = false
    crsSnippetExpanded.value = false
    crsSnippetFetched.value = false
    crsSnippetError.value = false
    void ensureCrsRuleIndex(seq)
  }
  if (kind.value === 'waf-custom') void loadCustomRule()
})
</script>

<style scoped>
/* ① 命中概览：共享面板承载布局，类型着色仅覆盖边框与底色 */
.trg-hero-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.trg-hero-stage { font-weight: 700; font-size: 14px; }
.trg-hero-ip-row { display: flex; align-items: baseline; gap: 8px; margin-top: 6px; min-width: 0; flex-wrap: wrap; }
.trg-hero-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 700; overflow-wrap: anywhere; }
.trg-hero-policy { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.trg-hero-policy-name { font-weight: 600; font-size: 13px; }
.trg-hero-hit { font-size: 13px; margin-top: 4px; color: var(--el-text-color-primary); }
.trg-hero-time { font-size: 12px; margin-top: 4px; color: var(--el-text-color-secondary); }
.trg-hero-meta { display: flex; align-items: center; gap: 8px; margin-top: 6px; font-size: 12px; color: var(--el-text-color-secondary); flex-wrap: wrap; }
/* ① 来源卡与命中概览：类型着色（全类型同构，仅色相区分） */
.trg-hero.trg-source--geo { border-color: var(--el-color-warning-light-7); background: var(--el-color-warning-light-9); }
.trg-hero.trg-source--crawler { border-color: var(--el-color-info-light-7); background: var(--el-color-info-light-9); }
.trg-hero.trg-source--threat { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-hero.trg-source--trust { border-color: var(--el-color-success-light-7); background: var(--el-color-success-light-9); }
.trg-hero.trg-source--acl { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-hero.trg-source--waf-crs, .trg-hero.trg-source--waf-custom { border-color: var(--el-color-primary-light-7); background: var(--el-color-primary-light-9); }
.trg-hero.trg-source--body { border-color: var(--el-color-info-light-7); background: var(--el-color-info-light-9); }
.trg-source-geo { color: var(--el-text-color-secondary); font-size: 12px; }
/* ② 信息卡：KV 行 */
.trg-kv { display: flex; gap: 8px; font-size: 13px; padding: 3px 0; }
.trg-kv .k { color: var(--el-text-color-secondary); flex-shrink: 0; width: 96px; }
.trg-cond { font-size: 13px; }
/* CRS 源码折叠 + 排除组（自 SecurityEvents 迁入，风格对齐卡片） */
.crs-snippet-toggle { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--el-color-primary); cursor: pointer; margin-top: 8px; }
/* 折叠头是键盘入口（Enter/Space）：焦点必须可见 */
.crs-snippet-toggle:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }
.crs-snippet-toggle-icon { transition: transform .2s; }
.crs-snippet-toggle-icon.is-expanded { transform: rotate(90deg); }
.crs-snippet-toggle-file { color: var(--el-text-color-secondary); }
.crs-snippet-body { margin-top: 8px; border: 1px solid var(--el-border-color-lighter); padding: 8px; max-height: 260px; overflow: auto; background: var(--el-fill-color-light); }
.crs-snippet-empty { font-size: 12px; color: var(--el-text-color-secondary); }
</style>
