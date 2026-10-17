<template>
  <el-dialog
    :model-value="modelValue"
    class="dialog-body-inset"
    title="触发详情"
    width="min(680px, 94vw)"
    top="5vh"
    append-to-body
    @close="emit('update:modelValue', false)"
  >
    <div v-loading="loading">
      <!-- ① 命中概览：阶段 → 策略 → 命中源（一眼可读） -->
      <div class="trg-hero" :class="`trg-source--${kind}`">
        <div class="trg-hero-row">
          <el-tag size="small" :type="sourceTagType" effect="dark">{{ categoryLabel }}</el-tag>
          <span class="trg-hero-stage">{{ heroStage }}</span>
          <span class="trg-hero-ip">{{ row?.client_ip }}</span>
          <span v-if="row?.ip_location" class="trg-source-geo">{{ row.ip_location }}</span>
          <!-- PM-3（第 77 轮）：geoLabel（策略 geoip_countries 区域清单）回退加
               kind 门控——归属地位置只对地域事件（kind==='geo'，xdb 未装时
               ip_location 为空的唯一回退位）展示区域清单有意义；非地域事件
               （ACL/信任/WAF…）显示策略区域清单会被误读为该事件归属地。
               Ruling（主审裁定）：选门控而非改标签语义——地域事件中区域清单
               是有效信息，保留。 -->
          <span v-else-if="kind === 'geo' && geoLabel" class="trg-source-geo">{{ geoLabel }}</span>
        </div>
        <div class="trg-hero-policy">
          <span class="trg-hero-policy-name">{{ policy?.name ?? (loading ? '加载中…' : policyMissing ? '（策略已删除）' : '（策略信息不可用）') }}</span>
          <el-tag size="small" :type="policy?.enabled ? 'success' : 'info'" effect="plain">
            {{ loading ? '…' : policy?.enabled ? '已启用' : '已禁用' }}
          </el-tag>
        </div>
        <div class="trg-hero-hit">{{ heroHitSource }}</div>
        <div v-if="row?.event_time" class="trg-hero-time">事件时间 · {{ formatTriggerTime(row.event_time) }}</div>
        <div class="trg-hero-meta">
          <span>来源 IP {{ row?.client_ip }}</span>
          <span v-if="(row?.duration_us ?? 0) > 0"><template v-if="isWafFamily">处理时长 {{ formatDurationUs((row?.duration_us ?? 0) + (row?.precheck_us ?? 0)) }}<template v-if="(row?.precheck_us ?? 0) > 0">（预检 {{ formatDurationUs(row?.precheck_us) }} + WAF 段 {{ formatDurationUs(row?.duration_us) }}）</template></template><template v-else>处理时长 {{ formatDurationUs(row?.duration_us ?? 0) }}（预检耗时）</template></span>
          <el-tag size="small" :type="row?.action === 'blocked' ? 'danger' : 'warning'" effect="plain">
            {{ row?.action === 'blocked' ? '已拦截' : '已记录（检测）' }}
          </el-tag>
          <span v-if="detectionNote">{{ detectionNote }}</span>
        </div>
      </div>

      <!-- ② 策略配置与命中明细（仅展示与本次触发相关的维度；零操作，处置在 IP 快捷弹框） -->
      <div v-if="loadError" class="info-note-bar"><span class="info-note-desc">策略信息加载失败，请关闭后重试</span></div>
      <div class="trg-card">
        <div class="trg-card-title">策略配置 · {{ dimensionTitle }}</div>
        <div class="trg-kv"><span class="k">当前配置</span><span>{{ relevantSummary }}</span></div>

        <!-- 命中的地址列表与内联名单（只读信息） -->
        <template v-if="kind === 'acl' || kind === 'geo' || kind === 'threat'">
          <div v-for="m in allHitLists" :key="m.id" class="trg-kv">
            <span class="k">命中列表</span>
            <span>{{ m.name }}<el-tag v-if="m.system" size="small" effect="plain" style="margin-left: 6px">内置只读</el-tag></span>
          </div>
          <div v-if="inlineAclHit" class="trg-kv"><span class="k">命中位置</span><span>策略内联{{ policy?.ip_acl_mode === 'allow' ? '白' : '黑' }}名单</span></div>
          <div v-if="trustHitNote" class="trg-kv"><span class="k">信任豁免</span><span>{{ trustHitNote }}</span></div>
          <div v-if="memberSystemTip" class="trg-tip">{{ memberSystemTip }}</div>
          <div v-if="allHitLists.length === 0 && !inlineAclHit && kind === 'acl' && !isAllowOutside" class="trg-tip">未定位到命中的地址列表（策略名单可能已变更；事件为历史记录）</div>
        </template>

        <!-- 信任名单：直通/保留检测语义说明 -->
        <template v-else-if="kind === 'trust'">
          <div class="trg-kv"><span class="k">命中名单</span><span>{{ trustHitListsText || '策略信任名单（内联）' }}</span></div>
          <div class="trg-kv"><span class="k">信任语义</span><span>{{ policy?.trust_detection === true ? '保留检测：继续后续阶段评估，事件动作=检测' : '直通上游：跳过后续安全阶段，不产生拦截' }}</span></div>
        </template>

        <!-- WAF · CRS：规则信息 + 源码折叠（只读） -->
        <template v-else-if="kind === 'waf-crs'">
          <div class="trg-kv"><span class="k">规则 ID</span><span>{{ row?.rule_triggered }}</span></div>
          <div class="trg-kv">
            <span class="k">描述</span>
            <span v-if="crsIndexLoading">加载中…</span>
            <template v-else-if="crsEntry">{{ crsEntry.msg || '（无描述）' }}</template>
            <template v-else>—</template>
          </div>
          <div class="trg-kv">
            <span class="k">文件 / 分类</span>
            <span v-if="crsIndexLoading">加载中…</span>
            <template v-else-if="crsEntry">{{ crsEntry.file }} · {{ crsEntry.category }}</template>
            <template v-else>—</template>
          </div>
          <div class="trg-kv"><span class="k">规则消息</span><span>{{ row?.rule_msg || '—' }}</span></div>
          <div v-if="!crsIndexLoading && !crsEntry" class="info-note-bar" style="margin-top: 10px">
            <span class="info-note-desc">{{ crsIndexReady
              ? '此规则已从当前 CRS 移除（存量排除条目仍生效）；排除管理请前往 安全防护 → 安全策略 → 策略编辑 → 排除规则'
              : '当前 CRS 索引加载失败，无法展示规则详情' }}</span>
          </div>
          <template v-if="crsEntry">
            <div class="crs-snippet-toggle" role="button" tabindex="0" @click="toggleCrsSnippet" @keydown.enter.prevent="toggleCrsSnippet" @keydown.space.prevent="toggleCrsSnippet">
              <el-icon class="crs-snippet-toggle-icon" :class="{ 'is-expanded': crsSnippetExpanded }"><ArrowRight /></el-icon>
              <span>{{ crsSnippetExpanded ? '收起规则源码' : '展开规则源码' }}</span>
              <span class="crs-snippet-toggle-file">{{ crsEntry.file }} · id:{{ row?.rule_triggered }} 所在行 ±10 行</span>
            </div>
            <div v-if="crsSnippetExpanded" v-loading="crsSnippetLoading" class="crs-snippet-body">
              <SyntaxHighlight v-if="crsSnippet" :content="crsSnippet" language="apacheconf" />
              <div v-else-if="crsSnippetError" class="crs-snippet-empty">规则源码加载失败，可收起后重新展开重试</div>
              <div v-else-if="!crsSnippetLoading" class="crs-snippet-empty">未在该文件中定位到规则定义（规则文件可能已更新）</div>
            </div>
          </template>
        </template>

        <!-- WAF · 自定义规则：规则完整明细 -->
        <template v-else-if="kind === 'waf-custom'">
          <template v-if="customRule">
            <div class="trg-kv"><span class="k">规则名称</span><span>{{ customRule.name }}</span></div>
            <div class="trg-kv">
              <span class="k">匹配条件</span>
              <span>
                <div v-for="(c, i) in customConditions" :key="i" class="trg-cond">
                  {{ c.target }} {{ c.operator }} <code>{{ c.pattern }}</code>
                </div>
                <span v-if="customConditions.length === 0">—</span>
              </span>
            </div>
            <div class="trg-kv"><span class="k">动作</span><span>{{ customActionLabel }}<template v-if="customRule.action === 'score'">（{{ customRule.score }} 分）</template></span></div>
            <div class="trg-kv"><span class="k">状态</span><span>{{ customRule.enabled ? '启用' : '禁用' }}</span></div>
          </template>
          <div v-else-if="!loading && customRuleLoadError" class="trg-tip">自定义规则加载失败，可关闭弹框后重新打开重试（事件为历史记录，展示不完整）</div>
          <div v-else-if="!loading" class="trg-tip">未找到该自定义规则（可能已被删除；事件为历史记录）</div>
          <div class="trg-tip">自定义规则 id {{ customDbId }}（事件携带的触发 id = 规则 id + 10000）。编辑请前往 安全防护 → 规则集 → 自定义规则。</div>
        </template>

        <!-- 请求体异常 -->
        <template v-else-if="kind === 'body'">
          <div class="trg-kv"><span class="k">说明</span><span>请求体解析失败（策略开启记录请求体后，无法解析的请求体触发）</span></div>
        </template>
      </div>

      <!-- 处置指引：IP 处置统一在快捷弹框（用户裁定） -->
      <div class="trg-tip" style="margin-top: 10px">
        IP 处置（移除/加入黑白名单、信任）请点击事件列表中的「IP 地址」打开快捷弹框操作。
      </div>
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">关闭</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ArrowRight } from '@element-plus/icons-vue'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { parseIPList, parseRefIds, entryMatchesIp, triggerStageFamily, sharedEntriesCache, subscribeSharedEntriesCache, ensureSharedEntries, formatDurationUs } from '@/utils/securityStages'
import { useCrsRuleIndex } from '@/composables/useCrsRuleIndex'
import { useCountryNamesCn, countryLabel } from '@/composables/useCountryNamesCn'
import type { APIResponse } from '@/types'

// 第 58 轮（用户裁定）：统一触发详情弹框——全部触发类型（IP 黑白名单/地域/威胁
// 情报库/信任/WAF·CRS/WAF·自定义/请求体异常）共用同一风格与交互；信息优先，
// IP 处置动作收敛到 IP 快捷弹框（第 59 轮裁定：触发详情零操作，
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

type Kind = 'acl' | 'geo' | 'threat' | 'trust' | 'waf-crs' | 'waf-custom' | 'body' | 'other'

// FE65-2：kind 改由共享 triggerStageFamily 投影（securityStages 唯一实现，原
// F62-10 双实现并存欠账）——细粒度族映射到本弹框展示 Kind（geoip→geo、
// threat→threat、wafCrs→waf-crs、wafCustom→waf-custom，其余同名）。
// 空 id 恒 other；未匹配的非空值兜底 acl（历史共享 GeoIP id:8 等归「IP 访问
// 控制」口径，R59-P3，与列表列一致）。
const kind = computed<Kind>(() => {
  const t = props.row?.rule_triggered ?? ''
  if (!t) return 'other'
  switch (triggerStageFamily(t)) {
    case 'trust': return 'trust'
    case 'ipAcl': return 'acl'
    case 'geoip': return 'geo'
    case 'threat': return 'threat'
    case 'wafCrs': return 'waf-crs'
    case 'wafCustom': return 'waf-custom'
    case 'body': return 'body'
    default: return 'acl'
  }
})

// Review66-Head ②（2026-10-03）：加和式仅 WAF 族——预检族（IP ACL/信任/
// GeoIP/威胁）duration_us≡precheck_us 同值（securityevents.go:202），加和
// 会翻倍并误标 WAF 段。
const isWafFamily = computed(() => ['waf-crs', 'waf-custom', 'body'].includes(kind.value))

const categoryLabel = computed(() => {
  switch (kind.value) {
    case 'geo': return '地域拦截'
    case 'threat': return '威胁情报库'
    case 'trust': return '信任名单'
    case 'waf-crs': return 'WAF · CRS'
    case 'waf-custom': return 'WAF · 自定义'
    case 'body': return '请求体异常'
    default: return 'IP 黑白名单'
  }
})
const sourceTagType = computed(() =>
  kind.value === 'geo' ? 'warning'
    : kind.value === 'threat' || kind.value === 'waf-crs' ? 'danger'
      : kind.value === 'trust' ? 'success'
        : kind.value === 'waf-custom' || kind.value === 'acl' ? 'danger' : 'info')

// 命中概览（用户裁定：一眼可读）——阶段名 / 命中源
const formatTriggerTime = (v: string): string => formatDate(v)

// 组合语义说明（第 59 轮）：logged 事件的「为什么不拦」——检测模式策略 或
// 信任保留检测（含跨策略豁免：预检 DetectionOnly 为事务级全局，命中策略与
// 豁免信任策略可以是两条不同策略——「黑名单命中但被另一策略的信任放行为检测」）。
const exemptingTrustPolicy = computed<string | null>(() => {
  if (!props.row || props.row.action === 'blocked') return null
  const ip = props.row.client_ip.trim()
  for (const p of [policy.value, ...enabledPolicies.value].filter((x): x is PolicyRow => !!x)) {
    if (!p.ip_whitelist_enabled || p.trust_detection !== true) continue
    if (parseIPList(p.ip_whitelist).some((e) => entryMatchesIp(e, ip))) return p.name
    const refs = parseRefIds(p.ip_whitelist_refs)
    if (refs.some((id) => (entriesCache.value[id] ?? []).some((e) => entryMatchesIp(e, ip)))) return p.name
  }
  return null
})
const detectionNote = computed<string>(() => {
  if (!props.row || props.row.action === 'blocked') return ''
  if (kind.value === 'trust') return ''
  if (policy.value?.mode === 'detection') return '所属策略为检测模式：命中只记录，不拦截'
  if (exemptingTrustPolicy.value) return `信任保留检测（跨策略豁免）：由策略「${exemptingTrustPolicy.value}」的信任名单放行，命中记录为检测`
  return ''
})

const heroStage = computed(() => {
  switch (kind.value) {
    case 'trust': return '阶段 0 · 信任名单'
    case 'acl': return '阶段 1 · IP 访问控制'
    case 'geo': return '阶段 1 · 地域拦截'
    case 'threat': return '阶段 1 · 威胁情报库'
    case 'waf-crs': case 'waf-custom': return '阶段 3 · WAF'
    case 'body': return '阶段 3 · 请求体检测'
    default: return '安全防护'
  }
})
const dimensionTitle = computed(() => {
  switch (kind.value) {
    case 'trust': return '信任名单'
    case 'acl': return 'IP 黑白名单'
    case 'geo': return '地域拦截'
    case 'threat': return '威胁情报库'
    case 'waf-crs': case 'waf-custom': return 'WAF'
    case 'body': return '请求体检测'
    default: return 'IP 黑白名单'
  }
})
// 相关维度配置摘要：只展示与本次触发相关的维度
const relevantSummary = computed(() => {
  switch (kind.value) {
    case 'trust': return trustSummary.value
    case 'geo': return geoSummary.value
    case 'threat': return `威胁情报库引用 · ${aclSummary.value}`
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
    case 'acl': {
      if (isAllowOutside.value) return '不在白名单中（白名单模式：仅名单内 IP 放行）'
      if (inlineAclHit.value) return `策略内联${policy.value?.ip_acl_mode === 'allow' ? '白' : '黑'}名单（规则 id:${ev.rule_triggered}）`
      if (allHitLists.value.length > 0) return allHitLists.value.map((m) => `地址列表「${m.name}」${m.system ? '（内置）' : ''}`).join('、')
      if (ev.rule_triggered === '4') return `遗留独立黑名单字段（id:4）${ev.rule_name ? ` · ${ev.rule_name}` : ''}`
      return `规则 id:${ev.rule_triggered}${ev.rule_name ? ` · ${ev.rule_name}` : ''}`
    }
    case 'geo':
      return `地域拦截规则 id:${ev.rule_triggered}（区域：${geoLabel.value || '未知'}）`
    case 'threat': {
      const names = allHitLists.value.filter((l) => l.system).map((l) => `「${l.name}」`)
      return names.length > 0 ? `威胁情报库 ${names.join('、')}` : `威胁情报库预检（id:${ev.rule_triggered}）`
    }
    case 'trust': {
      const t = trustHitListsText.value
      return t ? `信任名单「${t}」` : '策略信任名单'
    }
    case 'waf-crs':
      return `CRS 规则 ${ev.rule_triggered}${crsEntry.value?.msg ? ` · ${crsEntry.value.msg}` : ''}`
    case 'waf-custom':
      return customRule.value ? `自定义规则「${customRule.value.name}」` : `自定义规则 id:${customDbId.value}`
    case 'body':
      return '请求体解析失败'
    default:
      return `规则 id:${ev.rule_triggered}`
  }
})

// —— 策略与地址列表装载（直取策略详情，禁用/删除态可见）——
const loading = ref(false)
const policyMissing = ref(false)
const loadError = ref(false)
// 弹框会话序号（第 60 轮 P3）：快速关开换行时丢弃在途响应（同文件 crsDialogSeq
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
}
const policy = ref<PolicyRow | null>(null)
// 全部启用策略（第 59 轮追加修复：跨策略信任豁免判定——预检 DetectionOnly
// 为事务级全局，命中策略与豁免信任策略可以是两条不同策略）
const enabledPolicies = ref<PolicyRow[]>([])
const lists = ref<Array<{ id: number; name: string; system?: number | boolean }>>([])
// 跨组件共享条目缓存（第 61 轮 P2-2 修复：提升到 securityStages 模块级，
// IPLocationAction 写入动作经 invalidateSharedEntriesCache 清空——原实现
// 缓存在本组件 setup 内，快捷弹框的 onChanged 清不到它导致展示恒陈旧）
const entriesCache = ref<Record<number, string[]>>({ ...sharedEntriesCache })
// FE65-1：共享缓存失效即重拷本地副本（叠开 IP 处置改名单后徽标/列表即时
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
  policy.value = null
  enabledPolicies.value = []
  lists.value = []
  entriesCache.value = { ...sharedEntriesCache } // 从共享缓存起步，只补拉缺失
  try {
    if (row.policy_id > 0) {
      try {
        const res = await request.get<APIResponse<{ policy: PolicyRow }>>(`/security/policies/${row.policy_id}`, { silent: true })
        if (seq !== loadSeq) return // 第 61 轮 P2-4：首个 await 同样需竞态守卫
        policy.value = res.data?.policy ?? null
        if (!res.data?.policy) policyMissing.value = true
      } catch (err) {
        // 第 59 轮 R59-P3：网络/5xx 与「策略已删除」不可混同——404 归缺失，
        // 其余按加载失败提示（hero 不误标「已删除」）。
        policyMissing.value = err instanceof Error && 'status' in err && (err as { status?: number }).status === 404
        if (!policyMissing.value) loadError.value = true
      }
    } else {
      policyMissing.value = true
    }
    // 全部启用策略 + 名单/条目：ACL 与信任 refs 的条目缓存（信息展示用 +
    // 跨策略信任成员判定——第 59 轮追加修复）
    const [polRes, listRes] = await Promise.allSettled([
      request.get<APIResponse<PolicyRow[]>>('/security/policies?enabled=true', { silent: true }),
      request.get<APIResponse<Array<{ id: number; name: string; system?: number | boolean }>>>('/security/ip-lists', { silent: true }),
    ])
    if (seq !== loadSeq) return
    if (polRes.status === 'fulfilled') enabledPolicies.value = polRes.value.data || []
    lists.value = listRes.status === 'fulfilled' ? listRes.value.data || [] : []
    const refIds = new Set<number>()
    const allPolicies = [policy.value, ...enabledPolicies.value].filter((p): p is PolicyRow => !!p)
    for (const p of allPolicies) {
      for (const id of parseRefIds(p.ip_acl_list_refs)) refIds.add(id)
      for (const id of parseRefIds(p.ip_whitelist_refs)) refIds.add(id)
    }
    // 只补拉共享缓存缺失的名单（第 78 轮 U15-F08）：原实现对全部 refIds 无条件
    // 并发 GET——连续打开事件详情时同一批名单反复下载。写回/通知由缓存单源负责。
    await ensureSharedEntries(refIds, async (id) => {
      const res = await request.get<APIResponse<{ id: number; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`, { silent: true })
      return (res.data?.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
    })
    if (seq !== loadSeq) return
    entriesCache.value = { ...sharedEntriesCache }
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

// X1（第 74 轮）：区域清单展示层翻译——country_names_cn 单源映射，未命中
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
  return `内联 ${inlineCount} 条${names.length > 0 ? ` · 引用：${names.join('、')}` : ''}`
}
const aclSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (!p.ip_acl_enabled) return '未启用'
  const mode = p.ip_acl_mode === 'allow' ? '白名单模式' : p.ip_acl_mode === 'bypass' ? '旁路模式' : '黑名单模式'
  return `${mode} · ${listSummary(p.ip_acl_list, p.ip_acl_list_refs)}`
})
const trustSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (!p.ip_whitelist_enabled) return '未启用'
  return listSummary(p.ip_whitelist, p.ip_whitelist_refs)
})
const geoSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  if (!p.geoip_mode || p.geoip_mode === 'off') return '未启用'
  return `${p.geoip_mode === 'allow' ? '仅允许' : '拦截'}区域：${geoLabel.value || '—'}`
})
const wafSummary = computed(() => {
  const p = policy.value
  if (!p) return '—'
  const mode = p.mode === 'blocking' ? '阻断' : p.mode === 'detection' ? '检测' : p.mode === 'custom_only' ? '仅自定义规则' : p.mode === 'off' ? '关闭' : p.mode || '—'
  let groups = ''
  try {
    const g = (JSON.parse(p.crs_rule_groups ?? '[]') as string[]) || []
    if (p.mode !== 'off' && p.mode !== 'custom_only' && g.length > 0) groups = ` · CRS ${g.length} 组`
  } catch { /* 畸形按无组处理 */ }
  let custom = ''
  try {
    const c = (JSON.parse(p.custom_rules ?? '[]') as string[]) || []
    if ((p.mode === 'custom_only' || p.mode === 'blocking') && c.length > 0) custom = ` · 自定义 ${c.length} 条`
  } catch { /* 畸形按无规则处理 */ }
  return `${mode}${groups}${custom}`
})

// —— 来源语义行 ——

// —— ACL/威胁/信任命中明细（只读信息） ——
// 全部命中列表（第 59 轮补漏1）：自定义 + 内置威胁名单（只读展示名单名，
// 原实现只对自定义列表出「命中列表」行、内置名单仅泛化 tip——同一 IP 同时
// 命中 测试列表+中科大恶意IP名单 时内置侧不可见）。
const allHitLists = computed(() => {
  const p = policy.value
  if (!p) return []
  const refs = parseRefIds(p.ip_acl_list_refs)
  const ip = props.row?.client_ip.trim() ?? ''
  // 第 60 轮用户验收：CIDR 感知匹配——威胁库条目为 CIDR（如 45.148.10.0/24），
  // 精确串匹配漏报导致「未定位到命中的地址列表」误显
  return lists.value.filter((l) => refs.includes(l.id) && (entriesCache.value[l.id] ?? []).some((e) => entryMatchesIp(e, ip)))
})
// 白名单外拒绝形态（第 59 轮补漏2）：id:5/7 = allow 交集外——IP 不在任何名单
// 中，「命中列表」恒空是正确语义，须显式说明而非「未定位到」。
const isAllowOutside = computed(() => {
  const n = Number(props.row?.rule_triggered)
  return kind.value === 'acl' && (n === 5 || n === 7)
})

const inlineAclHit = computed(() => {
  const p = policy.value
  // 第 61 轮 P2-3：CIDR 感知（内联名单位 CIDR 条目命中实际 IP）
  return !!p && parseIPList(p.ip_acl_list).some((e) => entryMatchesIp(e, props.row?.client_ip.trim() ?? ''))
})
const trustHitListsText = computed(() => {
  const p = policy.value
  if (!p) return ''
  const ip = props.row?.client_ip.trim() ?? ''
  const refs = parseRefIds(p.ip_whitelist_refs)
  const hit = lists.value
    .filter((l) => refs.includes(l.id) && (entriesCache.value[l.id] ?? []).some((e) => entryMatchesIp(e, ip)))
    .map((l) => l.name)
  return hit.join('、')
})
const trustHitNote = computed(() => {
  const p = policy.value
  if (!p || kind.value === 'trust') return ''
  const ip = props.row?.client_ip.trim() ?? ''
  const refs = parseRefIds(p.ip_whitelist_refs)
  if (p.ip_whitelist_enabled === false) return '' // 第 61 轮 P3：信任已关闭时条目不生效（trustDead 同口径）
  const trusted = parseIPList(p.ip_whitelist).some((e) => entryMatchesIp(e, ip))
    || refs.some((id) => (entriesCache.value[id] ?? []).some((e) => entryMatchesIp(e, ip)))
  return trusted ? '该 IP 在策略信任名单中（DetectionOnly：全评估不拦但全记录）' : ''
})
const memberSystemTip = computed(() => {
  const p = policy.value
  if (!p) return ''
  const ip = props.row?.client_ip.trim() ?? ''
  const sysRefs = lists.value.filter((l) => l.system && parseRefIds(p.ip_acl_list_refs).includes(l.id) && (entriesCache.value[l.id] ?? []).some((e) => entryMatchesIp(e, ip)))
  return sysRefs.length > 0 ? '内置威胁名单为只读来源；误报可将该 IP 加入信任名单豁免。' : ''
})

// —— WAF · 自定义规则明细 ——
interface CustomRule {
  id: number
  name: string
  description: string
  action: string
  score?: number
  enabled: boolean
  conditions?: Array<{ target: string; operator: string; pattern: string }>
}
const customRule = ref<CustomRule | null>(null)
const customDbId = computed(() => {
  const n = Number(props.row?.rule_triggered)
  return Number.isFinite(n) && n >= 10000 ? n - 10000 : NaN
})
const ACTION_LABELS: Record<string, string> = { block: '拦截', log: '仅记录', score: '计分', pass: '放行' } // 第 61 轮 P3：补 pass（后端合法三态含 pass）
const customActionLabel = computed(() => {
  const a = customRule.value?.action ?? ''
  return ACTION_LABELS[a] ?? a
})
const customConditions = computed<Array<{ target: string; operator: string; pattern: string }>>(() => {
  // 后端列表接口 conditions 已是结构化数组（非 JSON 字符串）
  return (customRule.value?.conditions ?? []).filter((c) => !!c && typeof c.target === 'string')
})
// 第 62 轮 F62-2:补会话序号守卫(同 crsDialogSeq 范式)+try/catch——
// 快速关开弹框时在途响应晚到不再覆盖当前;加载失败不再误标「规则已删除」
const customRuleSeq = ref(0)
const customRuleLoadError = ref(false)
const loadCustomRule = async (): Promise<void> => {
  customRule.value = null
  customRuleLoadError.value = false
  if (!Number.isFinite(customDbId.value)) return
  const seq = ++customRuleSeq.value
  try {
    const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules', { silent: true })
    if (seq !== customRuleSeq.value) return
    customRule.value = (res.data || []).find((r) => r.id === customDbId.value) ?? null
  } catch {
    if (seq !== customRuleSeq.value) return
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

const extractRuleSnippet = (content: string, ruleId: string): string => {
  const needles = [`id:${ruleId}`, `id: ${ruleId}`, `id:'${ruleId}'`, `id:"${ruleId}"`]
  const lines = content.split('\n')
  const idx = lines.findIndex((line) => needles.some((n) => line.includes(n)))
  if (idx === -1) return ''
  return lines.slice(Math.max(0, idx - 10), Math.min(lines.length, idx + 11)).join('\n')
}

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
    crsSnippet.value = extractRuleSnippet(res.data?.content || '', ev.rule_triggered)
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
    const seq = ++crsDialogSeq
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
/* ① 来源卡：类型着色（全类型同构，仅色相区分） */
.trg-source--geo { border-color: var(--el-color-warning-light-7); background: var(--el-color-warning-light-9); }
.trg-source--threat { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-source--trust { border-color: var(--el-color-success-light-7); background: var(--el-color-success-light-9); }
.trg-source--acl { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-source--waf-crs, .trg-source--waf-custom { border-color: var(--el-color-primary-light-7); background: var(--el-color-primary-light-9); }
.trg-source--body { border-color: var(--el-color-info-light-7); background: var(--el-color-info-light-9); }

/* ① 命中概览（trg-hero）：类型着色同来源卡 + 三行结构 */
.trg-hero { border: 1px solid var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-hero-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.trg-hero-stage { font-weight: 700; font-size: 14px; }
.trg-hero-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 700; }
.trg-hero-policy { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.trg-hero-policy-name { font-weight: 600; font-size: 13px; }
.trg-hero-hit { font-size: 13px; margin-top: 4px; color: var(--el-text-color-primary); }
.trg-hero-time { font-size: 12px; margin-top: 4px; color: var(--el-text-color-secondary); }
.trg-hero-meta { display: flex; align-items: center; gap: 8px; margin-top: 6px; font-size: 12px; color: var(--el-text-color-secondary); flex-wrap: wrap; }
.trg-source-geo { color: var(--el-text-color-secondary); font-size: 12px; }
/* ②③ 信息卡：统一标题+分隔线+KV 行 */
.trg-card { border: 1px solid var(--el-border-color); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-card-title { font-size: 13px; font-weight: 600; padding-bottom: 6px; margin-bottom: 8px; border-bottom: 1px dashed var(--el-border-color-lighter); }
.trg-kv { display: flex; gap: 8px; font-size: 13px; padding: 3px 0; }
.trg-kv .k { color: var(--el-text-color-secondary); flex-shrink: 0; width: 96px; }
.trg-cond { font-size: 13px; }
.trg-tip { font-size: 12px; color: var(--el-text-color-secondary); margin-top: 6px; }
/* CRS 源码折叠 + 排除组（自 SecurityEvents 迁入，风格对齐卡片） */
.crs-snippet-toggle { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--el-color-primary); cursor: pointer; margin-top: 8px; }
.crs-snippet-toggle-icon { transition: transform .2s; }
.crs-snippet-toggle-icon.is-expanded { transform: rotate(90deg); }
.crs-snippet-toggle-file { color: var(--el-text-color-secondary); }
.crs-snippet-body { margin-top: 8px; border: 1px solid var(--el-border-color-lighter); border-radius: 6px; padding: 8px; max-height: 260px; overflow: auto; background: var(--el-fill-color-light); }
.crs-snippet-empty { font-size: 12px; color: var(--el-text-color-secondary); }
</style>
