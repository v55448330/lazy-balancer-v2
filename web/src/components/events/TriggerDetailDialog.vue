<template>
  <el-dialog
    :model-value="modelValue"
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
          <span v-if="geoLabel" class="trg-source-geo">{{ geoLabel }}</span>
        </div>
        <div class="trg-hero-policy">
          <span class="trg-hero-policy-name">{{ policy?.name ?? '（策略已删除）' }}</span>
          <el-tag size="small" :type="policy?.enabled ? 'success' : 'info'" effect="plain">
            {{ policy?.enabled ? '已启用' : '已禁用' }}
          </el-tag>
        </div>
        <div class="trg-hero-hit">{{ heroHitSource }}</div>
      </div>

      <!-- ② 策略配置与命中明细（仅展示与本次触发相关的维度；零操作，处置在 IP 快捷弹框） -->
      <div class="trg-card">
        <div class="trg-card-title">策略配置 · {{ dimensionTitle }}</div>
        <div class="trg-kv"><span class="k">当前配置</span><span>{{ relevantSummary }}</span></div>

        <!-- 命中的地址列表与内联名单（只读信息） -->
        <template v-if="kind === 'acl' || kind === 'geo' || kind === 'threat'">
          <div v-for="m in memberLists" :key="m.id" class="trg-kv">
            <span class="k">命中列表</span>
            <span>{{ m.name }}<el-tag v-if="m.system" size="small" effect="plain" style="margin-left: 6px">内置只读</el-tag></span>
          </div>
          <div v-if="inlineAclHit" class="trg-kv"><span class="k">命中位置</span><span>策略内联{{ policy?.ip_acl_mode === 'allow' ? '白' : '黑' }}名单</span></div>
          <div v-if="trustHitNote" class="trg-kv"><span class="k">信任豁免</span><span>{{ trustHitNote }}</span></div>
          <div v-if="memberSystemTip" class="trg-tip">{{ memberSystemTip }}</div>
          <div v-if="memberLists.length === 0 && !inlineAclHit && kind === 'acl'" class="trg-tip">未定位到命中的地址列表（策略名单可能已变更；事件为历史记录）</div>
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
          <el-alert
            v-if="!crsIndexLoading && !crsEntry"
            type="warning"
            :closable="false"
            show-icon
            :title="crsIndexReady
              ? '此规则已从当前 CRS 移除，无法加入排除（存量排除条目仍生效）'
              : '当前 CRS 索引加载失败，仍可将其加入排除'"
            style="margin-top: 10px"
          />
          <template v-if="crsEntry">
            <div class="crs-snippet-toggle" @click="toggleCrsSnippet">
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
          <div v-else-if="!loading" class="trg-tip">未找到该自定义规则（可能已被删除；事件为历史记录）</div>
          <div class="trg-tip">自定义规则 id {{ customDbId }}（事件携带的触发 id = 规则 id + 10000）。编辑请前往 安全防护 → 自定义规则。</div>
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
import { computed, ref, watch } from 'vue'
import { ArrowRight } from '@element-plus/icons-vue'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { request } from '@/utils/api'
import { parseIPList, parseRefIds } from '@/utils/securityStages'
import { useCrsRuleIndex } from '@/composables/useCrsRuleIndex'
import type { APIResponse } from '@/types'

// 第 58 轮（用户裁定）：统一触发详情弹框——全部触发类型（IP 黑白名单/地域/威胁
// 情报库/信任/WAF·CRS/WAF·自定义/请求体异常）共用同一风格与交互；信息优先，
// IP 处置动作收敛到 IP 快捷弹框。CRS 快捷排除为规则级误报治理动作，保留于此。
interface TriggerRow {
  id: number
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
}

const props = defineProps<{
  modelValue: boolean
  row: TriggerRow | null
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

type Kind = 'acl' | 'geo' | 'threat' | 'trust' | 'waf-crs' | 'waf-custom' | 'body' | 'other'

const kind = computed<Kind>(() => {
  const t = props.row?.rule_triggered ?? ''
  if (!t) return 'other'
  const n = Number(t)
  if (n >= 800000 && n < 900000) return 'geo'
  if (n === 14) return 'threat'
  if (n === 3 || n === 12) return 'trust'
  if (t === '11') return 'body'
  if (/^9\d{5}$/.test(t)) return 'waf-crs'
  if (/^\d{5}$/.test(t)) return 'waf-custom'
  return 'acl'
})

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
      if (inlineAclHit.value) return `策略内联黑名单（规则 id:${ev.rule_triggered}）`
      if (memberLists.value.length > 0) return memberLists.value.map((m) => `地址列表「${m.name}」`).join('、')
      return `规则 id:${ev.rule_triggered}${ev.rule_name ? ` · ${ev.rule_name}` : ''}`
    }
    case 'geo':
      return `地域拦截规则 id:${ev.rule_triggered}（区域：${geoLabel.value || '未知'}）`
    case 'threat': {
      const names = threatSourceLists.value.map((l) => `「${l.name}」`)
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
const lists = ref<Array<{ id: number; name: string; system?: number | boolean }>>([])
const entriesCache = ref<Record<number, string[]>>({})

const loadAll = async (): Promise<void> => {
  const row = props.row
  if (!row) return
  loading.value = true
  policyMissing.value = false
  policy.value = null
  try {
    if (row.policy_id > 0) {
      const res = await request.get<APIResponse<{ policy: PolicyRow }>>(`/security/policies/${row.policy_id}`, { silent: true } as never)
      policy.value = res.data?.policy ?? null
      if (!res.data?.policy) policyMissing.value = true
    } else {
      policyMissing.value = true
    }
    // 名单/条目：ACL 与信任 refs 的条目缓存（成员判定信息展示用）
    const listRes = await request.get<APIResponse<Array<{ id: number; name: string; system?: number | boolean }>>>('/security/ip-lists')
    lists.value = listRes.data || []
    const refIds = new Set<number>()
    if (policy.value) {
      for (const id of parseRefIds(policy.value.ip_acl_list_refs)) refIds.add(id)
      for (const id of parseRefIds(policy.value.ip_whitelist_refs)) refIds.add(id)
    }
    const results = await Promise.allSettled(
      [...refIds].map((id) => request.get<APIResponse<{ id: number; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`)),
    )
    const cache: Record<number, string[]> = {}
    results.forEach((r) => {
      if (r.status === 'fulfilled' && r.value.data) {
        cache[r.value.data.id] = (r.value.data.entries || []).map((e) => e.value.trim()).filter((v) => v !== '')
      }
    })
    entriesCache.value = cache
  } finally {
    loading.value = false
  }
}


const geoLabel = computed(() => {
  try {
    return ((JSON.parse(policy.value?.geoip_countries ?? '[]') as string[]) || []).filter(Boolean).join('、')
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
const threatSourceLists = computed(() => {
  const p = policy.value
  if (!p || kind.value !== 'threat') return []
  return lists.value
    .filter((l) => l.system && parseRefIds(p.ip_acl_list_refs).includes(l.id))
    .filter((l) => (entriesCache.value[l.id] ?? []).includes(props.row?.client_ip.trim() ?? ''))
})
const memberLists = computed(() => {
  const p = policy.value
  if (!p) return []
  const refs = parseRefIds(p.ip_acl_list_refs)
  const ip = props.row?.client_ip.trim() ?? ''
  return lists.value
    .filter((l) => refs.includes(l.id) && !l.system)
    .filter((l) => (entriesCache.value[l.id] ?? []).includes(ip))
})
const inlineAclHit = computed(() => {
  const p = policy.value
  return !!p && parseIPList(p.ip_acl_list).includes(props.row?.client_ip.trim() ?? '')
})
const trustHitListsText = computed(() => {
  const p = policy.value
  if (!p) return ''
  const ip = props.row?.client_ip.trim() ?? ''
  const refs = parseRefIds(p.ip_whitelist_refs)
  const hit = lists.value
    .filter((l) => refs.includes(l.id) && (entriesCache.value[l.id] ?? []).includes(ip))
    .map((l) => l.name)
  return hit.join('、')
})
const trustHitNote = computed(() => {
  const p = policy.value
  if (!p || kind.value === 'trust') return ''
  const ip = props.row?.client_ip.trim() ?? ''
  const refs = parseRefIds(p.ip_whitelist_refs)
  const trusted = parseIPList(p.ip_whitelist).includes(ip)
    || refs.some((id) => (entriesCache.value[id] ?? []).includes(ip))
  return trusted ? '该 IP 在策略信任名单中（DetectionOnly：全评估不拦但全记录）' : ''
})
const memberSystemTip = computed(() => {
  const p = policy.value
  if (!p) return ''
  const ip = props.row?.client_ip.trim() ?? ''
  const sysRefs = lists.value.filter((l) => l.system && parseRefIds(p.ip_acl_list_refs).includes(l.id) && (entriesCache.value[l.id] ?? []).includes(ip))
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
const ACTION_LABELS: Record<string, string> = { block: '拦截', log: '仅记录', score: '计分' }
const customActionLabel = computed(() => {
  const a = customRule.value?.action ?? ''
  return ACTION_LABELS[a] ?? a
})
const customConditions = computed<Array<{ target: string; operator: string; pattern: string }>>(() => {
  // 后端列表接口 conditions 已是结构化数组（非 JSON 字符串）
  return (customRule.value?.conditions ?? []).filter((c) => !!c && typeof c.target === 'string')
})
const loadCustomRule = async (): Promise<void> => {
  customRule.value = null
  if (!Number.isFinite(customDbId.value)) return
  const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules', { silent: true } as never)
  customRule.value = (res.data || []).find((r) => r.id === customDbId.value) ?? null
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
.trg-source { border: 1px solid var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-source--geo { border-color: var(--el-color-warning-light-7); background: var(--el-color-warning-light-9); }
.trg-source--threat { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-source--trust { border-color: var(--el-color-success-light-7); background: var(--el-color-success-light-9); }
.trg-source--acl { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-source--waf-crs, .trg-source--waf-custom { border-color: var(--el-color-primary-light-7); background: var(--el-color-primary-light-9); }
.trg-source--body { border-color: var(--el-color-info-light-7); background: var(--el-color-info-light-9); }

/* ① 命中概览（trg-hero）：类型着色同来源卡 + 三行结构 */
.trg-hero { border: 1px solid var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-hero--geo { border-color: var(--el-color-warning-light-7); background: var(--el-color-warning-light-9); }
.trg-hero--threat { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-hero--trust { border-color: var(--el-color-success-light-7); background: var(--el-color-success-light-9); }
.trg-hero--acl { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-hero--waf-crs, .trg-hero--waf-custom { border-color: var(--el-color-primary-light-7); background: var(--el-color-primary-light-9); }
.trg-hero--body { border-color: var(--el-color-info-light-7); background: var(--el-color-info-light-9); }
.trg-hero-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.trg-hero-stage { font-weight: 700; font-size: 14px; }
.trg-hero-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 700; }
.trg-hero-policy { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.trg-hero-policy-name { font-weight: 600; font-size: 13px; }
.trg-hero-hit { font-size: 13px; margin-top: 4px; color: var(--el-text-color-primary); }
.trg-source-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.trg-source-ip { font-weight: 700; font-size: 14px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.trg-source-geo { color: var(--el-text-color-secondary); font-size: 12px; }
.trg-source-line { font-size: 13px; color: var(--el-text-color-primary); }
/* ②③ 信息卡：统一标题+分隔线+KV 行 */
.trg-card { border: 1px solid var(--el-border-color); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-card-title { font-size: 13px; font-weight: 600; padding-bottom: 6px; margin-bottom: 8px; border-bottom: 1px dashed var(--el-border-color-lighter); }
.trg-policy-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.trg-policy-name { font-weight: 600; }
.trg-policy-body { display: grid; gap: 4px; }
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
.crs-action-group { border-top: 1px dashed var(--el-border-color-lighter); margin-top: 10px; padding-top: 8px; }
.crs-action-group-title { font-size: 12px; font-weight: 600; color: var(--el-text-color-regular); margin-bottom: 8px; }
.crs-action-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.crs-exclude-submit { margin-left: auto; }
</style>
