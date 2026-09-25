<template>
  <el-dialog
    :model-value="modelValue"
    :title="`触发详情 · IP 访问控制`"
    width="min(620px, 94vw)"
    append-to-body
    @close="emit('update:modelValue', false)"
  >
    <div v-loading="loading">
      <!-- 触发来源：按命中维度分类展示（地域 / 威胁情报库 / 黑白名单·地址列表 / 内联） -->
      <div class="trg-source" :class="`trg-source--${sourceKind}`">
        <div class="trg-source-head">
          <el-tag size="small" :type="sourceTagType" effect="dark">{{ sourceCategoryLabel }}</el-tag>
          <span class="trg-source-ip">{{ ip }}</span>
          <span v-if="geoLabel" class="trg-source-geo">{{ geoLabel }}</span>
        </div>
        <div class="trg-source-line">{{ sourceLine }}</div>
      </div>

      <!-- 触发策略详情 -->
      <div v-if="triggerPolicy" class="trg-policy">
        <div class="trg-policy-head">
          <span class="trg-policy-name">{{ triggerPolicy.name }}</span>
          <el-tag size="small" effect="plain">{{ policyTypeLabel }}</el-tag>
          <el-tag size="small" :type="triggerPolicy.enabled ? 'success' : 'info'" effect="plain">
            {{ triggerPolicy.enabled ? '已启用' : '已禁用' }}
          </el-tag>
        </div>
        <div class="trg-policy-body">
          <div class="trg-kv"><span class="k">黑名单</span><span>{{ aclSummary }}</span></div>
          <div class="trg-kv"><span class="k">信任名单</span><span>{{ trustSummary }}</span></div>
          <div class="trg-kv"><span class="k">地域拦截</span><span>{{ geoSummary }}</span></div>
        </div>
      </div>

      <!-- 引用地址列表成员明细 + 处置 -->
      <div v-if="memberLists.length > 0" class="trg-members">
        <div class="trg-members-title">此 IP 命中的地址列表</div>
        <div v-for="m in memberLists" :key="m.id" class="trg-member-row">
          <span class="trg-member-name" :title="m.name">{{ m.name }}</span>
          <el-tag v-if="m.system" size="small" effect="plain">内置只读</el-tag>
          <el-button
            v-else
            size="small"
            type="danger"
            plain
            :loading="busyListId === m.id"
            @click="removeFromList(m)"
          >从此列表移除</el-button>
        </div>
        <div v-if="memberSystemTip" class="trg-tip">{{ memberSystemTip }}</div>
      </div>

      <!-- 内联黑名单处置 -->
      <div v-if="inlineAclHit && triggerPolicy" class="trg-members">
        <div class="trg-members-title">此 IP 在策略「{{ triggerPolicy.name }}」的内联黑名单中</div>
        <el-button size="small" type="danger" plain @click="removeFromInlineAcl">从内联黑名单移除</el-button>
        <div class="trg-tip">移除将修改策略配置并重载 Caddy</div>
      </div>
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">关闭</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { request } from '@/utils/api'
import { parseIPList, parseRefIds } from '@/utils/securityStages'
import type { APIResponse } from '@/types'

const props = defineProps<{
  modelValue: boolean
  ip: string
  policyId: number
  policyName: string
  ruleTriggered: string
  ruleCaddyId?: string
  location?: string
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

interface PolicyRow {
  id: number
  name: string
  enabled: boolean
  policy_type?: string
  ip_acl_enabled?: boolean
  ip_acl_mode?: string
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_whitelist?: string
  ip_whitelist_enabled?: boolean
  ip_whitelist_refs?: string
  geoip_mode?: string
  geoip_countries?: string
}
interface ListRow { id: number; name: string; entry_count: number; system?: number }

const loading = ref(false)
const policies = ref<PolicyRow[]>([])
const lists = ref<ListRow[]>([])
const entriesCache = ref<Record<number, string[]>>({})

const triggerPolicy = computed(() => policies.value.find((p) => p.id === props.policyId))
const policyTypeLabel = computed(() => {
  const t = triggerPolicy.value?.policy_type ?? ''
  const map: Record<string, string> = { stage0: '阶段 0 · 信任名单', stage1: '阶段 1 · IP 访问控制', stage2: '阶段 2 · 限流', stage3: '阶段 3 · WAF', mixed: '存量混合' }
  return map[t] ?? t ?? '—'
})

const sourceKind = computed(() => {
  const n = Number(props.ruleTriggered)
  if (!Number.isFinite(n)) return 'unknown'
  if (n >= 800000 && n < 900000) return 'geo'
  if (n === 14) return 'threat'
  if (n === 3 || n === 12) return 'trust'
  return 'acl'
})
const sourceCategoryLabel = computed(() => {
  switch (sourceKind.value) {
    case 'geo': return '地域黑白名单'
    case 'threat': return '威胁情报库'
    case 'trust': return '信任名单'
    default: return 'IP 黑白名单'
  }
})
const sourceTagType = computed(() => (sourceKind.value === 'geo' ? 'warning' : sourceKind.value === 'threat' ? 'danger' : 'info'))

const loadAll = async (): Promise<void> => {
  loading.value = true
  try {
    const url = props.ruleCaddyId
      ? `/security/policies?enabled=true&rule_caddy_id=${encodeURIComponent(props.ruleCaddyId)}`
      : '/security/policies?enabled=true'
    const [polRes, listRes] = await Promise.allSettled([
      request.get<APIResponse<PolicyRow[]>>(url),
      request.get<APIResponse<ListRow[]>>('/security/ip-lists'),
    ])
    if (polRes.status === 'fulfilled') policies.value = polRes.value.data || []
    if (listRes.status === 'fulfilled') lists.value = listRes.value.data || []
    // 拉取在案引用名单的条目（成员判定值来源）；威胁库内置名单较大，仅拉策略引用到的
    const refIds = new Set<number>()
    for (const p of policies.value) {
      for (const id of parseRefIds(p.ip_acl_list_refs)) refIds.add(id)
      for (const id of parseRefIds(p.ip_whitelist_refs)) refIds.add(id)
    }
    const results = await Promise.allSettled(
      [...refIds].map((id) => request.get<APIResponse<{ id: number; name?: string; entries?: Array<{ value: string }> }>>(`/security/ip-lists/${id}`)),
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

// 触发来源描述行
const geoLabel = computed(() => {
  const p = triggerPolicy.value
  if (!p) return ''
  try {
    const regions = (JSON.parse(p.geoip_countries ?? '[]') as string[]).filter(Boolean)
    return regions.join('、')
  } catch {
    return ''
  }
})
const sourceLine = computed(() => {
  switch (sourceKind.value) {
    case 'geo':
      return `策略的地域拦截规则命中（来源区域：${geoLabel.value || '未知'}）`
    case 'threat': {
      const hit = threatSourceLists.value.map((l) => l.name)
      return hit.length > 0 ? `威胁情报库预检命中：${hit.join('、')}` : '威胁情报库预检命中'
    }
    case 'trust':
      return '来源 IP 命中信任名单（保留检测/直通语义，见策略详情）'
    default:
      return '来源 IP 命中策略黑名单'
  }
})

// 威胁情报库：判定命中的具体源库（策略引用列表中包含此 IP 且为系统内置名单）
const threatSourceLists = computed(() => {
  const p = triggerPolicy.value
  if (!p || sourceKind.value !== 'threat') return []
  return lists.value
    .filter((l) => l.system && parseRefIds(p.ip_acl_list_refs).includes(l.id))
    .filter((l) => (entriesCache.value[l.id] ?? []).includes(props.ip.trim()))
})

// 各引用列表中包含此 IP 的自定义列表（可移除）
const memberLists = computed(() => {
  const p = triggerPolicy.value
  if (!p) return []
  const refs = parseRefIds(p.ip_acl_list_refs)
  return lists.value
    .filter((l) => refs.includes(l.id) && !l.system)
    .filter((l) => (entriesCache.value[l.id] ?? []).includes(props.ip.trim()))
})
const memberSystemTip = computed(() => {
  const p = triggerPolicy.value
  if (!p) return ''
  const sysRefs = lists.value.filter((l) => l.system && parseRefIds(p.ip_acl_list_refs).includes(l.id) && (entriesCache.value[l.id] ?? []).includes(props.ip.trim()))
  return sysRefs.length > 0 ? '内置威胁名单为只读来源；误报可将其 IP 加入信任名单豁免，或调整策略引用。' : ''
})

const inlineAclHit = computed(() => {
  const p = triggerPolicy.value
  return !!p && sourceKind.value === 'acl' && parseIPList(p.ip_acl_list).includes(props.ip)
})

const aclSummary = computed(() => {
  const p = triggerPolicy.value
  if (!p) return '—'
  if (!p.ip_acl_enabled) return '未启用'
  const mode = p.ip_acl_mode === 'allow' ? '白名单模式' : p.ip_acl_mode === 'bypass' ? '旁路模式' : '黑名单模式'
  const inline = parseIPList(p.ip_acl_list).length
  const refs = parseRefIds(p.ip_acl_list_refs)
  const refNames = lists.value.filter((l) => refs.includes(l.id)).map((l) => l.name)
  const refPart = refNames.length > 0 ? `引用：${refNames.join('、')}` : ''
  return `${mode} · 内联 ${inline} 条${refPart ? ` · ${refPart}` : ''}`
})
const trustSummary = computed(() => {
  const p = triggerPolicy.value
  if (!p) return '—'
  if (!p.ip_whitelist_enabled) return '未启用'
  const inline = parseIPList(p.ip_whitelist).length
  const refs = parseRefIds(p.ip_whitelist_refs)
  const refNames = lists.value.filter((l) => refs.includes(l.id)).map((l) => l.name)
  return `内联 ${inline} 条${refNames.length > 0 ? ` · 引用：${refNames.join('、')}` : ''}`
})
const geoSummary = computed(() => {
  const p = triggerPolicy.value
  if (!p) return '—'
  if (p.geoip_mode === 'off' || !p.geoip_mode) return '未启用'
  const regions = (() => { try { return (JSON.parse(p.geoip_countries ?? '[]') as string[]).join('、') } catch { return '—' } })()
  return `${p.geoip_mode === 'allow' ? '仅允许' : '拦截'}区域：${regions || '—'}`
})

const busyListId = ref<number | null>(null)
const removeFromList = async (m: { id: number; name: string }): Promise<void> => {
  busyListId.value = m.id
  try {
    const res = await request.delete<APIResponse<{ removed: boolean }>>(`/security/ip-lists/${m.id}/ips`, { data: { value: props.ip } } as never)
    if (res.data?.removed) {
      ElMessage.success(`已从「${m.name}」移除`)
      const next = { ...entriesCache.value, [m.id]: (entriesCache.value[m.id] ?? []).filter((v) => v !== props.ip.trim()) }
      entriesCache.value = next
    } else {
      ElMessage.info('该 IP 已不在此列表中')
    }
  } finally {
    busyListId.value = null
  }
}

const removeFromInlineAcl = async (): Promise<void> => {
  const p = triggerPolicy.value
  if (!p) return
  const kept = parseIPList(p.ip_acl_list).filter((v) => v !== props.ip.trim())
  await request.put(`/security/policies/${p.id}`, { ip_acl_list: JSON.stringify(kept) })
  ElMessage.success('已从内联黑名单移除（策略已重载）')
}

watch(() => props.modelValue, (v) => {
  if (v) void loadAll()
})
</script>

<style scoped>
.trg-source { border: 1px solid var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-source--geo { border-color: var(--el-color-warning-light-7); background: var(--el-color-warning-light-9); }
.trg-source--threat { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-source--trust { border-color: var(--el-color-success-light-7); background: var(--el-color-success-light-9); }
.trg-source--acl { border-color: var(--el-color-danger-light-7); background: var(--el-color-danger-light-9); }
.trg-source-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.trg-source-ip { font-weight: 700; font-size: 14px; }
.trg-source-geo { color: var(--el-text-color-secondary); font-size: 12px; }
.trg-source-line { font-size: 13px; color: var(--el-text-color-primary); }
.trg-policy { border: 1px solid var(--el-border-color); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.trg-policy-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.trg-policy-name { font-weight: 600; }
.trg-policy-body { display: grid; gap: 4px; }
.trg-kv { display: flex; gap: 8px; font-size: 13px; }
.trg-kv .k { color: var(--el-text-color-secondary); flex-shrink: 0; width: 64px; }
.trg-members { margin-top: 4px; }
.trg-members-title { font-size: 13px; font-weight: 600; margin-bottom: 6px; }
.trg-member-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 4px 0; }
.trg-member-name { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trg-tip { font-size: 12px; color: var(--el-text-color-secondary); margin-top: 6px; }
</style>
