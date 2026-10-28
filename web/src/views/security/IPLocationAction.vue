<template>
  <el-popover
    v-if="canManage"
    :width="452"
    trigger="click"
    popper-class="ip-quick-popper"
    :popper-options="popperViewportSafe"
    @before-enter="onPopoverShow"
  >
    <template #reference>
      <span
        class="ip-cell ip-clickable"
        role="button"
        tabindex="0"
        :aria-label="`IP 名单管理：${ip}`"
        :title="location ? `${ip} · ${location}` : ip"
        @keydown.enter.prevent="activateOnce($event, () => openFromKeyboard($event))"
        @keydown.space.prevent="activateOnce($event, () => openFromKeyboard($event))"
      >
        <span class="ip-text">{{ ip }}</span>
        <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
      </span>
    </template>

    <div class="ipm-shell">
      <header class="ipm-header">
        <div>
          <div class="ipm-kicker">IP 名单管理</div>
          <div class="ipm-ip">{{ trimmedIp }}</div>
          <div v-if="location" class="ipm-location">{{ location }}</div>
        </div>
        <el-tooltip v-if="eventCount !== null" content="近 30 天安全事件" placement="top">
          <span class="ipm-event-count"><strong>{{ eventCount }}</strong> 次事件</span>
        </el-tooltip>
      </header>

      <div v-if="loadError" class="ipm-error" role="alert">
        <span>名单状态读取不完整，暂不能写入</span>
        <button type="button" @click="retryAll">重新加载</button>
      </div>

      <main class="ipm-body">
        <section v-for="section in sections" :key="section.side" class="ipm-section" :class="`is-${section.side}`">
          <div class="ipm-section-head">
            <span class="ipm-section-mark" aria-hidden="true"></span>
            <div class="ipm-section-title">
              <h3>{{ section.title }}</h3>
              <p>{{ section.description }}</p>
            </div>
            <button
              type="button"
              class="ipm-add"
              :disabled="writeUnavailable"
              @click="openAdd(section.side)"
            >
              <el-icon><Plus /></el-icon>
              添加
            </button>
          </div>

          <div v-if="activeAddSide === section.side" class="ipm-target-panel">
            <template v-if="model[section.side].targets.length > 0">
              <div class="ipm-target-title">选择目标名单</div>
              <label
                v-for="target in model[section.side].targets"
                :key="target.key"
                class="ipm-target"
                :class="{ 'is-selected': selectedTargetKey === target.key }"
              >
                <input v-model="selectedTargetKey" type="radio" :value="target.key" />
                <span class="ipm-target-copy">
                  <strong>{{ target.name }}</strong>
                  <small>{{ target.kind === 'list' ? `${target.entryCount} 条 · ${target.policies.length} 个策略引用` : `关联策略：${target.policies[0]?.name}` }}</small>
                </span>
              </label>
              <div class="ipm-target-actions">
                <button type="button" class="ipm-button is-quiet" @click="activeAddSide = null">取消</button>
                <button
                  type="button"
                  class="ipm-button is-primary"
                  :disabled="!selectedTargetKey || actionBusy"
                  @click="executeAdd"
                >
                  {{ actionBusy ? '正在写入…' : '确认添加' }}
                </button>
              </div>
            </template>
            <div v-else class="ipm-no-target">
              没有可写入的{{ section.title }}策略。请先在安全策略中创建对应策略。
              <a href="#/security-policies">前往安全策略</a>
            </div>
          </div>

          <div v-if="model[section.side].sources.length === 0" class="ipm-empty">
            {{ loading ? '正在读取名单…' : `未加入${section.title}` }}
          </div>
          <div v-else class="ipm-source-list">
            <article
              v-for="source in model[section.side].sources"
              :key="source.key"
              class="ipm-source"
              :class="{ 'is-clickable': source.policies.length > 0 }"
              :role="source.policies.length > 0 ? 'button' : undefined"
              :tabindex="source.policies.length > 0 ? 0 : undefined"
              :aria-expanded="source.policies.length > 0 ? expandedRefs.has(source.key) : undefined"
              @click="source.policies.length > 0 && toggleRefs(source.key)"
              @keydown.enter.prevent="source.policies.length > 0 && activateOnce($event, () => toggleRefs(source.key))"
              @keydown.space.prevent="source.policies.length > 0 && activateOnce($event, () => toggleRefs(source.key))"
            >
              <div class="ipm-source-main">
                <div class="ipm-source-name" :title="source.name">{{ source.name }}</div>
                <div class="ipm-source-meta">
                  <span v-if="source.kind === 'inline'">策略内联 · {{ source.entryCount }} 条</span>
                  <span v-else>{{ source.entryCount }} 条 · {{ source.policies.length }} 个策略引用</span>
                  <span v-if="!source.exact" class="ipm-cidr">命中 {{ source.matchedEntry }}</span>
                </div>
                <div v-if="expandedRefs.has(source.key)" class="ipm-ref-list">
                  <div class="ipm-ref-title">引用此名单的策略</div>
                  <span v-for="policy in source.policies" :key="policy.id">{{ policy.name }}</span>
                </div>
              </div>
              <div class="ipm-source-actions">
                <a v-if="!source.exact" class="ipm-text-button" :href="source.kind === 'list' ? '#/security-rules?tab=ip-lists' : '#/security-policies'" @click.stop>编辑</a>
                <button
                  v-else
                  type="button"
                  class="ipm-remove"
                  @click.stop="removeSource(section.side, source)"
                  :disabled="writeUnavailable || actionBusy"
                >
                  移除
                </button>
              </div>
            </article>
          </div>
        </section>

        <section class="ipm-section is-autoban">
          <div class="ipm-section-head">
            <span class="ipm-section-mark" aria-hidden="true"></span>
            <div class="ipm-section-title">
              <h3>自动封禁</h3>
              <p>仅管理自动封禁名单，不改变其它名单</p>
            </div>
          </div>
          <div v-if="autobanLoading" class="ipm-empty">正在读取封禁状态…</div>
          <div v-else-if="autobanError" class="ipm-autoban-error">
            封禁状态读取失败
            <button type="button" class="ipm-text-button" @click="retryAutoban">重试</button>
          </div>
          <div v-else-if="!autobanHit" class="ipm-empty">当前未被封禁</div>
          <article v-else class="ipm-source ipm-autoban-hit">
            <div class="ipm-source-main">
              <div class="ipm-source-name">
                {{ autoban?.listName || '自动封禁名单' }}
                <span class="ipm-ban-state">{{ autobanExpired ? '已到期' : '封禁中' }}</span>
              </div>
              <div class="ipm-source-meta">命中条目：{{ autobanHit.value }}</div>
              <div class="ipm-source-meta">
                <template v-if="!autobanHit.expires_at">永久封禁</template>
                <template v-else>{{ formatDate(autobanHit.expires_at) }} · {{ autobanExpired ? '可清理' : `剩余 ${autobanRemaining}` }}</template>
              </div>
            </div>
            <div class="ipm-source-actions">
              <a v-if="autobanHitIsCidr" class="ipm-text-button" href="#/security-rules?tab=ip-lists">编辑</a>
              <button v-else type="button" class="ipm-remove" :disabled="autobanUnbanning" @click="unbanAutoban">
                {{ autobanExpired ? '清理' : '移除封禁' }}
              </button>
            </div>
          </article>
        </section>
      </main>

      <footer class="ipm-footer">名单修改会同步到所有引用它的策略</footer>
    </div>
  </el-popover>

  <span v-else class="ip-cell" :title="location ? `${ip} · ${location}` : ip">
    <span class="ip-text">{{ ip }}</span>
    <span v-if="location" class="ip-loc" :title="location">{{ compactLocation }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { useAuthStore } from '@/stores/auth'
import { useTrustAssociation } from '@/composables/useTrustAssociation'
import type { IpListOption } from '@/composables/useIpListAdd'
import { entryMatchesIp, invalidateSharedEntriesCache, ensureSharedEntriesMissing, sharedEntriesCache, subscribeSharedEntriesCache, parseIPList, parseRefIds } from '@/utils/securityStages'
import { buildIpQuickModel, type IpQuickPolicy, type IpQuickList, type IpQuickSide, type IpQuickSource } from '@/utils/ipQuickLists'
import { popperViewportSafe } from '@/utils/popper'
import { activateOnce } from '@/utils/keyboardActivate'
import { formatDate } from '@/utils/date'
import { autobanEntryExpired, autobanEntryRemaining } from '@/utils/autobanEntry'
import type { APIResponse } from '@/types'

const props = defineProps<{ ip: string; location: string }>()
const trimmedIp = computed(() => props.ip.trim())
const compactLocation = computed(() => {
  if (!props.location) return ''
  const parts = props.location.split('·').map((part) => part.trim()).filter(Boolean)
  if (parts[0] === '保留地址') return '保留地址'
  if (parts[0] !== '中国') return parts[0]
  if (parts.length === 1) return '中国'
  return parts.length === 2 ? parts[1] : parts[2]
})

const authStore = useAuthStore()
const canManage = computed(() => authStore.readOnlyReason === null)
const openFromKeyboard = (event: KeyboardEvent): void => (event.currentTarget as HTMLElement).click()

const sections: Array<{ side: IpQuickSide; title: string; description: string }> = [
  { side: 'deny', title: '黑名单', description: '用于显式拒绝的 IP 名单' },
  { side: 'allow', title: '白名单', description: '用于允许访问的 IP 名单' },
  { side: 'trust', title: '信任列表', description: '用于信任策略的 IP 名单' },
]

interface IpListSummary extends IpListOption, IpQuickList {
  preset_autoban?: boolean
  ref_policies?: Array<{ id: number; name: string }>
}
interface IpListEntryPayload {
  value: string
  remark?: string
  expires_at?: string
}
interface IpListDetailPayload {
  id: number
  name?: string
  entries?: IpListEntryPayload[]
}
interface AutobanState {
  listId: number
  listName: string
  entries: IpListEntryPayload[]
}

const policies = ref<IpQuickPolicy[]>([])
const ipLists = ref<IpListSummary[]>([])
const ipListEntries = ref<Record<number, string[]>>({ ...sharedEntriesCache })
const loading = ref(false)
const loadError = ref(false)
const actionBusy = ref(false)
let loadSeq = 0
let unregisterEntriesCache: (() => void) | null = null

onMounted(() => {
  unregisterEntriesCache = subscribeSharedEntriesCache(() => {
    ipListEntries.value = { ...sharedEntriesCache }
  })
})
onUnmounted(() => unregisterEntriesCache?.())

const model = computed(() => buildIpQuickModel(trimmedIp.value, policies.value, ipLists.value, ipListEntries.value))
const writeUnavailable = computed(() => loading.value || loadError.value || actionBusy.value)

const loadListDetail = async (id: number): Promise<IpListDetailPayload> => {
  const res = await request.get<APIResponse<IpListDetailPayload>>(`/security/ip-lists/${id}`)
  return res.data ?? { id, entries: [] }
}
const loadListEntries = async (id: number): Promise<string[]> => {
  const detail = await loadListDetail(id)
  return (detail.entries || []).map((entry) => entry.value.trim()).filter(Boolean)
}

const loadAll = async (): Promise<void> => {
  const seq = ++loadSeq
  loading.value = true
  loadError.value = false
  try {
    const [policyRes, listRes] = await Promise.all([
      request.get<APIResponse<IpQuickPolicy[]>>('/security/policies'),
      request.get<APIResponse<IpListSummary[]>>('/security/ip-lists'),
    ])
    if (seq !== loadSeq) return
    policies.value = (policyRes.data || []).map((policy) => ({
      ...policy,
      ip_acl_mode: policy.ip_acl_mode || '',
      ip_acl_list: policy.ip_acl_list || '[]',
      ip_whitelist: policy.ip_whitelist || '[]',
    }))
    ipLists.value = listRes.data || []
    const refIds = new Set<number>()
    for (const policy of policies.value) {
      for (const id of parseRefIds(policy.ip_acl_list_refs)) refIds.add(id)
      for (const id of parseRefIds(policy.ip_whitelist_refs)) refIds.add(id)
    }
    const missing = await ensureSharedEntriesMissing(refIds, loadListEntries)
    if (seq !== loadSeq) return
    ipListEntries.value = { ...sharedEntriesCache }
    loadError.value = missing.length > 0
  } catch {
    if (seq === loadSeq) loadError.value = true
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

const refreshAfterWrite = async (): Promise<void> => {
  invalidateSharedEntriesCache()
  await loadAll()
}
const trustApi = useTrustAssociation({ getList: () => ipLists.value, onChanged: refreshAfterWrite })
const { ensureListAndJoin, removeFromSideRef } = trustApi

const activeAddSide = ref<IpQuickSide | null>(null)
const selectedTargetKey = ref('')
const openAdd = (side: IpQuickSide): void => {
  activeAddSide.value = activeAddSide.value === side ? null : side
  const targets = model.value[side].targets
  selectedTargetKey.value = targets.length === 1 ? targets[0].key : ''
}
const executeAdd = async (): Promise<void> => {
  const side = activeAddSide.value
  if (!side || actionBusy.value) return
  const target = model.value[side].targets.find((item) => item.key === selectedTargetKey.value)
  if (!target) return
  actionBusy.value = true
  try {
    if (target.kind === 'list' && target.listId) {
      const res = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${target.listId}/ips`, { value: trimmedIp.value })
      if (res.data?.added) showSaveResult(res as unknown as { message?: string }, `已将 ${trimmedIp.value} 加入「${target.name}」`)
      else ElMessage.info(`该 IP 已在「${target.name}」中`)
      await refreshAfterWrite()
    } else if (target.policyId) {
      const policy = policies.value.find((item) => item.id === target.policyId)
      if (policy) await ensureListAndJoin(policy, trimmedIp.value, side)
    }
    activeAddSide.value = null
    selectedTargetKey.value = ''
  } finally {
    actionBusy.value = false
  }
}

const removeSource = async (side: IpQuickSide, source: IpQuickSource): Promise<void> => {
  if (actionBusy.value) return
  if (source.kind === 'list' && source.listId) {
    actionBusy.value = true
    try {
      await removeFromSideRef({ id: source.listId, name: source.name }, trimmedIp.value)
    } finally {
      actionBusy.value = false
    }
    return
  }
  if (!source.policyId) return
  actionBusy.value = true
  try {
    await ElMessageBox.confirm(`将从策略「${source.name}」的内联名单移除 ${trimmedIp.value}。是否继续？`, '从内联名单移除', {
      confirmButtonText: '确认移除', cancelButtonText: '取消', type: 'warning',
    })
    const detail = await request.get<APIResponse<{ policy: IpQuickPolicy }>>(`/security/policies/${source.policyId}`)
    const latest = detail.data?.policy
    if (!latest) throw new Error('策略读取失败')
    const field = side === 'trust' ? 'ip_whitelist' : 'ip_acl_list'
    const remaining = parseIPList(latest[field]).filter((entry) => entry !== trimmedIp.value)
    const res = await request.put(`/security/policies/${source.policyId}`, { [field]: JSON.stringify(remaining) })
    showSaveResult(res as unknown as { message?: string }, `已从「${source.name}」移除 ${trimmedIp.value}`)
    await refreshAfterWrite()
  } catch {
    // 取消或失败由既有确认框/全局请求拦截器处理。
  } finally {
    actionBusy.value = false
  }
}

const expandedRefs = ref<Set<string>>(new Set())
const toggleRefs = (key: string): void => {
  const next = new Set(expandedRefs.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  expandedRefs.value = next
}

const autoban = ref<AutobanState | null>(null)
const autobanLoading = ref(false)
const autobanError = ref(false)
const autobanUnbanning = ref(false)
let autobanSeq = 0
const loadAutoban = async (): Promise<void> => {
  const seq = ++autobanSeq
  autobanLoading.value = true
  autobanError.value = false
  try {
    let list = ipLists.value.find((item) => item.preset_autoban === true)
    if (!list) {
      const res = await request.get<APIResponse<IpListSummary[]>>('/security/ip-lists', { silent: true })
      if (seq !== autobanSeq) return
      list = (res.data || []).find((item) => item.preset_autoban === true)
    }
    if (!list) {
      autoban.value = null
      return
    }
    const detail = await loadListDetail(list.id)
    if (seq !== autobanSeq) return
    autoban.value = {
      listId: list.id,
      listName: detail.name || list.name,
      entries: (detail.entries || []).map((entry) => ({ ...entry, value: entry.value.trim() })),
    }
  } catch {
    if (seq === autobanSeq) {
      autoban.value = null
      autobanError.value = true
    }
  } finally {
    if (seq === autobanSeq) autobanLoading.value = false
  }
}
const autobanHit = computed(() => autoban.value?.entries.find((entry) => entryMatchesIp(entry.value, trimmedIp.value)) ?? null)
const autobanExpired = computed(() => Boolean(autobanHit.value?.expires_at && autobanEntryExpired(autobanHit.value.expires_at)))
const autobanRemaining = computed(() => autobanHit.value?.expires_at ? autobanEntryRemaining(autobanHit.value.expires_at) : '')
const autobanHitIsCidr = computed(() => autobanHit.value?.value.includes('/') ?? false)
const retryAutoban = (): void => { void loadAutoban() }
const unbanAutoban = async (): Promise<void> => {
  const hit = autobanHit.value
  const listId = autoban.value?.listId
  if (!hit || !listId || autobanHitIsCidr.value || autobanUnbanning.value) return
  autobanUnbanning.value = true
  try {
    await ElMessageBox.confirm(
      `将把 ${hit.value} 从自动封禁名单移除，并清空该 IP 的自动封禁计数。其它黑名单和安全策略不受影响。是否继续？`,
      autobanExpired.value ? '清理过期封禁' : '移除自动封禁',
      { confirmButtonText: '确认移除', cancelButtonText: '取消', type: 'warning' },
    )
    const res = await request.post(`/security/ip-lists/${listId}/remove-ip`, { value: hit.value })
    showSaveResult(res as unknown as { message?: string }, `已从自动封禁名单移除 ${hit.value}`)
    invalidateSharedEntriesCache()
    await Promise.all([loadAll(), loadAutoban()])
  } catch {
    // 取消或失败由既有确认框/全局请求拦截器处理。
  } finally {
    autobanUnbanning.value = false
  }
}

const eventCount = ref<number | null>(null)
let eventCountSeq = 0
const loadEventCount = async (): Promise<void> => {
  const seq = ++eventCountSeq
  try {
    const res = await request.get<APIResponse<{ count: number }>>('/security/events/count', { params: { ip: trimmedIp.value, days: 30 }, silent: true })
    if (seq === eventCountSeq) eventCount.value = res.data?.count ?? 0
  } catch {
    if (seq === eventCountSeq) eventCount.value = null
  }
}
const onPopoverShow = (): void => {
  eventCount.value = null
  activeAddSide.value = null
  selectedTargetKey.value = ''
  void loadAll()
  void loadAutoban()
  void loadEventCount()
}
const retryAll = (): void => { void loadAll() }
</script>

<style scoped>
.ip-cell { display: inline-flex; align-items: center; gap: 4px; max-width: 100%; vertical-align: middle; }
.ip-clickable { cursor: pointer; border-radius: 3px; padding: 1px 3px; margin: -1px -3px; transition: background 0.15s, color 0.15s; }
.ip-clickable:hover { background: var(--el-color-primary-light-9, #ecf5ff); }
.ip-clickable:hover .ip-text { color: var(--el-color-primary, #409eff); }
.ip-clickable:active { background: var(--el-color-primary-light-8, #d9ecff); }
.ip-clickable:focus-visible { outline: 2px solid var(--el-color-primary, #409eff); outline-offset: 2px; }
.ip-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ip-loc { font-size: 11px; color: var(--text-secondary, #909399); white-space: nowrap; max-width: 72px; overflow: hidden; text-overflow: ellipsis; flex-shrink: 1; }
</style>

<style>
.ip-quick-popper.el-popover {
  padding: 0 !important;
  overflow: hidden;
  border: 1px solid var(--el-border-color-lighter, #e4e9f0);
  border-radius: 0;
  box-shadow: 0 18px 50px rgb(15 23 42 / 16%), 0 3px 12px rgb(15 23 42 / 7%);
}
.ip-quick-popper .ipm-shell {
  color: var(--el-text-color-primary, #1f2937);
  background: var(--el-bg-color, #fff);
  font-size: 12px;
}
.ip-quick-popper .ipm-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 20px 20px 17px;
  background: linear-gradient(135deg, rgb(59 130 246 / 7%), rgb(14 165 233 / 2%));
  border-bottom: 1px solid var(--el-border-color-lighter, #e8edf3);
}
.ip-quick-popper .ipm-kicker {
  margin-bottom: 5px;
  color: var(--el-text-color-secondary, #7a8699);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1px;
}
.ip-quick-popper .ipm-ip {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 21px;
  font-weight: 700;
  letter-spacing: -.4px;
  line-height: 1.25;
  overflow-wrap: anywhere;
}
.ip-quick-popper .ipm-location { margin-top: 5px; color: var(--el-text-color-secondary, #778196); }
.ip-quick-popper .ipm-event-count {
  flex: none;
  padding: 6px 9px;
  color: var(--el-text-color-secondary, #6f7b8f);
  background: rgb(255 255 255 / 70%);
  border: 1px solid rgb(148 163 184 / 22%);
  border-radius: 0;
  white-space: nowrap;
}
.ip-quick-popper .ipm-event-count strong { margin-right: 2px; color: var(--el-color-primary, #3b82f6); font-size: 15px; }
.ip-quick-popper .ipm-body { max-height: min(620px, 66vh); padding: 8px 14px; overflow-y: auto; }
.ip-quick-popper .ipm-section { padding: 13px 6px 12px; border-bottom: 1px solid var(--el-border-color-lighter, #edf0f4); }
.ip-quick-popper .ipm-section:last-child { border-bottom: 0; }
.ip-quick-popper .ipm-section-head { display: flex; align-items: center; gap: 9px; }
.ip-quick-popper .ipm-section-mark { width: 7px; height: 24px; flex: none; border-radius: 0; background: #94a3b8; }
.ip-quick-popper .is-deny .ipm-section-mark { background: #e06565; }
.ip-quick-popper .is-allow .ipm-section-mark { background: #4d8fe8; }
.ip-quick-popper .is-trust .ipm-section-mark { background: #43a580; }
.ip-quick-popper .is-autoban .ipm-section-mark { background: #d99a3d; }
.ip-quick-popper .ipm-section-title { min-width: 0; flex: 1; }
.ip-quick-popper .ipm-section-title h3 { margin: 0; font-size: 13px; font-weight: 650; line-height: 1.35; }
.ip-quick-popper .ipm-section-title p { margin: 2px 0 0; color: var(--el-text-color-secondary, #8a94a6); font-size: 11px; }
.ip-quick-popper button { font: inherit; }
.ip-quick-popper .ipm-add {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 5px 9px;
  color: var(--el-color-primary, #357cd8);
  background: transparent;
  border: 1px solid rgb(53 124 216 / 22%);
  border-radius: 0;
  cursor: pointer;
  transition: background .15s, border-color .15s;
}
.ip-quick-popper .ipm-add:hover:not(:disabled) { background: rgb(53 124 216 / 7%); border-color: rgb(53 124 216 / 40%); }
.ip-quick-popper .ipm-add:disabled, .ip-quick-popper .ipm-remove:disabled, .ip-quick-popper .ipm-button:disabled { opacity: .45; cursor: not-allowed; }
.ip-quick-popper .ipm-empty { padding: 11px 0 2px 16px; color: var(--el-text-color-secondary, #98a1af); }
.ip-quick-popper .ipm-source-list { display: grid; gap: 7px; padding-top: 10px; }
.ip-quick-popper .ipm-source {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 11px;
  background: var(--el-fill-color-lighter, #f8fafc);
  border: 1px solid var(--el-border-color-lighter, #e9edf2);
  border-radius: 0;
  transition: border-color .15s, background .15s;
}
.ip-quick-popper .ipm-source:hover { background: var(--el-bg-color, #fff); border-color: var(--el-border-color, #d7dee8); }
.ip-quick-popper .ipm-source.is-clickable { cursor: pointer; }
.ip-quick-popper .ipm-source.is-clickable:focus-visible { outline: 2px solid var(--el-color-primary, #3b82f6); outline-offset: 2px; }
.ip-quick-popper .ipm-source-main { min-width: 0; flex: 1; }
.ip-quick-popper .ipm-source-name { overflow: hidden; font-size: 12px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.ip-quick-popper .ipm-source-meta { display: flex; flex-wrap: wrap; gap: 4px 8px; margin-top: 4px; color: var(--el-text-color-secondary, #8792a3); font-size: 11px; }
.ip-quick-popper .ipm-cidr { color: var(--el-color-warning, #b57b24); }
.ip-quick-popper .ipm-source-actions { display: flex; flex: none; align-items: center; gap: 5px; }
.ip-quick-popper .ipm-remove, .ip-quick-popper .ipm-text-button {
  padding: 3px 5px;
  color: var(--el-text-color-secondary, #778296);
  background: transparent;
  border: 0;
  border-radius: 0;
  text-decoration: none;
  cursor: pointer;
}
.ip-quick-popper .ipm-remove { padding: 4px 8px; color: var(--el-color-danger-dark-2, #b4232d); background: var(--el-color-danger-light-9, #fef0f0); border: 1px solid var(--el-color-danger-light-7, #f3b6b6); font-weight: 500; }
.ip-quick-popper .ipm-remove:hover:not(:disabled), .ip-quick-popper .ipm-text-button:hover { background: rgb(100 116 139 / 8%); color: var(--el-text-color-primary, #334155); }
.ip-quick-popper .ipm-ref-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }
.ip-quick-popper .ipm-ref-title { flex-basis: 100%; color: var(--el-text-color-secondary, #8a94a6); font-size: 10px; }
.ip-quick-popper .ipm-ref-list span { padding: 2px 6px; background: var(--el-bg-color, #fff); border: 1px solid var(--el-border-color-lighter, #e5eaf0); border-radius: 0; color: var(--el-text-color-secondary, #6f7b8c); font-size: 10px; }
.ip-quick-popper .ipm-target-panel { margin: 11px 0 3px 16px; padding: 11px; background: rgb(59 130 246 / 4%); border: 1px solid rgb(59 130 246 / 14%); border-radius: 0; }
.ip-quick-popper .ipm-target-title { margin-bottom: 7px; color: var(--el-text-color-secondary, #718096); font-size: 11px; }
.ip-quick-popper .ipm-target { display: flex; align-items: center; gap: 8px; padding: 8px; border: 1px solid transparent; border-radius: 0; cursor: pointer; }
.ip-quick-popper .ipm-target.is-selected { background: var(--el-bg-color, #fff); border-color: rgb(59 130 246 / 24%); }
.ip-quick-popper .ipm-target input { accent-color: var(--el-color-primary, #3b82f6); }
.ip-quick-popper .ipm-target-copy { display: grid; min-width: 0; gap: 2px; }
.ip-quick-popper .ipm-target-copy strong { overflow: hidden; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.ip-quick-popper .ipm-target-copy small { color: var(--el-text-color-secondary, #8490a2); }
.ip-quick-popper .ipm-target-actions { display: flex; justify-content: flex-end; gap: 7px; margin-top: 9px; }
.ip-quick-popper .ipm-button { padding: 5px 11px; border: 1px solid var(--el-border-color, #d5dce6); border-radius: 0; cursor: pointer; }
.ip-quick-popper .ipm-button.is-quiet { color: var(--el-text-color-secondary, #6f7b8c); background: var(--el-bg-color, #fff); }
.ip-quick-popper .ipm-button.is-primary { color: #fff; background: var(--el-color-primary, #3b82f6); border-color: var(--el-color-primary, #3b82f6); }
.ip-quick-popper .ipm-no-target { color: var(--el-text-color-secondary, #7c8798); line-height: 1.6; }
.ip-quick-popper .ipm-no-target a { display: inline-block; margin-left: 6px; color: var(--el-color-primary, #3b82f6); }
.ip-quick-popper .ipm-ban-state { margin-left: 6px; padding: 2px 5px; color: #a76a16; background: rgb(217 154 61 / 10%); border-radius: 0; font-size: 10px; font-weight: 500; }
.ip-quick-popper .ipm-autoban-hit { background: rgb(217 154 61 / 5%); border-color: rgb(217 154 61 / 18%); }
.ip-quick-popper .ipm-autoban-error { display: flex; justify-content: space-between; padding: 10px 0 0 16px; color: var(--el-color-warning, #b57b24); }
.ip-quick-popper .ipm-error { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 20px; color: var(--el-color-warning, #a86c17); background: rgb(217 154 61 / 8%); }
.ip-quick-popper .ipm-error button { padding: 0; color: inherit; background: none; border: 0; text-decoration: underline; cursor: pointer; }
.ip-quick-popper .ipm-footer { padding: 10px 20px; color: var(--el-text-color-secondary, #98a1af); background: var(--el-fill-color-lighter, #fafbfc); border-top: 1px solid var(--el-border-color-lighter, #edf0f4); font-size: 11px; text-align: center; }
</style>
