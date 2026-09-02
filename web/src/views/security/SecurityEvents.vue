<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Warning /></el-icon>
          事件日志
        </h2>
        <p class="page-desc">查看 WAF 拦截和检测的安全事件记录</p>
      </div>
      <el-button :icon="Refresh" @click="fetchEvents">刷新</el-button>
    </div>

    <el-card>
      <div class="table-toolbar">
        <el-date-picker
          v-model="filters.timeRange"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="filter-date-range"
        />
        <el-select v-model="filters.action" placeholder="动作" clearable style="width: 120px">
          <el-option label="拦截" value="blocked" />
          <el-option label="检测" value="logged" />
        </el-select>
        <!-- R72 十九次（用户需求）：规则 ID 筛选替换为三列（负载规则/触发规则/策略）
             服务端筛选（rule_name/rule_triggered/policy_name LIKE）。 -->
        <el-input v-model="filters.rule_name" placeholder="负载规则" clearable style="width: 140px" @keyup.enter="applyFilters" />
        <!-- R72 二十次：触发规则改下拉+可输入——选项即表格显示的 family 标签（后端
             映射为 ID 前缀匹配）；也可直接输入 CRS 规则 ID（如 942100）或消息关键词。 -->
        <el-select v-model="filters.rule_triggered" placeholder="触发规则" clearable filterable allow-create style="width: 140px">
          <el-option label="IP 访问控制" value="IP 访问控制" />
          <el-option label="请求阻断评估" value="请求阻断评估" />
          <el-option label="协议异常" value="协议异常" />
          <el-option label="协议攻击" value="协议攻击" />
          <el-option label="自定义规则" value="自定义规则" />
        </el-select>
        <el-input v-model="filters.policy_name" placeholder="策略" clearable style="width: 120px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.ip" placeholder="IP 地址" clearable style="width: 150px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.uri" placeholder="URI" clearable style="width: 160px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>

      <el-table :data="events" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty description="暂无安全事件" :image-size="60" /></template>
        <el-table-column prop="event_time" label="时间" width="170" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
        <el-table-column label="动作" width="90" align="center">
          <template #default="{ row }">
            <el-tag :type="row.action === 'blocked' ? 'danger' : 'warning'" size="small" effect="light">{{ row.action === 'blocked' ? '拦截' : '检测' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="规则" min-width="140">
          <template #default="{ row }">
            <el-link v-if="row.rule_name || row.rule_caddy_id" type="primary" @click="goToRule(row)">{{ row.rule_name || row.rule_caddy_id || '—' }}</el-link>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="触发规则" min-width="100">
          <template #default="{ row }">
            <!-- CRS 规则（6 位 9xxxxx）：链接打开详情 + 快捷排除弹框；自定义 5 位/IP 族
                 1-8 维持原纯文本 + msg 悬浮，无链接行为 -->
            <el-link v-if="isCrsRuleId(row.rule_triggered)" type="primary" @click="openCrsDialog(row)">{{ triggeredLabel(row) }}</el-link>
            <el-tooltip v-else-if="showTriggeredMsg(row)" :content="row.rule_msg" placement="top" :show-after="200">
              <span class="cell-tip">{{ triggeredLabel(row) }}</span>
            </el-tooltip>
            <span v-else>{{ triggeredLabel(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="策略" min-width="170">
          <template #default="{ row }">
            <el-link v-if="row.policy_name || row.policy_id > 0" type="primary" @click="goToPolicy(row)">{{ row.policy_name || row.policy_id }}</el-link>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="客户端 IP" min-width="150">
          <template #default="{ row }">
            <IPLocationAction :ip="row.client_ip" :location="row.ip_location" :rule-caddy-id="row.rule_caddy_id" />
          </template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="70" align="center" />
        <el-table-column prop="uri" label="URI" min-width="180" show-overflow-tooltip />
        <!-- R72 二十二次（用户需求）：异常评分列——CRS 评分制下每事件携带的累计
             anomaly_score（后端已返回，此前未展示）；按分数着色便于快速识别高威胁。 -->
        <el-table-column label="评分" width="80" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.anomaly_score >= 15" type="danger" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <el-tag v-else-if="row.anomaly_score >= 5" type="warning" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <span v-else-if="row.anomaly_score > 0" class="text-secondary">{{ row.anomaly_score }}</span>
            <span v-else>—</span>
          </template>
        </el-table-column>
      </el-table>

      <div style="margin-top: 16px; display: flex; align-items: center;">
        <LogStorageBar log-key="security_events" style="margin-right: auto" />
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="fetchEvents"
        />
      </div>
    </el-card>

    <!-- CRS 规则详情 + 快捷排除：索引查 id/msg 全文/file/category，源码片段取该 ID
          所在行 ±10 行（apacheconf 高亮，默认折叠、展开才拉取）；索引无此 ID →
          「当前 CRS 已无此规则」仍可排除。提交 = GET 策略现有 crs_excluded_rules →
          追加一行 → PUT 全量（线上形态 ips 为逗号分隔字符串，见 confirmCrsExclude）。 -->
    <el-dialog v-model="crsDialogVisible" :title="`CRS 规则 ${crsEvent?.rule_triggered ?? ''}`" width="min(760px, 94vw)" top="5vh" append-to-body class="crs-event-dialog" @close="crsDialogSeq++">
      <template v-if="crsEvent">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="规则 ID">{{ crsEvent.rule_triggered }}</el-descriptions-item>
          <el-descriptions-item label="描述">
            <span v-if="crsIndexLoading">加载中…</span>
            <template v-else-if="crsEntry">{{ crsEntry.msg || '（无描述）' }}</template>
            <template v-else>—</template>
          </el-descriptions-item>
          <el-descriptions-item label="文件 / 分类">
            <span v-if="crsIndexLoading">加载中…</span>
            <template v-else-if="crsEntry">{{ crsEntry.file }} · {{ crsEntry.category }}</template>
            <template v-else>—</template>
          </el-descriptions-item>
          <el-descriptions-item label="事件来源 IP">{{ crsEvent.client_ip }}</el-descriptions-item>
          <el-descriptions-item label="归属策略">{{ crsEvent.policy_name || crsEvent.policy_id || '—' }}</el-descriptions-item>
        </el-descriptions>

        <el-alert
          v-if="!crsIndexLoading && !crsEntry"
          type="warning"
          :closable="false"
          show-icon
          title="当前 CRS 已无此规则（规则集更新后已移除），仍可将其加入排除"
          style="margin-top: 12px"
        />

        <!-- 规则源码默认折叠（降低弹框默认高度），展开时才按需拉取文件内容 -->
        <template v-if="crsEntry">
          <div class="crs-snippet-toggle" @click="toggleCrsSnippet">
            <el-icon class="crs-snippet-toggle-icon" :class="{ 'is-expanded': crsSnippetExpanded }"><ArrowRight /></el-icon>
            <span>{{ crsSnippetExpanded ? '收起规则源码' : '展开规则源码' }}</span>
            <span class="crs-snippet-toggle-file">{{ crsEntry.file }} · id:{{ crsEvent.rule_triggered }} 所在行 ±10 行</span>
          </div>
          <div v-if="crsSnippetExpanded" v-loading="crsSnippetLoading" class="crs-snippet-body">
            <SyntaxHighlight v-if="crsSnippet" :content="crsSnippet" language="apacheconf" />
            <div v-else-if="crsSnippetError" class="crs-snippet-empty">规则源码加载失败，可收起后重新展开重试</div>
            <div v-else-if="!crsSnippetLoading" class="crs-snippet-empty">未在该文件中定位到规则定义（规则文件可能已更新）</div>
          </div>
        </template>

        <div class="crs-action-group">
          <div class="crs-action-group-title">快捷排除（二选一）</div>
          <el-radio-group v-model="crsExcludeScope" :disabled="crsActionDisabled">
            <el-radio value="ip">仅排除该 IP（事件来源 {{ crsEvent.client_ip }}）</el-radio>
            <el-radio value="all">所属策略不限 IP</el-radio>
          </el-radio-group>
          <div v-if="crsPolicyState !== 'ok'" class="crs-policy-hint">
            <template v-if="crsPolicyState === 'checking'">策略状态检查中…</template>
            <template v-else-if="crsPolicyState === 'missing'">归属策略已删除，请在策略向导中操作</template>
            <template v-else-if="crsPolicyState === 'no-policy'">归属策略已删除，请在策略向导中操作</template>
            <template v-else>策略状态加载失败，请关闭后重试</template>
          </div>
          <div v-else-if="crsAlreadyExcluded" class="crs-policy-hint">该规则的同等排除已存在于所属策略（确认后将追加为独立条目）</div>
          <div class="crs-action-row">
            <el-button type="primary" :loading="crsSubmitting" :disabled="crsActionDisabled" @click="confirmCrsExclude">确认排除</el-button>
          </div>
        </div>

        <div class="crs-action-group">
          <div class="crs-action-group-title">把该 IP 加入地址列表</div>
          <div class="crs-action-row">
            <el-select
              v-model="crsIpListId"
              filterable
              clearable
              placeholder="选择地址列表"
              class="crs-ip-list-select"
              :disabled="!canManage || crsIpListSaving"
            >
              <el-option v-for="list in crsIpLists" :key="list.id" :label="`${list.name}（${list.entry_count} 条）`" :value="list.id" />
            </el-select>
            <el-button
              type="primary"
              plain
              :loading="crsIpListSaving"
              :disabled="!canManage || crsIpLists.length === 0 || crsIpListId === undefined"
              @click="addEventIpToList"
            >加入列表</el-button>
          </div>
          <div v-if="crsIpLists.length === 0 && !crsIpListLoading" class="crs-policy-hint">暂无地址列表，可在 规则集 → IP 地址列表 创建</div>
        </div>
      </template>
      <template #footer>
        <el-button @click="crsDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Refresh, Warning, ArrowRight } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess, ApiRequestError } from '@/utils/api'
import LogStorageBar from '@/components/LogStorageBar.vue'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { formatDate } from '@/utils/date'
import { useCrsRuleIndex, parseCrsExcludedRules, CRS_EXCLUDED_MAX_ROWS } from '@/composables/useCrsRuleIndex'
import type { CrsExcludedRow } from '@/composables/useCrsRuleIndex'
import { useAuthStore } from '@/stores/auth'
import type { APIResponse } from '@/types'

interface SecurityEvent { id: number; event_time: string; rule_caddy_id: string; rule_name: string; policy_id: number; policy_name: string; client_ip: string; ip_location: string; method: string; uri: string; event_type: string; rule_triggered: string; rule_msg: string; action: string; anomaly_score: number }

// 触发规则 family 映射：'2'-'5' 与 '7'（允许模式预检拒绝，IP 白名单拒绝）为 IP 访问控制拦截，
// '8' 为地域拦截，949 为异常评分评估拦截，920/921 为协议异常/攻击，其余为 CRS 规则 ID
const triggeredLabel = (row: SecurityEvent): string => {
  const t = row.rule_triggered
  if (!t) return '—'
  if (t === '2' || t === '3' || t === '4' || t === '5' || t === '7') return 'IP 访问控制'
  if (t === '8') return '地域拦截'
  if (/^949/.test(t)) return '请求阻断评估'
  if (/^920/.test(t)) return '协议异常'
  if (/^921/.test(t)) return '协议攻击'
  // 5 位数字 ID 仅自定义规则（emit=crID+10000）；与后端过滤器 GLOB/概览口径一致
  if (/^\d{5}$/.test(t)) return '自定义规则'
  return t
}
const showTriggeredMsg = (row: SecurityEvent): boolean => {
  const t = row.rule_triggered
  return !!t && t !== '2' && t !== '3' && t !== '4' && t !== '5' && !/^949/.test(t) && !!row.rule_msg
}

// —— CRS 规则快捷排除（6 位 9xxxxx 触发 ID → 详情弹框 + 二选一排除）——
// CRS 规则索引：弹框每次打开取一次（openSeq 会话守卫），供 id/msg/file/category
// 与源码片段文件名查询；失败退化为「当前 CRS 已无此规则」展示（loaded=false 时不误判）
const { loading: crsIndexLoading, byId: crsIndexById, ensureForDialog: ensureCrsRuleIndex } = useCrsRuleIndex()
const authStore = useAuthStore()
// admin 只读态（从节点/非管理员）禁用确认按钮——与 IPLocationAction.canManage 同口径
const canManage = computed(() => authStore.readOnlyReason === null)

const isCrsRuleId = (t: string): boolean => /^9\d{5}$/.test(t)

const crsDialogVisible = ref(false)
const crsEvent = ref<SecurityEvent | null>(null)
const crsExcludeScope = ref<'ip' | 'all'>('ip')
const crsSubmitting = ref(false)
const crsSnippet = ref('')
const crsSnippetLoading = ref(false)
// 源码默认折叠：展开才拉取文件内容（每次弹框会话至多一次，失败允许重展开重试）
const crsSnippetExpanded = ref(false)
const crsSnippetFetched = ref(false)
const crsSnippetError = ref(false)
// 「把该 IP 加入地址列表」动作组（与快捷排除互相独立）
interface IpListOption { id: number; name: string; entry_count: number }
const crsIpLists = ref<IpListOption[]>([])
const crsIpListId = ref<number | undefined>(undefined)
const crsIpListLoading = ref(false)
const crsIpListSaving = ref(false)
// ok=可提交 / checking=策略检查中 / missing=404 或无 policy_id / error=检查失败
const crsPolicyState = ref<'checking' | 'ok' | 'missing' | 'no-policy' | 'error'>('checking')
// 策略存在性检查顺带取回的现有排除清单（用于「已存在同等排除」提示；提交时仍重新 GET 最新）
const crsExistingRows = ref<CrsExcludedRow[]>([])
// 弹框会话序号：关闭/重开丢弃在途的索引、源码与策略检查返回
let crsDialogSeq = 0

const crsEntry = computed(() => (crsEvent.value ? crsIndexById.value.get(crsEvent.value.rule_triggered) ?? null : null))

// 同等排除已存在：同目标 + 同作用域（ip 时覆盖事件来源 IP）
const crsAlreadyExcluded = computed<boolean>(() => {
  const ev = crsEvent.value
  if (!ev) return false
  return crsExistingRows.value.some((r) =>
    r.target === ev.rule_triggered
    && r.scope === crsExcludeScope.value
    && (crsExcludeScope.value !== 'ip' || r.ips.includes(ev.client_ip)))
})

const crsActionDisabled = computed(() =>
  !canManage.value || crsPolicyState.value !== 'ok' || crsSubmitting.value)

// 源码片段：该规则 ID 所在行 ±10 行（id:<ID> 出现在 SecRule 动作里，兼容引号/空格变体）
const extractRuleSnippet = (content: string, ruleId: string): string => {
  const needles = [`id:${ruleId}`, `id: ${ruleId}`, `id:'${ruleId}'`, `id:"${ruleId}"`]
  const lines = content.split('\n')
  const idx = lines.findIndex((line) => needles.some((n) => line.includes(n)))
  if (idx === -1) return ''
  return lines.slice(Math.max(0, idx - 10), Math.min(lines.length, idx + 11)).join('\n')
}

// 策略存在性检查：silent（404 属预期路径，不弹全局错误 toast）；顺带取现有排除清单
const checkCrsPolicy = async (policyId: number, seq: number): Promise<void> => {
  try {
    const res = await request.get<APIResponse<{ policy: { crs_excluded_rules?: string } }>>(`/security/policies/${policyId}`, { silent: true })
    if (seq !== crsDialogSeq) return
    if (!res.data?.policy) {
      crsPolicyState.value = 'missing'
      return
    }
    crsExistingRows.value = parseCrsExcludedRules(res.data.policy.crs_excluded_rules)
    crsPolicyState.value = 'ok'
  } catch (error: unknown) {
    if (seq !== crsDialogSeq) return
    crsPolicyState.value = error instanceof ApiRequestError && error.status === 404 ? 'missing' : 'error'
  }
}

const openCrsDialog = async (row: SecurityEvent): Promise<void> => {
  const seq = ++crsDialogSeq
  crsEvent.value = row
  crsExcludeScope.value = 'ip'
  crsSnippet.value = ''
  crsSnippetLoading.value = false
  crsSnippetExpanded.value = false
  crsSnippetFetched.value = false
  crsSnippetError.value = false
  crsExistingRows.value = []
  crsIpListId.value = undefined
  crsIpListSaving.value = false
  void loadCrsIpLists(seq)
  if (!row.policy_id || row.policy_id <= 0) {
    crsPolicyState.value = 'no-policy'
  } else {
    crsPolicyState.value = 'checking'
    void checkCrsPolicy(row.policy_id, seq)
  }
  crsDialogVisible.value = true
  // 索引仅供详情区 id/msg/file/category 展示（源码内容等用户展开后再拉）
  await ensureCrsRuleIndex(seq)
}

// 折叠切换：首次展开时按 file 拉源码片段（索引失败/规则已移除时折叠行不渲染）
const toggleCrsSnippet = async (): Promise<void> => {
  crsSnippetExpanded.value = !crsSnippetExpanded.value
  const ev = crsEvent.value
  const entry = ev ? crsIndexById.value.get(ev.rule_triggered) : null
  if (!crsSnippetExpanded.value || !ev || !entry?.file || crsSnippetFetched.value) return
  const seq = crsDialogSeq
  crsSnippetFetched.value = true
  crsSnippetError.value = false
  crsSnippetLoading.value = true
  try {
    const res = await request.get<APIResponse<{ content: string }>>(`/security/crs/rules/${encodeURIComponent(entry.file)}`)
    if (seq !== crsDialogSeq || !crsDialogVisible.value) return
    crsSnippet.value = extractRuleSnippet(res.data?.content || '', ev.rule_triggered)
  } catch {
    if (seq !== crsDialogSeq || !crsDialogVisible.value) return
    crsSnippet.value = ''
    // 允许收起后再展开重试
    crsSnippetFetched.value = false
    crsSnippetError.value = true
  } finally {
    if (seq === crsDialogSeq) crsSnippetLoading.value = false
  }
}

const loadCrsIpLists = async (seq: number): Promise<void> => {
  crsIpListLoading.value = true
  try {
    const res = await request.get<APIResponse<IpListOption[]>>('/security/ip-lists')
    if (seq !== crsDialogSeq) return
    crsIpLists.value = res.data || []
  } catch {
    if (seq !== crsDialogSeq) return
    crsIpLists.value = []
  } finally {
    if (seq === crsDialogSeq) crsIpListLoading.value = false
  }
  // 列表已在别处删除时清理悬空选择，避免静默写往不存在的列表
  if (crsIpListId.value !== undefined && !crsIpLists.value.some((l) => l.id === crsIpListId.value)) {
    crsIpListId.value = undefined
  }
}

// 与 IPLocationAction 存入地址列表同口径：确认框（含列表名）→ 幂等 POST →
// added=false 静默 info；与「确认排除」互不影响（独立 loading/状态）
const addEventIpToList = async (): Promise<void> => {
  const ev = crsEvent.value
  if (!ev || !canManage.value || crsIpListSaving.value) return
  const list = crsIpLists.value.find((l) => l.id === crsIpListId.value)
  if (!list) return
  try {
    await ElMessageBox.confirm(
      `将把 ${ev.client_ip} 加入地址列表「${list.name}」（幂等，已存在时不会重复添加）。是否继续？`,
      '加入地址列表',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
    )
  } catch { return }
  const seq = crsDialogSeq
  crsIpListSaving.value = true
  try {
    // 非 silent：错误走全局拦截器提示，428 时全局 MFA step-up 弹码链完整生效
    const res = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${list.id}/ips`, { value: ev.client_ip })
    if (seq !== crsDialogSeq) return
    if (res.data?.added) mfaAwareSuccess(`已加入地址列表「${list.name}」`)
    else ElMessage.info(`该 IP 已在列表「${list.name}」中`)
    await loadCrsIpLists(seq)
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    if (seq === crsDialogSeq) crsIpListSaving.value = false
  }
}

// 提交：GET 最新 crs_excluded_rules → 追加（scope=ip 时 ips=[事件 IP]）→ PUT 全量；
// 非 silent——400 文案/MFA 428 全局链均由全局拦截器处理
const confirmCrsExclude = async (): Promise<void> => {
  const ev = crsEvent.value
  if (!ev || crsActionDisabled.value) return
  crsSubmitting.value = true
  try {
    const res = await request.get<APIResponse<{ policy: { crs_excluded_rules?: string } }>>(`/security/policies/${ev.policy_id}`)
    const detail = res.data?.policy
    if (!detail) throw new Error('策略详情响应缺少数据')
    const rows = parseCrsExcludedRules(detail.crs_excluded_rules)
    const scope = crsExcludeScope.value
    const ips = scope === 'ip' ? [ev.client_ip] : []
    // 幂等守卫：同目标 + 同作用域 + 同 IP 的行已存在时不再追加
    if (rows.some((r) => r.target === ev.rule_triggered && r.scope === scope && r.ips.join(',') === ips.join(',') && r.listRefs.length === 0)) {
      ElMessage.info('该排除已存在于所属策略')
      crsDialogVisible.value = false
      return
    }
    if (rows.length >= CRS_EXCLUDED_MAX_ROWS) {
      ElMessage.error(`所属策略的排除清单已达 ${CRS_EXCLUDED_MAX_ROWS} 条上限，请在策略向导中整理`)
      return
    }
    rows.push({ target: ev.rule_triggered, scope, ips, listRefs: [] })
    // 后端契约（services.CRSExcludedEntry）：ips 为逗号分隔字符串、listRefs 为数字
    // 数组；内存态 CrsExcludedRow.ips 是数组——先转线上形态再 stringify，否则
    // 后端 json.Unmarshal 类型不匹配直接 400「需为 JSON 数组字符串」
    const wireRows = rows.map((r) => ({ target: r.target, scope: r.scope, ips: r.ips.join(','), listRefs: r.listRefs }))
    await request.put(`/security/policies/${ev.policy_id}`, { crs_excluded_rules: JSON.stringify(wireRows) })
    mfaAwareSuccess(`已加入策略「${ev.policy_name || `#${ev.policy_id}`}」的排除清单，已生效并重载`)
    crsDialogVisible.value = false
  } catch {
    // 失败提示由全局拦截器弹出，这里只需终止流程
  } finally {
    crsSubmitting.value = false
  }
}

const loading = ref(false)
const events = ref<SecurityEvent[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const filters = ref({ action: '', ip: '', uri: '', rule_name: '', rule_triggered: '', policy_name: '', rule_caddy_id: '', timeRange: null as [string, string] | null })

const applyFilters = () => {
  // 时间区间校验：开始晚于结束时提示并清除该筛选（后端同样兜底 400）。
  // value-format 为 YYYY-MM-DD HH:mm:ss，字符串比较即时间先后比较。
  const range = filters.value.timeRange
  if (range?.[0] && range?.[1] && range[0] > range[1]) {
    ElMessage.warning('开始时间不能晚于结束时间')
    filters.value.timeRange = null
  }
  page.value = 1
  fetchEvents()
}

const resetFilters = () => {
  filters.value = { action: '', ip: '', uri: '', rule_name: '', rule_triggered: '', policy_name: '', rule_caddy_id: '', timeRange: null }
  page.value = 1
  fetchEvents()
}

const handleSizeChange = () => { page.value = 1; fetchEvents() }

const goToRule = (row: SecurityEvent) => { localStorage.setItem('rules-search', row.rule_caddy_id); window.open('/?page=rules', '_blank') }
const goToPolicy = (row: SecurityEvent) => {
  if (row.policy_id > 0) {
    localStorage.setItem('security-policies-focus-id', String(row.policy_id))
  } else if (row.policy_name) {
    localStorage.setItem('security-policies-search', row.policy_name)
  } else {
    return
  }
  window.open('/?page=security-policies', '_blank')
}

let fetchEventsSeq = 0
const fetchEvents = async () => {
  // 乱序响应守卫：只有最新一次请求的响应才允许写入列表，避免旧响应覆盖新页
  const requestSeq = ++fetchEventsSeq
  loading.value = true
  try {
    const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) })
    if (filters.value.action) p.set('action', filters.value.action)
    if (filters.value.ip) p.set('ip', filters.value.ip)
    if (filters.value.rule_caddy_id) p.set('rule_caddy_id', filters.value.rule_caddy_id)
    if (filters.value.rule_name) p.set('rule_name', filters.value.rule_name)
    if (filters.value.rule_triggered) p.set('rule_triggered', filters.value.rule_triggered)
    if (filters.value.policy_name) p.set('policy_name', filters.value.policy_name)
    if (filters.value.uri) p.set('uri', filters.value.uri)
    if (filters.value.timeRange?.[0]) p.set('start_time', filters.value.timeRange[0])
    if (filters.value.timeRange?.[1]) p.set('end_time', filters.value.timeRange[1])
    const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number }>>(`/security/events?${p}`)
    if (requestSeq !== fetchEventsSeq) return
    events.value = res.data?.events || []
    total.value = res.data?.total || 0
  } catch {
    // R68 D-N5：瞬态失败保留末次成功数据（对齐 AuditLog 口径）——此前清空列表
    // 却保留陈旧 total，空态文案「暂无安全事件」在排障窗口内误导为「无攻击」。
    // 全局拦截器已弹失败 toast。
  } finally {
    if (requestSeq === fetchEventsSeq) loading.value = false
  }
}
onMounted(fetchEvents)
</script>

<style scoped>
.table-toolbar { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-start; margin-bottom: 16px; align-items: center; }
.filter-actions { display: flex; gap: 0; margin-left: 8px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
.cell-tip { cursor: help; border-bottom: 1px dashed #c0c4cc; }

/* —— CRS 规则详情 + 快捷排除弹框 —— */
.crs-snippet-toggle { display: flex; align-items: center; gap: 6px; margin-top: 12px; font-size: 13px; font-weight: 500; color: var(--el-color-primary, #409eff); cursor: pointer; user-select: none; }
.crs-snippet-toggle:hover { opacity: 0.85; }
.crs-snippet-toggle-icon { font-size: 12px; transition: transform 0.2s; }
.crs-snippet-toggle-icon.is-expanded { transform: rotate(90deg); }
.crs-snippet-toggle-file { font-size: 12px; font-weight: 400; color: #9ca3af; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.crs-snippet-body { margin-top: 8px; min-height: 80px; }
.crs-snippet-body :deep(.prism-code) { max-height: 320px; }
.crs-snippet-empty { font-size: 12px; color: #9ca3af; padding: 12px 0; }
.crs-policy-hint { font-size: 12px; color: #e6a23c; line-height: 1.6; margin-top: 8px; }
.crs-action-group { border: 1px solid var(--el-border-color-lighter, #ebeef5); border-radius: var(--el-border-radius-base, 4px); padding: 12px; margin-top: 12px; }
.crs-action-group-title { font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 8px; }
.crs-action-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
.crs-ip-list-select { width: 240px; flex: 0 0 auto; }
</style>

<style>
.filter-date-range.el-date-editor {
  --el-date-editor-width: 360px;
  width: 360px;
  flex: 0 0 auto;
}

/* CRS 事件弹框：正文区自适应限高（top=5vh + 头/脚 ≈ 110px），源码展开时整体不超视口 */
.crs-event-dialog .el-dialog__body { max-height: calc(90vh - 130px); overflow-y: auto; }
</style>
