<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Warning /></el-icon>
          事件日志
        </h2>
        <p class="page-desc">查看安全拦截与检测事件记录</p>
      </div>
      <el-button :icon="Refresh" @click="fetchEvents">刷新</el-button>
    </div>

    <el-card>
      <div class="table-toolbar">
        <el-date-picker
          v-model="filters.timeRange"
          name="event-time-range"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="filter-date-range"
        />
        <el-select v-model="filters.action" placeholder="动作" clearable style="width: 90px">
          <el-option label="拦截" value="blocked" />
          <el-option label="检测" value="logged" />
        </el-select>
        <!-- R72 十九次（用户需求）：规则 ID 筛选替换为三列（负载规则/触发规则/策略）
             服务端筛选（rule_name/rule_triggered/policy_name LIKE）。 -->
        <el-input v-model="filters.rule_name" placeholder="负载规则" clearable style="width: 100px" @keyup.enter="applyFilters" />
        <!-- 触发规则筛选：多选 + 头部全选（勾的就是看的，统一正向心智）。
             全选（6 类别全中且无自定义 tag）或空选 = 不过滤，不发送参数；子集或含
             自定义 tag 时全部选中值英文逗号连接发送 rule_triggered（后端逐段按
             family/前缀/纯数字 ID 解析，OR 连接）。filterable + allow-create：可直接
             输入 CRS 规则 ID（如 942100）等自定义 tag 混入同一参数；自定义 tag 不参与
             全选判定（只看 6 个类别是否全中）。 -->
        <el-select
          v-model="filters.rule_triggered"
          multiple
          filterable
          allow-create
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="1"
          placeholder="触发阶段"
          style="width: 170px"
          popper-class="triggered-filter-popper"
        >
          <template #header>
            <el-checkbox
              :model-value="triggeredCheckAll"
              :indeterminate="triggeredIndeterminate"
              @change="toggleTriggeredAll"
            >全选</el-checkbox>
          </template>
          <el-option label="信任名单" value="信任名单" title="阶段 0 信任名单（id 3/12）" />
          <el-option label="IP 访问控制" value="IP 访问控制" title="黑白名单、地域拦截、威胁情报库（阶段 1 合并：id 2/4/5/7/800xxx/14）" />
          <el-option label="WAF" value="WAF" title="CRS 规则与自定义规则（阶段 3）" />
          <el-option label="请求体异常" value="请求体异常" title="请求体解析失败（id 11）" />
        </el-select>
        <el-input v-model="filters.policy_name" placeholder="策略" clearable style="width: 90px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.ip" placeholder="IP 地址" clearable style="width: 115px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.uri" placeholder="URI" clearable style="width: 115px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>

      <el-table :data="events" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty description="暂无安全事件" :image-size="60" /></template>
        <el-table-column prop="event_time" label="时间" width="190" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
        <el-table-column label="动作" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="row.action === 'blocked' ? 'danger' : 'warning'" size="small" effect="light">{{ row.action === 'blocked' ? '拦截' : '检测' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="规则" min-width="130">
          <template #default="{ row }">
            <el-link v-if="row.rule_name || row.rule_caddy_id" type="primary" @click="goToRule(row)">{{ row.rule_name || row.rule_caddy_id || '—' }}</el-link>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="触发阶段" min-width="110">
          <template #default="{ row }">
            <!-- 触发阶段四分类：信任名单 / IP 访问控制（黑白名单+地域+威胁库，点击看触发详情）/
                 WAF（CRS=详情+快捷排除弹框；自定义=规则详情弹框）/ 请求体异常（纯文本） -->
            <el-link v-if="stageCategory(row) === 'waf'" type="primary" @click="openTriggerDetail(row)">WAF</el-link>
            <el-link v-else-if="isIpAclFamily(row) || stageCategory(row) === 'trust'" type="primary" @click="openTriggerDetail(row)">{{ stageLabel(row) }}</el-link>
            <el-tooltip v-else-if="showTriggeredMsg(row)" :content="row.rule_msg" placement="top" :show-after="200">
              <span class="cell-tip">{{ stageLabel(row) }}</span>
            </el-tooltip>
            <span v-else>{{ stageLabel(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="策略" min-width="150">
          <template #default="{ row }">
            <el-link v-if="row.policy_name || row.policy_id > 0" type="primary" @click="goToPolicy(row)">{{ row.policy_name || row.policy_id }}</el-link>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <!-- 用户裁定(第 37 轮):内容上限 ~190-200px(IPv4 126+gap+归属地 72),定宽 200 不再挤占方法/URI -->
        <el-table-column label="客户端 IP" width="200">
          <template #default="{ row }">
            <IPLocationAction :ip="row.client_ip" :location="row.ip_location" :rule-caddy-id="row.rule_caddy_id" />
          </template>
        </el-table-column>
        <!-- OPTIONS 为最长方法名(7 字符),90 定宽 -->
        <el-table-column prop="method" label="方法" width="90" align="center" />
        <el-table-column prop="uri" label="URI" min-width="140" show-overflow-tooltip />
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
        <el-table-column label="操作" width="70" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openCtxDialog(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div style="margin-top: 16px; display: flex; align-items: center; flex-wrap: wrap; row-gap: 8px;">
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

    <!-- 触发详情弹框（第 58 轮统一）：全部触发类型共用同一风格与交互；
         信息优先展示，IP 处置动作收敛到 IP 快捷弹框（列表中点击 IP） -->
    <TriggerDetailDialog v-model="triggerDetailVisible" :row="triggerDetailRow" />

    <!-- 请求上下文详情：策略开启「记录请求体」后，命中规则事件携带的请求头/请求体。
         请求头为 map[string][]string JSON 文本（多值以 ", " 连接；Cookie/Authorization/
         Set-Cookie/Proxy-Authorization 值默认掩码，逐行眼睛图标点击显示）；合成键
         _dropped 渲染为信息行而非头行。请求体按契约前缀解析：base64-truncated: →
         base64: → 明文；明文尾部 \n...[TRUNCATED] 标记转为截断横幅；atob 解码失败
         展示原始内容 + 错误说明。宽度/顶距与 crs-event-dialog 一致。 -->
    <el-dialog v-model="ctxDialogVisible" width="min(760px, 94vw)" top="5vh" append-to-body class="ctx-event-dialog dialog-body-inset">
      <template #header>
        <div class="ctx-dialog-header">
          <el-icon class="ctx-dialog-icon"><Document /></el-icon>
          <div>
            <div class="ctx-dialog-title">请求详情</div>
            <div class="ctx-dialog-sub">{{ ctxEvent ? formatDate(ctxEvent.event_time) : '—' }} · {{ ctxEvent?.policy_name || '未知策略' }}</div>
          </div>
        </div>
      </template>
      <template v-if="ctxEvent">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="时间">{{ ctxEvent.event_time || '—' }}</el-descriptions-item>
          <el-descriptions-item label="方法">{{ ctxEvent.method || '—' }}</el-descriptions-item>
          <el-descriptions-item label="客户端 IP">{{ ctxEvent.client_ip || '—' }}</el-descriptions-item>
          <el-descriptions-item label="归属地">{{ ctxEvent.ip_location || '—' }}</el-descriptions-item>
          <el-descriptions-item label="URI" :span="2">{{ ctxEvent.uri || '—' }}</el-descriptions-item>
          <el-descriptions-item label="触发规则">{{ [ctxEvent.rule_name, ctxEvent.rule_triggered ? `id:${ctxEvent.rule_triggered}` : ''].filter(Boolean).join(' · ') || '—' }}</el-descriptions-item>
          <el-descriptions-item label="所属策略">{{ ctxEvent.policy_name || '—' }}</el-descriptions-item>
          <el-descriptions-item label="动作">
            <el-tag size="small" :type="ctxEvent.action === 'blocked' ? 'danger' : 'warning'" effect="plain">
              {{ ctxEvent.action === 'blocked' ? '已拦截' : ctxEvent.action === 'logged' ? '已记录' : ctxEvent.action || '—' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="异常评分">{{ ctxEvent.anomaly_score > 0 ? ctxEvent.anomaly_score : '—' }}</el-descriptions-item>
        </el-descriptions>

        <div class="ctx-section-title">请求头</div>
        <template v-if="ctxHeadersParsed.failed">
          <el-alert type="error" :closable="false" show-icon title="请求头记录解析失败，以下为原始内容" class="ctx-banner" />
          <pre class="ctx-body-pre">{{ ctxEvent.request_headers }}</pre>
        </template>
        <template v-else-if="ctxHeadersParsed.rows.length > 0 || ctxHeadersParsed.dropped > 0">
          <div v-if="ctxHeadersParsed.dropped > 0" class="ctx-info-line">已隐藏 {{ ctxHeadersParsed.dropped }} 个头（请求头超出 8KB 采集上限）</div>
          <el-table v-if="ctxHeadersParsed.rows.length > 0" :data="ctxHeadersParsed.rows" size="small" :max-height="260" :header-cell-style="{ background: '#f9fafb' }">
            <el-table-column prop="name" label="名称" width="200" show-overflow-tooltip />
            <el-table-column label="值" min-width="380">
              <template #default="{ row }">
                <div class="ctx-header-value-cell">
                  <span class="ctx-header-value">{{ ctxHeaderDisplay(row) }}</span>
                  <el-button
                    v-if="row.sensitive"
                    link
                    type="primary"
                    size="small"
                    class="ctx-reveal-btn"
                    :title="ctxRevealed.has(row.name.toLowerCase()) ? '点击隐藏' : '点击显示'"
                    @click="toggleCtxReveal(row.name)"
                  >
                    <el-icon><Hide v-if="ctxRevealed.has(row.name.toLowerCase())" /><View v-else /></el-icon>
                  </el-button>
                </div>
              </template>
            </el-table-column>
          </el-table>
        </template>
        <div v-else class="ctx-empty">暂无请求头记录</div>

        <div class="ctx-section-title">请求体</div>
        <template v-if="ctxBodyParsed.state === 'empty'">
          <div class="ctx-empty">无请求体记录</div>
        </template>
        <template v-else>
          <el-alert v-if="ctxBodyParsed.truncated" type="warning" :closable="false" show-icon title="请求体已截断，仅显示保留的前段内容" class="ctx-banner" />
          <div v-if="ctxBodyParsed.binary" class="info-note-bar"><span class="info-note-desc">请求体为二进制内容，已按 Base64 解码展示，可能包含不可读字符</span></div>
          <el-alert v-if="ctxBodyParsed.state === 'error'" type="error" :closable="false" show-icon title="Base64 解码失败，以下为原始内容" class="ctx-banner" />
          <pre class="ctx-body-pre">{{ ctxBodyParsed.text }}</pre>
        </template>
      </template>
      <template #footer>
        <el-button @click="ctxDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Refresh, Warning, View, Hide, Document } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import type { CheckboxValueType } from 'element-plus'
import { request } from '@/utils/api'
import LogStorageBar from '@/components/LogStorageBar.vue'
import TriggerDetailDialog from '@/components/events/TriggerDetailDialog.vue'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import { formatDate } from '@/utils/date'
import type { APIResponse } from '@/types'

interface SecurityEvent { id: number; event_time: string; rule_caddy_id: string; rule_name: string; policy_id: number; policy_name: string; client_ip: string; ip_location: string; method: string; uri: string; event_type: string; rule_triggered: string; rule_msg: string; action: string; anomaly_score: number; request_headers: string; request_body: string }

// 触发规则 family 映射：'2'-'5' 与 '7'（允许模式预检拒绝，IP 白名单拒绝）为 IP 访问控制拦截，
// '8' 为地域拦截，'14' 为威胁情报库预检拦截，'11' 为请求体解析失败，949 为异常评分评估拦截，920/921 为协议异常/攻击，其余为 CRS 规则 ID
// 触发阶段分类（第 57 轮追加需求，用户裁定）：IP ACL 族=黑白名单/信任/地域/
// 威胁库预检，统一展示「IP 访问控制」；WAF 含 CRS 与自定义两源；请求体异常独立。
const isIpAclFamily = (row: SecurityEvent): boolean => {
  const t = row.rule_triggered
  if (!t) return false
  const n = Number(t)
  if ([2, 3, 4, 5, 7, 14].includes(n)) return true
  return n >= 800000 && n < 900000
}
const isWafCrs = (row: SecurityEvent): boolean => /^9\d{5}$/.test(row.rule_triggered ?? '')
const isWafCustom = (row: SecurityEvent): boolean => /^\d{5}$/.test(row.rule_triggered ?? '')

const stageCategory = (row: SecurityEvent): 'trust' | 'acl' | 'waf' | 'body' | 'other' => {
  const t = row.rule_triggered
  if (!t) return 'other'
  const n = Number(t)
  if (n === 3 || n === 12) return 'trust'
  if (t === '11') return 'body'
  if (isWafCrs(row) || isWafCustom(row)) return 'waf'
  if (isIpAclFamily(row)) return 'acl'
  return 'other'
}
const stageLabel = (row: SecurityEvent): string => {
  switch (stageCategory(row)) {
    case 'trust': return '信任名单'
    case 'acl': return 'IP 访问控制'
    case 'waf': return 'WAF'
    case 'body': return '请求体异常'
    default: return row.rule_triggered || '—'
  }
}
const showTriggeredMsg = (row: SecurityEvent): boolean => {
  const t = row.rule_triggered
  return !!t && t !== '2' && t !== '3' && t !== '4' && t !== '5' && !/^949/.test(t) && !!row.rule_msg
}

// —— 触发详情弹框（第 58 轮统一入口）：全部触发类型共用 TriggerDetailDialog ——
const triggerDetailVisible = ref(false)
const triggerDetailRow = ref<SecurityEvent | null>(null)
const openTriggerDetail = (row: SecurityEvent): void => {
  triggerDetailRow.value = row
  triggerDetailVisible.value = true
}


const loading = ref(false)
const events = ref<SecurityEvent[]>([])

// —— 请求上下文详情弹框（策略「记录请求体」开启后事件携带 request_headers/request_body）——
const ctxDialogVisible = ref(false)
const ctxEvent = ref<SecurityEvent | null>(null)
// 敏感头逐行显示状态（key = 小写头名）：默认掩码 ••••••，眼睛图标点击切换
const ctxRevealed = ref<Set<string>>(new Set())

const CTX_SENSITIVE_HEADERS = new Set(['cookie', 'authorization', 'set-cookie', 'proxy-authorization'])
const CTX_TRUNCATED_SUFFIX = '\n...[TRUNCATED]'
const CTX_B64_TRUNCATED_PREFIX = 'base64-truncated:'
const CTX_B64_PREFIX = 'base64:'

interface CtxHeaderRow { name: string; value: string; sensitive: boolean }
interface CtxHeadersParsed { rows: CtxHeaderRow[]; dropped: number; failed: boolean }

// 请求头解析："" → 空态；JSON.parse try/catch 防御（失败展示原始内容 + 错误说明）；
// 合成键 _dropped: ["N"] 提取为信息行（N = 因 8KB 上限被丢弃的头数），不作为头行渲染；
// 多值头以 ", " 连接
const ctxHeadersParsed = computed<CtxHeadersParsed>(() => {
  const raw = ctxEvent.value?.request_headers ?? ''
  if (raw === '') return { rows: [], dropped: 0, failed: false }
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { rows: [], dropped: 0, failed: true }
    const rows: CtxHeaderRow[] = []
    let dropped = 0
    for (const [name, values] of Object.entries(parsed as Record<string, unknown>)) {
      const list = Array.isArray(values) ? values.map((v) => String(v)) : [String(values)]
      if (name === '_dropped') {
        const n = Number(list[0] ?? 0)
        if (Number.isFinite(n) && n > 0) dropped = n
        continue
      }
      rows.push({ name, value: list.join(', '), sensitive: CTX_SENSITIVE_HEADERS.has(name.toLowerCase()) })
    }
    return { rows, dropped, failed: false }
  } catch {
    return { rows: [], dropped: 0, failed: true }
  }
})

interface CtxBodyParsed { state: 'empty' | 'ok' | 'error'; text: string; truncated: boolean; binary: boolean }

// 请求体解析：前缀检查顺序 base64-truncated: → base64: → 明文；base64 系 atob 解码
//（失败回退原始内容 + error 态）；明文以 \n...[TRUNCATED] 结尾时剥离标记转为截断横幅
const ctxBodyParsed = computed<CtxBodyParsed>(() => {
  const raw = ctxEvent.value?.request_body ?? ''
  if (raw === '') return { state: 'empty', text: '', truncated: false, binary: false }
  if (raw.startsWith(CTX_B64_TRUNCATED_PREFIX)) return decodeCtxBody(raw.slice(CTX_B64_TRUNCATED_PREFIX.length), true)
  if (raw.startsWith(CTX_B64_PREFIX)) return decodeCtxBody(raw.slice(CTX_B64_PREFIX.length), false)
  if (raw.endsWith(CTX_TRUNCATED_SUFFIX)) {
    return { state: 'ok', text: raw.slice(0, -CTX_TRUNCATED_SUFFIX.length), truncated: true, binary: false }
  }
  return { state: 'ok', text: raw, truncated: false, binary: false }
})

const decodeCtxBody = (payload: string, truncated: boolean): CtxBodyParsed => {
  try {
    return { state: 'ok', text: atob(payload), truncated, binary: true }
  } catch {
    return { state: 'error', text: payload, truncated, binary: true }
  }
}

const ctxHeaderDisplay = (row: CtxHeaderRow): string =>
  row.sensitive && !ctxRevealed.value.has(row.name.toLowerCase()) ? '••••••' : row.value

const toggleCtxReveal = (name: string): void => {
  const key = name.toLowerCase()
  const next = new Set(ctxRevealed.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  ctxRevealed.value = next
}

const openCtxDialog = (row: SecurityEvent): void => {
  ctxEvent.value = row
  ctxRevealed.value = new Set()
  ctxDialogVisible.value = true
}

const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

// 触发阶段筛选为固定预置四类（第 58 轮用户裁定：固定预置值，不接受任意值）。
// 令牌 → 后端族段映射：请求侧展开为族名逗号串（后端逐段 OR）。
const TRIGGERED_CATEGORIES = ['信任名单', 'IP 访问控制', 'WAF', '请求体异常'] as const
type TriggeredCategory = typeof TRIGGERED_CATEGORIES[number]
const TRIGGERED_FAMILY_SEGMENTS: Record<TriggeredCategory, string[]> = {
  '信任名单': ['信任名单'],
  'IP 访问控制': ['IP 访问控制', '地域拦截', '威胁情报库'],
  'WAF': ['WAF 规则（CRS）', '自定义规则'],
  '请求体异常': ['请求体异常'],
}

const filters = ref({ action: '', ip: '', uri: '', rule_name: '', rule_triggered: [...TRIGGERED_CATEGORIES] as string[], policy_name: '', timeRange: null as [string, string] | null })

// 头部全选复选框三态：四类全中=全选；部分中=半选
const triggeredCheckAll = computed(() => TRIGGERED_CATEGORIES.every((c) => filters.value.rule_triggered.includes(c)))
const triggeredIndeterminate = computed(() => {
  const hit = TRIGGERED_CATEGORIES.filter((c) => filters.value.rule_triggered.includes(c)).length
  return hit > 0 && hit < TRIGGERED_CATEGORIES.length
})
// 全选：勾选=四类全选、取消=全清（固定预置值，无自定义形态）
const toggleTriggeredAll = (checked: CheckboxValueType) => {
  filters.value.rule_triggered = checked ? [...TRIGGERED_CATEGORIES] : []
}

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
  filters.value = { action: '', ip: '', uri: '', rule_name: '', rule_triggered: [...TRIGGERED_CATEGORIES], policy_name: '', timeRange: null }
  page.value = 1
  fetchEvents()
}

const handleSizeChange = () => { page.value = 1; fetchEvents() }

const goToRule = (row: SecurityEvent) => { window.open(`/?page=rules&rs=${encodeURIComponent(row.rule_caddy_id)}`, '_blank') }
const goToPolicy = (row: SecurityEvent) => {
  // FE42-1：交接改走 URL query（sp / sp-search 参数，同 goToRule 的 rs 形态），
  // SecurityPolicies.vue onMounted 消费后 replaceState 清除。
  if (row.policy_id > 0) {
    window.open(`/?page=security-policies&sp=${row.policy_id}`, '_blank')
  } else if (row.policy_name) {
    window.open(`/?page=security-policies&sp-search=${encodeURIComponent(row.policy_name)}`, '_blank')
  }
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
    if (filters.value.rule_name) p.set('rule_name', filters.value.rule_name)
    // 触发规则：全选（6 类别全中且无自定义 tag）或空选 = 不过滤，不发送参数；
    // 子集（1~5 个类别）或含自定义 tag 时，全部选中值英文逗号连接发送 rule_triggered
    //（后端逐段独立解析、OR 连接；含逗号的消息关键词会整串回退为消息搜索，前端只管连接）
    const triggeredSelected = filters.value.rule_triggered.filter((v): v is TriggeredCategory =>
      (TRIGGERED_CATEGORIES as readonly string[]).includes(v))
    const triggeredAllHit = TRIGGERED_CATEGORIES.every((c) => triggeredSelected.includes(c))
    if (triggeredSelected.length > 0 && !triggeredAllHit) {
      const segments = triggeredSelected.flatMap((c) => TRIGGERED_FAMILY_SEGMENTS[c])
      p.set('rule_triggered', segments.join(','))
    }
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
/* 工具行单行排布（1280px 视口全控件 + 筛选/重置一行放下）：nowrap 禁止换行，
   各控件定宽不收缩，极端窄视口降级为横向滚动而非把按钮顶到第二行 */
.table-toolbar { display: flex; flex-wrap: nowrap; gap: 8px; justify-content: flex-start; margin-bottom: 16px; align-items: center; overflow-x: auto; }
.table-toolbar > * { flex: 0 0 auto; }
.filter-actions { display: flex; gap: 0; }
.filter-actions .el-button { padding-left: 12px; padding-right: 12px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
.cell-tip { cursor: help; border-bottom: 1px dashed #c0c4cc; }


/* —— 请求上下文详情弹框 —— */
/* 请求详情弹框头部：图标 + 标题 + 副标题（dialog-header 统一范式） */
.ctx-dialog-header { display: flex; align-items: center; gap: 10px; }
.ctx-dialog-icon { display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 8px; background: var(--el-color-primary-light-9, #ecf5ff); color: var(--el-color-primary, #409eff); font-size: 18px; flex-shrink: 0; }
.ctx-dialog-title { font-size: 16px; font-weight: 700; color: var(--el-text-color-primary); line-height: 1.3; }
.ctx-dialog-sub { font-size: 12px; color: var(--el-text-color-secondary); margin-top: 2px; }
.ctx-section-title { font-size: 13px; font-weight: 600; color: #374151; margin: 16px 0 8px; }
.ctx-banner { margin-bottom: 8px; }
.ctx-info-line { font-size: 12px; color: #9ca3af; line-height: 1.6; margin-bottom: 6px; }
.ctx-empty { font-size: 12px; color: #9ca3af; padding: 4px 0 8px; }
.ctx-header-value-cell { display: flex; align-items: center; gap: 6px; }
.ctx-header-value { flex: 1; min-width: 0; word-break: break-all; font-family: monospace; font-size: 12px; }
.ctx-reveal-btn { flex-shrink: 0; }
/* 请求体滚动区：限高 320px 内部滚动，长行预格式换行 */
.ctx-body-pre {
  max-height: 320px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: monospace;
  font-size: 12px;
  line-height: 1.6;
  background: #f9fafb;
  border: 1px solid #ebeef5;
  border-radius: 4px;
  padding: 8px 10px;
  margin: 0;
}
</style>

<style>
.filter-date-range.el-date-editor {
  --el-date-editor-width: 320px;
  width: 320px;
  flex: 0 0 auto;
}

/* CRS 事件弹框 / 请求上下文弹框：正文区自适应限高（top=5vh + 头/脚 ≈ 110px），内容多时整体不超视口 */
.crs-event-dialog .el-dialog__body, .ctx-event-dialog .el-dialog__body { max-height: calc(90vh - 130px); overflow-y: auto; }
/* 请求上下文弹框正文 20px 水平留白走全局 .dialog-body-inset（2026-09-25 用户裁定；
   append-to-body teleport 场景 scoped :deep 不可靠，故类挂弹框、规则在 main.css） */

/* 触发规则筛选下拉：头部「全选」复选框整行可点（EP 自定义头部官方用法同款排布）；
   padding-left 20px 与选项行（EP 默认 20px）左对齐——默认 header-padding 10px 会
   导致复选框与选项文字错开 */
.triggered-filter-popper .el-select-dropdown__header { padding: 8px 6px; border-bottom: 1px solid var(--el-border-color-lighter, #ebeef5); }
.triggered-filter-popper .el-select-dropdown__header .el-checkbox { display: flex; height: unset; margin-right: 0; }
.triggered-filter-popper .el-select-dropdown__header .el-checkbox .el-checkbox__label { padding-left: 8px; }
/* 选中项不加粗：EP 2.14 多选下拉 is-selected 默认 font-weight:bold，该筛选常态
   全选（6 类别全勾）导致整列粗体，覆写回 normal（选中色与右侧 ✓ 保留） */
.triggered-filter-popper .el-select-dropdown__item.is-selected { font-weight: normal; }
</style>
