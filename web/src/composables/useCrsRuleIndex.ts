import { computed, ref } from 'vue'
import { request } from '@/utils/api'
import type { APIResponse } from '@/types'

/** CRS 规则索引条目（GET /security/crs/rule-index）——rules 由后端按 id 升序返回 */
export interface CrsRuleIndexEntry {
  readonly id: string
  readonly msg: string
  readonly file: string
  readonly category: string
}

interface CrsRuleIndexData {
  version: string
  rules: CrsRuleIndexEntry[]
}

/** msg 清洗：去换行/制表、连续空白折叠为单个空格（索引来源为 CRS 注释，偶含换行与缩进） */
const cleanCrsMsg = (msg: string): string => msg.replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim()

/** 两行选项主行 label 的截断上限（超长 msg 截断 + …，全文经 title 悬浮展示） */
const CRS_RULE_LABEL_MAX_CHARS = 48

export interface CrsRuleLabelView {
  /** 截断后的展示 label（≤48 字符，超出加 …） */
  label: string
  /** 不截断全文（title 悬浮用） */
  fullLabel: string
}

/**
 * 规则描述 label 构造（两处消费：策略向导规则组/排除目标下拉、事件快捷排除详情）：
 * msg 清洗（去换行折叠空白）→ 空则用 category → 仍空取「（无描述）」；
 * >48 字符截断 + …，fullLabel 保留全文供悬浮。
 */
export const crsRuleLabelView = (entry: Pick<CrsRuleIndexEntry, 'msg' | 'category'>): CrsRuleLabelView => {
  const fromMsg = cleanCrsMsg(entry.msg)
  const base = fromMsg !== '' ? fromMsg : cleanCrsMsg(entry.category)
  const fullLabel = base !== '' ? base : '（无描述）'
  return {
    label: fullLabel.length > CRS_RULE_LABEL_MAX_CHARS ? `${fullLabel.slice(0, CRS_RULE_LABEL_MAX_CHARS)}…` : fullLabel,
    fullLabel,
  }
}

/** 策略字段 crs_excluded_rules 的行形状（存储：对象数组 JSON 文本） */
export type CrsExclusionScope = 'all' | 'ip' | 'list'
export interface CrsExcludedRow {
  target: string
  scope: CrsExclusionScope
  ips: string[]
  listRefs: number[]
}

/** 排除规则行数上限（与向导编辑器/事件快捷排除同一条上限） */
export const CRS_EXCLUDED_MAX_ROWS = 50

/**
 * crs_excluded_rules 载荷容错解析（读侧统一归一为数组形态，写侧另行转线上形态）：
 * - 对象数组 [{target,scope,ips,listRefs}]：字段缺失/形状异常按空值兜底，target 空的行丢弃；
 *   ips 兼容两种形态——逗号分隔字符串（后端 CRSExcludedEntry 契约/落库形态）与数组
 *   （前端内存形态），读侧一律归一为数组；
 * - 旧字符串数组（历史存储：CRS 文件名/纯数字 ID/区间）：归一为 scope:'all' 行，
 *   target 原样保留（后端 SecRuleRemoveById 兼容文件名/纯数字/区间三种形态）。
 */
export const parseCrsExcludedRules = (raw: string | undefined | null): CrsExcludedRow[] => {
  if (!raw) return []
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  const rows: CrsExcludedRow[] = []
  for (const item of parsed) {
    if (typeof item === 'string') {
      const target = item.trim()
      if (target !== '') rows.push({ target, scope: 'all', ips: [], listRefs: [] })
      continue
    }
    if (typeof item !== 'object' || item === null) continue
    const rec = item as Record<string, unknown>
    const target = typeof rec.target === 'string' ? rec.target.trim() : ''
    if (target === '') continue
    const scope: CrsExclusionScope = rec.scope === 'ip' || rec.scope === 'list' ? rec.scope : 'all'
    // 后端契约 ips 为逗号分隔字符串（"1.1.1.1,10.0.0.0/8"）；数组形态一并兼容
    const ips = Array.isArray(rec.ips)
      ? rec.ips.filter((v): v is string => typeof v === 'string' && v.trim() !== '')
      : typeof rec.ips === 'string'
        ? rec.ips.split(',').map((v) => v.trim()).filter((v) => v !== '')
        : []
    const listRefs = Array.isArray(rec.listRefs)
      ? rec.listRefs.map(Number).filter((n) => Number.isInteger(n) && n > 0)
      : []
    rows.push({ target, scope, ips, listRefs })
  }
  return rows
}

/** 下拉选项视图：label/fullLabel 由 crsRuleLabelView 构造（截断/悬浮全文），副行 file · category */
export interface CrsRuleOptionView {
  readonly id: string
  readonly label: string
  readonly fullLabel: string
  readonly file: string
  readonly category: string
}

/**
 * CRS 规则索引组合 hook（约 832 条规则，含 id/msg/file/category）：
 * - ensureForDialog(openSeq)：策略对话框每次打开取一次索引，同一 openSeq 内复用缓存
 *   （步骤间切换不重复请求）；复用 openDialog 的会话序列号守卫模式——对话框快速
 *   关闭重开后，旧会话的在途响应不得覆盖新会话数据（与 fetchIpLists(seq) 同源）。
 * - load()：页面级加载（规则集页等非对话框场景），挂载时无条件刷新一次。
 * 失败语义：HTTP 错误已由全局拦截器 toast，这里退化为空列表（loaded 保持 false，
 * 供消费方区分「索引未就绪」与「规则确实不在索引中」）。
 */
export const useCrsRuleIndex = () => {
  const rules = ref<CrsRuleIndexEntry[]>([])
  const version = ref('')
  const loading = ref(false)
  // 仅在成功拿到索引后置 true；失败/未加载时为 false，消费方不得据此判定规则陈旧
  const loaded = ref(false)
  // 当前持有数据所属的对话框会话序号（null = 页面级加载或尚未加载）
  let loadedSeq: number | null = null
  // 已发起请求的会话序号：同会话并发去重 + 旧会话在途响应丢弃（null = 页面级加载）
  let requestedSeq: number | null = null

  const byId = computed(() => {
    const map = new Map<string, CrsRuleIndexEntry>()
    for (const rule of rules.value) map.set(rule.id, rule)
    return map
  })

  // 下拉选项视图（id — label 主行 + file · category 副行），rules 已按 id 升序
  const options = computed<CrsRuleOptionView[]>(() =>
    rules.value.map((r) => ({ id: r.id, ...crsRuleLabelView(r), file: r.file, category: r.category })))

  const fetchIndex = async (openSeq: number | null): Promise<void> => {
    loading.value = true
    try {
      const res = await request.get<APIResponse<CrsRuleIndexData>>('/security/crs/rule-index')
      // 会话已切换（对话框快速关闭重开）时丢弃过期返回
      if (openSeq !== null && openSeq !== requestedSeq) return
      const list = res.data?.rules
      rules.value = (Array.isArray(list) ? list : [])
        .filter((r): r is CrsRuleIndexEntry => !!r && typeof r.id === 'string' && r.id !== '')
        .map((r) => ({
          id: r.id,
          msg: typeof r.msg === 'string' ? r.msg : '',
          file: typeof r.file === 'string' ? r.file : '',
          category: typeof r.category === 'string' ? r.category : '',
        }))
      version.value = typeof res.data?.version === 'string' ? res.data.version : ''
      loaded.value = true
      loadedSeq = openSeq
    } catch (error: unknown) {
      if (openSeq !== null && openSeq !== requestedSeq) return
      console.warn('Failed to load CRS rule index:', error)
      rules.value = []
      version.value = ''
      loaded.value = false
      loadedSeq = openSeq
    } finally {
      if (openSeq === null || openSeq === requestedSeq) loading.value = false
    }
  }

  /** 对话框会话内取一次索引：同一 openSeq 已加载/在途时直接复用 */
  const ensureForDialog = (openSeq: number): Promise<void> => {
    if (loadedSeq === openSeq || requestedSeq === openSeq) return Promise.resolve()
    requestedSeq = openSeq
    return fetchIndex(openSeq)
  }

  /** 页面级加载（非对话框场景），无条件刷新 */
  const load = (): Promise<void> => {
    requestedSeq = null
    return fetchIndex(null)
  }

  return { rules, version, loading, loaded, byId, options, ensureForDialog, load }
}
