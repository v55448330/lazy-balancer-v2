import { computed, ref } from 'vue'
import { request } from '@/utils/api'
import { normalizeStringEntries } from '@/utils/securityStages'
import { createSessionSingleFlight } from '@/utils/sessionSingleFlight'
import type { APIResponse } from '@/types'

/** CRS 规则索引条目（GET /security/crs/rule-index）——rules 由后端按 id 升序返回 */
interface CrsRuleIndexEntry {
  readonly id: string
  readonly msg: string
  readonly file: string
  readonly category: string
}

// 响应还带 version（CRS 规则集版本号），前端零消费（版本展示走 /security/crs/status
// 的独立字段），故不在此声明——声明不消费的字段只会诱导调用方误以为有此数据源。
interface CrsRuleIndexData {
  rules: CrsRuleIndexEntry[]
}

/** msg 清洗：去换行/制表、连续空白折叠为单个空格（索引来源为 CRS 注释，偶含换行与缩进） */
const cleanCrsMsg = (msg: string): string => msg.replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim()

/** 两行选项主行 label 的截断上限（超长 msg 截断 + …，全文经 title 悬浮展示） */
const CRS_RULE_LABEL_MAX_CHARS = 48

interface CrsRuleLabelView {
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
type CrsExclusionScope = 'all' | 'ip' | 'list'
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
 * - 旧字符串数组（存储：CRS 文件名/纯数字 ID/区间）：归一为 scope:'all' 行，
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
      ? normalizeStringEntries(rec.ips)
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
 * - ensureForDialog(openSeq)：策略对话框每次打开取一次索引（会话号经 issueCrsIndexSession 全局发放），同一会话内复用缓存
 *   （步骤间切换不重复请求）；复用 openDialog 的会话序列号守卫模式——对话框快速
 *   关闭重开后，旧会话的在途响应不得覆盖新会话数据（与 fetchIpLists(seq) 同源）。
 * 失败语义：HTTP 错误已由全局拦截器 toast，这里退化为空列表（loaded 保持 false，
 * 供消费方区分「索引未就绪」与「规则确实不在索引中」）。
 *
 * 状态提升为模块级单例——索引纯只读、仅 CRS 库更新时变化，原先每个消费方
 * （策略向导/事件快捷排除/规则集页）各自挂载都全量拉取同一份 ~832 条索引
 * （≈100KB+ JSON）。ref 与 seq 计数器提升为模块顶层：会话序列守卫语义不变
 * （在途失配丢弃、失败不落 loadedSeq 允许同会话重试），并发去重改为跨实例生效
 * （任一消费方已有在途请求则不重复发起）。导出签名不变，消费方无需改动。
 */
// 模块级共享状态（单例）：所有 useCrsRuleIndex() 消费方共享同一份索引与加载态
const rules = ref<CrsRuleIndexEntry[]>([])
// rules/version/load 三个返回位全仓零消费（两个消费方仅
// 解构 loading/loaded/byId/options/ensureForDialog）——version ref 随死返回一并
// 删除（移除后写-only）；rules/loading 等模块级状态保留（byId/options 内部消费）
const loading = ref(false)
// 仅在成功拿到索引后置 true；失败/未加载时为 false，消费方不得据此判定规则陈旧
const loaded = ref(false)
const byId = computed(() => {
  const map = new Map<string, CrsRuleIndexEntry>()
  for (const rule of rules.value) map.set(rule.id, rule)
  return map
})

// 下拉选项视图（id — label 主行 + file · category 副行），rules 已按 id 升序
const options = computed<CrsRuleOptionView[]>(() =>
  rules.value.map((r) => ({ id: r.id, ...crsRuleLabelView(r), file: r.file, category: r.category })))

// 会话守卫/单飞状态机抽到 utils/sessionSingleFlight（无依赖工厂，
// 行为测试直测「旧请求后到丢弃 + 新会话链式补取 + 失败可重试」，不再源码正则断言）。
// 消费方语义与原实现一致：同一 openSeq 复用缓存；跨实例在途去重；失败不落
// loadedSession 允许同会话重试；旧会话响应丢弃。
// openSeq 的 null 形态（页面级加载）当前零调用方，工厂签名收窄为数字 seq。
const indexLoader = createSessionSingleFlight<CrsRuleIndexEntry[]>({
  load: async () => {
    // silent：失败由本组合子 onError 记录并使 loaded=false、消费方渲染
    // 「索引未加载」文案——不 silent 会再叠加一条全局错误 toast（同一次失败两处提示）。
    const res = await request.get<APIResponse<CrsRuleIndexData>>('/security/crs/rule-index', { silent: true })
    const list = res.data?.rules
    return (Array.isArray(list) ? list : [])
      .filter((r): r is CrsRuleIndexEntry => !!r && typeof r.id === 'string' && r.id !== '')
      .map((r) => ({
        id: r.id,
        msg: typeof r.msg === 'string' ? r.msg : '',
        file: typeof r.file === 'string' ? r.file : '',
        category: typeof r.category === 'string' ? r.category : '',
      }))
  },
  apply: (list) => {
    rules.value = list
    loaded.value = true
  },
  onError: (error) => {
    console.warn('Failed to load CRS rule index:', error)
    // 失败不得清空已加载索引（stale-while-error）——ensureForDialog 每次
    // 打开弹框都会新会话重拉（~832 条/100KB+），任一次网络抖动原实现把模块级
    // rules 清空，当前已打开的向导/规则集页下拉与描述列同时变空。保留旧索引供
    // 展示，loaded 复位允许同会话重试（消费方的「规则已移除 vs 索引未加载」文案
    // 只读 loaded，不受影响）。
    loaded.value = false
  },
  onLoadingChange: (value) => { loading.value = value },
})

// 会话序号全局发放：原各消费方用组件局部递增序号（TriggerDetailDialog
// crsDialogSeq、SecurityPolicies openSeq），序号空间重叠会造成跨组件错位——
// B 首次打开可能命中 A 的会话号而跳过刷新；交错时大序号被小序号覆盖，新会话
// 响应被判过期丢弃并多发一次全量索引请求。统一由本模块发放保证全局单调递增。
let nextCrsIndexSession = 0
export const issueCrsIndexSession = (): number => ++nextCrsIndexSession

export const useCrsRuleIndex = () => {
  /** 对话框会话内取一次索引：会话号必须来自 issueCrsIndexSession()（全局唯一）；
   *  同一会话已加载时直接复用；在途请求不重复发起；
   *  上次失败（loadedSeq 未落、请求已 settled）允许同会话重试 */
  const ensureForDialog = (openSeq: number): Promise<void> => indexLoader.ensure(openSeq)

  return { loading, loaded, byId, options, ensureForDialog }
}
