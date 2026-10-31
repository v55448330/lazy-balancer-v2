// 安全规则库展示单源：SecurityRules 与 SecurityOverview 此前各自
// 实现「状态标签/色调 + 多源聚合」，且已漂移（同为空 source 列表，规则集页
// 落 idle 显示「已最新」，总览页返回 '' 不显示标签）。本模块统一：
// - libraryStatusLabel / libraryStatusTagType：状态 → 文案/色调
// - summarizeLibrarySources：威胁情报库/爬虫地址库多源聚合（版本取最近、
//   条目求和、状态=更新中>失败>成功>未更新）
// - libraryHealthTag / librarySourceHealthTag：卡头健康标签
// 状态词表：missing=库文件/目录缺失（danger）、not-installed=库未安装（info）、
// never=从未更新（info）、cancelled=已取消（info）、failed/running/checking/
// downloading/installing/reloading/success/idle 与后端 update_status 同词。
// 文件缺失与未安装的用户可见词统一「未安装」（版本列 2026-09-24 用户裁定的
// 用词）：同一行/同一卡片的两个单元格不得用两个词描述同一事实；二者区别由
// 色调承载（缺失=danger，未安装=info）。
import { compareVersion } from './securityStages.ts'
import { hasOwn } from './hasOwn.ts'
import { formatInt } from './formatInt.ts'

type LibraryTagType = 'success' | 'warning' | 'danger' | 'info'

const STATUS_LABELS: Record<string, string> = {
  missing: '未安装',
  'not-installed': '未安装',
  never: '未更新',
  failed: '更新失败',
  running: '更新中',
  checking: '检查中',
  downloading: '下载中',
  installing: '安装中',
  reloading: '重载中',
  success: '已最新',
  idle: '已最新',
  cancelled: '已取消',
  disabled: '已关闭',
  // 零源多源库（威胁/爬虫）的占位行状态：与卡头健康标签「未配置」同词。
  'not-configured': '未配置',
}

// 状态词表是普通对象：后端异常值（'constructor'/'toString' 等）直接下标会命中
// 原型链上的函数，把函数当标签渲染。与 utils/hasOwn 同一具名守卫。
export const libraryStatusLabel = (status: string): string =>
  hasOwn(STATUS_LABELS, status) ? STATUS_LABELS[status] : status ?? ''

export const libraryStatusTagType = (status: string): LibraryTagType => {
  if (!status) return 'info'
  if (status === 'missing' || status === 'failed' || status.includes('失败') || status.includes('错误')) return 'danger'
  if (status === 'not-installed' || status === 'never' || status === 'disabled') return 'info'
  // 同族收敛：cancelled 是后端的持久状态（四类库均会写），原词表漏映射
  // 会让状态列直接显示英文原词——中立 info，不冒充失败/成功。
  if (status === 'cancelled') return 'info'
  if (status === 'checking' || status === 'downloading' || status === 'installing' || status === 'reloading' || status === 'running') return 'warning'
  if (status === 'success' || status === 'idle' || status.includes('最新')) return 'success'
  if (status.includes('中')) return 'warning'
  return 'info'
}

export interface LibrarySourceRow {
  readonly version?: string
  readonly update_status?: string
  readonly update_enabled?: boolean
  readonly entry_count?: number
  readonly last_checked?: string
  readonly next_update?: string
}

interface LibrarySummary {
  readonly latestVersion: string
  readonly totalEntries: number
  readonly status: 'running' | 'failed' | 'success' | 'never' | 'disabled'
  readonly lastChecked: string
  readonly nextUpdate: string
}

/**
 * 多源规则库聚合（威胁情报库/爬虫地址库共用）：
 * - latestVersion = 各源 version 最大值（compareVersion，日期/semver 通用；
 *   等值取行序最后一行，API 为 id 序——后端 latestSourceVersion 同口径；
 *   空/纯空白值先 trim 再跳过，与后端 TrimSpace 后 continue 同口径）；
 * - totalEntries = 各源 entry_count 之和；
 * - status = 任一更新中 > 任一失败 > 有版本=success > never（空源/无版本）。
 *   「从未更新」独立成 never，不折叠为 idle/「已最新」——原两页对空列表的
 * 结论互相矛盾。
 * formatDate 注入（缺省原样）避免本模块依赖 auth store，供 node 测试直测。
 */
export const summarizeLibrarySources = (
  sources: readonly LibrarySourceRow[],
  formatDate: (value?: string) => string = (value) => value || '',
): LibrarySummary => {
  // 已关闭源不参与任务状态聚合：关闭前的 failed 是历史态，继续计入会让
  // 库头持续显示「N 源更新失败」，而该源实际已不在任何更新任务内。
  const active = sources.filter((s) => s.update_enabled !== false)
  const anyRunning = active.some((s) => s.update_status === 'running')
  const anyFailed = !anyRunning && active.some((s) => s.update_status === 'failed')
  // 版本先 trim 再判空：后端 latestSourceVersion 对空/纯空白源 continue，
  // 前端在 trim 前用 !!v 过滤会把 " " 当有值——同一库在集群 hover（后端）
  // 显示未更新、在规则库页（前端）显示已最新。跨栈夹具
  // web/tests/fixtures/library-aggregate.tsv 由两端同读。
  const latestVersion = sources
    .map((s) => (s.version ?? '').trim())
    .filter((v) => v !== '')
    .sort(compareVersion)
    .pop() || ''
  const totalEntries = sources.reduce((sum, s) => sum + (s.entry_count || 0), 0)
  // 上次更新取最晚、下次更新取最早（空源 → '—'）；下次排程只看启用源。
  const lastChecked = sources.map((s) => formatDate(s.last_checked)).filter(Boolean).sort().pop() || '—'
  const nextUpdate = active.map((s) => formatDate(s.next_update)).filter(Boolean).sort().shift() || '—'
  return {
    latestVersion,
    totalEntries,
    status: active.length === 0 && sources.length > 0
      ? 'disabled'
      : anyRunning ? 'running' : anyFailed ? 'failed' : latestVersion ? 'success' : 'never',
    lastChecked,
    nextUpdate,
  }
}

interface LibraryHealthTag {
  readonly label: string
  readonly type: LibraryTagType
}

/**
 * 单库（CRS/IP 地理库）健康标签：加载失败/库文件缺失 → danger；库未安装
 * （版本未知/空）→ warning，不得再显示「正常」。
 * 用词与其他库页面统一「未安装」（缺失=危险色，未安装=警告色，词同一）。
 * loaded=false（首次响应未落地）→ 「加载中」（初值 available:true
 * 不得冒充正常态）；缺省 true，既有调用方口径不变。
 */
export const libraryHealthTag = (
  name: string,
  state: { loadError: boolean; available?: boolean; status?: string; loaded?: boolean },
): LibraryHealthTag => {
  if (state.loaded === false) return { label: `${name} · 加载中`, type: 'info' }
  if (state.loadError) return { label: `${name} · 加载失败`, type: 'danger' }
  if (state.available === false) return { label: `${name} · 未安装`, type: 'danger' }
  if (state.status === 'not-installed') return { label: `${name} · 未安装`, type: 'warning' }
  if (state.status === 'never') return { label: `${name} · 未更新`, type: 'warning' }
  // 持久 update_status 的失败/进行中/关闭态必须显性——该列可为
  // failed（更新失败落库），活动期还会 overlay checking/downloading/installing/
  // reloading/running。此前一律落「正常」，与同卡状态列（libraryStatusTagType）
  // 的「更新失败/更新中」自相矛盾。词表复用状态列单源。
  const status = state.status ?? ''
  if (status !== '' && status !== 'success' && status !== 'idle') {
    return { label: `${name} · ${libraryStatusLabel(status)}`, type: libraryStatusTagType(status) }
  }
  return { label: `${name} · 正常`, type: 'success' }
}

/** 多源库（威胁情报库/爬虫地址库）健康标签：更新中/部分失败为 warning；
 * loaded=false（首次响应未落地）→ 「加载中」。*/
export const librarySourceHealthTag = (
  name: string,
  sources: readonly LibrarySourceRow[],
  loadError: boolean,
  loaded = true,
): LibraryHealthTag => {
  if (!loaded) return { label: `${name} · 加载中`, type: 'info' }
  if (loadError) return { label: `${name} · 加载失败`, type: 'danger' }
  if (sources.length === 0) return { label: `${name} · 未配置`, type: 'warning' }
  const active = sources.filter((s) => s.update_enabled !== false)
  if (active.length === 0) return { label: `${name} · 已关闭`, type: 'info' }
  if (active.some((s) => s.update_status === 'running')) return { label: `${name} · 更新中`, type: 'warning' }
  const failed = active.filter((s) => s.update_status === 'failed').length
  if (failed > 0) return { label: `${name} · ${failed} 源更新失败`, type: 'warning' }
  return { label: `${name} · 正常`, type: 'success' }
}

/**
 * CRS 规则库「数量」列文案：后端 `rule_count` 是 SecRule
 * 指令条数（internal/services/crsrelease.go countSecRules 只数 SecRule 行）——
 * 写「条规则」而不是「个文件」，否则 832 条规则会被读成 832 个文件。
 * 读取失败由调用方先行置 '—'；0/缺省同样 '—'（0 条不等于「库已就绪」）。
 *
 * 千分位走单源 formatInt（utils/formatInt.ts，手工分组）：**不用**
 * `toLocaleString()` 的默认 locale——后者随宿主 LC_ALL/LANG 变（de → `1.234`，
 * fr → `1 234`），同一份代码在不同开发机/CI 上给出不同文案（守卫假红），
 * de/fr 用户还会把千分位读成小数点。
 */
export const crsRuleCountLabel = (ruleCount: number | undefined): string =>
  ruleCount && ruleCount > 0 ? `${formatInt(ruleCount)} 条规则` : '—'

/**
 * 规则库「定时更新」保存前校验：返回错误文案，合法时 null。
 * 时间被清空时原实现静默回落 04:00——输入框显示空、落库却是 04:00，用户看不到
 * 差异。改为显式拒绝保存（不代填），由组件以 warning 呈现。
 */
export const libraryScheduleError = (days: readonly number[], time: string | null | undefined): string | null => {
  if (days.length === 0) return '至少选择一天'
  if (!time) return '请选择时间'
  return null
}

/**
 * 定时更新卡片「父级轮询刷新是否可回填」判据：仅当用户未改动编辑态
 * （编辑值与上一次 props 快照一致）时才允许同步——否则用户编辑中的星期/时间
 * 会被 15s 轮询覆盖（用户输入丢失）。星期顺序敏感（周一/周二 ≠ 周二/周一），
 * 上一次时间为空时按默认显示值 04:00 比较（与输入框初值同口径）。
 */
export const scheduleEditUntouched = (
  edit: { readonly days: readonly number[]; readonly time: string },
  previous: { readonly days?: readonly number[]; readonly time?: string },
): boolean =>
  edit.days.join() === (previous.days ?? []).join()
  && edit.time === ((previous.time ?? '') || '04:00')

