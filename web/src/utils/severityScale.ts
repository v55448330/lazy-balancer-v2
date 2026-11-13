// anomaly_score 危险等级分档单源：威胁大屏事件定级与事件列表评分着色共用。
//
// 列表原用 ≥15/≥5、大屏用 ≥12/≥6——同一评分两页结论打架。统一为大屏口径
//（2026-10-17 用户裁定：≥12 高 / ≥6 中 / <6 低）。
//
// 检测模式（未拦截）整体降一级与 0 分行回退族同在本模块：两段都是用户可见的
// 严重度着色，集中在此保证大屏定级与事件列表共用同一口径。

export const ANOMALY_SCORE_HIGH = 12
export const ANOMALY_SCORE_MID = 6

export type AnomalySeverity = 'high' | 'mid' | 'low'

/** 评分 → 三档定级（不含检测模式降级——降级是动作语义，见 overlayDetectionGrade）。 */
export const anomalySeverity = (score: number): AnomalySeverity =>
  score >= ANOMALY_SCORE_HIGH ? 'high' : score >= ANOMALY_SCORE_MID ? 'mid' : 'low'

/**
 * 检测模式降级叠加：未拦截事件整体降一级（高→中、中→低、低保持），
 * 已拦截事件按基础档原样返回。
 */
export const overlayDetectionGrade = (base: AnomalySeverity, action: string): AnomalySeverity =>
  action === 'blocked' ? base : base === 'high' ? 'mid' : 'low'

/**
 * 0 分行（存量行）回退：现代引擎一律带评分，只有历史行落在这里。定性口径与
 * 后端入库补分（services/securityevents.go）一致——IP 名单/信任/威胁情报/
 * 爬虫伪装/预检=12（高），普通 GeoIP=6（中），爬虫豁免=0（低/审计轨迹），
 * 其余按动作给中/低。
 *
 * `^8\d{5}$` 一族不能一刀切：三族全部落在该模式内，必须按段界区分
 * （段界与 internal/services/security.go 的 encode/decode 同值——Go 侧是
 * 单一事实源，改动需同步）：
 * - 普通 GeoIP `[800000,810000)`（+policyID）=6 → 中危；
 * - 爬虫豁免 `[810000,850000)`（+policyID*16+引擎序号）=0 → 低危（放行轨迹）；
 * - 爬虫伪装 `[850000,900000)`（+policyID）=12 → 与 12 分族同档。
 *
 * 检测模式只把高危族降为中危（存量行是粗粒度定性，不做中→低的二次下调，
 * 与评分分支的整档下移不同）。481-484 是渲染器发射的 HTTP 阻断状态码，
 * 不是 rule_triggered 值，落入兜底分支。
 *
 * 阶段 2 配额限流退役后不再产生新的 429 事件行（CC 防护改由 lb_human 插件
 * 响应，事件 id 为 human_*）；退役前的 429 存量行仍带引擎评分，走 anomalySeverity
 * 分档，不落本回退（本回退只处理 anomaly_score=0 的历史行）。
 */
export const GEOIP_CRAWLER_EXEMPT_BASE = 810000
export const GEOIP_CRAWLER_SPOOF_BASE = 850000
/** 预检段右开界（CRS 保留段起点）。 */
export const GEOIP_PRECHECK_LIMIT = 900000

/**
 * 0 分行固定预检族：阶段 1 预检固定 id 清单（IP 名单 2/4/7、信任 3/12、
 * 威胁情报 14），`5` 为绕过模式占用的信任并集（pass,nolog 不产事件，防御位）。
 * GeoIP 的固定 id `8` 不在此列——它由下方段界分支单独分档。
 *
 * 单一事实源在后端 `internal/services/security.go` 的
 * `Stage1PrecheckIDSQLList` / `IsStage1PrecheckEventID`（入库补分 12），
 * 此处改动必须与后端同步：`web/tests/severityScale.spec.ts` 按后端口径对表钉住。
 */
export const ZERO_SCORE_PRECHECK_IDS: readonly string[] = ['2', '3', '4', '5', '7', '12', '14']

export const zeroScoreSeverity = (ruleTriggered: string, action: string): AnomalySeverity => {
  const blocked = action === 'blocked'
  if (ZERO_SCORE_PRECHECK_IDS.includes(ruleTriggered)) {
    return blocked ? 'high' : 'mid'
  }
  if (/^8\d{5}$/.test(ruleTriggered)) {
    const n = Number(ruleTriggered)
    if (n >= GEOIP_CRAWLER_SPOOF_BASE && n < GEOIP_PRECHECK_LIMIT) return blocked ? 'high' : 'mid'
    if (n >= GEOIP_CRAWLER_EXEMPT_BASE) return 'low'
    return 'mid'
  }
  if (ruleTriggered === '8') return 'mid'
  return blocked ? 'mid' : 'low'
}
