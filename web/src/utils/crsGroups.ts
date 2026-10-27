/**
 * CRS 规则组选择面的取值口径（安全策略编辑器 / 冲突视图 / peer 视图共用）。
 *
 * 存储形态是混合的（两位组号 ∪ 6 位规则 ID ∪ 历史文件名前缀），归一口径必须在
 * 一处：后端 Include 以两位组代码为键，历史文件前缀（REQUEST-9<code>-*.conf）
 * 折算成组号；系统基础组（01/49/59，后端强制加载）与基础设施规则 ID
 * （901/949/959）按后端写入面同语义剥离。
 *
 * 关键语义（不可识别的形态**保留**）：三字符组码、区间遗留（942100-942200）、
 * 任意残留文本一律原样返回——编辑器打开即归一，丢弃这些值会让任意一次保存
 * 静默裁短用户配置；而当归一后整组为空时，渲染语义会从「只评估指定组」变成
 * 「加载全部 CRS 规则」，WAF 评估面被无声扩大。保留值由选择器侧的 ghost 标签
 * 给出可读说明与删除入口。
 */

import { parseCrsFilename } from './securityStages.ts'

/** 系统基础组（初始化 901 / 请求评估 949 / 响应评估 959 的两位组码）。 */
export const CRS_INFRA_GROUP_CODES: readonly string[] = ['01', '49', '59']

/** 规则组选择不提供、但存储回读时给专属说明的隐藏组码（99 = 通用误报豁免）。 */
export const CRS_HIDDEN_GROUP_CODES: readonly string[] = ['99']

/** 基础设施规则 ID 前缀（901 初始化 / 949 请求评估 / 959 响应评估）。 */
const CRS_INFRA_ID_PREFIXES = ['901', '949', '959']

export const isInfraRuleId = (id: string): boolean => CRS_INFRA_ID_PREFIXES.some((prefix) => id.startsWith(prefix))

export const isInitRuleId = (id: string): boolean => id.startsWith('901')

/**
 * 归一已存/已选值：可识别形态折算成组号，不可识别形态原样保留（见文件头）。
 * 结果去重且保持首次出现顺序。
 */
export const normalizeCrsGroups = (values: readonly string[]): string[] => {
  const normalized = values.map((value) => {
    if (/^\d{2}$/.test(value)) return value
    if (/^\d{6}$/.test(value)) return isInfraRuleId(value) ? '' : value
    return parseCrsFilename(value)?.code ?? value
  }).filter((code) => code !== '' && !CRS_INFRA_GROUP_CODES.includes(code))
  return [...new Set(normalized)]
}
