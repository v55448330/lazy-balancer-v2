// GET /security/crs/rules 全量分页取回单源。
//
// 后端 page_size 上限为 50（internal/handlers/security.go）。单页取回会让
// 文件数 >50 时组名映射静默回退裸组码，且策略页会把握手不到的存量响应阶段组
// 判成「当前 CRS 已无此规则组」而允许删除——两处消费（流程弹框/策略页）
// 必须共用同一份全量实现。
import { request } from './api'
import type { APIResponse } from '@/types'
import type { CrsRuleFileOption } from './securityStages'
import { tSafe as t } from '../i18n/tSafe.ts'

export const CRS_RULE_PAGE_SIZE = 50
// 上限 40 页（2000 个文件）：防御异常 total/分页不收敛，当前 CRS 约 40 个文件。
// 触顶仍未取满时抛错（见下），不得静默返回不完整清单。
export const CRS_RULE_MAX_PAGES = 40

/**
 * 全量取回 CRS 规则文件清单（按 filename/category 逐页拼接，网络错误向上抛）。
 *
 * 未收敛（触页上限仍有更多、或服务端 total 大于已取条目）时抛错：不完整清单
 * 会让组名映射回退裸组码、策略页把握手不到的组判成「已无此规则组」而放行
 * 删除。两个消费方都走既有错误横幅/重试链路。
 */
export const fetchAllCrsRuleFiles = async (): Promise<CrsRuleFileOption[]> => {
  const all: CrsRuleFileOption[] = []
  let total: number | undefined
  for (let page = 1; page <= CRS_RULE_MAX_PAGES; page++) {
    const res = await request.get<APIResponse<{ rules: CrsRuleFileOption[]; total?: number }>>(
      `/security/crs/rules?page_size=${CRS_RULE_PAGE_SIZE}&page=${page}`,
      { silent: true },
    )
    const rules = res.data?.rules ?? []
    all.push(...rules)
    total = res.data?.total
    if (rules.length < CRS_RULE_PAGE_SIZE) break
    if (typeof total === 'number' && all.length >= total) break
  }
  // 收敛判据：服务端给出 total 时必须取满；未给出时以「触顶且末页仍满页」
  // 为不收敛（分页可能还有下一页）。
  const truncated = typeof total === 'number'
    ? all.length < total
    : all.length >= CRS_RULE_PAGE_SIZE * CRS_RULE_MAX_PAGES
  if (truncated) {
    const counted = typeof total === 'number' ? t('common.app.crsRuleFiles.serverTotalSuffix', { total }) : ''
    throw new Error(t('common.app.crsRuleFiles.listIncomplete', { count: all.length, suffix: counted }))
  }
  return all
}
