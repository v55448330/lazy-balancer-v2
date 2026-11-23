// 连接监控行分类与筛选键同源映射。
//
// 后端 /metrics/connections/list 的 connections[].category 是 socket 状态族
// （established/time_wait/closed，见 internal/handlers/connections_list.go），
// 而 requests[].category 与前端筛选器键是窗口语义（active/closing/closed）。
// 回退视图（req_mon=false）直接用原始 category 与筛选键比较时，默认 active
// 永远匹配不到 established——统计卡有计数、表格显示无连接。
//
// 映射保持幂等：请求视图行（已是 active/closing/closed）原样返回；未知形态
// 也原样返回（不静默归入 active，避免把未知连接藏进活跃视图）。

import { hasOwn } from './hasOwn.ts'

type ConnectionFilterCategory = 'active' | 'closing' | 'closed'

const SOCKET_STATE_TO_FILTER: Readonly<Record<string, ConnectionFilterCategory>> = {
  established: 'active',
  time_wait: 'closing',
  closed: 'closed',
}

/** socket 状态族/筛选键 → 筛选键（幂等）；未知形态原样返回。 */
export const connectionFilterCategory = (category: string): string =>
  hasOwn(SOCKET_STATE_TO_FILTER, category) ? SOCKET_STATE_TO_FILTER[category] : category
