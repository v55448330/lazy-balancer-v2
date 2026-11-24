// 投递流水分通道结果收敛（纯函数）。
//
// 一次投递的每次尝试都会向 notification_delivery_channels 追加同 channel_id
// 的结果行（daemon 重试/重发），列表 JOIN 会带出同一通道的全部历史行：
// 展开列表重复、成功/失败计数被历史重试放大。展示层按 channel_id 只保留最新
// 结果行——DTO 有 id 时取最大 id；无 id 时依赖接口 `ORDER BY nc.id`，后出现者
// 即最新。

interface DeliveryChannelResultLike {
  channel_id: number
  /** 结果行 id（可选：列表 DTO 目前不返回，按出现顺序收敛）。 */
  id?: number
}

export const latestChannelResults = <T extends DeliveryChannelResultLike>(channels: readonly T[]): T[] => {
  const byChannel = new Map<number, T>()
  for (const ch of channels) {
    const prev = byChannel.get(ch.channel_id)
    if (!prev) {
      byChannel.set(ch.channel_id, ch)
      continue
    }
    const prevId = typeof prev.id === 'number' ? prev.id : Number.NEGATIVE_INFINITY
    const curId = typeof ch.id === 'number' ? ch.id : Number.NEGATIVE_INFINITY
    if (curId >= prevId) byChannel.set(ch.channel_id, ch)
  }
  return [...byChannel.values()]
}

/** 分通道状态词条叶子键（app.notification.deliveries.*）；未知状态返回 null。
 *
 * 展开行/状态列的兜底：把未知状态（后端新增通道结果态）一律映射成「失败」
 * 会让排障读到与事实不符的结论——未知即原样回显状态码 + 中性着色。 */
type ChannelStatusMessageKey = 'statusPending' | 'statusSent' | 'statusFailed' | 'statusDead'

export const channelStatusMessageKey = (status: string): ChannelStatusMessageKey | null => {
  switch (status) {
    case 'pending': return 'statusPending'
    case 'sent': return 'statusSent'
    case 'failed': return 'statusFailed'
    case 'dead': return 'statusDead'
    default: return null
  }
}

/** 分通道状态标签的 el-tag 类型：success=已投递、danger=失败/死信、其余（含未知）中性。 */
type ChannelStatusTagType = 'info' | 'success' | 'warning' | 'danger'

export const channelStatusTagType = (status: string): ChannelStatusTagType => {
  if (status === 'sent') return 'success'
  return channelStatusMessageKey(status) === null ? 'info' : 'danger'
}

/** 展开行错误文案形态：有错误原文 / 失败但未记录原因 / 无错误（未失败）。
 *
 * 「失败但 error 为空」是历史行与聚合行的真实形态（写入侧正常带原因）：直接
 * 显示「无错误」与红色失败标签自相矛盾，读起来像投递成功。 */
type ChannelErrorKind = 'error' | 'missing' | 'none'

export const channelErrorKind = (channel: { status: string; error?: string | null }): ChannelErrorKind => {
  if ((channel.error ?? '').trim() !== '') return 'error'
  return channel.status === 'failed' || channel.status === 'dead' ? 'missing' : 'none'
}
