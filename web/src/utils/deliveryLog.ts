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
