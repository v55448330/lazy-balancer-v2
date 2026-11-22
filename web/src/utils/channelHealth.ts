// 通道复合健康态判定单源（卡片标签 + tooltip 共用），纯函数便于边界钉测。
//
// 优先级：停用 > 连接离线 > 微信会话待刷新 > 未验证 > 验证失败 > 就绪。
// 「未验证」必须早于「验证失败」：后端 last_test_ok 是 INTEGER 列，从未测试的
// 行默认 0（false）——先判 false 会把新通道全部渲染成「验证失败」，与
// last_test_at 为空的「未验证过」自相矛盾。

export type ChannelHealthState =
  | 'disabled' | 'link_down' | 'session_stale' | 'test_failed' | 'unverified' | 'ready'

interface ChannelHealthInput {
  type: string
  enabled: boolean
  link_connected?: boolean
  session_ready?: boolean
  last_test_at?: string
  last_test_ok?: boolean
}

export const channelHealthState = (ch: ChannelHealthInput): ChannelHealthState => {
  if (!ch.enabled) return 'disabled'
  if ((ch.type === 'qq' || ch.type === 'wx_clawbot') && ch.link_connected === false) return 'link_down'
  // 微信须接收者先建立会话才能主动发送；会话未就绪（或已知测试失败）优先提示刷新会话。
  if (ch.type === 'wx_clawbot' && !(ch.session_ready === true && ch.last_test_ok !== false)) return 'session_stale'
  if (!ch.last_test_at) return 'unverified'
  if (ch.last_test_ok === false) return 'test_failed'
  return 'ready'
}
