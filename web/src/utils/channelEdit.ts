// 通道编辑 PUT 体单源：target 是否提交由「脱敏态 + 是否输入新目标」决定。
//
// 管理员可见非属主通道的元数据，但后端对非属主 target 脱敏
// （ListNotificationChannels → maskChannelTarget）。脱敏串已不是合法 target
// JSON，编辑弹框必须置空目标输入框；用户不重新输入时 PUT 体**不得**带 target —
// 否则脱敏串会被当成新目标回写，真实接收者被覆盖且不可恢复。
// 输入了新目标则按通道类型的 target JSON 键正常提交（与新建同口径）。

interface ChannelEditDraft {
  name: string
  targetValue: string
  type: string
  /** 通道行 DTO 的 target_masked（后端标记：target 已脱敏）。 */
  targetMasked: boolean
}

interface ChannelEditPayload {
  name: string
  target?: string
}

// 通道类型 → target JSON 键（后端 validateChannelTarget / 投递消费同口径）。
export const channelTargetKey = (typ: string): string => {
  switch (typ) {
    case 'webhook': return 'url'
    case 'email': return 'email'
    case 'qq': return 'openid'
    case 'wx_clawbot': return 'receiver'
    default: return 'target'
  }
}

// 编辑保存体：脱敏态且未输入新目标 → 省略 target 键（保留服务端原值）；
// 其余形态（含未脱敏态的空目标）保持原行为提交 target。
export const channelEditPayload = (draft: ChannelEditDraft): ChannelEditPayload => {
  const payload: ChannelEditPayload = { name: draft.name.trim() }
  const target = draft.targetValue.trim()
  if (!(draft.targetMasked && target === '')) {
    payload.target = JSON.stringify({ [channelTargetKey(draft.type)]: target })
  }
  return payload
}
