// 事件消息缺省模板（通道未自定义 content_template 时的回退形态）——前端单一
// 来源，与后端 notify.defaultEventTemplate 同构：
//   - zh 模板与后端**逐字等价**（跨栈夹具 web/tests/fixtures/event-default-templates.json
//     两端共读；后端 internal/notify/defaultEventTemplate 的实际投递形态是准绳）；
//   - en 为前端本地化版式（同一行结构/占位符序列，仅标签词与冒号本地化）。
//
// 版式（2026-11-22 定稿样稿逐字）：
//   - QQ = markdown 富文本：## 标题 / --- / **正文** / --- / 加粗标签列表
//     （级别去 ⚠️、冒号后留一空格）/ --- / 品牌引用页脚，全程无空行；
//   - 微信 = iLink 纯文本：【标题】+分隔线+键值行+空行+品牌署名，无 markdown 标记。
// 无缺省模板的通道（webhook/email 由各自版式承载）返回空串。
type EventTplLang = 'zh' | 'en'

interface EventTplLabels {
  readonly levelB: string
  readonly eventName: string
  readonly nodeName: string
  readonly occurredAt: string
  readonly notifyCenter: string
  readonly colon: string
}

const EVENT_TPL_LABELS: Record<EventTplLang, EventTplLabels> = {
  zh: { levelB: '级别', eventName: '事件名称', nodeName: '所属节点', occurredAt: '发生时间', notifyCenter: '通知中心', colon: '：' },
  en: { levelB: 'Level', eventName: 'Event name', nodeName: 'Node', occurredAt: 'Occurred at', notifyCenter: 'Notification Center', colon: ': ' },
}

export const defaultEventTpl = (typ: string, lang: EventTplLang): string => {
  const L = EVENT_TPL_LABELS[lang]
  if (typ === 'qq') {
    return [
      '## 🔔 {{title}}',
      '---',
      '**{{body}}**',
      '---',
      `* **${L.levelB}**${L.colon} {{level}}`,
      `* **${L.eventName}**${L.colon}{{event_title}}`,
      `* **${L.nodeName}**${L.colon}{{node}}`,
      `* **${L.occurredAt}**${L.colon}{{time}}`,
      '---',
      `> {{brand}} ${L.notifyCenter}`,
    ].join('\n')
  }
  if (typ === 'wx_clawbot') {
    return [
      '【{{title}}】',
      '────────────',
      '{{body}}',
      '────────────',
      `${L.levelB}${L.colon}⚠️ {{level}}`,
      `${L.eventName}${L.colon}{{event_title}}`,
      `${L.nodeName}${L.colon}{{node}}`,
      `${L.occurredAt}${L.colon}{{time}}`,
      '',
      `—— {{brand}} ${L.notifyCenter}`,
    ].join('\n')
  }
  return ''
}
