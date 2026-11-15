// 归属地文本拆分单源：后端形如 `中国·广东省·深圳市`（海外 `美国·California`）。
// 光流地域键与弧线起点（threatShared.arcOriginForLocation）共用同一拆分规则——
// 两处各自 split('·') 会在分隔符/段数变化时让「键里的省」与「端点用的省」漂移。
//
// 独立小模块（不挂在 threatShared）：threatFlowRules 是独立 chunk，而
// threatShared 静态依赖 chinaProvinces/countryCentroids 大表——反向依赖会把
// 大表拖进光流规则 chunk。

export function parseIpLocation(ipLocation: string | undefined): { country: string; province: string } {
  const [country = '', province = ''] = (ipLocation ?? '').split('·')
  return { country, province }
}

/**
 * 归属地紧凑展示单源（事件日志/总览建议行与累犯弹框共用）：后端数据值为中文
 * 原文——「保留地址」与「中国」按词条本地化，海外国家名原样；国内三段
 * （国家·省·市）取市、两段取省。纯展示判定锚定数据值，不做二次翻译。
 * labels 由调用方传入已本地化的 reserved/china 词条（本模块保持无 i18n 依赖，
 * node 行为测试可直接消费）。
 */
export function compactIpLocation(ipLocation: string | undefined, labels: { reserved: string; china: string }): string {
  if (!ipLocation) return ''
  const parts = ipLocation.split('·').map((part) => part.trim()).filter(Boolean)
  if (parts[0] === '保留地址') return labels.reserved
  if (parts[0] !== '中国') return parts[0]
  if (parts.length === 1) return labels.china
  return parts.length === 2 ? parts[1] : parts[2]
}
