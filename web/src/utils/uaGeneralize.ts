// UA 归一简化单源（规则日志统计页与连接详情弹框共用，口径锁定）：
// 浏览器家族+主版本 / OS；无法识别返回原文（展示侧自行截断省略）。
// 抽取自 Rules.vue 内联实现（2026-11-12 用户裁定：连接详情 UA 简化与
// 日志统计页同口径），Rules.vue 侧改为消费本单源。
export const generalizeUA = (ua: string): string => {
  if (!ua) return '-'
  let client = ''
  let version = ''
  const pick = (marker: string) => {
    const i = ua.indexOf(marker)
    if (i < 0) return ''
    const rest = ua.slice(i + marker.length)
    const m = rest.match(/^[\d.]+/)
    return m ? m[0].split('.')[0] : ''
  }
  if (ua.includes('Edg/')) { client = 'Edge'; version = pick('Edg/') }
  else if (ua.includes('Chrome/')) { client = 'Chrome'; version = pick('Chrome/') }
  else if (ua.includes('Firefox/')) { client = 'Firefox'; version = pick('Firefox/') }
  else if (ua.includes('Version/') && ua.includes('Safari/')) { client = 'Safari'; version = pick('Version/') }
  else if (ua.includes('curl/')) { client = 'curl'; version = pick('curl/') }
  else if (ua.includes('PostmanRuntime')) client = 'Postman'
  else if (ua.includes('python-requests')) client = 'Python Requests'
  else if (ua.includes('Go-http-client')) client = 'Go Client'
  if (!client) return ua
  let osName = ''
  if (ua.includes('Windows NT')) osName = 'Windows'
  else if (ua.includes('Mac OS X')) osName = 'macOS'
  else if (ua.includes('iPhone') || ua.includes('iPad')) osName = 'iOS'
  else if (ua.includes('Android')) osName = 'Android'
  else if (ua.includes('Linux')) osName = 'Linux'
  const ver = version ? ` ${version}` : ''
  return osName ? `${client}${ver} / ${osName}` : `${client}${ver}`
}
