// 与后端 joinUpstreamAddress（net.JoinHostPort）同口径——IPv6 主机
// （含 ':'）包方括号，健康详情键两侧一致（后端键为 "[::1]:80" 形态）。
// Rules/Dashboard 共用（原 Rules 局部定义 + Dashboard 裸拼双份漂移）。
export const hostPortKey = (host: string, port: number): string =>
  host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`

// 「同一后端」判重的主机形态（与后端 upstreamDedupeHost 同口径）：
//   - IP 字面量按地址语义归一——WHATWG URL 解析器输出的 IPv6 是压缩规范形态，
//     2001:0db8:0:0:0:0:0:1 与 2001:db8::1 因此得到同一个键；
//   - 主机名保持文本归一（去首尾空白 + 小写，DNS 不区分大小写）。
// 同一后端的两种等价写法若被当成两个上游，权重会翻倍且健康检查跑两遍；后端
// 是权威门（写侧 400），这里只做同一口径的即时提示。
export const upstreamHostKey = (host: string): string => {
  const trimmed = host.trim()
  const bare = trimmed.replace(/^\[/, '').replace(/\]$/, '')
  if (bare.includes(':') && !bare.includes('%')) {
    try {
      const canonical = new URL(`http://[${bare}]/`).hostname
      if (canonical) return canonical.replace(/^\[/, '').replace(/\]$/, '').toLowerCase()
    } catch {
      // 非 IPv6 字面量（或非法形态）落文本归一，形状校验另行拒绝
    }
  }
  return trimmed.toLowerCase()
}

// 上游去重键 = 归一主机 + 端口（IPv6 按 hostPortKey 包方括号，与展示键同形）。
export const upstreamDedupeKey = (host: string, port: number): string =>
  hostPortKey(upstreamHostKey(host), port).toLowerCase()
