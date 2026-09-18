// LB-08：与后端 joinUpstreamAddress（net.JoinHostPort）同口径——IPv6 主机
// （含 ':'）包方括号，健康详情键两侧一致（后端键为 "[::1]:80" 形态）。
// FE40-D1-1：Rules/Dashboard 共用（原 Rules 局部定义 + Dashboard 裸拼双份漂移）。
export const hostPortKey = (host: string, port: number): string =>
  host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`
