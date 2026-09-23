// 「还原默认格式」按钮与初始 settings 共用的访问日志格式模板（唯一来源）。
// 注意：后端 db.go 迁移会在既有格式上追加 User-Agent / X-API-Key 行，
// 此处刻意保持前端原始模板不变（R41 F1：仅消除双份复制，不对齐后端迁移行）。
export const DEFAULT_ACCESS_LOG_FORMAT =
  'resp_headers -> delete\nrequest>tls -> delete\nrequest>remote_port -> delete\nlevel -> delete\nlogger -> delete\nmsg -> delete\nrequest>remote_ip -> src\nrequest>client_ip -> src_ip\nrequest>method -> http_method\nrequest>host -> server\nrequest>uri -> uri_path\nrequest>proto -> protocol\nuser_id -> user\nts -> time_local\nsize -> bytes_out\nbytes_read -> bytes_in\nduration -> request_time'

// CDN 受信代理预设（v2.3.x 真实 IP 支持）：仅辅助填充请求头（有序，权威头
// 在前）与提示文案——**不预置网段**（回源网段随时间变化，必须按官方文档
// 粘贴）。rangesDoc 为官方网段文档链接提示。
export interface CDNPreset {
  label: string
  headers: string[]
  note: string
  rangesDoc: string
}

export const CDN_PRESETS: CDNPreset[] = [
  { label: '通用（仅 X-Forwarded-For）', headers: ['X-Forwarded-For'], note: '仅采信 XFF 链，适合无专用头的 CDN', rangesDoc: '' },
  { label: 'Cloudflare', headers: ['CF-Connecting-IP', 'X-Forwarded-For'], note: '单值权威头优先；网段见官方列表', rangesDoc: 'https://www.cloudflare.com/ips/' },
  { label: 'Akamai', headers: ['True-Client-IP', 'X-Forwarded-For'], note: '需在 Akamai property 启用 True-Client-IP', rangesDoc: 'https://techdocs.akamai.com/' },
  { label: 'Fastly', headers: ['Fastly-Client-IP', 'X-Forwarded-For'], note: 'Fastly 默认注入 Fastly-Client-IP', rangesDoc: 'https://www.fastly.com/documentation/reference/api/utils/public-ip-list/' },
  { label: 'AWS CloudFront', headers: ['CloudFront-Viewer-Address', 'X-Forwarded-For'], note: 'CloudFront-Viewer-Address 含端口后缀', rangesDoc: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html' },
  { label: 'Google Cloud CDN', headers: ['X-Forwarded-For'], note: 'Google 前端追加真实 IP 到 XFF 链', rangesDoc: 'https://cloud.google.com/vpc/docs/identifying-ip-addresses' },
  { label: 'Azure Front Door', headers: ['X-Azure-ClientIP', 'X-Forwarded-For'], note: 'X-Azure-ClientIP 为单值权威头', rangesDoc: 'https://learn.microsoft.com/azure/frontdoor/front-door-faq' },
  { label: '阿里云 CDN', headers: ['X-Forwarded-For'], note: '阿里云 CDN 回源注入 XFF', rangesDoc: 'https://help.aliyun.com/zh/cdn/' },
  { label: '阿里云 ESA', headers: ['Ali-Real-Client-IP', 'X-Forwarded-For'], note: 'ESA 权威头为 Ali-Real-Client-IP', rangesDoc: 'https://help.aliyun.com/zh/esa/' },
  { label: '腾讯云 CDN', headers: ['X-Forwarded-For'], note: '回源重置注入，XFF 即真实 IP', rangesDoc: 'https://cloud.tencent.com/document/product/228' },
  { label: '腾讯云 EdgeOne', headers: ['EO-Connecting-IP', 'X-Forwarded-For'], note: 'EdgeOne 权威头为 EO-Connecting-IP', rangesDoc: 'https://cloud.tencent.com/document/product/1552' },
  { label: '华为云 CDN', headers: ['X-Forwarded-For'], note: '华为云 CDN 回源注入 XFF', rangesDoc: 'https://support.huaweicloud.com/cdn/' },
  { label: 'UCloud', headers: ['X-Real-IP', 'X-Forwarded-For'], note: 'UCloud 回源注入 X-Real-IP', rangesDoc: 'https://docs.ucloud.cn/' },
]
