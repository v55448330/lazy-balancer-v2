// 「还原默认格式」按钮与初始 settings 共用的访问日志格式模板（唯一来源）。
// 末行恒脱敏 API Key 请求头（面板机器接口凭证）——后端渲染层对任何
// 格式形态都会强制注入该行，模板显式携带使「落库格式=实际生效格式」。
// 拼写必须是引擎实际看到的头键形态（net/http 规范化的 X-Api-Key）：Caddy 的
// filter 编码器对字段路径做精确匹配，手写 X-API-Key 恒不命中。
// 注意：后端 db.go 迁移会在既有格式上补齐同一行。
// CDN 预设 label/note 为展示串:经 tSafe 词条安全 t() 进 common.app.views.caddyCfg;
// DEFAULT_ACCESS_LOG_FORMAT 是引擎契约模板(逐字跨栈钉),不参与抽词。
import { tSafe as t } from '../i18n/tSafe.ts'
export const DEFAULT_ACCESS_LOG_FORMAT =
  'resp_headers -> delete\nrequest>tls -> delete\nrequest>remote_port -> delete\nlevel -> delete\nlogger -> delete\nmsg -> delete\nrequest>remote_ip -> src\nrequest>client_ip -> src_ip\nrequest>method -> http_method\nrequest>host -> server\nrequest>uri -> uri_path\nrequest>proto -> protocol\nuser_id -> user\nts -> time_local\nsize -> bytes_out\nbytes_read -> bytes_in\nduration -> request_time\nrequest>headers>X-Api-Key -> delete'

// CDN 受信代理预设（v2.3.x 真实 IP 支持）：仅辅助填充请求头（有序，权威头
// 在前）与提示文案——**不预置网段**（回源网段随时间变化，必须按官方文档
// 粘贴）。rangesDoc 为官方网段文档链接提示。
interface CDNPreset {
  label: string
  headers: string[]
  note: string
  rangesDoc: string
}

export const CDN_PRESETS: CDNPreset[] = [
  { label: t('common.app.views.caddyCfg.presetGeneric'), headers: ['X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetGenericNote'), rangesDoc: '' },
  { label: t('common.app.views.caddyCfg.presetCloudflare'), headers: ['CF-Connecting-IP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetCloudflareNote'), rangesDoc: 'https://www.cloudflare.com/ips/' },
  { label: t('common.app.views.caddyCfg.presetAkamai'), headers: ['True-Client-IP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetAkamaiNote'), rangesDoc: 'https://techdocs.akamai.com/' },
  { label: t('common.app.views.caddyCfg.presetFastly'), headers: ['Fastly-Client-IP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetFastlyNote'), rangesDoc: 'https://www.fastly.com/documentation/reference/api/utils/public-ip-list/' },
  { label: t('common.app.views.caddyCfg.presetCloudFront'), headers: ['CloudFront-Viewer-Address', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetCloudFrontNote'), rangesDoc: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html' },
  { label: t('common.app.views.caddyCfg.presetGoogleCdn'), headers: ['X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetGoogleCdnNote'), rangesDoc: 'https://cloud.google.com/vpc/docs/identifying-ip-addresses' },
  { label: t('common.app.views.caddyCfg.presetAzureFd'), headers: ['X-Azure-ClientIP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetAzureFdNote'), rangesDoc: 'https://learn.microsoft.com/azure/frontdoor/front-door-faq' },
  { label: t('common.app.views.caddyCfg.presetAliyunCdn'), headers: ['X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetAliyunCdnNote'), rangesDoc: 'https://help.aliyun.com/zh/cdn/' },
  { label: t('common.app.views.caddyCfg.presetAliyunEsa'), headers: ['Ali-Real-Client-IP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetAliyunEsaNote'), rangesDoc: 'https://help.aliyun.com/zh/esa/' },
  { label: t('common.app.views.caddyCfg.presetTencentCdn'), headers: ['X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetTencentCdnNote'), rangesDoc: 'https://cloud.tencent.com/document/product/228' },
  { label: t('common.app.views.caddyCfg.presetEdgeOne'), headers: ['EO-Connecting-IP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetEdgeOneNote'), rangesDoc: 'https://cloud.tencent.com/document/product/1552' },
  { label: t('common.app.views.caddyCfg.presetHuaweiCdn'), headers: ['X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetHuaweiCdnNote'), rangesDoc: 'https://support.huaweicloud.com/cdn/' },
  { label: t('common.app.views.caddyCfg.presetUcloud'), headers: ['X-Real-IP', 'X-Forwarded-For'], note: t('common.app.views.caddyCfg.presetUcloudNote'), rangesDoc: 'https://docs.ucloud.cn/' },
]
