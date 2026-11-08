/**
 * 集群地址校验单源。
 *
 * 主节点地址（注册弹框）与节点访问地址（节点配置弹框）在后端共用
 * `models.ValidateClusterAccessURL`：scheme ∈ {http, https}、host 非空、
 * 不允许 userinfo / query / fragment。此前前端是两份实现——主节点地址只校验
 * scheme，访问地址才校验完整规则——同一地址会在注册表单通过、提交时被后端以
 * 同一中文错误拒绝（晚失败）。现两处共用本函数，规则逐条与后端对齐。
 *
 * 注意 WHATWG `new URL` 与后端 `url.Parse` 的语义差异：浏览器会把
 * `http:example.com`、`http:/example.com`、`https:///example.com` 补全成带主机
 * 的地址（`host` 非空），后端分别得到 opaque 段 / 空 `Host`，一律 400。因此
 * 只看 `parsed.host` 不够——先按原文要求 scheme 后确有 `//` 且 authority 非空
 * （对应后端 `Opaque == ""` 且 `Host != ""`），再把 userinfo 判定从解析结果的
 * username/password 扩到 authority 里的 `@`（`http://@host` 在后端 `User != nil`
 * 被拒，而浏览器解析出的 username 为空）。
 */

import { tSafe as t } from '../i18n/tSafe.ts'

interface ClusterUrlValidationOptions {
  /** 错误文案前缀，如「主节点地址」/「访问地址」。 */
  readonly label: string
  /** 空值错误文案；不传 = 空值合法（对应后端 AccessURL 允许空串）。 */
  readonly emptyMessage?: string
}

/** 返回错误文案；合法返回 null。 */
export const validateClusterUrl = (
  value: string,
  options: ClusterUrlValidationOptions,
): string | null => {
  const normalized = value.trim()
  if (!normalized) return options.emptyMessage ?? null
  let parsed: URL
  try {
    parsed = new URL(normalized)
  } catch {
    // new URL() 仅抛 TypeError；其余异常同样视为地址非法，走统一提示，不向外抛。
    return t('common.app.clusterUrl.formatInvalid', { label: options.label })
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return t('common.app.clusterUrl.mustBeHttp', { label: options.label })
  // scheme 后的 authority 形态门（见文件头）：`//` 缺失或 authority 为空即
  // 后端必然 400 的形态，字段级直接拦下。
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(normalized)
  if (!authority || !authority[1] || !parsed.host) return t('common.app.clusterUrl.formatInvalid', { label: options.label })
  if (parsed.username || parsed.password || authority[1].includes('@')) return t('common.app.clusterUrl.noCredentials', { label: options.label })
  if (parsed.search) return t('common.app.clusterUrl.noQuery', { label: options.label })
  if (parsed.hash) return t('common.app.clusterUrl.noFragment', { label: options.label })
  return null
}
