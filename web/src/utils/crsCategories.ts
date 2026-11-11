// CRS 规则分类显示映射:后端 CategorizeCRSFile 产出的 zh 分类码为有限集合,
// en 用户经词条显示;未登记值回落原文。键=后端 zh 分类码原文。
export const CRS_CATEGORY_KEYS: Record<string, string> = {
  '初始化': 'init',
  '初始化/排除': 'initExclusions',
  '通用异常': 'genericAnomalies',
  '方法限制': 'methodRestrictions',
  '爬虫检测': 'crawlerDetection',
  '协议异常': 'protocolAnomalies',
  '协议攻击': 'protocolAttacks',
  'multipart 攻击': 'multipartAbuse',
  '路径穿越 (LFI)': 'lfi',
  '远程文件包含 (RFI)': 'rfi',
  '远程代码执行 (RCE)': 'rce',
  'PHP 攻击': 'phpAttacks',
  '通用攻击': 'genericAttacks',
  'XSS 跨站脚本': 'xss',
  'SQL 注入': 'sqli',
  '会话固定': 'sessionFixation',
  'Java 攻击': 'javaAttacks',
  '评分拦截': 'scoringThreshold',
  '响应信息泄露': 'responseInfoDisclosure',
  '响应 SQL 泄露': 'responseSqlDisclosure',
  '响应 Java 泄露': 'responseJavaDisclosure',
  '响应 PHP 泄露': 'responsePhpDisclosure',
  '响应 IIS 泄露': 'responseIisDisclosure',
  'Webshell': 'webshell',
  '响应 Ruby 泄露': 'responseRubyDisclosure',
  '响应阻断评估': 'responseBlockingEvaluation',
  '事件关联': 'eventCorrelation',
  '请求体限制': 'requestBodyRestrictions',
  '通用排除（CRS 后）': 'genericExclusionsPostCrs',
}

import { tSafe } from '../i18n/tSafe.ts'
import { hasOwn } from './hasOwn'

export const crsCategoryLabel = (raw?: string): string => {
  if (!raw) return raw || ''
  const k = hasOwn(CRS_CATEGORY_KEYS, raw) ? CRS_CATEGORY_KEYS[raw] : undefined
  return k ? tSafe(`common.app.crsCategory.${k}`) : raw
}
