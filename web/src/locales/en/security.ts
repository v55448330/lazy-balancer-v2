// i18n batch C (security domain): six-file entries, keys app.security.*; en translated per style guide.
// 由批次C集成脚本从 workers 词条合并生成;注册接线由 main 统一做。
export default {
"app": {
  "security": {
    "ipLocation": {
      "cell": {
        "ariaLabel": {
          "zh": "IP 名单管理：{ip}",
          "en": "Manage IP lists: {ip}"
        }
      },
      "header": {
        "kicker": {
          "zh": "IP 名单管理",
          "en": "IP list management"
        },
        "eventCountTip": {
          "zh": "近 30 天安全事件",
          "en": "Security events in the last 30 days"
        },
        "eventCountUnit": {
          "zh": "次事件",
          "en": "events"
        }
      },
      "loadError": {
        "incomplete": {
          "zh": "名单状态读取不完整，暂不能写入",
          "en": "List status is incomplete — writes are unavailable for now"
        },
        "reload": {
          "zh": "重新加载",
          "en": "Reload"
        }
      },
      "sections": {
        "add": {
          "zh": "添加",
          "en": "Add"
        },
        "chooseTarget": {
          "zh": "选择目标名单",
          "en": "Choose a target list"
        },
        "targetMeta": {
          "zh": "{count} 条 · {refs} 个策略引用",
          "en": "{count} entries · {refs} policy references"
        },
        "targetPolicy": {
          "zh": "关联策略：{name}",
          "en": "Linked policy: {name}"
        },
        "cancel": {
          "zh": "取消",
          "en": "Cancel"
        },
        "writing": {
          "zh": "正在写入…",
          "en": "Writing…"
        },
        "confirmAdd": {
          "zh": "确认添加",
          "en": "Add"
        },
        "noTarget": {
          "zh": "没有可写入的{title}策略。请先在安全策略中创建对应策略。",
          "en": "No {title} policy to write to — create one in Security Policies first"
        },
        "goPolicies": {
          "zh": "前往安全策略",
          "en": "Go to Security Policies"
        },
        "readingLists": {
          "zh": "正在读取名单…",
          "en": "Loading lists…"
        },
        "notJoined": {
          "zh": "未加入{title}",
          "en": "Not in {title}"
        },
        "sourceInline": {
          "zh": "策略内联 · {count} 条",
          "en": "Policy inline · {count} entries"
        },
        "matchedCidr": {
          "zh": "命中 {entry}",
          "en": "matched {entry}"
        },
        "refsTitle": {
          "zh": "引用此名单的策略",
          "en": "Policies referencing this list"
        },
        "edit": {
          "zh": "编辑",
          "en": "Edit"
        },
        "remove": {
          "zh": "移除",
          "en": "Remove"
        }
      },
      "autoban": {
        "title": {
          "zh": "自动封禁",
          "en": "Auto-ban"
        },
        "desc": {
          "zh": "仅管理自动封禁名单，不改变其它名单",
          "en": "Manages the auto-ban list only — other lists are untouched"
        },
        "loadingStatus": {
          "zh": "正在读取封禁状态…",
          "en": "Loading ban status…"
        },
        "loadFailed": {
          "zh": "封禁状态读取失败",
          "en": "Failed to load ban status"
        },
        "retry": {
          "zh": "重试",
          "en": "Retry"
        },
        "none": {
          "zh": "当前未被封禁",
          "en": "Not currently banned"
        },
        "listName": {
          "zh": "自动封禁名单",
          "en": "Auto-ban list"
        },
        "stateExpired": {
          "zh": "已到期",
          "en": "Expired"
        },
        "stateActive": {
          "zh": "封禁中",
          "en": "Banned"
        },
        "matchedEntry": {
          "zh": "命中条目：{value}",
          "en": "Matched entry: {value}"
        },
        "permanent": {
          "zh": "永久封禁",
          "en": "Permanent ban"
        },
        "clearable": {
          "zh": "可清理",
          "en": "Clearable"
        },
        "remaining": {
          "zh": "剩余 {time}",
          "en": "{time} left"
        },
        "clear": {
          "zh": "清理",
          "en": "Clear"
        },
        "removeBan": {
          "zh": "移除封禁",
          "en": "Remove ban"
        }
      },
      "footer": {
        "syncNote": {
          "zh": "名单修改会同步到所有引用它的策略",
          "en": "List changes sync to every policy that references it"
        }
      },
      "geo": {
        "reserved": {
          "zh": "保留地址",
          "en": "Reserved"
        },
        "china": {
          "zh": "中国",
          "en": "China"
        }
      },
      "sideDefs": {
        "deny": {
          "zh": "黑名单",
          "en": "Blacklist"
        },
        "denyDesc": {
          "zh": "用于显式拒绝的 IP 名单",
          "en": "IP list for explicit denial"
        },
        "allow": {
          "zh": "白名单",
          "en": "Whitelist"
        },
        "allowDesc": {
          "zh": "用于允许访问的 IP 名单",
          "en": "IP list for allowing access"
        },
        "trust": {
          "zh": "信任列表",
          "en": "Trust list"
        },
        "trustDesc": {
          "zh": "用于信任策略的 IP 名单",
          "en": "IP list for trust policies"
        }
      },
      "verbs": {
        "block": {
          "zh": "拦截",
          "en": "Block"
        },
        "allow": {
          "zh": "放行",
          "en": "Allow"
        },
        "trust": {
          "zh": "信任",
          "en": "Trust"
        }
      },
      "inlineRemove": {
        "confirmText": {
          "zh": "将从策略「{name}」的内联名单移除 {ip}。是否继续？",
          "en": "Policy \"{name}\": this removes {ip} from its inline list. Continue?"
        },
        "confirmTitle": {
          "zh": "从内联名单移除",
          "en": "Remove from inline list"
        },
        "confirm": {
          "zh": "确认移除",
          "en": "Remove"
        },
        "policyLoadFailed": {
          "zh": "策略读取失败",
          "en": "Failed to load policy"
        },
        "removedToast": {
          "zh": "已从「{name}」移除 {ip}",
          "en": "Policy \"{name}\": removed {ip}"
        }
      },
      "autobanRemove": {
        "confirmText": {
          "zh": "将把 {ip} 从自动封禁名单移除，并清空该 IP 的自动封禁计数。其它黑名单和安全策略不受影响。是否继续？",
          "en": "{ip} will be removed from the auto-ban list and the IP's auto-ban counter cleared. Other blacklists and security policies are unaffected. Continue?"
        },
        "clearTitle": {
          "zh": "清理过期封禁",
          "en": "Clear expired ban"
        },
        "removeTitle": {
          "zh": "移除自动封禁",
          "en": "Remove auto ban"
        },
        "removedToast": {
          "zh": "已从自动封禁名单移除 {ip}",
          "en": "Removed {ip} from the auto-ban list"
        }
      }
    },
    "blockPages": {
      "page": {
        "title": {
          "zh": "拦截页面",
          "en": "Block pages"
        },
        "desc": {
          "zh": "管理各阶段拦截（IP 访问控制 / 限流 / WAF）返回给客户端的自定义页面",
          "en": "Manage the custom pages returned to clients when blocked at any stage (IP access control / rate limiting / WAF)"
        },
        "newPage": {
          "zh": "新建页面",
          "en": "New page"
        }
      },
      "alert": {
        "loadFailedStale": {
          "zh": "拦截页面加载失败：当前显示的是上次成功结果",
          "en": "Block pages failed to load — showing the last successful results"
        },
        "loadFailedEmpty": {
          "zh": "拦截页面加载失败：列表为空不代表没有页面",
          "en": "Block pages failed to load — an empty list doesn't mean there are no pages"
        },
        "retryNow": {
          "zh": "立即重试",
          "en": "Retry now"
        }
      },
      "table": {
        "empty": {
          "zh": "暂无拦截页面",
          "en": "No block pages"
        },
        "loadFailed": {
          "zh": "加载失败",
          "en": "Load failed"
        },
        "colName": {
          "zh": "页面名称",
          "en": "Name"
        },
        "builtin": {
          "zh": "内置",
          "en": "Built-in"
        },
        "contentType": {
          "zh": "内容类型",
          "en": "Content type"
        },
        "size": {
          "zh": "大小",
          "en": "Size"
        },
        "sizeTip": {
          "zh": "拦截响应体字节数——评估拦截面传输压力（出站流量 ≈ 每秒拦截次数 × 页面大小，64KB 上限）",
          "en": "Block response body size in bytes — gauge block-path traffic pressure (outbound ≈ blocks/sec × page size; 64 KB cap)"
        },
        "description": {
          "zh": "描述",
          "en": "Description"
        },
        "ruleRefs": {
          "zh": "规则引用",
          "en": "Rule refs"
        },
        "ruleRefsTip": {
          "zh": "引用本页的负载均衡规则数（启用策略绑定 ∪ 规则级阶段覆盖）",
          "en": "Load-balancer rules referencing this page (enabled policy bindings ∪ rule-level stage overrides)"
        },
        "updatedAt": {
          "zh": "更新时间",
          "en": "Updated"
        },
        "updatedBy": {
          "zh": "更新者",
          "en": "Updated by"
        },
        "actions": {
          "zh": "操作",
          "en": "Actions"
        }
      },
      "rowActions": {
        "preview": {
          "zh": "预览",
          "en": "Preview"
        },
        "view": {
          "zh": "查看",
          "en": "View"
        },
        "edit": {
          "zh": "编辑",
          "en": "Edit"
        },
        "delete": {
          "zh": "删除",
          "en": "Delete"
        }
      },
      "dialog": {
        "createTitle": {
          "zh": "新建拦截页面",
          "en": "New block page"
        },
        "viewTitle": {
          "zh": "查看拦截页面",
          "en": "View block page"
        },
        "editTitle": {
          "zh": "编辑拦截页面",
          "en": "Edit block page"
        },
        "subtitle": {
          "zh": "命中拦截规则时返回给客户端的响应页面，支持自定义内容类型",
          "en": "Response page returned to clients when an interception rule hits; content type is customizable"
        },
        "labelName": {
          "zh": "名称",
          "en": "Name"
        },
        "placeholderName": {
          "zh": "页面名称",
          "en": "Page name"
        },
        "placeholderDesc": {
          "zh": "页面描述",
          "en": "Page description"
        },
        "contentTypeTip": {
          "zh": "拦截响应的 Content-Type（均 UTF-8 编码）",
          "en": "Content-Type of the block response (all UTF-8)"
        },
        "labelContent": {
          "zh": "内容",
          "en": "Content"
        },
        "editorAria": {
          "zh": "拦截页面内容",
          "en": "Block page content"
        },
        "placeholderContent": {
          "zh": "响应内容（HTML 类型支持内联 CSS）",
          "en": "Response content (HTML supports inline CSS)"
        },
        "contentTipReadonly": {
          "zh": "内置页面内容只读，仅可查看",
          "en": "Built-in page content is read-only"
        },
        "contentTipEditable": {
          "zh": "拦截时返回给客户端的响应内容（HTML 类型支持内联 CSS）",
          "en": "Response content returned to clients when blocked (HTML supports inline CSS)"
        },
        "cancel": {
          "zh": "取消",
          "en": "Cancel"
        },
        "save": {
          "zh": "保存",
          "en": "Save"
        }
      },
      "preview": {
        "title": {
          "zh": "拦截页面预览",
          "en": "Block page preview"
        },
        "subtitle": {
          "zh": "在隔离沙箱中预览客户端接收的响应内容",
          "en": "Preview the response content the client receives in an isolated sandbox"
        },
        "effectTitle": {
          "zh": "页面效果",
          "en": "Rendered page"
        },
        "emptyContent": {
          "zh": "(空内容)",
          "en": "(no content)"
        }
      },
      "contentTypeOptions": {
        "html": {
          "zh": "HTML 页面（text/html）",
          "en": "HTML page (text/html)"
        },
        "plainText": {
          "zh": "纯文本（text/plain）",
          "en": "Plain text (text/plain)"
        }
      },
      "messages": {
        "nameRequired": {
          "zh": "请输入页面名称",
          "en": "Enter a page name"
        },
        "contentRequired": {
          "zh": "请输入页面内容",
          "en": "Enter page content"
        },
        "contentTooLarge": {
          "zh": "页面内容 {size} 超出 64KB 上限，请精简后保存",
          "en": "Page content ({size}) exceeds the 64 KB limit — trim it before saving"
        },
        "saved": {
          "zh": "保存成功",
          "en": "Saved"
        },
        "deleted": {
          "zh": "已删除",
          "en": "Deleted"
        }
      },
      "deleteConfirm": {
        "title": {
          "zh": "删除拦截页面",
          "en": "Delete block page"
        },
        "text": {
          "zh": "将删除拦截页面「{name}」。删除后无法恢复，引用它的策略将失去该自定义页面。",
          "en": "Block page “{name}” will be deleted. This can't be undone; policies referencing it will lose this custom page."
        },
        "confirm": {
          "zh": "确认删除",
          "en": "Delete"
        }
      }
    },
    "events": {
      "title": {
        "zh": "事件日志",
        "en": "Event log"
      },
      "desc": {
        "zh": "查看安全拦截与检测事件记录",
        "en": "View security block and detection event records"
      },
      "refresh": {
        "zh": "刷新",
        "en": "Refresh"
      },
      "statusLoadFail": {
        "zh": "自动封禁状态加载失败：控制项已禁用（不影响事件日志主功能），请稍后刷新重试。",
        "en": "Failed to load auto-ban status: controls are disabled (the event log is unaffected). Please refresh and try again later."
      },
      "autobanTitle": {
        "zh": "自动封禁",
        "en": "Auto-ban"
      },
      "masterOnlyBadge": {
        "zh": "仅主节点调度",
        "en": "Scheduled on primary node only"
      },
      "statScope": {
        "zh": "口径",
        "en": "Scope"
      },
      "statWindow": {
        "zh": "窗口",
        "en": "Window"
      },
      "statThreshold": {
        "zh": "阈值",
        "en": "Threshold"
      },
      "statDuration": {
        "zh": "时长",
        "en": "Duration"
      },
      "statTodayBanned": {
        "zh": "今日封禁",
        "en": "Banned today"
      },
      "statListEntries": {
        "zh": "名单",
        "en": "List entries"
      },
      "suffixMinutes": {
        "zh": " 分钟",
        "en": " min"
      },
      "suffixTimes": {
        "zh": " 次",
        "en": " hits"
      },
      "suffixEntries": {
        "zh": " 条",
        "en": " entries"
      },
      "actionDisable": {
        "zh": "禁用",
        "en": "Disable"
      },
      "actionEdit": {
        "zh": "编辑",
        "en": "Edit"
      },
      "actionEnable": {
        "zh": "启用",
        "en": "Enable"
      },
      "ineffectiveNotice": {
        "zh": "「自动封禁名单」尚未生效——名单为空，或尚未被启用中的 IP 访问控制（deny）策略引用；请到「安全规则 → IP 地址列表」将该名单引用到 IP 访问控制（deny）策略",
        "en": "The \"Auto-ban list\" is not active yet — the list is empty or not referenced by an enabled IP access control (deny) policy. Go to \"Security Rules → IP address lists\" and reference this list in an IP access control (deny) policy."
      },
      "feedDegradedPrefix": {
        "zh": "数据源降级：",
        "en": "Data source degraded: "
      },
      "feedDegradedDefault": {
        "zh": "安全事件补采/日志轮转已暂停，实时 IPC 入库仍在运行（自动封禁计数仍会随实时事件增长）",
        "en": "Security event backfill/log rotation is paused; real-time IPC ingestion is still running (auto-ban counters still grow with live events)."
      },
      "suggestionSummary": {
        "zh": "观察模式：以下 IP 在 {minutes} 分钟窗口内达到 {times} 次阈值（仅记录建议，不写入名单）",
        "en": "Observation mode: the following IPs reached the threshold of {times} hits within a {minutes}-minute window (suggestions only, not added to the list)."
      },
      "colHitCount": {
        "zh": "命中次数",
        "en": "Hits"
      },
      "colThresholdRatio": {
        "zh": "阈值倍数",
        "en": "Threshold ratio"
      },
      "colWindowSpan": {
        "zh": "窗口内首末",
        "en": "First/last hit in window"
      },
      "colSuggestedDuration": {
        "zh": "建议时长",
        "en": "Suggested duration"
      },
      "suggestionsLimit": {
        "zh": "仅展示命中次数最多的前 50 条，完整建议见任务日志",
        "en": "Showing only the top 50 by hit count; see the task log for the full suggestions."
      },
      "blockedReasonMasterOnly": {
        "zh": "仅主节点可修改自动封禁配置",
        "en": "Only the primary node can modify the auto-ban configuration"
      },
      "blockedReasonLoading": {
        "zh": "自动封禁状态加载中，暂不可配置",
        "en": "Auto-ban status is loading; configuration is unavailable"
      },
      "blockedReasonLoadFail": {
        "zh": "自动封禁状态加载失败，请刷新后重试",
        "en": "Failed to load auto-ban status. Please refresh and try again"
      },
      "filterAction": {
        "zh": "动作",
        "en": "Action"
      },
      "actionBlocked": {
        "zh": "拦截",
        "en": "Blocked"
      },
      "actionLogged": {
        "zh": "检测",
        "en": "Detected"
      },
      "filterType": {
        "zh": "类型",
        "en": "Type"
      },
      "rulePlaceholder": {
        "zh": "负载规则",
        "en": "Load rule"
      },
      "triggeredPlaceholder": {
        "zh": "触发阶段 / 规则 ID",
        "en": "Stage / Rule ID"
      },
      "selectAll": {
        "zh": "全选",
        "en": "Select all"
      },
      "crawlerBot": {
        "zh": "爬虫Bot",
        "en": "Crawler bot"
      },
      "crawlerBotHint": {
        "zh": "已验证爬虫放行/伪装（id 810000-899999）",
        "en": "Verified crawler allow/spoof (id 810000-899999)"
      },
      "geoBlock": {
        "zh": "地域拦截",
        "en": "Geo blocking"
      },
      "geoBlockHint": {
        "zh": "GeoIP 地域拦截（id 8/800xxx）",
        "en": "GeoIP geo blocking (id 8/800xxx)"
      },
      "ipAcl": {
        "zh": "IP 访问控制",
        "en": "IP access control"
      },
      "ipAclHint": {
        "zh": "IP ACL 黑白名单与自维护黑名单（id 2/4/7）",
        "en": "IP ACL allow/deny lists and self-maintained deny list (id 2/4/7)"
      },
      "trustList": {
        "zh": "信任名单",
        "en": "Trust list"
      },
      "trustListHint": {
        "zh": "信任名单/保留检测（id 3/12）",
        "en": "Trust list / detection retained (id 3/12)"
      },
      "threatIntel": {
        "zh": "威胁情报库",
        "en": "Threat intelligence"
      },
      "threatIntelHint": {
        "zh": "威胁情报库命中（id 14）",
        "en": "Threat intelligence hit (id 14)"
      },
      "bodyAnomaly": {
        "zh": "请求体异常",
        "en": "Request body anomaly"
      },
      "bodyAnomalyHint": {
        "zh": "请求体解析失败（id 11）",
        "en": "Request body parse failure (id 11)"
      },
      "wafCrsHint": {
        "zh": "OWASP CRS 规则全集（9xxxxx）",
        "en": "Full OWASP CRS rule set (9xxxxx)"
      },
      "wafCustom": {
        "zh": "WAF·自定义",
        "en": "WAF · Custom"
      },
      "wafCustomHint": {
        "zh": "自定义规则库（含 AND 链式规则、OR 条件分支与旧版合成规则）",
        "en": "Custom rule library (including AND chains, OR branches, and legacy composite rules)"
      },
      "policyPlaceholder": {
        "zh": "策略",
        "en": "Policy"
      },
      "ipPlaceholder": {
        "zh": "IP 地址",
        "en": "IP address"
      },
      "apply": {
        "zh": "筛选",
        "en": "Filter"
      },
      "reset": {
        "zh": "重置",
        "en": "Reset"
      },
      "loadErrorStale": {
        "zh": "安全事件加载失败：当前显示的是上次成功结果（与筛选/分页条件不符）",
        "en": "Failed to load security events: showing the last successful result (it does not match the current filters or page)"
      },
      "loadErrorEmpty": {
        "zh": "安全事件加载失败：表格为空不代表没有事件",
        "en": "Failed to load security events: an empty table does not mean there were no events"
      },
      "retryNow": {
        "zh": "立即重试",
        "en": "Retry now"
      },
      "empty": {
        "zh": "暂无安全事件",
        "en": "No security events"
      },
      "colTime": {
        "zh": "时间",
        "en": "Time"
      },
      "colAction": {
        "zh": "动作",
        "en": "Action"
      },
      "colRule": {
        "zh": "规则",
        "en": "Rule"
      },
      "colStage": {
        "zh": "触发阶段",
        "en": "Stage"
      },
      "colTriggerType": {
        "zh": "触发类型",
        "en": "Trigger type"
      },
      "colPolicy": {
        "zh": "策略",
        "en": "Policy"
      },
      "colClientIp": {
        "zh": "客户端 IP",
        "en": "Client IP"
      },
      "colMethod": {
        "zh": "方法",
        "en": "Method"
      },
      "colScore": {
        "zh": "评分",
        "en": "Score"
      },
      "colOps": {
        "zh": "操作",
        "en": "Actions"
      },
      "detail": {
        "zh": "详情",
        "en": "Details"
      },
      "rangeSeparator": {
        "zh": "至",
        "en": "to"
      },
      "startTime": {
        "zh": "开始时间",
        "en": "Start time"
      },
      "endTime": {
        "zh": "结束时间",
        "en": "End time"
      },
      "dialogTitle": {
        "zh": "自动封禁配置",
        "en": "Auto-ban configuration"
      },
      "dialogSubtitle": {
        "zh": "WAF 拦截（CRS 规则与自定义规则命中，已验证爬虫豁免除外）固定窗口计数达到阈值即写入「自动封禁名单」（调度开启时到期自动解封；IP 访问控制、地域拦截与威胁情报事件不参与计数）",
        "en": "WAF blocks (CRS and custom rule hits, excluding verified crawler exemptions) are counted per fixed window and written to the \"Auto-ban list\" once the threshold is reached (expiry unban applies when scheduling is enabled; IP access control, geo blocking, and threat intelligence events are not counted)."
      },
      "dryRunLabel": {
        "zh": "观察模式",
        "en": "Observation mode"
      },
      "dryRunHint": {
        "zh": "开启时仅记录达阈值建议、不写入名单（推荐先观察校准阈值）",
        "en": "When enabled, only records suggestions once the threshold is reached without adding IPs to the list (recommended for calibrating the threshold first)"
      },
      "scopeLabel": {
        "zh": "统计口径",
        "en": "Counting scope"
      },
      "windowLabel": {
        "zh": "统计窗口",
        "en": "Counting window"
      },
      "windowHint": {
        "zh": "分钟（同一 IP 窗口内累计计数，跨窗口自动重置）",
        "en": "minutes (counts accumulate per IP within a window and reset across windows)"
      },
      "thresholdLabel": {
        "zh": "封禁阈值",
        "en": "Ban threshold"
      },
      "thresholdHint": {
        "zh": "窗口内命中次数",
        "en": "Hits within the window"
      },
      "durationLabel": {
        "zh": "封禁时长",
        "en": "Ban duration"
      },
      "durationHint": {
        "zh": "到期自动解封（从名单移除）",
        "en": "Automatically unbanned on expiry (removed from the list)"
      },
      "counterResetNotice": {
        "zh": "修改统计窗口或口径会立即重置计数器（旧计数与新口径不可混算）",
        "en": "Changing the counting window or scope immediately resets the counters (old counts cannot be mixed with the new criteria)"
      },
      "cancel": {
        "zh": "取消",
        "en": "Cancel"
      },
      "save": {
        "zh": "保存",
        "en": "Save"
      },
      "saveConfigTitle": {
        "zh": "保存配置",
        "en": "Save configuration"
      },
      "saveConfirm": {
        "zh": "确认保存自动封禁配置？新配置将在下一轮调度生效。",
        "en": "Save the auto-ban configuration? The new configuration takes effect on the next scheduling cycle."
      },
      "confirmSave": {
        "zh": "确认保存",
        "en": "Confirm save"
      },
      "configUpdated": {
        "zh": "自动封禁配置已更新",
        "en": "Auto-ban configuration updated"
      },
      "enableConfirmTitle": {
        "zh": "启用自动封禁",
        "en": "Enable auto-ban"
      },
      "confirmEnable": {
        "zh": "确认启用",
        "en": "Confirm enable"
      },
      "enableHeading": {
        "zh": "确认启用自动封禁？",
        "en": "Enable auto-ban?"
      },
      "enableSub": {
        "zh": "达到阈值的 IP 将被自动加入封禁名单，到期自动解封",
        "en": "IPs that reach the threshold are automatically added to the auto-ban list and unbanned on expiry"
      },
      "enableNote1": {
        "zh": "新封禁约 1 分钟内生效，重载时长连接可能被重置",
        "en": "New bans take effect within about 1 minute; long-lived connections may be reset during reload"
      },
      "enableNote2": {
        "zh": "持续攻击时每分钟至多一次重载，有少量性能开销",
        "en": "Under sustained attacks, at most one reload occurs per minute, with a small performance cost"
      },
      "enableNote3": {
        "zh": "建议先以观察模式运行，确认建议准确后再正式封禁",
        "en": "Run in observation mode first and confirm the suggestions are accurate before enforcing bans"
      },
      "enableHowtoLabel": {
        "zh": "生效方式",
        "en": "How it takes effect"
      },
      "enableHowtoText": {
        "zh": "在 IP 访问控制（黑名单）策略中引用「自动封禁名单」地址列表",
        "en": "Reference the \"Auto-ban list\" address list in an IP access control (deny) policy"
      },
      "disableConfirmTitle": {
        "zh": "禁用自动封禁",
        "en": "Disable auto-ban"
      },
      "disableConfirm": {
        "zh": "确认禁用自动封禁？任务调度将停止，禁用时会立即清除已到期的封禁条目并即时生效；未到期条目保留至到期自动失效。",
        "en": "Disable auto-ban? Scheduling stops; expired ban entries are cleared immediately and take effect at once, while unexpired entries remain until they expire."
      },
      "confirmDisable": {
        "zh": "确认禁用",
        "en": "Confirm disable"
      },
      "disabledNotice": {
        "zh": "自动封禁已禁用（调度已停止）",
        "en": "Auto-ban disabled (scheduling stopped)"
      },
      "thresholdRange": {
        "zh": "阈值须在 1-10000 之间",
        "en": "Threshold must be between 1 and 10000"
      },
      "windowRange": {
        "zh": "统计窗口须在 1-60 分钟之间",
        "en": "Counting window must be between 1 and 60 minutes"
      },
      "timeRangeInvalid": {
        "zh": "开始时间不能晚于结束时间",
        "en": "Start time cannot be later than end time"
      },
      "ctxTitle": {
        "zh": "请求详情",
        "en": "Request details"
      },
      "ctxUnknownPolicy": {
        "zh": "未知策略",
        "en": "Unknown policy"
      },
      "ctxSummary": {
        "zh": "请求摘要",
        "en": "Request summary"
      },
      "ctxLocation": {
        "zh": "归属地",
        "en": "Location"
      },
      "ctxTriggeredRule": {
        "zh": "触发规则",
        "en": "Triggered rule"
      },
      "ctxPolicy": {
        "zh": "所属策略",
        "en": "Policy"
      },
      "ctxDuration": {
        "zh": "处理时长",
        "en": "Processing time"
      },
      "ctxPrecheckSuffix": {
        "zh": "（预检耗时，含事件记录开销）",
        "en": " (precheck time, including event logging overhead)"
      },
      "ctxDurationBreakdown": {
        "zh": "耗时分解",
        "en": "Time breakdown"
      },
      "ctxDurationBreakdownValue": {
        "zh": "预检 {precheck} + WAF 段 {waf}",
        "en": "Precheck {precheck} + WAF {waf}"
      },
      "tcpPlaceholder": {
        "zh": "—（TCP 连接）",
        "en": "— (TCP connection)"
      },
      "ctxHeadersTitle": {
        "zh": "请求头",
        "en": "Request headers"
      },
      "ctxHeadersParseFail": {
        "zh": "请求头记录解析失败，以下为原始内容",
        "en": "Failed to parse the recorded headers; showing the raw content below"
      },
      "ctxHeadersDropped": {
        "zh": "已隐藏 {count} 个头（请求头超出 64KB 采集上限）",
        "en": "{count} headers hidden (headers exceeded the 64 KB capture limit)"
      },
      "ctxHeadersListDropped": {
        "zh": "已隐藏 {count} 个头（请求头超出列表 16KB 展示上限）",
        "en": "{count} headers hidden (headers exceeded the 16 KB display limit)"
      },
      "ctxHeaderName": {
        "zh": "名称",
        "en": "Name"
      },
      "ctxHeaderValue": {
        "zh": "值",
        "en": "Value"
      },
      "ctxRevealHide": {
        "zh": "点击隐藏",
        "en": "Click to hide"
      },
      "ctxRevealShow": {
        "zh": "点击显示",
        "en": "Click to show"
      },
      "ctxHeadersEmpty": {
        "zh": "暂无请求头记录",
        "en": "No recorded request headers"
      },
      "ctxBodyTitle": {
        "zh": "请求体",
        "en": "Request body"
      },
      "ctxBodyTruncated": {
        "zh": "请求体已截断，仅显示保留的前段内容",
        "en": "The request body was truncated; only the retained leading portion is shown"
      },
      "ctxBodyBinary": {
        "zh": "请求体为二进制内容，已按 Base64 解码展示，可能包含不可读字符",
        "en": "The request body is binary; it is Base64-decoded for display and may contain unreadable characters"
      },
      "ctxBodyDecodeFail": {
        "zh": "Base64 解码失败，以下为原始内容",
        "en": "Base64 decoding failed; showing the raw content below"
      },
      "close": {
        "zh": "关闭",
        "en": "Close"
      },
      "duration10m": {
        "zh": "10 分钟",
        "en": "10 minutes"
      },
      "duration30m": {
        "zh": "30 分钟",
        "en": "30 minutes"
      },
      "duration1h": {
        "zh": "1 小时",
        "en": "1 hour"
      },
      "duration6h": {
        "zh": "6 小时",
        "en": "6 hours"
      },
      "duration12h": {
        "zh": "12 小时",
        "en": "12 hours"
      },
      "duration24h": {
        "zh": "24 小时",
        "en": "24 hours"
      },
      "durationPermanent": {
        "zh": "永久",
        "en": "Permanent"
      },
      "scopeAll": {
        "zh": "全部事件",
        "en": "All events"
      },
      "scopeBlockedOnly": {
        "zh": "仅拦截",
        "en": "Blocked only"
      },
      "scopeLoggedOnly": {
        "zh": "仅检测",
        "en": "Detected only"
      },
      "stageLegacyGeo": {
        "zh": "地域拦截（旧 id）",
        "en": "Geo blocking (legacy id)"
      }
    },
    "overview": {
      "page": {
        "title": {
          "zh": "安全总览",
          "en": "Security overview"
        },
        "desc": {
          "zh": "安全防护统计概览",
          "en": "Protection statistics at a glance"
        },
        "threatScreen": {
          "zh": "威胁大屏",
          "en": "Threat screen"
        },
        "loadFailed": {
          "zh": "安全总览数据加载失败",
          "en": "Security overview failed to load"
        },
        "retryNow": {
          "zh": "立即重试",
          "en": "Retry now"
        }
      },
      "status": {
        "cardTitle": {
          "zh": "防护运行状态",
          "en": "Protection status"
        },
        "blocked": {
          "zh": "拦截",
          "en": "Blocked"
        },
        "yesterday": {
          "zh": "昨日",
          "en": "Yesterday"
        },
        "detected": {
          "zh": "检测",
          "en": "Detected"
        },
        "normal": {
          "zh": "正常请求",
          "en": "Normal requests"
        },
        "normalTip": {
          "zh": "成功代理的流量：HTTP=总请求−拦截−检测放行；TCP=全部放行连接（含信任名单 IP 的保留检测流量，计入正常列）",
          "en": "Proxied traffic counted as normal: HTTP = total − blocked − detected-and-allowed; TCP = all allowed connections (incl. retained detection traffic for trusted-list IPs, counted under Normal)"
        },
        "tipReserved": {
          "zh": "总量含私网/保留地址事件（内网扫描、文档测试段等也会计入，与大屏排除口径不同）",
          "en": "Total includes private/reserved-address events (internal scans, documentation ranges etc. also count — unlike the threat screen's exclusion scope)"
        },
        "tipRollup": {
          "zh": "与大屏同口径（分钟汇总）：不含私网/保留地址事件，含当前分钟截至最近一次汇总的事件（滞后约 1 分钟）",
          "en": "Same scope as the threat screen (per-minute rollup): excludes private/reserved-address events; includes current-minute events up to the latest rollup (~1 min lag)"
        },
        "tipCrawlerNote": {
          "zh": "；已验证爬虫放行流量计入检测放行（logged）、不计入正常请求列",
          "en": "; verified crawler traffic allowed through counts as detected (logged), not under Normal"
        }
      },
      "libStatus": {
        "crs": {
          "zh": "CRS 规则集",
          "en": "CRS rule set"
        },
        "ipGeo": {
          "zh": "IP 地理库",
          "en": "IP geo library"
        },
        "threatIntel": {
          "zh": "威胁情报库",
          "en": "Threat intel library"
        },
        "crawlerDb": {
          "zh": "爬虫地址库",
          "en": "Crawler address library"
        },
        "notInstalled": {
          "zh": "未安装",
          "en": "Not installed"
        },
        "bundled": {
          "zh": "内置版本",
          "en": "Bundled"
        },
        "loadFailed": {
          "zh": "加载失败",
          "en": "Load failed"
        },
        "notUpdated": {
          "zh": "未更新",
          "en": "Not updated"
        }
      },
      "trend": {
        "title": {
          "zh": "7 天拦截趋势",
          "en": "7-day block trend"
        },
        "empty": {
          "zh": "暂无趋势数据",
          "en": "No trend data"
        },
        "attackTitle": {
          "zh": "攻击类型分布（近 7 天）",
          "en": "Attack types (last 7 days)"
        },
        "byStage": {
          "zh": "按阶段展示",
          "en": "By stage"
        },
        "emptyAttack": {
          "zh": "暂无攻击数据",
          "en": "No attack data"
        }
      },
      "events": {
        "title": {
          "zh": "最近拦截事件",
          "en": "Recent blocked events"
        },
        "viewAll": {
          "zh": "查看全部",
          "en": "View all"
        },
        "loadFailed": {
          "zh": "最近拦截事件加载失败",
          "en": "Recent blocked events failed to load"
        },
        "empty": {
          "zh": "暂无拦截事件",
          "en": "No blocked events"
        },
        "colTime": {
          "zh": "时间",
          "en": "Time"
        },
        "colSourceIp": {
          "zh": "来源 IP",
          "en": "Source IP"
        },
        "colProtocol": {
          "zh": "协议",
          "en": "Protocol"
        },
        "colRule": {
          "zh": "规则",
          "en": "Rule"
        },
        "colPolicy": {
          "zh": "策略",
          "en": "Policy"
        }
      },
      "rateLimit": {
        "title": {
          "zh": "限流拦截",
          "en": "Rate-limit blocks"
        },
        "tip": {
          "zh": "按 429 响应计（含上游自返 429）；自最近一次配置重载以来累计",
          "en": "Counted by 429 responses (incl. upstream-returned 429s); accumulated since the last config reload"
        },
        "tag": {
          "zh": "429 计数 · 重载后累计",
          "en": "429 count · since last reload"
        },
        "loadFailed": {
          "zh": "限流拦截数据加载失败",
          "en": "Rate-limit block data failed to load"
        },
        "total": {
          "zh": "累计拦截",
          "en": "Total blocked"
        },
        "colDomain": {
          "zh": "域名",
          "en": "Domain"
        },
        "colCount": {
          "zh": "拦截次数",
          "en": "Blocks"
        },
        "empty": {
          "zh": "暂无限流拦截",
          "en": "No rate-limit blocks"
        }
      },
      "topIps": {
        "title": {
          "zh": "Top 10 源 IP（近 7 天）",
          "en": "Top 10 source IPs (last 7 days)"
        },
        "empty": {
          "zh": "暂无数据",
          "en": "No data"
        },
        "colIp": {
          "zh": "IP 地址",
          "en": "IP address"
        },
        "colRecent10m": {
          "zh": "近10分钟",
          "en": "Last 10 min"
        },
        "colRecent1h": {
          "zh": "近1小时",
          "en": "Last hour"
        },
        "colRecent24h": {
          "zh": "近24小时",
          "en": "Last 24 hours"
        },
        "unitTimes": {
          "zh": "次",
          "en": "times"
        },
        "colAttackType": {
          "zh": "攻击类型",
          "en": "Attack type"
        },
        "colLastAttack": {
          "zh": "最后攻击",
          "en": "Last attack"
        }
      }
    },
    "threat": {
      "attackMapAria": {
        "zh": "攻击态势",
        "en": "Attack posture"
      },
      "legendAria": {
        "zh": "图例",
        "en": "Legend"
      },
      "legendNormalRequests": {
        "zh": "正常请求",
        "en": "Normal requests"
      },
      "legendAttackFlows": {
        "zh": "攻击光流",
        "en": "Attack flows"
      },
      "legendCountryHits": {
        "zh": "国家命中（对数）",
        "en": "Country hits (log scale)"
      },
      "backToWorld": {
        "zh": "返回世界",
        "en": "Back to world"
      },
      "hintControls": {
        "zh": "拖动{mode} · 点击国家下钻 · 点击空白返回",
        "en": "Drag to {mode} · click a country to drill down · click blank space to go back"
      },
      "hintRotate": {
        "zh": "旋转",
        "en": "rotate"
      },
      "hintPan": {
        "zh": "平移",
        "en": "pan"
      },
      "emptyNoEvents": {
        "zh": "近 {window}无安全事件",
        "en": "No security events in {window}"
      },
      "statsLoadFailed": {
        "zh": "大屏数据加载失败，正在重试…",
        "en": "Screen data failed to load; retrying..."
      },
      "backfillNotice": {
        "zh": "历史统计回填尚未完成，当前窗口总量可能少计；回填会自动继续补齐，无需处理",
        "en": "History backfill is not finished yet; this window's total may be undercounted. Backfill resumes automatically — no action needed"
      },
      "gotIt": {
        "zh": "知道了",
        "en": "Got it"
      },
      "rollupStaleNotice": {
        "zh": "统计汇总更新延迟，当前窗口数据可能不是最新；汇总恢复后自动显示最新数据，无需处理",
        "en": "Summary updates are delayed; this window's data may not be current. Latest data shows automatically once summaries recover — no action needed"
      },
      "engineLoadFailed": {
        "zh": "大屏引擎加载失败",
        "en": "Screen engine failed to load"
      },
      "retry": {
        "zh": "重试",
        "en": "Retry"
      },
      "trafficUnavailable": {
        "zh": "流量采集不可用（Caddy admin 不可达），曲线已保留上一帧",
        "en": "Traffic collection unavailable (Caddy admin unreachable); curve keeps the last frame"
      },
      "flowLoadFailed": {
        "zh": "光流数据加载失败，正在重试…",
        "en": "Flow data failed to load; retrying..."
      },
      "flowGapNotice": {
        "zh": "事件流有空洞：{count} 条事件因缓冲溢出未送达，弹道不连续属正常现象",
        "en": "Event stream has gaps: {count} events were not delivered due to buffer overflow; broken trajectories are expected"
      },
      "collectorRenewFailed": {
        "zh": "大屏流量采集续租失败（Caddy 侧逐请求计数已中断），正在重试…",
        "en": "Screen traffic collection lease renewal failed (per-request counting on the Caddy side interrupted); retrying..."
      },
      "configLoadFailedNotice": {
        "zh": "大屏配置读取失败，暂用默认视图与未设置坐标",
        "en": "Screen config failed to load; using default view with no site coordinates"
      },
      "siteNotConfigured": {
        "zh": "未配置站点坐标，本站信标与攻击弹道已隐藏",
        "en": "Site coordinates not configured; site beacon and attack trajectories are hidden"
      },
      "liveThreatEvents": {
        "zh": "实时威胁事件",
        "en": "Live threat events"
      },
      "newAttackAlerts": {
        "zh": "新攻击告警",
        "en": "New attack alerts"
      },
      "severityFilterAria": {
        "zh": "按危险等级筛选",
        "en": "Filter by severity"
      },
      "unknown": {
        "zh": "未知",
        "en": "Unknown"
      },
      "feedLoadFailed": {
        "zh": "事件流加载失败，正在重试…",
        "en": "Event feed failed to load; retrying..."
      },
      "noEvents": {
        "zh": "暂无事件",
        "en": "No events yet"
      },
      "severityAll": {
        "zh": "全部",
        "en": "All"
      },
      "severityHigh": {
        "zh": "高危",
        "en": "High"
      },
      "severityMid": {
        "zh": "中危",
        "en": "Medium"
      },
      "severityLow": {
        "zh": "低危",
        "en": "Low"
      },
      "screenTitle": {
        "zh": "安全威胁大屏",
        "en": "Security threat screen"
      },
      "subtitleRealtime": {
        "zh": "近 {window}安全态势实时监控",
        "en": "Real-time security posture · last {window}"
      },
      "coreMetricsAria": {
        "zh": "核心指标",
        "en": "Core metrics"
      },
      "kpiWindowEvents": {
        "zh": "{window}安全事件 · 拦截 {blocked} / 检测 {detected}",
        "en": "{window} security events · blocked {blocked} / detected {detected}"
      },
      "kpiBlockRate": {
        "zh": "拦截率 · 拦截 / 全部安全事件",
        "en": "Block rate · blocked / all security events"
      },
      "kpiBlocksPerMin": {
        "zh": "拦截/分钟 · 近 5 分钟",
        "en": "Blocks per minute · last 5 minutes"
      },
      "kpiActiveIps": {
        "zh": "活跃攻击 IP · 近 10 分钟",
        "en": "Active attack IPs · last 10 minutes"
      },
      "timeWindowAria": {
        "zh": "时间窗口",
        "en": "Time window"
      },
      "resetView": {
        "zh": "复位视角",
        "en": "Reset view"
      },
      "resumeTitle": {
        "zh": "继续（恢复轮询与服务端流量采集）",
        "en": "Resume (restores polling and server-side traffic collection)"
      },
      "pauseTitle": {
        "zh": "暂停（同时停止服务端流量采集）",
        "en": "Pause (also stops server-side traffic collection)"
      },
      "resumeBtn": {
        "zh": "继续",
        "en": "Resume"
      },
      "pauseBtn": {
        "zh": "暂停",
        "en": "Pause"
      },
      "exitScreenTitle": {
        "zh": "退出大屏",
        "en": "Exit threat screen"
      },
      "exitBtn": {
        "zh": "退出",
        "en": "Exit"
      },
      "postureStats": {
        "zh": "安全态势统计",
        "en": "Security posture stats"
      },
      "windowOverview": {
        "zh": "窗口概览",
        "en": "Window overview"
      },
      "switching": {
        "zh": "切换中…",
        "en": "Switching..."
      },
      "totalEvents": {
        "zh": "事件总量",
        "en": "Total events"
      },
      "blockedDetected": {
        "zh": "拦截 / 检测",
        "en": "Blocked / detected"
      },
      "peakHits": {
        "zh": "{n} 次",
        "en": "{n} hits"
      },
      "eventsUnit": {
        "zh": "事件",
        "en": "events"
      },
      "familyComposition": {
        "zh": "事件族构成",
        "en": "Event family composition"
      },
      "attackTypeShareAria": {
        "zh": "攻击类型占比：共 {total} 次",
        "en": "Attack type share: {total} hits total"
      },
      "others": {
        "zh": "其余",
        "en": "Others"
      },
      "geoipCountriesTip": {
        "zh": "仅统计窗口内具备 GeoIP 归属地的事件来源",
        "en": "Only counts event sources with GeoIP location in the window"
      },
      "topCountriesTitle": {
        "zh": "有归属地国家 TOP3",
        "en": "Top 3 countries with location"
      },
      "noGeoData": {
        "zh": "暂无归属地数据",
        "en": "No location data"
      },
      "topTargetsRules": {
        "zh": "TOP 目标 / 规则",
        "en": "Top targets / rules"
      },
      "topSumTip": {
        "zh": "当前维度前 3 条命中合计",
        "en": "Combined hits of top 3 in the current dimension"
      },
      "topDimensionAria": {
        "zh": "TOP 排名维度",
        "en": "Top rank dimension"
      },
      "tabTargets": {
        "zh": "被攻击目标",
        "en": "Attacked targets"
      },
      "tabRules": {
        "zh": "命中规则",
        "en": "Matched rules"
      },
      "noTargetData": {
        "zh": "暂无目标数据",
        "en": "No target data"
      },
      "noData": {
        "zh": "暂无数据",
        "en": "No data"
      },
      "ratelimitTip": {
        "zh": "自最近一次 Caddy 配置重载/进程启动以来累计；含上游自返 429；不受窗口切换影响",
        "en": "Cumulative since the last Caddy config reload / process start; includes upstream self-returned 429s; unaffected by window switching"
      },
      "ratelimitTotal": {
        "zh": "限流累计 · 自重载",
        "en": "Rate-limit total · since reload"
      },
      "windowIndependent": {
        "zh": "不受窗口影响",
        "en": "Not affected by window"
      },
      "trendTitle": {
        "zh": "{window}事件趋势",
        "en": "{window} event trend"
      },
      "totalLabel": {
        "zh": "合计",
        "en": "Total"
      },
      "histTooltip": {
        "zh": "{label} — {count} 次",
        "en": "{label} — {count} hits"
      },
      "trafficTitle": {
        "zh": "请求流量",
        "en": "Request traffic"
      },
      "trafficTip": {
        "zh": "仅统计经过 GeoIP 处理器规则的请求；正常桶含上游透传，不等于 2xx",
        "en": "Only requests through GeoIP processor rules are counted; the normal bucket includes upstream pass-through and is not 2xx"
      },
      "trafficMeta": {
        "zh": "正常 {normal}/s · 攻击 {attack}/s · 累计 正常 {normalTotal} / 攻击 {attackTotal}",
        "en": "Normal {normal}/s · attack {attack}/s · total normal {normalTotal} / attack {attackTotal}"
      },
      "normalSwatch": {
        "zh": "正常",
        "en": "Normal"
      },
      "attackSwatch": {
        "zh": "攻击",
        "en": "Attack"
      },
      "tcpDisconnected": {
        "zh": "TCP 断连",
        "en": "TCP disconnect"
      },
      "tcpTip": {
        "zh": "TCP 拒绝连接=断连（无 HTTP 拦截页），计入攻击通道；放行连接并入正常通道",
        "en": "TCP connection refused = disconnect (no HTTP block page); counted in the attack channel, allowed connections join the normal channel"
      },
      "ninetySecondsAgo": {
        "zh": "90s 前",
        "en": "90s ago"
      },
      "nowLabel": {
        "zh": "现在",
        "en": "Now"
      },
      "sampledSuffix": {
        "zh": "· 抽样估算",
        "en": "· sampled estimate"
      },
      "leaseFrozenSuffix": {
        "zh": "· 采集租约未生效，累计已冻结",
        "en": "· lease inactive, totals frozen"
      },
      "staleFrameLabel": {
        "zh": "上次结果 · {window}",
        "en": "Last result · {window}"
      },
      "ruleIdLabel": {
        "zh": "规则 #{id}",
        "en": "Rule #{id}"
      },
      "weekdaySun": {
        "zh": "日",
        "en": "Sun"
      },
      "weekdayMon": {
        "zh": "一",
        "en": "Mon"
      },
      "weekdayTue": {
        "zh": "二",
        "en": "Tue"
      },
      "weekdayWed": {
        "zh": "三",
        "en": "Wed"
      },
      "weekdayThu": {
        "zh": "四",
        "en": "Thu"
      },
      "weekdayFri": {
        "zh": "五",
        "en": "Fri"
      },
      "weekdaySat": {
        "zh": "六",
        "en": "Sat"
      },
      "clockDateFormat": {
        "zh": "{date} 星期{day}",
        "en": "{date} {day}"
      },
      "provinceLoadFailedMsg": {
        "zh": "省界数据加载失败，本次下钻未展开；可再次点击国家重试",
        "en": "Province boundaries failed to load; drill-down not expanded — click the country again to retry"
      }
    },
    "policies": {
      "action": {
        "bindRules": {
          "zh": "绑定规则",
          "en": "Bind Rules"
        },
        "edit": {
          "zh": "编辑",
          "en": "Edit"
        },
        "migrate": {
          "zh": "更新迁移",
          "en": "Migrate"
        },
        "view": {
          "zh": "查看",
          "en": "View"
        }
      },
      "bind": {
        "failedTitle": {
          "zh": "规则绑定数据加载失败，请先重新加载",
          "en": "Failed to load rule binding data; reload first"
        },
        "loadingTitle": {
          "zh": "规则绑定数据加载中",
          "en": "Rule binding data loading"
        },
        "appliesTo": {
          "zh": "将应用于 {n} 条已关联规则",
          "en": "Will apply to {n} bound rule(s)"
        },
        "none": {
          "zh": "尚未关联规则",
          "en": "No rules bound yet"
        },
        "boundLabel": {
          "zh": "已关联",
          "en": "Bound Rules"
        },
        "orderNote": {
          "zh": "策略按绑定顺序依次触发，先触发的先拦截；顺序调整仅改变触发先后，不影响拦截页归属",
          "en": "Policies trigger in binding order — earlier ones block first; reordering only changes trigger sequence, not block-page attribution"
        },
        "orderPending": {
          "zh": "顺序待保存",
          "en": "Order pending save"
        },
        "perfWarn": {
          "zh": "已关联规则存在绑定 3 条以上策略：处理链逐层叠加，可能影响转发性能",
          "en": "Some bound rules carry 3+ policies: processing chains stack up and may affect forwarding performance"
        },
        "pickPlaceholder": {
          "zh": "选择要关联的负载均衡规则",
          "en": "Select load-balancing rules to bind"
        },
        "relatedCount": {
          "zh": "已关联 {n} 条规则",
          "en": "{n} rule(s) bound"
        },
        "tcpWarn": {
          "zh": "TCP 规则拦截=断连（无拦截页）；CDN 回源需开启 PROXY protocol",
          "en": "TCP rule blocking = connection reset (no block page); enable PROXY protocol for CDN origin pulls"
        },
        "deadPageHint": {
          "zh": "策略「{name}」配置的拦截页面已删除或内容为空，该策略触发时将显示兜底策略的拦截页",
          "en": "The block page configured by policy \"{name}\" is deleted or empty; when it triggers, the fallback policy's page shows"
        },
        "mixedPagesHint": {
          "zh": "这些策略的拦截页/状态码不同——各策略触发时显示各自的拦截页，未配置的策略触发时兜底显示绑定链首个有页策略的页",
          "en": "These policies differ in block page/status code — each shows its own page when triggering; policies without one fall back to the first page-capable policy in the chain"
        },
        "tcpHint": {
          "zh": "拦截=断连，无拦截页；CDN 回源需开启 PROXY protocol",
          "en": "Blocking = connection reset, no block page; enable PROXY protocol for CDN origin pulls"
        }
      },
      "common": {
        "delete": {
          "zh": "删除",
          "en": "Delete"
        },
        "reload": {
          "zh": "重新加载",
          "en": "Reload"
        },
        "retryNow": {
          "zh": "立即重试",
          "en": "Retry now"
        },
        "sep": {
          "zh": "、",
          "en": ", "
        },
        "cancel": {
          "zh": "取消",
          "en": "Cancel"
        },
        "close": {
          "zh": "关闭",
          "en": "Close"
        },
        "extractAsList": {
          "zh": "提取为列表",
          "en": "Extract to list"
        },
        "groupCustom": {
          "zh": "自定义列表",
          "en": "Custom lists"
        },
        "ipEntryPlaceholder": {
          "zh": "输入 IP/CIDR 后回车",
          "en": "Enter IP/CIDR and press Enter"
        },
        "listWithNameCount": {
          "zh": "{name}（{count} 条）",
          "en": "{name} ({count} entries)"
        },
        "refListLabel": {
          "zh": "引用地址列表",
          "en": "Referenced IP lists"
        },
        "refListPlaceholder": {
          "zh": "选择要引用的 IP 地址列表",
          "en": "Select IP lists to reference"
        },
        "goCreateEdit": {
          "zh": "去创建/编辑",
          "en": "Create/Edit"
        },
        "enableLabel": {
          "zh": "启用",
          "en": "Enable"
        },
        "groupBuiltin": {
          "zh": "内置威胁名单",
          "en": "Built-in threat lists"
        },
        "modeLabel": {
          "zh": "控制模式",
          "en": "Control mode"
        },
        "retry": {
          "zh": "重试",
          "en": "Retry"
        },
        "moveDown": {
          "zh": "下移",
          "en": "Move down"
        },
        "moveUp": {
          "zh": "上移",
          "en": "Move up"
        },
        "remove": {
          "zh": "移除",
          "en": "Remove"
        },
        "selectedCount": {
          "zh": "已选 {n} 条",
          "en": "{n} selected"
        },
        "all": {
          "zh": "全部",
          "en": "All"
        },
        "clear": {
          "zh": "清空",
          "en": "Clear"
        },
        "confirm": {
          "zh": "确定",
          "en": "OK"
        },
        "nextStep": {
          "zh": "下一步",
          "en": "Next"
        },
        "notEnabled": {
          "zh": "未启用",
          "en": "Not enabled"
        },
        "prevStep": {
          "zh": "上一步",
          "en": "Previous"
        },
        "savePolicy": {
          "zh": "保存策略",
          "en": "Save policy"
        },
        "selectAll": {
          "zh": "全选",
          "en": "Select all"
        },
        "selfPolicy": {
          "zh": "本策略",
          "en": "This policy"
        },
        "countItems": {
          "zh": "{n} 条",
          "en": "{n}"
        },
        "disabledSuffix": {
          "zh": "（未启用）",
          "en": " (disabled)"
        },
        "groupsCount": {
          "zh": "{n} 组",
          "en": "{n} group(s)"
        },
        "pageNum": {
          "zh": "页面 #{n}",
          "en": "Page #{n}"
        },
        "sepSemi": {
          "zh": "；",
          "en": "; "
        },
        "etcSuffix": {
          "zh": " 等",
          "en": " etc"
        },
        "nameQuoted": {
          "zh": "「{name}」",
          "en": "“{name}”"
        },
        "confirmTitle": {
          "zh": "确认",
          "en": "Confirm"
        },
        "continueSave": {
          "zh": "继续保存",
          "en": "Save anyway"
        },
        "deleted": {
          "zh": "已删除",
          "en": "Deleted"
        },
        "saveSuccess": {
          "zh": "保存成功",
          "en": "Saved successfully"
        },
        "etcCountSuffix": {
          "zh": " 等 {n} 条",
          "en": " … {n} more"
        }
      },
      "list": {
        "auxFailBanner": {
          "zh": "部分辅助数据加载失败（{items}）：策略计数与冲突告警可能不完整",
          "en": "Some auxiliary data failed to load ({items}): policy counts and conflict alerts may be incomplete"
        },
        "empty": {
          "zh": "暂无安全策略",
          "en": "No security policies yet"
        },
        "loadFailedBanner": {
          "zh": "安全策略加载失败：列表为空/停留旧值不代表策略被清空",
          "en": "Failed to load security policies: an empty list or stale values does not mean policies were cleared"
        },
        "loadFailedHint": {
          "zh": "加载失败，请点击上方「立即重试」",
          "en": "Load failed; click \"Retry now\" above"
        },
        "searchPlaceholder": {
          "zh": "搜索策略名称",
          "en": "Search policy names"
        },
        "tabLabel": {
          "zh": "{label}（{count}）",
          "en": "{label} ({count})"
        }
      },
      "page": {
        "create": {
          "zh": "新建策略",
          "en": "New Policy"
        },
        "desc": {
          "zh": "管理 WAF 防火墙、IP 访问控制和限流策略",
          "en": "Manage WAF firewall, IP access control and rate-limiting policies"
        },
        "title": {
          "zh": "安全策略",
          "en": "Security Policies"
        }
      },
      "status": {
        "disabled": {
          "zh": "禁用",
          "en": "Disabled"
        },
        "enabled": {
          "zh": "启用",
          "en": "Enabled"
        },
        "off": {
          "zh": "关闭",
          "en": "Off"
        }
      },
      "table": {
        "actions": {
          "zh": "操作",
          "en": "Actions"
        },
        "name": {
          "zh": "策略名称",
          "en": "Policy Name"
        },
        "relatedRules": {
          "zh": "关联规则",
          "en": "Rules"
        },
        "relatedRulesAria": {
          "zh": "关联规则 {n} 条，查看并跳转规则",
          "en": "{n} related rule(s); view and jump to rules"
        },
        "status": {
          "zh": "状态",
          "en": "Status"
        },
        "summary": {
          "zh": "内容摘要",
          "en": "Summary"
        },
        "trigger24h": {
          "zh": "24h 触发",
          "en": "24h Hits"
        },
        "updatedAt": {
          "zh": "更新时间",
          "en": "Updated At"
        },
        "updatedBy": {
          "zh": "更新者",
          "en": "Updated By"
        }
      },
      "migrate": {
        "capRisk": {
          "zh": "上限风险：{names} 迁移后将超过每条规则 {max} 条绑定上限——这些规则保持原绑定并进入跳过清单",
          "en": "Cap risk: after migration {names} would exceed the {max}-binding-per-rule limit — these rules keep their original bindings and enter the skip list"
        },
        "childDisabled": {
          "zh": "{type} · 未启用（不生成）",
          "en": "{type} · Not enabled (not generated)"
        },
        "childWithType": {
          "zh": "{name}（{type}）",
          "en": "{name} ({type})"
        },
        "confirm": {
          "zh": "确认更新迁移",
          "en": "Confirm Migration"
        },
        "deleteNote": {
          "zh": "全部规则重映射成功后原策略将被删除；存在被跳过的规则时原策略保留（因仍在使用）",
          "en": "The original policy is deleted once all rules remap successfully; if any rule is skipped it is kept (still in use)"
        },
        "noBindings": {
          "zh": "当前无规则绑定本策略",
          "en": "No rules are bound to this policy"
        },
        "rateLimitRisk": {
          "zh": "限流唯一风险：{names} 已绑定其他限流策略——拆分将产出阶段 2 子策略，这些规则会跳过重映射（每条规则最多一条限流策略），保持原绑定",
          "en": "Rate-limit uniqueness risk: {names} already bind another rate-limit policy — the split produces stage 2 sub-policies, so these rules skip remapping (at most one rate-limit policy per rule) and keep their original bindings"
        },
        "remapDesc": {
          "zh": "原策略的绑定整体改挂到子策略",
          "en": "All bindings of the original policy move to its sub-policies"
        },
        "remapTitle": {
          "zh": "将重映射绑定",
          "en": "Bindings Will Be Remapped"
        },
        "subtitle": {
          "zh": "混合策略「{name}」将按阶段迁移为单职子策略（兼容组不再支持新建）",
          "en": "Mixed policy \"{name}\" will be migrated by stage into single-purpose sub-policies (the legacy combined type is no longer available for new policies)"
        },
        "title": {
          "zh": "更新迁移预演",
          "en": "Migration Preview"
        },
        "willCreate": {
          "zh": "将创建 {n} 条子策略",
          "en": "{n} sub-policies will be created"
        },
        "willSkip": {
          "zh": "将跳过（已有 stage2）",
          "en": "Will be skipped (stage 2 exists)"
        }
      },
      "view": {
        "noRules": {
          "zh": "未关联规则",
          "en": "No rules bound"
        },
        "relatedRulesTitle": {
          "zh": "关联规则（{n}）",
          "en": "Related rules ({n})"
        },
        "subtitle": {
          "zh": "混合策略（兼容旧版）· 只读查看——经「更新迁移」拆分为单职策略后可编辑",
          "en": "Mixed policy (legacy) · read-only view — editable after splitting via \"Migrate\" into single-purpose policies"
        },
        "attributionLabel": {
          "zh": "归因口径",
          "en": "Attribution"
        },
        "attributionValue": {
          "zh": "阶段 3 按触发策略显示；阶段 1 预检合并拦截与阶段 2 限流 429 由绑定链首位有页策略显示；规则级阶段 1/3 覆盖优先",
          "en": "Stage 3 shows by triggering policy; stage 1 precheck-merged blocking and stage 2 rate-limit 429 show by the first policy with a page in the binding chain; rule-level stage 1/3 overrides win"
        },
        "crsAllDefault": {
          "zh": "全部（默认）",
          "en": "All (default)"
        },
        "excludedWithPath": {
          "zh": "{n} 条（路径 {paths}）",
          "en": "{n} (paths {paths})"
        },
        "geoModeRegions": {
          "zh": "{mode} · {n} 区域",
          "en": "{mode} · {n} regions"
        },
        "geoModeUnset": {
          "zh": "未配置模式",
          "en": "mode not configured"
        },
        "noPageRateLimit": {
          "zh": "不使用自定义页面：限流 429 返回空响应体（阶段 1/3 拦截回落 Caddy 默认 403）",
          "en": "No custom page: rate-limit 429 returns an empty body (stage 1/3 blocking falls back to Caddy default 403)"
        },
        "pageWithStatus": {
          "zh": "{name}（状态码 {code}）",
          "en": "{name} (status {code})"
        },
        "pathMore": {
          "zh": " 等 {n} 条",
          "en": " … {n} more"
        },
        "rateDetail": {
          "zh": "{rps} 次/秒 · 突发 {burst} 次 · 拦截恒 429",
          "en": "{rps} rps · burst {burst} · blocking always 429"
        },
        "rateLimitLabel": {
          "zh": "速率限制",
          "en": "Rate Limit"
        },
        "trustCount": {
          "zh": "{n} 条{off}",
          "en": "{n}{off}"
        },
        "typeLabel": {
          "zh": "类型",
          "en": "Type"
        },
        "modeLabel": {
          "zh": "模式",
          "en": "Mode"
        }
      },
      "editor": {
        "descLabel": {
          "zh": "描述",
          "en": "Description"
        },
        "descPlaceholder": {
          "zh": "策略描述",
          "en": "Policy description"
        },
        "enabledLabel": {
          "zh": "启用状态",
          "en": "Enabled"
        },
        "enabledTip": {
          "zh": "禁用后该策略对所有关联规则停止生效",
          "en": "When disabled, this policy stops taking effect on all bound rules"
        },
        "nameLabel": {
          "zh": "名称",
          "en": "Name"
        },
        "namePlaceholder": {
          "zh": "策略名称",
          "en": "Policy name"
        },
        "titleCreate": {
          "zh": "新建策略",
          "en": "New Policy"
        },
        "titleEdit": {
          "zh": "编辑策略",
          "en": "Edit Policy"
        },
        "titleView": {
          "zh": "查看策略",
          "en": "View Policy"
        },
        "typeLabel": {
          "zh": "策略类型",
          "en": "Policy Type"
        },
        "subMixed": {
          "zh": "配置 WAF 检测规则、IP 访问控制、限流与规则关联",
          "en": "Configure WAF detection rules, IP access control, rate limiting and rule bindings"
        },
        "subStage0": {
          "zh": "配置信任名单条目与直通/保留检测模式",
          "en": "Configure trust list entries and pass-through / keep-detection mode"
        },
        "subStage1": {
          "zh": "配置 IP 访问控制、地域拦截与拦截页",
          "en": "Configure IP access control, geo blocking and block page"
        },
        "subStage2": {
          "zh": "配置速率限制（恒 429）",
          "en": "Configure rate limiting (always 429)"
        },
        "subStage3": {
          "zh": "配置 WAF 模式、CRS 规则组、自定义规则与拦截页",
          "en": "Configure WAF mode, CRS rule groups, custom rules and block page"
        }
      },
      "stage0": {
        "detectOff": {
          "zh": "关闭（默认）：信任 IP 直通上游，不产生任何安全事件",
          "en": "Off (default): trusted IPs pass through to upstream with no security events"
        },
        "detectOn": {
          "zh": "开启：信任 IP 跳过全部安全阶段，仅由独立轻量检测事务记录（事件动作=检测）、不拦截（限「类型=信任名单（stage0）」策略；mixed 等其他类型信任命中为引擎内检测降级）",
          "en": "On: trusted IPs skip all security stages and are only recorded by a separate lightweight detection transaction (event action=detected), without blocking (only for \"trust list (stage 0)\" policies; for mixed and other types a trust hit degrades to in-engine detection)"
        },
        "keepDetectLabel": {
          "zh": "保留检测记录",
          "en": "Keep detection records"
        },
        "projection": {
          "zh": "本策略将在关联规则的信任名单阶段生效——「类型=信任名单（stage0）」策略命中后跳过全部后续安全阶段（直通=零安全事件；保留检测=仅由独立轻量检测事务记录，动作=检测）；mixed 等其他类型策略信任命中为引擎内检测降级（仅记录不拦截、不跳段）",
          "en": "This policy takes effect at the trust-list stage of bound rules — \"trust list (stage 0)\" policy hits skip all later security stages (pass-through = zero security events; keep-detection = recorded only by a separate lightweight detection transaction with action=detected); for mixed and other policy types a trust hit degrades to in-engine detection (log only, no blocking, no stage skip)"
        },
        "trustIpLabel": {
          "zh": "信任 IP",
          "en": "Trusted IPs"
        },
        "trustTip": {
          "zh": "「类型=信任名单（stage0）」策略：名单内 IP 命中后跳过全部后续安全阶段（IP 访问控制 / 限流 / WAF；直通=零安全事件，保留检测=仅由独立轻量检测事务记录，动作=检测）；mixed 等其他类型策略信任命中为引擎内检测降级（仅记录不拦截、不跳段）；内联与引用列表合并生效",
          "en": "\"Trust list (stage 0)\" policy: trusted IPs skip all later security stages (IP ACL / rate limit / WAF; pass-through = zero security events, keep-detection = recorded only by a separate lightweight detection transaction with action=detected); for mixed and other types a trust hit degrades to in-engine detection (log only, no blocking, no stage skip); inline and referenced lists take effect merged"
        },
        "modeDetection": {
          "zh": "保留检测记录",
          "en": "keep-detection"
        },
        "modePass": {
          "zh": "直通上游",
          "en": "pass-through"
        },
        "detectDetail": {
          "zh": "保留检测记录（事件动作=检测）",
          "en": "keep-detection (event action=detected)"
        },
        "passDetail": {
          "zh": "直通上游（不产生安全事件）",
          "en": "pass-through (no security events)"
        },
        "trustListLabel": {
          "zh": "信任名单",
          "en": "Trust list"
        }
      },
      "waf": {
        "addExclusion": {
          "zh": "添加排除规则",
          "en": "Add exclusion"
        },
        "blockingEvalWarn": {
          "zh": "排除评估规则（949/959）将使拦截模式的评分阈值拦截失效",
          "en": "Excluding evaluation rules (949/959) disables threshold-based blocking in blocking mode"
        },
        "checkResponseBody": {
          "zh": "检查响应体",
          "en": "Check response body"
        },
        "checkResponseBodyTip": {
          "zh": "开启后 WAF 读取并检查上游响应内容（响应泄露类规则需要）；关闭可显著降低内存与 CPU 开销，大多数部署只需检查请求",
          "en": "When on, WAF reads and inspects upstream response content (required by response-leak rules); turning it off significantly reduces memory and CPU cost — most deployments only need request inspection"
        },
        "crsGroupsLabel": {
          "zh": "CRS 规则组",
          "en": "CRS Rule Groups"
        },
        "crsPlaceholder": {
          "zh": "留空加载全部 CRS 规则",
          "en": "Leave empty to load all CRS rules"
        },
        "crsTip": {
          "zh": "选择后仅加载所选规则组，留空加载全部 CRS 规则",
          "en": "When set, only selected rule groups load; leave empty to load all CRS rules"
        },
        "crsTip2": {
          "zh": "初始化（901）与拦截评估（949/959）为系统基础规则，随策略自动加载；通用误报豁免（999）在选择全部规则时自动包含",
          "en": "Initialization (901) and blocking evaluation (949/959) are system base rules loaded automatically with the policy; the generic false-positive exemption (999) is included automatically when all rules are selected"
        },
        "customOnlyHint": {
          "zh": "仅自定义模式：CRS 不生效，以下 CRS 配置不可用",
          "en": "Custom-only mode: CRS is inactive and CRS settings below are unavailable"
        },
        "customRulesLabel": {
          "zh": "自定义规则",
          "en": "Custom Rules"
        },
        "customRulesPlaceholder": {
          "zh": "选择要包含的自定义规则",
          "en": "Select custom rules to include"
        },
        "customRulesTip": {
          "zh": "自定义规则在\"规则集\"页面创建，",
          "en": "Custom rules are created on the \"Rule Sets\" page. "
        },
        "customTip": {
          "zh": "自定义规则在检测/拦截/仅自定义模式下按规则内动作执行；计分动作在 CRS 开启时由异常阈值统一裁决（检测计分、拦截按阈值）。",
          "en": "Custom rules execute their in-rule actions in detection/blocking/custom-only modes; scoring actions are adjudicated by the anomaly threshold when CRS is on (detection scores, blocking by threshold)."
        },
        "exclusionColTarget": {
          "zh": "目标规则 × 作用域 × 条件",
          "en": "Target rule × Scope × Condition"
        },
        "exclusionEmptyTip": {
          "zh": "未添加排除规则——排除的目标规则/规则组不会被检测或拦截；作用域限定排除仅对所选来源 IP/地址列表/路径生效",
          "en": "No exclusions yet — excluded target rules/groups are neither detected nor blocked; scoped exclusions apply only to the selected source IPs/IP lists/paths"
        },
        "exclusionLabel": {
          "zh": "排除规则",
          "en": "Excluded Rules"
        },
        "exclusionSearchPlaceholder": {
          "zh": "搜索规则 ID/描述，或输入组号、文件名",
          "en": "Search rule ID/description, or type a group number or file name"
        },
        "exclusionTableTip": {
          "zh": "排除的目标规则/规则组不会被检测或拦截；作用域限定排除仅对所选来源 IP/地址列表/路径生效",
          "en": "Excluded target rules/groups are neither detected nor blocked; scoped exclusions apply only to the selected source IPs/IP lists/paths"
        },
        "ipListSelectPlaceholder": {
          "zh": "选择 IP 地址列表",
          "en": "Select IP lists"
        },
        "logRequestBody": {
          "zh": "记录请求体",
          "en": "Log request body"
        },
        "logRequestBodyTip": {
          "zh": "仅 CRS/自定义规则命中事件记录请求体；当前模式关闭时不记录",
          "en": "Request body is logged only for CRS/custom rule hit events; not recorded while the current mode is off"
        },
        "logRequestBodyWarn": {
          "zh": "开启后命中规则事件的请求体将明文记录到事件库（单条上限 64KB），可能包含密码等敏感信息，请仅在排障期间开启",
          "en": "When on, request bodies of rule-hit events are stored in plaintext in the event store (64KB per-event cap) and may contain passwords or other sensitive data — enable only for troubleshooting"
        },
        "modeBlocking": {
          "zh": "拦截（CRS 阻断）",
          "en": "Blocking (CRS blocks)"
        },
        "modeCustomOnly": {
          "zh": "仅自定义规则（CRS 不生效）",
          "en": "Custom rules only (CRS inactive)"
        },
        "modeDetection": {
          "zh": "检测（CRS 只记录）",
          "en": "Detection (CRS logs only)"
        },
        "modeLabel": {
          "zh": "WAF 模式",
          "en": "WAF Mode"
        },
        "modeOff": {
          "zh": "关闭（全不生效）",
          "en": "Off (nothing takes effect)"
        },
        "offHint": {
          "zh": "当前 WAF 已关闭：CRS 与自定义规则均不生效，以下 CRS 配置不可用",
          "en": "WAF is currently off: neither CRS nor custom rules take effect, and CRS settings below are unavailable"
        },
        "offTip": {
          "zh": "关闭 = CRS 与自定义规则均不生效；IP 访问控制与地域拦截按各自开关独立生效。",
          "en": "Off = neither CRS nor custom rules take effect; IP access control and geo blocking follow their own switches."
        },
        "pathPlaceholder": {
          "zh": "如 /api/upload（前缀匹配）",
          "en": "e.g. /api/upload (prefix match)"
        },
        "projection": {
          "zh": "本策略将在关联规则的 WAF 阶段生效",
          "en": "This policy takes effect at the WAF stage of bound rules"
        },
        "responsePhaseWarn": {
          "zh": "已选含响应阶段的规则组（955 Webshell 等），但未开启「检查响应体」——这些组不会加载生效，请开启「检查响应体」或移除响应阶段组",
          "en": "Response-phase rule groups are selected (955 Webshell etc.) but \"Check response body\" is off — these groups will not load; turn on \"Check response body\" or remove response-phase groups"
        },
        "scopeAll": {
          "zh": "全部 IP",
          "en": "All IPs"
        },
        "scopeAllHint": {
          "zh": "对所有 IP 生效",
          "en": "Applies to all IPs"
        },
        "scopeIp": {
          "zh": "指定 IP",
          "en": "Specific IPs"
        },
        "scopeList": {
          "zh": "地址列表",
          "en": "IP lists"
        },
        "scopePath": {
          "zh": "路径 URI",
          "en": "Path URI"
        },
        "suggestionDesc": {
          "zh": "{label}（{file}）",
          "en": "{label} ({file})"
        },
        "thLoose": {
          "zh": "宽松（阈值 {n}）",
          "en": "Loose (threshold {n})"
        },
        "thStandard": {
          "zh": "标准（阈值 {n}）",
          "en": "Standard (threshold {n})"
        },
        "thStrict": {
          "zh": "严格（阈值 {n} · 存量档）",
          "en": "Strict (threshold {n} · legacy)"
        },
        "thUltraLoose": {
          "zh": "极宽松（阈值 {n}）",
          "en": "Ultra loose (threshold {n})"
        },
        "thVeryLoose": {
          "zh": "很宽松（阈值 {n}）",
          "en": "Very loose (threshold {n})"
        },
        "thresholdLabel": {
          "zh": "异常阈值",
          "en": "Anomaly Threshold"
        },
        "thresholdTip": {
          "zh": "阈值以异常分为单位：CRS 严重规则每条 +5（错误 +4、警告 +3），自定义「计分」规则按其分值累加。",
          "en": "The threshold is in anomaly points: each CRS critical rule adds 5 (error +4, warning +3); custom \"score\" rules add their configured score."
        },
        "thresholdTip2": {
          "zh": "累计达到阈值拦截；低于阈值的命中不拦截，但记录为检测事件（计入安全总览「今日检测」）。",
          "en": "Reaching the threshold blocks; hits below it are not blocked but recorded as detection events (counted in \"Today's detections\" on the security overview)."
        },
        "fileMeta": {
          "zh": "文件 · {phase} · {code}",
          "en": "file · {phase} · {code}"
        },
        "fileMetaCat": {
          "zh": "文件 · {phase} · {code} · {category}",
          "en": "file · {phase} · {code} · {category}"
        },
        "ghost99": {
          "zh": "{v} · 通用误报豁免（选择全部规则时自动包含）",
          "en": "{v} · generic false-positive exemption (auto-included when all rules are selected)"
        },
        "ghostGroup": {
          "zh": "{v} —（当前 CRS 已无此规则组，可删除）",
          "en": "{v} — (group no longer in current CRS; safe to remove)"
        },
        "ghostRule": {
          "zh": "{v} —（当前 CRS 已无此规则）",
          "en": "{v} — (no longer in current CRS)"
        },
        "phaseRequest": {
          "zh": "请求",
          "en": "request"
        },
        "rangeGhostTitle": {
          "zh": "区间遗留形态：按字面保存并按字面下发（SecRuleRemoveById 区间），不展开为规则组内全部规则 ID；作用域仅支持全部 IP",
          "en": "Legacy range form: saved and deployed verbatim (SecRuleRemoveById range), not expanded to all rule IDs in the group; only the all-IP scope supports it"
        },
        "groupLabel": {
          "zh": "规则组 {target}",
          "en": "Rule group {target}"
        }
      },
      "acl": {
        "divider": {
          "zh": "访问控制",
          "en": "Access Control"
        },
        "modeAllow": {
          "zh": "白名单（仅允许列表中的 IP，其他一律拒绝）",
          "en": "Whitelist (allow only listed IPs, deny all others)"
        },
        "modeAria": {
          "zh": "IP 访问控制模式",
          "en": "IP access control mode"
        },
        "modeBypass": {
          "zh": "免检测（列表中的 IP 跳过全部安全检测）",
          "en": "No-inspection (listed IPs skip all security checks)"
        },
        "modeDeny": {
          "zh": "黑名单（拒绝列表中的 IP，其他正常检测）",
          "en": "Blacklist (deny listed IPs, others pass normal checks)"
        },
        "projection": {
          "zh": "本策略将在关联规则的 IP 访问控制/地域拦截阶段生效",
          "en": "This policy takes effect at the IP access control / geo blocking stage of bound rules"
        },
        "refTip": {
          "zh": "引用「规则集 → IP 地址列表」中的可复用列表，条目与上方内联名单合并生效",
          "en": "Reference reusable lists from \"Rule Sets → IP Lists\"; their entries merge with the inline list above"
        },
        "hintAllow": {
          "zh": "仅列表中的 IP 可以访问，其他 IP 一律拒绝",
          "en": "Only listed IPs can access; all others are denied"
        },
        "hintBypass": {
          "zh": "列表中的 IP 将跳过全部安全检测",
          "en": "Listed IPs skip all security checks"
        },
        "hintDeny": {
          "zh": "列表中的 IP 将被拒绝访问，其他 IP 正常进行安全检测",
          "en": "Listed IPs will be denied access; others go through normal security checks"
        },
        "labelAllow": {
          "zh": "允许 IP",
          "en": "Allow IPs"
        },
        "labelBypass": {
          "zh": "免检测 IP",
          "en": "No-inspection IPs"
        },
        "labelDeny": {
          "zh": "拒绝 IP",
          "en": "Deny IPs"
        },
        "listFallback": {
          "zh": "IP 列表",
          "en": "IP list"
        },
        "allowShort": {
          "zh": "白名单",
          "en": "whitelist"
        },
        "bypassShort": {
          "zh": "免检测",
          "en": "no-inspection"
        }
      },
      "geo": {
        "crawlerLabel": {
          "zh": "爬虫豁免",
          "en": "Crawler Exemption"
        },
        "crawlerNoneWarn": {
          "zh": "未勾选任何引擎：等于豁免全部引擎（此形态不可保存，请至少勾选一个或关闭爬虫豁免）",
          "en": "No engine selected: this exempts all engines (this state cannot be saved — select at least one engine or turn off crawler exemption)"
        },
        "crawlerTip": {
          "zh": "勾选的引擎经反向 DNS/官方 IP 段验证为真实爬虫后豁免地域拦截（IP 名单/WAF/限流仍全量生效）；伪装爬虫 UA 的请求会被拒绝并记录攻击事件。360 无反查支持按官方 IP 段验证；标注「观察级」的引擎按厂商域名验证",
          "en": "Selected engines, once verified as genuine crawlers via reverse DNS/official IP ranges, are exempt from geo blocking (IP lists/WAF/rate limiting still apply in full); requests faking crawler UAs are rejected and logged as attack events. 360 lacks reverse-DNS support and is verified via official IP ranges; engines marked \"provisional\" are verified by vendor domains"
        },
        "divider": {
          "zh": "区域控制",
          "en": "Region Control"
        },
        "ipv4Note": {
          "zh": "地域规则仅对 IPv4 生效：IPv6 与不可解析客户端按「海外」处理（拦截模式勾选海外时将被拦截；仅允许模式只勾选省份时将被拦截）。IP 库未安装时地域规则不可启用。",
          "en": "Geo rules apply to IPv4 only: IPv6 and unresolvable clients are treated as \"overseas\" (blocked in deny mode when overseas is selected; blocked in allow-only mode when only provinces are selected). Geo rules cannot be enabled until the IP library is installed."
        },
        "loadFailed": {
          "zh": "地域数据加载失败，已保存的地域配置仍保留。",
          "en": "Failed to load geo data; your saved geo configuration is kept."
        },
        "modeAllow": {
          "zh": "仅允许所选区域（其他拦截）",
          "en": "Allow selected regions only (block others)"
        },
        "modeAria": {
          "zh": "地域控制模式",
          "en": "Geo control mode"
        },
        "modeDeny": {
          "zh": "拦截所选区域（其他放行）",
          "en": "Block selected regions (allow others)"
        },
        "regionLabel": {
          "zh": "区域选择",
          "en": "Region Selection"
        },
        "regionPlaceholder": {
          "zh": "选择区域（省 / 省-市 / 海外国家）",
          "en": "Select regions (province / province-city / overseas country)"
        },
        "regionTip": {
          "zh": "基于 IP2Region 离线库判断访客所在区域，与 CIDR 规则同时生效；只选省份 = 整省生效",
          "en": "Visitor regions are resolved via the offline IP2Region database and take effect alongside CIDR rules; selecting only a province applies to the whole province"
        },
        "overseasGroup": {
          "zh": "海外国家",
          "en": "Overseas countries"
        },
        "geoBlockLabel": {
          "zh": "地域拦截",
          "en": "Geo blocking"
        }
      },
      "bp": {
        "manageTip": {
          "zh": "拦截时返回给客户端的自定义页面，在\"拦截页面\"页面管理，",
          "en": "Custom pages returned to clients on blocking are managed on the \"Block Pages\" page. "
        },
        "noPageDefault": {
          "zh": "不使用自定义页面（Caddy 默认 403）",
          "en": "No custom page (Caddy default 403)"
        },
        "noPageStage2": {
          "zh": "不使用自定义页面（429 空响应体）",
          "en": "No custom page (empty 429 body)"
        },
        "noPageTipDefault": {
          "zh": "不配置拦截页：本策略触发拦截时兜底显示绑定链首个有页策略的页面；全链无页时返回 Caddy 默认 403",
          "en": "No block page: when this policy blocks, the page of the first policy with one in the binding chain is shown as fallback; if none has a page, Caddy's default 403 is returned"
        },
        "noPageTipStage2": {
          "zh": "不配置拦截页：429 返回空响应体（可选内置「限流拦截页面」）",
          "en": "No block page: 429 returns an empty body (built-in \"rate-limit block page\" optional)"
        },
        "pageLabel": {
          "zh": "拦截页面",
          "en": "Block Page"
        },
        "pagePlaceholder": {
          "zh": "选择拦截页面",
          "en": "Select block page"
        },
        "projection": {
          "zh": "触发本策略拦截时，向客户端返回下方选择的拦截页",
          "en": "When this policy blocks, the block page selected below is returned to the client"
        },
        "statusLabel": {
          "zh": "返回状态码",
          "en": "Status Code"
        },
        "statusTipDefault": {
          "zh": "WAF、IP ACL 拦截使用此状态码；限流拦截恒为 429（便于指标单独计量）",
          "en": "WAF and IP ACL blocking use this status code; rate-limit blocking always returns 429 (for separate metric accounting)"
        },
        "statusTipNoPage": {
          "zh": "未选择自定义页面时状态码不生效，拦截固定返回 Caddy 默认 403；请先选择页面",
          "en": "Without a custom page the status code has no effect — blocking returns Caddy's default 403; select a page first"
        },
        "statusTipStage2": {
          "zh": "限流拦截恒为 429（便于指标单独计量），不可修改",
          "en": "Rate-limit blocking always returns 429 (for separate metric accounting); not editable"
        },
        "bindingsAttribution": {
          "zh": "已关联 {n} 条规则：触发各策略拦截时，分别显示该策略自己配置的拦截页；未配置拦截页的策略触发时，显示兜底页（首个启用拦截页的策略{winner}）",
          "en": "{n} rule(s) bound: when any policy blocks, its own configured page shows; policies without a page fall back to the first page-enabled policy{winner}"
        },
        "fallbackFacet": {
          "zh": "{n} 条规则：其他未配页策略触发时，显示兜底页（首个启用拦截页的策略）",
          "en": "{n} rule(s): when other page-less policies trigger, the fallback page shows (first page-enabled policy)"
        },
        "fallbackNote": {
          "zh": "触发拦截时将显示兜底页（绑定链首个启用且有页的策略）",
          "en": "When blocking triggers, the fallback page shows (first enabled page-capable policy in the chain)"
        },
        "listUnavailable": {
          "zh": "拦截页列表未加载成功，无法判定本策略页面是否实际生效",
          "en": "The block-page list did not load; cannot determine whether this policy's page is actually in effect"
        },
        "noPageFallback": {
          "zh": "已关联 {n} 条规则：本策略未配置拦截页——触发拦截时显示兜底页（绑定链首个启用且有页的策略）",
          "en": "{n} rule(s) bound: this policy has no block page — blocking shows the fallback page (first enabled page-capable policy in the chain)"
        },
        "pageActive": {
          "zh": "已关联 {n} 条规则：触发本策略拦截时，均显示本拦截页「{page}」",
          "en": "{n} rule(s) bound: whenever this policy blocks, this page shows: \"{page}\""
        },
        "pageInvalid": {
          "zh": "已关联 {n} 条规则：本拦截页已失效（页面已删除或内容为空），保存前请重新选择",
          "en": "{n} rule(s) bound: this block page is no longer valid (deleted or empty); reselect before saving"
        },
        "rateLimitFacet": {
          "zh": "{n} 条限流规则：限流拦截状态码恒为 429（限流页按绑定链首个有页策略显示，不随触发策略变化）",
          "en": "{n} rate-limit rule(s): rate-limit blocking status is always 429 (the rate-limit page follows the first page-capable policy in the chain, independent of the triggering policy)"
        },
        "stage2NoPage": {
          "zh": "已关联 {n} 条规则：本策略未配置拦截页——限流拦截返回空响应体 429",
          "en": "{n} rule(s) bound: this policy has no block page — rate-limit blocking returns an empty-body 429"
        },
        "stageIneffective": {
          "zh": "{stage}：当前配置不会产生该阶段拦截，页面不会被使用",
          "en": "{stage}: the current configuration cannot produce a block at this stage, so the page will never be used"
        },
        "tcpFacet": {
          "zh": "{n} 条 TCP 规则：拦截为断连，不经过拦截页",
          "en": "{n} TCP rule(s): blocking resets the connection and never reaches a block page"
        }
      },
      "rate": {
        "burstLabel": {
          "zh": "突发余量",
          "en": "Burst Allowance"
        },
        "burstTip": {
          "zh": "次，短时允许超出速率上限的额外请求数",
          "en": "requests — extra requests briefly allowed above the rate limit"
        },
        "limitLabel": {
          "zh": "速率上限",
          "en": "Rate Limit"
        },
        "projection": {
          "zh": "本策略将在关联规则的限流阶段生效——限流拦截恒为 429（便于指标单独计量）；拦截页在下一步配置，缺省时跟随同规则其他策略的页面",
          "en": "This policy takes effect at the rate-limit stage of bound rules — rate-limit blocking always returns 429 (for separate metric accounting); the block page is configured in the next step and defaults to another policy's page on the same rule"
        }
      },
      "extract": {
        "categoryLabel": {
          "zh": "分类",
          "en": "Category"
        },
        "categoryPlaceholder": {
          "zh": "选择或输入分类",
          "en": "Select or enter a category"
        },
        "confirm": {
          "zh": "创建并引用",
          "en": "Create & Reference"
        },
        "inlineCount": {
          "zh": "（内联 {n} 条）",
          "en": " ({n} inline)"
        },
        "nameLabel": {
          "zh": "列表名称",
          "en": "List Name"
        },
        "namePlaceholder": {
          "zh": "列表名称",
          "en": "List name"
        },
        "note": {
          "zh": "将创建列表并清空内联条目，引用后语义不变",
          "en": "A list will be created and inline entries cleared; referencing keeps the same semantics"
        },
        "sourceLabel": {
          "zh": "来源",
          "en": "Source"
        },
        "subtitle": {
          "zh": "将内联 IP 转为可复用名单并关联到当前策略",
          "en": "Convert inline IPs into a reusable list referenced by this policy"
        },
        "title": {
          "zh": "提取为地址列表",
          "en": "Extract to IP List"
        },
        "remark": {
          "zh": "从策略提取",
          "en": "Extracted from policy"
        }
      },
      "picker": {
        "availableTitle": {
          "zh": "可选规则",
          "en": "Available Rules"
        },
        "filteredCount": {
          "zh": "筛选 {n} 条",
          "en": "{n} matched"
        },
        "noMatch": {
          "zh": "没有匹配的规则",
          "en": "No matching rules"
        },
        "protoAria": {
          "zh": "按协议筛选规则",
          "en": "Filter rules by protocol"
        },
        "searchPlaceholder": {
          "zh": "搜索规则名 / 域名 / 规则 ID",
          "en": "Search rule name / domain / rule ID"
        },
        "selfPos": {
          "zh": "本策略排第 {n} 位",
          "en": "This policy ranks #{n}"
        },
        "title": {
          "zh": "选择关联规则",
          "en": "Select Rules"
        },
        "blockCap": {
          "zh": "已达 {max} 条绑定上限，无法继续绑定",
          "en": "Reached the {max}-binding limit; cannot bind more"
        },
        "blockStage2": {
          "zh": "该规则已绑定其它限流策略（每规则仅一条），需先解绑",
          "en": "This rule already binds another rate-limit policy (one per rule); unbind it first"
        }
      },
      "preview": {
        "orderUpdate": {
          "zh": "按新执行序更新 {n} 条规则的绑定顺序",
          "en": "Updates binding order of {n} rule(s) to the new execution order"
        },
        "rulesCount": {
          "zh": "{n} 条已关联",
          "en": "{n} bound"
        },
        "rulesNone": {
          "zh": "未关联",
          "en": "Not bound"
        },
        "rulesTitle": {
          "zh": "适用规则",
          "en": "Applicable Rules"
        },
        "saveLabel": {
          "zh": "本次保存",
          "en": "This Save"
        },
        "scopeBound": {
          "zh": "本策略将应用于 {n} 条已关联规则",
          "en": "This policy will apply to {n} bound rule(s)"
        },
        "scopeLabel": {
          "zh": "生效范围",
          "en": "Scope"
        },
        "scopeUnbound": {
          "zh": "保存后可在「关联规则」步骤绑定，或在规则行点「安全」绑定",
          "en": "After saving, bind via the \"Rules\" step here, or via \"Security\" on a rule row"
        }
      },
      "msg": {
        "swapNoop": {
          "zh": "相邻为信任名单策略（阶段 0 恒置顶），交换不改变触发顺序",
          "en": "Adjacent trust-list policy (stage 0 is always first); swapping does not change trigger order"
        },
        "bindingsFailedReload": {
          "zh": "规则绑定数据加载失败，请先点击上方「重新加载」",
          "en": "Failed to load rule binding data; click \"Reload\" above first"
        },
        "bindingsLoading": {
          "zh": "规则绑定数据加载中，请稍后再试",
          "en": "Rule binding data is loading; try again shortly"
        },
        "bindingsRefreshFailed": {
          "zh": "规则绑定数据刷新失败，已取消打开；请稍后重试",
          "en": "Failed to refresh rule binding data; opening cancelled — try again later"
        },
        "migrateCreated": {
          "zh": "已创建 {n} 条子策略（{names}）",
          "en": "Created {n} sub-policies ({names})"
        },
        "migrateDone": {
          "zh": "更新迁移完成",
          "en": "Migration completed"
        },
        "migrateKeepOriginal": {
          "zh": "原策略因仍在使用未删除",
          "en": "Original policy kept because it is still in use"
        },
        "migrateRemapped": {
          "zh": "重映射 {n} 条规则绑定",
          "en": "Remapped bindings of {n} rules"
        },
        "migrateSkipped": {
          "zh": "{n} 条规则跳过：{reasons}",
          "en": "{n} rules skipped: {reasons}"
        },
        "builtinDenyOnly": {
          "zh": "内置威胁名单仅可用于黑名单模式，已从引用中移除",
          "en": "Built-in threat lists are blacklist-only and have been removed from references"
        },
        "exclusionNoIp": {
          "zh": "第 {n} 条排除规则（指定 IP）未填写 IP",
          "en": "Exclusion #{n} (specific IPs): no IP entered"
        },
        "exclusionNoList": {
          "zh": "第 {n} 条排除规则（地址列表）未选择列表",
          "en": "Exclusion #{n} (IP lists): no list selected"
        },
        "exclusionNoPath": {
          "zh": "第 {n} 条排除规则（路径 URI）未填写路径",
          "en": "Exclusion #{n} (path URI): no path entered"
        },
        "exclusionNoTarget": {
          "zh": "第 {n} 条排除规则未选择目标",
          "en": "Exclusion #{n}: no target selected"
        },
        "exclusionPathChars": {
          "zh": "第 {n} 条排除规则（路径 URI）含非法字符（空白/控制字符/引号/反斜杠）或超过 256 字符",
          "en": "Exclusion #{n} (path URI) contains invalid characters (whitespace/control chars/quotes/backslash) or exceeds 256 characters"
        },
        "exclusionPathSlash": {
          "zh": "第 {n} 条排除规则（路径 URI）必须以 / 开头（如 /api/upload）",
          "en": "Exclusion #{n} (path URI) must start with / (e.g. /api/upload)"
        },
        "invalidCidr": {
          "zh": "IP/CIDR 条目格式不正确：{items}",
          "en": "Invalid IP/CIDR entries: {items}"
        },
        "invalidTrustCidr": {
          "zh": "信任名单中的 IP/CIDR 条目格式不正确：{items}",
          "en": "Invalid IP/CIDR entries in the trust list: {items}"
        },
        "nameRequired": {
          "zh": "请输入策略名称",
          "en": "Please enter a policy name"
        },
        "regionRequired": {
          "zh": "区域控制启用后必须选择至少一个区域（引用即生效）",
          "en": "At least one region is required when region control is on (referencing takes effect immediately)"
        },
        "bindPartialFail": {
          "zh": "策略已保存，但部分规则绑定同步失败；对话框保持打开，重新点击保存可重试绑定（幂等）",
          "en": "Policy saved, but some rule bindings failed to sync; the dialog stays open — click Save again to retry bindings (idempotent)"
        },
        "bindRejected": {
          "zh": "策略已保存，但规则绑定被服务端拒绝：请按提示解绑冲突策略或调整关联规则后重试（原样重试不会成功）",
          "en": "Policy saved, but rule bindings were rejected by the server: unbind conflicting policies or adjust the rules per the prompts, then retry (an identical retry will not succeed)"
        },
        "capReached": {
          "zh": "以下规则已达 {max} 条绑定上限，无法继续关联：{names}",
          "en": "These rules reached the {max}-binding limit and cannot bind more: {names}"
        },
        "categoryTooLong": {
          "zh": "分类不能超过 32 字符",
          "en": "Category cannot exceed 32 characters"
        },
        "crawlerNoneSelected": {
          "zh": "已开启爬虫豁免但未勾选任何引擎：空选等于豁免「全部引擎」。请至少勾选一个引擎，或关闭爬虫豁免",
          "en": "Crawler exemption is on with no engine selected: an empty selection means exempting \"all engines\". Select at least one engine, or turn off crawler exemption"
        },
        "createdListNoId": {
          "zh": "创建列表响应缺少 id",
          "en": "List creation response lacks id"
        },
        "createdPolicyNoId": {
          "zh": "创建策略响应缺少 id",
          "en": "Policy creation response lacks id"
        },
        "deleteConfirm": {
          "zh": "将删除策略「{name}」。删除后无法恢复，规则上原有的其它策略不受影响。",
          "en": "Policy \"{name}\" will be deleted. This cannot be undone; other policies on the rules are unaffected."
        },
        "deleteConfirmBtn": {
          "zh": "确认删除",
          "en": "Delete"
        },
        "deleteTitle": {
          "zh": "删除安全策略",
          "en": "Delete Security Policy"
        },
        "detailNoData": {
          "zh": "策略详情响应缺少数据",
          "en": "Policy detail response lacks data"
        },
        "discard": {
          "zh": "放弃修改",
          "en": "Discard changes"
        },
        "emptyAllowConfirm": {
          "zh": "该策略关联的规则将拒绝所有请求，确定继续？",
          "en": "Rules bound to this policy will deny all requests. Continue?"
        },
        "emptyAllowTitle": {
          "zh": "空白名单确认",
          "en": "Empty Whitelist Confirmation"
        },
        "extractConfirm": {
          "zh": "确定创建列表「{name}」（{n} 条）并转为引用？内联条目将清空，拦截语义不变。",
          "en": "Create list \"{name}\" ({n} entries) and switch to referencing? Inline entries will be cleared; blocking semantics unchanged."
        },
        "extractDone": {
          "zh": "已创建列表「{name}」并转为引用，内联条目已清空（引用后语义不变），保存策略后生效",
          "en": "List \"{name}\" created and referenced; inline entries cleared (referencing keeps semantics). Takes effect after saving the policy"
        },
        "extractEmpty": {
          "zh": "内联名单为空，无需提取",
          "en": "Inline list is empty; nothing to extract"
        },
        "extractMax": {
          "zh": "每个列表最多 2000 条条目",
          "en": "Each list holds at most 2000 entries"
        },
        "invalidTrustEntry": {
          "zh": "信任名单条目「{entry}」不是合法的 IP/CIDR",
          "en": "Trust list entry \"{entry}\" is not a valid IP/CIDR"
        },
        "keepEditing": {
          "zh": "继续编辑",
          "en": "Keep editing"
        },
        "listNameRequired": {
          "zh": "请输入列表名称",
          "en": "Please enter a list name"
        },
        "listNameTooLong": {
          "zh": "列表名称不能超过 50 字符",
          "en": "List name cannot exceed 50 characters"
        },
        "orderPartialFail": {
          "zh": "策略已保存，但部分规则的绑定顺序同步失败；对话框保持打开，重新点击保存可重试（幂等）",
          "en": "Policy saved, but binding order failed to sync for some rules; the dialog stays open — click Save again to retry (idempotent)"
        },
        "orderRejected": {
          "zh": "策略已保存，但绑定顺序被服务端拒绝：请检查该批规则的绑定状态后重试（原样重试不会成功）",
          "en": "Policy saved, but the binding order was rejected by the server: check the binding state of those rules and retry (an identical retry will not succeed)"
        },
        "orderSkipNote": {
          "zh": "{name}（{reason}）",
          "en": "{name} ({reason})"
        },
        "orderSkipped": {
          "zh": "部分规则未应用绑定顺序：{notes}；这些规则保持「顺序待保存」，重新点击保存可重试",
          "en": "Binding order not applied for some rules: {notes}; they stay in \"order pending save\" — click Save again to retry"
        },
        "pageRefreshFailed": {
          "zh": "拦截页列表刷新失败，未能核对所选拦截页；保存前请刷新页面重试",
          "en": "Failed to refresh the block-page list; could not verify the selected page — refresh and retry before saving"
        },
        "pageResetDefault": {
          "zh": "原拦截页面已删除，已回退默认页面",
          "en": "The original block page was deleted; reverted to the default page"
        },
        "policyDeleted": {
          "zh": "策略 #{id} 已被删除，事件中显示的是事件发生时的名称",
          "en": "Policy #{id} has been deleted; events show the name at event time"
        },
        "regionLoadFailed": {
          "zh": "地域数据加载失败，策略编辑中的地域选择暂不可用，可在编辑弹框内重试",
          "en": "Failed to load geo data; region selection in policy editing is unavailable for now — retry inside the editor dialog"
        },
        "saveConfirm": {
          "zh": "确定保存安全策略「{name}」？将立即重新加载 Caddy 配置。",
          "en": "Save security policy \"{name}\"? This reloads the Caddy configuration immediately."
        },
        "saveFailed": {
          "zh": "保存失败",
          "en": "Save failed"
        },
        "stage0NeedsIp": {
          "zh": "阶段 0 · 信任名单策略必须配置至少一个信任 IP（内联或引用列表）",
          "en": "A stage 0 · trust-list policy requires at least one trusted IP (inline or referenced list)"
        },
        "stage2Conflict": {
          "zh": "以下规则已绑定其它限流策略（每规则仅一条），请先解绑后再关联：{names}",
          "en": "These rules already bind another rate-limit policy (one per rule); unbind before binding: {names}"
        },
        "unsavedConfirm": {
          "zh": "有未保存的修改，关闭将丢弃本次编辑。是否继续？",
          "en": "There are unsaved changes; closing will discard them. Continue?"
        }
      },
      "summary": {
        "aclOff": {
          "zh": "未启用 ACL",
          "en": "ACL not enabled"
        },
        "crsAll": {
          "zh": "CRS 全部",
          "en": "CRS: all"
        },
        "crsGroups": {
          "zh": "CRS 组 {n}",
          "en": "CRS groups: {n}"
        },
        "customCount": {
          "zh": "自定义 {n} 条",
          "en": "{n} custom"
        },
        "geoClosedKeep": {
          "zh": "GeoIP 已关闭（保留 {n} 区域）",
          "en": "GeoIP off ({n} regions kept)"
        },
        "geoOff": {
          "zh": "GeoIP 未启用",
          "en": "GeoIP not enabled"
        },
        "geoRegions": {
          "zh": "GeoIP {n} 区域",
          "en": "GeoIP {n} regions"
        },
        "mixedCombo": {
          "zh": "混合 · 阶段 1/2/3 组合",
          "en": "Mixed · stage 1/2/3 combination"
        },
        "rateSummary": {
          "zh": "{rps} 次/秒 · 突发 {burst}",
          "en": "{rps} rps · burst {burst}"
        },
        "stage0Precedence": {
          "zh": "{name} · 阶段 0·拦截判定前优先生效",
          "en": "{name} · stage 0 · effective before blocking decisions"
        },
        "trustSummary": {
          "zh": "信任 {n} 条 · {mode}",
          "en": "Trust {n} · {mode}"
        },
        "wafMode": {
          "zh": "WAF {mode}",
          "en": "WAF {mode}"
        },
        "wafOff": {
          "zh": "WAF 关闭",
          "en": "WAF off"
        }
      },
      "step": {
        "basic": {
          "zh": "基础信息",
          "en": "Basics"
        },
        "blockPage": {
          "zh": "拦截页",
          "en": "Block Page"
        },
        "stage0": {
          "zh": "阶段 0 · 信任名单",
          "en": "Stage 0 · Trust List"
        },
        "stage1": {
          "zh": "阶段 1 · IP 访问控制",
          "en": "Stage 1 · IP Access Control"
        },
        "stage2": {
          "zh": "阶段 2 · 限流",
          "en": "Stage 2 · Rate Limit"
        },
        "stage3": {
          "zh": "阶段 3 · WAF",
          "en": "Stage 3 · WAF"
        },
        "bindings": {
          "zh": "关联规则",
          "en": "Rules"
        },
        "preview": {
          "zh": "配置预览",
          "en": "Preview"
        },
        "stage3Waf": {
          "zh": "阶段 3 · WAF 规则",
          "en": "Stage 3 · WAF Rules"
        }
      },
      "hint": {
        "refCombo": {
          "zh": "内联 {inline} 条 + 引用列表 {refs} 条（合计 {total} 条）",
          "en": "{inline} inline + {refs} from referenced lists ({total} total)"
        }
      },
      "type": {
        "stage0": {
          "zh": "阶段 0 · 信任名单（信任名单直接转发上游；可选保留检测记录）",
          "en": "Stage 0 · Trust list (trusted IPs go straight upstream; optionally keep detection records)"
        },
        "stage1": {
          "zh": "阶段 1 · IP 访问控制（IP 名单 / 地域拦截 / 拦截页）",
          "en": "Stage 1 · IP access control (IP lists / geo blocking / block page)"
        },
        "stage2": {
          "zh": "阶段 2 · 限流（速率上限，拦截恒 429）",
          "en": "Stage 2 · Rate limiting (rate cap; blocking always 429)"
        },
        "stage3": {
          "zh": "阶段 3 · WAF（模式 / CRS / 自定义规则 / 拦截页）",
          "en": "Stage 3 · WAF (mode / CRS / custom rules / block page)"
        }
      },
      "aux": {
        "bindings": {
          "zh": "规则绑定",
          "en": "rule bindings"
        },
        "blockPages": {
          "zh": "拦截页面",
          "en": "block pages"
        },
        "crsOptions": {
          "zh": "CRS 规则选项",
          "en": "CRS rule options"
        },
        "customRules": {
          "zh": "自定义规则",
          "en": "custom rules"
        },
        "ipLists": {
          "zh": "IP 地址列表",
          "en": "IP lists"
        },
        "rules": {
          "zh": "规则列表",
          "en": "rule list"
        },
        "users": {
          "zh": "用户列表",
          "en": "user list"
        }
      },
      "crawler": {
        "baidu": {
          "zh": "百度",
          "en": "Baidu"
        },
        "bytespider": {
          "zh": "字节 Bytespider",
          "en": "ByteDance Bytespider"
        },
        "deepseek": {
          "zh": "DeepSeek（观察级）",
          "en": "DeepSeek (provisional)"
        },
        "gpt": {
          "zh": "OpenAI（GPTBot 等）",
          "en": "OpenAI (GPTBot etc.)"
        },
        "kimi": {
          "zh": "Kimi（观察级）",
          "en": "Kimi (provisional)"
        },
        "petal": {
          "zh": "华为 PetalBot（观察级）",
          "en": "Huawei PetalBot (provisional)"
        },
        "sogou": {
          "zh": "搜狗",
          "en": "Sogou"
        },
        "yisou": {
          "zh": "神马",
          "en": "Yisou"
        }
      },
      "conflict": {
        "contradicts": {
          "zh": "与规则组选择矛盾（排除优先）",
          "en": "Contradicts the rule-group selection (exclusion wins)"
        },
        "redundant": {
          "zh": "冗余：排除优先生效",
          "en": "Redundant: exclusion wins"
        },
        "addrAclDeny": {
          "zh": "地址 {addr} 在「{allow}」的访问控制名单中、同时在「{deny}」的黑名单中——{detail}",
          "en": "Address {addr} is in \"{allow}\"'s access-control list and in \"{deny}\"'s blacklist — {detail}"
        },
        "addrTrustDeny": {
          "zh": "地址 {addr} 在「{allow}」的信任名单中、同时在「{deny}」的黑名单中——{detail}",
          "en": "Address {addr} is in \"{allow}\"'s trust list and in \"{deny}\"'s blacklist — {detail}"
        },
        "allGroups": {
          "zh": "全部规则组",
          "en": "all rule groups"
        },
        "bypassMiddle": {
          "zh": "「{name}」为{mode}模式且夹在拦截策略中间：免检测/白名单仅作用于自身引擎，不会为前后策略放行流量，各策略引擎独立判定、位置不影响拦截效果；如需对特定来源整体放行，请使用免检测名单",
          "en": "\"{name}\" is in {mode} mode and sits between blocking policies: no-inspection/whitelist only affect their own engine and do not let traffic pass neighboring policies — each engine decides independently and position does not change blocking; to allow a specific source wholesale, use a no-inspection list"
        },
        "crsOverlap": {
          "zh": "「{a}」与「{b}」加载了相同的 CRS 规则组（{groups}），同一请求将被重复检测，建议只保留一个",
          "en": "\"{a}\" and \"{b}\" load the same CRS rule groups ({groups}); the same request will be inspected twice — keep only one"
        },
        "duplicateRule": {
          "zh": "自定义规则「{rule}」被 {owners} 重复引用，同一请求会被重复计分/处理，建议只保留一个",
          "en": "Custom rule \"{rule}\" is referenced by {owners} multiple times; the same request would be scored/processed repeatedly — keep only one"
        },
        "fromRefLists": {
          "zh": "（来自引用列表{names}）",
          "en": " (via referenced list(s) {names})"
        },
        "ifCoBoundSuffix": {
          "zh": "（若两策略绑定同一规则）",
          "en": " (if both policies bind the same rule)"
        },
        "moreSuffix": {
          "zh": "；共 {n} 条类似冲突",
          "en": "; {n} similar conflicts in total"
        },
        "passBlock": {
          "zh": "「{earlier}」的放行型自定义规则仅在本策略引擎内跳过匹配、不阻断请求，「{later}」的拦截型规则仍会独立执行；需注意前位拦截策略一旦命中将中断整条链，后位策略只处理前位放行的流量",
          "en": "The pass-type custom rules of \"{earlier}\" only skip matching within their own engine and do not block; the blocking rules of \"{later}\" still run independently. Note that once a leading blocking policy hits, it interrupts the whole chain and later policies only see traffic the earlier ones let pass"
        },
        "selfAclAllow": {
          "zh": "地址 {addr} 在「本策略」的访问控制名单中{src}、同时在「{peer}」的访问控制允许名单中——{detail}{suffix}",
          "en": "Address {addr} is in this policy's access-control list{src} and in \"{peer}\"'s allow list — {detail}{suffix}"
        },
        "selfAclDeny": {
          "zh": "地址 {addr} 在「本策略」的访问控制名单中、同时在「{peer}」的黑名单中——{detail}{suffix}",
          "en": "Address {addr} is in this policy's access-control list and in \"{peer}\"'s blacklist — {detail}{suffix}"
        },
        "selfAclTrust": {
          "zh": "地址 {addr} 在「本策略」的访问控制名单中{src}、同时在「{peer}」的信任名单中——{detail}{suffix}",
          "en": "Address {addr} is in this policy's access-control list{src} and in \"{peer}\"'s trust list — {detail}{suffix}"
        },
        "selfDenyAllow": {
          "zh": "地址 {addr} 在「本策略」的黑名单中、同时在「{peer}」的访问控制允许名单中——{detail}{suffix}",
          "en": "Address {addr} is in this policy's blacklist and in \"{peer}\"'s access-control allow list — {detail}{suffix}"
        },
        "selfDenyTrust": {
          "zh": "地址 {addr} 在「本策略」的黑名单中、同时在「{peer}」的信任名单中——{detail}{suffix}",
          "en": "Address {addr} is in this policy's blacklist and in \"{peer}\"'s trust list — {detail}{suffix}"
        },
        "selfTrustDeny": {
          "zh": "地址 {addr} 在「本策略」的信任名单中{src}、同时在「{peer}」的黑名单中——{detail}{suffix}",
          "en": "Address {addr} is in this policy's trust list{src} and in \"{peer}\"'s blacklist — {detail}{suffix}"
        },
        "crsOverlapIfCoBound": {
          "zh": "{names}也选择了相同的 CRS 规则组（{groups}），若二者绑定同一规则将重复检测",
          "en": "{names} also select the same CRS rule groups ({groups}); if both bind the same rule, requests will be inspected twice"
        },
        "crsOverlapNow": {
          "zh": "{names}已选择相同的 CRS 规则组（{groups}），绑定到同一规则时将被重复检测，建议只保留一个",
          "en": "{names} already select the same CRS rule groups ({groups}); binding both to the same rule would inspect the same request twice — keep only one"
        }
      },
      "stageName": {
        "s1": {
          "zh": "阶段 1",
          "en": "Stage 1"
        },
        "s2": {
          "zh": "阶段 2",
          "en": "Stage 2"
        },
        "s3": {
          "zh": "阶段 3",
          "en": "Stage 3"
        }
      }
    }
  }
}
} as const
