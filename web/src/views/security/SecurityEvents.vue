<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Warning /></el-icon>
          事件日志
        </h2>
        <p class="page-desc">查看安全拦截与检测事件记录</p>
      </div>
      <!-- 刷新联动自动封禁状态卡——建议列表/今日封禁/名单数不再
           停留在进入页面时的快照 -->
      <el-button :icon="Refresh" @click="refreshPage">刷新</el-button>
    </div>

    <!-- 自动封禁状态卡：状态/口径/窗口/阈值/时长/今日封禁/名单数；
         配置入口=点击卡片主体（2026-10-14 裁定：废除「配置」按钮），按钮区仅留
         启用/禁用 toggle（直接切换业务开关并联动调度；「立即执行」废除——任务只能
         由「启用后按配置调度执行」） -->
    <el-card class="autoban-card" v-loading="autobanStatusLoading">
      <div v-if="autobanStatusError" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">自动封禁状态加载失败：控制项已禁用（不影响事件日志主功能），请稍后刷新重试。</span>
      </div>
      <div v-else-if="autobanBlockedReason" class="info-note-bar">
        <span class="info-note-desc">{{ autobanBlockedReason }}</span>
      </div>
      <div class="autoban-bar">
        <el-tooltip :content="autobanConfigTooltip" :disabled="autobanWritable" placement="top" :show-after="200">
          <div
            class="autoban-main"
            :class="{ 'is-disabled': !autobanWritable }"
            :role="autobanWritable ? 'button' : undefined"
            :tabindex="autobanWritable ? 0 : -1"
            :aria-disabled="!autobanWritable"
            @click="openAutobanConfig"
            @keydown.enter.prevent="activateOnce($event, openAutobanConfig)"
            @keydown.space.prevent="activateOnce($event, openAutobanConfig)"
          >
            <div class="autoban-title">
              <el-icon class="title-icon"><Lock /></el-icon>
              <span>自动封禁</span>
              <el-tag :type="autobanStatusError ? 'info' : autobanStatus.enabled ? (autobanStatus.dry_run ? 'warning' : 'success') : 'info'" size="small" effect="plain">
                {{ autobanStateLabel(autobanStatusError, autobanStatus.enabled, autobanStatus.dry_run) }}
              </el-tag>
              <!-- 调度仅主节点执行——从端徽章标示+写按钮禁用。加载/读取失败均不渲染：
                   初值 is_master=false 会在未知态谎称「仅主节点调度」，且徽章闪现会把参数区推向右侧 -->
              <el-tag v-if="!autobanStatusLoading && !autobanStatusError && !autobanStatus.is_master" type="info" size="small" effect="plain">仅主节点调度</el-tag>
            </div>
            <div class="autoban-stats">
              <span class="autoban-stat">口径 <b>{{ autobanStatValue(autobanStatusError, autobanScopeText) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">窗口 <b>{{ autobanStatValue(autobanStatusError, autobanStatus.window_minutes, ' 分钟') }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">阈值 <b>{{ autobanStatValue(autobanStatusError, autobanStatus.threshold, ' 次') }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">时长 <b>{{ autobanStatValue(autobanStatusError, autobanDurationText) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">今日封禁 <b class="autoban-danger">{{ autobanStatValue(autobanStatusError, autobanStatus.banned_today) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">名单 <b>{{ autobanStatValue(autobanStatusError, autobanStatus.list_entries, ' 条') }}</b></span>
            </div>
          </div>
        </el-tooltip>
        <div class="autoban-actions">
          <template v-if="autobanStatus.enabled">
            <el-button size="small" type="danger" plain :disabled="!autobanWritable" :loading="autobanToggling" @click="toggleAutobanEnabled">禁用</el-button>
            <el-button size="small" plain :disabled="!autobanWritable" @click="openAutobanConfig">编辑</el-button>
          </template>
          <el-button v-else size="small" type="success" plain :disabled="!autobanWritable" @click="openAutobanConfigForEnable">启用</el-button>
        </div>
      </div>
      <!-- 未生效黄条：判据=ban_effective（名单非空且被启用+deny 的策略引用），
           不再用 list_referenced（四面引用集会把「仅被白名单/受信代理引用」误当生效） -->
      <div v-if="autobanIneffective" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">「自动封禁名单」尚未生效——名单为空，或尚未被启用中的 IP 访问控制（deny）策略引用；请到「安全规则 → IP 地址列表」将该名单引用到 IP 访问控制（deny）策略</span>
      </div>
      <!-- 喂入源降级：补采/轮转停摆或写侧持续失败时披露原因。实时 IPC 入库仍在
           运行并继续喂入计数器——兜底文案不得声称「计数不会增长」 -->
      <div v-if="autobanFeedDegraded" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">数据源降级：{{ autobanStatus.feed_degraded_reason || '安全事件补采/日志轮转已暂停，实时 IPC 入库仍在运行（自动封禁计数仍会随实时事件增长）' }}</span>
      </div>
      <!-- 观察模式建议列表：dry-run 下达阈值 IP（不封禁，供评估阈值/口径） -->
      <template v-if="autobanStatus.enabled && autobanStatus.dry_run && (autobanStatus.suggestions?.length ?? 0) > 0">
        <div class="info-note-bar autoban-warn-bar">
          <span class="info-note-desc">观察模式：以下 IP 在 {{ autobanStatus.window_minutes }} 分钟窗口内达到 {{ autobanStatus.threshold }} 次阈值（仅记录建议，不写入名单）</span>
        </div>
        <el-table :data="autobanStatus.suggestions" size="small" max-height="320" :header-cell-style="{ background: '#f9fafb' }">
          <el-table-column label="IP" min-width="230">
            <template #default="{ row }">
              <!-- 快捷处置弹框与事件表同款（无规则上下文：组件回退全量启用策略，SecurityOverview top_ips 同形态） -->
              <IPLocationAction :ip="row.ip" :location="row.ip_location || ''" />
            </template>
          </el-table-column>
          <el-table-column label="命中次数" width="110" align="center" sortable :sort-by="'count'" :sort-orders="['descending']">
            <template #default="{ row }"><span :style="suggestionCountStyle(row.count)">{{ row.count }}</span></template>
          </el-table-column>
          <el-table-column label="阈值倍数" min-width="150" align="center">
            <template #default="{ row }">
              <el-progress :percentage="Math.min(100, Math.round(row.count / Math.max(1, autobanStatus.threshold) * 100))" :stroke-width="8" :show-text="false" :color="suggestionProgressColor(row.count)" style="max-width: 130px; display: inline-block; vertical-align: middle;" />
              <span class="text-secondary" style="margin-left: 6px;">{{ (row.count / Math.max(1, autobanStatus.threshold)).toFixed(1) }}×</span>
            </template>
          </el-table-column>
          <el-table-column label="窗口内首末" min-width="190">
            <template #default="{ row }"><span class="text-secondary">{{ suggestionWindowSpan(row as AutobanSuggestion) }}</span></template>
          </el-table-column>
          <el-table-column label="建议时长" width="100" align="center">
            <template #default>
              <el-tag size="small" effect="plain" type="warning">{{ autobanDurationText }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        <div class="form-tip-inline" v-if="(autobanStatus.suggestions?.length ?? 0) >= 50">仅展示命中次数最多的前 50 条，完整建议见任务日志</div>
      </template>
    </el-card>

    <el-card>
      <div v-if="ingestionWarning" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">{{ ingestionWarning }}</span>
      </div>
      <div class="table-toolbar">
        <el-date-picker
          v-model="filters.timeRange"
          name="event-time-range"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="events-filter-date-range"
        />
        <el-select v-model="filters.action" placeholder="动作" clearable style="width: 90px">
          <el-option label="拦截" value="blocked" />
          <el-option label="检测" value="logged" />
        </el-select>
        <!-- （用户需求）：规则 ID 筛选替换为三列（负载规则/触发规则/策略）
             服务端筛选（rule_name/rule_triggered/policy_name LIKE）。 -->
        <el-input v-model="filters.rule_name" placeholder="负载规则" clearable style="width: 100px" @keyup.enter="applyFilters" />
        <!-- 触发规则筛选：多选 + 头部全选（勾的就是看的，统一正向心智）。
             全选（八类全中且无自定义 tag）或空选 = 不过滤，不发送参数；子集或含
             自定义 tag 时全部选中值英文逗号连接发送 rule_triggered（后端逐段按
             family/前缀/纯数字 ID 解析，OR 连接）。filterable + allow-create：可直接
             输入 CRS 规则 ID（如 942100）等自定义 tag 混入同一参数；自定义 tag 不参与
             全选判定（只看 8 个类别是否全中）。 -->
        <el-select
          v-model="filters.rule_triggered"
          multiple
          filterable
          allow-create
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="1"
          placeholder="触发阶段 / 规则 ID"
          style="width: 170px"
          popper-class="triggered-filter-popper"
        >
          <template #header>
            <el-checkbox
              :model-value="triggeredCheckAll"
              :indeterminate="triggeredIndeterminate"
              @change="toggleTriggeredAll"
            >全选</el-checkbox>
          </template>
          <el-option label="爬虫Bot" value="爬虫Bot" title="已验证爬虫放行/伪装（id 810000-899999）" />
          <el-option label="地域拦截" value="地域拦截" title="GeoIP 地域拦截（id 8/800xxx）" />
          <!-- 限流（429）不进安全事件表（caddy-ratelimit 直接返回、无审计行）：
               筛选选项移除，限流数据看安全总览「限流拦截」卡片。 -->
          <el-option label="IP 访问控制" value="IP 访问控制" title="IP ACL 黑白名单与自维护黑名单（id 2/4/7）" />
          <el-option label="信任名单" value="信任名单" title="信任名单/保留检测（id 3/12）" />
          <el-option label="威胁情报库" value="威胁情报库" title="威胁情报库命中（id 14）" />
          <el-option label="请求体异常" value="请求体异常" title="请求体解析失败（id 11）" />
          <el-option label="WAF·CRS" value="WAF·CRS" title="OWASP CRS 规则全集（9xxxxx）" />
          <el-option label="WAF·自定义" value="WAF·自定义" title="自定义规则库（含 AND 链式规则、OR 条件分支与旧版合成规则）" />
        </el-select>
        <el-input v-model="filters.policy_name" placeholder="策略" clearable style="width: 90px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.ip" placeholder="IP 地址" clearable style="width: 115px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.uri" placeholder="URI" clearable style="width: 115px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
      </div>

      <el-alert v-if="eventsLoadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
        <template #title>
          <div class="polling-error-title">
            <span>{{ events.length > 0 ? '安全事件加载失败：当前显示的是上次成功结果（与筛选/分页条件不符）' : '安全事件加载失败：表格为空不代表没有事件' }}</span>
            <el-button link type="danger" :loading="loading" @click="fetchEvents">立即重试</el-button>
          </div>
        </template>
      </el-alert>

      <el-table :data="events" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty description="暂无安全事件" :image-size="60" /></template>
        <el-table-column prop="event_time" label="时间" width="190" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
        <el-table-column label="动作" width="80" align="center">
          <template #default="{ row }">
            <el-tag :type="eventActionTone(row.action)" size="small" effect="light">{{ eventActionShort(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="规则" min-width="130">
          <template #default="{ row }">
            <AccessibleLink v-if="row.rule_name || row.rule_caddy_id" type="primary" @click="goToRule(row as SecurityEvent)">{{ row.rule_name || row.rule_caddy_id || '—' }}</AccessibleLink>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="触发阶段" min-width="100" class-name="col-nowrap">
          <template #default="{ row }">
            <!-- 触发阶段展示：信任名单 / IP 访问控制（黑白名单+地域+威胁库，点击看触发详情）/
                 WAF（CRS=详情+快捷排除弹框；自定义=规则详情弹框）/ 请求体异常（纯文本） -->
            <AccessibleLink v-if="stageCategory(row as SecurityEvent) === 'waf'" type="primary" @click="openTriggerDetail(row as SecurityEvent)">WAF</AccessibleLink>
            <AccessibleLink v-else-if="['acl', 'crawler', 'trust'].includes(stageCategory(row as SecurityEvent))" type="primary" @click="openTriggerDetail(row as SecurityEvent)">{{ stageLabel(row as SecurityEvent) }}</AccessibleLink>
            <el-tooltip v-else-if="showTriggeredMsg(row as SecurityEvent)" :content="row.rule_msg" placement="top" :show-after="200" :trigger="['hover', 'focus']">
              <span class="cell-tip" tabindex="0" :aria-label="row.rule_msg">{{ stageLabel(row as SecurityEvent) }}</span>
            </el-tooltip>
            <span v-else>{{ stageLabel(row as SecurityEvent) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="触发类型" min-width="100" class-name="col-nowrap">
          <template #default="{ row }">
            <span>{{ row.trigger_type || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="策略" min-width="150">
          <template #default="{ row }">
            <AccessibleLink v-if="row.policy_name || row.policy_id > 0" type="primary" @click="goToPolicy(row as SecurityEvent)">{{ row.policy_name || row.policy_id }}</AccessibleLink>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <!-- 用户裁定:内容上限 ~190-200px(IPv4 126+gap+归属地 72),定宽 200 不再挤占方法/URI-->
        <el-table-column label="客户端 IP" width="200">
          <template #default="{ row }">
            <IPLocationAction :ip="row.client_ip" :location="row.ip_location" />
          </template>
        </el-table-column>
        <!-- OPTIONS 为最长方法名(7 字符),90 定宽 -->
        <el-table-column prop="method" label="方法" width="90" align="center" />
        <el-table-column prop="uri" label="URI" min-width="140" show-overflow-tooltip />
        <!-- （用户需求）：异常评分列——CRS 评分制下每事件携带的累计
             anomaly_score（后端已返回，此前未展示）；按分数着色便于快速识别高威胁。
             分档与大屏定级同源（utils/severityScale：≥12 高 / ≥6 中）——
             原列表 ≥15/≥5 与大屏 ≥12/≥6 双口径，同分不同色结论打架。 -->
        <el-table-column label="评分" width="80" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.anomaly_score >= ANOMALY_SCORE_HIGH" type="danger" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <el-tag v-else-if="row.anomaly_score >= ANOMALY_SCORE_MID" type="warning" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <el-tag v-else-if="row.anomaly_score > 0" type="info" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="70" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openCtxDialog(row as SecurityEvent)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="events-footer">
        <!-- 统计口径：安全事件主容量 = 事件行数/行帽（库内真实容量），另附待补采
             缓存条数（IPC 正常时恒为 0）与库体量；audit.log 文件体量不再当作
             该行容量展示（写入侧同文件、随轮转与缓存漂移，会误导容量判断）。 -->
        <LogStorageBar log-key="security_events" :refresh-key="logStorageRefreshKey" class="events-storage" />
        <el-pagination
          class="events-pagination"
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="handleSizeChange"
          @current-change="fetchEvents"
        />
      </div>
    </el-card>

    <!-- 触发详情弹框（统一）：全部触发类型共用同一风格与交互；
         信息优先展示，IP 处置动作收敛到 IP 快捷弹框（列表中点击 IP） -->
    <TriggerDetailDialog v-model="triggerDetailVisible" :row="triggerDetailRow" />

    <!-- 自动封禁配置弹框：六项配置+口径/窗口变更重置提示-->
    <el-dialog v-model="autobanDialogVisible" width="min(600px, 94vw)" top="8vh" append-to-body class="dialog-body-inset" :close-on-click-modal="false" :close-on-press-escape="!autobanSaving" :show-close="!autobanSaving">
      <template #header>
        <!-- 喂入门只排除「已验证爬虫豁免」事件，ACL/GeoIP/威胁情报事件
             同样计数——文案不得自缩为「WAF 事件」，否则用户按「只有 WAF 命中才
             计数」校准阈值会过早封禁 -->
        <DialogHeader :icon="Lock" title="自动封禁配置" subtitle="安全事件（IP 访问控制/地域/WAF/威胁情报，已验证爬虫豁免除外）固定窗口计数达到阈值即写入「自动封禁名单」（调度开启时到期自动解封）" />
      </template>
      <el-form :model="autobanForm" label-width="96px" label-position="right" :disabled="autobanSaving">
        <el-form-item label="观察模式">
          <el-switch v-model="autobanForm.dry_run" />
          <div class="form-tip-line">开启时仅记录达阈值建议、不写入名单（推荐先观察校准阈值）</div>
        </el-form-item>
        <el-form-item label="统计口径">
          <el-radio-group v-model="autobanForm.scope">
            <el-radio v-for="s in AUTOBAN_SCOPES" :key="s.value" :value="s.value">{{ s.label }}</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="统计窗口">
          <el-input-number v-model="autobanForm.window_minutes" :min="1" :max="60" :step="5" controls-position="right" style="width: 140px" />
          <div class="form-tip-line">分钟（同一 IP 窗口内累计计数，跨窗口自动重置）</div>
        </el-form-item>
        <el-form-item label="封禁阈值">
          <el-input-number v-model="autobanForm.threshold" :min="1" :max="10000" :step="10" controls-position="right" style="width: 140px" />
          <div class="form-tip-line">窗口内命中次数</div>
        </el-form-item>
        <el-form-item label="封禁时长">
          <el-select v-model="autobanForm.duration" style="width: 160px">
            <el-option v-for="d in AUTOBAN_DURATIONS" :key="d.value" :label="d.label" :value="d.value" />
          </el-select>
          <div class="form-tip-line">到期自动解封（从名单移除）</div>
        </el-form-item>
      </el-form>
      <div class="info-note-bar"><span class="info-note-desc">修改统计窗口或口径会立即重置计数器（旧计数与新口径不可混算）</span></div>
      <template #footer>
        <el-button :disabled="autobanSaving" @click="autobanDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="autobanSaving" :disabled="!autobanWritable" @click="saveAutobanConfig">保存</el-button>
      </template>
    </el-dialog>

    <!-- 请求上下文详情：策略开启「记录请求体」后，命中规则事件携带的请求头/请求体。
         请求头为 map[string][]string JSON 文本（多值以 ", " 连接；Cookie/Authorization/
         Set-Cookie/Proxy-Authorization 值默认掩码，逐行眼睛图标点击显示）；合成键
         _lb_dropped_headers（采集 64KB）与 _lb_list_dropped_headers（列表 16KB）渲染为
         信息行而非头行。请求体按契约前缀解析：base64-truncated: →
         base64: → 明文；明文尾部 \n...[TRUNCATED] 标记转为截断横幅；atob 解码失败
         展示原始内容 + 错误说明。宽度/顶距与 crs-event-dialog 一致。 -->
    <el-dialog v-model="ctxDialogVisible" width="min(760px, 94vw)" top="5vh" append-to-body class="ctx-event-dialog dialog-body-inset">
      <template #header>
        <DialogHeader :icon="Document" title="请求详情"
          :subtitle="`${ctxEvent ? formatDate(ctxEvent.event_time) : '—'} · ${ctxEvent?.policy_name || '未知策略'}`" />
      </template>
      <template v-if="ctxEvent">
        <section class="ctx-detail-section">
          <DialogSectionHeader title="请求摘要" />
          <div class="dialog-panel dialog-panel--flush">
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="时间">{{ ctxEvent.event_time ? formatDate(ctxEvent.event_time) : '—' }}</el-descriptions-item>
              <el-descriptions-item label="方法">{{ ctxEvent.method || '—' }}</el-descriptions-item>
              <el-descriptions-item label="客户端 IP">{{ ctxEvent.client_ip || '—' }}</el-descriptions-item>
              <el-descriptions-item label="归属地">{{ ctxEvent.ip_location || '—' }}</el-descriptions-item>
              <el-descriptions-item label="URI" :span="2">{{ ctxEvent.uri || '—' }}</el-descriptions-item>
              <el-descriptions-item label="触发规则">{{ [ctxEvent.rule_name, ctxEvent.rule_triggered ? `id:${ctxEvent.rule_triggered}` : ''].filter(Boolean).join(' · ') || '—' }}</el-descriptions-item>
              <el-descriptions-item label="所属策略">{{ ctxEvent.policy_name || '—' }}</el-descriptions-item>
              <el-descriptions-item label="动作">
                <el-tag size="small" :type="eventActionTone(ctxEvent.action)" effect="plain">
                  {{ eventActionFull(ctxEvent.action) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="异常评分">{{ ctxEvent.anomaly_score > 0 ? ctxEvent.anomaly_score : '—' }}</el-descriptions-item>
              <el-descriptions-item label="处理时长">{{ formatDurationUs(ctxWafFamily ? ctxEvent.duration_us + ctxEvent.precheck_us : ctxEvent.duration_us) }}{{ ctxWafFamily ? '' : '（预检耗时，含事件记录开销）' }}</el-descriptions-item>
              <el-descriptions-item v-if="ctxWafFamily && ctxEvent.precheck_us > 0" label="耗时分解">预检 {{ formatDurationUs(ctxEvent.precheck_us) }} + WAF 段 {{ formatDurationUs(ctxEvent.duration_us) }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </section>

        <section class="ctx-detail-section">
          <DialogSectionHeader title="请求头" />
          <template v-if="ctxHeadersParsed.failed">
            <div class="info-note-bar ctx-banner"><span class="info-note-desc">请求头记录解析失败，以下为原始内容</span></div>
            <div class="dialog-panel dialog-panel--flush"><pre class="ctx-body-pre">{{ ctxEvent.request_headers }}</pre></div>
          </template>
          <template v-else-if="ctxHeadersParsed.rows.length > 0 || ctxHeadersParsed.dropped > 0 || ctxHeadersParsed.listDropped > 0">
            <div class="dialog-panel" :class="{ 'dialog-panel--flush': ctxHeadersParsed.rows.length > 0 }">
              <div v-if="ctxHeadersParsed.dropped > 0" class="ctx-info-line">已隐藏 {{ ctxHeadersParsed.dropped }} 个头（请求头超出 64KB 采集上限）</div>
              <div v-if="ctxHeadersParsed.listDropped > 0" class="ctx-info-line">已隐藏 {{ ctxHeadersParsed.listDropped }} 个头（请求头超出列表 16KB 展示上限）</div>
              <el-table v-if="ctxHeadersParsed.rows.length > 0" :data="ctxHeadersParsed.rows" size="small" :max-height="260" :header-cell-style="{ background: '#f9fafb' }">
                <el-table-column prop="name" label="名称" width="200" show-overflow-tooltip />
                <el-table-column label="值" min-width="380">
                  <template #default="{ row }">
                    <div class="ctx-header-value-cell">
                      <span class="ctx-header-value">{{ ctxHeaderDisplay(row as CtxHeaderRow) }}</span>
                      <el-button
                        v-if="row.sensitive"
                        link
                        type="primary"
                        size="small"
                        class="ctx-reveal-btn"
                        :title="ctxRevealed.has(row.name.toLowerCase()) ? '点击隐藏' : '点击显示'"
                        @click="toggleCtxReveal(row.name)"
                      >
                        <el-icon><Hide v-if="ctxRevealed.has(row.name.toLowerCase())" /><View v-else /></el-icon>
                      </el-button>
                    </div>
                  </template>
                </el-table-column>
              </el-table>
            </div>
          </template>
          <div v-else class="dialog-panel"><div class="ctx-empty">暂无请求头记录</div></div>
        </section>

        <section class="ctx-detail-section">
          <DialogSectionHeader title="请求体" />
          <div v-if="ctxBodyParsed.state === 'empty'" class="dialog-panel"><div class="ctx-empty">{{ ctxBodyEmptyText }}</div></div>
          <template v-else>
            <div v-if="ctxBodyParsed.truncated" class="info-note-bar ctx-banner"><span class="info-note-desc">请求体已截断，仅显示保留的前段内容</span></div>
            <div v-if="ctxBodyParsed.binary" class="info-note-bar"><span class="info-note-desc">请求体为二进制内容，已按 Base64 解码展示，可能包含不可读字符</span></div>
            <div v-if="ctxBodyParsed.state === 'error'" class="info-note-bar ctx-banner"><span class="info-note-desc">Base64 解码失败，以下为原始内容</span></div>
            <div class="dialog-panel dialog-panel--flush"><pre class="ctx-body-pre">{{ ctxBodyParsed.text }}</pre></div>
          </template>
        </section>
      </template>
      <template #footer>
        <el-button @click="ctxDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Refresh, Warning, View, Hide, Document, Lock } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { CheckboxValueType } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import LogStorageBar from '@/components/LogStorageBar.vue'
import TriggerDetailDialog from '@/components/events/TriggerDetailDialog.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import { formatDurationUs, isWafDurationFamily, triggerStageFamily } from '@/utils/securityStages'
import { TRIGGERED_CATEGORIES, serializeTriggeredFilter, CRAWLER_FAMILY_LABEL } from '@/utils/triggeredFilter'
import { ANOMALY_SCORE_HIGH, ANOMALY_SCORE_MID } from '@/utils/severityScale'
import { DEEP_LINK_PARAMS, pageUrl } from '@/utils/deepLink'
import { autobanStateLabel, autobanStatValue, isAutobanIneffective, suggestionBand, type SuggestionBand } from '@/utils/autobanStatus'
import { requestBodyEmptyNotice, viewerCanReadRequestBody } from '@/utils/requestBodyAccess'
import { activateOnce } from '@/utils/keyboardActivate'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import { formatDate } from '@/utils/date'
import { eventActionFull, eventActionShort, eventActionTone } from '@/utils/eventAction'
import { ingestionWarningMessage, type IngestionHealth } from '@/utils/ingestionHealth'
import type { APIResponse } from '@/types'

interface SecurityEvent { id: number; event_time: string; rule_caddy_id: string; rule_name: string; policy_id: number; policy_name: string; client_ip: string; ip_location: string; method: string; uri: string; event_type: string; rule_triggered: string; rule_msg: string; trigger_type?: string; action: string; anomaly_score: number; duration_us: number; precheck_us: number; request_headers: string; request_body: string }

// 自动封禁：状态卡/配置弹框 ——

interface AutobanSuggestion { ip: string; count: number; ip_location?: string; window_start?: string; last_seen?: string }
interface AutobanStatus {
  enabled: boolean; dry_run: boolean; threshold: number; window_minutes: number
  duration: string; scope: string; banned_today: number; list_entries: number
  // 黄条判据 = 封禁是否真正生效（名单非空 ∧ 被启用+IP ACL 启用+deny 的
  // 策略在 ip_acl_list_refs 引用）。后端 list_referenced 为热路径资格门的四面
  // 引用集（含白名单/受信代理/CRS 排除），不能区分「引用」与「拦截生效」——
  // 纯后端内部字段，本卡不声明不消费。
  ban_effective: boolean
  // 喂入源（安全事件补采/日志轮转）健康：补采停摆或写侧持续失败时计数可能
  // 偏少，状态卡据此就近提示降级原因并说明实时 IPC 入库仍在运行（不自动
  // 拉起用户显式停止的采集任务）。
  feed_degraded: boolean
  feed_degraded_reason: string
  suggestions: AutobanSuggestion[]
  // 后端另有 running/last_run/last_status/role/tracked_ips（API 契约保留）——
  // 本卡零消费，不再声明。
  is_master: boolean
}
const AUTOBAN_DURATIONS = [
  { value: '10m', label: '10 分钟' }, { value: '30m', label: '30 分钟' },
  { value: '1h', label: '1 小时' }, { value: '6h', label: '6 小时' },
  { value: '12h', label: '12 小时' }, { value: '24h', label: '24 小时' },
  { value: 'permanent', label: '永久' },
]
const AUTOBAN_SCOPES = [
  { value: 'all', label: '全部事件' }, { value: 'blocked', label: '仅拦截' }, { value: 'logged', label: '仅检测' },
]

const autobanStatus = ref<AutobanStatus>({
  enabled: false, dry_run: true, threshold: 100, window_minutes: 5, duration: '1h', scope: 'all',
  banned_today: 0, list_entries: 0, ban_effective: true, suggestions: [],
  // 成功响应前不得假定喂入源健康（默认 false：无额外黄条）
  feed_degraded: false, feed_degraded_reason: '',
  // 默认 false：成功响应前不得假定主节点可写
  is_master: false,
})
const autobanStatusLoading = ref(true)
const autobanToggling = ref(false)
// 状态读取失败：错误态不得按「确定状态」展示——写入口一律禁用
const autobanStatusError = ref(false)
// 黄条判据单源（utils/autobanStatus，行为钉测）：仅 enabled ∧ ban_effective===false
const autobanIneffective = computed(() => isAutobanIneffective(autobanStatus.value))
// 喂入源降级：仅在启用时提示（未启用时「不计数」无需解释）
const autobanFeedDegraded = computed(() => autobanStatus.value.enabled && autobanStatus.value.feed_degraded === true)
const authStore = useAuthStore()
// 四写入口统一门控（启用/禁用/编辑/保存）：全局只读契约 ∧ 主节点 ∧ 状态已加载
const autobanWritable = computed(() => authStore.readOnlyReason === null && autobanStatus.value.is_master && !autobanStatusError.value && !autobanStatusLoading.value)
const autobanBlockedReason = computed(() => {
  if (authStore.readOnlyReason !== null) return authStore.readOnlyMessage
  if (!autobanStatus.value.is_master) return '仅主节点可修改自动封禁配置'
  return ''
})
const autobanConfigTooltip = computed(() => {
  if (autobanWritable.value) return ''
  if (autobanStatusLoading.value) return '自动封禁状态加载中，暂不可配置'
  if (autobanStatusError.value) return '自动封禁状态加载失败，请刷新后重试'
  return autobanBlockedReason.value
})
const autobanScopeText = computed(() => AUTOBAN_SCOPES.find((s) => s.value === autobanStatus.value.scope)?.label ?? autobanStatus.value.scope)
const autobanDurationText = computed(() => AUTOBAN_DURATIONS.find((d) => d.value === autobanStatus.value.duration)?.label ?? autobanStatus.value.duration)

// 命中次数色深（命中越多越深）：档位判据单源 utils/autobanStatus 的 suggestionBand，
// 此处只做「档位 → 样式/颜色」映射。
const SUGGESTION_COUNT_STYLE: Record<SuggestionBand, string> = {
  high: 'color:#991b1b;font-weight:700',
  mid: 'color:#dc2626;font-weight:600',
  low: 'color:#ef4444',
}
const SUGGESTION_PROGRESS_COLOR: Record<SuggestionBand, string> = {
  high: '#991b1b',
  mid: '#dc2626',
  low: '#ef4444',
}
const suggestionCountStyle = (count: number): string => SUGGESTION_COUNT_STYLE[suggestionBand(count, autobanStatus.value.threshold)]

// 阈值倍数进度条配色（与命中次数色深同档）
const suggestionProgressColor = (count: number): string => SUGGESTION_PROGRESS_COLOR[suggestionBand(count, autobanStatus.value.threshold)]

// 建议窗口首末（同一统计窗口内通常同日）：同日展示「时刻 ~ 时刻」，
// 跨日展示完整起止；任一端缺失按 '—'。
const suggestionWindowSpan = (row: AutobanSuggestion): string => {
  const start = formatDate(row.window_start)
  const end = formatDate(row.last_seen)
  if (!start || !end) return '—'
  if (start.length < 19 || end.length < 19) return `${start} ~ ${end}`
  return start.slice(0, 10) === end.slice(0, 10) ? `${start.slice(11)} ~ ${end.slice(11)}` : `${start} ~ ${end}`
}

// 自动封禁状态读取会话序号：仅最新一次可写状态/错误位——连点刷新时
// 旧响应不得覆盖新状态（否则配置弹框按旧值回填、保存写回旧配置），
// 迟到的瞬时失败也不得把已成功的最新状态锁成错误态。
let autobanStatusSeq = 0
const fetchAutobanStatus = async (): Promise<void> => {
  const requestSeq = ++autobanStatusSeq
  autobanStatusLoading.value = true
  try {
    const res = await request.get<APIResponse<AutobanStatus>>('/security/autoban/status', { silent: true })
    if (requestSeq !== autobanStatusSeq) return
    if (res.data) autobanStatus.value = res.data
    autobanStatusError.value = false
  } catch {
    // 显性错误态：不再退化为「未启用」默认值并放行写按钮
    if (requestSeq !== autobanStatusSeq) return
    autobanStatusError.value = true
  }
  finally { if (requestSeq === autobanStatusSeq) autobanStatusLoading.value = false }
}

// 配置弹框（七项=六项配置+口径变更提示）
const autobanDialogVisible = ref(false)
const autobanSaving = ref(false)
const autobanForm = ref({ dry_run: true, threshold: 100, window_minutes: 5, duration: '1h', scope: 'all' })
const openAutobanConfig = (): void => {
  // 卡片主体/编辑/启用共用门：只读、从节点、状态加载中或加载失败均不打开
  // 配置弹框；表单从 autobanStatus 回填，错误态默认值保存会覆盖真实配置。
  if (!autobanWritable.value) return
  autobanForm.value = {
    dry_run: autobanStatus.value.dry_run,
    threshold: autobanStatus.value.threshold, window_minutes: autobanStatus.value.window_minutes,
    duration: autobanStatus.value.duration, scope: autobanStatus.value.scope,
  }
  autobanDialogVisible.value = true
}
const saveAutobanConfig = async (): Promise<void> => {
  // 函数级纵深守卫（与 openAutobanConfig 同构）：按钮 :disabled 仅呈现层
  if (!autobanWritable.value) return
  if (autobanForm.value.threshold < 1 || autobanForm.value.threshold > 10000) {
    ElMessage.warning('阈值须在 1-10000 之间'); return
  }
  if (autobanForm.value.window_minutes < 1 || autobanForm.value.window_minutes > 60) {
    ElMessage.warning('统计窗口须在 1-60 分钟之间'); return
  }
  // 保存二次确认（用户裁定 2026-10-14）：启用入口=完整须知+建议框（按钮「确认启用」）；
  // 已启用的编辑入口=简化确认（按钮「确认保存」，不带启用描述警告）。
  // 弹框无启用开关（外卡片持有启停职责）——payload enabled 恒 true（启用或保持）。
  if (autobanStatus.value.enabled) {
    try {
      await ElMessageBox.confirm('确认保存自动封禁配置？新配置将在下一轮调度生效。', '保存配置', {
        confirmButtonText: '确认保存', cancelButtonText: '取消', type: 'info',
      })
    } catch { return }
  } else if (!(await confirmAutobanApply())) return
  autobanSaving.value = true
  try {
    await request.put('/security/autoban', { ...autobanForm.value, enabled: true })
    mfaAwareSuccess('自动封禁配置已更新')
    autobanDialogVisible.value = false
    fetchAutobanStatus()
  } catch { /* 错误已由全局拦截器 toast */ }
  finally { autobanSaving.value = false }
}

// 启用二次确认（2026-10-14 用户裁定）：enabled 关→开的保存动作先确认——
// 威胁库+CRS+地域拦截已覆盖绝大多数恶意请求，自动封禁定位是少量高频攻击者
// 的资源救济；建议观察模式起步校准后转正式。取消=不保存。
// 排版：dangerouslyUseHTMLString 精排两段（启用前须知三条列表 + 使用建议正文），
// MessageBox 挂 body → 样式放非 scoped 块。纯静态文案、无任何用户输入插值，无注入面。
const AUTOBAN_ENABLE_CONFIRM_HTML = `
<div class="autoban-confirm">
  <div class="autoban-confirm-hero">
    <div class="autoban-confirm-icon"><svg viewBox="0 0 1024 1024" width="22" height="22"><path d="M512 64a448 448 0 1 1 0 896 448 448 0 0 1 0-896z m0 192a32 32 0 0 0-32 32v256a32 32 0 0 0 64 0V288a32 32 0 0 0-32-32z m0 416a48 48 0 1 0 0-96 48 48 0 0 0 0 96z" fill="currentColor"/></svg></div>
    <div class="autoban-confirm-head">
      <div class="autoban-confirm-heading">确认启用自动封禁？</div>
      <div class="autoban-confirm-sub">达到阈值的 IP 将被自动加入封禁名单，到期自动解封</div>
    </div>
  </div>
  <div class="autoban-confirm-notes">
    <div class="autoban-confirm-note"><span class="autoban-confirm-dot"></span>新封禁约 1 分钟内生效，重载时长连接可能被重置</div>
    <div class="autoban-confirm-note"><span class="autoban-confirm-dot"></span>持续攻击时每分钟至多一次重载，有少量性能开销</div>
    <div class="autoban-confirm-note"><span class="autoban-confirm-dot"></span>建议先以观察模式运行，确认建议准确后再正式封禁</div>
  </div>
  <div class="autoban-confirm-howto"><span class="autoban-confirm-howto-label">生效方式</span>在 IP 访问控制（黑名单）策略中引用「自动封禁名单」地址列表</div>
</div>`
const confirmAutobanApply = async (): Promise<boolean> => {
  try {
    await ElMessageBox.confirm(AUTOBAN_ENABLE_CONFIRM_HTML, '启用自动封禁', {
      confirmButtonText: '确认启用',
      cancelButtonText: '取消',
      dangerouslyUseHTMLString: true,
      customClass: 'autoban-confirm-box',
      customStyle: { width: '540px', paddingTop: '16px' },
    })
    return true
  } catch {
    return false
  }
}

// 启用/禁用直切业务开关（2026-10-14 裁定）：保存即联动调度——enabled=true
// 开 autoban 循环调度、false 停。PUT 需全量六项配置，从状态卡实态回填。
// 启用入口（用户裁定 2026-10-14）：先弹配置框（表单预置开启），在配置框内
// 保存/启用时才弹启用确认框——卡片按钮不直接确认启用。
const openAutobanConfigForEnable = (): void => {
  openAutobanConfig()
}

const toggleAutobanEnabled = async (): Promise<void> => {
  // 守卫：仅在已启用状态执行禁用（此前条件写反致禁用按钮无效——用户报告修复）；
  // autobanWritable 函数级纵深门（与 openAutobanConfig/saveAutobanConfig 同构）
  if (autobanToggling.value || !autobanStatus.value.enabled || !autobanWritable.value) return
  autobanToggling.value = true
  try {
    await ElMessageBox.confirm(
      '确认禁用自动封禁？任务调度将停止，禁用时会立即清除已到期的封禁条目并即时生效；未到期条目保留至到期自动失效。',
      '禁用自动封禁',
      { confirmButtonText: '确认禁用', cancelButtonText: '取消', type: 'warning' },
    )
    await request.put('/security/autoban', {
      enabled: false,
      dry_run: autobanStatus.value.dry_run,
      threshold: autobanStatus.value.threshold,
      window_minutes: autobanStatus.value.window_minutes,
      duration: autobanStatus.value.duration,
      scope: autobanStatus.value.scope,
    })
    mfaAwareSuccess('自动封禁已禁用（调度已停止）')
    fetchAutobanStatus()
  } catch { /* 取消无需处理；请求错误已由全局拦截器 toast */ }
  finally { autobanToggling.value = false }
}

// 触发阶段分类（追加需求，用户裁定）：IP ACL 族=黑白名单/信任/地域/
// 威胁库预检，统一展示「IP 访问控制」；WAF 含 CRS 与自定义两源；请求体异常独立。
// 原 isIpAclFamily 谓词与 stageCategory 口径重叠（且被其包含
// ——链接门 `isIpAclFamily || stageCategory==='trust'` 等价于 stageCategory ∈
// {acl,trust}），删除谓词，统一走 stageCategory 单一事实源。

// ctx 弹框耗时展示按族判定——仅 WAF 族（wafCrs/wafCustom/body）经 WAF 段独立
// 测量用加和式（duration_us=WAF 段，拦截/记录两形态同为纯段口径）；预检族
// duration_us≡precheck_us 单值展示（预检决策耗时，拦截与放行同口径——历史起
// 预检拦在决策后、403 写出前记录，不再混入链首全程）。族谓词单源
// securityStages.isWafDurationFamily（与触发详情弹框同一实现）。
const ctxWafFamily = computed(() => isWafDurationFamily(triggerStageFamily(ctxEvent.value?.rule_triggered ?? '')))

// stageCategory 改由共享 triggerStageFamily 投影（securityStages 唯一
// 实现，原双实现并存欠账）——本视图五桶 = 细粒度族的合并投影
// ipAcl/geoip/threat 同归「IP 访问控制」（阶段 1 合并口径），wafCrs/wafCustom
// 同归「WAF」；trust/body/other 同名直通。
// crawler 独立成类（后端 v2.3.8 将已验证爬虫/伪装从地域段拆出）——
// 阶段列展示词与筛选类别/触发类型列同源（crawler 族统一为后端权威词
// CRAWLER_FAMILY_LABEL「爬虫Bot」——原此处渲染「爬虫校验」，同页三称谓并存）。
// 点击进入同一触发详情弹框。
const stageCategory = (row: SecurityEvent): 'trust' | 'acl' | 'crawler' | 'waf' | 'body' | 'other' => {
  const t = row.rule_triggered
  if (!t) return 'other'
  switch (triggerStageFamily(t)) {
    case 'trust': return 'trust'
    case 'crawler': return 'crawler'
    case 'ipAcl': case 'geoip': case 'threat': return 'acl'
    case 'wafCrs': case 'wafCustom': return 'waf'
    case 'body': return 'body'
    default: return 'other'
  }
}
const stageLabel = (row: SecurityEvent): string => {
  // 存量 id '8' 中和文案（勿改分类——triggerStageFamily 对 8 归 ipAcl 是已钉住
  // 的历史共享 id 口径例外）：后端 trigger_type 显示「地域拦截」，阶段列沿用
  // IP 访问控制会自相矛盾；现代引擎地域事件已发 800xxx，仅存量/带外数据可达。
  if (row.rule_triggered === '8') return '地域拦截（旧 id）'
  switch (stageCategory(row)) {
    case 'trust': return '信任名单'
    case 'crawler': return CRAWLER_FAMILY_LABEL
    case 'acl': return 'IP 访问控制'
    case 'waf': return 'WAF'
    case 'body': return '请求体异常'
    default: return row.rule_triggered || '—'
  }
}
// tooltip 分支仅在模板 else 分支可达（trust/acl/crawler/waf 已由前两个
// AccessibleLink 分支截走）——原再排除 2/3/4/5/^949 是永不命中的死条件，误导读者以为 ACL/
// 信任行会走 tooltip。
const showTriggeredMsg = (row: SecurityEvent): boolean =>
  !!row.rule_triggered && !!row.rule_msg

// —— 触发详情弹框（统一入口）：全部触发类型共用 TriggerDetailDialog ——
const triggerDetailVisible = ref(false)
const triggerDetailRow = ref<SecurityEvent | null>(null)
const openTriggerDetail = (row: SecurityEvent): void => {
  triggerDetailRow.value = row
  triggerDetailVisible.value = true
}


const loading = ref(false)
// 列表加载失败：保留末次成功数据的同时必须有页内可见错误态——筛选/翻页失败
// 后分页器与筛选框已是新条件，旧列表不得在无提示下冒充当前结果。
const eventsLoadError = ref(false)
const events = ref<SecurityEvent[]>([])
const ingestionStatus = ref<IngestionHealth>({ observed: false, healthy: false, consecutive_failures: 0 })
// 采集健康位提示（任务已停/连续失败/审计写侧降级）——判据与文案与总览/大屏同源。
const ingestionWarning = computed(() => ingestionWarningMessage(ingestionStatus.value))

// —— 请求上下文详情弹框（策略「记录请求体」开启后事件携带 request_headers/request_body）——
const ctxDialogVisible = ref(false)
const ctxEvent = ref<SecurityEvent | null>(null)
// 敏感头逐行显示状态（key = 小写头名）：默认掩码 ••••••，眼睛图标点击切换
const ctxRevealed = ref<Set<string>>(new Set())

// 敏感头名单与后端 securityEventSensitiveHeaderNames（internal/handlers/security.go）
// 同源：后端是权威（非管理员/只读 Key 的响应已在服务端掩码），此处只决定管理员
// 查看时默认掩码哪些头。两边任何一侧新增都必须同步——契约测试按两处字面量对表。
const CTX_SENSITIVE_HEADERS = new Set([
  'cookie',
  'authorization',
  'set-cookie',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-forwarded-access-token',
  'x-amz-security-token',
  'x-goog-api-key',
  'x-ms-authentication-token',
])
const CTX_TRUNCATED_SUFFIX = '\n...[TRUNCATED]'
const CTX_UTF8_PREFIX = 'utf8:'
const CTX_B64_TRUNCATED_PREFIX = 'base64-truncated:'
const CTX_B64_PREFIX = 'base64:'

interface CtxHeaderRow { name: string; value: string; sensitive: boolean }
interface CtxHeadersParsed { rows: CtxHeaderRow[]; dropped: number; listDropped: number; failed: boolean }

// 请求头解析："" → 空态；JSON.parse try/catch 防御（失败展示原始内容 + 错误说明）；
// 合成键 _lb_dropped_headers（采集 64KB 裁剪）与 _lb_list_dropped_headers（列表 16KB
// 裁剪）是写侧保留键（客户端同名头已在摄取侧剥离），分别提取为信息行、不作为头行
// 渲染；多值头以 ", " 连接
const ctxHeadersParsed = computed<CtxHeadersParsed>(() => {
  const raw = ctxEvent.value?.request_headers ?? ''
  if (raw === '') return { rows: [], dropped: 0, listDropped: 0, failed: false }
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { rows: [], dropped: 0, listDropped: 0, failed: true }
    const rows: CtxHeaderRow[] = []
    let dropped = 0
    let listDropped = 0
    for (const [name, values] of Object.entries(parsed as Record<string, unknown>)) {
      const list = Array.isArray(values) ? values.map((v) => String(v)) : [String(values)]
      if (name === '_lb_dropped_headers') {
        const n = Number(list[0] ?? 0)
        if (Number.isFinite(n) && n > 0) dropped = n
        continue
      }
      if (name === '_lb_list_dropped_headers') {
        const n = Number(list[0] ?? 0)
        if (Number.isFinite(n) && n > 0) listDropped = n
        continue
      }
      rows.push({ name, value: list.join(', '), sensitive: CTX_SENSITIVE_HEADERS.has(name.toLowerCase()) })
    }
    return { rows, dropped, listDropped, failed: false }
  } catch {
    return { rows: [], dropped: 0, listDropped: 0, failed: true }
  }
})

interface CtxBodyParsed { state: 'empty' | 'ok' | 'error'; text: string; truncated: boolean; binary: boolean }

// 请求体解析：utf8:（显式文本转义，必须先于 base64 判断）→ base64-truncated:
// → base64: → 明文；base64 系 atob 解码（失败回退原始内容 + error 态）；
// 明文以 \n...[TRUNCATED] 结尾时剥离标记转为截断横幅。
// base64 两分支在真实管线属防御性不可达（coraza JSON 格式化器把非法 UTF-8
// 替换为 U+FFFD，摄取侧拿到的恒是合法 UTF-8）；写侧 body_truncated 标记由
// 摄取侧转成上述前缀/后缀，展示契约保持不变。
const ctxBodyParsed = computed<CtxBodyParsed>(() => {
  const raw = ctxEvent.value?.request_body ?? ''
  if (raw === '') return { state: 'empty', text: '', truncated: false, binary: false }
  if (raw.startsWith(CTX_UTF8_PREFIX)) {
    const text = raw.slice(CTX_UTF8_PREFIX.length)
    if (text.endsWith(CTX_TRUNCATED_SUFFIX)) {
      return { state: 'ok', text: text.slice(0, -CTX_TRUNCATED_SUFFIX.length), truncated: true, binary: false }
    }
    return { state: 'ok', text, truncated: false, binary: false }
  }
  if (raw.startsWith(CTX_B64_TRUNCATED_PREFIX)) return decodeCtxBody(raw.slice(CTX_B64_TRUNCATED_PREFIX.length), true)
  if (raw.startsWith(CTX_B64_PREFIX)) return decodeCtxBody(raw.slice(CTX_B64_PREFIX.length), false)
  if (raw.endsWith(CTX_TRUNCATED_SUFFIX)) {
    return { state: 'ok', text: raw.slice(0, -CTX_TRUNCATED_SUFFIX.length), truncated: true, binary: false }
  }
  return { state: 'ok', text: raw, truncated: false, binary: false }
})

const decodeCtxBody = (payload: string, truncated: boolean): CtxBodyParsed => {
  try {
    return { state: 'ok', text: atob(payload), truncated, binary: true }
  } catch {
    return { state: 'error', text: payload, truncated, binary: true }
  }
}

const ctxHeaderDisplay = (row: CtxHeaderRow): string =>
  row.sensitive && !ctxRevealed.value.has(row.name.toLowerCase()) ? '••••••' : row.value

// 请求体空态文案：非管理员看到的空串可能是服务端掩码（已记录但无权查看），
// 不得一律陈述成「本来就没记录」——与请求头区的掩码表现保持一致。
const ctxBodyEmptyText = computed(() => requestBodyEmptyNotice(viewerCanReadRequestBody(authStore.user?.role)))

const toggleCtxReveal = (name: string): void => {
  const key = name.toLowerCase()
  const next = new Set(ctxRevealed.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  ctxRevealed.value = next
}

const openCtxDialog = (row: SecurityEvent): void => {
  ctxEvent.value = row
  ctxRevealed.value = new Set()
  ctxDialogVisible.value = true
}

const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const logStorageRefreshKey = ref(0)

// 触发阶段筛选为固定预置八类（用户裁定：固定预置值，不接受任意值）。
// 令牌 → 后端族段映射与序列化单源在 utils/triggeredFilter
// 原实现内联在本文件、无行为测试）。
const filters = ref({ action: '', ip: '', uri: '', rule_name: '', rule_triggered: [...TRIGGERED_CATEGORIES] as string[], policy_name: '', timeRange: null as [string, string] | null })

// 头部全选复选框三态：八类全中=全选；部分中=半选
const triggeredCheckAll = computed(() => TRIGGERED_CATEGORIES.every((c) => filters.value.rule_triggered.includes(c)))
const triggeredIndeterminate = computed(() => {
  const hit = TRIGGERED_CATEGORIES.filter((c) => filters.value.rule_triggered.includes(c)).length
  return hit > 0 && hit < TRIGGERED_CATEGORIES.length
})
// 全选：勾选=八类并入当前选择（保留用户已输入的自定义 tag，与绑定编辑器/
// 策略向导的规则选择器同为并集语义）、取消=只摘八类、自定义 tag 原样保留——
// 该控件允许 allow-create 自定义规则 ID（如 942100），替换语义会在半选态点
// 「全选」时静默丢掉这些 tag，筛选结果集被改写而界面只显示「勾上了全选」。
const toggleTriggeredAll = (checked: CheckboxValueType) => {
  const custom = filters.value.rule_triggered.filter((v) => !(TRIGGERED_CATEGORIES as readonly string[]).includes(v))
  filters.value.rule_triggered = checked ? [...TRIGGERED_CATEGORIES, ...custom] : custom
}

const applyFilters = () => {
  // 时间区间校验：开始晚于结束时提示并清除该筛选（后端同样兜底 400）。
  // value-format 为 YYYY-MM-DD HH:mm:ss，字符串比较即时间先后比较。
  const range = filters.value.timeRange
  if (range?.[0] && range?.[1] && range[0] > range[1]) {
    ElMessage.warning('开始时间不能晚于结束时间')
    // 只清 end 保留已填的 start（原清空整个区间丢两侧输入）
    filters.value.timeRange = [range[0], '']
  }
  page.value = 1
  fetchEvents()
}

const resetFilters = () => {
  filters.value = { action: '', ip: '', uri: '', rule_name: '', rule_triggered: [...TRIGGERED_CATEGORIES], policy_name: '', timeRange: null }
  page.value = 1
  fetchEvents()
}

const handleSizeChange = () => { page.value = 1; fetchEvents() }

const goToRule = (row: SecurityEvent) => { window.open(pageUrl('rules', { [DEEP_LINK_PARAMS.ruleSearch]: row.rule_caddy_id }), '_blank') }
const goToPolicy = (row: SecurityEvent) => {
  // 交接改走 URL query（sp / sp-search 参数，同 goToRule 的 rs 形态），
  // SecurityPolicies.vue onMounted 消费后 replaceState 清除。
  if (row.policy_id > 0) {
    window.open(pageUrl('security-policies', { [DEEP_LINK_PARAMS.policyId]: row.policy_id }), '_blank')
  } else if (row.policy_name) {
    window.open(pageUrl('security-policies', { [DEEP_LINK_PARAMS.policySearch]: row.policy_name }), '_blank')
  }
}

let fetchEventsSeq = 0
const fetchEvents = async () => {
  // 乱序响应守卫：只有最新一次请求的响应才允许写入列表，避免旧响应覆盖新页
  const requestSeq = ++fetchEventsSeq
  loading.value = true
  try {
    const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) })
    if (filters.value.action) p.set('action', filters.value.action)
    if (filters.value.ip) p.set('ip', filters.value.ip)
    if (filters.value.rule_name) p.set('rule_name', filters.value.rule_name)
    // 触发规则：全选（八类全中且无自定义 tag）或空选 = 不过滤，不发送参数；
    // 子集或含自定义 tag 时按族段展开 + 自定义 tag 原样连接（单源 serializeTriggeredFilter）。
    const triggeredValue = serializeTriggeredFilter(filters.value.rule_triggered)
    if (triggeredValue !== null) p.set('rule_triggered', triggeredValue)
    if (filters.value.policy_name) p.set('policy_name', filters.value.policy_name)
    if (filters.value.uri) p.set('uri', filters.value.uri)
    if (filters.value.timeRange?.[0]) p.set('start_time', filters.value.timeRange[0])
    if (filters.value.timeRange?.[1]) p.set('end_time', filters.value.timeRange[1])
    const res = await request.get<APIResponse<{ events: SecurityEvent[]; total: number; ingestion?: IngestionHealth }>>(`/security/events?${p}`)
    if (requestSeq !== fetchEventsSeq) return
    events.value = res.data?.events || []
    total.value = res.data?.total || 0
    if (res.data?.ingestion) ingestionStatus.value = res.data.ingestion
    eventsLoadError.value = false
    logStorageRefreshKey.value++
  } catch {
    // 瞬态失败保留末次成功数据（对齐 AuditLog 口径）——此前清空列表
    // 却保留陈旧 total，空态文案「暂无安全事件」在排障窗口内误导为「无攻击」。
    // 但保留数据必须配可见错误条（分页/筛选条件已变，旧结果不得冒充当前结果）；
    // 全局拦截器只 toast 一次，过期请求的失败不污染当前态。
    if (requestSeq !== fetchEventsSeq) return
    eventsLoadError.value = true
  } finally {
    if (requestSeq === fetchEventsSeq) loading.value = false
  }
}
onMounted(() => {
  fetchEvents()
  fetchAutobanStatus()
})

// 页面刷新同时拉自动封禁状态（调度在后台持续运行，dry-run 建议
// 列表/banned_today/list_entries 不作长期快照）。
const refreshPage = (): void => {
  void fetchEvents()
  void fetchAutobanStatus()
}
</script>

<style scoped>
/* 自动封禁状态卡——*/
.autoban-card { margin-bottom: 16px; }
.autoban-bar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
/* 卡片主体=配置入口（2026-10-14 裁定）：标题/参数区可点，hover 灰底+pointer 反馈；
   padding+负 margin 扩大热区而不改变行内布局 */
.autoban-main { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; flex: 1; min-width: 0; cursor: pointer; padding: 4px; margin: -4px; border-radius: 6px; }
.autoban-main:hover { background: #f9fafb; }
.autoban-main.is-disabled { cursor: default; }
.autoban-main.is-disabled:hover { background: transparent; }
.autoban-main:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; }
.autoban-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; flex-shrink: 0; }
.autoban-title .title-icon { font-size: 16px; color: #3b82f6; }
.autoban-stats { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; flex: 0 1 auto; min-width: 0; font-size: 12px; color: var(--text-secondary, #6b7280); }
.autoban-stat b { color: #111827; font-weight: 600; margin-left: 2px; }
.autoban-danger { color: #f56c6c !important; }
.autoban-actions { flex-shrink: 0; display: flex; gap: 8px; }
.autoban-warn-bar { margin-top: 10px; }

/* 工具行单行排布（1280px 视口全控件 + 筛选/重置一行放下）：nowrap 禁止换行，
   各控件定宽不收缩，极端窄视口降级为横向滚动而非把按钮顶到第二行 */
.table-toolbar { display: flex; flex-wrap: nowrap; gap: 8px; justify-content: flex-start; margin-bottom: 16px; align-items: center; overflow-x: auto; }
.table-toolbar > * { flex: 0 0 auto; }
.filter-actions { display: flex; gap: 0; }
.filter-actions .el-button { padding-left: 12px; padding-right: 12px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
.cell-tip { cursor: help; border-bottom: 1px dashed #c0c4cc; }
.cell-tip:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }


/* —— 请求上下文详情弹框 —— */
.ctx-detail-section + .ctx-detail-section { margin-top: 16px; }
.ctx-banner { margin-bottom: 8px; }
.ctx-info-line { font-size: 12px; color: #9ca3af; line-height: 1.6; margin-bottom: 6px; }
.dialog-panel--flush .ctx-info-line { padding-right: 12px; padding-left: 12px; }
.dialog-panel--flush .ctx-info-line:first-child { padding-top: 12px; }
.ctx-empty { font-size: 12px; color: #9ca3af; }
.ctx-header-value-cell { display: flex; align-items: center; gap: 6px; }
.ctx-header-value { flex: 1; min-width: 0; word-break: break-all; font-family: monospace; font-size: 12px; }
.ctx-reveal-btn { flex-shrink: 0; }
/* 请求体滚动区：限高 320px 内部滚动，长行预格式换行 */
.ctx-body-pre {
  max-height: 320px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: monospace;
  font-size: 12px;
  line-height: 1.6;
  padding: 12px;
  margin: 0;
}
</style>

<style>
.events-filter-date-range.el-date-editor {
  --el-date-editor-width: 320px;
  width: 320px;
  flex: 0 0 auto;
}

/* 请求上下文弹框：正文区自适应限高（top=5vh + 头/脚 ≈ 110px），内容多时整体不超视口
   （.crs-event-dialog 左半选择器删除——CRS 事件弹框已迁入 TriggerDetailDialog） */
.ctx-event-dialog .el-dialog__body { max-height: calc(90vh - 130px); overflow-y: auto; }
/* 请求上下文弹框正文 20px 水平留白走全局 .dialog-body-inset（2026-09-25 用户裁定；
   append-to-body teleport 场景 scoped :deep 不可靠，故类挂弹框、规则在 main.css） */

/* 触发规则筛选下拉：头部「全选」复选框整行可点（EP 自定义头部官方用法同款排布）；
   padding-left 20px 与选项行（EP 默认 20px）左对齐——默认 header-padding 10px 会
   导致复选框与选项文字错开 */
.triggered-filter-popper .el-select-dropdown__header { padding: 8px 6px; border-bottom: 1px solid var(--el-border-color-lighter, #ebeef5); }
.triggered-filter-popper .el-select-dropdown__header .el-checkbox { display: flex; height: unset; margin-right: 0; }
.triggered-filter-popper .el-select-dropdown__header .el-checkbox .el-checkbox__label { padding-left: 8px; }
/* 选中项不加粗：EP 2.14 多选下拉 is-selected 默认 font-weight:bold，该筛选常态
   全选（八类全勾）导致整列粗体，覆写回 normal（选中色与右侧 ✓ 保留） */
.triggered-filter-popper .el-select-dropdown__item.is-selected { font-weight: normal; }

/* 自动封禁启用确认框（dangerouslyUseHTMLString 精排，2026-10-14 裁定）：
   MessageBox 挂 body，scoped 样式不可达 → 全局作用域。两段式（启用前须知三条
   列表 + 使用建议正文），13px 正文紧凑排布，弹框宽 480px（customStyle 指定） */
.autoban-confirm { text-align: left; }
.autoban-confirm-hero { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 18px; }
.autoban-confirm-icon { flex: none; width: 42px; height: 42px; border-radius: 50%; display: flex; align-items: center; justify-content: center; background: var(--el-color-warning-light-9, #fdf6ec); color: var(--el-color-warning, #e6a23c); }
.autoban-confirm-heading { font-size: 15px; font-weight: 600; color: var(--el-text-color-primary, #303133); line-height: 1.5; }
.autoban-confirm-sub { margin-top: 4px; font-size: 13px; line-height: 1.6; color: var(--el-text-color-regular, #606266); }
.autoban-confirm-notes { margin: 0 0 14px; padding: 12px 16px; border-radius: 8px; background: var(--el-fill-color-light, #f5f7fa); border: 1px solid var(--el-border-color-lighter, #ebeef5); }
.autoban-confirm-note { display: flex; align-items: baseline; gap: 10px; font-size: 12.5px; line-height: 2; color: var(--el-text-color-regular, #606266); }
.autoban-confirm-dot { flex: none; width: 5px; height: 5px; border-radius: 50%; background: var(--el-color-warning, #e6a23c); transform: translateY(-2px); }
.autoban-confirm-howto { display: flex; align-items: baseline; gap: 8px; font-size: 12.5px; line-height: 1.7; color: var(--el-text-color-secondary, #909399); }
.autoban-confirm-howto-label { flex: none; font-size: 11px; padding: 1px 8px; border-radius: 10px; color: var(--el-color-primary, #409eff); background: var(--el-color-primary-light-9, #ecf5ff); }
/* MessageBox 四区统一版式：外框零内边距，标题/正文/按钮区各自 24px 侧距——
   与 Element Plus 默认窄内边距（15px）整体覆盖，视觉边距一致 */
:global(.autoban-confirm-box) { padding: 0; }
:global(.autoban-confirm-box .el-message-box__header) { padding: 20px 24px 8px; }
:global(.autoban-confirm-box .el-message-box__title) { padding: 0; font-size: 16px; font-weight: 600; }
:global(.autoban-confirm-box .el-message-box__container) { padding: 0 24px; }
:global(.autoban-confirm-box .el-message-box__message) { display: block; padding: 4px 0 0; }
:global(.autoban-confirm-box .el-message-box__btns) { padding: 18px 24px 20px 0; }

/* 日志统计与分页固定同一行：统计占满剩余宽度并在内部省略，分页不换行、不被挤压。 */
.events-footer { margin-top: 16px; display: flex; align-items: center; gap: 16px; flex-wrap: nowrap; }
.events-storage { flex: 1 1 auto; min-width: 0; }
.events-pagination { flex: 0 0 auto; white-space: nowrap; }
</style>
