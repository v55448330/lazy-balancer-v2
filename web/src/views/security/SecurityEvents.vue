<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Warning /></el-icon>
          {{ t('app.security.events.title') }}
        </h2>
        <p class="page-desc">{{ t('app.security.events.desc') }}</p>
      </div>
      <!-- 刷新联动自动封禁状态卡——建议列表/今日封禁/名单数不再
           停留在进入页面时的快照 -->
      <el-button :icon="Refresh" @click="refreshPage">{{ t('app.security.events.refresh') }}</el-button>
    </div>

    <!-- 自动封禁状态卡：状态/口径/窗口/阈值/时长/今日封禁/名单数；
         配置入口=点击卡片主体（2026-10-14 裁定：废除「配置」按钮），按钮区仅留
         启用/禁用 toggle（直接切换业务开关并联动调度；「立即执行」废除——任务只能
         由「启用后按配置调度执行」） -->
    <el-card class="autoban-card" v-loading="autobanStatusLoading">
      <div v-if="autobanStatusError" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">{{ t('app.security.events.statusLoadFail') }}</span>
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
              <span>{{ t('app.security.events.autobanTitle') }}</span>
              <el-tag :type="autobanStatusError ? 'info' : autobanStatus.enabled ? (autobanStatus.dry_run ? 'warning' : 'success') : 'info'" size="small" effect="plain">
                {{ autobanStateLabel(autobanStatusError, autobanStatus.enabled, autobanStatus.dry_run) }}
              </el-tag>
              <!-- 调度仅主节点执行——从端徽章标示+写按钮禁用。加载/读取失败均不渲染：
                   初值 is_master=false 会在未知态谎称「仅主节点调度」，且徽章闪现会把参数区推向右侧 -->
              <el-tag v-if="!autobanStatusLoading && !autobanStatusError && !autobanStatus.is_master" type="info" size="small" effect="plain">{{ t('app.security.events.masterOnlyBadge') }}</el-tag>
            </div>
            <div class="autoban-stats">
              <span class="autoban-stat">{{ t('app.security.events.statScope') }} <b>{{ autobanStatValue(autobanStatusError, autobanScopeText) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">{{ t('app.security.events.statWindow') }} <b>{{ autobanStatValue(autobanStatusError, autobanStatus.window_minutes, t('app.security.events.suffixMinutes')) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">{{ t('app.security.events.statThreshold') }} <b>{{ autobanStatValue(autobanStatusError, autobanStatus.threshold, t('app.security.events.suffixTimes')) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">{{ t(autobanStatusEscalationOn ? 'app.security.events.firstBanDuration' : 'app.security.events.statDuration') }} <b>{{ autobanStatValue(autobanStatusError, autobanDurationText) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">{{ t('app.security.events.escalationLabel') }} <b>{{ t(autobanEscalationShortKey(autobanStatus.escalation)) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">{{ t('app.security.events.statTodayBanned') }} <b class="autoban-danger">{{ autobanStatValue(autobanStatusError, autobanStatus.banned_today) }}</b></span>
              <el-divider direction="vertical" />
              <span class="autoban-stat">{{ t('app.security.events.statListEntries') }} <b>{{ autobanStatValue(autobanStatusError, autobanStatus.list_entries, t('app.security.events.suffixEntries')) }}</b></span>
            </div>
          </div>
        </el-tooltip>
        <!-- 操作组：「封禁与累犯」合并弹框入口（当前封禁+累犯前科双 tab）
             与禁用/编辑同组同规格；状态加载中/失败禁用。 -->
        <div class="autoban-actions">
          <el-button size="small" type="primary" plain :disabled="autobanStatusError || autobanStatusLoading" @click="openBanConsole('bans')">{{ t('app.security.events.banConsoleAction', { n: autobanStatus.list_entries }) }}</el-button>
          <template v-if="autobanStatus.enabled">
            <el-button size="small" type="danger" plain :disabled="!autobanWritable" :loading="autobanToggling" @click="toggleAutobanEnabled">{{ t('app.security.events.actionDisable') }}</el-button>
            <el-button size="small" plain :disabled="!autobanWritable" @click="openAutobanConfig">{{ t('app.security.events.actionEdit') }}</el-button>
          </template>
          <el-button v-else size="small" type="success" plain :disabled="!autobanWritable" @click="openAutobanConfigForEnable">{{ t('app.security.events.actionEnable') }}</el-button>
        </div>
      </div>
      <!-- 未生效黄条：判据单源 utils/autobanStatus（enabled ∧ ban_effective===false，
           IP 名单通道：名单为空或未被启用中的 deny 策略引用） -->
      <div v-if="autobanIneffective" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">{{ t('app.security.events.ineffectiveNotice') }}</span>
        <el-button v-if="autobanWritable" size="small" type="primary" plain :loading="autobanFixing" @click="fixAutobanIneffective">{{ t('app.security.events.fixAction') }}</el-button>
      </div>
      <!-- 喂入源降级：补采/轮转停摆或写侧持续失败时披露原因。实时 IPC 入库仍在
           运行并继续喂入计数器——兜底文案不得声称「计数不会增长」 -->
      <div v-if="autobanFeedDegraded" class="info-note-bar autoban-warn-bar">
        <span class="info-note-desc">{{ t('app.security.events.feedDegradedPrefix') }}{{ autobanStatus.feed_degraded_reason || t('app.security.events.feedDegradedDefault') }}</span>
      </div>
      <!-- 观察模式建议列表：dry-run 下达阈值 IP（不封禁，供评估阈值/口径） -->
      <template v-if="autobanStatus.enabled && autobanStatus.dry_run && (autobanStatus.suggestions?.length ?? 0) > 0">
        <div class="info-note-bar autoban-warn-bar">
          <span class="info-note-desc">{{ t('app.security.events.suggestionSummary', { minutes: autobanStatus.window_minutes, times: autobanStatus.threshold }) }}</span>
          <el-button v-if="autobanWritable" size="small" type="warning" plain :loading="autobanEnforcing" @click="startAutobanEnforcement">{{ t('app.security.events.enforceAction') }}</el-button>
        </div>
        <el-table :data="autobanStatus.suggestions" size="small" max-height="320" :header-cell-style="{ background: '#f9fafb' }">
          <el-table-column :label="t('app.security.overview.autoban.colIdentity')" min-width="230">
            <template #default="{ row }">
              <IPLocationAction :ip="row.ip" :location="row.ip_location || ''" />
            </template>
          </el-table-column>
          <el-table-column :label="t('app.security.events.colHitCount')" width="110" align="center" sortable :sort-by="'count'" :sort-orders="['descending']">
            <template #default="{ row }"><span :style="suggestionCountStyle(row.count)">{{ row.count }}</span></template>
          </el-table-column>
          <!-- evidence 双分数列（classic 不渲染）：确证/嫌疑拆分。 -->
          <el-table-column v-if="autobanIsEvidence" :label="t('app.security.events.colEvidenceSplit')" width="130" align="center">
            <template #default="{ row }">
              <span class="autoban-score-confirmed">{{ t('app.security.events.scoreConfirmed', { n: row.confirmed_count ?? row.count }) }}</span>
              <span class="autoban-score-suspicion">{{ t('app.security.events.scoreSuspicion', { n: row.suspicion_count ?? 0 }) }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.security.events.colThresholdRatio')" min-width="150" align="center">
            <template #default="{ row }">
              <el-progress :percentage="Math.min(100, Math.round(row.count / Math.max(1, autobanStatus.threshold) * 100))" :stroke-width="8" :show-text="false" :color="suggestionProgressColor(row.count)" style="max-width: 130px; display: inline-block; vertical-align: middle;" />
              <span class="text-secondary" style="margin-left: 6px;">{{ (row.count / Math.max(1, autobanStatus.threshold)).toFixed(1) }}×</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('app.security.events.colWindowSpan')" min-width="190">
            <template #default="{ row }"><span class="text-secondary">{{ suggestionWindowSpan(row as AutobanSuggestion) }}</span></template>
          </el-table-column>
          <el-table-column :label="t('app.security.events.colSuggestedDuration')" width="130" align="center">
            <template #default>
              <!-- 建议时长=配置时长（升级档开启时 tooltip 披露「按累犯档升档」，
                   dry-run 候选无逐行累犯记账） -->
              <el-tooltip :content="t('app.security.overview.autoban.durationEscalatesTip')" :disabled="!autobanStatusEscalationOn" placement="top">
                <el-tag size="small" effect="plain" type="warning">{{ t(autobanSuggestedDurationKey(autobanStatus.duration)) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <!-- 观察闭环：候选行封禁（复用 useIpListAdd 处置链）。 -->
          <el-table-column v-if="autobanWritable" :label="t('app.security.events.colAction')" width="90" align="center">
            <template #default="{ row }">
              <el-button size="small" type="danger" plain @click="banSuggestion(row as AutobanSuggestion)">{{ t('app.security.events.banVerb') }}</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div class="form-tip-inline" v-if="(autobanStatus.suggestions?.length ?? 0) >= 50">{{ t('app.security.events.suggestionsLimit') }}</div>
      </template>
      <!-- 当前封禁折叠区块已并入「封禁与累犯」合并弹框（用户裁定：两视图
           入口收敛，卡片不再内嵌表格）。 -->
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
          :range-separator="t('app.security.events.rangeSeparator')"
          :start-placeholder="t('app.security.events.startTime')"
          :end-placeholder="t('app.security.events.endTime')"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="events-filter-date-range"
        />
        <el-select v-model="filters.action" :placeholder="t('app.security.events.filterAction')" clearable style="width: 90px">
          <el-option :label="t('app.security.events.actionBlocked')" value="blocked" />
          <el-option :label="t('app.security.events.actionLogged')" value="logged" />
          <el-option :label="t('app.security.events.actionTrust')" value="trust" />
          <el-option :label="t('app.security.events.actionChallenged')" value="challenged" />
        </el-select>
        <!-- 协议类型筛选：TCP（L4 断连事件）/HTTP（waf 口径，含带外 NULL 归并）；
             值原样透传 event_type 查询参数（后端精确匹配） -->
        <el-select v-model="filters.event_type" :placeholder="t('app.security.events.filterType')" clearable style="width: 86px">
          <el-option label="TCP" value="tcp" />
          <el-option label="HTTP" value="waf" />
        </el-select>
        <!-- （用户需求）：规则 ID 筛选替换为三列（负载规则/触发规则/策略）
             服务端筛选（rule_name/rule_triggered/policy_name LIKE）。 -->
        <el-input v-model="filters.rule_name" :placeholder="t('app.security.events.rulePlaceholder')" clearable style="width: 100px" @keyup.enter="applyFilters" />
        <!-- 触发规则筛选：多选 + 头部全选（勾的就是看的，统一正向心智）。
             全选（九类全中且无自定义 tag）或空选 = 不过滤，不发送参数；子集或含
             自定义 tag 时全部选中值英文逗号连接发送 rule_triggered（后端逐段按
             family/前缀/纯数字 ID 解析，OR 连接）。filterable + allow-create：可直接
             输入 CRS 规则 ID（如 942100）等自定义 tag 混入同一参数；自定义 tag 不参与
             全选判定（只看 9 个类别是否全中）。 -->
        <el-select
          v-model="filters.rule_triggered"
          multiple
          filterable
          allow-create
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="1"
          :placeholder="t('app.security.events.triggeredPlaceholder')"
          style="width: 170px"
          popper-class="triggered-filter-popper"
        >
          <template #header>
            <el-checkbox
              :model-value="triggeredCheckAll"
              :indeterminate="triggeredIndeterminate"
              @change="toggleTriggeredAll"
            >{{ t('app.security.events.selectAll') }}</el-checkbox>
          </template>
          <el-option :label="t('app.security.events.crawlerBot')" value="爬虫Bot" :title="t('app.security.events.crawlerBotHint')" />
          <el-option :label="t('app.security.events.geoBlock')" value="地域拦截" :title="t('app.security.events.geoBlockHint')" />
          <!-- 阶段 2 配额限流退役：旧「限流」筛选项移除，CC 防护事件由下方
               「CC 防护」项承载（human_* 整族）。退役前的 429 存量行仍在列表中
               显示（归类「CC防护」），但不属 human_* 族筛选范围。 -->
          <el-option :label="t('app.security.events.ipAcl')" value="IP 访问控制" :title="t('app.security.events.ipAclHint')" />
          <el-option :label="t('app.security.events.trustList')" value="信任名单" :title="t('app.security.events.trustListHint')" />
          <el-option :label="t('app.security.events.threatIntel')" value="威胁情报库" :title="t('app.security.events.threatIntelHint')" />
          <el-option :label="t('app.security.events.bodyAnomaly')" value="请求体异常" :title="t('app.security.events.bodyAnomalyHint')" />
          <el-option label="WAF·CRS" value="WAF·CRS" :title="t('app.security.events.wafCrsHint')" />
          <el-option :label="t('app.security.events.wafCustom')" value="WAF·自定义" :title="t('app.security.events.wafCustomHint')" />
          <!-- CC 防护（2026-11-13 用户裁定新增）：value=后端族键「CC 防护」，
               形态条件 humanFamilyCondition（human_* 整族），与前端单源
               TRIGGERED_CATEGORIES 同名同序。 -->
          <el-option :label="t('app.security.events.stageHuman')" value="CC 防护" :title="t('app.security.events.ccProtectionHint')" />
        </el-select>
        <el-input v-model="filters.policy_name" :placeholder="t('app.security.events.policyPlaceholder')" clearable style="width: 90px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.ip" :placeholder="t('app.security.events.ipPlaceholder')" clearable style="width: 115px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.uri" placeholder="URI" clearable style="width: 115px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">{{ t('app.security.events.apply') }}</el-button>
          <el-button @click="resetFilters">{{ t('app.security.events.reset') }}</el-button>
        </div>
      </div>

      <el-alert v-if="eventsLoadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
        <template #title>
          <div class="polling-error-title">
            <span>{{ events.length > 0 ? t('app.security.events.loadErrorStale') : t('app.security.events.loadErrorEmpty') }}</span>
            <el-button link type="danger" :loading="loading" @click="fetchEvents">{{ t('app.security.events.retryNow') }}</el-button>
          </div>
        </template>
      </el-alert>

      <el-table :data="events" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <template #empty><el-empty :description="t('app.security.events.empty')" :image-size="60" /></template>
        <el-table-column prop="event_time" :label="t('app.security.events.colTime')" width="190" :formatter="(row: SecurityEvent) => formatDate(row.event_time)" />
        <el-table-column :label="t('app.security.events.colAction')" width="85" align="center">
          <template #default="{ row }">
            <el-tag :type="eventActionTone(row.action, row.rule_triggered)" size="small" effect="light">{{ eventActionShort(row.action, row.rule_triggered) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.events.colRule')" min-width="130">
          <template #default="{ row }">
            <AccessibleLink v-if="row.rule_name || row.rule_caddy_id" type="primary" @click="goToRule(row as SecurityEvent)">{{ row.rule_name || row.rule_caddy_id || '—' }}</AccessibleLink>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.events.colStage')" min-width="140" class-name="col-nowrap">
          <template #default="{ row }">
            <!-- 触发阶段展示：信任名单 / IP 访问控制（黑白名单+地域+威胁库，点击看触发详情）/
                 WAF（CRS=详情+快捷排除弹框；自定义=规则详情弹框）/ 请求体异常（纯文本） -->
            <AccessibleLink v-if="stageCategory(row as SecurityEvent) === 'waf'" type="primary" @click="openTriggerDetail(row as SecurityEvent)">WAF</AccessibleLink>
            <AccessibleLink v-else-if="['acl', 'crawler', 'trust', 'human'].includes(stageCategory(row as SecurityEvent))" type="primary" @click="openTriggerDetail(row as SecurityEvent)">{{ stageLabel(row as SecurityEvent) }}</AccessibleLink>
            <el-tooltip v-else-if="showTriggeredMsg(row as SecurityEvent)" :content="row.rule_msg" placement="top" :show-after="200" :trigger="['hover', 'focus']">
              <span class="cell-tip" tabindex="0" :aria-label="row.rule_msg">{{ stageLabel(row as SecurityEvent) }}</span>
            </el-tooltip>
            <span v-else>{{ stageLabel(row as SecurityEvent) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.events.colTriggerType')" min-width="130" class-name="col-nowrap">
          <template #default="{ row }">
            <span>{{ triggerTypeLabel(row.trigger_type) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.events.colPolicy')" min-width="150">
          <template #default="{ row }">
            <AccessibleLink v-if="row.policy_name || row.policy_id > 0" type="primary" @click="goToPolicy(row as SecurityEvent)">{{ row.policy_name || row.policy_id }}</AccessibleLink>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <!-- 用户裁定:内容上限 ~190-200px(IPv4 126+gap+归属地 72),定宽 200 不再挤占方法/URI-->
        <el-table-column :label="t('app.security.events.colClientIp')" width="200">
          <template #default="{ row }">
            <IPLocationAction :ip="row.client_ip" :location="row.ip_location" />
          </template>
        </el-table-column>
        <!-- OPTIONS 为最长方法名(7 字符),90 定宽 -->
        <!-- 方法列统一徽标（用户裁定：两协议都加，样式=el-tag 上一版）；
             disable-transitions 根治翻页时挂载动画引发的行内右飘（用户实测 bug）。 -->
        <el-table-column prop="method" :label="t('app.security.events.colMethod')" width="90" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.event_type === 'tcp'" size="small" effect="plain" disable-transitions class="proto-tcp-tag event-method-tag">TCP</el-tag>
            <el-tag v-else size="small" effect="plain" type="primary" disable-transitions class="event-method-tag">{{ row.method || '—' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="uri" label="URI" min-width="140" show-overflow-tooltip />
        <!-- （用户需求）：异常评分列——CRS 评分制下每事件携带的累计
             anomaly_score（后端已返回，此前未展示）；按分数着色便于快速识别高威胁。
             分档与大屏定级同源（utils/severityScale：≥12 高 / ≥6 中）——
             原列表 ≥15/≥5 与大屏 ≥12/≥6 双口径，同分不同色结论打架。 -->
        <el-table-column :label="t('app.security.events.colScore')" width="80" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.anomaly_score >= ANOMALY_SCORE_HIGH" type="danger" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <el-tag v-else-if="row.anomaly_score >= ANOMALY_SCORE_MID" type="warning" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <el-tag v-else-if="row.anomaly_score > 0" type="info" size="small" effect="plain">{{ row.anomaly_score }}</el-tag>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('app.security.events.colOps')" width="70" fixed="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openCtxDialog(row as SecurityEvent)">{{ t('app.security.events.detail') }}</el-button>
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

    <!-- 自动封禁配置弹框：七项配置（六项基础 + 累犯升级）
         + 口径/窗口变更重置提示 -->
    <el-dialog v-model="autobanDialogVisible" width="min(980px, 96vw)" top="3vh" append-to-body class="autoban-config-dialog dialog-body-inset" :close-on-click-modal="false" :close-on-press-escape="!autobanSaving" :show-close="!autobanSaving">
      <template #header>
        <!-- 喂入门=四维统计口径（2026-11-13 多选裁定）：WAF 命中按 blocked/logged
             计数（CRS 与自定义两族，阶段门 autobanStage3Eligible，已验证爬虫豁免
             autobanSourceEligible 独立排除）；人机挑战发放/失败按 challenge_issued/
             challenge_failed 维度计数（挑战通过永不计）。IP 访问控制/地域/威胁情报/
             请求体异常等事件不进入计数。文案与后端喂入门同口径——用户按文案校准
             阈值必须与真实喂入一致，否则阈值永不达标且无告警 -->
        <DialogHeader :icon="Lock" :title="t('app.security.events.dialogTitle')" :subtitle="t('app.security.events.dialogSubtitle')" />
      </template>
      <div class="autoban-section-title">{{ t('app.security.events.sectionBanTitle') }}</div>
      <div class="autoban-section-desc">{{ t('app.security.events.sectionBanDesc') }}</div>
      <!-- 预设档位卡片（常显）：三档人话预设，选中整组回填；改参数落自定义。
           顶部一行说明取代悬空「自定义」徽标（用户裁定：徽标语义不明）。 -->
      <div class="autoban-preset-hint">{{ t('app.security.events.presetHint') }}</div>
      <div class="autoban-preset-row">
        <button v-for="id in AUTOBAN_PRESET_IDS" :key="id" type="button" class="autoban-preset-card" :class="{ active: autobanActivePreset === id }" :disabled="autobanSaving" @click="applyAutobanPreset(id)">
          <span class="autoban-preset-name">{{ t('app.security.events.preset.' + id + '.name') }}<span v-if="autobanActivePreset === id" class="autoban-preset-current">{{ t('app.security.events.presetCurrent') }}</span></span>
          <span class="autoban-preset-desc">{{ t('app.security.events.preset.' + id + '.desc') }}</span>
        </button>
      </div>
      <el-form :model="autobanForm" :label-width="$flw('96px')" label-position="top" size="small" :disabled="autobanSaving">
        <el-form-item :label="t('app.security.events.dryRunLabel')" label-position="right" class="autoban-dryrun-item">
          <el-switch v-model="autobanForm.dry_run" />
          <span class="form-tip-inline">{{ t('app.security.events.dryRunHint') }}</span>
        </el-form-item>
        <!-- 高级参数折叠：三列网格（980px 宽弹框，标签顶部对齐）——短项三三一行，
             口径/升级阶梯等宽项跨全列；目标全展开无垂直滚动（矮视口兜底 auto）。 -->
        <el-collapse v-model="autobanAdvancedOpen" class="autoban-advanced">
          <el-collapse-item :title="t('app.security.events.advancedTitle')" name="advanced">
            <div class="autoban-grid">
              <el-form-item :label="t('app.security.events.scopeLabel')" class="autoban-grid-full">
                <!-- 两组横向并排（标签顶部对齐，各占半宽；组内 label+checkbox 堆叠）。 -->
                <div class="autoban-scope-groups">
                  <div class="autoban-scope-group">
                    <div class="autoban-scope-group-label">{{ t('app.security.events.scopeGroupConfirmed') }}</div>
                    <el-checkbox-group v-model="autobanForm.scope">
                      <el-checkbox value="blocked">{{ autobanScopeLabel('blocked') }}</el-checkbox>
                      <el-checkbox value="challenge_failed">{{ autobanScopeLabel('challenge_failed') }}</el-checkbox>
                    </el-checkbox-group>
                  </div>
                  <div class="autoban-scope-group">
                    <div class="autoban-scope-group-label">{{ t('app.security.events.scopeGroupSuspicion') }}</div>
                    <el-checkbox-group v-model="autobanForm.scope">
                      <el-checkbox value="logged">{{ autobanScopeLabel('logged') }}</el-checkbox>
                      <el-checkbox value="challenge_issued">{{ autobanScopeLabel('challenge_issued') }}</el-checkbox>
                    </el-checkbox-group>
                  </div>
                </div>
                <div class="form-tip-line">{{ t('app.security.events.scopeHint') }}</div>
              </el-form-item>
              <el-form-item :label="t('app.security.events.windowLabel')">
                <el-input-number v-model="autobanForm.window_minutes" :min="1" :max="60" :step="5" controls-position="right" class="autoban-num" />
                <div class="form-tip-line">{{ t('app.security.events.windowHint') }}</div>
              </el-form-item>
              <el-form-item :label="t('app.security.events.thresholdLabel')">
                <el-input-number v-model="autobanForm.threshold" :min="1" :max="10000" :step="10" controls-position="right" class="autoban-num" />
                <div class="form-tip-line">{{ t('app.security.events.thresholdHint') }}</div>
              </el-form-item>
              <el-form-item>
                <template #label><span>{{ t(autobanFormEscalationOn ? 'app.security.events.firstBanDuration' : 'app.security.events.durationLabel') }}</span></template>
                <el-select v-model="autobanForm.duration" class="autoban-select">
                  <el-option v-for="d in AUTOBAN_DURATIONS" :key="d" :label="autobanDurationLabel(d)" :value="d" />
                </el-select>
                <div class="form-tip-line">{{ t('app.security.events.durationHint') }}</div>
              </el-form-item>
              <el-form-item :label="t('app.security.events.escalationLabel')">
                <el-select v-model="autobanForm.escalation" class="autoban-select" :disabled="autobanFormPermanentDuration">
                  <el-option v-for="e in AUTOBAN_ESCALATIONS" :key="e" :label="autobanEscalationLabel(e)" :value="e" />
                </el-select>
                <div class="form-tip-line">{{ t(autobanFormPermanentDuration ? 'app.security.events.escalationPermanentDisabledHint' : 'app.security.events.escalationHint') }}</div>
              </el-form-item>
              <!-- 升级阶梯预览：跨双列独立行（flex-basis:100% 强制断行，label 只与
                   select 单行居中）；off/永久档隐藏（各次相同时无信息量）。 -->
              <div v-if="autobanFormEscalationOn && !autobanFormPermanentDuration" class="autoban-ladder autoban-grid-full">
                <span class="autoban-ladder-label">{{ t('app.security.events.ladderTitle') }}</span>
                <span v-for="(d, i) in autobanLadderPreview" :key="i" class="autoban-ladder-step">{{ t('app.security.events.ladderOffense', { n: i + 1 }) }} {{ autobanDurationLabel(d) }}</span>
              </div>
              <el-form-item :label="t('app.security.events.countingModeLabel')" :class="autobanForm.counting_mode === 'evidence' ? '' : 'autoban-grid-full'">
                <el-select v-model="autobanForm.counting_mode" class="autoban-select">
                  <el-option value="classic" :label="t('app.security.events.countingClassic')" />
                  <el-option value="evidence" :label="t('app.security.events.countingEvidence')" />
                </el-select>
                <div class="form-tip-line">{{ t('app.security.events.countingModeHint') }}</div>
              </el-form-item>
              <template v-if="autobanForm.counting_mode === 'evidence'">
                <el-form-item :label="t('app.security.events.suspicionMultiplierLabel')">
                  <el-input-number v-model="autobanForm.suspicion_multiplier" :min="AUTOBAN_SUSPICION_MULTIPLIER_MIN" :max="AUTOBAN_SUSPICION_MULTIPLIER_MAX" :step="1" controls-position="right" class="autoban-num" />
                  <div class="form-tip-line">{{ t('app.security.events.suspicionMultiplierHint', { n: autobanForm.threshold * autobanForm.suspicion_multiplier }) }}</div>
                </el-form-item>
                <el-form-item :label="t('app.security.events.confirmFloorLabel')" class="autoban-grid-full">
                  <el-select v-model="autobanForm.confirm_floor_ratio" class="autoban-select">
                    <el-option v-for="f in AUTOBAN_CONFIRM_FLOOR_RATIOS" :key="f" :label="f" :value="f" />
                  </el-select>
                  <div class="form-tip-line">{{ t('app.security.events.confirmFloorHint', { n: autobanConfirmFloorCount }) }}</div>
                </el-form-item>
              </template>
            </div>
          </el-collapse-item>
        </el-collapse>
      </el-form>
      <div class="info-note-bar"><span class="info-note-desc">{{ t('app.security.events.counterResetNotice') }}</span></div>
      <template #footer>
        <el-button :disabled="autobanSaving" @click="autobanDialogVisible = false">{{ t('app.security.events.cancel') }}</el-button>
        <el-button type="primary" :loading="autobanSaving" :disabled="!autobanWritable" @click="saveAutobanConfig">{{ t('app.security.events.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- 封禁与累犯合并弹框（用户裁定：当前封禁列表与累犯弹框入口收敛为
         双 tab——「正在发生的封禁」与「历史前科记账」正交视图）。
         tab1 当前封禁：名单条目全功能（搜索/来源/剩余时长/解封/分页）；
         tab2 累犯前科：RecidivismTable 共享组件（总览下钻同款）。 -->
    <el-dialog v-model="banConsoleVisible" width="min(1280px, 96vw)" top="5vh" append-to-body class="ban-console-dialog dialog-body-inset" :close-on-click-modal="false">
      <template #header>
        <DialogHeader :icon="Lock" :title="t('app.security.events.banConsoleTitle')" :subtitle="t('app.security.events.banConsoleSubtitle')" />
      </template>
      <el-tabs v-model="banConsoleTab">
        <el-tab-pane :label="t('app.security.events.banConsoleTabBans', { n: autobanBansActive.length })" name="bans">
          <div class="recid-toolbar">
            <div class="recid-filters">
              <el-input v-model="banQuery" class="ban-query-input" size="small" :prefix-icon="Search" clearable :placeholder="t('app.security.events.banSearchPlaceholder')" />
            </div>
            <el-button size="small" :loading="autobanBansLoading" @click="fetchAutobanBans">{{ t('app.security.events.banRefresh') }}</el-button>
          </div>
          <el-table v-loading="autobanBansLoading" :data="autobanBansPaged" size="small" :height="480" :header-cell-style="{ background: '#f9fafb' }">
            <template #empty><el-empty :description="t('app.security.events.bansEmpty')" :image-size="60" /></template>
            <el-table-column :label="t('app.security.overview.autoban.colIdentity')" min-width="240">
              <template #default="{ row }"><IPLocationAction :ip="row.value" :location="''" @changed="onBanIpChanged" /></template>
            </el-table-column>
            <el-table-column :label="t('app.security.events.banSource')" width="110" align="center">
              <template #default="{ row }">
                <el-tag size="small" effect="plain" :type="row.remark === '自动封禁' ? 'warning' : 'info'">{{ row.remark === '自动封禁' ? t('app.security.events.banSourceAuto') : t('app.security.events.banSourceManual') }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.security.events.banRemaining')" width="170" align="center">
              <template #default="{ row }">
                <el-tag v-if="!row.expires_at" size="small" effect="plain" type="danger">{{ t('app.security.events.banPermanent') }}</el-tag>
                <el-tag v-else-if="autobanEntryExpired(row.expires_at)" size="small" effect="plain" type="info">{{ t('app.security.events.banExpired') }}</el-tag>
                <el-tooltip v-else :content="formatDate(row.expires_at)" placement="top">
                  <span class="text-secondary">{{ autobanEntryRemaining(row.expires_at) }}</span>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column :label="t('app.security.events.banCreatedAt')" width="170">
              <template #default="{ row }">{{ row.created_at ? formatDate(row.created_at) : '—' }}</template>
            </el-table-column>
            <el-table-column v-if="autobanWritable" :label="t('app.security.events.colAction')" width="100" align="center">
              <template #default="{ row }">
                <el-button size="small" type="primary" plain :disabled="autobanUnbanning" @click="unbanAutobanEntry(row as AutobanBanEntry)">{{ t('app.security.events.banRemoveVerb') }}</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div class="ban-console-bottom">
            <span class="form-tip-inline">{{ t('app.security.events.banConsoleCountNote', { active: autobanBansActive.length, total: autobanBansFiltered.length }) }}</span>
            <el-pagination v-model:current-page="banPage" v-model:page-size="banPageSize" :total="autobanBansFiltered.length" :page-sizes="[20, 50, 100]" layout="total, sizes, prev, pager, next" small />
          </div>
        </el-tab-pane>
        <el-tab-pane :label="t('app.security.events.banConsoleTabRecid')" name="recid">
          <RecidivismTable :active="banConsoleVisible && banConsoleTab === 'recid'" :writable="autobanWritable" :blocked-reason="autobanConfigTooltip" :duration="autobanStatus.duration" :escalation="autobanStatus.escalation" @reset="fetchAutobanStatus" />
        </el-tab-pane>
      </el-tabs>
      <template #footer>
        <el-button @click="banConsoleVisible = false">{{ t('app.security.overview.autoban.recidivismClose') }}</el-button>
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
        <DialogHeader :icon="Document" :title="t('app.security.events.ctxTitle')"
          :subtitle="ctxSubtitle" />
      </template>
      <template v-if="ctxEvent">
        <section class="ctx-detail-section">
          <DialogSectionHeader :title="t('app.security.events.ctxSummary')" />
          <div class="dialog-panel dialog-panel--flush">
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item :label="t('app.security.events.colTime')">{{ ctxEvent.event_time ? formatDate(ctxEvent.event_time) : '—' }}</el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.colMethod')">{{ ctxIsTcp ? t('app.security.events.tcpPlaceholder') : (ctxEvent.method || '—') }}</el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.colClientIp')"><span style="overflow-wrap: anywhere">{{ ctxEvent.client_ip || '—' }}</span></el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.ctxLocation')">{{ ctxEvent.ip_location || '—' }}</el-descriptions-item>
              <el-descriptions-item label="URI" :span="2">{{ ctxIsTcp ? t('app.security.events.tcpPlaceholder') : (ctxEvent.uri || '—') }}</el-descriptions-item>
              <!-- 规则协议徽标（数据源=event_type；字段缺失不显示——防御式）：
                   TCP 青 = 全局 proto-tcp-tag 单源，HTTP 蓝 = el-tag primary -->
              <el-descriptions-item :label="t('app.security.events.ctxTriggeredRule')"><el-tag v-if="ctxEvent.event_type === 'tcp'" size="small" effect="plain" class="proto-tcp-tag event-proto-tag">TCP</el-tag><el-tag v-else-if="ctxEvent.event_type" size="small" type="primary" effect="plain" class="event-proto-tag">HTTP</el-tag>{{ [ctxEvent.rule_name, ctxEvent.rule_triggered ? `id:${ctxEvent.rule_triggered}` : ''].filter(Boolean).join(' · ') || '—' }}</el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.ctxPolicy')">{{ ctxEvent.policy_name || '—' }}</el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.colAction')">
                <el-tag size="small" :type="eventActionTone(ctxEvent.action, ctxEvent.rule_triggered)" effect="plain">
                  {{ eventActionFull(ctxEvent.action, ctxEvent.rule_triggered) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.colScore')">{{ ctxEvent.anomaly_score > 0 ? ctxEvent.anomaly_score : '—' }}</el-descriptions-item>
              <el-descriptions-item :label="t('app.security.events.ctxDuration')">{{ formatDurationUs(ctxWafFamily ? ctxEvent.duration_us + ctxEvent.precheck_us : ctxEvent.duration_us) }}{{ ctxWafFamily ? '' : t('app.security.events.ctxPrecheckSuffix') }}</el-descriptions-item>
              <el-descriptions-item v-if="ctxWafFamily && ctxEvent.precheck_us > 0" :label="t('app.security.events.ctxDurationBreakdown')">{{ t('app.security.events.ctxDurationBreakdownValue', { precheck: formatDurationUs(ctxEvent.precheck_us), waf: formatDurationUs(ctxEvent.duration_us) }) }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </section>

        <!-- TCP（L4）事件无请求语义：请求头/请求体区块整段隐藏（连接级事件无 HTTP 明细） -->
        <section v-if="!ctxIsTcp" class="ctx-detail-section">
          <DialogSectionHeader :title="t('app.security.events.ctxHeadersTitle')" />
          <template v-if="ctxHeadersParsed.failed">
            <div class="info-note-bar ctx-banner"><span class="info-note-desc">{{ t('app.security.events.ctxHeadersParseFail') }}</span></div>
            <div class="dialog-panel dialog-panel--flush"><pre class="ctx-body-pre">{{ ctxEvent.request_headers }}</pre></div>
          </template>
          <template v-else-if="ctxHeadersParsed.rows.length > 0 || ctxHeadersParsed.dropped > 0 || ctxHeadersParsed.listDropped > 0">
            <div class="dialog-panel" :class="{ 'dialog-panel--flush': ctxHeadersParsed.rows.length > 0 }">
              <div v-if="ctxHeadersParsed.dropped > 0" class="ctx-info-line">{{ t('app.security.events.ctxHeadersDropped', { count: ctxHeadersParsed.dropped }) }}</div>
              <div v-if="ctxHeadersParsed.listDropped > 0" class="ctx-info-line">{{ t('app.security.events.ctxHeadersListDropped', { count: ctxHeadersParsed.listDropped }) }}</div>
              <el-table v-if="ctxHeadersParsed.rows.length > 0" :data="ctxHeadersParsed.rows" size="small" :max-height="260" :header-cell-style="{ background: '#f9fafb' }">
                <el-table-column prop="name" :label="t('app.security.events.ctxHeaderName')" width="200" show-overflow-tooltip />
                <el-table-column :label="t('app.security.events.ctxHeaderValue')" min-width="380">
                  <template #default="{ row }">
                    <div class="ctx-header-value-cell">
                      <span class="ctx-header-value">{{ ctxHeaderDisplay(row as CtxHeaderRow) }}</span>
                      <el-button
                        v-if="row.sensitive"
                        link
                        type="primary"
                        size="small"
                        class="ctx-reveal-btn"
                        :title="ctxRevealed.has(row.name.toLowerCase()) ? t('app.security.events.ctxRevealHide') : t('app.security.events.ctxRevealShow')"
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
          <div v-else class="dialog-panel"><div class="ctx-empty">{{ t('app.security.events.ctxHeadersEmpty') }}</div></div>
        </section>

        <section v-if="!ctxIsTcp" class="ctx-detail-section">
          <DialogSectionHeader :title="t('app.security.events.ctxBodyTitle')" />
          <div v-if="ctxBodyParsed.state === 'empty'" class="dialog-panel"><div class="ctx-empty">{{ ctxBodyEmptyText }}</div></div>
          <template v-else>
            <div v-if="ctxBodyParsed.truncated" class="info-note-bar ctx-banner"><span class="info-note-desc">{{ t('app.security.events.ctxBodyTruncated') }}</span></div>
            <div v-if="ctxBodyParsed.binary" class="info-note-bar"><span class="info-note-desc">{{ t('app.security.events.ctxBodyBinary') }}</span></div>
            <div v-if="ctxBodyParsed.state === 'error'" class="info-note-bar ctx-banner"><span class="info-note-desc">{{ t('app.security.events.ctxBodyDecodeFail') }}</span></div>
            <div class="dialog-panel dialog-panel--flush"><pre class="ctx-body-pre">{{ ctxBodyParsed.text }}</pre></div>
          </template>
        </section>
      </template>
      <template #footer>
        <el-button @click="ctxDialogVisible = false">{{ t('app.security.events.close') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Refresh, Warning, View, Hide, Document, Lock, Search } from '@element-plus/icons-vue'
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
import { autobanStateLabel, autobanStatValue, isAutobanIneffective, autobanSuggestedDurationKey, autobanDurationLabel, autobanEscalationShortKey, autobanEscalationLadder, suggestionBand, type SuggestionBand } from '@/utils/autobanStatus'
import { AUTOBAN_PRESETS, AUTOBAN_PRESET_IDS, AUTOBAN_SUSPICION_MULTIPLIER_MIN, AUTOBAN_SUSPICION_MULTIPLIER_MAX, AUTOBAN_CONFIRM_FLOOR_RATIOS, matchAutobanPreset, type AutobanPresetId } from '@/utils/autobanPresets'
import { autobanEntryExpired, autobanEntryRemaining } from '@/utils/autobanEntry'
import { useIpListAdd } from '@/composables/useIpListAdd'
import { parseRefIds, invalidateSharedEntriesCache } from '@/utils/securityStages'
import { showSaveResult } from '@/utils/saveResult'
import { requestBodyEmptyNotice, viewerCanReadRequestBody } from '@/utils/requestBodyAccess'
import { activateOnce } from '@/utils/keyboardActivate'
import IPLocationAction from '@/views/security/IPLocationAction.vue'
import RecidivismTable from '@/components/security/RecidivismTable.vue'
import { formatDate } from '@/utils/date'
import { eventActionFull, eventActionShort, eventActionTone } from '@/utils/eventAction'
import { ingestionWarningMessage, type IngestionHealth } from '@/utils/ingestionHealth'
import type { APIResponse } from '@/types'

const { t } = useI18n()

interface SecurityEvent { id: number; event_time: string; rule_caddy_id: string; rule_name: string; policy_id: number; policy_name: string; client_ip: string; ip_location: string; method: string; uri: string; event_type: string; rule_triggered: string; rule_msg: string; trigger_type?: string; action: string; anomaly_score: number; duration_us: number; precheck_us: number; request_headers: string; request_body: string }

// 自动封禁：状态卡/配置弹框 ——

interface AutobanSuggestion { ip: string; count: number; ip_location?: string; window_start?: string; last_seen?: string; confirmed_count?: number; suspicion_count?: number }
interface AutobanStatus {
  enabled: boolean; dry_run: boolean; threshold: number; window_minutes: number
  duration: string; scope: string; banned_today: number; list_entries: number
  // 黄条判据 = 封禁是否真正生效（IP 名单通道：名单非空且被启用中的 deny 策略引用）。
  // 后端 list_referenced 为热路径资格门的四面引用集（含白名单/受信代理/CRS
  // 排除），不能区分「引用」与「拦截生效」——纯后端内部字段，本卡不声明不消费。
  ban_effective: boolean
  // 累犯披露键（旧后端缺省 → 档位按 off、升级数按 0，防御式消费）。
  escalation?: string; escalated_count?: number
  // 证据分层计数键（旧后端缺省 → classic/4/0.4，防御式消费）。
  counting_mode?: string; suspicion_multiplier?: number; confirm_floor_ratio?: string
  // 自动封禁预置名单 id（卡片当前封禁列表数据源；旧后端缺省 → 不渲染列表）。
  list_id?: number
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
// 配置弹框回填/保存用的配置形态（GET/PUT /security/autoban 契约）。
interface AutobanConfig {
  enabled: boolean; dry_run: boolean; threshold: number; window_minutes: number
  duration: string; scope: string
  escalation: string
  counting_mode?: string; suspicion_multiplier?: number; confirm_floor_ratio?: string
}
const AUTOBAN_DURATIONS = ['10m', '30m', '1h', '6h', '12h', '24h', 'permanent']
const AUTOBAN_SCOPES = ['blocked', 'logged', 'challenge_issued', 'challenge_failed']
const AUTOBAN_SCOPE_DEFAULT = ['blocked', 'logged', 'challenge_issued', 'challenge_failed']
const AUTOBAN_ESCALATIONS = ['off', 'standard', 'aggressive']
const autobanEscalationLabel = (value: string): string => {
  switch (value) {
    case 'standard': return t('app.security.events.escalationStandard')
    case 'aggressive': return t('app.security.events.escalationAggressive')
    default: return t('app.security.events.escalationOff')
  }
}
// 时长标签单源 utils/autobanStatus.autobanDurationLabel（总览/累犯弹框共用，
// events.duration* 词条；未知值原样回显）。
const autobanScopeLabel = (value: string): string => {
  switch (value) {
    case 'blocked': return t('app.security.events.scopeBlocked')
    case 'logged': return t('app.security.events.scopeLogged')
    case 'challenge_issued': return t('app.security.events.scopeChallengeIssued')
    case 'challenge_failed': return t('app.security.events.scopeChallengeFailed')
    default: return value
  }
}
// 集合字符串 ↔ 数组互转（过滤非法成员；空集回退默认全选）。
const parseAutobanScope = (scope: string): string[] => {
  const parts = (scope || '').split(',').map(s => s.trim()).filter(s => AUTOBAN_SCOPES.includes(s))
  return parts.length > 0 ? parts : [...AUTOBAN_SCOPE_DEFAULT]
}
const autobanScopeTextOf = (scope: string): string => parseAutobanScope(scope).map(autobanScopeLabel).join(' + ')

const autobanStatus = ref<AutobanStatus>({
  enabled: false, dry_run: true, threshold: 100, window_minutes: 5, duration: '1h', scope: 'blocked,logged,challenge_issued,challenge_failed',
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
// 黄条判据单源（utils/autobanStatus，行为钉测）：仅 enabled ∧ ban_effective===false。
const autobanIneffective = computed(() => isAutobanIneffective(autobanStatus.value))
// 喂入源降级：仅在启用时提示（未启用时「不计数」无需解释）
const autobanFeedDegraded = computed(() => autobanStatus.value.enabled && autobanStatus.value.feed_degraded === true)
const authStore = useAuthStore()
// 四写入口统一门控（启用/禁用/编辑/保存）：全局只读契约 ∧ 主节点 ∧ 状态已加载
const autobanWritable = computed(() => authStore.readOnlyReason === null && autobanStatus.value.is_master && !autobanStatusError.value && !autobanStatusLoading.value)
const autobanBlockedReason = computed(() => {
  if (authStore.readOnlyReason !== null) return authStore.readOnlyMessage
  if (!autobanStatus.value.is_master) return t('app.security.events.blockedReasonMasterOnly')
  return ''
})
const autobanConfigTooltip = computed(() => {
  if (autobanWritable.value) return ''
  if (autobanStatusLoading.value) return t('app.security.events.blockedReasonLoading')
  if (autobanStatusError.value) return t('app.security.events.blockedReasonLoadFail')
  return autobanBlockedReason.value
})
const autobanScopeText = computed(() => autobanScopeTextOf(autobanStatus.value.scope))
const autobanDurationText = computed(() => autobanDurationLabel(autobanStatus.value.duration))
// 累犯升级开启时「封禁时长」语义收窄为「首封时长」（用户裁定方案 A）：
// 弹框标签/状态卡摘要同口径切换；判据与后端 autobanEscalatedDuration 档位
// 映射同口径（standard：首封配置时长→二次 24h→三次起永久；aggressive：首封
// 配置时长→二次起永久）。阶梯口径在累犯升级项 hint 披露，时长项不挂角标。
const autobanStatusEscalationOn = computed(() =>
  autobanStatus.value.escalation === 'standard' || autobanStatus.value.escalation === 'aggressive')
const autobanFormEscalationOn = computed(() =>
  autobanForm.value.escalation === 'standard' || autobanForm.value.escalation === 'aggressive')
// 方案 A：永久时长下升级无意义——弹框 escalation 选择禁用；切到永久时自动
// 归 off（直观披露：用户看到档位被重置，而非保留一个永不生效的值）。
const autobanFormPermanentDuration = computed(() => autobanForm.value.duration === 'permanent')

// 累犯前科面已并入「封禁与累犯」合并弹框 tab2（RecidivismTable 共享组件）。

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

// 配置弹框（七项配置 + 口径/窗口变更重置提示）
const autobanDialogVisible = ref(false)
const autobanSaving = ref(false)
const autobanForm = ref({ dry_run: true, threshold: 100, window_minutes: 5, duration: '1h', scope: [...AUTOBAN_SCOPE_DEFAULT] as string[], escalation: 'off', counting_mode: 'classic', suspicion_multiplier: 4, confirm_floor_ratio: '0.4' })
watch(() => autobanForm.value.duration, (duration) => {
  if (duration === 'permanent' && autobanForm.value.escalation !== 'off') autobanForm.value.escalation = 'off'
})
// 高级折叠态（预设档位卡片常显，详细参数收进折叠）。
const autobanAdvancedOpen = ref<string[]>([])
// 当前表单匹配的预设档位（null=自定义）；选预设=整组回填，改参数自动落自定义。
const autobanActivePreset = computed<AutobanPresetId | null>(() => matchAutobanPreset(autobanForm.value))
const applyAutobanPreset = (id: AutobanPresetId): void => {
  const p = AUTOBAN_PRESETS[id]
  autobanForm.value = { ...autobanForm.value, threshold: p.threshold, window_minutes: p.window_minutes, duration: p.duration, scope: [...p.scope], escalation: p.escalation, counting_mode: p.counting_mode, suspicion_multiplier: p.suspicion_multiplier, confirm_floor_ratio: p.confirm_floor_ratio }
}
// 升级阶梯预览（第 1/2/3 次封禁时长，复用 autobanNextBanDuration 跨栈口径）。
const autobanLadderPreview = computed(() => autobanEscalationLadder({ duration: autobanForm.value.duration, escalation: autobanForm.value.escalation }))
// 确证打底次数（⌈阈值×比例⌉，与后端 autobanEvidenceFloor 千分比整数同口径）——
// hint 文案动态显示具体次数，不怼公式。
const autobanConfirmFloorCount = computed(() => {
  const permille = Math.round(parseFloat(autobanForm.value.confirm_floor_ratio) * 1000)
  return Math.ceil(autobanForm.value.threshold * permille / 1000)
})
// 七项配置实态缓存（GET /security/autoban）：/status 不携带全部配置项时
// 弹框回填与禁用直切的兜底源；null=未成功拉取（回填退 /status 已知键）。
const autobanConfigCache = ref<AutobanConfig | null>(null)
const fetchAutobanConfig = async (): Promise<void> => {
  try {
    const res = await request.get<APIResponse<AutobanConfig>>('/security/autoban', { silent: true })
    if (res.data) autobanConfigCache.value = res.data
  } catch { /* 静默：回填退 /status 已知键，不阻塞弹框 */ }
}
const openAutobanConfig = (): void => {
  // 卡片主体/编辑/启用共用门：只读、从节点、状态加载中或加载失败均不打开
  // 配置弹框；表单从 autobanStatus（新键）/配置缓存回填，错误态默认值保存
  // 会覆盖真实配置。
  if (!autobanWritable.value) return
  const cfg = autobanConfigCache.value
  autobanForm.value = {
    dry_run: autobanStatus.value.dry_run,
    threshold: autobanStatus.value.threshold, window_minutes: autobanStatus.value.window_minutes,
    duration: autobanStatus.value.duration, scope: parseAutobanScope(autobanStatus.value.scope),
    escalation: autobanStatus.value.escalation ?? cfg?.escalation ?? 'off',
    counting_mode: autobanStatus.value.counting_mode ?? cfg?.counting_mode ?? 'classic',
    suspicion_multiplier: autobanStatus.value.suspicion_multiplier ?? cfg?.suspicion_multiplier ?? 4,
    confirm_floor_ratio: autobanStatus.value.confirm_floor_ratio ?? cfg?.confirm_floor_ratio ?? '0.4',
  }
  // 每次打开重置高级折叠为收起（弹框 DOM 常驻，展开态不得跨会话残留）。
  autobanAdvancedOpen.value = []
  autobanDialogVisible.value = true
}
const saveAutobanConfig = async (): Promise<void> => {
  // 函数级纵深守卫（与 openAutobanConfig 同构）：按钮 :disabled 仅呈现层
  if (!autobanWritable.value) return
  if (autobanForm.value.threshold < 1 || autobanForm.value.threshold > 10000) {
    ElMessage.warning(t('app.security.events.thresholdRange')); return
  }
  if (autobanForm.value.window_minutes < 1 || autobanForm.value.window_minutes > 60) {
    ElMessage.warning(t('app.security.events.windowRange')); return
  }
  if (autobanForm.value.scope.length === 0) {
    ElMessage.warning(t('app.security.events.scopeEmpty')); return
  }
  // 保存二次确认（用户裁定 2026-10-14）：启用入口=完整须知+建议框（按钮「确认启用」）；
  // 已启用的编辑入口=简化确认（按钮「确认保存」，不带启用描述警告）。
  // 弹框无启用开关（外卡片持有启停职责）——payload enabled 恒 true（启用或保持）。
  if (autobanStatus.value.enabled) {
    try {
      await ElMessageBox.confirm(t('app.security.events.saveConfirm'), t('app.security.events.saveConfigTitle'), {
        confirmButtonText: t('app.security.events.confirmSave'), cancelButtonText: t('app.security.events.cancel'), type: 'info',
      })
    } catch { return }
  } else if (!(await confirmAutobanApply())) return
  autobanSaving.value = true
  try {
    await request.put('/security/autoban', { ...autobanForm.value, scope: autobanForm.value.scope.join(','), enabled: true })
    mfaAwareSuccess(t('app.security.events.configUpdated'))
    autobanDialogVisible.value = false
    fetchAutobanStatus()
    void fetchAutobanConfig()
  } catch { /* 错误已由全局拦截器 toast */ }
  finally { autobanSaving.value = false }
}

// 启用二次确认（2026-10-14 用户裁定）：enabled 关→开的保存动作先确认——
// 威胁库+CRS+地域拦截已覆盖绝大多数恶意请求，自动封禁定位是少量高频攻击者
// 的资源救济；建议观察模式起步校准后转正式。取消=不保存。
// 排版：dangerouslyUseHTMLString 精排两段（启用前须知三条列表 + 使用建议正文），
// MessageBox 挂 body → 样式放非 scoped 块。纯静态文案、无任何用户输入插值，无注入面。
const autobanEnableConfirmHtml = computed(() => `
<div class="autoban-confirm">
  <div class="autoban-confirm-hero">
    <div class="autoban-confirm-icon"><svg viewBox="0 0 1024 1024" width="22" height="22"><path d="M512 64a448 448 0 1 1 0 896 448 448 0 0 1 0-896z m0 192a32 32 0 0 0-32 32v256a32 32 0 0 0 64 0V288a32 32 0 0 0-32-32z m0 416a48 48 0 1 0 0-96 48 48 0 0 0 0 96z" fill="currentColor"/></svg></div>
    <div class="autoban-confirm-head">
      <div class="autoban-confirm-heading">${t('app.security.events.enableHeading')}</div>
      <div class="autoban-confirm-sub">${t('app.security.events.enableSub')}</div>
    </div>
  </div>
  <div class="autoban-confirm-notes">
    <div class="autoban-confirm-note"><span class="autoban-confirm-dot"></span>${t('app.security.events.enableNote1')}</div>
    <div class="autoban-confirm-note"><span class="autoban-confirm-dot"></span>${t('app.security.events.enableNote2')}</div>
    <div class="autoban-confirm-note"><span class="autoban-confirm-dot"></span>${t('app.security.events.enableNote3')}</div>
  </div>
  <div class="autoban-confirm-howto"><span class="autoban-confirm-howto-label">${t('app.security.events.enableHowtoLabel')}</span>${t('app.security.events.enableHowtoText')}</div>
</div>`)
const confirmAutobanApply = async (): Promise<boolean> => {
  try {
    await ElMessageBox.confirm(autobanEnableConfirmHtml.value, t('app.security.events.enableConfirmTitle'), {
      confirmButtonText: t('app.security.events.confirmEnable'),
      cancelButtonText: t('app.security.events.cancel'),
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
// 开 autoban 循环调度、false 停。PUT 需全量七项配置，从状态卡实态回填。
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
      t('app.security.events.disableConfirm'),
      t('app.security.events.disableConfirmTitle'),
      { confirmButtonText: t('app.security.events.confirmDisable'), cancelButtonText: t('app.security.events.cancel'), type: 'warning' },
    )
    await request.put('/security/autoban', {
      enabled: false,
      dry_run: autobanStatus.value.dry_run,
      threshold: autobanStatus.value.threshold,
      window_minutes: autobanStatus.value.window_minutes,
      duration: autobanStatus.value.duration,
      scope: autobanStatus.value.scope,
      // escalation 从 /status 实态回填（旧后端缺键退配置缓存/缺省，与弹框回填同口径）
      escalation: autobanStatus.value.escalation ?? autobanConfigCache.value?.escalation ?? 'off',
      counting_mode: autobanStatus.value.counting_mode ?? autobanConfigCache.value?.counting_mode ?? 'classic',
      suspicion_multiplier: autobanStatus.value.suspicion_multiplier ?? autobanConfigCache.value?.suspicion_multiplier ?? 4,
      confirm_floor_ratio: autobanStatus.value.confirm_floor_ratio ?? autobanConfigCache.value?.confirm_floor_ratio ?? '0.4',
    })
    mfaAwareSuccess(t('app.security.events.disabledNotice'))
    fetchAutobanStatus()
  } catch { /* 取消无需处理；请求错误已由全局拦截器 toast */ }
  finally { autobanToggling.value = false }
}

// —— 封禁与累犯合并弹框（双 tab）：tab1 当前封禁全功能（搜索/来源/分页/解封），
//    tab2 累犯前科（RecidivismTable 共享组件）。数据源=名单 API（list_id 由
//    status 投影）；名单条目含手动封禁与到期残留（与累犯记账正交）。 ——
interface AutobanBanEntry { value: string; remark: string; created_at?: string; expires_at?: string }
const banConsoleVisible = ref(false)
const banConsoleTab = ref<'bans' | 'recid'>('bans')
const autobanBans = ref<AutobanBanEntry[]>([])
const autobanBansLoading = ref(false)
const banQuery = ref('')
const banPage = ref(1)
const banPageSize = ref(20)
// 生效条目（未到期）——tab 标题计数与 status.list_entries 同口径（后端
// AutobanActiveEntries 过滤已到期）；表体保留到期残留行（「已到期」态可清理）。
const autobanBansActive = computed(() => autobanBans.value.filter((e) => !e.expires_at || !autobanEntryExpired(e.expires_at)))
const autobanBansFiltered = computed(() => {
  const q = banQuery.value.trim().toLowerCase()
  if (!q) return autobanBans.value
  return autobanBans.value.filter((e) => e.value.toLowerCase().includes(q))
})
const autobanBansPaged = computed(() => {
  const maxPage = Math.max(1, Math.ceil(autobanBansFiltered.value.length / banPageSize.value))
  if (banPage.value > maxPage) banPage.value = maxPage
  const start = (banPage.value - 1) * banPageSize.value
  return autobanBansFiltered.value.slice(start, start + banPageSize.value)
})
watch(banQuery, () => { banPage.value = 1 })
const fetchAutobanBans = async (): Promise<void> => {
  const listId = autobanStatus.value.list_id
  if (!listId) return
  autobanBansLoading.value = true
  try {
    const res = await request.get<APIResponse<{ entries?: AutobanBanEntry[] }>>(`/security/ip-lists/${listId}`, { silent: true })
    autobanBans.value = res.data?.entries ?? []
  } catch { /* 静默：错误态由全局拦截器/重试按钮承载 */ }
  finally { autobanBansLoading.value = false }
}
const openBanConsole = (tab: 'bans' | 'recid'): void => {
  banConsoleTab.value = tab
  banConsoleVisible.value = true
  if (tab === 'bans') void fetchAutobanBans()
}
// tab 切回 bans 时重取（名单可能已被其他面改动）；status 刷新后跟进
// （onMounted/手动刷新/写动作后触发——无定时器轮询，注释与实现一致）。
watch(banConsoleTab, (tab) => { if (tab === 'bans' && banConsoleVisible.value) void fetchAutobanBans() })
watch(() => autobanStatus.value.list_entries, () => { if (banConsoleVisible.value && banConsoleTab.value === 'bans') void fetchAutobanBans() })
const autobanUnbanning = ref(false)
const unbanAutobanEntry = async (entry: AutobanBanEntry): Promise<void> => {
  const listId = autobanStatus.value.list_id
  if (!listId || autobanUnbanning.value || !autobanWritable.value) return
  autobanUnbanning.value = true
  try {
    await ElMessageBox.confirm(
      t('app.security.events.banRemoveConfirm', { ip: entry.value }),
      t('app.security.events.banRemoveTitle'),
      { confirmButtonText: t('app.security.events.banRemoveOk'), cancelButtonText: t('app.security.events.cancel'), type: 'warning' },
    )
    const res = await request.post(`/security/ip-lists/${listId}/remove-ip`, { value: entry.value })
    showSaveResult(res as unknown as { message?: string }, t('app.security.events.banRemovedToast', { ip: entry.value }))
    invalidateSharedEntriesCache()
    await Promise.all([fetchAutobanBans(), fetchAutobanStatus()])
  } catch { /* 取消/失败由确认框/全局拦截器处理 */ }
  finally { autobanUnbanning.value = false }
}
// 身份列 popover 内解封/处置完成 → 即时重取（@changed 联动，不滞留旧态）。
const onBanIpChanged = (): void => {
  void fetchAutobanBans()
  void fetchAutobanStatus()
}

// —— 未生效一键修复：把 autoban 名单绑到启用中的 deny 策略（复用补引用链）——
const autobanFixing = ref(false)
const fixAutobanIneffective = async (): Promise<void> => {
  const listId = autobanStatus.value.list_id
  if (!listId || autobanFixing.value || !autobanWritable.value) return
  autobanFixing.value = true
  try {
    const res = await request.get<APIResponse<Array<{ id: number; name: string; enabled: boolean; ip_acl_enabled: boolean; ip_acl_mode: string; ip_acl_list_refs?: string }>>>('/security/policies?enabled=true', { silent: true })
    const candidates = (res.data ?? []).filter((p) => p.enabled && p.ip_acl_enabled && p.ip_acl_mode === 'deny')
    if (candidates.length === 0) {
      // 无可用 deny 策略：深链引导创建。
      window.open(pageUrl('security-policies'), '_blank', 'noopener')
      ElMessage.info(t('app.security.events.fixNoPolicy'))
      return
    }
    const target = candidates[0]
    await ElMessageBox.confirm(
      t('app.security.events.fixConfirm', { policy: target.name }),
      t('app.security.events.fixTitle'),
      { confirmButtonText: t('app.security.events.fixOk'), cancelButtonText: t('app.security.events.cancel'), type: 'info' },
    )
    // 确认后重读最新 refs（防并发覆盖，与 useTrustAssociation 同口径）。
    const latest = await request.get<APIResponse<{ policy?: { ip_acl_list_refs?: string } }>>(`/security/policies/${target.id}`, { silent: true })
    const refs = parseRefIds(latest.data?.policy?.ip_acl_list_refs)
    if (refs.includes(listId)) { ElMessage.info(t('app.security.events.fixAlready')); await fetchAutobanStatus(); return }
    await request.put(`/security/policies/${target.id}`, { ip_acl_list_refs: JSON.stringify([...refs, listId]) })
    mfaAwareSuccess(t('app.security.events.fixDone'))
    await fetchAutobanStatus()
  } catch { /* 取消/失败由确认框/全局拦截器处理 */ }
  finally { autobanFixing.value = false }
}

// —— 观察闭环：候选行封禁（复用 useIpListAdd）+ 开始执法（PUT dry_run=false）——
const { addIpToList } = useIpListAdd()
const banSuggestion = async (row: AutobanSuggestion): Promise<void> => {
  const listId = autobanStatus.value.list_id
  if (!listId || !autobanWritable.value) return
  const ok = await addIpToList(row.ip, { id: listId, name: t('app.security.events.autobanListName'), entry_count: autobanStatus.value.list_entries }, { verb: t('app.security.events.banVerb') })
  if (ok) await fetchAutobanStatus()
}
const autobanEnforcing = ref(false)
const startAutobanEnforcement = async (): Promise<void> => {
  if (autobanEnforcing.value || !autobanWritable.value) return
  autobanEnforcing.value = true
  try {
    await ElMessageBox.confirm(
      t('app.security.events.enforceConfirm'),
      t('app.security.events.enforceTitle'),
      { confirmButtonText: t('app.security.events.enforceOk'), cancelButtonText: t('app.security.events.cancel'), type: 'warning' },
    )
    await request.put('/security/autoban', {
      enabled: true, dry_run: false,
      threshold: autobanStatus.value.threshold, window_minutes: autobanStatus.value.window_minutes,
      duration: autobanStatus.value.duration, scope: autobanStatus.value.scope,
      escalation: autobanStatus.value.escalation ?? autobanConfigCache.value?.escalation ?? 'off',
      counting_mode: autobanStatus.value.counting_mode ?? autobanConfigCache.value?.counting_mode ?? 'classic',
      suspicion_multiplier: autobanStatus.value.suspicion_multiplier ?? autobanConfigCache.value?.suspicion_multiplier ?? 4,
      confirm_floor_ratio: autobanStatus.value.confirm_floor_ratio ?? autobanConfigCache.value?.confirm_floor_ratio ?? '0.4',
    })
    mfaAwareSuccess(t('app.security.events.enforceDone'))
    await fetchAutobanStatus()
  } catch { /* 取消/失败由确认框/全局拦截器处理 */ }
  finally { autobanEnforcing.value = false }
}
// evidence 双分数展示判据（classic 不渲染分段）。
const autobanIsEvidence = computed(() => (autobanStatus.value.counting_mode ?? 'classic') === 'evidence')

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
const stageCategory = (row: SecurityEvent): 'trust' | 'acl' | 'crawler' | 'waf' | 'body' | 'human' | 'other' => {
  const trig = row.rule_triggered
  if (!trig) return 'other'
  switch (triggerStageFamily(trig)) {
    case 'trust': return 'trust'
    case 'crawler': return 'crawler'
    case 'ipAcl': case 'geoip': case 'threat': return 'acl'
    case 'wafCrs': case 'wafCustom': return 'waf'
    case 'body': return 'body'
    case 'human': return 'human'
    default: return 'other'
  }
}

// 触发类型显示映射:后端 trigger_type 为 zh 码(en 用户经此译;zh 用户命中 zh 词条同文)。
// 未登记值回落原文(新触发类型不因缺词条而丢失)。键集与后端 triggerTypeForRule
// 现行词对齐（爬虫Bot/WAF·CRS/WAF·自定义/威胁情报库/请求体异常/其他/CC防护）；
// 「爬虫豁免/手动黑名单」为存量事件词，保留兼容。
const TRIGGER_TYPE_KEYS: Record<string, string> = {
  'IP 访问控制': 'ipAcl',
  '地域拦截': 'geoBlock',
  '信任名单': 'trustList',
  '爬虫豁免': 'crawlerExempt',
  '手动黑名单': 'manualBlacklist',
  'CC防护': 'ccProtection',
  '爬虫Bot': 'crawlerBot',
  '威胁情报库': 'threatIntel',
  '请求体异常': 'bodyAnomaly',
  'WAF·CRS': 'wafCrs',
  'WAF·自定义': 'wafCustom',
  'CC 防护': 'ccProtectionSpaced',
  '其他': 'other',
}
const triggerTypeLabel = (raw?: string): string => {
  if (!raw) return '—'
  const k = TRIGGER_TYPE_KEYS[raw]
  return k ? t(`app.security.events.triggerType.${k}`) : raw
}

const stageLabel = (row: SecurityEvent): string => {
  // 存量 id '8' 中和文案（勿改分类——triggerStageFamily 对 8 归 ipAcl 是已钉住
  // 的历史共享 id 口径例外）：后端 trigger_type 显示「地域拦截」，阶段列沿用
  // IP 访问控制会自相矛盾；现代引擎地域事件已发 800xxx，仅存量/带外数据可达。
  if (row.rule_triggered === '8') return t('app.security.events.stageLegacyGeo')
  switch (stageCategory(row)) {
    case 'trust': return t('app.security.events.trustList')
    case 'crawler': return CRAWLER_FAMILY_LABEL
    case 'acl': return t('app.security.events.ipAcl')
    case 'waf': return 'WAF'
    case 'body': return t('app.security.events.bodyAnomaly')
    case 'human': return t('app.security.events.stageHuman')
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
// TCP（L4 断连）事件：无请求语义——method/uri 空、无请求头/请求体，
// 详情弹框按连接级形态渲染（占位符 + 隐藏 headers/body 区块）。
const ctxIsTcp = computed(() => ctxEvent.value?.event_type === 'tcp')
const ctxSubtitle = computed(() => {
  const when = ctxEvent.value ? formatDate(ctxEvent.value.event_time) : '—'
  const policy = ctxEvent.value?.policy_name || t('app.security.events.ctxUnknownPolicy')
  return `${when} · ${policy}`
})
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

// 触发阶段筛选为固定预置九类（用户裁定：固定预置值，不接受任意值）。
// 令牌 → 后端族段映射与序列化单源在 utils/triggeredFilter
// 原实现内联在本文件、无行为测试）。
const filters = ref({ action: '', event_type: '', ip: '', uri: '', rule_name: '', rule_triggered: [...TRIGGERED_CATEGORIES] as string[], policy_name: '', timeRange: null as [string, string] | null })

// 头部全选复选框三态：九类全中=全选；部分中=半选
const triggeredCheckAll = computed(() => TRIGGERED_CATEGORIES.every((c) => filters.value.rule_triggered.includes(c)))
const triggeredIndeterminate = computed(() => {
  const hit = TRIGGERED_CATEGORIES.filter((c) => filters.value.rule_triggered.includes(c)).length
  return hit > 0 && hit < TRIGGERED_CATEGORIES.length
})
// 全选：勾选=九类并入当前选择（保留用户已输入的自定义 tag，与绑定编辑器/
// 策略向导的规则选择器同为并集语义）、取消=只摘九类、自定义 tag 原样保留——
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
    ElMessage.warning(t('app.security.events.timeRangeInvalid'))
    // 只清 end 保留已填的 start（原清空整个区间丢两侧输入）
    filters.value.timeRange = [range[0], '']
  }
  page.value = 1
  fetchEvents()
}

const resetFilters = () => {
  filters.value = { action: '', event_type: '', ip: '', uri: '', rule_name: '', rule_triggered: [...TRIGGERED_CATEGORIES], policy_name: '', timeRange: null }
  page.value = 1
  fetchEvents()
}

const handleSizeChange = () => { page.value = 1; fetchEvents() }

const goToRule = (row: SecurityEvent) => { window.open(pageUrl('rules', { [DEEP_LINK_PARAMS.ruleSearch]: row.rule_caddy_id }), '_blank', 'noopener') }
const goToPolicy = (row: SecurityEvent) => {
  // 交接改走 URL query（sp / sp-search 参数，同 goToRule 的 rs 形态），
  // SecurityPolicies.vue onMounted 消费后 replaceState 清除。
  if (row.policy_id > 0) {
    window.open(pageUrl('security-policies', { [DEEP_LINK_PARAMS.policyId]: row.policy_id }), '_blank', 'noopener')
  } else if (row.policy_name) {
    window.open(pageUrl('security-policies', { [DEEP_LINK_PARAMS.policySearch]: row.policy_name }), '_blank', 'noopener')
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
    if (filters.value.event_type) p.set('event_type', filters.value.event_type)
    if (filters.value.ip) p.set('ip', filters.value.ip)
    if (filters.value.rule_name) p.set('rule_name', filters.value.rule_name)
    // 触发规则：全选（九类全中且无自定义 tag）或空选 = 不过滤，不发送参数；
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
  void fetchAutobanConfig()
})

// 页面刷新同时拉自动封禁状态（调度在后台持续运行，dry-run 建议
// 列表/banned_today/list_entries 不作长期快照）。
const refreshPage = (): void => {
  void fetchEvents()
  void fetchAutobanStatus()
  void fetchAutobanConfig()
}
</script>

<style scoped>
.autoban-section-title { font-size: 14px; font-weight: 600; color: var(--text-primary); margin: 0 0 2px; }
.autoban-section-desc { font-size: 12px; color: var(--text-secondary); line-height: 1.4; margin-bottom: 8px; }
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
/* 累犯记录入口与禁用/编辑按钮同组同规格（small plain），间距由组 gap 统一 */
.autoban-actions { flex-shrink: 0; display: flex; gap: 8px; }
.autoban-warn-bar { margin-top: 10px; }

/* 预设档位卡片：全项目直角令（main.css --el-border-radius-base:0），不得圆角。
   选中态=描边+浅底+「当前」角标；顶部说明行取代悬空自定义徽标。 */
.autoban-preset-hint { font-size: 12px; color: var(--text-secondary, #6b7280); margin-bottom: 4px; }
.autoban-preset-row { display: flex; gap: 8px; align-items: stretch; margin-bottom: 8px; }
.autoban-preset-card { flex: 1 1 0; min-width: 0; display: flex; flex-direction: column; gap: 2px; align-items: flex-start; text-align: left; padding: 6px 10px; border: 1px solid var(--el-border-color, #dcdfe6); border-radius: 0; background: var(--el-fill-color-blank, #fff); cursor: pointer; transition: border-color .15s, background .15s; }
.autoban-preset-card:hover { border-color: var(--el-color-primary, #409eff); }
.autoban-preset-card.active { border-color: var(--el-color-primary, #409eff); background: var(--el-color-primary-light-9, #ecf5ff); }
.autoban-preset-card:disabled { cursor: default; opacity: .6; }
.autoban-preset-name { font-size: 13px; font-weight: 600; color: var(--text-primary, #111827); display: flex; align-items: center; gap: 6px; }
.autoban-preset-current { font-size: 10px; font-weight: 600; color: var(--el-color-primary, #409eff); border: 1px solid currentColor; padding: 0 4px; line-height: 1.5; }
.autoban-preset-desc { font-size: 11px; color: var(--text-secondary, #6b7280); line-height: 1.3; }
/* 观察模式：右标签单行紧凑（开关+行内提示），不占顶部标签整行高度。 */
.autoban-dryrun-item { margin-bottom: 8px; }
.autoban-dryrun-item :deep(.el-form-item__label) { line-height: 32px; padding-bottom: 0; }
/* 高级参数折叠 + 三列网格（标签顶部对齐）：短项三三一行，宽项（口径/阶梯）跨全列。 */
.autoban-advanced { border-top: none; border-bottom: none; margin-top: 2px; }
.autoban-advanced :deep(.el-collapse-item__header) { font-size: 13px; font-weight: 600; color: var(--text-secondary, #6b7280); height: 36px; line-height: 36px; }
.autoban-advanced :deep(.el-collapse-item__content) { padding-bottom: 4px; }
.autoban-grid { display: grid; grid-template-columns: repeat(3, 1fr); column-gap: 20px; align-items: start; }
.autoban-grid-full { grid-column: 1 / -1; }
.autoban-grid .el-form-item { margin-bottom: 6px; }
.autoban-grid :deep(.el-form-item__label) { padding-bottom: 0; line-height: 1.2; font-size: 12px; }
.autoban-grid .form-tip-line { font-size: 11px; line-height: 1.3; margin-top: 0; }
/* 控件宽度：数字 120 / 下拉占满列宽，每列左缘对齐。 */
.autoban-num { width: 120px; }
.autoban-select { width: 100%; }
/* 口径分组：两组横向并排（标签顶部对齐，各占半宽），checkbox 行内紧凑。 */
.autoban-scope-groups { display: flex; gap: 24px; flex-wrap: wrap; }
.autoban-scope-group { margin-bottom: 2px; }
.autoban-scope-group-label { font-size: 12px; font-weight: 600; color: var(--text-secondary, #6b7280); margin-bottom: 1px; }
.autoban-scope-group :deep(.el-checkbox) { height: 24px; margin-right: 12px; }
/* 升级阶梯预览：跨全列独立行，单行紧凑徽标（直角，无负 margin）。 */
.autoban-ladder { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin: 0 0 6px; }
.autoban-ladder-label { font-size: 12px; color: var(--text-secondary, #6b7280); }
.autoban-ladder-step { font-size: 11px; color: var(--text-secondary, #6b7280); background: var(--el-fill-color-light, #f5f7fa); border-radius: 0; padding: 1px 6px; line-height: 1.6; }
/* 封禁与累犯合并弹框：搜索框/底部行 + evidence 双分数。 */
.ban-query-input { width: 240px; }
.ban-console-bottom { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
.recid-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.recid-filters { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.autoban-score-confirmed { display: block; font-size: 11px; color: #f56c6c; font-weight: 600; }
.autoban-score-suspicion { display: block; font-size: 11px; color: #e6a23c; }

/* 工具行单行排布（1280px 视口全控件 + 筛选/重置一行放下）：nowrap 禁止换行，
   各控件定宽不收缩，极端窄视口降级为横向滚动而非把按钮顶到第二行 */
.table-toolbar { display: flex; flex-wrap: nowrap; gap: 8px; justify-content: flex-start; margin-bottom: 16px; align-items: center; overflow-x: auto; }
.table-toolbar > * { flex: 0 0 auto; }
.filter-actions { display: flex; gap: 0; }
.filter-actions .el-button { padding-left: 12px; padding-right: 12px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
.cell-tip { cursor: help; border-bottom: 1px dashed #c0c4cc; }
/* TCP 协议徽标与规则名链接的间距（cell inline-flex 全局基线上） */
.event-proto-tag { margin-right: 6px; }
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
/* 自动封禁配置弹框：三列网格压缩高度后常态无滚动；限高仅作矮视口兜底
   （top=3vh + header/footer/padding≈230px 实测），保证保存按钮恒在视口内。 */
.autoban-config-dialog .el-dialog__body { max-height: calc(100vh - 222px); overflow-y: auto; padding: 14px 20px; }
.autoban-config-dialog .info-note-bar { margin-top: 6px; padding: 6px 10px; }
/* 封禁与累犯合并弹框：同款限高（top=5vh，表高 480 + 工具行/分页/tab 头）。 */
.ban-console-dialog .el-dialog__body { max-height: calc(90vh - 130px); overflow-y: auto; }
/* 请求上下文弹框正文 20px 水平留白走全局 .dialog-body-inset（2026-09-25 用户裁定；
   append-to-body teleport 场景 scoped :deep 不可靠，故类挂弹框、规则在 main.css） */

/* 触发规则筛选下拉：头部「全选」复选框整行可点（EP 自定义头部官方用法同款排布）；
   padding-left 20px 与选项行（EP 默认 20px）左对齐——默认 header-padding 10px 会
   导致复选框与选项文字错开 */
.triggered-filter-popper .el-select-dropdown__header { padding: 8px 6px; border-bottom: 1px solid var(--el-border-color-lighter, #ebeef5); }
.triggered-filter-popper .el-select-dropdown__header .el-checkbox { display: flex; height: unset; margin-right: 0; }
.triggered-filter-popper .el-select-dropdown__header .el-checkbox .el-checkbox__label { padding-left: 8px; }
/* 选中项不加粗：EP 2.14 多选下拉 is-selected 默认 font-weight:bold，该筛选常态
   全选（九类全勾）导致整列粗体，覆写回 normal（选中色与右侧 ✓ 保留） */
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

/* 方法列协议 chip（span 非法 el-tag——翻页零重排）：定宽居中，徽标观感。 */
</style>
