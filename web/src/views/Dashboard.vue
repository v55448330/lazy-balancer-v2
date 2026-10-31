<template>
  <div class="dashboard">
    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card class="system-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon"><Monitor /></el-icon>
                <span>系统概览</span>
              </div>
              <el-tag :type="nodeModeTagType" size="small" effect="plain">
                {{ nodeModeLabel }}
              </el-tag>
            </div>
          </template>
          <el-descriptions :column="6" border>
            <el-descriptions-item label="主机名">
              <span class="text-primary">{{ systemInfoUnavailable ? '采集失败' : systemInfo?.hostname || '-' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="操作系统">{{ systemInfoUnavailable ? '采集失败' : systemInfo?.os_info || '-' }}</el-descriptions-item>
            <el-descriptions-item label="内核">{{ systemInfoUnavailable ? '采集失败' : systemInfo?.kernel || '-' }}</el-descriptions-item>
            <el-descriptions-item label="架构">{{ systemInfoUnavailable ? '采集失败' : systemInfo?.architecture || '-' }}</el-descriptions-item>
            <el-descriptions-item label="Caddy版本">
              <el-tag type="info" size="small">{{ systemInfoUnavailable ? '采集失败' : systemInfo?.caddy_version || '-' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="运行时间">{{ systemInfoUnavailable ? '采集失败' : formatUptime(systemInfo?.uptime) }}</el-descriptions-item>
          </el-descriptions>
          <div v-if="ipList.length > 0" class="network-section">
            <div class="section-label">网络接口</div>
            <div class="network-tags">
              <el-tag v-for="item in ipList" :key="item.iface" size="small" effect="plain" class="network-tag">
                {{ item.iface }}: {{ item.ip }}
              </el-tag>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card class="caddy-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon caddy-icon"><Cpu /></el-icon>
                <span>Caddy 服务状态</span>
                <el-tooltip v-if="caddyApplyError && !caddyStatusUnavailable" placement="bottom" :content="caddyApplyError">
                  <el-tag type="danger" size="small" effect="plain" style="margin-left: 8px">配置应用失败</el-tag>
                </el-tooltip>
                <!-- 审计项：后台数据类重载（证书部署/CRS/IP库/威胁库/自动封禁）失败
                     独立横幅——库已更新但运行配置未收敛，与写路径「保存失败」区分。 -->
                <el-tooltip v-if="caddyBackgroundApplyError && !caddyStatusUnavailable" placement="bottom" :content="caddyBackgroundApplyError" :popper-style="{ maxWidth: '420px' }">
                  <el-tag type="warning" size="small" effect="plain" style="margin-left: 8px">后台重载失败</el-tag>
                </el-tooltip>
              </div>
              <div class="header-actions">
                <el-tag v-if="caddyStatusUnavailable" type="info" size="small" effect="plain">状态采集失败</el-tag>
                <el-tag
                  v-else
                  :type="caddyStatus === 'running' ? 'success' : caddyStatus === 'stopped' ? 'danger' : 'info'"
                  size="small"
                  effect="plain"
                  :class="['status-tag', caddyStatusClass]"
                >
                  {{ caddyStatus === 'running' ? (caddyPid !== '0' && caddyPid !== '' ? `运行中 ${caddyPid}` : '运行中') : caddyStatus === 'stopped' ? '已停止' : '未知' }}
                </el-tag>
                <!-- 审计项：从节点不执行独立的配置一致性检查（配置由主节点快照
                     下发），此前沿用主节点口径显示「配置正常」= 从未执行过的检查。
                     从节点改为「主节点权威」声明，主节点保持一致性横幅。
                     角色未知窗口（nodeMode===null：/config 首拉失败或 15s 重试期）
                     同样不得宣告「配置正常」——此时 configConsistent 是上一轮/
                     默认值，展示层必须 fail-closed 声明角色未知。 -->
                <el-tooltip v-if="authStore.isSlaveNode" placement="bottom" content="从节点配置由主节点快照下发，本机不执行独立一致性检查" :popper-style="{ maxWidth: '360px' }">
                  <el-tag type="info" size="small" effect="plain">主节点权威</el-tag>
                </el-tooltip>
                <el-tooltip v-else-if="nodeModeRole === 'unknown'" placement="bottom" content="节点角色尚未确认（配置拉取中或失败），暂不判定配置一致性" :popper-style="{ maxWidth: '360px' }">
                  <el-tag type="info" size="small" effect="plain">角色未知</el-tag>
                </el-tooltip>
                <el-tag v-else-if="configConsistent === 'true' && !caddyStatusUnavailable" type="success" size="small" effect="plain">配置正常</el-tag>
                <el-tooltip v-else-if="configConsistent === 'false' && !caddyStatusUnavailable" placement="bottom" :content="configDrift" :popper-style="{ maxWidth: '360px' }">
                  <el-tag type="danger" size="small" effect="plain">配置异常</el-tag>
                </el-tooltip>
                <div v-if="authStore.readOnlyReason === null && !caddyStatusUnavailable" class="caddy-actions">
                  <el-button v-if="caddyStatus === 'running'" type="warning" size="small" @click="controlCaddy('restart')" :loading="caddyLoading">
                    重启
                  </el-button>
                  <el-button v-if="caddyStatus === 'running'" type="danger" size="small" @click="controlCaddy('stop')" :loading="caddyLoading">
                    停止
                  </el-button>
                  <el-button v-if="caddyStatus === 'stopped'" type="success" size="small" @click="controlCaddy('start')" :loading="caddyLoading">
                    启动
                  </el-button>
                </div>
              </div>
            </div>
          </template>
          <el-row :gutter="16">
            <el-col :span="8">
              <div class="stat-item">
                <div class="stat-icon stat-blue">
                  <el-icon><Document /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ caddyMetricsUnavailable ? '采集失败' : caddyMetrics ? formatInt(caddyMetrics.requests_total) : '-' }}</div>
                  <div class="stat-label" :title="METRIC_RELOAD_RESET_NOTE">总请求数</div>
                </div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Loading /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ caddyMetricsUnavailable ? '采集失败' : caddyMetrics ? caddyMetrics.requests_in_flight : '-' }}</div>
                  <div class="stat-label">进行中请求</div>
                </div>
              </div>
            </el-col>
            <el-col :span="8">
              <div class="stat-item">
                <div class="stat-icon stat-green">
                  <el-icon><CircleCheck /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ hostMetricsUnavailable ? '采集失败' : hostMetrics ? hostMetrics.length : '-' }}</div>
                  <div class="stat-label">域名统计</div>
                </div>
              </div>
            </el-col>
          </el-row>
          <el-row :gutter="16" style="margin-top: 16px;">
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-blue">
                  <el-icon><TrendCharts /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? overview.requests_per_sec.toFixed(2) : '-' }}</div>
                  <div class="stat-label">请求速率 /s</div>
                </div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Odometer /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? `${overview.latency_p50}ms` : '-' }}</div>
                  <div class="stat-label">延迟 P50</div>
                </div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Odometer /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? `${overview.latency_p95}ms` : '-' }}</div>
                  <div class="stat-label">延迟 P95</div>
                </div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="stat-item">
                <div class="stat-icon stat-purple">
                  <el-icon><Odometer /></el-icon>
                </div>
                <div class="stat-content">
                  <div class="stat-value">{{ overviewUnavailable ? '采集失败' : overview ? `${overview.latency_p99}ms` : '-' }}</div>
                  <div class="stat-label">延迟 P99</div>
                </div>
              </div>
            </el-col>
          </el-row>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="24">
        <el-card class="resource-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon resource-icon"><Odometer /></el-icon>
                <span>系统资源</span>
              </div>
            </div>
          </template>
          <el-skeleton v-if="initialLoading" :rows="2" animated />
          <div v-else-if="systemMetricsUnavailable" class="collection-state">采集失败</div>
          <template v-else-if="systemMetrics">
            <div v-if="degradedSystemParts.size" class="info-note-bar">
              <span class="info-note-desc">部分指标采集失败：{{ degradedSystemLabels.join('、') }}</span>
              <span>（仅展示其余可用指标；该项数值不代表真实用量）</span>
            </div>
            <div class="resource-grid">
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">CPU 使用率</span>
                  <span class="resource-value text-blue">
                    {{ degradedSystemParts.has('cpu') ? '采集失败' : `${systemMetrics.cpu_percent.toFixed(1)}%` }}
                  </span>
                </div>
                <el-progress v-if="cpuProgressPercent !== null" :percentage="cpuProgressPercent" :stroke-width="6" color="#3b82f6" :show-text="false" />
              </div>
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">内存使用</span>
                  <span class="resource-value text-purple">
                    <template v-if="degradedSystemParts.has('memory')">采集失败</template>
                    <template v-else>
                      {{ formatBytes(systemMetrics.memory_used) }}
                      <span class="resource-total">/ {{ formatBytes(systemMetrics.memory_total) }}</span>
                    </template>
                  </span>
                </div>
                <el-progress v-if="memoryProgressPercent !== null" :percentage="memoryProgressPercent" :stroke-width="6" color="#8b5cf6" :show-text="false" />
              </div>
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label">磁盘使用</span>
                  <span class="resource-value text-cyan">
                    <template v-if="degradedSystemParts.has('disk')">采集失败</template>
                    <template v-else>
                      {{ formatBytes(systemMetrics.disk_used) }}
                      <span class="resource-total">/ {{ formatBytes(systemMetrics.disk_total) }}</span>
                    </template>
                  </span>
                </div>
                <el-progress v-if="diskProgressPercent !== null" :percentage="diskProgressPercent" :stroke-width="6" color="#06b6d4" :show-text="false" />
              </div>
              <div class="resource-item">
                <div class="resource-header">
                  <span class="resource-label-group">
                    <span class="resource-label">进程配额</span>
                    <FieldHelpIcon :content="pidsTooltip" />
                  </span>
                  <span class="resource-value-group">
                    <template v-if="degradedSystemParts.has('pids')">采集失败</template>
                    <template v-else>
                      <span class="resource-value" :class="pidsValueClass">{{ pidsUsageParts.current }}</span>
                      <span class="resource-total">/ {{ pidsUsageParts.maxPart }}<template v-if="systemMetrics.pids_max > 0"> ({{ pidsPercentLabel(systemMetrics.pids_percent) }}%)</template></span>
                    </template>
                  </span>
                </div>
                <el-progress v-if="pidsProgressPercentValue !== null" :percentage="pidsProgressPercentValue" :stroke-width="6" :color="pidsProgressColor" :show-text="false" />
              </div>
            </div>
          </template>
          <div v-else class="collection-state">-</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="mb-5">
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon chart-icon"><TrendCharts /></el-icon>
                <span>流量监控</span>
              </div>
            </div>
          </template>
          <el-skeleton v-if="initialLoading" :rows="4" animated class="chart-skeleton" />
          <div v-else-if="trafficUnavailable && trafficTimestamps.length === 0" class="chart-container collection-state">采集失败</div>
          <div v-else class="chart-container">
            <div v-if="trafficUnavailable" class="chart-stale-hint">采集失败：展示上次结果</div>
            <v-chart :option="trafficChartOption" autoresize />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon chart-icon"><DataLine /></el-icon>
                <span>连接统计</span>
              </div>
            </div>
          </template>
          <el-skeleton v-if="initialLoading" :rows="4" animated class="chart-skeleton" />
          <div v-else-if="connectionsUnavailable && connTimestamps.length === 0" class="chart-container collection-state">采集失败</div>
          <div v-else class="chart-container">
            <div v-if="connectionsUnavailable" class="chart-stale-hint">采集失败：展示上次结果</div>
            <v-chart :option="connChartOption" autoresize />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20">
      <el-col :span="24">
        <el-card class="rules-card">
          <template #header>
            <div class="card-header">
              <div class="card-title">
                <el-icon class="title-icon rules-icon"><List /></el-icon>
                <span>负载均衡规则</span>
              </div>
              <div class="card-header-actions">
                <!-- 刷新失败但有缓存时必须明示陈旧：表格仍渲染上一次结果，与
                     新鲜的指标列混排，不提示会被误读为当前真实规则集 -->
                <el-tag v-if="rulesUnavailable && rules.length > 0" type="warning" size="small" effect="plain" title="规则列表刷新失败，当前展示上次拉取的结果">规则列表刷新失败：展示上次结果</el-tag>
                <el-radio-group v-model="rankBy" size="small" aria-label="规则排序方式">
                  <el-radio-button value="requests">按请求数</el-radio-button>
                  <el-radio-button value="bytes">按流量</el-radio-button>
                </el-radio-group>
                <span class="rules-count" :title="`共 ${rules.length} 条规则；本卡展示请求数/流量前 10 条 + 指标采集失败行（零流量规则不进入排行）`">{{ rules.length }}</span>
              </div>
            </div>
          </template>
          <el-table
            v-loading="initialLoading"
            element-loading-text="加载中"
            :data="sortedRules"
            row-key="caddy_id"
            stripe
            :header-cell-style="{ background: '#f9fafb' }"
          >
            <!-- 宽度二调（用户实测 458/230 失调）：min-width 弹性列按
                 值比例分配剩余空间（260:130 把 2/3 剩余给了状态码列）——改固定 width
                 才能精确控制比例；名称列取 280（内容列），右端空白由表格自然留白。 -->
            <el-table-column prop="name" label="规则名称" min-width="300" show-overflow-tooltip>
              <template #default="{ row }">
                <!-- 长规则名省略号 + 悬浮全文（列宽 100→130 用户反馈调整）。-->
                <!-- 省略号样式必须放在 slot 内层 span——el-link 根是
                     inline-flex，text 直接内容在 .el-link__inner flex item 里，根上的
                     text-overflow 不会渲染 …（flex 容器无自有行盒），只硬裁切。 -->
                <AccessibleLink type="primary" underline="never" :title="row.name" @click="openRuleHistory(row as Rule)"><span style="display: block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ row.name }}</span></AccessibleLink>
              </template>
            </el-table-column>
            <el-table-column label="协议" width="85">
              <template #default="{ row }">
                <el-tag :type="getRuleProtocolTagType(row as Rule)" size="small" effect="plain">
                  {{ getRuleProtocolLabel(row as Rule) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="listen_port" label="端口" width="70" />
            <el-table-column label="负载策略" width="80">
              <template #default="{ row }">
                <span class="text-secondary">{{ getStrategyLabel(row.strategy) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="70">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="plain">
                  {{ row.enabled ? '启用' : '禁用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="请求数" width="110">
              <template #default="{ row }">
                <span class="text-primary" :title="ruleMetricCellTitle({ disabled: isRuleDisabled(row as Rule), unavailable: !!ruleMetricsUnavailable[row.caddy_id], tcp: row.protocol === 'tcp', value: ruleRequestsTotalText(row.caddy_id) })">{{ isRuleDisabled(row as Rule) ? '已禁用' : ruleMetricsUnavailable[row.caddy_id] ? '采集失败' : ruleRequestsTotalText(row.caddy_id) }}</span>
              </template>
            </el-table-column>
            <!-- 初版 310 过宽（用户反馈）→ 260：常见量级（万级以内）
                 五 badge（2xx/3xx/4xx/5xx/Block）单行 ~290px 舒适；计数升到
                 百万级时由 .status-codes 的 flex-wrap 换行兜底（badge 自身
                 nowrap，不出现数字内折）——不得改回 nowrap + overflow:hidden：
                 那会把末尾 Block 静默裁掉，让「有拦截」看起来是「无拦截」。
                 历史（用户反馈）：入站/出站流量列 90→100（字节量级数字易被截），
                 差额从状态码列 380→360 划出。 -->
            <el-table-column label="状态码" width="360">
              <template #default="{ row }">
                <span v-if="isRuleDisabled(row as Rule)" class="text-secondary">已禁用</span>
                <div v-else-if="row.protocol === 'tcp'" class="text-secondary">-</div>
                <span v-else-if="ruleMetricsUnavailable[row.caddy_id]" class="text-secondary">采集失败</span>
                <div v-else-if="hasRuleRequests(row.caddy_id)" class="status-codes">
                  <span class="status-code status-2xx" :title="`成功 ${ruleMetrics[row.caddy_id].status_2xx}`">2xx {{ ruleMetrics[row.caddy_id].status_2xx }}</span>
                  <span class="status-code status-3xx" :title="`重定向 ${ruleMetrics[row.caddy_id].status_3xx}`">3xx {{ ruleMetrics[row.caddy_id].status_3xx }}</span>
                  <span class="status-code status-4xx" :title="`客户端错误 ${ruleMetrics[row.caddy_id].status_4xx}`">4xx {{ ruleMetrics[row.caddy_id].status_4xx }}</span>
                  <span class="status-code status-5xx" :title="`服务器错误 ${ruleMetrics[row.caddy_id].status_5xx}`">5xx {{ ruleMetrics[row.caddy_id].status_5xx }}</span>
                  <span class="status-code status-blocked" :title="`安全拦截(WAF/GeoIP/IP ACL/限流) ${ruleMetrics[row.caddy_id].blocked ?? 0}`">Block {{ ruleMetrics[row.caddy_id].blocked ?? 0 }}</span>
                </div>
                <span v-else class="text-secondary">-</span>
              </template>
            </el-table-column>
            <el-table-column label="入站流量" width="100">
              <template #default="{ row }">
                <span v-if="isRuleDisabled(row as Rule)" class="text-secondary">已禁用</span>
                <span v-else-if="row.protocol === 'tcp'" class="text-secondary">-</span>
                <span v-else-if="ruleMetricsUnavailable[row.caddy_id]" class="text-secondary">采集失败</span>
                <span v-else class="text-secondary">{{ ruleMetrics[row.caddy_id] ? formatBytes(ruleMetrics[row.caddy_id].bytes_in) : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="出站流量" width="100">
              <template #default="{ row }">
                <span v-if="isRuleDisabled(row as Rule)" class="text-secondary">已禁用</span>
                <span v-else-if="row.protocol === 'tcp'" class="text-secondary">-</span>
                <span v-else-if="ruleMetricsUnavailable[row.caddy_id]" class="text-secondary">采集失败</span>
                <span v-else class="text-secondary">{{ ruleMetrics[row.caddy_id] ? formatBytes(ruleMetrics[row.caddy_id].bytes_out) : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="处理中" width="70">
              <template #default="{ row }">
                <span class="text-secondary" :title="ruleMetricCellTitle({ disabled: isRuleDisabled(row as Rule), unavailable: !!ruleMetricsUnavailable[row.caddy_id], tcp: row.protocol === 'tcp', value: String(ruleMetrics[row.caddy_id]?.requests_in_flight ?? '-') })">{{ isRuleDisabled(row as Rule) ? '已禁用' : ruleMetricsUnavailable[row.caddy_id] ? '采集失败' : ruleMetrics[row.caddy_id]?.requests_in_flight ?? '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="健康状态" width="80">
              <template #default="{ row }">
                <el-tag v-if="!row.enabled" type="info" size="small" effect="plain">-</el-tag>
                <el-tag v-else-if="ruleHealthUnavailable || !ruleHealth[row.caddy_id] || ruleHealth[row.caddy_id] === 'unknown'" type="info" size="small" effect="plain">-</el-tag>
                <el-tag v-else-if="ruleHealth[row.caddy_id] === 'unhealthy'" type="danger" size="small" effect="plain">异常</el-tag>
                <el-tag v-else-if="ruleHealth[row.caddy_id] === 'degraded'" type="warning" size="small" effect="plain">降级</el-tag>
                <el-tag v-else type="success" size="small" effect="plain">健康</el-tag>
              </template>
            </el-table-column>
            <template #empty>
              <el-empty :description="rulesEmptyText" :image-size="80" />
            </template>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog v-model="ruleHistoryVisible" width="min(900px, 92vw)" destroy-on-close class="history-dialog">
      <template #header>
        <DialogHeader :icon="TrendCharts" title="历史统计" :subtitle="`${ruleHistoryRule?.name || ''} · ${ruleHistoryRule ? getRuleProtocolLabel(ruleHistoryRule) : ''} · :${ruleHistoryRule?.listen_port}`" />
      </template>
      <div class="history-toolbar">
        <el-radio-group v-model="ruleHistoryRange" size="small" aria-label="历史统计时间范围" @change="fetchRuleHistory">
          <el-radio-button value="1h">近 1 小时</el-radio-button>
          <el-radio-button value="6h">近 6 小时</el-radio-button>
          <el-radio-button value="24h">近 24 小时</el-radio-button>
          <el-radio-button value="7d">近 7 天</el-radio-button>
        </el-radio-group>
      </div>
      <el-empty v-if="ruleHistoryUnsupported" description="TCP 规则暂无历史流量统计（四层代理无流量计数指标）" :image-size="60" />
      <template v-else>
        <!-- 加载失败 ≠ 该时间范围无数据——失败态与空态分文案（同页
             「采集失败 ≠ 无数据」固化口径），并提供重试。-->
        <el-alert v-if="ruleHistoryError" type="error" :closable="false" show-icon class="polling-error-alert error-banner history-error-alert">
          <template #title>
            <div class="polling-error-title">
              <span>历史统计加载失败：图表为空不代表该时间范围没有流量</span>
              <el-button link type="danger" @click="fetchRuleHistory">立即重试</el-button>
            </div>
          </template>
        </el-alert>
        <template v-else>
          <el-empty v-if="!ruleHistoryLoading && ruleHistoryDeltas.deltas.length === 0" description="该时间范围内暂无数据" :image-size="60" />
          <div v-else v-loading="ruleHistoryLoading">
            <section class="dialog-panel history-card">
              <DialogSectionHeader title="请求数与状态码" />
              <v-chart :option="ruleRequestsChartOption" autoresize style="height: 260px;" />
            </section>
            <section class="dialog-panel history-card">
              <DialogSectionHeader title="流量（入站 / 出站）" />
              <v-chart :option="ruleBytesChartOption" autoresize style="height: 260px;" />
            </section>
          </div>
        </template>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { formatDate, formatChartTimeInConfigTz } from '@/utils/date'
import { getStrategyLabel } from '@/utils/strategyLabels'
import { hostPortKey } from '@/utils/upstreamKeys'
import '@/utils/echarts' // 统一注册（副作用，全站单点）
import type { EChartsOption, LineSeriesOption, TooltipComponentFormatterCallbackParams } from 'echarts'
import VChart from 'vue-echarts'
import { useAuthStore } from '@/stores/auth'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatBytes } from '@/utils/formatBytes'
import { formatInt } from '@/utils/formatInt'
import { ElMessageBox } from 'element-plus'
import { Monitor, Cpu, Document, Loading, CircleCheck, Odometer, TrendCharts, DataLine, List } from '@element-plus/icons-vue'
import type { APIResponse, SystemInfo, SystemMetrics, CaddyMetrics, Rule, RuleMetrics, HostMetrics, MetricsOverview } from '@/types'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import { usePollingTask } from '@/composables/usePollingTask'
import { httpStatusColors } from '@/utils/chartTheme'
import { resolveNodeRole } from '@/utils/nodeRole'
import { buildRuleMetricsUnavailable, METRIC_RELOAD_RESET_NOTE, ruleMetricCellTitle } from '@/utils/dashboardMetrics'
import { degradedMetricLabels, degradedMetricParts, metricProgressPercent, pidsPercentLabel, pidsProgressPercent, pidsTooltipText, pidsUsageLabel, pidsValueTone } from '@/utils/systemMetrics'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import FieldHelpIcon from '@/components/common/FieldHelpIcon.vue'


const authStore = useAuthStore()

const formatUptime = (seconds?: number): string => {
  // 0 秒是合法运行时长（刚启动）：仅缺失/负数才显示「-」，否则会被读成「无数据」。
  if (seconds == null || seconds < 0) return '-'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d} 天 ${h} 小时`
  if (h > 0) return `${h} 小时 ${m} 分`
  if (m > 0) return `${m} 分 ${Math.floor(seconds % 60)} 秒`
  return `${Math.floor(seconds)} 秒`
}

const formatChartTime = (ms: number): string => formatChartTimeInConfigTz(ms)

const systemInfo = ref<SystemInfo | null>(null)
const systemInfoUnavailable = ref(false)
const systemMetrics = ref<SystemMetrics | null>(null)
const caddyMetrics = ref<CaddyMetrics | null>(null)
const caddyStatus = ref('unknown')
// /caddy/status 失败显性标记（与 systemInfoUnavailable 等 8 项同构）——
// 缺它时状态标签/配置一致性/应用失败横幅全部静默陈旧（「运行中/配置正常」
// 可能是上一轮残值，而真实 Caddy 已停或配置已漂移）。
const caddyStatusUnavailable = ref(false)
const caddyApplyError = ref('')
const caddyBackgroundApplyError = ref('')
const caddyPid = ref('0')
const configConsistent = ref('')
const configDrift = ref('')
const caddyLoading = ref(false)
const rules = ref<Rule[]>([])
interface DashboardRuleMetrics extends RuleMetrics {
  enabled?: boolean
}
const ruleMetrics = ref<Record<string, DashboardRuleMetrics>>({})
const ruleMetricsUnavailable = ref<Record<string, boolean>>({})
// 规则请求数列文案（单元格与 hover title 同源）：缺采集 → '-'，千分位走
// formatInt 单源（原来两处内联 `?.toLocaleString() ?? '-'`）。
const ruleRequestsTotalText = (caddyId: string): string => {
  const total = ruleMetrics.value[caddyId]?.requests_total
  return typeof total === 'number' ? formatInt(total) : '-'
}
const rankBy = ref<'requests' | 'bytes'>('requests')
type RuleHealth = 'unknown' | 'unhealthy' | 'degraded' | 'healthy'
const ruleHealth = ref<Record<string, RuleHealth>>({})
const ruleHealthUnavailable = ref(false)
const hostMetrics = ref<HostMetrics[] | null>(null)
const overview = ref<MetricsOverview | null>(null)
const systemMetricsUnavailable = ref(false)
// 分项降级（后端 degraded 契约）：失败分项显示「采集失败」而非零值——
// CPU 单点故障时内存/磁盘仍照常展示，只有失败项标注不可用。
const degradedSystemParts = computed(() => degradedMetricParts(systemMetrics.value?.degraded))
const degradedSystemLabels = computed(() => degradedMetricLabels(systemMetrics.value?.degraded))
const pidsToneValue = computed(() => pidsValueTone(systemMetrics.value?.pids_percent ?? 0, degradedSystemParts.value.has('pids')))
const pidsValueClass = computed(() => ({
  'text-green': pidsToneValue.value === 'normal',
  'text-amber': pidsToneValue.value === 'warning',
  'text-red': pidsToneValue.value === 'critical',
}))
const cpuProgressPercent = computed(() => metricProgressPercent(systemMetrics.value?.cpu_percent ?? 0, degradedSystemParts.value.has('cpu')))
const memoryProgressPercent = computed(() => metricProgressPercent(systemMetrics.value?.memory_percent ?? 0, degradedSystemParts.value.has('memory')))
const diskProgressPercent = computed(() => metricProgressPercent(systemMetrics.value?.disk_percent ?? 0, degradedSystemParts.value.has('disk')))
const pidsProgressPercentValue = computed(() => pidsProgressPercent(systemMetrics.value?.pids_percent ?? 0, systemMetrics.value?.pids_max ?? 0, degradedSystemParts.value.has('pids')))
// 「已用 / 上限」文案单源 pidsUsageLabel：上限 0→「不限」与负值夹取都由该函数
// 持有（原模板内联 `max > 0 ? max : '不限'` 双份文案且丢负值夹取）。返回串按
// ' / ' 拆回两段维持「当前值着色 / 总量灰化」的双 span 视觉。
const pidsUsageParts = computed(() => {
  const [current = '', maxPart = ''] = pidsUsageLabel(systemMetrics.value?.pids_current ?? 0, systemMetrics.value?.pids_max ?? 0).split(' / ')
  return { current, maxPart }
})
const pidsTooltip = computed(() => pidsTooltipText(systemMetrics.value?.nproc_limit ?? 0))
const pidsProgressColor = computed(() => {
  if (pidsToneValue.value === 'critical') return '#ef4444'
  if (pidsToneValue.value === 'warning') return '#f59e0b'
  return '#10b981'
})
// 「已落地」与「可用」分离：/rules 可能先于 /metrics/dashboard 落地，
// 此时不能把「指标尚未到达」当成「采集失败」——首轮逐规则列会全部闪「采集失败」。
// landed 只在 dashboard 响应成功/失败后置位；未落地前一律视为「无结论」。
const dashboardMetricsLanded = ref(false)
const caddyMetricsUnavailable = ref(false)
const hostMetricsUnavailable = ref(false)
const overviewUnavailable = ref(false)
const trafficUnavailable = ref(false)
const connectionsUnavailable = ref(false)
const rulesUnavailable = ref(false)
const initialLoading = ref(true)

const trafficInHistory = ref<number[]>([])
const trafficOutHistory = ref<number[]>([])
const trafficTimestamps = ref<number[]>([])
const connEstablishedHistory = ref<number[]>([])
const connTimeWaitHistory = ref<number[]>([])
const connTimestamps = ref<number[]>([])

// 节点角色三态（fail-closed 展示）——nodeMode 为 null（/config 首拉失败
// 或 15s 重试窗口内）时不显示「主节点」：同页写控件按 readOnlyReason（含
// 'unknown'）隐藏，展示层不能反向宣告「主节点」误导运维。
// 三态派生的判据单源在 utils/nodeRole（行为用例穷举 master/slave/null/undefined）
const nodeRoleView = computed(() => resolveNodeRole(authStore.nodeMode))
const nodeModeRole = computed(() => nodeRoleView.value.role)
const nodeModeLabel = computed(() => nodeRoleView.value.label)
const nodeModeTagType = computed(() => nodeRoleView.value.tagType)

// caddyStatus 取值 running/stopped/unknown，样式类须映射——原先直接拼
// caddyStatus 使 `.status-tag.info`（未知态灰底）零命中。
const caddyStatusClass = computed(() => caddyStatus.value === 'running' ? 'running' : caddyStatus.value === 'stopped' ? 'stopped' : 'info')

interface RuleHistoryRow {
  timestamp: string
  requests_total: number
  requests_2xx: number
  requests_3xx: number
  requests_4xx: number
  requests_5xx: number
  requests_blocked: number
  bytes_in: number
  bytes_out: number
}

interface RuleHistoryDelta {
  requests: number
  status2xx: number
  status3xx: number
  status4xx: number
  status5xx: number
  blocked: number
  bytesIn: number
  bytesOut: number
}

interface RuleHistoryResponse {
  supported?: boolean
  bucket_interval_seconds?: number
  rows?: RuleHistoryRow[]
}

interface DashboardMetricsResponse {
  global: CaddyMetrics
  hosts: HostMetrics[]
  overview: MetricsOverview
  rules: Record<string, DashboardRuleMetrics>
}

interface UpstreamHealth {
  healthy?: boolean
  unknown?: boolean
  degraded?: boolean
}

type HealthResponse = Record<string, Record<string, UpstreamHealth>>

const ruleHistoryVisible = ref(false)
const ruleHistoryRule = ref<Rule | null>(null)
const ruleHistoryRange = ref('24h')
const ruleHistoryRows = ref<RuleHistoryRow[]>([])
const ruleHistoryBucketSeconds = ref(0)
const ruleHistoryLoading = ref(false)
const ruleHistoryUnsupported = ref(false)
// 请求失败必须与「该时间范围内暂无数据」区分（否则取证/排障会被误导）。
const ruleHistoryError = ref('')

const openRuleHistory = (rule: Rule) => {
  ruleHistoryRule.value = rule
  ruleHistoryVisible.value = true
  ruleHistoryRange.value = '24h'
  fetchRuleHistory()
}

let ruleHistorySeq = 0

const fetchRuleHistory = async () => {
  if (disposed || !ruleHistoryRule.value) return
  const seq = ++ruleHistorySeq
  ruleHistoryLoading.value = true
  ruleHistoryUnsupported.value = false
  ruleHistoryError.value = ''
  ruleHistoryRows.value = []
  ruleHistoryBucketSeconds.value = 0
  try {
    const res = await request.get<APIResponse<RuleHistoryResponse>>(`/rules/${ruleHistoryRule.value.caddy_id}/metrics-history`, {
      params: { range: ruleHistoryRange.value },
      signal: dashboardPolling.signal,
    })
    if (disposed || seq !== ruleHistorySeq) return
    if (res.data?.supported === false) {
      ruleHistoryUnsupported.value = true
      ruleHistoryRows.value = []
    } else {
      ruleHistoryRows.value = res.data?.rows || []
      ruleHistoryBucketSeconds.value = res.data?.bucket_interval_seconds || 0
    }
  } catch (error: unknown) {
    if (!disposed && seq === ruleHistorySeq) {
      console.error('Failed to fetch rule history:', error)
      ruleHistoryRows.value = []
      ruleHistoryError.value = error instanceof Error ? error.message : '历史统计请求失败'
    }
  } finally {
    if (!disposed && seq === ruleHistorySeq) {
      ruleHistoryLoading.value = false
    }
  }
}

const diffCounters = (previous: RuleHistoryRow, current: RuleHistoryRow): RuleHistoryDelta | null => {
  const reset = current.requests_total < previous.requests_total
    || current.requests_2xx < previous.requests_2xx
    || current.requests_3xx < previous.requests_3xx
    || current.requests_4xx < previous.requests_4xx
    || current.requests_5xx < previous.requests_5xx
    || current.requests_blocked < previous.requests_blocked
    || current.bytes_in < previous.bytes_in
    || current.bytes_out < previous.bytes_out
  if (reset) return null
  return {
    requests: current.requests_total - previous.requests_total,
    status2xx: current.requests_2xx - previous.requests_2xx,
    status3xx: current.requests_3xx - previous.requests_3xx,
    // 历史图 4xx 与实时表同口径扣除 Block(钳制 ≥0)——
    // 存储双列(当次裁定),展示面不再双计。
    status4xx: Math.max(0, (current.requests_4xx - previous.requests_4xx) - (current.requests_blocked - previous.requests_blocked)),
    status5xx: current.requests_5xx - previous.requests_5xx,
    blocked: current.requests_blocked - previous.requests_blocked,
    bytesIn: current.bytes_in - previous.bytes_in,
    bytesOut: current.bytes_out - previous.bytes_out,
  }
}

const ruleHistoryDeltas = computed(() => {
  const labels: string[] = []
  const deltas: Array<RuleHistoryDelta | null> = []
  for (let index = 1; index < ruleHistoryRows.value.length; index += 1) {
    const previous = ruleHistoryRows.value[index - 1]
    const current = ruleHistoryRows.value[index]
    if (!previous || !current) continue
    // 缺 timestamp 的行给空标签而非抛 TypeError：formatDate 恒返回 string，
    // 原 `?.slice(5,16) || current.timestamp.slice(5,16)` 在行缺 timestamp 时触发 undefined.slice。
    labels.push(current.timestamp ? (formatDate(current.timestamp).slice(5, 16) || '') : '')
    deltas.push(diffCounters(previous, current))
  }
  return { labels, deltas }
})

const historyChartBase = (legend: string[], series: LineSeriesOption[], valueFormatter?: (value: number) => string): EChartsOption => ({
  tooltip: { trigger: 'axis', backgroundColor: 'rgba(255,255,255,0.95)', borderColor: '#e5e7eb', textStyle: { color: '#374151', fontSize: 12 } },
  legend: { data: legend, bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 55, right: 15, top: 15, bottom: 40 },
  xAxis: { type: 'category', data: ruleHistoryDeltas.value.labels, axisLine: { lineStyle: { color: '#e5e7eb' } }, axisLabel: { fontSize: 10, color: '#9ca3af', interval: ruleHistoryBucketSeconds.value >= 900 ? 'auto' : undefined } },
  yAxis: { type: 'value', axisLine: { show: false }, axisLabel: { fontSize: 10, color: '#9ca3af', ...(valueFormatter ? { formatter: valueFormatter } : {}) }, splitLine: { lineStyle: { color: '#f3f4f6' } } },
  series,
})

const ruleRequestsChartOption = computed<EChartsOption>(() => {
  const mk = (name: string, key: keyof RuleHistoryDelta, color: string): LineSeriesOption => ({ name, type: 'line', color, data: ruleHistoryDeltas.value.deltas.map((row) => row === null ? null : row[key]), sampling: 'lttb', connectNulls: false, smooth: true, showSymbol: false, lineStyle: { color, width: 2 }, areaStyle: { color: `${color}1a` } })
  return historyChartBase(['总请求', '2xx', '3xx', '4xx', '5xx', 'Block'], [
    mk('总请求', 'requests', httpStatusColors.requests),
    mk('2xx', 'status2xx', httpStatusColors.s2xx),
    mk('3xx', 'status3xx', httpStatusColors.s3xx),
    mk('4xx', 'status4xx', httpStatusColors.s4xx),
    mk('5xx', 'status5xx', httpStatusColors.s5xx),
    mk('Block', 'blocked', httpStatusColors.blocked),
  ])
})

const ruleBytesChartOption = computed<EChartsOption>(() => {
  const mk = (name: string, key: 'bytesIn' | 'bytesOut', color: string): LineSeriesOption => ({ name, type: 'line', color, data: ruleHistoryDeltas.value.deltas.map((row) => row === null ? null : row[key]), sampling: 'lttb', connectNulls: false, smooth: true, showSymbol: false, lineStyle: { color, width: 2 }, areaStyle: { color: `${color}1a` } })
  return historyChartBase(['入站', '出站'], [mk('入站', 'bytesIn', '#3b82f6'), mk('出站', 'bytesOut', '#10b981')], formatBytes)
})

const ruleRankValue = (caddyId: string): number => {
  const metrics = ruleMetrics.value[caddyId]
  if (!metrics) return 0
  return rankBy.value === 'requests' ? (metrics.requests_total ?? 0) : (metrics.bytes_in ?? 0) + (metrics.bytes_out ?? 0)
}

const rankableRules = computed(() => {
  // 单条规则指标缺失时 ruleRankValue=0 会被「>0」过滤掉，外观等同
  // 「无流量」且逐列「采集失败」分支永不渲染。
  // 采集失败的行必须可见——排在正常行之后，保持「故障 ≠ 无数据」口径。
  const ranked = rules.value.filter((rule) =>
    ruleRankValue(rule.caddy_id) > 0 || ruleMetricsUnavailable.value[rule.caddy_id] === true,
  )
  return ranked.sort((a, b) => {
    const aUnavailable = ruleMetricsUnavailable.value[a.caddy_id] === true
    const bUnavailable = ruleMetricsUnavailable.value[b.caddy_id] === true
    if (aUnavailable !== bUnavailable) return aUnavailable ? 1 : -1
    return ruleRankValue(b.caddy_id) - ruleRankValue(a.caddy_id)
  })
})

const sortedRules = computed(() => {
  // 失败行不占排行榜的 10 个名额——前 10 按指标排，失败行全部追加在
  // 末尾。否则 10 条有流量规则会把失败行挤出 slice，故障再次静默消失。
  const ranked = rankableRules.value.filter((rule) => ruleMetricsUnavailable.value[rule.caddy_id] !== true)
  const failed = rankableRules.value.filter((rule) => ruleMetricsUnavailable.value[rule.caddy_id] === true)
  return [...ranked.slice(0, 10), ...failed]
})

const rulesEmptyText = computed(() => {
  if (rulesUnavailable.value) return '采集失败'
  if (rules.value.length === 0) return '暂无负载均衡规则'
  // 指标采集失败 ≠ 无流量——失败口径与页面其它「采集失败」一致，
  // 不再把采集故障误报为「暂无请求/流量数据」。
  if (caddyMetricsUnavailable.value) return '采集失败'
  return rankBy.value === 'bytes' ? '暂无流量数据' : '暂无请求数据'
})

const hasRuleRequests = (caddyId: string): boolean => {
  const requests = ruleMetrics.value[caddyId]?.requests_total
  return requests !== undefined && requests > 0
}

const isRuleDisabled = (rule: Rule): boolean => !rule.enabled || ruleMetrics.value[rule.caddy_id]?.enabled === false

const ipList = computed(() => {
  const ips = systemInfo.value?.network_ips
  if (!ips || typeof ips !== 'object') return []
  return Object.entries(ips).map(([iface, ip]) => ({ iface, ip }))
})

// 策略文案映射提取至 utils/strategyLabels（死键 round_robin 已删）。

const getRuleProtocolLabel = (rule: Rule): 'HTTP' | 'HTTPS' | 'TCP' => {
  if (rule.protocol === 'tcp') return 'TCP'
  return rule.enable_tls ? 'HTTPS' : 'HTTP'
}

const getRuleProtocolTagType = (rule: Rule): 'primary' | 'success' | 'warning' => {
  if (rule.protocol === 'tcp') return 'warning'
  return rule.enable_tls ? 'success' : 'primary'
}

// /metrics/realtime 的 bytes_in/bytes_out 是每秒速率；图表必须按速率口径显示，
// 与同页「请求速率 /s」一致，避免把 1.2 MB/s 读成上一轮新增 1.2 MB。
const formatTrafficRate = (value: number): string => `${formatBytes(value)}/s`

const trafficChartOption = computed<EChartsOption>(() => ({
  tooltip: { 
    trigger: 'axis', 
    backgroundColor: 'rgba(255,255,255,0.95)', 
    borderColor: '#e5e7eb', 
    textStyle: { color: '#374151', fontSize: 12 },
    formatter: (params: TooltipComponentFormatterCallbackParams) => {
      const items = Array.isArray(params) ? params : [params]
      let result = `${items[0]?.name ?? ''}<br/>`
      items.forEach((item) => {
        const value = typeof item.value === 'number' ? item.value : Number(item.value ?? 0)
        result += `${item.marker} ${item.seriesName}: ${formatTrafficRate(value)}<br/>`
      })
      return result
    }
  },
  legend: { data: ['入站', '出站'], bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 45, right: 15, top: 15, bottom: 40 },
  xAxis: { 
    type: 'category', 
     data: trafficTimestamps.value.map(t => formatChartTime(t)),
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisLabel: { fontSize: 10, color: '#9ca3af' }
  },
  yAxis: { 
    type: 'value', 
    axisLine: { show: false },
    axisLabel: { fontSize: 10, color: '#9ca3af', formatter: formatTrafficRate },
    splitLine: { lineStyle: { color: '#f3f4f6' } }
  },
  series: [
    { name: '入站', type: 'line', color: '#3b82f6', data: trafficInHistory.value, smooth: true, showSymbol: trafficInHistory.value.length < 2, lineStyle: { color: '#3b82f6', width: 2 }, areaStyle: { color: 'rgba(59,130,246,0.1)' } },
    { name: '出站', type: 'line', color: '#10b981', data: trafficOutHistory.value, smooth: true, showSymbol: trafficOutHistory.value.length < 2, lineStyle: { color: '#10b981', width: 2 }, areaStyle: { color: 'rgba(16,185,129,0.1)' } },
  ],
}))

const connChartOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'axis', backgroundColor: 'rgba(255,255,255,0.95)', borderColor: '#e5e7eb', textStyle: { color: '#374151', fontSize: 12 } },
  legend: { data: ['已建立', '等待释放'], bottom: 0, textStyle: { fontSize: 11, color: '#6b7280' } },
  grid: { left: 45, right: 15, top: 15, bottom: 40 },
  xAxis: { 
    type: 'category', 
     data: connTimestamps.value.map(t => formatChartTime(t)),
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisLabel: { fontSize: 10, color: '#9ca3af' }
  },
  yAxis: { 
    type: 'value', 
    axisLine: { show: false },
    axisLabel: { fontSize: 10, color: '#9ca3af' },
    splitLine: { lineStyle: { color: '#f3f4f6' } }
  },
  series: [
    { name: '已建立', type: 'line', color: '#10b981', data: connEstablishedHistory.value, smooth: true, showSymbol: connEstablishedHistory.value.length < 2, lineStyle: { color: '#10b981', width: 2 } },
    { name: '等待释放', type: 'line', color: '#f59e0b', data: connTimeWaitHistory.value, smooth: true, showSymbol: connTimeWaitHistory.value.length < 2, lineStyle: { color: '#f59e0b', width: 2 } },
  ],
}))

let statusRefreshTimer: number | null = null
let statusConfirmTimer: number | null = null
let disposed = false
let fetchAllDataPromise: Promise<void> | null = null
let ruleHealthInFlight = false
// 在途期间到达的新版本需求：收尾补跑。原布尔门直接丢弃新需求，而旧响应又因
// 版本守卫被丢弃 → 新规则集整轮拿不到健康结论（健康列按 caddy_id 沿用上一版本
// 映射，且无陈旧提示）。只保留最新一次需求（同版本重复无意义）。
let pendingRuleHealth: { readonly rules: Rule[]; readonly version: number } | null = null
let rulesVersion = 0

// 慢车道（15s，与规则页健康列同口径）：/rules 是全量规则 + upstreams hydrate，
// /config/health 依赖它派生列——原随 5s 主轮询每轮拉取（3 倍频）。门户首页
// 常驻且可多标签页叠加，这两项是无采样意义的重复负载；采样曲线类端点
// （realtime/connections/metrics）仍 5s。
const SLOW_LANE_INTERVAL_MS = 15000
let lastSlowLaneAt = 0
const slowLaneDue = (): boolean => Date.now() - lastSlowLaneAt >= SLOW_LANE_INTERVAL_MS

// /rules 与 /config/health 都是慢车道：必须脱离轮询数组 fire-and-forget，否则
// 大规则集/DB 抖动（最长 30s）会让同一轮资源、曲线与 Caddy 状态全部延后。
let rulesSlowLaneInFlight = false
let pendingSlowLane = false
const fetchRulesSlowLane = (roundSignal?: AbortSignal): void => {
  if (disposed) return
  if (rulesSlowLaneInFlight) {
    // 在途期间只保留一个补跑需求；窗口时间不得提前推进，否则本次刷新会被
    // 直接吃掉并再等待一个完整周期。补跑使用页级 signal，不继承已结束轮次。
    pendingSlowLane = true
    return
  }
  rulesSlowLaneInFlight = true
  lastSlowLaneAt = Date.now()
  void request.get('/rules', { signal: roundSignal ?? dashboardPolling.signal, silent: true }).then((res) => {
    if (disposed) return
    if (!res.data) {
      rulesUnavailable.value = true
      return
    }
    rules.value = res.data || []
    rulesUnavailable.value = false
    // 指标尚未落地时不写映射：false 在本 helper 中表示「明确采集失败」，
    // 不是「尚无结论」。等 /metrics/dashboard 到达后由它重建映射。
    if (dashboardMetricsLanded.value) {
      ruleMetricsUnavailable.value = buildRuleMetricsUnavailable(rules.value, ruleMetrics.value, dashboardMetricsLanded.value && !caddyMetricsUnavailable.value)
    }
    const version = ++rulesVersion
    const currentRules = rules.value
    // 健康查询同属慢车道；版本守卫与 ruleHealthInFlight/pending 保证迟到响应
    // 不写回、更新版本补跑，函数内部自带 try/catch。
    void fetchRuleHealth(currentRules, version, roundSignal)
  }).catch(() => { if (!disposed) rulesUnavailable.value = true }).finally(() => {
    rulesSlowLaneInFlight = false
    if (!pendingSlowLane || disposed) return
    pendingSlowLane = false
    fetchRulesSlowLane()
  })
}

const fetchAllData = (roundSignal?: AbortSignal): Promise<void> => {
  if (disposed) return Promise.resolve()
  if (fetchAllDataPromise) return fetchAllDataPromise

  // 删除手造 Authorization 头——api.ts 请求拦截器对全部
  // 同域相对路径请求统一从 localStorage 注入同一 token(api.ts:186-196)。
  // 轮询轮次传入本轮 signal（pause/stop 可取消在途请求）；手动刷新（Caddy
  // 操作后的补偿刷新）无轮次可用，回落页级永久 signal（随卸载终止）。
  const config = { signal: roundSignal ?? dashboardPolling.signal, silent: true }
  const slowLane = slowLaneDue()
  if (slowLane) fetchRulesSlowLane(roundSignal)
  fetchAllDataPromise = Promise.allSettled([
    request.get('/system/info', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        systemInfoUnavailable.value = true
        return
      }
      systemInfo.value = res.data
      systemInfoUnavailable.value = false
    }).catch(() => { if (!disposed) systemInfoUnavailable.value = true }),
    request.get('/system/metrics', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        systemMetricsUnavailable.value = true
        return
      }
      systemMetrics.value = res.data
      systemMetricsUnavailable.value = false
    }).catch(() => { if (!disposed) systemMetricsUnavailable.value = true }),
    request.get('/metrics/realtime', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        trafficUnavailable.value = true
        return
      }
      const data = res.data
      const now = Date.now()
      trafficInHistory.value = [...trafficInHistory.value, data.bytes_in].slice(-60)
      trafficOutHistory.value = [...trafficOutHistory.value, data.bytes_out].slice(-60)
      trafficTimestamps.value = [...trafficTimestamps.value, now].slice(-60)
      trafficUnavailable.value = false
    }).catch(() => { if (!disposed) trafficUnavailable.value = true }),
    request.get<APIResponse<DashboardMetricsResponse>>('/metrics/dashboard', config).then((res) => {
      if (disposed) return
      dashboardMetricsLanded.value = true
      const data = res.data
      if (!data) {
        caddyMetricsUnavailable.value = true
        hostMetricsUnavailable.value = true
        overviewUnavailable.value = true
        ruleMetricsUnavailable.value = buildRuleMetricsUnavailable(rules.value, undefined, false)
        return
      }
      caddyMetrics.value = data.global
      hostMetrics.value = data.hosts
      overview.value = data.overview
      ruleMetrics.value = data.rules
      ruleMetricsUnavailable.value = buildRuleMetricsUnavailable(rules.value, data.rules, true)
      caddyMetricsUnavailable.value = false
      hostMetricsUnavailable.value = false
      overviewUnavailable.value = false
    }).catch(() => {
      if (disposed) return
      dashboardMetricsLanded.value = true
      caddyMetricsUnavailable.value = true
      hostMetricsUnavailable.value = true
      overviewUnavailable.value = true
      // 移除 rulesUnavailable.value = true（与 /rules then 竞态）。
      // rulesUnavailable 由 /rules 自己的 then/catch 管理，避免双 setter 竞态。
      ruleMetricsUnavailable.value = buildRuleMetricsUnavailable(rules.value, undefined, false)
    }),
    request.get('/metrics/connections', config).then((res) => {
      if (disposed) return
      if (!res.data) {
        connectionsUnavailable.value = true
        return
      }
      const connData = res.data
      const now = Date.now()
      connEstablishedHistory.value = [...connEstablishedHistory.value, connData.established].slice(-60)
      connTimeWaitHistory.value = [...connTimeWaitHistory.value, connData.time_wait].slice(-60)
      connTimestamps.value = [...connTimestamps.value, now].slice(-60)
      connectionsUnavailable.value = false
    }).catch(() => { if (!disposed) connectionsUnavailable.value = true }),
    request.get('/caddy/status', config).then((res) => {
      if (disposed) return
      if (res.data) {
        caddyStatus.value = res.data.status || 'unknown'
        caddyApplyError.value = res.data.apply_error || ''
        caddyBackgroundApplyError.value = res.data.background_apply_error || ''
        caddyPid.value = res.data.pid || '0'
        configConsistent.value = res.data.config_consistent || ''
        configDrift.value = res.data.config_drift || ''
        caddyStatusUnavailable.value = false
      } else {
        caddyStatusUnavailable.value = true
      }
    }).catch(() => { if (!disposed) caddyStatusUnavailable.value = true }),
  ]).then(() => undefined).finally(() => {
    if (!disposed) initialLoading.value = false
    fetchAllDataPromise = null
  })

  return fetchAllDataPromise
}

const fetchRuleHealth = async (currentRules: Rule[], version: number, roundSignal?: AbortSignal) => {
  if (disposed || currentRules.length === 0) return
  if (ruleHealthInFlight) {
    // 在途：记下更新的版本供收尾补跑（旧版本已被取代，不排队）
    if (!pendingRuleHealth || pendingRuleHealth.version < version) pendingRuleHealth = { rules: currentRules, version }
    return
  }
  ruleHealthInFlight = true
  try {
    const res = await request.get<APIResponse<HealthResponse>>('/config/health', { signal: roundSignal ?? dashboardPolling.signal, silent: true })
    if (disposed || version !== rulesVersion) return
    const healthData = res.data || {}
    // healthData 是 {server: {hostPort: health}} 嵌套——
    // 预展平为 Map<hostPort, health>一次遍历,消除 rule×upstream×server 三重
    // 嵌套扫描(原每上游遍历全部 server 健康组,15s 轮询全量执行)。
    const healthByHostPort = new Map<string, NonNullable<HealthResponse[string]>[string]>()
    for (const serverHealth of Object.values(healthData)) {
      for (const [key, upHealth] of Object.entries(serverHealth || {})) {
        if (upHealth && !healthByHostPort.has(key)) healthByHostPort.set(key, upHealth)
      }
    }
    const nextRuleHealth: Record<string, RuleHealth> = {}
    currentRules.forEach((rule: Rule) => {
      const enabledUpstreams = rule.upstreams?.filter((upstream) => upstream.enabled !== false) || []
      let status: RuleHealth = 'unknown'
      if (rule.enabled && enabledUpstreams.length) {
        let hasUnknown = false
        let hasUnhealthy = false
        let hasDegraded = false

        enabledUpstreams.forEach((u) => {
          const key = hostPortKey(u.host, u.port)
          const upHealth = healthByHostPort.get(key)
          if (!upHealth) {
            hasUnknown = true
          } else if (upHealth.unknown) {
            hasUnknown = true
          } else if (!upHealth.healthy) {
            hasUnhealthy = true
          } else if (upHealth.degraded) {
            hasDegraded = true
          }
        })

        if (hasUnhealthy) status = 'unhealthy'
        else if (hasDegraded) status = 'degraded'
        else if (hasUnknown) status = 'unknown'
        else status = 'healthy'
      }
      nextRuleHealth[rule.caddy_id] = status
    })
    if (!disposed && version === rulesVersion) {
      ruleHealth.value = nextRuleHealth
      ruleHealthUnavailable.value = false
    }
  } catch (e) {
    // 与成功分支同款版本守卫——跨版本在途失败不污染新版本规则集的
    // 健康列（短暂全「-」误判）。
    if (!disposed && version === rulesVersion) {
      ruleHealthUnavailable.value = true
      console.error('Failed to fetch rule health:', e)
    }
  } finally {
    ruleHealthInFlight = false
    const pending = pendingRuleHealth
    pendingRuleHealth = null
    // 同一版本无需重跑（在途那轮已覆盖该版本）；补跑不携旧轮次的 signal——
    // 上一轮可能已被 pause/stop 或后续轮次 abort，回落页级永久 signal。
    if (pending && !disposed && pending.version !== version) {
      await fetchRuleHealth(pending.rules, pending.version)
    }
  }
}

const controlCaddy = async (action: 'start' | 'stop' | 'restart') => {
  if (authStore.readOnlyReason !== null) return
  // 占位先于确认（同 TaskMonitor/ClusterSettings 范式）：确认框悬挂期同样没有门，
  // 双击或「重启→停止」连点会叠加两次写请求，最终服务状态取决于返回顺序。
  if (caddyLoading.value) return
  caddyLoading.value = true
  
  const actionText = { start: '启动', stop: '停止', restart: '重启' }[action]
  const actionDesc = {
    start: '确定要启动 Caddy 服务吗？',
    stop: '确定要停止 Caddy 服务吗？停止后网站将无法访问。',
    restart: '确定要重启 Caddy 服务吗？'
  }[action]
  
  try {
    await ElMessageBox.confirm(actionDesc, `${actionText} Caddy 服务`, {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning',
    })
    if (disposed) return
    
    await request.post(`/caddy/${action}`, undefined, { signal: dashboardPolling.signal })
    if (disposed) return
    
    // After start or restart, reload config from database
    if (action === 'start' || action === 'restart') {
      await request.post('/config/reload', undefined, { signal: dashboardPolling.signal })
      if (disposed) return
    }
    
    // Optimistic update - show the expected status immediately
    if (action === 'stop') {
      caddyStatus.value = 'stopped'
    } else if (action === 'start' || action === 'restart') {
      caddyStatus.value = 'running'
    }
    
    mfaAwareSuccess(`Caddy ${actionText}成功`)
    
    // Also fetch actual status to confirm
    if (statusRefreshTimer) clearTimeout(statusRefreshTimer)
    if (statusConfirmTimer) clearTimeout(statusConfirmTimer)
    statusRefreshTimer = window.setTimeout(() => {
      void fetchAllData().then(() => {
        if (disposed) return
        statusConfirmTimer = window.setTimeout(fetchAllData, 1500)
      })
    }, 1000)
  } catch (error: unknown) {
    if (disposed) return
    if (error === 'cancel' || error === 'close') return
    // Error toast is already shown by the global axios interceptor.
    console.error('Failed to control Caddy:', error)
  } finally {
    if (!disposed) caddyLoading.value = false
  }
}

const dashboardPolling = usePollingTask(async (task) => fetchAllData(task.signal), {
  interval: 5000,
  onError: (error) => console.error('Failed to poll dashboard:', error),
})

onMounted(() => {
  // 首跑立即（usePollingTask.start() 只设定时器，首轮要等满 interval 5s——
  // 页面会空转圈整轮；与任务监控页同修）
  void dashboardPolling.run()
  dashboardPolling.start()
})

onUnmounted(() => {
  disposed = true
  if (statusRefreshTimer) clearTimeout(statusRefreshTimer)
  if (statusConfirmTimer) clearTimeout(statusConfirmTimer)
})
</script>

<style scoped>
.dashboard { max-width: 1500px; margin: 0 auto; }

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
.rules-count {
  font-size: 13px;
  font-weight: 600;
  color: var(--el-color-primary);
  line-height: 1;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}

.title-icon {
  font-size: 16px;
  color: #3b82f6;
}

.caddy-icon { color: #10b981; }
.resource-icon { color: #8b5cf6; }
.chart-icon { color: #f59e0b; }
.rules-icon { color: #3b82f6; }

.header-actions { display: flex; align-items: center; gap: 12px; }

.status-tag {
  min-width: 56px;
  text-align: center;
  font-weight: 500;
}

.status-tag.running { background: #ecfdf5; border-color: #a7f3d0; }
.status-tag.stopped { background: #fef2f2; border-color: #fecaca; }
.status-tag.info { background: #f3f4f6; border-color: #e5e7eb; }

.caddy-actions { display: flex; gap: 2px; }

.caddy-actions :deep(.el-button) {
  margin: 0;
  padding: 8px 12px;
}

.network-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid #f3f4f6; }
.section-label { font-size: 13px; color: #6b7280; margin-bottom: 10px; }
.network-tags { display: flex; flex-wrap: wrap; gap: 8px; }
.network-tag { background: #f3f4f6; }

.stat-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px;
  background: #f9fafb;
  border-radius: 8px;
}

.stat-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
}

.stat-blue { background: #eff6ff; color: #3b82f6; }
.stat-purple { background: #f5f3ff; color: #8b5cf6; }
.stat-green { background: #ecfdf5; color: #10b981; }

.stat-value { font-size: 20px; font-weight: 600; color: #111827; line-height: 1.2; }
.stat-label { font-size: 12px; color: #6b7280; margin-top: 2px; }

.resource-grid {
  display: grid;
  /* 四列等宽 + minmax(0,1fr)：数值不换行时压缩间距而不是折行 */
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 24px;
}
.resource-item { padding: 4px 0; min-width: 0; }
.resource-header { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 10px; white-space: nowrap; }
.resource-label-group { display: inline-flex; align-items: center; gap: 4px; min-width: 0; }
.resource-label { color: #4b5563; font-size: 13px; white-space: nowrap; }
.resource-value-group { display: inline-flex; align-items: baseline; gap: 2px; white-space: nowrap; }
.resource-value { font-size: 14px; font-weight: 500; white-space: nowrap; font-variant-numeric: tabular-nums; }
.text-blue { color: #3b82f6; }
.text-purple { color: #8b5cf6; }
.text-cyan { color: #0891b2; }
.text-green { color: #059669; }
.text-amber { color: #d97706; }
.text-red { color: #dc2626; }
.resource-total { font-size: 12px; color: #9ca3af; font-weight: 400; }
@media (max-width: 1280px) {
  .resource-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 700px) {
  .resource-grid { grid-template-columns: minmax(0, 1fr); }
}

.chart-card :deep(.el-card__body) { height: 240px; padding: 16px; box-sizing: border-box; }
.chart-container { height: 200px; }
.chart-skeleton { height: 200px; }
.collection-state { display: flex; align-items: center; justify-content: center; min-height: 80px; color: #909399; }

.text-primary { color: #111827; }
.text-secondary { color: #6b7280; }

.status-codes {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-start;
  gap: 4px;
}
.status-code {
  font-size: 10px;
  padding: 1px 4px;
  border-radius: 4px;
  font-weight: 500;
  white-space: nowrap;
  flex-shrink: 0;
}
.status-2xx { background: #ecfdf5; color: #059669; }
.status-3xx { background: #eff6ff; color: #2563eb; }
.status-4xx { background: #fffbeb; color: #d97706; }
.status-5xx { background: #fef2f2; color: #dc2626; }
.status-blocked { background: #f3e8ff; color: #7c3aed; }
.history-toolbar { display: flex; justify-content: flex-end; margin-top: 8px; padding-bottom: 16px; border-bottom: 1px solid var(--border-lighter); margin-bottom: 20px; }
.history-error-alert { margin-bottom: 16px; }

</style>
