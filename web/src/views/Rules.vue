<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Operation /></el-icon>
          负载均衡规则
        </h2>
        <p class="page-desc">管理流量分发策略和上游服务器配置</p>
      </div>
      <el-button type="primary" :disabled="isReadOnly || saving" @click="openWizard()">
        <el-icon><Plus /></el-icon>
        新建规则
      </el-button>
    </div>

    <el-alert v-if="certPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>证书状态加载失败：{{ certPollingError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="certRetryLoading" @click="retryCertPolling">立即重试</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ certPollingErrorDescription }}</div>
    </el-alert>

    <el-alert v-if="certInfoError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>证书详情加载失败：TLS 列可能显示为「加载失败」（非真实证书状态）</span>
          <el-button link type="danger" :loading="certInfoRetryLoading" @click="retryCertInfo">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-alert v-if="healthPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>上游健康状态加载失败：{{ healthPollingError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="healthRetryLoading" @click="retryHealthPolling">立即重试</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ healthPollingErrorDescription }}</div>
    </el-alert>

    <el-alert v-if="rulesLoadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>负载均衡规则加载失败，下方「暂无规则」不代表真实状态</span>
          <el-button link type="danger" :loading="loading" @click="fetchRules()">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-alert v-if="auxDataLoadFailed" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>辅助数据加载失败（{{ [
            usersLoadError ? '更新者列表（更新者列将显示「-」）' : '',
            certConfigsLoadError ? 'DNS 提供商配置（ACME 规则编辑无法选择 DNS 配置）' : '',
            caProvidersLoadError ? 'CA 提供商（选择器仅剩「系统默认」）' : '',
          ].filter(Boolean).join('；') }}）</span>
          <el-button link type="danger" :loading="auxDataRetryLoading" @click="retryAuxData">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-alert v-if="securityBindingsError" type="warning" :closable="false" show-icon class="polling-error-alert">
      <template #title>
        <div class="polling-error-title">
          <span>安全策略绑定数据加载失败：锁图标与流程投影可能显示为未绑定（非真实状态）</span>
          <el-button link type="warning" :loading="securityBindingsLoading" @click="retrySecurityBindings">重新加载</el-button>
        </div>
      </template>
    </el-alert>

    <el-card>
      <div class="table-toolbar">
        <el-input v-model="searchQuery" placeholder="搜索规则名 / 域名 / 端口 / ID" clearable :prefix-icon="Search" class="search-input" />
      </div>
      <el-table :data="pagedRules" row-key="caddy_id" v-loading="loading" stripe class="rules-table" :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <el-table-column prop="name" label="规则名称" min-width="140">
          <template #default="{ row }">
            <div class="rule-name-cell">
              <!-- 锁 hover 摘要（鼠标悬停）：按阶段 0/1/2/3 分组的紧凑摘要；
                   「查看完整处理流程」链接跳转流程弹框（跳转前 hide 本 popover 防遮挡）。
                   键盘可达：popover 内容 teleport 到 body，Tab 序到不了里面的按钮，
                   故锁图标本身是 role=button —— Enter/Space 直接打开流程弹框（弹框内
                   含完整阶段链路，信息面覆盖本摘要）；trigger-keys 置空是关掉 EP
                   默认的 Enter/Space 开关 popover（否则同键既开弹框又弹只读面板）。
                   2026-09-21 用户裁定：HTTP/HTTPS 规则恒显示锁（未绑定=warning 黄锁，
                   四阶段灰态「未启用」；绑定=is-allow 绿锁现状）；TCP 规则与 HTTP 同构
                   （阶段 0/1 放开）：未绑/已绑同色阶，阶段 2/3 恒灰态「不适用」。 -->
              <el-popover
                :ref="(el: unknown) => setLockPopover(row.caddy_id, el)"
                placement="right-start"
                trigger="hover"
                :trigger-keys="[]"
                :width="360"
                :popper-options="popperViewportSafe"
                popper-class="rule-lock-popper"
              >
                <template #reference>
                  <el-icon
                    :size="14"
                    class="acl-lock-icon"
                    :class="ruleStageModel(row as Rule).ruleDisabled ? 'is-unbound' : ruleStageModel(row as Rule).hasAnyPolicy ? 'is-allow' : 'is-unbound'"
                    role="button"
                    tabindex="0"
                    :aria-label="`查看「${row.name}」的安全处理流程`"
                    @keydown.enter.prevent="activateOnce($event, () => openFlowFromLock(row as Rule))"
                    @keydown.space.prevent="activateOnce($event, () => openFlowFromLock(row as Rule))"
                  ><Lock /></el-icon>
                </template>
                <div class="lock-summary">
                  <div class="popover-title">安全防护 · 阶段摘要</div>
                  <!-- 禁用规则的安全链不进入运行配置（零 listener 路由）——
                       摘要顶部必须点名，否则从锁图标巡检会高估防护 -->
                  <div v-if="ruleStageModel(row as Rule).ruleDisabled" class="lock-summary-hint">
                    规则已禁用——安全链未进入运行配置（绑定与阶段页保留，启用后生效）
                  </div>
                  <template v-for="stage in ruleStageModel(row as Rule).stages" :key="stage.stage">
                    <div class="lock-stage">
                      <div class="lock-stage-head" :class="`lock-stage-head--s${stage.stage}`">{{ stage.title }}</div>
                      <!-- TCP 规则阶段 2/3 恒灰态「不适用」（L4 无限流/WAF 引擎面，绑定侧已门）——
                           组有无均不落「未启用」（未启用=可绑未绑，语义不同） -->
                      <div v-if="row.protocol === 'tcp' && stage.stage >= 2" class="lock-stage-line lock-stage-empty">不适用（TCP 仅支持阶段 0/1）</div>
                      <!-- 四阶段恒出（2026-09-21 用户裁定：与流程弹框同口径）——空阶段灰态「未启用」不再整段缺席 -->
                      <div v-else-if="stage.groups.length === 0" class="lock-stage-line lock-stage-empty">未启用</div>
                      <!-- 按策略分小组（2026-09-21 用户裁定）：策略名做弱化小标题，该策略的阶段能力行
                           （含拦截页行）逐行挂其下，信息密度与流程弹框面板一致；单策略绑定时免分组框
                           保持紧凑。阶段 3 的 WAF 模式由投影首行（WAF（拦截/检测/仅自定义））承载，
                           不再单独渲染 mode tag -->
                      <template v-else>
                        <div
                          v-for="group in stage.groups"
                          :key="group.key"
                          class="lock-policy-group"
                          :class="{ 'is-compact': stage.groups.length === 1, 'is-disabled': !group.enabled }"
                        >
                          <div class="lock-policy-head">
                            <span class="lock-policy-name" :title="group.name">{{ group.name }}</span>
                          </div>
                          <div v-for="row in group.rows" :key="row.label" class="lock-stage-row">
                            <span class="lock-row-label">{{ row.label }}</span>
                            <span class="lock-row-detail" :title="row.detail">{{ row.detail }}</span>
                          </div>
                        </div>
                      </template>
                    </div>
                  </template>
                  <div class="lock-summary-hint"><el-button link type="primary" @click="openFlowFromLock(row as Rule)">查看完整处理流程 →</el-button></div>
                </div>
              </el-popover>
              <!-- 规则名入口复用 AccessibleLink：手写 <a role=button> 缺按键自动重复
                   守卫与统一焦点环（同页曾有两套键盘语义） -->
              <AccessibleLink class="rule-name-link" :title="row.name" @click="viewConfig(row as Rule)">{{ row.name }}</AccessibleLink>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="domain" label="域名" min-width="210" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="domain">{{ row.domain || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="协议" width="80">
          <template #default="{ row }">
            <el-tag :type="row.protocol === 'tcp' ? 'warning' : (row.enable_tls ? 'success' : 'primary')" size="small" effect="plain">
              {{ row.protocol === 'tcp' ? 'TCP' : (row.enable_tls ? 'HTTPS' : 'HTTP') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="负载策略" width="101" align="center" show-overflow-tooltip>
          <template #default="{ row }">
            <span>{{ getStrategyLabel(row.strategy) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="listen_port" label="端口" width="67" align="center">
          <template #default="{ row }">
            <span class="port">{{ row.listen_port }}</span>
          </template>
        </el-table-column>
        <el-table-column label="上游" width="64" align="center">
          <template #default="{ row }">
            <el-tag :type="row.dynamic_dns ? 'primary' : 'success'" size="small" effect="plain">
              {{ row.dynamic_dns ? '动态' : '静态' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="TLS" width="106" align="center">
          <template #default="{ row }">
            <el-popover
              v-if="row.enable_tls"
              placement="top"
              trigger="hover"
              :width="280"
              :popper-options="popperViewportSafe"
              :disabled="!certInfoMap[row.caddy_id]"
            >
              <template #reference>
                <el-tag :type="tlsTagType(row as Rule)" size="small" effect="plain" class="tls-tag">
                  {{ tlsTagLabel(row as Rule) }}
                </el-tag>
              </template>
              <div class="cert-tooltip" v-if="certInfoMap[row.caddy_id]">
                <div class="popover-title">证书信息</div>
                <div class="cert-row">
                  <span class="cert-label">来源</span>
                  <el-tag size="small" :type="certInfoMap[row.caddy_id]?.source === 'manual' ? 'primary' : 'success'">
                    {{ certInfoMap[row.caddy_id]?.source === 'manual' ? '手动上传' : 'ACME 自动' }}
                  </el-tag>
                </div>
                <div class="cert-row">
                  <span class="cert-label">域名</span>
                  <span class="cert-value" :title="certInfoMap[row.caddy_id]?.domains">{{ certInfoMap[row.caddy_id]?.domains || '-' }}</span>
                </div>
                <div class="cert-row">
                  <span class="cert-label">颁发者</span>
                  <span class="cert-value" :title="certInfoMap[row.caddy_id]?.issuer">{{ certInfoMap[row.caddy_id]?.issuer || '-' }}</span>
                </div>
                <div class="cert-row">
                  <span class="cert-label">生效时间</span>
                  <span class="cert-value">{{ formatDate(certInfoMap[row.caddy_id]?.not_before || '') || '-' }}</span>
                </div>
                <div class="cert-row">
                  <span class="cert-label">过期时间</span>
                  <span class="cert-value">{{ formatDate(certInfoMap[row.caddy_id]?.not_after || '') || '-' }}</span>
                </div>
                <div class="cert-row">
                  <span class="cert-label">剩余天数</span>
                  <!-- 过期证书不渲染裸负数（「-1 天」易误读为已过期一整天）-->
                  <span :class="['cert-days', certInfoMap[row.caddy_id]?.status]">
                    {{ certInfoMap[row.caddy_id]?.status === 'expired'
                      ? `已过期 ${Math.abs(certInfoMap[row.caddy_id]?.days_remaining ?? 0)} 天`
                      : `${certInfoMap[row.caddy_id]?.days_remaining} 天` }}
                  </span>
                </div>
                <div class="cert-row" v-if="certInfoMap[row.caddy_id]?.error">
                  <span class="cert-label">错误</span>
                  <span class="cert-error" :title="certInfoMap[row.caddy_id]?.error">{{ certInfoMap[row.caddy_id]?.error }}</span>
                </div>
                <div class="cert-row" v-if="certInfoMap[row.caddy_id]?.status === 'valid' && certJobMap[row.caddy_id]?.status === 'failed'">
                  <span class="cert-label">最近重签</span>
                  <span class="cert-error" :title="certJobMap[row.caddy_id]?.message">失败：{{ certJobMap[row.caddy_id]?.message || '未知错误' }}</span>
                </div>
              </div>
            </el-popover>
            <span v-else class="text-secondary">-</span>
          </template>
        </el-table-column>
        <el-table-column label="健康" width="64" align="center">
          <template #default="{ row }">
            <!-- 零启用上游的启用态规则：渲染层跳过（不发路由/不注册 logger），
                 与「已禁用」的「-」同形会让用户无法从列表区分「未发布」。 -->
            <el-tooltip
              v-if="row.enabled && Array.isArray(row.upstreams) && getEnabledUpstreams(row as Rule).length === 0"
              content="未发布：已启用但零启用上游，运行配置跳过该规则（Caddy 不会代理）"
              placement="top"
            >
              <el-tag type="warning" size="small" effect="plain">未发布</el-tag>
            </el-tooltip>
            <el-popover v-else-if="row.enabled && healthStatus[row.caddy_id]" placement="top" trigger="hover" :width="240" :popper-options="popperViewportSafe">
              <template #reference>
                <el-tag :type="getHealthTagType(healthStatus[row.caddy_id])" size="small" effect="plain" class="health-tag">
                  {{ getHealthLabel(healthStatus[row.caddy_id]) }}
                </el-tag>
              </template>
              <div class="health-tooltip">
                <div class="popover-title">上游服务器状态</div>
                <template v-if="row.dynamic_dns">
                  <div v-for="(status, address) in healthStatus[row.caddy_id]?.upstreams || {}" :key="address" class="upstream-item">
                    <span class="upstream-address">{{ address }}</span>
                    <el-tooltip v-if="status.unknown && status.dynamic" content="健康不可观测（动态 DNS 按解析后 IP 跟踪 / TCP 被动熔断无指标端点）" placement="top"><span class="upstream-na">N/A</span></el-tooltip>
                    <el-tag v-else-if="status.unknown" size="small" effect="plain" type="info">启用·待观测</el-tag>
                    <el-icon v-else-if="status.degraded" class="upstream-degraded"><WarningFilled /></el-icon>
                    <el-icon v-else-if="status.healthy" class="upstream-healthy"><CircleCheckFilled /></el-icon>
                    <el-icon v-else class="upstream-unhealthy"><CircleCloseFilled /></el-icon>
                  </div>
                </template>
                <template v-else>
                  <div v-for="upstream in getEnabledUpstreams(row as Rule)" :key="upstream.id" class="upstream-item">
                    <div class="upstream-item-row">
                      <span class="upstream-address">{{ upstream.host }}:{{ upstream.port }}</span>
                      <span class="upstream-status">
                        <el-tooltip v-if="getUpstreamHealthStatus(row.caddy_id, upstream).unknown && (getUpstreamHealthStatus(row.caddy_id, upstream).dynamic || (row.protocol === 'tcp' && !row.enable_active_health_check))" content="健康不可观测（动态 DNS 按解析后 IP 跟踪 / TCP 被动熔断无指标端点）" placement="top"><span class="upstream-na">N/A</span></el-tooltip>
                        <el-tag v-else-if="getUpstreamHealthStatus(row.caddy_id, upstream).unknown" size="small" effect="plain" type="info">启用·待观测</el-tag>
                        <el-icon v-else-if="getUpstreamHealthStatus(row.caddy_id, upstream).degraded" class="upstream-degraded"><WarningFilled /></el-icon>
                        <el-icon v-else-if="getUpstreamHealthStatus(row.caddy_id, upstream).healthy" class="upstream-healthy"><CircleCheckFilled /></el-icon>
                        <el-icon v-else class="upstream-unhealthy"><CircleCloseFilled /></el-icon>
                        <span v-if="getUpstreamMetrics(row.caddy_id, upstream).fails > 0" class="upstream-fails">失败 {{ getUpstreamMetrics(row.caddy_id, upstream).fails }}</span>
                      </span>
                    </div>
                  </div>
                </template>
                <!-- 路径规则自定义上游（2026-09-21 用户裁定）：仅自定义路由开启且路径规则携带上游时，
                     主上游之后按路径规则分组展示（健康/指标键同 host:port，复用既有查询函数） -->
                <template v-for="pathRule in healthPathRules(row as Rule)" :key="pathRule.id ?? pathRule.path">
                  <div v-if="pathRule.upstreams && pathRule.upstreams.length > 0" class="path-rule-health-group">
                    <div class="path-rule-health-title">{{ pathRule.path }}（{{ pathRule.match_type === 'exact' ? '精确' : '前缀' }}）</div>
                    <div v-for="pu in pathRule.upstreams" :key="`${pu.address}:${pu.port}`" class="upstream-item">
                      <div class="upstream-item-row">
                        <span class="upstream-address">{{ pu.address }}:{{ pu.port }}</span>
                        <span class="upstream-status">
                          <el-tooltip v-if="getUpstreamHealthStatus(row.caddy_id, pathUpstreamRef(pu)).unknown && getUpstreamHealthStatus(row.caddy_id, pathUpstreamRef(pu)).dynamic" content="健康不可观测（动态 DNS 按解析后 IP 跟踪 / TCP 被动熔断无指标端点）" placement="top"><span class="upstream-na">N/A</span></el-tooltip>
                          <el-tag v-else-if="getUpstreamHealthStatus(row.caddy_id, pathUpstreamRef(pu)).unknown" size="small" effect="plain" type="info">启用·待观测</el-tag>
                          <el-icon v-else-if="getUpstreamHealthStatus(row.caddy_id, pathUpstreamRef(pu)).degraded" class="upstream-degraded"><WarningFilled /></el-icon>
                          <el-icon v-else-if="getUpstreamHealthStatus(row.caddy_id, pathUpstreamRef(pu)).healthy" class="upstream-healthy"><CircleCheckFilled /></el-icon>
                          <el-icon v-else class="upstream-unhealthy"><CircleCloseFilled /></el-icon>
                          <span v-if="getUpstreamMetrics(row.caddy_id, pathUpstreamRef(pu)).fails > 0" class="upstream-fails">失败 {{ getUpstreamMetrics(row.caddy_id, pathUpstreamRef(pu)).fails }}</span>
                        </span>
                      </div>
                    </div>
                  </div>
                </template>
              </div>
            </el-popover>
            <el-tag v-else-if="!row.enabled" type="info" size="small" effect="plain">-</el-tag>
            <span v-else class="text-secondary">-</span>
          </template>
        </el-table-column>
        <el-table-column label="更新者" width="66" align="center" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="updater-name">{{ getUpdaterName(row.updated_by || row.created_by) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="更新时间" width="164" align="center" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="updated-time">{{ formatUpdatedTime(row.updated_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="64" align="center">
          <template #default="{ row }">
            <el-tooltip
              :disabled="!isReadOnly && !isCertJobActive(certJobMap[row.caddy_id]?.status) && !ruleTogglePending[row.caddy_id]"
              :content="isReadOnly ? readOnlyMessage : ruleTogglePending[row.caddy_id] ? '规则状态更新中，请稍候' : certJobLockTooltip(row as Rule, '证书申请中，请等待完成或失败后再启停规则')"
            >
              <div>
                <el-switch
                  v-model="row.enabled"
                  :loading="ruleTogglePending[row.caddy_id]"
                  :disabled="isReadOnly || isCertJobActive(certJobMap[row.caddy_id]?.status) || ruleTogglePending[row.caddy_id]"
                  :aria-label="`${row.name} 的启用状态`"
                  @change="toggleRule(row as Rule)"
                  class="status-switch"
                />
              </div>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="172" fixed="right" align="center">
          <template #default="{ row }">
            <div class="operation-buttons">
              <!-- 只读态（从节点/非管理员）全部渲染但禁用，tooltip 显示原因（authStore.readOnlyMessage 同构） -->
              <el-tooltip
                :disabled="!isReadOnly && canEditRule(row as Rule)"
                :content="isReadOnly ? readOnlyMessage : certJobLockTooltip(row as Rule, '证书申请中，请等待完成或失败后再修改规则')"
              >
                <div>
                <el-button type="primary" link size="small" @click="openWizard(row as Rule)" :disabled="isReadOnly || saving || !canEditRule(row as Rule)">
                    编辑
                  </el-button>
                </div>
              </el-tooltip>
              <el-tooltip :disabled="!isReadOnly" :content="readOnlyMessage">
                <div>
                <el-button type="primary" link size="small" :disabled="isReadOnly || saving" @click="duplicateRule(row as Rule)">
                  复制
                </el-button>
                </div>
              </el-tooltip>
              <el-tooltip :disabled="!isReadOnly && row.log_enabled" :content="isReadOnly ? readOnlyMessage : '该规则未开启访问日志'">
                <div>
                <el-button type="primary" link size="small" :disabled="isReadOnly || !row.log_enabled" @click="openRuleLogDialog(row as Rule)">
                  日志
                </el-button>
                </div>
              </el-tooltip>
              <!-- TCP（阶段 0/1）与 HTTP 同入口；含 2/3 特征策略的拒绝由编辑器选择侧置灰 + 后端 400 承接 -->
              <el-tooltip :disabled="!isReadOnly && !securityBindingsLoading && !securityBindingsError" :content="securityBindingsLoading ? '安全策略绑定加载中…' : securityBindingsError ? '安全策略绑定加载失败，请先点击上方重新加载' : readOnlyMessage">
                <div>
                <el-button type="primary" link size="small" :disabled="isReadOnly || saving || securityBindingsLoading || securityBindingsError" @click="openBindDialog(row as Rule)">
                  安全
                </el-button>
                </div>
              </el-tooltip>
              <el-tooltip
                :disabled="!isReadOnly && canDeleteRule(row as Rule) && certJobStatusOf(row as Rule) !== 'waiting_ca'"
                :content="isReadOnly ? readOnlyMessage : certJobLockTooltip(row as Rule, '证书申请中，请等待完成或失败后再删除规则')"
              >
                <div>
                <el-button type="danger" link size="small" @click="deleteRule(row as Rule)" :disabled="isReadOnly || !canDeleteRule(row as Rule)">
                    删除
                  </el-button>
                </div>
              </el-tooltip>
            </div>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="暂无负载均衡规则" :image-size="80" />
        </template>
      </el-table>
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :total="filteredRules.length"
        :page-sizes="[10, 20, 30, 50]"
        layout="total, sizes, prev, pager, next"
        class="rules-pagination"
      />
    </el-card>


    <el-dialog v-model="wizardVisible" class="dialog-body-inset" width="min(960px, 94vw)" top="5vh" :close-on-click-modal="false" :before-close="beforeWizardClose" @close="resetWizard">
      <template #header>
        <DialogHeader :icon="Connection" :title="editingRule ? '编辑规则' : (isCopyMode ? '复制规则' : '新建规则')"
          subtitle="配置负载均衡规则的监听、TLS、上游与路由行为" />
      </template>
      <el-steps :active="visualStepIndex" finish-status="success" align-center class="wizard-steps" :class="{ 'is-clickable': stepsClickable }">
        <el-step title="基本配置" :icon="InfoFilled" @click="jumpToStep(WIZARD_STEP.BASIC)" />
        <el-step v-if="showTlsStep" title="TLS 配置" :icon="Lock" @click="jumpToStep(WIZARD_STEP.TLS)" />
        <el-step title="上游服务器" :icon="Connection" @click="jumpToStep(WIZARD_STEP.UPSTREAMS)" />
        <el-step v-if="showCustomRoutesStep" title="自定义路由" :icon="Guide" @click="jumpToStep(WIZARD_STEP.CUSTOM_ROUTES)" />
        <el-step title="高级选项" :icon="Setting" @click="jumpToStep(WIZARD_STEP.ADVANCED)" />
        <el-step title="预览保存" :icon="Check" @click="jumpToStep(WIZARD_STEP.PREVIEW)" />
      </el-steps>

      <div class="wizard-content">
        <!-- Step 0: 基本配置 -->
        <div v-show="currentStep === WIZARD_STEP.BASIC" class="step-content">
          <el-form :model="wizardForm" label-width="100px" :disabled="saving">
            <el-form-item label="规则名称" required>
              <el-input v-model="wizardForm.name" placeholder="例如：我的网站负载均衡" maxlength="100" show-word-limit />
            </el-form-item>
            
            <!-- 原生表单行（2026-10-11 用户裁定：对齐统一走 el-form-item，弃自管标签行
                 ——后者曾因侧距与 el-form-item 不一致致 20px 漂移；radio-group 的 Firefox
                 label-for 控制台告警为 EP 上游已知形态，非用户可见） -->
            <el-form-item label="协议" required>
              <el-radio-group v-model="wizardForm.protocol" aria-label="协议">
                <el-radio value="http">HTTP</el-radio>
                <el-radio value="tcp">TCP</el-radio>
              </el-radio-group>
            </el-form-item>

            <el-form-item label="域名" required v-if="wizardForm.protocol === 'http'" class="domain-item">
              <el-input v-model="wizardForm.domain" placeholder="例如：example.com, www.example.com" />
              <div class="form-tip-line">多个域名用逗号分隔，用于 HTTPS 证书和 HTTP 重定向</div>
            </el-form-item>

            <el-form-item label="监听端口" required>
              <el-input-number v-model="wizardForm.listen_port" :min="1" :max="65535" controls-position="right" @change="userExplicitPort = true" />
              <span class="form-tip-inline">
                <span v-if="portWarning" class="port-warning">{{ portWarning }}</span>
                <span v-else-if="wizardForm.protocol === 'http'">建议使用 80 或其他非保留端口</span>
                <span v-else>建议使用 10000-60000 范围内的端口</span>
              </span>
              <div class="form-tip-line">服务端还会按当前部署校验实际管理端口（面板监听端口与 Caddy admin 端口），自定义端口以保存结果为准</div>
            </el-form-item>

            <el-form-item label="启用 HTTPS" v-if="wizardForm.protocol === 'http'">
              <el-switch v-model="wizardForm.enable_tls" :disabled="isCurrentRuleLocked" />
              <span class="form-tip-inline">
                <span v-if="isCurrentRuleLocked" class="port-warning">证书申请中，暂不能修改 TLS 设置</span>
                <span v-else>启用 TLS 加密传输</span>
              </span>
            </el-form-item>

            <el-form-item label="描述">
              <el-input v-model="wizardForm.description" type="textarea" :rows="3" placeholder="可选填写，便于理解规则用途" maxlength="300" show-word-limit class="description-input" />
            </el-form-item>

            <el-form-item label="访问日志" v-if="wizardForm.protocol === 'http'">
              <el-switch v-model="wizardForm.log_enabled" />
              <span class="form-tip-inline">开启后记录该规则的访问日志到 /app/logs/rules/ 目录</span>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 1: TLS 配置 (仅当启用 HTTPS 时显示) -->
        <div v-show="currentStep === WIZARD_STEP.TLS" class="step-content">
          <div v-if="tlsDetailError && wizardForm.tls_source === 'manual'" class="info-note-bar">
            <span class="info-note-desc">证书详情加载失败：手动 TLS 配置可能不完整，已阻止进入下一步与保存。</span>
            <el-button size="small" type="primary" plain :loading="tlsDetailLoading" @click="retryTlsDetail">重新加载</el-button>
          </div>
          <el-form :model="wizardForm" label-width="100px" v-if="wizardForm.enable_tls && wizardForm.protocol === 'http'" :disabled="saving">
            <el-form-item label="证书来源">
              <el-radio-group v-model="wizardForm.tls_source" :disabled="isCurrentRuleLocked" aria-label="证书来源">
                <el-radio value="manual">手动上传</el-radio>
                <el-radio value="acme_dns">ACME + DNS 自动</el-radio>
              </el-radio-group>
              <div v-if="isCurrentRuleLocked" class="form-tip-line port-warning">证书申请中，暂不能修改证书来源</div>
            </el-form-item>
            <template v-if="wizardForm.tls_source === 'acme_dns'">
              <el-form-item label="DNS 配置">
                <el-select v-model="wizardForm.acme_config_id" placeholder="选择 DNS 提供商配置" style="width: 100%;">
                  <!-- 口径与下方 CA 下拉同源：启用项 ∪ 当前值（已禁用仅回显、置 disabled
                       不可新选；后端写侧要求 enabled=1，选禁用项保存必 400） -->
                  <el-option v-for="cfg in wizardCertConfigOptions" :key="cfg.id" :label="referencedOptionLabel(cfg)" :value="cfg.id" :disabled="!cfg.enabled" />
                </el-select>
                <div v-if="certConfigsLoadError" class="form-tip-line port-warning">DNS 提供商配置加载失败（下拉为空≠未配置）——请经页面顶部横幅重试后再编辑</div>
                <div v-else class="form-tip-line">请先在「系统设置 / 免费证书」中添加 DNS 提供商配置</div>
              </el-form-item>
              <el-form-item label="CA 提供商">
                <el-select v-model="wizardForm.ca_provider_id" placeholder="系统默认" clearable style="width: 100%">
                  <el-option label="系统默认" :value="0" />
                  <!-- 选项=启用 ∪ 当前值（已禁用项仅回显、置 disabled 不可新选；
                       口径单源 utils/caProviderOptions） -->
                  <el-option v-for="p in wizardCAProviderOptions" :key="p.id" :label="referencedOptionLabel(p)" :value="p.id" :disabled="!p.enabled" />
                </el-select>
                <div class="form-tip-line">选择自动签发证书使用的 CA 提供商，留空或「系统默认」将跟随全局默认设置</div>
              </el-form-item>
            </template>
            <template v-else>
              <el-form-item label="证书 (PEM)">
                <div class="cert-input-wrapper">
                  <el-input 
                    v-model="wizardForm.tls_cert" 
                    type="textarea" 
                    :rows="8" 
                    placeholder="-----BEGIN CERTIFICATE-----..." 
                    class="cert-textarea"
                    @blur="validateCertificate"
                  />
                  <el-button size="small" class="paste-btn" @click="pasteFromFile('cert')">
                    <el-icon><Document /></el-icon>从文件粘贴
                  </el-button>
                </div>
              </el-form-item>
              <el-form-item label="私钥 (KEY)">
                <div class="cert-input-wrapper">
                  <el-input 
                    v-model="wizardForm.tls_key" 
                    type="textarea" 
                    :rows="8" 
                    :placeholder="wizardForm.tlsKeySet && !wizardForm.tls_key.trim() ? '已配置（私钥已隐藏，粘贴新私钥可更换）' : '-----BEGIN PRIVATE KEY-----...'"
                    class="cert-textarea"
                    @blur="validateCertificate"
                  />
                  <el-button size="small" class="paste-btn" @click="pasteFromFile('key')">
                    <el-icon><Document /></el-icon>从文件粘贴
                  </el-button>
                </div>
              </el-form-item>
              
              <!-- Certificate Info Display -->
              <div v-if="certInfo.valid || certInfo.warning || certInfo.error" class="cert-info-container">
                <div v-if="certInfo.valid" class="info-note-bar cert-info-alert">
                  <span class="info-note-desc">{{ certInfo.warning ? '证书验证通过（有警告）' : '证书验证通过' }}</span>
                  <span class="info-note-sub">域名: {{ certInfo.domain }} | 过期时间: {{ certInfo.expiryDate }} <span v-if="certInfo.daysUntilExpiry <= 30" class="cert-expiry-warning">(剩余 {{ certInfo.daysUntilExpiry }} 天)</span><span v-else class="cert-expiry-normal">(剩余 {{ certInfo.daysUntilExpiry }} 天)</span></span>
                  <span v-if="certInfo.warning" class="info-note-sub">⚠️ {{ certInfo.warning }}</span>
                </div>
                <div v-if="certInfo.error" class="info-note-bar cert-info-alert"><span class="info-note-desc">{{ certInfo.error }}</span></div>
              </div>
            </template>
            <el-form-item label="HTTP 重定向">
              <el-switch v-model="wizardForm.tls_http_redirect" />
              <span class="form-tip-inline">将 HTTP 请求自动重定向到 HTTPS</span>
            </el-form-item>
          </el-form>
          <!-- 原「请先在基本配置中启用 HTTPS」说明框已删除：
               showTlsStep=protocol http && enable_tls 时本步才渲染，而该框 v-if 要
               !enable_tls——恒不可达的死模板。 -->
        </div>


        <!-- Step 2: 上游服务器 -->
        <div v-show="currentStep === WIZARD_STEP.UPSTREAMS" class="step-content">
          <el-form :model="wizardForm" label-width="100px" :disabled="saving">
            <div class="upstream-header">
              <span class="section-title">上游服务器列表</span>
              <el-button size="small" type="primary" @click="addUpstream" :disabled="wizardForm.upstreams.length >= MAX_UPSTREAM_ROWS || (wizardForm.dynamic_dns && wizardForm.upstreams.length >= 1)">
                <el-icon><Plus /></el-icon>添加上游
              </el-button>
            </div>
            <div v-if="wizardForm.dynamic_dns" class="info-note-bar"><span class="info-note-desc">动态上游模式下仅需一个上游条目，DNS 将动态解析出多个 IP</span></div>

            <el-table :data="wizardForm.upstreams" border class="upstream-table" :fit="true">
              <el-table-column label="主机地址 *" min-width="150">
                <template #default="{ row, $index }">
                  <el-input 
                    v-model="row.host" 
                    placeholder="IP 或域名" 
                    size="small" 
                    class="upstream-input"
                    :aria-label="`上游第 ${$index + 1} 行主机地址`"
                    :class="{ 'is-error': upstreamRowInvalid(row as UpstreamInput, $index) }"
                    @blur="upstreamTouched[$index] = true"
                  />
                </template>
              </el-table-column>
              <el-table-column label="端口" width="96">
                <template #default="{ row, $index }">
                  <el-input-number v-model="row.port" :min="1" :max="65535" size="small" controls-position="right" class="upstream-input-small" :class="{ 'is-error': upstreamRowMissingPort(row as UpstreamInput, $index) }" :aria-label="`上游第 ${$index + 1} 行端口`" @blur="upstreamTouched[$index] = true" />
                </template>
              </el-table-column>
              <el-table-column label="协议" width="88">
                <template #default="{ row, $index }">
                  <el-select v-model="row.protocol" size="small" placeholder="协议" :aria-label="`上游第 ${$index + 1} 行协议`">
                    <template v-if="wizardForm.protocol === 'tcp'">
                      <el-option value="tcp" label="TCP" />
                      <el-option value="tls" label="TLS" />
                    </template>
                    <template v-else>
                      <el-option value="http" label="HTTP" />
                      <el-option value="https" label="HTTPS" />
                    </template>
                  </el-select>
                </template>
              </el-table-column>
              <el-table-column min-width="124" v-if="wizardForm.protocol === 'http'">
                <template #header>
                  回源域名<FieldHelpIcon content="该上游独立的回源 Host 头与 HTTPS SNI（主机名，不带端口；端口沿用左侧端口列配置）。留空=不覆盖（Host 跟随客户端请求或上游地址）" />
                </template>
                <template #default="{ row, $index }">
                  <el-tooltip placement="top" :disabled="!wizardForm.dynamic_dns" content="动态上游模式不支持回源域名（改写 Host 请经 API/MCP 设置规则级 host_header）">
                    <el-input
                      v-model="row.origin_domain"
                      placeholder="留空=不覆盖"
                      size="small"
                      class="upstream-input"
                      :aria-label="`上游第 ${$index + 1} 行回源域名`"
                      :disabled="wizardForm.dynamic_dns"
                    />
                  </el-tooltip>
                </template>
              </el-table-column>
              <el-table-column width="80">
                <template #header>
                  权重 %<FieldHelpIcon content="数字越大，分配到的请求越多；权重相同时即为普通轮询。至少需要添加一个上游服务器。" />
                </template>
                <template #default="{ row, $index }">
                  <el-input-number v-model="row.weight" :min="1" :max="100" size="small" controls-position="right" class="upstream-input-small" :aria-label="`上游第 ${$index + 1} 行权重（%）`" :disabled="!row.enabled" @change="onWeightChange($index)" />
                </template>
              </el-table-column>
              <el-table-column width="104">
                <template #header>
                  {{ wizardForm.protocol === 'tcp' ? '最大连接' : '最大请求数' }}<FieldHelpIcon :content="wizardForm.protocol === 'tcp'
                    ? '该上游并发连接数上限（HTTP 规则映射为 reverse_proxy 每上游并发请求数 max_requests；TCP 规则映射为 caddy-l4 max_connections），0 为不限制'
                    : '该上游同时处理的请求数达到上限后判定不可用并移出负载，0 为不限制——HTTP 反代无逐上游并发连接限制'" />
                </template>
                <template #default="{ row, $index }">
                  <el-tooltip placement="top" :disabled="!wizardForm.dynamic_dns" :content="`动态上游模式下${wizardForm.protocol === 'tcp' ? '最大连接' : '最大请求数'}不生效`">
                    <el-input-number v-model="row.max_connections" :min="RULE_NUMERIC_LIMITS.maxConnectionsMin" size="small" controls-position="right" class="upstream-input-small" :aria-label="`上游第 ${$index + 1} 行${wizardForm.protocol === 'tcp' ? '最大连接' : '最大请求数'}`" :disabled="wizardForm.dynamic_dns" />
                  </el-tooltip>
                </template>
              </el-table-column>
              <el-table-column label="启用" width="52" align="center">
                <template #default="{ row, $index }">
                  <el-switch v-model="row.enabled" size="small" :aria-label="`上游第 ${$index + 1} 行启用`" @change="onWeightChange($index)" />
                </template>
              </el-table-column>
              <el-table-column width="48" align="center">
                <template #default="{ $index }">
                  <el-button type="danger" link size="small" :aria-label="`删除上游第 ${$index + 1} 行`" @click="removeUpstream($index)">
                    <el-icon><Delete /></el-icon>
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
            <div v-if="upstreamFieldWarning" class="form-tip-line">
              <span class="port-warning">{{ upstreamFieldWarning }}</span>
            </div>

            <template v-if="wizardForm.protocol === 'http'">
              <el-divider content-position="left" class="compact-divider">路由与后端兼容</el-divider>
              <el-form-item label="自定义路由">
                <el-switch v-model="wizardForm.custom_routes_enabled" @change="onCustomRoutesToggle" />
                <span class="form-tip-inline">开启后在下一步配置按路径转发规则</span>
              </el-form-item>
              <!-- NTLM 兼容（2026-10-12 用户定稿）：与自定义路由同区（后端兼容域）；
                   开启后以 NTLM 接管形态锁定 7 字段（清单见 onNtlmToggle 弹框） -->
              <el-form-item>
                <template #label><span>NTLM 兼容<FieldHelpIcon popper-class="ntlm-help-popper">
                    <template #content>
                      <div class="ntlm-help-line">适用场景：Exchange / AD / 旧版 IIS 等使用 NTLM / 协商认证的后端</div>
                      <div class="ntlm-help-line">已知限制：</div>
                      <div class="ntlm-help-line">· 若后端协商到 Kerberos，建议不改写 Host</div>
                      <div class="ntlm-help-line">· 入口 HTTP/2 由客户端自动降级，不受本开关控制</div>
                    </template>
                  </FieldHelpIcon></span>
                </template>
                <div class="ntlm-switch-control">
                  <el-switch :model-value="ntlmOn" @change="onNtlmToggle" />
                  <span class="form-tip-inline">为 NTLM / 协商认证后端锁定长连接亲和的代理形态</span>
                </div>
              </el-form-item>

              <div v-if="ntlmOn" class="info-note-bar">
                <span class="info-note-desc">NTLM 接管已生效：负载策略锁定 Cookie 会话保持 · 请求重试禁用 · 响应立即透传 · Keepalive 300s + 强制 HTTP/1.1 · 主动健康检查关闭（被动健康检查仍在役）</span>
              </div>
            </template>

            <el-divider content-position="left" class="compact-divider">负载策略</el-divider>

            <div class="strategy-cards" role="radiogroup" aria-label="负载策略">
              <el-tooltip
                v-for="card in strategyCardOptions"
                :key="card.value"
                placement="top"
                :disabled="!ntlmOn || card.value === 'cookie'"
                content="NTLM 模式下已锁定"
              >
                <div
                  class="strategy-card"
                  :class="{ active: wizardForm.strategy === card.value, locked: strategyLocked(card.value) }"
                  role="radio"
                  :aria-checked="wizardForm.strategy === card.value"
                  :aria-disabled="strategyLocked(card.value)"
                  :tabindex="strategyTabindex(card.value)"
                  :ref="(el: unknown) => setStrategyCardRef(card.value, el)"
                  @click="selectStrategy(card.value)"
                  @keydown="onStrategyKeydown($event)"
                  @keydown.enter.prevent="activateOnce($event, () => selectStrategy(card.value))"
                  @keydown.space.prevent="activateOnce($event, () => selectStrategy(card.value))"
                >
                  <div class="strategy-card-head">
                    <span class="strategy-card-icon" aria-hidden="true">
                      <el-icon><component :is="strategyIcon(card.value)" /></el-icon>
                    </span>
                    <span class="strategy-card-title">{{ card.title }}</span>
                    <span class="strategy-card-mark" aria-hidden="true">
                      <el-icon v-if="ntlmOn && card.value === 'cookie'" class="strategy-lock-icon"><Lock /></el-icon>
                      <el-icon v-else-if="wizardForm.strategy === card.value" class="strategy-check-icon"><Check /></el-icon>
                    </span>
                  </div>
                  <div class="strategy-card-desc">{{ card.desc }}</div>
                </div>
              </el-tooltip>
            </div>


            <el-divider content-position="left" class="compact-divider">健康检查</el-divider>

            <!-- 三个健康阈值控件均不设上限：后端只校验 ≥1（handlers.go），
                 带外合法值（API/MCP 写入 20）不得在编辑触碰控件时被静默夹到 10。 -->
            <el-form-item label="失败阈值">
              <el-input-number v-model="wizardForm.health_check_unhealthy_threshold" :min="1" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">次失败后标记为不健康（被动计数与主动探测共用）</span>
            </el-form-item>


            <el-form-item label="检查间隔">
              <el-input-number v-model="wizardForm.health_check_interval" :min="RULE_NUMERIC_LIMITS.healthCheckIntervalMin" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">秒，主动探测间隔；被动失败记忆窗口为其 3 倍</span>
            </el-form-item>

            <template v-if="wizardForm.protocol === 'http'">
              <el-form-item label="主动检查">
                <div class="active-check-control">
                  <el-switch v-model="wizardForm.enable_active_health_check" :disabled="ntlmOn" />
                  <TakeoverBadge v-if="ntlmOn" />
                  <span class="form-tip-inline">{{ ntlmOn
                    ? '已关闭：NTLM 后端探测返回 401 会被误判摘除；被动健康检查仍在役'
                    : (wizardForm.enable_active_health_check ? '周期探测，异常节点持续摘除直至恢复（推荐）' : '仅被动熔断，异常节点会周期恢复并重新接收流量') }}</span>
                </div>
              </el-form-item>

              <!-- 混合回源域名 + 主动检查提示（2026-10-10 用户裁定）：探测不感知
                   逐上游回源域名（引擎硬墙：probe 不走处理链、replacer 无提供者），
                   统一 Host 探测可能误摘按域名严格校验的后端节点 -->
              <div v-if="mixedOriginActiveCheckWarn" class="info-note-bar">
                <span class="info-note-desc">已配置逐上游回源域名：主动健康检查不感知回源域名，探测请求的 Host 将统一使用「健康检查域名」（留空则跟随后端域名（若配置），否则用上游地址）——按域名严格校验 Host 的后端可能被误摘为不健康。建议设置一个所有后端都接受的健康检查域名，或关闭主动检查改用被动熔断</span>
              </div>

              <template v-if="wizardForm.enable_active_health_check">
                <el-form-item label="主动探测超时">
                  <el-input-number v-model="wizardForm.health_check_timeout" :min="RULE_NUMERIC_LIMITS.healthCheckTimeoutMin" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">秒，仅主动探测单次超时；被动熔断不使用该值</span>
                </el-form-item>
                <el-form-item label="检查路径">
                  <el-input v-model="wizardForm.health_check_path" placeholder="默认 /" style="width: 180px;" />
                  <span class="form-tip-inline">留空探测 /，需返回 2xx 否则判为异常</span>
                </el-form-item>
                <el-form-item label="健康检查域名">
                  <el-input v-model="wizardForm.health_check_host" placeholder="留空=跟随后端域名（若配置），否则用上游地址" style="width: 220px;" />
                  <span class="form-tip-inline">探测请求的 Host 头；HTTPS 上游的探测不携带独立 SNI（回源域名仅作用于代理流量）</span>
                </el-form-item>
                <el-form-item label="恢复阈值">
                  <el-input-number v-model="wizardForm.health_check_healthy_threshold" :min="1" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">次连续探测成功后恢复为健康</span>
                </el-form-item>
              </template>
            </template>

            <template v-if="wizardForm.protocol === 'tcp'">
              <el-form-item label="主动检查">
                <div class="active-check-control">
                  <el-switch v-model="wizardForm.enable_active_health_check" />
                  <span class="form-tip-inline">{{ wizardForm.enable_active_health_check ? '周期探测上游端口，异常节点持续摘除直至恢复（推荐）' : '仅被动熔断，异常节点会周期恢复并重新接收流量' }}</span>
                </div>
              </el-form-item>

              <template v-if="wizardForm.enable_active_health_check">
                <el-form-item label="主动探测超时">
                  <el-input-number v-model="wizardForm.health_check_timeout" :min="RULE_NUMERIC_LIMITS.healthCheckTimeoutMin" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">秒，仅主动探测单次超时；被动熔断不使用该值</span>
                </el-form-item>
                <el-form-item label="检查端口">
                  <el-input-number v-model="wizardForm.tcp_health_check_port" :min="0" :max="65535" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">留空或 0 表示按各上游自身端口探测</span>
                </el-form-item>
                <el-form-item label="恢复阈值">
                  <el-input-number v-model="wizardForm.health_check_healthy_threshold" :min="1" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">次连续探测成功后恢复为健康</span>
                </el-form-item>
              </template>
            </template>
          </el-form>
        </div>

        <!-- Step 3: 自定义路由（仅 HTTP 且启用时显示） -->
        <div v-show="currentStep === WIZARD_STEP.CUSTOM_ROUTES" class="step-content">
          <PathRulesEditor v-if="showCustomRoutesStep" v-model="wizardForm.path_rules" />
        </div>

        <!-- Step 4: 高级选项 -->
        <div v-show="currentStep === WIZARD_STEP.ADVANCED" class="step-content">
          <el-form :model="wizardForm" label-width="130px" :disabled="saving">
            <template v-if="wizardForm.protocol === 'http'">
              <el-divider content-position="left" class="compact-divider">DNS 服务器</el-divider>

              <el-form-item label="启用 DNS">
                <div class="dynamic-dns-content">
                  <el-switch v-model="wizardForm.enable_dns_server" />
                  <span class="form-tip-inline">启用后，DNS 配置会在转发时生效</span>
                </div>
              </el-form-item>

              <template v-if="wizardForm.enable_dns_server">
                <el-form-item label="DNS 服务器">
                  <el-input v-model="wizardForm.dns_server" placeholder="8.8.8.8 或 8.8.8.8,1.1.1.1" style="width: 220px;" />
                  <span class="form-tip-inline">多个地址用逗号分隔，按顺序尝试</span>
                </el-form-item>
              </template>

              <el-divider content-position="left" class="compact-divider">压缩配置</el-divider>

              <el-form-item label="启用压缩">
                <div class="dynamic-dns-content">
                  <el-switch v-model="wizardForm.enable_compress" />
                  <span class="form-tip-inline">启用后，响应将被压缩传输以减少带宽</span>
                </div>
              </el-form-item>
              <el-form-item v-if="wizardForm.enable_compress" label="压缩方式">
                <el-radio-group v-model="compressType" aria-label="压缩方式">
                  <el-radio value="gzip">gzip</el-radio>
                  <el-radio value="zstd">zstd（更快、压缩比更高，需客户端支持）</el-radio>
                </el-radio-group>
              </el-form-item>

              <el-divider content-position="left" class="compact-divider">动态上游</el-divider>

              <el-form-item label="启用动态上游">
                <div class="dynamic-dns-content">
                  <el-switch v-model="wizardForm.dynamic_dns" @change="onDynamicDnsToggle" />
                  <span class="form-tip-inline">启用后，通过 DNS A/AAAA 记录动态发现上游 IP 变化（仅使用第一个上游条目）</span>
                </div>
              </el-form-item>

              <template v-if="wizardForm.dynamic_dns">
                <el-form-item label="协议栈">
                  <el-checkbox-group v-model="wizardForm.dns_family" style="width: 200px;" aria-label="协议栈">
                    <el-checkbox value="ipv4">IPv4</el-checkbox>
                    <el-checkbox value="ipv6">IPv6</el-checkbox>
                  </el-checkbox-group>
                </el-form-item>
              </template>

              <el-divider content-position="left" class="compact-divider">代理超时</el-divider>
              <ProxyTimeoutFields :value="wizardForm" inherit-label="全局" :field-overrides="proxyTimeoutFieldOverrides" @update="updateRuleProxyTimeout" />

              <!-- 上游兼容：通用强制 HTTP/1.1（https 上游禁 ALPN h2）；
                   NTLM 接管时由开关锁定为开，呈灰态 -->
              <el-divider content-position="left" class="compact-divider">上游兼容</el-divider>

              <el-form-item label="强制 HTTP/1.1">
                <div class="active-check-control">
                  <el-switch v-model="wizardForm.upstream_force_http1" :active-value="1" :inactive-value="0" :disabled="ntlmOn" />
                  <TakeoverBadge v-if="ntlmOn" />
                  <span class="form-tip-inline">后端不支持 HTTP/2 或使用 NTLM 认证时开启；仅对 https 上游生效</span>
                </div>
              </el-form-item>
            </template>

            <template v-if="wizardForm.protocol === 'http' || wizardForm.protocol === 'tcp'">
              <el-divider content-position="left" class="compact-divider">连接重试</el-divider>

              <el-form-item>
                <template #label>重试窗口
                </template>
                <el-input-number v-model="wizardForm.tcp_try_duration" :min="ntlmOn ? -1 : 0" :max="60000" controls-position="right" style="width: 120px;" :disabled="ntlmOn" />
                <span class="form-tip-inline"><TakeoverBadge v-if="ntlmOn" />{{ ntlmOn
                  ? '禁用重试（NTLM 模式锁定）'
                  : (wizardForm.protocol === 'tcp'
                      ? '毫秒，0 表示不重试；连接失败后在窗口期内尝试其他上游'
                      : '毫秒，0 = 默认 5 秒窗口；失败后在窗口期内尝试其他上游') }}</span>
              </el-form-item>

              <el-form-item label="重试间隔">
                <el-input-number v-model="wizardForm.tcp_try_interval" :min="(wizardForm.tcp_try_duration || 0) > 0 ? 1 : 0" :max="RULE_NUMERIC_LIMITS.tcpTryIntervalMax" controls-position="right" style="width: 120px;" :disabled="ntlmOn || (wizardForm.tcp_try_duration || 0) <= 0" />
                <span class="form-tip-inline"><TakeoverBadge v-if="ntlmOn" />{{ ntlmOn ? '重试已禁用，间隔不生效' : ((wizardForm.tcp_try_duration || 0) <= 0 ? '窗口未启用时间隔不生效' : '毫秒，每次重试间隔；窗口启用时必须 ≥1') }}</span>
              </el-form-item>

              <el-form-item v-if="wizardForm.protocol === 'tcp'" label="PROXY V2">
                <el-switch v-model="wizardForm.tcp_proxy_protocol" />
                <span class="form-tip-inline">开启后向上游发送 PROXY v2 协议头传递真实客户端 IP，需后端支持</span>
              </el-form-item>
            </template>

            <el-divider content-position="left" class="compact-divider">Caddy 全局覆盖</el-divider>

            <el-form-item label="请求体大小">
              <el-input-number v-model="wizardForm.request_body_max_size_mb" :min="0" :max="1024" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">MB，0 = 全局默认；最大 1024，限制单个请求体的最大大小</span>
            </el-form-item>

            <el-form-item label="Keepalive 超时">
              <!-- 不设上限：后端只拒绝负值（rules.go），带外合法值（API/MCP 写入 7200）
                   在编辑时不得被控件静默夹到 3600 —— 与 ProxyTimeoutFields 同口径。 -->
              <el-input-number v-model="wizardForm.upstream_keepalive_timeout" :min="0" controls-position="right" style="width: 120px;" :disabled="ntlmOn" />
              <span class="form-tip-inline"><TakeoverBadge v-if="ntlmOn" />{{ ntlmOn ? 'NTLM 模式锁定 300s（关闭后恢复全局继承）' : '秒，0 = 全局默认；与上游服务器长连接的空闲超时' }}</span>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 5: 预览保存 -->
        <div v-show="currentStep === WIZARD_STEP.PREVIEW" class="step-content">
          <el-descriptions title="配置预览" :column="1" border>
            <el-descriptions-item label="规则名称">{{ wizardForm.name }}</el-descriptions-item>
            <el-descriptions-item label="协议">
              <el-tag :type="wizardForm.protocol === 'tcp' ? 'warning' : (wizardForm.enable_tls ? 'success' : 'primary')">
                {{ wizardForm.protocol === 'tcp' ? 'TCP' : (wizardForm.enable_tls ? 'HTTPS' : 'HTTP') }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="域名" v-if="wizardForm.protocol === 'http'">{{ wizardForm.domain || '-' }}</el-descriptions-item>
            <el-descriptions-item label="监听端口">{{ wizardForm.listen_port }}</el-descriptions-item>
            <el-descriptions-item label="负载策略">{{ getStrategyLabel(wizardForm.strategy) }}</el-descriptions-item>
            <el-descriptions-item label="NTLM 兼容" v-if="wizardForm.protocol === 'http' && ntlmOn">
              开启（Cookie 会话保持 · 禁用重试 · 立即透传 · Keepalive 300s · 强制 HTTP/1.1 · 主动健康检查关闭）
            </el-descriptions-item>
            <!-- 健康检查行取自 utils/healthCheckSummary 单源：主动分支曾只打印
                 path/interval/timeout（HTTP）或探测端口（TCP），失败/恢复阈值只在
                 被动分支出现——预览自称配置核对面，改过的阈值必须同处可见。 -->
            <el-descriptions-item label="健康检查" v-if="wizardForm.protocol === 'http' || wizardForm.protocol === 'tcp'">
              {{ healthCheckSummary(wizardForm) }}
            </el-descriptions-item>
            <el-descriptions-item label="连接重试" v-if="wizardForm.protocol === 'http' || wizardForm.protocol === 'tcp'">
              <template v-if="(wizardForm.tcp_try_duration || 0) > 0">
                窗口 {{ wizardForm.tcp_try_duration || 0 }}ms / 间隔 {{ wizardForm.tcp_try_interval || 0 }}ms
              </template>
              <template v-else-if="(wizardForm.tcp_try_duration || 0) < 0">禁用重试（NTLM 模式）</template>
              <template v-else>{{ wizardForm.protocol === 'tcp' ? '禁用' : '默认 5s 窗口' }}</template>
            </el-descriptions-item>
            <!-- 访问日志与连接重试都是高级步可编辑项：预览自称配置核对面，
                 漏项会让误配置只能保存后从单规则配置查看器发现 -->
            <el-descriptions-item label="访问日志" v-if="wizardForm.protocol === 'http'">
              {{ wizardForm.log_enabled ? '开启' : '关闭' }}
            </el-descriptions-item>
            <!-- 高级步其余可编辑项同为「配置核对面」成员：口径取自单规则配置
                 查看器与代理超时字段单源（utils/proxyTimeouts.ts），预览不另造
                 第二份文案——漏项会让误配置只能保存后才发现。 -->
            <el-descriptions-item label="请求体大小">
              {{ (wizardForm.request_body_max_size_mb || 0) > 0 ? `${wizardForm.request_body_max_size_mb}MB` : '全局默认' }}
            </el-descriptions-item>
            <el-descriptions-item label="Keepalive 超时">
              {{ (wizardForm.upstream_keepalive_timeout || 0) > 0 ? `${wizardForm.upstream_keepalive_timeout}s` : '全局默认' }}
            </el-descriptions-item>
            <el-descriptions-item label="代理超时" v-if="wizardForm.protocol === 'http'">
              {{ proxyTimeoutSummary(wizardForm) }}
            </el-descriptions-item>
            <el-descriptions-item label="强制 HTTP/1.1" v-if="wizardForm.protocol === 'http'">
              {{ wizardForm.upstream_force_http1 ? '开启' : '关闭' }}
            </el-descriptions-item>
            <el-descriptions-item label="PROXY 协议 v2" v-if="wizardForm.protocol === 'tcp'">
              {{ wizardForm.tcp_proxy_protocol ? '启用' : '禁用' }}
            </el-descriptions-item>
            <el-descriptions-item label="DNS 服务器" v-if="wizardForm.protocol === 'http'">
              <template v-if="wizardForm.enable_dns_server">
                {{ wizardForm.dns_server || '默认' }}
              </template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="动态上游" v-if="wizardForm.protocol === 'http'">
              <template v-if="wizardForm.dynamic_dns">
                启用 (协议栈: {{ (() => { const families = wizardForm.dns_family || []; if (families.length === 2) return 'IPv4/IPv6'; if (families.includes('ipv4')) return 'IPv4'; if (families.includes('ipv6')) return 'IPv6'; return '无'; })() }})
              </template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="压缩" v-if="wizardForm.protocol === 'http'">
              {{ wizardForm.enable_compress ? compressType : '禁用' }}
            </el-descriptions-item>
            <el-descriptions-item label="自定义路由" v-if="wizardForm.protocol === 'http'">
              {{ customRoutesPreview() }}
            </el-descriptions-item>
            <el-descriptions-item label="TLS 证书" v-if="wizardForm.enable_tls">
              <div v-if="wizardForm.tls_source === 'acme_dns'">{{ certTypeLabels.auto }} ({{ caProviderLabel }})</div>
              <div v-else>
                <div>{{ certTypeLabels.manual }}</div>
                <div v-if="certInfo.valid">
                  <el-tag size="small" :type="certInfo.warning ? 'warning' : 'success'">{{ certInfo.domain }}</el-tag>
                  <span>过期: {{ certInfo.expiryDate }}</span>
                  <span v-if="certInfo.daysUntilExpiry <= 30" class="cert-expiry-warning">({{ certInfo.daysUntilExpiry }} 天后)</span>
                </div>
              </div>
            </el-descriptions-item>
            <el-descriptions-item label="HTTP 重定向" v-if="wizardForm.enable_tls">
              {{ wizardForm.tls_http_redirect ? '启用' : '禁用' }}
            </el-descriptions-item>
            <el-descriptions-item label="状态">
              <el-tag :type="wizardForm.enabled ? 'success' : 'info'">{{ wizardForm.enabled ? '启用' : '禁用' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="上游服务器" :span="1">
              <el-table :data="wizardForm.upstreams" size="small" border>
                <el-table-column prop="host" label="主机" />
                <el-table-column prop="port" label="端口" width="80" />
                <el-table-column prop="protocol" label="协议" width="80">
                  <template #default="{ row }">
                    {{ row.protocol || 'http' }}
                  </template>
                </el-table-column>
                <el-table-column label="权重" width="70">
                  <template #default="{ row }">{{ row.enabled ? `${weightPercent(wizardForm.upstreams, row)}%` : '禁用' }}</template>
                </el-table-column>
                <el-table-column prop="max_connections" :label="wizardForm.protocol === 'http' ? '最大请求数' : '最大连接'" width="100" />
                <el-table-column v-if="wizardForm.protocol === 'http'" label="回源域名" min-width="130">
                  <template #default="{ row }">{{ row.origin_domain || '-' }}</template>
                </el-table-column>
                <el-table-column prop="enabled" label="状态" width="70">
                  <template #default="{ row }">
                    {{ row.enabled ? '启用' : '禁用' }}
                  </template>
                </el-table-column>
              </el-table>
            </el-descriptions-item>
          </el-descriptions>
        </div>
      </div>

      <template #footer>
        <div class="wizard-footer">
          <el-button v-if="hasPreviousStep" :disabled="saving" @click="prevStep">
            <el-icon><ArrowLeft /></el-icon>上一步
          </el-button>
          <el-button v-if="hasNextStep" type="primary" :disabled="saving" @click="nextStep">
            下一步<el-icon><ArrowRight /></el-icon>
          </el-button>
          <el-button v-if="currentStep === WIZARD_STEP.PREVIEW" type="primary" :loading="saving" :disabled="tlsDetailError && wizardForm.tls_source === 'manual'" :title="tlsDetailError && wizardForm.tls_source === 'manual' ? '证书详情加载失败：请先在 TLS 步骤重新加载' : ''" @click="submitWizard">
            <span>保存规则</span><el-icon style="margin-left: 6px;"><Check /></el-icon>
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- View Config Dialog -->
    <el-dialog v-model="configDialogVisible" width="min(900px, 94vw)" top="5vh" :close-on-click-modal="true" @close="onConfigDialogClosed">
      <template #header>
        <DialogHeader :icon="Document" title="Caddy 配置"
          subtitle="单规则渲染产物的只读预览（规则信息 / JSON / Caddyfile）" />
      </template>
      <div v-if="configLoading" v-loading="configLoading" style="min-height: 200px;"></div>
      <el-result v-else-if="configLoadError" icon="error" title="Caddy 配置加载失败" :sub-title="configLoadError">
        <template #extra><el-button type="primary" @click="retryViewConfig">重试</el-button></template>
      </el-result>
      <div v-else-if="ruleConfig" class="config-view">
        <section class="dialog-panel">
          <DialogSectionHeader title="规则信息" />
        <el-descriptions :column="2" border size="small" class="config-info">
          <el-descriptions-item label="规则ID">{{ ruleConfig.caddy_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="规则名称">{{ ruleConfig.name }}</el-descriptions-item>
          <el-descriptions-item label="域名">{{ ruleConfig.domain || '-' }}</el-descriptions-item>
          <el-descriptions-item label="端口">{{ ruleConfig.listen_port }}</el-descriptions-item>
          <el-descriptions-item label="协议">
            <el-tag :type="ruleConfig.protocol === 'tcp' ? 'warning' : (ruleConfig.enable_tls ? 'success' : 'primary')" size="small">
              {{ ruleConfig.protocol === 'tcp' ? 'TCP' : (ruleConfig.enable_tls ? 'HTTPS' : 'HTTP') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="负载策略">{{ getStrategyLabel(ruleConfig.strategy) }}</el-descriptions-item>
          <el-descriptions-item label="动态上游">{{ ruleConfig.dynamic_dns ? '启用' : '禁用' }}</el-descriptions-item>
          <el-descriptions-item label="DNS 服务器" v-if="ruleConfig.protocol === 'http'">
            {{ ruleConfig.enable_dns_server ? (ruleConfig.dns_server || '未配置') : '禁用' }}
          </el-descriptions-item>
          <el-descriptions-item label="后端域名" v-if="ruleConfig.protocol === 'http'">{{ ruleConfig.host_header || '-' }}</el-descriptions-item>
          <el-descriptions-item label="TLS" v-if="ruleConfig.enable_tls">
            {{ ruleConfig.tls_http_redirect ? '启用 (HTTP重定向)' : '启用' }}
            <span v-if="ruleConfig.tls_source === 'manual'">(手动上传)</span>
            <span v-else-if="ruleConfig.tls_source === 'acme_dns'">(ACME 自动)</span>
          </el-descriptions-item>
          <el-descriptions-item label="TLS" v-else>禁用</el-descriptions-item>
          <el-descriptions-item label="压缩" v-if="ruleConfig.protocol === 'http'">
            {{ ruleConfig.enable_compress ? (Array.isArray(ruleConfig.compress_types) ? ruleConfig.compress_types[0] : (ruleConfig.compress_types || 'gzip')) : '禁用' }}
          </el-descriptions-item>
          <!-- 与向导预览同一份摘要单源（utils/healthCheckSummary）：主动行同样点名
               失败/恢复阈值，被动行只在未启用主动探测时补位。 -->
          <el-descriptions-item label="主动健康检查" v-if="ruleConfig.enable_active_health_check">
            {{ activeHealthCheckSummary(ruleConfig) }}
          </el-descriptions-item>
          <el-descriptions-item label="主动健康检查" v-else>未启用</el-descriptions-item>
          <el-descriptions-item label="被动健康检查" v-if="!ruleConfig.enable_active_health_check">
            {{ passiveHealthCheckSummary(ruleConfig) }}
          </el-descriptions-item>
          <el-descriptions-item label="连接重试" v-if="ruleConfig.protocol === 'http' || ruleConfig.protocol === 'tcp'">
            <template v-if="ruleConfig.tcp_try_duration > 0">
              窗口 {{ ruleConfig.tcp_try_duration }}ms / 间隔 {{ ruleConfig.tcp_try_interval }}ms
            </template>
            <template v-else-if="ruleConfig.tcp_try_duration === -1">禁用重试（NTLM 模式）</template>
            <template v-else>{{ ruleConfig.protocol === 'tcp' ? '禁用' : '默认 5s 窗口' }}</template>
          </el-descriptions-item>
          <el-descriptions-item label="请求体大小">{{ (ruleConfig.request_body_max_size_mb || 0) > 0 ? ruleConfig.request_body_max_size_mb + 'MB' : '全局默认' }}</el-descriptions-item>
            <el-descriptions-item label="Keepalive 超时">{{ (ruleConfig.upstream_keepalive_timeout || 0) > 0 ? ruleConfig.upstream_keepalive_timeout + 's' : '全局默认' }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="ruleConfig.enabled ? 'success' : 'info'" size="small">{{ ruleConfig.enabled ? '启用' : '禁用' }}</el-tag>
          </el-descriptions-item>
        </el-descriptions>
        </section>

        <section class="dialog-panel">
          <DialogSectionHeader title="上游服务器" />
        <el-table :data="ruleConfig.upstreams" size="small" border v-if="ruleConfig.upstreams?.length">
          <el-table-column prop="host" label="主机地址" />
          <el-table-column prop="port" label="端口" align="center" />
          <el-table-column prop="protocol" label="协议" align="center">
            <template #default="{ row }">
              <el-tag size="small" :type="row.protocol === 'https' ? 'warning' : 'primary'">{{ row.protocol || 'http' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="权重" align="center">
            <template #default="{ row }">{{ weightPercent(ruleConfig?.upstreams, row) }}%</template>
          </el-table-column>
          <el-table-column prop="max_connections" :label="ruleConfig?.protocol === 'http' ? '最大请求数' : '最大连接'" align="center" />
          <el-table-column v-if="ruleConfig?.protocol === 'http'" label="回源域名" align="center">
            <template #default="{ row }">{{ row.origin_domain || '-' }}</template>
          </el-table-column>
          <el-table-column prop="enabled" label="状态" align="center">
            <template #default="{ row }">
              <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        </section>

        <section class="dialog-panel">
          <DialogSectionHeader title="Caddy 配置（JSON）" />
          <el-empty v-if="ruleConfig.config_not_exists" description="配置不存在" :image-size="60" />
          <SyntaxHighlight v-else :content="JSON.stringify(ruleConfig.config, null, 2)" language="json" />
        </section>
      </div>
      <div v-else class="config-empty">
        <el-empty description="未找到该规则的配置信息" :image-size="60" />
      </div>
    </el-dialog>

    <el-dialog
      v-model="ruleLogDialogVisible"
      width="min(1100px, 94vw)"
      top="5vh"
      destroy-on-close
      @opened="onRuleLogDialogOpened"
      @close="onRuleLogDialogClosed"
    >
      <template #header>
        <DialogHeader :icon="Tickets" :title="`访问日志 - ${ruleLogRuleName}`" subtitle="负载均衡规则请求访问日志" />
      </template>
      <div class="log-toolbar">
        <el-switch v-model="ruleLogAutoRefresh" active-text="自动刷新" />
        <el-button type="primary" :loading="ruleLogLoading" size="small" @click="refreshRuleLogs">
          <el-icon><RefreshRight /></el-icon>刷新
        </el-button>
      </div>
      <el-tabs v-model="ruleLogTab" @tab-change="onRuleLogTabChange">
        <el-tab-pane label="日志" name="log">
          <div ref="ruleLogContainerRef" class="dialog-panel rule-log-viewer" v-html="ruleLogHtml" />
        </el-tab-pane>
        <el-tab-pane label="统计" name="stats">
          <div v-if="ruleLogStatsLoading || (!ruleLogStats && !ruleLogStatsError)" class="stats-state" aria-live="polite">
            <el-text type="info">正在统计日志...</el-text>
            <el-skeleton :rows="6" animated />
          </div>
          <el-result
            v-else-if="ruleLogStatsError"
            icon="error"
            title="日志统计加载失败"
            :sub-title="ruleLogStatsError"
          >
            <template #extra>
              <el-button type="primary" @click="startLogStats">重试</el-button>
            </template>
          </el-result>
          <template v-else-if="ruleLogStats">
            <div class="stats-summary">
              <el-tag size="small" type="info" effect="plain">共 {{ ruleLogStats.total }} 次请求</el-tag>
              <el-text type="info" size="small" style="margin-left: 8px;">含最近 ≤1000 行日志（自 {{ ruleLogStats.started_at }}）· 每 5 秒实时叠加</el-text>
            </div>
            <div class="stats-grid">
              <section class="dialog-panel stats-card">
                <DialogSectionHeader title="IP TOP" />
                <el-table :data="ruleLogStats.top_ips" size="small" :show-header="false">
                  <el-table-column prop="value" show-overflow-tooltip />
                  <el-table-column prop="count" width="70" align="right">
                    <template #default="{ row }"><span class="stats-count">{{ row.count }}</span></template>
                  </el-table-column>
                  <template #empty><el-empty description="暂无数据" :image-size="40" /></template>
                </el-table>
              </section>
              <section class="dialog-panel stats-card">
                <DialogSectionHeader title="客户端 TOP" />
                <el-table :data="ruleLogStats.top_uas" size="small" :show-header="false">
                  <el-table-column prop="value" show-overflow-tooltip />
                  <el-table-column prop="count" width="70" align="right">
                    <template #default="{ row }"><span class="stats-count">{{ row.count }}</span></template>
                  </el-table-column>
                  <template #empty><el-empty description="暂无数据" :image-size="40" /></template>
                </el-table>
              </section>
              <section class="dialog-panel stats-card">
                <DialogSectionHeader title="URI TOP" />
                <el-table :data="ruleLogStats.top_uris" size="small" :show-header="false">
                  <el-table-column prop="value" show-overflow-tooltip />
                  <el-table-column prop="count" width="70" align="right">
                    <template #default="{ row }"><span class="stats-count">{{ row.count }}</span></template>
                  </el-table-column>
                  <template #empty><el-empty description="暂无数据" :image-size="40" /></template>
                </el-table>
              </section>
            </div>
          </template>
        </el-tab-pane>
      </el-tabs>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="rule_access" :caddy-id="ruleLogCaddyId" style="margin-right: auto" />
          <el-button @click="ruleLogDialogVisible = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>

    <!-- NTLM 开关确认（参照更新迁移预演范式）：开启=接管清单确认；关闭=恢复默认告知 -->
    <el-dialog v-model="ntlmConfirmVisible" class="dialog-body-inset" width="min(560px, 94vw)" top="10vh" :close-on-click-modal="false">
      <template #header>
        <DialogHeader :icon="ntlmConfirmMode === 'on' ? WarningFilled : CircleCheckFilled"
          :title="ntlmConfirmMode === 'on' ? '开启 NTLM 兼容' : 'NTLM 兼容已关闭'"
          :subtitle="ntlmConfirmMode === 'on' ? '为 NTLM / 协商认证后端锁定长连接亲和的代理形态' : '已恢复默认配置'" />
      </template>
      <div v-if="ntlmConfirmMode === 'on'" class="ntlm-confirm-body">
        <div class="ntlm-confirm-title">开启后将接管以下配置：</div>
        <ul class="ntlm-confirm-list">
          <li>负载策略锁定为 <b>Cookie 会话保持</b></li>
          <li>禁用请求重试</li>
          <li>响应立即透传</li>
          <li>上游连接保持 300s + 强制 HTTP/1.1</li>
          <li>主动健康检查关闭（探测返回 401 会被误判摘除；被动健康检查仍在役）</li>
        </ul>
        <div class="info-note-bar"><span class="info-note-desc">原配置不保留记忆，关闭时恢复默认</span></div>
      </div>
      <div v-else class="ntlm-confirm-body">
        <ul class="ntlm-confirm-list">
          <li>负载策略解锁为轮询</li>
          <li>重试窗口恢复 5s 默认</li>
          <li>透传 / Keepalive / HTTP 版本恢复全局继承</li>
          <li>主动健康检查保持关闭，可按需重新开启</li>
        </ul>
      </div>
      <template #footer>
        <el-button v-if="ntlmConfirmMode === 'on'" @click="ntlmConfirmVisible = false">取消</el-button>
        <el-button v-if="ntlmConfirmMode === 'on'" type="warning" @click="confirmNtlmToggle">开启</el-button>
        <el-button v-else type="primary" @click="confirmNtlmToggle">确认关闭</el-button>
      </template>
    </el-dialog>
    <SecurityBindingEditor
      v-model="bindDialogVisible"
      mode="rule"
      :rule="bindDialogRule"
      :policies="securityPolicies"
      :bindings="securityBindings"
      :rules="rules"
      :block-pages="blockPages"
      @saved="fetchSecurityBindings"
    />

    <RuleFlowDialog v-model="flowDialogVisible" :target="flowDialogTarget" :model="flowDialogModel" :policies="securityPolicies" :ip-lists="ipLists" />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, computed, watch, h } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request, mfaAwareSuccess, ApiRequestError } from '@/utils/api'
import { Plus, Operation, Delete, InfoFilled, Lock, Connection, Guide, Check, ArrowLeft, ArrowRight, Document, CircleCheckFilled, CircleCloseFilled, Setting, RefreshRight, Search, WarningFilled, Location, Link, Tickets } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
import FieldHelpIcon from '@/components/common/FieldHelpIcon.vue'
import TakeoverBadge from '@/components/common/TakeoverBadge.vue'
import { ElMessageBox, ElMessage } from 'element-plus'
import axios from 'axios'
import { ansiToHtml } from '@/utils/ansi'
import { useLogTailPolling } from '@/composables/useLogTailPolling'
import { updaterName } from '@/utils/updaterName'
import { DEEP_LINK_PARAMS } from '@/utils/deepLink'
import { formatDate, parseDbTimeMs } from '@/utils/date'
import LogStorageBar from '@/components/LogStorageBar.vue'
import RuleFlowDialog from '@/components/RuleFlowDialog.vue'
import SecurityBindingEditor from '@/components/SecurityBindingEditor.vue'
import { buildStageModel } from '@/utils/securityStages'
import type {
  RuleFlowTarget,
  RuleStageModel,
  SecurityStageBinding,
  SecurityStageBlockPage,
  SecurityStageIPList,
  SecurityStagePolicy,
} from '@/utils/securityStages'
import type {
  APIResponse,
  CertJobListItem,
  CreateRuleRequest,
  PathRule,
  ProxyTimeoutConfig,
  PathRuleUpstream,
  Rule,
  RuleProtocol,
  UpdateRuleRequest,
  Upstream,
  UpstreamInput,
  UpstreamProtocol,
  UserListItem,
} from '@/types'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import PathRulesEditor from '@/components/rules/PathRulesEditor.vue'
import ProxyTimeoutFields from '@/components/rules/ProxyTimeoutFields.vue'
import { proxyTimeoutSummary } from '@/utils/proxyTimeouts'
import { activeHealthCheckSummary, healthCheckSummary, passiveHealthCheckSummary } from '@/utils/healthCheckSummary'
import { activateOnce } from '@/utils/keyboardActivate'
import { nextRadioValue, rovingTabindex } from '@/utils/rovingRadio'
import { isValidHostName, validatePathRules, RULE_NUMERIC_LIMITS } from '@/utils/ruleValidation'
import { getStrategyLabel, strategyCardsForProtocol, strategyValuesForProtocol } from '@/utils/strategyLabels'
import { selectableReferencedOptions, referencedOptionLabel } from '@/utils/caProviderOptions'
import { popperViewportSafe } from '@/utils/popper'
import { hostPortKey, upstreamDedupeKey } from '@/utils/upstreamKeys'
import { MAX_UPSTREAM_ROWS, normalizeWeights, payloadWeight, redistributeWeight, weightPercent } from '@/utils/upstreamWeights'
import { projectRuleFlowPath } from '@/utils/ruleFlow'
import { clampPassiveHealthCheckTimeout, copyRuleHostHeader, dnsServerAfterToggle, newRuleWizardStageOverrides, stageBlockPageOverrides, stageBlockPagePatch } from '@/utils/ruleWizard'
import { createLogStatBuckets, recordLogStatEntry, type LogStatBuckets } from '@/utils/logStatCap'
import { certJobStatusLabel } from '@/utils/certJobStatus'
import type { CertJobStatus } from '@/utils/certJobStatus'
import { usePollingTask } from '@/composables/usePollingTask'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { usePollingErrorState } from '@/composables/usePollingErrorState'

interface RuleForm extends Omit<CreateRuleRequest, 'dns_family' | 'upstreams' | 'acme_config_id' | 'ca_provider_id' | 'compress_types' | 'host_header'> {
  dns_family: string[]
  upstreams: UpstreamInput[]
  acme_config_id?: number
  ca_provider_id?: number
  compress_types: string[]
  enabled: boolean
  // 编辑手动证书规则时 GetRule 回传的「私钥已隐藏」标记
  tlsKeySet: boolean
}

interface CertificateConfig {
  id: number
  name: string
  dns_provider: string
  dns_credentials: string
  enabled: boolean
  created_at: string
  updated_at: Rule['updated_at']
}

interface CAProvider {
  id: number
  name: string
  provider: string
  directory_url: string
  credentials?: string
  max_concurrent: number
  min_interval_ms: number
  enabled: boolean
  created_at: string
  updated_at: string
}

interface UpstreamHealthDetail {
  healthy: boolean
  unknown: boolean
  dynamic?: boolean
  degraded: boolean
  num_requests: number
  fails: number
}

type UpstreamHealthResponse = Record<string, Record<string, UpstreamHealthDetail>>

interface CertificateParseResult {
  valid: boolean
  domain: string
  issuer: string
  not_before: string
  not_after: string
  days_until_expiry: number
  warning?: string
  error?: string
}

interface RuleCaddyConfigResponse {
  caddy_id: string
  enabled: boolean
  config?: object | null
  config_not_exists?: boolean
}

interface RuleConfigView {
  host_header: string
  id: number
  caddy_id: string
  name: string
  domain: string
  listen_port: number
  protocol: RuleProtocol
  strategy: string
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  health_check_host: string
  enable_tls: boolean
  tls_source: string
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string[]
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_healthy_threshold: number
  health_check_unhealthy_threshold: number
  enable_active_health_check: boolean
  tcp_health_check_port: number
  tcp_try_duration: number
  tcp_try_interval: number
  request_body_max_size_mb: number
  upstream_keepalive_timeout: number
  server_tokens_hidden: number
  upstreams: Upstream[]
  enabled: boolean
  config: object | null
  config_not_exists: boolean
}

interface RuleLogData {
  content: string
  offset: number
}

interface RuleLogStreamData {
  offset: number
  lines: string[]
}

interface CaddyLogRequest {
  client_ip?: string
  src_ip?: string
  src?: string
  remote_ip?: string
  uri?: string
  uri_path?: string
  user_agent?: string
  headers?: Record<string, string[] | undefined>
}

interface CaddyLogEntry {
  request?: CaddyLogRequest
}

interface LogStatItem {
  value: string
  count: number
}

interface RuleLogStats {
  total: number
  started_at: string
  top_ips: LogStatItem[]
  top_uas: LogStatItem[]
  top_uris: LogStatItem[]
}

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
// 只读原因文案（从节点只读/非管理员只读/加载中）——操作列禁用 tooltip 统一口径
const readOnlyMessage = computed(() => authStore.readOnlyMessage)
let disposed = false

const certTypeLabels = {
  auto: 'ACME 自动证书',
  manual: '手动证书',
}

const caProviderLabel = computed(() => {
  const id = wizardForm.ca_provider_id
  if (id === undefined || id === null || id === 0) return '系统默认'
  return caProviders.value.find(p => p.id === id)?.name || '未知 CA'
})

interface CertInfo {
  caddy_id: string
  source: string
  domains: string
  issuer: string
  not_before: string
  not_after: string
  days_remaining: number
  status: string
  error?: string
}

// 证书任务精简视图：types/index.ts CertJobListItem（后端 certJobListItem 投影
// 单源）的 Pick 子集——后端字段增改时只动一处。
type CertJob = Pick<CertJobListItem, 'id' | 'rule_id' | 'domain' | 'status' | 'message' | 'expires_at' | 'ca_available_after'>

class CertInfoRefreshError extends Error {
  readonly name = 'CertInfoRefreshError'

  constructor() {
    super('证书任务已更新，但证书详情刷新失败')
  }
}

const rules = ref<Rule[]>([])
// v2.2.0：一规则可绑多策略——/security/bindings 返回 rule_caddy_id → 绑定数组（policy_id ASC）。

const securityBindings = ref<Record<string, SecurityStageBinding[]>>({})
// 策略摘要 / IP 名单 / 拦截页类型与投影模型统一定义在 utils/securityStages.ts——
// 锁弹框、向导安全步骤、流程抽屉三处共用同一数据源，禁止在本文件另起第二份口径。
const securityPolicies = ref<SecurityStagePolicy[]>([])
const ipLists = ref<SecurityStageIPList[]>([])
const blockPages = ref<SecurityStageBlockPage[]>([])

const rulesLoadError = ref(false)
const securityBindingsError = ref(false)
// 绑定数据未就绪时禁止打开编辑器：组件预选空集 + 全量替换语义会把
// 「加载失败/未完成」保存成「解除全部绑定」。
const securityBindingsLoading = ref(true)
const fetchSecurityBindings = async (includeSecurityCatalog = false) => {
  securityBindingsLoading.value = true
  try {
    const [bindingsRes, policiesRes, ipListRes, blockPagesRes] = await Promise.all([
      request.get<APIResponse<typeof securityBindings.value>>('/security/bindings'),
      includeSecurityCatalog ? request.get<APIResponse<SecurityStagePolicy[]>>('/security/policies') : Promise.resolve(null),
      includeSecurityCatalog ? request.get<APIResponse<SecurityStageIPList[]>>('/security/ip-lists') : Promise.resolve(null),
      includeSecurityCatalog ? request.get<APIResponse<SecurityStageBlockPage[]>>('/security/block-pages') : Promise.resolve(null),
    ])
    if (bindingsRes.data) securityBindings.value = bindingsRes.data
    if (policiesRes?.data) securityPolicies.value = policiesRes.data
    if (ipListRes?.data) ipLists.value = ipListRes.data
    if (blockPagesRes?.data) blockPages.value = blockPagesRes.data
    securityBindingsError.value = false
  } catch {
    // 首屏/显式重试时任一安全端点失败都必须显性化：保持的数据可能为空，
    // 静默会把加载失败伪装成「未绑定」。常规规则写后只刷新 bindings，不再
    // 重拉与本次写无关的策略、名单和拦截页目录。
    securityBindingsError.value = true
  } finally {
    securityBindingsLoading.value = false
  }
}
const retrySecurityBindings = (): void => { void fetchSecurityBindings(true) }

// 锁摘要 popover 实例登记（el-popover 组件公开 hide() 方法，其实例类型未导出——
// 命名校验后落登记表；跳转流程弹框前显式关闭，防 popover 残留遮挡）
const lockPopovers: Record<string, { hide: () => void }> = {}
const setLockPopover = (caddyId: string, el: unknown): void => {
  if (el && typeof el === 'object' && 'hide' in el && typeof (el as { hide: unknown }).hide === 'function') {
    lockPopovers[caddyId] = el as { hide: () => void }
  } else delete lockPopovers[caddyId]
}

// 历史（用户反馈）：表格 hover 弹框（锁摘要/TLS/健康）在靠底或靠顶行会被视口裁切
// popperViewportSafe 已提取至 utils/popper 共享（/5 家族：四处弹框统一
// 视口安全回退——flip 多向回退含水平 + preventOverflow padding 8）。
// 弹框内容超高时由 .rule-lock-popper 的 max-height + overflow-y 内部滚动承接。
const openFlowFromLock = (rule: Rule): void => {
  lockPopovers[rule.caddy_id]?.hide()
  openFlowDialog(rule)
}

const ruleStageModel = (rule: Rule): RuleStageModel =>
  ruleStageModelMap.value.get(rule.caddy_id) ?? buildStageModel([], securityPolicies.value, ipLists.value, blockPages.value, rule, rule.enabled)

const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const filteredRules = computed(() => {
  const query = searchQuery.value.trim().toLowerCase()
  const base = query
    ? rules.value.filter((rule) => {
        const name = (rule.name || '').toLowerCase()
        const domain = (rule.domain || '').toLowerCase()
        const port = String(rule.listen_port || '')
        const caddyId = (rule.caddy_id || '').toLowerCase()
        return name.includes(query) || domain.includes(query) || port.includes(query) || caddyId.includes(query)
      })
    : rules.value
  return [...base].sort((a, b) => ruleUpdatedAtMs(b) - ruleUpdatedAtMs(a))
})


// 墙钟串统一经 parseDbTimeMs 的 +Z 规范化——裸 new Date 在 Safari 对
// 空格分隔格式返回 NaN，曾致排序比较恒 0 退化。
const ruleUpdatedAtMs = (rule: Rule): number => parseDbTimeMs(rule.updated_at) ?? 0

// 分页夹紧+切片：useClampedPagination 单一范式
const { pagedItems: pagedRules } = useClampedPagination(filteredRules, currentPage, pageSize)

watch(searchQuery, () => {
  currentPage.value = 1
})

// 每条规则的四阶段分组投影缓存（规则/绑定/策略/名单/拦截页任一变化即整体重算）。
// 只投影当前页可见规则（原实现对全部规则重算，绑定/策略/名单任一
// 变化即 O(R×阶段数) 全量重建）。流程弹框的目标行恒来自表格行；非可见行经
// ruleStageModel 的兜底分支即时构建。
const ruleStageModelMap = computed<Map<string, RuleStageModel>>(() => {
  const map = new Map<string, RuleStageModel>()
  for (const rule of pagedRules.value) {
    map.set(rule.caddy_id, buildStageModel(
      securityBindings.value[rule.caddy_id] || [],
      securityPolicies.value,
      ipLists.value,
      blockPages.value,
      rule,
      rule.enabled,
    ))
  }
  return map
})



const users = ref<UserListItem[]>([])
const certInfoMap = ref<Record<string, CertInfo | null>>({})
// 证书详情加载失败显性化——原实现仅 console，TLS 列回落「未签发/手动」
// 且页面无任何提示（与同页证书任务轮询的错误横幅不一致）。
const certInfoError = ref(false)
const certJobMap = ref<Record<string, CertJob>>({})
const pendingCertInfoRefresh = new Set<string>()
const ruleTogglePending = ref<Record<string, boolean>>({})
const certInfoGenerations = new Map<string, number>()
let certInfoGeneration = 0
let rulesRequestSeq = 0

// 更新者显示名走 utils/updaterName 单源
const getUpdaterName = (userId?: number) => updaterName(users.value, userId)

const fetchRules = async (includeSecurityCatalog = false) => {
  if (disposed) return
  const requestSeq = ++rulesRequestSeq
  loading.value = true
  try {
    const res = await request.get<APIResponse<Rule[]>>('/rules', { signal: healthPolling.signal })
    if (disposed || requestSeq !== rulesRequestSeq) return
    rules.value = res.data || []
    rulesLoadError.value = false
    void fetchSecurityBindings(includeSecurityCatalog)
    // Fetch health status after rules are loaded
    void healthPolling.run()
    // Fetch certificate info for TLS-enabled rules
    void fetchCertInfo()
    // Fetch cert job statuses for ACME rules
    void certJobsPolling.run()
  } catch (error: unknown) {
    if (axios.isCancel(error) || disposed || requestSeq !== rulesRequestSeq) return
    // Error toast is already shown by the global axios interceptor; swallow here
    // so fire-and-forget refresh calls don't surface as unhandled rejections.
    console.error('Failed to fetch rules:', error)
    rulesLoadError.value = true
  } finally {
    if (!disposed && requestSeq === rulesRequestSeq) loading.value = false
  }
}

const fetchCertInfo = async (caddyIds?: readonly string[]): Promise<boolean> => {
  if (disposed) return false
  const requestedIds = caddyIds ? new Set(caddyIds) : null
  const tlsRules = rules.value.filter(r => r.enable_tls && (!requestedIds || requestedIds.has(r.caddy_id)))
  const targetIds = tlsRules.map(r => r.caddy_id)
  const targetIdSet = new Set(targetIds)
  const generation = ++certInfoGeneration
  if (!requestedIds) {
    for (const id of certInfoGenerations.keys()) {
      if (!targetIdSet.has(id)) certInfoGenerations.delete(id)
    }
  }
  const generationIds = requestedIds ? [...requestedIds] : targetIds
  generationIds.forEach(id => certInfoGenerations.set(id, generation))
  if (!requestedIds) {
    certInfoMap.value = Object.fromEntries(Object.entries(certInfoMap.value).filter(([id]) => targetIdSet.has(id)))
  } else {
    requestedIds.forEach(id => {
      if (!targetIdSet.has(id)) delete certInfoMap.value[id]
    })
  }
  if (tlsRules.length === 0) {
    certInfoError.value = false
    return true
  }
  try {
    const certInfo: Record<string, CertInfo | null> = {}
    for (let index = 0; index < targetIds.length; index += 200) {
      const batchIds = targetIds.slice(index, index + 200)
      const res = await request.post<APIResponse<Record<string, CertInfo | null>>>('/rules/cert-info', {
        caddy_ids: batchIds,
      }, { signal: healthPolling.signal })
      if (disposed) return false
      Object.assign(certInfo, res.data || {})
    }
    if (disposed) return false
    const patch: Record<string, CertInfo | null> = {}
    targetIds.forEach(id => {
      if (certInfoGenerations.get(id) === generation) patch[id] = certInfo[id] ?? null
    })
    certInfoMap.value = { ...certInfoMap.value, ...patch }
    certInfoError.value = false
    return true
  } catch (error: unknown) {
    if (!axios.isCancel(error) && !disposed && generation === certInfoGeneration) {
      console.error('Failed to fetch certificate info:', error)
      certInfoError.value = true
    }
    return false
  }
}

// 证书详情重试入口（横幅按钮）——重试全量 TLS 规则详情。
const certInfoRetryLoading = ref(false)
const retryCertInfo = async (): Promise<void> => {
  if (certInfoRetryLoading.value) return
  certInfoRetryLoading.value = true
  try {
    await fetchCertInfo()
  } finally {
    certInfoRetryLoading.value = false
  }
}

const fetchCertJobs = async (roundSignal?: AbortSignal): Promise<void> => {
  if (disposed) return
  const requestedRuleIds = pagedRules.value.map((rule) => rule.caddy_id)
  const requestedRuleIdSet = new Set(requestedRuleIds)
  const res = await request.post<APIResponse<Record<string, CertJob | null>>>('/certificates/jobs/current', {
    rule_ids: requestedRuleIds,
  }, { signal: roundSignal ?? certJobsPolling.signal, silent: true })
  if (!res.data) throw new TypeError('当前证书任务响应缺少 data')
  if (disposed) return
  const nextMap = { ...certJobMap.value }
  requestedRuleIds.forEach((ruleId) => delete nextMap[ruleId])
  Object.entries(res.data).forEach(([ruleId, job]) => {
    if (job === null) return
    if (!requestedRuleIdSet.has(ruleId) || job.rule_id !== ruleId) {
      throw new TypeError(`当前证书任务响应包含未请求的规则 ${ruleId}`)
    }
    nextMap[ruleId] = job
  })
  const newlyIssuedRuleIds = Object.entries(res.data)
    .filter(([ruleId, job]) => {
      if (job === null) return false
      const previousStatus = certJobMap.value[ruleId]?.status
      return previousStatus !== undefined && previousStatus !== 'issued' && job.status === 'issued'
    })
    .map(([ruleId]) => ruleId)
  if (disposed) return
  certJobMap.value = nextMap
  newlyIssuedRuleIds.forEach((ruleId) => pendingCertInfoRefresh.add(ruleId))
  if (pendingCertInfoRefresh.size === 0) return
  const refreshRuleIds = [...pendingCertInfoRefresh]
  const refreshed = await fetchCertInfo(refreshRuleIds)
  if (!refreshed && !disposed) throw new CertInfoRefreshError()
  if (refreshed) refreshRuleIds.forEach((ruleId) => pendingCertInfoRefresh.delete(ruleId))
}

// （用户裁定，对齐后端 HasRunningJobForRule）：waiting_ca（CA 限流冷却）不算
// 活动态——不阻塞规则启停与删除；downloaded（部署退避窗）仍按活动态保留。
const isCertJobActive = (status?: CertJobStatus) => {
  if (!status) return false
  return !['issued', 'failed', 'disabled', 'waiting_ca'].includes(status)
}

// 编辑锁与后端 ruleEditBlockingCertJobStatuses 同口径：只有 worker 真正在跑的
// 状态阻止编辑。waiting_ca（CA 限流冷却 1–3h，无 worker）与 downloaded（部署
// 退避重试，无 worker）不阻断——此前一律锁定，冷却期内连改名称/上游都 409，
// 与删除/禁用口径矛盾；改域风险由后端提交后迁移与退役补偿覆盖。
const isCertJobEditLocked = (status?: CertJobStatus) => {
  if (!status) return false
  return !['issued', 'failed', 'disabled', 'waiting_ca', 'downloaded'].includes(status)
}

const certJobStatusOf = (row: Rule): CertJobStatus | undefined =>
  certJobMap.value[row.caddy_id]?.status

// 冷却/退避期不锁编辑：文案点名「签发在后台重试，编辑不受限」，
// 避免旧文案（「证书申请中…」「编辑暂锁定」）误报必败提交。
const certJobLockTooltip = (row: Rule, activeText: string): string => {
  if (isReadOnly.value) return authStore.readOnlyMessage
  const status = certJobStatusOf(row)
  if (status === 'waiting_ca') {
    return 'CA 限流冷却中，不阻塞规则启停、删除与编辑（后台稍后重试签发）'
  }
  if (status === 'downloaded') {
    return '证书已签发、部署退避重试中，不阻塞编辑；启停/删除待部署收敛'
  }
  return activeText
}

const canEditRule = (row: Rule) => {
  if (isReadOnly.value) return false
  if (row.tls_source === 'acme_dns' && isCertJobEditLocked(certJobMap.value[row.caddy_id]?.status)) {
    return false
  }
  return true
}

const canDeleteRule = (row: Rule) => {
  if (isReadOnly.value) return false
  if (row.tls_source === 'acme_dns' && isCertJobActive(certJobMap.value[row.caddy_id]?.status)) {
    return false
  }
  return true
}

const tlsTagType = (row: Rule) => {
  const cert = certInfoMap.value[row.caddy_id]
  // 详情加载失败且无缓存 → danger（不得回落为「未签发/手动」正常态）
  if (certInfoError.value && cert === undefined) return 'danger'
  const jobStatus = certJobMap.value[row.caddy_id]?.status
  // 重新签发进行中（含切换 CA）优先呈现活动态——在役证书 valid 不再抢先显示
  //「已签发」（用户报告：签发任务执行中标签无变化）。
  if (row.tls_source === 'acme_dns' && jobStatus && (isCertJobActive(jobStatus) || jobStatus === 'waiting_ca')) return 'warning'
  if (cert?.status === 'expired') return 'danger'
  if (cert?.status === 'expiring') return 'warning'
  if (cert?.status === 'valid') return 'success'
  if (row.tls_source === 'acme_dns') {
    if (jobStatus === 'issued') return 'success'
    if (jobStatus === 'failed') return 'danger'
    if (jobStatus === 'disabled') return 'info'
    if (jobStatus) return 'warning'
    return 'info'
  }
  return 'primary'
}

const tlsTagLabel = (row: Rule) => {
  const cert = certInfoMap.value[row.caddy_id]
  if (certInfoError.value && cert === undefined) return '加载失败'
  const jobStatus = certJobMap.value[row.caddy_id]?.status
  // 活动签发态（含限流冷却）优先用任务阶段性短标签（certJobStatusLabel 2-4 字，
  // 适配 106px 列宽）——重新签发/切 CA 期间每个阶段实时可见。
  if (row.tls_source === 'acme_dns' && jobStatus && (isCertJobActive(jobStatus) || jobStatus === 'waiting_ca')) {
    return certJobStatusLabel(jobStatus)
  }
  if (cert?.status === 'expired') return '已过期'
  if (cert?.status === 'expiring') return `临期 ${cert.days_remaining} 天`
  if (cert?.status === 'valid') return row.tls_source === 'acme_dns' ? '已签发' : '手动'
  if (row.tls_source === 'acme_dns') {
    return (jobStatus ? certJobStatusLabel(jobStatus) : '') || '未签发'
  }
  return '手动'
}

const isCurrentRuleLocked = computed(() => {
  if (!editingRule.value) return false
  return editingRule.value.tls_source === 'acme_dns' && isCertJobEditLocked(certJobMap.value[editingRule.value.caddy_id]?.status)
})

const loading = ref(false)
const wizardVisible = ref(false)
const saving = ref(false)
const editingRule = ref<Rule | null>(null)
// 打开编辑表单时该行 updated_at 的基线（乐观并发前置条件）：保存时随
// expected_updated_at 回传，服务端在事务内比对——他人已提交时返回 409，
// 而不是让陈旧表单静默覆盖（含 enabled 翻转与上游/路径规则整组替换）。
const editingRuleVersion = ref('')
const isCopyMode = ref(false)
// 复制源规则（openCopyWizard 带入）——POST /rules 不携带策略绑定，副本创建后
// 经 PUT /security/rules/:id/policies 从源快照复制（submitWizard 复制分支消费）
const copySourceRuleId = ref<string | null>(null)
// 复制走 POST /rules 重建，Create 无 nil=保留语义——规则级回源 Host
// 必须显式随载荷携带，否则副本静默丢失 Host 覆盖（编辑路径不受影响）。
const copySourceHostHeader = ref('')
// 向导打开时的阶段页覆盖快照：编辑保存只提交相对快照变化的键（后端 nil=保留），
// 避免把另一会话写入的覆盖静默回退。
const wizardStagePageSnapshot = ref(newRuleWizardStageOverrides())
const WIZARD_STEP = {
  BASIC: 0,
  TLS: 1,
  UPSTREAMS: 2,
  CUSTOM_ROUTES: 3,
  ADVANCED: 4,
  PREVIEW: 5,
} as const
type WizardStep = (typeof WIZARD_STEP)[keyof typeof WIZARD_STEP]
const currentStep = ref<WizardStep>(WIZARD_STEP.BASIC)
const upstreamTouched = ref<boolean[]>([])
let nextTemporaryPathRuleId = -1
const certConfigs = ref<CertificateConfig[]>([])
const caProviders = ref<CAProvider[]>([])
// 启用项 ∪ 当前选中项（存量规则指向已禁用项时回显「名称（已禁用）」灰态选项，
// 不再显示裸数字 id——原口径会让用户以为未设置而实际仍引用旧值）。CA 与 DNS
// 配置两个同类下拉共用同一 helper（utils/caProviderOptions）。
const wizardCAProviderOptions = computed(() => selectableReferencedOptions(caProviders.value, Number(wizardForm.ca_provider_id || 0)))
const wizardCertConfigOptions = computed(() => selectableReferencedOptions(certConfigs.value, Number(wizardForm.acme_config_id || 0)))
const healthStatus = ref<Record<string, { healthy: number; unhealthy: number; degraded: number; unknown: number; na: number; total: number; upstreams: Record<string, { healthy: boolean; unknown: boolean; dynamic?: boolean; degraded?: boolean; num_requests?: number; fails?: number }> }>>({})
// Config viewing
const configDialogVisible = ref(false)
const configLoading = ref(false)
const configLoadError = ref('')
const configTargetRule = ref<Rule | null>(null)
let configRequestSeq = 0

const ruleLogDialogVisible = ref(false)
const ruleLogRuleName = ref('')
const ruleLogCaddyId = ref('')
const ruleLogContent = ref('')
// ruleLogLoading 由 ruleLogTail.loading 承载
const ruleLogAutoRefresh = ref(true)
const ruleLogContainerRef = ref<HTMLElement | null>(null)
let ruleLogPollTimer: ReturnType<typeof setInterval> | null = null
let ruleLogRequestSeq = 0

const ruleLogHtml = computed(() => ansiToHtml(ruleLogContent.value || '暂无日志'))
const ruleConfig = ref<RuleConfigView | null>(null)

// 结构性简化（D 域 2(e)）：上游启用行的完整性门谓词单源化——红框、常驻警告、
// 步进门、提交门四腿共用同一谓词（提交门先全量置 touched 再判定，与步进门口径
// 一致）。host 与 port 缺一即无效：载荷过滤按 host+port 身份剔除行，端口被
// el-input-number 清空的行不会报错也不会进载荷——保存「成功」但规则少了上游。
const upstreamRowMissingHost = (u: UpstreamInput, i: number): boolean =>
  !u.host && u.enabled !== false && upstreamTouched.value[i]

const upstreamRowMissingPort = (u: UpstreamInput, i: number): boolean =>
  !(Number(u.port) > 0) && u.enabled !== false && upstreamTouched.value[i]

const upstreamRowInvalid = (u: UpstreamInput, i: number): boolean =>
  upstreamRowMissingHost(u, i) || upstreamRowMissingPort(u, i)

// 逐行点名缺哪一列（全局 toast 只能给一句话，字段级定位靠这里）
const upstreamFieldWarning = computed(() => {
  const missingHost: number[] = []
  const missingPort: number[] = []
  wizardForm.upstreams.forEach((u, i) => {
    if (upstreamRowMissingHost(u, i)) missingHost.push(i + 1)
    else if (upstreamRowMissingPort(u, i)) missingPort.push(i + 1)
  })
  const parts: string[] = []
  if (missingHost.length) parts.push(`第 ${missingHost.join('、')} 行主机地址`)
  if (missingPort.length) parts.push(`第 ${missingPort.join('、')} 行端口`)
  return parts.length ? `${parts.join('，')}为必填项，请填写完整` : ''
})

// 混合回源域名 + 主动健康检查警告谓词（2026-10-10 用户裁定）：HTTP 规则 +
// 主动检查开启 + 未设统一健康检查域名 + 任一启用上游配置了回源域名。
// 已设健康检查域名=用户已做统一探测旁路，不再警告。
// 谓词从「≥2 去重值」放宽到「任一启用上游配了回源域名」——
// 单值形态（仅一个回源域名+主动检查+健康检查域名空）同样分裂：代理流量
// Host=回源域名、探测 Host=上游地址/后端域名，无警告会静默误摘后端。
const mixedOriginActiveCheckWarn = computed(() => {
  if (wizardForm.protocol !== 'http' || !wizardForm.enable_active_health_check) return false
  if ((wizardForm.health_check_host || '').trim() !== '') return false
  return wizardForm.upstreams
    .filter(u => u.enabled !== false)
    .some(u => (u.origin_domain || '').trim() !== '')
})

interface HealthSummary { healthy: number; unhealthy: number; degraded: number; unknown: number; na: number; total: number }

const getEnabledUpstreams = (rule: Rule): Upstream[] =>
  rule.upstreams?.filter((upstream) => upstream.enabled !== false) || []

// 健康 hover 的路径规则自定义上游（2026-09-21 用户裁定）：仅自定义路由开启时展示，主上游之后
// 按路径规则分组；后端 GetUpstreamHealthDetailed 已含路径规则代理上游（键同 host:port，直达命中）
const healthPathRules = (rule: Rule): PathRule[] => (rule.custom_routes_enabled ? rule.path_rules || [] : [])
// PathRuleUpstream.address 即主机（该类型无 enabled 标志，列出即生效上游），适配既有健康/指标查询入参
const pathUpstreamRef = (upstream: PathRuleUpstream): { host: string; port: number } => ({ host: upstream.address, port: upstream.port })

const getHealthTagType = (status: HealthSummary) => {
  if (status.unhealthy + status.degraded === status.total) return 'danger'
  if (status.unhealthy + status.degraded > 0) return 'warning'
  if (status.unknown === status.total) return 'info'
  if (status.unknown > 0) return 'warning'
  // 动态 DNS 上游结构性 N/A(引擎按解析 IP 跟踪,域名级不可观测)
  if (status.na === status.total) return 'info'
  return 'success'
}

const getHealthLabel = (status: HealthSummary) => {
  if (status.unhealthy + status.degraded === status.total) return '异常'
  if (status.unhealthy + status.degraded > 0) return '降级'
  if (status.unknown === status.total) return '未知'
  if (status.unknown > 0) return '降级'
  if (status.na === status.total) return 'N/A'
  return '正常'
}

// hostPortKey 提取至 utils/upstreamKeys（Dashboard 共用）。

interface UpstreamHealthView {
  healthy: boolean
  unknown: boolean
  dynamic?: boolean
  degraded: boolean
}
const getUpstreamHealthStatus = (ruleId: string, upstream: Upstream | UpstreamInput | { host: string; port: number }): UpstreamHealthView => {
  const status = healthStatus.value[ruleId]
  if (!status || !status.upstreams) return { healthy: false, unknown: true, degraded: false }
  const upstreamKey = hostPortKey(upstream.host, upstream.port)
  const upstreamData = status.upstreams[upstreamKey]
  return upstreamData
    ? { healthy: upstreamData.healthy, unknown: upstreamData.unknown, dynamic: upstreamData.dynamic, degraded: upstreamData.degraded ?? false }
    : { healthy: false, unknown: true, degraded: false }
}

const getUpstreamMetrics = (ruleId: string, upstream: Upstream | UpstreamInput | { host: string; port: number }) => {
  const status = healthStatus.value[ruleId]
  if (!status || !status.upstreams) return { num_requests: 0, fails: 0 }
  const upstreamKey = hostPortKey(upstream.host, upstream.port)
  const upstreamData = status.upstreams[upstreamKey]
  return {
    num_requests: upstreamData?.num_requests || 0,
    fails: upstreamData?.fails || 0
  }
}

const formatUpdatedTime = (updatedAt: Rule['updated_at']): string => {
  if (!updatedAt) return '-'
  return formatDate(updatedAt) || '-'
}

const fetchHealthStatus = async (roundSignal?: AbortSignal) => {
  if (disposed) return
  try {
    const res = await request.get<APIResponse<UpstreamHealthResponse>>('/config/health', { signal: roundSignal ?? healthPolling.signal, silent: true })
    if (disposed) return
    const healthData = res.data || {}
    // 扁平索引（host:port → detail）一次构建——原 probeUpstream 对每个
    // 上游再遍历全部 server 映射（O(R×S×U) → O(S+U)）。首见优先（与原扫描顺序等价）。
    const healthDetailIndex = new Map<string, { healthy: boolean; unknown: boolean; dynamic?: boolean; degraded?: boolean; num_requests?: number; fails?: number }>()
    for (const serverHealth of Object.values(healthData)) {
      if (!serverHealth || typeof serverHealth !== 'object') continue
      for (const [key, detail] of Object.entries(serverHealth)) {
        if (!healthDetailIndex.has(key)) healthDetailIndex.set(key, detail)
      }
    }
    const mapped: Record<string, { healthy: number; unhealthy: number; degraded: number; unknown: number; na: number; total: number; upstreams: Record<string, { healthy: boolean; unknown: boolean; dynamic?: boolean; degraded?: boolean; num_requests?: number; fails?: number }> }> = {}
    for (const rule of rules.value) {
      const enabledUpstreams = getEnabledUpstreams(rule)
      if (enabledUpstreams.length > 0) {
        let healthy = 0
        let unhealthy = 0
        let degraded = 0
        let unknown = 0
        let na = 0
        const upstreamStatus: Record<string, { healthy: boolean; unknown: boolean; dynamic?: boolean; degraded?: boolean; num_requests?: number; fails?: number }> = {}
        // TCP 被动健康(未开主动探测)为结构性 N/A——caddy-l4 无
        // admin 端点,被动熔断不产指标(gauge 仅主动检查写),与动态 DNS 同口径。
        const tcpPassive = rule.protocol === 'tcp' && !rule.enable_active_health_check
        const probeUpstream = (upstreamKey: string) => {
          let isHealthy = false
          let isUnknown = true
          let isDegraded = false
          let isDynamic = false
          let numRequests = 0
          let fails = 0
          const detail = healthDetailIndex.get(upstreamKey)
          if (detail) {
            isUnknown = detail.unknown === true
            isDynamic = detail.dynamic === true
            if (!isUnknown) {
              isHealthy = detail.healthy !== false
              isDegraded = detail.degraded === true
            }
            numRequests = detail.num_requests || 0
            fails = detail.fails || 0
          }
          return { healthy: isHealthy, unknown: isUnknown, dynamic: isDynamic, degraded: isDegraded, num_requests: numRequests, fails }
        }
        for (const upstream of enabledUpstreams) {
          const upstreamKey = hostPortKey(upstream.host, upstream.port)
          const entry = probeUpstream(upstreamKey)
          upstreamStatus[upstreamKey] = entry
          if (entry.unknown && (entry.dynamic || tcpPassive)) na++
          else if (entry.unknown) unknown++
          else if (!entry.healthy) unhealthy++
          else if (entry.degraded) degraded++
          else healthy++
        }
        // 自定义路由上游并入映射（2026-09-21 用户报障：路径规则上游从不入映射，
        // 健康浮层对它们恒回落 unknown 问号）：仅补 upstreams 查询键空间供浮层
        // 与流程弹框按 host:port 直查，规则级计数与 total 保持主上游口径不变；
        // 与主上游同键视为同一上游，去重跳过
        if (rule.custom_routes_enabled) {
          for (const pathRule of healthPathRules(rule)) {
            for (const pathUpstream of pathRule.upstreams || []) {
              const upstreamKey = hostPortKey(pathUpstream.address, pathUpstream.port)
              if (upstreamKey in upstreamStatus) continue
              upstreamStatus[upstreamKey] = probeUpstream(upstreamKey)
            }
          }
        }
        if (rule.caddy_id) {
          mapped[rule.caddy_id] = { healthy, unhealthy, degraded, unknown, na, total: enabledUpstreams.length, upstreams: upstreamStatus }
        }
      }
    }
    if (!disposed) {
      healthStatus.value = mapped
      healthPollingError.clear()
    }
  } catch (error: unknown) {
    // pause/stop/卸载触发的取消不是失败（不得弹错误横幅）
    if (!disposed && !axios.isCancel(error)) {
      console.error('Failed to fetch health status:', error)
      healthPollingError.recordError(error)
    }
  }
}

const defaultUpstream = (protocol: UpstreamProtocol = 'http'): UpstreamInput => ({
  host: '',
  port: protocol === 'tcp' ? 8080 : 80,
  weight: 100,
  dynamic_dns: false,
  enabled: true,
  protocol,
  max_connections: 0,
  origin_domain: '',
})

const pathRuleUpstreamsToPercent = (upstreams: readonly PathRuleUpstream[] | null | undefined): PathRuleUpstream[] | null => {
  if (!upstreams) return null
  const normalized = upstreams.map((upstream) => ({
    ...upstream,
    protocol: upstream.protocol || 'http',
  }))
  normalizeWeights(normalized)
  return normalized
}

const certInfo = reactive({
  valid: false,
  domain: '',
  expiryDate: '',
  daysUntilExpiry: 0,
  warning: '',
  error: ''
})
let certValidationSeq = 0
let certValidationSessionSeq = 0
// 手动 TLS 详情加载失败：列表行不含证书正文（rule_features
// 直取时省略），详情 GET 失败若仅 console，表单会以空证书快照静默继续——保存
// 后把既有证书覆盖为空。失败即阻断 TLS 步/保存，并提供重试。
const tlsDetailError = ref(false)
const tlsDetailLoading = ref(false)
const tlsDetailRuleId = ref('')
// 证书详情重试的会话序号：关闭向导/换表单即失效，在途响应不得把旧规则的
// 证书与私钥写进新表单（与 openWizard 的 wizardOpenSeq 同范式）。
let tlsDetailSeq = 0

function markTlsDetailFailed(caddyId: string): void {
  tlsDetailError.value = true
  tlsDetailRuleId.value = caddyId
  ElMessage.warning('证书详情加载失败：TLS 配置可能不完整，已阻止保存；请在 TLS 步骤点「重新加载」')
}

/** TLS 步重试：只回填证书相关字段（不重水合整表单，避免覆盖用户已改内容）。 */
async function retryTlsDetail(): Promise<void> {
  const caddyId = tlsDetailRuleId.value
  if (!caddyId || tlsDetailLoading.value) return
  // 会话快照：响应回填前三者必须仍一致，否则说明向导已关闭或已换到另一表单，
  // 回填会把旧规则的证书材料写进新规则（manual 私钥校验还会被 tlsKeySet 放行）。
  const sessionSeq = ++tlsDetailSeq
  const openSeq = wizardOpenSeq
  // 目标规则取 tlsDetailRuleId（失败时由 markTlsDetailFailed 记下源规则 id）——
  // 复制流程有意清空 editingRule（新建语义），用编辑态判定会让复制态的重试恒被
  // 丢弃：回填与提示都在守卫之后，tlsDetailError 永不清除 → TLS 步/保存永久卡死。
  const sessionAlive = (): boolean =>
    sessionSeq === tlsDetailSeq &&
    openSeq === wizardOpenSeq &&
    wizardVisible.value &&
    tlsDetailRuleId.value === caddyId
  tlsDetailLoading.value = true
  try {
    const resp = await request.get<APIResponse<Rule>>(`/rules/${encodeURIComponent(caddyId)}`)
    if (!sessionAlive()) return
    if (resp.code !== 0 || !resp.data) {
      ElMessage.warning('证书详情仍不可用，请稍后重试')
      return
    }
    wizardForm.tls_cert = resp.data.tls_cert || ''
    wizardForm.tls_key = resp.data.tls_key || ''
    // 掩码私钥标记——已配置且回显空串时允许沿用原值
    wizardForm.tlsKeySet = resp.data.tls_key_set === true
    tlsDetailError.value = false
    // 回填后复现正常加载路径的派生效果：certInfo 只由 textarea 的 blur 触发解析，
    // 不回读会让 TLS 步的验证块与预览域名/有效期保持空（用户误判材料不可用）。
    // validateCertificate 自带 certValidationSeq/会话序号守卫，换表单/关向导后
    // 的迟到响应不会写回。
    void validateCertificate()
    ElMessage.success('证书详情已重新加载')
  } catch (error: unknown) {
    if (!sessionAlive()) return
    console.warn('[retryTlsDetail] failed', error)
    ElMessage.warning('证书详情加载失败，请稍后重试')
  } finally {
    // 仅当前会话负责收尾 loading；会话已被新一代接管时由新一代自行管理
    if (sessionSeq === tlsDetailSeq) tlsDetailLoading.value = false
  }
}

const resetCertInfo = (): void => {
  Object.assign(certInfo, {
    valid: false,
    domain: '',
    expiryDate: '',
    daysUntilExpiry: 0,
    warning: '',
    error: '',
  })
}

const wizardForm = reactive<RuleForm>({
  name: '',
  description: '',
  protocol: 'http',
  domain: '',
  listen_port: 80,
  strategy: 'weighted_round_robin',
  dynamic_dns: false,
  enable_dns_server: false,
  dns_server: '',
  dns_family: ['ipv4'],
  health_check_path: '',
  health_check_interval: 10,
  health_check_timeout: 2,
  health_check_healthy_threshold: 2,
  health_check_unhealthy_threshold: 3,
  enable_active_health_check: true,
  tcp_health_check_port: 0,
  tcp_proxy_protocol: false,
  tcp_try_duration: 0,
  tcp_try_interval: 250,
  health_check_host: '',
  upstreams: [],
  enable_tls: false,
  tls_source: 'manual',
  acme_config_id: 0,
  ca_provider_id: undefined as number | undefined,
  tls_cert: '',
  tls_key: '',
  tlsKeySet: false,
  tls_http_redirect: false,
  enable_compress: false,
  compress_types: ['gzip'],
  request_body_max_size_mb: 0,
  upstream_keepalive_timeout: 0,
  server_tokens_hidden: 0,
  ntlm_compatible: 0,
  upstream_force_http1: 0,
  enabled: true,
  log_enabled: false,
  custom_routes_enabled: false,
  path_rules: [],
  proxy_dial_timeout: 0,
  proxy_response_header_timeout: 0,
  proxy_read_timeout: 0,
  proxy_write_timeout: 0,
  proxy_stream_timeout: 0,
  proxy_flush_interval: 0,
  proxy_stream_close_delay: 0,
})

watch(() => wizardForm.path_rules, (pathRules) => {
  pathRules.forEach((pathRule) => {
    if (pathRule.id === undefined) {
      pathRule.id = nextTemporaryPathRuleId
      nextTemporaryPathRuleId -= 1
    }
  })
}, { deep: true })

let hydratingWizard = false
// 向导打开序列号——丢弃编辑/复制在途 GET 的过期返回，防止覆盖新建表单。
let wizardOpenSeq = 0
// TLS/端口提示去重：3 秒内最多一条，连续拨动不堆叠 toast。
let lastTlsHintAt = 0
const showTlsHint = (message: string) => {
  const now = Date.now()
  if (now - lastTlsHintAt <= 3000) return
  lastTlsHintAt = now
  ElMessage.info(message)
}
// 用户是否显式/已提交过监听端口：置位后停止 80↔443/8080 的自动联动，避免静默改回默认端口。
// 编辑态打开即置位（DB 中的 listen_port 就是用户已提交的显式配置）；联动仅保留 create/复制流的默认便捷。
const userExplicitPort = ref(false)
// http→tcp 迁移前的 HTTP 态快照：回转 http 时判断「是否实际改过端口 / 是否被强制关闭过 TLS」。
let preTcpSnapshot: { listenPort: number; enableTls: boolean } | null = null

// Watch for enable_tls toggle to adjust default listen port
// （用户裁定）：启用 TLS 时端口直接默认 443（不仅是提示）——
// 编辑态与创建态统一，开启分支必须先于 userExplicitPort 短路（2026-10-13
// 生产实证：短路前置导致编辑态拨 TLS 永不改端口）。用户随后手动改端口即置
// userExplicitPort，关闭方向的自动回 80 仍受其约束（既有语义）。
watch(() => wizardForm.enable_tls, (newVal, oldVal) => {
  if (hydratingWizard) return
  if (wizardForm.protocol !== 'http') return
  if (newVal && !oldVal) {
    if (wizardForm.listen_port !== 443) {
      wizardForm.listen_port = 443
      showTlsHint('已默认切换为 443 端口')
    }
    return
  }
  if (!newVal && oldVal && userExplicitPort.value && wizardForm.listen_port === 443) {
    showTlsHint('端口当前为 443，关闭 TLS 后如需 HTTP 访问建议改为 80')
  }
  if (userExplicitPort.value) return
  if (!newVal && oldVal) {
    // Disabling HTTPS: revert to 80 if currently 443
    if (wizardForm.listen_port === 443) {
      wizardForm.listen_port = 80
    }
  }
}, { flush: 'sync' })

// Watch for protocol changes to adjust defaults for TCP rules
watch(() => wizardForm.protocol, (newVal, oldVal) => {
  if (hydratingWizard) return
  if (newVal !== 'tcp') wizardForm.tcp_proxy_protocol = false
  if (newVal === 'tcp') {
    // 快照进入 TCP 前的 HTTP 态（须先于下方端口/ enable_tls 变更），供回转提示判断
    preTcpSnapshot = { listenPort: wizardForm.listen_port, enableTls: wizardForm.enable_tls }
    // Switching to TCP: use a neutral high port and plain TCP upstreams.
    // 无条件迁移：DB 中不存在 TCP:80/443 存量规则（后端无条件拒绝），编辑态无需保留该值
    if (wizardForm.listen_port === 80 || wizardForm.listen_port === 443) {
      wizardForm.listen_port = 8080
      ElMessage.info('已切换为 TCP，监听端口自动调整为 8080')
    }
    wizardForm.enable_tls = false
    if (wizardForm.strategy === 'cookie') wizardForm.strategy = 'weighted_round_robin'
    // NTLM 兼容是 HTTP 语义：切 TCP 开关自动关 + 接管字段恢复默认（静默，设计定稿）
    if (wizardForm.ntlm_compatible === 1) {
      wizardForm.ntlm_compatible = 0
      restoreNtlmDefaults()
    }
    // 上游强制 HTTP/1.1 同为 HTTP 传输语义——切 TCP 一并弃置
    wizardForm.upstream_force_http1 = 0
    wizardForm.custom_routes_enabled = false
    wizardForm.health_check_host = ''
    wizardForm.path_rules = []
    // 动态上游与 DNS 服务发现同为 HTTP 语义：TCP 下这两组控件整段不渲染，
    // 但载荷仍无条件上送——残留值会被后端「TCP 规则不支持…」门恒拒，
    // 且用户没有可见控件可关闭（与上方 HTTP-only 字段同族清理）。
    wizardForm.dynamic_dns = false
    wizardForm.enable_dns_server = false
    wizardForm.dns_server = ''
    wizardForm.upstreams.forEach(u => {
      // 回源域名是 HTTP-only 语义——切换即弃置，
      // 否则隐藏残留字段被后端「回源域名仅 HTTP 规则支持」门恒拒，卡死保存
      u.origin_domain = ''
      if (u.protocol === 'http') u.protocol = 'tcp'
      if (u.protocol === 'https') u.protocol = 'tls'
    })
  } else if (newVal === 'http' && oldVal === 'tcp') {
    // 回转判断基于快照而非 userExplicitPort：编辑态（userExplicitPort=true）进 TCP 同样被
    // 无条件迁移 80/443→8080，回转不还原会保存即静默改写 DB 端口
    const portChanged =
      wizardForm.listen_port === 8080 &&
      (preTcpSnapshot?.listenPort === 80 || preTcpSnapshot?.listenPort === 443)
    const tlsWasOn = preTcpSnapshot?.enableTls === true
    if (portChanged && preTcpSnapshot) wizardForm.listen_port = preTcpSnapshot.listenPort
    wizardForm.upstreams.forEach(u => {
      if (u.protocol === 'tcp') u.protocol = 'http'
      if (u.protocol === 'tls') u.protocol = 'https'
    })
    // 回转提示：仅在实际改端口 / 曾强制关 TLS 时给出，走 showTlsHint 去重通道
    const notes: string[] = []
    if (portChanged && preTcpSnapshot) notes.push(`监听端口已调整为 ${preTcpSnapshot.listenPort}`)
    if (tlsWasOn) notes.push('TLS 已在 TCP 模式下关闭，如需 HTTPS 请重新开启')
    if (notes.length > 0) showTlsHint(`已切换为 HTTP，${notes.join('；')}`)
  }
}, { flush: 'sync' })

// 水合 false 配置时保留已存 dns_server；仅用户主动关闭才清空。
watch(() => wizardForm.enable_dns_server, (newVal) => {
  wizardForm.dns_server = dnsServerAfterToggle(wizardForm.dns_server, newVal, hydratingWizard)
}, { flush: 'sync' })

// Watch for enable_active_health_check toggle to set default path.
// TCP 探测端口保持用户值——0=按各上游自身端口探测（后端仅在 >0
// 时发射 active.port）；自动填首上游端口会静默改变多端口上游的探测语义。
watch(() => wizardForm.enable_active_health_check, (newVal) => {
  if (!newVal) return
  if (!wizardForm.health_check_path) {
    wizardForm.health_check_path = '/'
  }
})

// 默认部署的管理端口（面板 :8000 / Caddy admin :2019）——仅作前端即时提示。
// 真实判据在服务端（validateRuleListenPortForSave 校验本进程面板端口 +
// caddy_admin_url 端口 + 2019）：自定义部署（如面板 8443、admin 不落 2019）时
// 这里可能漏拦/误拦，保存结果以服务端 400 为准（下方提示文案已声明）。
const DEFAULT_DEPLOYMENT_ADMIN_PORTS: readonly number[] = [8000, 2019]
const httpReservedPorts = [80, 443]

const showTlsStep = computed(() => wizardForm.protocol === 'http' && wizardForm.enable_tls)
const showCustomRoutesStep = computed(() => wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled)
const visibleWizardSteps = computed<readonly WizardStep[]>(() => [
  WIZARD_STEP.BASIC,
  ...(showTlsStep.value ? [WIZARD_STEP.TLS] : []),
  WIZARD_STEP.UPSTREAMS,
  ...(showCustomRoutesStep.value ? [WIZARD_STEP.CUSTOM_ROUTES] : []),
  WIZARD_STEP.ADVANCED,
  WIZARD_STEP.PREVIEW,
])

const visualStepIndex = computed(() => {
  const index = visibleWizardSteps.value.indexOf(currentStep.value)
  return index >= 0 ? index : 0
})

const hasPreviousStep = computed(() => visualStepIndex.value > 0)
const hasNextStep = computed(() => visualStepIndex.value < visibleWizardSteps.value.length - 1)

// 步骤可点击快跳(镜像 SecurityPolicies.vue 向导先例,同口径):仅编辑态开放——
// 新建/复制时基本配置步骤的协议/TLS/自定义路由选择决定可见步骤集,且表单尚未水合,
// 跳过前置步骤会绕过步进校验。快跳本身不执行校验(与策略向导一致:步进校验只作用于上一页/下一页按钮)。
// 保存中一律不可跳步：请求在途时改到的字段不进本次载荷，成功关窗即静默丢弃。
const stepsClickable = computed(() => editingRule.value !== null && !saving.value)

const jumpToStep = (step: WizardStep): void => {
  if (!stepsClickable.value) return
  currentStep.value = step
}

const portWarning = computed(() => {
  // Get existing ports (excluding current editing rule)
  const currentRule = editingRule.value
  // 与后端 validatePortFromDB 的 enabled-only 语义对齐：禁用规则不占端口（管理端口拦截保持无条件）
  const existingRules = (currentRule
    ? rules.value.filter(r => r.caddy_id !== currentRule.caddy_id)
    : rules.value).filter(r => r.enabled)
  const httpPorts = existingRules.filter(r => r.protocol === 'http').map(r => r.listen_port)
  const tcpPorts = existingRules.filter(r => r.protocol === 'tcp').map(r => r.listen_port)
  
  if (wizardForm.protocol === 'http') {
    // HTTP rules cannot use admin ports and cannot share a port with any TCP rule.
    if (DEFAULT_DEPLOYMENT_ADMIN_PORTS.includes(wizardForm.listen_port)) {
      return `端口 ${wizardForm.listen_port} 为管理端口，不可使用`
    }
    if (tcpPorts.includes(wizardForm.listen_port)) {
      return `端口已被 TCP 规则占用`
    }
    // 80 端口 + TLS 跳转自环（跳转目标 https://host:80 与来源同端口）：
    // 后端保存门同判据，前端先拦并在端口行内提示。
    if (wizardForm.listen_port === 80 && wizardForm.enable_tls && wizardForm.tls_http_redirect) {
      return '80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转'
    }
  } else if (wizardForm.protocol === 'tcp') {
    // TCP rules cannot use admin ports, 80/443, or share a port with any other rule.
    if (httpReservedPorts.includes(wizardForm.listen_port)) {
      return `端口 ${wizardForm.listen_port} 为 HTTP/Web 端口，TCP 规则不可使用`
    }
    if (DEFAULT_DEPLOYMENT_ADMIN_PORTS.includes(wizardForm.listen_port)) {
      return `端口 ${wizardForm.listen_port} 为管理端口，不可使用`
    }
    if (httpPorts.includes(wizardForm.listen_port) || tcpPorts.includes(wizardForm.listen_port)) {
      return `端口已被其他规则占用`
    }
  }
  return ''
})

// 策略文案映射提取至 utils/strategyLabels（Dashboard 共用，
// 死键 header 已删）。

// 三个辅助端点（更新者列/ACME DNS 配置/CA 提供商）失败必须显性化——
// 原仅 console.error：「更新者」列全列回落「-」与「无更新者」不可区分、
// ACME 规则编辑时 DNS 配置下拉空白（用户被「请选择 DNS 提供商配置」拦住却
// 无法判断是未配置还是加载失败）、CA 选择器只剩「系统默认」。
const usersLoadError = ref(false)
const certConfigsLoadError = ref(false)
const caProvidersLoadError = ref(false)
const auxDataLoadFailed = computed(() => usersLoadError.value || certConfigsLoadError.value || caProvidersLoadError.value)
const auxDataRetryLoading = ref(false)

const fetchUsers = async () => {
  try {
  const res = await request.get<APIResponse<UserListItem[]>>('/users')
    users.value = res.data || []
    usersLoadError.value = false
  } catch (e) {
    console.error('Failed to fetch users:', e)
    usersLoadError.value = true
  }
}

const fetchCertConfigs = async () => {
  try {
    const res = await request.get<APIResponse<CertificateConfig[]>>('/certificate-configs')
    certConfigs.value = res.data || []
    certConfigsLoadError.value = false
  } catch (e) {
    console.error('Failed to fetch cert configs:', e)
    certConfigsLoadError.value = true
  }
}

const fetchCAProviders = async () => {
  try {
    const res = await request.get<APIResponse<CAProvider[]>>('/ca-providers')
    caProviders.value = res.data || []
    caProvidersLoadError.value = false
  } catch (e) {
    console.error('Failed to load CA providers:', e)
    caProvidersLoadError.value = true
  }
}

const retryAuxData = async (): Promise<void> => {
  if (auxDataRetryLoading.value) return
  auxDataRetryLoading.value = true
  try {
    const retries: Promise<void>[] = []
    if (usersLoadError.value) retries.push(fetchUsers())
    if (certConfigsLoadError.value) retries.push(fetchCertConfigs())
    if (caProvidersLoadError.value) retries.push(fetchCAProviders())
    await Promise.all(retries)
  } finally {
    auxDataRetryLoading.value = false
  }
}

const validateCertificate = async () => {
  const validationSeq = ++certValidationSeq
  const sessionSeq = certValidationSessionSeq
  resetCertInfo()

  const certPEM = wizardForm.tls_cert?.trim() || ''
  const keyPEM = wizardForm.tls_key?.trim() || ''

  if (!certPEM && !keyPEM) return

  if (!certPEM) {
    certInfo.error = '请提供证书 (PEM)'
    return
  }

  if (!keyPEM) {
    // 掩码私钥（后端 tls_key 空 + tls_key_set=true）：沿用已保存私钥，
    // 不误报「请提供私钥」（保存门已按同一契约放行）。
    if (wizardForm.tlsKeySet) return
    certInfo.error = '请提供私钥 (KEY)'
    return
  }

  // Validate certificate format
  if (!certPEM.includes('-----BEGIN CERTIFICATE-----') || !certPEM.includes('-----END CERTIFICATE-----')) {
    certInfo.error = '证书格式无效，必须以 -----BEGIN CERTIFICATE----- 开头'
    return
  }

  // Validate private key format
  // 旧哨兵串 $$PRIVATEKEY_* 全仓零产生方（后端现行掩码=tls_key 空+
  // tls_key_set），真实 PEM 曾被误判「私钥格式无效」致 /certificates/parse
  // 永不发起——改认真实 PEM 头（RSA/EC/PKCS#8/OPENSSH/ENCRYPTED 等
  // * PRIVATE KEY 形态）；本门仅 advisory，终裁仍由后端 parseTLSCertificate
  // （tls.X509KeyPair）判定。
  if (!/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(keyPEM)) {
    certInfo.error = '私钥格式无效，须以 -----BEGIN ... PRIVATE KEY----- 开头'
    return
  }

  // Call backend API to parse certificate
  try {
    const res = await request.post<APIResponse<CertificateParseResult>>('/certificates/parse', {
      cert_pem: certPEM,
      key_pem: keyPEM
    })
    if (validationSeq !== certValidationSeq || sessionSeq !== certValidationSessionSeq) return
    
    if (res.code === 0 && res.data) {
      const data = res.data
      certInfo.valid = data.valid
      certInfo.domain = data.domain || '未知'
      certInfo.expiryDate = data.not_after || ''
      certInfo.daysUntilExpiry = data.days_until_expiry || 0
      certInfo.warning = data.warning || ''
      certInfo.error = ''
    } else {
      certInfo.error = res.message || '证书验证失败'
    }
  } catch (error: unknown) {
    if (validationSeq !== certValidationSeq || sessionSeq !== certValidationSessionSeq) return
    certInfo.error = error instanceof Error ? error.message : '证书验证请求失败'
  }
}

const selectedCompressTypes = (value: string | string[]): string[] => {
  if (Array.isArray(value)) return value.length > 0 ? value : ['gzip']
  if (typeof value === 'string' && value.trim()) return value.split(',').map(s => s.trim()).filter(Boolean)
  return ['gzip']
}

const wizardFormFromRule = (fullRule: Rule): Partial<RuleForm> => ({
  name: fullRule.name,
  description: fullRule.description || '',
  protocol: fullRule.protocol,
  domain: fullRule.domain || '',
  listen_port: fullRule.listen_port,
  strategy: fullRule.strategy || 'weighted_round_robin',
  dynamic_dns: fullRule.dynamic_dns || false,
  enable_dns_server: fullRule.enable_dns_server || false,
  dns_server: fullRule.dns_server || '',
  dns_family: selectedDnsFamilies(fullRule.dns_family),
  health_check_path: fullRule.health_check_path || '',
  health_check_interval: fullRule.health_check_interval || 10,
  health_check_timeout: fullRule.health_check_timeout || 2,
  health_check_healthy_threshold: fullRule.health_check_healthy_threshold || 2,
  health_check_unhealthy_threshold: fullRule.health_check_unhealthy_threshold || 3,
  enable_active_health_check: fullRule.enable_active_health_check === true,
  tcp_health_check_port: fullRule.tcp_health_check_port || 0,
  tcp_proxy_protocol: fullRule.tcp_proxy_protocol === true,
  tcp_try_duration: fullRule.tcp_try_duration || 0,
  tcp_try_interval: fullRule.tcp_try_interval ?? 250,
  health_check_host: fullRule.health_check_host || '',
  upstreams: fullRule.upstreams?.map(u => ({
    ...u,
    dynamic_dns: false,
    protocol: u.protocol || 'http',
    max_connections: u.max_connections ?? 0,
    origin_domain: u.origin_domain || '',
  })) || [],
  enable_tls: fullRule.enable_tls || false,
  tls_source: fullRule.tls_source || 'manual',
  acme_config_id: fullRule.acme_config_id || undefined,
  ca_provider_id: fullRule.ca_provider_id ?? 0,
  tls_cert: fullRule.tls_cert || '',
  tls_key: fullRule.tls_key || '',
  // GetRule 掩码私钥时仅回 tls_key_set：区分「未配置」与「已隐藏」，
  // 提交空 tls_key 时后端保留原值。
  tlsKeySet: fullRule.tls_key_set === true,
  tls_http_redirect: fullRule.tls_http_redirect || false,
  enable_compress: fullRule.enable_compress !== false,
  compress_types: fullRule.compress_types ? selectedCompressTypes(fullRule.compress_types) : ['gzip'],
  request_body_max_size_mb: fullRule.request_body_max_size_mb || 0,
  upstream_keepalive_timeout: fullRule.upstream_keepalive_timeout || 0,
  server_tokens_hidden: fullRule.server_tokens_hidden || 0,
  // 阶段拦截页覆盖：复制/编辑均保留（后端 DuplicateRule 同口径）；键集与
  // 新建/重置路径共用 stageBlockPageOverrides。
  ...stageBlockPageOverrides(fullRule),
  // NTLM 接管态原样回填；编辑/复制均保留实际接管字段。
  ntlm_compatible: fullRule.ntlm_compatible === 1 ? 1 : 0,
  upstream_force_http1: fullRule.upstream_force_http1 === 1 ? 1 : 0,
  enabled: fullRule.enabled,
  log_enabled: fullRule.log_enabled || false,
  custom_routes_enabled: fullRule.custom_routes_enabled === true,
  path_rules: [...(fullRule.path_rules || [])]
    .sort((left, right) => left.sort_order - right.sort_order)
    .map((pathRule) => ({
      ...pathRule,
      // UI 哨兵：空串模式映射为 forward；提交时归一回空串。
      response_mode: pathRule.response_mode || 'forward',
      upstreams: pathRuleUpstreamsToPercent(pathRule.upstreams),
    })),
  proxy_dial_timeout: fullRule.proxy_dial_timeout || 0,
  proxy_response_header_timeout: fullRule.proxy_response_header_timeout || 0,
  proxy_read_timeout: fullRule.proxy_read_timeout || 0,
  proxy_write_timeout: fullRule.proxy_write_timeout || 0,
  proxy_stream_timeout: fullRule.proxy_stream_timeout || 0,
  proxy_flush_interval: fullRule.proxy_flush_interval || 0,
  proxy_stream_close_delay: fullRule.proxy_stream_close_delay || 0,
})

const buildRuleConfigView = (
  rule: Rule,
  caddyId: string,
  config: object | null,
  configNotExists: boolean,
  compressTypes?: string[],
): RuleConfigView => ({
  id: rule.id || 0,
  caddy_id: caddyId,
  name: rule.name || '',
  domain: rule.domain || '',
  listen_port: rule.listen_port || 0,
  protocol: rule.protocol || 'http',
  strategy: rule.strategy || 'weighted_round_robin',
  dynamic_dns: rule.dynamic_dns || false,
  enable_dns_server: rule.enable_dns_server || false,
  dns_server: rule.dns_server || '',
  host_header: rule.host_header || '',
  health_check_host: rule.health_check_host || '',
  enable_tls: rule.enable_tls || false,
  tls_source: rule.tls_source || 'manual',
  tls_http_redirect: rule.tls_http_redirect || false,
  enable_compress: rule.enable_compress !== false,
  compress_types: compressTypes ?? (rule.compress_types ? selectedCompressTypes(rule.compress_types) : ['gzip']),
  health_check_path: rule.health_check_path || '',
  health_check_interval: rule.health_check_interval || 10,
  health_check_timeout: rule.health_check_timeout || 2,
  health_check_healthy_threshold: rule.health_check_healthy_threshold || 2,
  health_check_unhealthy_threshold: rule.health_check_unhealthy_threshold || 3,
  enable_active_health_check: rule.enable_active_health_check === true,
  tcp_health_check_port: rule.tcp_health_check_port || 0,
  tcp_try_duration: rule.tcp_try_duration || 0,
  tcp_try_interval: rule.tcp_try_interval ?? 250,
  request_body_max_size_mb: rule.request_body_max_size_mb || 0,
  upstream_keepalive_timeout: rule.upstream_keepalive_timeout || 0,
  server_tokens_hidden: rule.server_tokens_hidden || 0,
  upstreams: rule.upstreams || [],
  enabled: rule.enabled !== false,
  config,
  config_not_exists: configNotExists,
})

const compressType = computed<string>({
  get: () => wizardForm.compress_types[0] ?? 'gzip',
  set: (v: string) => { wizardForm.compress_types = [v] },
})

const selectedDnsFamilies = (value: string | string[]): string[] => {
  if (Array.isArray(value)) return value
  if (value === 'both') return ['ipv4', 'ipv6']
  if (value === 'ipv4') return ['ipv4']
  if (value === 'ipv6') return ['ipv6']
  return ['ipv4']
}

// 证书/私钥「从文件读取」：证书文件体积有合理上限（1 MiB 足以容纳任何 PEM
// 链），超限直接拒绝——整份超大文本会进 textarea 并触发后续解析/高亮，主线程
// 卡顿且无收益。读取失败只在 FileReader.onerror 可达（同步 try/catch 包不住
// 异步读），旧实现的 catch 恒为死代码、失败则静默无反馈。
const CERT_FILE_MAX_BYTES = 1024 * 1024

const pasteFromFile = (type: 'cert' | 'key'): void => {
  const input = document.createElement('input')
  input.type = 'file'
  // 不放开 `,*`：它让选择器默认展示任意文件，误选二进制后 readAsText 会把
  // 一堆替换字符写进证书/私钥表单
  input.accept = '.pem,.crt,.key,.txt'

  input.onchange = (e: Event) => {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (!file) return
    if (file.size > CERT_FILE_MAX_BYTES) {
      ElMessage.error(`文件超过 ${Math.round(CERT_FILE_MAX_BYTES / 1024)}KB 上限，请手动粘贴证书或私钥内容`)
      return
    }

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result
      if (typeof content !== 'string') {
        ElMessage.error('读取文件失败，请重试或手动粘贴')
        return
      }
      if (type === 'cert') {
        wizardForm.tls_cert = content
      } else {
        wizardForm.tls_key = content
      }
      ElMessage.success('已从文件读取内容')
      // 写入后必须重算校验：原实现只由 textarea @blur 触发（点击按钮本身会让
      // textarea 失焦、以旧内容校验一次），新内容不回填结论会让校验块与预览
      // 停留在上一份证书的域名/到期日。validateCertificate 自带
      // certValidationSeq/会话守卫并先 resetCertInfo，换表单后的迟到响应不会写回。
      void validateCertificate()
    }
    reader.onerror = () => {
      ElMessage.error('读取文件失败，请重试或手动粘贴')
    }
    reader.readAsText(file)
  }

  input.click()
}

const openWizard = async (rule?: Rule) => {
  if (isReadOnly.value || saving.value) return
  // 向导打开序列号（同 viewConfig 的 configRequestSeq 模式）——
  // 编辑/复制手动 TLS 规则时在途 GET 期间用户再点「新建」，首个返回会覆盖
  // 新建表单并把保存语义从 create 翻成 PUT。过期返回直接丢弃。
  const openSeq = ++wizardOpenSeq
  hydratingWizard = true
  preTcpSnapshot = null
  userExplicitPort.value = false
  certValidationSessionSeq++
  certValidationSeq++
  resetCertInfo()
  wizardForm.tlsKeySet = false // 掩码态随向导重置
  tlsDetailError.value = false
  // 证书详情重试会话换新：在途响应随旧会话失效
  tlsDetailSeq++
  tlsDetailLoading.value = false
  tlsDetailRuleId.value = ''
  upstreamTouched.value = []
  isCopyMode.value = false
  copySourceRuleId.value = null
  copySourceHostHeader.value = ''
  if (rule) {
    // 编辑态一律保留已存端口：DB 中的 listen_port 即用户显式配置，TLS/协议切换不再静默迁移端口
    userExplicitPort.value = true
    let fullRule: Rule = rule
    if (rule.enable_tls && rule.tls_source === 'manual') {
      try {
        const resp = await request.get<APIResponse<Rule>>(`/rules/${rule.caddy_id}`)
        // 过期返回直接 return，且不得在此复位 hydratingWizard——复位归属
        // 最新一次打开调用的生命周期（新建/无 GET 编辑同步复位；带 GET 的编辑/复制
        // 由自身新鲜请求走到函数尾部复位）。此处代为复位会拆掉在途新调用的
        // hydration 守卫，sync watch 会在半水合表单上误触发端口迁移。
        if (openSeq !== wizardOpenSeq) return
        if (resp.code === 0 && resp.data) {
          fullRule = resp.data
        }
    } catch (error: unknown) {
      // 与 try 路径同款 seq 守卫——过期请求的失败分支同样不得触碰
      // 在途表单（否则「新建」被过期 fullRule 覆盖，保存语义翻转为 PUT 更新既有规则）。
      // 过期分支同样不复位 hydratingWizard（归属最新调用的生命周期）。
      if (openSeq !== wizardOpenSeq) return
      console.warn('[openWizard] Failed to fetch cert data for', rule.caddy_id, error)
      markTlsDetailFailed(rule.caddy_id)
    }
    }
    editingRule.value = fullRule
    // 版本基线取水合用的那份行（手动 TLS 编辑时是 GET 的新鲜行）。
    editingRuleVersion.value = fullRule.updated_at || ''
    Object.assign(wizardForm, wizardFormFromRule(fullRule))
    wizardStagePageSnapshot.value = stageBlockPageOverrides(fullRule)
    weightsToPercent(wizardForm.upstreams)
    if (wizardForm.dynamic_dns) onDynamicDnsToggle(true)
  } else {
    editingRule.value = null
    editingRuleVersion.value = ''
    wizardStagePageSnapshot.value = newRuleWizardStageOverrides()
    Object.assign(wizardForm, {
      name: '',
      description: '',
      protocol: 'http',
      domain: '',
      listen_port: 80,
      strategy: 'weighted_round_robin',
      dynamic_dns: false,
      health_check_path: '',
      health_check_interval: 10,
      health_check_timeout: 2,
      health_check_healthy_threshold: 2,
      health_check_unhealthy_threshold: 3,
      enable_active_health_check: true,
      tcp_health_check_port: 0,
      tcp_proxy_protocol: false,
      tcp_try_duration: 0,
      tcp_try_interval: 250,
      health_check_host: '',
      dns_server: '',
      dns_family: ['ipv4'],
      upstreams: [defaultUpstream()],
      enable_tls: false,
      tls_source: 'manual',
      acme_config_id: undefined as number | undefined,
      ca_provider_id: 0,
      tls_cert: '',
      tls_key: '',
      tlsKeySet: false, // 私钥掩码态随表单重置（stale true 曾致新建/复制误显「已配置」）
      tls_http_redirect: false,
      enable_compress: false,
      compress_types: ['gzip'],
      request_body_max_size_mb: 0,
      upstream_keepalive_timeout: 0,
      server_tokens_hidden: 0,
      ntlm_compatible: 0,
      upstream_force_http1: 0,
      enable_dns_server: false,
      log_enabled: false,
      enabled: true,
      custom_routes_enabled: false,
      path_rules: [],
      proxy_dial_timeout: 0,
      proxy_response_header_timeout: 0,
      proxy_read_timeout: 0,
      proxy_write_timeout: 0,
      proxy_stream_timeout: 0,
      proxy_flush_interval: 0, // 此前重置族缺失：NTLM 开启后 flush=-1 为可达态，防 stale 泄漏进新建表单
      proxy_stream_close_delay: 0,
      // 「新建规则」必须清掉上一条规则（编辑/复制水合而来）的阶段
      // 拦截页覆盖——否则新规则静默继承旧规则的 stage1/stage3 页面与状态码。
      ...newRuleWizardStageOverrides(),
    })
  }
  hydratingWizard = false
  currentStep.value = WIZARD_STEP.BASIC
  wizardVisible.value = true
}

const resetWizard = () => {
  preTcpSnapshot = null
  userExplicitPort.value = false
  certValidationSessionSeq++
  certValidationSeq++
  resetCertInfo()
  wizardForm.tlsKeySet = false // 掩码态随向导重置
  // 关闭即作废证书详情重试会话（在途响应不得回填下一次打开的表单）
  tlsDetailSeq++
  tlsDetailLoading.value = false
  tlsDetailRuleId.value = ''
  // 关闭向导即清空私钥/证书明文（对齐 MFA secret 关闭即清先例）——
  // 两次打开之间不留明文于响应式状态/DevTools。
  wizardForm.tls_cert = ''
  wizardForm.tls_key = ''
  upstreamTouched.value = []
  editingRule.value = null
  editingRuleVersion.value = ''
  isCopyMode.value = false
  copySourceRuleId.value = null
  copySourceHostHeader.value = ''
  // 关闭向导同样清态——resetWizard 是下次「新建」之前的最后一道
  // 兜底（openWizard 新建分支已同源清零，两处共用 newRuleWizardStageOverrides）。
  Object.assign(wizardForm, newRuleWizardStageOverrides())
  wizardForm.enable_dns_server = false
  wizardForm.dns_server = ''
  currentStep.value = WIZARD_STEP.BASIC
}

const beforeWizardClose = (done: () => void): void => {
  if (!saving.value) done()
}

// Weights are shown and edited as percentages of enabled upstreams; the
// interlock keeps the enabled total at 100 so values stay meaningful.
const onWeightChange = (changedIdx: number): void => redistributeWeight(wizardForm.upstreams, changedIdx)

const weightsToPercent = (upstreams: UpstreamInput[]): void => normalizeWeights(upstreams)

const onDynamicDnsToggle = (enabled: string | number | boolean): void => {
  if (!Boolean(enabled)) return
  const enabledUpstreams = wizardForm.upstreams.filter((upstream) => upstream.enabled !== false)
  enabledUpstreams.slice(1).forEach((upstream) => {
    upstream.enabled = false
    upstream.weight = 0
  })
  const retained = enabledUpstreams[0]
  if (retained) retained.weight = 100
}

const validateEnabledUpstreams = (): string => {
  const enabledUpstreams = wizardForm.upstreams.filter((upstream) => upstream.enabled !== false)
  if (enabledUpstreams.length === 0) return '至少需要一个启用的上游服务器'
  if (wizardForm.dynamic_dns && enabledUpstreams.length !== 1) return '动态上游模式仅允许一个启用的上游服务器'
  if (wizardForm.dynamic_dns && wizardForm.dns_family.length === 0) return '动态上游模式至少需要选择一种协议栈'
  const totalWeight = enabledUpstreams.reduce((total, upstream) => total + (upstream.weight || 0), 0)
  if (totalWeight !== 100) return `启用的上游权重总和必须为 100%，当前为 ${totalWeight}%`
  return ''
}



const addUpstream = () => {
  if (wizardForm.upstreams.length >= MAX_UPSTREAM_ROWS) return
  const upstream = defaultUpstream(wizardForm.protocol === 'tcp' ? 'tcp' : 'http')
  upstream.weight = 0
  wizardForm.upstreams.push(upstream)
  // touched 与行数组等长（removeUpstream 已同步 splice）：新增行按「未触达」补齐，
  // 否则进入过上游步（touched 全 true）后新增行读 touched[i]=undefined → 空 host 不显红框。
  while (upstreamTouched.value.length < wizardForm.upstreams.length) upstreamTouched.value.push(false)
  redistributeWeight(wizardForm.upstreams, wizardForm.upstreams.length - 1)
}

const customRoutesPreview = (): string => {
  if (!wizardForm.custom_routes_enabled || wizardForm.path_rules.length === 0) return '禁用'
  const paths = wizardForm.path_rules.slice(0, 3).map((rule) => rule.path || '/').join('、')
  const suffix = wizardForm.path_rules.length > 3 ? ' 等' : ''
  return `${wizardForm.path_rules.length} 条 · ${paths}${suffix}`
}

const removeUpstream = (index: number) => {
  upstreamTouched.value.splice(index, 1) // touched 数组同步重排(防行索引漂移)
  wizardForm.upstreams.splice(index, 1)
  const lastEnabled = wizardForm.upstreams.findIndex(u => u.enabled)
  if (lastEnabled >= 0) {
    onWeightChange(lastEnabled)
  }
}

const onCustomRoutesToggle = (enabled: string | number | boolean): void => {
  if (Boolean(enabled) && wizardForm.path_rules.length === 0) {
    wizardForm.path_rules.push({ id: nextTemporaryPathRuleId, match_type: 'prefix', path: '/', upstream_path: '', sort_order: 0, upstreams: null, response_mode: 'forward', response_status: 200, response_body: '', response_content_type: '', redirect_to: '' })
    nextTemporaryPathRuleId -= 1
  }
  if (!enabled) wizardForm.path_rules = []
}

const updateRuleProxyTimeout = (field: keyof ProxyTimeoutConfig, value: number): void => {
  wizardForm[field] = value
}

// ── NTLM 兼容开关（2026-10-12 用户定稿）：开启=UI 修改器，7 字段全落库；
// 关闭/切 TCP=恢复默认（原值不保留记忆）。被接管控件呈灰态 + 「NTLM 接管」徽标 ──
const ntlmOn = computed(() => wizardForm.protocol === 'http' && wizardForm.ntlm_compatible === 1)

// 卡片集与提交白名单（allowedStrategies）同源——utils/strategyLabels 的
// STRATEGY_CARD_OPTIONS 与后端 validateStrategyForProtocol 白名单逐协议对齐
//（含 random/first；cookie 仅 HTTP）。曾各自维护：白名单放行的 random/first
// 在向导内无卡片高亮，点任意卡片即静默改写策略。
const strategyCardOptions = computed(() => strategyCardsForProtocol(wizardForm.protocol))

// 策略卡片图标：仅作视觉分区，语义以标题为准（六种策略一一对应，
// 新增策略必须同时补图标，缺失时回落到轮询图标而不是渲染空白）。
const STRATEGY_ICONS: Record<string, typeof Connection> = {
  weighted_round_robin: RefreshRight,
  least_conn: Connection,
  ip_hash: Location,
  random: Operation,
  first: Guide,
  cookie: Link,
}
const strategyIcon = (strategy: string) => STRATEGY_ICONS[strategy] ?? RefreshRight

// 策略卡片是自定义单选组（role=radiogroup + role=radio）：整组只留一个 tab stop
// （roving tabindex），方向键在可选项间移动并切换——与原生 radio 组/APG 一致，
// 不再要求逐张 Tab 且方向键无效。
const strategyLocked = (value: string): boolean => ntlmOn.value && value !== 'cookie'

const strategyCardRefs = new Map<string, HTMLElement>()
const setStrategyCardRef = (value: string, el: unknown): void => {
  if (el instanceof HTMLElement) strategyCardRefs.set(value, el)
  else strategyCardRefs.delete(value)
}

const strategyTabindex = (value: string): number =>
  rovingTabindex(strategyCardOptions.value.map((card) => card.value), wizardForm.strategy, strategyLocked, value)

const onStrategyKeydown = (event: KeyboardEvent): void => {
  if (event.repeat) return
  const next = nextRadioValue(strategyCardOptions.value.map((card) => card.value), wizardForm.strategy, strategyLocked, event.key)
  if (next === null) return
  event.preventDefault()
  selectStrategy(next)
  strategyCardRefs.get(next)?.focus()
}

const selectStrategy = (strategy: string): void => {
  if (ntlmOn.value || saving.value) return // NTLM 接管：策略锁定 cookie，其余卡片置灰不可选；保存中冻结选择
  wizardForm.strategy = strategy
}

const applyNtlmTakeover = (): void => {
  wizardForm.strategy = 'cookie'
  wizardForm.proxy_flush_interval = -1
  wizardForm.upstream_keepalive_timeout = 300
  wizardForm.upstream_force_http1 = 1
  wizardForm.tcp_try_duration = -1
  wizardForm.enable_active_health_check = false
}

const restoreNtlmDefaults = (): void => {
  wizardForm.strategy = 'weighted_round_robin'
  wizardForm.proxy_flush_interval = 0
  wizardForm.upstream_keepalive_timeout = 0
  wizardForm.upstream_force_http1 = 0
  wizardForm.tcp_try_duration = 0
  // 主动健康检查保持关闭（默认关，用户可再自行开启）——关闭弹框中明示
  wizardForm.enable_active_health_check = false
}

// NTLM 开关确认弹框（参照安全策略「更新迁移预演」范式：DialogHeader+分区清单+footer）
const ntlmConfirmVisible = ref(false)
const ntlmConfirmMode = ref<'on' | 'off'>('on')

const onNtlmToggle = (enabled: string | number | boolean): void => {
  ntlmConfirmMode.value = Boolean(enabled) ? 'on' : 'off'
  ntlmConfirmVisible.value = true // 开关由 model-value 驱动：取消则自动回弹零改动
}

const confirmNtlmToggle = (): void => {
  if (ntlmConfirmMode.value === 'on') {
    wizardForm.ntlm_compatible = 1
    applyNtlmTakeover()
  } else {
    wizardForm.ntlm_compatible = 0
    restoreNtlmDefaults()
  }
  ntlmConfirmVisible.value = false
}

// 代理超时区被接管字段（仅刷新间隔）：灰态 + 徽标 + 「立即透传」显示值
const proxyTimeoutFieldOverrides = computed(() => ntlmOn.value
  ? { proxy_flush_interval: { disabled: true, badge: 'NTLM 接管', note: '立即透传（-1 = 所有响应无缓冲）' } }
  : undefined)

const moveToAdjacentWizardStep = (direction: -1 | 1): void => {
  // 保存中冻结步骤前进/后退：请求在途时的编辑不会进入本次载荷
  if (saving.value) return
  const currentIndex = visibleWizardSteps.value.indexOf(currentStep.value)
  const targetStep = visibleWizardSteps.value[currentIndex + direction]
  if (targetStep !== undefined) currentStep.value = targetStep
}

// M33：与后端 handlers.go 同口径的 host:port 查重——不分启用状态（禁用行也会
// 随规则提交，重复行在保存时会被后端整单拒绝），空行按提交口径先行剔除。
const findDuplicateUpstream = (): { rowIndex: number; key: string } | null => {
  const seen = new Set<string>()
  for (const [index, upstream] of wizardForm.upstreams.entries()) {
    if (!upstream.host || !upstream.port) continue
    // 与后端 upstreamDedupeHost 同口径（IP 按地址语义归一、主机名 lower+trim）：
    // 2001:db8::1 与 2001:0db8:0:0:0:0:0:1 是同一个后端，漏判会让权重翻倍。
    const key = upstreamDedupeKey(upstream.host, upstream.port)
    if (seen.has(key)) return { rowIndex: index + 1, key }
    seen.add(key)
  }
  return null
}

// M34：主动健康检查路径必须以 / 开头——对齐后端按提交原串的校验（空串回退
// '/' 的既有逻辑不受影响；纯空白或非斜杠开头都会被后端拒绝，前端先拦）。
const hasInvalidActiveHealthCheckPath = (): boolean =>
  wizardForm.enable_active_health_check && !(wizardForm.health_check_path || '/').startsWith('/')

const nextStep = (): void => {
  if (currentStep.value === WIZARD_STEP.BASIC) {
    if (!wizardForm.name) {
      ElMessage.warning('请输入规则名称')
      return
    }
    if (wizardForm.protocol === 'http' && !wizardForm.domain) {
      ElMessage.warning('HTTP 协议必须填写域名')
      return
    }
    if (!wizardForm.listen_port) {
      ElMessage.warning('请输入监听端口')
      return
    }
    if (portWarning.value) {
      ElMessage.warning(portWarning.value)
      return
    }
    moveToAdjacentWizardStep(1)
    return
  }
  if (currentStep.value === WIZARD_STEP.TLS) {
    // 详情失败只影响「手动 TLS」的证书材料：切到 ACME 后证书正文不再参与保存，
    // 无条件的门会把用户钉死在 TLS 步（横幅文案本身也自述「手动 TLS 配置」）。
    if (tlsDetailError.value && wizardForm.tls_source === 'manual') {
      ElMessage.warning('证书详情加载失败：请先在 TLS 步骤点「重新加载」')
      return
    }
    if (wizardForm.tls_source === 'acme_dns' && !wizardForm.acme_config_id) {
      ElMessage.warning('请选择 DNS 提供商配置')
      return
    }
    // 掩码私钥（tlsKeySet=true）且未粘贴新私钥时允许通过——后端保留原值
    if (wizardForm.tls_source === 'manual' && (!wizardForm.tls_cert.trim() || (!wizardForm.tls_key.trim() && !wizardForm.tlsKeySet))) {
      ElMessage.warning(wizardForm.tls_cert.trim() ? '请上传证书和私钥（或粘贴新私钥以更换）' : '请上传证书和私钥')
      return
    }
    moveToAdjacentWizardStep(1)
    return
  }
  if (currentStep.value === WIZARD_STEP.UPSTREAMS) {
    upstreamTouched.value = wizardForm.upstreams.map(() => true)
    // 完整性门与提交口径对齐（只检查启用行；此处 touched 已全置 true，
    // 故与红框/警告共用同一谓词）：host 与 port 缺一不放过——提交侧按
    // host+port 过滤身份，端口清空行会被静默剔除。
    if (wizardForm.upstreams.some((u, i) => upstreamRowInvalid(u, i))) {
      ElMessage.warning(upstreamFieldWarning.value || '请填写所有已启用上游服务器的主机地址与端口')
      return
    }
    const validUpstreams = wizardForm.upstreams.filter(u => u.host && u.port)
    if (validUpstreams.length === 0) {
      ElMessage.warning('请至少添加一个有效的上游服务器')
      return
    }
    // Check if at least one upstream is enabled
    const upstreamError = validateEnabledUpstreams()
    if (upstreamError) {
      ElMessage.warning(upstreamError)
      return
    }
    // M33/M34：上游 host:port 查重与健康检查路径门在此步前置拦截（提交侧同款双保险）
    const duplicated = findDuplicateUpstream()
    if (duplicated) {
      ElMessage.error(`上游第 ${duplicated.rowIndex} 行重复：${duplicated.key}`)
      return
    }
    if (hasInvalidActiveHealthCheckPath()) {
      ElMessage.error('健康检查路径必须以 / 开头')
      return
    }
    moveToAdjacentWizardStep(1)
    return
  }
  if (currentStep.value === WIZARD_STEP.CUSTOM_ROUTES) {
    if (wizardForm.path_rules.length === 0) {
      ElMessage.warning('请至少添加一条路径规则')
      return
    }
    const pathRuleError = validatePathRules(wizardForm.path_rules)
    if (pathRuleError) {
      ElMessage.warning(pathRuleError)
      return
    }
  }
  if (currentStep.value === WIZARD_STEP.ADVANCED && wizardForm.dynamic_dns && wizardForm.dns_family.length === 0) {
    ElMessage.warning('动态上游模式至少需要选择一种协议栈')
    return
  }
  moveToAdjacentWizardStep(1)
}

const prevStep = (): void => {
  moveToAdjacentWizardStep(-1)
}

const submitWizard = async () => {
  if (isReadOnly.value || saving.value) return
  saving.value = true
  if (!wizardForm.name) {
    ElMessage.warning('请输入规则名称')
    saving.value = false
    return
  }
  // step 标题可点击跳步绕过步进校验——提交前镜像 BASIC 步
  // 的 domain/端口前置（后端 400 兜底仍在，但报错晚且不带定位）。
  if (wizardForm.protocol === 'http' && !wizardForm.domain) {
    ElMessage.warning('HTTP 协议必须填写域名')
    saving.value = false
    return
  }
  if (!wizardForm.listen_port) {
    ElMessage.warning('请输入监听端口')
    saving.value = false
    return
  }
  if (portWarning.value) {
    ElMessage.warning(portWarning.value)
    saving.value = false
    return
  }
  // TLS 步校验镜像（跳步绕过 nextStep 时提交前兜底）
  if (wizardForm.enable_tls && wizardForm.protocol === 'http') {
    // ACME 引用门同镜像——后端 validateRuleACMEReferences 在
    // enable_tls+acme_dns 且 acme_config_id=0 时返回 400；不在此前置拦截时
    // 从 TLS 步直接跳预览保存才报错，晚且无定位。
    if (wizardForm.tls_source === 'acme_dns' && !wizardForm.acme_config_id) {
      ElMessage.warning('请选择 DNS 提供商配置')
      saving.value = false
      return
    }
    // 补 tlsKeySet 豁免(与 nextStep TLS 步同款条件——掩码私钥未粘贴
    // 新私钥时允许通过, 契约:空 key+tlsKeySet=保留原私钥)
    if (!wizardForm.tls_cert?.trim() || (!wizardForm.tls_key?.trim() && !wizardForm.tlsKeySet)) {
      if (wizardForm.tls_source === 'manual') {
        ElMessage.warning('TLS 手动模式须上传证书与私钥')
        saving.value = false
        return
      }
    }
  }
  if (wizardForm.upstreams.length === 0) {
    ElMessage.warning('请至少添加一个上游服务器')
    saving.value = false
    return
  }
  if (wizardForm.upstreams.length > MAX_UPSTREAM_ROWS) {
    ElMessage.warning(`上游服务器最多允许 ${MAX_UPSTREAM_ROWS} 条`)
    saving.value = false
    return
  }
  // 启用上游完整性门（host+port；与步进门同谓词镜像——编辑态可点步标题跳步
  // 绕过 nextStep 的 UPSTREAMS 分支；缺此门时空 host/port 行被载荷过滤静默
  // 剔除，保存「成功」但规则少了上游）。touched 全置与步进门口径对齐，
  // 同时让红框标出待补行。
  upstreamTouched.value = wizardForm.upstreams.map(() => true)
  if (wizardForm.upstreams.some((u, i) => upstreamRowInvalid(u, i))) {
    ElMessage.warning(upstreamFieldWarning.value || '请填写所有已启用上游服务器的主机地址与端口')
    saving.value = false
    return
  }
  if (wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled) {
    // 提交门镜像步进门（nextStep 的 CUSTOM_ROUTES 分支同文案）：启用自定义路由
    // 却没有路径规则时，载荷会落 custom_routes_enabled=1 + path_rules=[]，
    // 预览却按空数组显示「禁用」——字段与文案相反的死配置。
    if (wizardForm.path_rules.length === 0) {
      ElMessage.warning('请至少添加一条路径规则')
      saving.value = false
      return
    }
    const pathRuleError = validatePathRules(wizardForm.path_rules)
    if (pathRuleError) {
      ElMessage.warning(pathRuleError)
      saving.value = false
      return
    }
  }

  const upstreamError = validateEnabledUpstreams()
  if (upstreamError) {
    ElMessage.warning(upstreamError)
    saving.value = false
    return
  }
  // M33：上游 host:port 查重（不分启用状态，同后端口径）
  const duplicated = findDuplicateUpstream()
  if (duplicated) {
    ElMessage.error(`上游第 ${duplicated.rowIndex} 行重复：${duplicated.key}`)
    saving.value = false
    return
  }
  // M34：主动健康检查路径必须以 / 开头
  if (hasInvalidActiveHealthCheckPath()) {
    ElMessage.error('健康检查路径必须以 / 开头')
    saving.value = false
    return
  }
  // 被动模式不展示超时输入，但校验与提交载荷
  // 不区分主动/被动——存量数据 timeout >= interval 时会被下面 历史 校验拦下，
  // 而输入框不可见=无处修改。保存前在被动模式把越界值钳到合法区间并显性提示
  // （后端不变式保留；主动模式仍走原校验与提示）。
  if (!wizardForm.enable_active_health_check) {
    const clampedTimeout = clampPassiveHealthCheckTimeout(wizardForm.health_check_interval, wizardForm.health_check_timeout)
    if (clampedTimeout.clamped) {
      ElMessage.info(`被动检查不展示「健康检查超时」：该值须小于间隔 ${wizardForm.health_check_interval} 秒，已自动从 ${wizardForm.health_check_timeout} 秒调整为 ${clampedTimeout.timeout} 秒`)
      wizardForm.health_check_timeout = clampedTimeout.timeout
    }
  }
  // health_check_timeout >= health_check_interval 校验——
  // 与后端 validateRuleFeatures同口径，不区分主动/被动场景。
  if (wizardForm.health_check_interval > 0
      && wizardForm.health_check_timeout > 0
      && wizardForm.health_check_timeout >= wizardForm.health_check_interval) {
    ElMessage.warning(`健康检查超时时间（${wizardForm.health_check_timeout} 秒）必须小于检查间隔（${wizardForm.health_check_interval} 秒）`)
    saving.value = false
    return
  }
  const allowedProtocols: readonly UpstreamProtocol[] = wizardForm.protocol === 'tcp' ? ['tcp', 'tls'] : ['http', 'https']
  if (wizardForm.upstreams.some(u => !allowedProtocols.includes(u.protocol))) {
    ElMessage.warning(`${wizardForm.protocol.toUpperCase()} 规则包含协议族不匹配的上游服务器`)
    saving.value = false
    return
  }
  // 混布门：HTTP 规则启用上游 http/https 混布
  // 会在 Caddy 池级 TLS 传输下使 http 上游静默全灭——保存前拦截
  if (wizardForm.protocol === 'http') {
    const enabledProtos = new Set(wizardForm.upstreams.filter(u => u.enabled !== false).map(u => u.protocol || 'http'))
    if (enabledProtos.has('http') && enabledProtos.has('https')) {
      ElMessage.warning('同一 HTTP 规则的启用上游协议须一致（http/https 混布时 http 上游会被 TLS 化而无法访问；如需共存请拆分为两条规则）')
      saving.value = false
      return
    }
  }
  // 逐上游回源域名（2026-10-10）：与后端 validateRulePayloadBeforeSave 同口径——
  // 纯主机名不带端口（端口已有独立配置列）、仅 HTTP 静态上游可用
  // 正则双份收敛为共享 isValidHostName（标签首尾 alnum、63/253 与后端对齐）
  for (const [index, upstream] of wizardForm.upstreams.entries()) {
    const origin = (upstream.origin_domain || '').trim()
    if (origin === '') continue
    if (wizardForm.protocol !== 'http') {
      ElMessage.warning(`上游 #${index + 1}：回源域名仅 HTTP 规则支持`)
      saving.value = false
      return
    }
    if (wizardForm.dynamic_dns) {
      ElMessage.warning(`上游 #${index + 1}：动态上游模式不支持回源域名（改写 Host 请经 API/MCP 设置规则级 host_header）`)
      saving.value = false
      return
    }
    if (!isValidHostName(origin)) {
      ElMessage.warning(`上游 #${index + 1}：回源域名 "${origin}" 无效（仅支持主机名，不带端口）`)
      saving.value = false
      return
    }
  }
  // 健康检查域名：probe Host 头，纯主机名不带端口（与后端同口径）
  const healthCheckHost = (wizardForm.health_check_host || '').trim()
  if (healthCheckHost !== '' && wizardForm.protocol === 'http' && !isValidHostName(healthCheckHost)) {
    ElMessage.warning(`健康检查域名 "${healthCheckHost}" 无效（仅支持主机名，不带端口）`)
    saving.value = false
    return
  }
  const allowedStrategies = strategyValuesForProtocol(wizardForm.protocol)
  if (!allowedStrategies.includes(wizardForm.strategy)) {
    ElMessage.warning(`${wizardForm.protocol.toUpperCase()} 规则包含协议族不匹配的负载策略`)
    saving.value = false
    return
  }
  // NTLM 兼容预校验（与后端 validateRuleFeatures 同口径；正常交互不可达，
  // 兜直改 DB/导入产生的失配态）
  if (wizardForm.protocol === 'http' && wizardForm.ntlm_compatible === 1 && wizardForm.strategy !== 'cookie') {
    ElMessage.warning('NTLM 兼容模式要求负载策略为 Cookie 会话保持')
    saving.value = false
    return
  }
  if (wizardForm.protocol === 'tcp' && wizardForm.ntlm_compatible === 1) {
    ElMessage.warning('TCP 规则不支持 NTLM 兼容模式（仅 HTTP 规则可用）')
    saving.value = false
    return
  }

  // 复制向导确认框双保存按钮（用户裁定）：「含安全策略」=副本携带源规则全部策略绑定；
  // 「仅负载规则」=副本不含任何安全策略绑定（需后绑定）。普通新建/编辑不受影响
  let copyWithBindings = false
  if (!editingRule.value && isCopyMode.value) {
    if (securityBindingsLoading.value || securityBindingsError.value) {
      ElMessage.warning(securityBindingsLoading.value ? '安全策略绑定加载中，请稍后再复制' : '安全策略绑定加载失败，请先重新加载后再复制')
      saving.value = false
      return
    }
    const sourceBoundCount = copySourceRuleId.value ? (securityBindings.value[copySourceRuleId.value] || []).length : 0
    try {
      await ElMessageBox.confirm(
        `复制规则 "${wizardForm.name}"：「含安全策略」副本携带源规则的全部 ${sourceBoundCount} 条策略绑定；「仅负载规则」副本不含任何安全策略绑定，保存后可到规则行「安全」再绑定。`,
        '复制确认',
        { type: 'warning', confirmButtonText: '含安全策略', cancelButtonText: '仅负载规则', distinguishCancelAndClose: true }
      )
      copyWithBindings = true
    } catch (e) {
      if (e === 'cancel') {
        copyWithBindings = false
      } else {
        // 关闭/ESC：放弃本次复制
        saving.value = false
        return
      }
    }
  } else {
    const action = editingRule.value ? '更新' : '创建'
    try {
      await ElMessageBox.confirm(
        `确定要${action}规则 "${wizardForm.name}" 吗？`,
        `${action}确认`,
        { type: 'warning', confirmButtonText: '确定', cancelButtonText: '取消' }
      )
    } catch (e) {
      saving.value = false
      return
    }
  }

  try {
    const validUpstreams = wizardForm.upstreams.filter(u => u.host && u.port).map(u => ({
      ...u,
      // 禁用行草稿权重为 0（变异契约），载荷边界经 payloadWeight
      // 送 1（后端 weight<1 已响亮 400，0→1 静默归一废除）。
      weight: payloadWeight(u),
      dynamic_dns: wizardForm.dynamic_dns,
      max_connections: u.max_connections ?? 0,
      // 动态上游模式回源域名不可用（后端同口径 400；UI 列已禁用，此处防 stale 值外泄）
      origin_domain: wizardForm.dynamic_dns ? '' : (u.origin_domain || ''),
    }))

    const data: UpdateRuleRequest = {
      name: wizardForm.name,
      // 编辑保存的乐观并发前置条件（仅编辑态有基线；新建/复制为空）。
      // 省略键=后端不校验（API/MCP 兼容），编辑态恒回传打开时基线。
      ...(editingRule.value && !isCopyMode.value && editingRuleVersion.value
        ? { expected_updated_at: editingRuleVersion.value }
        : {}),
      // 复制重建规则时必须显式携带源规则级回源 Host（省略=落空串）；
      // 编辑/新建不带该键——Update 的 nil=保留语义不需要，新建本就无覆盖。
      ...(isCopyMode.value ? { host_header: copySourceHostHeader.value } : {}),
      description: wizardForm.description,
      protocol: wizardForm.protocol,
      domain: wizardForm.domain,
      listen_port: wizardForm.listen_port,
      strategy: wizardForm.strategy,
      dynamic_dns: wizardForm.dynamic_dns,
      enable_dns_server: wizardForm.enable_dns_server,
      dns_server: wizardForm.dns_server,
      dns_family: wizardForm.dns_family.length === 2 ? 'both' : wizardForm.dns_family[0],
      health_check_path: wizardForm.enable_active_health_check ? (wizardForm.health_check_path || '/') : '',
      health_check_interval: wizardForm.health_check_interval,
      health_check_timeout: wizardForm.health_check_timeout,
      health_check_healthy_threshold: wizardForm.health_check_healthy_threshold,
      health_check_unhealthy_threshold: wizardForm.health_check_unhealthy_threshold,
      enable_active_health_check: wizardForm.enable_active_health_check,
      tcp_health_check_port: wizardForm.tcp_health_check_port || 0,
      tcp_proxy_protocol: wizardForm.protocol === 'tcp' && wizardForm.tcp_proxy_protocol,
      tcp_try_duration: wizardForm.tcp_try_duration || 0,
      tcp_try_interval: wizardForm.tcp_try_interval ?? 250,
      health_check_host: wizardForm.health_check_host || '',
      upstreams: validUpstreams,
      enable_tls: wizardForm.enable_tls,
      tls_source: wizardForm.tls_source,
      acme_config_id: wizardForm.acme_config_id || 0,
      ca_provider_id: Number(wizardForm.ca_provider_id || 0),
      tls_cert: wizardForm.tls_source === 'manual' ? wizardForm.tls_cert : '',
      tls_key: wizardForm.tls_source === 'manual' ? wizardForm.tls_key : '',
      tls_http_redirect: wizardForm.tls_http_redirect,
      enable_compress: wizardForm.enable_compress,
      compress_types: wizardForm.compress_types.join(',') || 'gzip',
      // 编辑态只提交相对打开快照变化的阶段页键（后端 *int nil=保留）；
      // 新建/复制显式全量（Create 无 nil 语义，副本需继承源覆盖）。
      ...((isCopyMode.value || !editingRule.value)
        ? stageBlockPageOverrides(wizardForm)
        : stageBlockPagePatch(wizardForm, wizardStagePageSnapshot.value)),
      request_body_max_size_mb: wizardForm.request_body_max_size_mb || 0,
      upstream_keepalive_timeout: wizardForm.upstream_keepalive_timeout || 0,
      server_tokens_hidden: wizardForm.server_tokens_hidden || 0,
      // NTLM 兼容：HTTP 规则显式 0/1（Update nil 合并语义下 undefined=保留原值，
      // 关闭 NTLM 必须落 0）；TCP 规则不上送 ntlm（设计定稿，后端恒归零兜底）
      ntlm_compatible: wizardForm.protocol === 'http' ? (wizardForm.ntlm_compatible === 1 ? 1 : 0) : undefined,
      upstream_force_http1: wizardForm.upstream_force_http1 === 1 ? 1 : 0,
      enabled: wizardForm.enabled,
      log_enabled: wizardForm.log_enabled || false,
      custom_routes_enabled: wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled,
      path_rules: wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled
        ? wizardForm.path_rules.map((pathRule, index) => ({
            ...(pathRule.id !== undefined && pathRule.id > 0 ? { id: pathRule.id } : {}),
            match_type: pathRule.match_type,
            path: pathRule.path,
            upstream_path: pathRule.upstream_path || '',
            sort_order: index,
            // 直接返回/301 跳转（2026-10-10）：'forward' 为 UI 哨兵（el-select 空串选项不显示标签），提交归一 ''
            ...(() => {
              const mode: '' | 'static' | 'redirect' = pathRule.response_mode === 'static' || pathRule.response_mode === 'redirect' ? pathRule.response_mode : ''
              return {
                response_mode: mode,
                response_status: mode === 'static' ? (pathRule.response_status || 200) : 200,
                response_body: mode === 'static' ? (pathRule.response_body || '') : '',
                response_content_type: mode === 'static' ? (pathRule.response_content_type || '') : '',
                redirect_to: mode === 'redirect' ? (pathRule.redirect_to || '') : '',
                upstreams: mode ? null : (pathRule.upstreams?.map((upstream) => ({ ...upstream })) || null),
              }
            })(),
          }))
        : [],
      proxy_dial_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_dial_timeout : 0,
      proxy_response_header_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_response_header_timeout : 0,
      proxy_read_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_read_timeout : 0,
      proxy_write_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_write_timeout : 0,
      proxy_stream_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_stream_timeout : 0,
      proxy_flush_interval: wizardForm.protocol === 'http' ? wizardForm.proxy_flush_interval : 0,
      proxy_stream_close_delay: wizardForm.protocol === 'http' ? wizardForm.proxy_stream_close_delay : 0,
    }

    let submitWarnings: string[] = []
    if (editingRule.value) {
      const updateRes = await request.put<APIResponse<{ warnings?: string[] }>>(`/rules/${editingRule.value.caddy_id}`, data)
      mfaAwareSuccess('更新成功')
      // 后端把「本次保存造成的可用性变化」放在 data.warnings（如 ACME 改域：
      // 旧证书已弃用、新证书签发完成前 HTTPS 不可用）。只弹 toast 等于没告知
      // ——这些披露描述的正是「保存成功后马上会遇到的故障」。
      submitWarnings = updateRes.data?.warnings ?? []

    } else {
      const createRes = await request.post<APIResponse<{ caddy_id: string }>>('/rules', data)
      // 复制路径（openCopyWizard 带入的源规则）：POST /rules 不经 /duplicate、不携带绑定——
      // 源绑定从 bindings 快照取经 PUT 复制到新规则；绑定失败不回滚副本（口径同策略绑定失败）
      let createMessage = createRes.message || '创建成功'
      const sourceId = isCopyMode.value ? copySourceRuleId.value : null
      const sourcePolicyIds = sourceId && copyWithBindings ? (securityBindings.value[sourceId] || []).map((b) => b.policy_id) : []
      const newCaddyId = createRes.data?.caddy_id
      if (sourceId && sourcePolicyIds.length > 0) {
        if (!newCaddyId) {
          console.error('copy bindings failed: create response missing caddy_id')
          ElMessage.error('副本已创建，策略绑定复制失败')
        } else {
          try {
            await request.put<APIResponse>(`/security/rules/${encodeURIComponent(newCaddyId)}/policies`, { policy_ids: sourcePolicyIds })
            createMessage += `，已携带 ${sourcePolicyIds.length} 条策略绑定`
          } catch (bindError: unknown) {
            console.error('copy bindings failed', bindError)
            ElMessage.error('副本已创建，策略绑定复制失败')
          }
        }
      }
      mfaAwareSuccess(createMessage)
    }
    wizardVisible.value = false
    fetchRules()
    if (submitWarnings.length > 0) {
      // 与设置页导入/还原同口径：披露逐条独立成行，用户必须确认后才消失
      // （可用性变化不是可忽略的提示条）。
      await ElMessageBox.alert(
        h('div', submitWarnings.map((warning) => h('div', warning))),
        '规则已更新，请留意',
        { confirmButtonText: '知道了', type: 'warning' },
      ).catch(() => undefined)
    }
  } catch (error: unknown) {
    // 版本前置条件冲突：他人已提交该规则，本表单是陈旧快照。刷新列表并
    // 提示重开——继续用旧表单重试只会重复 409（或在不带版本时静默覆盖）。
    if (error instanceof ApiRequestError && error.status === 409 && error.message.includes('规则已被他人修改')) {
      fetchRules()
      ElMessage.warning('规则已被他人修改，已刷新列表，请关闭向导后重新打开再编辑')
    }
    // Error message is already shown by the global axios interceptor.
    console.error('submit wizard failed', error)
  } finally {
    saving.value = false
  }
}

// ── 规则处理流程弹框：唯一入口 = 锁图标点击（已绑策略时显示） ──
const flowDialogVisible = ref(false)
const flowDialogTarget = ref<RuleFlowTarget | null>(null)
const flowDialogModel = ref<RuleStageModel | null>(null)


const upstreamSummaryForRule = (rule: Rule): string => {
  const count = getEnabledUpstreams(rule).length
  const health = healthStatus.value[rule.caddy_id]
  if (health && health.total > 0) return `${count} 个上游 · 健康 ${health.healthy}/${health.total}`
  return `${count} 个上游`
}

const openFlowDialog = (rule: Rule): void => {
  const health = healthStatus.value[rule.caddy_id]
  const upstreamHealth: RuleFlowTarget['upstreamHealth'] = {}
  if (health?.upstreams) {
    for (const [key, status] of Object.entries(health.upstreams)) {
      upstreamHealth[key] = { healthy: status.healthy, unknown: status.unknown, degraded: status.degraded, dynamic: status.dynamic }
    }
  }
  flowDialogTarget.value = {
    caddyId: rule.caddy_id,
    name: rule.name || rule.caddy_id,
    protocol: rule.protocol,
    listenPort: rule.listen_port,
    enableTls: rule.enable_tls,
    tlsSource: rule.tls_source,
    acmeConfigName: rule.tls_source === 'acme_dns' ? certConfigs.value.find((c) => c.id === rule.acme_config_id)?.name : undefined,
    // 全部域名（逗号分隔逐个 chip；TCP/空域名回落空数组，接入卡显示「-」）
    domains: (rule.domain || '').split(',').map((d) => d.trim()).filter((d) => d !== ''),
    hostHeader: rule.host_header || '',
    upstreamSummary: upstreamSummaryForRule(rule),
    upstreams: (rule.upstreams || []).map((u) => ({
      host: u.host,
      port: u.port,
      protocol: u.protocol,
      weight: u.weight,
      max_connections: u.max_connections ?? 0,
      enabled: u.enabled !== false,
    })),
    // 路由分发节点数据源：与健康浮层 healthPathRules 同门（仅 custom_routes_enabled）。
    // 静态返回 / 301 跳转的路径规则也投影（此前按「有上游」过滤，
    // 与预览「全部 path_rules 计数」口径分叉，且这两类路由在唯一呈现处完全不可见）；
    // PathRuleUpstream 无 enabled 概念，列出即生效
    // upstreams=null 原样保留，流程弹框据此显示「跟随主路由上游」。
    pathRules: healthPathRules(rule).map(projectRuleFlowPath),
    health: health ? { healthy: health.healthy, unhealthy: health.unhealthy, degraded: health.degraded, unknown: health.unknown, na: health.na, total: health.total } : undefined,
    upstreamHealth,
  }
  // TCP（阶段 0/1）与 HTTP 同构传模型：弹框按协议渲染阶段 2/3 灰态
  flowDialogModel.value = ruleStageModel(rule)
  flowDialogVisible.value = true
}

// ── 规则安全策略绑定（行「安全」按钮）——编辑交互在共享组件 SecurityBindingEditor 内
//（与策略页「绑定规则」同一组件，勿造第二份）；本页仅持有打开态
const bindDialogVisible = ref(false)
const bindDialogRule = ref<Rule | null>(null)

const openBindDialog = (rule: Rule): void => {
  if (securityBindingsLoading.value || securityBindingsError.value) {
    ElMessage.warning(securityBindingsLoading.value ? '安全策略绑定加载中，请稍后再试' : '安全策略绑定加载失败，请先重新加载')
    return
  }
  bindDialogRule.value = rule
  bindDialogVisible.value = true
}

const toggleRule = async (rule: Rule) => {
  if (isReadOnly.value) return
  if (ruleTogglePending.value[rule.caddy_id]) return
  const nextEnabled = rule.enabled
  const action = rule.enabled ? '启用' : '禁用'
  ruleTogglePending.value[rule.caddy_id] = true
  try {
    await ElMessageBox.confirm(`确定要${action}规则 "${rule.name}" 吗？`, `${action}确认`, { type: 'warning' })
    if (rule.enabled) {
      await request.post<APIResponse>(`/rules/${rule.caddy_id}/enable`)
    } else {
      await request.post<APIResponse>(`/rules/${rule.caddy_id}/disable`)
    }
    mfaAwareSuccess(`${action}成功`)
    await fetchRules()
  } catch (e) {
    // 回滚开关后必须回读列表：写其实已生效但响应丢失（网关 5xx/超时）时，
    // 只拨回本地状态会让页面与服务端长期相反——规则列表没有轮询可以兜底，
    // 回读是唯一能收敛到服务端事实的路径（与 Users 启停失败同口径）。
    rule.enabled = !nextEnabled
    void fetchRules()
  } finally {
    ruleTogglePending.value[rule.caddy_id] = false
  }
}

const deletingRuleId = ref<string | null>(null)
const deleteRule = async (rule: Rule) => {
  if (isReadOnly.value) return
  // 重入守卫（同 SecurityPolicies deletingPolicyId 范式）：快速双击
  // 不再叠加双确认框→双 DELETE 误报
  if (deletingRuleId.value !== null) return
  deletingRuleId.value = rule.caddy_id
  try {
    await ElMessageBox.confirm(`确定要删除规则 "${rule.name}" 吗？`, '删除确认', { type: 'warning' })
    await request.delete<APIResponse>(`/rules/${rule.caddy_id}`)
    mfaAwareSuccess('删除成功')
    fetchRules()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('delete rule failed', error)
  } finally {
    deletingRuleId.value = null
  }
}

const duplicateRule = async (rule: Rule) => {
  if (isReadOnly.value) return
  try {
    await ElMessageBox.confirm(`确定要复制规则 "${rule.name}" 吗？`, '复制确认', { type: 'info' })
    openCopyWizard(rule)
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('duplicate rule failed', error)
  }
}

const openCopyWizard = async (rule: Rule) => {
  if (saving.value) return
  // 同 openWizard 的序列号守卫——复制在途 GET 过期返回丢弃。
  const openSeq = ++wizardOpenSeq
  hydratingWizard = true
  preTcpSnapshot = null
  userExplicitPort.value = false
  certValidationSessionSeq++
  certValidationSeq++
  resetCertInfo()
  wizardForm.tlsKeySet = false // 掩码态随向导重置
  tlsDetailError.value = false
  // 证书详情重试会话换新：在途响应随旧会话失效
  tlsDetailSeq++
  tlsDetailLoading.value = false
  tlsDetailRuleId.value = ''
  upstreamTouched.value = []
  isCopyMode.value = true
  copySourceRuleId.value = rule.caddy_id
  // 复制是新建路径：显式清空编辑目标（submitWizard 以 editingRule 判定 PUT/POST，
  // 依赖调用前状态会在新入口出现时静默变成「改源规则」）。
  editingRule.value = null
  // 复制走 POST /rules（新建），不存在版本前置条件。
  editingRuleVersion.value = ''
  let fullRule: Rule = rule
  if (rule.enable_tls && rule.tls_source === 'manual') {
    try {
      const resp = await request.get<APIResponse<Rule>>(`/rules/${rule.caddy_id}`)
      // 同 openWizard——过期返回不复位 hydratingWizard（归属最新调用生命周期）。
      if (openSeq !== wizardOpenSeq) return
      if (resp.code === 0 && resp.data) fullRule = resp.data
    } catch (error: unknown) {
      // 与 try 路径同款 seq 守卫（详见 openWizard catch 处注释）。
      if (openSeq !== wizardOpenSeq) return
      // 不允许静默回退列表快照（证书记载缺失 → 保存会写空证书）
      console.warn('[openCopyWizard] Failed to fetch cert data for', rule.caddy_id, error)
      markTlsDetailFailed(rule.caddy_id)
    }
  }
  copySourceHostHeader.value = copyRuleHostHeader(fullRule)
  Object.assign(wizardForm, wizardFormFromRule(fullRule), {
    name: `${fullRule.name}（副本）`,
    enabled: false,
  })
  wizardStagePageSnapshot.value = stageBlockPageOverrides(fullRule)
  weightsToPercent(wizardForm.upstreams)
  if (wizardForm.dynamic_dns) onDynamicDnsToggle(true)
  hydratingWizard = false
  currentStep.value = WIZARD_STEP.BASIC
  wizardVisible.value = true
}

const viewConfig = async (rule: Rule) => {
  const targetId = rule.caddy_id
  const requestSeq = ++configRequestSeq
  configTargetRule.value = rule
  configDialogVisible.value = true
  configLoading.value = true
  configLoadError.value = ''
  ruleConfig.value = null
  try {
    // Get rule-specific Caddy config from API
    const res = await request.get<APIResponse<RuleCaddyConfigResponse>>(`/rules/${targetId}/caddy-config`)
    if (requestSeq !== configRequestSeq || !configDialogVisible.value) return
     
    ruleConfig.value = buildRuleConfigView(
      rule,
      res.data?.caddy_id || '',
      res.data?.config ?? null,
      res.data?.config_not_exists === true,
    )
  } catch (error: unknown) {
    if (requestSeq !== configRequestSeq || !configDialogVisible.value) return
    // Error message is already shown by the global axios interceptor; the dialog
    // keeps an independent visible error instead of presenting synthetic JSON.
    console.error('view config failed', error)
    configLoadError.value = error instanceof Error ? error.message : '获取配置失败'
  } finally {
    if (requestSeq === configRequestSeq) configLoading.value = false
  }
}
const retryViewConfig = (): void => {
  if (configTargetRule.value) void viewConfig(configTargetRule.value)
}

const onConfigDialogClosed = (): void => {
  configRequestSeq++
  configLoading.value = false
  configTargetRule.value = null
}

const openRuleLogDialog = (rule: Rule) => {
  ruleLogRequestSeq++
  ruleLogRuleName.value = rule.name || rule.caddy_id
  ruleLogCaddyId.value = rule.caddy_id
  ruleLogDialogVisible.value = true
}

const ruleLogTab = ref('log')
const ruleLogStats = ref<RuleLogStats | null>(null)
const ruleLogStatsLoading = ref(false)
const ruleLogStatsError = ref('')
const logStatsOffset = ref(0)
interface LogStatMaps extends LogStatBuckets {
  startedAt: string
}
const logStatsMaps = ref<LogStatMaps | null>(null)
const logStatsInFlight = ref(false)
const LOG_STAT_CHUNK_SIZE = 200

const generalizeUA = (ua: string): string => {
  if (!ua) return '-'
  let client = ''
  let version = ''
  const pick = (marker: string) => {
    const i = ua.indexOf(marker)
    if (i < 0) return ''
    const rest = ua.slice(i + marker.length)
    const m = rest.match(/^[\d.]+/)
    return m ? m[0].split('.')[0] : ''
  }
  if (ua.includes('Edg/')) { client = 'Edge'; version = pick('Edg/') }
  else if (ua.includes('Chrome/')) { client = 'Chrome'; version = pick('Chrome/') }
  else if (ua.includes('Firefox/')) { client = 'Firefox'; version = pick('Firefox/') }
  else if (ua.includes('Version/') && ua.includes('Safari/')) { client = 'Safari'; version = pick('Version/') }
  else if (ua.includes('curl/')) { client = 'curl'; version = pick('curl/') }
  else if (ua.includes('PostmanRuntime')) client = 'Postman'
  else if (ua.includes('python-requests')) client = 'Python Requests'
  else if (ua.includes('Go-http-client')) client = 'Go Client'
  if (!client) return ua
  let osName = ''
  if (ua.includes('Windows NT')) osName = 'Windows'
  else if (ua.includes('Mac OS X')) osName = 'macOS'
  else if (ua.includes('iPhone') || ua.includes('iPad')) osName = 'iOS'
  else if (ua.includes('Android')) osName = 'Android'
  else if (ua.includes('Linux')) osName = 'Linux'
  const ver = version ? ` ${version}` : ''
  return osName ? `${client}${ver} / ${osName}` : `${client}${ver}`
}

const consumeLogLine = (maps: LogStatBuckets, line: string) => {
  let entry: CaddyLogEntry
  try {
    entry = JSON.parse(line)
  } catch {
    return
  }
  const req = entry?.request
  if (!req) return
  let uri = req.uri || req.uri_path || '-'
  const qi = uri.indexOf('?')
  if (qi >= 0) uri = uri.slice(0, qi)
  let ua = req.user_agent || ''
  if (!ua && req.headers) {
    const list = req.headers['User-Agent']
    if (Array.isArray(list) && list.length) ua = list[0]
  }
  // total 与三桶的推进由 util 单点维护（recordLogStatEntry），不再手写 total++
  recordLogStatEntry(maps, {
    ip: req.client_ip || req.src_ip || req.src || req.remote_ip || '-',
    uri,
    ua: generalizeUA(ua),
  })
}

const consumeLogLinesChunked = async (
  lines: readonly string[],
  maps: LogStatBuckets,
  isCurrent: () => boolean,
): Promise<boolean> => {
  for (let start = 0; start < lines.length; start += LOG_STAT_CHUNK_SIZE) {
    if (!isCurrent()) return false
    const end = Math.min(start + LOG_STAT_CHUNK_SIZE, lines.length)
    for (let index = start; index < end; index++) {
      const line = lines[index]
      if (line?.trim()) consumeLogLine(maps, line)
    }
    if (end < lines.length) {
      await new Promise<void>((resolve) => setTimeout(resolve, 0))
      if (!isCurrent()) return false
    }
  }
  return isCurrent()
}

const topN = (m: Record<string, number>, n: number) =>
  Object.entries(m).map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, n)

// parseLogLineTimestamp 取访问日志行的 ts（秒，浮点）；非 JSON/缺失返回 null。
const parseLogLineTimestamp = (line: string): number | null => {
  try {
    const ts = JSON.parse(line)?.ts
    return typeof ts === 'number' && ts > 0 ? ts : null
  } catch {
    return null
  }
}

const rebuildStatsView = (m: LogStatMaps) => {
  ruleLogStats.value = {
    total: m.total,
    started_at: m.startedAt,
    top_ips: topN(m.ip, 20),
    top_uas: topN(m.ua, 20),
    top_uris: topN(m.uri, 20),
  }
}

const fetchLogStream = async () => {
  if (disposed || !ruleLogCaddyId.value || ruleLogStatsLoading.value || logStatsInFlight.value) return
  const targetId = ruleLogCaddyId.value
  const targetMaps = logStatsMaps.value
  const targetOffset = logStatsOffset.value
  const requestSeq = ++ruleLogRequestSeq
  if (!targetMaps) return
  logStatsInFlight.value = true
  try {
    const res = await request.get<APIResponse<RuleLogStreamData>>(`/rules/${targetId}/log-stream`, { params: { offset: targetOffset }, signal: healthPolling.signal, timeout: 8000, silent: true })
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId) return
    const lines: string[] = res.data?.lines || []
    if (lines.length) {
      const completed = await consumeLogLinesChunked(lines, targetMaps, () => (
        !disposed
        && requestSeq === ruleLogRequestSeq
        && ruleLogDialogVisible.value
        && ruleLogTab.value === 'stats'
        && ruleLogCaddyId.value === targetId
      ))
      if (!completed) return
      rebuildStatsView(targetMaps)
    }
    logStatsOffset.value = res.data?.offset ?? targetOffset
    ruleLogStatsError.value = ''
  } catch (error: unknown) {
    if (disposed || axios.isCancel(error) || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId) return
    console.error('Failed to fetch log stream:', error)
    ruleLogStatsError.value = error instanceof Error ? error.message : '请稍后重试'
  } finally {
    if (!disposed && requestSeq === ruleLogRequestSeq) logStatsInFlight.value = false
  }
}

const startLogStats = async () => {
  if (disposed) return
  // 激活去重：加载中的重复激活（重复 emit/快速切 tab）直接合并到在途轮，
  // 避免「第二次激活重置 offset=0 → 第一次响应被守卫丢弃 → 统计从全量历史重灌」。
  if (ruleLogStatsLoading.value) return
  const targetId = ruleLogCaddyId.value
  if (!targetId) return
  // 单飞锁随本轮请求所有权移交：错误态「重试」会自增 ruleLogRequestSeq，
  // 若此刻恰有流请求在途，其 finally 因 seq 失配跳过释放——不在此清锁则锁
  // 永久为 true，统计轮询此后每 tick 早退（面板静默冻结、无 loading/错误）。
  // 在途的旧请求同理因 seq/maps 失配不会写回。
  logStatsInFlight.value = false
  const requestSeq = ++ruleLogRequestSeq
  // 统计起始时间走 formatDate（配置时区口径），与页面其他时间戳一致，
  // 不再用浏览器本地时区的 toLocaleString（started_at 为直接渲染的预格式化文本）
  const maps: LogStatMaps = { ...createLogStatBuckets(), startedAt: formatDate(new Date().toISOString()) }
  logStatsMaps.value = maps
  ruleLogStats.value = null
  ruleLogStatsLoading.value = true
  ruleLogStatsError.value = ''
  logStatsOffset.value = 0
  try {
    const res = await request.get<APIResponse<RuleLogData>>(`/rules/${targetId}/logs`, { signal: healthPolling.signal, timeout: 8000, silent: true })
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId) return
    // 打开即统计已有最近 ≤1000 行历史（2026-10-30 用户裁定，取代旧的
    // 「只借 offset 不消费历史」口径）：content 为完整行（EOF 行对齐），
    // 消费后 offset=EOF，流式增量与之零重叠。
    const historyLines = (res.data?.content || '').split('\n').filter((line) => line.trim())
    if (historyLines.length) {
      const firstTs = parseLogLineTimestamp(historyLines[0])
      if (firstTs !== null) maps.startedAt = formatDate(new Date(firstTs * 1000).toISOString())
      const completed = await consumeLogLinesChunked(historyLines, maps, () => (
        !disposed && requestSeq === ruleLogRequestSeq && ruleLogDialogVisible.value && ruleLogTab.value === 'stats' && ruleLogCaddyId.value === targetId
      ))
      if (!completed) return
    }
    rebuildStatsView(maps)
    logStatsOffset.value = res.data?.offset ?? 0
  } catch (error: unknown) {
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId) return
    console.error('Failed to init log stats:', error)
    ruleLogStatsError.value = error instanceof Error ? error.message : '请稍后重试'
  } finally {
    if (!disposed && requestSeq === ruleLogRequestSeq) ruleLogStatsLoading.value = false
  }
}

// el-tabs 的 tab-change 载荷是 TabPaneName（string | number），这里只按名字比较，
// 参数类型跟随组件声明以免与组件的 emit 契约冲突。
const onRuleLogTabChange = (name: string | number) => {
  const tab = String(name)
  ruleLogRequestSeq++
  ruleLogTail.invalidate()
  logStatsInFlight.value = false
  ruleLogStatsLoading.value = false
  ruleLogStatsError.value = ''
  if (tab === 'stats') {
    startLogStats()
  } else {
    ruleLogContent.value = ''
    refreshRuleLogs()
  }
}

const onRuleLogDialogOpened = () => {
  ruleLogRequestSeq++
  ruleLogTab.value = 'log'
  refreshRuleLogs()
  startRuleLogPolling()
}

const onRuleLogDialogClosed = () => {
  ruleLogRequestSeq++
  // 关闭即停本地 5s 定时器——原实现只停 tail，定时器继续空转
  //（refreshRuleLogs 被 isActive/空 caddyId 挡掉，仍每 5s 白跑分发链）。
  stopRuleLogPolling()
  ruleLogTail.stop()
  ruleLogContent.value = ''
  ruleLogCaddyId.value = ''
  logStatsMaps.value = null
  ruleLogStats.value = null
  ruleLogStatsLoading.value = false
  ruleLogStatsError.value = ''
  logStatsOffset.value = 0
  logStatsInFlight.value = false
}

// 日志尾轮询收敛 useLogTailPolling 单源（取数/写回/滚底/单飞/会话
// 序号守卫）；定时器保留在本地——log/stats 双 tab 分支由 refreshRuleLogs 分发。
const ruleLogTail = useLogTailPolling({
  interval: 5000,
  content: ruleLogContent,
  container: ruleLogContainerRef,
  isActive: () => !disposed && ruleLogDialogVisible.value && ruleLogTab.value === 'log' && ruleLogCaddyId.value !== '',
  fetch: async () => {
    const targetId = ruleLogCaddyId.value
    if (!targetId) return null
    const res = await request.get<APIResponse<RuleLogData>>(`/rules/${targetId}/logs`, { signal: healthPolling.signal, silent: true })
    if (disposed || !ruleLogDialogVisible.value || ruleLogTab.value !== 'log' || ruleLogCaddyId.value !== targetId) return null
    return res.data?.content || ''
  },
  onError: (error) => { console.error('Failed to fetch rule logs:', error) },
})
const ruleLogLoading = ruleLogTail.loading

const startRuleLogPolling = () => {
  stopRuleLogPolling()
  if (ruleLogAutoRefresh.value) {
    ruleLogPollTimer = setInterval(refreshRuleLogs, 5000)
  }
}

const stopRuleLogPolling = () => {
  if (ruleLogPollTimer) {
    clearInterval(ruleLogPollTimer)
    ruleLogPollTimer = null
  }
}

const refreshRuleLogs = () => {
  // 后台标签页暂停轮询：定时器空转跳过，回到可见后的下一个 tick 立即补拉
  if (disposed || document.hidden) return
  if (ruleLogTab.value === 'stats') {
    fetchLogStream()
    return
  }
  void ruleLogTail.refresh()
}

watch(ruleLogAutoRefresh, (val) => {
  if (!ruleLogDialogVisible.value) return
  if (val) startRuleLogPolling()
  else stopRuleLogPolling()
})

// 健康轮询错误态（复用 usePollingErrorState，与证书任务轮询同口径）——
// 原实现仅 console，/config/health 失败时健康列回落「-」且无任何提示。
const healthPollingError = usePollingErrorState()
const healthPolling = usePollingTask(async (task) => {
  // 接入退避门（与 certJobsPolling 同口径）——横幅「自动重试已退避」
  // 与实际轮询一致；fetchHealthStatus 内部捕获并 recordError 不抛出，
  // 原轮询错误回调永不可达（死代码已删除）。
  if (!healthPollingError.canRun()) return
  await fetchHealthStatus(task.signal)
}, {
  interval: 15000,
})
const healthPollingErrorDescription = computed(() => {
  const lastError = formatDate(healthPollingError.lastErrorAt.value)
  const retryAt = formatDate(healthPollingError.retryAt.value)
  return retryAt ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}` : `最后错误：${lastError}`
})
const healthRetryLoading = ref(false)
const retryHealthPolling = async (): Promise<void> => {
  if (healthRetryLoading.value) return
  healthRetryLoading.value = true
  try {
    healthPollingError.resetBackoff()
    await healthPolling.run()
  } finally {
    healthRetryLoading.value = false
  }
}
const certPollingError = usePollingErrorState()
const certPollingErrorDescription = computed(() => {
  const lastError = formatDate(certPollingError.lastErrorAt.value)
  const retryAt = formatDate(certPollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const certJobsPolling = usePollingTask(async (task) => {
  if (!certPollingError.canRun()) return
  if (rules.value.some((rule) => rule.tls_source === 'acme_dns') || pendingCertInfoRefresh.size > 0) {
    await fetchCertJobs(task.signal)
  }
  certPollingError.clear()
}, {
  interval: 5000,
  onError: (error) => {
    console.error('Failed to poll certificate jobs:', error)
    certPollingError.recordError(error)
  },
})

const certRetryLoading = ref(false)
const retryCertPolling = async (): Promise<void> => {
  if (certRetryLoading.value) return
  certRetryLoading.value = true
  try {
    certPollingError.resetBackoff()
    await certJobsPolling.run()
  } finally {
    certRetryLoading.value = false
  }
}

watch(
  () => pagedRules.value.map((rule) => rule.caddy_id).join('\u0000'),
  () => void certJobsPolling.run(),
)

onMounted(() => {
  // 安全事件/策略页的「查看规则」交接改走 URL query（rs 参数），
  // 消费后 replaceState 清除——localStorage 通道在多标签/隐私模式下错乱。
  const rs = new URLSearchParams(window.location.search).get(DEEP_LINK_PARAMS.ruleSearch)
  if (rs) {
    searchQuery.value = rs
    window.history.replaceState(null, '', window.location.pathname)
  }
  void fetchRules(true)
  void fetchUsers()
  void fetchCertConfigs()
  void fetchCAProviders()
  void healthPolling.run()
  healthPolling.start()
  certJobsPolling.start()
})

onUnmounted(() => {
  disposed = true
  rulesRequestSeq++
  configRequestSeq++
  ruleLogRequestSeq++
  certInfoGeneration++
  // 弹框 OPEN 时 SPA 切页不会触发 @close——必须在此显式停 tail，
  // 否则 5s 定时器与整份组件闭包永久存活（isActive 已 false，轮次空转）。
  stopRuleLogPolling()
  ruleLogTail.stop()
})
</script>

<style scoped>
.table-toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; }
/* 表格密度（列宽重排 2026-09-21）：.cell 水平内边距 12→8px，12 列合计省 96px——
   总最小宽收敛进典型容器宽（消除横向滚动条）的前提项 */
.rules-table :deep(.el-table .cell) { padding: 0 6px; }
.search-input { width: 280px; }
/* .rules-pagination 已收敛 styles/main.css（四处逐字重复单源化） */
/* .polling-error-alert 已收敛 main.css（三处 scoped 逐字重复删除） */
/* .polling-error-title/.polling-error-meta 已收敛 main.css*/
/* .mode-row 自管标签行族已全量退役（2026-10-11 用户裁定：对齐统一走原生
 * el-form-item）——.mode-row-label/.mode-row-content/.required-mark 死 CSS 一并删除 */
/* .page-header/.header-left/.page-title/.title-icon/.page-desc 与
 * styles/main.css 全局定义逐字等价(字面值=对应 CSS 变量解析值),已删除 */


.rule-name-cell { display: flex; align-items: center; flex-wrap: nowrap; gap: 6px; white-space: nowrap; }
.acl-lock-icon { flex: 0 0 auto; cursor: pointer; }
/* 键盘焦点可见：锁图标是流程弹框的键盘入口（Enter/Space），默认 el-icon 无焦点环 */
.acl-lock-icon:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }
.acl-lock-icon.is-allow { color: var(--el-color-success); }
.acl-lock-icon.is-unbound { color: var(--el-color-warning); }
.rule-name-link { 
  font-weight: 500; 
  color: #111827; 
  cursor: pointer;
  text-decoration: none;
}
.rule-name-link:hover {
  color: #3b82f6;
}
.domain { font-family: monospace; color: #374151; }
.port { font-family: monospace; color: #374151; }
.tls-tag {
  min-width: 44px;
}
.port-warning { color: #eab308; }

/* 页内其余表格（日志统计等）单元格 padding——主规则表由更特异的
   .rules-table :deep(.el-table .cell)（0 6px）覆盖，两套密度为有意分层
   （主表 12 列宽收敛 vs 次表宽松，历史 B3 裁定保留并注明）*/
:deep(.el-table .cell) {
  padding: 0 10px;
}

/* Updater column */
.updater-name {
  color: #374151;
  font-size: 13px;
}

.updated-time {
  color: #6b7280;
  font-size: 12px;
}

/* Health tag */
.health-tag {
  cursor: pointer;
}

/* Health tooltip */
.health-tooltip {
  font-size: 12px !important;
  padding: 0 !important;
  margin: 0 !important;
  width: 100% !important;
}

.upstream-item {
  display: flex !important;
  flex-direction: row !important;
  align-items: center !important;
  justify-content: space-between !important;
  padding: 2px 0 !important;
  margin: 0 !important;
  gap: 4px !important;
  box-sizing: border-box !important;
  border-bottom: 1px solid #f3f4f6;
}

.upstream-item > * {
  flex-shrink: 0 !important;
}

.upstream-address {
  color: #4b5563;
  font-family: monospace;
  font-size: 12px;
  line-height: 1;
  flex: 1 !important;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.upstream-degraded {
  color: var(--el-color-warning);
}
.upstream-na {
  font-size: 11px;
  color: var(--el-text-color-secondary);
}


.upstream-item:last-child {
  border-bottom: none;
}

/* 路径规则自定义上游分组（健康 hover，2026-09-21 用户裁定） */
.path-rule-health-title { font-size: 11px; color: #9ca3af; margin: 6px 0 2px; }

.upstream-item-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.upstream-status {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.upstream-fails {
  font-size: 11px;
  color: #ef4444;
  font-weight: 500;
  line-height: 1;
}

.upstream-healthy {
  color: #22c55e;
  font-size: 14px;
}

.upstream-unhealthy {
  color: #ef4444;
  font-size: 14px;
}


/* Status switch */
.status-switch :deep(.el-switch__core) {
  margin: 0;
}

/* Operation buttons */
.operation-buttons {
  display: flex;
  gap: 5px;
  justify-content: center;
}
.operation-buttons .el-button {
  margin: 0;
  padding: 2px 1px;
  min-width: auto;
  line-height: 1;
}

.dynamic-dns-content {
  display: flex;
  align-items: center;
  gap: 8px;
}
/* Description input */
.description-input :deep(.el-textarea__inner) {
  min-height: 80px !important;
}

/* Certificate input */
.cert-input-wrapper {
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 100%;
}
.cert-textarea :deep(.el-textarea__inner) {
  min-height: 160px !important;
  font-family: monospace;
  font-size: 12px;
}
.paste-btn {
  align-self: flex-end;
}

.cert-info-container {
  margin: 8px 20px;
  max-width: calc(100% - 40px);
}

.cert-info-alert {
  margin-bottom: 8px;
  word-break: break-word;
}

.cert-expiry-warning {
  color: #e6a23c;
  font-weight: 600;
}

.cert-expiry-normal {
  color: #67c23a;
}


.wizard-steps { margin-bottom: 24px; }
.wizard-steps.is-clickable :deep(.el-step) { cursor: pointer; }

.wizard-content { min-height: min(350px, 55dvh); max-height: 55dvh; overflow-y: auto; padding-right: 8px; }

.step-content { padding: 8px 0; }

.step-content :deep(.el-form-item) {
  padding: 0 30px 0 20px;
}

.upstream-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 16px;
  margin-bottom: 12px;
  padding: 0 20px;
}

.upstream-table { width: 100%; margin-bottom: 8px; }
/* 上游表紧凑行高：列宽收窄后仍需让两行上游 + 负载策略卡落在首屏内，
   减少纵向滚动条出现概率。 */
.upstream-table :deep(.el-table__cell) { padding: 4px 0; }
.upstream-table :deep(.el-table__header th .cell) { padding: 0 6px; }
.upstream-table :deep(.el-table__body td .cell) { padding: 0 6px; }

.upstream-input { width: 100%; }
.upstream-input.is-error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px #f56c6c inset;
}
/* 端口列（数字输入框窄列）同红框：host 与 port 缺一都算该行无效 */
.upstream-input-small.is-error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px #f56c6c inset;
}
.upstream-input-small { width: 100%; }
/* 数字输入框左侧空白收敛（2026-10-10 两轮用户反馈，根因实证）：EP
   el-input-number 的 .el-input__wrapper 恒 padding 42px 双侧（为侧排 +/- 预留），
   controls-position=right 时左侧 42px 纯浪费——窄值居中/贴边都救不了，须收
   wrapper 层；右 31px 保留给右侧 spinner。内层同时左对齐。 */
.upstream-input-small :deep(.el-input__wrapper) { padding-left: 6px; padding-right: 24px; }
.upstream-input-small :deep(.el-input__inner) { padding-left: 0; text-align: left; }
/* 上游表列标题不换行（列宽按内容精修后防止标题折行） */
.upstream-table :deep(.el-table__header th .cell) { white-space: nowrap; }

/* 策略卡片：3 列紧凑网格。六张卡占两行（约 140px），比原先的整卡
   两行描述省出近 70px，避免弹框过早出现纵向滚动条；标题/描述统一基线，
   选中态用主色描边 + 图标底色 + 右上勾选，锁定态灰化。 */
.strategy-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  width: 100%;
  padding: 8px 20px 10px;
  box-sizing: border-box;
}

@media (max-width: 960px) {
  .strategy-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 560px) {
  .strategy-cards { grid-template-columns: minmax(0, 1fr); }
}

.strategy-card {
  min-width: 0;
  padding: 6px 10px;
  border: 1px solid var(--el-border-color);
  border-radius: 8px;
  background: var(--el-fill-color-blank);
  cursor: pointer;
  transition: border-color 0.18s ease, background-color 0.18s ease, box-shadow 0.18s ease;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 2px;
  min-height: 52px;
  box-sizing: border-box;
}

.strategy-card-head {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.strategy-card-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  flex: 0 0 20px;
  border-radius: 6px;
  background: var(--el-fill-color-light);
  color: var(--el-text-color-secondary);
  font-size: 13px;
  transition: background-color 0.18s ease, color 0.18s ease;
}

.strategy-card-title {
  flex: 1;
  min-width: 0;
  font-weight: 600;
  color: var(--el-text-color-primary);
  font-size: 13px;
  line-height: 18px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.strategy-card-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  flex: 0 0 16px;
}

.strategy-check-icon {
  color: var(--el-color-primary);
  font-size: 14px;
}

.strategy-card-desc {
  font-size: 11px;
  color: var(--el-text-color-secondary);
  line-height: 14px;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  overflow: hidden;
}

.compact-divider {
  margin: 12px 0 8px 0;
}

.compact-divider :deep(.el-divider__text) {
  font-size: 14px;
  font-weight: 500;
  padding: 0 8px;
}

.compact-divider :deep(.el-divider__line) {
  width: calc(50% - 30px);
}

.strategy-card:hover {
  border-color: var(--el-color-primary-light-5);
  background-color: var(--el-color-primary-light-9);
}

.strategy-card.active {
  border-color: var(--el-color-primary);
  background-color: var(--el-color-primary-light-9);
  box-shadow: 0 0 0 1px var(--el-color-primary) inset;
}

.strategy-card.active .strategy-card-icon {
  background: var(--el-color-primary-light-8);
  color: var(--el-color-primary);
}

/* NTLM 接管：非 cookie 策略卡片置灰禁点 */
.strategy-card.locked {
  opacity: 0.45;
  cursor: not-allowed;
}

.strategy-card.locked:hover {
  border-color: var(--el-border-color);
  background: var(--el-fill-color-blank);
}

.strategy-lock-icon {
  color: var(--el-color-primary);
  font-size: 14px;
}

.ntlm-switch-control {
  display: flex;
  align-items: center;
  gap: 8px;
}

.active-check-control {
  display: flex;
  align-items: center;
  gap: 8px;
}

.wizard-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

/* Config view dialog */
.config-view {
  font-size: 13px;
  width: 100%;
}

/* 2026-09-19 用户反馈:JSON 代码框沿用组件默认 max-height:70vh,弹框整体
   超出屏幕;收窄至 30vh(70→50→40→30 三次收窄),仅作用于本弹框,组件默认不变。 */
.config-view :deep(.prism-code) {
  max-height: 30vh;
}

.config-info {
  width: 100% !important;
}

.config-info :deep(.el-descriptions__table) {
  table-layout: fixed;
  width: 100% !important;
}

.config-info :deep(.el-descriptions__cell) {
  width: auto !important;
}

.config-info :deep(.el-descriptions__label) {
  width: 30% !important;
}

.config-info :deep(.el-descriptions__content) {
  width: 70% !important;
}

.stats-summary { margin-bottom: 14px; display: flex; align-items: center; }
.stats-state { min-height: 280px; display: flex; flex-direction: column; gap: 16px; padding: 12px 4px; }
.stats-grid { display: grid; grid-template-columns: 1fr 1.5fr 1.5fr; gap: 14px; }
.stats-grid > .dialog-panel + .dialog-panel { margin-top: 0; }
@media (max-width: 767px) {
  .stats-grid { grid-template-columns: 1fr; }
}
.stats-card { min-width: 0; }
.stats-count { color: var(--el-color-primary); font-weight: 600; }
.rule-log-viewer {
  height: 55vh;
  min-height: 300px;
  max-height: 650px;
  overflow: auto;
  padding: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.7;
  background: #0f172a;
  color: #e2e8f0;
  border: 1px solid #1e293b;
  border-radius: 0;
  white-space: pre-wrap;
}

.log-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.config-empty {
  padding: 20px 0;
}


.cert-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 6px;
  font-size: 13px;
  line-height: 1.4;
  gap: 8px;
}

.cert-label {
  color: #6b7280;
  flex-shrink: 0;
}

.cert-value {
  color: #1f2937;
  text-align: right;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 170px;
}

.cert-days {
  font-weight: 500;
}

.cert-days.valid {
  color: #10b981;
}

.cert-days.expiring {
  color: #f59e0b;
  font-weight: 600;
}

.cert-days.expired {
  color: #ef4444;
  font-weight: 600;
}

.cert-days.unknown {
  color: #9ca3af;
}

.cert-error {
  color: #ef4444;
  text-align: right;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 170px;
}
</style>

<!-- el-popover popper 挂载到 body，scoped 样式无法命中，单独非 scoped 块
     （阴影沿用 el-popover 默认 box-shadow token，与健康/证书 hover 框一致） -->
<style>

/* 锁 hover 阶段摘要：卡片化分组 + 阶段色阶标题行 */
.rule-lock-popper { padding: 10px 12px !important; max-height: 62vh; overflow-y: auto; }
.rule-lock-popper .lock-summary { display: flex; flex-direction: column; gap: 8px; }
.rule-lock-popper .lock-stage { border: 1px solid #ebeef5; border-radius: 8px; padding: 6px 10px; background: #fff; }
.rule-lock-popper .lock-stage-head { font-size: 12px; font-weight: 600; margin-bottom: 3px; }
.rule-lock-popper .lock-stage-head--s0 { color: var(--el-color-success); }
.rule-lock-popper .lock-stage-head--s1 { color: var(--el-color-primary); }
.rule-lock-popper .lock-stage-head--s2 { color: var(--el-color-warning); }
.rule-lock-popper .lock-stage-head--s3 { color: var(--el-color-danger); }
.rule-lock-popper .lock-stage-line { font-size: 12px; color: #374151; line-height: 1.8; }
.rule-lock-popper .lock-stage-empty { color: #b1b5bd; }
/* 策略小组：多策略同阶段时框式分区；单策略（is-compact）免框保持紧凑不加重层级 */
.rule-lock-popper .lock-policy-group { border: 1px solid #f3f4f6; border-radius: 6px; padding: 5px 8px; }
.rule-lock-popper .lock-policy-group + .lock-policy-group { margin-top: 6px; }
.rule-lock-popper .lock-policy-group.is-compact { border: none; padding: 0; }
.rule-lock-popper .lock-policy-group.is-disabled { opacity: 0.45; }
.rule-lock-popper .lock-policy-head { display: flex; align-items: center; gap: 6px; margin-bottom: 1px; }
.rule-lock-popper .lock-policy-name { font-size: 12px; font-weight: 500; color: #1f2937; }
.rule-lock-popper .lock-stage-row { display: flex; align-items: baseline; gap: 6px; font-size: 12px; color: #374151; line-height: 1.7; }
.rule-lock-popper .lock-row-label { flex: 0 0 auto; color: #9ca3af; }
.rule-lock-popper .lock-row-detail { min-width: 0; color: #374151; word-break: break-all; }
.rule-lock-popper .lock-summary-hint { font-size: 12px; color: #9ca3af; border-top: 1px dashed #e5e7eb; padding-top: 6px; }
/* NTLM 帮助 tooltip：popper 挂 body，须非 scoped */
.ntlm-help-popper { max-width: 360px; }
.ntlm-help-popper .ntlm-help-line { font-size: 12px; line-height: 1.7; }
.ntlm-confirm-body { padding: 2px 4px; }
.ntlm-confirm-title { font-size: 13px; color: var(--el-text-color-regular); margin-bottom: 6px; }
.ntlm-confirm-list { margin: 0 0 4px; padding-left: 18px; font-size: 13px; line-height: 2; color: var(--el-text-color-regular); }
.ntlm-confirm-list b { color: var(--el-text-color-primary); }
</style>
