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

    <el-alert v-if="certPollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert">
      <template #title>
        <div class="polling-error-title">
          <span>证书状态加载失败：{{ certPollingError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="loading" @click="retryCertPolling">立即重试</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ certPollingErrorDescription }}</div>
    </el-alert>

    <el-card>
      <div class="table-toolbar">
        <el-input v-model="searchQuery" placeholder="搜索规则名 / 域名 / 端口 / ID" clearable :prefix-icon="Search" class="search-input" />
      </div>
      <el-table :data="pagedRules" row-key="caddy_id" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <el-table-column prop="name" label="规则名称" min-width="140">
          <template #default="{ row }">
            <div class="rule-name-cell">
              <el-tooltip
                v-if="ruleProtections(row.caddy_id).length > 0"
                placement="top"
                effect="light"
              >
                <template #content>
                  <div class="cert-tooltip security-tooltip">
                    <div class="tooltip-title">安全防护已启用</div>
                    <div
                      v-for="group in ruleProtections(row.caddy_id)"
                      :key="group.key"
                      class="policy-group"
                      :class="{ 'is-disabled': !group.enabled }"
                    >
                      <div class="policy-group-header">
                        <span class="policy-order">#{{ group.order }}</span>
                        <span class="policy-name" :title="group.name">{{ group.name }}</span>
                        <el-tag v-if="group.blockPageActive" type="warning" size="small" effect="plain">拦截页生效中</el-tag>
                        <el-tag v-if="!group.enabled" type="info" size="small" effect="plain">已禁用</el-tag>
                      </div>
                      <div v-for="protection in group.rows" :key="protection.label" class="cert-row">
                        <span class="cert-label">{{ protection.label }}</span>
                        <span class="cert-value" :title="protection.detail">{{ protection.detail }}</span>
                      </div>
                    </div>
                  </div>
                </template>
                <el-icon
                  :size="14"
                  class="acl-lock-icon is-allow"
                  tabindex="0"
                ><Lock /></el-icon>
              </el-tooltip>
              <a class="rule-name-link" role="button" tabindex="0" @click.prevent="viewConfig(row)" @keydown.enter.prevent="viewConfig(row)" @keydown.space.prevent="viewConfig(row)">{{ row.name }}</a>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="domain" label="域名" min-width="200" show-overflow-tooltip>
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
        <el-table-column label="负载策略" width="100" align="center">
          <template #default="{ row }">
            <span>{{ getStrategyLabel(row.strategy) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="listen_port" label="端口" width="60" align="center">
          <template #default="{ row }">
            <span class="port">{{ row.listen_port }}</span>
          </template>
        </el-table-column>
        <el-table-column label="上游" width="60" align="center">
          <template #default="{ row }">
            <el-tag :type="row.dynamic_dns ? 'primary' : 'success'" size="small" effect="plain">
              {{ row.dynamic_dns ? '动态' : '静态' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="TLS" width="110" align="center">
          <template #default="{ row }">
            <el-popover
              v-if="row.enable_tls"
              placement="top"
              trigger="hover"
              :width="280"
              :disabled="!certInfoMap[row.caddy_id]"
            >
              <template #reference>
                <el-tag :type="tlsTagType(row)" size="small" effect="plain" class="tls-tag">
                  {{ tlsTagLabel(row) }}
                </el-tag>
              </template>
              <div class="cert-tooltip" v-if="certInfoMap[row.caddy_id]">
                <div class="tooltip-title">证书信息</div>
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
                  <!-- R66 D-N4：过期证书不渲染裸负数（「-1 天」易误读为已过期一整天） -->
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
        <el-table-column label="健康" width="80" align="center">
          <template #default="{ row }">
            <el-popover v-if="row.enabled && healthStatus[row.caddy_id]" placement="top" trigger="hover" :width="240">
              <template #reference>
                <el-tag :type="getHealthTagType(healthStatus[row.caddy_id])" size="small" effect="plain" class="health-tag">
                  {{ getHealthLabel(healthStatus[row.caddy_id]) }}
                </el-tag>
              </template>
              <div class="health-tooltip">
                <div class="tooltip-title">上游服务器状态</div>
                <template v-if="row.dynamic_dns">
                  <div v-for="(status, address) in healthStatus[row.caddy_id]?.upstreams || {}" :key="address" class="upstream-item">
                    <span class="upstream-address">{{ address }}</span>
                    <el-icon v-if="status.unknown" class="upstream-unknown"><QuestionFilled /></el-icon>
                    <el-icon v-else-if="status.degraded" class="upstream-degraded"><WarningFilled /></el-icon>
                    <el-icon v-else-if="status.healthy" class="upstream-healthy"><CircleCheckFilled /></el-icon>
                    <el-icon v-else class="upstream-unhealthy"><CircleCloseFilled /></el-icon>
                  </div>
                </template>
                <template v-else>
                  <div v-for="upstream in getEnabledUpstreams(row)" :key="upstream.id" class="upstream-item">
                    <div class="upstream-item-row">
                      <span class="upstream-address">{{ upstream.host }}:{{ upstream.port }}</span>
                      <span class="upstream-status">
                        <el-icon v-if="getUpstreamHealthStatus(row.caddy_id, upstream).unknown" class="upstream-unknown"><QuestionFilled /></el-icon>
                        <el-icon v-else-if="getUpstreamHealthStatus(row.caddy_id, upstream).degraded" class="upstream-degraded"><WarningFilled /></el-icon>
                        <el-icon v-else-if="getUpstreamHealthStatus(row.caddy_id, upstream).healthy" class="upstream-healthy"><CircleCheckFilled /></el-icon>
                        <el-icon v-else class="upstream-unhealthy"><CircleCloseFilled /></el-icon>
                        <span v-if="getUpstreamMetrics(row.caddy_id, upstream).fails > 0" class="upstream-fails">失败 {{ getUpstreamMetrics(row.caddy_id, upstream).fails }}</span>
                      </span>
                    </div>
                  </div>
                </template>
              </div>
            </el-popover>
            <el-tag v-else-if="!row.enabled" type="info" size="small" effect="plain">-</el-tag>
            <span v-else class="text-secondary">-</span>
          </template>
        </el-table-column>
        <el-table-column label="更新者" width="80" align="center">
          <template #default="{ row }">
            <span class="updater-name">{{ getUpdaterName(row.updated_by || row.created_by) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="更新时间" width="160" align="center">
          <template #default="{ row }">
            <span class="updated-time">{{ formatUpdatedTime(row.updated_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="70" align="center">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              :loading="ruleTogglePending[row.caddy_id]"
              :disabled="isReadOnly || isCertJobActive(certJobMap[row.caddy_id]?.status) || ruleTogglePending[row.caddy_id]"
              @change="toggleRule(row)"
              class="status-switch"
            />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="225" fixed="right" align="center">
          <template #default="{ row }">
            <div class="operation-buttons">
              <el-tooltip
              :disabled="!isReadOnly && canEditRule(row)"
              :content="isReadOnly ? authStore.readOnlyMessage : '证书申请中，请等待完成或失败后再修改规则'"
              >
                <div>
                <el-button type="primary" link size="small" @click="openWizard(row)" :disabled="isReadOnly || saving || !canEditRule(row)">
                    编辑
                  </el-button>
                </div>
              </el-tooltip>
              <div>
              <el-button type="primary" link size="small" :disabled="isReadOnly || saving" @click="duplicateRule(row)">
                  复制
                </el-button>
              </div>
              <div>
                <el-button type="primary" link size="small" :disabled="!row.log_enabled" @click="openRuleLogDialog(row)">
                  日志
                </el-button>
              </div>
              <el-tooltip
                :disabled="!isReadOnly && canEditRule(row)"
                :content="isReadOnly ? authStore.readOnlyMessage : '证书申请中，请等待完成或失败后再删除规则'"
              >
                <div>
                <el-button type="danger" link size="small" @click="deleteRule(row)" :disabled="isReadOnly || !canEditRule(row)">
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

    <el-dialog v-model="wizardVisible" :title="editingRule ? '编辑规则' : (isCopyMode ? '复制规则' : '新建规则')" width="min(800px, 94vw)" top="5vh" :close-on-click-modal="false" :before-close="beforeWizardClose" @close="resetWizard">
      <el-steps :active="visualStepIndex" finish-status="success" align-center class="wizard-steps">
        <el-step title="基本配置" :icon="InfoFilled" />
        <el-step v-if="showTlsStep" title="TLS 配置" :icon="Lock" />
        <el-step title="上游服务器" :icon="Connection" />
        <el-step v-if="showCustomRoutesStep" title="自定义路由" :icon="Guide" />
        <el-step title="高级选项" :icon="Setting" />
        <el-step title="预览保存" :icon="Check" />
      </el-steps>

      <div class="wizard-content">
        <!-- Step 0: 基本配置 -->
        <div v-show="currentStep === WIZARD_STEP.BASIC" class="step-content">
          <el-form :model="wizardForm" label-width="100px">
            <el-form-item label="规则名称" required>
              <el-input v-model="wizardForm.name" placeholder="例如：我的网站负载均衡" />
            </el-form-item>
            
            <el-form-item label="协议" required>
              <el-radio-group v-model="wizardForm.protocol">
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
            </el-form-item>

            <el-form-item label="后端域名" v-if="wizardForm.protocol === 'http'">
              <el-input v-model="wizardForm.host_header" placeholder="例如：www.baidu.com" style="width: 300px;" />
              <span class="form-tip-inline">设置转发到上游服务器时的 Host 头</span>
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
          <el-form :model="wizardForm" label-width="100px" v-if="wizardForm.enable_tls && wizardForm.protocol === 'http'">
            <el-form-item label="证书来源">
              <el-radio-group v-model="wizardForm.tls_source" :disabled="isCurrentRuleLocked">
                <el-radio value="manual">手动上传</el-radio>
                <el-radio value="acme_dns">ACME + DNS 自动</el-radio>
              </el-radio-group>
              <div v-if="isCurrentRuleLocked" class="form-tip-line port-warning">证书申请中，暂不能修改证书来源</div>
            </el-form-item>
            <template v-if="wizardForm.tls_source === 'acme_dns'">
              <el-form-item label="DNS 配置">
                <el-select v-model="wizardForm.acme_config_id" placeholder="选择 DNS 提供商配置" style="width: 100%;">
                  <el-option v-for="cfg in certConfigs" :key="cfg.id" :label="cfg.name" :value="cfg.id" />
                </el-select>
                <div class="form-tip-line">请先在「系统设置 / 免费证书」中添加 DNS 提供商配置</div>
              </el-form-item>
              <el-form-item label="CA 提供商">
                <el-select v-model="wizardForm.ca_provider_id" placeholder="系统默认" clearable style="width: 100%">
                  <el-option label="系统默认" :value="0" />
                  <el-option v-for="p in enabledCAProviders" :key="p.id" :label="p.name" :value="p.id" />
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
                    placeholder="-----BEGIN PRIVATE KEY-----..." 
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
                <!-- Success or Warning with info -->
                <el-alert
                  v-if="certInfo.valid"
                  :type="certInfo.warning ? 'warning' : 'success'"
                  :closable="false"
                  class="cert-info-alert"
                >
                  <template #title>
                    <div class="cert-info-title">
                      {{ certInfo.warning ? '证书验证通过（有警告）' : '证书验证通过' }}
                    </div>
                    <div class="cert-info-detail">
                      域名: {{ certInfo.domain }} | 
                      过期时间: {{ certInfo.expiryDate }} 
                      <span v-if="certInfo.daysUntilExpiry <= 30" class="cert-expiry-warning">
                        (剩余 {{ certInfo.daysUntilExpiry }} 天)
                      </span>
                      <span v-else class="cert-expiry-normal">
                        (剩余 {{ certInfo.daysUntilExpiry }} 天)
                      </span>
                    </div>
                    <div v-if="certInfo.warning" class="cert-warning-text">
                      ⚠️ {{ certInfo.warning }}
                    </div>
                  </template>
                </el-alert>
                
                <!-- Error only -->
                <el-alert
                  v-if="certInfo.error"
                  :title="certInfo.error"
                  type="error"
                  :closable="false"
                  class="cert-info-alert"
                />
              </div>
            </template>
            <el-form-item label="HTTP 重定向">
              <el-switch v-model="wizardForm.tls_http_redirect" />
              <span class="form-tip-inline">将 HTTP 请求自动重定向到 HTTPS</span>
            </el-form-item>
          </el-form>
          <el-alert v-if="wizardForm.protocol === 'http' && !wizardForm.enable_tls" type="info" :closable="false" title="请先在基本配置中启用 HTTPS" style="margin-top: 20px;" />
        </div>

        <!-- Step 2: 上游服务器 -->
        <div v-show="currentStep === WIZARD_STEP.UPSTREAMS" class="step-content">
          <el-form :model="wizardForm" label-width="100px">
            <div class="upstream-header">
              <span class="section-title">上游服务器列表</span>
              <el-button size="small" type="primary" @click="addUpstream" :disabled="wizardForm.upstreams.length >= MAX_UPSTREAM_ROWS || (wizardForm.dynamic_dns && wizardForm.upstreams.length >= 1)">
                <el-icon><Plus /></el-icon>添加上游
              </el-button>
            </div>
            <el-alert v-if="wizardForm.dynamic_dns" type="info" :closable="false" title="动态上游模式下仅需一个上游条目，DNS 将动态解析出多个 IP" style="margin-bottom: 12px;" />

            <el-table :data="wizardForm.upstreams" border class="upstream-table" :fit="true">
              <el-table-column label="主机地址 *" min-width="180">
                <template #default="{ row, $index }">
                  <el-input 
                    v-model="row.host" 
                    placeholder="IP 或域名" 
                    size="small" 
                    class="upstream-input"
                    :class="{ 'is-error': upstreamRowNeedsHost(row, $index) }"
                    @blur="upstreamTouched[$index] = true"
                  />
                </template>
              </el-table-column>
              <el-table-column label="端口" width="110">
                <template #default="{ row }">
                  <el-input-number v-model="row.port" :min="1" :max="65535" size="small" controls-position="right" class="upstream-input-small" />
                </template>
              </el-table-column>
              <el-table-column label="协议" width="100">
                <template #default="{ row }">
                  <el-select v-model="row.protocol" size="small" placeholder="协议">
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
              <el-table-column label="权重 %" width="110">
                <template #default="{ row, $index }">
                  <el-input-number v-model="row.weight" :min="0" :max="100" size="small" controls-position="right" class="upstream-input-small" :disabled="!row.enabled" @change="onWeightChange($index)" />
                </template>
              </el-table-column>
              <el-table-column label="最大连接" width="120">
                <template #default="{ row }">
                  <el-input-number v-model="row.max_connections" :min="0" :max="100000" size="small" controls-position="right" class="upstream-input-small" />
                </template>
              </el-table-column>
              <el-table-column label="启用" width="60" align="center">
                <template #default="{ row, $index }">
                  <el-switch v-model="row.enabled" size="small" @change="onWeightChange($index)" />
                </template>
              </el-table-column>
              <el-table-column width="50" align="center">
                <template #default="{ $index }">
                  <el-button type="danger" link size="small" @click="removeUpstream($index)">
                    <el-icon><Delete /></el-icon>
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
            <div class="form-tip-line">
              <span v-if="upstreamHostWarning" class="port-warning">{{ upstreamHostWarning }}</span>
              <span v-else>权重：数字越大，分配到的请求越多；权重相同时即为普通轮询。至少需要添加一个上游服务器。</span>
            </div>

            <template v-if="wizardForm.protocol === 'http'">
              <el-divider content-position="left" class="compact-divider">自定义路由</el-divider>
              <el-form-item label="自定义路由">
                <el-switch v-model="wizardForm.custom_routes_enabled" @change="onCustomRoutesToggle" />
                <span class="form-tip-inline">开启后在下一步配置按路径转发规则</span>
              </el-form-item>
            </template>

            <el-divider content-position="left" class="compact-divider">负载策略</el-divider>

            <div class="strategy-cards">
              <div 
                class="strategy-card" 
                :class="{ active: wizardForm.strategy === 'weighted_round_robin' }"
                @click="wizardForm.strategy = 'weighted_round_robin'"
              >
                <div class="strategy-card-title">轮询</div>
                <div class="strategy-card-desc">按上游权重比例分配，权重相同即为普通轮询</div>
              </div>
              <div 
                class="strategy-card" 
                :class="{ active: wizardForm.strategy === 'least_conn' }"
                @click="wizardForm.strategy = 'least_conn'"
              >
                <div class="strategy-card-title">最少连接</div>
                <div class="strategy-card-desc">优先分配给连接数最少的服务器</div>
              </div>
              <div 
                class="strategy-card" 
                :class="{ active: wizardForm.strategy === 'ip_hash' }"
                @click="wizardForm.strategy = 'ip_hash'"
              >
                <div class="strategy-card-title">IP 哈希</div>
                <div class="strategy-card-desc">按客户端 IP 固定分配</div>
              </div>
              <div 
                v-if="wizardForm.protocol === 'http'"
                class="strategy-card" 
                :class="{ active: wizardForm.strategy === 'cookie' }"
                @click="wizardForm.strategy = 'cookie'"
              >
                <div class="strategy-card-title">Cookie 粘滞</div>
                <div class="strategy-card-desc">通过 Cookie 实现精确会话粘滞</div>
              </div>
            </div>

            <el-divider content-position="left" class="compact-divider">健康检查</el-divider>

            <el-form-item label="失败阈值">
              <el-input-number v-model="wizardForm.health_check_unhealthy_threshold" :min="1" :max="10" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">次失败后标记为不健康（被动计数与主动探测共用）</span>
            </el-form-item>


            <el-form-item label="检查间隔">
              <el-input-number v-model="wizardForm.health_check_interval" :min="5" :max="300" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">秒，主动探测间隔；被动失败记忆窗口为其 3 倍</span>
            </el-form-item>

            <template v-if="wizardForm.protocol === 'http'">
              <el-form-item label="超时时间">
                <el-input-number v-model="wizardForm.health_check_timeout" :min="1" :max="30" controls-position="right" style="width: 120px;" />
                <span class="form-tip-inline">秒，连接/健康检查超时</span>
              </el-form-item>

              <el-form-item label="主动检查">
                <div class="active-check-control">
                  <el-switch v-model="wizardForm.enable_active_health_check" />
                  <span class="form-tip-inline">{{ wizardForm.enable_active_health_check ? '周期探测，异常节点持续摘除直至恢复（推荐）' : '仅被动熔断，异常节点会周期恢复并重新接收流量' }}</span>
                </div>
              </el-form-item>

              <template v-if="wizardForm.enable_active_health_check">
                <el-form-item label="检查路径">
                  <el-input v-model="wizardForm.health_check_path" placeholder="默认 /" style="width: 180px;" />
                  <span class="form-tip-inline">留空探测 /，需返回 2xx 否则判为异常；携带后端域名作为 Host 头</span>
                </el-form-item>
                <el-form-item label="恢复阈值">
                  <el-input-number v-model="wizardForm.health_check_healthy_threshold" :min="1" :max="10" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">次连续探测成功后恢复为健康</span>
                </el-form-item>
              </template>
            </template>

            <template v-if="wizardForm.protocol === 'tcp'">
              <el-form-item label="超时时间">
                <el-input-number v-model="wizardForm.health_check_timeout" :min="1" :max="30" controls-position="right" style="width: 120px;" />
                <span class="form-tip-inline">秒，TCP 连接/健康检查超时</span>
              </el-form-item>

              <el-form-item label="主动检查">
                <div class="active-check-control">
                  <el-switch v-model="wizardForm.enable_active_health_check" />
                  <span class="form-tip-inline">{{ wizardForm.enable_active_health_check ? '周期探测上游端口，异常节点持续摘除直至恢复（推荐）' : '仅被动熔断，异常节点会周期恢复并重新接收流量' }}</span>
                </div>
              </el-form-item>

              <template v-if="wizardForm.enable_active_health_check">
                <el-form-item label="检查端口">
                  <el-input-number v-model="wizardForm.tcp_health_check_port" :min="1" :max="65535" controls-position="right" style="width: 120px;" />
                  <span class="form-tip-inline">0 表示使用第一个上游端口</span>
                </el-form-item>
                <el-form-item label="恢复阈值">
                  <el-input-number v-model="wizardForm.health_check_healthy_threshold" :min="1" :max="10" controls-position="right" style="width: 120px;" />
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
          <el-form :model="wizardForm" label-width="130px">
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
                  <el-input v-model="wizardForm.dns_server" placeholder="例如：8.8.8.8 或 223.5.5.5" style="width: 200px;" />
                  <span class="form-tip-inline">用于解析上游服务器域名的 DNS 服务器</span>
                </el-form-item>
              </template>

              <el-divider content-position="left" class="compact-divider">压缩配置</el-divider>

              <el-form-item label="启用压缩">
                <div class="dynamic-dns-content">
                  <el-switch v-model="wizardForm.enable_compress" />
                  <span class="form-tip-inline">启用后，响应将被压缩传输以减少带宽</span>
                </div>
              </el-form-item>
              <el-form-item label="压缩方式" v-if="wizardForm.enable_compress">
                <el-radio-group v-model="compressType">
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
                  <el-checkbox-group v-model="wizardForm.dns_family" style="width: 200px;">
                    <el-checkbox value="ipv4">IPv4</el-checkbox>
                    <el-checkbox value="ipv6">IPv6</el-checkbox>
                  </el-checkbox-group>
                </el-form-item>
              </template>

              <el-divider content-position="left" class="compact-divider">代理超时</el-divider>
              <ProxyTimeoutFields :value="wizardForm" inherit-label="全局" @update="updateRuleProxyTimeout" />
            </template>

            <template v-if="wizardForm.protocol === 'tcp'">
              <el-divider content-position="left" class="compact-divider">连接重试</el-divider>

              <el-form-item label="重试窗口">
                <el-input-number v-model="wizardForm.tcp_try_duration" :min="0" :max="60000" controls-position="right" style="width: 120px;" />
                <span class="form-tip-inline">毫秒，0 表示不重试；连接失败后在窗口期内尝试其他上游</span>
              </el-form-item>

              <el-form-item label="重试间隔">
                <el-input-number v-model="wizardForm.tcp_try_interval" :min="0" :max="10000" controls-position="right" style="width: 120px;" />
                <span class="form-tip-inline">毫秒，每次重试间隔；0 表示使用 Caddy 默认间隔</span>
              </el-form-item>

              <el-form-item label="PROXY V2">
                <el-switch v-model="wizardForm.tcp_proxy_protocol" />
                <span class="form-tip-inline">开启后向上游发送 PROXY v2 协议头传递真实客户端 IP，需后端支持</span>
              </el-form-item>
            </template>

            <el-divider content-position="left" class="compact-divider">Caddy 全局覆盖</el-divider>

            <el-form-item label="请求体大小">
              <el-input-number v-model="wizardForm.request_body_max_size_mb" :min="0" :max="10240" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">MB，0 = 全局默认；限制单个请求体的最大大小</span>
            </el-form-item>

            <el-form-item label="Keepalive 超时">
              <el-input-number v-model="wizardForm.upstream_keepalive_timeout" :min="0" :max="3600" controls-position="right" style="width: 120px;" />
              <span class="form-tip-inline">秒，0 = 全局默认；与上游服务器长连接的空闲超时</span>
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
            <el-descriptions-item label="后端域名" v-if="wizardForm.protocol === 'http'">{{ wizardForm.host_header || '-' }}</el-descriptions-item>
            <el-descriptions-item label="负载策略">{{ getStrategyLabel(wizardForm.strategy) }}</el-descriptions-item>
            <el-descriptions-item label="健康检查" v-if="wizardForm.protocol === 'http'">
              <template v-if="wizardForm.enable_active_health_check">
                {{ wizardForm.health_check_path || '/' }} ({{ wizardForm.health_check_interval }}s/{{ wizardForm.health_check_timeout }}s)
              </template>
              <template v-else>被动检查 (失败 {{ wizardForm.health_check_unhealthy_threshold }} 次视为不健康, 超时 {{ wizardForm.health_check_timeout }}s)</template>
            </el-descriptions-item>
            <el-descriptions-item label="健康检查" v-if="wizardForm.protocol === 'tcp'">
              <template v-if="wizardForm.enable_active_health_check">
                TCP 主动探测端口 {{ wizardForm.tcp_health_check_port || '默认' }} ({{ wizardForm.health_check_interval }}s/{{ wizardForm.health_check_timeout }}s)
              </template>
              <template v-else>被动检查 (失败 {{ wizardForm.health_check_unhealthy_threshold }} 次视为不健康, 超时 {{ wizardForm.health_check_timeout }}s)</template>
            </el-descriptions-item>
            <el-descriptions-item label="连接重试" v-if="wizardForm.protocol === 'tcp'">
              <template v-if="(wizardForm.tcp_try_duration || 0) > 0">
                窗口 {{ wizardForm.tcp_try_duration || 0 }}ms / 间隔 {{ wizardForm.tcp_try_interval || 0 }}ms
              </template>
              <template v-else>禁用</template>
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
                <div v-if="certInfo.valid" class="cert-preview-info">
                  <el-tag size="small" :type="certInfo.warning ? 'warning' : 'success'">{{ certInfo.domain }}</el-tag>
                  <span class="cert-expiry">过期: {{ certInfo.expiryDate }}</span>
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
                <el-table-column prop="max_connections" label="最大连接" width="90" />
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
          <el-button v-if="hasPreviousStep" @click="prevStep">
            <el-icon><ArrowLeft /></el-icon>上一步
          </el-button>
          <el-button v-if="hasNextStep" type="primary" @click="nextStep">
            下一步<el-icon><ArrowRight /></el-icon>
          </el-button>
          <el-button v-if="currentStep === WIZARD_STEP.PREVIEW" type="primary" :loading="saving" @click="submitWizard">
            <span>保存规则</span><el-icon style="margin-left: 6px;"><Check /></el-icon>
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- View Config Dialog -->
    <el-dialog v-model="configDialogVisible" title="Caddy 配置" width="min(900px, 94vw)" :close-on-click-modal="true" @close="onConfigDialogClosed">
      <div v-if="configLoading" v-loading="configLoading" style="min-height: 200px;"></div>
      <div v-else-if="ruleConfig" class="config-view">
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
          <el-descriptions-item label="负载策略">{{ ruleConfig.strategy }}</el-descriptions-item>
          <el-descriptions-item label="动态上游">{{ ruleConfig.dynamic_dns ? '启用' : '禁用' }}</el-descriptions-item>
          <el-descriptions-item label="DNS 服务器" v-if="ruleConfig.protocol === 'http'">
            {{ ruleConfig.enable_dns_server ? (ruleConfig.dns_server || '未配置') : '禁用' }}
          </el-descriptions-item>
          <el-descriptions-item label="后端域名" v-if="ruleConfig.protocol === 'http'">{{ ruleConfig.host_header || '-' }}</el-descriptions-item>
          <el-descriptions-item label="TLS" v-if="ruleConfig.enable_tls">
            {{ ruleConfig.tls_http_redirect ? '启用 (HTTP重定向)' : '启用' }}
            <span v-if="ruleConfig.tls_source === 'manual'" class="tls-source-tag">(手动上传)</span>
            <span v-else-if="ruleConfig.tls_source === 'acme_dns'" class="tls-source-tag">(ACME 自动)</span>
          </el-descriptions-item>
          <el-descriptions-item label="TLS" v-else>禁用</el-descriptions-item>
          <el-descriptions-item label="压缩" v-if="ruleConfig.protocol === 'http'">
            {{ ruleConfig.enable_compress ? (Array.isArray(ruleConfig.compress_types) ? ruleConfig.compress_types[0] : (ruleConfig.compress_types || 'gzip')) : '禁用' }}
          </el-descriptions-item>
          <el-descriptions-item label="主动健康检查" v-if="ruleConfig.protocol === 'http' && ruleConfig.health_check_path">
            {{ ruleConfig.health_check_path }} ({{ ruleConfig.health_check_interval }}s/{{ ruleConfig.health_check_timeout }}s)
          </el-descriptions-item>
          <el-descriptions-item label="主动健康检查" v-if="ruleConfig.protocol === 'http' && !ruleConfig.health_check_path">未启用</el-descriptions-item>
          <el-descriptions-item label="主动健康检查" v-if="ruleConfig.protocol === 'tcp' && ruleConfig.enable_active_health_check">
            TCP 探测端口 {{ ruleConfig.tcp_health_check_port || '默认' }} ({{ ruleConfig.health_check_interval }}s/{{ ruleConfig.health_check_timeout }}s)
          </el-descriptions-item>
          <el-descriptions-item label="主动健康检查" v-if="ruleConfig.protocol === 'tcp' && !ruleConfig.enable_active_health_check">未启用</el-descriptions-item>
          <el-descriptions-item label="被动健康检查" v-if="ruleConfig.protocol === 'http' || ruleConfig.protocol === 'tcp'">
            失败 {{ ruleConfig.health_check_unhealthy_threshold || 3 }} 次视为不健康, 间隔 {{ ruleConfig.health_check_interval || 10 }}s, 超时 {{ ruleConfig.health_check_timeout || 2 }}s
          </el-descriptions-item>
          <el-descriptions-item label="连接重试" v-if="ruleConfig.protocol === 'tcp'">
            <template v-if="ruleConfig.tcp_try_duration > 0">
              窗口 {{ ruleConfig.tcp_try_duration }}ms / 间隔 {{ ruleConfig.tcp_try_interval }}ms
            </template>
            <template v-else>禁用</template>
          </el-descriptions-item>
          <el-descriptions-item label="请求体大小">{{ (ruleConfig.request_body_max_size_mb || 0) > 0 ? ruleConfig.request_body_max_size_mb + 'MB' : '全局默认' }}</el-descriptions-item>
            <el-descriptions-item label="Keepalive 超时">{{ (ruleConfig.upstream_keepalive_timeout || 0) > 0 ? ruleConfig.upstream_keepalive_timeout + 's' : '全局默认' }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="ruleConfig.enabled ? 'success' : 'info'" size="small">{{ ruleConfig.enabled ? '启用' : '禁用' }}</el-tag>
          </el-descriptions-item>
        </el-descriptions>
        
        <el-divider content-position="left">上游服务器</el-divider>
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
          <el-table-column prop="max_connections" label="最大连接" align="center" />
          <el-table-column prop="enabled" label="状态" align="center">
            <template #default="{ row }">
              <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        
        <el-divider content-position="left">Caddy 配置 (JSON)</el-divider>
        <el-empty v-if="ruleConfig.config_not_exists" description="配置不存在" :image-size="60" />
        <SyntaxHighlight v-else :content="JSON.stringify(ruleConfig.config, null, 2)" language="json" />
      </div>
      <div v-else class="config-empty">
        <el-empty description="未找到该规则的配置信息" :image-size="60" />
      </div>
    </el-dialog>

    <el-dialog
      v-model="ruleLogDialogVisible"
      :title="`访问日志 - ${ruleLogRuleName}`"
      width="min(1100px, 94vw)"
      destroy-on-close
      @opened="onRuleLogDialogOpened"
      @close="onRuleLogDialogClosed"
    >
      <el-tabs v-model="ruleLogTab" @tab-change="onRuleLogTabChange">
        <el-tab-pane label="日志" name="log">
          <div class="log-toolbar">
            <el-switch v-model="ruleLogAutoRefresh" active-text="自动刷新" />
            <el-button type="primary" :loading="ruleLogLoading" size="small" @click="refreshRuleLogs">
              <el-icon><RefreshRight /></el-icon>刷新
            </el-button>
          </div>
          <div ref="ruleLogContainerRef" class="rule-log-viewer" v-html="ruleLogHtml" />
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
              <el-text type="info" size="small" style="margin-left: 8px;">自 {{ ruleLogStats.started_at }} 起，每 5 秒实时统计</el-text>
            </div>
            <div class="stats-grid">
              <el-card shadow="never" class="stats-card">
                <template #header>
                  <div class="stats-card-header"><el-icon><Location /></el-icon><span>IP TOP</span></div>
                </template>
                <el-table :data="ruleLogStats.top_ips" size="small" :show-header="false">
                  <el-table-column prop="value" show-overflow-tooltip />
                  <el-table-column prop="count" width="70" align="right">
                    <template #default="{ row }"><span class="stats-count">{{ row.count }}</span></template>
                  </el-table-column>
                  <template #empty><el-empty description="暂无数据" :image-size="40" /></template>
                </el-table>
              </el-card>
              <el-card shadow="never" class="stats-card">
                <template #header>
                  <div class="stats-card-header"><el-icon><Monitor /></el-icon><span>客户端 TOP</span></div>
                </template>
                <el-table :data="ruleLogStats.top_uas" size="small" :show-header="false">
                  <el-table-column prop="value" show-overflow-tooltip />
                  <el-table-column prop="count" width="70" align="right">
                    <template #default="{ row }"><span class="stats-count">{{ row.count }}</span></template>
                  </el-table-column>
                  <template #empty><el-empty description="暂无数据" :image-size="40" /></template>
                </el-table>
              </el-card>
              <el-card shadow="never" class="stats-card">
                <template #header>
                  <div class="stats-card-header"><el-icon><Link /></el-icon><span>URI TOP</span></div>
                </template>
                <el-table :data="ruleLogStats.top_uris" size="small" :show-header="false">
                  <el-table-column prop="value" show-overflow-tooltip />
                  <el-table-column prop="count" width="70" align="right">
                    <template #default="{ row }"><span class="stats-count">{{ row.count }}</span></template>
                  </el-table-column>
                  <template #empty><el-empty description="暂无数据" :image-size="40" /></template>
                </el-table>
              </el-card>
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
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, computed, watch, nextTick } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request, mfaAwareSuccess } from '@/utils/api'
import { Plus, Operation, Delete, InfoFilled, Lock, Connection, Guide, Check, ArrowLeft, ArrowRight, Document, CircleCheckFilled, CircleCloseFilled, QuestionFilled, Setting, RefreshRight, Search, WarningFilled, Location, Monitor, Link} from '@element-plus/icons-vue'
import { ElMessageBox, ElMessage } from 'element-plus'
import axios from 'axios'
import { ansiToHtml } from '@/utils/ansi'
import { formatDate } from '@/utils/date'
import LogStorageBar from '@/components/LogStorageBar.vue'
import type {
  APIResponse,
  CreateRuleRequest,
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
import { validatePathRules } from '@/utils/ruleValidation'
import { MAX_UPSTREAM_ROWS, normalizeWeights, redistributeWeight } from '@/utils/upstreamWeights'
import { certJobStatusLabel } from '@/utils/certJobStatus'
import type { CertJobStatus } from '@/utils/certJobStatus'
import { usePollingTask } from '@/composables/usePollingTask'
import { usePollingErrorState } from '@/composables/usePollingErrorState'

interface RuleForm extends Omit<CreateRuleRequest, 'dns_family' | 'upstreams' | 'acme_config_id' | 'ca_provider_id' | 'compress_types'> {
  id?: number
  caddy_id: string
  dns_family: string[]
  upstreams: UpstreamInput[]
  acme_config_id?: number
  ca_provider_id?: number
  compress_types: string[]
  enabled: boolean
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
  host_header: string
  enable_tls: boolean
  tls_source: string
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string[]
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
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

interface CertJob {
  id: number
  rule_id: string
  domain: string
  status: CertJobStatus
  message: string
  expires_at?: string | null
  ca_available_after?: string | null
}

class CertInfoRefreshError extends Error {
  readonly name = 'CertInfoRefreshError'

  constructor() {
    super('证书任务已更新，但证书详情刷新失败')
  }
}

const rules = ref<Rule[]>([])
// v2.2.0：一规则可绑多策略——/security/bindings 返回 rule_caddy_id → 绑定数组（policy_id ASC）。
interface SecurityBindingInfo {
  policy_id: number
  name: string
  mode: string
  enabled: boolean
  rate_limit_enabled: boolean
  block_page_id?: number
}

const securityBindings = ref<Record<string, SecurityBindingInfo[]>>({})

interface SecurityPolicySummary {
  id: number
  mode: string
  enabled: boolean
  has_ip_control: boolean
  has_rate_limit: boolean
  // R72 三十次追加 a：GeoIP/自定义规则 flag + 计数（后端 models 同款）。
  has_geoip: boolean
  has_custom_rules: boolean
  geoip_countries: string
  custom_rules_count: number
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  rate_limit_rps: number
  rate_limit_burst: number
}

const securityPolicies = ref<SecurityPolicySummary[]>([])

const fetchSecurityBindings = async () => {
  try {
    const [bindingsRes, policiesRes] = await Promise.all([
      request.get<APIResponse<typeof securityBindings.value>>('/security/bindings'),
      request.get<APIResponse<SecurityPolicySummary[]>>('/security/policies'),
    ])
    if (bindingsRes.data) securityBindings.value = bindingsRes.data
    if (policiesRes.data) securityPolicies.value = policiesRes.data
  } catch { /* silent */ }
}

interface ProtectionRow {
  label: string
  detail: string
}

interface PolicyProtectionGroup {
  key: number
  order: number
  name: string
  enabled: boolean
  blockPageActive: boolean
  rows: ProtectionRow[]
}

const parseIPListCount = (raw: string): number => {
  if (!raw) return 0
  try {
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.length : 0
  } catch {
    return 0
  }
}

const ruleProtections = (caddyID: string): PolicyProtectionGroup[] => {
  const bindings = securityBindings.value[caddyID]
  if (!bindings || bindings.length === 0) return []
  // v2.2.0：逐绑定策略分组（后端已按 policy_id ASC 排序）。序号 = 绑定顺序（1-based）；
  // 拦截优先级 = 绑定顺序，首个启用且配置了拦截页（block_page_id>0）策略的拦截页生效
  //（与后端 caddy.go 生成口径一致；Caddy 只为启用策略生成配置，绑定列表可能含禁用策略）；
  // 禁用策略标灰但保留显示（绑定关系可见，不再消失）。全部禁用/均未配置拦截页时无策略生效，不标注拦截页。
  const firstEnabledIndex = bindings.findIndex((b) => b.enabled && (b.block_page_id ?? 0) > 0)
  return bindings.map((binding, index) => {
    const policy = securityPolicies.value.find((p) => p.id === binding.policy_id)
    const rows: ProtectionRow[] = []
    const mode = policy ? policy.mode : binding.mode
    if (mode === 'blocking') rows.push({ label: 'WAF（拦截）', detail: '命中即阻断' })
    else if (mode === 'detection') rows.push({ label: 'WAF（检测）', detail: '仅记录不阻断' })
    if (policy?.has_ip_control) {
      const modeLabel = policy.ip_acl_mode === 'allow' ? '白名单模式' : (policy.ip_acl_mode === 'bypass' ? '免检测' : '黑名单模式')
      const parts = [`${modeLabel} · ${parseIPListCount(policy.ip_acl_list)} 条`]
      const trustCount = parseIPListCount(policy.ip_whitelist)
      if (trustCount > 0 && policy.ip_acl_mode !== 'bypass') parts.push(`免检测 ${trustCount} 条`)
      rows.push({ label: 'IP 访问控制', detail: parts.join(' · ') })
    }
    if (policy?.has_rate_limit) rows.push({ label: '速率限制', detail: `${policy.rate_limit_rps} 次/秒 · 突发 ${policy.rate_limit_burst} 次` })
    if (policy?.has_geoip) rows.push({ label: 'GeoIP', detail: `${policy.geoip_countries ? (JSON.parse(policy.geoip_countries) as string[]).length : 0} 个地区` })
    if (policy?.has_custom_rules) rows.push({ label: '自定义规则', detail: `${policy.custom_rules_count} 条` })
    return {
      key: binding.policy_id,
      order: index + 1,
      name: binding.name,
      enabled: binding.enabled,
      blockPageActive: index === firstEnabledIndex,
      rows,
    }
  })
}
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

const ruleUpdatedAtMs = (rule: Rule): number => {
  const value = rule.updated_at
  const t = value ? new Date(value).getTime() : 0
  return Number.isNaN(t) ? 0 : t
}

const pagedRules = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredRules.value.slice(start, start + pageSize.value)
})

watch(searchQuery, () => {
  currentPage.value = 1
})

watch([() => filteredRules.value.length, pageSize], ([ruleCount, size]) => {
  const maxPage = Math.max(1, Math.ceil(ruleCount / size))
  currentPage.value = Math.min(Math.max(currentPage.value, 1), maxPage)
})
const users = ref<UserListItem[]>([])
const certInfoMap = ref<Record<string, CertInfo | null>>({})
const certJobMap = ref<Record<string, CertJob>>({})
const pendingCertInfoRefresh = new Set<string>()
const ruleTogglePending = ref<Record<string, boolean>>({})
const certInfoGenerations = new Map<string, number>()
let certInfoGeneration = 0
let rulesRequestSeq = 0

const getUpdaterName = (userId?: number) => {
  if (!userId || userId === 0) return '-'
  const user = users.value.find(u => u.id === userId)
  if (user) {
    const displayName = user.display_name || ''
    return displayName || user.username || '-'
  }
  return '-'
}

const fetchRules = async () => {
  if (disposed) return
  const requestSeq = ++rulesRequestSeq
  loading.value = true
  try {
    const res = await request.get<APIResponse<Rule[]>>('/rules', { signal: healthPolling.signal })
    if (disposed || requestSeq !== rulesRequestSeq) return
    rules.value = res.data || []
    void fetchSecurityBindings()
    // Fetch health status after rules are loaded
    void healthPolling.run()
    // Fetch certificate info for TLS-enabled rules
    void fetchCertInfo()
    // Fetch cert job statuses for ACME rules
    void certJobsPolling.run()
  } catch (error: unknown) {
    if (axios.isCancel(error)) return
    // Error toast is already shown by the global axios interceptor; swallow here
    // so fire-and-forget refresh calls don't surface as unhandled rejections.
    console.error('Failed to fetch rules:', error)
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
    return true
  } catch (error: unknown) {
    if (!axios.isCancel(error) && !disposed) console.error('Failed to fetch certificate info:', error)
    return false
  }
}

const fetchCertJobs = async (): Promise<void> => {
  if (disposed) return
  const requestedRuleIds = pagedRules.value.map((rule) => rule.caddy_id)
  const requestedRuleIdSet = new Set(requestedRuleIds)
  const res = await request.post<APIResponse<Record<string, CertJob | null>>>('/certificates/jobs/current', {
    rule_ids: requestedRuleIds,
  }, { signal: certJobsPolling.signal, silent: true })
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

const isCertJobActive = (status?: CertJobStatus) => {
  if (!status) return false
  return !['issued', 'failed', 'disabled'].includes(status)
}

const canEditRule = (row: Rule) => {
  if (isReadOnly.value) return false
  if (row.tls_source === 'acme_dns' && isCertJobActive(certJobMap.value[row.caddy_id]?.status)) {
    return false
  }
  return true
}

const tlsTagType = (row: Rule) => {
  const cert = certInfoMap.value[row.caddy_id]
  if (cert?.status === 'expired') return 'danger'
  if (cert?.status === 'expiring') return 'warning'
  if (cert?.status === 'valid') return 'success'
  if (row.tls_source === 'acme_dns') {
    const status = certJobMap.value[row.caddy_id]?.status
    if (status === 'issued') return 'success'
    if (status === 'failed') return 'danger'
    if (status === 'disabled') return 'info'
    if (status) return 'warning'
    return 'info'
  }
  return 'primary'
}

const tlsTagLabel = (row: Rule) => {
  const cert = certInfoMap.value[row.caddy_id]
  if (cert?.status === 'expired') return '已过期'
  if (cert?.status === 'expiring') return `临期 ${cert.days_remaining} 天`
  if (cert?.status === 'valid') return row.tls_source === 'acme_dns' ? '已签发' : '手动'
  if (row.tls_source === 'acme_dns') {
    const status = certJobMap.value[row.caddy_id]?.status
    const label = status ? certJobStatusLabel(status) : ''
    return label || '未签发'
  }
  return '手动'
}

const isCurrentRuleLocked = computed(() => {
  if (!editingRule.value) return false
  return editingRule.value.tls_source === 'acme_dns' && isCertJobActive(certJobMap.value[editingRule.value.caddy_id]?.status)
})

const loading = ref(false)
const wizardVisible = ref(false)
const saving = ref(false)
const editingRule = ref<Rule | null>(null)
const isCopyMode = ref(false)
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
const enabledCAProviders = computed(() => caProviders.value.filter(p => p.enabled))
const healthStatus = ref<Record<string, { healthy: number; unhealthy: number; degraded: number; unknown: number; total: number; upstreams: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; num_requests?: number; fails?: number }> }>>({})
// Config viewing
const configDialogVisible = ref(false)
const configLoading = ref(false)
let configRequestSeq = 0

const ruleLogDialogVisible = ref(false)
const ruleLogRuleName = ref('')
const ruleLogCaddyId = ref('')
const ruleLogContent = ref('')
const ruleLogLoading = ref(false)
const ruleLogAutoRefresh = ref(true)
const ruleLogContainerRef = ref<HTMLElement | null>(null)
let ruleLogPollTimer: ReturnType<typeof setInterval> | null = null
let ruleLogRequestSeq = 0

const ruleLogHtml = computed(() => ansiToHtml(ruleLogContent.value || '暂无日志'))
const ruleConfig = ref<RuleConfigView | null>(null)

// R69 结构性简化（D 域 2(e)）：四方 host 门的核心谓词单源化——红框/常驻警告/
// 步进门三条腿此前手工维护同一条件（R67 D-1 的消息腿落后一轮正是该维护风险
// 的实证），现共用一个谓词；提交过滤（host+port 载荷身份）概念不同、不参与。
const upstreamRowNeedsHost = (u: UpstreamInput, i: number): boolean =>
  !u.host && u.enabled !== false && upstreamTouched.value[i]

const upstreamHostWarning = computed(() =>
  wizardForm.upstreams.some((u, i) => upstreamRowNeedsHost(u, i)) ? '主机地址为必填项，请填写完整' : '')

interface HealthSummary { healthy: number; unhealthy: number; degraded: number; unknown: number; total: number }

const getEnabledUpstreams = (rule: Rule): Upstream[] =>
  rule.upstreams?.filter((upstream) => upstream.enabled !== false) || []

const getHealthTagType = (status: HealthSummary) => {
  if (status.unhealthy + status.degraded === status.total) return 'danger'
  if (status.unhealthy + status.degraded > 0) return 'warning'
  if (status.unknown === status.total) return 'info'
  if (status.unknown > 0) return 'warning'
  return 'success'
}

const getHealthLabel = (status: HealthSummary) => {
  if (status.unhealthy + status.degraded === status.total) return '异常'
  if (status.unhealthy + status.degraded > 0) return '降级'
  if (status.unknown === status.total) return '未知'
  if (status.unknown > 0) return '降级'
  return '正常'
}

const getUpstreamHealthStatus = (ruleId: string, upstream: Upstream | UpstreamInput) => {
  const status = healthStatus.value[ruleId]
  if (!status || !status.upstreams) return { healthy: false, unknown: true }
  const upstreamKey = `${upstream.host}:${upstream.port}`
  const upstreamData = status.upstreams[upstreamKey]
  return upstreamData ? { healthy: upstreamData.healthy, unknown: upstreamData.unknown, degraded: upstreamData.degraded } : { healthy: false, unknown: true, degraded: false }
}

const getUpstreamMetrics = (ruleId: string, upstream: Upstream | UpstreamInput) => {
  const status = healthStatus.value[ruleId]
  if (!status || !status.upstreams) return { num_requests: 0, fails: 0 }
  const upstreamKey = `${upstream.host}:${upstream.port}`
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

const fetchHealthStatus = async () => {
  if (disposed) return
  try {
    const res = await request.get<APIResponse<UpstreamHealthResponse>>('/config/health', { signal: healthPolling.signal, silent: true })
    if (disposed) return
    const healthData = res.data || {}
    const mapped: Record<string, { healthy: number; unhealthy: number; degraded: number; unknown: number; total: number; upstreams: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; num_requests?: number; fails?: number }> }> = {}
    for (const rule of rules.value) {
      const enabledUpstreams = getEnabledUpstreams(rule)
      if (enabledUpstreams.length > 0) {
        let healthy = 0
        let unhealthy = 0
        let degraded = 0
        let unknown = 0
        const upstreamStatus: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; num_requests?: number; fails?: number }> = {}
        for (const upstream of enabledUpstreams) {
          const upstreamKey = `${upstream.host}:${upstream.port}`
          let isHealthy = false
          let isUnknown = true
          let isDegraded = false
          let numRequests = 0
          let fails = 0
          for (const serverHealth of Object.values(healthData)) {
            if (serverHealth && typeof serverHealth === 'object') {
              if (upstreamKey in serverHealth) {
                const detail = serverHealth[upstreamKey]
                isUnknown = detail.unknown === true
                if (!isUnknown) {
                  isHealthy = detail.healthy !== false
                  isDegraded = detail.degraded === true
                }
                numRequests = detail.num_requests || 0
                fails = detail.fails || 0
                break
              }
            }
          }
          upstreamStatus[upstreamKey] = { healthy: isHealthy, unknown: isUnknown, degraded: isDegraded, num_requests: numRequests, fails }
          if (isUnknown) unknown++
          else if (!isHealthy) unhealthy++
          else if (isDegraded) degraded++
          else healthy++
        }
        if (rule.caddy_id) {
          mapped[rule.caddy_id] = { healthy, unhealthy, degraded, unknown, total: enabledUpstreams.length, upstreams: upstreamStatus }
        }
      }
    }
    if (!disposed) healthStatus.value = mapped
  } catch (error: unknown) {
    if (!disposed) console.error('Failed to fetch health status:', error)
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
  issuer: '',
  expiryDate: '',
  daysUntilExpiry: 0,
  warning: '',
  error: ''
})
let certValidationSeq = 0
let certValidationSessionSeq = 0

const resetCertInfo = (): void => {
  Object.assign(certInfo, {
    valid: false,
    domain: '',
    issuer: '',
    expiryDate: '',
    daysUntilExpiry: 0,
    warning: '',
    error: '',
  })
}

const wizardForm = reactive<RuleForm>({
  caddy_id: '',
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
  host_header: '',
  upstreams: [],
  enable_tls: false,
  tls_source: 'manual',
  acme_config_id: 0,
  ca_provider_id: undefined as number | undefined,
  tls_cert: '',
  tls_key: '',
  tls_http_redirect: false,
  enable_compress: false,
  compress_types: ['gzip'],
  request_body_max_size_mb: 0,
  upstream_keepalive_timeout: 0,
  server_tokens_hidden: 0,
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
// R59 D-F1：向导打开序列号——丢弃编辑/复制在途 GET 的过期返回，防止覆盖新建表单。
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
// http→tcp 迁移前的 HTTP 态快照：回转 http 时判断「是否实际改过端口 / 是否被强制关闭过 TLS」（D-2）。
let preTcpSnapshot: { listenPort: number; enableTls: boolean } | null = null

// Watch for enable_tls toggle to adjust default listen port
watch(() => wizardForm.enable_tls, (newVal, oldVal) => {
  if (hydratingWizard) return
  // 编辑态下端口不做自动迁移（保留已提交配置），但 TLS 开关与非常态端口组合时给出非静默提示
  if (newVal && !oldVal && userExplicitPort.value && wizardForm.listen_port === 80) {
    showTlsHint('端口当前为 80，如需 HTTPS 访问建议改为 443')
  }
  if (!newVal && oldVal && userExplicitPort.value && wizardForm.listen_port === 443) {
    showTlsHint('端口当前为 443，关闭 TLS 后如需 HTTP 访问建议改为 80')
  }
  if (userExplicitPort.value) return
  if (wizardForm.protocol !== 'http') return
  if (newVal && !oldVal) {
    // Enabling HTTPS: default to 443 if currently using the HTTP default 80
    if (wizardForm.listen_port === 80) {
      wizardForm.listen_port = 443
    }
  } else if (!newVal && oldVal) {
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
    wizardForm.custom_routes_enabled = false
    wizardForm.path_rules = []
    wizardForm.upstreams.forEach(u => {
      if (u.protocol === 'http') u.protocol = 'tcp'
      if (u.protocol === 'https') u.protocol = 'tls'
    })
  } else if (newVal === 'http' && oldVal === 'tcp') {
    // 回转判断基于快照而非 userExplicitPort：编辑态（userExplicitPort=true）进 TCP 同样被
    // 无条件迁移 80/443→8080，回转不还原会保存即静默改写 DB 端口（BUG-03）
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

// Watch for enable_dns_server toggle to clear DNS fields when disabled
watch(() => wizardForm.enable_dns_server, (newVal) => {
  if (!newVal) {
    wizardForm.dns_server = ''
  }
})

// Watch for enable_active_health_check toggle to set default path / TCP port
watch(() => wizardForm.enable_active_health_check, (newVal) => {
  if (!newVal) return
  if (!wizardForm.health_check_path) {
    wizardForm.health_check_path = '/'
  }
  // For TCP rules, default the active health check port to the first upstream port
  if (wizardForm.protocol === 'tcp' && wizardForm.tcp_health_check_port === 0) {
    const firstUpstream = wizardForm.upstreams.find(u => u.port && u.port > 0)
    if (firstUpstream) {
      wizardForm.tcp_health_check_port = firstUpstream.port
    }
  }
})

const adminPorts = [8000, 2019]
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
    if (adminPorts.includes(wizardForm.listen_port)) {
      return `端口 ${wizardForm.listen_port} 为管理端口，不可使用`
    }
    if (tcpPorts.includes(wizardForm.listen_port)) {
      return `端口已被 TCP 规则占用`
    }
  } else if (wizardForm.protocol === 'tcp') {
    // TCP rules cannot use admin ports, 80/443, or share a port with any other rule.
    if (httpReservedPorts.includes(wizardForm.listen_port)) {
      return `端口 ${wizardForm.listen_port} 为 HTTP/Web 端口，TCP 规则不可使用`
    }
    if (adminPorts.includes(wizardForm.listen_port)) {
      return `端口 ${wizardForm.listen_port} 为管理端口，不可使用`
    }
    if (httpPorts.includes(wizardForm.listen_port) || tcpPorts.includes(wizardForm.listen_port)) {
      return `端口已被其他规则占用`
    }
  }
  return ''
})

const getStrategyLabel = (strategy: string) => {
  const labels: Record<string, string> = {
    weighted_round_robin: '轮询',
    least_conn: '最少连接',
    ip_hash: 'IP 哈希',
    cookie: 'Cookie 粘滞',
    first: '首个可用',
    random: '随机',
    header: 'Header',
  }
  return labels[strategy] || strategy
}

const fetchUsers = async () => {
  try {
  const res = await request.get<APIResponse<UserListItem[]>>('/users')
    users.value = res.data || []
  } catch (e) {
    console.error('Failed to fetch users:', e)
  }
}

const fetchCertConfigs = async () => {
  try {
    const res = await request.get<APIResponse<CertificateConfig[]>>('/certificate-configs')
    certConfigs.value = res.data || []
  } catch (e) {
    console.error('Failed to fetch cert configs:', e)
  }
}

const fetchCAProviders = async () => {
  try {
    const res = await request.get<APIResponse<CAProvider[]>>('/ca-providers')
    caProviders.value = res.data || []
  } catch (e) {
    console.error('Failed to load CA providers:', e)
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
    certInfo.error = '请提供私钥 (KEY)'
    return
  }

  // Validate certificate format
  if (!certPEM.includes('-----BEGIN CERTIFICATE-----') || !certPEM.includes('-----END CERTIFICATE-----')) {
    certInfo.error = '证书格式无效，必须以 -----BEGIN CERTIFICATE----- 开头'
    return
  }

  // Validate private key format
  const keyValid = 
    (keyPEM.includes('-----BEGIN PRIVATE KEY-----') && keyPEM.includes('-----END PRIVATE KEY-----')) ||
    (keyPEM.includes('-----BEGIN RSA PRIVATE KEY-----') && keyPEM.includes('-----END RSA PRIVATE KEY-----')) ||
    (keyPEM.includes('-----BEGIN EC PRIVATE KEY-----') && keyPEM.includes('-----END EC PRIVATE KEY-----'))

  if (!keyValid) {
    certInfo.error = '私钥格式无效'
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
      certInfo.issuer = data.issuer || ''
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

const pasteFromFile = async (type: 'cert' | 'key') => {
  try {
    // Create a file input element
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.pem,.crt,.key,.txt,*'
    
    input.onchange = async (e: Event) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file) return
      
      const reader = new FileReader()
      reader.onload = (event) => {
        const content = event.target?.result as string
        if (type === 'cert') {
          wizardForm.tls_cert = content
        } else {
          wizardForm.tls_key = content
        }
        ElMessage.success('已从文件读取内容')
      }
      reader.readAsText(file)
    }
    
    input.click()
  } catch (e) {
    ElMessage.error('读取文件失败')
  }
}

const openWizard = async (rule?: Rule) => {
  if (isReadOnly.value || saving.value) return
  // R59 D-F1：向导打开序列号（同 viewConfig 的 configRequestSeq 模式）——
  // 编辑/复制手动 TLS 规则时在途 GET 期间用户再点「新建」，首个返回会覆盖
  // 新建表单并把保存语义从 create 翻成 PUT。过期返回直接丢弃。
  const openSeq = ++wizardOpenSeq
  hydratingWizard = true
  preTcpSnapshot = null
  userExplicitPort.value = false
  certValidationSessionSeq++
  certValidationSeq++
  resetCertInfo()
  upstreamTouched.value = []
  isCopyMode.value = false
  if (rule) {
    // 编辑态一律保留已存端口：DB 中的 listen_port 即用户显式配置，TLS/协议切换不再静默迁移端口
    userExplicitPort.value = true
    let fullRule: Rule = rule
    if (rule.enable_tls && rule.tls_source === 'manual') {
      try {
        const resp = await request.get<APIResponse<Rule>>(`/rules/${rule.caddy_id}`)
        if (openSeq !== wizardOpenSeq) return
        if (resp.code === 0 && resp.data) {
          fullRule = resp.data
        }
    } catch {
      // R62 D-1：与 try 路径同款 seq 守卫——过期请求的失败分支同样不得触碰
      // 在途表单（否则「新建」被过期 fullRule 覆盖，保存语义翻转为 PUT 更新既有规则）。
      if (openSeq !== wizardOpenSeq) return
      console.warn('[openWizard] Failed to fetch cert data for', rule.caddy_id)
    }
    }
    editingRule.value = fullRule
    const compressTypes = fullRule.compress_types ? selectedCompressTypes(fullRule.compress_types) : ['gzip']
    Object.assign(wizardForm, {
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
      host_header: fullRule.host_header || '',
      upstreams: fullRule.upstreams?.map(u => ({
        ...u,
        dynamic_dns: false,
        protocol: u.protocol || 'http',
        max_connections: u.max_connections ?? 0,
      })) || [],
      enable_tls: fullRule.enable_tls || false,
      tls_source: fullRule.tls_source || 'manual',
      acme_config_id: fullRule.acme_config_id || undefined,
      ca_provider_id: fullRule.ca_provider_id ?? 0,
      tls_cert: fullRule.tls_cert || '',
      tls_key: fullRule.tls_key || '',
      tls_http_redirect: fullRule.tls_http_redirect || false,
      enable_compress: fullRule.enable_compress !== false,
      compress_types: compressTypes,
      request_body_max_size_mb: fullRule.request_body_max_size_mb || 0,
      upstream_keepalive_timeout: fullRule.upstream_keepalive_timeout || 0,
      server_tokens_hidden: fullRule.server_tokens_hidden || 0,
      enabled: fullRule.enabled,
      log_enabled: fullRule.log_enabled || false,
      custom_routes_enabled: fullRule.custom_routes_enabled === true,
      path_rules: [...(fullRule.path_rules || [])]
        .sort((left, right) => left.sort_order - right.sort_order)
        .map((pathRule) => ({
          ...pathRule,
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
    weightsToPercent(wizardForm.upstreams)
    if (wizardForm.dynamic_dns) onDynamicDnsToggle(true)
  } else {
    editingRule.value = null
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
      host_header: '',
      dns_server: '',
      dns_family: ['ipv4'],
      upstreams: [defaultUpstream()],
      enable_tls: false,
      tls_source: 'manual',
      acme_config_id: undefined as number | undefined,
      ca_provider_id: 0,
      tls_cert: '',
      tls_key: '',
      tls_http_redirect: false,
      enable_compress: false,
      compress_types: ['gzip'],
      request_body_max_size_mb: 0,
      upstream_keepalive_timeout: 0,
      server_tokens_hidden: 0,
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
      proxy_flush_interval: 0,
      proxy_stream_close_delay: 0,
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
  upstreamTouched.value = []
  editingRule.value = null
  isCopyMode.value = false
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

const weightPercent = (upstreams: readonly (Upstream | UpstreamInput)[] | undefined, row: Upstream | UpstreamInput): number => {
  if (!upstreams?.length) return 0
  if (row.enabled === false) return 0
  const sum = upstreams.filter((upstream) => upstream.enabled !== false).reduce((s, u) => s + (u.weight || 0), 0)
  if (sum <= 0) return 0
  return Math.round(((row.weight || 0) / sum) * 100)
}

const addUpstream = () => {
  if (wizardForm.upstreams.length >= MAX_UPSTREAM_ROWS) return
  const upstream = defaultUpstream(wizardForm.protocol === 'tcp' ? 'tcp' : 'http')
  upstream.weight = 0
  wizardForm.upstreams.push(upstream)
  redistributeWeight(wizardForm.upstreams, wizardForm.upstreams.length - 1)
}

const customRoutesPreview = (): string => {
  if (!wizardForm.custom_routes_enabled || wizardForm.path_rules.length === 0) return '禁用'
  const paths = wizardForm.path_rules.slice(0, 3).map((rule) => rule.path || '/').join('、')
  const suffix = wizardForm.path_rules.length > 3 ? ' 等' : ''
  return `${wizardForm.path_rules.length} 条 · ${paths}${suffix}`
}

const removeUpstream = (index: number) => {
  wizardForm.upstreams.splice(index, 1)
  const lastEnabled = wizardForm.upstreams.findIndex(u => u.enabled)
  if (lastEnabled >= 0) {
    onWeightChange(lastEnabled)
  }
}

const onCustomRoutesToggle = (enabled: string | number | boolean): void => {
  if (Boolean(enabled) && wizardForm.path_rules.length === 0) {
    wizardForm.path_rules.push({ id: nextTemporaryPathRuleId, match_type: 'prefix', path: '/', sort_order: 0, upstreams: null })
    nextTemporaryPathRuleId -= 1
  }
  if (!enabled) wizardForm.path_rules = []
}

const updateRuleProxyTimeout = (field: keyof ProxyTimeoutConfig, value: number): void => {
  wizardForm[field] = value
}

const moveToAdjacentWizardStep = (direction: -1 | 1): void => {
  const currentIndex = visibleWizardSteps.value.indexOf(currentStep.value)
  const targetStep = visibleWizardSteps.value[currentIndex + direction]
  if (targetStep !== undefined) currentStep.value = targetStep
}

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
    if (wizardForm.tls_source === 'acme_dns' && !wizardForm.acme_config_id) {
      ElMessage.warning('请选择 DNS 提供商配置')
      return
    }
    if (wizardForm.tls_source === 'manual' && (!wizardForm.tls_cert.trim() || !wizardForm.tls_key.trim())) {
      ElMessage.warning('请上传证书和私钥')
      return
    }
    moveToAdjacentWizardStep(1)
    return
  }
  if (currentStep.value === WIZARD_STEP.UPSTREAMS) {
    upstreamTouched.value = wizardForm.upstreams.map(() => true)
    // R65 D-N2：host 门与提交口径对齐（只检查启用行；此处 touched 已全置 true，
    // 故与红框/警告共用同一谓词）。提交侧 validUpstreams 按 host+port 过滤空行，
    // 启用性由下方「至少一个启用上游」检查兜底。
    if (wizardForm.upstreams.some((u, i) => upstreamRowNeedsHost(u, i))) {
      ElMessage.warning('请填写所有已启用上游服务器的主机地址')
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
  if (wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled) {
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
  // Round 38 I-4: 前端补全 health_check_timeout >= health_check_interval 关系校验（与后端 Round 37 I-6 对齐）。
  if (wizardForm.enable_active_health_check
      && wizardForm.health_check_interval > 0
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
  const allowedStrategies = wizardForm.protocol === 'tcp'
    ? ['weighted_round_robin', 'ip_hash', 'least_conn', 'random', 'first']
    : ['weighted_round_robin', 'ip_hash', 'least_conn', 'random', 'first', 'cookie']
  if (!allowedStrategies.includes(wizardForm.strategy)) {
    ElMessage.warning(`${wizardForm.protocol.toUpperCase()} 规则包含协议族不匹配的负载策略`)
    saving.value = false
    return
  }

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

  try {
    const validUpstreams = wizardForm.upstreams.filter(u => u.host && u.port).map(u => ({
      ...u,
      weight: u.weight ?? 100,
      dynamic_dns: wizardForm.dynamic_dns,
      max_connections: u.max_connections ?? 0,
    }))

    const data: UpdateRuleRequest = {
      name: wizardForm.name,
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
      host_header: wizardForm.host_header,
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
      request_body_max_size_mb: wizardForm.request_body_max_size_mb || 0,
      upstream_keepalive_timeout: wizardForm.upstream_keepalive_timeout || 0,
      server_tokens_hidden: wizardForm.server_tokens_hidden || 0,
      enabled: wizardForm.enabled,
      log_enabled: wizardForm.log_enabled || false,
      custom_routes_enabled: wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled,
      path_rules: wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled
        ? wizardForm.path_rules.map((pathRule, index) => ({
            ...(pathRule.id !== undefined && pathRule.id > 0 ? { id: pathRule.id } : {}),
            match_type: pathRule.match_type,
            path: pathRule.path,
            sort_order: index,
            upstreams: pathRule.upstreams?.map((upstream) => ({ ...upstream })) || null,
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

    if (editingRule.value) {
      await request.put<APIResponse>(`/rules/${editingRule.value.caddy_id}`, data)
    } else {
      await request.post<APIResponse>('/rules', data)
    }

    mfaAwareSuccess(editingRule.value ? '更新成功' : '创建成功')
    wizardVisible.value = false
    fetchRules()
  } catch (error: unknown) {
    // Error message is already shown by the global axios interceptor.
    console.error('submit wizard failed', error)
  } finally {
    saving.value = false
  }
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
    // 启停已在服务端生效，刷新失败不回退开关（fetchRules 内部已吞错），等待下次轮询同步
    await fetchRules()
  } catch (e) {
    rule.enabled = !nextEnabled
  } finally {
    ruleTogglePending.value[rule.caddy_id] = false
  }
}

const deleteRule = async (rule: Rule) => {
  if (isReadOnly.value) return
  try {
    await ElMessageBox.confirm(`确定要删除规则 "${rule.name}" 吗？`, '删除确认', { type: 'warning' })
    await request.delete<APIResponse>(`/rules/${rule.caddy_id}`)
    mfaAwareSuccess('删除成功')
    fetchRules()
  } catch (error: unknown) {
    if (error === 'cancel' || error === 'close') return
    console.error('delete rule failed', error)
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
  // R59 D-F1：同 openWizard 的序列号守卫——复制在途 GET 过期返回丢弃。
  const openSeq = ++wizardOpenSeq
  hydratingWizard = true
  preTcpSnapshot = null
  userExplicitPort.value = false
  certValidationSessionSeq++
  certValidationSeq++
  resetCertInfo()
  upstreamTouched.value = []
  editingRule.value = null
  isCopyMode.value = true
  let fullRule: Rule = rule
  if (rule.enable_tls && rule.tls_source === 'manual') {
    try {
      const resp = await request.get<APIResponse<Rule>>(`/rules/${rule.caddy_id}`)
      if (openSeq !== wizardOpenSeq) return
      if (resp.code === 0 && resp.data) fullRule = resp.data
    } catch {
      // R62 D-1：与 try 路径同款 seq 守卫（详见 openWizard catch 处注释）。
      if (openSeq !== wizardOpenSeq) return
      /* fallback to list data */
    }
  }
  const compressTypes = fullRule.compress_types ? selectedCompressTypes(fullRule.compress_types) : ['gzip']
  Object.assign(wizardForm, {
    caddy_id: '',
    id: undefined,
    name: `${fullRule.name}（副本）`,
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
    host_header: fullRule.host_header || '',
    upstreams: fullRule.upstreams?.map(u => ({
      ...u,
      dynamic_dns: false,
      protocol: u.protocol || 'http',
      max_connections: u.max_connections ?? 0,
    })) || [],
    enable_tls: fullRule.enable_tls || false,
    tls_source: fullRule.tls_source || 'manual',
    acme_config_id: fullRule.acme_config_id || undefined,
    ca_provider_id: fullRule.ca_provider_id ?? 0,
    tls_cert: fullRule.tls_cert || '',
    tls_key: fullRule.tls_key || '',
    request_body_max_size_mb: fullRule.request_body_max_size_mb || 0,
    upstream_keepalive_timeout: fullRule.upstream_keepalive_timeout || 0,
    server_tokens_hidden: fullRule.server_tokens_hidden || 0,
    log_enabled: fullRule.log_enabled || false,
    custom_routes_enabled: fullRule.custom_routes_enabled === true,
    path_rules: [...(fullRule.path_rules || [])]
      .sort((left, right) => left.sort_order - right.sort_order)
      .map((pathRule) => ({
        ...pathRule,
        upstreams: pathRuleUpstreamsToPercent(pathRule.upstreams),
      })),
    proxy_dial_timeout: fullRule.proxy_dial_timeout || 0,
    proxy_response_header_timeout: fullRule.proxy_response_header_timeout || 0,
    proxy_read_timeout: fullRule.proxy_read_timeout || 0,
    proxy_write_timeout: fullRule.proxy_write_timeout || 0,
    proxy_stream_timeout: fullRule.proxy_stream_timeout || 0,
    proxy_flush_interval: fullRule.proxy_flush_interval || 0,
    proxy_stream_close_delay: fullRule.proxy_stream_close_delay || 0,
    tls_http_redirect: fullRule.tls_http_redirect || false,
    enable_compress: fullRule.enable_compress !== false,
    compress_types: compressTypes,
    enabled: false,
    })
  weightsToPercent(wizardForm.upstreams)
  if (wizardForm.dynamic_dns) onDynamicDnsToggle(true)
  hydratingWizard = false
  currentStep.value = WIZARD_STEP.BASIC
  wizardVisible.value = true
}

const viewConfig = async (rule: Rule) => {
  const targetId = rule.caddy_id
  const requestSeq = ++configRequestSeq
  configDialogVisible.value = true
  configLoading.value = true
  ruleConfig.value = null
  
  try {
    // Get rule-specific Caddy config from API
    const res = await request.get<APIResponse<RuleCaddyConfigResponse>>(`/rules/${targetId}/caddy-config`)
    if (requestSeq !== configRequestSeq || !configDialogVisible.value) return
     
    // Build the display config
    const compressTypes = rule.compress_types ? selectedCompressTypes(rule.compress_types) : ['gzip']
    
    ruleConfig.value = {
      id: rule.id || 0,
      caddy_id: res.data?.caddy_id || '',
      name: rule.name || '',
      domain: rule.domain || '',
      listen_port: rule.listen_port || 0,
      protocol: rule.protocol || 'http',
      strategy: rule.strategy || 'weighted_round_robin',
      dynamic_dns: rule.dynamic_dns || false,
      enable_dns_server: rule.enable_dns_server || false,
      dns_server: rule.dns_server || '',
      host_header: rule.host_header || '',
      enable_tls: rule.enable_tls || false,
      tls_source: rule.tls_source || 'manual',
      tls_http_redirect: rule.tls_http_redirect || false,
      enable_compress: rule.enable_compress !== false,
      compress_types: compressTypes,
      health_check_path: rule.health_check_path || '',
      health_check_interval: rule.health_check_interval || 10,
      health_check_timeout: rule.health_check_timeout || 2,
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
      config: res.data?.config ?? null,
      config_not_exists: res.data?.config_not_exists === true,
    }
  } catch (error: unknown) {
    if (requestSeq !== configRequestSeq || !configDialogVisible.value) return
    // Error message is already shown by the global axios interceptor.
    console.error('view config failed', error)
    ruleConfig.value = {
      id: rule.id || 0,
      caddy_id: '',
      name: rule.name || '',
      domain: rule.domain || '',
      listen_port: rule.listen_port || 0,
      protocol: rule.protocol || 'http',
      strategy: rule.strategy || 'weighted_round_robin',
      dynamic_dns: rule.dynamic_dns || false,
      enable_dns_server: rule.enable_dns_server || false,
      dns_server: rule.dns_server || '',
      host_header: rule.host_header || '',
      enable_tls: rule.enable_tls || false,
      tls_source: rule.tls_source || 'manual',
      tls_http_redirect: rule.tls_http_redirect || false,
      enable_compress: rule.enable_compress !== false,
      compress_types: ['gzip'],
      health_check_path: rule.health_check_path || '',
      health_check_interval: rule.health_check_interval || 10,
      health_check_timeout: rule.health_check_timeout || 2,
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
      config: { error: '获取配置失败', details: error instanceof Error ? error.message : undefined },
      config_not_exists: false,
    }
  } finally {
    if (requestSeq === configRequestSeq) configLoading.value = false
  }
}

const onConfigDialogClosed = (): void => {
  configRequestSeq++
  configLoading.value = false
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
const logStatsMaps = ref<{ ip: Record<string, number>; ua: Record<string, number>; uri: Record<string, number>; total: number; startedAt: string } | null>(null)
const logStatsInFlight = ref(false)
const MAX_LOG_STAT_KEYS = 500
const OTHER_LOG_STAT_KEY = '其他'
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

const consumeLogLine = (maps: { ip: Record<string, number>; ua: Record<string, number>; uri: Record<string, number>; total: number }, line: string) => {
  let entry: CaddyLogEntry
  try {
    entry = JSON.parse(line)
  } catch {
    return
  }
  const req = entry?.request
  if (!req) return
  maps.total++
  const ip = req.client_ip || req.src_ip || req.src || req.remote_ip || '-'
  incrementCappedStat(maps.ip, ip)
  let uri = req.uri || req.uri_path || '-'
  const qi = uri.indexOf('?')
  if (qi >= 0) uri = uri.slice(0, qi)
  incrementCappedStat(maps.uri, uri)
  let ua = req.user_agent || ''
  if (!ua && req.headers) {
    const list = req.headers['User-Agent']
    if (Array.isArray(list) && list.length) ua = list[0]
  }
  const g = generalizeUA(ua)
  incrementCappedStat(maps.ua, g)
}

const consumeLogLinesChunked = async (
  lines: readonly string[],
  maps: { ip: Record<string, number>; ua: Record<string, number>; uri: Record<string, number>; total: number },
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

const incrementCappedStat = (map: Record<string, number>, key: string): void => {
  if (Object.prototype.hasOwnProperty.call(map, key)) {
    map[key] += 1
    return
  }
  if (Object.keys(map).length < MAX_LOG_STAT_KEYS - 1) {
    map[key] = 1
    return
  }
  map[OTHER_LOG_STAT_KEY] = (map[OTHER_LOG_STAT_KEY] || 0) + 1
}

const topN = (m: Record<string, number>, n: number) =>
  Object.entries(m).map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, n)

const rebuildStatsView = (m: { ip: Record<string, number>; ua: Record<string, number>; uri: Record<string, number>; total: number; startedAt: string }) => {
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
    const res = await request.get<APIResponse<RuleLogStreamData>>(`/rules/${targetId}/log-stream`, { params: { offset: targetOffset }, signal: healthPolling.signal, silent: true })
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId || logStatsMaps.value !== targetMaps) return
    const lines: string[] = res.data?.lines || []
    if (lines.length) {
      const completed = await consumeLogLinesChunked(lines, targetMaps, () => (
        !disposed
        && requestSeq === ruleLogRequestSeq
        && ruleLogDialogVisible.value
        && ruleLogTab.value === 'stats'
        && ruleLogCaddyId.value === targetId
        && logStatsMaps.value === targetMaps
      ))
      if (!completed) return
      rebuildStatsView(targetMaps)
    }
    logStatsOffset.value = res.data?.offset ?? targetOffset
  } catch (error: unknown) {
    if (!disposed) console.error('Failed to fetch log stream:', error)
  } finally {
    if (!disposed && requestSeq === ruleLogRequestSeq) logStatsInFlight.value = false
  }
}

const startLogStats = async () => {
  if (disposed) return
  const targetId = ruleLogCaddyId.value
  if (!targetId) return
  const requestSeq = ++ruleLogRequestSeq
  const maps = { ip: {}, ua: {}, uri: {}, total: 0, startedAt: new Date().toLocaleString() }
  logStatsMaps.value = maps
  ruleLogStats.value = null
  ruleLogStatsLoading.value = true
  ruleLogStatsError.value = ''
  logStatsOffset.value = 0
  try {
    const res = await request.get<APIResponse<RuleLogData>>(`/rules/${targetId}/logs`, { signal: healthPolling.signal, silent: true })
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId || logStatsMaps.value !== maps) return
    const content: string = res.data?.content || ''
    const completed = await consumeLogLinesChunked(content.split('\n'), maps, () => (
      !disposed
      && requestSeq === ruleLogRequestSeq
      && ruleLogDialogVisible.value
      && ruleLogTab.value === 'stats'
      && ruleLogCaddyId.value === targetId
      && logStatsMaps.value === maps
    ))
    if (!completed) return
    rebuildStatsView(maps)
    logStatsOffset.value = res.data?.offset ?? 0
  } catch (error: unknown) {
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'stats' || ruleLogCaddyId.value !== targetId || logStatsMaps.value !== maps) return
    console.error('Failed to init log stats:', error)
    ruleLogStatsError.value = error instanceof Error ? error.message : '请稍后重试'
  } finally {
    if (!disposed && requestSeq === ruleLogRequestSeq) ruleLogStatsLoading.value = false
  }
}

const onRuleLogTabChange = (tab: string) => {
  ruleLogRequestSeq++
  ruleLogLoading.value = false
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
  stopRuleLogPolling()
  ruleLogContent.value = ''
  ruleLogCaddyId.value = ''
  logStatsMaps.value = null
  ruleLogStats.value = null
  ruleLogStatsLoading.value = false
  ruleLogStatsError.value = ''
  logStatsOffset.value = 0
  ruleLogLoading.value = false
  logStatsInFlight.value = false
}

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

const refreshRuleLogs = async () => {
  if (disposed) return
  if (ruleLogTab.value === 'stats') {
    fetchLogStream()
    return
  }
  if (!ruleLogCaddyId.value || ruleLogLoading.value) return
  const targetId = ruleLogCaddyId.value
  const requestSeq = ++ruleLogRequestSeq
  ruleLogLoading.value = true
  try {
    const res = await request.get<APIResponse<RuleLogData>>(`/rules/${targetId}/logs`, { signal: healthPolling.signal, silent: true })
    if (disposed || requestSeq !== ruleLogRequestSeq || !ruleLogDialogVisible.value || ruleLogTab.value !== 'log' || ruleLogCaddyId.value !== targetId) return
    ruleLogContent.value = res.data?.content || ''
    nextTick(() => {
      if (disposed) return
      const el = ruleLogContainerRef.value
      if (el) el.scrollTop = el.scrollHeight
    })
  } catch (error: unknown) {
    if (!disposed) console.error('Failed to fetch rule logs:', error)
  } finally {
    if (!disposed && requestSeq === ruleLogRequestSeq) ruleLogLoading.value = false
  }
}

watch(ruleLogAutoRefresh, (val) => {
  if (!ruleLogDialogVisible.value) return
  if (val) startRuleLogPolling()
  else stopRuleLogPolling()
})

const healthPolling = usePollingTask(async () => fetchHealthStatus(), {
  interval: 15000,
  onError: (error) => console.error('Failed to poll health status:', error),
})
const certPollingError = usePollingErrorState()
const certPollingErrorDescription = computed(() => {
  const lastError = formatDate(certPollingError.lastErrorAt.value)
  const retryAt = formatDate(certPollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const certJobsPolling = usePollingTask(async () => {
  if (!certPollingError.canRun()) return
  if (rules.value.some((rule) => rule.tls_source === 'acme_dns') || pendingCertInfoRefresh.size > 0) {
    await fetchCertJobs()
  }
  certPollingError.clear()
}, {
  interval: 5000,
  onError: (error) => {
    console.error('Failed to poll certificate jobs:', error)
    certPollingError.recordError(error)
  },
})

const retryCertPolling = async (): Promise<void> => {
  certPollingError.resetBackoff()
  await certJobsPolling.run()
}

watch(
  () => pagedRules.value.map((rule) => rule.caddy_id).join('\u0000'),
  () => void certJobsPolling.run(),
)

onMounted(() => {
  const ruleSearch = localStorage.getItem('rules-search')
  if (ruleSearch) { searchQuery.value = ruleSearch; localStorage.removeItem('rules-search') }
  void fetchRules()
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
  stopRuleLogPolling()
})
</script>

<style scoped>
.table-toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; }
.search-input { width: 280px; }
.rules-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
.polling-error-alert { margin-bottom: 16px; }
.polling-error-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%; }
.polling-error-meta { font-size: 12px; }
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header-left { flex: 1; }

.page-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.title-icon { color: #3b82f6; font-size: 20px; }

.page-desc {
  font-size: 13px;
  color: #6b7280;
  margin: 4px 0 0 28px;
}

.rule-name-cell { display: flex; align-items: center; flex-wrap: nowrap; gap: 6px; white-space: nowrap; }
.acl-lock-icon { flex: 0 0 auto; cursor: pointer; }
.acl-lock-icon.is-allow { color: var(--el-color-success); }
.acl-lock-icon.is-deny { color: var(--el-color-danger); }
.security-tooltip { min-width: 200px; font-size: 13px; }
.security-tooltip .cert-value { max-width: 240px; }
.security-tooltip .policy-group + .policy-group { margin-top: 8px; padding-top: 8px; border-top: 1px dashed #e5e7eb; }
.security-tooltip .policy-group.is-disabled { opacity: 0.45; }
.security-tooltip .policy-group-header { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; font-weight: 600; }
.security-tooltip .policy-order { color: #6b7280; font-variant-numeric: tabular-nums; }
.security-tooltip .policy-name { color: #1f2937; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rule-name-link { 
  font-weight: 500; 
  color: #111827; 
  cursor: pointer;
  text-decoration: none;
}
.rule-name-link:hover { 
  color: #3b82f6; 
  text-decoration: underline;
}
.domain { font-family: monospace; color: #374151; }
.description { 
  display: block;
  max-width: 130px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #6b7280;
}
.port { font-family: monospace; color: #374151; }
.tls-tag {
  min-width: 44px;
}
.text-secondary { color: #6b7280; }
.port-warning { color: #eab308; }

/* Fix table cell padding */
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

/* Override el-popover inner content */
:deep(.el-popover__content) {
  padding: 12px !important;
}

.tooltip-title {
  font-weight: 600;
  margin: 0 0 4px 0;
  color: #374151;
  padding: 0;
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

.upstream-healthy {
  color: #22c55e;
  font-size: 12px;
}

.upstream-unhealthy {
  color: #ef4444;
  font-size: 12px;
}

.upstream-degraded {
  color: var(--el-color-warning);
}
.upstream-unknown {
  color: #9ca3af;
  font-size: 12px;
}

.upstream-metrics {
  display: flex !important;
  align-items: center !important;
  gap: 2px !important;
  font-size: 11px;
  color: #6b7280;
}

.metric-num {
  color: #3b82f6;
}

.metric-fails {
  color: #ef4444;
}

/* Fix cell padding issue */
.el-popover.el-popper {
  padding: 12px;
}

.tooltip-title {
  font-weight: 600;
  margin-bottom: 8px;
  color: #374151;
  border-bottom: 1px solid #e5e7eb;
  padding-bottom: 6px;
}

.upstream-item:last-child {
  border-bottom: none;
}

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

.upstream-unknown {
  color: #9ca3af;
  font-size: 14px;
}

.upstream-metrics {
  display: flex;
  gap: 12px;
  font-size: 11px;
  padding-left: 4px;
}

.metric-num {
  color: #3b82f6;
}

.metric-fails {
  color: #ef4444;
}

/* Status switch */
.status-switch :deep(.el-switch__core) {
  margin: 0;
}

/* Operation buttons */
.operation-buttons {
  display: flex;
  gap: 2px;
  justify-content: center;
}
.operation-buttons .el-button {
  margin: 0;
  padding: 2px 4px;
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

.cert-info-alert :deep(.el-alert__content) {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.cert-info-title {
  font-weight: 600;
  font-size: 14px;
}

.cert-info-detail {
  font-size: 13px;
  color: #606266;
  line-height: 1.4;
}

.cert-expiry-warning {
  color: #e6a23c;
  font-weight: 600;
}

.cert-expiry-normal {
  color: #67c23a;
}

.cert-warning-text {
  color: #e6a23c;
  font-size: 13px;
  margin-top: 4px;
  font-weight: 500;
}

.wizard-steps { margin-bottom: 24px; }

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

.upstream-input { width: 100%; }
.upstream-input.is-error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px #f56c6c inset;
}
.upstream-input-small { width: 100%; }

.strategy-cards {
  display: flex;
  gap: 8px;
  width: 100%;
  padding: 0 20px;
  box-sizing: border-box;
}

.strategy-card {
  flex: 1;
  min-width: 0;
  padding: 8px 10px;
  border: 1px solid #e5e7eb;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  flex-direction: column;
  justify-content: center;
  min-height: 44px;
  box-sizing: border-box;
}

.compact-divider {
  margin: 16px 0 12px 0;
}

.compact-divider :deep(.el-divider__text) {
  font-size: 14px;
  font-weight: 500;
  padding: 0 8px;
}

.compact-divider :deep(.el-divider__line) {
  width: calc(50% - 30px);
}

.active-check-control {
  display: flex;
  align-items: center;
  gap: 12px;
}

.strategy-card:hover {
  background-color: #f8fafc;
  border-color: #cbd5e1;
}

.strategy-card.active {
  background-color: #f0f9ff;
  border-color: #3b82f6;
}

.strategy-card-title {
  font-weight: 500;
  color: #1e293b;
  font-size: 14px;
  line-height: 1.2;
}

.strategy-card-desc {
  font-size: 11px;
  color: #64748b;
  line-height: 1.3;
  margin-top: 2px;
}

.active-check-control {
  display: flex;
  align-items: center;
  gap: 12px;
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

.config-info {
  margin-bottom: 16px;
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
@media (max-width: 767px) {
  .stats-grid { grid-template-columns: 1fr; }
}
.stats-card { border: 1px solid var(--border-lighter); border-radius: 8px; }
.stats-card :deep(.el-card__header) { padding: 8px 12px; background: #f9fafb; }
.stats-card :deep(.el-card__body) { padding: 4px 8px; }
.stats-card-header { display: flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 600; color: #374151; }
.stats-card-header .el-icon { color: var(--el-color-primary); }
.stats-count { color: var(--el-color-primary); font-weight: 600; }
.rule-log-viewer {
  height: 60vh;
  min-height: 300px;
  max-height: 700px;
  overflow: auto;
  padding: 12px 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.7;
  background: #0f172a;
  color: #e2e8f0;
  border: 1px solid #1e293b;
  border-radius: 4px;
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

/* Certificate hover tooltip */
.cert-tooltip .tooltip-title {
  font-weight: 600;
  margin-bottom: 8px;
  border-bottom: 1px solid #e5e7eb;
  padding-bottom: 6px;
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
