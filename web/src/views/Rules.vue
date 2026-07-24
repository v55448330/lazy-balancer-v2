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
      <el-button type="primary" :disabled="isReadOnly" @click="openWizard()">
        <el-icon><Plus /></el-icon>
        新建规则
      </el-button>
    </div>

    <el-card>
      <div class="table-toolbar">
        <el-input v-model="searchQuery" placeholder="搜索规则名 / 域名 / 端口" clearable :prefix-icon="Search" class="search-input" />
      </div>
      <el-table :data="pagedRules" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
        <el-table-column prop="name" label="规则名称" min-width="140">
          <template #default="{ row }">
            <div class="rule-name-cell">
              <a class="rule-name-link" @click.prevent="viewConfig(row)">{{ row.name }}</a>
              <el-tag v-if="row.ip_acl_mode === 'allow'" type="success" size="small" effect="plain">白名单 {{ row.ip_acl_list?.length || 0 }}</el-tag>
              <el-tag v-else-if="row.ip_acl_mode === 'deny'" type="danger" size="small" effect="plain">黑名单 {{ row.ip_acl_list?.length || 0 }}</el-tag>
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
                  <span class="cert-value">{{ certInfoMap[row.caddy_id]?.not_before || '-' }}</span>
                </div>
                <div class="cert-row">
                  <span class="cert-label">过期时间</span>
                  <span class="cert-value">{{ certInfoMap[row.caddy_id]?.not_after || '-' }}</span>
                </div>
                <div class="cert-row">
                  <span class="cert-label">剩余天数</span>
                  <span :class="['cert-days', certInfoMap[row.caddy_id]?.status]">
                    {{ certInfoMap[row.caddy_id]?.days_remaining }} 天
                  </span>
                </div>
                <div class="cert-row" v-if="certInfoMap[row.caddy_id]?.error">
                  <span class="cert-label">错误</span>
                  <span class="cert-error" :title="certInfoMap[row.caddy_id]?.error">{{ certInfoMap[row.caddy_id]?.error }}</span>
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
                  <div v-for="upstream in row.upstreams" :key="upstream.id" class="upstream-item">
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
                <el-button type="primary" link size="small" @click="openWizard(row)" :disabled="isReadOnly || !canEditRule(row)">
                    编辑
                  </el-button>
                </div>
              </el-tooltip>
              <div>
              <el-button type="primary" link size="small" :disabled="isReadOnly" @click="duplicateRule(row)">
                  复制
                </el-button>
              </div>
              <div>
                <el-button type="primary" link size="small" :disabled="!row.log_enabled" @click="openRuleLogDialog(row)">
                  日志
                </el-button>
              </div>
              <div>
                <el-button type="primary" link size="small" :disabled="isReadOnly" @click="openAclDialog(row)">
                  访问控制
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

    <RuleAclDialog
      :visible="aclDialogVisible"
      :rule-name="aclTarget?.name || ''"
      :initial-mode="aclTarget?.ip_acl_mode || ''"
      :initial-cidrs="aclTarget?.ip_acl_list || []"
      :saving="aclSaving"
      @update:visible="aclDialogVisible = $event"
      @save="saveAcl"
    />

    <el-dialog v-model="wizardVisible" :title="editingRule ? '编辑规则' : (isCopyMode ? '复制规则' : '新建规则')" width="min(800px, 94vw)" top="5vh" :close-on-click-modal="false" @close="resetWizard">
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
              <div class="form-tip-tight">多个域名用逗号分隔，用于 HTTPS 证书和 HTTP 重定向</div>
            </el-form-item>

            <el-form-item label="监听端口" required>
              <el-input-number v-model="wizardForm.listen_port" :min="1" :max="65535" controls-position="right" />
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
                <div class="form-tip">请先在「系统设置 / 免费证书」中添加 DNS 提供商配置</div>
              </el-form-item>
              <el-form-item label="CA 提供商">
                <el-select v-model="wizardForm.ca_provider_id" placeholder="系统默认" clearable style="width: 100%">
                  <el-option label="系统默认" :value="0" />
                  <el-option v-for="p in enabledCAProviders" :key="p.id" :label="p.name" :value="p.id" />
                </el-select>
                <div class="form-tip">选择自动签发证书使用的 CA 提供商，留空或「系统默认」将跟随全局默认设置</div>
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
              <el-button size="small" type="primary" @click="addUpstream" :disabled="wizardForm.dynamic_dns && wizardForm.upstreams.length >= 1">
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
                    :class="{ 'is-error': !row.host && upstreamTouched[$index] }"
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
              <el-table-column label="PROXY" width="100">
                <template #default="{ row }">
                  <el-select v-model="row.proxy_protocol" size="small" placeholder="无">
                    <el-option value="" label="无" />
                    <el-option value="v1" label="v1" />
                    <el-option value="v2" label="v2" />
                  </el-select>
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
            <div class="form-tip">
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
                <el-select v-model="wizardForm.compress_types" placeholder="选择压缩方式" style="width: 200px;">
                  <el-option value="gzip" label="gzip" />
                  <el-option value="zstd" label="zstd" />
                </el-select>
              </el-form-item>

              <el-divider content-position="left" class="compact-divider">动态上游</el-divider>

              <el-form-item label="启用动态上游">
                <div class="dynamic-dns-content">
                  <el-switch v-model="wizardForm.dynamic_dns" />
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
            <el-descriptions-item label="DNS 服务器" v-if="wizardForm.protocol === 'http'">
              <template v-if="wizardForm.enable_dns_server">
                {{ wizardForm.dns_server || '默认' }}
              </template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="动态上游" v-if="wizardForm.protocol === 'http'">
              <template v-if="wizardForm.dynamic_dns">
                启用 (协议栈: {{ (() => { const families = wizardForm.dns_family || []; if (families.length === 2) return 'IPv4/IPv6'; if (families.includes('ipv4')) return 'IPv4'; if (families.includes('ipv6')) return 'IPv6'; return 'None'; })() }})
              </template>
              <template v-else>禁用</template>
            </el-descriptions-item>
            <el-descriptions-item label="压缩" v-if="wizardForm.protocol === 'http'">
              {{ wizardForm.enable_compress ? (wizardForm.compress_types || 'gzip') : '禁用' }}
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
                  <template #default="{ row }">{{ weightPercent(wizardForm.upstreams, row) }}%</template>
                </el-table-column>
                <el-table-column prop="max_connections" label="最大连接" width="90" />
                <el-table-column prop="proxy_protocol" label="PROXY" width="80" />
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
    <el-dialog v-model="configDialogVisible" title="Caddy 配置" width="900" :close-on-click-modal="true">
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
            {{ ruleConfig.enable_compress ? (ruleConfig.compress_types || 'gzip') : '禁用' }}
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
            失败 {{ ruleConfig.health_check_unhealthy_threshold || 3 }} 次视为不健康, 间隔 {{ ruleConfig.health_check_interval || 10 }}s, 超时 {{ ruleConfig.health_check_timeout || 5 }}s
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
          <el-table-column prop="proxy_protocol" label="PROXY" align="center" />
          <el-table-column prop="enabled" label="状态" align="center">
            <template #default="{ row }">
              <el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        
        <el-divider content-position="left">Caddy 配置 (JSON)</el-divider>
        <pre class="config-code">{{ JSON.stringify(ruleConfig.config, null, 2) }}</pre>
      </div>
      <div v-else class="config-empty">
        <el-empty description="未找到该规则的配置信息" :image-size="60" />
      </div>
    </el-dialog>

    <el-dialog
      v-model="ruleLogDialogVisible"
      :title="`访问日志 - ${ruleLogRuleName}`"
      width="70%"
      :style="{ maxWidth: '70vw' }"
      destroy-on-close
      @opened="onRuleLogDialogOpened"
      @closed="onRuleLogDialogClosed"
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
          <template v-if="ruleLogStats">
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
        <el-button @click="ruleLogDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, computed, watch, nextTick } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/api'
import { Plus, Operation, Delete, InfoFilled, Lock, Connection, Guide, Check, ArrowLeft, ArrowRight, Document, CircleCheckFilled, CircleCloseFilled, QuestionFilled, Setting, RefreshRight, Search, WarningFilled, Location, Monitor, Link} from '@element-plus/icons-vue'
import { ElMessageBox, ElMessage } from 'element-plus'
import { ansiToHtml } from '@/utils/ansi'
import { formatDate } from '@/utils/date'
import type { IpAclMode, PathRule, ProxyTimeoutConfig } from '@/types'
import RuleAclDialog from '@/components/rules/RuleAclDialog.vue'
import PathRulesEditor from '@/components/rules/PathRulesEditor.vue'
import ProxyTimeoutFields from '@/components/rules/ProxyTimeoutFields.vue'
import { validatePathRules } from '@/utils/ruleValidation'

interface Upstream {
  id?: number
  rule_id?: number
  host: string
  port: number
  weight: number
  domain: string
  dynamic_dns: boolean
  enabled: boolean
  protocol?: string
  max_connections?: number
  proxy_protocol?: string
}

interface Rule extends ProxyTimeoutConfig {
  id?: number
  caddy_id: string
  name: string
  description?: string
  protocol: string
  domain: string
  listen_port: number
  strategy: string
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  dns_family: string[]
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_healthy_threshold: number
  health_check_unhealthy_threshold: number
  enable_active_health_check: boolean
  tcp_health_check_port?: number
  tcp_try_duration?: number
  tcp_try_interval?: number
  host_header: string
  upstreams: Upstream[]
  enable_tls: boolean
  tls_source?: string
  acme_config_id?: number | undefined
  ca_provider_id?: number | undefined
  tls_cert: string
  tls_key: string
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string
  request_body_max_size_mb?: number
  upstream_keepalive_timeout?: number
  server_tokens_hidden?: number
  enabled: boolean
  log_enabled?: boolean
  ip_acl_mode: IpAclMode
  ip_acl_list: string[]
  custom_routes_enabled: boolean
  path_rules: PathRule[]
  created_by?: number
  updated_by?: number
  creator_name?: string
  created_at?: string
  updated_at?: any
}

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

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
  status: string
  message: string
  expires_at?: string
}

const rules = ref<Rule[]>([])
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
        return name.includes(query) || domain.includes(query) || port.includes(query)
      })
    : rules.value
  return [...base].sort((a, b) => ruleUpdatedAtMs(b) - ruleUpdatedAtMs(a))
})

const ruleUpdatedAtMs = (rule: Rule): number => {
  const value: any = rule.updated_at
  const raw = typeof value === 'object' && value !== null && 'Time' in value ? value.Time : value
  const t = raw ? new Date(raw).getTime() : 0
  return Number.isNaN(t) ? 0 : t
}

const pagedRules = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredRules.value.slice(start, start + pageSize.value)
})

watch(searchQuery, () => {
  currentPage.value = 1
})
const users = ref<any[]>([])
const certInfoMap = ref<Record<string, CertInfo | null>>({})
const certJobMap = ref<Record<string, CertJob>>({})
const ruleTogglePending = ref<Record<string, boolean>>({})

const getUpdaterName = (userId?: number) => {
  if (!userId || userId === 0) return '-'
  const user = users.value.find(u => u.id === userId)
  if (user) {
    // Handle display_name which can be { String: "", Valid: false } or direct string
    let displayName = ''
    if (user.display_name) {
      if (typeof user.display_name === 'string') {
        displayName = user.display_name
      } else if (user.display_name.String) {
        displayName = user.display_name.String
      }
    }
    return displayName || user.username || '-'
  }
  return '-'
}

const fetchRules = async () => {
  loading.value = true
  try {
    const res = await request.get('/rules')
    rules.value = res.data || []
    // Fetch health status after rules are loaded
    fetchHealthStatus()
    // Fetch certificate info for TLS-enabled rules
    fetchCertInfo()
    // Fetch cert job statuses for ACME rules
    fetchCertJobs()
  } finally {
    loading.value = false
  }
}

const fetchCertInfo = async () => {
  const tlsRules = rules.value.filter(r => r.enable_tls)
  if (tlsRules.length === 0) {
    certInfoMap.value = {}
    return
  }
  try {
    const res = await request.post('/rules/cert-info', {
      caddy_ids: tlsRules.map(r => r.caddy_id)
    })
    certInfoMap.value = res.data || {}
  } catch (e: any) {
    // Non-critical: keep existing cert info map or clear it
    certInfoMap.value = {}
  }
}

let certJobsInFlight = false
const fetchCertJobs = async () => {
  if (certJobsInFlight) return
  certJobsInFlight = true
  try {
    const res = await request.get('/certificates/jobs')
    const jobs: CertJob[] = res.data || []
    const map: Record<string, CertJob> = {}
    jobs.forEach(job => {
      if (job.rule_id) {
        // Keep the most recent non-terminal job if multiple exist
        const existing = map[job.rule_id]
        if (!existing || isCertJobActive(existing.status)) {
          map[job.rule_id] = job
        }
      }
    })
    certJobMap.value = map
  } catch (e: any) {
    certJobMap.value = {}
  } finally {
    certJobsInFlight = false
  }
}

const isCertJobActive = (status?: string) => {
  if (!status) return false
  return !['issued', 'failed', 'disabled'].includes(status)
}

const certJobStatusLabel = (status?: string) => {
  switch (status) {
    case 'issued': return '已签发'
    case 'failed': return '签发失败'
    case 'disabled': return '已禁用'
    case 'pending': return '待处理'
    case 'queued':
    case 'creating_account':
    case 'creating_order':
    case 'order_created':
    case 'presenting_dns':
    case 'waiting_propagation':
    case 'dns_propagated':
    case 'accepting_challenge':
    case 'validating':
    case 'validated':
    case 'finalizing':
    case 'finalized':
    case 'downloading':
    case 'downloaded':
    case 'cleanup_dns':
    case 'cleanup_warning':
      return '签发中'
    case 'waiting_ca': return '等待 CA'
    default: return status || '未知'
  }
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
  if (row.tls_source === 'acme_dns') {
    const status = certJobMap.value[row.caddy_id]?.status
    if (status === 'issued') return 'success'
    if (status === 'failed') return 'danger'
    return 'warning'
  }
  return 'primary'
}

const tlsTagLabel = (row: Rule) => {
  const cert = certInfoMap.value[row.caddy_id]
  if (cert?.status === 'expired') return '已过期'
  if (cert?.status === 'expiring') return `临期 ${cert.days_remaining} 天`
  if (row.tls_source === 'acme_dns') {
    const status = certJobMap.value[row.caddy_id]?.status
    const label = status ? certJobStatusLabel(status) : 'ACME'
    return `ACME · ${label}`
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
const certConfigs = ref<any[]>([])
const caProviders = ref<Array<{ id: number; name: string; enabled: boolean }>>([])
const enabledCAProviders = computed(() => caProviders.value.filter(p => p.enabled))
const globalConfig = ref<{ default_ca_provider_id?: number }>({})
const healthStatus = ref<Record<string, { healthy: number; unhealthy: number; degraded: number; unknown: number; total: number; upstreams: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; num_requests?: number; fails?: number }> }>>({})
let healthPollTimer: ReturnType<typeof setInterval> | null = null
let certJobPollTimer: ReturnType<typeof setInterval> | null = null

// Config viewing
const configDialogVisible = ref(false)
const configLoading = ref(false)

const aclDialogVisible = ref(false)
const aclSaving = ref(false)
const aclTarget = ref<Rule | null>(null)

const openAclDialog = (rule: Rule): void => {
  if (isReadOnly.value) return
  aclTarget.value = rule
  aclDialogVisible.value = true
}

const saveAcl = async (value: { readonly mode: IpAclMode; readonly cidrs: readonly string[] }): Promise<void> => {
  const target = aclTarget.value
  if (!target || isReadOnly.value || aclSaving.value) return
  aclSaving.value = true
  try {
    const response = await request.get<{ readonly data: Rule }>(`/rules/${target.caddy_id}`)
    await request.put(`/rules/${target.caddy_id}`, {
      ...response.data,
      ip_acl_mode: value.mode,
      ip_acl_list: [...value.cidrs],
    })
    ElMessage.success('访问控制已保存')
    aclDialogVisible.value = false
    await fetchRules()
  } finally {
    aclSaving.value = false
  }
}

const ruleLogDialogVisible = ref(false)
const ruleLogRuleName = ref('')
const ruleLogCaddyId = ref('')
const ruleLogContent = ref('')
const ruleLogLoading = ref(false)
const ruleLogAutoRefresh = ref(true)
const ruleLogContainerRef = ref<HTMLElement | null>(null)
let ruleLogPollTimer: ReturnType<typeof setInterval> | null = null

const ruleLogHtml = computed(() => ansiToHtml(ruleLogContent.value || '暂无日志'))
const ruleConfig = ref<{
  id: number
  caddy_id: string
  name: string
  domain: string
  listen_port: number
  protocol: string
  strategy: string
  dynamic_dns: boolean
  enable_dns_server: boolean
  dns_server: string
  host_header: string
  enable_tls: boolean
  tls_source: string
  tls_http_redirect: boolean
  enable_compress: boolean
  compress_types: string
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
  upstreams: any[]
  enabled: boolean
  config: any
} | null>(null)

const upstreamHostWarning = computed(() => {
  const hasEmptyHost = wizardForm.upstreams.some((u, i) => !u.host && upstreamTouched.value[i])
  if (hasEmptyHost) {
    return '主机地址为必填项，请填写完整'
  }
  return ''
})

interface HealthSummary { healthy: number; unhealthy: number; degraded: number; unknown: number; total: number }

const getHealthTagType = (status: HealthSummary) => {
  if (status.unhealthy + status.degraded === status.total) return 'danger'
  if (status.unhealthy + status.degraded > 0) return 'warning'
  if (status.unknown === status.total) return 'info'
  return 'success'
}

const getHealthLabel = (status: HealthSummary) => {
  if (status.unhealthy + status.degraded === status.total) return '异常'
  if (status.unhealthy + status.degraded > 0) return '异常'
  if (status.unknown === status.total) return '未知'
  return '正常'
}

const getUpstreamHealthStatus = (ruleId: string, upstream: any) => {
  const status = healthStatus.value[ruleId]
  if (!status || !status.upstreams) return { healthy: false, unknown: true }
  const upstreamKey = `${upstream.host}:${upstream.port}`
  const upstreamData = status.upstreams[upstreamKey]
  return upstreamData ? { healthy: upstreamData.healthy, unknown: upstreamData.unknown, degraded: upstreamData.degraded } : { healthy: false, unknown: true, degraded: false }
}

const getUpstreamMetrics = (ruleId: string, upstream: any) => {
  const status = healthStatus.value[ruleId]
  if (!status || !status.upstreams) return { num_requests: 0, fails: 0 }
  const upstreamKey = `${upstream.host}:${upstream.port}`
  const upstreamData = status.upstreams[upstreamKey]
  return {
    num_requests: upstreamData?.num_requests || 0,
    fails: upstreamData?.fails || 0
  }
}

const formatUpdatedTime = (updatedAt: any): string => {
  if (!updatedAt) return '-'
  return formatDate(updatedAt) || '-'
}

let healthInFlight = false
const fetchHealthStatus = async () => {
  if (healthInFlight) return
  healthInFlight = true
  try {
    const res = await request.get('/config/health')
    const healthData = res.data || {}
    console.log('Health data received:', JSON.stringify(healthData))
    
    const mapped: Record<string, { healthy: number; unhealthy: number; degraded: number; unknown: number; total: number; upstreams: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; num_requests?: number; fails?: number }> }> = {}
    for (const rule of rules.value) {
      if (rule.upstreams && rule.upstreams.length > 0) {
        let healthy = 0
        let unhealthy = 0
        let degraded = 0
        let unknown = 0
        const upstreamStatus: Record<string, { healthy: boolean; unknown: boolean; degraded?: boolean; num_requests?: number; fails?: number }> = {}
        for (const upstream of rule.upstreams) {
          const upstreamKey = `${upstream.host}:${upstream.port}`
          
          let isHealthy = false
          let isUnknown = true
          let isDegraded = false
          let numRequests = 0
          let fails = 0
          
          for (const serverHealth of Object.values(healthData) as any[]) {
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
          mapped[rule.caddy_id] = { healthy, unhealthy, degraded, unknown, total: rule.upstreams.length, upstreams: upstreamStatus }
        }
      }
    }
    healthStatus.value = mapped
  } catch (e) {
    console.error('Failed to fetch health status:', e)
  } finally {
    healthInFlight = false
  }
}

const defaultUpstream = (protocol: string = 'http'): Upstream => ({
  host: '',
  port: protocol === 'tcp' ? 8080 : 80,
  weight: 1,
  domain: '',
  dynamic_dns: false,
  enabled: true,
  protocol,
  max_connections: 0,
  proxy_protocol: '',
})

const certInfo = reactive({
  valid: false,
  domain: '',
  issuer: '',
  expiryDate: '',
  daysUntilExpiry: 0,
  warning: '',
  error: ''
})

const wizardForm = reactive<Rule>({
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
  health_check_timeout: 5,
  health_check_healthy_threshold: 2,
  health_check_unhealthy_threshold: 3,
  enable_active_health_check: true,
  tcp_health_check_port: 0,
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
  compress_types: 'gzip',
  request_body_max_size_mb: 0,
  upstream_keepalive_timeout: 0,
  server_tokens_hidden: 0,
  enabled: true,
  log_enabled: false,
  ip_acl_mode: '',
  ip_acl_list: [],
  custom_routes_enabled: false,
  path_rules: [],
  proxy_dial_timeout: 0,
  proxy_response_header_timeout: 0,
  proxy_read_timeout: 0,
  proxy_write_timeout: 0,
  proxy_stream_timeout: 0,
})

// Watch for enable_tls toggle to adjust default listen port
watch(() => wizardForm.enable_tls, (newVal, oldVal) => {
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
})

// Watch for protocol changes to adjust defaults for TCP rules
watch(() => wizardForm.protocol, (newVal, oldVal) => {
  if (newVal === 'tcp') {
    // Switching to TCP: use a neutral high port and plain TCP upstreams
    if (wizardForm.listen_port === 80 || wizardForm.listen_port === 443) {
      wizardForm.listen_port = 8080
    }
    wizardForm.enable_tls = false
    wizardForm.custom_routes_enabled = false
    wizardForm.path_rules = []
    wizardForm.upstreams.forEach(u => {
      if (!u.host && (u.protocol === 'http' || u.protocol === 'https')) {
        u.protocol = 'tcp'
      }
    })
  } else if (newVal === 'http' && oldVal === 'tcp') {
    if (wizardForm.listen_port === 8080) {
      wizardForm.listen_port = 80
    }
    wizardForm.upstreams.forEach(u => {
      if (!u.host && (u.protocol === 'tcp' || u.protocol === 'tls')) {
        u.protocol = 'http'
      }
    })
  }
})

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
  const existingRules = editingRule.value 
    ? rules.value.filter(r => r.caddy_id !== editingRule.value!.caddy_id)
    : rules.value
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
    const res = await request.get('/users')
    users.value = res.data || []
  } catch (e) {
    console.error('Failed to fetch users:', e)
  }
}

const fetchCertConfigs = async () => {
  try {
    const res = await request.get('/certificate-configs')
    certConfigs.value = res.data || []
  } catch (e) {
    console.error('Failed to fetch cert configs:', e)
  }
}

const fetchCAProviders = async () => {
  try {
    const res = await request.get('/ca-providers')
    caProviders.value = res.data || []
  } catch (e) {
    console.error('Failed to load CA providers:', e)
  }
}

const fetchGlobalConfig = async () => {
  try {
    const res = await request.get('/config')
    globalConfig.value = res.data || {}
  } catch (e) {
    console.error('Failed to load global config:', e)
  }
}

const validateCertificate = async () => {
  certInfo.valid = false
  certInfo.warning = ''
  certInfo.error = ''
  certInfo.domain = ''
  certInfo.expiryDate = ''
  certInfo.daysUntilExpiry = 0

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
    const res = await request.post('/certificates/parse', {
      cert_pem: certPEM,
      key_pem: keyPEM
    })
    
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
  } catch (e: any) {
    certInfo.error = e.message || '证书验证请求失败'
  }
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

const openWizard = (rule?: Rule) => {
  if (isReadOnly.value) return
  isCopyMode.value = false
  if (rule) {
    editingRule.value = rule
    let compressType = 'gzip'
    if (rule.compress_types) {
      if (Array.isArray(rule.compress_types) && rule.compress_types.length > 0) {
        compressType = rule.compress_types[0] as string
      } else if (typeof rule.compress_types === 'string') {
        compressType = (rule.compress_types as string).split(',')[0].trim()
      }
    }
    Object.assign(wizardForm, {
      name: rule.name,
      description: rule.description || '',
      protocol: rule.protocol,
      domain: rule.domain || '',
      listen_port: rule.listen_port,
      strategy: rule.strategy || 'weighted_round_robin',
      dynamic_dns: rule.dynamic_dns || false,
      enable_dns_server: (rule as any).enable_dns_server || false,
      dns_server: (rule as any).dns_server || '',
      dns_family: (() => { const df = (rule as any).dns_family; if (Array.isArray(df)) return df; if (df === 'both') return ['ipv4', 'ipv6']; if (df === 'ipv4') return ['ipv4']; if (df === 'ipv6') return ['ipv6']; return ['ipv4']; })(),
      health_check_path: rule.health_check_path || '',
      health_check_interval: rule.health_check_interval || 10,
      health_check_timeout: rule.health_check_timeout || 5,
      health_check_healthy_threshold: rule.health_check_healthy_threshold || 2,
      health_check_unhealthy_threshold: rule.health_check_unhealthy_threshold || 3,
      enable_active_health_check: rule.enable_active_health_check === true,
      tcp_health_check_port: (rule as any).tcp_health_check_port || 0,
      tcp_try_duration: (rule as any).tcp_try_duration || 0,
      tcp_try_interval: (rule as any).tcp_try_interval ?? 250,
      host_header: rule.host_header || '',
      upstreams: rule.upstreams?.map(u => ({
        ...u,
        dynamic_dns: false,
        protocol: u.protocol || 'http',
        max_connections: u.max_connections ?? 0,
        proxy_protocol: u.proxy_protocol ?? '',
      })) || [],
      enable_tls: rule.enable_tls || false,
      tls_source: rule.tls_source || 'manual',
      acme_config_id: rule.acme_config_id || undefined,
      ca_provider_id: rule.ca_provider_id ?? 0,
      tls_cert: rule.tls_cert || '',
      tls_key: rule.tls_key || '',
      tls_http_redirect: rule.tls_http_redirect || false,
      enable_compress: rule.enable_compress !== false,
      compress_types: compressType,
      request_body_max_size_mb: (rule as any).request_body_max_size_mb || 0,
      upstream_keepalive_timeout: (rule as any).upstream_keepalive_timeout || 0,
      server_tokens_hidden: (rule as any).server_tokens_hidden || 0,
      enabled: rule.enabled,
      log_enabled: (rule as any).log_enabled || false,
      ip_acl_mode: rule.ip_acl_mode || '',
      ip_acl_list: [...(rule.ip_acl_list || [])],
      custom_routes_enabled: rule.custom_routes_enabled === true,
      path_rules: [...(rule.path_rules || [])]
        .sort((left, right) => left.sort_order - right.sort_order)
        .map((pathRule) => ({
          ...pathRule,
          upstreams: pathRule.upstreams?.map((upstream) => ({ ...upstream })) || null,
        })),
      proxy_dial_timeout: rule.proxy_dial_timeout || 0,
      proxy_response_header_timeout: rule.proxy_response_header_timeout || 0,
      proxy_read_timeout: rule.proxy_read_timeout || 0,
      proxy_write_timeout: rule.proxy_write_timeout || 0,
      proxy_stream_timeout: rule.proxy_stream_timeout || 0,
    })
    weightsToPercent(wizardForm.upstreams)
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
      health_check_timeout: 5,
      health_check_healthy_threshold: 2,
      health_check_unhealthy_threshold: 3,
      enable_active_health_check: true,
      tcp_health_check_port: 0,
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
      compress_types: 'gzip',
      request_body_max_size_mb: 0,
      upstream_keepalive_timeout: 0,
      server_tokens_hidden: 0,
      enable_dns_server: false,
      log_enabled: false,
      enabled: true,
      ip_acl_mode: '',
      ip_acl_list: [],
      custom_routes_enabled: false,
      path_rules: [],
      proxy_dial_timeout: 0,
      proxy_response_header_timeout: 0,
      proxy_read_timeout: 0,
      proxy_write_timeout: 0,
      proxy_stream_timeout: 0,
    })
  }
  currentStep.value = WIZARD_STEP.BASIC
  wizardVisible.value = true
}

const resetWizard = () => {
  editingRule.value = null
  isCopyMode.value = false
  currentStep.value = WIZARD_STEP.BASIC
}

// Weights are shown and edited as percentages of enabled upstreams; the
// interlock keeps the enabled total at 100 so values stay meaningful.
const onWeightChange = (changedIdx: number) => {
  const rows = wizardForm.upstreams
  if (!rows.length) return
  const enabled = rows.map((r, i) => ({ r, i })).filter(({ r }) => r.enabled)
  if (enabled.length === 0) return
  const changed = rows[changedIdx]
  if (changed && !changed.enabled) {
    // Disabled a row: redistribute its share across the remaining enabled rows.
    changed.weight = 0
  }
  const anchor = enabled.find(({ i }) => i === changedIdx)
  const others = enabled.filter(({ i }) => i !== changedIdx)
  if (others.length === 0) {
    if (anchor) anchor.r.weight = 100
    return
  }
  const anchorVal = anchor ? Math.min(100, Math.max(0, anchor.r.weight || 0)) : 0
  if (anchor) anchor.r.weight = anchorVal
  const remaining = 100 - anchorVal
  const othersSum = others.reduce((sum, { r }) => sum + (r.weight || 0), 0)
  if (othersSum === 0) {
    const base = Math.floor(remaining / others.length)
    others.forEach(({ r }, k) => {
      r.weight = k === 0 ? remaining - base * (others.length - 1) : base
    })
  } else {
    let acc = 0
    others.forEach(({ r }, k) => {
      if (k === others.length - 1) {
        r.weight = remaining - acc
      } else {
        const v = Math.round(((r.weight || 0) / othersSum) * remaining)
        r.weight = v
        acc += v
      }
    })
  }
}

const weightsToPercent = (upstreams: any[]) => {
  const enabled = upstreams.filter(u => u.enabled)
  const sum = enabled.reduce((s, u) => s + (u.weight || 0), 0)
  if (enabled.length === 0) return
  if (sum === 0) {
    const base = Math.floor(100 / enabled.length)
    enabled.forEach((u, k) => { u.weight = k === 0 ? 100 - base * (enabled.length - 1) : base })
    return
  }
  let acc = 0
  enabled.forEach((u, k) => {
    if (k === enabled.length - 1) {
      u.weight = 100 - acc
    } else {
      const v = Math.round(((u.weight || 0) / sum) * 100)
      u.weight = v
      acc += v
    }
  })
}

const weightPercent = (upstreams: any[] | undefined, row: any): number => {
  if (!upstreams?.length) return 0
  const sum = upstreams.reduce((s, u) => s + (u.weight || 0), 0)
  if (sum <= 0) return 0
  return Math.round(((row.weight || 0) / sum) * 100)
}

const addUpstream = () => {
  const upstream = defaultUpstream(wizardForm.protocol === 'tcp' ? 'tcp' : 'http')
  upstream.weight = 0
  wizardForm.upstreams.push(upstream)
  if (wizardForm.upstreams.length === 1) {
    upstream.weight = 100
  }
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
    wizardForm.path_rules.push({ match_type: 'prefix', path: '/', sort_order: 0, upstreams: null })
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
    const hasEmptyHost = wizardForm.upstreams.some(u => !u.host)
    if (hasEmptyHost) {
      ElMessage.warning('请填写所有上游服务器的主机地址')
      return
    }
    const validUpstreams = wizardForm.upstreams.filter(u => u.host && u.port)
    if (validUpstreams.length === 0) {
      ElMessage.warning('请至少添加一个有效的上游服务器')
      return
    }
    // Check if at least one upstream is enabled
    const enabledCount = wizardForm.upstreams.filter(u => u.enabled).length
    if (enabledCount === 0) {
      ElMessage.warning('至少需要一个启用的上游服务器')
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
  moveToAdjacentWizardStep(1)
}

const prevStep = (): void => {
  moveToAdjacentWizardStep(-1)
}

const submitWizard = async () => {
  if (isReadOnly.value) return
  if (!wizardForm.name) {
    ElMessage.warning('请输入规则名称')
    return
  }
  if (wizardForm.upstreams.length === 0) {
    ElMessage.warning('请至少添加一个上游服务器')
    return
  }
  if (wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled) {
    const pathRuleError = validatePathRules(wizardForm.path_rules)
    if (pathRuleError) {
      ElMessage.warning(pathRuleError)
      return
    }
  }

  const enabledUpstreams = wizardForm.upstreams.filter(u => u.enabled)
  if (enabledUpstreams.length === 0) {
    ElMessage.warning('至少需要一个启用的上游服务器')
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
    return
  }

  saving.value = true
  try {
    const validUpstreams = wizardForm.upstreams.filter(u => u.host && u.port).map(u => ({
      ...u,
      weight: u.weight ?? 100,
      dynamic_dns: wizardForm.dynamic_dns,
      max_connections: u.max_connections ?? 0,
      proxy_protocol: u.proxy_protocol ?? '',
    }))

    const data = {
      name: wizardForm.name,
      description: wizardForm.description,
      protocol: wizardForm.protocol,
      domain: wizardForm.domain,
      listen_port: wizardForm.listen_port,
      strategy: wizardForm.strategy,
      dynamic_dns: wizardForm.dynamic_dns,
      enable_dns_server: wizardForm.enable_dns_server,
      dns_server: wizardForm.dns_server,
      dns_family: (() => { const families = wizardForm.dns_family || []; if (families.length === 2) return 'both'; return families[0] || 'ipv4'; })(),
      health_check_path: wizardForm.enable_active_health_check ? (wizardForm.health_check_path || '/') : '',
      health_check_interval: wizardForm.health_check_interval,
      health_check_timeout: wizardForm.health_check_timeout,
      health_check_healthy_threshold: wizardForm.health_check_healthy_threshold,
      health_check_unhealthy_threshold: wizardForm.health_check_unhealthy_threshold,
      enable_active_health_check: wizardForm.enable_active_health_check,
      tcp_health_check_port: wizardForm.tcp_health_check_port || 0,
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
      compress_types: wizardForm.compress_types || 'gzip',
      request_body_max_size_mb: wizardForm.request_body_max_size_mb || 0,
      upstream_keepalive_timeout: wizardForm.upstream_keepalive_timeout || 0,
      server_tokens_hidden: wizardForm.server_tokens_hidden || 0,
      enabled: wizardForm.enabled,
      log_enabled: wizardForm.log_enabled || false,
      ip_acl_mode: wizardForm.ip_acl_mode,
      ip_acl_list: [...wizardForm.ip_acl_list],
      custom_routes_enabled: wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled,
      path_rules: wizardForm.protocol === 'http' && wizardForm.custom_routes_enabled
        ? wizardForm.path_rules.map((pathRule, index) => ({
            ...pathRule,
            sort_order: index,
            upstreams: pathRule.upstreams?.map((upstream) => ({ ...upstream })) || null,
          }))
        : [],
      proxy_dial_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_dial_timeout : 0,
      proxy_response_header_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_response_header_timeout : 0,
      proxy_read_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_read_timeout : 0,
      proxy_write_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_write_timeout : 0,
      proxy_stream_timeout: wizardForm.protocol === 'http' ? wizardForm.proxy_stream_timeout : 0,
    }

    if (editingRule.value) {
      await request.put(`/rules/${editingRule.value.caddy_id}`, data)
    } else {
      await request.post('/rules', data)
    }

    ElMessage.success(editingRule.value ? '更新成功' : '创建成功')
    wizardVisible.value = false
    fetchRules()
  } catch (e: any) {
    // Error message is already shown by the global axios interceptor.
    console.error('submit wizard failed', e)
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
      await request.post(`/rules/${rule.caddy_id}/enable`)
    } else {
      await request.put(`/rules/${rule.caddy_id}/disable`)
    }
    ElMessage.success(`${action}成功`)
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
    await request.delete(`/rules/${rule.caddy_id}`)
    ElMessage.success('删除成功')
    fetchRules()
  } catch (e) {}
}

const duplicateRule = async (rule: Rule) => {
  if (isReadOnly.value) return
  try {
    await ElMessageBox.confirm(`确定要复制规则 "${rule.name}" 吗？`, '复制确认', { type: 'info' })
    openCopyWizard(rule)
  } catch (e) {}
}

const openCopyWizard = (rule: Rule) => {
  editingRule.value = null
  isCopyMode.value = true
  let compressType = 'gzip'
  if (rule.compress_types) {
    if (Array.isArray(rule.compress_types) && rule.compress_types.length > 0) {
      compressType = rule.compress_types[0] as string
    } else if (typeof rule.compress_types === 'string') {
      compressType = (rule.compress_types as string).split(',')[0].trim()
    }
  }
  Object.assign(wizardForm, {
    caddy_id: '',
    id: undefined,
    name: `${rule.name} (Copy)`,
    description: rule.description || '',
    protocol: rule.protocol,
    domain: rule.domain || '',
    listen_port: rule.listen_port,
    strategy: rule.strategy || 'weighted_round_robin',
    dynamic_dns: rule.dynamic_dns || false,
    enable_dns_server: (rule as any).enable_dns_server || false,
    dns_server: (rule as any).dns_server || '',
    dns_family: (() => { const df = (rule as any).dns_family; if (Array.isArray(df)) return df; if (df === 'both') return ['ipv4', 'ipv6']; if (df === 'ipv4') return ['ipv4']; if (df === 'ipv6') return ['ipv6']; return ['ipv4']; })(),
    health_check_path: rule.health_check_path || '',
    health_check_interval: rule.health_check_interval || 10,
    health_check_timeout: rule.health_check_timeout || 5,
    health_check_healthy_threshold: rule.health_check_healthy_threshold || 2,
    health_check_unhealthy_threshold: rule.health_check_unhealthy_threshold || 3,
    enable_active_health_check: rule.enable_active_health_check === true,
    tcp_health_check_port: (rule as any).tcp_health_check_port || 0,
    tcp_try_duration: (rule as any).tcp_try_duration || 0,
    tcp_try_interval: (rule as any).tcp_try_interval ?? 250,
    host_header: rule.host_header || '',
    upstreams: rule.upstreams?.map(u => ({
      ...u,
      dynamic_dns: false,
      protocol: u.protocol || 'http',
      max_connections: u.max_connections ?? 0,
      proxy_protocol: u.proxy_protocol ?? '',
    })) || [],
    enable_tls: rule.enable_tls || false,
    tls_source: rule.tls_source || 'manual',
    acme_config_id: rule.acme_config_id || undefined,
    ca_provider_id: rule.ca_provider_id ?? 0,
    tls_cert: rule.tls_cert || '',
    request_body_max_size_mb: (rule as any).request_body_max_size_mb || 0,
    upstream_keepalive_timeout: (rule as any).upstream_keepalive_timeout || 0,
    server_tokens_hidden: (rule as any).server_tokens_hidden || 0,
    log_enabled: (rule as any).log_enabled || false,
    ip_acl_mode: rule.ip_acl_mode || '',
    ip_acl_list: [...(rule.ip_acl_list || [])],
    custom_routes_enabled: rule.custom_routes_enabled === true,
    path_rules: [...(rule.path_rules || [])]
      .sort((left, right) => left.sort_order - right.sort_order)
      .map((pathRule) => ({
        ...pathRule,
        upstreams: pathRule.upstreams?.map((upstream) => ({ ...upstream })) || null,
      })),
    proxy_dial_timeout: rule.proxy_dial_timeout || 0,
    proxy_response_header_timeout: rule.proxy_response_header_timeout || 0,
    proxy_read_timeout: rule.proxy_read_timeout || 0,
    proxy_write_timeout: rule.proxy_write_timeout || 0,
    proxy_stream_timeout: rule.proxy_stream_timeout || 0,
      tls_key: rule.tls_key || '',
      tls_http_redirect: rule.tls_http_redirect || false,
      enable_compress: rule.enable_compress !== false,
      compress_types: compressType,
      enabled: false,
    })
  currentStep.value = WIZARD_STEP.BASIC
  wizardVisible.value = true
}

const viewConfig = async (rule: Rule) => {
  configDialogVisible.value = true
  configLoading.value = true
  ruleConfig.value = null
  
  try {
    // Get rule-specific Caddy config from API
    const res = await request.get(`/rules/${rule.caddy_id}/caddy-config`)
     
    // Build the display config
    let compressType = 'gzip'
    if (rule.compress_types) {
      if (Array.isArray(rule.compress_types) && rule.compress_types.length > 0) {
        compressType = rule.compress_types[0] as string
      } else if (typeof rule.compress_types === 'string') {
        compressType = (rule.compress_types as string).split(',')[0].trim()
      }
    }
    
    ruleConfig.value = {
      id: rule.id || 0,
      caddy_id: res.data?.caddy_id || '',
      name: rule.name || '',
      domain: rule.domain || '',
      listen_port: rule.listen_port || 0,
      protocol: rule.protocol || 'http',
      strategy: rule.strategy || 'weighted_round_robin',
      dynamic_dns: rule.dynamic_dns || false,
      enable_dns_server: (rule as any).enable_dns_server || false,
      dns_server: (rule as any).dns_server || '',
      host_header: rule.host_header || '',
      enable_tls: rule.enable_tls || false,
      tls_source: rule.tls_source || 'manual',
      tls_http_redirect: rule.tls_http_redirect || false,
      enable_compress: rule.enable_compress !== false,
      compress_types: compressType,
      health_check_path: rule.health_check_path || '',
      health_check_interval: rule.health_check_interval || 10,
      health_check_timeout: rule.health_check_timeout || 5,
      health_check_unhealthy_threshold: rule.health_check_unhealthy_threshold || 3,
      enable_active_health_check: rule.enable_active_health_check === true,
      tcp_health_check_port: (rule as any).tcp_health_check_port || 0,
      tcp_try_duration: (rule as any).tcp_try_duration || 0,
      tcp_try_interval: (rule as any).tcp_try_interval ?? 250,
      request_body_max_size_mb: (rule as any).request_body_max_size_mb || 0,
      upstream_keepalive_timeout: (rule as any).upstream_keepalive_timeout || 0,
      server_tokens_hidden: (rule as any).server_tokens_hidden || 0,
      upstreams: rule.upstreams || [],
      enabled: rule.enabled !== false,
      config: res.data?.config || {}
    }
  } catch (e: any) {
    // Error message is already shown by the global axios interceptor.
    console.error('view config failed', e)
    ruleConfig.value = {
      id: rule.id || 0,
      caddy_id: '',
      name: rule.name || '',
      domain: rule.domain || '',
      listen_port: rule.listen_port || 0,
      protocol: rule.protocol || 'http',
      strategy: rule.strategy || 'weighted_round_robin',
      dynamic_dns: rule.dynamic_dns || false,
      enable_dns_server: (rule as any).enable_dns_server || false,
      dns_server: (rule as any).dns_server || '',
      host_header: rule.host_header || '',
      enable_tls: rule.enable_tls || false,
      tls_source: rule.tls_source || 'manual',
      tls_http_redirect: rule.tls_http_redirect || false,
      enable_compress: rule.enable_compress !== false,
      compress_types: 'gzip',
      health_check_path: rule.health_check_path || '',
      health_check_interval: rule.health_check_interval || 10,
      health_check_timeout: rule.health_check_timeout || 5,
      health_check_unhealthy_threshold: rule.health_check_unhealthy_threshold || 3,
      enable_active_health_check: rule.enable_active_health_check === true,
      tcp_health_check_port: (rule as any).tcp_health_check_port || 0,
      tcp_try_duration: (rule as any).tcp_try_duration || 0,
      tcp_try_interval: (rule as any).tcp_try_interval ?? 250,
      request_body_max_size_mb: (rule as any).request_body_max_size_mb || 0,
      upstream_keepalive_timeout: (rule as any).upstream_keepalive_timeout || 0,
      server_tokens_hidden: (rule as any).server_tokens_hidden || 0,
      upstreams: rule.upstreams || [],
      enabled: rule.enabled !== false,
      config: { error: '获取配置失败', details: e.message }
    }
  } finally {
    configLoading.value = false
  }
}

const openRuleLogDialog = (rule: Rule) => {
  ruleLogRuleName.value = rule.name || rule.caddy_id
  ruleLogCaddyId.value = rule.caddy_id
  ruleLogDialogVisible.value = true
}

const ruleLogTab = ref('log')
const ruleLogStats = ref<any>(null)
const logStatsOffset = ref(0)
const logStatsMaps = ref<{ ip: Record<string, number>; ua: Record<string, number>; uri: Record<string, number>; total: number; startedAt: string } | null>(null)
const logStatsInFlight = ref(false)

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
  let entry: any
  try {
    entry = JSON.parse(line)
  } catch {
    return
  }
  const req = entry?.request
  if (!req) return
  maps.total++
  const ip = req.client_ip || req.src_ip || req.src || req.remote_ip || '-'
  maps.ip[ip] = (maps.ip[ip] || 0) + 1
  let uri = req.uri || req.uri_path || '-'
  const qi = uri.indexOf('?')
  if (qi >= 0) uri = uri.slice(0, qi)
  maps.uri[uri] = (maps.uri[uri] || 0) + 1
  let ua = req.user_agent || ''
  if (!ua && req.headers) {
    const list = req.headers['User-Agent']
    if (Array.isArray(list) && list.length) ua = list[0]
  }
  const g = generalizeUA(ua)
  maps.ua[g] = (maps.ua[g] || 0) + 1
}

const topN = (m: Record<string, number>, n: number) =>
  Object.entries(m).map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, n)

const rebuildStatsView = () => {
  if (!logStatsMaps.value) return
  const m = logStatsMaps.value
  ruleLogStats.value = {
    total: m.total,
    started_at: m.startedAt,
    top_ips: topN(m.ip, 20),
    top_uas: topN(m.ua, 20),
    top_uris: topN(m.uri, 20),
  }
}

const fetchLogStream = async () => {
  if (!ruleLogCaddyId.value || logStatsInFlight.value) return
  logStatsInFlight.value = true
  try {
    const res: any = await request.get(`/rules/${ruleLogCaddyId.value}/log-stream`, { params: { offset: logStatsOffset.value } })
    const lines: string[] = res.data?.lines || []
    if (logStatsMaps.value && lines.length) {
      for (const line of lines) consumeLogLine(logStatsMaps.value, line)
      rebuildStatsView()
    }
    logStatsOffset.value = res.data?.offset ?? logStatsOffset.value
  } catch (e: any) {
    console.error('Failed to fetch log stream:', e)
  } finally {
    logStatsInFlight.value = false
  }
}

const startLogStats = async () => {
  logStatsMaps.value = { ip: {}, ua: {}, uri: {}, total: 0, startedAt: new Date().toLocaleString() }
  logStatsOffset.value = 0
  try {
    const res: any = await request.get(`/rules/${ruleLogCaddyId.value}/logs`)
    const content: string = res.data?.content || ''
    for (const line of content.split('\n')) {
      if (line.trim()) consumeLogLine(logStatsMaps.value, line)
    }
    rebuildStatsView()
    logStatsOffset.value = res.data?.offset ?? 0
  } catch (e: any) {
    console.error('Failed to init log stats:', e)
  }
}

const onRuleLogTabChange = (tab: string) => {
  if (tab === 'stats') {
    startLogStats()
  }
}

const onRuleLogDialogOpened = () => {
  ruleLogTab.value = 'log'
  refreshRuleLogs()
  startRuleLogPolling()
}

const onRuleLogDialogClosed = () => {
  stopRuleLogPolling()
  ruleLogContent.value = ''
  ruleLogCaddyId.value = ''
  logStatsMaps.value = null
  ruleLogStats.value = null
  logStatsOffset.value = 0
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
  if (ruleLogTab.value === 'stats') {
    fetchLogStream()
    return
  }
  if (!ruleLogCaddyId.value || ruleLogLoading.value) return
  ruleLogLoading.value = true
  try {
    const res: any = await request.get(`/rules/${ruleLogCaddyId.value}/logs`)
    ruleLogContent.value = res.data?.content || ''
    nextTick(() => {
      const el = ruleLogContainerRef.value
      if (el) el.scrollTop = el.scrollHeight
    })
  } catch (e: any) {
    console.error('Failed to fetch rule logs:', e)
  } finally {
    ruleLogLoading.value = false
  }
}

watch(ruleLogAutoRefresh, (val) => {
  if (!ruleLogDialogVisible.value) return
  if (val) startRuleLogPolling()
  else stopRuleLogPolling()
})

onMounted(() => {
  fetchRules()
  fetchUsers()
  fetchCertConfigs()
  fetchCAProviders()
  fetchGlobalConfig()
  fetchHealthStatus()
  healthPollTimer = setInterval(fetchHealthStatus, 15000)
  certJobPollTimer = setInterval(() => {
    if (rules.value.some(r => r.tls_source === 'acme_dns')) {
      fetchCertJobs()
    }
  }, 5000)
})

onUnmounted(() => {
  stopRuleLogPolling()
  if (healthPollTimer) {
    clearInterval(healthPollTimer)
    healthPollTimer = null
  }
  if (certJobPollTimer) {
    clearInterval(certJobPollTimer)
    certJobPollTimer = null
  }
})
</script>

<style scoped>
.table-toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; }
.search-input { width: 280px; }
.rules-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
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

.mb-5 { margin-bottom: 20px; }

.rule-name { font-weight: 500; color: #111827; }
.rule-name-cell { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
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
.form-tip { font-size: 12px; color: #9ca3af; margin-top: 8px; }
.form-tip-inline { font-size: 12px; color: #9ca3af; margin-left: 8px; vertical-align: middle; line-height: 1; }
.form-tip-inline-tight { font-size: 12px; color: #9ca3af; margin-left: 6px; }
.form-tip-line { font-size: 12px; color: #9ca3af; margin-top: 4px; }
.form-tip-tight { font-size: 12px; color: #9ca3af; margin-top: 2px; }
.form-tip-below { font-size: 12px; color: #9ca3af; margin-top: 8px; display: block; }
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

.tcp-health-tag {
  white-space: nowrap;
  overflow: visible;
  display: inline-flex;
  max-width: none;
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
}

.upstream-item > * {
  flex-shrink: 0 !important;
}

.upstream-address {
  color: #4b5563;
  font-family: monospace;
  font-size: 11px;
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

.metric-sep {
  color: #d1d5db;
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

.upstream-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 0;
  border-bottom: 1px solid #f3f4f6;
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

.upstream-address {
  color: #4b5563;
  font-family: monospace;
  font-size: 12px;
  line-height: 1;
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

/* Dynamic DNS alignment */
.dynamic-dns-item :deep(.el-form-item__content) {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
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

.upstream-title {
  font-size: 14px;
  font-weight: 500;
  color: #111827;
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
  margin: 20px 0 20px 0;
}

.compact-divider :deep(.el-divider__text) {
  font-size: 14px;
  font-weight: 500;
  padding: 0 8px;
}

.compact-divider :deep(.el-divider__line) {
  width: calc(50% - 30px);
}

.health-check-wrapper {
  padding: 0 80px;
}

.health-check-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.active-check-control {
  display: flex;
  align-items: center;
  gap: 12px;
}

.compact-divider {
  margin: 16px 0 12px 0;
}

.compact-divider :deep(.el-divider__text) {
  font-size: 14px;
  font-weight: 500;
}

.section-wrapper {
  padding: 0;
}

.health-form {
  padding: 0 20px;
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
  font-size: 12px;
  color: #64748b;
  line-height: 1.3;
  margin-top: 2px;
}

.strategy-item {
  margin-bottom: 12px;
}

.strategy-card-desc {
  font-size: 11px;
  color: #64748b;
  line-height: 1.3;
}

.health-check-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.health-check-section {
  padding: 0 80px;
}

.active-check-control {
  display: flex;
  align-items: center;
  gap: 12px;
}

.health-summary {
  margin-top: 8px;
}

.health-summary-text {
  display: flex;
  align-items: center;
  gap: 8px;
}

.summary-desc {
  font-size: 12px;
  color: #6b7280;
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

.config-code {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 16px;
  border-radius: 6px;
  font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.5;
  overflow: auto;
  max-height: 400px;
  white-space: pre-wrap;
  word-break: break-all;
}

.stats-summary { margin-bottom: 14px; display: flex; align-items: center; }
.stats-grid { display: grid; grid-template-columns: 1fr 1.5fr 1.5fr; gap: 14px; }
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
