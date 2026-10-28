package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

var clusterProcessStartedAt = time.Now()

func (s *SyncService) Report(ctx context.Context) error {
	var masterURL, token, storedSyncError string
	var appliedVersion int
	var isMaster bool
	var lastSync sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(master_url,''), COALESCE(cluster_token,''), COALESCE(applied_version,0), last_sync, COALESCE(last_sync_error,''), COALESCE(is_master,1) FROM global_config WHERE id=1`).Scan(&masterURL, &token, &appliedVersion, &lastSync, &storedSyncError, &isMaster); err != nil {
		return fmt.Errorf("读取上报状态: %w", err)
	}
	// 升主后本节点已无上报对象：master_url 被清空，继续构造只会必然失败并让
	// 调用方把「状态上报失败: …」交给 recordSyncError。写侧虽有从端角色谓词兜底，
	// 这里仍 fail-early——避免无意义请求与错误文案进入日志/审计。
	if isMaster {
		return nil
	}
	lastSyncError, reportSyncErrorCode := decodeSyncError(storedSyncError)
	lastSyncAt := ""
	if lastSync.Valid {
		lastSyncAt = lastSync.Time.UTC().Format(time.RFC3339)
	}
	var rulesCount, expiringCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules").Scan(&rulesCount); err != nil {
		return fmt.Errorf("统计规则: %w", err)
	}
	// 到期口径跟随 cert_expiry_days 配置（与规则页「即将过期」状态一致）；
	// JSON 字段名 certs_expiring_30d 为历史名，保留以兼容旧版主节点解析。
	// 字面量 30 → db.DefaultCertExpiryDays 绑定参数（caddy.go
	// 形态，库值唯一真相单源）；读失败/非法值回退口径原样（warn 留痕）。
	expiryDays := db.DefaultCertExpiryDays
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(cert_expiry_days,?) FROM global_config WHERE id=1", db.DefaultCertExpiryDays).Scan(&expiryDays); err != nil || expiryDays <= 0 || expiryDays > 365 {
		// 读失败/非法值回退治理默认时留痕（家族扫描唯一漏点，
		// 同族 certissuer/certificates/certinfo/certjobs 均已带留痕）。
		// Report 每同步周期都会读该列——列持续非法（带外直写）时
		// 按状态转换「失败/恢复各记一次」，不再每 60s 一条 warn。
		if level := logStateTransition("cluster-report-cert-expiry", true); level != "" {
			Logf(level, "集群报告: 读取证书到期口径失败，回退 %d 天", db.DefaultCertExpiryDays)
		}
		expiryDays = db.DefaultCertExpiryDays
	} else if level := logStateTransition("cluster-report-cert-expiry", false); level != "" {
		Logf(level, "集群报告: 证书到期口径读取恢复正常")
	}
	// expiryDays 经 Scan 已是纯整数（非法/非数字值回退 30），strconv.Itoa 只产生
	// 数字修饰符；SQLite datetime 修饰符无法参数化，格式化必须保证纯数字。
	expiryModifier := strconv.Itoa(expiryDays)
	// 状态集必须覆盖部署生命周期——cleanup_dns/cleanup_warning
	//（JobLifecycle=Downloaded）材料已落库、待部署，此前漏计会与规则页/任务
	// 页的到期口径分叉（状态集单源见 jobstate.go 的 DeploymentLifecycleJobStatusSQL）。
	// 下界 `> now` 必须与上界同时存在：expired 与 expiring 在
	// CertificateExpiryStatus 里互斥（先判 expired），只有上界会把数月前就过期、
	// 尚未续期的行算成「临期」，健康卡数字虚高且与规则页状态矛盾。
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_jobs WHERE status IN ('issued','failed',`+DeploymentLifecycleJobStatusSQL+`) AND expires_at IS NOT NULL AND datetime(expires_at)>datetime('now') AND datetime(expires_at)<=datetime('now','+`+expiryModifier+` days')`).Scan(&expiringCount); err != nil {
		return fmt.Errorf("统计即将到期证书: %w", err)
	}
	// 构造契约允许 caddy=nil（测试/独立运维路径）；nil 下按
	// 「不可判定 → degraded，CaddyOK=false」上报，而不是解引用 panic。
	var caddyErr error
	if s.caddy == nil {
		caddyErr = errors.New("Caddy 服务未初始化")
	} else {
		_, caddyErr = s.caddy.GetConfig()
	}
	serviceStatus := "ok"
	if caddyErr != nil || lastSyncError != "" {
		serviceStatus = "degraded"
	}
	// 分区哈希取 cluster_applied_sections 的已应用记录（apply 路径
	// recordAppliedSectionHashes 维护，含漂移重放后的本地重建口径）：
	// 代表本地当前已落库内容，无需为上报重建全量快照。
	// 读取失败（nil）与「表为空」（空 map）必须区分：前者本轮无法上报分区状态，
	// 显式置 unavailable 让主节点保留历史（否则主节点按「旧版本从节点」清空该
	// 节点的分区记录，节点列表的分区同步列整体消失，运维信号从「某节滞后」
	// 退化为「无数据」）；后者等价于「从未同步」，仍按旧版从节点占位展示。
	sectionHashes := readAppliedSectionHashes(ctx, s.db)
	report := models.ClusterReport{
		AppliedVersion:           appliedVersion,
		ServiceStatus:            serviceStatus,
		LastSyncAt:               lastSyncAt,
		LastSyncError:            lastSyncError,
		SyncErrorCode:            reportSyncErrorCode,
		SectionHashes:            sectionHashes,
		SectionHashesUnavailable: sectionHashes == nil,
		Health: models.ClusterHealth{
			CaddyOK:          caddyErr == nil,
			RulesCount:       rulesCount,
			CertsExpiring30d: expiringCount,
			UptimeSec:        int64(time.Since(clusterProcessStartedAt).Seconds()),
			SyncErrorCode:    reportSyncErrorCode,
		},
	}
	// v2.3.0(2026-09-18 用户裁定):规则库版本随上报上送——主节点集群管理
	// 节点列表状态列 hover 可见从节点 CRS/IP2Region 版本(从节点跟随主节点
	// 同步,无需登录从节点查看)。
	// 上报为每同步周期的热路径,只消费两个版本串——改走轻量
	// 版本读取(两个小文件),不再经 BuildWafFileRef 的 tarGzDirSum 全树哈希
	// 与 xdb sha256(那是快照/漂移检测的口径,上报无需)。
	report.Health.CRSVersion, report.Health.IP2RegionTag = reportWafFileVersions()
	// 多源规则库（威胁情报库/爬虫地址库）版本：与前端
	// utils/securityLibraries.summarizeLibrarySources 同口径聚合（各源
	// version 取最近、空源为空串），供主节点集群列表展示。
	// 热路径=两条小表全列扫描（每库 3-4 行），无哈希/文件 IO。
	report.Health.ThreatVersion, report.Health.CrawlerVersion = reportSecurityLibraryVersions(ctx, s.db)
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("编码节点上报: %w", err)
	}
	// 小请求截止：上报是每同步周期必经的热路径，请求体仅数百字节；无截止时
	// 对端「接受连接但永不响应」会让 run 循环停在首字节之前——不拉取、不上报、
	// 不写 last_sync_error、零日志（只有主节点侧因缺上报判离线）。
	callCtx, cancel := newClusterSmallRequestContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/nodes/report", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("创建节点上报请求: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Token", token)
	resp, err := s.doSmall(req)
	if err != nil {
		// 审计节流：主节点持续宕机时上报每个同步周期都失败，同一错误只记录
		// 一次；错误内容变化或上报恢复后再次失败时重记，避免按分钟刷审计日志。
		s.reportAuditMu.Lock()
		auditChanged := s.lastReportFailureMsg != err.Error()
		s.lastReportFailureMsg = err.Error()
		s.reportAuditMu.Unlock()
		if auditChanged {
			RecordAuditLog("system", "上报失败", "集群节点", err.Error(), "")
		}
		return fmt.Errorf("上报主节点失败: %w", err)
	}
	defer resp.Body.Close()
	// 同主机 http→https 升级已被 DoWithSameHostTLSUpgradeRedirect 按
	// 原方法重放,残留 3xx(跨主机/反代重定向)说明主节点地址形态需
	// 人工修正——此前落进「非 4xx 即成功」被静默吞掉;给与 Pull 3xx 分支同款
	// 可行动指引,经 reportErr→recordSyncError 通道落库(last_sync_error
	// 显「状态上报失败: …」),审计节流与拒绝分支同口径。
	if isHTTPRedirect(resp.StatusCode) {
		message := fmt.Sprintf("主节点返回 %d 重定向(%s)——主节点启用 HTTPS 后请将主节点地址改为 https:// 并重新注册", resp.StatusCode, resp.Header.Get("Location"))
		s.reportAuditMu.Lock()
		auditChanged := s.lastReportFailureMsg != message
		s.lastReportFailureMsg = message
		s.reportAuditMu.Unlock()
		if auditChanged {
			RecordAuditLog("system", "上报失败", "集群节点", message, "")
		}
		return errors.New(message)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		// 任何 ≥400 一律按「本轮上报失败」返回错误，**不**按状态码分支终止：
		// 终止上报循环的单点是下一轮 Pull 的 errSyncTokenRevoked（401），
		// 只在此处再加一个终止源会让两处终止判据打架（例如未来 Pull 允许 401
		// 重试时，这里的 404 终止就会变成静默失效）。主节点的 404 只提供
		// 「节点身份不存在」的诊断语义，不承担「从端停手」的职责。
		// 与传输失败相同的审计节流：主节点持续拒绝上报时同一错误只记录
		// 一次；错误内容变化或上报恢复后再次失败时重记。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		// LimitReader 按字节截断可能切断多字节 UTF-8 字符尾部；回退到合法边界，
		// 避免审计消息尾部出现乱码。
		body = truncateValidUTF8Tail(body)
		message := fmt.Sprintf("主节点拒绝状态上报: %d", resp.StatusCode)
		if detail := strings.TrimSpace(string(body)); detail != "" {
			message += " body=" + detail
		}
		s.reportAuditMu.Lock()
		auditChanged := s.lastReportFailureMsg != message
		s.lastReportFailureMsg = message
		s.reportAuditMu.Unlock()
		if auditChanged {
			RecordAuditLog("system", "上报失败", "集群节点", message, "")
		}
		return errors.New(message)
	}
	s.reportAuditMu.Lock()
	s.lastReportFailureMsg = ""
	s.reportAuditMu.Unlock()
	return nil
}

// truncateValidUTF8Tail 将字节截断尾部退回到最后一个合法 UTF-8 字符边界，
// 消除 LimitReader 按字节截断导致的多字节字符残片乱码。
func truncateValidUTF8Tail(data []byte) []byte {
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}
	return data
}

// reportSecurityLibraryVersions 返回威胁情报库/爬虫地址库的「最近版本」。
// 口径与前端 utils/securityLibraries.summarizeLibrarySources 对齐：latestVersion
// = 各源 version 的最大值（compareLibraryVersion，日期与 semver 通用），
// 空源/全部空版本 → 空串。读失败按空串上报（版本是展示面，不得因单表读失败
// 中断整份上报；主节点显示「未更新」而非陈旧值）。
func reportSecurityLibraryVersions(ctx context.Context, database *sql.DB) (string, string) {
	return latestLibraryVersionOrEmpty(ctx, database, "security_threat_sources"),
		latestLibraryVersionOrEmpty(ctx, database, "security_crawler_sources")
}

// latestLibraryVersionOrEmpty 把「版本未知」降级为空串并留一条 warn：
// 上报不得因单表读失败中断，但也不得把残缺行集的最大值当成真实版本
// （失败口径见 latestSourceVersion）。
func latestLibraryVersionOrEmpty(ctx context.Context, database *sql.DB, table string) string {
	version, err := latestSourceVersion(ctx, database, table)
	if err != nil {
		Logf("warn", "读取 %s 版本失败（上报按未更新处理）: %v", table, err)
		return ""
	}
	return version
}

// latestSourceVersion 返回单库各源 version 的最大值；任何读/扫描/遍历失败
// 都返回错误，由调用方按「未更新」上报——绝不返回部分行集上的聚合结果：
// 被跳过的行可能是更大的版本，那样选出的「最近版本」既非真实最大值也非
// 「未知」，主节点悬停显示陈旧版本且零信号。
func latestSourceVersion(ctx context.Context, database *sql.DB, table string) (string, error) {
	if database == nil {
		return "", nil
	}
	// ORDER BY id + 「等值取后者」复刻前端 summarizeLibrarySources 的
	// sort(compareVersion) + pop()：前端数据源同为本 API 的 id 序，稳定排序后
	// 取末位即「最大值中行序最后一行」。否则同一库可能主节点 hover 显示
	// 1.2.0、从节点列表显示 1.2（比较器已判等价，差异只剩形态）。
	rows, err := database.QueryContext(ctx, `SELECT COALESCE(version,'') FROM `+table+` ORDER BY id`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	latest := ""
	for rows.Next() {
		var version string
		// 逐行 Scan 失败与行遍历错误同口径（失败即整体未知）——静默 continue
		// 曾让残缺行集的聚合结果被当作「最近版本」上报。
		if err := rows.Scan(&version); err != nil {
			return "", fmt.Errorf("扫描 %s 版本行: %w", table, err)
		}
		version = strings.TrimSpace(version)
		if version == "" {
			continue
		}
		if latest == "" || compareLibraryVersion(version, latest) >= 0 {
			latest = version
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("遍历 %s 版本行: %w", table, err)
	}
	return latest, nil
}

// compareLibraryVersion 复刻前端 utils/securityStages.compareVersion 的宽松
// 语义：按 `.`/`-` 分段，两侧均可解析为数值时按数值比较，否则按原段字符串序
// 兜底；**缺段与空段按 0**（"1.2" 与 "1.2.0" 等价）——两端聚合口径必须一致，
// 否则同一库在主节点列表与从节点本地显示不同版本。跨栈共享夹具
// web/tests/fixtures/version-compare.tsv 由前后端测试同读，防止再次分叉。
func compareLibraryVersion(a, b string) int {
	pa, pb := splitLibraryVersion(a), splitLibraryVersion(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		sa, sb := "", ""
		if i < len(pa) {
			sa = pa[i]
		}
		if i < len(pb) {
			sb = pb[i]
		}
		na, aNumeric := libraryVersionSegmentNumber(sa)
		nb, bNumeric := libraryVersionSegmentNumber(sb)
		if aNumeric && bNumeric {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	return 0
}

// libraryVersionSegmentNumber 复刻 JS Number() 在本比较器可达输入上的语义：
// 首尾空白忽略、空段（含缺段）按 0。Number 的十六进制/Infinity 形态不在
// 版本号取值范围（日期/纯数字/semver），不模拟（声明边界）。
func libraryVersionSegmentNumber(segment string) (float64, bool) {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return 0, true
	}
	if n, err := strconv.Atoi(trimmed); err == nil {
		return float64(n), true
	}
	if n, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsInf(n, 0) && !math.IsNaN(n) {
		return n, true
	}
	return 0, false
}

// splitLibraryVersion 与前端一致：只剥前导 'v'，按 '.'/'-' 分段，不预裁剪
// 整串空白（空白段由 libraryVersionSegmentNumber 的数值化容错吸收，非数字段
// 的字符串兜底保持原样，与 JS 侧同形）。
//
// 必须保留空段：JS 侧用 String.split(/[.-]/)，连续/前导/尾随分隔符会产出空串
// 段（JS 侧 Number(空串) === 0）。此前用 strings.FieldsFunc 丢弃空段，`1..2` 被读成
// [1,2] 而 JS 读成 [1,0,2]，同一库在两侧选出不同「最近版本」（跨栈夹具
// version-compare.tsv 已补该形态）。
func splitLibraryVersion(version string) []string {
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return nil
	}
	segments := make([]string, 0, 4)
	start := 0
	for i, r := range version {
		if r == '.' || r == '-' {
			segments = append(segments, version[start:i])
			start = i + 1
		}
	}
	return append(segments, version[start:])
}

// reportWafFileVersions 是 BuildWafFileRef 的轻量版本读取:只读
// crsLiveDir/VERSION 与 ip2regionLivePath+".version" 两个小文件取版本串,
// 不做 tarGzDirSum 全树哈希与 xdb sha256(Report 每同步周期调用,重哈希是
// 无谓的 IO/CPU 放大)。语义边界与 BuildWafFileRef 对齐:
//   - 文件缺失 = 空串(版本串 TrimSpace 口径、tag 经 sanitizeBundleVersion
//     形状校验,与 BuildWafFileRef 完全一致);
//   - seen 语义(rules 目录与 xdb 均缺失 = 视为「无安全数据」,两版本串保持
//     空串)以 os.Stat 等价复刻——BuildWafFileRef 的 seen 由哈希成功置位,
//     哈希 IO 异常失败时其整体返回 nil(不上报版本);本 helper 在该边缘仍
//     上报已读到的版本串,展示面(hover 空态一致性)在可读文件形态下不变。
func reportWafFileVersions() (crsVersion, ip2regionTag string) {
	if _, err := os.Stat(filepath.Join(crsLiveDir, "rules")); err != nil {
		if _, xdbErr := os.Stat(ip2regionLivePath); xdbErr != nil {
			return "", ""
		}
	}
	if v, err := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); err == nil {
		crsVersion = strings.TrimSpace(string(v))
	}
	if v, err := os.ReadFile(ip2regionLivePath + ".version"); err == nil {
		ip2regionTag = sanitizeBundleVersion(strings.TrimSpace(string(v)))
	}
	return crsVersion, ip2regionTag
}
