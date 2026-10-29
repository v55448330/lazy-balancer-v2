package handlers

// 5xx 响应体政策（本文件全域，与 rules/metrics/system 等 business 组端点的
// 「固定文案」政策并存）：
//   - business 组（任意登录用户可读，如 /settings 的 GetConfig）一律固定文案：
//     底层错误（SQL 文本、路径、admin 地址）只进运行日志与操作审计。
//   - admin 组（本文件内的配置读写/校验/重载/Caddy 原始配置/启停）保留
//     底层错误文本——这些端点是管理员排障接口，需要区分「admin 不可达 / 响应
//     超限 / 解析失败 / exec exit status / 路径权限」；固定文案会把根因抹平
//     （GetCaddyConfig 的超限用例即要求「不得误报为解析失败」）。
//   - 组归属以 middleware.go 的路由表为准：同一文件里的 GetCaddyLogs 注册在
//     business 组（任意登录用户可读），故它按固定文案处理（路径/errno 只进
//     运行日志）——「在哪个组」决定政策，而不是「在哪个文件」。
//   - 两份口径由 caddyAdmin5xxDetailFunctions 清单（error_body_leak_rules_test.go）
//     + 源码门禁钉住：新增 5xx 写点或端点路由组变化必须同步清单，否则测试红。
//     此前本文件内两条 5xx 收敛为固定文案、其余仍带细节，读者无法判断哪条是
//     政策、哪条是遗漏。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/accesslog"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var caddyRunCommand = func() *exec.Cmd {
	return exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
}

// caddyAdminTransport 是 admin API 探针/读取的共享 Transport：连接池跨请求
// 复用（此前每个调用点 `&http.Client{Timeout: …}` 每请求新建客户端——Transport
// 要么落到共享 DefaultTransport 与其他组件抢池，要么每次新建即每次新连接）。
// 每请求超时语义由 context 承载（覆盖到 body 读取，与 client.Timeout 等价）。
var caddyAdminTransport = func() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 8
	return transport
}()

var caddyAdminHTTPClient = &http.Client{Transport: caddyAdminTransport}

// caddyAdminCancelBody 在 Body.Close 时释放请求 context 的超时计时器——
// 请求超时用 context 表达后，计时器必须随响应体关闭回收（否则每个请求按
// 最长 timeout 持有计时器）。
type caddyAdminCancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *caddyAdminCancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// caddyAdminGet 以共享客户端 GET admin API 路径，timeout 为单请求超时
// （旧形态 client.Timeout 的等价语义）。
func caddyAdminGet(ctx context.Context, adminURL, path string, timeout time.Duration) (*http.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(adminURL, "/")+path, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := caddyAdminHTTPClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		cancel()
		return resp, err
	}
	if resp.Body == nil {
		cancel()
		return resp, nil
	}
	resp.Body = &caddyAdminCancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

var caddyStopCommand = func(adminURL string) *exec.Cmd {
	address := adminURL
	if parsed, err := url.Parse(adminURL); err == nil && parsed.Host != "" {
		address = parsed.Host
	}
	return exec.Command("caddy", "stop", "--address", address)
}

// caddyPauseFile 与 docker-entrypoint.sh 的 Caddy 监督器协调
// stopCaddy 建文件 → 监督器见文件不重启(admin 停止是用户意图);
// startCaddy 删文件 → 监督器 ≤1s 检测并启动;handler 等 admin 就绪。
// 改为包级 var 作测试注入缝（caddyProcRoot 同模式）。
var caddyPauseFile = "/tmp/lazy-balancer-caddy-paused"

// caddySupervisorPidFile 是监督器在位标记(entrypoint 父壳在后台化监督器
// 子 shell 后立即写入——$!=子 shell pid）——
// startCaddy 仅在标记在场时走监督器委托路径;测试环境(无监督器)直启不等待。
var caddySupervisorPidFile = "/tmp/lazy-balancer-caddy-supervisor.pid"

// caddySupervisorWaitTimeout 是监督器委托的 admin 就绪等待上限（生产 5s；
// 测试调小）。测试注入缝。
var caddySupervisorWaitTimeout = 5 * time.Second

// caddyStartupReplayMarkerFile 是监督器「启动回放阶段完成」标记（启动
// 竞态修复；与 docker-entrypoint.sh 的 CADDY_STARTUP_REPLAY_DONE 同一路径）：
// 监督器 reapply_last_good 尾部写（LKG 缺失/回放失败也写——标记语义是
// 「admin 就绪+回放阶段已了结」，不是「回放成功」），app 启动配置载入等标记
// 后再应用。包级 var 作测试注入缝（caddyPauseFile 同模式）。
var caddyStartupReplayMarkerFile = "/tmp/lazy-balancer-caddy-startup-replayed"

// startupReplayWaitTimeout 是启动载入等待回放标记的上限（生产 30s；测试调小）。
// 有界放行：监督器夭折（标记永不出现）时退化语义=修复前（app 直接应用），
// 不得挂死启动。测试注入缝。
var startupReplayWaitTimeout = 30 * time.Second

// waitStartupReplayDone 启动竞态修复：监督器首启 last-good 回放与
// app BootSync 配置载入各等 admin 就绪即写，先后为硬币——app 渲染先落时，
// 监督器回放的旧 LKG 快照覆盖新配置（v2.3.7-beta 发版实锤：新配置被盖到手动
// 重载才生效）。协议：监督器回放阶段尾部写标记，app 启动载入等标记后再应用，
// 时序构造性定死为「回放→标记→应用」。supervisorAlive 不在场（测试/裸跑）
// 协议关闭立即返回；标记永不出现（监督器夭折）等满超时后 WARN 放行；
// 手动重载/caddy-restart 到场时标记必已存在（本容器生命周期内监督器首启
// 必写过），首轮探测即返回。
//
// 超时放行路径的收敛兜底在监督器侧——admin 就绪逾 10
// 探针时 slow-start 后台环补写 /tmp/caddy-restarted（绕过首启豁免），
// caddy-restart watcher 随后走与启动同源的 DB 渲染→校验→应用强制重收敛；
// 本函数的超时是有界的面板可用性保障，不因拉高等待上限换取就绪竞态收窄
// （docker-entrypoint.sh slow-start 块 Ruling 注释）。
func waitStartupReplayDone() {
	if !supervisorAlive() {
		return
	}
	deadline := time.Now().Add(startupReplayWaitTimeout)
	for {
		if _, err := os.Stat(caddyStartupReplayMarkerFile); err == nil {
			return
		}
		if time.Now().After(deadline) {
			services.Logf("warn", "等待 Caddy 监督器启动回放标记超时（%s），继续启动配置载入（监督器可能未按协议写标记，last-good 回放存在乱序覆盖风险）", startupReplayWaitTimeout)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// caddyProcRoot 是进程状态读取的根目录（生产=/proc；测试指向临时伪 /proc 目录）。
var caddyProcRoot = "/proc"

// caddyProcessRunning 纯 /proc 实现：遍历 /proc/*/stat，存在任一 comm=caddy 且
// 状态非 Z（僵尸）的进程即为运行中。Z=僵尸——entrypoint 孵化、父进程未回收的
// caddy 子进程死后会永久滞留（Go 不回收非 exec 子进程），其 comm 仍为 caddy、
// 进程仍在，但已 dead 不能服务，必须排除在「运行中」之外（否则 stop/restart 的
// 完成判定在该僵尸存在期间永远失败——2026-08-28 生产复现）。不用 ps：busybox ps
// 不支持 -p 选项（alpine 容器内 GNU 语法的 ps -o stat= -p 直接报
// "unrecognized option"），/proc 是唯一可靠来源。
func caddyProcessRunning() bool {
	return caddyLivePID() > 0
}

// parseProcStat 解析 /proc/<pid>/stat 行，返回 comm 与状态字节。stat 格式：
// pid (comm) state ...；comm 可含空格与右括号，取最后一个 ')' 之后的单字符
// 状态（R/S/D/T/Z…）。畸形行返回 ok=false。caddyLivePID 与 supervisorAlive
// 共用本解析（监督器存活判定与 caddy 存活判定同口径排 Z）。
func parseProcStat(line string) (comm string, state byte, ok bool) {
	open := strings.Index(line, "(")
	close := strings.LastIndex(line, ")")
	if open < 0 || close <= open || close+2 >= len(line) {
		return "", 0, false
	}
	return line[open+1 : close], line[close+2], true
}

// caddyLivePID 返回存活（非 Z 状态）caddy 进程中的最小 pid，无存活进程时
// 返回 0。与 caddyProcessRunning 共用同一 /proc 遍历（仪表盘「运行中（pid）」
// 展示）。取最小 pid 而非 ReadDir 序首个：监督器 churn 窗口内可能同时存在
// 两个 caddy 进程，ReadDir 返回序不确定会让仪表盘 pid 在两次轮询间跳动。
func caddyLivePID() int {
	entries, err := os.ReadDir(caddyProcRoot)
	if err != nil {
		return 0
	}
	lowest := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(caddyProcRoot, entry.Name(), "stat"))
		if err != nil {
			continue // 进程可能刚退出，stat 已消失——视为非运行候选，跳过
		}
		comm, state, ok := parseProcStat(string(content))
		if !ok || comm != "caddy" {
			continue
		}
		if state == 'Z' {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if lowest == 0 || pid < lowest {
			lowest = pid
		}
	}
	return lowest
}

func caddyAdminReady(adminURL string) bool {
	response, err := caddyAdminGet(context.Background(), adminURL, "/config/", 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode < http.StatusInternalServerError
}

// supervisorAlive：监督器在位判定——pid 标记在场且
// 所记 pid 仍存活。存活校验从「/proc/<pid> 目录在场」
// 升级为读 /proc/<pid>/stat 状态字节——监督器 kill -9 后父进程（PID1 app，
// Go 不回收非 exec 子进程）未回收期间僵尸滞留 /proc（目录在场、状态字节
// Z），目录判定恒活会让 startCaddy 恒委托空等 5s 超时、直启兜底永不可达；
// Z 视死（与 caddyLivePID 同口径，共用 parseProcStat 与 caddyProcRoot 注入
// 缝）。comm 不校验——pid 标记是权威记录，监督器 subshell 的 comm 形态
// 不稳定。标记内容非正整数（旧格式/损坏）视为陈旧；stat 缺失/畸形视为死
// （宁可直启不空等）。
func supervisorAlive() bool {
	data, err := os.ReadFile(caddySupervisorPidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}
	content, err := os.ReadFile(filepath.Join(caddyProcRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false // /proc/<pid>/stat 不在场=进程已退出
	}
	_, state, ok := parseProcStat(string(content))
	return ok && state != 'Z'
}

func startCaddy(adminURL string) error {
	// 监督器在场(标记文件)时优先委托(删 pause → 监督器 ≤1s 启动),
	// 等 admin 就绪;标记不在场(测试环境/监督器死亡)直接 spawn。
	// 在场判定升级为 pid 存活校验——标记文件在但
	// pid 已死（监督器被杀/容器异常重启残留）时，委托只会空等超时后报错；
	// 落直启（与标记不在场同语义；标记留存不删，由存活判定消化）。
	if supervisorAlive() {
		_ = os.Remove(caddyPauseFile)
		supervisorDeadline := time.Now().Add(caddySupervisorWaitTimeout)
		for time.Now().Before(supervisorDeadline) {
			if caddyAdminReady(adminURL) {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		// 委托超时不落直启——监督器活着但慢启动时
		// 直启会双启抢 admin/监听端口，败者触发监督器崩溃重拉 churn（或
		// 假 500：监督器实例其实已正常服务）。pause 已解除，监督器仍在
		// 重试，返回明确错误即可。
		return fmt.Errorf("Caddy 监督器在场但 %s 内未拉起就绪的 Caddy（pause 已解除，监督器仍在重试，请稍后复查或检查容器日志）", caddySupervisorWaitTimeout)
	}
	// 直启路径不再删 pid 标记——app 检查
	// supervisorAlive 之后、监督器子 shell 首写标记之前，Remove 会误删刚
	// 写入的在位标记（永久失标 → 下次直启与监督器拉起双启抢口）。陈旧
	// 标记（死 pid）留存无害：supervisorAlive 按 pid 存活判定消化；标记
	// 不在场时 Remove 本是 no-op。僵尸误报半边由 状态字节判定承接。
	cmd := caddyRunCommand()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			if err == nil {
				err = errors.New("Caddy 在 Admin API 就绪前退出")
			}
			return err
		case <-ticker.C:
			if caddyAdminReady(adminURL) {
				return nil
			}
		case <-deadline.C:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				<-exited
			}
			return errors.New("Caddy Admin API 未就绪")
		}
	}
}

// stopCaddy 停 Caddy 并维持监督器的 standby（pause 文件语义）。
//
// 分类原则：结果按**事实**判定，而不是按 `caddy stop` 的退出码。已停止
// （admin 不可达且无 caddy 进程）时命令必然非零退出（连接失败），旧实现把它
// 当成「停止失败」并删除 pause——监督器下一 tick 无条件拉起 Caddy，于是
// 「再点一次停止」把服务反向启动。现在的口径：
//   - 已停止 → 成功（写 pause 留痕：管理员要求「保持停止」）；
//   - 命令失败但 Caddy 仍存活/可达 → 回滚 pause（监督器继续看护）+ 可读错误；
//   - 命令成功但 3s 内仍可达 → 保留 pause（停止意图仍生效）+ 超时错误，
//     任何重试都会落到第一个分支得到成功，不会再反转。
//
// pause 写失败必须中止：没有 pause 的 stop 会被监督器立刻反转，回 200 是假成功。
func stopCaddy(adminURL string) error {
	if !caddyAdminReady(adminURL) && !caddyProcessRunning() {
		if err := os.WriteFile(caddyPauseFile, nil, 0o644); err != nil {
			return fmt.Errorf("Caddy 已停止，但无法写入停止标记 %s（监督器会重新拉起）: %w", caddyPauseFile, err)
		}
		return nil
	}
	// 先建 pause 再停——防监督器在 admin stop 与进程退出之间竞态重启
	if err := os.WriteFile(caddyPauseFile, nil, 0o644); err != nil {
		return fmt.Errorf("无法写入停止标记 %s（停止会被监督器立刻反转，未执行停止）: %w", caddyPauseFile, err)
	}
	command := caddyStopCommand(adminURL)
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		// 按事实分类：命令失败时 Caddy 可能已经不在服务（重复停止/崩溃空窗/
		// admin 已关），那就是「已停止」，保留 pause；只有仍在服务才回滚 pause。
		if !caddyAdminReady(adminURL) && !caddyProcessRunning() {
			return nil
		}
		_ = os.Remove(caddyPauseFile) // 停止失败回滚 pause(监督器继续看护)
		reason := strings.TrimSpace(stderr.String())
		if reason == "" {
			reason = err.Error()
		}
		return fmt.Errorf("Caddy 停止失败（Caddy 仍在运行，已回滚停止标记）: %s", reason)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !caddyAdminReady(adminURL) && !caddyProcessRunning() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("停止后 3s 内 Caddy Admin API 仍可达（停止标记已保留，服务仍在排空；稍后重试或复查容器日志）")
}

func (h *Handlers) GetConfig(c *gin.Context) {
	var cfg models.GlobalConfig
	// 治理默认值列的读路径 SQL 字面量是默认值的第三次复制
	//（DDL DEFAULT+启动回填+此处）——改参数绑定 db.Default* 常量单源化，
	// 常量变更不再需要三处同步。日志体量/保留期/JWT、威胁大屏与安全事件
	// 默认值同样走参数绑定；非治理列（log 级别/布尔等）字面量原状。
	err := db.DB.QueryRowContext(c.Request.Context(), `
		SELECT id, caddy_config,
		       COALESCE(acme_email,'') as acme_email, COALESCE(cert_expiry_days,?) as cert_expiry_days,
		       COALESCE(cert_renewal_days,?) as cert_renewal_days,
		       COALESCE(cert_renewal_attempts,?) as cert_renewal_attempts,
		       COALESCE(default_ca_provider_id,0) as default_ca_provider_id,
		       log_level,

		       COALESCE(caddy_log_level,'info') as caddy_log_level,
		       COALESCE(caddy_log_size_mb,?) as caddy_log_size_mb,
		       COALESCE(request_body_max_size_mb,?) as request_body_max_size_mb,
		       COALESCE(http_read_timeout,?) as http_read_timeout,
		       COALESCE(http_write_timeout,?) as http_write_timeout,
		       COALESCE(http_idle_timeout,?) as http_idle_timeout,
		       COALESCE(upstream_keepalive_timeout,0) as upstream_keepalive_timeout,
		       COALESCE(proxy_dial_timeout,0) as proxy_dial_timeout,
		       COALESCE(proxy_response_header_timeout,0) as proxy_response_header_timeout,
		       COALESCE(proxy_read_timeout,0) as proxy_read_timeout,
		       COALESCE(proxy_write_timeout,0) as proxy_write_timeout,
		       COALESCE(proxy_stream_timeout,0) as proxy_stream_timeout,
		       COALESCE(proxy_flush_interval,0) as proxy_flush_interval,
		       COALESCE(proxy_stream_close_delay,0) as proxy_stream_close_delay,
		       COALESCE(server_tokens_hidden,FALSE) as server_tokens_hidden,
		       COALESCE(task_log_size_mb,?) as task_log_size_mb,
		       COALESCE(audit_log_size_mb,?) as audit_log_size_mb,
		       COALESCE(runtime_log_size_mb,?) as runtime_log_size_mb,
		       COALESCE(access_log_json,TRUE) as access_log_json,
	       COALESCE(access_log_format,'') as access_log_format,
	       COALESCE(audit_retention_months,?) as audit_retention_months,
	       COALESCE(jwt_expire_minutes,?) as jwt_expire_minutes,
	       COALESCE(timezone,?) as timezone,
	       COALESCE(github_proxy_url,'https://v4.gh-proxy.org/') as github_proxy_url,
	       COALESCE(github_token,'') as github_token,
	       COALESCE(mfa_write_guard,0) as mfa_write_guard,
	       COALESCE(mfa_lockout_enabled,0) as mfa_lockout_enabled,
	       COALESCE(trusted_proxy_enabled,0) as trusted_proxy_enabled,
	       COALESCE(trusted_proxy_ranges,'[]') as trusted_proxy_ranges,
	       COALESCE(trusted_proxy_range_refs,'[]') as trusted_proxy_range_refs,
	       COALESCE(trusted_proxy_headers,'[]') as trusted_proxy_headers,
	       COALESCE(trusted_proxy_strict,1) as trusted_proxy_strict,
	       COALESCE(server_map_lat,0) as server_map_lat,
	       COALESCE(server_map_lon,0) as server_map_lon,
	       COALESCE(threat_screen_mode,?) as threat_screen_mode,
	       COALESCE(threat_traffic_sample_n,?) as threat_traffic_sample_n,
	       COALESCE(security_events_retention_days,?) as security_events_retention_days,
	       COALESCE(security_events_row_cap,?) as security_events_row_cap,
	       COALESCE(is_master,1) as is_master, COALESCE(master_url, '') as master_url, sync_interval,
	       last_sync, updated_at
		FROM global_config WHERE id = 1
	`,
		// 占位符序=cert_expiry_days/cert_renewal_days/cert_renewal_attempts/
		// caddy_log_size_mb/request_body_max_size_mb/http_read_timeout/http_write_timeout/
		// http_idle_timeout、日志体量/保留期/JWT 五列；追加大屏/安全事件四列。
		db.DefaultCertExpiryDays, db.DefaultCertRenewalDays, db.DefaultCertRenewalAttempts,
		db.DefaultCaddyLogSizeMB, db.DefaultRequestBodyMaxSizeMB,
		db.DefaultHTTPReadTimeout, db.DefaultHTTPWriteTimeout, db.DefaultHTTPIdleTimeout,
		db.DefaultTaskLogSizeMB, db.DefaultAuditLogSizeMB, db.DefaultRuntimeLogSizeMB,
		db.DefaultAuditRetentionMonths, db.DefaultJWTExpireMinutes, db.DefaultTimezone,
		db.DefaultThreatScreenMode, db.DefaultThreatTrafficSampleN,
		db.DefaultSecurityEventsRetentionDays, db.DefaultSecurityEventsRowCap,
	).Scan(
		&cfg.ID, &cfg.CaddyConfig,
		&cfg.ACMEEmail, &cfg.CertExpiryDays, &cfg.CertRenewalDays, &cfg.CertRenewalAttempts, &cfg.DefaultCAProviderID,
		&cfg.LogLevel,
		&cfg.CaddyLogLevel, &cfg.CaddyLogSizeMB,
		&cfg.RequestBodyMaxSizeMB, &cfg.HTTPReadTimeout, &cfg.HTTPWriteTimeout, &cfg.HTTPIdleTimeout,
		&cfg.UpstreamKeepaliveTimeout, &cfg.ProxyDialTimeout, &cfg.ProxyResponseHeaderTimeout, &cfg.ProxyReadTimeout, &cfg.ProxyWriteTimeout, &cfg.ProxyStreamTimeout, &cfg.ProxyFlushInterval, &cfg.ProxyStreamCloseDelay,
		&cfg.ServerTokensHidden, &cfg.TaskLogSizeMB, &cfg.AuditLogSizeMB, &cfg.RuntimeLogSizeMB, &cfg.AccessLogJSON, &cfg.AccessLogFormat, &cfg.AuditRetentionMonths, &cfg.JWTExpireMinutes, &cfg.Timezone, &cfg.GitHubProxyURL, &cfg.GitHubToken, &cfg.MFAWriteGuard, &cfg.MFALockoutEnabled,
		&cfg.TrustedProxyEnabled, &cfg.TrustedProxyRanges, &cfg.TrustedProxyRangeRefs, &cfg.TrustedProxyHeaders, &cfg.TrustedProxyStrict,
		&cfg.ServerMapLat, &cfg.ServerMapLon, &cfg.ThreatScreenMode, &cfg.ThreatTrafficSampleN,
		&cfg.SecurityEventsRetentionDays, &cfg.SecurityEventsRowCap,
		&cfg.IsMaster, &cfg.MasterURL, &cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	if err != nil {
		writeInternalError(c, http.StatusInternalServerError, "获取全局配置失败", err)
		return
	}
	// 展示口径与运行时 clamp 对齐(<10 → 60)。
	// 钳位移到 err 判定之后——err 非 nil 时 cfg 为零值
	// 废弃对象，先行钳位是对废弃对象的无意义写（顺序误导读者）。
	if cfg.SyncInterval < 10 {
		cfg.SyncInterval = 60
	} else if cfg.SyncInterval > 86400 {
		// 与运行时/节点状态阈值同界，存量脏数据不得原样展示。
		cfg.SyncInterval = 86400
	}
	// （2026-09-05 证书域审计裁定，2026-10-26 列退役）：global_config.dns_credentials
	// 为退役列（签发链唯一凭证来源是 certificate_configs.dns_credentials，前端
	// 零消费），GET /config 不再返回该键；写路径同步收口，集群快照亦不再携带，
	// 存量列由启动迁移删除。

	cfg.HasGitHubToken = cfg.GitHubToken != ""
	// 自定义 Caddy 配置可能内联私钥或敏感 header；与规则 tls_key 同口径，
	// 非管理员及只读 API Key 不返回原文，管理员 JWT/读写 Key 保持可读。
	if !canReadSensitiveSecrets(c) {
		cfg.CaddyConfig = ""
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}

func (h *Handlers) GetUpstreamHealth(c *gin.Context) {
	healthStatus, err := h.caddyService.GetUpstreamHealthDetailed()
	if err != nil {
		services.Logf("error", "collect upstream health: %v", err)
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: "收集上游健康状态失败"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: healthStatus})
}

// validateUpdateConfigRequest 全局配置保存/预览共用的入参校验与归一
// 此前 preview 仅共用受信代理校验，可对保存必 400
// 的载荷给出「可变更」的清单。现保存与预览调用同一实现——数值范围、日志级别
// 枚举归一、时区、采样契约、安全事件保留值域、代理 URL 白名单全部同一组校验。
func normalizeACMEEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if len(email) > 254 {
		return "", errors.New("ACME 邮箱长度不能超过 254 字符")
	}
	if email == "" {
		return "", nil
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Name != "" || parsed.Address != email {
		return "", errors.New("ACME 邮箱格式无效")
	}
	return email, nil
}

func validateUpdateConfigRequest(req *models.UpdateConfigRequest) error {
	if err := validateTrustedProxyFields(req); err != nil {
		return err
	}
	if req.ACMEEmail != nil {
		email, err := normalizeACMEEmail(*req.ACMEEmail)
		if err != nil {
			return err
		}
		*req.ACMEEmail = email
	}

	if req.LogLevel != nil {
		level := strings.ToLower(strings.TrimSpace(*req.LogLevel))
		switch level {
		case "debug", "info", "warn", "error":
			*req.LogLevel = level
		default:
			return errors.New("无效的应用日志级别")
		}
	}

	// (2026-09-10 审计):与 LogLevel 同口径归一(ToLower+TrimSpace 后回写)
	// ——此前仅校验不归一,"DEBUG"/" info " 形态 400 或原样落库,两字段口径漂移。
	if req.CaddyLogLevel != nil {
		level := strings.ToLower(strings.TrimSpace(*req.CaddyLogLevel))
		switch level {
		case "debug", "info", "warn", "error":
			*req.CaddyLogLevel = level
		default:
			return errors.New("无效的 Caddy 日志级别")
		}
	}

	if req.AccessLogFormat != nil {
		// 规模门先于语义门：字节/行数检查不解析 DSL，超大串先按规模 400，
		// 避免对整串做逐行解析。
		if err := validateAccessLogFormatSize(*req.AccessLogFormat); err != nil {
			return err
		}
		if err := validateAccessLogFormat(*req.AccessLogFormat); err != nil {
			return err
		}
		// 写侧归一强制携带 API Key 头脱敏行（渲染层另有恒等
		// 不变量兜底旧库/直接改库/导入形态）——落库值即所见，UI 不再需要
		// 猜测渲染层偷偷追加了什么。空格式保持为空（=「不裁剪原生字段」，
		// 渲染层仍注入脱敏行）。
		*req.AccessLogFormat = normalizeAccessLogRedaction(*req.AccessLogFormat)
		// 归一可能多出一行脱敏规则，门必须同时认落库值——否则「上限内输入
		// + 脱敏行」落库即超限，回读再保存会被自己的门 400。
		if err := validateAccessLogFormatSize(*req.AccessLogFormat); err != nil {
			return fmt.Errorf("%v（保存时会自动补一行脱敏规则，落库值按此计数）", err)
		}
	}

	// 补上限与 UI:max=10240(CaddyGlobalSettings.vue)对齐——
	// 此前仅 ≥100 下限,天文值可落库使轮转实效、日志无限增长。
	if req.CaddyLogSizeMB != nil && (*req.CaddyLogSizeMB < 100 || *req.CaddyLogSizeMB > 10240) {
		return errors.New("Caddy 日志大小需在 100-10240MB 之间")
	}

	// 上界取 services.CertRenewalDaysMax（安全上限）而非旧的 90=证书寿命：
	// 窗口 ≥ 寿命-24h 时窗口门与成功侧迟滞数学等价，证书一签发就落进窗口，
	// 每次扫描整轮重签 → CA 重复证书限流后任务 failed → 约一个寿命后到期中断。
	// 写侧拒绝、导入钳制与读侧生效窗口共用该单源。
	if req.CertRenewalDays != nil && (*req.CertRenewalDays < 0 || *req.CertRenewalDays > services.CertRenewalDaysMax) {
		return fmt.Errorf("cert_renewal_days 必须在 0-%d 之间（证书寿命 %d 天，续签窗口需比寿命小一整天以上，否则会在每次扫描时重新签发并触发 CA 重复证书限流）",
			services.CertRenewalDaysMax, services.CertRenewalLifetimeDays)
	}

	if req.CertRenewalAttempts != nil && (*req.CertRenewalAttempts < 1 || *req.CertRenewalAttempts > 10) {
		return errors.New("cert_renewal_attempts 必须在 1-10 之间")
	}

	// cert_expiry_days 与另两个续签数值同边界（导入侧已按
	// [1,365] 钳制）——写侧缺校验会让 0/负值落库，续期窗口计算漂移。
	if req.CertExpiryDays != nil && (*req.CertExpiryDays < 1 || *req.CertExpiryDays > 365) {
		return errors.New("cert_expiry_days 必须在 1-365 之间")
	}

	if req.DefaultCAProviderID != nil {
		if err := services.ValidateDefaultCAProvider(*req.DefaultCAProviderID); err != nil {
			return err
		}
	}

	// 上限 1024MB 与 Coraza SecRequestBodyLimit 一致；保存侧拒绝更高值，
	// 不让面板承诺一个渲染层只能静默钳制的上限。值型列 0 无效，
	// 不再是「跟随全局/不限」——落库值恒有效，渲染直读零兜底。
	if req.RequestBodyMaxSizeMB != nil && (*req.RequestBodyMaxSizeMB < 1 || *req.RequestBodyMaxSizeMB > maxRequestBodySizeMB) {
		return fmt.Errorf("request_body_max_size_mb 必须在 1-%d MB 之间", maxRequestBodySizeMB)
	}
	// 库值唯一真相（批 1+2）：http_read/write/idle_timeout 为类型①值型列
	// （NOT NULL DEFAULT 60/60/120+启动回填），>=1 合法——0 的「省略=引擎默认」
	// 语义废除（渲染无条件发射库值）。upstream_keepalive_timeout 保持类型②
	// 省略型（0=继承 Caddy/Go Transport 默认 2 分钟，用户裁定），仅拒负数。
	if req.HTTPReadTimeout != nil && *req.HTTPReadTimeout < 1 {
		return errors.New("http_read_timeout 必须大于 0")
	}
	if req.HTTPWriteTimeout != nil && *req.HTTPWriteTimeout < 1 {
		return errors.New("http_write_timeout 必须大于 0")
	}
	if req.HTTPIdleTimeout != nil && *req.HTTPIdleTimeout < 1 {
		return errors.New("http_idle_timeout 必须大于 0")
	}
	if req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0 {
		return errors.New("Keepalive超时不能为负数")
	}
	if (req.ProxyDialTimeout != nil && *req.ProxyDialTimeout < 0) ||
		(req.ProxyResponseHeaderTimeout != nil && *req.ProxyResponseHeaderTimeout < 0) ||
		(req.ProxyReadTimeout != nil && *req.ProxyReadTimeout < 0) ||
		(req.ProxyWriteTimeout != nil && *req.ProxyWriteTimeout < 0) ||
		(req.ProxyStreamTimeout != nil && *req.ProxyStreamTimeout < 0) {
		return errors.New("代理超时时间不能为负数")
	}
	if req.ProxyFlushInterval != nil && *req.ProxyFlushInterval < -1 {
		return errors.New("代理刷新间隔不能小于 -1")
	}
	if req.ProxyStreamCloseDelay != nil && *req.ProxyStreamCloseDelay < 0 {
		return errors.New("代理流关闭延迟不能为负数")
	}

	// 与 caddy_log_size_mb同族补上限——此前仅 >0
	// 下限,天文值落库使轮转实效、日志无限增长。2026-09-25 用户裁定：上限收
	// 窄为 1024（原 10240 过宽），与 UI :max=1024 同口径。
	if req.TaskLogSizeMB != nil && (*req.TaskLogSizeMB <= 0 || *req.TaskLogSizeMB > 1024) {
		return errors.New("任务日志大小需在 1-1024MB 之间")
	}
	if req.RuntimeLogSizeMB != nil && (*req.RuntimeLogSizeMB <= 0 || *req.RuntimeLogSizeMB > 1024) {
		return errors.New("运行日志大小需在 1-1024MB 之间")
	}
	// 审计日志轮转大小上限 512MB（主节点侧校验；从节点经集群
	// 同步照单全收，配置源始终为主节点）。
	if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB <= 0 {
		return errors.New("审计日志轮转大小必须大于 0")
	}
	if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB > 512 {
		return errors.New("审计日志轮转大小上限 512MB")
	}
	if req.JWTExpireMinutes != nil && (*req.JWTExpireMinutes <= 0 || *req.JWTExpireMinutes > 1440) {
		return errors.New("jwt_expire_minutes 必须在 1-1440 之间")
	}
	// audit_retention_months 服务端范围校验（UI 口径 1-12）——超大值使
	// 年龄裁剪的 datetime('now', '-N days') 越出 SQLite 年份范围返回 NULL，
	// 年龄 DELETE 恒假静默失效（仅剩条数兜底）。
	if req.AuditRetentionMonths != nil && (*req.AuditRetentionMonths < 1 || *req.AuditRetentionMonths > 12) {
		return errors.New("日志保留月数必须在 1-12 之间")
	}
	// 威胁大屏本站坐标（v3）：纬度 ±90、经度 ±180，越界 400 不改库值
	// （fail-visible——静默钳位会让用户以为坐标已生效）。
	if err := validateServerMapCoordinates(req.ServerMapLat, req.ServerMapLon); err != nil {
		return err
	}
	// 威胁大屏模式（v2.3.8）：枚举白名单，非法值 400（fail-visible）。
	// 枚举与从端 apply 归一、快照装载归一共用 models 单源。
	if req.ThreatScreenMode != nil && !models.IsValidThreatScreenMode(*req.ThreatScreenMode) {
		return errors.New("威胁大屏模式仅支持 map 或 globe")
	}
	// 大屏逐请求流量采样：仅 -1=自适应（内部从全量起步，按事件速率在 1/4/8
	// 档间滞回）、0=关闭。全量档已退役（自适应低流量等价全量）；存量 1 与
	// 固定 2..64 由启动迁移归一为 -1，写侧不再接受。
	if req.ThreatTrafficSampleN != nil {
		switch *req.ThreatTrafficSampleN {
		case -1, 0:
		default:
			return errors.New("大屏流量采样仅支持 -1（自适应）或 0（关闭）")
		}
	}
	// 安全事件保留：0=自动的旧语义废除——写侧只接受
	// 显式值（天数 1-3650、行数上限 1-1 亿）。此前接受 0 但启动迁移每次把 0
	// 改写成 90/1000000，用户显式保存的 0 重启即被静默改写（库值不再反映输入）。
	// 存量 0/NULL 由 SVC 的一次性 marker 迁移收敛，服务层保留 legacy 防御。
	if req.SecurityEventsRetentionDays != nil && (*req.SecurityEventsRetentionDays < 1 || *req.SecurityEventsRetentionDays > db.MaxSecurityEventsRetentionDays) {
		return fmt.Errorf("安全事件保留天数必须在 1 到 %d 之间", db.MaxSecurityEventsRetentionDays)
	}
	if req.SecurityEventsRowCap != nil && (*req.SecurityEventsRowCap < 1 || *req.SecurityEventsRowCap > db.MaxSecurityEventsRowCap) {
		return fmt.Errorf("安全事件行数上限必须在 1 到 %d 之间", db.MaxSecurityEventsRowCap)
	}
	if req.Timezone != nil {
		// 空串必须显式拒绝（time.LoadLocation("") 是合法特殊值=UTC）：否则
		// 落库后读侧 COALESCE 只兜 NULL，全站展示/审计窗口静默切 UTC。
		if err := services.ValidateLocationName(*req.Timezone); err != nil {
			return err
		}
	}

	// GitHub 加速代理仅允许内置选项（防 SSRF），CRS/IP2Region 下载共用。
	if req.GitHubProxyURL != nil {
		if err := services.ValidateGitHubProxyURL(*req.GitHubProxyURL); err != nil {
			return err
		}
	}

	return nil
}

// resolveAccessLogFormatGate 是保存与预览共用的 access_log_json ×
// access_log_format 跨字段门与存量归一（此前只写在 UpdateConfig 内，preview
// 可对保存必 400 的载荷给出「可变更」清单，且看不到「保存会顺手清空格式」）：
//   - 生效值 json=true → 无门，返回 cleared=false；
//   - json=false 且请求显式携带非空格式 → 错误（不静默丢弃用户输入）；
//   - json=false 且（请求或存量）存有格式 → 把 req.AccessLogFormat 置空串并
//     返回 cleared=true（保存侧据此清空列；预览侧 plan 因此展示该清空）。
func resolveAccessLogFormatGate(req *models.UpdateConfigRequest, old configSnapshot) (bool, error) {
	effectiveAccessLogJSON := old.AccessLogJSON
	if req.AccessLogJSON != nil {
		effectiveAccessLogJSON = *req.AccessLogJSON
	}
	if effectiveAccessLogJSON {
		return false, nil
	}
	if req.AccessLogFormat != nil && strings.TrimSpace(*req.AccessLogFormat) != "" {
		return false, errors.New("访问日志 JSON 输出已关闭，自定义字段映射不生效：请先开启 JSON 输出，或清空访问日志格式")
	}
	storedFormat := old.AccessLogFormat
	if req.AccessLogFormat != nil {
		storedFormat = *req.AccessLogFormat
	}
	if storedFormat == "" {
		return false, nil
	}
	emptyFormat := ""
	req.AccessLogFormat = &emptyFormat
	return true, nil
}

func (h *Handlers) PreviewConfigUpdate(c *gin.Context) {
	var req models.UpdateConfigRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	if err := validateUpdateConfigRequest(&req); err != nil {
		writeUpdateConfigValidationFailure(c, err, false)
		return
	}
	old, err := loadConfigSnapshot(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前配置失败"})
		return
	}
	// 与保存同一跨字段门与归一（含存量格式清空的预告）。
	if _, err := resolveAccessLogFormatGate(&req, old); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 与保存同一判据的无变化短路：无变化=无写入，无需预检（存量坏规则不该
	// 阻断「确认无变更」流程），两端对同一载荷给出同一答案。
	plan := planConfigChanges(req, old)
	if !plan.Changed {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置无变化", Data: plan})
		return
	}
	// 与 UpdateConfig 同门、同分类器：DB 故障不得被回成 400 携带底层错误文本
	// （管理员会误判为载荷非法），纯配置错误才 400 展示全部问题。
	// 预览是 AuditPolicySkip（不落库的查询）：不产生失败留痕。
	if err := validateEnabledStoredRuleConfigs(c.Request.Context()); err != nil {
		writeConfigValidationFailure(c, err, false)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: plan})
}

// isPureConfigValidationError 展开 errors.Join 树，判定全部叶子均为
// *configValidationError（含 fmt.Errorf %w 包装的配置错误）。
func isPureConfigValidationError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !isPureConfigValidationError(child) {
				return false
			}
		}
		return true
	}
	var validationErr *configValidationError
	return errors.As(err, &validationErr)
}

// writeConfigValidationFailure 映射聚合预校验错误。纯配置错误
// 保持 400 且展示全部规则问题；一旦混入非配置类错误（DB 故障
// 等），改映射 500 通用文案并记日志——否则 400 消息携带底层 DB 错误文本，
// 客户端会把服务端故障误判为配置问题。
// auditFailure 由调用方的审计策略决定：保存端点（PUT /config）是 Explicit，
// 中间件不为失败兜底，5xx 必须在此留痕；预览端点（AuditPolicySkip）必须传
// false，否则会给不落库的查询产生虚假留痕。4xx 不审计是既定政策。
func writeConfigValidationFailure(c *gin.Context, err error, auditFailure bool) {
	// 5xx 留痕只在 Explicit 语义（保存）下发生；4xx 是载荷/配置状态错误，
	// 按既定政策不入审计。
	auditServerFailure := func() {
		if !auditFailure {
			return
		}
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail(
			"预校验规则配置失败", err.Error(), services.AuditResultPart("failure")))
	}
	var validationErr *configValidationError
	if !errors.As(err, &validationErr) {
		auditServerFailure()
		writeInternalError(c, http.StatusInternalServerError, "预校验规则配置失败", err)
		return
	}
	if !isPureConfigValidationError(err) {
		services.Logf("error", "更新全局配置的规则预校验混入非配置类错误：%v", err)
		auditServerFailure()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败"})
		return
	}
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
}

// writeUpdateConfigValidationFailure 映射 UpdateConfig/PreviewConfigUpdate 的
// 入参校验错误：受信代理校验内含 DB 读取（读存量网段/引用展开），其失败是
// 服务端故障——必须 500 + 固定文案并留痕，不得回 400 让管理员误判载荷非法，
// 也不得把 SQL/驱动文本透给客户端。其余纯载荷错误保持 400 全部展示。
// auditFailure 与 writeConfigValidationFailure 同签名同口径：由调用方的审计
// 策略决定——保存端点（PUT /config）是 Explicit，中间件不为失败兜底，5xx 必须
// 在此留痕；预览端点（AuditPolicySkip）必须传 false，否则会给不落库的查询
// 产生虚假留痕。4xx 不审计是既定政策。
func writeUpdateConfigValidationFailure(c *gin.Context, err error, auditFailure bool) {
	var readErr *trustedProxyReadError
	if errors.As(err, &readErr) {
		cause := readErr.Unwrap()
		if cause == nil {
			cause = readErr
		}
		if auditFailure {
			recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail(
				"读取受信代理配置失败", cause.Error(), services.AuditResultPart("failure")))
		}
		writeInternalError(c, http.StatusInternalServerError, errTrustedProxyRead.Error(), cause)
		return
	}
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
}

func (h *Handlers) UpdateConfig(c *gin.Context) {
	// global_config 全量替换的写者：导入窗口内提交会被导入静默覆盖，事务开启
	// 后则排队至导入结束（客户端早已超时但请求仍在导入后落库）——与同族
	// settings 写者同口径 409 fast-fail，且必须在取 caddyOpMu 之前早退。
	if rejectWriteDuringImport(c, "保存基础设置（配置导入进行中）") {
		return
	}
	var req models.UpdateConfigRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}

	// 与规则写路径同一锁序：先 caddyOpMu，DB 写入与 Caddy 应用全程持锁
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if err := validateUpdateConfigRequest(&req); err != nil {
		writeUpdateConfigValidationFailure(c, err, true)
		return
	}

	old, err := loadConfigSnapshot(caddyWriteCtx(c))
	if err != nil {
		// 保存端点服务端失败分支留痕（操作者归因 + 错误详情），
		// 此前仅成功路径写审计；动作复用既有 danger 词条「更新失败」。
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("读取当前配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前配置失败"})
		return
	}
	// access_log_json=false 时 access_log_format 不生效（渲染层
	// buildAccessLogEncoder 仅在 json=true 时消费自定义映射）——跨字段门与
	// 存量归一单源见 resolveAccessLogFormatGate（保存/预览共用）。
	formatCleared, gateErr := resolveAccessLogFormatGate(&req, old)
	if gateErr != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: gateErr.Error()})
		return
	}
	plan := planConfigChanges(req, old)
	if !plan.Changed {
		recordAudit(c, "更新", plan.Section, "无修改")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置无变化", Data: plan})
		return
	}

	// 只有进入渲染的变更才需要 Caddy 侧前置条件（存量规则可渲染性、运行
	// 配置快照）。面板/保留策略等非渲染字段的保存不得被 Caddy 可用性绑架。
	var oldRuntimeConfig map[string]interface{}
	if plan.AffectsCaddy {
		if err := validateEnabledStoredRuleConfigs(c.Request.Context()); err != nil {
			writeConfigValidationFailure(c, err, true)
			return
		}

		// 2026-09-07 裁定：撤 pre-tx /load 探针（与 ④'「探针已撤除」对齐）——
		// 候选合法性由 applyFromTxNote 内 CLI 真 validate-only + 事务内应用承担；
		// 探针曾使 SQL 失败分支面临「运行配置已换候选但 DB 未提交」的分叉，
		// 撤除后该窗口不存在。只读快照保留，仅供提交失败回弹使用。
		var err error
		oldRuntimeConfig, err = h.caddyService.GetConfig()
		if err != nil {
			recordAudit(c, "更新失败", "全局配置", caddyFailureAuditDetail("获取当前 Caddy 配置失败", err))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取当前 Caddy 配置失败"})
			return
		}
	}

	// Validation passed — write in a transaction; Caddy applies the uncommitted
	// state and the transaction only commits after a successful apply, so a
	// failed apply leaves DB and env unchanged.
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("开启配置事务失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启配置事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "UpdateConfig rollback failed: %v", rollbackErr)
			}
		}
	}()
	// 可空列（acme_email/access_log_format/default_ca_provider_id）需支持
	// 清空：传空值即置 NULL（COALESCE 无法区分“未传”与“清空”）。其余列保留 COALESCE 语义
	// —— 未传(nil) 保持原值。CASE WHEN ? IS NULL 用于区分 nil 与空字符串。
	// global_config.dns_credentials 为退役列（签发链唯一凭证来源是
	// certificate_configs）：读路径早已不回显，写分支亦已收口——不可见的凭证
	// 不再可被写入；存量列由启动迁移删除。
	res, err := tx.Exec(`
			UPDATE global_config SET
				acme_email = CASE WHEN ? IS NULL THEN acme_email ELSE NULLIF(?, '') END,
				cert_expiry_days = COALESCE(?, cert_expiry_days),
				cert_renewal_days = COALESCE(?, cert_renewal_days),
				cert_renewal_attempts = COALESCE(?, cert_renewal_attempts),
				default_ca_provider_id = CASE WHEN ? IS NULL THEN default_ca_provider_id ELSE NULLIF(?, 0) END,
				log_level = COALESCE(?, log_level),
				caddy_log_level = COALESCE(?, caddy_log_level),
				caddy_log_size_mb = COALESCE(?, caddy_log_size_mb),
				request_body_max_size_mb = COALESCE(?, request_body_max_size_mb),
				http_read_timeout = COALESCE(?, http_read_timeout),
				http_write_timeout = COALESCE(?, http_write_timeout),
				http_idle_timeout = COALESCE(?, http_idle_timeout),
				upstream_keepalive_timeout = COALESCE(?, upstream_keepalive_timeout),
				proxy_dial_timeout = COALESCE(?, proxy_dial_timeout),
				proxy_response_header_timeout = COALESCE(?, proxy_response_header_timeout),
				proxy_read_timeout = COALESCE(?, proxy_read_timeout),
				proxy_write_timeout = COALESCE(?, proxy_write_timeout),
				proxy_stream_timeout = COALESCE(?, proxy_stream_timeout),
				proxy_flush_interval = COALESCE(?, proxy_flush_interval),
				proxy_stream_close_delay = COALESCE(?, proxy_stream_close_delay),
				server_tokens_hidden = COALESCE(?, server_tokens_hidden),
				task_log_size_mb = COALESCE(?, task_log_size_mb),
				audit_log_size_mb = COALESCE(?, audit_log_size_mb),
				runtime_log_size_mb = COALESCE(?, runtime_log_size_mb),
				access_log_json = COALESCE(?, access_log_json),
				access_log_format = CASE WHEN ? IS NULL THEN access_log_format ELSE NULLIF(?, '') END,
			audit_retention_months = COALESCE(?, audit_retention_months),
			jwt_expire_minutes = COALESCE(?, jwt_expire_minutes),
				timezone = COALESCE(?, timezone),
				github_proxy_url = COALESCE(?, github_proxy_url),
				github_token = CASE WHEN ? IS NULL THEN github_token ELSE ? END,
				mfa_write_guard = COALESCE(?, mfa_write_guard),
				mfa_lockout_enabled = COALESCE(?, mfa_lockout_enabled),
				trusted_proxy_enabled = COALESCE(?, trusted_proxy_enabled),
				trusted_proxy_ranges = COALESCE(?, trusted_proxy_ranges),
				trusted_proxy_range_refs = COALESCE(?, trusted_proxy_range_refs),
				trusted_proxy_headers = COALESCE(?, trusted_proxy_headers),
				trusted_proxy_strict = COALESCE(?, trusted_proxy_strict),
				server_map_lat = COALESCE(?, server_map_lat),
				server_map_lon = COALESCE(?, server_map_lon),
				threat_screen_mode = COALESCE(?, threat_screen_mode),
				threat_traffic_sample_n = COALESCE(?, threat_traffic_sample_n),
				security_events_retention_days = COALESCE(?, security_events_retention_days),
				security_events_row_cap = COALESCE(?, security_events_row_cap),
				updated_at = datetime('now')
			WHERE id = 1
		`, req.ACMEEmail, req.ACMEEmail, req.CertExpiryDays, req.CertRenewalDays, req.CertRenewalAttempts, req.DefaultCAProviderID, req.DefaultCAProviderID, req.LogLevel,
		req.CaddyLogLevel, req.CaddyLogSizeMB,
		req.RequestBodyMaxSizeMB, req.HTTPReadTimeout, req.HTTPWriteTimeout, req.HTTPIdleTimeout,
		req.UpstreamKeepaliveTimeout, req.ProxyDialTimeout, req.ProxyResponseHeaderTimeout, req.ProxyReadTimeout, req.ProxyWriteTimeout, req.ProxyStreamTimeout, req.ProxyFlushInterval, req.ProxyStreamCloseDelay,
		req.ServerTokensHidden, req.TaskLogSizeMB, req.AuditLogSizeMB, req.RuntimeLogSizeMB, req.AccessLogJSON, req.AccessLogFormat, req.AccessLogFormat, req.AuditRetentionMonths, req.JWTExpireMinutes, req.Timezone, req.GitHubProxyURL, req.GitHubToken, req.GitHubToken, req.MFAWriteGuard, req.MFALockoutEnabled,
		req.TrustedProxyEnabled, req.TrustedProxyRanges, req.TrustedProxyRangeRefs, req.TrustedProxyHeaders, req.TrustedProxyStrict,
		req.ServerMapLat, req.ServerMapLon, req.ThreatScreenMode, req.ThreatTrafficSampleN, req.SecurityEventsRetentionDays, req.SecurityEventsRowCap)
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败"})
		return
	}
	rows, err := res.RowsAffected()
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败"})
		return
	}
	if rows != 1 {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", fmt.Sprintf("影响记录数为 %d", rows), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("配置写入数据库失败: 影响记录数为 %d", rows)})
		return
	}
	// 主节点坐标是未单独配置坐标的从节点的默认值：变化时必须 bump 集群版本，
	// 否则从节点 304 继续使用旧默认值；server_map 仍不进入 global_config
	// 通用同步列/触发器（按节点 node_sites 下发）。
	siteChanged := (req.ServerMapLat != nil && *req.ServerMapLat != old.ServerMapLat) ||
		(req.ServerMapLon != nil && *req.ServerMapLon != old.ServerMapLon)
	if siteChanged {
		if err := services.BumpClusterVersion(caddyWriteCtx(c), tx); err != nil {
			recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("递增集群版本失败", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "递增集群版本失败"})
			return
		}
	}

	// rulesWrittenInTx=false：本事务只写 global_config（lb_rules 视图与已提交
	// 视图恒一致），ACME 谓词 miss 补查在本路径无意义（逐 acme 规则空查）。
	// 非渲染字段（面板/保留策略/坐标等）不进入 Caddy：直接提交事务，零渲染、
	// 零 CLI 校验、零 /load——这类保存不应被 Caddy 进程可用性阻断。
	var reloadNote *txApplyNote
	if plan.AffectsCaddy {
		var applyErr error
		reloadNote, applyErr = h.applyFromTxNote(c, tx, "保存配置后自动重载", false)
		if applyErr != nil {
			// CLI 预检/事务内应用两轮渲染已按未提交内容重写
			// 投影（tp.txt 等）——tx 回滚的同时把磁盘回退到已提交态（零 /load）。
			h.caddyService.RollbackIPListProjectionsToCommittedInLock()
			restoreErr := h.caddyService.ApplyConfig(oldRuntimeConfig)
			if services.IsSameConfig(restoreErr) {
				// 回弹目标=请求前运行配置：拒绝/生成失败时字节相同，回升是
				// 成功空操作，不得 join 成「恢复失败」假信号（横幅/审计污染）。
				restoreErr = nil
			}
			applyErr = errors.Join(applyErr, restoreErr)
			// 回弹目标可能本身就是漂移形态（外来路由/带外改动）——先回滚事务
			// 释放写锁，再把 LKG 钉回已提交库视图：LKG 的全族不变量是「最后一次
			// 已提交且已下发的配置」，不得被请求前运行配置固化。
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				applyErr = errors.Join(applyErr, rbErr)
			}
			if pinErr := h.pinLastGoodAfterCompensation(); pinErr != nil {
				// 附带失败走统一留痕（`recordCaddyApplyFailure` 的两态标签只由
				// 运行配置恢复决定，LKG 未钉回不改变该事实，但重启兜底可能回放
				// 漂移形态，必须留下审计而不只是可能被过滤的 warn 日志）。
				h.recordCompensationSideEffects("Caddy 配置应用失败", pinErr)
			}
			// 横幅事实源：只有库态与运行态可能分叉的失败才写——配置拒绝（CLI
			// 校验/admin 4xx）时候选未 /load、事务已回滚，运行配置仍是旧形态，
			// 横幅会制造不存在的不一致（finishTxApply 拒绝分支即不写）；恢复失败
			// （Caddy 不可达/超时）则运行配置状态未知，必须落横幅。
			rejected := services.IsConfigRejected(applyErr)
			if !rejected || restoreErr != nil {
				h.recordCaddyApplyFailure(applyErr, restoreErr)
			}
			recordAudit(c, "更新失败", "全局配置", caddyFailureAuditDetail("Caddy 配置应用失败", applyErr))
			// 2026-09-07：与规则域统一——配置拒绝→400，传输/系统→500。
			if rejected {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过，配置未保存: " + applyErr.Error()})
			} else {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，配置未保存: " + applyErr.Error()})
			}
			return
		}
		if err := commitTx(tx); err != nil {
			// +: apply 已把未提交事务视图的投影/证书写盘并把
			// 该内容写入 LKG；commit 失败统一走已提交视图恢复（回滚事务 + 重渲染
			// /load + 回退 LKG——恢复 /load 失败时仍把已提交字节写回 LKG）。
			recovery := h.recoverCommittedViewAfterCommitFailure(tx)
			// 真实 /load 已在 commit 之前发生——「触发重载必须留痕」不因随后失败
			// 而豁免（同规则族 commit 失败分支）。
			reloadNote.auditReload()
			// 横幅两态：恢复失败=「运行配置状态未知」，恢复成功=「旧配置已保留」。
			// 提交失败不是配置应用失败（apply 已发生）——失败对象用提交口径。
			h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
			err = errors.Join(err, recovery.err())
			recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail(services.RedactCaddyAdminEndpoint(commitUncertainLabel+"："+err.Error()), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel + "：" + err.Error()})
			return
		}
	} else if err := commitTx(tx); err != nil {
		// 非渲染变更没有 Caddy 交互：提交失败只回滚事务、不触碰运行配置与
		// LKG（本次保存从未下发任何内容）。
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("提交配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交配置失败：" + err.Error()})
		return
	}
	committed = true
	// 成功清横幅由 reloadNote 单收口；此处重复 UPDATE
	// 只增加写放大且违反「note 唯一收口」约定。
	services.ApplyLogLevel()
	// task_log_size_mb 经本端点写库，服务端 5 分钟 TTL
	// 缓存此前零失效点——改设置后最长 5 分钟仍按旧阈值滚动任务日志。无条件
	// 失效（幂等、零成本；其余写入口已在各自域补齐）。
	services.InvalidateTaskLogSizeCache()
	if req.Timezone != nil {
		if _, err := services.ConfigureLocation(*req.Timezone); err != nil {
			// 时区已在写库前经 time.LoadLocation 预校验，
			// 此分支仅可能为环境级异常；配置已提交并应用，宣告 500 更新失败会
			// 误导客户端（重试=重复写同一已生效值）。降级为错误日志，响应保持成功。
			services.Logf("error", "配置已提交并应用，但运行时应用时区失败（提交前已预校验，疑似环境异常）: %v", err)
		} else if *req.Timezone != old.Timezone {
			// 时区真实变更：已武装的未来排程槽按新时区重算（槽=本地日历
			// 计算、UTC 落库——不重排则首轮仍按旧偏移触发，「下次执行」
			// 展示同错）。过期槽不动（补跑语义保留）。
			services.RearmScheduleSlotsAfterTimezoneChange()
		}
	}

	if len(plan.SectionChanges) > 0 {
		// 按分区名排序遍历：多个分区同时变更时，审计行落库顺序必须稳定
		// （map 序会让同一载荷两次提交的行序不同）。
		for _, section := range sortedStringKeys(plan.SectionChanges) {
			recordAudit(c, "更新", section, fmt.Sprintf("修改了: %s", strings.Join(plan.SectionChanges[section], ", ")))
		}
	}

	reloadNote.finalize()

	message := "配置已更新并应用"
	if !plan.AffectsCaddy {
		message = "配置已更新"
	}
	if formatCleared {
		message += "（访问日志 JSON 已关闭，自定义格式已清空：该格式不生效）"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: plan})
}

func (h *Handlers) ValidateConfig(c *gin.Context) {
	// 导入窗口 fast-fail：CLI 不可用回退路径会真实 /load 并回弹配置，
	// 且全程要等 caddyOpMu（导入持有）——排队到导入后的语义不可接受。
	if rejectWriteDuringImport(c, "校验 Caddy 配置（配置导入进行中）") {
		return
	}
	// 先读请求体再取写锁（UpdateConfig/PutCaddyConfig 同序）——
	// 已认证客户端的慢速/chunked 上传此前在持有 caddyOpMu 时读 body，会阻塞
	// 全部规则/配置写与后台强制重载。全局 body 上限可配到 1024MB，窗口可观。
	var configData map[string]interface{}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的配置 JSON"})
		return
	}
	rendered, err := json.Marshal(configData)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的配置 JSON"})
		return
	}
	// CLI 不可用回退路径仍执行真实 /load，保持与其他写
	// 端点共享 caddyOpMu。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	// 2026-09-06 裁定 ④' 收口：真 validate-only（caddy CLI，零运行时扰动），
	// 与 apidocs「不触发 Caddy」的既有承诺对齐；CLI 不可用回退 -c
	// 的 load+回弹口径。
	if err := h.caddyService.ValidateJSONViaCLI(rendered); err == nil {
		recordAudit(c, "校验成功", "Caddy配置", services.FormatAuditDetail("配置校验", services.AuditResultPart("success")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置有效"})
		return
	} else if !errors.Is(err, services.ErrCLIValidatorUnavailable) {
		recordAudit(c, "校验失败", "Caddy配置", services.FormatAuditDetail("配置校验", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败", Data: err.Error()})
		return
	}
	// CLI 校验器不可用回退：-c——/load 无 validate-only 语义，候选
	// 载荷会成为运行配置。候选可能已被 Caddy 加载后请求才
	// 断连/超时（客户端看到传输错误），因此**无论 ValidateConfig 成功或
	// 失败**都必须回弹 DB 权威全量配置；只有回弹成功才允许把错误归类为
	// 「配置无效」（400），传输/系统错误映射 500，回弹失败一律 500 并
	// join 双错误（与 UpdateConfig/PutCaddyConfig 的失败快照恢复同口径）。
	validateErr := h.caddyService.ValidateConfig(configData)
	restoreErr := h.caddyService.ApplyConfig(services.GenerateCaddyConfig())
	if services.IsSameConfig(restoreErr) {
		// 候选=权威配置时回升是同字节空操作（不是恢复失败）。
		restoreErr = nil
	}
	if restoreErr != nil {
		joined := errors.Join(validateErr, restoreErr)
		// 横幅事实源：恢复 /load 失败意味着运行配置可能停留为校验载荷，
		// 响应丢失后必须仍可见（与 UpdateConfig/PutCaddyConfig 同一持久化口径）。
		h.recordCaddyApplyFailure(joined, restoreErr)
		recordAudit(c, "校验失败", "Caddy配置", caddyFailureAuditDetail(
			"校验回退加载后恢复权威配置失败，运行配置可能停留为校验载荷", joined))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置校验后恢复运行配置失败: " + joined.Error()})
		return
	}
	if validateErr != nil {
		recordAudit(c, "校验失败", "Caddy配置", caddyFailureAuditDetail("配置校验", validateErr))
		if services.IsConfigRejected(validateErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败", Data: validateErr.Error()})
			return
		}
		// 传输/超时等系统故障不得伪装成「配置无效」——候选是否被拒未知，
		// 但运行配置已回弹权威值。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置校验请求失败（运行配置已恢复）: " + validateErr.Error()})
		return
	}

	recordAudit(c, "校验成功", "Caddy配置", services.FormatAuditDetail("配置校验", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置有效"})
}

func (h *Handlers) ReloadCaddy(c *gin.Context) {
	// 导入窗口 fast-fail：手动重载要等 caddyOpMu（导入持有），且会在导入
	// 事务未提交时按旧库渲染——导入结束再执行已与用户意图脱节。
	if rejectWriteDuringImport(c, "重载 Caddy 配置（配置导入进行中）") {
		return
	}
	if err := h.applyCaddyConfigE(); err != nil {
		// 手动重载恰是最需要留痕的操作——失败分支记录
		// 操作者归因 + 错误详情（recordCaddyApplyResult 的系统级「应用失败」
		// 不带用户身份，不能替代本条）。
		recordAudit(c, "重载失败", "Caddy服务", caddyFailureAuditDetail("手动重载 Caddy 配置", err))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置重载失败: " + err.Error()})
		return
	}
	// 手动重载成功同样需要留痕（69d809b4 曾误删本行）。
	recordAudit(c, "重载", "Caddy服务", "手动重载 Caddy 配置")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 配置已重载"})
}

func (h *Handlers) GetCaddyStatus(c *gin.Context) {
	applyError := ""
	if db.DB != nil {
		// 读取失败不再静默吞——apply_error 缺失会让
		// 状态接口丢失真实失败横幅,需 warn 留痕。
		if err := db.DB.QueryRowContext(c.Request.Context(), `SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&applyError); err != nil {
			services.Logf("warn", "GetCaddyStatus: 读取 caddy_apply_error 失败(状态接口 apply_error 字段为空): %v", err)
		}
	}
	drift := services.CurrentConfigDrift()
	pid := caddyLivePID()
	// 审计项：后台数据类重载失败面（证书部署/CRS/IP2Region/威胁库/自动封禁）
	// 与 handler 写路径的 caddy_apply_error 分开呈现——后者是「保存失败」，
	// 前者是「库已更新但运行配置未收敛」。
	backgroundApplyError := services.BackgroundApplyFailureBanner()
	statusData := func(state string) map[string]string {
		return map[string]string{
			"status":                 state,
			"pid":                    strconv.Itoa(pid),
			"apply_error":            applyError,
			"background_apply_error": backgroundApplyError,
			"config_consistent":      strconv.FormatBool(drift.Consistent),
			"config_drift":           driftBannerText(drift),
			"config_drift_since":     driftSinceText(drift),
		}
	}
	resp, err := caddyAdminGet(c.Request.Context(), h.cfg.CaddyAdminURL, "/config/", 2*time.Second)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
			return
		}
	}
	// /config/ 不可达时按 /proc 判定进程存活（替换 GNU ps 管线：busybox ps 不支持 -p，
	// 原实现 'ps -o state= -p' 在容器内恒判 stopped）。
	if caddyProcessRunning() {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("stopped")})
}

// driftBannerText 生成前端全局横幅的主文案（一致时为空串；检测时间
// 拆出到 driftSinceText 供 meta 次行展示，不再内嵌正文）。
func driftBannerText(drift services.ConfigDriftStatus) string {
	if drift.Consistent {
		return ""
	}
	return formatDriftBanner(drift.Missing, drift.Extra)
}

// driftSinceText 漂移首次检测时间（一致时为空串）。
func driftSinceText(drift services.ConfigDriftStatus) string {
	if drift.Consistent {
		return ""
	}
	return drift.Since
}

func formatDriftBanner(missing, extra []string) string {
	// 文案与长度上限单源在 services（看门狗审计同源）——此处
	// 仅保留 handler 层命名供既有调用/测试使用。
	return services.FormatDriftRoutes(missing, extra)
}

func (h *Handlers) GetCaddyConfig(c *gin.Context) {
	// 原始运行配置可能含经 PUT /caddy/config 逃生口写入的内联私钥
	// 或敏感 header——与 GetConfig 的 caddy_config 脱敏同口径：非管理员及
	// 只读 API Key 一律拒绝（路由已收敛到 admin 组，此处为纵深防御）。
	if !canReadSensitiveSecrets(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅管理员可读取原始 Caddy 配置"})
		return
	}
	// 与 GetCaddyStatus 同源取 cfg.CaddyAdminURL——此前硬编码
	// localhost:2019，自定义 admin 地址的部署读到的是错误端点。
	resp, err := caddyAdminGet(c.Request.Context(), h.cfg.CaddyAdminURL, "/config/", 5*time.Second)
	if err != nil {
		// admin 不可达=上游/网关级故障（与 GetRuleCaddyConfig、GetUpstreamHealth
		// 同口径的 502）；500 留给「读到的字节解析失败/超限」这类面板侧失败。
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: "连接 Caddy 失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	// 状态分类 + 32MB+1 探测统一走 services.ReadAdminConfigBody（裸 LimitReader
	// 静默截断会把「超限」误报为下游「解析失败」，排障误导）。
	body, err := services.ReadAdminConfigBody(resp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 Caddy 配置失败: " + err.Error()})
		return
	}
	var configData interface{}
	if err := json.Unmarshal(body, &configData); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 Caddy 配置失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configData})
}

// caddyLogPaths 四份 Caddy 日志的固定路径（写入端写死 /app/logs，与 LOG_FILE
// 无关——见 logstats.go logPaths 注释）。包级 var 支持测试注入
// （wafAuditLogFile/defaultRuntimeLogPath 同模式）。
var caddyLogPaths = map[string]string{
	"runtime": "/app/logs/caddy.log",
	"tls":     "/app/logs/caddy-tls.log",
	"server":  "/app/logs/caddy-server.log",
	"proxy":   "/app/logs/caddy-proxy.log",
}

// caddyLogsStatHook 是测试专用钩子（生产恒 nil）：在 Stat 成功之后、打开并
// 读取之前触发，用于模拟「Stat 与 Read 之间日志增长」的窗口（回归测试
// 读取必须受 128KB 窗口上限约束，不得随增长无界放大）。
var caddyLogsStatHook func()

// caddyLogTypes 返回 caddyLogPaths 的确定性展示顺序（错误文案与文档共用）——
// 由路径表即时派生而非第二份手写枚举：新增日志类型时只改路径表，文案不会
// 漏项（sortedStringKeys 保证遍历序稳定，避免直接遍历 map 造成顺序漂移）。
// 必须是函数而非包级 var：包初始化快照会在测试注入路径表后与查表分叉，
// 「单源派生」只剩口头保证。
func caddyLogTypes() []string {
	return sortedStringKeys(caddyLogPaths)
}

func (h *Handlers) GetCaddyLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "runtime")
	logPath, ok := caddyLogPaths[logType]
	if !ok {
		// fail-visible：未知类型此前静默回落到 runtime 日志，
		// 排障者会误读错误文件（不同日志族内容完全不同）。
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Code: 400, Message: fmt.Sprintf("未知日志类型 %q，可选值：%s", logType, strings.Join(caddyLogTypes(), "、")),
		})
		return
	}

	const maxBytes = 128 * 1024
	const maxLines = 500

	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": ""}})
			return
		}
		// 本端点在 business 组（任意登录用户可读）：5xx 一律固定文案，路径与
		// errno 只进运行日志（admin 细节政策只适用于 admin 组端点，见文件头）。
		writeInternalError(c, http.StatusInternalServerError, "日志文件不可访问", err)
		return
	}

	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}
	// 测试专用钩子（生产恒 nil）：在 Stat 与读取之间模拟日志增长，钉住
	// 「读取严格受窗口上限约束」的不变量。
	if caddyLogsStatHook != nil {
		caddyLogsStatHook()
	}

	f, err := os.Open(logPath)
	if err != nil {
		writeInternalError(c, http.StatusInternalServerError, "打开日志文件失败", err)
		return
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		writeInternalError(c, http.StatusInternalServerError, "读取日志文件失败", err)
		return
	}

	// 与 certjobs.readCertJobLogFile 同源形态——
	// Stat 与 Read 之间日志增长（高流量 + 轮转滞后）时，裸 ReadAll 会突破
	// 128KB 尾窗上限；LimitReader 把读取严格钉在窗口大小。
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil {
		writeInternalError(c, http.StatusInternalServerError, "读取日志文件失败", err)
		return
	}
	// 尾窗首行残段截断统一走 tailLogWindow
	// 口径——窗口内无 '\n' 时整窗为同一巨行中段，输出为空；此前此处分叉
	// 返回原始中段，多字节 rune 切断处 U+FFFD 污染）。
	data = tailLogWindow(f, data, startOffset)

	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	content := convertLogTimezone(strings.Join(lines, "\n"))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

var logTimeRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)`)

// convertLogTimezone 把 Caddy 日志行首的 UTC 时间戳转换为当前生效时区。
// 时区取 services.CurrentLocation（启动与设置变更时已刷新，含 taskengine），
// 不再每请求点查 global_config + LoadLocation——日志查看是高频只读路径，
// 每次展示几百行只需一次原子读。UTC 时区直接短路（无需逐行换算）。
func convertLogTimezone(content string) string {
	loc := services.CurrentLocation()
	if loc == nil || loc.String() == "UTC" {
		return content
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := logTimeRe.FindString(line)
		if m == "" {
			continue
		}
		t, err := time.ParseInLocation("2006/01/02 15:04:05.000", m, time.UTC)
		if err != nil {
			continue
		}
		lines[i] = t.In(loc).Format("2006/01/02 15:04:05.000") + line[len(m):]
	}
	return strings.Join(lines, "\n")
}

// errCaddyAdminLockout 是逃生口护栏的固定文案（不含底层地址细节，
// 管理员排障需要地址时由审计明细携带）。
const errCaddyAdminLockout = "配置中的 admin 段会让面板失去对 Caddy 的控制（admin 已关闭或监听地址与 caddy_admin_url 不一致），请保留面板自管的 admin 端点"

// validateCaddyAdminSection 是原始配置逃生口的 admin 端点护栏。admin 是
// 面板自管资源：/load、GetConfig、启停全部经它访问，一旦提交
// {"admin":{"disabled":true}} 或把 listen 改到面板不可达的 host:port，本次
// apply 会成功，随后面板所有配置写与 Caddy 生命周期操作全部失联，只能重启
// 容器由引导 Caddyfile 恢复。护栏只拦「自锁」两种形态，其余 admin 选项
// （origins/enforce_origin/远程管理地址）放行。
//
// admin 段在 Caddy JSON 中可为对象（listen/disabled）或字符串（监听地址，
// "off" 表示关闭），省略时为默认 localhost:2019——三种形态都要归一比对。
func validateCaddyAdminSection(configData map[string]interface{}, adminURL string) error {
	expectedHost, expectedPort, ok := adminURLHostPort(adminURL)
	if !ok {
		// 畸形 caddy_admin_url 由连接层报错；此处不把逃生口锁死。
		return nil
	}
	listen, err := caddyAdminListenOf(configData)
	if err != nil {
		return err
	}
	if !caddyAdminListenReachable(listen, expectedHost, expectedPort) {
		return fmt.Errorf("%s（当前 admin.listen=%s，面板配置为 %s:%s）", errCaddyAdminLockout, listen, expectedHost, expectedPort)
	}
	return nil
}

// caddyAdminListenOf 归一 admin 段的监听地址：省略/显式 null=Caddy 默认
// localhost:2019；字符串或对象的 listen 即该地址；"off"/disabled 返回自锁
// 错误。护栏与非回环暴露提示共用同一解析，三种形态的解释不得分叉。
func caddyAdminListenOf(configData map[string]interface{}) (string, error) {
	listen := "localhost:2019" // Caddy 默认 admin 端点
	raw, present := configData["admin"]
	if !present {
		return listen, nil
	}
	switch admin := raw.(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(admin), "off") {
			return "", fmt.Errorf("%s", errCaddyAdminLockout)
		}
		return strings.TrimSpace(admin), nil
	case map[string]interface{}:
		if disabled, _ := admin["disabled"].(bool); disabled {
			return "", fmt.Errorf("%s", errCaddyAdminLockout)
		}
		if raw2, ok := admin["listen"]; ok {
			value, isString := raw2.(string)
			if !isString {
				return "", fmt.Errorf("admin.listen 必须是字符串地址")
			}
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				listen = trimmed
			}
		}
		return listen, nil
	case nil:
		// 显式 null 等同省略（Caddy 回落默认 admin 端点）。
		return listen, nil
	default:
		return "", fmt.Errorf("admin 段必须是监听地址字符串或对象")
	}
}

// caddyAdminNonLoopbackWarning 返回 admin 监听落在非回环地址时的显式警告
// （空串=无警告）。护栏只拦自锁、放行通配/自定义监听以保留逃生口——但
// Caddy admin API 无鉴权（PUT /load 可全量改写配置），把监听暴露到非回环
// 网段必须让管理员在保存成功时就看到后果。
func caddyAdminNonLoopbackWarning(configData map[string]interface{}) string {
	listen, err := caddyAdminListenOf(configData)
	if err != nil {
		return ""
	}
	host, _, splitErr := net.SplitHostPort(listen)
	if splitErr != nil {
		if strings.HasPrefix(listen, ":") {
			host = ""
		} else {
			return ""
		}
	}
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::":
		return fmt.Sprintf("admin 监听已改为非回环地址 %s（所有网段），Caddy admin API 无鉴权，可被对应网络访问", listen)
	case "localhost", "127.0.0.1", "::1":
		return ""
	default:
		return fmt.Sprintf("admin 监听已改为非回环地址 %s，Caddy admin API 无鉴权，可被该网段访问", listen)
	}
}

// adminURLHostPort 解析 caddy_admin_url 的 host 与 port（缺端口按 scheme 默认）。
func adminURLHostPort(rawURL string) (host, port string, ok bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", "", false
	}
	host = parsed.Hostname()
	port = parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", "", false
		}
	}
	return host, port, true
}

// caddyAdminListenReachable 判定配置中的 admin 监听地址是否仍能被面板
// （期望 host:port）访问：端口必须一致，且监听主机为通配（覆盖回环）或与
// 期望主机同属回环等价类（localhost/127.0.0.1/::1）。
func caddyAdminListenReachable(listen, expectedHost, expectedPort string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Caddy 也接受 ":2019" 这类省略主机的形态：只有「端口段」无法还原时
		// 才判定不可达（宁可拒绝也不放行自锁形态）。
		if strings.HasPrefix(listen, ":") {
			host, port = "", strings.TrimPrefix(listen, ":")
		} else {
			return false
		}
	}
	if port != expectedPort {
		return false
	}
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::":
		return true
	}
	return adminHostsEquivalent(strings.ToLower(host), strings.ToLower(expectedHost))
}

func adminHostsEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	loopback := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	return loopback[a] && loopback[b]
}

func (h *Handlers) PutCaddyConfig(c *gin.Context) {
	// 导入窗口 fast-fail：原始配置逃生口写 global_config.caddy_config 并
	// 立即应用；导入全量替换后排队重放会把「按导入前用户意图」的载荷写成
	// 导入后的运行配置（语义漂移）。
	if rejectWriteDuringImport(c, "保存原始 Caddy 配置（配置导入进行中）") {
		return
	}
	// 限制请求体大小防止超大 JSON 全量缓冲（与 CreateRule
	// maxCreateRuleBodyBytes 同口径）。
	const maxPutCaddyConfigBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxPutCaddyConfigBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPutCaddyConfigBytes)

	// 先读请求体再取写锁（ValidateConfig
	// 同序）——已认证客户端的慢速/chunked 上传在持锁期间读 body 会阻塞全部
	// 规则/配置写与后台强制重载。
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// MaxBytesReader 超限（chunked/未知 ContentLength）映射 413，与导入路径口径一致
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var configData map[string]interface{}
	if err := json.Unmarshal([]byte(req.Content), &configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 JSON 配置"})
		return
	}
	// admin 自锁护栏（CLI 校验/事务/apply 之前）：admin off 或监听地址改到
	// 面板不可达的 host:port 会让本次 apply 成功后所有配置写与启停全部失联。
	if h.cfg != nil {
		if err := validateCaddyAdminSection(configData, h.cfg.CaddyAdminURL); err != nil {
			recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("Caddy 配置校验未通过", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// 2026-09-06 裁定 ④' 边界补齐：逃生口同样过 Caddy CLI 校验层——校验输入
	// 即将应用的原始 JSON。校验器不可用放行（下方 ApplyConfig 拒绝即回滚）。
	if err := h.caddyService.ValidateJSONViaCLI([]byte(req.Content)); err != nil {
		if !errors.Is(err, services.ErrCLIValidatorUnavailable) {
			recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("Caddy 配置校验未通过", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过: " + err.Error()})
			return
		}
		services.Logf("error", "caddy CLI 校验器不可用，跳过逃生口预检（应用拒绝仍回滚）: %v", err)
	}

	runtimeSnapshot, err := h.snapshotImportRuntime(nil)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", caddyFailureAuditDetail("备份当前 Caddy 配置失败", err))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前 Caddy 配置失败: " + err.Error()})
		return
	}
	tx, err := beginCaddyWriteTx(c)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("开启 Caddy 配置事务失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启 Caddy 配置事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "PutCaddyConfig rollback failed: %v", rollbackErr)
			}
		}
	}()
	result, err := tx.ExecContext(caddyWriteCtx(c), "UPDATE global_config SET caddy_config=?, updated_at=datetime('now') WHERE id=1", req.Content)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("保存 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败: " + err.Error()})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("保存 Caddy 配置失败", fmt.Sprintf("影响记录数为 %d", rowsAffected), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败"})
		return
	}
	appliedConfig, loaded, applyErr := h.caddyService.ApplyConfigReportingForCommit(configData)
	if err := applyErr; err != nil {
		rollbackErr := tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		err = errors.Join(err, rollbackErr, restoreErr)
		// 回弹目标是请求前运行配置（可能已漂移）——事务已显式回滚，把 LKG
		// 钉回已提交库视图，维持「LKG=已提交库视图」的全族不变量（逃生口的
		// 成功路径仍是例外：LKG=用户原始载荷）。
		if pinErr := h.pinLastGoodAfterCompensation(); pinErr != nil {
			h.recordCompensationSideEffects("Caddy 配置应用失败", pinErr)
		}
		// 横幅事实源：配置拒绝（admin 4xx）时候选未生效、事务已回滚，库态与
		// 运行态无分叉——不写横幅（与 finishTxApply 拒绝分支同口径）；恢复失败
		// 表示运行配置状态未知，必须持久化（事务已显式回滚）。
		rejected := services.IsConfigRejected(err)
		if !rejected || restoreErr != nil {
			h.recordCaddyApplyFailure(err, restoreErr)
		}
		recordAudit(c, "更新失败", "Caddy配置", caddyFailureAuditDetail("Caddy 配置应用失败", err))
		// 2026-09-07：与统一——配置拒绝→400，传输/系统→500。
		if rejected {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 拒绝配置: " + err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，配置未保存: " + err.Error()})
		}
		return
	}
	if err := commitTx(tx); err != nil {
		// commit 失败统一走已提交视图恢复（回滚事务 + 重渲染
		// /load + 回退 LKG/投影/证书物化——恢复 /load 失败时仍把已提交字节
		// 写回 LKG，运行配置不停留在一次性逃生口载荷上）。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		// loaded=true 表示 apply 已真实 /load——提交失败不豁免「重载」留痕。
		if loaded {
			recordAudit(c, "重载", "Caddy服务", "保存配置后自动重载")
		}
		// 横幅两态（恢复成功=旧配置已保留 / 失败=运行配置状态未知），失败对象
		// 为提交而非配置应用。
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
		err = errors.Join(err, recovery.err())
		recordAudit(c, "更新失败", "Caddy配置", caddyFailureAuditDetail(commitUncertainLabel, err))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel + ": " + err.Error()})
		return
	}
	committed = true
	// apply 在 commit 前执行，LKG 只能在提交成功后记录候选载荷；否则
	// apply→commit 之间进程中断会让启动兜底回放从未提交的原始配置。
	h.caddyService.PersistLastGoodBytesInLock(appliedConfig)
	// 2026-09-07 裁定：同 UpdateConfig——成功后清除既往失败标记。
	h.recordCaddyApplyResult(nil)

	adminWarning := caddyAdminNonLoopbackWarning(configData)
	if adminWarning != "" {
		services.Logf("warn", "PutCaddyConfig: %s", adminWarning)
	}
	successDetail := "保存 Caddy 全局配置"
	if adminWarning != "" {
		successDetail += "；" + adminWarning
	}
	recordAudit(c, "更新", "Caddy配置", successDetail)
	// 事务型路径重载审计（69d809b4 曾误删，2026-09-06 恢复）。
	// 2026-09-25 审计真实性裁定：仅在真实 /load 发生时落笔——自定义配置与
	// 运行配置同字节时短路零 provision，记「重载」即虚假事件。
	if loaded {
		recordAudit(c, "重载", "Caddy服务", "保存配置后自动重载")
	}
	// （裁决：保留逃生口 + 明示后果）：自定义 Caddy 配置是
	// 一次性逃生口，数据库生成器从不消费 caddy_config 列——任何后续规则/
	// 配置变更或集群同步都会以权威生成配置覆盖它。保存成功即明示。
	successMessage := "配置已保存（注意：自定义配置为一次性逃生口，任何后续规则/配置变更或集群同步都会以数据库生成的权威配置覆盖它）"
	if adminWarning != "" {
		successMessage += "；" + adminWarning
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: successMessage})
}

func (h *Handlers) StartCaddy(c *gin.Context) {
	// 导入窗口 fast-fail（与 ReloadCaddy 同门，且必须在取 caddyOpMu 之前）：
	// 导入全程持锁，排队请求会在导入提交后才执行——启停按陈旧意图落地。
	if rejectWriteDuringImport(c, "启停 Caddy 服务（配置导入进行中）") {
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// `caddy run` boots with the bare Caddyfile (welcome page); re-apply the
	// database-generated config so every rule survives a Caddy restart.
	// caddyApplyNoteLocked: caller already holds caddyOpMu (applyCaddyConfigE
	// would re-lock the non-reentrant mutex and deadlock).
	if note := h.caddyApplyNoteLocked(); note != "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: caddyLifecycleApplyFailureMessage("Caddy 已启动", note)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已启动"})
}

func (h *Handlers) StopCaddy(c *gin.Context) {
	// Stop 是不可逆的可用性动作（pause 文件同时抑制监督器自愈）：导入窗口内
	// 排队到导入提交后再停，会在用户以为「还原成功」的时刻中断全部流量。
	if rejectWriteDuringImport(c, "启停 Caddy 服务（配置导入进行中）") {
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已停止"})
}

func (h *Handlers) RestartCaddy(c *gin.Context) {
	if rejectWriteDuringImport(c, "启停 Caddy 服务（配置导入进行中）") {
		return
	}
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// Same as StartCaddy: caller holds caddyOpMu, use the locked variant.
	if note := h.caddyApplyNoteLocked(); note != "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: caddyLifecycleApplyFailureMessage("Caddy 已重启", note)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已重启"})
}

// accessLogRedactionLine 恒脱敏行的规范形态（与 services 渲染层同一路径，
// 此处是该契约的写入侧视图）。路径由 accesslog 单源派生：引擎 filter 精确
// 匹配 http.Header 的规范化键名，字面量拼写不会命中。
var accessLogRedactionLine = accesslog.APIKeyHeaderPath() + " -> delete"

// normalizeAccessLogRedaction 把脱敏行归一为规范形态
// 移除任何既有的 API Key 映射行（rename 会让头改道，delete 可能写在中间
// 被后续行覆盖），再追加唯一的 delete 行——幂等。识别口径是「同一个 HTTP 头」
// （大小写不敏感，覆盖旧模板的字面量拼写），故同一事实不会在落库值里留两行。
// 解析单源 services.ParseAccessLogFormat（按行号定位脱敏行，其余行原文保留）；
// 非法行由写侧 validateAccessLogFormat 先行 400，本函数不重复拒绝。
// 空白格式原样返回（默认形态：不裁剪原生字段，渲染层注入脱敏行）。
// 尾随换行先裁剪——否则 Split 产生的末尾空元素会被当成一行保留，追加脱敏行
// 后落库值多一行空行（渲染零差异，但 UI/导出/回显多出空白行）。
func normalizeAccessLogRedaction(format string) string {
	if strings.TrimSpace(format) == "" {
		return format
	}
	format = strings.TrimRight(format, "\n")
	redactLines := make(map[int]bool)
	for _, r := range services.ParseAccessLogFormat(format).Rules {
		if accesslog.IsAPIKeyPath(r.Path) {
			redactLines[r.Line] = true
		}
	}
	out := make([]string, 0, 8)
	for i, line := range strings.Split(format, "\n") {
		if redactLines[i+1] {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(append(out, accessLogRedactionLine), "\n")
}

// access_log_format 规模上限：该列是管理员可写的自由多行 DSL，落库后进入每次
// 渲染（同一 encoder map 在每个启用日志的 rule logger 下重复序列化）、/load
// 载荷、LKG/集群快照与变更计划——上限族（规则 name/description、受信网段总量、
// IP 名单条数）对该字段逐条成立，唯独它此前无规模门。按 bytes + 物理行数计
// （DSL 以行分隔，行数与字节数决定放大倍数），口径为落库值：非空白 DSL 写侧
// 归一后恒含一行 API Key 头脱敏规则（故门在归一时前后各过一次）；空白串原样
// 落库，同按原始长度计数。
const (
	maxAccessLogFormatBytes = 16 * 1024
	maxAccessLogFormatLines = 200
)

// validateAccessLogFormatSize 是 access_log_format 规模门的单一事实源
// （保存/预览/备份导入共用）。空白格式=「不裁剪原生字段」的语义，但空白串
// 仍是可落库自由串（DB、GET /config、备份、集群快照都会带上原值），故同样
// 受字节/行数上限约束——规模检查先于任何空白短路，否则纯空格超限串可绕过
// 上限落库。超限 400 点名（fail-visible，不做静默截断）。
func validateAccessLogFormatSize(format string) error {
	if n := len(format); n > maxAccessLogFormatBytes {
		return fmt.Errorf("访问日志格式过长（最多 %d 字节，当前 %d 字节）", maxAccessLogFormatBytes, n)
	}
	lines := strings.Count(strings.TrimRight(format, "\n"), "\n") + 1
	if strings.TrimSpace(format) == "" {
		// 空白格式不裁剪落库；纯换行若先 TrimRight 会任意数量都折叠成一行。
		lines = strings.Count(format, "\n")
		if lines == 0 {
			lines = 1
		}
	}
	if lines > maxAccessLogFormatLines {
		return fmt.Errorf("访问日志格式行数过多（最多 %d 行，当前 %d 行）", maxAccessLogFormatLines, lines)
	}
	return nil
}

// validateAccessLogFormat enforces the fields the log stats feature relies
// on: a client IP and a request URI must survive the format (present natively
// or renamed, never deleted). 非法行（非 `路径 -> 动作` 形态）400 点名行号
// ——解析单源 services.ParseAccessLogFormat，与渲染层零口径差。
func validateAccessLogFormat(format string) error {
	if strings.TrimSpace(format) == "" {
		return nil
	}
	parsed := services.ParseAccessLogFormat(format)
	if len(parsed.Invalid) > 0 {
		return fmt.Errorf("日志格式第 %d 行无效：需要 `路径 -> delete/新名` 形式", parsed.Invalid[0])
	}
	type rule struct {
		path   string
		action string
	}
	var rules []rule
	for _, r := range parsed.Rules {
		rules = append(rules, rule{r.Path, r.Action})
	}
	fieldKept := func(paths ...string) bool {
		for _, p := range paths {
			for _, r := range rules {
				if r.action != "delete" {
					continue
				}
				// 祖先路径同样致命——删除 request 整树会连带抹掉
				// remote_ip/uri/headers 全部统计字段；精确相等或 r.path 是
				// 受保护路径的祖先前缀（request 是 request>remote_ip 的前缀）
				// 均视为删除。
				if r.path == p || strings.HasPrefix(p, r.path+">") {
					return false
				}
			}
		}
		return true
	}
	if !fieldKept("request>remote_ip", "request>client_ip") {
		return fmt.Errorf("日志格式不能删除客户端 IP 字段（request>remote_ip / request>client_ip），日志统计依赖该字段")
	}
	if !fieldKept("request>uri") {
		return fmt.Errorf("日志格式不能删除 URI 字段（request>uri），日志统计依赖该字段")
	}
	if !fieldKept("request>headers") {
		return fmt.Errorf("日志格式不能删除请求头（request>headers），UA 统计依赖该字段")
	}
	if !fieldKept("request>headers>User-Agent") {
		return fmt.Errorf("日志格式不能删除 User-Agent 字段（request>headers>User-Agent），UA 统计依赖该字段")
	}
	renameAlias := func(paths []string, allowed []string) error {
		for _, p := range paths {
			for _, r := range rules {
				if r.action == "delete" || r.action == "" {
					continue
				}
				// 父级改名同样移走子树（request>headers 改名会把
				// 一并带走）——祖先前缀视为命中。
				if r.path != p && !strings.HasPrefix(p, r.path+">") {
					continue
				}
				ok := false
				for _, a := range allowed {
					if r.action == a {
						ok = true
						break
					}
				}
				if !ok {
					return fmt.Errorf("字段 %s 重命名为 %s 后统计将无法识别，仅支持：%s", p, r.action, strings.Join(allowed, " / "))
				}
			}
		}
		return nil
	}
	if err := renameAlias([]string{"request>remote_ip", "request>client_ip"}, []string{"src", "src_ip"}); err != nil {
		return err
	}
	if err := renameAlias([]string{"request>uri"}, []string{"uri_path"}); err != nil {
		return err
	}
	// 祖先前缀同样命中——request>headers 或 request
	// 整树改名会连带移走 （与:1082-1088 fieldKept 的祖先删除、
	// :1111-1114 renameAlias 的祖先前缀同口径）。
	for _, r := range rules {
		if r.action == "" || r.action == "delete" {
			continue
		}
		const uaPath = "request>headers>User-Agent"
		if r.path == uaPath || strings.HasPrefix(uaPath, r.path+">") {
			return fmt.Errorf("User-Agent 字段不能重命名（%s），UA 统计依赖固定字段名", r.path)
		}
	}
	return nil
}
