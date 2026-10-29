package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"lazy-balancer-v2/internal/atomicfile"
)

const defaultLogFile = "/app/logs/lazy-balancer.log"

// defaultPort 是面板 HTTP 端口默认值（cfg 初始化与越界告警共用同一处）。
// 告警文案里的「using default」必须指向本常量：端口越界时 cfg.Port 保持
// 默认值不动，运维按提示改成别的数字反而继续落入越界分支。
const defaultPort = 8000

type Config struct {
	// Server
	Port      int    `json:"port"`
	DataDir   string `json:"data_dir"`
	StaticDir string `json:"static_dir"`
	Version   string `json:"version"`

	// Caddy
	// CaddyAdminURL 是生产 Caddy Admin API（配置加载、状态、生命周期与任务
	// 守卫）的唯一地址；CaddyMetricsURL 是所有 Prometheus 指标采集的唯一地址，
	// 两者可指向同机不同端口/路径，指标消费不得再由 admin URL 拼接。
	CaddyAdminURL   string `json:"caddy_admin_url"`
	CaddyMetricsURL string `json:"caddy_metrics_url"`

	// Metrics
	MetricsInterval int `json:"metrics_interval"` // seconds

	// Node
	NodeName string `json:"node_name"`

	// Log
	LogFile string `json:"log_file"` // effective runtime log path (LOG_FILE env or default)

	// JWT
	JWTSecret string `json:"jwt_secret"`

	// Backup: 自动备份落盘目录（调度器仅主节点运行）
	BackupDir string `json:"backup_dir"`
}

// configWarnf 是启动期告警出口：LoadCollectWarnings 把告警收集给调用方，在
// 运行日志装配完成后统一重放（否则配置误配信号只存在于容器 stdout，只采集
// 日志文件的部署完全看不到）。
type configWarnf func(format string, args ...any)

// configValueKind 是配置文件键在 JSON 中的期望类型。
type configValueKind int

const (
	configStringValue configValueKind = iota
	configNumberValue
)

// configFileKey 是配置文件（-config）键的单一登记项：期望类型 + 应用函数。
// 「未知键告警 / 类型校验 / 应用」全部由本表驱动——此前三份平行键表
// （支持集合、类型 switch、应用块）各自维护，新增一个键漏一处即表现为
// 「支持但静默不生效」（本文件反复强调要避免的失败形态）。
type configFileKey struct {
	kind  configValueKind
	apply func(cfg *Config, value any, warnf configWarnf)
}

func (k configFileKey) matchesType(value any) bool {
	switch k.kind {
	case configNumberValue:
		_, ok := value.(float64)
		return ok
	default:
		_, ok := value.(string)
		return ok
	}
}

// configFileKeys 是配置文件支持且会被解析的键表。其余键不参与解析
// （log_file/jwt_secret/backup_dir/node_name/version 只接受环境变量或默认值），
// 出现在文件中时逐条告警——静默忽略会让「改了配置没生效」无迹可循。
var configFileKeys = map[string]configFileKey{
	"data_dir": {kind: configStringValue, apply: func(cfg *Config, value any, _ configWarnf) {
		if v, ok := value.(string); ok && v != "" {
			cfg.DataDir = v
		}
	}},
	"static_dir": {kind: configStringValue, apply: func(cfg *Config, value any, _ configWarnf) {
		if v, ok := value.(string); ok && v != "" {
			cfg.StaticDir = v
		}
	}},
	"port": {kind: configNumberValue, apply: func(cfg *Config, value any, warnf configWarnf) {
		v := value.(float64)
		// 浮点截断不得静默——8000.9→8000 会让「配置未生效」无从排查。
		// 与 metrics_interval 同口径先判界再转换：1e300 之类巨值直接
		// float→int 是实现相关结果（实测回绕成 MaxInt64）。
		switch {
		case math.IsNaN(v) || v < 1 || v > 65535:
			// 默认值取 cfg.Port（apply 不改它，此时即 defaultPort）——与
			// metrics_interval 同口径，默认值改动不会让文案说谎。
			warnf("config: port %v outside 1-65535; using default %d", v, cfg.Port)
		default:
			if v != math.Trunc(v) {
				warnf("config: port %v is not an integer; truncated to %d", v, int(v))
			}
			cfg.Port = int(v)
		}
	}},
	"caddy_admin_url": {kind: configStringValue, apply: func(cfg *Config, value any, _ configWarnf) {
		if v, ok := value.(string); ok && v != "" {
			cfg.CaddyAdminURL = v
		}
	}},
	"caddy_metrics_url": {kind: configStringValue, apply: func(cfg *Config, value any, _ configWarnf) {
		if v, ok := value.(string); ok && v != "" {
			cfg.CaddyMetricsURL = v
		}
	}},
	"metrics_interval": {kind: configNumberValue, apply: func(cfg *Config, value any, warnf configWarnf) {
		v := value.(float64)
		// ≤0 与超范围都必须可见（旧实现 0/负值静默回落默认 30s；巨值
		// float→int 转换是未定义语义，可能回绕成负数再被静默抬到 5s 高频
		// 采集）。先判界再转换。
		switch {
		case v <= 0:
			warnf("config: metrics_interval %v must be positive; using default %d", v, cfg.MetricsInterval)
		case v > metricsIntervalMax:
			warnf("config: metrics_interval %v above maximum %d; clamped to %d", v, metricsIntervalMax, metricsIntervalMax)
			cfg.MetricsInterval = metricsIntervalMax
		default:
			// 下限钳位与截断均留痕（此前 1 被静默抬到 5、1.9 被静默
			// 截断——看似「配置未生效」）。
			if v < 5 {
				warnf("config: metrics_interval %v below minimum 5; clamped to 5", v)
			} else if v != math.Trunc(v) {
				warnf("config: metrics_interval %v is not an integer; truncated to %d", v, int(v))
			}
			cfg.MetricsInterval = max(5, int(v))
		}
	}},
}

// minJWTSecretBytes 是 JWT/OIDC state 签名密钥的最短长度（HS256 强度下限）。
// 文件通道（loadOrCreateJWTSecret）与环境变量通道共用本阈值——旧实现
// 只校验文件通道，JWT_SECRET=abc 这类 3 字节密钥可直接绕过。
const minJWTSecretBytes = 32

// metricsIntervalMax 是 metrics_interval 的合理上限（24h）。超出范围的浮点
// 直接转 int 是未定义语义（巨值可能回绕成负数再被静默抬到下限），必须先判界。
const metricsIntervalMax = 86400

// minJWTSecretDistinctBytes 是密钥的最小不同字节数（熵下限）。仅长度检查会
// 让 32 个空格、或单字符重复 32 次通过——HS256 密钥可预测等价于无签名
// （JWT/OIDC state 可离线伪造）。随机 hex（64 字符）与正常口令短语都远高于
// 该下限，只有明显退化的密钥形态被拒。
const minJWTSecretDistinctBytes = 8

// jwtSecretWeakness 返回密钥不合格的原因（空串=合格）。文件通道（生成随机
// 64 位 hex）、环境变量通道与既有密钥文件校验共用本判据。
func jwtSecretWeakness(secret string) string {
	if len(secret) < minJWTSecretBytes {
		return fmt.Sprintf("长度过短（%d 字节 < %d）", len(secret), minJWTSecretBytes)
	}
	distinct := make(map[byte]struct{}, minJWTSecretDistinctBytes)
	for index := range len(secret) {
		distinct[secret[index]] = struct{}{}
		if len(distinct) >= minJWTSecretDistinctBytes {
			return ""
		}
	}
	return fmt.Sprintf("熵不足（仅 %d 个不同字节 < %d）", len(distinct), minJWTSecretDistinctBytes)
}

// jwtSecretStrongEnough 判定密钥是否满足最短长度与熵下限。空串（未配置）不走
// 本判定——文件通道会生成随机密钥。
func jwtSecretStrongEnough(secret string) bool { return jwtSecretWeakness(secret) == "" }

// LoadCollectWarnings 加载运行配置并收集启动期告警：默认值 → 配置文件（仅
// configFileKeys 支持的键）→ 环境变量。配置文件中的未知键/类型错误逐条收集
// 后忽略；读取/解析失败同样可见（回退默认值）。告警不直接打印，而是随返回值
// 交给调用方在运行日志装配完成后统一重放（经统一日志级别门）——配置告警发生
// 在日志装配之前，只在 stdout 可见，只采集日志文件的部署看不到未知键、类型
// 错误、弱 JWT 密钥、APP_VERSION 未注入等误配信号。
// 本函数是生产唯一加载入口（测试侧的单返回值包装见 config_test.go 的
// loadForTest）：产品文件不承载 test-only 入口，双入口会让「测试覆盖的路径 ≠
// 生产路径」的分叉无从发现。
func LoadCollectWarnings(path string) (*Config, []string) {
	var warnings []string
	cfg := load(path, func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	})
	return cfg, warnings
}

func load(path string, warnf configWarnf) *Config {
	// Default values
	// APP_VERSION 未注入时兜底 "unknown"（fail-visible）——显示一个并非
	// 当前构建的版本号会误导排障；发版链（Dockerfile ARG VERSION +
	// buildx --build-arg）显式传参，不受兜底值影响。
	if os.Getenv("APP_VERSION") == "" {
		warnf("config: APP_VERSION 未注入，面板版本显示为 unknown（发布构建应经 Dockerfile ARG VERSION / buildx --build-arg 显式传参）")
	}
	cfg := &Config{
		Port:            defaultPort,
		DataDir:         "/app/data",
		StaticDir:       "/app/ui",
		CaddyAdminURL:   "http://localhost:2019",
		CaddyMetricsURL: "http://localhost:2019/metrics",
		MetricsInterval: 30,
		NodeName:        getEnv("NODE_NAME", "node-1"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		Version:         getEnv("APP_VERSION", "unknown"),
		LogFile:         getEnv("LOG_FILE", defaultLogFile),
	}

	// Load from config file if provided
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// 配置文件读取失败必须可见（与下方解析失败分支对称）——静默回落
			// 默认值会让「指定了 -config 却没生效」排查无门。
			warnf("config: failed to read config file %s (%v); using defaults", path, err)
		} else {
			// Try to parse as JSON (simple approach)
			var fileCfg map[string]interface{}
			if jerr := json.Unmarshal(data, &fileCfg); jerr != nil {
				// 文件存在但解析失败必须可见——静默回落
				// 默认值会让「改了配置没生效」排查无门。
				warnf("config: file %s exists but failed to parse (%v); using defaults", path, jerr)
			} else {
				// 未知键必须可见——支持键之外的字段不会生效。
				unsupported := make([]string, 0, len(fileCfg))
				for key := range fileCfg {
					if _, supported := configFileKeys[key]; !supported {
						unsupported = append(unsupported, key)
					}
				}
				sort.Strings(unsupported)
				for _, key := range unsupported {
					warnf("config: ignoring unsupported config key %q in %s", key, path)
				}
				// 支持键按 key 排序逐项校验+应用（顺序稳定使告警可对表）：
				// 类型不符沿用默认值并逐键告警——port/data_dir 误配后不得看似
				// 「配置未生效」甚至切到空库。
				keys := make([]string, 0, len(configFileKeys))
				for key := range configFileKeys {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					value, exists := fileCfg[key]
					if !exists {
						continue
					}
					spec := configFileKeys[key]
					if !spec.matchesType(value) {
						warnf("config: invalid type for key %q in %s; using default", key, path)
						continue
					}
					spec.apply(cfg, value, warnf)
				}
			}
		}
	}

	// 自动备份目录(v2.3.x):默认挂 DataDir 同级 backup(容器 /app/data → /app/backup，
	// 本地 ./data → ./backup)；BACKUP_DIR env 可覆盖。计算在配置文件解析之后——
	// data_dir 可被文件覆盖，目录锚点必须取最终值。
	// data_dir/backup_dir 进入投影与 @ipListFast 白名单前必须是绝对
	// 路径；相对路径会让 IPListDataDir 越出 AllowedPathPrefix，整份配置被拒。
	if abs, err := filepath.Abs(cfg.DataDir); err == nil {
		cfg.DataDir = abs
	}
	cfg.BackupDir = getEnv("BACKUP_DIR", filepath.Join(filepath.Dir(cfg.DataDir), "backup"))
	if abs, err := filepath.Abs(cfg.BackupDir); err == nil {
		cfg.BackupDir = abs
	}

	// static_dir 与 data_dir/backup_dir 同口径：消费侧直接字符串拼接
	// （r.Static(cfg.StaticDir+"/assets")），相对值会按**进程 cwd** 解析——
	// systemd/容器的 cwd 与预期不同时面板静态资源整体 404，且启动期无信号。
	// 绝对化 + Clean 去尾随斜杠（避免拼出 "//assets"）；目录不存在时启动期
	// 告警（fail-visible）而不是等到运行期 404。
	if cfg.StaticDir != "" {
		if abs, err := filepath.Abs(cfg.StaticDir); err == nil {
			cfg.StaticDir = abs
		}
		cfg.StaticDir = filepath.Clean(cfg.StaticDir)
		if info, err := os.Stat(cfg.StaticDir); err != nil || !info.IsDir() {
			warnf("config: static_dir %q 不存在或不是目录——面板静态资源将返回 404", cfg.StaticDir)
		}
	}

	// log_file 与 static_dir 同口径：相对值按进程 cwd 解析——systemd/容器
	// 的 cwd 与预期不同时日志静默落到别处，logstats 投影与轮转 writer 读的
	// 是另一条路径。非空值绝对化 + Clean；父目录建不出来时启动期告警
	// （fail-visible）——运行期 writer 只会回退 stdout，面板表现为「文件
	// 日志关闭」而无任何信号。
	if cfg.LogFile != "" {
		if abs, err := filepath.Abs(cfg.LogFile); err == nil {
			cfg.LogFile = abs
		}
		cfg.LogFile = filepath.Clean(cfg.LogFile)
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); err != nil {
			warnf("config: log_file %q 父目录无法创建（%v）——文件日志将回退 stdout", cfg.LogFile, err)
		}
	}

	// JWT secret: env wins; otherwise persist a random one so tokens survive
	// restarts and the secret is never predictable.
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = loadOrCreateJWTSecretWith(cfg.DataDir, warnf)
	} else if reason := jwtSecretWeakness(cfg.JWTSecret); reason != "" {
		// 环境变量通道此前完全不校验长度（文件通道强制 ≥32 并再生）。
		// env 是运维显式输入，不自动替换（替换会让所有令牌静默失效），只告警
		// 可见。判据增加熵下限——纯长度达标但形态可预测（空格/重复
		// 字节）的密钥同样告警。
		warnf("config: JWT_SECRET 环境变量强度不足——%s；JWT HS256 与 OIDC state 可被离线伪造，请改用 ≥%d 字节的高熵随机密钥", reason, minJWTSecretBytes)
	}

	// 端口范围无二次校验：port 只有配置文件一个通道（见 configFileKeys），
	// 该通道在应用前已判界并钳到默认值——任何落地的 cfg.Port 必在 1-65535。
	// 保留一个"回退 8000"分支只会误导后来者以为存在未校验的 env 通道。

	// caddy_admin_url 一致性校验（fail-visible）：渲染产物的 admin 监听恒为
	// 127.0.0.1:2019（services.CaddyAdminListenAddr 单源），首次成功 /load 后
	// Caddy admin 即迁到该地址。caddy_admin_url 只是「首次 /load 之前」的引导
	// 端点——指向其他地址时面板配置的端点在首次 /load 后失联（需人工恢复），
	// 启动期必须可见而非届时静默断联。
	if scheme, listen, ok := adminURLListen(cfg.CaddyAdminURL); ok && (scheme != "http" || !adminListenEquivalentToRender(listen)) {
		warnf("config: caddy_admin_url=%q 与渲染产物自管 admin 的 http://127.0.0.1:2019 不等价——首次成功 /load 后 Caddy admin 将迁到该 HTTP 回环端点，本配置端点随即失联；请改为 http://127.0.0.1:2019 或移除该配置项", cfg.CaddyAdminURL)
	}

	return cfg
}

// adminListenEquivalentToRender 判定 caddy_admin_url 的监听地址是否等价于
// 渲染产物的 admin 监听 127.0.0.1:2019。回环主机名属同一等价类：默认配置即
// http://localhost:2019，未规范化直接字符串比较会把出厂默认值误报为「端点与
// 渲染不一致」的严重配置错误（每次启动一条自相矛盾告警，且提示移除一个并非
// 配置项的东西）。localhost 解析到 ::1 失败后由 Go 连接器回落到 127.0.0.1，
// admin 仍可拨通。
func adminListenEquivalentToRender(listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port != "2019" {
		return false
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// adminURLListen 解析 caddy_admin_url 的 scheme 与 host:port（失败时 ok=false——
// 畸形 URL 由使用方连接时报错，此处不重复告警）。非 HTTP scheme 即使缺省端口
// 无法推导也返回 ok=true，让调用方对 scheme 本身发出一致性告警。
func adminURLListen(rawURL string) (string, string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", "", false
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		// 未显式写端口时按 scheme 默认端口判定。
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return parsed.Scheme, "", true
		}
	}
	// JoinHostPort 而非字符串拼接：IPv6 回环（::1）必须成 [::1]:2019 才能
	// 被 SplitHostPort 还原，否则等价类判定永远 miss。
	return parsed.Scheme, net.JoinHostPort(host, port), true
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// jwtSecretWrite 是 JWT 签名密钥的落盘接缝：默认值就是仓内唯一的原子落盘
// 原语（同目录临时文件 → 权限 → fsync → rename → 父目录 fsync）。此前的
// os.WriteFile 直写没有 fsync/rename，掉电窗口下可能留下截断文件——下次启动
// 判为弱密钥重生成，全部已签发 JWT/OIDC state 失效。接缝同时供测试注入
// 写失败，断言「错误可见且旧密钥文件不被破坏」。
var jwtSecretWrite = atomicfile.WriteAtomic

// loadOrCreateJWTSecretWith 的告警统一走调用方给的出口（LoadCollectWarnings
// 收集后重放；测试直调入口在同包 config_test.go 的
// loadOrCreateJWTSecretForTest）。
func loadOrCreateJWTSecretWith(dataDir string, warnf configWarnf) string {
	secretPath := filepath.Join(dataDir, "jwt_secret")
	if data, err := os.ReadFile(secretPath); err == nil {
		if jwtSecretStrongEnough(string(data)) {
			return string(data)
		}
		if len(data) > 0 {
			// 非空弱密钥的覆写必须可见——此前静默
			// 重生成，旧令牌全部失效且零日志信号；与下方目录/写失败分支
			// 及端口回退的可见性准则对齐。空文件等同未初始化，不告警。
			// 原因含长度或熵两类（"长度过短"/"熵不足"）。
			warnf("JWT 密钥文件 %s 内容%s，已重新生成（旧令牌将失效）", secretPath, jwtSecretWeakness(string(data)))
		}
	} else if !os.IsNotExist(err) {
		// 文件存在但读取失败（瞬时 IO/ACL 形态）
		// 此前静默落入重生成——写入成功则全部 JWT 失效且零日志，是同文件
		// 唯一未留痕分支；ENOENT（首次启动）不告警。
		warnf("JWT 密钥文件 %s 读取失败（%v），将重新生成（旧令牌将失效）", secretPath, err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("生成 JWT 密钥失败: %v", err)
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		// 目录创建失败必须可见——此前静默跳过写入，JWT 密钥每次启动
		// 随机重生成（旧令牌全部失效）且零日志信号；与下方写失败分支对称。
		warnf("JWT 密钥目录 %s 创建失败（重启后令牌将失效）: %v", dataDir, err)
	} else if err := jwtSecretWrite(secretPath, []byte(secret), 0600); err != nil {
		warnf("JWT 密钥写入 %s 失败（重启后令牌将失效）: %v", secretPath, err)
	}
	return secret
}
