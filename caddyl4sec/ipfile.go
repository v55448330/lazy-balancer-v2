package caddyl4sec

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/fsnotify/fsnotify"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// —— layer4.matchers.lb_ipfile ——
//
// 上游 layer4.matchers.remote_ip_list（caddy-l4 v0.1.2）的替代实现。上游有三处
// 缺陷（容器实证 P0：caddy validate 偶发挂死）：
//
//  1. Cleanup 的 `stop <- true` 是无缓冲 send——monitor 已沿 ctx.Done/watcher
//     错误路径退出后，Cleanup 永久阻塞（validate 生命周期被随机击杀）；
//  2. 文件重读发生在 Match 连接路径（reloadNeededMutex 持锁读文件）；
//  3. watcher 一旦出错/关闭 monitor 直接退出，只剩 stale 集合 + 每次 Match
//     刷一条 warn。
//
// 本实现逐条修正：
//   - 生命周期信号 = close(stopCh)（sync.Once 幂等）+ ctx.Done 双保险，
//     Cleanup 绝不阻塞、绝不 panic，重复调用安全；
//   - 文件重读只在 monitor goroutine（fsnotify 事件 + 1s mtime/size stat
//     兜底节流，wafiplist 同模式），Match 读 atomic 快照——连接路径零 IO 零锁；
//   - watcher 错误不退出 monitor（降级 stat 兜底），文件/目录缺失 = 空集 +
//     热载自愈，Provision 不拒绝配置（投影文件未就绪不该打死整份配置）。
//
// 行解析与匹配语义与上游逐字对齐（复用同一 caddyhttp.CIDRExpressionToPrefix）：
// CIDR 与裸 IP（/32、/128）混排、解析失败行忽略（注释/空行天然忽略）、
// 文件缺失=空集；对端地址不可解析时 (true, err)——上游同款（MatcherSet 语境
// 下 error 等效不匹配，deny/信任路由双双落回兜底路由）。多文件 = 渲染侧多
// 实例 + match 多 set（OR），本模块只持单文件。

// l4IPFilePollInterval stat 兜底节流间隔（var：测试收窄）。
var l4IPFilePollInterval = 1 * time.Second

// ipPrefixSet 是已编译的匹配快照（atomic 交换，Match 无锁读）。
type ipPrefixSet struct {
	cidrs []netip.Prefix
}

// L4IPFileMatcher 按文件内容（CIDR/IP 逐行）匹配连接对端地址。
type L4IPFileMatcher struct {
	// File 是名单投影文件路径（writeIPListFile 稳定命名产物；单文件，多
	// 名单由渲染侧多实例表达）。
	File string `json:"file,omitempty"`

	logger    *zap.Logger
	ctx       caddy.Context
	snap      atomic.Pointer[ipPrefixSet]
	lastMod   time.Time // monitor 私有：上次成功加载的文件形态（stat 兜底基线）
	lastSize  int64
	stopCh    chan struct{}
	stopOnce  sync.Once
	done      chan struct{}
	warnLog   *keyedWarnThrottle // 同原因节流告警（指针：禁止值拷贝带锁结构）
	provision sync.Mutex         // Provision 内部顺序化（非热路径）
}

// CaddyModule returns the Caddy module information.
func (*L4IPFileMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.lb_ipfile",
		New: func() caddy.Module { return new(L4IPFileMatcher) },
	}
}

// Provision 加载初始快照并启动 monitor（文件/目录缺失降级空集 + 热载自愈）。
func (m *L4IPFileMatcher) Provision(ctx caddy.Context) error {
	m.provision.Lock()
	defer m.provision.Unlock()
	m.logger = ctx.Logger()
	m.ctx = ctx
	if m.File == "" {
		return fmt.Errorf("lb_ipfile: file 不能为空（渲染侧必须发射名单投影路径）")
	}
	if m.warnLog == nil {
		m.warnLog = newKeyedWarnThrottle(time.Minute)
	}
	set, mod, size, err := m.readSet()
	if err != nil {
		// 读取失败（权限/IO）：空集降级 + 节流告警，热载自愈。
		m.logThrottled("initial-load", err)
	}
	m.lastMod, m.lastSize = mod, size
	m.snap.Store(set)

	m.stopCh = make(chan struct{})
	m.done = make(chan struct{})
	go m.monitor()
	return nil
}

// Cleanup 停止 monitor：close 信号幂等且永不阻塞（上游无缓冲 send 的 P0
// 修点）。monitor 侧 defer 关闭 watcher；已退出的 monitor 收到 close 无副作用。
func (m *L4IPFileMatcher) Cleanup() error {
	if m.stopCh != nil {
		m.stopOnce.Do(func() { close(m.stopCh) })
	}
	return nil
}

// Match 实现 layer4.ConnMatcher：对端地址解析与上游 getRemoteIP 同款
// （SplitHostPort → ParseAddr，整体回退）；解析失败 (true, err) 与上游逐字
// 对齐（MatcherSet 语境等效不匹配）。命中判定读 atomic 快照，零锁零 IO。
func (m *L4IPFileMatcher) Match(cx *layer4.Connection) (bool, error) {
	raw := ""
	if cx != nil && cx.Conn != nil && cx.Conn.RemoteAddr() != nil {
		raw = cx.Conn.RemoteAddr().String()
	}
	ipStr, _, err := net.SplitHostPort(raw)
	if err != nil {
		ipStr = raw
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		// 上游同款：按「命中+错误」返回（集合语境等效不匹配）。
		return true, fmt.Errorf("invalid remote IP address: %s", ipStr)
	}
	set := m.snap.Load()
	if set == nil {
		return false, nil
	}
	for _, cidr := range set.cidrs {
		if cidr.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// monitor 事件循环：fsnotify（目录监听 + 文件名过滤，Create/Write 置重载）
// 与 1s mtime/size stat 兜底并行；stopCh/ctx.Done 任一触发即退出（defer 关
// watcher）。watcher 错误只告警不退出——stat 兜底继续自愈（上游在此退出=
// 永久 stale）。
func (m *L4IPFileMatcher) monitor() {
	defer close(m.done)
	ticker := time.NewTicker(l4IPFilePollInterval)
	defer ticker.Stop()

	var events <-chan fsnotify.Event
	var errs <-chan error
	if w, err := fsnotify.NewWatcher(); err != nil {
		m.logThrottled("watcher-create", err)
	} else {
		defer func() { _ = w.Close() }()
		if st, serr := os.Stat(filepath.Dir(m.File)); serr == nil && st.IsDir() {
			if aerr := w.Add(filepath.Dir(m.File)); aerr != nil {
				m.logThrottled("watcher-add", aerr)
			}
		} else {
			// 目录缺席：不 Add（fsnotify 无法监听不存在的目录）；stat 兜底
			// 会在文件/目录出现后自愈（本进程内 watcher 不重建，属已披露
			// 降级——投影目录在容器生命周期内常驻）。
			m.logThrottled("watcher-dir-missing", fmt.Errorf("directory of %s absent", m.File))
		}
		events, errs = w.Events, w.Errors
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-m.ctx.Done():
			return
		case err, ok := <-errs:
			if !ok {
				errs = nil // watcher 关闭：转纯 stat 兜底，不退出
				continue
			}
			m.logThrottled("watcher-error", err)
		case ev, ok := <-events:
			if !ok {
				events = nil // 同上
				continue
			}
			if ev.Name == m.File && (ev.Has(fsnotify.Create) || ev.Has(fsnotify.Write)) {
				m.tryReload()
			}
		case <-ticker.C:
			m.statCompare()
		}
	}
}

// statCompare mtime/size 兜底：形态变化（或从无到有/有到无）才重读，1s 节流
// ——覆盖 fsnotify 丢失/目录重建等失效形态（wafiplist 同模式）。
func (m *L4IPFileMatcher) statCompare() {
	st, err := os.Stat(m.File)
	if err != nil {
		if m.lastSize != -1 {
			// 文件从有到无：清空集合（名单文件被移除=空名单语义）
			m.tryReload()
		}
		return
	}
	if st.ModTime().Equal(m.lastMod) && st.Size() == m.lastSize {
		return
	}
	m.tryReload()
}

// tryReload 重读文件并交换快照：失败保留旧快照（fail-stale）+ 节流告警。
func (m *L4IPFileMatcher) tryReload() {
	set, mod, size, err := m.readSet()
	if err != nil {
		m.logThrottled("reload", err)
		return
	}
	m.lastMod, m.lastSize = mod, size
	m.snap.Store(set)
}

// readSet 读取并编译名单：CIDR 与裸 IP 经 caddyhttp.CIDRExpressionToPrefix
// （与上游同一解析函数=同一语义：裸 IP 收敛 /32|/128，注释/空行/非法行忽略）。
// 文件缺失 = 空集（err=nil，降级语义）；返回文件形态供 stat 兜底记基线。
func (m *L4IPFileMatcher) readSet() (*ipPrefixSet, time.Time, int64, error) {
	st, err := os.Stat(m.File)
	if err != nil {
		return &ipPrefixSet{}, time.Time{}, -1, nil
	}
	file, err := os.Open(m.File)
	if err != nil {
		// 错误路径返回 nil 集合：调用方（Provision/tryReload）对 err!=nil
		// 不 Store——读失败绝不把旧快照/空集误固化（fail-stale）。
		return nil, st.ModTime(), st.Size(), fmt.Errorf("error opening the IP list file %v: %w", m.File, err)
	}
	defer func() { _ = file.Close() }()
	var cidrs []netip.Prefix
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cidr, perr := caddyhttp.CIDRExpressionToPrefix(scanner.Text())
		if perr == nil {
			cidrs = append(cidrs, cidr)
		}
	}
	if serr := scanner.Err(); serr != nil {
		return nil, st.ModTime(), st.Size(), fmt.Errorf("error reading the IPs from %v: %w", m.File, serr)
	}
	return &ipPrefixSet{cidrs: cidrs}, st.ModTime(), st.Size(), nil
}

// logThrottled 同原因节流告警（keyedWarnThrottle 复用）。
func (m *L4IPFileMatcher) logThrottled(reason string, err error) {
	if m.logger == nil {
		return
	}
	if !m.warnLog.allow(m.File + "|" + reason) {
		return
	}
	m.logger.Warn("lb_ipfile: IP list load degraded (fail-stale)",
		zap.String("file", m.File), zap.String("reason", reason), zap.Error(err))
}

// 编译期契约。
var (
	_ layer4.ConnMatcher = (*L4IPFileMatcher)(nil)
	_ caddy.Provisioner  = (*L4IPFileMatcher)(nil)
	_ caddy.CleanerUpper = (*L4IPFileMatcher)(nil)
	_ caddy.Module       = (*L4IPFileMatcher)(nil)
)

func init() {
	caddy.RegisterModule(&L4IPFileMatcher{})
}
