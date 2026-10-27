package handlers

// 安全事件 IPC 服务端（B 形态主路径的面板侧）：Caddy 进程内的审计写插件把
// 原始 audit JSON 行经 Unix socket 投递给本服务端，由面板入库（Caddy 永不
// 直连数据库）。socket 路径/端点/命名契约与写侧逐字对齐，单一真源在
// services（SecurityEventsIPCSocketPath / SecurityEventsIPCIngestPath）。
//
// 语义要点：
//   - 204 只在 DB commit 完成之后返回（写侧据此判定该批无需 spool）；
//   - 依赖未就绪（数据库句柄缺失）或入库失败一律 5xx——写侧按可重试处理并把
//     整批落 fallback spool，由采集任务补采；
//   - 请求体过大 413 / 读失败 400 表示「该批不可入库」，写侧不 spool（避免毒批
//     无限重试）；
//   - socket 权限 0600、仅本机（Unix domain socket 天然不到网络）。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/services"
)

// SecurityEventsIPCServer 是 UDS 上的最小 HTTP 服务端（仅一个入库端点）。
type SecurityEventsIPCServer struct {
	server   *http.Server
	listener net.Listener
	path     string
}

// SecurityEventsEventsIngestHandler 处理一批换行分隔 audit JSON 的入库请求。
// 独立成方法便于测试直接驱动（不经过真 socket）。
func (s *SecurityEventsIPCServer) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, services.SecurityEventsIPCMaxBodyBytes())
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "security events batch too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read security events batch: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 入库过程与请求生命周期解耦：写侧连接超时/断开不得让一批事件在半途中止
	// （半批提交后写侧仍会把整批 spool，重试幂等但平白放大重复量）。批次本身
	// 有界（body 上限 8MiB），最坏占用有界。
	ctx := context.WithoutCancel(r.Context())
	ingested, ierr := services.IngestSecurityEventBatch(ctx, raw)
	if ierr != nil {
		code := http.StatusInternalServerError
		if errors.Is(ierr, services.ErrSecurityEventsIngestUnavailable) || securityEventsIngestErrorRetryable(ierr) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, "security events ingest failed: "+ierr.Error(), code)
		return
	}
	// 仅当整批消费完成（commit 完成）才回 204——写侧以 204 作为「无需 spool」
	// 的唯一判据。新增行数经响应头回传，便于写侧与排障核对（非契约字段）。
	w.Header().Set("X-Lb-Security-Events-Ingested", strconv.Itoa(ingested))
	w.WriteHeader(http.StatusNoContent)
}

// securityEventsIngestErrorRetryable 判定入库错误是否属「可重试」类（SQLite
// busy/locked、临时 IO 故障）：可重试 → 503，写侧落 spool 稍后补采。
func securityEventsIngestErrorRetryable(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"database is locked", "database is busy", "busy", "locked", "disk i/o error", "no space left"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// StartSecurityEventsIPCServer 在契约 socket 上启动入库服务端：目录缺失时
// 创建（0700）、陈旧 socket 清理、socket 权限 0600。返回的 *Server 由调用方
// 在关停时 Stop（移除 socket 文件）。
func StartSecurityEventsIPCServer() (*SecurityEventsIPCServer, error) {
	path := services.SecurityEventsIPCSocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建安全事件 IPC 目录失败: %w", err)
	}
	// 陈旧 socket 清理：只删 socket 类型，绝不删普通文件（路径被误配成数据
	// 文件时宁可启动失败）。
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("安全事件 IPC 路径已被非 socket 文件占用: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("清理陈旧安全事件 IPC socket 失败: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("检查安全事件 IPC socket 失败: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("监听安全事件 IPC socket 失败: %w", err)
	}
	// 仅本机同用户可写：0600（写侧与面板同用户/同容器）。
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("设置安全事件 IPC socket 权限失败: %w", err)
	}
	s := &SecurityEventsIPCServer{listener: ln, path: path}
	// Handler 引用 s 自身的方法：先建 s 再装 server（同一指针）。
	s.server = &http.Server{
		Handler:           http.HandlerFunc(s.ingestRouter),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if serr := s.server.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			services.Logf("error", "安全事件 IPC 服务异常退出（Caddy 将回退 spool 补采）: %v", serr)
		}
	}()
	services.Logf("info", "安全事件 IPC 服务已启动: %s %s", path, services.SecurityEventsIPCIngestPath)
	return s, nil
}

// ingestRouter 只接受契约端点（其余 404）：最小暴露面。
func (s *SecurityEventsIPCServer) ingestRouter(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != services.SecurityEventsIPCIngestPath {
		http.NotFound(w, r)
		return
	}
	s.handleIngest(w, r)
}

// Stop 关闭服务端并移除 socket 文件（关停预算由调用方给）。
func (s *SecurityEventsIPCServer) Stop(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	if s.path != "" {
		_ = os.Remove(s.path)
	}
	return err
}
