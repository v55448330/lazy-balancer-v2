package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

// 容器 HEALTHCHECK 走二进制自带子命令：不派生 shell/wget/ssl_client，
// 探针本身只有一个进程。此前的 `sh -c wget https://...` 在 PID 1 不回收
// 孤儿的镜像里会持续累积僵尸（生产实证：十余小时堆到 2252 个 ssl_client，
// 打满 cgroup pids 配额，连 `cat` 都无法 fork）。
//
// 语义与旧探针保持一致：HTTPS 先行（面板管理 TLS 是常态），失败回落明文；
// 两者都只认 200。回环地址 + 自签证书 → 忽略证书校验只用于本机存活判定，
// 不承担证书正确性验证。
const dockerHealthcheckTimeout = 5 * time.Second

var (
	healthcheckHTTPSURL = "https://127.0.0.1:8000/health"
	healthcheckHTTPURL  = "http://127.0.0.1:8000/health"
	// 单次尝试上限：两段（HTTPS→HTTP）合计必须小于 Docker HEALTHCHECK 的
	// --timeout=5s，否则探针会先被运行时杀掉（137），日志里只剩「超时」。
	healthcheckTimeout = 2 * time.Second
)

// healthcheckRequested 判断是否以健康检查模式启动。只认首个参数，避免与
// 既有 -config/-init 标志解析相互影响。
func healthcheckRequested(args []string) bool {
	return len(args) > 1 && args[1] == "--healthcheck"
}

// runHealthcheck 执行一次存活探测并返回进程退出码：0=健康，1=不健康。
func runHealthcheck() int {
	client := &http.Client{
		Timeout: healthcheckTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 回环自签
		},
		// 不跟随跳转：面板在管理 TLS 模式下可能把明文请求 302 到登录页，
		// 跟随会把「登录页 200」误判为健康。健康判定只认第一跳 200。
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, url := range []string{healthcheckHTTPSURL, healthcheckHTTPURL} {
		if probeHealth(client, url) {
			return 0
		}
	}
	return 1
}

func probeHealth(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
