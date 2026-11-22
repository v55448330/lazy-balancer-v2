package services

// 集群上报（从节点事件/日报统计）的 TLS 信任装配：与快照同步共用同一 TOFU
// 指纹体系（cluster_ca_pins/<host:port>）。newClusterTOFUTransport 对**所有**
// https 主节点（含公网可信证书）只按 pin 校验叶证书——InsecureSkipVerify 下
// 没有系统根分支；首次指纹落盘即信任，之后逐次比对。此前上报走默认 transport，
// 自签主节点下 TLS 握手失败导致事件/统计永远 spool 重传不出去（2026-11-22 实测定位）。

import (
	"net/http"
	"net/url"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// InstallNotifyClusterForwardTransport 装配 notify 集群上报传输工厂（进程启动
// 装配一次）。HTTP 主节点返回 nil（无需 TLS 配置）。
func InstallNotifyClusterForwardTransport() {
	notify.SetClusterForwardTransportFactory(func(masterURL string) http.RoundTripper {
		u, err := url.Parse(masterURL)
		if err != nil || u.Scheme != "https" {
			return nil
		}
		return newClusterTOFUTransport(db.DataDir(), db.DB, nil)
	})
}
