package services

import "net/http"

// roundTripFunc 供各测试注入 http.Client.Transport（原定义随限流抓取测试
// 一并移除后，其余集群/静态资源测试仍依赖该共享形状）。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
