package caddygeoip

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// fakeResolver 可编程 DNS 替身：PTR 与正向结果按表返回。
type fakeResolver struct {
	mu      sync.Mutex
	ptr     map[string][]string // ip → PTR names（含尾点模拟 LookupAddr）
	host    map[string][]string // name → addrs
	ptrErr  map[string]error
	hostErr map[string]error
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.ptrErr[addr]; ok {
		return nil, err
	}
	return f.ptr[addr], nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.hostErr[host]; ok {
		return nil, err
	}
	return f.host[host], nil
}

// Given/When/Then：真爬虫（双跳通过）、机房伪装、伪造 PTR、超时、缓存命中。
func TestVerifyCrawler_passFailMatrix(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"34.100.1.1":  {"vm-34-100-1-1.bc.googleusercontent.com."},
			"1.2.3.4":     {"fake.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"fake.googlebot.com":              {"66.249.66.999"}, // 正向不含原 IP
		},
	})
	// 真 Googlebot：PTR 属域 + 正向回验含原 IP → 通过
	if !VerifyCrawler("66.249.66.1", "googlebot") {
		t.Error("真 Googlebot 应通过")
	}
	// GCP 机房伪装：PTR 后缀不属引擎域 → 拒
	if VerifyCrawler("34.100.1.1", "googlebot") {
		t.Error("GCP PTR 伪装应拒绝")
	}
	// 伪造 PTR 指向官方域：正向回验不含原 IP → 拒
	if VerifyCrawler("1.2.3.4", "googlebot") {
		t.Error("伪造 PTR（正向不含原 IP）应拒绝")
	}
	// 缓存：同 IP 二次询问不再触 DNS（通过结论已缓存）
	if !VerifyCrawler("66.249.66.1", "googlebot") {
		t.Error("缓存命中应直接通过")
	}
}

func TestVerifyCrawler_dnsFailureFailClosed(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptrErr: map[string]error{"5.6.7.8": errors.New("resolver down")},
	})
	if VerifyCrawler("5.6.7.8", "googlebot") {
		t.Error("DNS 失败必须 fail-closed 拒绝")
	}
}
