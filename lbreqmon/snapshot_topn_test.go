package lbreqmon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// resetRingForTest 重置环形缓冲（测试隔离；写指针归零）。
func resetRingForTest() {
	ringInitOnce()
	for i := range shards {
		shards[i].mu.Lock()
		shards[i].count = 0
		for j := range shards[i].slots {
			shards[i].slots[j] = RequestRecord{}
		}
		shards[i].mu.Unlock()
	}
	writeIdx.Store(0)
}

// 目标形状：limit=N 只取最新 N 条（top-N 选择，不做全量排序）；
// 结果与「全量快照截尾」完全一致（最新优先契约不变）。
func TestSnapshotTopN_matchesFullSnapshotPrefix(t *testing.T) {
	resetRingForTest()
	const n = 200
	for i := range n {
		Record(RequestRecord{Ts: int64(1000 + i), URI: "/r" + itoa(i)})
	}
	for _, limit := range []int{1, 5, 50, n} {
		top := SnapshotTopN(limit)
		full := Snapshot()
		if len(top) != limit {
			t.Fatalf("limit=%d len=%d, want %d", limit, len(top), limit)
		}
		for i := range top {
			if top[i] != full[i] {
				t.Fatalf("limit=%d index=%d: top=%+v full=%+v (must equal full-snapshot prefix)", limit, i, top[i], full[i])
			}
		}
	}
}

// 边界形状：limit 覆盖空缓冲/未写满/超容量/非法值。
func TestSnapshotTopN_boundaryShapes(t *testing.T) {
	resetRingForTest()
	if got := SnapshotTopN(10); len(got) != 0 {
		t.Fatalf("empty ring: len=%d, want 0", len(got))
	}
	for i := range 7 {
		Record(RequestRecord{Ts: int64(i), URI: "/x"})
	}
	if got := SnapshotTopN(100); len(got) != 7 {
		t.Fatalf("partially filled ring: len=%d, want 7 (all written records)", len(got))
	}
	for i := range 7 {
		if got := SnapshotTopN(100); got[i].Ts != int64(6-i) {
			t.Fatalf("newest-first broken at %d: %+v", i, got)
		}
	}
	for _, limit := range []int{0, -3} {
		if got := SnapshotTopN(limit); got != nil {
			t.Fatalf("limit=%d must return nil (caller falls back to full snapshot), got %d entries", limit, len(got))
		}
	}
}

// 回归形状：写满覆盖后 top-N 仍是全局最新 N 条（跨分片、含覆盖）。
func TestSnapshotTopN_afterWraparound(t *testing.T) {
	resetRingForTest()
	const total = RingCapacity + 1234
	for i := range total {
		Record(RequestRecord{Ts: int64(i), URI: "/w"})
	}
	const limit = 64
	top := SnapshotTopN(limit)
	if len(top) != limit {
		t.Fatalf("len=%d, want %d", len(top), limit)
	}
	for i := range top {
		want := int64(total - 1 - i)
		if top[i].Ts != want {
			t.Fatalf("index=%d Ts=%d, want %d (global newest after wraparound)", i, top[i].Ts, want)
		}
	}
}

// 并发形状：写侧持续写入时 top-N 读不竞争、结果条数正确（-race）。
func TestSnapshotTopN_concurrentWrites(t *testing.T) {
	resetRingForTest()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := range 4 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				Record(RequestRecord{Ts: int64(g*1000000 + i), URI: "/c"})
			}
		}(g)
	}
	for range 20 {
		top := SnapshotTopN(32)
		if len(top) > 32 {
			t.Fatalf("len=%d exceeds limit", len(top))
		}
		for i := 1; i < len(top); i++ {
			if top[i-1].Ts < top[i].Ts {
				t.Fatalf("newest-first violated: %d < %d", top[i-1].Ts, top[i].Ts)
			}
		}
	}
	close(stop)
	wg.Wait()
}

// admin 端点 limit=N 契约：返回最新 N 条 + capacity 字段不变。
func TestServeReqMonSnapshot_limitReturnsNewestN(t *testing.T) {
	resetRingForTest()
	const n = 300
	for i := range n {
		Record(RequestRecord{Ts: int64(5000 + i), URI: "/a" + itoa(i)})
	}
	req := httptest.NewRequest(http.MethodGet, "/lb/reqmon/snapshot?limit=25", nil)
	rec := httptest.NewRecorder()
	if err := serveReqMonSnapshot(rec, req); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var payload struct {
		Capacity int             `json:"capacity"`
		Entries  []RequestRecord `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Capacity != RingCapacity {
		t.Fatalf("capacity=%d, want %d", payload.Capacity, RingCapacity)
	}
	if len(payload.Entries) != 25 {
		t.Fatalf("entries=%d, want 25", len(payload.Entries))
	}
	for i := range payload.Entries {
		want := int64(5000 + n - 1 - i)
		if payload.Entries[i].Ts != want {
			t.Fatalf("entry %d Ts=%d, want %d (newest first)", i, payload.Entries[i].Ts, want)
		}
	}
}

// 回归形状：无 limit/非法 limit 走全量快照（既有契约不变）。
func TestServeReqMonSnapshot_noLimitFullSnapshot(t *testing.T) {
	resetRingForTest()
	for i := range 12 {
		Record(RequestRecord{Ts: int64(i), URI: "/f"})
	}
	for _, q := range []string{"", "?limit=0", "?limit=-1", "?limit=abc", "?limit=999999"} {
		req := httptest.NewRequest(http.MethodGet, "/lb/reqmon/snapshot"+q, nil)
		rec := httptest.NewRecorder()
		if err := serveReqMonSnapshot(rec, req); err != nil {
			t.Fatalf("serve %q: %v", q, err)
		}
		var payload struct {
			Entries []RequestRecord `json:"entries"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode %q: %v", q, err)
		}
		if len(payload.Entries) != 12 {
			t.Fatalf("query %q entries=%d, want full 12", q, len(payload.Entries))
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
