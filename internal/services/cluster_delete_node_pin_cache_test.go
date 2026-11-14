package services

// DeleteNode 删除节点伴随的 pin 清理必须同时失效内存指纹缓存（与
// ForgetNodePin handler 的 ForgetNodePinCache 收尾对称）：磁盘 pin 已删而
// 内存 verifiedPins 残留旧指纹时，本节点曾作为从节点时代的旧指纹继续参与
// 复核，内存/磁盘 TOFU 生命周期分叉。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/config"
)

func TestClusterService_DeleteNode_invalidatesMemoryPinCache(t *testing.T) {
	// Given：一个带 pin 文件与内存指纹缓存的从节点
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,is_approved)
		VALUES (21,'slave-a','172.18.0.2',8000,'http','https://node-a.example:8443',1)`); err != nil {
		t.Fatal(err)
	}
	sync := NewSyncService(database, &config.Config{}, nil)
	t.Cleanup(func() { unregisterSyncDrainer(sync) })
	host := "node-a.example:8443"
	pinPath, err := clusterPinPath("", database, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(pinPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("sha256-fingerprint\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sync.pinMu.Lock()
	sync.verifiedPins[pinPath] = "sha256-fingerprint"
	sync.pinMu.Unlock()

	// When：删除节点
	if err := cluster.DeleteNode(context.Background(), 21); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	// Then：磁盘 pin 与内存缓存条目都已清除
	if _, err := os.Stat(pinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("磁盘 pin 未删除: %v", err)
	}
	sync.pinMu.Lock()
	_, cached := sync.verifiedPins[pinPath]
	sync.pinMu.Unlock()
	if cached {
		t.Fatal("内存指纹缓存残留被删节点的旧指纹（内存/磁盘生命周期分叉）")
	}
}
