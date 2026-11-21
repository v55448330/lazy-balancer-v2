package notify

import (
	"fmt"
	"net"
	"strconv"
	"sync"
)

// ── 节点标签与级别汉化（用户裁定 2026-11-22 第三轮）──
// 事件节点标识不再只显示注册名（"slave-test"分不清是谁）：
//   - 主节点本地事件 → 「主节点(ip:port)」
//   - 从节点转发事件 → 「从节点 name(ip:port)」（以 nodes 表认证行为准）
// 消息级别（critical/warn/info）是内部枚举，展示面一律渲染中文
// （严重/警告/信息）——中文消息里不再出现英文级别词。

// levelLabelZh 级别枚举 → 中文展示词（单源；未知值原样透出便于排查）。
func levelLabelZh(level string) string {
	switch level {
	case "critical":
		return "严重"
	case "warn":
		return "警告"
	case "info":
		return "信息"
	}
	return level
}

// masterLabel 主节点标签（进程装配时经 SetMasterNodeLabel 注入；未注入回退
// 「主节点(本机)」——测试与无网络环境稳定）。
var masterLabel struct {
	mu    sync.RWMutex
	value string
}

// SetMasterNodeLabel 装配主节点标签（main 启动期调用一次）。
func SetMasterNodeLabel(label string) {
	masterLabel.mu.Lock()
	masterLabel.value = label
	masterLabel.mu.Unlock()
}

// MasterNodeLabel 读取主节点标签。
func MasterNodeLabel() string {
	masterLabel.mu.RLock()
	defer masterLabel.mu.RUnlock()
	if masterLabel.value == "" {
		return "主节点(本机)"
	}
	return masterLabel.value
}

// MasterPanelAddress 探测本机出站 IPv4 + 面板端口 → 「ip:port」（UDP dial
// 不发包，无网络环境返回错误由调用方回退）。port 为面板监听端口。
func MasterPanelAddress(port int) (string, error) {
	conn, err := net.Dial("udp", "223.5.5.5:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil || addr.IP.IsUnspecified() {
		return "", fmt.Errorf("出站地址不可解析")
	}
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(port)), nil
}

// BuildMasterNodeLabel 主节点标签装配单源（探测失败回退主机名）。
func BuildMasterNodeLabel(hostname string, port int) string {
	if addr, err := MasterPanelAddress(port); err == nil {
		return "主节点(" + addr + ")"
	}
	if hostname != "" {
		return "主节点(" + hostname + ")"
	}
	return "主节点(本机)"
}

// SlaveNodeLabel 从节点标签：name 来自 nodes 表认证行（防伪造），ip:port
// 取注册上报地址；地址缺失时退化为「从节点 name」。
func SlaveNodeLabel(name, ip string, port int) string {
	label := "从节点 " + name
	if ip != "" && port > 0 {
		label += "(" + net.JoinHostPort(ip, strconv.Itoa(port)) + ")"
	} else if ip != "" {
		label += "(" + ip + ")"
	}
	return label
}
