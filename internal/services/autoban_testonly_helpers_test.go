package services

import "time"

// autobanObserveEvent / autobanObserveEventScoped 是**测试缝**（同包测试专用）：
// 生产摄取只走 autobanObserveBatch（每批一次配置读取，整份 cfg 下传到
// autobanObserveEventScopedAt）。这两个入口按「每事件直读配置」驱动单事件计数
// 行为，属已优化掉的旧热路径形态——留在生产文件里会让符号表多出无调用入口，
// 误复用即把逐事件 SELECT 拉回主链。故宿主必须是 *_test.go（编译进测试二进制，
// 不进产品符号表），并由 testonly_symbols_test.go 的绊线清单登记防回迁。
func autobanObserveEvent(ip, action, ruleTriggered string) {
	if !autobanIsMaster() || ruleTriggered == "" {
		return
	}
	cfg, err := GetAutobanConfig()
	if err != nil || !cfg.Enabled {
		return
	}
	autobanObserveEventScoped(cfg, ip, action, ruleTriggered)
}

func autobanObserveEventScoped(cfg AutobanConfig, ip, action, ruleTriggered string) {
	autobanObserveEventScopedAt(cfg, ip, action, ruleTriggered, time.Time{})
}
