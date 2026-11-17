package i18n

// 手工补充词条（非 codemod 产物）：后端响应注记键，zh 母本 + en 译文。
// catalog_gen.go 由 gencatalog 从 JSON 生成不可手改；新增后端词条在此登记，
// 键 = FNV1a(zh)（与 codemod key_of 同算法）。

func init() {
	// IPv6 地理库开关退化提交注记（200 + 重载失败详情槽）。
	Register("k_7d87740a", "已保存，但重载 Caddy 配置失败（待下次成功重载生效）: %s", "Saved, but reloading the Caddy config failed (takes effect on the next successful reload): %s")
	// IPv6 地理库开关写失败 5xx 固定文案（DB 细节由服务层 error 日志留痕）。
	Register("k_6a9699ed", "保存 IPv6 开关失败", "Failed to save the IPv6 toggle")
	// 从节点服务控制执行失败 5xx 固定文案（票据凭证端点，底层错误只进审计+日志）。
	Register("k_37dad086", "服务控制执行失败", "Service control execution failed")
}
