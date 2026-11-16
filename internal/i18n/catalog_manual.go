package i18n

// 手工补充词条（非 codemod 产物）：后端响应注记键，zh 母本 + en 译文。
// catalog_gen.go 由 gencatalog 从 JSON 生成不可手改；新增后端词条在此登记，
// 键 = FNV1a(zh)（与 codemod key_of 同算法）。

func init() {
	// IPv6 地理库开关退化提交注记（200 + 重载失败详情槽）。
	Register("k_7d87740a", "已保存，但重载 Caddy 配置失败（待下次成功重载生效）: %s", "Saved, but reloading the Caddy config failed (takes effect on the next successful reload): %s")
}
