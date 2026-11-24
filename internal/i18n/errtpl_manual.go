package i18n

// 手工补充错误模板（非 codemod 产物）：errtpl_gen.go 带 "Code generated" 标记
// 不可手改，仓库内也没有可重跑的 errtpl 生成器——生成面之外新增的服务层错误
// 模板在此登记（与 catalog_manual.go 之于 catalog_gen.go 同构）。zh 母本 +
// en 译文成对；RegisterErrTpl 自带去重与按字面量具体度排序。

func init() {
	// 认证网关地址携带用户名/密码凭据的写侧拒绝
	// （services.ErrForwardAuthGatewayCredentials 经 rule_features.go 包成
	// 「认证网关地址无效: %w」后由 apimsg.ErrMsg 按完整消息前缀翻译）。
	RegisterErrTpl("认证网关地址无效: 认证网关地址不能包含用户名/密码凭据（地址只承载 host:port；网关鉴权请在网关侧配置）: %s", "Invalid authentication gateway address: the authentication gateway address must not contain username/password credentials (the address carries host:port only; configure gateway authentication on the gateway side): %s")
}
