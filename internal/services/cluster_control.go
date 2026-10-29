package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/netutil"
)

// 服务控制票据错误哨兵。前两个是调用方面向外部的分类依据：
// ErrInvalidServiceControlTicket 决定从节点端点 401 与主节点「从节点拒绝」中继
// 文案；ErrInvalidServiceAction 决定 400。后三个由 ValidateServiceControlTicket
// errors.Join 在通用哨兵上附细因——生产消费方=从节点端点的审计原因
// （serviceControlTicketFailureReason），供运维区分「票据重放（无需重注册）」与
// 「签名错误（节点凭证不一致）」；同时是测试契约（errors.Is 逐因断言）。
var (
	ErrInvalidServiceAction        = errors.New("不支持的服务控制动作")
	ErrInvalidServiceControlTicket = errors.New("服务控制票据无效或已过期")
	ErrServiceControlSignature     = errors.New("服务控制票据签名错误")
	ErrServiceControlExpired       = errors.New("服务控制票据已过期")
	ErrServiceControlReplay        = errors.New("服务控制票据已使用")
)

// serviceControlTicketTTL 与登录票据同口径：签发侧预留时钟偏移（90s），
// 从节点按自身时钟校验；一次性消费（jti 记入 used_login_tickets）。
const serviceControlTicketTTL = 90 * time.Second

// IssueServiceControlTicket 主节点侧：为目标从节点签发一次性服务控制票据。
// HMAC 密钥取 nodes.cluster_token_hash 的原始字节（= sha256(cluster_token)）——
// 主节点只存哈希即可签发，从节点凭自身 cluster_token 推导同一密钥验签，
// 与登录票据（GenerateLoginTicket）同一机制，无需在主节点落任何明文令牌。
// 不要求节点 status=online：挂死节点恰恰是 restart_app 的恢复对象，
// 可达性由实际 HTTP 调用判定。
func (s *ClusterService) IssueServiceControlTicket(ctx context.Context, nodeID int, action string, now time.Time) (models.ClusterServiceControlIssue, error) {
	if !models.IsValidClusterServiceAction(action) {
		return models.ClusterServiceControlIssue{}, ErrInvalidServiceAction
	}
	var name, ipAddress, protocol, accessURL, keyHash string
	var port int
	var approved bool
	if err := s.db.QueryRowContext(ctx, `SELECT name,ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),COALESCE(cluster_token_hash,''),is_approved FROM nodes WHERE id=? AND `+masterRoleConditionSQL, nodeID).
		Scan(&name, &ipAddress, &port, &protocol, &accessURL, &keyHash, &approved); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 0 行先复核角色：降级竞态（handler 角色门通过后 is_master 翻转）
			// 统一 403 语义，不得落成「节点不存在」404。
			return models.ClusterServiceControlIssue{}, s.masterScopeMissError(ctx, ErrNodeNotFound)
		}
		return models.ClusterServiceControlIssue{}, fmt.Errorf("读取服务控制目标节点: %w", err)
	}
	if !approved {
		// 未审批=不可控，按不存在处理（ErrNodeNotFound→404）：审批边界之前
		// 票据面不泄露该节点的存在性，也不可对其签发能力凭证。与下方「已批准
		// 但令牌待交付→ErrNodeTokenPending(409)」的口径分叉是有意的——409 只
		// 表达「节点身份已确认、集群令牌在途」，审批未完成则连身份都不对外承诺。
		return models.ClusterServiceControlIssue{}, ErrNodeNotFound
	}
	if keyHash == "" {
		// 与登录票据同口径：已批准但令牌待交付 → 409 族，不落成「节点不存在」。
		return models.ClusterServiceControlIssue{}, ErrNodeTokenPending
	}
	key, err := hex.DecodeString(keyHash)
	if err != nil || len(key) != sha256.Size {
		return models.ClusterServiceControlIssue{}, fmt.Errorf("节点集群凭证无效")
	}
	jti, err := randomHex(32)
	if err != nil {
		return models.ClusterServiceControlIssue{}, err
	}
	claims := models.ClusterServiceControlClaims{
		NodeID: nodeID, Action: action, JTI: jti,
		ExpiresAt: now.UTC().Add(serviceControlTicketTTL).Unix(),
	}
	ticket, err := signServiceControlTicket(claims, key)
	if err != nil {
		return models.ClusterServiceControlIssue{}, err
	}
	accessURL = resolveNodeAccessURL(ipAddress, port, protocol, accessURL)
	return models.ClusterServiceControlIssue{Ticket: ticket, NodeName: name, URL: accessURL}, nil
}

// signServiceControlTicket 保留包装（服务控制票据的调用面命名），实现与
// 登录票据共用 signClusterTicket。
func signServiceControlTicket(claims models.ClusterServiceControlClaims, key []byte) (string, error) {
	ticket, err := signClusterTicket(claims, key)
	if err != nil {
		return "", fmt.Errorf("编码服务控制票据: %w", err)
	}
	return ticket, nil
}

// ErrNoClusterPin 表示目标节点在本地没有 TOFU 指纹钉（http 地址或从未对其
// 发起过服务控制），供调用方以幂等语义处理。
var ErrNoClusterPin = errors.New("该节点没有已钉扎的证书指纹")

// NodePinHost 解析单个从节点服务控制 TOFU 指纹钉的定位信息（不删除）：
// 地址口径与 ForgetNodePin 一致（access_url 优先，回退 protocol://ip:port）。
// 供「事务内先解析、提交后按 host 删除」的延迟清理形态使用（备份导入删除
// 节点：地址解析需现存行，而删除必须等事务提交）。
func (s *ClusterService) NodePinHost(ctx context.Context, nodeID int) (string, error) {
	var ipAddress, protocol, accessURL string
	var port int
	if err := s.db.QueryRowContext(ctx, `SELECT ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,'') FROM nodes WHERE id=? AND `+masterRoleConditionSQL, nodeID).
		Scan(&ipAddress, &port, &protocol, &accessURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// SQL 级角色条件（同族 TOCTOU 唯一漏点）——0 行时复核
			// 角色：降级窗口返回 403 哨兵，而不是继续主节点目录下的 pin 操作。
			return "", s.nodeWriteMissError(ctx)
		}
		return "", fmt.Errorf("读取节点访问地址: %w", err)
	}
	accessURL = resolveNodeAccessURL(ipAddress, port, protocol, accessURL)
	_, host, err := nodePinPathFromAccessURL(s.dataDir, s.db, accessURL)
	if err != nil {
		return "", err
	}
	return host, nil
}

// ForgetNodePinHost 按 host:port 删除主节点侧的 pin 文件（幂等：不存在返回
// ErrNoClusterPin）。与 NodePinHost 成对，pin 目录/命名单源 clusterPinPath。
func (s *ClusterService) ForgetNodePinHost(host string) error {
	pinPath, err := clusterPinPath(s.dataDir, s.db, host)
	if err != nil {
		return err
	}
	if err := os.Remove(pinPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNoClusterPin
		}
		return fmt.Errorf("删除节点证书指纹: %w", err)
	}
	return nil
}

// ForgetNodePin 删除主节点侧针对单个从节点的服务控制 TOFU 指纹钉（与
// 从节点侧 forget-pins 端点对称）：从节点更换管理面板证书后主节点对其服务控制
// 持续 PinMismatch，本方法按 IssueServiceControlTicket 同一口径（access_url
// 优先，回退 protocol://ip:port）推导地址并定位 cluster_ca_pins 下的 pin 文件，
// 只删除该节点的钉。返回定位到的 host:port 供审计与内存缓存失效使用。
func (s *ClusterService) ForgetNodePin(ctx context.Context, nodeID int) (string, error) {
	host, err := s.NodePinHost(ctx, nodeID)
	if err != nil {
		return "", err
	}
	if err := s.ForgetNodePinHost(host); err != nil {
		return "", err
	}
	return host, nil
}

// ValidateServiceControlTicket 从节点侧：验签 + 过期 + 节点归属 + 动作绑定 +
// 原子消费（与登录票据 ValidateLoginTicket 同一事务形态：DB 错误不消耗票据）。
func (s *ClusterService) ValidateServiceControlTicket(ctx context.Context, ticket, action string, now time.Time) error {
	if !models.IsValidClusterServiceAction(action) {
		return ErrInvalidServiceControlTicket
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return ErrInvalidServiceControlTicket
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始服务控制票据事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 角色走 db.IsMasterNode（单源谓词 + 接受 *sql.Tx），凭证在同一事务内另读。
	isMaster, err := db.IsMasterNode(ctx, tx)
	if err != nil {
		return fmt.Errorf("读取从节点凭证: %w", err)
	}
	var clusterToken string
	var registrationID int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(cluster_token,''),COALESCE(registration_id,0) FROM global_config WHERE id=1`).Scan(&clusterToken, &registrationID); err != nil {
		return fmt.Errorf("读取从节点凭证: %w", err)
	}
	if isMaster || clusterToken == "" {
		return ErrInvalidServiceControlTicket
	}
	key := sha256.Sum256([]byte(clusterToken))
	payload, verify := verifyClusterTicket(ticket, key[:])
	switch verify {
	case clusterTicketSignature:
		return errors.Join(ErrInvalidServiceControlTicket, ErrServiceControlSignature)
	case clusterTicketMalformed:
		return ErrInvalidServiceControlTicket
	}
	var claims models.ClusterServiceControlClaims
	// 票据与请求动作绑定（防动作替换）且必须发给本节点（防跨节点重定向）。
	if err := json.Unmarshal(payload, &claims); err != nil || claims.NodeID <= 0 || claims.JTI == "" || claims.Action != action || claims.NodeID != registrationID {
		return ErrInvalidServiceControlTicket
	}
	if claims.ExpiresAt <= now.UTC().Unix() {
		return errors.Join(ErrInvalidServiceControlTicket, ErrServiceControlExpired)
	}
	consumed, err := consumeClusterTicketJTI(ctx, tx, claims.JTI, now.UTC(), time.Unix(claims.ExpiresAt, 0).UTC())
	if err != nil {
		return fmt.Errorf("消费服务控制票据: %w", err)
	}
	if !consumed {
		return errors.Join(ErrInvalidServiceControlTicket, ErrServiceControlReplay)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交服务控制票据消费: %w", err)
	}
	return nil
}

// NewClusterControlHTTPClient 主节点→从节点服务控制调用的 HTTP 客户端：
// 复用集群同步的 TOFU 指纹校验 transport（自签从节点管理面板可握手，
// 中间人替换证书在第二次连接起被 pinned 指纹拒绝）。
func NewClusterControlHTTPClient(dataDir string, database *sql.DB) *http.Client {
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: newClusterTOFUTransport(dataDir, database, nil),
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// DoWithSameHostTLSUpgradeRedirect 处理同主机 http→https 301/302/307/308：节点启用管理 HTTPS 后
// 明文端口整体 301/302（TCP 嗅探层，早于路由），而集群各客户端
// CheckRedirect=ErrUseLastResponse 会让调用方拿到空 body 走 JSON 解析且无自愈
// 路径（2026-09-18 实测）。仅当 Location 与原请求**同主机名**且升级为 https
// 时按原方法重放一次（凭证不出原主机）；跨主机重定向一律不跟随（凭证外泄
// 防护）。消费方：脱离通知（cluster.go
// notifyMasterDetach）与服务控制调用（handlers callClusterServiceControl）。
// 客户端必须设置 CheckRedirect=ErrUseLastResponse，否则 301/302/307/308 被标准库先行
// 跟随（POST 可能被改写为 GET）而本函数永远看不到升级信号。
func DoWithSameHostTLSUpgradeRedirect(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if !netutil.IsTLSUpgradeRedirect(resp.StatusCode) {
		// 非升级信号直接返回。
		return resp, nil
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return resp, nil
	}
	target, err := url.Parse(location)
	// 主机名比较不区分大小写：url.URL.Hostname() 原样保留书写形态，
	// 主节点地址填 https://Master.Example 而明文端口回 https://master.example
	// 时字符串比较会让升级重放永远不触发（调用方拿到空 body 走重定向指引）。
	// 端口变化隐含允许（明文端口 80→443 是升级的常规形态）。
	if err != nil || target.Scheme != "https" || !strings.EqualFold(target.Hostname(), req.URL.Hostname()) {
		return resp, nil
	}
	resp.Body.Close()
	retry := req.Clone(req.Context())
	// Location 只带主机（`https://host`，不带 path）是反代/管理面 HTTPS 升级的
	// 常见形态：直接赋值会让标准库把空 Path 规范化成 `/`，重放打到根路径得到
	// 404/HTML，调用方只能报「解析响应失败」，既有可行动 3xx 指引分支永远走不到。
	// 空 path 必须继承原请求路径（RawPath 同步继承，保持转义形态）。
	if target.Path == "" {
		target.Path = req.URL.Path
		target.RawPath = req.URL.RawPath
	}
	// Location 携带 userinfo 时不得以 URL Basic 认证外发：目标主机虽相同，
	// 但凭证由对端 Location 注入，清零后重放只带原请求头。
	target.User = nil
	retry.URL = target
	if target.RawQuery == "" && req.URL.RawQuery != "" {
		retry.URL.RawQuery = req.URL.RawQuery
	}
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("重放 https 升级请求: %w", err)
		}
		retry.Body = body
	} else if req.Body != nil {
		// 无 GetBody 的带体请求不可重放(body 已被首次请求消费,
		// 重放会发送空/残缺载荷)——原实现返回已 Close 的 resp(调用方读 body
		// 报错),合并后取 cluster_sync 方法版语义:返回合成空壳 301 响应。
		return &http.Response{
			StatusCode: http.StatusMovedPermanently,
			Status:     "301 Moved Permanently",
			Header:     resp.Header.Clone(),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}
	return client.Do(retry)
}
