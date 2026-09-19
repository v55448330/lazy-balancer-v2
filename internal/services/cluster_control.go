package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/models"
)

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
	if err := s.db.QueryRowContext(ctx, `SELECT name,ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),COALESCE(cluster_token_hash,''),is_approved FROM nodes WHERE id=?`, nodeID).
		Scan(&name, &ipAddress, &port, &protocol, &accessURL, &keyHash, &approved); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ClusterServiceControlIssue{}, ErrNodeNotFound
		}
		return models.ClusterServiceControlIssue{}, fmt.Errorf("读取服务控制目标节点: %w", err)
	}
	if !approved || keyHash == "" {
		return models.ClusterServiceControlIssue{}, ErrNodeNotFound
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
	if protocol != "https" {
		protocol = "http"
	}
	if accessURL == "" {
		accessURL = protocol + "://" + net.JoinHostPort(ipAddress, strconv.Itoa(port))
	}
	return models.ClusterServiceControlIssue{Ticket: ticket, NodeName: name, URL: accessURL}, nil
}

func signServiceControlTicket(claims models.ClusterServiceControlClaims, key []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("编码服务控制票据: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encodedPayload))
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ErrNoClusterPin 表示目标节点在本地没有 TOFU 指纹钉（http 地址或从未对其
// 发起过服务控制），供调用方以幂等语义处理。
var ErrNoClusterPin = errors.New("该节点没有已钉扎的证书指纹")

// ForgetNodePin 删除主节点侧针对单个从节点的服务控制 TOFU 指纹钉（C-3，与
// 从节点侧 forget-pins 端点对称）：从节点更换管理面板证书后主节点对其服务控制
// 持续 PinMismatch，本方法按 IssueServiceControlTicket 同一口径（access_url
// 优先，回退 protocol://ip:port）推导地址并定位 cluster_ca_pins 下的 pin 文件，
// 只删除该节点的钉。返回定位到的 host:port 供审计与内存缓存失效使用。
func (s *ClusterService) ForgetNodePin(ctx context.Context, nodeID int) (string, error) {
	var ipAddress, protocol, accessURL string
	var port int
	if err := s.db.QueryRowContext(ctx, `SELECT ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,'') FROM nodes WHERE id=?`, nodeID).
		Scan(&ipAddress, &port, &protocol, &accessURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNodeNotFound
		}
		return "", fmt.Errorf("读取节点访问地址: %w", err)
	}
	if protocol != "https" {
		protocol = "http"
	}
	if accessURL == "" {
		accessURL = protocol + "://" + net.JoinHostPort(ipAddress, strconv.Itoa(port))
	}
	parsed, err := url.Parse(accessURL)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("节点访问地址无效: %q", accessURL)
	}
	pinPath, err := clusterPinPathForDatabase(s.db, parsed.Host)
	if err != nil {
		return "", err
	}
	if err := os.Remove(pinPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNoClusterPin
		}
		return "", fmt.Errorf("删除节点证书指纹: %w", err)
	}
	return parsed.Host, nil
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
	var isMaster bool
	var clusterToken string
	var registrationID int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(is_master,1),COALESCE(cluster_token,''),COALESCE(registration_id,0) FROM global_config WHERE id=1`).Scan(&isMaster, &clusterToken, &registrationID); err != nil {
		return fmt.Errorf("读取从节点凭证: %w", err)
	}
	if isMaster || clusterToken == "" {
		return ErrInvalidServiceControlTicket
	}
	key := sha256.Sum256([]byte(clusterToken))
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.Join(ErrInvalidServiceControlTicket, ErrServiceControlSignature)
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return errors.Join(ErrInvalidServiceControlTicket, ErrServiceControlSignature)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM used_login_tickets WHERE expires_at<=?", now.UTC()); err != nil {
		return fmt.Errorf("清理过期服务控制票据: %w", err)
	}
	jtiHash := sha256.Sum256([]byte(claims.JTI))
	result, err := tx.ExecContext(ctx, `INSERT INTO used_login_tickets (jti_hash,expires_at) VALUES (?,?) ON CONFLICT(jti_hash) DO NOTHING`, hex.EncodeToString(jtiHash[:]), time.Unix(claims.ExpiresAt, 0).UTC())
	if err != nil {
		return fmt.Errorf("消费服务控制票据: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取服务控制票据消费结果: %w", err)
	}
	if inserted != 1 {
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

// DoWithSameHostTLSUpgradeRedirect 处理同主机 http→https 301/308，与集群同步
// （cluster_sync.go doWithTLSUpgradeRedirect）同一契约：节点启用管理 HTTPS 后
// 明文端口整体 301（TCP 嗅探层，早于路由），而集群各客户端
// CheckRedirect=ErrUseLastResponse 会让调用方拿到空 body 走 JSON 解析且无自愈
// 路径（2026-09-18 实测）。仅当 Location 与原请求**同主机名**且升级为 https
// 时按原方法重放一次（凭证不出原主机）；跨主机重定向一律不跟随（凭证外泄
// 防护）。CL42-2（第 42 轮审计）消费方：脱离通知（cluster.go
// notifyMasterDetach）与服务控制调用（handlers callClusterServiceControl）。
// 客户端必须设置 CheckRedirect=ErrUseLastResponse，否则 301 被标准库先行
// 跟随（POST 会被改写为 GET）而本函数永远看不到升级信号。
func DoWithSameHostTLSUpgradeRedirect(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusPermanentRedirect {
		return resp, nil
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return resp, nil
	}
	target, err := url.Parse(location)
	if err != nil || target.Scheme != "https" || target.Hostname() != req.URL.Hostname() {
		return resp, nil
	}
	resp.Body.Close()
	retry := req.Clone(req.Context())
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
	}
	return client.Do(retry)
}
