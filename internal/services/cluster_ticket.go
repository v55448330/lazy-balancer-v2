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
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// ErrNodeOffline 表示目标节点已审批但当前不可达（从未上报或已超过在线阈值）：
// 与「节点不存在/未审批」（ErrNodeNotFound → 404）区分开，handler 映射 409
// 并给出「确认从节点在线后重试」的可行动文案。
var ErrNodeOffline = errors.New("节点尚未上报或已离线")

// ErrNodeTokenPending 表示目标节点已批准、但集群令牌尚未交付：批准路径把
// cluster_token_hash 置 NULL，哈希只在从节点轮询注册状态后才回写。此时节点
// 存在且已被信任，只是还没有可用于签发票据的密钥——与「节点不存在/未审批」
// （ErrNodeNotFound → 404）必须区分，否则排障方会去查节点是否被删除；与
// 「已离线」（ErrNodeOffline）区分：tokenless 节点的 last_seen 恒空，文案应
// 指向「等待从节点完成令牌交付」而不是「确认从节点在线」。
var ErrNodeTokenPending = errors.New("节点已批准但尚未完成令牌交付（等待从节点上报注册状态后重试）")

var (
	ErrInvalidLoginTicket         = errors.New("登录票据无效或已过期")
	ErrLoginTicketSignature       = errors.New("登录票据签名错误")
	ErrLoginTicketExpired         = errors.New("登录票据已过期")
	ErrLoginTicketReplay          = errors.New("登录票据已使用")
	ErrLoginTicketUserUnavailable = errors.New("登录票据用户不存在或已禁用")
)

// clusterTicketVerify 是集群一次性票据的验签结果分类：登录票据
// 与服务控制票据共用同一 HMAC/base64 实现，调用方只按分类映射各自哨兵
// （两者错误文案不同，不能合并成同一 error）。
type clusterTicketVerify uint8

const (
	clusterTicketOK        clusterTicketVerify = iota
	clusterTicketMalformed                     // 结构/载荷不可解析
	clusterTicketSignature                     // HMAC 不匹配
)

// signClusterTicket 把 claims 编码为 "b64(payload).b64(HMAC-SHA256)"。
// 登录票据与服务控制票据的唯一签发实现（此前两份逐字重复，安全细节单点收敛）。
func signClusterTicket(claims any, key []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encodedPayload))
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyClusterTicket 拆分并用 key 验签（常数时间比较），返回载荷与分类。
func verifyClusterTicket(ticket string, key []byte) ([]byte, clusterTicketVerify) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return nil, clusterTicketMalformed
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, clusterTicketSignature
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, clusterTicketSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, clusterTicketMalformed
	}
	return payload, clusterTicketOK
}

// consumeClusterTicketJTI 在调用方事务内一次性消费票据（清理过期记录 +
// jti 去重插入）；返回 false 表示重放。事务提交由调用方负责，DB 错误不消耗
// 票据——登录票据与服务控制票据的唯一消费实现。
func consumeClusterTicketJTI(ctx context.Context, tx *sql.Tx, jti string, now, expiresAt time.Time) (bool, error) {
	if _, err := tx.ExecContext(ctx, "DELETE FROM used_login_tickets WHERE expires_at<=?", now); err != nil {
		return false, err
	}
	jtiHash := sha256.Sum256([]byte(jti))
	result, err := tx.ExecContext(ctx, `INSERT INTO used_login_tickets (jti_hash,expires_at) VALUES (?,?) ON CONFLICT(jti_hash) DO NOTHING`, hex.EncodeToString(jtiHash[:]), expiresAt)
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return inserted == 1, nil
}

func (s *ClusterService) GenerateLoginTicket(ctx context.Context, claims models.ClusterLoginTicketClaims, now time.Time) (models.ClusterLoginTicketResponse, error) {
	var ipAddress, protocol, accessURL, keyHash, nodeName string
	var port int
	var lastSeen sql.NullTime
	var approved bool
	// name 一并取出:审计事件需带节点名(与服务控制事件「节点 %d（%s）」同格式)。
	if err := s.db.QueryRowContext(ctx, `SELECT ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),COALESCE(cluster_token_hash,''),COALESCE(name,''),last_seen,is_approved FROM nodes WHERE id=? AND `+masterRoleConditionSQL, claims.NodeID).
		Scan(&ipAddress, &port, &protocol, &accessURL, &keyHash, &nodeName, &lastSeen, &approved); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ClusterLoginTicketResponse{}, s.nodeWriteMissError(ctx)
		}
		return models.ClusterLoginTicketResponse{}, fmt.Errorf("读取登录目标节点: %w", err)
	}
	// 在线判定改动态口径（与 Nodes()/ComputeNodeStatus 一致）——nodes.status
	// 只在注册/上报时写入、从不回写 'offline'，按陈旧 status 列判定会把已停止
	// 上报的从节点仍当作在线放行签发登录票据。sync_interval 同款读取（含脏值
	// clamp，由 ComputeNodeStatus 内部归一）。
	var syncInterval int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&syncInterval); err != nil {
		return models.ClusterLoginTicketResponse{}, fmt.Errorf("读取同步间隔: %w", err)
	}
	if !approved {
		return models.ClusterLoginTicketResponse{}, ErrNodeNotFound
	}
	if keyHash == "" {
		// 已批准但令牌待交付：与「不存在」（404）区分，见 ErrNodeTokenPending。
		return models.ClusterLoginTicketResponse{}, ErrNodeTokenPending
	}
	// 已批准但从未上报/已离线与「节点不存在
	// 或未审批」是两类问题——前者 handler 映射 409 + 「确认从节点在线后重试」，
	// 后者维持 404。keyHash 为空（从未取得集群令牌）仍按不存在处理。
	if ComputeNodeStatus(approved, lastSeen.Time, syncInterval, now) != "online" {
		return models.ClusterLoginTicketResponse{}, ErrNodeOffline
	}
	key, err := hex.DecodeString(keyHash)
	if err != nil || len(key) != sha256.Size {
		return models.ClusterLoginTicketResponse{}, fmt.Errorf("节点集群凭证无效")
	}
	jti, err := randomHex(32)
	if err != nil {
		return models.ClusterLoginTicketResponse{}, err
	}
	claims.JTI = jti
	// 签发侧预留时钟偏移（60s→90s）：从节点按自身时钟校验，两侧偏差超过
	// 一分钟时票据恒被拒且无重试窗口。校验侧语义不变。
	claims.ExpiresAt = now.UTC().Add(90 * time.Second).Unix()
	ticket, err := signClusterTicket(claims, key)
	if err != nil {
		return models.ClusterLoginTicketResponse{}, fmt.Errorf("编码登录票据: %w", err)
	}
	accessURL = resolveNodeAccessURL(ipAddress, port, protocol, accessURL)
	return models.ClusterLoginTicketResponse{Ticket: ticket, URL: accessURL, NodeName: nodeName}, nil
}

// 票据登录刻意不检查从节点本地
// login_locked_until——该列是从节点自身密码登录端点的暴破防护记账
// 本地写入、不随快照同步），而本路径不含任何口令猜测面：票据由主节点在
// 完整认证（本地用户强制 MFA 步进验证/OIDC 会话经 IdP 二因子）后签发，
// 票据本身即主端 MFA 事实；一次性消费（jti 入 used_login_tickets）+90s
// TTL+HMAC 绑定节点，重查本地锁对暴破防护无增量，反而会让主端合法跳转
// 被从节点残留的本地锁误拦。
func (s *ClusterService) ValidateLoginTicket(ctx context.Context, ticket string, now time.Time) (models.ClusterLoginTicketClaims, models.User, int64, error) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, ErrInvalidLoginTicket
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("开始登录票据事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var isMaster bool
	var clusterToken string
	var registrationID int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(is_master,1),COALESCE(cluster_token,''),COALESCE(registration_id,0) FROM global_config WHERE id=1`).Scan(&isMaster, &clusterToken, &registrationID); err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("读取从节点凭证: %w", err)
	}
	if isMaster || clusterToken == "" {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, ErrInvalidLoginTicket
	}
	key := sha256.Sum256([]byte(clusterToken))
	payload, verify := verifyClusterTicket(ticket, key[:])
	switch verify {
	case clusterTicketSignature:
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketSignature)
	case clusterTicketMalformed:
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, ErrInvalidLoginTicket
	}
	var claims models.ClusterLoginTicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.UserID <= 0 || claims.Username == "" || claims.JTI == "" || claims.NodeID != registrationID {
		return claims, models.User{}, 0, ErrInvalidLoginTicket
	}
	// 以下全部失败分支的 claims 均已通过 HMAC 验签（主体身份可信），
	// 必须随错误返回——此前一律返回零值，票据登录失败审计的 actor 恒为空，
	// 「谁的票据被重放/过期」这两类最需取证的票据事件无法归因。未验签分支
	// （上方签名/载荷解析失败）保持零值，不得凭空归因。
	if claims.ExpiresAt <= now.UTC().Unix() {
		return claims, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketExpired)
	}
	var meta db.UserRowMeta
	// 用户列清单单源（含 is_setup_admin）——票据登录是与密码登录并列的
	// UserResponse 产出路径，漏列会让从节点会话把 break-glass 管理员显示成
	// 普通管理员。
	user, err := db.ScanUserRow(tx.QueryRowContext(ctx, `SELECT `+db.UserRowColumns("")+` FROM users WHERE id=?`, claims.UserID), &meta)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!user.IsEnabled || user.Username != claims.Username) {
		return claims, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketUserUnavailable)
	}
	if err != nil {
		return claims, models.User{}, 0, fmt.Errorf("读取登录票据用户: %w", err)
	}
	consumed, err := consumeClusterTicketJTI(ctx, tx, claims.JTI, now.UTC(), time.Unix(claims.ExpiresAt, 0).UTC())
	if err != nil {
		return claims, models.User{}, 0, fmt.Errorf("消费登录票据: %w", err)
	}
	if !consumed {
		return claims, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketReplay)
	}
	if err := tx.Commit(); err != nil {
		return claims, models.User{}, 0, fmt.Errorf("提交登录票据消费: %w", err)
	}
	return claims, user, meta.PasswordVersion, nil
}
