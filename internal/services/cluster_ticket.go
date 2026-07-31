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
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/models"
)

var (
	ErrInvalidLoginTicket         = errors.New("登录票据无效或已过期")
	ErrLoginTicketSignature       = errors.New("登录票据签名错误")
	ErrLoginTicketExpired         = errors.New("登录票据已过期")
	ErrLoginTicketReplay          = errors.New("登录票据已使用")
	ErrLoginTicketUserUnavailable = errors.New("登录票据用户不存在或已禁用")
)

func (s *ClusterService) GenerateLoginTicket(ctx context.Context, claims models.ClusterLoginTicketClaims, now time.Time) (models.ClusterLoginTicketResponse, error) {
	var ipAddress, protocol, accessURL, keyHash, status string
	var port int
	var approved bool
	if err := s.db.QueryRowContext(ctx, `SELECT ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),COALESCE(cluster_token_hash,''),status,is_approved FROM nodes WHERE id=?`, claims.NodeID).
		Scan(&ipAddress, &port, &protocol, &accessURL, &keyHash, &status, &approved); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ClusterLoginTicketResponse{}, ErrNodeNotFound
		}
		return models.ClusterLoginTicketResponse{}, fmt.Errorf("读取登录目标节点: %w", err)
	}
	if !approved || status != "online" || keyHash == "" {
		return models.ClusterLoginTicketResponse{}, ErrNodeNotFound
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
	claims.ExpiresAt = now.UTC().Add(time.Minute).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		return models.ClusterLoginTicketResponse{}, fmt.Errorf("编码登录票据: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encodedPayload))
	ticket := encodedPayload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if protocol != "https" {
		protocol = "http"
	}
	if accessURL == "" {
		accessURL = protocol + "://" + net.JoinHostPort(ipAddress, strconv.Itoa(port))
	}
	return models.ClusterLoginTicketResponse{Ticket: ticket, URL: accessURL}, nil
}

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
	if err := tx.QueryRowContext(ctx, `SELECT is_master,COALESCE(cluster_token,''),COALESCE(registration_id,0) FROM global_config WHERE id=1`).Scan(&isMaster, &clusterToken, &registrationID); err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("读取从节点凭证: %w", err)
	}
	if isMaster || clusterToken == "" {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, ErrInvalidLoginTicket
	}
	key := sha256.Sum256([]byte(clusterToken))
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketSignature)
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketSignature)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, ErrInvalidLoginTicket
	}
	var claims models.ClusterLoginTicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.UserID <= 0 || claims.Username == "" || claims.JTI == "" || claims.NodeID != registrationID {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, ErrInvalidLoginTicket
	}
	if claims.ExpiresAt <= now.UTC().Unix() {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketExpired)
	}
	var user models.User
	var passwordVersion int64
	err = tx.QueryRowContext(ctx, `SELECT id,username,role,display_name,is_enabled,created_at,last_login,password_version FROM users WHERE id=?`, claims.UserID).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &passwordVersion)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!user.IsEnabled || user.Username != claims.Username) {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketUserUnavailable)
	}
	if err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("读取登录票据用户: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM used_login_tickets WHERE expires_at<=?", now.UTC()); err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("清理过期登录票据: %w", err)
	}
	jtiHash := sha256.Sum256([]byte(claims.JTI))
	result, err := tx.ExecContext(ctx, `INSERT INTO used_login_tickets (jti_hash,expires_at) VALUES (?,?) ON CONFLICT(jti_hash) DO NOTHING`, hex.EncodeToString(jtiHash[:]), time.Unix(claims.ExpiresAt, 0).UTC())
	if err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("消费登录票据: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("读取登录票据消费结果: %w", err)
	}
	if inserted != 1 {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, errors.Join(ErrInvalidLoginTicket, ErrLoginTicketReplay)
	}
	if err := tx.Commit(); err != nil {
		return models.ClusterLoginTicketClaims{}, models.User{}, 0, fmt.Errorf("提交登录票据消费: %w", err)
	}
	return claims, user, passwordVersion, nil
}
