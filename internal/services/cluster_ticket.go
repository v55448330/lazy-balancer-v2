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

var ErrInvalidLoginTicket = errors.New("登录票据无效或已过期")

func (s *ClusterService) GenerateLoginTicket(ctx context.Context, claims models.ClusterLoginTicketClaims, now time.Time) (models.ClusterLoginTicketResponse, error) {
	var ipAddress, protocol, keyHash, status string
	var port int
	var approved bool
	if err := s.db.QueryRowContext(ctx, `SELECT ip_address,port,COALESCE(protocol,'http'),COALESCE(cluster_token_hash,''),status,is_approved FROM nodes WHERE id=?`, claims.NodeID).
		Scan(&ipAddress, &port, &protocol, &keyHash, &status, &approved); err != nil {
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
	return models.ClusterLoginTicketResponse{Ticket: ticket, URL: protocol + "://" + net.JoinHostPort(ipAddress, strconv.Itoa(port))}, nil
}

func (s *ClusterService) ValidateLoginTicket(ctx context.Context, ticket string, now time.Time) (models.ClusterLoginTicketClaims, error) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	var isMaster bool
	var clusterToken string
	var registrationID int
	if err := s.db.QueryRowContext(ctx, `SELECT is_master,COALESCE(cluster_token,''),COALESCE(registration_id,0) FROM global_config WHERE id=1`).Scan(&isMaster, &clusterToken, &registrationID); err != nil {
		return models.ClusterLoginTicketClaims{}, fmt.Errorf("读取从节点凭证: %w", err)
	}
	if isMaster || clusterToken == "" {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	key := sha256.Sum256([]byte(clusterToken))
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	var claims models.ClusterLoginTicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.UserID <= 0 || claims.Username == "" || claims.Role == "" || claims.NodeID != registrationID || claims.ExpiresAt <= now.UTC().Unix() {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	ticketHash := sha256.Sum256([]byte(ticket))
	hashKey := hex.EncodeToString(ticketHash[:])
	s.usedTicketMu.Lock()
	defer s.usedTicketMu.Unlock()
	for used, expiresAt := range s.usedTickets {
		if !expiresAt.After(now) {
			delete(s.usedTickets, used)
		}
	}
	if _, used := s.usedTickets[hashKey]; used {
		return models.ClusterLoginTicketClaims{}, ErrInvalidLoginTicket
	}
	s.usedTickets[hashKey] = time.Unix(claims.ExpiresAt, 0)
	return claims, nil
}
