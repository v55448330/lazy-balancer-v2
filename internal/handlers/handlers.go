package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var startTime = time.Now()

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getHostname() string {
	cmd := exec.Command("hostname")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func getOSInfo() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		cmd := exec.Command("uname", "-s")
		output, err := cmd.Output()
		if err != nil {
			return "unknown"
		}
		return strings.TrimSpace(string(output))
	}
	lines := strings.Split(string(data), "\n")
	var prettyName, name string
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		}
	}
	if prettyName != "" {
		return prettyName
	}
	if name != "" {
		return name
	}
	return "Linux"
}

func getKernel() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func getArchitecture() string {
	cmd := exec.Command("arch")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func getNetworkIPs() map[string]string {
	ips := make(map[string]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				ips[iface.Name] = ip.String()
			}
		}
	}
	return ips
}

func getCaddyVersion() string {
	cmd := exec.Command("caddy", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	parts := strings.Fields(string(output))
	if len(parts) >= 1 {
		return strings.TrimPrefix(parts[0], "v")
	}
	return strings.TrimSpace(string(output))
}

func getUptime() int64 {
	return int64(time.Since(startTime).Seconds())
}

func getSystemMetrics() (models.SystemMetrics, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memoryTotal := m.TotalAlloc
	memoryUsed := m.Alloc

	vmStat, err := os.ReadFile("/proc/meminfo")
	var memTotal, memAvailable, diskUsed, diskTotal uint64
	if err == nil {
		lines := strings.Split(string(vmStat), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
					memTotal *= 1024
				}
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
					memAvailable *= 1024
				}
			}
		}
		if memTotal > 0 && memAvailable > 0 {
			memoryTotal = memTotal
			memoryUsed = memTotal - memAvailable
		}
	}

	diskStat, err := os.Stat("/")
	if err == nil {
		diskTotal = uint64(diskStat.Size())
	}

	dfCmd := exec.Command("df", "-B1", "/")
	dfOutput, err := dfCmd.Output()
	if err == nil {
		lines := strings.Split(string(dfOutput), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				diskUsed, _ = strconv.ParseUint(fields[2], 10, 64)
				diskTotal, _ = strconv.ParseUint(fields[3], 10, 64)
			}
		}
	}

	cpuPercent := getCPUPercent()

	var memPercent float64
	if memoryTotal > 0 {
		memPercent = float64(memoryUsed) / float64(memoryTotal) * 100
	}
	var diskPercent float64
	if diskTotal > 0 {
		diskPercent = float64(diskUsed) / float64(diskTotal) * 100
	}

	return models.SystemMetrics{
		CPUPercent:    cpuPercent,
		MemoryTotal:   memoryTotal,
		MemoryUsed:    memoryUsed,
		MemoryPercent: memPercent,
		DiskTotal:     diskTotal,
		DiskUsed:      diskUsed,
		DiskPercent:   diskPercent,
	}, nil
}

func getCPUPercent() float64 {
	cmd := exec.Command("sh", "-c", "cat /proc/stat | head -1 | awk '{print ($2+$3+$4)/($2+$3+$4+$5)*100}'")
	output, err := cmd.Output()
	if err == nil {
		line := strings.TrimSpace(string(output))
		if val, err := strconv.ParseFloat(line, 64); err == nil {
			return val
		}
	}
	return 0
}

func getCPUFromProc() float64 {
	readFile := func(path string) []byte {
		data, _ := os.ReadFile(path)
		return data
	}

	prevStats := parseCPUStats(string(readFile("/proc/stat")))
	if prevStats == nil {
		cmd := exec.Command("sh", "-c", "cat /proc/stat | head -1")
		output, _ := cmd.Output()
		prevStats = parseCPUStats(string(output))
		if prevStats == nil {
			return 0
		}
	}
	time.Sleep(500 * time.Millisecond)
	currStats := parseCPUStats(string(readFile("/proc/stat")))
	if currStats == nil {
		return 0
	}

	prevTotal := prevStats.total()
	currTotal := currStats.total()
	if currTotal <= prevTotal {
		return 0
	}

	prevIdle := prevStats.idle + prevStats.iowait
	currIdle := currStats.idle + currStats.iowait
	idleDelta := currIdle - prevIdle
	totalDelta := currTotal - prevTotal

	if totalDelta == 0 {
		return 0
	}

	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100
}

type cpuStats struct {
	user, nice, system, idle, iowait, irq, softirq uint64
}

func (c *cpuStats) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq
}

func parseCPUStats(data string) *cpuStats {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				return nil
			}
			user, _ := strconv.ParseUint(fields[1], 10, 64)
			nice, _ := strconv.ParseUint(fields[2], 10, 64)
			system, _ := strconv.ParseUint(fields[3], 10, 64)
			idle, _ := strconv.ParseUint(fields[4], 10, 64)
			iowait, _ := strconv.ParseUint(fields[5], 10, 64)
			irq, _ := strconv.ParseUint(fields[6], 10, 64)
			softirq, _ := strconv.ParseUint(fields[7], 10, 64)
			return &cpuStats{user, nice, system, idle, iowait, irq, softirq}
		}
	}
	return nil
}

func (h *Handlers) ListCertificateConfigs(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, domain, cert_pem, key_pem, issuer, acme_email, expires_at, created_at, updated_at FROM tls_certificates ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query configs"})
		return
	}
	defer rows.Close()

	var configs []models.CertificateConfig
	for rows.Next() {
		var cfg models.CertificateConfig
		rows.Scan(&cfg.ID, &cfg.Name, &cfg.ACMEEmail, &cfg.DNSProvider, &cfg.DNSID, &cfg.DNSKey, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt)
		configs = append(configs, cfg)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configs})
}

func (h *Handlers) CreateCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot create configs on slave node"})
		return
	}

	var req models.CreateCertificateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.DNSProvider == "" {
		req.DNSProvider = "dnspod"
	}

	result, err := db.DB.Exec(`
		INSERT INTO certificate_configs (name, acme_email, dns_provider, dns_id, dns_key, enabled)
		VALUES (?, ?, ?, ?, ?, ?)
	`, req.Name, req.ACMEEmail, req.DNSProvider, req.DNSID, req.DNSKey, req.Enabled)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create config"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Config created", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot update configs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))

	var req models.UpdateCertificateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	query := "UPDATE certificate_configs SET "
	var args []interface{}

	if req.Name != "" {
		query += "name = ?, "
		args = append(args, req.Name)
	}
	if req.ACMEEmail != "" {
		query += "acme_email = ?, "
		args = append(args, req.ACMEEmail)
	}
	if req.DNSProvider != "" {
		query += "dns_provider = ?, "
		args = append(args, req.DNSProvider)
	}
	if req.DNSID != "" || req.DNSKey != "" {
		if req.DNSID != "" {
			query += "dns_id = ?, "
			args = append(args, req.DNSID)
		}
		if req.DNSKey != "" {
			query += "dns_key = ?, "
			args = append(args, req.DNSKey)
		}
	}
	if req.Enabled != nil {
		query += "enabled = ?, "
		args = append(args, *req.Enabled)
	}

	query += "updated_at = datetime('now') WHERE id = ?"
	args = append(args, id)

	db.DB.Exec(query, args...)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}

func (h *Handlers) DeleteCertificateConfig(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete configs on slave node"})
		return
	}

	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM certificate_configs WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config deleted"})
}

var lastNetStats struct {
	bytesIn  uint64
	bytesOut uint64
	time     time.Time
}

func getRealtimeTraffic() (models.RealtimeTraffic, error) {
	netStat, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return models.RealtimeTraffic{}, err
	}

	var totalBytesIn, totalBytesOut uint64
	lines := strings.Split(string(netStat), "\n")
	for _, line := range lines {
		if strings.Contains(line, "eth0") || strings.Contains(line, "ens") || strings.Contains(line, "docker0") {
			fields := strings.Fields(line)
			if len(fields) >= 11 {
				bytesIn, _ := strconv.ParseUint(fields[1], 10, 64)
				bytesOut, _ := strconv.ParseUint(fields[9], 10, 64)
				totalBytesIn += bytesIn
				totalBytesOut += bytesOut
			}
		}
	}

	now := time.Now()
	var rateIn, rateOut int64

	if !lastNetStats.time.IsZero() {
		elapsed := now.Sub(lastNetStats.time).Seconds()
		if elapsed > 0 {
			rateIn = int64(float64(totalBytesIn-lastNetStats.bytesIn) / elapsed)
			rateOut = int64(float64(totalBytesOut-lastNetStats.bytesOut) / elapsed)
			if rateIn < 0 {
				rateIn = 0
			}
			if rateOut < 0 {
				rateOut = 0
			}
		}
	}

	lastNetStats.bytesIn = totalBytesIn
	lastNetStats.bytesOut = totalBytesOut
	lastNetStats.time = now

	return models.RealtimeTraffic{
		BytesIn:  rateIn,
		BytesOut: rateOut,
	}, nil
}

func getConnectionStats() (models.ConnectionStats, error) {
	stats := models.ConnectionStats{}

	cmd := exec.Command("netstat", "-tan")
	output, err := cmd.Output()
	if err != nil {
		return stats, nil
	}

	lines := strings.Split(string(output), "\n")
	stateCounts := make(map[string]int64)

	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		if i == 0 && fields[0] == "Proto" {
			continue
		}

		state := fields[5]
		switch state {
		case "ESTABLISHED":
			stateCounts["established"]++
		case "SYN-SENT":
			stateCounts["syn_sent"]++
		case "SYN-RECV":
			stateCounts["syn_recv"]++
		case "FIN-WAIT1":
			stateCounts["fin_wait1"]++
		case "FIN-WAIT2":
			stateCounts["fin_wait2"]++
		case "CLOSE-WAIT":
			stateCounts["close_wait"]++
		case "CLOSING":
			stateCounts["closing"]++
		case "LAST-ACK":
			stateCounts["last_ack"]++
		case "LISTEN":
			stateCounts["listening"]++
		case "TIME-WAIT":
			stateCounts["time_wait"]++
		}
	}

	stats.Established = stateCounts["established"]
	stats.SynSent = stateCounts["syn_sent"]
	stats.SynRecv = stateCounts["syn_recv"]
	stats.FinWait1 = stateCounts["fin_wait1"]
	stats.FinWait2 = stateCounts["fin_wait2"]
	stats.CloseWait = stateCounts["close_wait"]
	stats.Closing = stateCounts["closing"]
	stats.LastAck = stateCounts["last_ack"]
	stats.Listening = stateCounts["listening"]
	stats.TimeWait = stateCounts["time_wait"]

	stats.Total = stats.Established + stats.SynSent + stats.SynRecv + stats.FinWait1 +
		stats.FinWait2 + stats.CloseWait + stats.Closing + stats.LastAck + stats.TimeWait

	return stats, nil
}

type Handlers struct {
	cfg            *config.Config
	caddyService   *services.CaddyService
	metricsService *services.MetricsService
	nodeService    *services.NodeService
	syncService    *services.SyncService
}

func NewHandlers(cfg *config.Config, caddy *services.CaddyService, metrics *services.MetricsService, node *services.NodeService, sync *services.SyncService) *Handlers {
	h := &Handlers{
		cfg:            cfg,
		caddyService:   caddy,
		metricsService: metrics,
		nodeService:    node,
		syncService:    sync,
	}

	// Initialize default admin user
	h.initDefaultAdmin()

	// Initialize default config
	h.initDefaultConfig()

	return h
}

func (h *Handlers) initDefaultAdmin() {
	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", h.cfg.InitialAdminUser).Scan(&count)

	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte(h.cfg.InitialAdminPassword), bcrypt.DefaultCost)
		db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
			h.cfg.InitialAdminUser, string(hash))
		log.Printf("Created default admin user: %s", h.cfg.InitialAdminUser)
	}
}

func (h *Handlers) initDefaultConfig() {
	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM global_config WHERE id = 1").Scan(&count)

	if count == 0 {
		defaultConfig, _ := json.Marshal(map[string]interface{}{})
		db.DB.Exec("INSERT INTO global_config (id, caddy_config, dns_provider, is_master) VALUES (1, ?, 'dnspod', 1)",
			string(defaultConfig))
	}
}

// Auth handlers

func (h *Handlers) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var user models.User
	var passwordHash string
	err := db.DB.QueryRow("SELECT id, username, password_hash, role, display_name, last_login FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &passwordHash, &user.Role, &user.DisplayName, &user.LastLogin)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Invalid credentials"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Invalid credentials"})
		return
	}

	// Update last login
	db.DB.Exec("UPDATE users SET last_login = datetime('now') WHERE id = ?", user.ID)

	// Get node mode
	nodeMode := h.cfg.NodeMode
	if nodeMode == "" {
		nodeMode = "master"
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID,
		"username":  user.Username,
		"role":      user.Role,
		"node_mode": nodeMode,
		"exp":       time.Now().Add(h.cfg.JWTExpire).Unix(),
	})

	tokenString, _ := token.SignedString([]byte(h.cfg.JWTSecret))

	c.JSON(http.StatusOK, models.LoginResponse{
		Token:    tokenString,
		User:     user,
		NodeMode: nodeMode,
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Logged out"})
}

// User management (admin only)

func (h *Handlers) GetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Not authenticated"})
		return
	}

	var userIDInt int
	switch v := userID.(type) {
	case float64:
		userIDInt = int(v)
	case int:
		userIDInt = v
	default:
		userIDInt = 0
	}

	var user models.User
	err := db.DB.QueryRow(`
		SELECT id, username, role, display_name, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "User not found"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: user})
}

type UpdateCurrentUserRequest struct {
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

func (h *Handlers) UpdateCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "Not authenticated"})
		return
	}

	var userIDInt int
	switch v := userID.(type) {
	case float64:
		userIDInt = int(v)
	case int:
		userIDInt = v
	default:
		userIDInt = 0
	}

	var req UpdateCurrentUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// Update display name
	if req.DisplayName != "" {
		db.DB.Exec("UPDATE users SET display_name = ? WHERE id = ?", req.DisplayName, userIDInt)
	}

	// Update password if provided
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
			return
		}
		db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), userIDInt)
	}

	// Return updated user
	var user models.User
	err := db.DB.QueryRow(`
		SELECT id, username, role, display_name, created_at, last_login 
		FROM users WHERE id = ?
	`, userIDInt).Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.CreatedAt, &user.LastLogin)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get user"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: user})
}

func (h *Handlers) ListUsers(c *gin.Context) {
	rows, err := db.DB.Query("SELECT id, username, role, display_name, is_enabled, created_at, last_login FROM users ORDER BY id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.Role, &u.DisplayName, &u.IsEnabled, &u.CreatedAt, &u.LastLogin)
		users = append(users, u)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: users})
}

func (h *Handlers) CreateUser(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid role"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
		return
	}

	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled) VALUES (?, ?, ?, ?, 1)",
		req.Username, string(hash), req.Role, req.DisplayName)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "用户名已存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建用户失败"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "User created", Data: gin.H{"id": id}})
}

func (h *Handlers) UpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		DisplayName string `json:"display_name"`
	}
	c.ShouldBindJSON(&req)

	if req.Role != "" && req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid role"})
		return
	}

	if req.Username != "" {
		db.DB.Exec("UPDATE users SET username = ? WHERE id = ?", req.Username, id)
	}

	if req.Role != "" {
		db.DB.Exec("UPDATE users SET role = ? WHERE id = ?", req.Role, id)
	}

	// DisplayName can be updated even if empty (to clear it)
	db.DB.Exec("UPDATE users SET display_name = ? WHERE id = ?", req.DisplayName, id)

	if req.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), id)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User updated"})
}

func (h *Handlers) DeleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	userID, _ := c.Get("user_id")
	var userIDInt int
	switch v := userID.(type) {
	case float64:
		userIDInt = int(v)
	case int:
		userIDInt = v
	default:
		userIDInt = 0
	}

	if userIDInt == id {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Cannot delete yourself"})
		return
	}

	result, err := db.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete user"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "User not found"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User deleted"})
}

func (h *Handlers) ToggleUserStatus(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		IsEnabled bool `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	_, err := db.DB.Exec("UPDATE users SET is_enabled = ? WHERE id = ?", req.IsEnabled, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update user status"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "User status updated"})
}

func (h *Handlers) ResetUserPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to hash password"})
		return
	}

	_, err = db.DB.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Password reset successfully"})
}

// API Key management (admin only)

func (h *Handlers) ListAPIKeys(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT k.id, k.name, k.key_prefix, k.created_by, k.last_used, k.expires_at, k.created_at, u.username 
		FROM api_keys k 
		JOIN users u ON k.created_by = u.id 
		ORDER BY k.id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	type APIKeyWithUser struct {
		ID        int          `json:"id"`
		Name      string       `json:"name"`
		KeyPrefix string       `json:"key_prefix"`
		CreatedBy int          `json:"created_by"`
		Username  string       `json:"username"`
		LastUsed  sql.NullTime `json:"last_used"`
		ExpiresAt sql.NullTime `json:"expires_at"`
		CreatedAt time.Time    `json:"created_at"`
	}

	var keys []APIKeyWithUser
	for rows.Next() {
		var k APIKeyWithUser
		rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.CreatedBy, &k.LastUsed, &k.ExpiresAt, &k.CreatedAt, &k.Username)
		keys = append(keys, k)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: keys})
}

func (h *Handlers) CreateAPIKey(c *gin.Context) {
	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// Generate API key
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	apiKey := "lb_sk_" + base64.URLEncoding.EncodeToString(keyBytes)[:32]

	// Hash the key for storage
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := apiKey[:12]

	userID, _ := c.Get("user_id")

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt
	}

	result, err := db.DB.Exec(`
		INSERT INTO api_keys (name, key_hash, key_prefix, created_by, expires_at) 
		VALUES (?, ?, ?, ?, ?)
	`, req.Name, keyHash, keyPrefix, userID, expiresAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create API key"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Data: gin.H{
		"id":      id,
		"key":     apiKey,
		"message": "This key will only be shown once. Please save it securely.",
	}})
}

func (h *Handlers) DeleteAPIKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "API key deleted"})
}

// LB Rules management

func (h *Handlers) ListRules(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT COALESCE(caddy_id,'') AS caddy_id, name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, strategy, 
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_ttl,300), COALESCE(dns_timeout,5), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       COALESCE(enable_active_health_check,0), COALESCE(enable_tls,0), COALESCE(tls_auto_cert,0), COALESCE(tls_http_redirect,0),
		       COALESCE(tls_hsts,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), enabled, created_by, created_at, updated_at, updated_by,
		       COALESCE(host_header,'')
		FROM lb_rules ORDER BY id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var rules []models.LbRule
	for rows.Next() {
		var r models.LbRule
		var domain, strategy, description, compressTypes, hostHeader, dnsFamily string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect, enableCompress bool
		var tlsHSTS int
		var createdBy sql.NullInt64
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		var updatedBy sql.NullInt64
		err := rows.Scan(&r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &r.DnsTTL, &r.DnsTimeout, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval,
			&enableActiveHealthCheck, &enableTLS, &tlsAutoCert, &tlsHTTPRedirect,
			&tlsHSTS, &enableCompress, &compressTypes, &r.Enabled, &createdBy, &createdAt, &updatedAt, &updatedBy,
			&hostHeader)
		if err != nil {
			continue
		}
		if createdBy.Valid {
			r.CreatedBy = int(createdBy.Int64)
		}
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time
		}
		if updatedAt.Valid {
			r.UpdatedAt = updatedAt
		}
		if updatedBy.Valid {
			r.UpdatedBy = int(updatedBy.Int64)
		}
		r.Description = description
		r.Domain = domain
		r.Strategy = strategy
		if r.Strategy == "" {
			r.Strategy = "round_robin"
		}
		r.DynamicDNS = dynamicDNS
		r.EnableDnsServer = enableDnsServer
		r.DnsFamily = dnsFamily
		r.EnableActiveHealthCheck = enableActiveHealthCheck
		r.EnableTLS = enableTLS
		r.TLSAutoCert = tlsAutoCert
		r.TLSHTTPRedirect = tlsHTTPRedirect
		r.TLSHSTS = tlsHSTS
		r.EnableCompress = enableCompress
		r.CompressTypes = compressTypes
		r.HostHeader = hostHeader

		upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?`, r.CaddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
				r.Upstreams = append(r.Upstreams, u)
			}
			upstreamRows.Close()
		}

		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

func (h *Handlers) GetRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r models.LbRule
	var domain, strategy, hostHeader, dnsFamily string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect bool
	var tlsHSTS int
	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_ttl,300), COALESCE(dns_timeout,5), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       COALESCE(tls_hsts,0), enabled, created_at, updated_at, COALESCE(host_header,''), caddy_id
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &r.DnsTTL, &r.DnsTimeout, &dnsFamily,
		&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
		&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &enableTLS, &r.TLSCert, &r.TLSKey, &tlsAutoCert, &r.TLSEmail, &tlsHTTPRedirect,
		&tlsHSTS, &r.Enabled, &r.CreatedAt, &r.UpdatedAt, &hostHeader, &r.CaddyID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	r.Domain = domain
	r.Strategy = strategy
	if r.Strategy == "" {
		r.Strategy = "round_robin"
	}
	r.DynamicDNS = dynamicDNS
	r.EnableDnsServer = enableDnsServer
	r.DnsFamily = dnsFamily
	r.EnableActiveHealthCheck = enableActiveHealthCheck
	r.EnableTLS = enableTLS
	r.TLSAutoCert = tlsAutoCert
	r.TLSHTTPRedirect = tlsHTTPRedirect
	r.TLSHSTS = tlsHSTS
	r.HostHeader = hostHeader

	upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?`, caddyID)
	if upstreamRows != nil {
		for upstreamRows.Next() {
			var u models.Upstream
			upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			r.Upstreams = append(r.Upstreams, u)
		}
		upstreamRows.Close()
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: r})
}

// GetRuleCaddyConfig generates and returns Caddy configuration for a specific rule
func (h *Handlers) GetRuleCaddyConfig(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r struct {
		Name                          string
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		EnableDnsServer               bool
		DnsServer                     string
		DnsTTL                        int
		DnsTimeout                    int
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSCert                       string
		TLSKey                        string
		TLSAutoCert                   bool
		TLSEmail                      string
		TLSHTTPRedirect               bool
		TLSHSTS                       int
		Enabled                       bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
		CaddyID                       string
	}

	var domain, strategy, hostHeader, compressTypes, tlsCert, tlsKey, tlsEmail string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect, enableCompress bool
	var tlsHSTS int

	log.Printf("GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_ttl,300), COALESCE(dns_timeout,5),
		       COALESCE(dns_family,'ipv4'), health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       COALESCE(tls_hsts,0), enabled, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
		       COALESCE(enable_active_health_check,0), COALESCE(host_header,''), COALESCE(caddy_id,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &r.DnsTTL, &r.DnsTimeout, &r.DnsFamily, &r.HealthCheckPath, &r.HealthCheckInterval,
		&r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableTLS, &tlsCert, &tlsKey, &tlsAutoCert, &tlsEmail, &tlsHTTPRedirect,
		&tlsHSTS, &r.Enabled, &enableCompress, &compressTypes,
		&enableActiveHealthCheck, &hostHeader, &r.CaddyID)

	if err != nil {
		log.Printf("GetRuleCaddyConfig: query/scan error for rule caddy_id=%s: %v", caddyID, err)
	}

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get rule: " + err.Error()})
		return
	}

	r.Domain = domain
	r.Strategy = strategy
	if r.Strategy == "" {
		r.Strategy = "round_robin"
	}
	r.DynamicDNS = dynamicDNS
	r.EnableActiveHealthCheck = enableActiveHealthCheck
	r.EnableTLS = enableTLS
	r.TLSCert = tlsCert
	r.TLSKey = tlsKey
	r.TLSAutoCert = tlsAutoCert
	r.TLSEmail = tlsEmail
	r.TLSHTTPRedirect = tlsHTTPRedirect
	r.TLSHSTS = tlsHSTS
	r.EnableCompress = enableCompress
	r.CompressTypes = compressTypes
	r.HostHeader = hostHeader

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, COALESCE(weight,1), COALESCE(protocol,'http'), enabled
		FROM upstreams WHERE rule_id = ? AND enabled = 1
	`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get upstreams"})
		return
	}
	defer upstreamRows.Close()

	var ups []services.UpstreamConfig
	for upstreamRows.Next() {
		var u services.UpstreamConfig
		var protocol string
		var enabled bool
		upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &protocol, &enabled)
		u.Protocol = protocol
		u.Enabled = enabled
		ups = append(ups, u)
	}

	log.Printf("GetRuleCaddyConfig: caddyID=%s, protocol=%s, domain=%s, port=%d, upstreams=%d, enabled=%v",
		r.CaddyID, r.Protocol, r.Domain, r.ListenPort, len(ups), r.Enabled)

	responseData := map[string]interface{}{
		"caddy_id": r.CaddyID,
		"enabled":  r.Enabled,
	}

	if r.CaddyID == "" || !r.Enabled {
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	caddyActualConfig, err := h.caddyService.GetConfigByID(r.CaddyID)
	if err != nil {
		log.Printf("GetRuleCaddyConfig: failed to get config from Caddy for caddy_id=%s: %v", r.CaddyID, err)
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	responseData["config"] = caddyActualConfig
	responseData["config_not_exists"] = false
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
}

func (h *Handlers) CreateRule(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot create rules on slave node"})
		return
	}

	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		body, _ := io.ReadAll(c.Request.Body)
		log.Printf("CreateRule bind error: %v, body: %s", err, string(body))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("Invalid request: %v", err)})
		return
	}
	log.Printf("CreateRule bind success: name=%s, protocol=%s, port=%d, upstreams=%d", req.Name, req.Protocol, req.ListenPort, len(req.Upstreams))

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Name is required"})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Protocol is required"})
		return
	}
	if req.ListenPort <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Listen port must be greater than 0"})
		return
	}
	if len(req.Upstreams) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "At least one upstream required"})
		return
	}

	if err := h.validatePort(req.Protocol, req.ListenPort, ""); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Set defaults before validation
	if req.Strategy == "" {
		req.Strategy = "round_robin"
	}
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = 10
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = 5
	}
	if req.CompressTypes == "" {
		req.CompressTypes = "gzip"
	}

	// Determine server name based on port and protocol (needed for validation)
	var serverName string
	var listenPort int
	if req.Protocol == "http" && req.ListenPort == 80 {
		serverName = "http_80"
		listenPort = 80
	} else if req.Protocol == "https" && req.ListenPort == 443 {
		serverName = "https_443"
		listenPort = 443
	} else {
		if req.Protocol == "http" {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
		} else if req.Protocol == "https" {
			serverName = fmt.Sprintf("https_%d", req.ListenPort)
		} else {
			serverName = fmt.Sprintf("tcp_%d", req.ListenPort)
		}
		listenPort = req.ListenPort
	}

	userID, _ := c.Get("user_id")
	var userIDInt int64
	if userID != nil {
		userIDInt = int64(userID.(float64))
	}

	// Generate caddy_id for @id-based management
	caddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to generate caddy ID"})
		return
	}

	// Build route config for Caddy validation (using request data before DB write)
	ruleConfig := services.SingleRuleConfig{
		Protocol:                req.Protocol,
		Domain:                  req.Domain,
		ListenPort:              req.ListenPort,
		Strategy:                req.Strategy,
		DynamicDNS:              req.DynamicDNS,
		EnableDnsServer:         req.EnableDnsServer,
		DnsServer:               req.DnsServer,
		DnsTTL:                  req.DnsTTL,
		DnsTimeout:              req.DnsTimeout,
		DnsFamily:               req.DnsFamily,
		HealthCheckPath:         req.HealthCheckPath,
		HealthCheckInterval:     req.HealthCheckInterval,
		HealthCheckTimeout:      req.HealthCheckTimeout,
		EnableTLS:               req.EnableTLS,
		TLSHTTPRedirect:         req.TLSHTTPRedirect,
		TLSHSTS:                 req.TLSHSTS,
		EnableCompress:          req.EnableCompress,
		CompressTypes:           req.CompressTypes,
		EnableActiveHealthCheck: req.EnableActiveHealthCheck,
		HostHeader:              req.HostHeader,
		CaddyID:                 caddyID,
	}
	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			protocol = "http"
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, "new_"+generateRandomString(8), serverName); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	if err := h.caddyService.CreateServerIfNotExists(serverName, listenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to create server: " + err.Error()})
		return
	}

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to generate route config: " + err.Error()})
		return
	}

	if err := h.caddyService.PrependRouteToServer(serverName, routeConfig); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to add route to Caddy: " + err.Error()})
		return
	}

	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	_, err = db.DB.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server, dns_ttl, dns_timeout,
			health_check_path, health_check_interval, health_check_timeout, 
			health_check_unhealthy_threshold, health_check_healthy_threshold, 
			enable_active_health_check, host_header, enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email, tls_http_redirect, tls_hsts, 
			enable_compress, compress_types, enabled, created_by, updated_at, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Description, req.Protocol, req.Domain, req.ListenPort, req.Strategy, req.DynamicDNS, req.EnableDnsServer, req.DnsServer, req.DnsTTL, req.DnsTimeout,
		req.HealthCheckPath, req.HealthCheckInterval, req.HealthCheckTimeout,
		req.HealthCheckUnhealthyThreshold, req.HealthCheckHealthyThreshold,
		req.EnableActiveHealthCheck, req.HostHeader, req.EnableTLS, req.TLSCert, req.TLSKey, req.TLSAutoCert, req.TLSEmail,
		req.TLSHTTPRedirect, req.TLSHSTS, req.EnableCompress, req.CompressTypes, 1, userIDInt, time.Now().Format("2006-01-02 15:04:05"), caddyID)

	if err != nil {
		log.Printf("CreateRule database error: %v, rolling back Caddy", err)
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create rule, Caddy route rolled back"})
		return
	}

	for _, u := range req.Upstreams {
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Protocol == "" {
			u.Protocol = "http"
		}
		db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
	}

	log.Printf("Rule created with caddy_id=%s, applied via @id mechanism (no full reload)", caddyID)
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Rule created", Data: gin.H{"caddy_id": caddyID}})
}

func (h *Handlers) UpdateRule(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot update rules on slave node"})
		return
	}

	caddyID := c.Param("caddy_id")

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// Prevent port change - get current rule's port
	if req.ListenPort > 0 {
		var currentPort int
		err := db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&currentPort)
		if err != nil {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
			return
		}
		if currentPort != req.ListenPort {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Port cannot be changed after rule creation"})
			return
		}
	}

	// Determine server name for validation - port can't change so use req.ListenPort or query existing
	var validationServerName string
	validationPort := req.ListenPort
	if validationPort == 0 {
		db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&validationPort)
	}
	validationProtocol := req.Protocol
	if validationProtocol == "" {
		db.DB.QueryRow("SELECT COALESCE(protocol,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&validationProtocol)
	}
	if validationProtocol == "http" && validationPort == 80 {
		validationServerName = "http_80"
	} else if validationProtocol == "https" && validationPort == 443 {
		validationServerName = "https_443"
	} else if validationProtocol == "http" {
		validationServerName = fmt.Sprintf("http_%d", validationPort)
	} else if validationProtocol == "https" {
		validationServerName = fmt.Sprintf("https_%d", validationPort)
	} else {
		validationServerName = fmt.Sprintf("tcp_%d", validationPort)
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, fmt.Sprintf("update_%s_%s", caddyID, generateRandomString(8)), validationServerName); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Build dynamic update for lb_rules table
	query := "UPDATE lb_rules SET "
	var args []interface{}

	if req.Name != "" {
		query += "name = ?, "
		args = append(args, req.Name)
	}
	if req.Protocol != "" {
		query += "protocol = ?, "
		args = append(args, req.Protocol)
	}
	if req.Domain != "" {
		query += "domain = ?, "
		args = append(args, req.Domain)
	}
	if req.ListenPort > 0 {
		query += "listen_port = ?, "
		args = append(args, req.ListenPort)

		if err := h.validatePortFromDB(req.Protocol, req.ListenPort, caddyID); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if req.Strategy != "" {
		query += "strategy = ?, "
		args = append(args, req.Strategy)
	}
	query += "dynamic_dns = ?, "
	args = append(args, req.DynamicDNS)
	query += "enable_dns_server = ?, "
	args = append(args, req.EnableDnsServer)
	query += "dns_server = ?, "
	args = append(args, req.DnsServer)
	query += "dns_ttl = ?, "
	args = append(args, req.DnsTTL)
	query += "dns_timeout = ?, "
	args = append(args, req.DnsTimeout)
	if req.HealthCheckPath != "" {
		query += "health_check_path = ?, "
		args = append(args, req.HealthCheckPath)
	}
	if req.HealthCheckInterval > 0 {
		query += "health_check_interval = ?, "
		args = append(args, req.HealthCheckInterval)
	}
	if req.HealthCheckTimeout > 0 {
		query += "health_check_timeout = ?, "
		args = append(args, req.HealthCheckTimeout)
	}
	if req.HealthCheckUnhealthyThreshold > 0 {
		query += "health_check_unhealthy_threshold = ?, "
		args = append(args, req.HealthCheckUnhealthyThreshold)
	}
	if req.HealthCheckHealthyThreshold > 0 {
		query += "health_check_healthy_threshold = ?, "
		args = append(args, req.HealthCheckHealthyThreshold)
	}
	query += "enable_active_health_check = ?, "
	args = append(args, req.EnableActiveHealthCheck)
	if req.HostHeader != "" {
		query += "host_header = ?, "
		args = append(args, req.HostHeader)
	}
	query += "enable_tls = ?, "
	args = append(args, req.EnableTLS)
	if req.TLSCert != "" {
		query += "tls_cert = ?, "
		args = append(args, req.TLSCert)
	}
	if req.TLSKey != "" {
		query += "tls_key = ?, "
		args = append(args, req.TLSKey)
	}
	query += "tls_auto_cert = ?, "
	args = append(args, req.TLSAutoCert)
	if req.TLSEmail != "" {
		query += "tls_email = ?, "
		args = append(args, req.TLSEmail)
	}
	query += "tls_http_redirect = ?, "
	args = append(args, req.TLSHTTPRedirect)
	query += "tls_hsts = ?, "
	args = append(args, req.TLSHSTS)
	query += "enable_compress = ?, "
	args = append(args, req.EnableCompress)
	if req.CompressTypes != "" {
		query += "compress_types = ?, "
		args = append(args, req.CompressTypes)
	}
	query += "enabled = ?, "
	args = append(args, req.Enabled)

	// Get existing rule's caddy_id for @id-based update
	var existingProtocol, existingDomain string
	var existingListenPort int
	err := db.DB.QueryRow("SELECT COALESCE(caddy_id,''), protocol, COALESCE(domain,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &existingProtocol, &existingDomain, &existingListenPort)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	if caddyID == "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Rule has no caddy_id, cannot use @id-based update"})
		return
	}

	// Build full rule config for route generation
	protocol := req.Protocol
	if protocol == "" {
		protocol = existingProtocol
	}
	domain := req.Domain
	if domain == "" {
		domain = existingDomain
	}
	listenPort := req.ListenPort
	if listenPort == 0 {
		listenPort = existingListenPort
	}

	strategy := req.Strategy
	if strategy == "" {
		db.DB.QueryRow("SELECT COALESCE(strategy,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&strategy)
		if strategy == "" {
			strategy = "round_robin"
		}
	}

	upstreams := req.Upstreams
	if len(upstreams) == 0 {
		upstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?", caddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
				upstreams = append(upstreams, u)
			}
			upstreamRows.Close()
		}
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                protocol,
		Domain:                  domain,
		ListenPort:              listenPort,
		Strategy:                strategy,
		DynamicDNS:              req.DynamicDNS,
		EnableDnsServer:         req.EnableDnsServer,
		DnsServer:               req.DnsServer,
		DnsTTL:                  req.DnsTTL,
		DnsTimeout:              req.DnsTimeout,
		DnsFamily:               req.DnsFamily,
		HealthCheckPath:         req.HealthCheckPath,
		HealthCheckInterval:     req.HealthCheckInterval,
		HealthCheckTimeout:      req.HealthCheckTimeout,
		EnableTLS:               req.EnableTLS,
		TLSHTTPRedirect:         req.TLSHTTPRedirect,
		TLSHSTS:                 req.TLSHSTS,
		EnableCompress:          req.EnableCompress,
		CompressTypes:           req.CompressTypes,
		EnableActiveHealthCheck: req.EnableActiveHealthCheck,
		HostHeader:              req.HostHeader,
		CaddyID:                 caddyID,
	}
	for _, u := range upstreams {
		protocol := u.Protocol
		if protocol == "" {
			protocol = "http"
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to generate route config: " + err.Error()})
		return
	}

	if err := h.caddyService.SetConfigByID(caddyID, routeConfig); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy update failed: " + err.Error()})
		return
	}

	// Verify the route was actually written to Caddy
	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	userID, _ := c.Get("user_id")
	var userIDInt int64
	if userID != nil {
		userIDInt = int64(userID.(float64))
	}
	query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?"
	args = append(args, userIDInt, caddyID)

	db.DB.Exec(query, args...)

	if len(req.Upstreams) > 0 {
		db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
		for _, u := range req.Upstreams {
			if u.Weight == 0 {
				u.Weight = 1
			}
			if u.Protocol == "" {
				u.Protocol = "http"
			}
			db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol) 
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
		}
	}

	log.Printf("Rule %s updated, applied via @id mechanism", caddyID)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule updated"})
}

func (h *Handlers) DeleteRule(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete rules on slave node"})
		return
	}

	caddyID := c.Param("caddy_id")

	var protocol string
	var listenPort int
	var domain string
	err := db.DB.QueryRow("SELECT COALESCE(caddy_id,''), COALESCE(protocol,''), listen_port, COALESCE(domain,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &protocol, &listenPort, &domain)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	var serverName string
	var serverPort int
	if protocol == "http" && listenPort == 80 {
		serverName = "http_80"
		serverPort = 80
	} else if protocol == "https" && listenPort == 443 {
		serverName = "https_443"
		serverPort = 443
	} else if protocol == "http" {
		serverName = fmt.Sprintf("http_%d", listenPort)
		serverPort = listenPort
	} else if protocol == "https" {
		serverName = fmt.Sprintf("https_%d", listenPort)
		serverPort = listenPort
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
		serverPort = listenPort
	}

	// Remove route from server
	if caddyID != "" {
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
	}

	// HTTP port 80 and HTTPS port 443 servers should never be deleted (default site)
	keepServer := (protocol == "http" && listenPort == 80) || (protocol == "https" && listenPort == 443)

	if !keepServer {
		// Check if there are other enabled rules using this server
		var otherEnabledCount int
		db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id != ? AND listen_port = ? AND enabled = 1", caddyID, serverPort).Scan(&otherEnabledCount)

		if otherEnabledCount == 0 {
			h.caddyService.DeleteServer(serverName)
			log.Printf("Rule %s deleted, server %s removed", caddyID, serverName)
		} else {
			log.Printf("Rule %s deleted, server %s kept (%d other enabled rules)", caddyID, serverName, otherEnabledCount)
		}
	} else {
		log.Printf("Rule %s deleted, server %s kept (reserved port)", caddyID, serverName)
	}

	// Delete upstreams first
	db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
	db.DB.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID)
	// Delete the rule
	db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule deleted"})
}

func (h *Handlers) DuplicateRule(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot duplicate rules on slave node"})
		return
	}

	caddyID := c.Param("caddy_id")

	var rule models.LbRule
	err := db.DB.QueryRow(`
		SELECT caddy_id, name, protocol, domain, listen_port, strategy, dynamic_dns,
		       health_check_path, health_check_interval, health_check_timeout,
		       health_check_unhealthy_threshold, health_check_healthy_threshold,
		       enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email,
		       tls_http_redirect, tls_hsts, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip,zstd'), enabled, created_by,
		       COALESCE(host_header,''), COALESCE(dns_server,''), COALESCE(dns_ttl,300)
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&rule.EnableTLS, &rule.TLSCert, &rule.TLSKey, &rule.TLSAutoCert, &rule.TLSEmail,
		&rule.TLSHTTPRedirect, &rule.TLSHSTS, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.CreatedBy,
		&rule.HostHeader, &rule.DnsServer, &rule.DnsTTL,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	userID, _ := c.Get("user_id")

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to generate caddy ID"})
		return
	}

	result, err := db.DB.Exec(`
		INSERT INTO lb_rules (name, protocol, domain, listen_port, strategy, dynamic_dns, dns_server, dns_ttl,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email,
			tls_http_redirect, tls_hsts, enable_compress, compress_types, enabled, created_by, updated_by, created_at, updated_at, host_header, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?)
	`, rule.Name+" (Copy)", rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
		rule.DynamicDNS, rule.DnsServer, rule.DnsTTL, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
		rule.EnableTLS, rule.TLSCert, rule.TLSKey, rule.TLSAutoCert, rule.TLSEmail,
		rule.TLSHTTPRedirect, rule.TLSHSTS, rule.EnableCompress, rule.CompressTypes, 0, userID, userID,
		rule.HostHeader, newCaddyID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to duplicate rule"})
		return
	}

	_ = result

	db.DB.Exec("UPDATE lb_rules SET updated_by = ? WHERE caddy_id = ?", userID, newCaddyID)

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, weight, domain, dynamic_dns, enabled, COALESCE(protocol,'http')
		FROM upstreams WHERE rule_id = ?
	`, caddyID)
	if err == nil {
		for upstreamRows.Next() {
			var u struct {
				Host       string
				Port       int
				Weight     int
				Domain     string
				DynamicDNS bool
				Enabled    bool
				Protocol   string
			}
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			db.DB.Exec(`
				INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`, newCaddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
		}
		upstreamRows.Close()
	}

	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Rule duplicated", Data: gin.H{"caddy_id": newCaddyID}})
}

func (h *Handlers) EnableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var protocol string
	var listenPort int
	err := db.DB.QueryRow("SELECT COALESCE(protocol,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol, &listenPort)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	var serverName string
	if protocol == "http" && listenPort == 80 {
		serverName = "http_80"
	} else if protocol == "https" && listenPort == 443 {
		serverName = "https_443"
	} else if protocol == "http" {
		serverName = fmt.Sprintf("http_%d", listenPort)
	} else if protocol == "https" {
		serverName = fmt.Sprintf("https_%d", listenPort)
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
	}

	if h.caddyService.RouteExistsInServer(serverName, caddyID) {
		db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule enabled"})
		return
	}

	var rule models.LbRule
	err = db.DB.QueryRow(`
		SELECT COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_ttl,300), COALESCE(dns_timeout,5), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		       COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       COALESCE(tls_hsts,0), enabled, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
		       COALESCE(enable_active_health_check,0), COALESCE(host_header,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.EnableDnsServer, &rule.DnsServer, &rule.DnsTTL, &rule.DnsTimeout, &rule.DnsFamily, &rule.HealthCheckPath, &rule.HealthCheckInterval,
		&rule.HealthCheckTimeout, &rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&rule.EnableTLS, &rule.TLSCert, &rule.TLSKey, &rule.TLSAutoCert, &rule.TLSEmail,
		&rule.TLSHTTPRedirect, &rule.TLSHSTS, &rule.Enabled, &rule.EnableCompress, &rule.CompressTypes,
		&rule.EnableActiveHealthCheck, &rule.HostHeader,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get rule"})
		return
	}

	upstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?", caddyID)
	if upstreamRows != nil {
		for upstreamRows.Next() {
			var u models.Upstream
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			rule.Upstreams = append(rule.Upstreams, u)
		}
		upstreamRows.Close()
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                rule.Protocol,
		Domain:                  rule.Domain,
		ListenPort:              rule.ListenPort,
		Strategy:                rule.Strategy,
		DynamicDNS:              rule.DynamicDNS,
		DnsServer:               rule.DnsServer,
		DnsTTL:                  rule.DnsTTL,
		DnsFamily:               rule.DnsFamily,
		HealthCheckPath:         rule.HealthCheckPath,
		HealthCheckInterval:     rule.HealthCheckInterval,
		HealthCheckTimeout:      rule.HealthCheckTimeout,
		EnableTLS:               rule.EnableTLS,
		TLSHTTPRedirect:         rule.TLSHTTPRedirect,
		TLSHSTS:                 rule.TLSHSTS,
		EnableCompress:          rule.EnableCompress,
		CompressTypes:           rule.CompressTypes,
		EnableActiveHealthCheck: rule.EnableActiveHealthCheck,
		HostHeader:              rule.HostHeader,
		CaddyID:                 rule.CaddyID,
	}
	for _, u := range rule.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			protocol = "http"
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	h.caddyService.CreateServerIfNotExists(serverName, listenPort)

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	if err := h.caddyService.PrependRouteToServer(serverName, routeConfig); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Failed to add route to Caddy: %v", err)})
		return
	}

	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule enabled"})
}

func (h *Handlers) DisableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var protocol string
	var listenPort int
	err := db.DB.QueryRow("SELECT COALESCE(protocol,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol, &listenPort)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	var serverName string
	if protocol == "http" && listenPort == 80 {
		serverName = "http_80"
	} else if protocol == "https" && listenPort == 443 {
		serverName = "https_443"
	} else if protocol == "http" {
		serverName = fmt.Sprintf("http_%d", listenPort)
	} else if protocol == "https" {
		serverName = fmt.Sprintf("https_%d", listenPort)
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
	}

	db.DB.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)

	if caddyID != "" {
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule disabled"})
}

// Config handlers

func (h *Handlers) GetConfig(c *gin.Context) {
	var cfg models.GlobalConfig
	err := db.DB.QueryRow(`
		SELECT id, caddy_config, dns_provider, COALESCE(dns_credentials,'') as dns_credentials,
		       COALESCE(letsencrypt_email,'') as letsencrypt_email, log_level, access_log_enabled,
		       is_master, COALESCE(master_url, '') as master_url, sync_interval, 
		       last_sync, updated_at
		FROM global_config WHERE id = 1
	`).Scan(&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider, &cfg.DNSCredentials,
		&cfg.LETSEncryptEmail, &cfg.LogLevel, &cfg.AccessLogEnabled, &cfg.IsMaster, &cfg.MasterURL,
		&cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get config: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}

func (h *Handlers) GetUpstreamHealth(c *gin.Context) {
	healthStatus, err := h.caddyService.GetUpstreamHealthDetailed()
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]map[string]interface{}{}})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: healthStatus})
}

func (h *Handlers) UpdateConfig(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot update config on slave node"})
		return
	}

	var req models.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	// Update DNS credentials in environment if provided
	if req.DNSCredentials != "" {
		parts := strings.Split(req.DNSCredentials, ",")
		if len(parts) >= 2 {
			os.Setenv("DNSPOD_ID", parts[0])
			os.Setenv("DNSPOD_TOKEN", parts[1])
		}
	}

	db.DB.Exec(`
		UPDATE global_config SET
			dns_provider = COALESCE(?, dns_provider),
			dns_credentials = COALESCE(?, dns_credentials),
			letsencrypt_email = COALESCE(?, letsencrypt_email),
			log_level = COALESCE(?, log_level),
			access_log_enabled = COALESCE(?, access_log_enabled),
			is_master = COALESCE(?, is_master),
			master_url = COALESCE(?, master_url),
			sync_interval = COALESCE(?, sync_interval),
			updated_at = datetime('now')
		WHERE id = 1
	`, req.DNSProvider, req.DNSCredentials, req.LETSEncryptEmail, req.LogLevel, req.AccessLogEnabled,
		req.IsMaster, req.MasterURL, req.SyncInterval)

	// Update node mode in memory
	if req.IsMaster != nil && *req.IsMaster {
		h.nodeService.SetMode("master")
	} else if req.IsMaster != nil && !*req.IsMaster {
		h.nodeService.SetMode("slave")
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config updated"})
}

func (h *Handlers) ValidateConfig(c *gin.Context) {
	var configData map[string]interface{}
	c.ShouldBindJSON(&configData)

	// Call Caddy validate endpoint
	resp, err := http.Post(h.cfg.CaddyAdminURL+"/adapt", "application/json", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to validate config"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Config validation failed", Data: string(body)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config is valid"})
}

func (h *Handlers) ReloadCaddy(c *gin.Context) {
	h.applyCaddyConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy config reloaded"})
}

func (h *Handlers) applyCaddyConfig() {
	// Generate Caddy config from DB
	config := services.GenerateCaddyConfig(h.cfg)

	// Push to Caddy
	if err := h.caddyService.ApplyConfig(config); err != nil {
		log.Printf("Failed to apply Caddy config: %v", err)
	}
}

// applyCaddyConfigWithRollback backs up current config, applies new config, and rolls back on failure
func (h *Handlers) applyCaddyConfigWithRollback() error {
	// Backup current Caddy config before applying
	if err := h.caddyService.BackupConfig(); err != nil {
		log.Printf("Warning: Failed to backup Caddy config: %v", err)
	}

	// Generate Caddy config from DB
	config := services.GenerateCaddyConfig(h.cfg)

	configJSON, _ := json.Marshal(config)
	log.Printf("Generated Caddy config: %s", string(configJSON))

	// Push to Caddy
	if err := h.caddyService.ApplyConfig(config); err != nil {
		log.Printf("Failed to apply Caddy config: %v", err)

		// Attempt rollback
		if rollbackErr := h.caddyService.Rollback(); rollbackErr != nil {
			log.Printf("CRITICAL: Failed to rollback Caddy config: %v", rollbackErr)
			return fmt.Errorf("config apply failed and rollback also failed: %v (rollback error: %v)", err, rollbackErr)
		}

		return fmt.Errorf("config apply failed, rolled back to previous config: %v", err)
	}

	// Clear backup after successful apply
	h.caddyService.ClearBackup()
	return nil
}

func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, uniqueID string, serverName string) error {
	type requestUpstream struct {
		Host       string
		Port       int
		Weight     int
		Domain     string
		DynamicDNS bool
		Enabled    bool
		Protocol   string
	}

	type requestData struct {
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		DnsServer                     string
		DnsTTL                        int
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSHTTPRedirect               bool
		TLSHSTS                       int
		TLSEmail                      string
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
		Upstreams                     []requestUpstream
	}

	var data requestData
	var upstreams []requestUpstream

	switch r := req.(type) {
	case models.CreateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsTTL = r.DnsTTL
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.TLSHSTS = r.TLSHSTS
		data.TLSEmail = r.TLSEmail
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight, Domain: u.Domain,
				DynamicDNS: u.DynamicDNS, Enabled: u.Enabled, Protocol: u.Protocol,
			})
		}
		data.Upstreams = upstreams
	case models.UpdateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsTTL = r.DnsTTL
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.TLSHSTS = r.TLSHSTS
		data.TLSEmail = r.TLSEmail
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight, Domain: u.Domain,
				DynamicDNS: u.DynamicDNS, Enabled: u.Enabled, Protocol: u.Protocol,
			})
		}
		data.Upstreams = upstreams
	default:
		return nil
	}

	if data.Strategy == "" {
		data.Strategy = "round_robin"
	}
	if data.HealthCheckInterval == 0 {
		data.HealthCheckInterval = 10
	}
	if data.HealthCheckTimeout == 0 {
		data.HealthCheckTimeout = 5
	}
	if data.HealthCheckUnhealthyThreshold == 0 {
		data.HealthCheckUnhealthyThreshold = 3
	}
	if data.HealthCheckHealthyThreshold == 0 {
		data.HealthCheckHealthyThreshold = 2
	}
	if data.CompressTypes == "" {
		data.CompressTypes = "gzip"
	}

	if data.Protocol != "http" && data.Protocol != "https" && data.Protocol != "tcp" {
		return fmt.Errorf("invalid protocol: must be http, https, or tcp")
	}

	if data.ListenPort < 1 || data.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: must be between 1 and 65535")
	}

	validStrategies := map[string]bool{
		"round_robin": true, "ip_hash": true, "least_conn": true,
		"random": true, "first": true, "least_time": true,
	}
	if !validStrategies[data.Strategy] {
		return fmt.Errorf("invalid strategy: must be round_robin, ip_hash, least_conn, random, first, or least_time")
	}

	if data.Domain != "" && (data.Protocol == "http" || data.Protocol == "https") {
		domains := strings.Split(data.Domain, ",")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if !isValidDomain(d) {
				return fmt.Errorf("invalid domain format: '%s'", d)
			}
		}
	}

	if len(data.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	enabledUpstreamCount := 0
	hostPortSeen := make(map[string]bool)
	for i, u := range data.Upstreams {
		if u.Host == "" {
			return fmt.Errorf("upstream #%d: host is required", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("upstream #%d: invalid port %d (must be 1-65535)", i+1, u.Port)
		}
		if u.Weight < 0 {
			return fmt.Errorf("upstream #%d: weight cannot be negative", i+1)
		}

		key := fmt.Sprintf("%s:%d", u.Host, u.Port)
		if hostPortSeen[key] {
			return fmt.Errorf("upstream %s:%d is duplicated", u.Host, u.Port)
		}
		hostPortSeen[key] = true

		if !isValidHost(u.Host) {
			return fmt.Errorf("upstream #%d: invalid host '%s'", i+1, u.Host)
		}

		if u.Enabled {
			enabledUpstreamCount++
		}
	}

	if enabledUpstreamCount == 0 {
		return fmt.Errorf("at least one enabled upstream is required")
	}

	if data.EnableTLS && data.TLSEmail != "" {
		if !strings.Contains(data.TLSEmail, "@") {
			return fmt.Errorf("invalid TLS email format")
		}
	}

	if data.TLSHSTS < 0 {
		return fmt.Errorf("invalid TLS HSTS value: must be >= 0")
	}

	if data.HealthCheckInterval < 1 {
		return fmt.Errorf("health check interval must be >= 1 second")
	}

	if data.HealthCheckTimeout < 1 {
		return fmt.Errorf("health check timeout must be >= 1 second")
	}

	tempCaddyID := "validate_" + uniqueID

	ruleConfig := services.SingleRuleConfig{
		Protocol:                data.Protocol,
		Domain:                  data.Domain,
		ListenPort:              data.ListenPort,
		Strategy:                data.Strategy,
		DynamicDNS:              data.DynamicDNS,
		DnsServer:               data.DnsServer,
		DnsTTL:                  data.DnsTTL,
		DnsFamily:               data.DnsFamily,
		HealthCheckPath:         data.HealthCheckPath,
		HealthCheckInterval:     data.HealthCheckInterval,
		HealthCheckTimeout:      data.HealthCheckTimeout,
		EnableTLS:               data.EnableTLS,
		TLSHTTPRedirect:         data.TLSHTTPRedirect,
		TLSHSTS:                 data.TLSHSTS,
		EnableCompress:          data.EnableCompress,
		CompressTypes:           data.CompressTypes,
		EnableActiveHealthCheck: data.EnableActiveHealthCheck,
		HostHeader:              data.HostHeader,
		CaddyID:                 tempCaddyID,
	}

	for _, u := range data.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			protocol = "http"
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	routeConfig, routeErr := services.GenerateRouteObject(ruleConfig)
	if routeErr != nil {
		return fmt.Errorf("route config generation failed: %v", routeErr)
	}
	if mergeErr := h.caddyService.ValidateRouteMergedConfig(serverName, routeConfig, uniqueID+"_merge"); mergeErr != nil {
		return fmt.Errorf("Caddy configuration validation failed: %v", mergeErr)
	}

	if delErr := h.caddyService.DeleteRouteByID(serverName, tempCaddyID); delErr != nil {
		log.Printf("Warning: failed to delete validation temp route %s: %v (continuing anyway)", tempCaddyID, delErr)
	}

	return nil
}

func (h *Handlers) ApplyConfigOnStartup() error {
	// Wait for Caddy to be ready (up to 10 seconds)
	maxRetries := 20
	retryDelay := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://localhost:2019/config/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				break
			}
		}
		time.Sleep(retryDelay)
	}

	rows, err := db.DB.Query(`SELECT caddy_id FROM lb_rules WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var caddyID string
		if err := rows.Scan(&caddyID); err != nil {
			continue
		}
		count++
	}

	log.Printf("Applying Caddy config on startup (enabled rules: %d)", count)
	h.applyCaddyConfig()

	return nil
}

// Metrics handlers

func (h *Handlers) GetMetricsOverview(c *gin.Context) {
	overview := h.metricsService.GetOverview()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: overview})
}

func (h *Handlers) GetRuleMetrics(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var totalRequests, requests2xx, requests3xx, requests4xx, requests5xx int64
	var bytesIn, bytesOut int64

	db.DB.QueryRow(`
		SELECT COALESCE(SUM(requests_total), 0), COALESCE(SUM(requests_2xx), 0),
		       COALESCE(SUM(requests_3xx), 0), COALESCE(SUM(requests_4xx), 0),
		       COALESCE(SUM(requests_5xx), 0), COALESCE(SUM(bytes_in), 0),
		       COALESCE(SUM(bytes_out), 0)
		FROM metrics_history 
		WHERE rule_id = ? AND timestamp > datetime('now', '-1 hour')
	`, caddyID).Scan(&totalRequests, &requests2xx, &requests3xx, &requests4xx, &requests5xx, &bytesIn, &bytesOut)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"total_requests": totalRequests,
		"status_2xx":     requests2xx,
		"status_3xx":     requests3xx,
		"status_4xx":     requests4xx,
		"status_5xx":     requests5xx,
		"bytes_in":       bytesIn,
		"bytes_out":      bytesOut,
	}})
}

func (h *Handlers) GetMetricsHistory(c *gin.Context) {
	ruleID := c.Query("rule_id")
	interval := c.DefaultQuery("interval", "1h")

	var rows *sql.Rows
	var err error

	if ruleID != "" {
		rows, err = db.DB.Query(`
			SELECT timestamp, requests_total, requests_2xx, requests_3xx, 
			       requests_4xx, requests_5xx, bytes_in, bytes_out
			FROM metrics_history 
			WHERE rule_id = ? AND timestamp > datetime('now', '-'+?)
			ORDER BY timestamp
		`, ruleID, interval)
	} else {
		rows, err = db.DB.Query(`
			SELECT timestamp, SUM(requests_total), SUM(requests_2xx), SUM(requests_3xx), 
			       SUM(requests_4xx), SUM(requests_5xx), SUM(bytes_in), SUM(bytes_out)
			FROM metrics_history 
			WHERE timestamp > datetime('now', '-'+?)
			GROUP BY timestamp
			ORDER BY timestamp
		`, interval)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	type MetricRow struct {
		Timestamp     time.Time `json:"timestamp"`
		RequestsTotal int64     `json:"requests_total"`
		Status2xx     int64     `json:"status_2xx"`
		Status3xx     int64     `json:"status_3xx"`
		Status4xx     int64     `json:"status_4xx"`
		Status5xx     int64     `json:"status_5xx"`
		BytesIn       int64     `json:"bytes_in"`
		BytesOut      int64     `json:"bytes_out"`
	}

	var metrics []MetricRow
	for rows.Next() {
		var m MetricRow
		rows.Scan(&m.Timestamp, &m.RequestsTotal, &m.Status2xx, &m.Status3xx,
			&m.Status4xx, &m.Status5xx, &m.BytesIn, &m.BytesOut)
		metrics = append(metrics, m)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

// Node management

func (h *Handlers) RegisterNode(c *gin.Context) {
	var req models.RegisterNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	if req.Port == 0 {
		req.Port = 8000
	}

	// Get master node (first master node)
	var masterID int
	err := db.DB.QueryRow("SELECT id FROM nodes WHERE mode = 'master' AND is_approved = 1 LIMIT 1").Scan(&masterID)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "No master node available"})
		return
	}

	// Check if already registered
	var existingID int
	err = db.DB.QueryRow(`
		SELECT id FROM nodes 
		WHERE ip_address = ? AND port = ? AND master_id = ?
	`, req.IPAddress, req.Port, masterID).Scan(&existingID)

	if err == nil {
		// Already registered, just update status
		db.DB.Exec("UPDATE nodes SET status = 'pending', name = ? WHERE id = ?", req.Name, existingID)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Node re-registered", Data: gin.H{"id": existingID}})
		return
	}

	// Create new registration
	result, err := db.DB.Exec(`
		INSERT INTO nodes (name, mode, ip_address, port, master_id, status)
		VALUES (?, 'slave', ?, ?, ?, 'pending')
	`, req.Name, req.IPAddress, req.Port, masterID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to register node"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Node registered, waiting for approval", Data: gin.H{"id": id}})
}

func (h *Handlers) ListNodes(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT id, name, mode, ip_address, port, is_approved, sync_enabled,
		       sync_interval, sync_scope, status, last_seen, created_at
		FROM nodes ORDER BY id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var nodes []models.Node
	for rows.Next() {
		var n models.Node
		rows.Scan(&n.ID, &n.Name, &n.Mode, &n.IPAddress, &n.Port,
			&n.IsApproved, &n.SyncEnabled, &n.SyncInterval, &n.SyncScope,
			&n.Status, &n.LastSeen, &n.CreatedAt)
		nodes = append(nodes, n)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: nodes})
}

func (h *Handlers) ListPendingNodes(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT id, name, mode, ip_address, port, status, created_at
		FROM nodes WHERE status = 'pending' ORDER BY id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var nodes []models.Node
	for rows.Next() {
		var n models.Node
		rows.Scan(&n.ID, &n.Name, &n.Mode, &n.IPAddress, &n.Port, &n.Status, &n.CreatedAt)
		nodes = append(nodes, n)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: nodes})
}

func (h *Handlers) ApproveNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("UPDATE nodes SET is_approved = 1, status = 'online' WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Node approved"})
}

func (h *Handlers) RejectNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM nodes WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Node rejected"})
}

func (h *Handlers) DeleteNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("DELETE FROM nodes WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Node deleted"})
}

func (h *Handlers) UpdateNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var req models.UpdateNodeRequest
	c.ShouldBindJSON(&req)

	if req.Name != "" {
		db.DB.Exec("UPDATE nodes SET name = ? WHERE id = ?", req.Name, id)
	}
	if req.SyncEnabled != nil {
		db.DB.Exec("UPDATE nodes SET sync_enabled = ? WHERE id = ?", *req.SyncEnabled, id)
	}
	if req.SyncInterval != nil {
		db.DB.Exec("UPDATE nodes SET sync_interval = ? WHERE id = ?", *req.SyncInterval, id)
	}
	if req.SyncScope != "" {
		db.DB.Exec("UPDATE nodes SET sync_scope = ? WHERE id = ?", req.SyncScope, id)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Node updated"})
}

func (h *Handlers) NodeHeartbeat(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	db.DB.Exec("UPDATE nodes SET status = 'online', last_seen = datetime('now') WHERE id = ?", id)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Heartbeat received"})
}

// Sync handlers

func (h *Handlers) GetSyncStatus(c *gin.Context) {
	var lastSync sql.NullTime
	var pendingCount int

	db.DB.QueryRow("SELECT last_sync, (SELECT COUNT(*) FROM nodes WHERE status = 'pending') FROM global_config WHERE id = 1").
		Scan(&lastSync, &pendingCount)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"last_sync":     lastSync,
		"pending_nodes": pendingCount,
		"node_mode":     h.nodeService.GetMode(),
	}})
}

func (h *Handlers) GetSyncConfig(c *gin.Context) {
	// Get current config version
	var version int64
	db.DB.QueryRow("SELECT COALESCE(MAX(version), 0) FROM config_versions").Scan(&version)

	// Get all rules
	rows, _ := db.DB.Query(`
		SELECT id, COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(dns_server,''), COALESCE(dns_ttl,300),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_tls,0), COALESCE(tls_auto_cert,0), COALESCE(tls_http_redirect,0),
		       COALESCE(tls_hsts,0), enabled, created_at, updated_at
		FROM lb_rules
	`)
	defer rows.Close()

	var rules []models.LbRule
	for rows.Next() {
		var r models.LbRule
		var domain, strategy string
		var dynamicDNS, enableTLS, tlsAutoCert, tlsHTTPRedirect bool
		var tlsHSTS int
		err := rows.Scan(&r.ID, &r.CaddyID, &r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &r.DnsServer, &r.DnsTTL, &r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
			&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&enableTLS, &tlsAutoCert, &tlsHTTPRedirect,
			&tlsHSTS, &r.Enabled, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			continue
		}
		r.Domain = domain
		r.Strategy = strategy
		if r.Strategy == "" {
			r.Strategy = "round_robin"
		}
		r.DynamicDNS = dynamicDNS
		r.EnableTLS = enableTLS
		r.TLSAutoCert = tlsAutoCert
		r.TLSHTTPRedirect = tlsHTTPRedirect
		r.TLSHSTS = tlsHSTS

		// Get upstreams for this rule
		upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?`, r.CaddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
				r.Upstreams = append(r.Upstreams, u)
			}
			upstreamRows.Close()
		}

		rules = append(rules, r)
	}

	// Get global config
	var cfg models.GlobalConfig
	db.DB.QueryRow(`
		SELECT id, caddy_config, dns_provider, log_level, access_log_enabled,
		       is_master, master_url, sync_interval, last_sync, updated_at
		FROM global_config WHERE id = 1
	`).Scan(&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider, &cfg.LogLevel,
		&cfg.AccessLogEnabled, &cfg.IsMaster, &cfg.MasterURL,
		&cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	sinceVersion, _ := strconv.ParseInt(c.Query("since_version"), 10, 64)
	if sinceVersion > 0 && sinceVersion >= version {
		c.JSON(http.StatusNotModified, models.APIResponse{Code: 304, Message: "No changes"})
		return
	}

	syncData := models.SyncData{
		Version:   version + 1,
		Timestamp: time.Now(),
		Rules:     rules,
		Config:    cfg,
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: syncData})
}

func (h *Handlers) ManualSync(c *gin.Context) {
	if err := h.syncService.SyncFromMaster(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Sync completed"})
}

// Certificate handlers

func (h *Handlers) ListCertificates(c *gin.Context) {
	// Call Caddy to get certificates
	resp, err := http.Get(h.cfg.CaddyAdminURL + "/pki/ca/local")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get certificates"})
		return
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

func (h *Handlers) IssueCertificate(c *gin.Context) {
	h.applyCaddyConfig()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Certificate issuance triggered"})
}

// System handlers

func (h *Handlers) GetSystemInfo(c *gin.Context) {
	info := models.SystemInfo{
		IPAddress:     getOutboundIP(),
		Hostname:      getHostname(),
		OSInfo:        getOSInfo(),
		Kernel:        getKernel(),
		Architecture:  getArchitecture(),
		NetworkIPs:    getNetworkIPs(),
		CaddyVersion:  getCaddyVersion(),
		RunningStatus: "running",
		Uptime:        getUptime(),
		NodeMode:      h.cfg.NodeMode,
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func (h *Handlers) GetSystemMetrics(c *gin.Context) {
	metrics, err := getSystemMetrics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetRealtimeTraffic(c *gin.Context) {
	traffic, err := getRealtimeTraffic()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: traffic})
}

func (h *Handlers) GetConnectionStats(c *gin.Context) {
	stats, err := getConnectionStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: stats})
}

func (h *Handlers) GetCaddyMetrics(c *gin.Context) {
	resp, err := http.Get(h.cfg.CaddyAdminURL + "/metrics")
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: models.CaddyMetrics{}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	metrics := parsePrometheusMetrics(string(body))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetHostMetrics(c *gin.Context) {
	resp, err := http.Get(h.cfg.CaddyAdminURL + "/metrics")
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: []models.HostMetrics{}})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	metrics := parseHostMetrics(string(body))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func parsePrometheusMetrics(body string) models.CaddyMetrics {
	m := models.CaddyMetrics{}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		value, _ := strconv.ParseFloat(fields[1], 64)
		switch name {
		case "caddy_http_requests_total":
			m.RequestsTotal = int64(value)
		case "caddy_http_requests_in_flight":
			m.RequestsInFlight = int64(value)
		case "go_goroutines":
			m.Goroutines = int64(value)
		}
		if strings.Contains(name, "request_size_bytes") && !strings.Contains(name, "bucket") {
			m.BytesIn += int64(value)
		}
		if strings.Contains(name, "response_size_bytes") && !strings.Contains(name, "bucket") {
			m.BytesOut += int64(value)
		}
		if strings.HasSuffix(name, `{code="2xx"}`) {
			m.Status2xx = int64(value)
		}
		if strings.HasSuffix(name, `{code="3xx"}`) {
			m.Status3xx = int64(value)
		}
		if strings.HasSuffix(name, `{code="4xx"}`) {
			m.Status4xx = int64(value)
		}
		if strings.HasSuffix(name, `{code="5xx"}`) {
			m.Status5xx = int64(value)
		}
	}
	return m
}

func parseHostMetrics(body string) []models.HostMetrics {
	hostMap := make(map[string]*models.HostMetrics)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		value, _ := strconv.ParseFloat(fields[1], 64)

		host := extractLabel(name, "Host")
		if host == "" {
			continue
		}
		if _, ok := hostMap[host]; !ok {
			hostMap[host] = &models.HostMetrics{Host: host}
		}
		h := hostMap[host]

		switch {
		case strings.HasPrefix(name, "caddy_http_requests_total"):
			h.RequestsTotal = int64(value)
		case strings.HasPrefix(name, "caddy_http_requests_in_flight"):
			h.RequestsInFlight = int64(value)
		case strings.Contains(name, "request_size_bytes") && !strings.Contains(name, "bucket"):
			h.BytesIn += int64(value)
		case strings.Contains(name, "response_size_bytes") && !strings.Contains(name, "bucket"):
			h.BytesOut += int64(value)
		case strings.HasSuffix(name, `{code="2xx",Host="`+host+`"}`) || strings.Contains(name, `code="2xx"`) && extractLabel(name, "Host") == host:
			h.Status2xx = int64(value)
		case strings.HasSuffix(name, `{code="3xx",Host="`+host+`"}`) || strings.Contains(name, `code="3xx"`) && extractLabel(name, "Host") == host:
			h.Status3xx = int64(value)
		case strings.HasSuffix(name, `{code="4xx",Host="`+host+`"}`) || strings.Contains(name, `code="4xx"`) && extractLabel(name, "Host") == host:
			h.Status4xx = int64(value)
		case strings.HasSuffix(name, `{code="5xx",Host="`+host+`"}`) || strings.Contains(name, `code="5xx"`) && extractLabel(name, "Host") == host:
			h.Status5xx = int64(value)
		}
	}
	result := make([]models.HostMetrics, 0, len(hostMap))
	for _, h := range hostMap {
		result = append(result, *h)
	}
	return result
}

func extractLabel(metricName string, label string) string {
	idx := strings.Index(metricName, label+`="`)
	if idx == -1 {
		return ""
	}
	start := idx + len(label) + 2
	end := strings.Index(metricName[start:], `"`)
	if end == -1 {
		return ""
	}
	return metricName[start : start+end]
}

func (h *Handlers) GetCaddyStatus(c *gin.Context) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:2019/config/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"status": "running"}})
			return
		}
	}
	cmd := exec.Command("sh", "-c", "pgrep -x caddy 2>/dev/null | head -1 | xargs -I{} ps -o state= -p {} 2>/dev/null | grep -E '^[RSD]' && echo running || echo stopped")
	output, _ := cmd.Output()
	if strings.Contains(string(output), "running") {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"status": "running"}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"status": "stopped"}})
}

func (h *Handlers) GetCaddyConfig(c *gin.Context) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:2019/config/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to connect to Caddy: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy returned error status"})
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read Caddy config: " + err.Error()})
		return
	}
	var configData interface{}
	if err := json.Unmarshal(body, &configData); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to parse Caddy config: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configData})
}

func (h *Handlers) PutCaddyConfig(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request"})
		return
	}

	var configData interface{}
	if err := json.Unmarshal([]byte(req.Content), &configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid JSON config"})
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	body, err := json.Marshal(configData)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to marshal config"})
		return
	}

	resp, err := client.Post("http://localhost:2019/config/", "application/json", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to connect to Caddy: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy rejected config: " + string(respBody)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Config saved"})
}

func (h *Handlers) StartCaddy(c *gin.Context) {
	cmd := exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	time.Sleep(2 * time.Second)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy started"})
}

func (h *Handlers) StopCaddy(c *gin.Context) {
	exec.Command("sh", "-c", "kill -9 $(pgrep -x caddy) 2>/dev/null || killall -9 caddy 2>/dev/null || pkill -9 -x caddy 2>/dev/null || true").Run()
	time.Sleep(1 * time.Second)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy stopped"})
}

func (h *Handlers) RestartCaddy(c *gin.Context) {
	exec.Command("sh", "-c", "kill -9 $(pgrep -x caddy) 2>/dev/null || killall -9 caddy 2>/dev/null || pkill -9 -x caddy 2>/dev/null || true").Run()
	time.Sleep(1 * time.Second)
	cmd := exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	time.Sleep(2 * time.Second)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy restarted"})
}

func (h *Handlers) validatePort(protocol string, port int, excludeCaddyID string) error {
	adminPorts := []int{8000, 2019}
	httpReservedPorts := []int{80, 443}

	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	for _, p := range adminPorts {
		if port == p {
			return fmt.Errorf("port %d is reserved for admin", port)
		}
	}

	if protocol == "tcp" {
		for _, p := range httpReservedPorts {
			if port == p {
				return fmt.Errorf("port %d is reserved for HTTP", port)
			}
		}
	}

	return h.validatePortFromDB(protocol, port, excludeCaddyID)
}

func (h *Handlers) validatePortFromDB(protocol string, port int, excludeCaddyID string) error {
	// Check conflict with existing rules
	var count int
	if excludeCaddyID != "" {
		db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND protocol != ?", port, excludeCaddyID, protocol).Scan(&count)
	} else {
		db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND protocol != ?", port, protocol).Scan(&count)
	}

	if count > 0 {
		return fmt.Errorf("port %d is already in use by another rule with different protocol", port)
	}

	return nil
}

func (h *Handlers) validateUpstreams(upstreams []models.Upstream) error {
	if len(upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	hostPortSeen := make(map[string]bool)
	for i, u := range upstreams {
		if u.Host == "" {
			return fmt.Errorf("upstream #%d: host is required", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("upstream %s:%d: invalid port", u.Host, u.Port)
		}

		// Check for duplicate host:port
		key := fmt.Sprintf("%s:%d", u.Host, u.Port)
		if hostPortSeen[key] {
			return fmt.Errorf("upstream %s:%d is duplicated", u.Host, u.Port)
		}
		hostPortSeen[key] = true

		// Validate host format - must be valid IP or domain
		if !isValidHost(u.Host) {
			return fmt.Errorf("upstream %s:%d: invalid host format '%s' (must be IP address or domain name)", u.Host, u.Port, u.Host)
		}
	}

	return nil
}

func isValidHost(host string) bool {
	// Check if it's a valid IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return true
	}

	// Check if it's a valid domain name
	// Domain should not contain IP address-like patterns
	if len(host) > 253 {
		return false
	}

	// Basic domain validation - letters, numbers, dots, hyphens
	valid := true
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if part == "" {
			valid = false
			break
		}
		if len(part) > 63 {
			valid = false
			break
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
				valid = false
				break
			}
		}
		if !valid {
			break
		}
	}

	return valid
}

func isValidDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
		if len(part) > 63 {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
				return false
			}
		}
	}
	return true
}
