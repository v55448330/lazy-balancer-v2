package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

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

