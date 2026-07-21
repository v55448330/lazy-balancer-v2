package services

import (
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

var currentLocation atomic.Value

func init() {
	currentLocation.Store(time.FixedZone("CST", 8*3600))
	go func() {
		refreshLocation()
		for range time.Tick(30 * time.Second) {
			refreshLocation()
		}
	}()
}

func refreshLocation() {
	if db.DB == nil {
		return
	}
	var tz string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tz); err != nil {
		return
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		currentLocation.Store(loc)
		// Keep the process-local timezone in sync so time.Now() users (e.g.
		// runtime log rotation filenames) follow the configured timezone
		// without a restart.
		time.Local = loc
	}
}

func CurrentLocation() *time.Location {
	if loc, ok := currentLocation.Load().(*time.Location); ok && loc != nil {
		return loc
	}
	return time.UTC
}

func ApplyLogLevel() {
	level := "info"
	if db.DB != nil {
		_ = db.DB.QueryRow("SELECT COALESCE(log_level,'info') FROM global_config WHERE id=1").Scan(&level)
	}
	if level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
}
