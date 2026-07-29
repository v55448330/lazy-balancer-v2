package services

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

var currentLocation atomic.Value

func init() {
	currentLocation.Store(time.FixedZone("CST", 8*3600))
	go func() {
		if err := refreshLocation(); err != nil {
			log.Printf("refresh timezone: %v", err)
		}
		for range time.Tick(30 * time.Second) {
			if err := refreshLocation(); err != nil {
				log.Printf("refresh timezone: %v", err)
			}
		}
	}()
}

func refreshLocation() error {
	database := db.GetDB()
	if database == nil {
		return nil
	}
	var tz string
	if err := database.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tz); err != nil {
		return fmt.Errorf("read configured timezone: %w", err)
	}
	if _, err := ConfigureLocation(tz); err != nil {
		return fmt.Errorf("load configured timezone %q: %w", tz, err)
	}
	return nil
}

func ConfigureLocation(name string) (*time.Location, error) {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, err
	}
	currentLocation.Store(loc)
	return loc, nil
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
