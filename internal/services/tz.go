package services

import (
	"sync/atomic"
	"time"

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
	}
}

func CurrentLocation() *time.Location {
	if loc, ok := currentLocation.Load().(*time.Location); ok && loc != nil {
		return loc
	}
	return time.UTC
}
