package services

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

var currentLocation atomic.Value
var applicationLogLevel atomic.Int32

const (
	logLevelDebug int32 = iota
	logLevelInfo
	logLevelWarn
	logLevelError
)

var timezoneRefresh struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func init() {
	currentLocation.Store(time.FixedZone("CST", 8*3600))
	applicationLogLevel.Store(logLevelInfo)
	StartTimezoneRefresh(context.Background())
}

func StartTimezoneRefresh(ctx context.Context) <-chan struct{} {
	timezoneRefresh.Lock()
	defer timezoneRefresh.Unlock()
	if timezoneRefresh.cancel != nil {
		timezoneRefresh.cancel()
		<-timezoneRefresh.done
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	timezoneRefresh.cancel = cancel
	timezoneRefresh.done = done
	go func() {
		defer close(done)
		if err := refreshLocation(); err != nil {
			Logf("error", "refresh timezone: %v", err)
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := refreshLocation(); err != nil {
					Logf("error", "refresh timezone: %v", err)
				}
			case <-workerCtx.Done():
				return
			}
		}
	}()
	return done
}

func StopTimezoneRefresh() {
	timezoneRefresh.Lock()
	defer timezoneRefresh.Unlock()
	if timezoneRefresh.cancel == nil {
		return
	}
	timezoneRefresh.cancel()
	<-timezoneRefresh.done
	timezoneRefresh.cancel = nil
	timezoneRefresh.done = nil
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

func ConfigureLogLevel(level string) error {
	var threshold int32
	switch level {
	case "debug":
		threshold = logLevelDebug
	case "info":
		threshold = logLevelInfo
	case "warn":
		threshold = logLevelWarn
	case "error":
		threshold = logLevelError
	default:
		return fmt.Errorf("unsupported application log level %q", level)
	}
	applicationLogLevel.Store(threshold)
	if threshold == logLevelDebug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	return nil
}

func CurrentLogLevel() string {
	switch applicationLogLevel.Load() {
	case logLevelDebug:
		return "debug"
	case logLevelWarn:
		return "warn"
	case logLevelError:
		return "error"
	default:
		return "info"
	}
}

func ShouldLog(level string) bool {
	var candidate int32
	switch level {
	case "debug":
		candidate = logLevelDebug
	case "info":
		candidate = logLevelInfo
	case "warn":
		candidate = logLevelWarn
	case "error":
		candidate = logLevelError
	default:
		return false
	}
	return candidate >= applicationLogLevel.Load()
}

func Logf(level, format string, args ...any) {
	if !ShouldLog(level) {
		return
	}
	switch level {
	case "warn":
		log.Printf("WARNING: "+format, args...)
	case "error":
		log.Printf("ERROR: "+format, args...)
	default:
		log.Printf(format, args...)
	}
}

type applicationLogWriter struct {
	w io.Writer
}

func NewApplicationLogWriter(writer io.Writer) io.Writer {
	return &applicationLogWriter{w: writer}
}

func (writer *applicationLogWriter) Write(p []byte) (int, error) {
	threshold := applicationLogLevel.Load()
	if threshold <= logLevelInfo {
		return writer.w.Write(p)
	}
	line := trimLeadingASCIIWhitespace(p)
	if threshold >= logLevelError && !hasASCIIPrefixFold(line, "ERROR") {
		return len(p), nil
	}
	if threshold == logLevelWarn && !hasASCIIPrefixFold(line, "WARN") && !hasASCIIPrefixFold(line, "ERROR") {
		return len(p), nil
	}
	written, err := writer.w.Write(p)
	if err != nil {
		return written, err
	}
	return len(p), nil
}

func trimLeadingASCIIWhitespace(value []byte) []byte {
	for len(value) > 0 {
		switch value[0] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			value = value[1:]
		default:
			return value
		}
	}
	return value
}

func hasASCIIPrefixFold(value []byte, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := range len(prefix) {
		candidate := value[index]
		if candidate >= 'a' && candidate <= 'z' {
			candidate -= 'a' - 'A'
		}
		if candidate != prefix[index] {
			return false
		}
	}
	return true
}

func ApplyLogLevel() {
	level := "info"
	if db.DB != nil {
		_ = db.DB.QueryRow("SELECT COALESCE(log_level,'info') FROM global_config WHERE id=1").Scan(&level)
	}
	if err := ConfigureLogLevel(level); err != nil {
		Logf("error", "apply application log level: %v", err)
	}
}
