package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// 模板作用域的读面与写面同口径。读时归一
// （notify.ParseChannelStyle）只能凭行形态识别存量日报模板——「事件键非空 +
// 无 daily_* 键 + 带 daily_mode」。写入侧必须保证新写的行不再落进这个形态，
// 否则 API 在带 daily_mode 的通道上写的事件模板会被静默归一成日报模板；
// 读面必须输出已归一的布局，否则客户端原样回写会把旧事件键带回来。

const (
	scopeLegacyDailyStyle = `{"daily_mode":"template","payload_template":"{\"requests\": {{requests}}}"}`
	scopeDailyPayloadTpl  = `{"requests": {{requests}}}`
)

func newChannelScopeRouter(t *testing.T) *gin.Engine {
	h := newBackupTestHandlers(t)
	r := newNotificationChannelsRouter(h, 7, "user")
	r.POST("/notification/channels", h.CreateNotificationChannel)
	return r
}

func seedScopeChannel(t *testing.T, style string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, created_at, updated_at)
		VALUES (7, 'webhook', 'hook', '{"url":"https://example.com/hook"}', ?, 1, datetime('now'), datetime('now'))`, style)
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func storedScopeStyle(t *testing.T, id int64) string {
	t.Helper()
	var stored string
	if err := db.DB.QueryRow(`SELECT style_config FROM notification_channels WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatalf("read stored style: %v", err)
	}
	return stored
}

// 目标形状：带 daily_mode 的通道上经 API 写入事件模板（更新与创建两个入口）
// → 保持事件作用域。
func TestNotificationChannels_eventTemplateOnDailyModeChannelStaysEvent(t *testing.T) {
	r := newChannelScopeRouter(t)
	const eventTpl = `{"ev": {{event}}}`
	style := `{"daily_mode":"modules","payload_template":` + strconv.Quote(eventTpl) + `}`

	id := seedScopeChannel(t, `{"daily_mode":"modules"}`)
	status, out := doNotifyRequest(t, r, http.MethodPut, "/notification/channels/"+strconv.FormatInt(id, 10), `{"style_config":`+style+`}`)
	if status != http.StatusOK {
		t.Fatalf("update status=%d out=%v, want 200", status, out)
	}
	if stored := storedScopeStyle(t, id); notify.ParseChannelStyle(stored).PayloadTemplate != eventTpl {
		t.Fatalf("更新：带 daily_mode 的通道上写入的事件模板必须保持事件作用域: stored=%s", stored)
	}

	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/channels",
		`{"type":"webhook","name":"hook2","target":"{\"url\":\"https://example.com/hook2\"}","style_config":`+style+`}`)
	if status != http.StatusOK {
		t.Fatalf("create status=%d out=%v, want 200", status, out)
	}
	var stored2 string
	if err := db.DB.QueryRow(`SELECT style_config FROM notification_channels WHERE name='hook2'`).Scan(&stored2); err != nil {
		t.Fatalf("read created style: %v", err)
	}
	if notify.ParseChannelStyle(stored2).PayloadTemplate != eventTpl {
		t.Fatalf("创建：带 daily_mode 的通道上写入的事件模板必须保持事件作用域: stored=%s", stored2)
	}
}

// 回归形状：未改动的存量行被原样回写（只改名字）→ 读时归一的结论随写入落库，
// 日报模板不丢、也不再留在事件键上。
func TestUpdateNotificationChannel_unchangedLegacyDailyTemplateMigratesOnWrite(t *testing.T) {
	r := newChannelScopeRouter(t)
	id := seedScopeChannel(t, scopeLegacyDailyStyle)
	status, out := doNotifyRequest(t, r, http.MethodPut, "/notification/channels/"+strconv.FormatInt(id, 10),
		`{"name":"renamed","style_config":`+scopeLegacyDailyStyle+`}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d out=%v, want 200", status, out)
	}
	stored := storedScopeStyle(t, id)
	if s := notify.ParseChannelStyle(stored); s.DailyPayloadTemplate != scopeDailyPayloadTpl || strings.Contains(stored, `"payload_template"`) {
		t.Fatalf("原样回写的存量日报模板必须迁入日报键: stored=%s parsed=%+v", stored, s)
	}
}

// 读面同口径：列表接口对存量行直接输出新布局，且不写库。
func TestListNotificationChannels_returnsCanonicalTemplateScope(t *testing.T) {
	r := newChannelScopeRouter(t)
	id := seedScopeChannel(t, scopeLegacyDailyStyle)
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/channels", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d out=%v, want 200", status, out)
	}
	style, _ := channelByID(t, out, float64(id))["style_config"].(string)
	if !strings.Contains(style, `"daily_payload_template"`) || strings.Contains(style, `"payload_template"`) {
		t.Fatalf("列表必须输出已归一的模板作用域: %s", style)
	}
	if stored := storedScopeStyle(t, id); !strings.Contains(stored, `"payload_template"`) {
		t.Fatalf("读面归一不得写库: %s", stored)
	}
}

// 陈旧客户端形状：缓存未刷新的旧版前端仍把日报草稿写进事件键。引用日报变量
// 的模板只可能是日报模板（事件消息没有日报变量）→ 归入日报键，不得落成
// 事件模板。
func TestUpdateNotificationChannel_dailyTemplateUnderEventKeyIsDaily(t *testing.T) {
	r := newChannelScopeRouter(t)
	id := seedScopeChannel(t, `{"daily_mode":"template","daily_payload_template":"{\"old\": {{requests}}}"}`)
	const fresh = `{"new": {{requests}}}`
	status, out := doNotifyRequest(t, r, http.MethodPut, "/notification/channels/"+strconv.FormatInt(id, 10),
		`{"style_config":{"daily_mode":"template","payload_template":`+strconv.Quote(fresh)+`}}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d out=%v, want 200", status, out)
	}
	stored := storedScopeStyle(t, id)
	s := notify.ParseChannelStyle(stored)
	if s.PayloadTemplate != "" || s.DailyPayloadTemplate != fresh || strings.Contains(stored, `"payload_template"`) {
		t.Fatalf("引用日报变量的模板必须归入日报键: stored=%s parsed=%+v", stored, s)
	}
}
