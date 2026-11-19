package notify

// email 通道适配器：net/smtp 直发（STARTTLS 自动协商；465 端口隐式 TLS）。
// SMTP 凭据读全局设置（global_config 单行列 notify_smtp_host/port/user/pass/
// from，凭据管理端点写入同列）；收件人=通道 target 的 {"email":"..."}。
// 主题=标题、正文=正文（UTF-8，主题 Q 编码、正文 base64，中文安全）。
// Send 不 panic——任何失败以错误返回给投递 Daemon 留痕。

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type emailSender struct{}

func (emailSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	var cfg struct {
		Email           string `json:"email"`
		SubjectTemplate string `json:"subject_template"`
		BodyTemplate    string `json:"body_template"`
		BodyFormat      string `json:"body_format"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("邮件通道目标解析失败: %w", err)
	}
	if cfg.Email == "" {
		return fmt.Errorf("邮件通道目标缺少 email")
	}
	host, port, user, pass, from, err := smtpSettings()
	if err != nil {
		return err
	}
	ts := msg.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	subject := msg.Title
	if cfg.SubjectTemplate != "" {
		subject = renderStyleTemplate(cfg.SubjectTemplate, msg, ts)
	}
	body := msg.Body
	if cfg.BodyTemplate != "" {
		body = renderStyleTemplate(cfg.BodyTemplate, msg, ts)
	}
	tlsEnabled, insecure := smtpTLSOptions()
	return sendSMTPMail(ctx, host, port, user, pass, from, cfg.Email, subject, body, cfg.BodyFormat == "html", tlsEnabled, insecure)
}

func (s emailSender) Test(ctx context.Context, targetJSON string) error {
	return s.Send(ctx, targetJSON, testNotificationMessage())
}

// smtpSettings 读全局 SMTP 发信凭据（notify_settings KV 表；host 空=未配置，
// fail-loud）。端口缺省 25；发件人缺省回落 SMTP 用户名。
func smtpSettings() (host, port, user, pass, from string, err error) {
	kv := GetSettings(KeySMTPHost, KeySMTPPort, KeySMTPUser, KeySMTPPass, KeySMTPFrom)
	host = kv[KeySMTPHost]
	port = kv[KeySMTPPort]
	user = kv[KeySMTPUser]
	pass = kv[KeySMTPPass]
	from = kv[KeySMTPFrom]
	if host == "" {
		return "", "", "", "", "", errors.New("SMTP 服务器未配置（全局设置→通知凭据）")
	}
	if port == "" {
		port = "25"
	}
	if from == "" {
		from = user
	}
	if from == "" {
		return "", "", "", "", "", errors.New("SMTP 发件人为空（未配置发件人与用户名）")
	}
	return host, port, user, pass, from, nil
}

const (
	smtpDialTimeout  = 10 * time.Second
	smtpTotalTimeout = 30 * time.Second
)

// sendSMTPMail 完成一次 SMTP 会话（隐式 TLS 于 465 端口；其余端口服务端
// 宣告 STARTTLS 则升级；认证仅在服务端宣告 AUTH 且已配置用户名时进行）。
func sendSMTPMail(ctx context.Context, host, port, user, pass, from, to, subject, body string, htmlBody, tlsEnabled, insecure bool) error {
	dialer := net.Dialer{Timeout: smtpDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("SMTP 连接失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpTotalTimeout))
	// TLS 由调用方传入（全局设置或测试草稿），不再内部读全局。
	if tlsEnabled && port == "465" {
		conn = tlsClient(conn, host, insecure)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()
	if tlsEnabled && port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfigFor(host, insecure)); err != nil {
				return fmt.Errorf("SMTP STARTTLS 升级失败: %w", err)
			}
		}
	}
	if user != "" {
		if ok, mechs := c.Extension("AUTH"); ok {
			// 按服务端宣告机制择优 LOGIN > PLAIN > CRAM-MD5：Office365/Outlook
			// 仅宣告 LOGIN（PLAIN 报 504 5.7.4 Unrecognized authentication type）；
			// 部分企业/老旧服务器仅宣告 CRAM-MD5（挑战响应，net/smtp 内置）。
			// 未识别机制回退 PLAIN（保持旧行为）。
			upper := strings.ToUpper(mechs)
			var auth smtp.Auth
			switch {
			case strings.Contains(upper, "LOGIN"):
				auth = loginAuth{user: user, pass: pass}
			case strings.Contains(upper, "PLAIN"):
				auth = smtp.PlainAuth("", user, pass, host)
			case strings.Contains(upper, "CRAM-MD5"):
				auth = smtp.CRAMMD5Auth(user, pass)
			default:
				auth = smtp.PlainAuth("", user, pass, host)
			}
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("SMTP 认证失败: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM 失败: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO 失败: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA 失败: %w", err)
	}
	if _, err := w.Write(buildRFC822Message(from, to, subject, body, htmlBody)); err != nil {
		return fmt.Errorf("SMTP 写入正文失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP 结束正文失败: %w", err)
	}
	return c.Quit()
}

// buildRFC822Message 组装邮件（主题 Q 编码、正文 base64 76 列折行；
// htmlBody=true 时 Content-Type text/html——日报/模板的富文本形态）。
func buildRFC822Message(from, to, subject, body string, htmlBody bool) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	ct := "text/plain"
	if htmlBody {
		ct = "text/html"
	}
	b.WriteString("Content-Type: " + ct + "; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	if enc != "" {
		b.WriteString(enc + "\r\n")
	}
	return b.Bytes()
}

// SMTPDraft 未保存的 SMTP 配置草稿（测试先于保存：用户可先验证再保存，
// 避免保存无效配置）。Pass 空=沿用已保存密码。
type SMTPDraft struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	From     string `json:"from"`
	TLS      bool   `json:"tls"`
	Insecure bool   `json:"insecure"`
}

// SmtpConnectivityTest SMTP 连通性测试：draft 非空且 Host 非空用草稿（测试
// 先于保存），否则用已保存全局凭据。testTo 空=发给自己（握手+投递验证）。
func SmtpConnectivityTest(ctx context.Context, testTo string, draft *SMTPDraft) error {
	host, port, user, pass, from, err := smtpSettings()
	tlsEnabled, insecure := smtpTLSOptions()
	if draft != nil && draft.Host != "" {
		host, port, user, from = draft.Host, draft.Port, draft.User, draft.From
		if draft.Pass != "" {
			pass = draft.Pass
		}
		tlsEnabled, insecure = draft.TLS, draft.Insecure
		if port == "" {
			port = "25"
		}
		if from == "" {
			from = user
		}
		if host == "" || from == "" {
			return errors.New("SMTP 草稿缺少服务器或发件人")
		}
	} else if err != nil {
		return err
	}
	to := testTo
	if to == "" {
		to = from
	}
	return sendSMTPMail(ctx, host, port, user, pass, from, to,
		"Lazy Balancer SMTP 测试", "这是一封 SMTP 连通性测试邮件（系统凭据页触发）。", false, tlsEnabled, insecure)
}

// loginAuth AUTH LOGIN（Office365/Outlook 等仅宣告 LOGIN 的服务器；net/smtp
// 只内置 PLAIN/CRAMMD5）。c.Auth 负责 base64 编解码，Next 收解码后的提示。
type loginAuth struct{ user, pass string }

func (a loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }
func (a loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch {
	case strings.Contains(strings.ToLower(string(from)), "username"):
		return []byte(a.user), nil
	case strings.Contains(strings.ToLower(string(from)), "password"):
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected AUTH LOGIN challenge: %q", from)
}

// smtpTLSOptions TLS 启用（缺省启用，"0"=明文）与忽略证书校验（"1"=跳过）。
func smtpTLSOptions() (enabled, insecure bool) {
	kv := GetSettings(KeySMTPTLS, KeySMTPInsecure)
	return kv[KeySMTPTLS] != "0", kv[KeySMTPInsecure] == "1"
}

// tlsConfigFor 服务器名用于证书校验；insecure=跳过校验（自签证书场景）。
func tlsConfigFor(host string, insecure bool) *tls.Config {
	return &tls.Config{ServerName: host, InsecureSkipVerify: insecure}
}

// tlsClient 在既有 TCP 连接上套隐式 TLS（465 端口形态）。
func tlsClient(conn net.Conn, host string, insecure bool) net.Conn {
	return tls.Client(conn, tlsConfigFor(host, insecure))
}

func init() { RegisterSender("email", emailSender{}) }
