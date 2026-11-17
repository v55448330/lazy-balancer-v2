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
	"time"
)

type emailSender struct{}

func (emailSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	var cfg struct {
		Email string `json:"email"`
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
	return sendSMTPMail(ctx, host, port, user, pass, from, cfg.Email, msg.Title, msg.Body)
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
func sendSMTPMail(ctx context.Context, host, port, user, pass, from, to, subject, body string) error {
	dialer := net.Dialer{Timeout: smtpDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("SMTP 连接失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpTotalTimeout))
	if port == "465" {
		conn = tlsClient(conn, host)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()
	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfigFor(host)); err != nil {
				return fmt.Errorf("SMTP STARTTLS 升级失败: %w", err)
			}
		}
	}
	if user != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
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
	if _, err := w.Write(buildRFC822Message(from, to, subject, body)); err != nil {
		return fmt.Errorf("SMTP 写入正文失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP 结束正文失败: %w", err)
	}
	return c.Quit()
}

// buildRFC822Message 组装纯文本邮件（主题 Q 编码、正文 base64，76 列折行）。
func buildRFC822Message(from, to, subject, body string) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
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

// tlsConfigFor 服务器名只用于证书校验（系统根证书，不跳过验证）。
func tlsConfigFor(host string) *tls.Config {
	return &tls.Config{ServerName: host}
}

// tlsClient 在既有 TCP 连接上套隐式 TLS（465 端口形态）。
func tlsClient(conn net.Conn, host string) net.Conn {
	return tls.Client(conn, tlsConfigFor(host))
}

func init() { RegisterSender("email", emailSender{}) }
