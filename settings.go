package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anydoapi/volc-sg-sync/internal/config"
)

// webSettings is deliberately separate from config.yaml. Secrets are never returned by the API.
type webSettings struct {
	AccessKeyID     string   `json:"access_key_id,omitempty"`
	SecretAccessKey string   `json:"secret_access_key,omitempty"`
	PasswordSalt    string   `json:"password_salt,omitempty"`
	PasswordHash    string   `json:"password_hash,omitempty"`
	IPProviders     []string `json:"ip_providers,omitempty"`
	Interval        string   `json:"interval,omitempty"`
	ScheduleTimes   []string `json:"schedule_times,omitempty"`
	DryRun          bool     `json:"dry_run"`
	WebListen       string   `json:"web_listen,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

func settingsPath(cfg config.Config) string { return cfg.StateFile + ".web.json" }

func loadWebSettings(path string) (webSettings, error) {
	var s webSettings
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	return s, nil
}

func saveWebSettings(path string, s webSettings) error {
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	_ = os.Chmod(path, 0600)
	return nil
}

func applyWebSettings(cfg *config.Config, s webSettings) {
	if len(s.IPProviders) > 0 {
		cfg.IPProviders = append([]string(nil), s.IPProviders...)
	}
	if s.DryRun {
		os.Setenv("DRY_RUN", "1")
	} else {
		os.Unsetenv("DRY_RUN")
	}
	if s.AccessKeyID != "" {
		os.Setenv("VOLCENGINE_ACCESS_KEY_ID", s.AccessKeyID)
	}
	if s.SecretAccessKey != "" {
		os.Setenv("VOLCENGINE_SECRET_ACCESS_KEY", s.SecretAccessKey)
	}
}

func hashPassword(password, salt string) string {
	b := []byte(salt + password)
	for i := 0; i < 120000; i++ {
		sum := sha256.Sum256(b)
		b = sum[:]
	}
	return hex.EncodeToString(b)
}

func setPassword(s *webSettings, password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		s.PasswordHash, s.PasswordSalt = "", ""
		return nil
	}
	if len(password) < 8 || len(password) > 128 {
		return errors.New("Web 密码长度必须为 8-128 位")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	s.PasswordSalt = hex.EncodeToString(b)
	s.PasswordHash = hashPassword(password, s.PasswordSalt)
	return nil
}

func verifyPassword(s webSettings, password string) bool {
	got := hashPassword(password, s.PasswordSalt)
	return s.PasswordHash != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.PasswordHash)) == 1
}

func validateSettings(s webSettings) error {
	if s.Interval != "" {
		d, err := time.ParseDuration(s.Interval)
		if err != nil || d < 30*time.Second {
			return fmt.Errorf("检测频率必须是至少 30s 的 duration")
		}
	}
	for _, raw := range s.ScheduleTimes {
		parts := strings.Split(strings.TrimSpace(raw), ":")
		if len(parts) != 2 {
			return fmt.Errorf("固定执行时间格式无效: %s", raw)
		}
		var h, m int
		if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil {
			return fmt.Errorf("固定执行时间格式无效: %s", raw)
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return fmt.Errorf("固定执行时间格式无效: %s", raw)
		}
	}
	for _, p := range s.IPProviders {
		u, err := url.Parse(strings.TrimSpace(p))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("公网 IP 查询源必须是不带凭据的 HTTPS URL")
		}
	}
	if s.WebListen == "" {
		s.WebListen = "127.0.0.1:12345"
	}
	return nil
}
