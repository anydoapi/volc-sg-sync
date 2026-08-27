package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	IPProviders []string `yaml:"ip_providers"`
	StateFile   string   `yaml:"state_file"`
	InventoryDB string   `yaml:"inventory_db"`
	Rules       []Rule   `yaml:"rules"`
}

type Rule struct {
	Name            string `yaml:"name"`
	Region          string `yaml:"region"`
	SecurityGroupID string `yaml:"security_group_id"`
	Protocol        string `yaml:"protocol"`
	PortStart       int64  `yaml:"port_start"`
	PortEnd         int64  `yaml:"port_end"`
	Priority        int64  `yaml:"priority"`
	Description     string `yaml:"description"`
	IPMatch         string `yaml:"ip_match,omitempty"`
	IPMatchMode     string `yaml:"ip_match_mode,omitempty"`
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	if len(cfg.IPProviders) == 0 {
		cfg.IPProviders = []string{"https://api4.ipify.org", "https://ipv4.icanhazip.com", "https://4.ident.me", "https://v4.ident.me", "https://ifconfig.me/ip"}
	}
	if cfg.StateFile == "" {
		cfg.StateFile = "volc-sg-sync-state.json"
	}
	if cfg.InventoryDB == "" {
		cfg.InventoryDB = "volc-sg-sync.db"
	}
	if len(cfg.Rules) == 0 {
		return Config{}, errors.New("至少配置一条安全组规则")
	}
	seen := map[string]struct{}{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		r.Region = strings.TrimSpace(r.Region)
		r.SecurityGroupID = strings.TrimSpace(r.SecurityGroupID)
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
		if r.Name == "" || r.Region == "" || r.SecurityGroupID == "" {
			return Config{}, fmt.Errorf("规则 %d 缺少名称、地域或安全组ID", i+1)
		}
		if _, ok := seen[r.Name]; ok {
			return Config{}, fmt.Errorf("规则名重复: %s", r.Name)
		}
		seen[r.Name] = struct{}{}
		if r.Protocol == "" {
			r.Protocol = "tcp"
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" && r.Protocol != "all" {
			return Config{}, fmt.Errorf("规则 %s 协议无效", r.Name)
		}
		if r.Protocol == "icmp" || r.Protocol == "all" {
			r.PortStart, r.PortEnd = -1, -1
		}
		if r.PortStart < -1 || r.PortEnd < -1 || r.PortStart > 65535 || r.PortEnd > 65535 || r.PortStart > r.PortEnd {
			return Config{}, fmt.Errorf("规则 %s 端口范围无效", r.Name)
		}
		if r.Priority == 0 {
			r.Priority = 1
		}
		if r.Description == "" {
			r.Description = "company dynamic public IP"
		}
		r.IPMatch = strings.TrimSpace(r.IPMatch)
		r.IPMatchMode = strings.ToLower(strings.TrimSpace(r.IPMatchMode))
		if r.IPMatchMode == "" {
			r.IPMatchMode = "contains"
		}
		if r.IPMatchMode != "contains" && r.IPMatchMode != "exact" && r.IPMatchMode != "cidr" && r.IPMatchMode != "prefix" {
			return Config{}, fmt.Errorf("规则 %s IP 匹配方式无效", r.Name)
		}
	}
	for i, raw := range cfg.IPProviders {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return Config{}, fmt.Errorf("公网 IP 查询源 %d 必须是不带凭据的 HTTPS URL", i+1)
		}
	}
	return cfg, nil
}

func CIDR(ip string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", errors.New("公网 IP 格式无效")
	}
	if parsed.To4() != nil {
		return parsed.String() + "/32", nil
	}
	return parsed.String() + "/128", nil
}
