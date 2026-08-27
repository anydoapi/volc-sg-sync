package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anydoapi/volc-sg-sync/internal/config"
	"github.com/anydoapi/volc-sg-sync/internal/inventory"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

const managedPrefix = "volc-sg-sync-"
const legacyManagedPrefix = "volc-sg-sync:"

func managedRuleDescription(name string) string { return managedPrefix + name }
func isManagedRuleDescription(description, name string) bool {
	return description == managedRuleDescription(name) || description == legacyManagedPrefix+name
}

type State struct {
	Rules     map[string]string `json:"rules"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type Permission struct {
	CidrIP                 string
	Protocol               string
	PortStart, PortEnd     int64
	Priority               int64
	Description, Direction string
}

type Cloud interface {
	Permissions(ctx context.Context, rule config.Rule) ([]Permission, error)
	Add(ctx context.Context, rule config.Rule, cidr string) error
	Remove(ctx context.Context, rule config.Rule, permission Permission) error
}

type CloudRuleEditor interface {
	AddPermission(ctx context.Context, rule config.Rule, permission Permission) error
	RemovePermission(ctx context.Context, rule config.Rule, permission Permission) error
}

// CloudRuleModifier is optional. Volcengine currently supports in-place
// description updates, while CIDR changes still need the safe fallback below.
type CloudRuleModifier interface {
	ModifyPermission(ctx context.Context, rule config.Rule, old Permission, next Permission) error
}

var errRuleModifyUnsupported = errors.New("云端不支持该规则的原地修改")

// replaceCloudPermission prefers a native in-place update. When the provider
// cannot modify the requested fields, it falls back to add-before-revoke so a
// failed request never removes the old access rule first.
func replaceCloudPermission(ctx context.Context, cloud Cloud, rule config.Rule, old, next Permission) (string, error) {
	editor, ok := cloud.(CloudRuleEditor)
	if !ok {
		return "", errors.New("云端规则编辑不可用")
	}
	if modifier, ok := cloud.(CloudRuleModifier); ok {
		if err := modifier.ModifyPermission(ctx, rule, old, next); err == nil {
			return "modified", nil
		} else if !errors.Is(err, errRuleModifyUnsupported) {
			return "modified", err
		}
	}
	if err := editor.AddPermission(ctx, rule, next); err != nil {
		return "add", err
	}
	if err := editor.RemovePermission(ctx, rule, old); err != nil {
		return "add-revoke", err
	}
	return "add-revoke", nil
}

type volcCloud struct{ clients map[string]*vpc.VPC }

func newVolcCloud() (*volcCloud, error) {
	return &volcCloud{clients: map[string]*vpc.VPC{}}, nil
}
func (c *volcCloud) client(region string) (*vpc.VPC, error) {
	ak, sk := os.Getenv("VOLCENGINE_ACCESS_KEY_ID"), os.Getenv("VOLCENGINE_SECRET_ACCESS_KEY")
	if ak == "" || sk == "" {
		return nil, errors.New("缺少火山云 Access Key ID 或 Secret Access Key，请在 Web 设置中填写")
	}
	if v := c.clients[region]; v != nil {
		return v, nil
	}
	cfg := volcengine.NewConfig().WithRegion(region).WithCredentials(credentials.NewStaticCredentials(ak, sk, ""))
	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, err
	}
	v := vpc.New(sess)
	c.clients[region] = v
	return v, nil
}
func (c *volcCloud) Permissions(ctx context.Context, rule config.Rule) ([]Permission, error) {
	svc, err := c.client(rule.Region)
	if err != nil {
		return nil, err
	}
	out, err := svc.DescribeSecurityGroupAttributesWithContext(ctx, &vpc.DescribeSecurityGroupAttributesInput{SecurityGroupId: volcengine.String(rule.SecurityGroupID)})
	if err != nil {
		return nil, err
	}
	var permissions []Permission
	for _, p := range out.Permissions {
		if p == nil {
			continue
		}
		permissions = append(permissions, Permission{CidrIP: volcengine.StringValue(p.CidrIp), Protocol: volcengine.StringValue(p.Protocol), PortStart: volcengine.Int64Value(p.PortStart), PortEnd: volcengine.Int64Value(p.PortEnd), Priority: volcengine.Int64Value(p.Priority), Description: volcengine.StringValue(p.Description), Direction: volcengine.StringValue(p.Direction)})
	}
	return permissions, nil
}
func (c *volcCloud) Add(ctx context.Context, rule config.Rule, cidr string) error {
	svc, err := c.client(rule.Region)
	if err != nil {
		return err
	}
	_, err = svc.AuthorizeSecurityGroupIngressWithContext(ctx, &vpc.AuthorizeSecurityGroupIngressInput{CidrIp: volcengine.String(cidr), Description: volcengine.String(managedRuleDescription(rule.Name)), Policy: volcengine.String("accept"), PortStart: volcengine.Int64(rule.PortStart), PortEnd: volcengine.Int64(rule.PortEnd), Priority: volcengine.Int64(rule.Priority), Protocol: volcengine.String(rule.Protocol), SecurityGroupId: volcengine.String(rule.SecurityGroupID)})
	return err
}

func (c *volcCloud) AddPermission(ctx context.Context, rule config.Rule, p Permission) error {
	if p.Direction != "" && p.Direction != "ingress" {
		return errors.New("当前仅允许编辑入方向规则")
	}
	svc, err := c.client(rule.Region)
	if err != nil {
		return err
	}
	_, err = svc.AuthorizeSecurityGroupIngressWithContext(ctx, &vpc.AuthorizeSecurityGroupIngressInput{CidrIp: volcengine.String(p.CidrIP), Description: volcengine.String(p.Description), Policy: volcengine.String("accept"), PortStart: volcengine.Int64(p.PortStart), PortEnd: volcengine.Int64(p.PortEnd), Priority: volcengine.Int64(p.Priority), Protocol: volcengine.String(p.Protocol), SecurityGroupId: volcengine.String(rule.SecurityGroupID)})
	return err
}
func (c *volcCloud) RemovePermission(ctx context.Context, rule config.Rule, p Permission) error {
	return c.Remove(ctx, rule, p)
}

func (c *volcCloud) ModifyPermission(ctx context.Context, rule config.Rule, old, next Permission) error {
	if old.Direction != "" && old.Direction != "ingress" || next.Direction != "" && next.Direction != "ingress" {
		return errors.New("当前仅允许编辑入方向规则")
	}
	// Volcengine exposes a description-only update operation. CIDR, protocol,
	// ports, and priority still require the safe add-before-revoke fallback.
	if old.CidrIP != next.CidrIP || old.Protocol != next.Protocol || old.PortStart != next.PortStart || old.PortEnd != next.PortEnd || old.Priority != next.Priority {
		return errRuleModifyUnsupported
	}
	if old.Description == next.Description {
		return nil
	}
	svc, err := c.client(rule.Region)
	if err != nil {
		return err
	}
	_, err = svc.ModifySecurityGroupRuleDescriptionsIngressWithContext(ctx, &vpc.ModifySecurityGroupRuleDescriptionsIngressInput{
		CidrIp:          volcengine.String(old.CidrIP),
		Description:     volcengine.String(next.Description),
		Policy:          volcengine.String("accept"),
		PortStart:       volcengine.Int64(old.PortStart),
		PortEnd:         volcengine.Int64(old.PortEnd),
		Priority:        volcengine.Int64(old.Priority),
		Protocol:        volcengine.String(old.Protocol),
		SecurityGroupId: volcengine.String(rule.SecurityGroupID),
	})
	return err
}
func (c *volcCloud) Remove(ctx context.Context, rule config.Rule, p Permission) error {
	svc, err := c.client(rule.Region)
	if err != nil {
		return err
	}
	_, err = svc.RevokeSecurityGroupIngressWithContext(ctx, &vpc.RevokeSecurityGroupIngressInput{CidrIp: volcengine.String(p.CidrIP), Policy: volcengine.String("accept"), PortStart: volcengine.Int64(p.PortStart), PortEnd: volcengine.Int64(p.PortEnd), Priority: volcengine.Int64(p.Priority), Protocol: volcengine.String(p.Protocol), SecurityGroupId: volcengine.String(rule.SecurityGroupID)})
	return err
}

func currentIP(ctx context.Context, providers []string) (string, error) {
	if len(providers) < 2 {
		return "", errors.New("至少需要两个公网 IP 查询源")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	var successes int
	var errs []string
	counts := map[string]int{}
	for _, endpoint := range providers {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if readErr != nil {
			errs = append(errs, readErr.Error())
			continue
		}
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Sprintf("%s 返回 HTTP %d", endpoint, resp.StatusCode))
			continue
		}
		cidr, cidrErr := parsePublicIP(body)
		if cidrErr != nil {
			errs = append(errs, cidrErr.Error())
			continue
		}
		successes++
		counts[cidr]++
	}
	best, bestCount := "", 0
	for cidr, count := range counts {
		if count > bestCount {
			best, bestCount = cidr, count
		}
	}
	if successes < 2 || bestCount < 2 {
		return "", fmt.Errorf("至少需要两个公网 IP 查询源返回一致结果，成功 %d: %s", successes, strings.Join(errs, "; "))
	}
	return best, nil
}

func parsePublicIP(body []byte) (string, error) {
	value := strings.TrimSpace(string(body))
	if cidr, err := config.CIDR(value); err == nil {
		return cidr, nil
	}
	var payload map[string]any
	if json.Unmarshal(body, &payload) == nil {
		for _, key := range []string{"ip", "origin", "address"} {
			if raw, ok := payload[key].(string); ok {
				for _, candidate := range strings.Split(raw, ",") {
					if cidr, err := config.CIDR(strings.TrimSpace(candidate)); err == nil {
						return cidr, nil
					}
				}
			}
		}
	}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ',' || r == ':' || r == '"'
	}) {
		if cidr, err := config.CIDR(strings.Trim(token, "[]{}()")); err == nil {
			return cidr, nil
		}
	}
	return "", errors.New("公网 IP 响应格式无效")
}

func loadState(path string) (State, error) {
	var s State
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{Rules: map[string]string{}}, nil
	}
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	if s.Rules == nil {
		s.Rules = map[string]string{}
	}
	return s, nil
}
func saveState(path string, s State) error {
	s.UpdatedAt = time.Now().UTC()
	raw, _ := json.MarshalIndent(s, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func run(ctx context.Context, cfg config.Config, cloud Cloud, dry bool) error {
	managed, err := managedConfig(cfg)
	if err != nil {
		return err
	}
	cfg = managed
	state, err := loadState(cfg.StateFile)
	if err != nil {
		return err
	}
	var audit *inventory.Store
	if cfg.InventoryDB != "" {
		audit, err = inventory.Open(cfg.InventoryDB)
		if err != nil {
			return fmt.Errorf("打开资产规则库: %w", err)
		}
		defer audit.Close()
	}
	ip, err := currentIP(ctx, cfg.IPProviders)
	if err != nil {
		return err
	}
	log.Printf("当前公网地址 %s", ip)
	previousIP := ""
	if audit != nil {
		previousIP, _ = audit.LastPublicIP()
		if len(cfg.Rules) == 0 && previousIP != "" && previousIP != ip {
			history, _ := audit.PublicIPHistory()
			if len(history) == 0 {
				history = append(history, previousIP)
			}
			cfg.Rules = autoRulesFromInventory(audit, history)
			log.Printf("未配置同步目标，按出口 IP 前缀自动发现 %d 条规则", len(cfg.Rules))
		}
		if err := audit.RecordPublicIP(ip); err != nil {
			return err
		}
	}
	for _, r := range cfg.Rules {
		old := state.Rules[r.Name]
		perms, err := cloud.Permissions(ctx, r)
		if err != nil {
			return fmt.Errorf("读取规则 %s: %w", r.Name, err)
		}
		hasCurrent := false
		for _, p := range perms {
			if p.Direction == "ingress" && p.CidrIP == ip && p.Protocol == r.Protocol && p.PortStart == r.PortStart && p.PortEnd == r.PortEnd && (isManagedRuleDescription(p.Description, r.Name) || old == ip) {
				hasCurrent = true
			}
		}
		if dry {
			log.Printf("DRY-RUN %s: state=%s target=%s cloud_current=%t", r.Name, old, ip, hasCurrent)
			continue
		}
		if !hasCurrent {
			if err := cloud.Add(ctx, r, ip); err != nil {
				if audit != nil {
					_ = audit.Event(r.Name, "add", r.SecurityGroupID, old, ip, false, err.Error())
				}
				return fmt.Errorf("新增规则 %s: %w", r.Name, err)
			}
			if audit != nil {
				_ = audit.Event(r.Name, "add", r.SecurityGroupID, old, ip, true, "")
			}
		}
		for _, p := range perms {
			managed := isManagedRuleDescription(p.Description, r.Name)
			sameShape := p.Protocol == r.Protocol && p.PortStart == r.PortStart && p.PortEnd == r.PortEnd
			if p.Direction == "ingress" && p.CidrIP != ip && (managed || (sameShape && (p.CidrIP == old || (r.IPMatch != "" && cidrMatchesSelector(p.CidrIP, r.IPMatch, r.IPMatchMode))))) {
				// The selector chooses the rule on its first run; afterwards follow
				// the last recorded address so a changed IP keeps being replaced.
				if p.CidrIP != old && !cidrMatchesSelector(p.CidrIP, r.IPMatch, r.IPMatchMode) {
					continue
				}
				if err := cloud.Remove(ctx, r, p); err != nil {
					if audit != nil {
						_ = audit.Event(r.Name, "remove", r.SecurityGroupID, p.CidrIP, ip, false, err.Error())
					}
					return fmt.Errorf("删除旧规则 %s: %w", r.Name, err)
				}
				if audit != nil {
					_ = audit.Event(r.Name, "remove", r.SecurityGroupID, p.CidrIP, ip, true, "")
				}
			}
		}
		state.Rules[r.Name] = ip
		if hasCurrent && old == ip {
			log.Printf("规则 %s 无变化", r.Name)
		} else {
			log.Printf("已对账规则 %s: %s -> %s", r.Name, old, ip)
		}
	}
	if !dry {
		return saveState(cfg.StateFile, state)
	}
	return nil
}

func autoRulesFromInventory(store *inventory.Store, history []string) []config.Rule {
	snapshot, err := store.ActiveSnapshot()
	if err != nil {
		return nil
	}
	prefixes := map[string]bool{}
	for _, previousCIDR := range history {
		ip, _, err := net.ParseCIDR(previousCIDR)
		if err != nil || ip == nil || ip.To4() == nil {
			continue
		}
		octets := strings.Split(ip.To4().String(), ".")
		if len(octets) >= 2 {
			prefixes[octets[0]+"."+octets[1]+"."] = true
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	var rules []config.Rule
	for _, group := range snapshot.Groups {
		for i, r := range group.Rules {
			matched := false
			matchedPrefix := ""
			for prefix := range prefixes {
				if strings.HasPrefix(strings.TrimSpace(r.CIDR), prefix) {
					matched = true
					matchedPrefix = prefix
					break
				}
			}
			if r.Direction != "ingress" || !matched {
				continue
			}
			rules = append(rules, config.Rule{Name: fmt.Sprintf("auto-%s-%d", group.ID, i), Region: group.Region, SecurityGroupID: group.ID, Protocol: r.Protocol, PortStart: r.PortStart, PortEnd: r.PortEnd, Priority: r.Priority, Description: r.Description, IPMatch: matchedPrefix, IPMatchMode: "prefix"})
		}
	}
	return rules
}

func cidrMatchesSelector(cidr, selector, mode string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return true
	}
	cidr = strings.TrimSpace(cidr)
	if mode == "exact" {
		if ip := net.ParseIP(selector); ip != nil {
			selector, _ = config.CIDR(selector)
		}
		return cidr == selector
	}
	if mode == "cidr" {
		_, network, err := net.ParseCIDR(selector)
		if err != nil {
			return false
		}
		ipText := cidr
		if ip, _, err := net.ParseCIDR(cidr); err == nil {
			ipText = ip.String()
		} else if ip := net.ParseIP(cidr); ip != nil {
			ipText = ip.String()
		}
		ip := net.ParseIP(ipText)
		return ip != nil && network.Contains(ip)
	}
	if mode == "prefix" {
		return strings.HasPrefix(cidr, selector)
	}
	return strings.Contains(cidr, selector)
}

func bulkIPSelector(value string) (string, string) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err == nil {
			return value, "cidr"
		}
		return "", ""
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			p := strings.Split(ip4.String(), ".")
			return p[0] + "." + p[1] + ".", "prefix"
		}
		return ip.String(), "exact"
	}
	value = strings.TrimSuffix(value, ".0.0")
	value = strings.TrimSuffix(value, ".0")
	if strings.Count(value, ".") >= 1 {
		return strings.TrimSuffix(value, ".") + ".", "prefix"
	}
	return "", ""
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	once := flag.Bool("once", false, "只同步一次后退出")
	discoverMode := flag.Bool("discover", false, "只读发现北京地域 ECS/安全组并输出 JSON")
	inventoryDB := flag.String("inventory-db", "volc-sg-sync.db", "本地资产规则库路径")
	webListen := flag.String("web-listen", "127.0.0.1:12345", "Web 控制台监听地址，留空可禁用")
	webStaticDir := flag.String("web-static-dir", "", "React Web 静态文件目录，留空使用内嵌兼容页面")
	flag.Parse()
	cloud, cloudErr := newVolcCloud()
	if *discoverMode {
		if cloudErr != nil {
			log.Fatal(cloudErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := discover(ctx, []string{"cn-beijing"}); err != nil {
			log.Fatal(err)
		}
		if summary, err := syncInventory(ctx, *inventoryDB, []string{"cn-beijing"}); err != nil {
			log.Fatal(err)
		} else {
			log.Printf("资产规则库同步完成: %s", summary)
		}
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if settings, settingsErr := loadWebSettings(settingsPath(cfg)); settingsErr == nil {
		applyWebSettings(&cfg, settings)
		if settings.WebListen != "" {
			*webListen = settings.WebListen
		}
	}
	if *webListen != "" {
		staticDir := *webStaticDir
		if staticDir == "" {
			if executable, e := os.Executable(); e == nil {
				candidate := filepath.Join(filepath.Dir(executable), "webui")
				if _, e = os.Stat(filepath.Join(candidate, "index.html")); e == nil {
					staticDir = candidate
				}
			}
		}
		startWebServer(*webListen, cfg, cloud, staticDir)
	}
	if cloudErr != nil {
		if *webListen != "" {
			log.Printf("Web 控制台已启动，但云凭据不可用: %v", cloudErr)
			select {}
		}
		log.Fatal(cloudErr)
	}
	if !*once {
		runScheduler(cfg, cloud)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	if summary, err := syncInventory(ctx, cfg.InventoryDB, regionsFromConfig(cfg)); err != nil {
		cancel()
		log.Fatal(err)
	} else {
		log.Printf("资产规则库同步完成: %s", summary)
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := run(ctx, cfg, cloud, os.Getenv("DRY_RUN") == "1"); err != nil {
		log.Fatal(err)
	}
}
