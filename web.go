package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anydoapi/volc-sg-sync/internal/config"
	"github.com/anydoapi/volc-sg-sync/internal/inventory"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
)

type webRunState struct {
	mu        sync.RWMutex
	running   bool
	lastRun   time.Time
	lastError string
}

type webRuntime struct {
	mu       sync.RWMutex
	cfg      config.Config
	settings webSettings
	state    *webRunState
	sessions map[string]time.Time
	lastReq  map[string]time.Time
	queue    *ruleSyncQueue
}

type ruleSyncJob struct {
	ID         string            `json:"id"`
	Status     string            `json:"status"`
	Match      string            `json:"match"`
	NewCIDR    string            `json:"new_cidr"`
	Mode       string            `json:"mode"`
	QueuedAt   time.Time         `json:"queued_at"`
	StartedAt  time.Time         `json:"started_at,omitempty"`
	FinishedAt time.Time         `json:"finished_at,omitempty"`
	Matched    int               `json:"matched"`
	Replaced   int               `json:"replaced"`
	Skipped    int               `json:"skipped"`
	Failed     int               `json:"failed"`
	Error      string            `json:"error,omitempty"`
	SkipKeys   map[string]bool   `json:"-"`
	RunConfig  *config.Config    `json:"-"`
	Rules      []ruleSyncJobRule `json:"rules,omitempty"`
}

type ruleSyncJobRule struct {
	Key       string `json:"key"`
	Region    string `json:"region"`
	GroupID   string `json:"security_group_id"`
	CIDR      string `json:"cidr"`
	NewCIDR   string `json:"new_cidr"`
	Protocol  string `json:"protocol"`
	PortStart int64  `json:"port_start"`
	PortEnd   int64  `json:"port_end"`
	Priority  int64  `json:"priority"`
	Strategy  string `json:"strategy,omitempty"`
	Status    string `json:"status"`
}

func syncRuleKey(groupID string, rule inventory.Rule) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%d|%s", groupID, rule.Direction, rule.CIDR, rule.PortStart, rule.PortEnd, rule.Priority, rule.Protocol)
}

func runRuleSyncJob(rt *webRuntime, cloud Cloud, job *ruleSyncJob) {
	setJob := func(update func(*ruleSyncJob)) {
		rt.queue.mu.Lock()
		update(job)
		rt.queue.mu.Unlock()
	}
	setJob(func(j *ruleSyncJob) { j.Status = "running"; j.StartedAt = time.Now().UTC() })
	if job.RunConfig != nil {
		runFullSyncJob(rt, cloud, job)
		return
	}
	_, ok := cloud.(CloudRuleEditor)
	if !ok {
		setJob(func(j *ruleSyncJob) {
			j.Status = "failed"
			j.Error = "云端规则编辑不可用"
			j.FinishedAt = time.Now().UTC()
		})
		return
	}
	selector, mode := bulkIPSelector(job.Match)
	if job.Mode != "" {
		mode = job.Mode
	}
	rt.mu.RLock()
	dbPath := rt.cfg.InventoryDB
	rt.mu.RUnlock()
	store, err := inventory.Open(dbPath)
	if err != nil {
		setJob(func(j *ruleSyncJob) {
			j.Status = "failed"
			j.Error = "打开资产规则库失败"
			j.FinishedAt = time.Now().UTC()
		})
		return
	}
	defer store.Close()
	snapshot, err := store.ActiveSnapshot()
	if err != nil {
		setJob(func(j *ruleSyncJob) {
			j.Status = "failed"
			j.Error = "读取资产规则库失败"
			j.FinishedAt = time.Now().UTC()
		})
		return
	}
	if err := store.AddSyncTargets(autoTargetCandidates(snapshot, selector, mode)); err != nil {
		setJob(func(j *ruleSyncJob) {
			j.Status = "failed"
			j.Error = "同步规则清单保存失败"
			j.FinishedAt = time.Now().UTC()
		})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, group := range snapshot.Groups {
		for _, oldRule := range group.Rules {
			if oldRule.Direction != "ingress" || oldRule.CIDR == job.NewCIDR || !cidrMatchesSelector(oldRule.CIDR, selector, mode) {
				continue
			}
			key := syncRuleKey(group.ID, oldRule)
			setJob(func(j *ruleSyncJob) {
				j.Matched++
				j.Rules = append(j.Rules, ruleSyncJobRule{Key: key, Region: group.Region, GroupID: group.ID, CIDR: oldRule.CIDR, NewCIDR: job.NewCIDR, Protocol: oldRule.Protocol, PortStart: oldRule.PortStart, PortEnd: oldRule.PortEnd, Priority: oldRule.Priority, Status: "queued"})
			})
			if job.SkipKeys[key] {
				setJob(func(j *ruleSyncJob) {
					j.Skipped++
					j.Rules[len(j.Rules)-1].Status = "skipped"
				})
				continue
			}
			rule := config.Rule{Region: group.Region, SecurityGroupID: group.ID}
			oldPerm := Permission{Direction: oldRule.Direction, CidrIP: oldRule.CIDR, Protocol: oldRule.Protocol, PortStart: oldRule.PortStart, PortEnd: oldRule.PortEnd, Priority: oldRule.Priority, Description: oldRule.Description}
			newPerm := oldPerm
			newPerm.CidrIP = job.NewCIDR
			if isDryRun() {
				_ = store.Event(oldRule.Description, "replace", group.ID, oldRule.CIDR, job.NewCIDR, true, "dry-run，未调用云端接口")
				setJob(func(j *ruleSyncJob) { j.Replaced++ })
				continue
			}
			strategy, replaceErr := replaceCloudPermission(ctx, cloud, rule, oldPerm, newPerm)
			err = replaceErr
			setJob(func(j *ruleSyncJob) { j.Rules[len(j.Rules)-1].Strategy = strategy })
			if err != nil {
				_ = store.Event(oldRule.Description, "replace", group.ID, oldRule.CIDR, job.NewCIDR, false, redactError(err.Error()))
				setJob(func(j *ruleSyncJob) {
					j.Failed++
					j.Rules[len(j.Rules)-1].Status = "failed"
				})
				continue
			}
			_ = store.Event(oldRule.Description, "replace", group.ID, oldRule.CIDR, job.NewCIDR, true, strategy)
			setJob(func(j *ruleSyncJob) {
				j.Replaced++
				j.Rules[len(j.Rules)-1].Status = "succeeded"
			})
		}
	}
	setJob(func(j *ruleSyncJob) {
		j.Status = "succeeded"
		if j.Failed > 0 {
			j.Status = "completed_with_errors"
		}
		j.FinishedAt = time.Now().UTC()
	})
}

func runFullSyncJob(rt *webRuntime, cloud Cloud, job *ruleSyncJob) {
	setJob := func(update func(*ruleSyncJob)) {
		rt.queue.mu.Lock()
		update(job)
		rt.queue.mu.Unlock()
	}
	rt.state.mu.Lock()
	if rt.state.running {
		rt.state.mu.Unlock()
		setJob(func(j *ruleSyncJob) {
			j.Status = "failed"
			j.Error = "已有同步任务正在运行"
			j.FinishedAt = time.Now().UTC()
		})
		return
	}
	rt.state.running = true
	rt.state.lastError = ""
	rt.state.mu.Unlock()
	defer func() {
		rt.state.mu.Lock()
		rt.state.running = false
		rt.state.lastRun = time.Now().UTC()
		rt.state.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	err := error(nil)
	if _, err = syncInventory(ctx, job.RunConfig.InventoryDB, regionsFromConfig(*job.RunConfig)); err == nil {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
		err = run(ctx, *job.RunConfig, cloud, isDryRun())
	}
	cancel()
	if err != nil {
		rt.state.mu.Lock()
		rt.state.lastError = redactError(err.Error())
		rt.state.mu.Unlock()
		setJob(func(j *ruleSyncJob) {
			j.Status = "failed"
			j.Error = redactError(err.Error())
			j.FinishedAt = time.Now().UTC()
		})
		return
	}
	setJob(func(j *ruleSyncJob) {
		j.Status = "succeeded"
		j.FinishedAt = time.Now().UTC()
	})
}

type ruleSyncQueue struct {
	mu   sync.RWMutex
	jobs map[string]*ruleSyncJob
	ch   chan *ruleSyncJob
}

func newRuleSyncQueue(worker func(*ruleSyncJob)) *ruleSyncQueue {
	q := &ruleSyncQueue{jobs: map[string]*ruleSyncJob{}, ch: make(chan *ruleSyncJob, 64)}
	go func() {
		for job := range q.ch {
			worker(job)
		}
	}()
	return q
}

func (q *ruleSyncQueue) enqueue(job *ruleSyncJob) bool {
	q.mu.Lock()
	q.jobs[job.ID] = job
	q.mu.Unlock()
	select {
	case q.ch <- job:
		return true
	default:
		q.mu.Lock()
		job.Status = "failed"
		job.Error = "同步队列已满"
		job.FinishedAt = time.Now().UTC()
		q.mu.Unlock()
		return false
	}
}

func (q *ruleSyncQueue) list() []*ruleSyncJob {
	q.mu.RLock()
	defer q.mu.RUnlock()
	out := make([]*ruleSyncJob, 0, len(q.jobs))
	for _, job := range q.jobs {
		copy := *job
		copy.SkipKeys = nil
		copy.Rules = append([]ruleSyncJobRule(nil), job.Rules...)
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.Before(out[j].QueuedAt) })
	return out
}

type webStatus struct {
	Rules       map[string]string `json:"rules"`
	UpdatedAt   time.Time         `json:"updated_at"`
	RuleCount   int               `json:"rule_count"`
	Running     bool              `json:"running"`
	LastRun     time.Time         `json:"last_run"`
	LastError   string            `json:"last_error,omitempty"`
	DryRun      bool              `json:"dry_run"`
	StateFile   string            `json:"state_file"`
	InventoryDB string            `json:"inventory_db"`
}

func previousIPPrefix(cidr string) string {
	parsed, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || parsed.To4() == nil {
		return ""
	}
	octets := strings.Split(parsed.To4().String(), ".")
	if len(octets) < 2 {
		return ""
	}
	return octets[0] + "." + octets[1] + "."
}

func autoTargetCandidates(snapshot inventory.Snapshot, selector, mode string) []inventory.SyncTarget {
	if selector == "" {
		return nil
	}
	var candidates []inventory.SyncTarget
	for _, group := range snapshot.Groups {
		if isPlaceholderSecurityGroupID(group.ID) {
			continue
		}
		for index, rule := range group.Rules {
			if rule.Direction != "ingress" || !cidrMatchesSelector(rule.CIDR, selector, mode) {
				continue
			}
			candidates = append(candidates, inventory.SyncTarget{
				Name:            fmt.Sprintf("auto-%s-%d", group.ID, index),
				GroupName:       group.Name,
				Note:            rule.Description,
				Region:          group.Region,
				SecurityGroupID: group.ID,
				Protocol:        rule.Protocol,
				PortStart:       rule.PortStart,
				PortEnd:         rule.PortEnd,
				Priority:        rule.Priority,
				Enabled:         true,
				IPMatch:         selector,
				IPMatchMode:     mode,
			})
		}
	}
	return candidates
}

func newWebHandler(cfg config.Config, cloud Cloud, staticDir string) http.Handler {
	state := &webRunState{}
	settings, _ := loadWebSettings(settingsPath(cfg))
	applyWebSettings(&cfg, settings)
	rt := &webRuntime{cfg: cfg, settings: settings, state: state, sessions: map[string]time.Time{}, lastReq: map[string]time.Time{}}
	rt.queue = newRuleSyncQueue(func(job *ruleSyncJob) { runRuleSyncJob(rt, cloud, job) })
	mux := http.NewServeMux()
	if staticDir != "" {
		mux.Handle("/", staticWebHandler(staticDir))
	} else {
		mux.HandleFunc("/", webIndex)
	}
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var req struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || !verifyPassword(rt.settings, req.Password) {
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "密码错误"})
			return
		}
		sid := randomToken(32)
		rt.mu.Lock()
		rt.sessions[sid] = time.Now().Add(12 * time.Hour)
		rt.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "volc_session", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
		setCSRF(w, sid)
		writeJSON(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorizeWebRequest(rt, w, r, false) {
			return
		}
		rt.mu.RLock()
		localCfg := rt.cfg
		rt.mu.RUnlock()
		stored, err := loadState(localCfg.StateFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state.mu.RLock()
		status := webStatus{Rules: stored.Rules, UpdatedAt: stored.UpdatedAt, RuleCount: len(localCfg.Rules), Running: state.running, LastRun: state.lastRun, LastError: state.lastError, StateFile: localCfg.StateFile, InventoryDB: localCfg.InventoryDB}
		state.mu.RUnlock()
		status.DryRun = isDryRun()
		writeJSON(w, status)
	})
	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorizeWebRequest(rt, w, r, false) {
			return
		}
		writeJSON(w, rt.queue.list())
	})
	mux.HandleFunc("/api/sync-plan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorizeWebRequest(rt, w, r, false) {
			return
		}
		rt.mu.RLock()
		localCfg := rt.cfg
		rt.mu.RUnlock()
		plan := map[string]any{
			"mode":           "automatic",
			"enabled":        true,
			"interval":       rt.settings.Interval,
			"current_cidr":   "",
			"previous_cidr":  "",
			"replacement":    "",
			"rule_count":     0,
			"group_count":    0,
			"target_count":   0,
			"match":          "",
			"history":        []string{},
			"schedule_times": []string{"09:00", "18:00"},
		}
		if len(rt.settings.ScheduleTimes) > 0 {
			plan["schedule_times"] = append([]string(nil), rt.settings.ScheduleTimes...)
		}
		times := plan["schedule_times"].([]string)
		plan["next_check_at"] = time.Now().Add(sleepUntilNext(time.Now(), times, 2*time.Hour)).Format(time.RFC3339)
		if strings.TrimSpace(plan["interval"].(string)) == "" {
			plan["interval"] = "2h（默认）"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		ip, ipErr := currentIP(ctx, localCfg.IPProviders)
		cancel()
		if ipErr == nil {
			plan["current_cidr"] = ip
			plan["replacement"] = ip
		}
		store, err := inventory.Open(localCfg.InventoryDB)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer store.Close()
		if previous, err := store.LastPublicIP(); err == nil {
			plan["previous_cidr"] = previous
		}
		if history, err := store.PublicIPHistory(); err == nil {
			plan["history"] = history
		}
		targets, err := store.ListSyncTargets()
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		snapshot, err := store.ActiveSnapshot()
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		groups := map[string]bool{}
		validTargets := 0
		for _, target := range targets {
			if target.Enabled && !isPlaceholderSecurityGroupID(target.SecurityGroupID) {
				validTargets++
			}
		}
		if validTargets == 0 {
			selector := previousIPPrefix(plan["previous_cidr"].(string))
			if selector != "" {
				candidates := autoTargetCandidates(snapshot, selector, "prefix")
				if err := store.AddSyncTargets(candidates); err != nil {
					writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "自动规则清单保存失败"})
					return
				}
				targets, _ = store.ListSyncTargets()
				for _, target := range targets {
					if target.Enabled && !isPlaceholderSecurityGroupID(target.SecurityGroupID) {
						validTargets++
					}
				}
			}
		}
		if validTargets > 0 {
			plan["mode"] = "targets"
			for _, target := range targets {
				if !target.Enabled || isPlaceholderSecurityGroupID(target.SecurityGroupID) {
					continue
				}
				plan["target_count"] = plan["target_count"].(int) + 1
				groups[target.SecurityGroupID] = true
				if target.IPMatch != "" {
					plan["match"] = target.IPMatch
				}
			}
			plan["rule_count"] = plan["target_count"]
		} else {
			prefix := previousIPPrefix(plan["previous_cidr"].(string))
			plan["match"] = prefix
			for _, group := range snapshot.Groups {
				for _, rule := range group.Rules {
					if rule.Direction == "ingress" && prefix != "" && strings.HasPrefix(strings.TrimSpace(rule.CIDR), prefix) {
						plan["rule_count"] = plan["rule_count"].(int) + 1
						groups[group.ID] = true
					}
				}
			}
		}
		plan["group_count"] = len(groups)
		if ipErr != nil {
			plan["error"] = redactError(ipErr.Error())
		}
		writeJSON(w, plan)
	})
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorizeWebRequest(rt, w, r, true) {
			return
		}
		if cloud == nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "云凭据不可用，请重新运行 install.bat 设置 AK/SK"})
			return
		}
		rt.mu.RLock()
		localCfg := rt.cfg
		rt.mu.RUnlock()
		runCfg := localCfg
		var request struct {
			TargetIDs []int64 `json:"target_ids"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&request)
		}
		if len(request.TargetIDs) > 0 {
			store, err := inventory.Open(localCfg.InventoryDB)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			targets, err := store.ListSyncTargets()
			store.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			selected := map[int64]bool{}
			for _, id := range request.TargetIDs {
				selected[id] = true
			}
			runCfg.Rules = nil
			for _, target := range targets {
				if selected[target.ID] && target.Enabled && !isPlaceholderSecurityGroupID(target.SecurityGroupID) {
					runCfg.Rules = append(runCfg.Rules, config.Rule{Name: target.Name, Region: target.Region, SecurityGroupID: target.SecurityGroupID, Protocol: target.Protocol, PortStart: target.PortStart, PortEnd: target.PortEnd, Priority: target.Priority, Description: target.Note, IPMatch: target.IPMatch, IPMatchMode: target.IPMatchMode})
				}
			}
			if len(runCfg.Rules) == 0 {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "没有选中启用的同步目标"})
				return
			}
		}
		job := &ruleSyncJob{
			ID:        randomToken(12),
			Status:    "queued",
			Mode:      "full-sync",
			Match:     "手动同步",
			QueuedAt:  time.Now().UTC(),
			RunConfig: &runCfg,
		}
		if !rt.queue.enqueue(job) {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "同步队列已满"})
			return
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "queued", "job_id": job.ID})
	})
	mux.HandleFunc("/api/inventory", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorizeWebRequest(rt, w, r, false) {
			return
		}
		rt.mu.RLock()
		localCfg := rt.cfg
		rt.mu.RUnlock()
		store, err := inventory.Open(localCfg.InventoryDB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer store.Close()
		snapshot, err := store.ActiveSnapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, snapshot)
	})
	mux.HandleFunc("/api/discover", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorizeWebRequest(rt, w, r, true) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		rt.mu.RLock()
		localCfg := rt.cfg
		rt.mu.RUnlock()
		if _, err := syncInventory(ctx, localCfg.InventoryDB, regionsFromConfig(localCfg)); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"status": "discovered"})
	})
	mux.HandleFunc("/api/targets", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeWebRequest(rt, w, r, r.Method != http.MethodGet) {
			return
		}
		rt.mu.RLock()
		localCfg := rt.cfg
		rt.mu.RUnlock()
		store, err := inventory.Open(localCfg.InventoryDB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer store.Close()
		switch r.Method {
		case http.MethodGet:
			targets, err := store.ListSyncTargets()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			filtered := targets[:0]
			for _, target := range targets {
				if !isPlaceholderSecurityGroupID(target.SecurityGroupID) {
					filtered = append(filtered, target)
				}
			}
			writeJSON(w, filtered)
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			var targets []inventory.SyncTarget
			if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := store.ReplaceSyncTargets(targets); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]string{"status": "saved"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeWebRequest(rt, w, r, r.Method != http.MethodGet) {
			return
		}
		rt.mu.Lock()
		defer rt.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			interval := rt.settings.Interval
			if interval == "" {
				interval = "2h"
			}
			times := rt.settings.ScheduleTimes
			if len(times) == 0 {
				times = []string{"09:00", "18:00"}
			}
			writeJSON(w, map[string]any{"access_key_id_set": rt.settings.AccessKeyID != "" || os.Getenv("VOLCENGINE_ACCESS_KEY_ID") != "", "secret_access_key_set": rt.settings.SecretAccessKey != "" || os.Getenv("VOLCENGINE_SECRET_ACCESS_KEY") != "", "password_set": rt.settings.PasswordHash != "", "ip_providers": rt.settings.IPProviders, "interval": interval, "schedule_times": times, "dry_run": rt.settings.DryRun, "web_listen": rt.settings.WebListen})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			var req struct {
				AccessKeyID     string   `json:"access_key_id"`
				SecretAccessKey string   `json:"secret_access_key"`
				Password        string   `json:"password"`
				IPProviders     []string `json:"ip_providers"`
				Interval        string   `json:"interval"`
				ScheduleTimes   []string `json:"schedule_times"`
				DryRun          *bool    `json:"dry_run"`
				WebListen       string   `json:"web_listen"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "配置格式无效"})
				return
			}
			next := rt.settings
			hadPassword := rt.settings.PasswordHash != ""
			if req.AccessKeyID != "" {
				next.AccessKeyID = strings.TrimSpace(req.AccessKeyID)
			}
			if req.SecretAccessKey != "" {
				next.SecretAccessKey = strings.TrimSpace(req.SecretAccessKey)
			}
			if req.Password != "" {
				if err := setPassword(&next, req.Password); err != nil {
					writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
					return
				}
			}
			if req.IPProviders != nil {
				next.IPProviders = req.IPProviders
			}
			if req.Interval != "" {
				next.Interval = strings.TrimSpace(req.Interval)
			}
			if req.ScheduleTimes != nil {
				next.ScheduleTimes = req.ScheduleTimes
			}
			if req.DryRun != nil {
				next.DryRun = *req.DryRun
			}
			if req.WebListen != "" {
				next.WebListen = strings.TrimSpace(req.WebListen)
			}
			if err := validateSettings(next); err != nil {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := saveWebSettings(settingsPath(rt.cfg), next); err != nil {
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "配置保存失败"})
				return
			}
			rt.settings = next
			applyWebSettings(&rt.cfg, next)
			if vc, ok := cloud.(*volcCloud); ok {
				vc.clients = map[string]*vpc.VPC{}
			}
			if _, cookieErr := r.Cookie("volc_session"); !hadPassword && next.PasswordHash != "" && cookieErr != nil {
				sid := randomToken(32)
				rt.sessions[sid] = time.Now().Add(12 * time.Hour)
				http.SetCookie(w, &http.Cookie{Name: "volc_session", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
				setCSRF(w, sid)
			}
			writeJSON(w, map[string]string{"status": "saved"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/current-ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !authorizeWebRequest(rt, w, r, false) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		rt.mu.RLock()
		providers := append([]string(nil), rt.cfg.IPProviders...)
		dbPath := rt.cfg.InventoryDB
		rt.mu.RUnlock()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		ip, err := currentIP(ctx, providers)
		if err != nil {
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": redactError(err.Error())})
			return
		}
		if dbPath != "" {
			if store, e := inventory.Open(dbPath); e == nil {
				_ = store.RecordPublicIP(ip)
				store.Close()
			}
		}
		writeJSON(w, map[string]string{"cidr": ip})
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !authorizeWebRequest(rt, w, r, false) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		rt.mu.RLock()
		dbPath := rt.cfg.InventoryDB
		rt.mu.RUnlock()
		store, err := inventory.Open(dbPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer store.Close()
		events, err := store.ListEvents(100)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, events)
	})
	mux.HandleFunc("/api/rules/replace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !authorizeWebRequest(rt, w, r, true) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		_, ok := cloud.(CloudRuleEditor)
		if !ok {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "云端规则编辑不可用"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		var req struct {
			NewCIDR string `json:"new_cidr"`
			Rules   []struct {
				Region          string `json:"region"`
				SecurityGroupID string `json:"security_group_id"`
				Direction       string `json:"direction"`
				CIDR            string `json:"cidr"`
				Protocol        string `json:"protocol"`
				Description     string `json:"description"`
				PortStart       int64  `json:"port_start"`
				PortEnd         int64  `json:"port_end"`
				Priority        int64  `json:"priority"`
			} `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Rules) == 0 || len(req.Rules) > 100 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "替换规则数量或格式无效"})
			return
		}
		if _, _, err := net.ParseCIDR(req.NewCIDR); err != nil {
			if net.ParseIP(req.NewCIDR) != nil {
				req.NewCIDR, _ = config.CIDR(req.NewCIDR)
			} else {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "新 CIDR 无效"})
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		store, _ := inventory.Open(rt.cfg.InventoryDB)
		defer func() {
			if store != nil {
				store.Close()
			}
		}()
		success := 0
		modified := 0
		fallback := 0
		for _, x := range req.Rules {
			if x.Region == "" || x.SecurityGroupID == "" || x.Direction != "ingress" || x.CIDR == "" {
				continue
			}
			rule := config.Rule{Region: x.Region, SecurityGroupID: x.SecurityGroupID}
			old := Permission{Direction: x.Direction, CidrIP: x.CIDR, Protocol: x.Protocol, PortStart: x.PortStart, PortEnd: x.PortEnd, Priority: x.Priority, Description: x.Description}
			strategy, err := replaceCloudPermission(ctx, cloud, rule, old, Permission{Direction: x.Direction, CidrIP: req.NewCIDR, Protocol: x.Protocol, PortStart: x.PortStart, PortEnd: x.PortEnd, Priority: x.Priority, Description: x.Description})
			if err != nil {
				if store != nil {
					_ = store.Event(x.Description, "replace", x.SecurityGroupID, x.CIDR, req.NewCIDR, false, redactError(err.Error()))
				}
				continue
			}
			if store != nil {
				_ = store.Event(x.Description, "replace", x.SecurityGroupID, x.CIDR, req.NewCIDR, true, strategy)
			}
			if strategy == "modified" {
				modified++
			} else {
				fallback++
			}
			success++
		}
		writeJSON(w, map[string]any{"status": "ok", "requested": len(req.Rules), "replaced": success, "modified": modified, "add_revoke": fallback, "new_cidr": req.NewCIDR})
	})
	mux.HandleFunc("/api/rules/preview-match", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !authorizeWebRequest(rt, w, r, true) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		var req struct {
			Match string `json:"match"`
			Mode  string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Match) == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "旧 IP 或网段不能为空"})
			return
		}
		selector, mode := bulkIPSelector(req.Match)
		if req.Mode != "" {
			mode = req.Mode
		}
		if selector == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "旧 IP 或网段格式无效"})
			return
		}
		rt.mu.RLock()
		dbPath := rt.cfg.InventoryDB
		rt.mu.RUnlock()
		store, err := inventory.Open(dbPath)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "打开资产规则库失败"})
			return
		}
		defer store.Close()
		snapshot, err := store.ActiveSnapshot()
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "读取资产规则库失败"})
			return
		}
		var rules []map[string]any
		for _, group := range snapshot.Groups {
			for _, rule := range group.Rules {
				if rule.Direction == "ingress" && cidrMatchesSelector(rule.CIDR, selector, mode) {
					rules = append(rules, map[string]any{"key": syncRuleKey(group.ID, rule), "region": group.Region, "security_group_id": group.ID, "security_group_name": group.Name, "cidr": rule.CIDR, "protocol": rule.Protocol, "port_start": rule.PortStart, "port_end": rule.PortEnd, "priority": rule.Priority, "description": rule.Description})
				}
			}
		}
		writeJSON(w, map[string]any{"selector": selector, "mode": mode, "rules": rules, "count": len(rules)})
	})
	mux.HandleFunc("/api/rules/sync-by-match", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !authorizeWebRequest(rt, w, r, true) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		_, ok := cloud.(CloudRuleEditor)
		if !ok {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "云端规则编辑不可用"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		var req struct {
			Match   string   `json:"match"`
			NewCIDR string   `json:"new_cidr"`
			Mode    string   `json:"mode"`
			Skip    []string `json:"skip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Match) == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "旧 IP 或网段不能为空"})
			return
		}
		selector, mode := bulkIPSelector(req.Match)
		if selector == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "旧 IP 或网段格式无效"})
			return
		}
		if req.Mode != "" {
			mode = req.Mode
		}
		if req.NewCIDR == "" {
			rt.mu.RLock()
			providers := append([]string(nil), rt.cfg.IPProviders...)
			rt.mu.RUnlock()
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			ip, err := currentIP(ctx, providers)
			cancel()
			if err != nil {
				writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": redactError(err.Error())})
				return
			}
			req.NewCIDR = ip
		} else if _, _, err := net.ParseCIDR(req.NewCIDR); err != nil {
			if net.ParseIP(req.NewCIDR) != nil {
				req.NewCIDR, _ = config.CIDR(req.NewCIDR)
			} else {
				writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "新 IP/CIDR 格式无效"})
				return
			}
		}
		job := &ruleSyncJob{ID: randomToken(12), Status: "queued", Match: strings.TrimSpace(req.Match), Mode: mode, NewCIDR: req.NewCIDR, SkipKeys: map[string]bool{}, QueuedAt: time.Now().UTC()}
		for _, key := range req.Skip {
			if len(key) <= 256 {
				job.SkipKeys[key] = true
			}
		}
		if !rt.queue.enqueue(job) {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "同步队列已满"})
			return
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"status": "queued", "job_id": job.ID, "new_cidr": req.NewCIDR})
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeWebRequest(rt, w, r, true) {
			return
		}
		editor, ok := cloud.(CloudRuleEditor)
		if !ok {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "云端规则编辑不可用"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		var req struct {
			Region          string `json:"region"`
			SecurityGroupID string `json:"security_group_id"`
			Direction       string `json:"direction"`
			CIDR            string `json:"cidr"`
			Protocol        string `json:"protocol"`
			PortStart       int64  `json:"port_start"`
			PortEnd         int64  `json:"port_end"`
			Priority        int64  `json:"priority"`
			Description     string `json:"description"`
			OldCIDR         string `json:"old_cidr"`
			OldProtocol     string `json:"old_protocol"`
			OldPortStart    int64  `json:"old_port_start"`
			OldPortEnd      int64  `json:"old_port_end"`
			OldPriority     int64  `json:"old_priority"`
			OldDescription  string `json:"old_description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "规则格式无效"})
			return
		}
		_, _, cidrErr := net.ParseCIDR(req.CIDR)
		if req.Region == "" || req.SecurityGroupID == "" || req.Protocol == "" || cidrErr != nil || len(req.Description) > 512 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "地域、安全组、CIDR、协议或描述无效"})
			return
		}
		if req.Priority < 1 || req.Priority > 100 || req.PortStart < 0 || req.PortEnd < req.PortStart || req.PortEnd > 65535 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "端口或优先级无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		rule := config.Rule{Region: req.Region, SecurityGroupID: req.SecurityGroupID}
		p := Permission{Direction: req.Direction, CidrIP: req.CIDR, Protocol: req.Protocol, PortStart: req.PortStart, PortEnd: req.PortEnd, Priority: req.Priority, Description: req.Description}
		var err error
		strategy := ""
		if r.Method == http.MethodPost {
			err = editor.AddPermission(ctx, rule, p)
		} else if r.Method == http.MethodDelete {
			err = editor.RemovePermission(ctx, rule, p)
		} else if r.Method == http.MethodPut {
			old := p
			if req.OldCIDR != "" {
				old.CidrIP = req.OldCIDR
			}
			if req.OldProtocol != "" {
				old.Protocol = req.OldProtocol
			}
			if req.OldPortStart != 0 || req.OldPortEnd != 0 {
				old.PortStart, old.PortEnd = req.OldPortStart, req.OldPortEnd
			}
			if req.OldPriority != 0 {
				old.Priority = req.OldPriority
			}
			if req.OldDescription != "" {
				old.Description = req.OldDescription
			}
			strategy, err = replaceCloudPermission(ctx, cloud, rule, old, p)
		} else {
			writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持新增、修改或删除规则"})
			return
		}
		if err != nil {
			writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": redactError(err.Error())})
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "strategy": strategy})
	})
	mux.HandleFunc("/api/rules/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !authorizeWebRequest(rt, w, r, true) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		editor, ok := cloud.(CloudRuleEditor)
		if !ok {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "云端规则编辑不可用"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		var req struct {
			Rules []struct {
				Region          string `json:"region"`
				SecurityGroupID string `json:"security_group_id"`
				Direction       string `json:"direction"`
				CIDR            string `json:"cidr"`
				Protocol        string `json:"protocol"`
				PortStart       int64  `json:"port_start"`
				PortEnd         int64  `json:"port_end"`
				Priority        int64  `json:"priority"`
				Description     string `json:"description"`
			} `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Rules) == 0 || len(req.Rules) > 100 {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "批量规则数量或格式无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		success := 0
		for _, x := range req.Rules {
			if x.Region == "" || x.SecurityGroupID == "" || x.Direction != "ingress" {
				continue
			}
			if _, _, err := net.ParseCIDR(x.CIDR); err != nil || x.Protocol == "" || x.PortStart < 0 || x.PortEnd < x.PortStart || x.PortEnd > 65535 || x.Priority < 1 || x.Priority > 100 || len(x.Description) > 512 {
				continue
			}
			if err := editor.RemovePermission(ctx, config.Rule{Region: x.Region, SecurityGroupID: x.SecurityGroupID}, Permission{Direction: x.Direction, CidrIP: x.CIDR, Protocol: x.Protocol, PortStart: x.PortStart, PortEnd: x.PortEnd, Priority: x.Priority, Description: x.Description}); err == nil {
				success++
			}
		}
		writeJSON(w, map[string]any{"status": "ok", "requested": len(req.Rules), "deleted": success})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Cache-Control", "no-store")
		}
		if _, err := r.Cookie("volc_csrf"); err != nil {
			http.SetCookie(w, &http.Cookie{Name: "volc_csrf", Value: randomToken(16), Path: "/", SameSite: http.SameSiteStrictMode, MaxAge: 43200})
		}
		mux.ServeHTTP(w, r)
	})
}

func authorizeWebRequest(rt *webRuntime, w http.ResponseWriter, r *http.Request, mutate bool) bool {
	if mutate && !rateLimit(rt, r) {
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "请求过于频繁"})
		return false
	}
	rt.mu.RLock()
	settings := rt.settings
	rt.mu.RUnlock()
	if settings.PasswordHash != "" {
		c, _ := r.Cookie("volc_session")
		ok := false
		if c != nil {
			rt.mu.Lock()
			expiry, exists := rt.sessions[c.Value]
			if exists && expiry.After(time.Now()) {
				ok = true
			}
			rt.mu.Unlock()
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="volc-sg-sync"`)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "需要登录"})
			return false
		}
	} else if password := strings.TrimSpace(os.Getenv("WEB_PASSWORD")); password != "" {
		_, provided, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="volc-sg-sync"`)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "需要 Web 密码"})
			return false
		}
	} else {
		token := strings.TrimSpace(os.Getenv("WEB_TOKEN"))
		if token != "" {
			want := "Bearer " + token
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
				writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "需要 WEB_TOKEN"})
				return false
			}
		}
	}
	if mutate && !checkCSRF(w, r) {
		return false
	}
	return true
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
func setCSRF(w http.ResponseWriter, sid string) {
	token := randomToken(16)
	http.SetCookie(w, &http.Cookie{Name: "volc_csrf", Value: token, Path: "/", SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	_ = sid
}
func checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	c, _ := r.Cookie("volc_csrf")
	token := r.Header.Get("X-CSRF-Token")
	if c == nil || token == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) != 1 {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "CSRF 校验失败，请刷新页面"})
		return false
	}
	return true
}
func rateLimit(rt *webRuntime, r *http.Request) bool {
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	now := time.Now()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if t := rt.lastReq[ip]; now.Sub(t) < 150*time.Millisecond {
		return false
	}
	rt.lastReq[ip] = now
	return true
}

func redactError(message string) string {
	for _, key := range []string{"VOLCENGINE_ACCESS_KEY_ID", "VOLCENGINE_SECRET_ACCESS_KEY", "WEB_PASSWORD", "WEB_TOKEN"} {
		if value := os.Getenv(key); value != "" {
			message = strings.ReplaceAll(message, value, "[已隐藏]")
		}
	}
	return message
}

func startWebServer(addr string, cfg config.Config, cloud Cloud, staticDir string) {
	server := &http.Server{Addr: addr, Handler: newWebHandler(cfg, cloud, staticDir), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("Web 控制台监听 %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web 控制台停止: %v", err)
		}
	}()
}

func staticWebHandler(dir string) http.Handler {
	root := filepath.Clean(dir)
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relative := strings.TrimPrefix(filepath.Clean(filepath.FromSlash(r.URL.Path)), string(filepath.Separator))
		candidate := filepath.Join(root, relative)
		rootAbs, _ := filepath.Abs(root)
		candidateAbs, _ := filepath.Abs(candidate)
		inside := candidateAbs == rootAbs || strings.HasPrefix(candidateAbs, rootAbs+string(filepath.Separator))
		if inside && r.URL.Path == "/" || (inside && candidate != root && fileExists(candidate)) {
			files.ServeHTTP(w, r)
			return
		}
		index := filepath.Join(root, "index.html")
		if !fileExists(index) {
			webIndex(w, r)
			return
		}
		http.ServeFile(w, r, index)
	})
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isDryRun() bool { return os.Getenv("DRY_RUN") == "1" }

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	writeJSON(w, value)
}

var webPage = template.Must(template.New("index").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>火山同步控制台</title><style>
:root{font:14px -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#1f2329;background:#f5f6f8;--blue:#1664d9;--line:#e6e9ef}*{box-sizing:border-box}body{margin:0}.app{display:flex;min-height:100vh}.side{width:220px;background:#fff;border-right:1px solid var(--line);padding:16px 10px;flex:none}.brand{font-size:18px;font-weight:700;padding:12px 14px 22px;color:#172033}.brand span{color:var(--blue);font-size:12px;display:block;margin-top:4px;font-weight:400}.nav-title{font-size:12px;color:#8b95a5;padding:14px}.nav button{display:block;width:100%;text-align:left;border:0;background:transparent;padding:11px 14px;border-radius:6px;color:#4e5969;cursor:pointer;margin:2px 0}.nav button.active,.nav button:hover{background:#eaf2ff;color:var(--blue);font-weight:600}.content{flex:1;min-width:0}.topbar{height:64px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 28px}.crumb{font-size:18px;font-weight:600}.top-actions{display:flex;gap:10px;align-items:center}.avatar{width:30px;height:30px;border-radius:50%;background:#dbe8ff;color:var(--blue);display:grid;place-items:center;font-weight:700}.page{padding:24px 28px;max-width:1500px}.sub{color:#7d8796;margin:7px 0 20px}.section{display:none}.section.active{display:block}.cards{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:14px;margin-bottom:18px}.card,.panel{background:#fff;border:1px solid var(--line);border-radius:8px}.card{padding:18px 20px}.label{color:#697586;font-size:13px}.value{font-size:26px;font-weight:650;margin-top:12px}.trend{font-size:12px;color:#0b8f55;margin-top:8px}.panel{padding:20px;margin-bottom:18px}.panel-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}.panel h2{font-size:16px;margin:0}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}.toolbar .grow{flex:1;min-width:180px}button.primary{background:var(--blue);color:#fff;border:1px solid var(--blue)}button.ghost{background:#fff;color:#445166;border:1px solid #cfd6e2}button.warn{background:#fff5e8;color:#b86a00;border:1px solid #ffdca8}button{border-radius:6px;padding:8px 14px;cursor:pointer;font-size:13px}button:disabled{opacity:.5;cursor:not-allowed}input,select,textarea{border:1px solid #cfd6e2;border-radius:6px;padding:8px 10px;font:inherit;background:#fff}input:focus,select:focus,textarea:focus{outline:2px solid #cfe0ff;border-color:#76a5f1}table{width:100%;border-collapse:collapse}th{font-weight:500;color:#697586;background:#fafbfc;text-align:left}th,td{padding:12px 10px;border-bottom:1px solid var(--line);white-space:nowrap}td{color:#303846}tr:hover td{background:#fafcff}.muted{color:#8a94a4}.badge{display:inline-block;padding:3px 8px;border-radius:10px;font-size:12px;background:#eaf7ef;color:#11834d}.badge.off{background:#f1f2f4;color:#8a94a4}.msg{min-height:24px;margin-bottom:10px}.ok{color:#087443}.err{color:#b4232f}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(260px,1fr));gap:16px}.field label{display:block;color:#5c6879;font-size:13px;margin-bottom:6px}.field input,.field textarea{width:100%}.secret{font-family:monospace}.empty{text-align:center;padding:38px;color:#8a94a4}.detail{max-height:240px;overflow:auto;background:#101827;color:#d9e4ff;padding:14px;border-radius:6px;white-space:pre-wrap}.pill{padding:5px 9px;background:#f0f4fa;border-radius:5px;font-size:12px;color:#536174}.drawer{position:fixed;z-index:10;right:0;top:0;height:100vh;width:min(720px,94vw);background:#fff;box-shadow:-12px 0 35px #15233b22;transform:translateX(105%);transition:transform .2s ease;overflow:auto}.drawer.open{transform:translateX(0)}.drawer-head{height:64px;padding:0 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}.drawer-body{padding:20px}@media(max-width:900px){.side{width:68px}.brand{font-size:0;padding:16px 10px}.brand:before{content:'火';font-size:22px}.brand span,.nav-title,.nav button span{display:none}.nav button{text-align:center}.topbar{padding:0 16px}.page{padding:18px 14px}.cards{grid-template-columns:repeat(2,1fr)}.form-grid{grid-template-columns:1fr}}
</style></head><body><div class="app"><aside class="side"><div class="brand">火山同步<span>公网 IP 安全组管理</span></div><div class="nav-title">资源管理</div><nav class="nav"><button class="active" data-page="overview">◉ <span>概览</span></button><button data-page="instances">▣ <span>实例资产</span></button><button data-page="groups">◇ <span>安全组</span></button><button data-page="targets">≡ <span>同步目标</span></button></nav><div class="nav-title">系统</div><nav class="nav"><button data-page="settings">⚙ <span>控制台设置</span></button></nav></aside><div class="content"><header class="topbar"><div class="crumb" id="crumb">概览</div><div class="top-actions"><button id="loginBtn" class="ghost">登录</button><button id="sync" class="primary">立即同步</button><div class="avatar">火</div></div></header><main class="page"><div id="msg" class="msg"></div>
<section id="overview" class="section active"><h1>概览</h1><div class="sub">集中查看四台服务器、网络安全组与同步运行状态</div><div class="cards"><div class="card"><div class="label">同步目标</div><div class="value" id="count">-</div><div class="trend">已纳入管理</div></div><div class="card"><div class="label">任务状态</div><div class="value" id="running">-</div><div class="trend" id="last">尚未执行</div></div><div class="card"><div class="label">当前公网 IP</div><div class="value" id="ip">-</div><div class="trend">双源校验</div></div><div class="card"><div class="label">运行模式</div><div class="value" id="mode">安全模式</div><div class="trend">本机监听</div></div></div><div class="panel"><div class="panel-head"><h2>最近同步</h2><button class="ghost" data-page="targets">查看全部</button></div><div id="overviewTable" class="empty">加载中...</div></div></section>
<section id="instances" class="section"><h1>实例资产</h1><div class="sub">四台服务器、网卡和公网地址的统一视图</div><div class="panel"><div class="toolbar"><input id="instanceFilter" class="grow" placeholder="搜索实例名称、ID、IP"><button id="refreshInventory" class="ghost">刷新</button><button id="discover" class="primary">云端发现</button></div><div id="instanceTable" class="empty">暂无数据</div></div></section>
<section id="groups" class="section"><h1>安全组</h1><div class="sub">按地域查看安全组及入/出方向规则</div><div class="panel"><div class="toolbar"><input id="groupSearch" class="grow" placeholder="搜索安全组名称或 ID"><select id="regionFilter"><option value="">全部地域</option></select></div><div id="groupTable" class="empty">暂无数据</div></div></section>
<section id="targets" class="section"><h1>同步目标</h1><div class="sub">自动模式负责定时巡检出口 IP；手动模式按旧 IP/网段一次性替换所有匹配规则。</div><div class="panel plan-panel"><div class="panel-head"><div><h2>自动同步计划</h2><div class="muted">系统会把下方“旧值”命中的入方向规则，统一替换为当前出口 IP。</div></div><button id="refreshPlan" class="ghost">刷新计划</button></div><div id="syncPlan" class="plan-grid"><div class="empty">正在读取实际同步范围...</div></div></div><div class="panel"><div class="panel-head"><div><h2>按旧 IP / 网段立即同步</h2><div class="muted">例如输入 <b>39.181.0.0</b>，默认替换为当前出口 IP；也可以指定新的 IP/CIDR。</div></div></div><div class="toolbar"><label class="inline-label">旧 IP/网段</label><input id="globalIPMatch" class="grow" placeholder="例如 39.181.0.0 或 39.181.0.0/16"><select id="globalIPMode"><option value="contains">包含</option><option value="exact">精确</option><option value="cidr">网段</option><option value="prefix">前缀</option></select><label class="inline-label">替换为</label><input id="bulkNewIP" class="grow" placeholder="留空自动使用当前出口 IP"><button id="syncByIP" class="primary">扫描并替换</button></div><div class="toolbar muted"><span>范围：全部已发现安全组的入方向规则</span><span>支持精确 IP、CIDR、前缀模糊匹配</span></div></div><div class="panel"><div class="panel-head"><div><h2>已保存的细分目标</h2><div class="muted">只有需要单独分组、备注或停用时才需要保存目标；不保存也不影响自动模式。</div></div></div><div class="toolbar"><input id="filter" class="grow" placeholder="搜索名称 / 安全组 / 备注"><select id="groupFilter"><option value="">全部分组</option></select><button id="selectAll" class="ghost">全选当前</button><button id="save" class="primary">保存目标</button><button id="syncSelected" class="primary">同步选中</button></div><div id="targetsTable" class="empty">加载中...</div></div></section>
<section id="settings" class="section"><h1>控制台设置</h1><div class="sub">敏感信息仅写入本机受保护文件，不会回显</div><div class="panel"><div class="panel-head"><h2>火山引擎凭据</h2><span class="pill" id="configState">读取中</span></div><div class="form-grid"><div class="field"><label>Access Key ID</label><input id="ak" class="secret" type="password" placeholder="留空保持不变"></div><div class="field"><label>Secret Access Key</label><input id="sk" class="secret" type="password" placeholder="留空保持不变"></div><div class="field"><label>Web 登录密码（至少 8 位）</label><input id="pwd" type="password" placeholder="留空保持不变"></div><div class="field"><label>监听地址</label><input id="listen" value="127.0.0.1:12345"></div></div></div><div class="panel"><div class="panel-head"><h2>同步策略</h2></div><div class="form-grid"><div class="field"><label>检测频率（至少 15 分钟）</label><input id="interval" value="2h" placeholder="例如 30m"></div><div class="field"><label>固定执行时间</label><input id="times" placeholder="例如 09:00,18:00"></div><div class="field"><label>公网 IP 查询源（每行一个 HTTPS URL）</label><textarea id="providers" rows="4"></textarea></div><div class="field"><label>运行模式</label><label><input id="dry" type="checkbox"> 预演模式（不修改云端规则）</label></div></div><button id="saveConfig" class="primary">保存配置</button></div></section>
<div id="ruleDrawer" class="drawer"><div class="drawer-head"><strong id="drawerTitle">安全组规则</strong><button id="closeDrawer" class="ghost">关闭</button></div><div class="drawer-body"><div class="toolbar"><button id="addRule" class="primary">添加规则</button><input id="ruleSearch" class="grow" placeholder="筛选 CIDR、端口、描述"></div><div id="ruleTable" class="empty">请选择安全组</div><form id="ruleForm" class="form-grid" style="display:none"><div class="field"><label>CIDR</label><input id="ruleCIDR" required placeholder="例如 1.2.3.4/32"></div><div class="field"><label>协议</label><select id="ruleProtocol"><option>tcp</option><option>udp</option><option>icmp</option><option>all</option></select></div><div class="field"><label>起始端口</label><input id="rulePortStart" type="number" min="0" max="65535" value="22"></div><div class="field"><label>结束端口</label><input id="rulePortEnd" type="number" min="0" max="65535" value="22"></div><div class="field"><label>优先级</label><input id="rulePriority" type="number" min="1" max="100" value="1"></div><div class="field"><label>描述</label><input id="ruleDescription" maxlength="512"></div><div><button class="primary" type="submit">保存规则</button><button id="cancelRule" type="button" class="ghost">取消</button></div></form></div></div><section class="panel" style="margin-top:18px"><div class="panel-head"><h2>审计详情</h2><button id="assets" class="ghost">刷新</button></div><pre id="detail" class="detail">等待加载...</pre></section></main></div></div><script>
const $=id=>document.getElementById(id),msg=(s,ok=false)=>{const e=$('msg');e.textContent=s;e.className='msg '+(ok?'ok':'err')},csrf=()=>{const m=document.cookie.match(/(?:^|; )volc_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):''},api=async(url,opt={})=>{opt.headers={...(opt.headers||{}),'X-CSRF-Token':csrf()};const r=await fetch(url,opt);let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||('HTTP '+r.status));return d};let targetData=[],inventory={instances:[],groups:[]};
function table(headers,rows){const t=document.createElement('table'),h=document.createElement('tr');headers.forEach(x=>{const e=document.createElement('th');e.textContent=x;h.append(e)});t.append(h);rows.forEach(c=>{const r=document.createElement('tr');c.forEach(x=>{const e=document.createElement('td');if(x instanceof Node)e.append(x);else e.textContent=x??'';r.append(e)});t.append(r)});return t}
function renderTargets(){const box=$('targetsTable');box.replaceChildren();const q=$('filter').value.toLowerCase(),g=$('groupFilter').value,sg=$('sgFilter')?.value||'',rows=[];targetData.forEach((t,i)=>{if(g&&t.group!==g||sg&&t.security_group_id!==sg||q&&!(t.name+' '+t.security_group_id+' '+t.note+' '+(t.ip_match||'')).toLowerCase().includes(q))return;const pick=document.createElement('input');pick.type='checkbox';pick.className='pick';pick.dataset.i=i;const gi=document.createElement('input');gi.value=t.group||'';gi.dataset.i=i;gi.className='group';const ni=document.createElement('input');ni.value=t.note||'';ni.dataset.i=i;ni.className='note';const im=document.createElement('input');im.value=t.ip_match||'';im.placeholder='例如 112.10';im.dataset.i=i;im.className='ipmatch';im.oninput=()=>t.ip_match=im.value.trim();const mode=document.createElement('select');['contains','exact','cidr','prefix'].forEach(v=>mode.append(new Option({contains:'包含',exact:'精确',cidr:'网段',prefix:'前缀'}[v],v)));mode.value=t.ip_match_mode||'contains';mode.dataset.i=i;mode.className='ipmode';mode.onchange=()=>t.ip_match_mode=mode.value;const en=document.createElement('input');en.type='checkbox';en.checked=!!t.enabled;en.dataset.i=i;en.className='enabled';const badge=document.createElement('span');badge.className='badge '+(t.enabled?'':'off');badge.textContent=t.enabled?'启用':'停用';const del=document.createElement('button');del.className='warn';del.textContent='删除';del.onclick=()=>{if(!confirm('确认删除此同步目标？'))return;targetData.splice(i,1);renderTargets()};rows.push([pick,t.name,gi,t.region+' / '+t.security_group_id+' / '+t.protocol+':'+t.port_start+'-'+t.port_end,im,mode,ni,en,badge,del])});if(rows.length)box.append(table(['','名称','分组','规则','旧 IP 匹配','方式','备注','状态','','操作'],rows));else box.textContent='暂无匹配目标'}
function initTargetActions(){if(window.targetActionsReady)return;window.targetActionsReady=true;const bar=$('save').parentElement;const importBtn=document.createElement('button');importBtn.className='ghost';importBtn.textContent='从安全组导入全部规则';bar.append(importBtn);const apply=document.createElement('button');apply.className='ghost';apply.textContent='应用 IP 匹配到选中目标';bar.append(apply);importBtn.onclick=async()=>{try{await loadInventory();const existing=new Set(targetData.map(t=>t.name));let added=0;(inventory.groups||[]).forEach(g=>(g.rules||[]).forEach((r,n)=>{if(r.direction&&r.direction!=='ingress')return;const base=(g.name||g.id)+'-'+r.protocol+'-'+r.port_start+'-'+r.port_end;let name=base,i=2;while(existing.has(name))name=base+'-'+i++;existing.add(name);targetData.push({name,group:g.name||'',note:r.description||'',region:g.region,security_group_id:g.id,protocol:r.protocol,port_start:r.port_start,port_end:r.port_end,priority:r.priority||1,enabled:true,ip_match:$('globalIPMatch').value.trim(),ip_match_mode:$('globalIPMode').value});added++}));renderTargets();msg('已导入 '+added+' 条规则，请点击保存目标',true)}catch(e){msg(e.message)}};apply.onclick=()=>{const selected=[...document.querySelectorAll('.pick:checked')].map(e=>Number(e.dataset.i));const indexes=selected.length?selected:targetData.map((_,i)=>i);indexes.forEach(i=>{targetData[i].ip_match=$('globalIPMatch').value.trim();targetData[i].ip_match_mode=$('globalIPMode').value});renderTargets();msg('已应用到 '+indexes.length+' 个同步目标',true)}}
function initBulkSync(){if(!$('syncByIP'))return;$('syncByIP').onclick=async()=>{const old=$('globalIPMatch').value.trim();if(!old)return msg('请先填写旧 IP 或网段');const custom=$('bulkNewIP').value.trim();const target=custom||$('ip').textContent||'当前出口 IP';if(!confirm('将把全部安全组中匹配 '+old+' 的规则替换为 '+target+'，确认继续？'))return;const b=$('syncByIP');b.disabled=true;b.textContent='扫描并替换中...';try{const d=await api('/api/rules/sync-by-match',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({match:old,new_cidr:custom})});msg('完成：扫描 '+d.matched+' 条，成功替换 '+d.replaced+' 条为 '+d.new_cidr,true);await loadInventory();await loadSyncPlan()}catch(e){msg(e.message)}finally{b.disabled=false;b.textContent='扫描并替换'}}
function renderSyncPlan(p){const box=$('syncPlan');if(!box)return;box.replaceChildren();const vals=[['运行模式',p.mode==='targets'?'已保存目标':'自动发现'],['当前出口 IP',p.current_cidr||'检测失败'],['旧值（将被替换）',p.previous_cidr||'尚无历史 IP'],['未来替换为',p.replacement||'等待检测'],['匹配范围',p.match||'首次运行仅新增当前 IP'],['规则数量',String(p.rule_count||0)],['安全组数量',String(p.group_count||0)],['检测频率',p.interval||'未设置']];vals.forEach(([label,value])=>{const d=document.createElement('div');d.className='plan-item';Object.assign(d.style,{border:'1px solid var(--line)',borderRadius:'8px',padding:'14px',background:'#fafbfc'});const l=document.createElement('div');l.className='label';l.textContent=label;const v=document.createElement('div');v.className='plan-value';v.textContent=value;Object.assign(v.style,{fontSize:'16px',fontWeight:'650',marginTop:'7px',wordBreak:'break-word'});d.append(l,v);box.append(d)});const note=document.createElement('div');note.className='muted';note.style.gridColumn='1/-1';note.textContent=p.error?'当前出口 IP 检测失败：'+p.error:(p.previous_cidr&&p.current_cidr&&p.previous_cidr!==p.current_cidr?'检测到 IP 变化，下一次自动同步会执行旧值 → 当前出口 IP 的替换。':'当前没有 IP 变化时不会重复修改规则。');box.append(note);if($('bulkNewIP')&&!$('bulkNewIP').value&&p.current_cidr)$('bulkNewIP').placeholder='留空使用当前出口 IP（'+p.current_cidr+'）'}
async function loadSyncPlan(){try{renderSyncPlan(await api('/api/sync-plan'))}catch(e){const b=$('syncPlan');if(b)b.textContent='同步计划读取失败：'+e.message}}
function initSecurityGroupFilter(){if($('sgFilter'))return;const sg=document.createElement('select');sg.id='sgFilter';sg.append(new Option('全部安全组',''));sg.onchange=renderTargets;$('save').parentElement.insertBefore(sg,$('save'))}
async function loadTargets(){try{initTargetActions();initBulkSync();initSecurityGroupFilter();targetData=(await api('/api/targets'))||[];const groups=[...new Set(targetData.map(t=>t.group).filter(Boolean))];$('groupFilter').replaceChildren(new Option('全部分组',''),...groups.map(g=>new Option(g,g)));const sgs=[...new Set(targetData.map(t=>t.security_group_id).filter(Boolean))];$('sgFilter').replaceChildren(new Option('全部安全组',''),...sgs.map(id=>new Option(id,id)));renderTargets();renderOverview();loadSyncPlan()}catch(e){msg(e.message)}}
function renderOverview(){const rows=targetData.slice(0,6).map(t=>[t.name,t.region,t.security_group_id,t.enabled?'启用':'停用']);$('overviewTable').replaceChildren(rows.length?table(['目标','地域','安全组','状态'],rows):Object.assign(document.createElement('div'),{textContent:'暂无同步目标',className:'empty'}));if(!$('eventsPanel')){const p=document.createElement('div');p.id='eventsPanel';p.className='panel';const h=document.createElement('div');h.className='panel-head';const title=document.createElement('h2');title.textContent='IP 变更记录';const refreshBtn=document.createElement('button');refreshBtn.className='ghost';refreshBtn.textContent='刷新';refreshBtn.onclick=loadEvents;h.append(title,refreshBtn);const box=document.createElement('div');box.id='eventsTable';box.className='empty';box.textContent='加载中...';p.append(h,box);$('overview').append(p)}loadEvents()}
async function loadEvents(){const box=$('eventsTable');if(!box)return;try{const events=(await api('/api/events'))||[];const rows=events.slice(0,20).map(e=>[new Date(e.occurred_at).toLocaleString(),e.rule_name,e.action,e.old_cidr||'-',e.new_cidr||'-',e.success?'成功':'失败']);box.replaceChildren(rows.length?table(['时间','规则','动作','旧 IP/CIDR','新 IP/CIDR','结果'],rows):Object.assign(document.createElement('div'),{textContent:'暂无 IP 变更记录',className:'empty'}))}catch(e){box.textContent='记录加载失败'}}
function renderInventory(){const ins=inventory.instances||[],groups=inventory.groups||[],q=($('instanceFilter')?.value||'').toLowerCase();const ir=ins.filter(x=>(x.name+' '+x.id+' '+x.eip).toLowerCase().includes(q)).map(x=>[x.region,x.name,x.id,x.status,x.eip,(x.security_groups||[]).join(', ')]);$('instanceTable').replaceChildren(ir.length?table(['地域','实例名称','实例 ID','状态','主公网 IP','安全组'],ir):Object.assign(document.createElement('div'),{textContent:'暂无实例数据',className:'empty'}));const gq=($('groupSearch')?.value||'').toLowerCase(),rf=$('regionFilter')?.value||'';const rows=[];groups.filter(x=>(!rf||x.region===rf)&&(!gq||(x.name+' '+x.id).toLowerCase().includes(gq))).forEach(x=>{const b=document.createElement('button');b.className='ghost';b.textContent='查看规则';b.onclick=()=>openRules(x);rows.push([x.region,x.name,x.id,String((x.rules||[]).length),b])});$('groupTable').replaceChildren(rows.length?table(['地域','安全组名称','安全组 ID','规则数','操作'],rows):Object.assign(document.createElement('div'),{textContent:'暂无安全组数据',className:'empty'}))}
let activeGroup=null,editingRule=null;function openRules(g){initRuleDrawer();activeGroup=g;$('drawerTitle').textContent=g.name+' · '+g.id;$('ruleDrawer').style.width='100vw';$('ruleDrawer').style.inset='0';$('ruleDrawer').classList.add('open');renderRules();ensureRulePickers()}function renderRules(){const q=$('ruleSearch').value.toLowerCase(),rows=[];(activeGroup?.rules||[]).filter(x=>(x.cidr+' '+x.protocol+' '+x.port_start+' '+x.description).toLowerCase().includes(q)).forEach((x,i)=>{const edit=document.createElement('button');edit.className='ghost';edit.textContent='编辑';edit.onclick=()=>showRuleForm(x);const del=document.createElement('button');del.className='warn';del.textContent='删除';del.onclick=()=>deleteRule(x);rows.push([x.direction,x.cidr,x.protocol,x.port_start===-1?'ALL':x.port_start+'-'+x.port_end,x.priority,x.description,edit,del])});$('ruleTable').replaceChildren(rows.length?table(['方向','来源','协议','端口','优先级','描述','', ''],rows):Object.assign(document.createElement('div'),{textContent:'该安全组暂无规则',className:'empty'}))}
function ensureRulePickers(){document.querySelectorAll('#ruleTable tr').forEach((r,i)=>{if(i>0&&!r.querySelector('.rule-pick')){const c=document.createElement('input');c.type='checkbox';c.className='rule-pick';c.dataset.i=i-1;r.insertBefore(document.createElement('td'),r.firstChild).append(c)}})}
const _renderRules=renderRules;renderRules=()=>{_renderRules();ensureRulePickers()};
function hideRuleForm(){const f=$('ruleForm'),b=$('ruleModalBackdrop');if(f)f.style.display='none';if(b)b.style.display='none';if($('ruleDrawer'))$('ruleDrawer').style.zIndex='10';document.body.style.overflow=''}
function setupRuleModal(){if($('ruleModalBackdrop'))return;const b=document.createElement('div');b.id='ruleModalBackdrop';Object.assign(b.style,{position:'fixed',inset:'0',background:'rgba(23,32,51,.42)',zIndex:'25',display:'none',alignItems:'center',justifyContent:'center'});b.onclick=e=>{if(e.target===b)hideRuleForm()};document.body.append(b);document.addEventListener('keydown',e=>{if(e.key==='Escape'&&b.style.display!=='none')hideRuleForm()});const f=$('ruleForm'),title=document.createElement('h3');title.id='ruleModalTitle';title.textContent='安全组规则';Object.assign(title.style,{gridColumn:'1/-1',margin:'0 0 4px',fontSize:'18px'});f.insertBefore(title,f.firstChild);f.style.position='fixed';f.style.zIndex='30';f.style.left='50%';f.style.top='50%';f.style.transform='translate(-50%,-50%)';f.style.width='min(640px,calc(100vw - 32px))';f.style.maxHeight='calc(100vh - 48px)';f.style.overflow='auto';f.style.padding='24px';f.style.background='#fff';f.style.border='1px solid #dfe4ec';f.style.borderRadius='12px';f.style.boxShadow='0 24px 70px rgba(21,35,59,.27)'}
function showRuleForm(x){setupRuleModal();editingRule=x||null;$('ruleModalTitle').textContent=editingRule?'编辑安全组规则':'添加安全组规则';$('ruleDrawer').style.zIndex='40';$('ruleForm').style.display='grid';$('ruleModalBackdrop').style.display='flex';document.body.style.overflow='hidden';$('ruleCIDR').value=x?.cidr||'';$('ruleProtocol').value=x?.protocol||'tcp';$('rulePortStart').value=x?.port_start>0?x.port_start:22;$('rulePortEnd').value=x?.port_end>0?x.port_end:22;$('rulePriority').value=x?.priority||1;$('ruleDescription').value=x?.description||'';$('ruleCIDR').focus()}
async function deleteRule(x){if(!confirm('确认删除这条云端规则？'))return;try{await api('/api/rules',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({region:activeGroup.region,security_group_id:activeGroup.id,direction:x.direction,cidr:x.cidr,protocol:x.protocol,port_start:x.port_start,port_end:x.port_end,priority:x.priority,description:x.description})});msg('规则已删除',true);await loadInventory();activeGroup=(inventory.groups||[]).find(g=>g.id===activeGroup.id);renderRules()}catch(e){msg(e.message)}}
async function loadInventory(){try{inventory=await api('/api/inventory');const rs=[...new Set((inventory.groups||[]).map(x=>x.region))];$('regionFilter').replaceChildren(new Option('全部地域',''),...rs.map(x=>new Option(x,x)));renderInventory();$('detail').textContent=JSON.stringify(inventory,null,2);refreshCurrentIP()}catch(e){msg(e.message)}}
function initRuleDrawer(){if(window.ruleDrawerReady)return;window.ruleDrawerReady=true;$('closeDrawer').onclick=()=>{hideRuleForm();$('ruleDrawer').classList.remove('open')};$('addRule').onclick=()=>showRuleForm(null);$('cancelRule').onclick=hideRuleForm;$('ruleSearch').oninput=renderRules;const batch=document.createElement('button');batch.id='batchDelete';batch.className='warn';batch.textContent='批量删除';$('addRule').parentElement.append(batch);const replaceCIDR=document.createElement('input');replaceCIDR.id='replaceCIDR';replaceCIDR.placeholder='新 IP/CIDR，留空自动获取';replaceCIDR.className='grow';$('addRule').parentElement.append(replaceCIDR);const replaceBtn=document.createElement('button');replaceBtn.className='primary';replaceBtn.textContent='替换选中 IP';$('addRule').parentElement.append(replaceBtn);batch.onclick=async()=>{const picks=[...document.querySelectorAll('.rule-pick:checked')].map(e=>activeGroup.rules[Number(e.dataset.i)]).filter(Boolean);if(!picks.length)return msg('请先选择规则');if(!confirm('确认删除选中的 '+picks.length+' 条规则？'))return;try{const d=await api('/api/rules/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rules:picks.map(x=>({region:activeGroup.region,security_group_id:activeGroup.id,direction:x.direction,cidr:x.cidr,protocol:x.protocol,port_start:x.port_start,port_end:x.port_end,priority:x.priority,description:x.description}))})});msg('已删除 '+d.deleted+' 条规则',true);await loadInventory();activeGroup=(inventory.groups||[]).find(x=>x.id===activeGroup.id);renderRules()}catch(e){msg(e.message)}};replaceBtn.onclick=async()=>{const picks=[...document.querySelectorAll('.rule-pick:checked')].map(e=>activeGroup.rules[Number(e.dataset.i)]).filter(Boolean);if(!picks.length)return msg('请先选择规则');let cidr=replaceCIDR.value.trim();try{if(!cidr)cidr=(await api('/api/current-ip')).cidr;const d=await api('/api/rules/replace',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_cidr:cidr,rules:picks.map(x=>({region:activeGroup.region,security_group_id:activeGroup.id,direction:x.direction,cidr:x.cidr,protocol:x.protocol,port_start:x.port_start,port_end:x.port_end,priority:x.priority,description:x.description}))})});msg('已替换 '+d.replaced+' 条规则为 '+cidr,true);replaceCIDR.value='';await loadInventory();activeGroup=(inventory.groups||[]).find(x=>x.id===activeGroup.id);renderRules()}catch(e){msg(e.message)}};$('ruleForm').onsubmit=async e=>{e.preventDefault();const b={region:activeGroup.region,security_group_id:activeGroup.id,direction:'ingress',cidr:$('ruleCIDR').value.trim(),protocol:$('ruleProtocol').value,port_start:Number($('rulePortStart').value),port_end:Number($('rulePortEnd').value),priority:Number($('rulePriority').value),description:$('ruleDescription').value.trim()};if(editingRule){b.old_cidr=editingRule.cidr;b.old_protocol=editingRule.protocol;b.old_port_start=editingRule.port_start;b.old_port_end=editingRule.port_end;b.old_priority=editingRule.priority;b.old_description=editingRule.description}try{await api('/api/rules',{method:editingRule?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});msg(editingRule?'规则已修改':'规则已添加',true);hideRuleForm();await loadInventory();activeGroup=(inventory.groups||[]).find(x=>x.id===activeGroup.id);renderRules()}catch(e){msg(e.message)}}}
let lastIPCheck=0;async function refreshCurrentIP(){if(Date.now()-lastIPCheck<30000)return;lastIPCheck=Date.now();try{const d=await api('/api/current-ip');$('ip').textContent=d.cidr;$('ip').title='最近检测：'+new Date().toLocaleString()}catch(e){$('ip').textContent='检测失败';$('ip').title=e.message}}
async function refresh(){try{const s=await api('/api/status');$('count').textContent=s.rule_count;$('running').textContent=s.running?'运行中':(s.last_error?'失败':'空闲');$('last').textContent=s.last_run?new Date(s.last_run).toLocaleString():'尚未执行';$('mode').textContent=s.dry_run?'预演模式':'安全模式';$('sync').disabled=s.running;if(s.last_error)msg(s.last_error);refreshCurrentIP()}catch(e){msg(e.message)}}
async function loadConfig(){try{const c=await api('/api/config');$('providers').value=(c.ip_providers||[]).join('\\n');$('interval').value=c.interval||'2h';$('times').value=(c.schedule_times||[]).join(',');$('listen').value=c.web_listen||'127.0.0.1:12345';$('dry').checked=!!c.dry_run;$('configState').textContent=c.password_set?'密码已启用':'未设置密码';document.querySelectorAll('#settings label').forEach(e=>{if(e.textContent.includes('检测频率'))e.firstChild.textContent='检测频率（至少 30 秒）'});if(!$('checkIP')){const b=document.createElement('button');b.id='checkIP';b.className='ghost';b.textContent='立即检测出口 IP';b.onclick=async()=>{try{const d=await api('/api/current-ip');msg('当前出口 IP：'+d.cidr,true)}catch(e){msg(e.message)}};$('saveConfig').parentElement.append(b)}}catch(e){msg(e.message)}}
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>{const p=b.dataset.page;document.querySelectorAll('.section').forEach(x=>x.classList.toggle('active',x.id===p));document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.page===p));$('crumb').textContent=b.textContent.trim();if(p==='instances'||p==='groups')loadInventory()});$('filter').oninput=renderTargets;$('groupFilter').onchange=renderTargets;$('instanceFilter').oninput=renderInventory;$('groupSearch').oninput=renderInventory;$('regionFilter').onchange=renderInventory;$('selectAll').onclick=()=>document.querySelectorAll('.pick').forEach(e=>e.checked=true);$('sync').onclick=async()=>{try{await api('/api/sync',{method:'POST',body:'{}'});msg('同步任务已启动，请观察状态变化',true);refresh()}catch(e){msg(e.message)}};$('syncSelected').onclick=async()=>{try{const ids=[...document.querySelectorAll('.pick:checked')].map(e=>targetData[e.dataset.i].id);if(!ids.length)throw Error('请先选择目标');await api('/api/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target_ids:ids})});msg('选中目标同步已启动',true);refresh()}catch(e){msg(e.message)}};$('save').onclick=async()=>{try{document.querySelectorAll('.group').forEach(e=>targetData[e.dataset.i].group=e.value);document.querySelectorAll('.note').forEach(e=>targetData[e.dataset.i].note=e.value);document.querySelectorAll('.enabled').forEach(e=>targetData[e.dataset.i].enabled=e.checked);await api('/api/targets',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(targetData)});msg('同步目标已保存',true);loadTargets()}catch(e){msg(e.message)}};$('discover').onclick=async()=>{try{msg('正在同步云端资产...',true);await api('/api/discover',{method:'POST'});msg('云端发现完成',true);loadInventory()}catch(e){msg(e.message)}};$('refreshInventory').onclick=loadInventory;$('assets').onclick=loadInventory;$('saveConfig').onclick=async()=>{try{await api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({access_key_id:$('ak').value,secret_access_key:$('sk').value,password:$('pwd').value,ip_providers:$('providers').value.split(/\\n/).map(x=>x.trim()).filter(Boolean),interval:$('interval').value,schedule_times:$('times').value.split(',').map(x=>x.trim()).filter(Boolean),web_listen:$('listen').value,dry_run:$('dry').checked})});$('ak').value='';$('sk').value='';$('pwd').value='';msg('配置已安全保存，密钥不会回显',true);loadConfig()}catch(e){msg(e.message)}};$('loginBtn').onclick=async()=>{const p=prompt('请输入 Web 密码');if(p===null)return;try{await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});msg('登录成功',true);loadConfig();loadTargets();refresh()}catch(e){msg(e.message)}};refresh();loadTargets();loadConfig();loadInventory();setInterval(refresh,5000);
</script></body></html>`))

func webIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = webPage.Execute(w, nil)
}
