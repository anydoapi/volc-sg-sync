package inventory

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Instance struct {
	Region         string   `json:"region"`
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Status         string   `json:"status"`
	EIP            string   `json:"eip"`
	SecurityGroups []string `json:"security_groups"`
}
type Group struct {
	Region string `json:"region"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Rules  []Rule `json:"rules"`
}
type Rule struct {
	Direction   string `json:"direction"`
	CIDR        string `json:"cidr"`
	Protocol    string `json:"protocol"`
	PortStart   int64  `json:"port_start"`
	PortEnd     int64  `json:"port_end"`
	Priority    int64  `json:"priority"`
	Description string `json:"description"`
}
type Snapshot struct {
	Instances []Instance `json:"instances"`
	Groups    []Group    `json:"groups"`
}

type SyncTarget struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	GroupName       string `json:"group"`
	Note            string `json:"note"`
	Region          string `json:"region"`
	SecurityGroupID string `json:"security_group_id"`
	Protocol        string `json:"protocol"`
	PortStart       int64  `json:"port_start"`
	PortEnd         int64  `json:"port_end"`
	Priority        int64  `json:"priority"`
	Enabled         bool   `json:"enabled"`
	IPMatch         string `json:"ip_match"`
	IPMatchMode     string `json:"ip_match_mode"`
}

// ActiveSnapshot returns the latest active inventory records for read-only views.
func (s *Store) ActiveSnapshot() (Snapshot, error) {
	var out Snapshot
	rows, err := s.db.Query(`SELECT region,instance_id,name,status,eip,security_group_ids FROM instances WHERE active=1 ORDER BY instance_id`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var i Instance
		var groups string
		if err := rows.Scan(&i.Region, &i.ID, &i.Name, &i.Status, &i.EIP, &groups); err != nil {
			rows.Close()
			return out, err
		}
		if err := json.Unmarshal([]byte(groups), &i.SecurityGroups); err != nil {
			rows.Close()
			return out, err
		}
		out.Instances = append(out.Instances, i)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()
	groupsRows, err := s.db.Query(`SELECT region,security_group_id,name FROM security_groups WHERE active=1 ORDER BY security_group_id`)
	if err != nil {
		return out, err
	}
	for groupsRows.Next() {
		var g Group
		if err := groupsRows.Scan(&g.Region, &g.ID, &g.Name); err != nil {
			groupsRows.Close()
			return out, err
		}
		ruleRows, err := s.db.Query(`SELECT direction,cidr,protocol,port_start,port_end,priority,description FROM security_group_rules WHERE security_group_id=? AND active=1 ORDER BY priority,cidr`, g.ID)
		if err != nil {
			groupsRows.Close()
			return out, err
		}
		for ruleRows.Next() {
			var r Rule
			if err := ruleRows.Scan(&r.Direction, &r.CIDR, &r.Protocol, &r.PortStart, &r.PortEnd, &r.Priority, &r.Description); err != nil {
				ruleRows.Close()
				groupsRows.Close()
				return out, err
			}
			g.Rules = append(g.Rules, r)
		}
		if err := ruleRows.Err(); err != nil {
			ruleRows.Close()
			groupsRows.Close()
			return out, err
		}
		ruleRows.Close()
		out.Groups = append(out.Groups, g)
	}
	if err := groupsRows.Err(); err != nil {
		groupsRows.Close()
		return out, err
	}
	groupsRows.Close()
	return out, nil
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA synchronous=NORMAL"} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	if path != "" {
		if err := os.Chmod(path, 0600); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS inventory_runs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT,
 status TEXT NOT NULL, instance_count INTEGER NOT NULL DEFAULT 0,
 group_count INTEGER NOT NULL DEFAULT 0, rule_count INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS instances(
 region TEXT NOT NULL, instance_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
 eip TEXT NOT NULL, security_group_ids TEXT NOT NULL, active INTEGER NOT NULL,
 first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, last_run_id INTEGER NOT NULL REFERENCES inventory_runs(id));
CREATE TABLE IF NOT EXISTS security_groups(
 region TEXT NOT NULL, security_group_id TEXT PRIMARY KEY, name TEXT NOT NULL,
 active INTEGER NOT NULL, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
 last_run_id INTEGER NOT NULL REFERENCES inventory_runs(id));
CREATE TABLE IF NOT EXISTS security_group_rules(
 rule_key TEXT PRIMARY KEY, security_group_id TEXT NOT NULL REFERENCES security_groups(security_group_id),
 direction TEXT NOT NULL, cidr TEXT NOT NULL, protocol TEXT NOT NULL,
 port_start INTEGER NOT NULL, port_end INTEGER NOT NULL, priority INTEGER NOT NULL,
 description TEXT NOT NULL, active INTEGER NOT NULL, first_seen_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL, last_run_id INTEGER NOT NULL REFERENCES inventory_runs(id));
CREATE INDEX IF NOT EXISTS idx_rules_group_active ON security_group_rules(security_group_id,active);
CREATE TABLE IF NOT EXISTS sync_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, rule_name TEXT NOT NULL,
 action TEXT NOT NULL, security_group_id TEXT NOT NULL, old_cidr TEXT NOT NULL,
 new_cidr TEXT NOT NULL, success INTEGER NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observed_public_ip(
 id INTEGER PRIMARY KEY CHECK(id=1), cidr TEXT NOT NULL, observed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observed_public_ip_history(
 cidr TEXT PRIMARY KEY, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sync_targets(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, group_name TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
 region TEXT NOT NULL, security_group_id TEXT NOT NULL, protocol TEXT NOT NULL, port_start INTEGER NOT NULL, port_end INTEGER NOT NULL,
 priority INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL);
`)
	if err != nil {
		return err
	}
	for _, q := range []string{
		`ALTER TABLE sync_targets ADD COLUMN ip_match TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sync_targets ADD COLUMN ip_match_mode TEXT NOT NULL DEFAULT 'contains'`,
	} {
		if _, e := db.Exec(q); e != nil && !strings.Contains(strings.ToLower(e.Error()), "duplicate column") {
			return e
		}
	}
	return nil
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func key(group string, r Rule) string {
	b, _ := json.Marshal([]any{group, r.Direction, r.CIDR, r.Protocol, r.PortStart, r.PortEnd, r.Priority, r.Description})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Store) Sync(snapshot Snapshot) (err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	t := now()
	res, err := tx.Exec(`INSERT INTO inventory_runs(started_at,status) VALUES(?,?)`, t, "running")
	if err != nil {
		return err
	}
	rid64, _ := res.LastInsertId()
	rid := int(rid64)
	if _, err = tx.Exec(`UPDATE instances SET active=0`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE security_groups SET active=0`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE security_group_rules SET active=0`); err != nil {
		return err
	}
	for _, i := range snapshot.Instances {
		sg, _ := json.Marshal(i.SecurityGroups)
		_, err = tx.Exec(`INSERT INTO instances(region,instance_id,name,status,eip,security_group_ids,active,first_seen_at,last_seen_at,last_run_id) VALUES(?,?,?,?,?,?,1,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET region=excluded.region,name=excluded.name,status=excluded.status,eip=excluded.eip,security_group_ids=excluded.security_group_ids,active=1,last_seen_at=excluded.last_seen_at,last_run_id=excluded.last_run_id`, i.Region, i.ID, i.Name, i.Status, i.EIP, string(sg), t, t, rid)
		if err != nil {
			return err
		}
	}
	ruleCount := 0
	for _, g := range snapshot.Groups {
		_, err = tx.Exec(`INSERT INTO security_groups(region,security_group_id,name,active,first_seen_at,last_seen_at,last_run_id) VALUES(?,?,?,1,?,?,?) ON CONFLICT(security_group_id) DO UPDATE SET region=excluded.region,name=excluded.name,active=1,last_seen_at=excluded.last_seen_at,last_run_id=excluded.last_run_id`, g.Region, g.ID, g.Name, t, t, rid)
		if err != nil {
			return err
		}
		for _, r := range g.Rules {
			ruleCount++
			_, err = tx.Exec(`INSERT INTO security_group_rules(rule_key,security_group_id,direction,cidr,protocol,port_start,port_end,priority,description,active,first_seen_at,last_seen_at,last_run_id) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?) ON CONFLICT(rule_key) DO UPDATE SET active=1,last_seen_at=excluded.last_seen_at,last_run_id=excluded.last_run_id`, key(g.ID, r), g.ID, r.Direction, r.CIDR, r.Protocol, r.PortStart, r.PortEnd, r.Priority, r.Description, t, t, rid)
			if err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(`UPDATE inventory_runs SET finished_at=?,status='success',instance_count=?,group_count=?,rule_count=? WHERE id=?`, now(), len(snapshot.Instances), len(snapshot.Groups), ruleCount, rid)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) RecordPublicIP(cidr string) error {
	t := now()
	if _, err := s.db.Exec(`INSERT INTO observed_public_ip(id,cidr,observed_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET cidr=excluded.cidr,observed_at=excluded.observed_at`, cidr, t); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO observed_public_ip_history(cidr,first_seen_at,last_seen_at) VALUES(?,?,?) ON CONFLICT(cidr) DO UPDATE SET last_seen_at=excluded.last_seen_at`, cidr, t, t)
	return err
}

func (s *Store) LastPublicIP() (string, error) {
	var cidr string
	err := s.db.QueryRow(`SELECT cidr FROM observed_public_ip WHERE id=1`).Scan(&cidr)
	return cidr, err
}

func (s *Store) PublicIPHistory() ([]string, error) {
	rows, err := s.db.Query(`SELECT cidr FROM observed_public_ip_history ORDER BY first_seen_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		out = append(out, cidr)
	}
	return out, rows.Err()
}
func (s *Store) Event(ruleName, action, group, oldCIDR, newCIDR string, success bool, detail string) error {
	v := 0
	if success {
		v = 1
	}
	_, err := s.db.Exec(`INSERT INTO sync_events(occurred_at,rule_name,action,security_group_id,old_cidr,new_cidr,success,detail) VALUES(?,?,?,?,?,?,?,?)`, now(), ruleName, action, group, oldCIDR, newCIDR, v, detail)
	return err
}

type SyncEvent struct {
	ID              int64  `json:"id"`
	OccurredAt      string `json:"occurred_at"`
	RuleName        string `json:"rule_name"`
	Action          string `json:"action"`
	SecurityGroupID string `json:"security_group_id"`
	OldCIDR         string `json:"old_cidr"`
	NewCIDR         string `json:"new_cidr"`
	Success         bool   `json:"success"`
	Detail          string `json:"detail"`
}

func (s *Store) ListEvents(limit int) ([]SyncEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,occurred_at,rule_name,action,security_group_id,old_cidr,new_cidr,success,detail FROM sync_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyncEvent
	for rows.Next() {
		var e SyncEvent
		var ok int
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.RuleName, &e.Action, &e.SecurityGroupID, &e.OldCIDR, &e.NewCIDR, &ok, &e.Detail); err != nil {
			return nil, err
		}
		e.Success = ok != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListSyncTargets() ([]SyncTarget, error) {
	rows, err := s.db.Query(`SELECT id,name,group_name,note,region,security_group_id,protocol,port_start,port_end,priority,enabled,ip_match,ip_match_mode FROM sync_targets ORDER BY group_name,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SyncTarget, 0)
	for rows.Next() {
		var t SyncTarget
		var enabled int
		if err := rows.Scan(&t.ID, &t.Name, &t.GroupName, &t.Note, &t.Region, &t.SecurityGroupID, &t.Protocol, &t.PortStart, &t.PortEnd, &t.Priority, &enabled, &t.IPMatch, &t.IPMatchMode); err != nil {
			return nil, err
		}
		t.Enabled = enabled != 0
		if t.IPMatchMode == "" {
			t.IPMatchMode = "contains"
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddSyncTargets adds discovered candidates without deleting user selections.
// It is used when automatic mode first materializes matching cloud rules into SQLite.
func (s *Store) AddSyncTargets(targets []SyncTarget) error {
	if len(targets) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range targets {
		if t.Name == "" || t.Region == "" || t.SecurityGroupID == "" {
			continue
		}
		if t.IPMatchMode == "" {
			t.IPMatchMode = "prefix"
		}
		enabled := 0
		if t.Enabled {
			enabled = 1
		}
		_, err = tx.Exec(`INSERT INTO sync_targets(name,group_name,note,region,security_group_id,protocol,port_start,port_end,priority,enabled,updated_at,ip_match,ip_match_mode) VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?) ON CONFLICT(name) DO NOTHING`, t.Name, t.GroupName, t.Note, t.Region, t.SecurityGroupID, t.Protocol, t.PortStart, t.PortEnd, t.Priority, enabled, now(), t.IPMatch, t.IPMatchMode)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ReplaceSyncTargets(targets []SyncTarget) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM sync_targets`); err != nil {
		return err
	}
	for _, t := range targets {
		if len(t.Name) == 0 || len(t.Name) > 128 || len(t.GroupName) > 64 || len(t.Note) > 512 || len(t.IPMatch) > 128 || t.Region == "" || len(t.Region) > 64 || t.SecurityGroupID == "" || len(t.SecurityGroupID) > 128 {
			return fmt.Errorf("同步目标缺少名称、地域或安全组ID")
		}
		if t.Priority == 0 {
			t.Priority = 1
		}
		switch t.Protocol {
		case "tcp", "udp":
			if t.PortStart < 0 || t.PortEnd < t.PortStart || t.PortEnd > 65535 {
				return fmt.Errorf("同步目标 %s 端口无效", t.Name)
			}
		case "icmp", "all":
			t.PortStart, t.PortEnd = -1, -1
		default:
			return fmt.Errorf("同步目标 %s 协议无效", t.Name)
		}
		if t.Priority < 1 || t.Priority > 100 {
			return fmt.Errorf("同步目标 %s 优先级无效", t.Name)
		}
		if t.IPMatchMode == "" {
			t.IPMatchMode = "contains"
		}
		if t.IPMatchMode != "contains" && t.IPMatchMode != "exact" && t.IPMatchMode != "cidr" && t.IPMatchMode != "prefix" {
			return fmt.Errorf("同步目标 %s IP 匹配方式无效", t.Name)
		}
		enabled := 0
		if t.Enabled {
			enabled = 1
		}
		if _, err = tx.Exec(`INSERT INTO sync_targets(name,group_name,note,region,security_group_id,protocol,port_start,port_end,priority,enabled,updated_at,ip_match,ip_match_mode) VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?)`, t.Name, t.GroupName, t.Note, t.Region, t.SecurityGroupID, t.Protocol, t.PortStart, t.PortEnd, t.Priority, enabled, now(), t.IPMatch, t.IPMatchMode); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Summary() (string, error) {
	var i, g, r int
	for _, q := range []struct {
		sql string
		dst *int
	}{{`SELECT COUNT(*) FROM instances WHERE active=1`, &i}, {`SELECT COUNT(*) FROM security_groups WHERE active=1`, &g}, {`SELECT COUNT(*) FROM security_group_rules WHERE active=1`, &r}} {
		if err := s.db.QueryRow(q.sql).Scan(q.dst); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("instances=%d security_groups=%d rules=%d", i, g, r), nil
}
