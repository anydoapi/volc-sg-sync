package inventory

import (
	"path/filepath"
	"testing"
)

func TestSyncKeepsCurrentInventoryAndHistoricalRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first := Snapshot{Instances: []Instance{{Region: "cn-beijing", ID: "i-1", Name: "server", Status: "RUNNING", EIP: "1.2.3.4", SecurityGroups: []string{"sg-1"}}}, Groups: []Group{{Region: "cn-beijing", ID: "sg-1", Name: "main", Rules: []Rule{{Direction: "ingress", CIDR: "10.0.0.0/8", Protocol: "tcp", PortStart: 22, PortEnd: 22, Priority: 1, Description: "ssh"}}}}}
	if err := s.Sync(first); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Summary(); got != "instances=1 security_groups=1 rules=1" {
		t.Fatal(got)
	}
	second := Snapshot{Instances: first.Instances, Groups: []Group{{Region: "cn-beijing", ID: "sg-1", Name: "main"}}}
	if err := s.Sync(second); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Summary(); got != "instances=1 security_groups=1 rules=0" {
		t.Fatal(got)
	}
	var total, active int
	if err := s.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(active),0) FROM security_group_rules`).Scan(&total, &active); err != nil {
		t.Fatal(err)
	}
	if total != 1 || active != 0 {
		t.Fatalf("total=%d active=%d", total, active)
	}
	if err := s.RecordPublicIP("2.2.2.2/32"); err != nil {
		t.Fatal(err)
	}
	if err := s.Event("ssh", "add", "sg-1", "", "2.2.2.2/32", true, ""); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sync_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatal(events)
	}
}
