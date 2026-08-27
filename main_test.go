package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/anydoapi/volc-sg-sync/internal/config"
)

type fakeCloud struct {
	perms []Permission
	calls []string
}

func (f *fakeCloud) Permissions(context.Context, config.Rule) ([]Permission, error) {
	return append([]Permission(nil), f.perms...), nil
}
func (f *fakeCloud) Add(_ context.Context, r config.Rule, cidr string) error {
	f.calls = append(f.calls, "add:"+r.Name+":"+cidr)
	return nil
}
func (f *fakeCloud) Remove(_ context.Context, r config.Rule, p Permission) error {
	f.calls = append(f.calls, "remove:"+r.Name+":"+p.CidrIP)
	return nil
}

func ipServer(t *testing.T, ip string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(ip)) }))
}

func TestRunAddsNewBeforeRemovingOnlyManagedOldRule(t *testing.T) {
	a, b := ipServer(t, "2.2.2.2"), ipServer(t, "2.2.2.2")
	defer a.Close()
	defer b.Close()
	state := filepath.Join(t.TempDir(), "state.json")
	cfg := config.Config{IPProviders: []string{a.URL, b.URL}, StateFile: state, Rules: []config.Rule{{Name: "office-ssh", Region: "cn-beijing", SecurityGroupID: "sg-1", Protocol: "tcp", PortStart: 22, PortEnd: 22, Priority: 1}}}
	cloud := &fakeCloud{perms: []Permission{{CidrIP: "1.1.1.1/32", Description: "volc-sg-sync:office-ssh", Direction: "ingress"}, {CidrIP: "9.9.9.9/32", Description: "manual-rule"}}}
	if err := run(context.Background(), cfg, cloud, false); err != nil {
		t.Fatal(err)
	}
	want := []string{"add:office-ssh:2.2.2.2/32", "remove:office-ssh:1.1.1.1/32"}
	if len(cloud.calls) != len(want) {
		t.Fatalf("calls=%v", cloud.calls)
	}
	for i := range want {
		if cloud.calls[i] != want[i] {
			t.Fatalf("calls=%v", cloud.calls)
		}
	}
}

func TestRunSkipsUnchangedRule(t *testing.T) {
	a, b := ipServer(t, "2.2.2.2"), ipServer(t, "2.2.2.2")
	defer a.Close()
	defer b.Close()
	state := filepath.Join(t.TempDir(), "state.json")
	if err := saveState(state, State{Rules: map[string]string{"ssh": "2.2.2.2/32"}}); err != nil {
		t.Fatal(err)
	}
	cloud := &fakeCloud{perms: []Permission{{CidrIP: "2.2.2.2/32", Protocol: "tcp", PortStart: 22, PortEnd: 22, Description: "volc-sg-sync:ssh", Direction: "ingress"}}}
	cfg := config.Config{IPProviders: []string{a.URL, b.URL}, StateFile: state, Rules: []config.Rule{{Name: "ssh", Region: "cn-beijing", SecurityGroupID: "sg-1", Protocol: "tcp", PortStart: 22, PortEnd: 22}}}
	if err := run(context.Background(), cfg, cloud, false); err != nil {
		t.Fatal(err)
	}
	if len(cloud.calls) != 0 {
		t.Fatalf("calls=%v", cloud.calls)
	}
}

func TestRunRepairsMissingCloudRuleEvenWhenStateMatches(t *testing.T) {
	a, b := ipServer(t, "2.2.2.2"), ipServer(t, "2.2.2.2")
	defer a.Close()
	defer b.Close()
	state := filepath.Join(t.TempDir(), "state.json")
	if err := saveState(state, State{Rules: map[string]string{"ssh": "2.2.2.2/32"}}); err != nil {
		t.Fatal(err)
	}
	cloud := &fakeCloud{}
	cfg := config.Config{IPProviders: []string{a.URL, b.URL}, StateFile: state, Rules: []config.Rule{{Name: "ssh", Region: "cn-beijing", SecurityGroupID: "sg-1", Protocol: "tcp", PortStart: 22, PortEnd: 22}}}
	if err := run(context.Background(), cfg, cloud, false); err != nil {
		t.Fatal(err)
	}
	if len(cloud.calls) != 1 || cloud.calls[0] != "add:ssh:2.2.2.2/32" {
		t.Fatalf("calls=%v", cloud.calls)
	}
}

func TestCurrentIPRejectsDisagreement(t *testing.T) {
	a, b := ipServer(t, "2.2.2.2"), ipServer(t, "3.3.3.3")
	defer a.Close()
	defer b.Close()
	if _, err := currentIP(context.Background(), []string{a.URL, b.URL}); err == nil {
		t.Fatal("disagreement accepted")
	}
}
