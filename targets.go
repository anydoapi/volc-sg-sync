package main

import (
	"github.com/anydoapi/volc-sg-sync/internal/config"
	"github.com/anydoapi/volc-sg-sync/internal/inventory"
	"strings"
)

func isPlaceholderSecurityGroupID(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	return strings.Contains(id, "xxxxxxxx") || strings.Contains(id, "yyyyyyyy") || strings.Contains(id, "placeholder")
}

// managedConfig uses Web-managed targets when the table has been populated.
func managedConfig(cfg config.Config) (config.Config, error) {
	store, err := inventory.Open(cfg.InventoryDB)
	if err != nil {
		return cfg, err
	}
	defer store.Close()
	targets, err := store.ListSyncTargets()
	if err != nil {
		return cfg, err
	}
	if len(targets) == 0 {
		for _, r := range cfg.Rules {
			if isPlaceholderSecurityGroupID(r.SecurityGroupID) {
				continue
			}
			targets = append(targets, inventory.SyncTarget{Name: r.Name, Region: r.Region, SecurityGroupID: r.SecurityGroupID, Protocol: r.Protocol, PortStart: r.PortStart, PortEnd: r.PortEnd, Priority: r.Priority, Note: r.Description, Enabled: true, IPMatch: r.IPMatch, IPMatchMode: r.IPMatchMode})
		}
		if len(targets) > 0 {
			if err := store.ReplaceSyncTargets(targets); err != nil {
				return cfg, err
			}
		}
		if len(targets) == 0 {
			cfg.Rules = nil
		}
		return cfg, nil
	}
	rules := make([]config.Rule, 0, len(targets))
	for _, t := range targets {
		if !t.Enabled || isPlaceholderSecurityGroupID(t.SecurityGroupID) {
			continue
		}
		rules = append(rules, config.Rule{Name: t.Name, Region: t.Region, SecurityGroupID: t.SecurityGroupID, Protocol: t.Protocol, PortStart: t.PortStart, PortEnd: t.PortEnd, Priority: t.Priority, Description: t.Note, IPMatch: t.IPMatch, IPMatchMode: t.IPMatchMode})
	}
	cfg.Rules = rules
	return cfg, nil
}
