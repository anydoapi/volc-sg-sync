package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/anydoapi/volc-sg-sync/internal/config"
	"github.com/anydoapi/volc-sg-sync/internal/inventory"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

type discoveredInstance struct {
	Region         string   `json:"region"`
	ID             string   `json:"instance_id"`
	Name           string   `json:"instance_name"`
	Status         string   `json:"status"`
	EIP            string   `json:"eip,omitempty"`
	SecurityGroups []string `json:"security_group_ids"`
}
type discoveredGroup struct {
	Region string       `json:"region"`
	ID     string       `json:"security_group_id"`
	Name   string       `json:"name"`
	Rules  []Permission `json:"rules"`
}
type discoveryOutput struct {
	Instances      []discoveredInstance `json:"instances"`
	SecurityGroups []discoveredGroup    `json:"security_groups"`
}

func discoverRegion(ctx context.Context, region string) ([]discoveredInstance, []discoveredGroup, error) {
	ak, sk := os.Getenv("VOLCENGINE_ACCESS_KEY_ID"), os.Getenv("VOLCENGINE_SECRET_ACCESS_KEY")
	sess, err := session.NewSession(volcengine.NewConfig().WithRegion(region).WithCredentials(credentials.NewStaticCredentials(ak, sk, "")))
	if err != nil {
		return nil, nil, err
	}
	e := ecs.New(sess)
	v := vpc.New(sess)
	resp, err := e.DescribeInstancesWithContext(ctx, &ecs.DescribeInstancesInput{MaxResults: volcengine.Int32(100)})
	if err != nil {
		return nil, nil, err
	}
	instances := make([]discoveredInstance, 0)
	groups := map[string]*discoveredGroup{}
	for _, item := range resp.Instances {
		if item == nil {
			continue
		}
		d := discoveredInstance{Region: region, ID: volcengine.StringValue(item.InstanceId), Name: volcengine.StringValue(item.InstanceName), Status: volcengine.StringValue(item.Status)}
		if item.EipAddress != nil {
			d.EIP = volcengine.StringValue(item.EipAddress.IpAddress)
		}
		for _, ni := range item.NetworkInterfaces {
			if ni == nil {
				continue
			}
			for _, gid := range ni.SecurityGroupIds {
				g := volcengine.StringValue(gid)
				if g == "" {
					continue
				}
				d.SecurityGroups = append(d.SecurityGroups, g)
				if _, ok := groups[g]; !ok {
					groups[g] = &discoveredGroup{Region: region, ID: g}
				}
			}
		}
		instances = append(instances, d)
	}
	// Discover every security group in the region, including groups not currently attached to an instance.
	groupResp, err := v.DescribeSecurityGroupsWithContext(ctx, &vpc.DescribeSecurityGroupsInput{MaxResults: volcengine.Int64(100)})
	if err != nil {
		return nil, nil, err
	}
	for _, item := range groupResp.SecurityGroups {
		if item == nil || item.SecurityGroupId == nil {
			continue
		}
		id := volcengine.StringValue(item.SecurityGroupId)
		if id == "" {
			continue
		}
		if _, ok := groups[id]; !ok {
			groups[id] = &discoveredGroup{Region: region, ID: id, Name: volcengine.StringValue(item.SecurityGroupName)}
		}
	}
	for id, g := range groups {
		attrs, err := v.DescribeSecurityGroupAttributesWithContext(ctx, &vpc.DescribeSecurityGroupAttributesInput{SecurityGroupId: volcengine.String(id)})
		if err != nil {
			return nil, nil, fmt.Errorf("describe %s: %w", id, err)
		}
		g.Name = volcengine.StringValue(attrs.SecurityGroupName)
		for _, p := range attrs.Permissions {
			if p == nil {
				continue
			}
			g.Rules = append(g.Rules, Permission{CidrIP: volcengine.StringValue(p.CidrIp), Protocol: volcengine.StringValue(p.Protocol), PortStart: volcengine.Int64Value(p.PortStart), PortEnd: volcengine.Int64Value(p.PortEnd), Priority: volcengine.Int64Value(p.Priority), Description: volcengine.StringValue(p.Description), Direction: volcengine.StringValue(p.Direction)})
		}
	}
	outGroups := make([]discoveredGroup, 0, len(groups))
	for _, g := range groups {
		outGroups = append(outGroups, *g)
	}
	sort.Slice(outGroups, func(i, j int) bool { return outGroups[i].ID < outGroups[j].ID })
	return instances, outGroups, nil
}
func syncInventory(ctx context.Context, dbPath string, regions []string) (string, error) {
	var snapshot inventory.Snapshot
	for _, region := range regions {
		instances, groups, err := discoverRegion(ctx, region)
		if err != nil {
			return "", err
		}
		for _, item := range instances {
			snapshot.Instances = append(snapshot.Instances, inventory.Instance{Region: item.Region, ID: item.ID, Name: item.Name, Status: item.Status, EIP: item.EIP, SecurityGroups: item.SecurityGroups})
		}
		for _, group := range groups {
			g := inventory.Group{Region: group.Region, ID: group.ID, Name: group.Name}
			for _, rule := range group.Rules {
				g.Rules = append(g.Rules, inventory.Rule{Direction: rule.Direction, CIDR: rule.CidrIP, Protocol: rule.Protocol, PortStart: rule.PortStart, PortEnd: rule.PortEnd, Priority: rule.Priority, Description: rule.Description})
			}
			snapshot.Groups = append(snapshot.Groups, g)
		}
	}
	store, err := inventory.Open(dbPath)
	if err != nil {
		return "", err
	}
	defer store.Close()
	if err := store.Sync(snapshot); err != nil {
		return "", err
	}
	return store.Summary()
}

func regionsFromConfig(cfg config.Config) []string {
	seen := map[string]bool{}
	regions := make([]string, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		region := strings.TrimSpace(r.Region)
		if region != "" && !seen[region] {
			seen[region] = true
			regions = append(regions, region)
		}
	}
	if len(regions) == 0 {
		regions = []string{"cn-beijing"}
	}
	return regions
}

func discover(ctx context.Context, regions []string) error {
	var out discoveryOutput
	for _, r := range regions {
		i, g, err := discoverRegion(ctx, r)
		if err != nil {
			return err
		}
		out.Instances = append(out.Instances, i...)
		out.SecurityGroups = append(out.SecurityGroups, g...)
	}
	raw, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(raw))
	return nil
}
