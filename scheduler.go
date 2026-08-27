package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anydoapi/volc-sg-sync/internal/config"
)

func sleepUntilNext(now time.Time, times []string, interval time.Duration) time.Duration {
	if len(times) == 0 {
		return interval
	}
	best := 24 * time.Hour
	for _, raw := range times {
		parts := strings.Split(strings.TrimSpace(raw), ":")
		if len(parts) != 2 {
			continue
		}
		h, e1 := strconv.Atoi(parts[0])
		m, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			continue
		}
		next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		if d := next.Sub(now); d < best {
			best = d
		}
	}
	if best == 24*time.Hour {
		return interval
	}
	return best
}

func runScheduler(cfg config.Config, cloud Cloud) {
	defaultInterval := 2 * time.Hour
	interval := defaultInterval
	if raw := os.Getenv("INTERVAL"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 30*time.Second {
			interval = d
		}
	}
	// The default policy is two daily checks, one in the morning and one in
	// the evening. Web settings can override these times without reinstalling.
	defaultTimes := []string{"09:00", "18:00"}
	times := append([]string(nil), defaultTimes...)
	if raw := os.Getenv("SCHEDULE_TIMES"); raw != "" {
		times = strings.Split(raw, ",")
	}
	for {
		interval = defaultInterval
		if raw := os.Getenv("INTERVAL"); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil && d >= 30*time.Second {
				interval = d
			}
		}
		// Web settings are reloaded each cycle so frequency and schedule changes take effect without reinstalling.
		times = append([]string(nil), defaultTimes...)
		if raw := os.Getenv("SCHEDULE_TIMES"); raw != "" {
			times = strings.Split(raw, ",")
		}
		if s, err := loadWebSettings(settingsPath(cfg)); err == nil {
			applyWebSettings(&cfg, s)
			if s.Interval != "" {
				if d, err := time.ParseDuration(s.Interval); err == nil && d >= 30*time.Second {
					interval = d
				}
			}
			if len(s.ScheduleTimes) > 0 {
				times = append([]string(nil), s.ScheduleTimes...)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		if summary, err := syncInventory(ctx, cfg.InventoryDB, []string{"cn-beijing"}); err != nil {
			log.Printf("资产规则库同步失败: %v", err)
		} else {
			log.Printf("资产规则库同步完成: %s", summary)
		}
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
		err := run(ctx, cfg, cloud, os.Getenv("DRY_RUN") == "1")
		cancel()
		if err != nil {
			log.Printf("同步失败: %v", err)
		}
		d := sleepUntilNext(time.Now(), times, interval)
		log.Printf("下一次同步将在 %s 后执行", d.Round(time.Second))
		time.Sleep(d)
	}
}
