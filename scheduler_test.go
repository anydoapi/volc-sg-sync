package main

import (
	"testing"
	"time"
)

func TestSleepUntilNextScheduledTime(t *testing.T) {
	loc := time.FixedZone("CST", 8*60*60)
	now := time.Date(2026, 8, 25, 8, 0, 0, 0, loc)
	if got := sleepUntilNext(now, []string{"09:00", "13:00"}, 2*time.Hour); got != time.Hour {
		t.Fatalf("got %s", got)
	}
	now = time.Date(2026, 8, 25, 14, 0, 0, 0, loc)
	if got := sleepUntilNext(now, []string{"09:00", "13:00"}, 2*time.Hour); got != 19*time.Hour {
		t.Fatalf("got %s", got)
	}
}
