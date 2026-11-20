package clock

import (
	"testing"
	"time"
)

func TestSystemIsUTCNow(t *testing.T) {
	before := time.Now()
	now := System{}.Now()
	if now.Location() != time.UTC || now.Before(before.Add(-time.Second)) || now.After(time.Now().Add(time.Second)) {
		t.Errorf("System.Now() = %v", now)
	}
}

func TestFrozen(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("X", 3600))
	tests := []struct {
		name string
		move func(*Frozen)
		want time.Time
	}{
		{"stays put", func(*Frozen) {}, base},
		{"advance", func(f *Frozen) { f.Advance(90 * time.Second) }, base.Add(90 * time.Second)},
		{"set", func(f *Frozen) { f.Set(base.Add(time.Hour)) }, base.Add(time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFrozen(base)
			tt.move(f)
			got := f.Now()
			if !got.Equal(tt.want) || got.Location() != time.UTC || !f.Now().Equal(got) {
				t.Errorf("Now() = %v, want %v in UTC", got, tt.want)
			}
		})
	}
}
