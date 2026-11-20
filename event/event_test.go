package event

import (
	"context"
	"slices"
	"testing"
)

func TestBusDeliversInSubscriptionOrder(t *testing.T) {
	tests := []struct {
		name      string
		listeners int
		events    []Event
		want      []string
	}{
		{"no listeners", 0, []Event{UserLoggedIn{UserID: "u"}}, nil},
		{"one listener", 1, []Event{UserLoggedIn{UserID: "u"}}, []string{"0:user.logged_in"}},
		{"in order", 2, []Event{UserLoggedIn{UserID: "u"}, UserDeleted{UserID: "u"}},
			[]string{"0:user.logged_in", "1:user.logged_in", "0:user.deleted", "1:user.deleted"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Bus
			var got []string
			for i := range tt.listeners {
				b.Subscribe(func(_ context.Context, e Event) { got = append(got, string(rune('0'+i))+":"+e.EventName()) })
			}
			for _, e := range tt.events {
				b.Dispatch(context.Background(), e)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNopDropsEvents(t *testing.T) {
	var d Dispatcher = Nop{}
	d.Dispatch(context.Background(), UserLoggedIn{}) // must not panic
}
