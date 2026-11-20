package wiring

import (
	"testing"

	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/notify/notifytest"
)

type portsPlugin struct{ m notify.Mailer }

func (portsPlugin) ID() string     { return "ports" }
func (p portsPlugin) Ports() Ports { return Ports{Mailer: p.m} }

type laterPorts struct{ portsPlugin }

func (laterPorts) ID() string { return "later" }

func TestPluginPortsServeUnsetConfigPorts(t *testing.T) {
	first, second := &notifytest.Mailer{}, &notifytest.Mailer{}
	g := &Graph{config: Config{}, plugins: []Plugin{portsPlugin{first}, laterPorts{portsPlugin{second}}}}
	g.defaults()
	if g.mailer != first {
		t.Fatalf("first plugin providing a port must win, got %T", g.mailer)
	}
	if _, ok := g.sms.(*notify.LogSMS); !ok {
		t.Fatalf("unprovided port keeps its default, got %T", g.sms)
	}
	own := &notifytest.Mailer{}
	g = &Graph{config: Config{Mailer: own}, plugins: []Plugin{portsPlugin{first}}}
	g.defaults()
	if g.mailer != own {
		t.Fatal("Config's own port must win")
	}
}
