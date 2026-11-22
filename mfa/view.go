package mfa

import "github.com/univeros/polaris.go/model"

// FactorView is a factor as the client sees it at the login challenge: enough to choose and
// label it, never a secret or a full destination. Its JSON is the wire shape: id, type
// and default always, label and destination only when present.
type FactorView struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Default     bool   `json:"default"`
	Label       string `json:"label,omitempty"`
	Destination string `json:"destination,omitempty"` // masked; sms and email factors only
}

// ViewOf returns f's client view, its sms/email destination masked.
func ViewOf(f model.MFAFactor) FactorView {
	var destination string
	switch f.Type {
	case model.FactorSMS:
		destination = deref(f.PhoneE164)
	case model.FactorEmail:
		destination = deref(f.Email)
	}
	return FactorView{ID: f.ID, Type: f.Type, Default: f.IsDefault, Label: deref(f.Label), Destination: MaskDestination(f.Type, destination)}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
