package mfa

import "github.com/univeros/polaris.go/model"

// ManagedFactorView is the management-list shape: the login view plus confirmed, since the
// management list shows pending factors too.
type ManagedFactorView struct {
	FactorView
	Confirmed bool `json:"confirmed"`
}

// ManagedViewOf returns f's management view.
func ManagedViewOf(f model.MFAFactor) ManagedFactorView {
	return ManagedFactorView{FactorView: ViewOf(f), Confirmed: f.ConfirmedAt != nil}
}
