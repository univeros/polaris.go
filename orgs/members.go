package orgs

// Member is one membership of an organization as listed.
type Member struct {
	UserID      string
	Email       *string // nil when withheld (see ListMembers) or the user is gone
	DisplayName *string
	Status      string
	Roles       []string // role slugs
}
