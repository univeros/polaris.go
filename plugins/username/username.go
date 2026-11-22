// Package username is the username plugin: a user sets a username
// (PATCH /username) and signs in with it or with the email (POST /username/sign-in) through core's
// password path, so lockout, timing parity, the email-verification rule, the MFA gate and the
// login envelope are core's. Usernames are unique without regard to case: the lowercased form is
// stored under a unique index (it holds on every database without collations) and the display form
// is kept as the user typed it.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{username.New(username.Config{})}, // default rules
//	})
//	mux.Handle("/", p.Handler()) // includes POST /username/sign-in, PATCH /username
package username

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/internal/maintenance"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.username.*.
const ID = "username"

// TableUsernames is the table the plugin owns.
const TableUsernames = "polaris_username"

// Defaults of Config.
const (
	DefaultMinLength = 3
	DefaultMaxLength = 30
)

// DefaultPattern is the characters a username may have by default: ASCII letters, digits, _ and ".".
var DefaultPattern = regexp.MustCompile(`\A[A-Za-z0-9_.]+\z`)

// DefaultReserved are the names nobody may take by default, compared without regard to case.
var DefaultReserved = []string{"admin", "administrator", "root", "system", "support", "help", "polaris", "anonymous", "null", "undefined", "me"}

// SentinelRoutes is the sign-in route for the sentinel plugin's routes option (path: attempt kind).
var SentinelRoutes = map[string]string{"/username/sign-in": "sign_in"}

// Config holds the username rules; the zero value is the defaults.
type Config struct {
	// MinLength and MaxLength bound the length in characters; zero: 3 and 30.
	MinLength, MaxLength int
	// Pattern is what a username must match whole; nil: DefaultPattern.
	Pattern *regexp.Regexp
	// Reserved replaces DefaultReserved when non-nil (an empty list reserves nothing).
	Reserved []string
}

func (c Config) withDefaults() (Config, error) {
	if c.MinLength == 0 {
		c.MinLength = DefaultMinLength
	}
	if c.MaxLength == 0 {
		c.MaxLength = DefaultMaxLength
	}
	if c.Pattern == nil {
		c.Pattern = DefaultPattern
	}
	if c.Reserved == nil {
		c.Reserved = DefaultReserved
	}
	switch {
	case c.MinLength < 1:
		return c, fmt.Errorf("username: Config.MinLength is %d, want at least 1 (0 means %d)", c.MinLength, DefaultMinLength)
	case c.MaxLength < c.MinLength:
		return c, fmt.Errorf("username: Config.MaxLength is %d, below MinLength %d", c.MaxLength, c.MinLength)
	case c.MaxLength > 64:
		return c, fmt.Errorf("username: Config.MaxLength is %d, the column holds 64", c.MaxLength)
	}
	return c, nil
}

// Errors. A refused username matches ErrInvalid (a *InvalidError listing the rules it breaks) or
// ErrTaken.
var (
	ErrInvalid = errors.New("username: the username is not valid")
	ErrTaken   = errors.New("username: the username is taken")
)

// InvalidError lists the rules a username breaks, as the 422 body shows them.
type InvalidError struct{ Violations []string }

func (e *InvalidError) Error() string {
	return ErrInvalid.Error() + ": " + strings.Join(e.Violations, " ")
}

// Is matches ErrInvalid.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Username is a user's username: Username is the lowercased form uniqueness is checked on,
// DisplayUsername the form the user typed.
type Username struct {
	UserID          string
	Username        string
	DisplayUsername string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Models returns polaris_username; its columns are the schema existing databases hold.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableUsernames,
			schema.StringField("userId", 36).AsPrimary(),
			schema.StringField("username", 64),
			schema.StringField("displayUsername", 64),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).Unique([]string{"username"}, "polaris_username_unique"),
	}
}

// Plugin is the username plugin. Its service exists once polaris.New has run.
type Plugin struct {
	cfg       Config
	g         *wiring.Graph
	usernames *Usernames
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_username.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (declared in internal/apispec/api/username).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/username")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// Init builds the username service.
func (p *Plugin) Init(g *wiring.Graph) error {
	u, err := NewUsernames(g.DB(), g.Clock(), p.cfg)
	if err != nil {
		return err
	}
	p.g, p.usernames = g, u
	return nil
}

// Endpoints serves POST /username/sign-in and PATCH /username.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return map[string]endpoint.Endpoint{
		RouteSignIn: endpoint.Func(p.signIn),
		RouteUpdate: endpoint.Func(p.update),
	}, nil
}

// Usernames is the username service.
func (p *Plugin) Usernames() *Usernames { return p.usernames }

// Of returns the username plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// Usernames reads and sets usernames. Safe for concurrent use: the unique index decides a race
// between two users, the lookups before it only give the common case a clean answer.
type Usernames struct {
	db    store.Adapter
	clock clock.Clock
	cfg   Config
}

// NewUsernames returns the service over db (which must hold polaris_username); a nil clk means
// clock.System.
func NewUsernames(db store.Adapter, clk clock.Clock, cfg Config) (*Usernames, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &Usernames{db: db, clock: clk, cfg: cfg}, nil
}

// Normalize is a username as stored for uniqueness: lowercased.
func Normalize(username string) string { return strings.ToLower(username) }

// trimBlank strips surrounding spaces, tabs, newlines, carriage returns, NUL and vertical tabs
// (not the other Unicode spaces strings.TrimSpace strips). The set is fixed on purpose: a trimmed
// username is stored (Set) and compared with stored ones (UserID, sign-in), so the same input must
// keep trimming to the same name existing rows hold.
func trimBlank(s string) string { return strings.Trim(s, " \t\n\r\x00\x0B") }

// Violations lists the rules username breaks; none means acceptable.
func (u *Usernames) Violations(username string) []string {
	var errs []string
	if n := utf8.RuneCountInString(username); n < u.cfg.MinLength || n > u.cfg.MaxLength {
		errs = append(errs, fmt.Sprintf("The username must be %d to %d characters long.", u.cfg.MinLength, u.cfg.MaxLength))
	}
	if !u.cfg.Pattern.MatchString(username) {
		errs = append(errs, "The username contains characters that are not allowed.")
	}
	for _, name := range u.cfg.Reserved {
		if Normalize(name) == Normalize(username) {
			errs = append(errs, "The username is reserved.")
			break
		}
	}
	return errs
}

// ForUser returns the user's username; ok is false when they have none.
func (u *Usernames) ForUser(ctx context.Context, userID string) (Username, bool, error) {
	r, err := u.db.FindOne(ctx, TableUsernames, store.Criteria{"user_id": userID})
	if err != nil || r == nil {
		return Username{}, false, err
	}
	rec := Username{UserID: r.String("user_id"), Username: r.String("username"), DisplayUsername: r.String("display_username")}
	rec.CreatedAt, _ = r.Time("created_at")
	rec.UpdatedAt, _ = r.Time("updated_at")
	return rec, true, nil
}

// UserID returns the user a username belongs to, without regard to case; "" when nobody has it.
func (u *Usernames) UserID(ctx context.Context, username string) (string, error) {
	r, err := u.db.FindOne(ctx, TableUsernames, store.Criteria{"username": Normalize(trimBlank(username))})
	if err != nil || r == nil {
		return "", err
	}
	return r.String("user_id"), nil
}

// Set sets or changes the user's username; display "" means the username as typed, otherwise it
// must be the same letters in another case. It returns a *InvalidError (ErrInvalid) for a username
// breaking the rules and ErrTaken for another user's, also when that user took it concurrently.
func (u *Usernames) Set(ctx context.Context, userID, username, display string) (Username, error) {
	username = trimBlank(username)
	violations := u.Violations(username)
	if display = trimBlank(display); display == "" {
		display = username
	}
	if Normalize(display) != Normalize(username) {
		violations = append(violations, "The display username must be the username with another case.")
	}
	if len(violations) > 0 {
		return Username{}, &InvalidError{Violations: violations}
	}
	normalized := Normalize(username)
	if err := u.ownedByOther(ctx, userID, normalized); err != nil {
		return Username{}, err
	}
	if err := u.write(ctx, userID, normalized, display); err != nil {
		return Username{}, err
	}
	rec, ok, err := u.ForUser(ctx, userID)
	if err == nil && !ok {
		err = ErrTaken // erased concurrently
	}
	return rec, err
}

func (u *Usernames) ownedByOther(ctx context.Context, userID, normalized string) error {
	owner, err := u.UserID(ctx, normalized)
	if err != nil {
		return fmt.Errorf("username: %w", err)
	}
	if owner != "" && owner != userID {
		return ErrTaken
	}
	return nil
}

// write updates the user's row or inserts it. A unique violation is another user taking the name
// after the lookup (ErrTaken) or the same user's concurrent first write, after which the update
// applies.
func (u *Usernames) write(ctx context.Context, userID, normalized, display string) error {
	now := u.clock.Now().UTC().Truncate(time.Second)
	update := func() (int64, error) {
		return u.db.Update(ctx, TableUsernames, store.Criteria{"user_id": userID},
			store.Data{"username": normalized, "display_username": display, "updated_at": now})
	}
	n, err := update()
	if err == nil && n == 0 {
		err = u.db.Insert(ctx, TableUsernames, store.Row{"user_id": userID, "username": normalized,
			"display_username": display, "created_at": now, "updated_at": now})
	}
	if errors.Is(err, store.ErrDuplicate) {
		if err := u.ownedByOther(ctx, userID, normalized); err != nil {
			return err
		}
		_, err = update()
	}
	if err != nil {
		return fmt.Errorf("username: %w", err)
	}
	return nil
}

// Listeners delete an erased user's usernames (event.UserDeleted).
func (*Plugin) Listeners(g *wiring.Graph) []event.Listener {
	return []event.Listener{maintenance.EraseOnUserDeleted(g.DB(), g.Logger(),
		maintenance.UserRows{Table: TableUsernames, Column: "user_id"})}
}
