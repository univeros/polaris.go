package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/go-sql-driver/mysql"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/upstream"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/agents"
	"github.com/univeros/polaris-go/plugins/anonymous"
	"github.com/univeros/polaris-go/plugins/apikeys"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/mcp"
	"github.com/univeros/polaris-go/plugins/messaging"
	"github.com/univeros/polaris-go/plugins/multisession"
	"github.com/univeros/polaris-go/plugins/oauth"
	"github.com/univeros/polaris-go/plugins/passwordless"
	"github.com/univeros/polaris-go/plugins/scim"
	"github.com/univeros/polaris-go/plugins/sentinel"
	"github.com/univeros/polaris-go/plugins/sso"
	"github.com/univeros/polaris-go/plugins/username"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
	"github.com/univeros/polaris-go/wiring"
)

const remedyDSN = "set DATABASE_URL (in the environment or .env) or pass --dsn: postgres://user:pass@host:5432/db, mysql://user:pass@host:3306/db or sqlite:path/to/polaris.db"

// source is where a command's instance, schema, manifest and database come from: the host's
// instance (Run), or the environment, --dsn and --plugins (Main). Everything is built once.
type source struct {
	host   *polaris.Polaris
	stderr io.Writer

	// standalone
	dsn, pluginNames, envFile string
	env                       map[string]string // the .env file
	envLoaded                 bool
	plugs                     []polaris.Plugin
	plugsBuilt                bool
	db                        *sqlstore.Store
	inst                      *polaris.Polaris
}

// standardPlugin is a plugin the standalone binary can enable by name.
type standardPlugin struct {
	name, id   string
	importPath string
	snippet    string // its constructor in the quickstart
	build      func(s *source) polaris.Plugin
}

func standardPlugins() []standardPlugin {
	const base = "github.com/univeros/polaris-go/plugins/"
	return []standardPlugin{
		{"audit", audit.ID, base + "audit", "audit.New(audit.Config{})", func(*source) polaris.Plugin { return audit.New(audit.Config{}) }},
		{"admin", admin.ID, base + "admin", "admin.New(admin.Config{})", func(*source) polaris.Plugin { return admin.New(admin.Config{}) }},
		{"apikeys", apikeys.ID, base + "apikeys", "apikeys.New(apikeys.Config{})", func(*source) polaris.Plugin { return apikeys.New(apikeys.Config{}) }},
		{"oauth", oauth.ID, base + "oauth", "oauth.New(oauth.Config{})", func(*source) polaris.Plugin { return oauth.New(oauth.Config{}) }},
		{"agents", agents.ID, base + "agents", "agents.New(agents.Config{ /* Capabilities: … */ })", func(*source) polaris.Plugin { return agents.New(agents.Config{}) }},
		{"mcp", mcp.ID, base + "mcp", `mcp.New(mcp.Config{BaseURL: os.Getenv("AUTH_ISSUER")})`, func(s *source) polaris.Plugin {
			issuer, _ := s.getenv("AUTH_ISSUER")
			return mcp.New(mcp.Config{BaseURL: issuer, Schema: s.ddl})
		}},
		{"anonymous", anonymous.ID, base + "anonymous", "anonymous.New(anonymous.Config{})", func(*source) polaris.Plugin { return anonymous.New(anonymous.Config{}) }},
		{"username", username.ID, base + "username", "username.New(username.Config{})", func(*source) polaris.Plugin { return username.New(username.Config{}) }},
		{"multisession", multisession.ID, base + "multisession", "multisession.New(multisession.Config{})", func(*source) polaris.Plugin { return multisession.New(multisession.Config{}) }},
		{"passwordless", passwordless.ID, base + "passwordless", "passwordless.New(passwordless.Config{})", func(*source) polaris.Plugin { return passwordless.New(passwordless.Config{}) }},
		{"messaging", messaging.ID, base + "messaging", "messaging.New(messaging.Config{ /* Email: &messaging.SMTP{…} */ })", func(*source) polaris.Plugin { return messaging.New(messaging.Config{}) }},
		{"sentinel", sentinel.ID, base + "sentinel", "sentinel.New(sentinel.Config{})", func(*source) polaris.Plugin { return sentinel.New(sentinel.Config{}) }},
		{"sso", sso.ID, base + "sso", "sso.New(sso.Config{})", func(*source) polaris.Plugin { return sso.New(sso.Config{}) }},
		{"scim", scim.ID, base + "scim", "scim.New(scim.Config{})", func(*source) polaris.Plugin { return scim.New(scim.Config{}) }},
	}
}

func pluginNames() []string {
	var names []string
	for _, p := range standardPlugins() {
		names = append(names, p.name)
	}
	return names
}

// prepare reads the .env file of the standalone binary, once.
func (s *source) prepare() error {
	if s.host != nil || s.envLoaded {
		return nil
	}
	env, err := readDotenv(s.envFile)
	if err != nil {
		return fail(err.Error(), "fix that line of "+s.envFile+", or point --env-file at another file")
	}
	s.env, s.envLoaded = env.values, true
	return nil
}

// getenv reads the process environment, then the .env file; an empty variable counts as unset.
func (s *source) getenv(key string) (string, bool) {
	if v := os.Getenv(key); v != "" {
		return v, true
	}
	v, ok := s.env[key]
	return v, ok
}

// plugins are the host's, or the ones --plugins / POLARIS_PLUGINS name.
func (s *source) plugins() ([]polaris.Plugin, error) {
	if s.host != nil {
		return s.host.Graph().Plugins(), nil
	}
	if s.plugsBuilt {
		return s.plugs, nil
	}
	names := s.pluginNames
	if names == "" {
		names, _ = s.getenv("POLARIS_PLUGINS")
	}
	known := standardPlugins()
	var out []polaris.Plugin
	for name := range strings.SplitSeq(names, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		i := slices.IndexFunc(known, func(p standardPlugin) bool { return p.name == name })
		if i < 0 {
			return nil, usage(fmt.Sprintf("unknown plugin %q", name), "use --plugins with any of: "+strings.Join(pluginNames(), ", "))
		}
		out = append(out, known[i].build(s))
	}
	s.plugs, s.plugsBuilt = out, true
	return out, nil
}

// models is the schema of core and the plugins.
func (s *source) models() ([]schema.Model, error) {
	if s.host != nil {
		return s.host.Graph().Schema(), nil
	}
	plugs, err := s.plugins()
	if err != nil {
		return nil, err
	}
	var extra [][]schema.Model
	for _, p := range plugs {
		if sp, ok := p.(wiring.SchemaProvider); ok {
			extra = append(extra, sp.Schema())
		}
	}
	models, err := schema.Merge(schema.Core(), extra...)
	if err != nil {
		return nil, fail(err.Error(), "two plugins define the same table: enable only one of them")
	}
	return models, nil
}

// manifest is the routes of core and the plugins, loaded as polaris.New loads them.
func (s *source) manifest() (*manifest.Manifest, error) {
	if s.host != nil {
		return s.host.Graph().Manifest(), nil
	}
	plugs, err := s.plugins()
	if err != nil {
		return nil, err
	}
	core, err := fs.Sub(upstream.API, "api/core")
	if err != nil {
		return nil, err
	}
	dirs := []fs.FS{core}
	for _, p := range plugs {
		if mp, ok := p.(wiring.ManifestProvider); ok && mp.Manifest() != nil {
			dirs = append(dirs, mp.Manifest())
		}
	}
	m, err := manifest.Load(dirs...)
	if err != nil {
		return nil, fail(err.Error(), "the route specs conflict: remove the plugin the message names")
	}
	return m, nil
}

// config is the secrets and auth settings, validated.
func (s *source) config() (config.Secrets, config.Auth, error) {
	if s.host != nil {
		g := s.host.Graph()
		return g.Config().Secrets, g.Auth(), nil
	}
	secrets, auth, err := config.FromLookup(s.getenv)
	if err != nil {
		return secrets, auth, fail(err.Error(), "run `polaris init` (writes APP_KEY, a JWT key pair and AUTH_ISSUER to .env), or set the variables named above")
	}
	return secrets, auth, nil
}

// sqlStore finds the *sqlstore.Store under a, unwrapping decorators (telemetry/otel.Store) that
// expose Unwrap() store.Adapter.
func sqlStore(a store.Adapter) (*sqlstore.Store, bool) {
	for a != nil {
		if db, ok := a.(*sqlstore.Store); ok {
			return db, true
		}
		u, ok := a.(interface{ Unwrap() store.Adapter })
		if !ok {
			return nil, false
		}
		a = u.Unwrap()
	}
	return nil, false
}

// database is the SQL store the schema commands work on.
func (s *source) database(ctx context.Context) (*sqlstore.Store, error) {
	if s.host != nil {
		db, ok := sqlStore(s.host.Graph().DB())
		if !ok {
			return nil, fail(fmt.Sprintf("the instance's database adapter (%s) is not an SQL store", s.host.Graph().DB().Dialect()), "the schema commands need a store/sqlstore database: build the instance with sqlstore.Open")
		}
		return db, nil
	}
	if s.db != nil {
		return s.db, nil
	}
	dsn := s.dsn
	if dsn == "" {
		dsn, _ = s.getenv("DATABASE_URL")
	}
	if dsn == "" {
		return nil, fail("no database: --dsn and DATABASE_URL are empty", remedyDSN)
	}
	d, conn, err := parseDSN(dsn)
	if err != nil {
		return nil, usage(err.Error(), remedyDSN)
	}
	db, err := sqlstore.Open(ctx, d, conn)
	if err != nil {
		return nil, fail(err.Error(), "check that the database is running and reachable, and the URL's credentials and database name")
	}
	s.db = db
	return db, nil
}

// instance is the host's instance, or one built from the environment.
func (s *source) instance(ctx context.Context) (*polaris.Polaris, error) {
	if s.host != nil {
		return s.host, nil
	}
	if s.inst != nil {
		return s.inst, nil
	}
	secrets, auth, err := s.config()
	if err != nil {
		return nil, err
	}
	db, err := s.database(ctx)
	if err != nil {
		return nil, err
	}
	plugs, err := s.plugins()
	if err != nil {
		return nil, err
	}
	p, err := polaris.New(polaris.Config{
		Secrets: secrets, Auth: auth, DB: db, Plugins: plugs,
		Logger: slog.New(slog.NewTextHandler(s.stderr, nil)),
	})
	if err != nil {
		return nil, fail(err.Error(), "fix what the message names (the environment, .env or --plugins; standalone, oauth and mcp take their base URL from AUTH_ISSUER), then run `polaris doctor`")
	}
	s.inst = p
	return p, nil
}

// ddl is the schema as the instance's database creates it (mcp's polaris://schema resource).
func (s *source) ddl(ctx context.Context) (string, error) {
	db, err := s.database(ctx)
	if err != nil {
		return "", err
	}
	models, err := s.models()
	if err != nil {
		return "", err
	}
	return sqlstore.DDL(models, db.Dialect())
}

func (s *source) close() {
	if s.db != nil {
		_ = s.db.DB().Close()
	}
}

// parseDSN maps a database URL to its dialect and the driver's DSN.
func parseDSN(dsn string) (store.Dialect, string, error) {
	scheme, rest, _ := strings.Cut(dsn, ":")
	switch strings.ToLower(scheme) {
	case "postgres", "postgresql":
		return store.Postgres, dsn, nil
	case "mysql":
		conn, err := mysqlDSN(rest)
		return store.MySQL, conn, err
	case "sqlite", "sqlite3":
		return store.SQLite, sqliteDSN(strings.TrimPrefix(rest, "//")), nil
	case "file":
		return store.SQLite, sqliteDSN(rest), nil
	}
	return "", "", errors.New("unrecognized database URL: it must start with postgres://, mysql://, sqlite: or file:")
}

// sqliteDSN enables foreign keys and a busy timeout, unless the URL sets its own parameters.
func sqliteDSN(path string) string {
	if strings.Contains(path, "?") {
		return "file:" + path
	}
	return "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// mysqlDSN accepts the driver's own form (user:pass@tcp(host:3306)/db) or a URL
// (mysql://user:pass@host:3306/db?params).
func mysqlDSN(rest string) (string, error) {
	rest = strings.TrimPrefix(rest, "//")
	if strings.Contains(rest, "@tcp(") || strings.Contains(rest, "@unix(") {
		return rest, nil
	}
	u, err := url.Parse("mysql://" + rest)
	if err != nil {
		return "", fmt.Errorf("the MySQL URL does not parse: %w", err)
	}
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.DBName = "tcp", u.Host, strings.TrimPrefix(u.Path, "/")
	if u.User != nil {
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
	}
	conn := cfg.FormatDSN()
	if u.RawQuery != "" {
		sep := "?"
		if strings.Contains(conn, "?") {
			sep = "&"
		}
		conn += sep + u.RawQuery
	}
	return conn, nil
}
