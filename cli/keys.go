package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"slices"
	"strings"

	polaris "github.com/univeros/polaris-go"
)

const rsaBits = 2048

// keyPair is a fresh JWT key pair as environment values.
type keyPair struct{ private, public string }

func rsaPair() (keyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return keyPair{}, err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return keyPair{}, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return keyPair{}, err
	}
	encode := func(typ string, der []byte) string {
		return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})))
	}
	return keyPair{encode("PRIVATE KEY", priv), encode("PUBLIC KEY", pub)}, nil
}

func appKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func keysGenerate(_ *app, fs *flag.FlagSet) runFunc {
	alg := fs.String("alg", "RS256", "RS256 | EdDSA")
	return func(context.Context) (report, error) {
		key, err := appKey()
		if err != nil {
			return report{}, fail(err.Error(), "the system's random source failed: retry")
		}
		var pair keyPair
		note := ""
		switch *alg {
		case "RS256":
			pair, err = rsaPair()
		case "EdDSA":
			// The token package takes the raw libsodium keys (64-byte secret, 32-byte public), which
			// an environment variable cannot hold: they are printed base64-encoded.
			var pub ed25519.PublicKey
			var priv ed25519.PrivateKey
			pub, priv, err = ed25519.GenerateKey(rand.Reader)
			pair = keyPair{base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)}
			note = "EdDSA keys are base64 of the raw libsodium keys: decode them into config.Secrets and set Auth.AccessToken.Signer = config.SignerEdDSA (polaris.FromEnv reads RS256 PEMs only)"
		default:
			return report{}, usage(fmt.Sprintf("unknown algorithm %q", *alg), "use --alg=RS256 or --alg=EdDSA")
		}
		if err != nil {
			return report{}, fail(err.Error(), "key generation failed: retry")
		}
		env := [][2]string{{"APP_KEY", key}, {"AUTH_JWT_PRIVATE_KEY", pair.private}, {"AUTH_JWT_PUBLIC_KEY", pair.public}}
		var b strings.Builder
		if note != "" {
			b.WriteString("# " + note + "\n")
		}
		values := map[string]any{}
		for _, kv := range env {
			b.WriteString(envLine(kv[0], kv[1]) + "\n")
			values[kv[0]] = kv[1]
		}
		data := map[string]any{"alg": *alg, "env": values}
		if note != "" {
			data["note"] = note
		}
		return report{text: b.String(), data: data}, nil
	}
}

func initCommand(a *app, fs *flag.FlagSet) runFunc {
	force := fs.Bool("force", false, "replace the values already in the file")
	issuer := fs.String("issuer", "http://localhost:8080", "AUTH_ISSUER, written when the file lacks it: your public base URL")
	if a.src.host != nil {
		a.src.envFile = ".env"
		fs.StringVar(&a.src.envFile, "env-file", a.src.envFile, "the file to write")
	}
	return func(context.Context) (report, error) {
		path := a.src.envFile
		file, err := readDotenv(path)
		if err != nil {
			return report{}, fail(err.Error(), "fix that line of "+path+", or point --env-file at another file")
		}
		set := map[string]string{}
		_, hasPriv := file.values["AUTH_JWT_PRIVATE_KEY"]
		_, hasPub := file.values["AUTH_JWT_PUBLIC_KEY"]
		switch {
		case hasPriv != hasPub && !*force:
			return report{}, fail(path+" has only half of the JWT key pair (AUTH_JWT_PRIVATE_KEY / AUTH_JWT_PUBLIC_KEY)", "rerun with --force to replace both with a fresh pair, or add the missing half")
		case !hasPriv || *force:
			pair, err := rsaPair()
			if err != nil {
				return report{}, fail(err.Error(), "key generation failed: retry")
			}
			set["AUTH_JWT_PRIVATE_KEY"], set["AUTH_JWT_PUBLIC_KEY"] = pair.private, pair.public
		}
		if _, ok := file.values["APP_KEY"]; !ok || *force {
			if set["APP_KEY"], err = appKey(); err != nil {
				return report{}, fail(err.Error(), "the system's random source failed: retry")
			}
		}
		if _, ok := file.values["AUTH_ISSUER"]; !ok || (*force && flagSet(fs, "issuer")) {
			set["AUTH_ISSUER"] = *issuer
		}

		added, replaced, kept := []string{}, []string{}, []string{}
		for _, key := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
			_, had := file.values[key]
			_, changed := set[key]
			switch {
			case changed && had:
				replaced = append(replaced, key)
			case changed:
				added = append(added, key)
			default:
				kept = append(kept, key)
			}
		}
		if len(set) > 0 {
			if err := file.write(path, set); err != nil {
				return report{}, fail(err.Error(), "check that "+path+" is writable")
			}
		}

		plugs, err := a.src.plugins()
		if err != nil {
			return report{}, err
		}
		snippet := quickstart(plugs)
		var b strings.Builder
		if len(set) == 0 {
			fmt.Fprintf(&b, "%s already has every value; nothing changed (--force replaces them).\n", path)
		} else {
			fmt.Fprintf(&b, "Wrote %s: added %s; replaced %s. Keep it out of version control.\n", path, orNone(added), orNone(replaced))
		}
		fmt.Fprintf(&b, "\nQuickstart (load %s into the environment first, e.g. `set -a; . ./%s; set +a`):\n\n%s", path, path, snippet)
		data := map[string]any{"file": path, "added": added, "replaced": replaced, "kept": kept, "snippet": snippet}
		return report{text: b.String(), data: data}, nil
	}
}

// flagSet reports whether the flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) { found = found || f.Name == name })
	return found
}

// quickstart is llms.txt's quickstart for the plugins.
func quickstart(plugs []polaris.Plugin) string {
	imports := []string{`polaris "github.com/univeros/polaris-go"`, `"github.com/univeros/polaris-go/store"`, `"github.com/univeros/polaris-go/store/sqlstore"`}
	args := []string{"db"}
	for _, p := range plugs {
		i := slices.IndexFunc(standardPlugins(), func(s standardPlugin) bool { return s.id == p.ID() })
		if i < 0 {
			continue
		}
		sp := standardPlugins()[i]
		imports = append(imports, fmt.Sprintf("%q", sp.importPath))
		args = append(args, sp.snippet)
	}
	var b strings.Builder
	b.WriteString("import (\n")
	for _, imp := range imports {
		b.WriteString("\t" + imp + "\n")
	}
	b.WriteString(")\n\n")
	b.WriteString(`db, err := sqlstore.Open(ctx, store.Postgres, os.Getenv("DATABASE_URL")) // or store.MySQL, store.SQLite` + "\n")
	fmt.Fprintf(&b, "cfg, err := polaris.FromEnv(%s)\n", strings.Join(args, ", "))
	b.WriteString("p, err := polaris.New(cfg)        // validates everything; errors say how to fix\n")
	b.WriteString("_, err = p.Migrate(ctx)            // creates missing tables, seeds permissions; idempotent\n")
	b.WriteString("mux := http.NewServeMux()\n")
	b.WriteString(`mux.Handle("/", p.Handler())       // every Polaris route` + "\n")
	b.WriteString(`mux.Handle("GET /api/invoices", p.Protect(invoicesHandler, "org.read")) // your routes, Polaris principals` + "\n")
	return b.String()
}
