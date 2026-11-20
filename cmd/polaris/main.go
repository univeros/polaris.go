// Command polaris is the standalone Polaris command line: the instance comes from the environment
// and .env, the database from DATABASE_URL or --dsn, the plugins from --plugins. Run
// `polaris help`. A host that registers its own plugins builds its binary with cli.Run instead.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/univeros/polaris.go/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
