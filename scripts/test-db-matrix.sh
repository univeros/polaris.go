#!/usr/bin/env bash
# Runs the test suite against PostgreSQL 17 and MySQL 8.4 in throwaway Docker containers (WP8
# database matrix).
#
#   scripts/test-db-matrix.sh                 # every package
#   scripts/test-db-matrix.sh ./orgs/...      # only these packages
#   KEEP=1 scripts/test-db-matrix.sh          # leave the containers running afterwards
#
# Needs Docker. It starts postgres:17 and mysql:8.4 on free local ports, waits until both accept
# connections, exports POLARIS_TEST_PG_DSN and POLARIS_TEST_MYSQL_DSN and runs `go test -race`
# twice: once with POLARIS_TEST_DB=postgres and once with POLARIS_TEST_DB=mysql. Every test that
# loops over storetest.Backends() runs on memstore, SQLite, PostgreSQL and MySQL each pass; the
# polaristest servers (the contract fixture suites) run on the database POLARIS_TEST_DB names.
# Each test gets its own schema (PostgreSQL) or database (MySQL), dropped when it ends. The
# containers are stopped and removed on exit. Exit status is non-zero if either pass fails.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
docker=${DOCKER:-docker}
packages=("$@")
[ ${#packages[@]} -eq 0 ] && packages=(./...)

suffix=$$
pg=polaris-matrix-pg-$suffix
my=polaris-matrix-mysql-$suffix
cleanup() {
  [ -n "${KEEP:-}" ] && { echo "containers kept: $pg $my" >&2; return; }
  "$docker" rm -f "$pg" "$my" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$docker" run -d --name "$pg" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=polaris -e POSTGRES_PASSWORD=polaris -e POSTGRES_DB=polaris \
  postgres:17 -c max_connections=1000 -c fsync=off >/dev/null
"$docker" run -d --name "$my" -p 127.0.0.1::3306 \
  -e MYSQL_ROOT_PASSWORD=polaris -e MYSQL_DATABASE=polaris \
  mysql:8.4 --max-connections=2000 --innodb-flush-log-at-trx-commit=0 --skip-log-bin >/dev/null

port() { "$docker" port "$1" "$2" | head -1 | sed 's/.*://'; }
pg_port=$(port "$pg" 5432)
my_port=$(port "$my" 3306)

wait_for() {
  local name=$1; shift
  for _ in $(seq 1 120); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "$name did not become ready" >&2
  exit 1
}
wait_for postgres "$docker" exec "$pg" psql -U polaris -d polaris -c 'SELECT 1'
# The entrypoint's temporary server also answers; wait for the final one on TCP.
wait_for mysql "$docker" exec "$my" mysql -h127.0.0.1 -uroot -ppolaris -e 'SELECT 1'

export POLARIS_TEST_PG_DSN="postgres://polaris:polaris@127.0.0.1:$pg_port/polaris?sslmode=disable"
export POLARIS_TEST_MYSQL_DSN="root:polaris@tcp(127.0.0.1:$my_port)/polaris"

cd "$root"
status=0
for db in postgres mysql; do
  echo "== go test -race (polaristest on $db; loops on memory, sqlite, postgres, mysql)"
  POLARIS_TEST_DB=$db go test -race -count=1 "${packages[@]}" || status=1
done
exit $status
