#!/bin/sh
# pbseed entrypoint: durable SQLite via litestream when R2 is configured,
# plain app otherwise (local dev needs no credentials).
#
# With R2_* set: litestream restores data.db from the replica when the local
# file is missing (fresh deploy on ephemeral disk), then runs the app as its
# child (-exec) and streams every WAL change to R2 (~1s RPO). The replica
# covers data.db ONLY (users/sessions/settings/notes) — see README.
#
# SINGLE INSTANCE ONLY: never run 2+ replicas of this service with the same
# R2 bucket — two writers would fork the database (split brain).
set -e

if [ -n "$R2_ACCOUNT_ID" ] && [ -n "$R2_BUCKET" ] \
  && [ -n "$R2_ACCESS_KEY_ID" ] && [ -n "$R2_SECRET_ACCESS_KEY" ]; then
  echo "entrypoint: R2 configured, starting under litestream (bucket $R2_BUCKET)"
  exec /pb/litestream replicate -restore-if-db-not-exists \
    -config /pb/litestream.yml -exec "$*"
fi

echo "entrypoint: no R2 credentials, starting app directly (ephemeral disk)"
exec "$@"
