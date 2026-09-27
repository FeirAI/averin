#!/bin/sh
# First-boot role layout for the compose stack (runs once, from /docker-entrypoint-initdb.d, as the
# bootstrap superuser, on an empty data volume only).
#
#   averin_owner  migration identity: owns the averin database and every table averin-migrate creates.
#                 Not a superuser. Used only by the one-shot `migrate` and `grants` services.
#   averin_app    runtime identity the server connects as: not an owner, not a superuser, no role
#                 memberships, and only the table privileges runtime-grants.sql gives it.
#
# averin-server refuses to start as a superuser, as a table owner, or with mutation privilege on an
# append-only table (pgschema.CheckRuntime), so this split is required, not optional.
set -eu
: "${AVERIN_DB_OWNER_PASSWORD:?}"
: "${AVERIN_DB_RUNTIME_PASSWORD:?}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$AVERIN_DB_OWNER_PASSWORD" -v runtime_pw="$AVERIN_DB_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE averin_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'owner_pw';
CREATE ROLE averin_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD :'runtime_pw';
CREATE DATABASE averin OWNER averin_owner;
-- An advancing averin-migrate cutover must see every other session to refuse while one is
-- connected; PostgreSQL hides other roles' sessions from pg_stat_activity without this.
GRANT pg_read_all_stats TO averin_owner;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname averin <<'SQL'
REVOKE ALL ON DATABASE averin FROM PUBLIC;
GRANT CONNECT ON DATABASE averin TO averin_owner, averin_app;
-- PostgreSQL 15+: public is owned by pg_database_owner (averin_owner here), which alone may CREATE.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO averin_app;
SQL
