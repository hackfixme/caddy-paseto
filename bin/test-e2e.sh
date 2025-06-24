#!/usr/bin/env bash
set -eEuo pipefail

_currdir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
source "${_currdir}/utils.sh"
__log_ts="1"

_rootdir="$(git rev-parse --show-toplevel)"
_tmpdir=$(mktemp -d)
_caddy="${_tmpdir}/caddy-paseto"
_caddy_log="${_tmpdir}/caddy.log"
_caddy_pid=""

# External dependencies
_go="go"
_paseto="paseto"      # https://go.hackfix.me/paseto-cli
_curl="curl"
_envsubst="envsubst"

cleanup() {
  if [ -n "$_caddy_pid" ] && kill -0 "$_caddy_pid" 2>/dev/null; then
    log "Stopping Caddy process group $_caddy_pid ..."
    kill -INT -"$_caddy_pid" 2>/dev/null || true
    wait "$_caddy_pid" 2>/dev/null || true
  fi
  rm -rf "$_tmpdir"
}
trap cleanup EXIT

check_deps() {
  _go="$(command -v "$_go" || quit 'go not found')"
  _paseto="$(command -v "$_paseto" || quit 'paseto not found')"
  _curl="$(command -v "$_curl" || quit 'curl not found')"
  _envsubst="$(command -v "$_envsubst" || quit 'envsubst not found')"
}

build_caddy() {
  log "Building ${_caddy} ..."
  "$_go" build -o "${_caddy}" "${_rootdir}/cmd/caddy-paseto"
}

create_paseto_files() {
  "$_paseto" genkey public --protocol-version 4 --out-file "${_tmpdir}/v4"
  echo '{"role":"admin","priority":1,"sub":"Alice"}' \
    | "$_paseto" sign --protocol-version 4 --key-file "${_tmpdir}/v4-priv.key" \
        --expiration 5m --claim - --claim aud='Test Audience' --claim iss='Test Issuer' \
        > "${_tmpdir}/token-v4-pub.txt"
}

create_caddy_config() {
  CADDY_PASETO_KEY="$(cat "${_tmpdir}/v4-pub.key")" \
  CADDY_PASETO_VERSION=4 \
  CADDY_PASETO_PURPOSE=public \
  "$_envsubst" < "${_rootdir}/Caddyfile-test" > "${_tmpdir}/Caddyfile"
}

run_caddy() {
  log "Starting Caddy ..."
  setsid bash -c "'$_caddy' run --config '${_tmpdir}/Caddyfile' 2>&1 | tee '${_caddy_log}'" &
  _caddy_pid=$!

  sleep 0.5
  if ! kill -0 "$_caddy_pid" 2>/dev/null; then
    quit "Caddy process died shortly after starting"
  fi
}

# Parse the actual address the Caddy server is listening on
parse_caddy_address() {
  _actual_address=""
  local _attempts=0
  local _max_attempts=10
  local _line=""

  log "Parsing Caddy listening address ..."

  while [ -z "$_actual_address" ] && [ $_attempts -lt $_max_attempts ]; do
    if [ -f "$_caddy_log" ]; then
      _line=$(grep '"msg":"port 0 listener"' "${_caddy_log}" 2>/dev/null | tail -1 || true)
      if [ -n "$_line" ]; then
        _actual_address=$(echo "$_line" | grep -o '"actual_address":"[^"]*"' | cut -d'"' -f4)
        [ -n "$_actual_address" ] && break
      fi
    fi

    if ! kill -0 "$_caddy_pid" 2>/dev/null; then
      quit "Caddy process died while waiting for startup"
    fi

    sleep 0.5
    _attempts=$((_attempts + 1))
  done

  if [ -z "$_actual_address" ]; then
    quit "Timeout waiting for Caddy to report listening address"
  fi
}

run_tests() {
  log "Running tests against $_actual_address"
  _resp="$(timeout 5 curl --silent --fail --show-error \
    "http://${_actual_address}/?token=$(cat "${_tmpdir}/token-v4-pub.txt")")"
  _exp_resp='{"user":"Alice","role":"admin","priority":1}'
  if [ "$_resp" = "$_exp_resp" ]; then
    ok "Response: $_resp"
  else
    quit "Response: $_resp"
  fi
}

check_deps
build_caddy
create_paseto_files
create_caddy_config
run_caddy
parse_caddy_address
run_tests
