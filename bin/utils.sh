# Text color helper borrowed from acme.sh
# https://github.com/sparanoid/live-dl/blob/master/live-dl
# TODO: Disable color when stdout is not a tty

TZ="${TZ:="$(date +%Z)"}"

__green() {
  printf '\033[1;31;32m%b\033[0m' "$1"
}

__yellow() {
  printf '\033[1;31;33m%b\033[0m' "$1"
}

__red() {
  printf '\033[1;31;40m%b\033[0m' "$1"
}

__timestamp() {
  [ -n "${__log_ts:-}" ] && printf "%s " "$(date -Iseconds)" || true
}

log() {
  { __timestamp; printf "\033[1mINFO\033[0m: %s\n" "$*"; } >&2
}

ok() {
  { __timestamp; __green "OK"; printf ": %s\n" "$*"; } >&2
}

warn() {
  { __timestamp; __yellow "WARN"; printf ": %s\n" "$*"; } >&2
}

err() {
  { __timestamp; __red "ERROR"; printf ": %s\n" "$*"; } >&2
}

quit() {
  err "$*"
  exit 1
}
