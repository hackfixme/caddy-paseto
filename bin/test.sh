#!/usr/bin/env bash
set -eEuo pipefail

_currdir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
source "${_currdir}/utils.sh"
__log_ts="1"

cov=0
e2e=0
pkgs=()
argsa=(-v -race -count=1 -failfast)
argsb=()

_rootdir="$(git rev-parse --show-toplevel)"
_covdir="${_rootdir}/coverage"

# It would be nice if Just supported recipe flags, so we could avoid manually
# parsing arguments. See https://github.com/casey/just/issues/476
while [ "$#" -gt 0 ]; do
  case $1 in
    -c|--coverage)  cov=1 ;;
    --e2e)          e2e=1 ;;
    # Other options are passed through to go test
    -*)             argsa+=("$1") ;;
    *)              pkgs+=("$1") ;;
  esac
  shift
done

if [ "$e2e" -gt 0 ]; then
  "${_rootdir}/bin/test-e2e.sh"
  exit $?
fi

if [ "$cov" -gt 0 ]; then
  mkdir -p "${_covdir}"
  argsa+=(-coverpkg=./...)
  argsb+=(-args -test.gocoverdir="${_covdir}")

  log "Applying Go coverage workaround ..."
  ./bin/fix-missing-go-coverage.sh
fi

[ "${#pkgs[@]}" -eq 0 ] && pkgs=(./...)

go test "${argsa[@]}" "${pkgs[@]}" "${argsb[@]}"

if [ "$cov" -gt 0 ]; then
  go tool covdata textfmt -i="${_covdir}" -o "${_covdir}/coverage.txt"
  fcov report "${_covdir}/coverage.txt"
fi
