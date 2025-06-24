set dotenv-load

rootdir := `git rev-parse --show-toplevel`
distdir := rootdir + '/dist'
covdir  := rootdir + '/coverage'

default:
  @just --list

test *args:
  @{{rootdir}}/bin/test.sh '{{args}}'

lint report="":
  #!/usr/bin/env sh
  if [ -z '{{report}}' ]; then
    golangci-lint run --timeout=5m --output.tab.path=stdout ./...
    exit $?
  fi

  _report_id="$(date '+%Y%m%d')-$(git describe --tags --abbrev=10 --always)"
  golangci-lint run --timeout 5m --output.tab.path=stdout --issues-exit-code=0 \
      --show-stats=false ./... \
    | tee "golangci-lint-${_report_id}.txt" \
    | awk 'NF {if ($2 == "revive") print $2 ":" $3; else print $2}' \
    | sed 's,:$,,' | sort | uniq -c | sort -nr \
    | tee "golangci-lint-summary-${_report_id}.txt"

clean:
  @rm -rf "{{distdir}}" "{{covdir}}" "{{rootdir}}"/golangci-lint*.txt
  @git ls-files --others --exclude-standard | grep '_test\.go' | xargs -r rm
